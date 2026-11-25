import Foundation

// AVPN (этап D3): хостовый Swift-тест (macOS, без устройства) для изолированных файлов
// TunnelRuntimeStatus.swift + XraySocketCallbackLifecycle.swift. Запуск —
// tests/run_ios_swift_checks.sh (компилирует и выполняет, затем typecheck провайдера на стабах).

private func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
    guard condition() else {
        fputs("FAIL: \(message)\n", stderr)
        exit(1)
    }
}

private final class Token {}

private final class ConcurrentTeardownHarness: @unchecked Sendable {
    let started = DispatchSemaphore(value: 0)
    let allowStopReturn = DispatchSemaphore(value: 0)
    private let gate = XrayNativeLifecycleGate()
    private let lock = NSLock()
    private let registry: XraySocketCallbackRegistry<Token>
    private let identity: XraySocketCallbackIdentity
    private let token: Token
    private(set) var stopCount = 0
    private(set) var retireCount = 0
    private(set) var results = [Bool]()

    init(registry: XraySocketCallbackRegistry<Token>,
         identity: XraySocketCallbackIdentity, token: Token) {
        self.registry = registry
        self.identity = identity
        self.token = token
    }

    func runAndRecord() {
        let result = gate.withExclusive {
            guard registry.value(for: identity) != nil else { return registry.count == 0 }
            return XraySocketCallbackTeardown.execute(
                stopCore: {
                    lock.lock(); stopCount += 1; lock.unlock()
                    started.signal()
                    _ = allowStopReturn.wait(timeout: .now() + 2)
                    return true
                },
                drain: { true },
                retireContext: {
                    lock.lock(); retireCount += 1; lock.unlock()
                    return registry.remove(identity: identity) === token
                })
        }
        lock.lock(); results.append(result); lock.unlock()
    }

    func snapshot() -> (results: [Bool], stopCount: Int, retireCount: Int) {
        lock.lock(); defer { lock.unlock() }
        return (results, stopCount, retireCount)
    }
}

private func uuid(_ value: UInt64) -> String {
    String(format: "00000000-0000-4000-8000-%012llx", value)
}

private func sample(rx: UInt64, tx: UInt64, rxp: UInt64 = 0, txp: UInt64 = 0) -> TunnelTrafficSample {
    TunnelTrafficSample(rxBytes: rx, txBytes: tx, rxPackets: rxp, txPackets: txp)
}

private func testTrafficAccumulator() {
    var acc = ResetSafeTrafficAccumulator()
    var delta = acc.record(sample(rx: 100, tx: 50))
    expect(delta.sample == sample(rx: 100, tx: 50) && !delta.resetDetected,
           "first raw sample from zero baseline is the delta")
    delta = acc.record(sample(rx: 160, tx: 70))
    expect(delta.sample == sample(rx: 60, tx: 20), "monotonic raw growth yields exact delta")
    expect(acc.cumulative == sample(rx: 160, tx: 70), "cumulative follows raw while monotonic")

    // Движок перезапустился: сырые счётчики упали. Весь новый отсчёт — трафик после рестарта,
    // он и есть дельта; кумулятив не теряется и не откатывается, reset считается.
    delta = acc.record(sample(rx: 5, tx: 1))
    expect(delta.resetDetected && delta.sample == sample(rx: 5, tx: 1),
           "backward raw value is a reset whose delta is the whole new reading")
    expect(acc.cumulative == sample(rx: 165, tx: 71), "reset never erases accumulated traffic")
    expect(acc.resetCount == 1, "reset is counted once")
    delta = acc.record(sample(rx: 25, tx: 11))
    expect(delta.sample == sample(rx: 20, tx: 10), "growth after reset rebases on the new raw baseline")
    expect(acc.cumulative == sample(rx: 185, tx: 81), "cumulative continues after reset")

    // Перебазирование (стейл-счётчики прошлого запуска в том же процессе не засчитываются).
    acc.reset()
    acc.rebase(sample(rx: 1_000, tx: 2_000))
    delta = acc.record(sample(rx: 1_000, tx: 2_000))
    expect(delta.sample == .zero && !delta.resetDetected, "rebase makes the stale raw value a zero delta")
    delta = acc.record(sample(rx: 0, tx: 0))
    expect(delta.resetDetected && acc.cumulative == .zero, "engine restart after rebase is a clean reset")
    delta = acc.record(sample(rx: 7, tx: 3))
    expect(acc.cumulative == sample(rx: 7, tx: 3), "traffic after rebase+reset is counted exactly")

    // Насыщение вместо переполнения UInt64.
    acc.reset()
    _ = acc.record(sample(rx: UInt64.max - 1, tx: 0))
    acc.rebase(.zero)
    _ = acc.record(sample(rx: 10, tx: 0))
    expect(acc.cumulative.rxBytes == UInt64.max, "cumulative saturates instead of wrapping")
}

private func testRuntimeSession() {
    let session = TunnelRuntimeSession()
    expect(session.snapshot().state == .stopped && session.snapshot().generation == 0,
           "fresh session is stopped at generation 0")

    let gen1 = session.beginSession(protocolName: "xray")
    expect(gen1 == 1 && session.snapshot().state == .starting, "beginSession bumps generation to 1")
    expect(XraySocketCallbackIdentity(generation: gen1, sessionId: session.snapshot().sessionId) != nil,
           "generated session id is a lowercase uuid usable as callback identity")
    expect(!session.record(sample(rx: 1, tx: 1), generation: gen1),
           "counters are not recorded before running")
    expect(session.transition(to: .running, generation: gen1), "starting -> running")
    expect(session.record(sample(rx: 100, tx: 40), generation: gen1), "running session records")
    expect(!session.record(sample(rx: 200, tx: 80), generation: gen1 + 1),
           "stale generation cannot record")
    expect(session.snapshot().counters == sample(rx: 100, tx: 40), "cumulative reflects recorded sample")

    // Первый провал терминален ровно один раз; стейл-поколение не роняет сессию.
    expect(!session.fail(generation: gen1 + 7), "stale generation cannot fail the session")
    expect(session.fail(generation: gen1), "first failure of the current generation is reported")
    expect(!session.fail(generation: gen1), "second failure of the same generation is swallowed")
    expect(session.snapshot().state == .failed, "session is failed")

    let stopGen = session.beginStop()
    expect(stopGen == gen1 + 1 && !session.isCurrent(generation: gen1),
           "beginStop invalidates the previous generation")
    expect(session.snapshot().sessionId == session.snapshot().sessionId, "session id survives stop")
    expect(session.transition(to: .stopped, generation: stopGen), "stopping -> stopped")

    // Рестарт по смене сети: кумулятив сохраняется, поколение новое.
    let sessionIdBefore = session.snapshot().sessionId
    let gen3 = session.beginSession(protocolName: "xray", preservingCounters: true)
    expect(gen3 == stopGen + 1, "restart bumps generation")
    expect(session.snapshot().sessionId != sessionIdBefore, "restart issues a fresh session id")
    expect(session.snapshot().counters == sample(rx: 100, tx: 40),
           "preservingCounters keeps the cumulative across the restart")
    expect(session.rebase(sample(rx: 100, tx: 40), generation: gen3), "rebase on current generation")
    expect(!session.rebase(.zero, generation: gen1), "rebase on stale generation is refused")
    expect(session.transition(to: .running, generation: gen3), "restart -> running")
    expect(session.record(sample(rx: 3, tx: 2), generation: gen3), "engine counters reset after restart")
    expect(session.snapshot().counters == sample(rx: 103, tx: 42),
           "traffic after restart adds to the preserved cumulative")
    expect(session.snapshot().counterResetCount == 1, "restart reset is counted")

    // Полный новый старт (без сохранения) обнуляет кумулятив.
    let gen4 = session.beginSession(protocolName: "xray")
    expect(session.snapshot().counters == .zero && !session.snapshot().countersAvailable,
           "fresh session starts from zero counters")

    // Payload: строки для счётчиков, плоские rx/tx для старого парсера, handshake = null.
    _ = session.transition(to: .running, generation: gen4)
    _ = session.record(sample(rx: 12, tx: 34, rxp: 5, txp: 6), generation: gen4)
    let payload = session.payload(core: ["engine": "xray"])
    expect(payload["type"] as? String == TunnelRuntimeSession.payloadType, "payload type")
    expect(payload["runtime_state"] as? String == "running", "payload runtime_state")
    expect(payload["rx_bytes"] as? String == "12" && payload["tx_bytes"] as? String == "34",
           "flat rx/tx are decimal strings")
    expect(payload["last_handshake_time_sec"] is NSNull, "xray has no handshake: null")
    let counters = payload["counters"] as? [String: Any]
    expect(counters?["available"] as? Bool == true, "counters available after record")
    expect(counters?["rx_packets"] as? String == "5" && counters?["tx_packets_delta"] as? String == "6",
           "packet counters and deltas are strings")
    expect(JSONSerialization.isValidJSONObject(payload), "payload is JSON-serializable")
}

private func testIPv4RouteSpec() {
    let canonical = IPv4RouteSpec(cidr: "103.228.2.0/24")
    expect(canonical?.destinationAddress == "103.228.2.0" &&
           canonical?.subnetMask == "255.255.255.0",
           "canonical IPv4 CIDR is preserved")
    let hostBits = IPv4RouteSpec(cidr: "10.0.0.17/24")
    expect(hostBits?.destinationAddress == "10.0.0.0" &&
           hostBits?.subnetMask == "255.255.255.0",
           "host bits are masked before creating NEIPv4Route")
    let defaultRoute = IPv4RouteSpec(cidr: "0.0.0.0/0")
    expect(defaultRoute?.destinationAddress == "0.0.0.0" &&
           defaultRoute?.subnetMask == "0.0.0.0",
           "default IPv4 route is valid")
    expect(IPv4RouteSpec(cidr: "2a00:1450::/32") == nil,
        "IPv6 CIDR is never passed to NEIPv4Route")
    expect(IPv4RouteSpec(cidr: "10.0.0.1/33") == nil,
        "out-of-range prefix is rejected")
    expect(IPv4RouteSpec(cidr: "not-a-route") == nil,
        "malformed CIDR is rejected")
}

// AVPN (IPv6-волна 2026-09-08): NEIPv6Route требует СЕТЕВОЙ адрес префикса, а не произвольный хост
// внутри него, и не принимает v4/scope-строки. Тот же контракт, что у IPv4RouteSpec выше, —
// нужен для v6-половины RU-split на xray-пути (2174 префикса ru_prefixes.h).
private func testIPv6RouteSpec() {
    let expanded = IPv6RouteSpec(cidr: "2001:0640:0000:0000:0000:0000:0000:0000/32")
    expect(expanded?.destinationAddress == "2001:640::" && expanded?.networkPrefixLength == 32,
           "expanded IPv6 CIDR is canonicalized (RFC 5952)")
    let hostBits = IPv6RouteSpec(cidr: "2001:640:1:2::5/32")
    expect(hostBits?.destinationAddress == "2001:640::" && hostBits?.networkPrefixLength == 32,
           "host bits are masked before creating NEIPv6Route")
    let defaultRoute = IPv6RouteSpec(cidr: "::/0")
    expect(defaultRoute?.destinationAddress == "::" && defaultRoute?.networkPrefixLength == 0,
           "default IPv6 route is valid")
    let hostRoute = IPv6RouteSpec(cidr: "2606:4700:4700::1111/128")
    expect(hostRoute?.destinationAddress == "2606:4700:4700::1111" &&
           hostRoute?.networkPrefixLength == 128,
           "/128 host route keeps every bit")
    expect(IPv6RouteSpec(cidr: "10.0.0.0/8") == nil,
           "IPv4 CIDR is never passed to NEIPv6Route")
    expect(IPv6RouteSpec(cidr: "2001:640::/129") == nil,
           "out-of-range prefix is rejected")
    expect(IPv6RouteSpec(cidr: "fe80::1%en0/64") == nil,
           "scoped address is rejected — a route has no interface scope")
    expect(IPv6RouteSpec(cidr: "2001:640::") == nil,
           "bare address without a prefix is rejected")
    expect(IPv6RouteSpec(cidr: "not-a-route") == nil,
           "malformed CIDR is rejected")
}

// AVPN (device round air-B 24.11; reviews R43 F1-F3, R46 R1-R3): the stop of an Xray session, through the real
// decisions (TunnelRuntimeSession's generation + hev phase + run epoch, XrayHevRuns, XrayHevStop, TunnelStartSlot,
// StopClosableSlot) in the provider's order (stopTunnel: stopBegan at entry; stopXray: under the native gate the
// generation move, then the hev stop; then abortForStop right before the stop's own answer; the hev worker: the
// process's run slot, then enterHev, then it answers and runs).
// hev is a model of the native library (recipes/hev-socks5-tunnel) with both protocols of the stop request:
//  - .scoped (patches 0001 + 0002): a request is kept only while a run is in progress and dies with it; the stopper's
//    set-and-check and the run's publish-and-take are one critical section each, under one mutex;
//  - .unsynchronized (patch 0001 alone, the library before R46): the request is a process-global flag that survives
//    the run, the run publishes `run = 1` and reads the flag without the mutex. Its two stores can sit in store buffers
//    (arm64): `storeBuffering` makes the next handshake take the order in which both sides read the other's old value.
// Its blocking quit loops until a run has created its event fd (100 ms sleeps), like hev_socks5_tunnel_stop.
private final class SystemCompletions: @unchecked Sendable {
    private let lock = NSLock()
    private(set) var startAnswers: [String] = []
    private(set) var stopAnswered = false
    private(set) var order: [String] = []
    func start(_ error: Error?) {
        lock.lock(); defer { lock.unlock() }
        let what = error == nil ? "ok" : (error is TunnelStartAbort ? "stopped_during_start" : "error")
        startAnswers.append(what)
        order.append("start:" + what)
    }
    func stop() {
        lock.lock(); defer { lock.unlock() }
        stopAnswered = true
        order.append("stop")
    }
    func snapshot() -> (starts: [String], stopped: Bool, order: [String]) {
        lock.lock(); defer { lock.unlock() }
        return (startAnswers, stopAnswered, order)
    }
}

private enum FakeStartError: Error { case superseded, hevBusy, leaseTerminal }

private final class ModelHev: XrayHevControl, @unchecked Sendable {
    enum Native { case scoped, unsynchronized }
    let native: Native
    private let mutex = NSLock()           // stop_mutex
    private var scope = false              // run_scope (scoped)
    private var running = false            // run
    private var eventFd = false            // event_fds[1] >= 0
    private var requested = false          // stop_requested
    private var event = false              // the quit event written
    var storeBuffering = false             // unsynchronized: the next handshake loses (both read old values)
    var initMs = 20
    var outlivesStopUntil: Date?           // a session keeps the run alive past its stop until then (nil: never)
    private(set) var runs = 0
    private(set) var stoppedRuns = 0       // runs that ended on a quit event
    init(native: Native) { self.native = native }

    // hev_socks5_tunnel_main_*: scope, init (the event fd), run (publish + take), the loop until the event, fini.
    func main(runMs: Int = 60_000) {
        mutex.lock(); runs += 1
        if native == .scoped { scope = true; requested = false }
        mutex.unlock()
        usleep(useconds_t(initMs * 1000))
        mutex.lock(); eventFd = true; mutex.unlock()
        switch native {
        case .scoped:
            mutex.lock(); running = true; if requested { event = true }; mutex.unlock()
        case .unsynchronized:
            mutex.lock(); let lose = storeBuffering; mutex.unlock()
            if lose {
                // store buffering: the run's `run = 1` is not visible to the stopper yet and the stopper's request is
                // not visible here - this check reads 0; the stopper reads run == 0 (handled in tryQuit)
                mutex.lock(); running = true; mutex.unlock()
            } else {
                mutex.lock(); running = true; let r = requested; mutex.unlock()
                if r { _ = tryQuit() }
            }
        }
        let end = Date().addingTimeInterval(Double(runMs) / 1000)
        while Date() < end {
            mutex.lock(); let e = event; let keep = outlivesStopUntil; mutex.unlock()
            if e && (keep == nil || Date() >= keep!) { mutex.lock(); stoppedRuns += 1; mutex.unlock(); break }
            usleep(1_000)
        }
        mutex.lock()
        running = false; eventFd = false; event = false
        requested = false // fini (both protocols)
        if native == .scoped { scope = false }
        mutex.unlock()
    }

    func tryQuit() -> Int32 {
        mutex.lock(); defer { mutex.unlock() }
        switch native {
        case .scoped:
            guard scope else { return -ESRCH }
            requested = true
            guard running, eventFd else { return -EAGAIN }
            event = true
            return 0
        case .unsynchronized:
            requested = true
            if storeBuffering && running {
                storeBuffering = false // this one handshake reads the old `run`: the request is lost
                return -EAGAIN
            }
            guard running, eventFd else { return -EAGAIN }
            event = true
            return 0
        }
    }

    func quitBlocking() {
        while true {
            mutex.lock()
            if eventFd { event = true; mutex.unlock(); return }
            mutex.unlock()
            usleep(100_000)
        }
    }

    // a stale request left in the process (unsynchronized: it survives the run that set it)
    var requestLeft: Bool { mutex.lock(); defer { mutex.unlock() }; return requested }
}

private final class FakeRenewer {}

// One Xray session of the provider, in the order of the real code (PacketTunnelProvider.swift / +Xray / +Upstream).
private final class ProviderModel: @unchecked Sendable {
    let system = SystemCompletions()
    let slot = TunnelStartSlot()
    let gate = XrayNativeLifecycleGate()
    let session = TunnelRuntimeSession()
    let renewers = StopClosableSlot<FakeRenewer>()
    let runs: XrayHevRuns
    let hev: ModelHev
    let workers = DispatchGroup()
    var startAnswer: (Error?) -> Void = { _ in }
    var generation: UInt64 = 0
    var hevStop: XrayHevStop?
    var runMs = 60_000
    var stopLimit = XrayHevStop.exitLimitSeconds   // XrayHevStop's hard limit
    var enterWait = XrayHevStop.exitLimitSeconds   // the worker's wait for the run slot
    var idleWait = XrayHevStop.exitLimitSeconds    // the roam retry's wait for the earlier run
    private let stateLock = NSLock()
    private var reassertingStorage = false
    private(set) var clearedWithoutHev = false     // reasserting cleared while no hev of this session runs
    private(set) var cancels: [String] = []
    private(set) var coreStarts = 0
    var reasserting: Bool { stateLock.lock(); defer { stateLock.unlock() }; return reassertingStorage }

    init(hev: ModelHev, runs: XrayHevRuns = XrayHevRuns()) {
        self.hev = hev
        self.runs = runs
        startAnswer = slot.begin { [system] in system.start($0) } // startTunnel
        renewers.reopen()                                          // beginUpstreamMeter
        generation = session.beginSession(protocolName: "xray")    // startXray
    }

    // a core restart inside the same session (network change): stopXray {} then startXray(preservingCounters: true)
    func restart() {
        nativeStop()
        generation = session.beginSession(protocolName: "xray", preservingCounters: true)
        queueHevWorker()
    }

    // setupAndRunTun2socks + its worker
    func queueHevWorker(beforeEnter: (() -> Void)? = nil, afterReturn: (() -> Void)? = nil,
                        answer: ((Error?) -> Void)? = nil) {
        let startAnswer = answer ?? self.startAnswer
        let gen = generation
        let queued: Bool = gate.withExclusive {
            guard session.isCurrent(generation: gen), session.transition(to: .running, generation: gen),
                  session.queueHev(generation: gen) else { return false }
            return true
        }
        guard queued else { startAnswer(FakeStartError.superseded); return }
        workers.enter()
        DispatchQueue.global().async { [self] in
            defer { workers.leave() }
            beforeEnter?()
            guard let run = runs.enter(waitSeconds: enterWait) else {
                session.exitHev(generation: gen)
                startAnswer(FakeStartError.hevBusy)
                return
            }
            guard session.enterHev(generation: gen, run: run) else {
                runs.exit(run)
                startAnswer(FakeStartError.superseded)
                return
            }
            _ = renewers.attach(FakeRenewer()) // attachUpstreamRenewer (refused after the stop took the slot)
            startAnswer(nil)
            hev.main(runMs: runMs)
            afterReturn?()                     // between the native return and the worker's bookkeeping
            session.exitHev(generation: gen)
            runs.exit(run)
        }
    }

    // stopXray's native part (the gate section)
    func nativeStop() {
        gate.withExclusive {
            let stopping = session.beginStopReportingHev()
            hevStop = XrayHevStop.execute(run: stopping.hevRun, runs: runs, hev: hev, limitSeconds: stopLimit)
        }
    }

    // stopTunnel -> stopXrayThenReleaseUpstream -> stopXray, then the completion wrapper. Returns how long it took (ms)
    // or nil when it did not return within `bound`.
    func stop(bound: TimeInterval = 3) -> Double? {
        let done = DispatchSemaphore(value: 0)
        let began = DispatchTime.now()
        DispatchQueue.global().async { [self] in
            _ = slot.stopBegan()
            _ = renewers.take()
            nativeStop()
            _ = slot.abortForStop()
            system.stop()
            done.signal()
        }
        guard done.wait(timeout: .now() + bound) == .success else { return nil }
        return Double(DispatchTime.now().uptimeNanoseconds - began.uptimeNanoseconds) / 1_000_000
    }

    func hevRunning() -> Bool { session.hevPhaseNow == .running }

    // handle(networkChange:) through the provider's XrayRoamDriver
    let roamQueue = DispatchQueue(label: "test.roam")
    var leaseStopped = false                       // tribeUpstream.coreStoppedByLease (upstreamLeaseTerminal)
    var duringRestartStop: (() -> Void)?           // something that lands between the restart's stop and its start
    func roam(completion: @escaping (Error?) -> Void) {
        let driver = XrayRoamDriver(
            stopCore: { [self] in nativeStop(); duringRestartStop?() },
            startCore: { [self] done in
                stateLock.lock(); coreStarts += 1; stateLock.unlock()
                // startXray's guard (PacketTunnelProvider+Xray.swift): a core the lease stopped is never started
                guard !leaseStopped else { done(FakeStartError.leaseTerminal); return }
                generation = session.beginSession(protocolName: "xray", preservingCounters: true)
                queueHevWorker(answer: done)
            },
            classify: { [self] error in
                (superseded: (error as? FakeStartError) == .superseded,
                 leaseEnded: (error as? FakeStartError) == .leaseTerminal || leaseStopped)
            },
            sessionStopping: { [self] in slot.sessionStopping },
            waitEarlierRun: { [self] in _ = runs.waitIdle(until: Date().addingTimeInterval(idleWait)) },
            setReasserting: { [self] on in
                stateLock.lock()
                if !on && session.hevPhaseNow != .running { clearedWithoutHev = true }
                reassertingStorage = on
                stateLock.unlock()
            },
            endTunnel: { [self] error in stateLock.lock(); cancels.append("\(error)"); stateLock.unlock() },
            log: { _ in },
            queue: roamQueue)
        roamQueue.async { driver.run(completion: completion) }
    }
}

private func waitUntil(_ seconds: TimeInterval, _ cond: () -> Bool) -> Bool {
    let end = Date().addingTimeInterval(seconds)
    while Date() < end { if cond() { return true }; usleep(1_000) }
    return cond()
}

private func testStopDuringXrayStart() {
    // Control: the model is faithful - the blocking quit of a hev that never started does not return.
    do {
        let hev = ModelHev(native: .scoped)
        let returned = DispatchSemaphore(value: 0)
        DispatchQueue.global().async { hev.quitBlocking(); returned.signal() }
        expect(returned.wait(timeout: .now() + 0.6) == .timedOut, "control: the blocking quit of a hev never started returned")
    }
    // 1. The 24.11 case: the stop comes while the start waits for its network settings (no hev worker yet).
    do {
        let m = ProviderModel(hev: ModelHev(native: .scoped))
        let ms = m.stop()
        expect(ms != nil && (ms ?? 99_999) < 500, "the stop of a start still waiting for its settings took \(ms ?? -1) ms")
        expect(m.hevStop == .notRunning, "no hev to stop: \(String(describing: m.hevStop))")
        let snap = m.system.snapshot()
        expect(snap.starts == ["stopped_during_start"] && snap.order == ["start:stopped_during_start", "stop"],
               "one start answer, an error, before the stop's: \(snap)")
        m.queueHevWorker() // the settings call back after all: the stopped generation queues nothing
        expect(m.workers.wait(timeout: .now() + 2) == .success && m.hev.runs == 0 && m.renewers.current == nil,
               "a late settings callback started hev or attached a renewer")
    }
    // 2. (R43 F2) The worker is queued, the stop comes before it enters: it neither answers success nor runs.
    do {
        let m = ProviderModel(hev: ModelHev(native: .scoped))
        let release = DispatchSemaphore(value: 0)
        m.queueHevWorker(beforeEnter: { _ = release.wait(timeout: .now() + 2) })
        let ms = m.stop()
        release.signal()
        usleep(100_000)
        expect(m.hev.runs == 0, "a queued worker ran hev after the stop")
        expect(m.workers.wait(timeout: .now() + 2) == .success, "the queued worker ended")
        expect(ms != nil && (ms ?? 99_999) < 500 && m.hevStop == .notRunning, "stop with a queued worker: \(ms ?? -1) ms")
        expect(m.renewers.current == nil && m.system.snapshot().starts == ["stopped_during_start"], "no renewer, one error")
    }
    // 3. hev entered and is still initialising (300 ms): the request is kept for its run, the stop waits for that
    //    run's return - and returns as soon as it did.
    do {
        let hev = ModelHev(native: .scoped)
        hev.initMs = 300
        let m = ProviderModel(hev: hev)
        m.queueHevWorker()
        expect(waitUntil(2) { m.hevRunning() }, "the worker entered")
        let ms = m.stop()
        expect(ms != nil && (ms ?? 99_999) < 300 + 200, "the stop of an initialising hev took \(ms ?? -1) ms")
        if case .returned = m.hevStop {} else { expect(false, "the run must have returned: \(String(describing: m.hevStop))") }
        expect(!m.hevRunning() && hev.stoppedRuns == 1, "the run returned before the stop completed")
        expect(m.renewers.current == nil && m.system.snapshot().order.last == "stop", "renewer taken, stop answered last")
    }
    // 4. A running hev: the stop completes after its run returned.
    do {
        let m = ProviderModel(hev: ModelHev(native: .scoped))
        m.queueHevWorker()
        expect(waitUntil(2) { !m.system.snapshot().starts.isEmpty }, "the start answered")
        usleep(50_000)
        let ms = m.stop()
        expect(ms != nil && (ms ?? 99_999) < 100, "the stop of a running hev took \(ms ?? -1) ms")
        expect(m.hevStop == .returned(requests: 1) && !m.hevRunning(), "one request, the run returned: \(String(describing: m.hevStop))")
        expect(m.system.snapshot().starts == ["ok"], "the start that came up answered success once")
    }
    // 5. hev exited by itself earlier: a later stop requests nothing and waits for nothing.
    do {
        let m = ProviderModel(hev: ModelHev(native: .scoped))
        m.runMs = 30
        m.queueHevWorker()
        expect(m.workers.wait(timeout: .now() + 2) == .success, "hev ended on its own")
        let ms = m.stop()
        expect(ms != nil && m.hevStop == .notRunning, "a stop after hev exited: \(String(describing: m.hevStop))")
    }
}

// (R47 H1b) a failed in-place restart on a network change never ends as "Connected" without hev: it is tried once more
// after the earlier run returned, and a second failure ends the tunnel with its error.
private func testRoamRestartFailure() {
    // 1. the earlier run outlives its stop (a session kept alive past the stop) and returns at 1.0 s: the first start
    //    finds the run slot taken and fails, the retry after the earlier run returned connects
    do {
        let hev = ModelHev(native: .scoped)
        let m = ProviderModel(hev: hev)
        m.stopLimit = 0.3; m.enterWait = 0.3; m.idleWait = 2
        m.queueHevWorker()
        expect(waitUntil(2) { m.hevRunning() }, "A runs")
        usleep(30_000)
        hev.outlivesStopUntil = Date().addingTimeInterval(1.0)
        let done = DispatchSemaphore(value: 0)
        var result: Error?? = .none
        m.roam { result = .some($0); done.signal() }
        expect(done.wait(timeout: .now() + 5) == .success, "the restart ended")
        expect(result.map { $0 == nil } == true && m.coreStarts == 2, "the retry connects: \(String(describing: result)), starts \(m.coreStarts)")
        expect(!m.reasserting && m.hevRunning() && !m.clearedWithoutHev && m.cancels.isEmpty,
               "connected with hev running (reasserting \(m.reasserting), hev \(m.hevRunning()), cancels \(m.cancels))")
        _ = m.stop()
        _ = m.workers.wait(timeout: .now() + 3)
    }
    // 2. the earlier run never returns: both starts fail, the tunnel ends with the error - reasserting is never cleared
    do {
        let hev = ModelHev(native: .scoped)
        let m = ProviderModel(hev: hev)
        m.stopLimit = 0.2; m.enterWait = 0.2; m.idleWait = 0.3
        m.queueHevWorker()
        expect(waitUntil(2) { m.hevRunning() }, "A runs")
        usleep(30_000)
        hev.outlivesStopUntil = Date().addingTimeInterval(30)
        let done = DispatchSemaphore(value: 0)
        var failed = false
        m.roam { failed = $0 != nil; done.signal() }
        expect(done.wait(timeout: .now() + 5) == .success, "the restart ended")
        expect(failed && m.coreStarts == 2 && m.cancels.count == 1 && m.reasserting && !m.clearedWithoutHev,
               "two failures end the tunnel (cancels \(m.cancels), reasserting \(m.reasserting), cleared without hev \(m.clearedWithoutHev))")
        hev.outlivesStopUntil = nil
        _ = m.stop(bound: 5)
        _ = m.workers.wait(timeout: .now() + 3)
    }
    // 3. the ordinary roam: the earlier run returns at once, one start, connected
    do {
        let m = ProviderModel(hev: ModelHev(native: .scoped))
        m.queueHevWorker()
        expect(waitUntil(2) { m.hevRunning() }, "A runs")
        usleep(30_000)
        let done = DispatchSemaphore(value: 0)
        var ok = false
        let began = Date()
        m.roam { ok = $0 == nil; done.signal() }
        expect(done.wait(timeout: .now() + 3) == .success && ok && m.coreStarts == 1, "the ordinary roam connects")
        expect(Date().timeIntervalSince(began) < 0.3 && !m.reasserting && m.hevRunning() && m.hev.runs == 2,
               "one restart, hev running (\(Date().timeIntervalSince(began)) s)")
        _ = m.stop()
        _ = m.workers.wait(timeout: .now() + 3)
    }
    // 4. the session's stop comes during a failing restart: no retry, no tunnel error, reasserting untouched
    do {
        let hev = ModelHev(native: .scoped)
        let m = ProviderModel(hev: hev)
        m.stopLimit = 0.2; m.enterWait = 0.2; m.idleWait = 1
        m.queueHevWorker()
        expect(waitUntil(2) { m.hevRunning() }, "A runs")
        usleep(30_000)
        hev.outlivesStopUntil = Date().addingTimeInterval(0.6)
        let done = DispatchSemaphore(value: 0)
        m.roam { _ in done.signal() }
        usleep(100_000)
        _ = m.slot.stopBegan()
        expect(done.wait(timeout: .now() + 5) == .success, "the restart ended")
        expect(m.cancels.isEmpty && !m.clearedWithoutHev && m.reasserting,
               "a stopping session got no retry, no tunnel error, reasserting untouched (reasserting \(m.reasserting))")
        _ = m.workers.wait(timeout: .now() + 3)
    }
    // 5. (review R50 1) the seat ends during the restart (a terminal renewal answer between its stop and its start):
    //    the start is refused, nothing is retried and the tunnel is not cancelled, and `reasserting` is cleared - the
    //    tunnel is back in the state of an ordinary terminal answer (Connected, core stopped by the lease), where the
    //    app's status poll (Connected only) reads `upstream.state = terminal` and leaves the node (onUpstreamLeave).
    do {
        let m = ProviderModel(hev: ModelHev(native: .scoped))
        m.queueHevWorker()
        expect(waitUntil(2) { m.hevRunning() }, "A runs")
        usleep(30_000)
        m.duringRestartStop = { [m] in m.leaseStopped = true }
        let done = DispatchSemaphore(value: 0)
        var result: Error?? = .none
        m.roam { result = .some($0); done.signal() }
        expect(done.wait(timeout: .now() + 3) == .success, "the restart ended")
        let refused = result.flatMap { $0 }.map { ($0 as? FakeStartError) == .leaseTerminal } ?? false
        expect(refused && m.coreStarts == 1 && m.cancels.isEmpty,
               "the lease's refusal is final: no retry, no tunnel error (result \(String(describing: result)), starts \(m.coreStarts), cancels \(m.cancels))")
        expect(!m.reasserting,
               "a lease that ended during the restart must not leave the tunnel reasserting (the app never polls a reasserting tunnel)")
        expect(!m.hevRunning(), "no hev was started for a core the lease stopped")
        _ = m.stop()
        _ = m.workers.wait(timeout: .now() + 3)
    }
}

// (R46 R1a) the network-change restart inside one provider: the stop of hev-A, at once a new start of hev-B. B must
// never meet A's stop: the stop completes only after A returned, B enters only then, and the request was A's alone.
private func testRestartDoesNotInheritTheStop() {
    for native in [ModelHev.Native.scoped, .unsynchronized] {
        let m = ProviderModel(hev: ModelHev(native: native))
        m.queueHevWorker()
        expect(waitUntil(2) { m.hevRunning() && m.hev.runs == 1 }, "A runs")
        usleep(30_000)
        m.restart()
        expect(waitUntil(2) { m.hev.runs == 2 && m.hevRunning() }, "B entered after the restart (\(native))")
        usleep(200_000)
        expect(m.hevRunning() && m.hev.stoppedRuns == 1, "B was stopped by A's request (\(native)): runs \(m.hev.runs) stopped \(m.hev.stoppedRuns)")
        _ = m.stop()
        expect(m.workers.wait(timeout: .now() + 3) == .success, "B stopped at the end")
    }
}

// (R46 R1b) a stop that comes after A's native run returned but before the worker noted it: nothing may be left for
// the next run. Needs the scoped native protocol (patch 0002): with the global flag of 0001 the request survives.
private func testStopAfterReturnLeavesNothing() {
    let hev = ModelHev(native: .scoped)
    let m = ProviderModel(hev: hev)
    m.runMs = 100
    let returnedNatively = DispatchSemaphore(value: 0)
    let release = DispatchSemaphore(value: 0)
    m.queueHevWorker(afterReturn: { returnedNatively.signal(); _ = release.wait(timeout: .now() + 2) })
    expect(returnedNatively.wait(timeout: .now() + 2) == .success, "A returned natively")
    DispatchQueue.global().asyncAfter(deadline: .now() + 0.05) { release.signal() }
    m.nativeStop() // sees A still entered: requests for A's run and waits for its bookkeeping
    if case .returned = m.hevStop {} else { expect(false, "the stop after the native return: \(String(describing: m.hevStop))") }
    expect(!hev.requestLeft, "a request was left behind for the next run")
    m.generation = m.session.beginSession(protocolName: "xray", preservingCounters: true)
    m.runMs = 60_000
    m.queueHevWorker()
    expect(waitUntil(2) { hev.runs == 2 && m.hevRunning() }, "B entered")
    usleep(200_000)
    expect(m.hevRunning() && hev.stoppedRuns == 0, "B was stopped by a request made after A had returned")
    _ = m.stop()
    expect(m.workers.wait(timeout: .now() + 3) == .success, "B stopped at the end")
    // the same sequence on patch 0001 alone (the library before R46) leaves the request behind: why 0002 is needed
    let old = ModelHev(native: .unsynchronized)
    let o = ProviderModel(hev: old)
    o.runMs = 100
    let back = DispatchSemaphore(value: 0)
    let go = DispatchSemaphore(value: 0)
    o.queueHevWorker(afterReturn: { back.signal(); _ = go.wait(timeout: .now() + 2) })
    expect(back.wait(timeout: .now() + 2) == .success, "0001: A returned natively")
    DispatchQueue.global().asyncAfter(deadline: .now() + 0.05) { go.signal() }
    o.nativeStop()
    expect(old.requestLeft, "0001 characterisation: a request made after the run returned is kept for the next run")
}

// (R46 R2) the handshake of one request with a starting run, in both orders, and the lost one of 0001 (store
// buffering). One request on the scoped protocol is never lost; on 0001 it can be - and the stop's re-drive still
// ends the run.
private func testHandshakeOrders() {
    // order 1: the request before the run publishes (kept, taken as it runs); order 2: after (the event)
    for (name, delayMs) in [("request first", 0), ("run first", 60)] {
        let hev = ModelHev(native: .scoped)
        hev.initMs = 30
        let runner = DispatchSemaphore(value: 0)
        DispatchQueue.global().async { hev.main(runMs: 2_000); runner.signal() }
        usleep(useconds_t((5 + delayMs) * 1000))
        let rc = hev.tryQuit()
        expect(rc == 0 || rc == -EAGAIN, "\(name): one request (rc \(rc)) is taken or queued")
        expect(runner.wait(timeout: .now() + 1) == .success && hev.stoppedRuns == 1, "\(name): one request stops the run")
    }
    // 0001, the store-buffering order: one request is lost (characterises the native defect) ...
    do {
        let hev = ModelHev(native: .unsynchronized)
        hev.storeBuffering = true
        let runner = DispatchSemaphore(value: 0)
        DispatchQueue.global().async { hev.main(runMs: 1_500); runner.signal() }
        usleep(60_000)
        let rc = hev.tryQuit()
        expect(rc == -EAGAIN && runner.wait(timeout: .now() + 0.5) == .timedOut, "0001 store buffering: the one request was not lost (rc \(rc))")
        _ = runner.wait(timeout: .now() + 2)
    }
    // ... and the stop drives the request again until the run returned: the run ends all the same.
    do {
        let hev = ModelHev(native: .unsynchronized)
        hev.storeBuffering = true
        let m = ProviderModel(hev: hev)
        m.queueHevWorker()
        expect(waitUntil(2) { m.hevRunning() }, "the run entered")
        usleep(60_000)
        let ms = m.stop()
        expect(ms != nil && (ms ?? 99_999) < 500 && !m.hevRunning(), "a lost request ended the stop without the run's return (\(ms ?? -1) ms)")
        if case .returned(let n) = m.hevStop { expect(n >= 2, "the request was driven again (\(n))") } else { expect(false, "\(String(describing: m.hevStop))") }
    }
}

// (R46 R1) a run that never returns: the stop ends at its hard limit (loudly), and no new run enters beside it.
private func testHevThatNeverReturns() {
    final class StuckHev: XrayHevControl { func tryQuit() -> Int32 { 0 }; func quitBlocking() {} }
    let runs = XrayHevRuns()
    guard let a = runs.enter(waitSeconds: 0.1) else { expect(false, "slot"); return }
    let began = Date()
    let result = XrayHevStop.execute(run: a, runs: runs, hev: StuckHev(), limitSeconds: 0.3)
    let ms = Date().timeIntervalSince(began) * 1000
    if case .exitTimedOut = result {} else { expect(false, "a run that never returns: \(result)") }
    expect(ms >= 290 && ms < 600, "the stop ends at its limit (\(ms) ms)")
    expect(runs.enter(waitSeconds: 0.2) == nil, "a new run entered beside a run that never returned")
    runs.exit(a)
    expect(runs.enter(waitSeconds: 0.2) != nil, "a new run enters once the old one returned")
}

// (R43 F3, R46 R3) the decision of what the start delivers is made at its call: a delivery that took its answer,
// was preempted for longer than the stop's bounds and calls after the stop began delivers the error, never success.
private func testSuccessAfterStopBegan() {
    let system = SystemCompletions()
    let slot = TunnelStartSlot()
    let startAnswer = slot.begin { system.start($0) }
    expect(slot.stopBegan(), "the start is still unanswered when the stop begins")
    startAnswer(nil)
    _ = slot.abortForStop()
    system.stop()
    expect(system.snapshot().order == ["start:stopped_during_start", "stop"], "\(system.snapshot().order)")
    // R3: the start thread takes its answer, is preempted 1.5 s (past the 1 s bound); the stop begins meanwhile
    do {
        let sys = SystemCompletions()
        let s = TunnelStartSlot()
        let taken = DispatchSemaphore(value: 0)
        s.testHookBeforeDecision = { taken.signal(); Thread.sleep(forTimeInterval: 1.5) }
        let answer = s.begin { sys.start($0) }
        let startDone = DispatchSemaphore(value: 0)
        DispatchQueue.global().async { answer(nil); startDone.signal() }
        expect(taken.wait(timeout: .now() + 2) == .success, "the start took its answer")
        _ = s.stopBegan()
        _ = s.abortForStop()
        sys.stop()
        expect(startDone.wait(timeout: .now() + 3) == .success, "the start delivered")
        let snap = sys.snapshot()
        expect(snap.starts == ["stopped_during_start"], "a success was delivered after the stop began: \(snap.order)")
    }
    // many threads race the start's answer and the stop: exactly one answer, always before the stop's
    for round in 0..<200 {
        let sys = SystemCompletions()
        let s = TunnelStartSlot()
        let answer = s.begin { sys.start($0) }
        let group = DispatchGroup()
        for i in 0..<6 {
            DispatchQueue.global().async(group: group) {
                if i % 2 == 0 { answer(i == 0 ? nil : FakeStartError.superseded) } else { _ = s.stopBegan(); _ = s.abortForStop(); sys.stop() }
            }
        }
        expect(group.wait(timeout: .now() + 2) == .success, "round \(round) finished")
        let snap = sys.snapshot()
        expect(snap.starts.count == 1 && snap.order.first?.hasPrefix("start:") == true,
               "round \(round): one start answer, first: \(snap.order)")
    }
}

// (R43 F2) The renewer slot: a stop takes and closes, an attach after it is refused, a new session opens it again.
private func testStopClosableSlot() {
    let slot = StopClosableSlot<FakeRenewer>()
    let first = FakeRenewer()
    expect(slot.attach(first) && slot.current === first, "attach while the session runs")
    expect(slot.take() === first && slot.current == nil, "the stop takes it")
    expect(!slot.attach(FakeRenewer()) && slot.current == nil, "nothing attaches after the stop")
    slot.reopen()
    expect(slot.attach(FakeRenewer()), "a new session attaches again")
}

@main
private struct XraySocketCallbackLifecycleTests {
    static func main() throws {
        testStopDuringXrayStart()
        testRestartDoesNotInheritTheStop()
        testRoamRestartFailure()
        testStopAfterReturnLeavesNothing()
        testHandshakeOrders()
        testHevThatNeverReturns()
        testSuccessAfterStopBegan()
        testStopClosableSlot()
        testTrafficAccumulator()
        testRuntimeSession()
        testIPv4RouteSpec()
        testIPv6RouteSpec()

        expect(XrayNativeCStringResult.consume(nil), "nil callback result is success")
        expect(XrayNativeCStringResult.consume(strdup("")),
               "allocated empty Run/Stop result is success")
        expect(!XrayNativeCStringResult.consume(strdup("native failure")),
               "non-empty native result is failure")
        expect(XraySocketCallbackIdentity(generation: 0, sessionId: uuid(1)) == nil,
               "generation 0 is not a callback identity")
        // uuid(1) состоит из цифр — uppercased() его не меняет; берём значение с hex-буквами.
        let mixedCaseUuid = uuid(0xabc)
        expect(mixedCaseUuid.uppercased() != mixedCaseUuid, "test fixture actually changes case")
        expect(XraySocketCallbackIdentity(generation: 1, sessionId: mixedCaseUuid.uppercased()) == nil,
               "uppercase uuid is not a callback identity")
        expect(XraySocketCallbackIdentity(generation: 1, sessionId: mixedCaseUuid) != nil,
               "lowercase uuid is a callback identity")
        expect(XraySocketCallbackIdentity(generation: 1, sessionId: "not-a-uuid") == nil,
               "non-uuid session id is not a callback identity")

        let registry = XraySocketCallbackRegistry<Token>()
        for generation in UInt64(1)...128 {
            let identity = XraySocketCallbackIdentity(
                generation: generation, sessionId: uuid(generation))!
            let token = Token()
            expect(registry.install(token, identity: identity),
                   "sequential callback context \(generation) installs")
            expect(registry.count == 1, "only one native callback slot is live")
            expect(registry.remove(identity: identity) === token,
                   "exact generation/session removal succeeds")
            expect(registry.count == 0, "context \(generation) is released")
        }

        let old = XraySocketCallbackIdentity(generation: 200, sessionId: uuid(200))!
        let current = XraySocketCallbackIdentity(generation: 201, sessionId: uuid(201))!
        let token = Token()
        expect(registry.install(token, identity: current), "current context installs")
        expect(!registry.install(Token(), identity: old), "slot busy: second install is refused")
        expect(registry.remove(identity: old) == nil, "stale teardown cannot remove current context")
        expect(registry.value(for: current) === token, "current context survives stale removal")

        var teardownTrace: [String] = []
        expect(XraySocketCallbackTeardown.execute(
            stopCore: { teardownTrace.append("stop"); return true },
            drain: { teardownTrace.append("drain"); return true },
            retireContext: {
                teardownTrace.append("retire")
                return registry.remove(identity: current) === token
            }), "successful teardown returns exact native/context receipt")
        expect(teardownTrace == ["stop", "drain", "retire"],
               "core stops while protection is armed, then callback drains before removal")
        expect(registry.count == 0, "successful core cleanup leaves no context")

        let failedToken = Token()
        expect(registry.install(failedToken, identity: current),
               "failure-injection context installs")
        teardownTrace.removeAll()
        expect(!XraySocketCallbackTeardown.execute(
            stopCore: { teardownTrace.append("stop"); return true },
            drain: { teardownTrace.append("drain"); return false },
            retireContext: {
                teardownTrace.append("retire")
                return registry.remove(identity: current) != nil
            }), "failed native drain is fail closed")
        expect(teardownTrace == ["stop", "drain"],
               "core remains protected until stop; drain failure retains raw context")
        expect(registry.count == 1,
               "context remains retained when native drain receipt is absent")
        _ = registry.remove(identity: current)

        let stopFailureToken = Token()
        expect(registry.install(stopFailureToken, identity: current),
               "stop-failure context installs")
        teardownTrace.removeAll()
        expect(!XraySocketCallbackTeardown.execute(
            stopCore: { teardownTrace.append("stop"); return false },
            drain: { teardownTrace.append("drain"); return true },
            retireContext: {
                teardownTrace.append("retire")
                return registry.remove(identity: current) != nil
            }), "ambiguous core stop is fail closed")
        expect(teardownTrace == ["stop"],
               "failed core close cannot clear the still-required protect callback")
        expect(registry.value(for: current) === stopFailureToken,
               "failed core close retains exact callback context for recovery")
        _ = registry.remove(identity: current)

        let concurrentToken = Token()
        expect(registry.install(concurrentToken, identity: current),
               "concurrent teardown token installs")
        let harness = ConcurrentTeardownHarness(
            registry: registry, identity: current, token: concurrentToken)
        let group = DispatchGroup()
        for _ in 0..<2 {
            group.enter()
            DispatchQueue.global().async {
                harness.runAndRecord()
                group.leave()
            }
        }
        expect(harness.started.wait(timeout: .now() + 2) == .success,
               "first teardown reached synchronous stop")
        harness.allowStopReturn.signal()
        expect(group.wait(timeout: .now() + 2) == .success,
               "concurrent teardowns completed")
        let teardownSnapshot = harness.snapshot()
        expect(teardownSnapshot.results.allSatisfy { $0 }
               && teardownSnapshot.stopCount == 1 && teardownSnapshot.retireCount == 1,
               "concurrent exact teardown stops/retires once and second call is idempotent")

        // Детерминированные барьеры позднего старта: стоп, инвалидировавший поколение до захвата
        // нативного gate'а, не даёт стартовать; если старт первым взял gate — стоп идёт строго после.
        let nativeGate = XrayNativeLifecycleGate()
        let lifecycleLock = NSLock()
        var currentGeneration = true
        var tunStartCount = 0
        nativeGate.withExclusive {
            lifecycleLock.lock(); currentGeneration = false; lifecycleLock.unlock()
        }
        nativeGate.withExclusive {
            lifecycleLock.lock(); let current = currentGeneration; lifecycleLock.unlock()
            if current { tunStartCount += 1 }
        }
        expect(tunStartCount == 0, "stop between readiness and tun start prevents late adapter")

        currentGeneration = true
        var coreRunCount = 0
        var coreStopCount = 0
        let installed = DispatchSemaphore(value: 0)
        let allowRun = DispatchSemaphore(value: 0)
        group.enter()
        DispatchQueue.global().async {
            nativeGate.withExclusive {
                installed.signal()
                _ = allowRun.wait(timeout: .now() + 2)
                lifecycleLock.lock(); let current = currentGeneration; lifecycleLock.unlock()
                if current { coreRunCount += 1 }
            }
            group.leave()
        }
        expect(installed.wait(timeout: .now() + 2) == .success,
               "callback install barrier reached")
        group.enter()
        DispatchQueue.global().async {
            nativeGate.withExclusive {
                lifecycleLock.lock(); currentGeneration = false; lifecycleLock.unlock()
                coreStopCount += 1
            }
            group.leave()
        }
        allowRun.signal()
        expect(group.wait(timeout: .now() + 2) == .success, "serialized start/stop completed")
        expect(coreRunCount == 1 && coreStopCount == 1,
               "start that owns gate completes before exactly one stop; no post-stop core start")

        let fence = XraySocketCallbackFence(identity: current)
        expect(fence.accepts(currentGeneration: current.generation,
                             currentSessionId: current.sessionId), "exact callback accepted")
        expect(!fence.accepts(currentGeneration: current.generation + 1,
                              currentSessionId: uuid(202)),
               "late callback after generation/session swap is fenced")
        expect(!fence.deactivate(expected: old), "fence ignores deactivation with a foreign identity")
        expect(fence.deactivate(expected: current), "exact fence deactivation")
        expect(!fence.accepts(currentGeneration: current.generation,
                              currentSessionId: current.sessionId),
               "deactivated callback stays fenced")
        _ = registry.remove(identity: current)

        // AVPN (девайс-разбор 2026-09-02): счётчики protect считают из многих потоков ядра —
        // терять инкременты нельзя, иначе «Подключено без трафика» снова станет безымянным.
        let counters = XrayProtectCounters()
        let counterGroup = DispatchGroup()
        for i in 0..<300 {
            DispatchQueue.global().async(group: counterGroup) {
                switch i % 3 {
                case 0: counters.countBound()
                case 1: counters.countUnbound()
                default: counters.countRejected()
                }
            }
        }
        expect(counterGroup.wait(timeout: .now() + 5) == .success, "protect counters finished")
        let snapshot = counters.snapshot()
        expect(snapshot == XrayProtectCounters.Snapshot(bound: 100, unbound: 100, rejected: 100),
               "protect counters lose nothing under concurrency: \(snapshot)")
        counters.reset()
        expect(counters.snapshot() == XrayProtectCounters.Snapshot(bound: 0, unbound: 0, rejected: 0),
               "reset clears the session counters")

        print("Apple Xray runtime status + callback lifecycle tests passed (128 sessions)")
    }
}
