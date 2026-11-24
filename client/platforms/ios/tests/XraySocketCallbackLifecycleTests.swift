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

// AVPN (device round air-B 24.11; review R43 F1-F3): the stop of an Xray session that is still starting, through the
// real decisions (TunnelRuntimeSession's generation + hev phase, XrayHevStop, TunnelStartSlot, StopClosableSlot) and
// the provider's order (stopTunnel: stopBegan at entry; stopXray: under the native gate the generation move, then the
// hev decision; then abortForStop right before the stop's own answer; the hev worker: enterHev before it answers or
// runs). hev itself is a faithful double of hev 2.15.0 + recipe patch 0001: its blocking quit loops until run() has
// created the event fd (100 ms sleeps); try_quit sets stop_requested, answers -EAGAIN until hev runs, and a hev that
// reaches run with stop_requested set quits at once.
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

private enum FakeStartError: Error { case superseded }

private final class FakeHev: XrayHevControl, @unchecked Sendable {
    private let lock = NSLock()
    private var running = false
    private var eventFd = false      // hev's event_fds[1] >= 0
    private var stopRequested = false
    private var quitEvent = false
    private(set) var mains = 0
    private(set) var exited = 0
    let initMs: Int
    init(initMs: Int) { self.initMs = initMs }

    // Socks5Tunnel.run: init creates the event fd after initMs, then run (= 1; stop_requested -> try_quit), the
    // event loop until the quit event, then fini.
    func main() {
        lock.lock(); mains += 1; lock.unlock()
        Thread.sleep(forTimeInterval: Double(initMs) / 1000)
        lock.lock(); eventFd = true; running = true; let requested = stopRequested; lock.unlock()
        if requested { _ = tryQuit() }
        while true {
            lock.lock(); let q = quitEvent; lock.unlock()
            if q { break }
            usleep(5_000)
        }
        lock.lock(); running = false; eventFd = false; stopRequested = false; quitEvent = false; exited += 1; lock.unlock()
    }

    // hev_socks5_tunnel_stop: `for (;;) { if fd >= 0 break; usleep(100 ms) }` then the event.
    func quitBlocking() {
        while true {
            lock.lock()
            if eventFd { quitEvent = true; lock.unlock(); return }
            lock.unlock()
            usleep(100_000)
        }
    }

    // hev_socks5_tunnel_try_quit (patch 0001).
    func tryQuit() -> Int32 {
        lock.lock(); defer { lock.unlock() }
        stopRequested = true
        guard running, eventFd else { return -EAGAIN }
        quitEvent = true
        return 0
    }

    var state: (mains: Int, exited: Int) { lock.lock(); defer { lock.unlock() }; return (mains, exited) }
}

private final class FakeRenewer {}

// One Xray session of the provider, modelled on its real order (PacketTunnelProvider.swift / +Xray.swift / +Upstream).
private final class ProviderModel: @unchecked Sendable {
    let system = SystemCompletions()
    let slot = TunnelStartSlot()
    let gate = XrayNativeLifecycleGate()
    let session = TunnelRuntimeSession()
    let renewers = StopClosableSlot<FakeRenewer>()
    let hev: FakeHev
    let workers = DispatchGroup()
    var startAnswer: (Error?) -> Void = { _ in }
    var generation: UInt64 = 0
    var hevStop: XrayHevStop?

    init(hev: FakeHev) {
        self.hev = hev
        startAnswer = slot.begin { [system] in system.start($0) } // startTunnel
        renewers.reopen()                                          // beginUpstreamMeter
        generation = session.beginSession(protocolName: "xray")    // startXray
    }

    // setupAndRunTun2socks: under the gate the worker is queued; the worker enters (or finds the stop), answers the
    // start, attaches the renewer, runs hev.
    func queueHevWorker(beforeEnter: (() -> Void)? = nil) {
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
            guard session.enterHev(generation: gen) else {
                startAnswer(FakeStartError.superseded)
                return
            }
            if renewers.attach(FakeRenewer()) {} // attachUpstreamRenewer (refused after the stop took the slot)
            startAnswer(nil)
            hev.main()
            session.exitHev(generation: gen)
        }
    }

    // stopTunnel -> stopXrayThenReleaseUpstream -> stopXray, then the completion wrapper. Returns how long it took (ms)
    // or nil when it did not return within `bound`.
    func stop(bound: TimeInterval = 2) -> Double? {
        let done = DispatchSemaphore(value: 0)
        let began = DispatchTime.now()
        DispatchQueue.global().async { [self] in
            _ = slot.stopBegan()
            _ = renewers.take()
            gate.withExclusive {
                let stopping = session.beginStopReportingHev()
                hevStop = XrayHevStop.execute(hevRunning: stopping.hevRunning, hev: hev)
            }
            _ = slot.abortForStop()
            system.stop()
            done.signal()
        }
        guard done.wait(timeout: .now() + bound) == .success else { return nil }
        return Double(DispatchTime.now().uptimeNanoseconds - began.uptimeNanoseconds) / 1_000_000
    }
}

private func testStopDuringXrayStart() {
    // Control: the double is faithful - the blocking quit of a hev that never started does not return (this is what
    // stopXray did on 24.11, inside the native gate).
    do {
        let hev = FakeHev(initMs: 0)
        let returned = DispatchSemaphore(value: 0)
        DispatchQueue.global().async { hev.quitBlocking(); returned.signal() }
        expect(returned.wait(timeout: .now() + 0.6) == .timedOut, "control: the blocking quit of a hev never started returned")
    }
    // 1. The 24.11 case: the stop comes while the start waits for its network settings (no hev worker yet); the
    //    settings never call back. The stop returns at once, the start gets exactly one answer (an error) before the
    //    stop's, no hev runs, no renewer attaches.
    do {
        let m = ProviderModel(hev: FakeHev(initMs: 50))
        let ms = m.stop()
        expect(ms != nil, "the stop of a start still waiting for its settings did not return within 2 s")
        expect((ms ?? 99_999) < 500, "the stop took \(ms ?? -1) ms")
        expect(m.hevStop == .notRunning, "no hev to stop: \(String(describing: m.hevStop))")
        let snap = m.system.snapshot()
        expect(snap.starts == ["stopped_during_start"] && snap.order == ["start:stopped_during_start", "stop"],
               "one start answer, an error, before the stop's: \(snap)")
        m.queueHevWorker() // the settings call back after all: the stopped generation queues nothing
        expect(m.workers.wait(timeout: .now() + 2) == .success, "no worker left")
        expect(m.hev.state.mains == 0 && m.renewers.current == nil && m.system.snapshot().starts.count == 1,
               "a late settings callback started hev, attached a renewer or answered again")
    }
    // 2. (F2) The hev worker is queued, the stop comes before it runs: the worker finds the stop - it neither answers
    //    success nor attaches nor runs hev.
    do {
        let m = ProviderModel(hev: FakeHev(initMs: 50))
        let release = DispatchSemaphore(value: 0)
        m.queueHevWorker(beforeEnter: { _ = release.wait(timeout: .now() + 2) })
        let ms = m.stop()
        release.signal()
        usleep(100_000) // the worker runs now
        expect(m.hev.state.mains == 0, "a queued worker ran hev after the stop")
        expect(m.workers.wait(timeout: .now() + 2) == .success, "the queued worker ended")
        expect(ms != nil && (ms ?? 99_999) < 500 && m.hevStop == .notRunning, "stop with a queued worker: \(ms ?? -1) ms")
        expect(m.renewers.current == nil, "a queued worker attached a renewer after the stop")
        expect(m.system.snapshot().starts == ["stopped_during_start"], "start answers: \(m.system.snapshot().starts)")
    }
    // 3. hev has entered and is still initialising (400 ms) when the stop comes: the non-blocking quit is deferred,
    //    the stop returns at once, hev quits as soon as it runs.
    do {
        let m = ProviderModel(hev: FakeHev(initMs: 400))
        let entered = DispatchSemaphore(value: 0)
        m.queueHevWorker()
        DispatchQueue.global().async { while m.session.hevPhaseNow != .running { usleep(1_000) }; entered.signal() }
        expect(entered.wait(timeout: .now() + 2) == .success, "the worker entered")
        let ms = m.stop()
        expect(ms != nil && (ms ?? 99_999) < 300, "the stop of an initialising hev waited \(ms ?? -1) ms")
        expect(m.hevStop == .quitDeferred(-EAGAIN), "the quit is deferred while hev initialises: \(String(describing: m.hevStop))")
        expect(m.workers.wait(timeout: .now() + 2) == .success && m.hev.state.exited == 1, "hev quit once it ran")
        expect(m.session.hevPhaseNow == .none, "no hev left after its exit")
        let snap = m.system.snapshot()
        expect(snap.starts.count == 1 && snap.order.last == "stop", "one start answer before the stop's: \(snap)")
        // the renewer this start attached before the stop was taken by the stop - nothing outlives it
        expect(m.renewers.current == nil, "a renewer outlived the stop")
    }
    // 4. hev runs: the quit is queued at once and hev exits.
    do {
        let m = ProviderModel(hev: FakeHev(initMs: 10))
        m.queueHevWorker()
        while m.system.snapshot().starts.isEmpty { usleep(1_000) }
        usleep(50_000)
        let ms = m.stop()
        expect(ms != nil && m.hevStop == .quitQueued, "the stop of a running hev: \(String(describing: m.hevStop))")
        expect(m.workers.wait(timeout: .now() + 2) == .success && m.hev.state.exited == 1, "a running hev quit")
        expect(m.system.snapshot().starts == ["ok"], "the start that came up answered success once")
    }
    // 5. hev exited by itself earlier: a later stop does not quit (the blocking quit would wait for ever: fds closed).
    do {
        let m = ProviderModel(hev: FakeHev(initMs: 10))
        m.queueHevWorker()
        while m.session.hevPhaseNow != .running { usleep(1_000) }
        usleep(30_000)
        _ = m.hev.tryQuit() // hev ends on its own (tun2socks exit)
        expect(m.workers.wait(timeout: .now() + 2) == .success, "hev ended on its own")
        let ms = m.stop()
        expect(ms != nil && m.hevStop == .notRunning, "a stop after hev exited: \(String(describing: m.hevStop))")
    }
}

// (F3) After the stop began, a start that would report success reports an error.
private func testSuccessAfterStopBegan() {
    let system = SystemCompletions()
    let slot = TunnelStartSlot()
    let startAnswer = slot.begin { system.start($0) }
    expect(slot.stopBegan(), "the start is still unanswered when the stop begins")
    startAnswer(nil)
    _ = slot.abortForStop()
    system.stop()
    expect(system.snapshot().order == ["start:stopped_during_start", "stop"], "\(system.snapshot().order)")
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

// (F2) The renewer slot: a stop takes and closes, an attach after it is refused, a new session opens it again.
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
