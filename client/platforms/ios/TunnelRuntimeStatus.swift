import Foundation

// AVPN (волна AWG 3.1 + Xray, этап D3): протокол-нейтральный runtime-статус NE для IPC
// приложение <-> Network Extension. Изолированный файл (Foundation-only): аккумулятор и
// сессия покрыты хостовым Swift-тестом (tests/run_ios_swift_checks.sh) без устройства.
//
// Контракт счётчиков — CONNECT-INVARIANTS §17.1: rx/tx КУМУЛЯТИВНЫЕ с подъёма туннеля,
// 0 = «неизвестно». Нативный движок (hev-socks5-tunnel) сбрасывает свои process-local
// счётчики при каждом старте — ResetSafeTrafficAccumulator превращает их в монотонный
// кумулятив текущей NE-сессии.
enum TunnelRuntimeState: String {
    case starting
    case running
    case stopping
    case stopped
    case reconnecting
    case failed
    case unknown
}

struct TunnelTrafficSample: Equatable {
    var rxBytes: UInt64 = 0
    var txBytes: UInt64 = 0
    var rxPackets: UInt64 = 0
    var txPackets: UInt64 = 0

    static let zero = TunnelTrafficSample()
}

struct TunnelTrafficDelta: Equatable {
    let sample: TunnelTrafficSample
    let resetDetected: Bool
}

// Нативному движку разрешено обнулять свои счётчики при рестарте/ребайнде: сырое значение
// «назад» перебазирует компонент и даёт нулевую дельту; UInt64 никогда не переполняется, уже
// накопленный трафик сессии не теряется.
struct ResetSafeTrafficAccumulator {
    private(set) var cumulative = TunnelTrafficSample.zero
    private(set) var previousRaw = TunnelTrafficSample.zero
    private(set) var resetCount: UInt64 = 0

    mutating func reset() {
        cumulative = .zero
        previousRaw = .zero
        resetCount = 0
    }

    // Перебазировать «предыдущее сырое» без учёта дельты: используется на старте сессии,
    // чтобы стейл-счётчики предыдущего запуска движка в том же процессе NE не засчитались
    // как трафик новой сессии.
    mutating func rebase(_ raw: TunnelTrafficSample) {
        previousRaw = raw
    }

    mutating func record(_ raw: TunnelTrafficSample) -> TunnelTrafficDelta {
        let rxBytes = Self.delta(raw.rxBytes, previousRaw.rxBytes)
        let txBytes = Self.delta(raw.txBytes, previousRaw.txBytes)
        let rxPackets = Self.delta(raw.rxPackets, previousRaw.rxPackets)
        let txPackets = Self.delta(raw.txPackets, previousRaw.txPackets)
        let resetDetected = rxBytes.reset || txBytes.reset || rxPackets.reset || txPackets.reset

        if resetDetected {
            resetCount = Self.saturatingAdd(resetCount, 1)
        }

        let delta = TunnelTrafficSample(
            rxBytes: rxBytes.value,
            txBytes: txBytes.value,
            rxPackets: rxPackets.value,
            txPackets: txPackets.value
        )
        cumulative = TunnelTrafficSample(
            rxBytes: Self.saturatingAdd(cumulative.rxBytes, delta.rxBytes),
            txBytes: Self.saturatingAdd(cumulative.txBytes, delta.txBytes),
            rxPackets: Self.saturatingAdd(cumulative.rxPackets, delta.rxPackets),
            txPackets: Self.saturatingAdd(cumulative.txPackets, delta.txPackets)
        )
        previousRaw = raw
        return TunnelTrafficDelta(sample: delta, resetDetected: resetDetected)
    }

    // Сырое значение «назад» = движок обнулил свои счётчики (hev_socks5_tunnel init зануляет
    // stat_* на каждом старте). Значит ВЕСЬ текущий отсчёт — трафик после рестарта: он и есть
    // дельта. Отдать здесь 0 значило бы терять всё, что прошло между стартом движка и первым
    // опросом статуса (до тика таймера checkStatus) — это нарушило бы §17.1 (rx/tx —
    // кумулятив с подъёма туннеля).
    private static func delta(_ current: UInt64, _ previous: UInt64) -> (value: UInt64, reset: Bool) {
        guard current >= previous else { return (current, true) }
        return (current - previous, false)
    }

    private static func saturatingAdd(_ lhs: UInt64, _ rhs: UInt64) -> UInt64 {
        let result = lhs.addingReportingOverflow(rhs)
        return result.overflow ? UInt64.max : result.partialValue
    }
}

struct TunnelRuntimeSnapshot {
    let generation: UInt64
    let sessionId: String
    let protocolName: String
    let state: TunnelRuntimeState
    let counters: TunnelTrafficSample
    let latestDelta: TunnelTrafficSample
    let counterResetCount: UInt64
    let countersAvailable: Bool
}

// Один лок защищает поколение жизненного цикла и счётчики. Асинхронные колбэки старта несут
// поколение, выданное beginSession(); колбэки остановленной или вытесненной сессии игнорируются.
final class TunnelRuntimeSession {
    static let payloadType = "tunnel_runtime_status_v1"
    static let payloadSchema = 1

    private let lock = NSLock()
    private var generation: UInt64 = 0
    private var sessionId = ""
    private var protocolName = "unknown"
    private var state: TunnelRuntimeState = .stopped
    private var accumulator = ResetSafeTrafficAccumulator()
    private var latestDelta = TunnelTrafficSample.zero
    private var countersAvailable = false

    // preservingCounters = true — рестарт движка внутри той же NE-сессии (смена сети):
    // поколение и id сессии обновляются, кумулятив трафика сохраняется (сброс сырых
    // счётчиков движка аккумулятор переживёт сам).
    @discardableResult
    func beginSession(protocolName: String, sessionId expectedSessionId: String? = nil,
                      preservingCounters: Bool = false) -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        generation = nextGeneration(generation)
        if let expectedSessionId,
           expectedSessionId == expectedSessionId.lowercased(),
           let uuid = UUID(uuidString: expectedSessionId),
           uuid.uuidString.lowercased() == expectedSessionId {
            sessionId = expectedSessionId
        } else {
            sessionId = UUID().uuidString.lowercased()
        }
        self.protocolName = protocolName
        state = .starting
        if !preservingCounters {
            accumulator.reset()
        }
        latestDelta = .zero
        countersAvailable = false
        return generation
    }

    // Инвалидирует все висящие колбэки старта/рестарта, сохраняя id сессии, чтобы наблюдатель
    // видел starting -> stopping -> stopped в одной эпохе статуса.
    @discardableResult
    func beginStop() -> UInt64 {
        beginStopReportingHev().generation
    }

    // AVPN (review R43 F1/F2): hev (tun2socks) of the Xray path, under the same lock as the generation, so a stop and
    // the hev worker decide in one order. hev is process-global and its blocking quit (hev 2.15.0
    // hev_socks5_tunnel_stop) waits, without a bound, for an event fd that only a running hev creates - so the stop
    // must know whether hev runs. queued: the worker is on its queue; running: the worker entered (Socks5Tunnel.run
    // is called or about to be); none: no worker, or it returned.
    enum HevPhase { case none, queued, running }
    private var hevPhase: HevPhase = .none
    private var hevGeneration: UInt64 = 0
    private var hevRun: UInt64 = 0 // the process-wide epoch of the entered run (XrayHevRuns), 0 = none

    /// Under the native gate, when the hev worker is handed to its queue: only for the current generation.
    func queueHev(generation expectedGeneration: UInt64) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard generation == expectedGeneration else { return false }
        hevPhase = .queued
        hevGeneration = expectedGeneration
        return true
    }

    /// In the worker, once it holds the process's run slot (`run`, XrayHevRuns.enter) and before it answers the start
    /// or runs hev: false = a stop came after the queueing - nothing of that generation may answer success or run
    /// (the worker then gives the run slot back).
    func enterHev(generation expectedGeneration: UInt64, run: UInt64) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard generation == expectedGeneration, hevGeneration == expectedGeneration, hevPhase == .queued else {
            return false
        }
        hevPhase = .running
        hevRun = run
        return true
    }

    /// In the worker, when Socks5Tunnel.run returned (or when it never got a run slot).
    func exitHev(generation expectedGeneration: UInt64) {
        lock.lock()
        defer { lock.unlock() }
        if hevGeneration == expectedGeneration {
            hevPhase = .none
            hevRun = 0
        }
    }

    /// The stop's generation move, and the run epoch of the hev worker that had entered at that moment (0 = none: a
    /// worker still queued finds the new generation in enterHev and never runs - nothing to stop, nothing to wait for).
    func beginStopReportingHev() -> (generation: UInt64, hevRun: UInt64) {
        lock.lock()
        defer { lock.unlock() }
        generation = nextGeneration(generation)
        state = .stopping
        let run = hevPhase == .running ? hevRun : 0
        if hevPhase == .queued { hevPhase = .none }
        return (generation, run)
    }

    var hevPhaseNow: HevPhase {
        lock.lock()
        defer { lock.unlock() }
        return hevPhase
    }

    @discardableResult
    func transition(to newState: TunnelRuntimeState, generation expectedGeneration: UInt64) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard generation == expectedGeneration else { return false }
        state = newState
        return true
    }

    // Терминальный провал текущего поколения. true — только при ПЕРВОМ переводе в failed
    // (повторные провалы той же сессии и стейл-поколения дают false) — вызывающий по этому
    // признаку гасит туннель ровно один раз.
    @discardableResult
    func fail(generation expectedGeneration: UInt64) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard generation == expectedGeneration, state != .failed else { return false }
        state = .failed
        return true
    }

    func isCurrent(generation expectedGeneration: UInt64) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return generation == expectedGeneration
    }

    // Перебазировать аккумулятор на текущие сырые счётчики движка (до старта — стейл прошлого
    // запуска в том же процессе не должен стать «трафиком» новой сессии).
    @discardableResult
    func rebase(_ raw: TunnelTrafficSample, generation expectedGeneration: UInt64) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard generation == expectedGeneration else { return false }
        accumulator.rebase(raw)
        return true
    }

    @discardableResult
    func record(_ raw: TunnelTrafficSample, generation expectedGeneration: UInt64) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard generation == expectedGeneration, state == .running else { return false }
        let delta = accumulator.record(raw)
        latestDelta = delta.sample
        countersAvailable = true
        return true
    }

    func snapshot() -> TunnelRuntimeSnapshot {
        lock.lock()
        defer { lock.unlock() }
        return TunnelRuntimeSnapshot(
            generation: generation,
            sessionId: sessionId,
            protocolName: protocolName,
            state: state,
            counters: accumulator.cumulative,
            latestDelta: latestDelta,
            counterResetCount: accumulator.resetCount,
            countersAvailable: countersAvailable
        )
    }

    func payload(core: [String: Any], lastHandshakeEpochSec: UInt64? = nil) -> [String: Any] {
        let value = snapshot()
        let counters: [String: Any] = [
            "available": value.countersAvailable,
            "source": "hev_socks5_tunnel",
            "epoch": value.sessionId,
            // JSON-числа в QJson/JavaScript — IEEE-754 и теряют точность выше 2^53.
            // Runtime status v1 отдаёт каждый счётчик/дельту каноничной беззнаковой
            // десятичной строкой (ios_controller.mm парсит строки strtoull).
            "rx_bytes": String(value.counters.rxBytes),
            "tx_bytes": String(value.counters.txBytes),
            "rx_packets": String(value.counters.rxPackets),
            "tx_packets": String(value.counters.txPackets),
            "rx_bytes_delta": String(value.latestDelta.rxBytes),
            "tx_bytes_delta": String(value.latestDelta.txBytes),
            "rx_packets_delta": String(value.latestDelta.rxPackets),
            "tx_packets_delta": String(value.latestDelta.txPackets),
            "reset_count": String(value.counterResetCount)
        ]
        return [
            "type": Self.payloadType,
            "schema": Self.payloadSchema,
            "session_id": value.sessionId,
            "protocol": value.protocolName,
            "runtime_state": value.state.rawValue,
            "core": core,
            "counters": counters,
            // Аддитивная совместимость с плоским ответом WG-пути ({rx_bytes, tx_bytes,
            // last_handshake_time_sec}) — IosController::checkStatus читает эти ключи.
            "rx_bytes": String(value.counters.rxBytes),
            "tx_bytes": String(value.counters.txBytes),
            "last_handshake_time_sec": lastHandshakeEpochSec.map { String($0) as Any } ?? NSNull()
        ]
    }

    private func nextGeneration(_ value: UInt64) -> UInt64 {
        value == UInt64.max ? 1 : value + 1
    }
}

// AVPN (device round air-B 24.11; review R43 F1/F3): the one answer to startTunnel, for every protocol.
//
// The system calls stopTunnel while a start may still be running (the app stops a leg it raised a moment ago). In that
// round stopTunnel was entered within 20 ms of the app's stop of an Xray leg 0.2 s into its start, and the session
// reached Disconnected 25 s later. The stop itself hung: stopXray's blocking hev quit waits for a hev that was never
// started (TunnelRuntimeSession.HevPhase; fixed there). Besides that the Xray start waits, without a bound, for
// setTunnelNetworkSettings to call back, which the system does not always do (the AmneziaWG adapter bounds the same
// wait to 5 s for that reason: WireGuardAdapter.setNetworkSettings) - such a start never answers by itself.
// The order of the two answers (one decision, under this lock):
//  - stopBegan() at stopTunnel entry: from then on the start can only be answered with an error - a start that would
//    report success after the stop began reports TunnelStartAbort.stoppedDuringStart;
//  - abortForStop() when the native stop is done, right before the stop's own answer: a start still unanswered is
//    answered now (the error), and an answer already being delivered is waited for (bounded). What a delivery delivers
//    is decided at its call, under the delivery lock (review R46 R3): after stopBegan() it is an error even if the call
//    comes late; only a success decided before the stop began can still be under way (its call is waited for, bounded);
//  - a second begin() answers the first start, if it is still unanswered (supersededByNewStart).
// Exactly one answer per startTunnel. The start goes on to its next checkpoint, where the stop's new generation ends
// it (TunnelRuntimeSession.isCurrent / enterHev); the stop still takes the native gate (one tunnel session at a time).
// begin() also wraps the start on the macOS NE target (the same provider file, not built by Tribe); only stopBegan /
// abortForStop are called on iOS alone.
enum TunnelStartAbort: Error {
    case stoppedDuringStart
    case supersededByNewStart
}

/// The answer to ONE startTunnel. Thread-safe, at most once. What is delivered is decided at the call itself (review
/// R46 R3): the delivery lock is held from the last read of `stopping` through the handler call, and stopBegan() sets
/// `stopping` at once - so once the stop began no success can be decided any more; the bounded waits below only bound
/// how long the stop waits for a delivery already under way, never what it delivers.
final class TunnelStartAnswer {
    static let deliveryWaitSeconds: TimeInterval = 1
    private let state = NSLock()             // handler, stopping
    private let delivery = NSRecursiveLock() // held from the decision through the handler call
    private var handler: ((Error?) -> Void)?
    private var stopping = false
    /// Tests only: runs after a delivery took its answer and before it decides and calls (a preempted thread).
    var testHookBeforeDecision: (() -> Void)?

    init(_ handler: @escaping (Error?) -> Void) {
        self.handler = handler
    }

    /// true: this call answered the start (the first one); false: it was answered already, this answer is dropped.
    /// After stopBegan() a success becomes stoppedDuringStart, whenever the call happens.
    @discardableResult
    func answer(_ error: Error?) -> Bool {
        delivery.lock()
        defer { delivery.unlock() }
        state.lock()
        guard let pending = handler else {
            state.unlock()
            return false
        }
        handler = nil
        state.unlock()
        testHookBeforeDecision?()
        state.lock()
        let stopNow = stopping
        state.unlock()
        // Residual (review R47, PATHOLOGICAL, left as is): a thread preempted between this read and the call below for
        // longer than both bounds of the stop (2 x deliveryWaitSeconds) delivers the success it read before the stop
        // began, after the stop's own answer. No bounded wait can exclude it; an unbounded one would turn a stuck
        // system completion into a stuck stop.
        pending(stopNow ? (error ?? TunnelStartAbort.stoppedDuringStart) : error)
        return true
    }

    /// The stop began: from now on nothing but an error can be decided. Then waits (bounded) for a delivery already
    /// under way. true: the start was not answered yet, or its answer was being delivered.
    func stopBegan() -> Bool {
        state.lock()
        stopping = true
        let unanswered = handler != nil
        state.unlock()
        let inFlight = !delivery.try()
        if inFlight {
            if delivery.lock(before: Date().addingTimeInterval(Self.deliveryWaitSeconds)) { delivery.unlock() }
        } else {
            delivery.unlock()
        }
        return unanswered || inFlight
    }

    /// The stop's own answer is next: a start still unanswered is answered now (an error); a delivery under way is
    /// waited for (bounded - past the bound it can only deliver an error, decided after stopBegan()).
    func abortForStop() -> Bool {
        guard delivery.lock(before: Date().addingTimeInterval(Self.deliveryWaitSeconds)) else { return false }
        defer { delivery.unlock() }
        return answer(TunnelStartAbort.stoppedDuringStart)
    }

    var answered: Bool {
        state.lock()
        defer { state.unlock() }
        return handler == nil
    }
}

/// Per provider: the start in flight. begin() at startTunnel; stopBegan() at stopTunnel entry; abortForStop() when the
/// native stop is done.
final class TunnelStartSlot {
    private let lock = NSLock()
    private var current: TunnelStartAnswer?
    private var stopRequested = false
    /// Tests only: handed to every start begun after it is set (TunnelStartAnswer.testHookBeforeDecision).
    var testHookBeforeDecision: (() -> Void)?

    /// A start began and is not answered yet.
    var pending: Bool {
        lock.lock()
        let start = current
        lock.unlock()
        return start.map { !$0.answered } ?? false
    }

    /// The completion to hand to the protocol's start. A start still unanswered from an earlier begin() is answered
    /// now (supersededByNewStart): no start is left without its answer.
    func begin(_ handler: @escaping (Error?) -> Void) -> (Error?) -> Void {
        let start = TunnelStartAnswer(handler)
        start.testHookBeforeDecision = testHookBeforeDecision
        lock.lock()
        let previous = current
        current = start
        stopRequested = false
        lock.unlock()
        previous?.answer(TunnelStartAbort.supersededByNewStart)
        return { error in start.answer(error) }
    }

    /// stopTunnel entry: from now on the start can only be answered with an error. true: it was still unanswered.
    func stopBegan() -> Bool {
        lock.lock()
        let start = current
        stopRequested = true
        lock.unlock()
        return start?.stopBegan() ?? false
    }

    /// The session's stopTunnel began (until the next startTunnel): a network-change restart does not start again.
    var sessionStopping: Bool {
        lock.lock()
        defer { lock.unlock() }
        return stopRequested
    }

    /// The native stop is done: a start still unanswered is answered (stoppedDuringStart), one being delivered is
    /// waited for. true: this call answered it.
    func abortForStop() -> Bool {
        lock.lock()
        let start = current
        current = nil
        lock.unlock()
        return start?.abortForStop() ?? false
    }
}

// AVPN (review R43 F2): one value the running session owns (the Xray path's seat renewer). The stop takes it and
// closes the slot in one step, so a start still under way can never attach it afterwards (nothing of a stopped session
// outlives its stop); a fresh tunnel start opens the slot again. Thread-safe.
final class StopClosableSlot<Value: AnyObject> {
    private let lock = NSLock()
    private var value: Value?
    private var closed = false

    var current: Value? {
        lock.lock()
        defer { lock.unlock() }
        return value
    }

    /// Replace the value while the session runs (nil clears it); does not reopen a closed slot.
    func set(_ newValue: Value?) {
        lock.lock()
        value = newValue
        lock.unlock()
    }

    /// The start's attach: false = the session's stop took the slot first - the value must not be started.
    func attach(_ newValue: Value) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !closed else { return false }
        value = newValue
        return true
    }

    /// The stop: the value, and nothing attaches until reopen().
    func take() -> Value? {
        lock.lock()
        defer { lock.unlock() }
        closed = true
        let taken = value
        value = nil
        return taken
    }

    /// A fresh tunnel start (not a core restart inside the session).
    func reopen() {
        lock.lock()
        closed = false
        lock.unlock()
    }
}
