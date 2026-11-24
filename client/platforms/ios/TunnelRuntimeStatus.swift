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
        lock.lock()
        defer { lock.unlock() }
        generation = nextGeneration(generation)
        state = .stopping
        return generation
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

// AVPN (device round air-B 24.11): the one answer to startTunnel, for every protocol.
//
// The system calls stopTunnel while a start may still be running (the app stops a leg it raised a moment ago). In that
// round the stop record shows stopTunnel entered within 20 ms of the app's stop of an Xray leg 0.2 s into its start,
// yet the session reached Disconnected 25 s later; every stop of a tunnel already up took 0.4-1.0 s. The Xray start
// waits, without a bound, for setTunnelNetworkSettings to call back, and the system does not always call it back (the
// AmneziaWG adapter bounds the same wait to 5 s for that reason: WireGuardAdapter.setNetworkSettings): such a start
// never answers, and the system can hold the session for it. Inferred, not proven - the extension's log of that round
// was not readable; the stop record's stop_ms / start_pending (PacketTunnelProvider.stopTunnel) tell it next time.
// So a start still unanswered is answered by the stop itself, with `TunnelStartAbort.stoppedDuringStart`, as soon as
// the native stop is done (right before the stop's own answer: nothing of the session runs any more when the system
// hears of either); the start's own later answer is dropped. Exactly one answer reaches the system per startTunnel.
// The start goes on to its next checkpoint, where the stop's new generation ends it (the Xray path:
// TunnelRuntimeSession.isCurrent after the settings, inside the native gate before the core and before hev); the stop
// still takes the native gate, so the core and hev are never touched by two at once (one tunnel session at a time).
enum TunnelStartAbort: Error {
    case stoppedDuringStart
}

/// The answer to ONE startTunnel. Thread-safe; the handler runs outside the lock, at most once.
final class TunnelStartAnswer {
    private let lock = NSLock()
    private var handler: ((Error?) -> Void)?

    init(_ handler: @escaping (Error?) -> Void) {
        self.handler = handler
    }

    /// true: this call answered the start (the first one); false: it was answered already, this answer is dropped.
    @discardableResult
    func answer(_ error: Error?) -> Bool {
        lock.lock()
        let pending = handler
        handler = nil
        lock.unlock()
        guard let pending else { return false }
        pending(error)
        return true
    }

    var answered: Bool {
        lock.lock()
        defer { lock.unlock() }
        return handler == nil
    }
}

/// Per provider: the start in flight. begin() at startTunnel; at stopTunnel `pending` (for the stop record) and, once
/// the native stop is done, abortForStop().
final class TunnelStartSlot {
    private let lock = NSLock()
    private var current: TunnelStartAnswer?

    /// A start began and is not answered yet.
    var pending: Bool {
        lock.lock()
        let start = current
        lock.unlock()
        return start.map { !$0.answered } ?? false
    }

    /// The completion to hand to the protocol's start: the first of it and abortForStop() answers the system.
    func begin(_ handler: @escaping (Error?) -> Void) -> (Error?) -> Void {
        let start = TunnelStartAnswer(handler)
        lock.lock()
        current = start
        lock.unlock()
        return { error in start.answer(error) }
    }

    /// stopTunnel: a start still unanswered is answered now (stoppedDuringStart). true: there was one.
    func abortForStop() -> Bool {
        lock.lock()
        let start = current
        current = nil
        lock.unlock()
        return start?.answer(TunnelStartAbort.stoppedDuringStart) ?? false
    }
}
