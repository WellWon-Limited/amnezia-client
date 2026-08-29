import Foundation

// Versioned, protocol-neutral runtime status used by the app <-> Network
// Extension IPC.  Keep this file Foundation-only: the accumulator is covered
// by a host-side Swift smoke test without requiring an iOS device.
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

// Native engines are allowed to reset their process-local counters during a
// rebind/restart.  A backwards raw value therefore rebases that component and
// contributes a zero delta; it must never wrap UInt64 or erase already
// accumulated traffic from the current provider session.
struct ResetSafeTrafficAccumulator {
    private(set) var cumulative = TunnelTrafficSample.zero
    private(set) var previousRaw = TunnelTrafficSample.zero
    private(set) var resetCount: UInt64 = 0

    mutating func reset() {
        cumulative = .zero
        previousRaw = .zero
        resetCount = 0
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

    private static func delta(_ current: UInt64, _ previous: UInt64) -> (value: UInt64, reset: Bool) {
        guard current >= previous else { return (0, true) }
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

// One lock protects lifecycle generation and counters.  Async setup callbacks
// carry the generation returned by beginSession(); callbacks from a stopped or
// superseded session are ignored.
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

    @discardableResult
    func beginSession(protocolName: String, sessionId expectedSessionId: String? = nil) -> UInt64 {
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
        accumulator.reset()
        latestDelta = .zero
        countersAvailable = false
        return generation
    }

    // Invalidates every outstanding start/restart callback while retaining the
    // session id so observers can see starting -> stopping -> stopped in one
    // status epoch.
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

    func isCurrent(generation expectedGeneration: UInt64) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return generation == expectedGeneration
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
            // JSON numbers are IEEE-754 in QJson/JavaScript and lose integer
            // precision above 2^53.  Runtime status v1 uses canonical unsigned
            // decimal strings for every counter/delta.
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
            // Additive compatibility for app builds that only understand the
            // pre-v1 flat status response.
            "rx_bytes": String(value.counters.rxBytes),
            "tx_bytes": String(value.counters.txBytes),
            "last_handshake_time_sec": lastHandshakeEpochSec.map { String($0) as Any } ?? NSNull()
        ]
    }

    private func nextGeneration(_ value: UInt64) -> UInt64 {
        value == UInt64.max ? 1 : value + 1
    }
}
