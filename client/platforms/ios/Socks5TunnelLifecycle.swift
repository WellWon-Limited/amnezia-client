import Foundation

// Pure lifecycle reducer for the process-global HEV C library.  Keeping this
// independent of NetworkExtension and the native module makes the failure
// races testable on a host Swift toolchain.
enum Socks5TunnelLifecyclePhase: Equatable {
    case idle
    case starting
    case running
    case stopping
    case stopped
    case failed
    case quarantined
}

enum Socks5TunnelStartFailure: Equatable {
    case native(Int32)
    case cancelled
    case timedOut
}

enum Socks5TunnelLifecycleAction: Equatable {
    case reportStarted
    case reportStartFailure(Socks5TunnelStartFailure)
    case requestNativeStop
    case reportStopped
    case reportStopTimedOut
    case reportUnexpectedExit(Int32)
}

struct Socks5TunnelLifecycle {
    private(set) var phase: Socks5TunnelLifecyclePhase = .idle
    private var startReported = false
    private var stopReported = false

    mutating func beginStart() -> Bool {
        guard phase == .idle || phase == .stopped || phase == .failed else {
            return false
        }
        phase = .starting
        startReported = false
        stopReported = false
        return true
    }

    mutating func observeReady() -> [Socks5TunnelLifecycleAction] {
        guard phase == .starting else {
            return phase == .stopping ? [.requestNativeStop] : []
        }
        phase = .running
        guard !startReported else { return [] }
        startReported = true
        return [.reportStarted]
    }

    mutating func observeNativeReturn(_ code: Int32) -> [Socks5TunnelLifecycleAction] {
        switch phase {
        case .starting:
            phase = .failed
            guard !startReported else { return [] }
            startReported = true
            return [.reportStartFailure(.native(code))]
        case .running:
            phase = .failed
            return [.reportUnexpectedExit(code)]
        case .stopping:
            phase = .stopped
            var actions: [Socks5TunnelLifecycleAction] = []
            if !startReported {
                startReported = true
                actions.append(.reportStartFailure(.cancelled))
            }
            if !stopReported {
                stopReported = true
                actions.append(.reportStopped)
            }
            return actions
        case .quarantined:
            // The bounded stop callback has already fired.  Never allow this
            // process-global native instance to be reused after a timeout.
            return []
        case .idle, .stopped, .failed:
            return []
        }
    }

    mutating func requestStop() -> [Socks5TunnelLifecycleAction] {
        switch phase {
        case .starting:
            phase = .stopping
            var actions: [Socks5TunnelLifecycleAction] = []
            if !startReported {
                startReported = true
                actions.append(.reportStartFailure(.cancelled))
            }
            actions.append(.requestNativeStop)
            return actions
        case .running:
            phase = .stopping
            return [.requestNativeStop]
        case .stopping:
            return [.requestNativeStop]
        case .idle, .stopped, .failed:
            phase = .stopped
            stopReported = true
            // Every caller owns a distinct completion. Even after an earlier stop already
            // reached a terminal state, a later provider/release teardown must receive the
            // same deterministic proof instead of being left queued forever.
            return [.reportStopped]
        case .quarantined:
            stopReported = true
            // Quarantine is permanent for this process-global instance, but every later exact
            // stop waiter still needs a deterministic terminal receipt. Returning an action per
            // request does not restart or release the native singleton.
            return [.reportStopTimedOut]
        }
    }

    mutating func startTimedOut() -> [Socks5TunnelLifecycleAction] {
        guard phase == .starting else { return [] }
        phase = .stopping
        var actions: [Socks5TunnelLifecycleAction] = []
        if !startReported {
            startReported = true
            actions.append(.reportStartFailure(.timedOut))
        }
        actions.append(.requestNativeStop)
        return actions
    }

    mutating func stopTimedOut() -> [Socks5TunnelLifecycleAction] {
        guard phase == .stopping else { return [] }
        phase = .quarantined
        guard !stopReported else { return [] }
        stopReported = true
        return [.reportStopTimedOut]
    }
}
