import Darwin
import Foundation

/// awg-apple's historical Xray C ABI uses two success representations: callback registration
/// returns nil, while Run/Stop return an allocated empty C string. All non-empty strings are
/// failures. This consumer owns and frees every non-nil result exactly once.
enum XrayNativeCStringResult {
    static func consume(_ result: UnsafeMutablePointer<CChar>?) -> Bool {
        guard let result else { return true }
        defer { free(result) }
        return result.pointee == 0
    }
}

struct XraySocketCallbackIdentity: Hashable {
    let generation: UInt64
    let sessionId: String

    init?(generation: UInt64, sessionId: String) {
        guard generation > 0,
              sessionId == sessionId.lowercased(),
              UUID(uuidString: sessionId)?.uuidString.lowercased() == sessionId else {
            return nil
        }
        self.generation = generation
        self.sessionId = sessionId
    }
}

/// The native callback slot owns at most one raw Swift context. Removal is legal only after
/// LibXraySetSockCallback(nil, nil) has synchronously drained native invocations.
final class XraySocketCallbackRegistry<Value: AnyObject> {
    private let lock = NSLock()
    private var entry: (identity: XraySocketCallbackIdentity, value: Value)?

    func install(_ value: Value, identity: XraySocketCallbackIdentity) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard entry == nil else { return false }
        entry = (identity, value)
        return true
    }

    func value(for identity: XraySocketCallbackIdentity) -> Value? {
        lock.lock()
        defer { lock.unlock() }
        guard entry?.identity == identity else { return nil }
        return entry?.value
    }

    @discardableResult
    func remove(identity: XraySocketCallbackIdentity) -> Value? {
        lock.lock()
        defer { lock.unlock() }
        guard entry?.identity == identity else { return nil }
        let value = entry?.value
        entry = nil
        return value
    }

    var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return entry == nil ? 0 : 1
    }
}

final class XraySocketCallbackFence {
    private let lock = NSLock()
    let identity: XraySocketCallbackIdentity
    private var active = true

    init(identity: XraySocketCallbackIdentity) {
        self.identity = identity
    }

    func accepts(currentGeneration: UInt64, currentSessionId: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return active && identity.generation == currentGeneration
            && identity.sessionId == currentSessionId
    }

    @discardableResult
    func deactivate(expected: XraySocketCallbackIdentity) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard active, identity == expected else { return false }
        active = false
        return true
    }
}

/// One recursive process-local gate serializes exact native Xray start/stop calls. Rechecks of
/// TunnelRuntimeSession happen inside this gate immediately before native mutation, so a stop that
/// already invalidated the generation cannot be followed by a late core or tun2socks start.
final class XrayNativeLifecycleGate {
    private let lock = NSRecursiveLock()

    func withExclusive<T>(_ body: () throws -> T) rethrows -> T {
        lock.lock()
        defer { lock.unlock() }
        return try body()
    }
}

enum XraySocketCallbackTeardown {
    /// StopXray synchronously closes the core while the protect callback remains armed. Clearing
    /// then takes the native write lock and drains callbacks already in flight. The raw context is
    /// released only after both operations, avoiding both an unprotected-dial window and UAF.
    static func execute(stopCore: () -> Bool, drain: () -> Bool,
                        retireContext: () -> Bool) -> Bool {
        // A failed/ambiguous synchronous close cannot authorize clearing the protect slot: the
        // core may still create sockets. Keep both the callback and its context armed so the
        // outer guard remains fail-closed and a later recovery attempt can retry exact teardown.
        guard stopCore() else { return false }
        let drained = drain()
        guard drained else { return false }
        return retireContext()
    }
}

enum XraySocketFailureContainmentAction: Equatable {
    case ignoreStale
    case cancelLegacyProvider
    case quarantineGuardedOuter
}

enum XraySocketFailureContainmentPolicy {
    static func action(callback: XraySocketCallbackIdentity,
                       runtimeGeneration: UInt64,
                       runtimeSessionId: String,
                       guardExpectedRuntimeSessionId: String?,
                       guardPhase: String?) -> XraySocketFailureContainmentAction {
        guard callback.generation == runtimeGeneration,
              callback.sessionId == runtimeSessionId else { return .ignoreStale }
        guard let guarded = guardExpectedRuntimeSessionId else {
            return .cancelLegacyProvider
        }
        guard guarded == callback.sessionId,
              guardPhase == "starting" || guardPhase == "running" else {
            return .ignoreStale
        }
        return .quarantineGuardedOuter
    }
}
