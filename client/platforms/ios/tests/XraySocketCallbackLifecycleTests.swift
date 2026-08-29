import Foundation

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

@main
private struct XraySocketCallbackLifecycleTests {
    static func main() throws {
        expect(XrayNativeCStringResult.consume(nil), "nil callback result is success")
        expect(XrayNativeCStringResult.consume(strdup("")),
               "allocated empty Run/Stop result is success")
        expect(!XrayNativeCStringResult.consume(strdup("native failure")),
               "non-empty native result is failure")
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

        // Deterministic late-start barriers: a stop that invalidated the generation before the
        // native gate wins prevents start; if start owns the gate first, stop follows it exactly.
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
        expect(fence.deactivate(expected: current), "exact fence deactivation")
        expect(!fence.accepts(currentGeneration: current.generation,
                              currentSessionId: current.sessionId),
               "deactivated callback stays fenced")
        _ = registry.remove(identity: current)

        expect(XraySocketFailureContainmentPolicy.action(
            callback: current, runtimeGeneration: current.generation,
            runtimeSessionId: current.sessionId,
            guardExpectedRuntimeSessionId: current.sessionId,
            guardPhase: "running") == .quarantineGuardedOuter,
            "exact guarded bind failure quarantines outer owner")
        expect(XraySocketFailureContainmentPolicy.action(
            callback: current, runtimeGeneration: current.generation,
            runtimeSessionId: current.sessionId,
            guardExpectedRuntimeSessionId: nil,
            guardPhase: nil) == .cancelLegacyProvider,
            "legacy bind failure keeps legacy provider cancellation")
        expect(XraySocketFailureContainmentPolicy.action(
            callback: current, runtimeGeneration: current.generation + 1,
            runtimeSessionId: uuid(202),
            guardExpectedRuntimeSessionId: current.sessionId,
            guardPhase: "running") == .ignoreStale,
            "stale callback cannot affect a replacement runtime")

        let guardOwner = TribeNativeSessionGuard()
        let guardIdentity = try TribeNativeGuardIdentity(
            operation: "1", session: "1",
            policySHA256: String(repeating: "a", count: 64),
            expectedRuntimeSessionId: current.sessionId)
        let outer = "outer-bind-fi"
        _ = try guardOwner.arm(guardIdentity,
                               outerPolicySHA256: String(repeating: "b", count: 64),
                               generatedOuterSessionId: outer)
        try guardOwner.beginActivation(guardIdentity, outer: outer)
        try guardOwner.markRunning(expectedRuntimeSessionId: current.sessionId)
        _ = guardOwner.lostEvent(reason: "socket_protection_failed")
        expect(guardOwner.snapshot().phase == .quarantined,
               "bind FI leaves the outer owner quarantined")
        do {
            _ = try guardOwner.release(guardIdentity, outer: outer)
            expect(false, "quarantined outer owner released without exact recovery stop")
        } catch TribeNativeSessionGuardError.quarantined {}
        let recoveryNeedsStop = try guardOwner.beginRecoveryStop(guardIdentity, outer: outer)
        expect(recoveryNeedsStop,
               "quarantined owner reserves one exact recovery teardown")
        try guardOwner.proveRecoveryStopped(guardIdentity, outer: outer)
        _ = try guardOwner.release(guardIdentity, outer: outer)
        expect(guardOwner.snapshot().phase == .idle,
               "exact recovery stop/release is required to leave quarantine")

        print("Apple Xray callback lifecycle/containment tests passed (128 sessions)")
    }
}
