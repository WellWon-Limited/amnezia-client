import Foundation

private func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
    guard condition() else { fputs("FAIL: \(message)\n", stderr); exit(1) }
}

@main
private struct RuntimeAuthorityWatchdogTests {
    static func main() throws {
        let wall = Date(timeIntervalSince1970: 1_800_000_000)
        let runtime = "123e4567-e89b-42d3-a456-426614174000"
        let snapshot = TribeRuntimeAuthorityLeaseSnapshot(
            profileId: "profile-1", transport: "awg",
            configGeneration: "1", bindingGeneration: "1",
            policySHA256: String(repeating: "a", count: 64), catalogRevision: 10,
            catalogPayloadSHA256: String(repeating: "b", count: 64),
            catalogSigningKid: "key-1",
            hardDeadline: wall.addingTimeInterval(10), trustedUtcAtDispatch: wall,
            catalogIssuedAt: wall.addingTimeInterval(-60), capturedWallUtc: wall,
            capturedMonotonic: 100)
        let remaining = try TribeRuntimeAuthorityWatchdogPlanner.remaining(
            snapshot: snapshot, wallUtc: wall.addingTimeInterval(3), monotonic: 103)
        expect(abs(remaining - 7) < 0.000_001,
               "one-shot delay lands on the exact trusted hard deadline")
        do {
            _ = try TribeRuntimeAuthorityWatchdogPlanner.remaining(
                snapshot: snapshot, wallUtc: wall.addingTimeInterval(10), monotonic: 110)
            expect(false, "deadline instant retained authority")
        } catch TribeRuntimeAuthorityLeaseError.expired {}

        let fence = TribeRuntimeAuthorityWatchdogFence()
        let prior = fence.arm()
        let renewed = fence.arm() // renewal immediately before the old expiry
        expect(!fence.consume(prior), "stale prior timer cannot consume renewed authority")
        expect(fence.consume(renewed), "renewed one-shot timer remains authoritative")
        expect(!fence.consume(renewed), "timer handler is exactly once")

        let owner = TribeNativeSessionGuard()
        let identity = try TribeNativeGuardIdentity(
            operation: "1", session: "1",
            policySHA256: String(repeating: "a", count: 64),
            expectedRuntimeSessionId: runtime)
        let outer = "outer-deadline-fi"
        _ = try owner.arm(identity, outerPolicySHA256: String(repeating: "c", count: 64),
                          generatedOuterSessionId: outer)
        try owner.beginActivation(identity, outer: outer)
        try owner.markRunning(expectedRuntimeSessionId: runtime)
        // A late/suspended handler evaluates first, then quarantines before dispatching teardown.
        do {
            _ = try TribeRuntimeAuthorityWatchdogPlanner.remaining(
                snapshot: snapshot, wallUtc: wall.addingTimeInterval(20), monotonic: 120)
            expect(false, "late wake retained expired authority")
        } catch TribeRuntimeAuthorityLeaseError.expired {
            _ = owner.lostEvent(reason: "runtime_authority_expired")
        }
        expect(owner.snapshot().phase == .quarantined,
               "late handler quarantines outer ownership before inner teardown")
        do {
            _ = try owner.release(identity, outer: outer)
            expect(false, "expired quarantine released without exact recovery stop")
        } catch TribeNativeSessionGuardError.quarantined {}

        print("Apple exact runtime-authority watchdog tests passed")
    }
}
