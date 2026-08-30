import Foundation

private func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
    guard condition() else { fputs("FAIL: \(message)\n", stderr); exit(1) }
}

private func identity(_ operation: String, _ runtime: String) -> TribeNativeGuardIdentity {
    try! TribeNativeGuardIdentity(
        operation: operation,
        session: operation,
        policySHA256: String(repeating: Character(operation == "1" ? "a" : "b"), count: 64),
        expectedRuntimeSessionId: runtime
    )
}

@main
private struct NativeGuardTests {
    static func main() throws {
        let runtime1 = "123e4567-e89b-42d3-a456-426614174000"
        let runtime2 = "123e4567-e89b-42d3-a456-426614174001"
        let first = identity("1", runtime1)
        let second = identity("2", runtime2)
        let owner = TribeNativeSessionGuard()
        let outer1 = "provider:123e4567-e89b-42d3-a456-426614174010"
        let outer2 = "provider:123e4567-e89b-42d3-a456-426614174011"
        let outerPolicy = String(repeating: "c", count: 64)

        do {
            _ = try TribeNativeSessionGuard().arm(
                first, outerPolicySHA256: outerPolicy,
                generatedOuterSessionId: "outer-тест")
            expect(false, "Unicode outer identity crossed the C++/Swift boundary")
        } catch TribeNativeSessionGuardError.malformedIdentity {}

        let armed = try owner.arm(first, outerPolicySHA256: outerPolicy,
                                  generatedOuterSessionId: outer1)
        expect(armed.keys.count == 9 && armed["kind"] as? String == "armed",
               "closed Armed receipt")
        try owner.beginActivation(first, outer: outer1)
        try owner.markRunning(expectedRuntimeSessionId: runtime1)

        do {
            try owner.beginStop(outer: outer1, expectedRuntimeSessionId: runtime2)
            expect(false, "stale runtime stop accepted")
        } catch TribeNativeSessionGuardError.stale {}
        try owner.beginStop(outer: outer1, expectedRuntimeSessionId: runtime1)
        try owner.markStopped(expectedRuntimeSessionId: runtime1)

        do {
            _ = try owner.arm(second, outerPolicySHA256: String(repeating: "d", count: 64),
                              generatedOuterSessionId: outer2)
            expect(false, "different outer policy replaced live guard")
        } catch TribeNativeSessionGuardError.outerPolicyChanged {}

        _ = try owner.arm(second, outerPolicySHA256: outerPolicy,
                          generatedOuterSessionId: outer2)
        do {
            try owner.beginActivation(first, outer: outer1)
            expect(false, "N-2 activation accepted")
        } catch TribeNativeSessionGuardError.stale {}
        try owner.beginActivation(second, outer: outer2)
        try owner.markRunning(expectedRuntimeSessionId: runtime2)
        do {
            _ = try owner.release(second, outer: outer2)
            expect(false, "release while inner owns packet flow")
        } catch TribeNativeSessionGuardError.innerStillOwned {}
        try owner.beginStop(outer: outer2, expectedRuntimeSessionId: runtime2)
        try owner.markStopped(expectedRuntimeSessionId: runtime2)
        let released = try owner.release(second, outer: outer2)
        expect(released["kind"] as? String == "released", "exact release receipt")
        expect(owner.snapshot().phase == .idle, "owner returned idle")

        let asynchronousRelease = TribeNativeSessionGuard()
        _ = try asynchronousRelease.arm(first, outerPolicySHA256: outerPolicy,
                                        generatedOuterSessionId: outer1)
        try asynchronousRelease.beginRelease(first, outer: outer1)
        expect(asynchronousRelease.snapshot().phase == .releasing,
               "OS settings clear has an explicit release reservation")
        do {
            _ = try asynchronousRelease.arm(second, outerPolicySHA256: outerPolicy,
                                            generatedOuterSessionId: outer2)
            expect(false, "replacement armed while an old settings clear was in flight")
        } catch TribeNativeSessionGuardError.busy {}
        do {
            try asynchronousRelease.beginActivation(first, outer: outer1)
            expect(false, "inner activation crossed an in-flight settings clear")
        } catch TribeNativeSessionGuardError.stale {}
        do {
            try asynchronousRelease.proveRecoveryStopped(first, outer: outer1)
            expect(false, "duplicate recovery stop erased the release reservation")
        } catch TribeNativeSessionGuardError.stale {}
        asynchronousRelease.quarantine(expectedRuntimeSessionId: runtime1)
        expect(asynchronousRelease.snapshot().phase == .releasing,
               "late quarantine callback erased the release reservation")
        expect(asynchronousRelease.lostEvent(reason: "late_recovery_stop_failed") == nil,
               "late lost callback emitted a false terminal during release")
        expect(asynchronousRelease.snapshot().phase == .releasing,
               "late lost callback erased the release reservation")
        do {
            try asynchronousRelease.cancelRelease(second, outer: outer2)
            expect(false, "stale settings callback cancelled another release reservation")
        } catch TribeNativeSessionGuardError.stale {}
        expect(asynchronousRelease.snapshot().phase == .releasing,
               "stale cancellation mutated the exact release reservation")
        try asynchronousRelease.cancelRelease(first, outer: outer1)
        expect(asynchronousRelease.snapshot().phase == .armed,
               "failed OS settings clear restores the exact pre-clear phase")
        try asynchronousRelease.beginRelease(first, outer: outer1)
        _ = try asynchronousRelease.commitRelease(first, outer: outer1)
        expect(asynchronousRelease.snapshot().phase == .idle,
               "successful OS settings receipt commits the exact reservation")
        do {
            _ = try asynchronousRelease.commitRelease(first, outer: outer1)
            expect(false, "late duplicate release callback committed twice")
        } catch TribeNativeSessionGuardError.stale {}

        let blackholeRelease = TribeNativeSessionGuard()
        _ = try blackholeRelease.arm(first, outerPolicySHA256: outerPolicy,
                                     generatedOuterSessionId: outer1)
        try blackholeRelease.beginActivation(first, outer: outer1)
        try blackholeRelease.markRunning(expectedRuntimeSessionId: runtime1)
        try blackholeRelease.beginStop(outer: outer1, expectedRuntimeSessionId: runtime1)
        try blackholeRelease.markStopped(expectedRuntimeSessionId: runtime1)
        try blackholeRelease.beginRelease(first, outer: outer1)
        try blackholeRelease.cancelRelease(first, outer: outer1)
        expect(blackholeRelease.snapshot().phase == .blackhole,
               "failed OS settings clear restores a stopped outer blackhole")
        try blackholeRelease.beginRelease(first, outer: outer1)
        do {
            _ = try blackholeRelease.commitRelease(second, outer: outer2)
            expect(false, "stale success callback committed another release reservation")
        } catch TribeNativeSessionGuardError.stale {}
        expect(blackholeRelease.snapshot().phase == .releasing,
               "stale success callback mutated the exact release reservation")
        _ = try blackholeRelease.commitRelease(first, outer: outer1)
        expect(blackholeRelease.snapshot().phase == .idle,
               "exact stopped-owner release commits after the OS receipt")

        let startRace = TribeNativeSessionGuard()
        _ = try startRace.arm(first, outerPolicySHA256: outerPolicy,
                              generatedOuterSessionId: outer1)
        try startRace.beginActivation(first, outer: outer1)
        try startRace.beginStop(outer: outer1, expectedRuntimeSessionId: runtime1)
        startRace.quarantine(expectedRuntimeSessionId: runtime1)
        expect(startRace.lostEvent(reason: "late_start_failed") == nil,
               "late start callback emitted Lost during ordinary stop")
        expect(startRace.snapshot().phase == .stopping,
               "late start callback erased the ordinary stop reservation")
        try startRace.markStopped(expectedRuntimeSessionId: runtime1)
        expect(startRace.snapshot().phase == .blackhole,
               "stop during starting retains the outer blackhole")

        let stopFailure = TribeNativeSessionGuard()
        _ = try stopFailure.arm(first, outerPolicySHA256: outerPolicy,
                                generatedOuterSessionId: outer1)
        try stopFailure.beginActivation(first, outer: outer1)
        try stopFailure.markRunning(expectedRuntimeSessionId: runtime1)
        try stopFailure.beginStop(outer: outer1, expectedRuntimeSessionId: runtime1)
        let stopLost = try stopFailure.failStop(
            first, outer: outer1, reason: "inner_stop_failed")
        expect(stopLost["kind"] as? String == "lost"
                && stopFailure.snapshot().phase == .quarantined,
               "exact ordinary stop failure quarantines the retained outer owner")

        let failed = TribeNativeSessionGuard()
        _ = try failed.arm(first, outerPolicySHA256: outerPolicy,
                           generatedOuterSessionId: outer1)
        try failed.beginActivation(first, outer: outer1)
        failed.quarantine(expectedRuntimeSessionId: runtime1)
        let lost = failed.lostEvent(reason: "inner_start_failed")
        expect(lost?.keys.count == 9 && lost?["kind"] as? String == "lost",
               "failed partial start has exact Lost receipt")
        do {
            _ = try failed.release(first, outer: outer1)
            expect(false, "quarantined owner released without teardown proof")
        } catch TribeNativeSessionGuardError.quarantined {}
        do {
            _ = try failed.beginRecoveryStop(second, outer: outer1)
            expect(false, "recovery teardown accepted a stale runtime identity")
        } catch TribeNativeSessionGuardError.stale {}
        let quarantinedNeedsInnerStop = try failed.beginRecoveryStop(first, outer: outer1)
        expect(quarantinedNeedsInnerStop,
               "quarantined recovery reserves an exact native teardown")
        do {
            _ = try failed.beginRecoveryStop(first, outer: outer1)
            expect(false, "duplicate recovery teardown dispatched a second native stop")
        } catch TribeNativeSessionGuardError.busy {}
        do {
            try failed.markStopped(expectedRuntimeSessionId: runtime1)
            expect(false, "late ordinary stop callback claimed the recovery reservation")
        } catch TribeNativeSessionGuardError.stale {}
        expect(failed.snapshot().phase == .recoveryStopping,
               "late ordinary stop callback mutated the recovery reservation")
        failed.quarantine(expectedRuntimeSessionId: runtime1)
        expect(failed.lostEvent(reason: "late_start_failed") == nil,
               "late start callback emitted Lost during recovery teardown")
        expect(failed.snapshot().phase == .recoveryStopping,
               "late start callback erased the recovery reservation")
        try failed.proveRecoveryStopped(first, outer: outer1)
        _ = try failed.release(first, outer: outer1)
        expect(failed.snapshot().phase == .idle,
               "exact recovery teardown permits outer release")

        let noInnerRecovery = TribeNativeSessionGuard()
        _ = try noInnerRecovery.arm(first, outerPolicySHA256: outerPolicy,
                                    generatedOuterSessionId: outer1)
        let armedNeedsInnerStop = try noInnerRecovery.beginRecoveryStop(first, outer: outer1)
        expect(!armedNeedsInnerStop,
               "armed recovery does not dispatch an inner stop")
        try noInnerRecovery.proveRecoveryStopped(first, outer: outer1)
        try noInnerRecovery.beginRelease(first, outer: outer1)
        _ = try noInnerRecovery.commitRelease(first, outer: outer1)

        let recoveryFailure = TribeNativeSessionGuard()
        _ = try recoveryFailure.arm(first, outerPolicySHA256: outerPolicy,
                                    generatedOuterSessionId: outer1)
        try recoveryFailure.beginActivation(first, outer: outer1)
        try recoveryFailure.markRunning(expectedRuntimeSessionId: runtime1)
        let runningNeedsInnerStop = try recoveryFailure.beginRecoveryStop(
            first, outer: outer1)
        expect(runningNeedsInnerStop, "running recovery reserves an inner stop")
        let recoveryLost = try recoveryFailure.failRecoveryStop(
            first, outer: outer1, reason: "recovery_stop_failed")
        expect(recoveryLost["kind"] as? String == "lost"
                && recoveryFailure.snapshot().phase == .quarantined,
               "exact recovery stop failure quarantines the retained outer owner")

        let adopt = TribeNativeSessionGuard()
        _ = try adopt.arm(first, outerPolicySHA256: outerPolicy,
                          generatedOuterSessionId: outer1)
        do {
            try adopt.validateRecoveryAdoption(first, outer: outer1)
            expect(false, "Armed-only guard adopted as a running inner")
        } catch TribeNativeSessionGuardError.stale {}
        try adopt.beginActivation(first, outer: outer1)
        try adopt.markRunning(expectedRuntimeSessionId: runtime1)
        try adopt.validateRecoveryAdoption(first, outer: outer1)

        let rejected = TribeNativeSessionGuard.event(
            identity: first, kind: "arm_rejected", outerSessionId: "",
            reason: "prepare_rejected")
        expect(rejected.keys.count == 9 && rejected["policy_sha256"] as? String
                == first.policySHA256, "rejection echoes immutable identity")

        let armTransaction = TribeNativeSessionGuard()
        _ = try armTransaction.arm(first, outerPolicySHA256: outerPolicy,
                                   generatedOuterSessionId: outer1)
        try armTransaction.beginActivation(first, outer: outer1)
        try armTransaction.markRunning(expectedRuntimeSessionId: runtime1)
        try armTransaction.beginStop(outer: outer1, expectedRuntimeSessionId: runtime1)
        try armTransaction.markStopped(expectedRuntimeSessionId: runtime1)
        try armTransaction.beginArm(second, outerPolicySHA256: outerPolicy,
                                    generatedOuterSessionId: outer2)
        expect(armTransaction.snapshot().phase == .arming
                && armTransaction.snapshot().identity == first,
               "PREPARE reservation retains the previous exact blackhole owner")
        do {
            try armTransaction.beginRelease(first, outer: outer1)
            expect(false, "release crossed an in-flight PREPARE settings mutation")
        } catch TribeNativeSessionGuardError.innerStillOwned {}
        try armTransaction.cancelArm(second)
        expect(armTransaction.snapshot().phase == .blackhole
                && armTransaction.snapshot().identity == first,
               "settings rejection restores the previous exact blackhole")
        try armTransaction.beginArm(second, outerPolicySHA256: outerPolicy,
                                    generatedOuterSessionId: outer2)
        let committedArm = try armTransaction.commitArm(second)
        expect(committedArm["kind"] as? String == "armed"
                && armTransaction.snapshot().identity == second,
               "Armed is emitted only after the exact PREPARE reservation commits")

        let failedArmCommit = TribeNativeSessionGuard()
        try failedArmCommit.beginArm(first, outerPolicySHA256: outerPolicy,
                                     generatedOuterSessionId: outer1)
        let commitLost = try failedArmCommit.failArmCommit(
            first, reason: "arm_commit_failed")
        expect(commitLost["kind"] as? String == "lost"
                && failedArmCommit.snapshot().phase == .quarantined
                && failedArmCommit.snapshot().identity == first,
               "accepted OS settings can fail state commit only as exact Lost")

        let timedOutArm = TribeNativeSessionGuard()
        try timedOutArm.beginArm(first, outerPolicySHA256: outerPolicy,
                                 generatedOuterSessionId: outer1)
        let ambiguousArm = timedOutArm.reconcileTimedOutArm(first)
        expect(ambiguousArm?["kind"] as? String == "lost"
                && timedOutArm.snapshot().phase == .quarantined,
               "in-flight PREPARE timeout is quarantined instead of guessed absent")
        do {
            _ = try timedOutArm.commitArm(first)
            expect(false, "late PREPARE callback resurrected a reconciled identity")
        } catch TribeNativeSessionGuardError.stale {}

        let absentArm = TribeNativeSessionGuard()
        let absentReceipt = absentArm.reconcileTimedOutArm(first)
        expect(absentReceipt?["kind"] as? String == "arm_rejected"
                && absentReceipt?["outer_session_id"] as? String == ""
                && absentArm.snapshot().phase == .idle,
               "ArmRejected is emitted only from proven zero new ownership")
        do {
            _ = try absentArm.arm(first, outerPolicySHA256: outerPolicy,
                                  generatedOuterSessionId: outer1)
            expect(false, "late tombstoned PREPARE resurrected after ArmRejected")
        } catch TribeNativeSessionGuardError.stale {}
        let laterSameOperation = try TribeNativeGuardIdentity(
            operation: "1", session: "2", policySHA256: first.policySHA256,
            expectedRuntimeSessionId: runtime2)
        _ = try absentArm.arm(laterSameOperation, outerPolicySHA256: outerPolicy,
                              generatedOuterSessionId: outer2)
        expect(absentArm.snapshot().identity == laterSameOperation,
               "arm tombstone does not reject a later fallback session")

        let releaseReconcile = TribeNativeSessionGuard()
        _ = try releaseReconcile.arm(first, outerPolicySHA256: outerPolicy,
                                     generatedOuterSessionId: outer1)
        try releaseReconcile.beginRelease(first, outer: outer1)
        let retainedReceipt = releaseReconcile.reconcileTimedOutRelease(first, outer: outer1)
        expect(retainedReceipt == nil && releaseReconcile.snapshot().phase == .releasing,
               "in-flight release remains ambiguous for its late exact OS receipt")
        _ = try releaseReconcile.commitRelease(first, outer: outer1)
        let releasedReceipt = releaseReconcile.reconcileTimedOutRelease(first, outer: outer1)
        expect(releasedReceipt?["kind"] as? String == "released",
               "durable exact release tombstone reconciles a lost Released reply")
        expect(releaseReconcile.reconcileTimedOutRelease(second, outer: outer2) == nil,
               "release reconciliation never clears or invents a mismatched identity")

        print("Apple native session guard state tests passed")
    }
}
