import Foundation

enum TribeNativeSessionGuardError: Error, Equatable {
    case malformedIdentity
    case busy
    case stale
    case outerPolicyChanged
    case innerStillOwned
    case quarantined
}

struct TribeNativeGuardIdentity: Equatable {
    let operation: String
    let session: String
    let policySHA256: String
    let expectedRuntimeSessionId: String

    init(operation: String, session: String, policySHA256: String,
         expectedRuntimeSessionId: String) throws {
        guard Self.canonicalCounter(operation), Self.canonicalCounter(session),
              Self.lowerHexSHA256(policySHA256),
              Self.canonicalUUID(expectedRuntimeSessionId) else {
            throw TribeNativeSessionGuardError.malformedIdentity
        }
        self.operation = operation
        self.session = session
        self.policySHA256 = policySHA256
        self.expectedRuntimeSessionId = expectedRuntimeSessionId
    }

    private static func canonicalCounter(_ value: String) -> Bool {
        guard !value.isEmpty, value.count <= 20,
              value == "0" || value.first != "0",
              value.allSatisfy({ $0 >= "0" && $0 <= "9" }),
              let parsed = UInt64(value), parsed > 0 else { return false }
        return String(parsed) == value
    }

    private static func lowerHexSHA256(_ value: String) -> Bool {
        value.count == 64 && value.allSatisfy {
            ($0 >= "0" && $0 <= "9") || ($0 >= "a" && $0 <= "f")
        }
    }

    private static func canonicalUUID(_ value: String) -> Bool {
        value == value.lowercased() && UUID(uuidString: value)?.uuidString.lowercased() == value
    }
}

/// Pure ownership state machine used by PacketTunnelProvider. Production PREPARE is a three-step
/// transaction: reserve the exact identity, apply Network Extension settings, then commit Armed.
/// This makes an ArmRejected receipt proof that the attempted identity never acquired new outer
/// ownership, even when another stopped identity remains protected by the existing blackhole.
final class TribeNativeSessionGuard {
    enum Phase: String {
        case idle, arming, armed, starting, running, stopping, recoveryStopping, blackhole, releasing
        case quarantined
    }

    struct Snapshot: Equatable {
        let phase: Phase
        let identity: TribeNativeGuardIdentity?
        let outerSessionId: String
        let outerPolicySHA256: String
    }

    private let lock = NSLock()
    private var phase: Phase = .idle
    private var identity: TribeNativeGuardIdentity?
    private var outerSessionId = ""
    private var outerPolicySHA256 = ""
    private var armRollbackPhase: Phase?
    private var pendingArmIdentity: TribeNativeGuardIdentity?
    private var pendingArmOuterSessionId = ""
    private var pendingArmPolicySHA256 = ""
    private var releaseRollbackPhase: Phase?
    private var lastReleasedIdentity: TribeNativeGuardIdentity?
    private var lastReleasedOuterSessionId = ""
    // Operation/session are reducer-owned monotonic counters for the lifetime of this provider.
    // A high-water tombstone is sufficient and bounded: an exact or older late PREPARE can never
    // resurrect after timeout reconciliation, while a later fallback session remains legal.
    private var armTombstoneOperation: UInt64 = 0
    private var armTombstoneSession: UInt64 = 0

    static func event(identity: TribeNativeGuardIdentity, kind: String,
                      outerSessionId: String, reason: String) -> [String: Any] {
        [
            "type": "native_session_guard_v1",
            "schema": 1,
            "operation": identity.operation,
            "session": identity.session,
            "kind": kind,
            "policy_sha256": identity.policySHA256,
            "outer_session_id": outerSessionId,
            "expected_runtime_session_id": identity.expectedRuntimeSessionId,
            "reason": reason,
        ]
    }

    func beginArm(_ request: TribeNativeGuardIdentity, outerPolicySHA256 policy: String,
                  generatedOuterSessionId: String = UUID().uuidString.lowercased()) throws {
        lock.lock()
        defer { lock.unlock() }
        guard Self.safeOuter(generatedOuterSessionId), Self.lowerHexSHA256(policy) else {
            throw TribeNativeSessionGuardError.malformedIdentity
        }
        guard !isArmTombstonedLocked(request) else {
            throw TribeNativeSessionGuardError.stale
        }
        if phase != .idle {
            guard phase == .blackhole else { throw TribeNativeSessionGuardError.busy }
            guard outerPolicySHA256 == policy else {
                throw TribeNativeSessionGuardError.outerPolicyChanged
            }
        }
        armRollbackPhase = phase
        pendingArmIdentity = request
        pendingArmOuterSessionId = generatedOuterSessionId
        pendingArmPolicySHA256 = policy
        phase = .arming
    }

    func cancelArm(_ request: TribeNativeGuardIdentity) throws {
        lock.lock()
        defer { lock.unlock() }
        guard phase == .arming, pendingArmIdentity == request,
              let rollback = armRollbackPhase,
              rollback == .idle || rollback == .blackhole else {
            throw TribeNativeSessionGuardError.stale
        }
        phase = rollback
        clearPendingArmLocked()
    }

    func commitArm(_ request: TribeNativeGuardIdentity) throws -> [String: Any] {
        lock.lock()
        defer { lock.unlock() }
        guard phase == .arming, pendingArmIdentity == request,
              let rollback = armRollbackPhase,
              rollback == .idle || rollback == .blackhole else {
            throw TribeNativeSessionGuardError.stale
        }
        identity = request
        outerSessionId = pendingArmOuterSessionId
        outerPolicySHA256 = pendingArmPolicySHA256
        phase = .armed
        clearPendingArmLocked()
        return eventLocked(kind: "armed", reason: "")
    }

    /// Settings were accepted by the OS but the exact state commit could not be completed. The
    /// attempted identity is promoted to quarantine because its routes may own the packet flow.
    /// Returning Lost is intentionally the only truthful terminal receipt in that condition.
    func failArmCommit(_ request: TribeNativeGuardIdentity,
                       reason: String) throws -> [String: Any] {
        lock.lock()
        defer { lock.unlock() }
        guard Self.safeReason(reason) else {
            throw TribeNativeSessionGuardError.malformedIdentity
        }
        if phase == .arming, pendingArmIdentity == request {
            identity = request
            outerSessionId = pendingArmOuterSessionId
            outerPolicySHA256 = pendingArmPolicySHA256
            phase = .quarantined
            clearPendingArmLocked()
            return eventLocked(kind: "lost", reason: reason)
        }
        // Timeout reconciliation may already have promoted this exact reservation to quarantine.
        guard phase == .quarantined, identity == request else {
            throw TribeNativeSessionGuardError.stale
        }
        return eventLocked(kind: "lost", reason: reason)
    }

    /// Synchronous convenience retained for Foundation state tests. Production code must reserve
    /// before `setTunnelNetworkSettings` and commit only from its success callback.
    func arm(_ request: TribeNativeGuardIdentity, outerPolicySHA256 policy: String,
             generatedOuterSessionId: String = UUID().uuidString.lowercased()) throws -> [String: Any] {
        try beginArm(request, outerPolicySHA256: policy,
                     generatedOuterSessionId: generatedOuterSessionId)
        return try commitArm(request)
    }

    func beginActivation(_ request: TribeNativeGuardIdentity, outer: String) throws {
        lock.lock()
        defer { lock.unlock() }
        guard phase == .armed, identity == request, outerSessionId == outer else {
            throw TribeNativeSessionGuardError.stale
        }
        phase = .starting
    }

    func markRunning(expectedRuntimeSessionId: String) throws {
        lock.lock()
        defer { lock.unlock() }
        guard phase == .starting,
              identity?.expectedRuntimeSessionId == expectedRuntimeSessionId else {
            throw TribeNativeSessionGuardError.stale
        }
        phase = .running
    }

    func beginStop(outer: String, expectedRuntimeSessionId: String) throws {
        lock.lock()
        defer { lock.unlock() }
        guard (phase == .running || phase == .starting), outerSessionId == outer,
              identity?.expectedRuntimeSessionId == expectedRuntimeSessionId else {
            throw TribeNativeSessionGuardError.stale
        }
        phase = .stopping
    }

    func markStopped(expectedRuntimeSessionId: String) throws {
        lock.lock()
        defer { lock.unlock() }
        guard phase == .stopping,
              identity?.expectedRuntimeSessionId == expectedRuntimeSessionId else {
            throw TribeNativeSessionGuardError.stale
        }
        phase = .blackhole
    }

    /// Only the callback belonging to the exact ordinary stop may fail that transaction. Late
    /// callbacks from the start being cancelled are fenced while `.stopping`.
    @discardableResult
    func failStop(_ request: TribeNativeGuardIdentity, outer: String,
                  reason: String) throws -> [String: Any] {
        lock.lock()
        defer { lock.unlock() }
        guard phase == .stopping, identity == request, outerSessionId == outer,
              Self.safeReason(reason) else {
            throw TribeNativeSessionGuardError.stale
        }
        let event = eventLocked(kind: "lost", reason: reason)
        phase = .quarantined
        return event
    }

    /// Reserves one exact recovery teardown before an inner stop is dispatched. The separate
    /// phase prevents both duplicate recovery calls and a late ordinary `markStopped` callback
    /// from claiming the recovery transaction. Returns false when no inner can still be live.
    func beginRecoveryStop(_ request: TribeNativeGuardIdentity, outer: String) throws -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard identity == request, outerSessionId == outer else {
            throw TribeNativeSessionGuardError.stale
        }
        guard phase == .armed || phase == .blackhole || phase == .starting
                || phase == .running || phase == .quarantined else {
            throw TribeNativeSessionGuardError.busy
        }
        let needsInnerStop = phase != .armed && phase != .blackhole
        phase = .recoveryStopping
        return needsInnerStop
    }

    /// Only the callback belonging to a reserved recovery teardown may turn the exact owner into
    /// the blackhole state from which the outer Network Extension settings can be released.
    func proveRecoveryStopped(_ request: TribeNativeGuardIdentity, outer: String) throws {
        lock.lock()
        defer { lock.unlock() }
        guard phase == .recoveryStopping, identity == request, outerSessionId == outer else {
            throw TribeNativeSessionGuardError.stale
        }
        phase = .blackhole
    }

    /// The recovery stop callback is the only callback allowed to fail its reservation. Generic
    /// engine callbacks are deliberately fenced while `.recoveryStopping` because cancellation of
    /// a pending start reports through those older callbacks before physical teardown completes.
    @discardableResult
    func failRecoveryStop(_ request: TribeNativeGuardIdentity, outer: String,
                          reason: String) throws -> [String: Any] {
        lock.lock()
        defer { lock.unlock() }
        guard phase == .recoveryStopping, identity == request, outerSessionId == outer,
              Self.safeReason(reason) else {
            throw TribeNativeSessionGuardError.stale
        }
        let event = eventLocked(kind: "lost", reason: reason)
        phase = .quarantined
        return event
    }

    /// Adoption is deliberately narrower than status discovery: a blackhole/quarantined owner is
    /// not a running tunnel, and a stale app must never promote it by replaying an Armed receipt.
    func validateRecoveryAdoption(_ request: TribeNativeGuardIdentity, outer: String) throws {
        lock.lock()
        defer { lock.unlock() }
        guard phase == .running, identity == request, outerSessionId == outer else {
            throw TribeNativeSessionGuardError.stale
        }
    }

    func quarantine(expectedRuntimeSessionId: String) {
        lock.lock()
        defer { lock.unlock() }
        // Once an exact settings-clear reservation exists, callbacks from duplicate/older
        // teardown attempts are stale. They must not destroy the reservation between the OS
        // receipt and commitRelease().
        guard phase != .arming, phase != .stopping, phase != .releasing,
              phase != .recoveryStopping,
              identity?.expectedRuntimeSessionId == expectedRuntimeSessionId else { return }
        phase = .quarantined
    }

    /// Reserves the exact outer owner before the asynchronous NetworkExtension settings clear.
    /// While `.releasing`, no prepare/activate/stop/recovery transition may replace this owner.
    func beginRelease(_ request: TribeNativeGuardIdentity, outer: String) throws {
        lock.lock()
        defer { lock.unlock() }
        guard phase != .quarantined else { throw TribeNativeSessionGuardError.quarantined }
        guard phase == .blackhole || phase == .armed else {
            throw TribeNativeSessionGuardError.innerStillOwned
        }
        guard identity == request, outerSessionId == outer else {
            throw TribeNativeSessionGuardError.stale
        }
        releaseRollbackPhase = phase
        phase = .releasing
    }

    /// Restores the exact pre-clear state only when the OS rejected the settings update.
    func cancelRelease(_ request: TribeNativeGuardIdentity, outer: String) throws {
        lock.lock()
        defer { lock.unlock() }
        guard phase == .releasing, identity == request, outerSessionId == outer,
              let rollback = releaseRollbackPhase,
              rollback == .blackhole || rollback == .armed else {
            throw TribeNativeSessionGuardError.stale
        }
        phase = rollback
        releaseRollbackPhase = nil
    }

    /// Commits Released only after setTunnelNetworkSettings(nil) succeeded for the reservation.
    func commitRelease(_ request: TribeNativeGuardIdentity, outer: String) throws -> [String: Any] {
        lock.lock()
        defer { lock.unlock() }
        guard phase == .releasing, releaseRollbackPhase != nil,
              identity == request, outerSessionId == outer else {
            throw TribeNativeSessionGuardError.stale
        }
        let event = eventLocked(kind: "released", reason: "")
        lastReleasedIdentity = request
        lastReleasedOuterSessionId = outer
        phase = .idle
        identity = nil
        outerSessionId = ""
        outerPolicySHA256 = ""
        releaseRollbackPhase = nil
        return event
    }

    /// Synchronous convenience retained for the Foundation state tests. Production code must use
    /// beginRelease/commitRelease around the asynchronous NetworkExtension settings receipt.
    func release(_ request: TribeNativeGuardIdentity, outer: String) throws -> [String: Any] {
        try beginRelease(request, outer: outer)
        return try commitRelease(request, outer: outer)
    }

    func armedEvent(_ request: TribeNativeGuardIdentity) throws -> [String: Any] {
        lock.lock()
        defer { lock.unlock() }
        guard phase == .armed, identity == request else {
            throw TribeNativeSessionGuardError.stale
        }
        return eventLocked(kind: "armed", reason: "")
    }

    func lostEvent(reason: String) -> [String: Any]? {
        lock.lock()
        defer { lock.unlock() }
        // release is an atomic reservation/OS-receipt/commit transaction. A late engine or
        // duplicate recovery callback cannot revoke it after setTunnelNetworkSettings(nil) was
        // issued for the exact owner.
        guard phase != .arming, phase != .stopping, phase != .releasing,
              phase != .recoveryStopping,
              identity != nil, Self.safeReason(reason) else { return nil }
        let event = eventLocked(kind: "lost", reason: reason)
        phase = .quarantined
        return event
    }

    func snapshot() -> Snapshot {
        lock.lock()
        defer { lock.unlock() }
        return Snapshot(phase: phase, identity: identity, outerSessionId: outerSessionId,
                        outerPolicySHA256: outerPolicySHA256)
    }

    /// Exact reconciliation for a PREPARE whose ordinary reply exceeded the app-owned deadline.
    /// - Existing exact owner: Armed proves ownership.
    /// - Exact in-flight settings mutation: Lost quarantines the possibly-applied settings.
    /// - Proven absence: ArmRejected also writes a monotonic tombstone before replying, so the
    ///   delayed PREPARE callback cannot resurrect this identity afterward.
    /// - Any replacement/mismatch: nil; the caller must remain fail-closed and recover explicitly.
    func reconcileTimedOutArm(_ request: TribeNativeGuardIdentity) -> [String: Any]? {
        lock.lock()
        defer { lock.unlock() }
        if phase == .arming, pendingArmIdentity == request {
            identity = request
            outerSessionId = pendingArmOuterSessionId
            outerPolicySHA256 = pendingArmPolicySHA256
            phase = .quarantined
            clearPendingArmLocked()
            return eventLocked(kind: "lost", reason: "arm_timeout_ambiguous")
        }
        if identity == request {
            guard phase != .idle else { return nil }
            return eventLocked(kind: phase == .quarantined ? "lost" : "armed",
                               reason: phase == .quarantined
                                   ? "guard_quarantined" : "reconciled_present")
        }
        guard phase == .idle, identity == nil, pendingArmIdentity == nil else { return nil }
        advanceArmTombstoneLocked(request)
        return Self.event(identity: request, kind: "arm_rejected", outerSessionId: "",
                          reason: "reconciled_absent")
    }

    /// Exact reconciliation for a RELEASE whose ordinary reply exceeded the app-owned deadline.
    /// Released is returned only from an exact release tombstone. A retained exact owner returns
    /// ReleaseRejected; an in-flight OS settings clear stays unanswered/ambiguous until its own
    /// callback supplies the authoritative Released or ReleaseRejected receipt.
    func reconcileTimedOutRelease(_ request: TribeNativeGuardIdentity,
                                  outer: String) -> [String: Any]? {
        lock.lock()
        defer { lock.unlock() }
        guard Self.safeOuter(outer) else { return nil }
        if identity == request, outerSessionId == outer {
            guard phase != .idle else { return nil }
            // The OS settings callback is still authoritative. A query cannot prove whether the
            // asynchronous clear will ultimately commit; retain the reservation and accept its
            // late exact Released/ReleaseRejected receipt.
            if phase == .releasing { return nil }
            return eventLocked(kind: "release_rejected",
                               reason: "reconciled_retained")
        }
        if phase == .idle, identity == nil, pendingArmIdentity == nil,
           lastReleasedIdentity == request, lastReleasedOuterSessionId == outer {
            return Self.event(identity: request, kind: "released", outerSessionId: outer,
                              reason: "reconciled_released")
        }
        return nil
    }

    private func eventLocked(kind: String, reason: String) -> [String: Any] {
        guard let identity else { return [:] }
        return Self.event(identity: identity, kind: kind,
                          outerSessionId: outerSessionId, reason: reason)
    }

    private func clearPendingArmLocked() {
        armRollbackPhase = nil
        pendingArmIdentity = nil
        pendingArmOuterSessionId = ""
        pendingArmPolicySHA256 = ""
    }

    private func isArmTombstonedLocked(_ request: TribeNativeGuardIdentity) -> Bool {
        guard let operation = UInt64(request.operation),
              let session = UInt64(request.session), armTombstoneOperation != 0 else {
            return false
        }
        return operation < armTombstoneOperation
            || (operation == armTombstoneOperation && session <= armTombstoneSession)
    }

    private func advanceArmTombstoneLocked(_ request: TribeNativeGuardIdentity) {
        guard let operation = UInt64(request.operation),
              let session = UInt64(request.session) else { return }
        if operation > armTombstoneOperation
            || (operation == armTombstoneOperation && session > armTombstoneSession) {
            armTombstoneOperation = operation
            armTombstoneSession = session
        }
    }

    private static func safeOuter(_ value: String) -> Bool {
        !value.isEmpty && value.count <= 200 && value.unicodeScalars.allSatisfy {
            let c = $0.value
            return (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a)
                || (c >= 0x30 && c <= 0x39) || c == 0x2d || c == 0x5f
                || c == 0x3a || c == 0x2e
        }
    }

    private static func safeReason(_ value: String) -> Bool {
        value.utf8.count <= 96 && value.utf8.allSatisfy { $0 >= 0x20 && $0 <= 0x7e }
    }

    private static func lowerHexSHA256(_ value: String) -> Bool {
        value.count == 64 && value.allSatisfy {
            ($0 >= "0" && $0 <= "9") || ($0 >= "a" && $0 <= "f")
        }
    }
}
