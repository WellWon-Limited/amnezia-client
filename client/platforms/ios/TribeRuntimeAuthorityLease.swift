import Foundation

enum TribeRuntimeAuthorityLeaseError: Error, Equatable {
    case malformed
    case expired
    case identityChanged
    case staleRevision
    case clockRollback
}

struct TribeRuntimeAuthorityLeaseSnapshot: Equatable {
    let profileId: String
    let transport: String
    let configGeneration: String
    let bindingGeneration: String
    let policySHA256: String
    let catalogRevision: UInt64
    let catalogPayloadSHA256: String
    let catalogSigningKid: String
    let hardDeadline: Date
    let trustedUtcAtDispatch: Date
    let catalogIssuedAt: Date
    let capturedWallUtc: Date
    let capturedMonotonic: TimeInterval
}

/// Process-lifetime trusted-time lease for a running NE session.  It never treats wall-clock
/// rollback as extra authority. Persistent cross-boot adoption remains a separate release gate.
final class TribeRuntimeAuthorityLease {
    private let lock = NSLock()
    private var value: TribeRuntimeAuthorityLeaseSnapshot

    init(configuration: [String: Any], wallUtc: Date = Date(),
         monotonic: TimeInterval = ProcessInfo.processInfo.systemUptime) throws {
        value = try Self.parse(configuration, wallUtc: wallUtc, monotonic: monotonic)
    }

    func snapshot() -> TribeRuntimeAuthorityLeaseSnapshot {
        lock.lock(); defer { lock.unlock() }
        return value
    }

    func evaluate(wallUtc: Date = Date(),
                  monotonic: TimeInterval = ProcessInfo.processInfo.systemUptime) throws {
        lock.lock(); defer { lock.unlock() }
        try Self.evaluate(value, wallUtc: wallUtc, monotonic: monotonic)
    }

    @discardableResult
    func renew(configuration: [String: Any], wallUtc: Date = Date(),
               monotonic: TimeInterval = ProcessInfo.processInfo.systemUptime,
               persist: (TribeRuntimeAuthorityLeaseSnapshot) throws -> Void) throws
        -> TribeRuntimeAuthorityLeaseSnapshot {
        let replacement = try Self.parse(configuration, wallUtc: wallUtc, monotonic: monotonic)
        lock.lock(); defer { lock.unlock() }
        try Self.evaluate(value, wallUtc: wallUtc, monotonic: monotonic)
        guard replacement.profileId == value.profileId,
              replacement.transport == value.transport,
              replacement.configGeneration == value.configGeneration,
              replacement.bindingGeneration == value.bindingGeneration,
              replacement.policySHA256 == value.policySHA256 else {
            throw TribeRuntimeAuthorityLeaseError.identityChanged
        }
        guard replacement.catalogRevision >= value.catalogRevision else {
            throw TribeRuntimeAuthorityLeaseError.staleRevision
        }
        if replacement.catalogRevision == value.catalogRevision {
            guard replacement.catalogPayloadSHA256 == value.catalogPayloadSHA256,
                  replacement.catalogSigningKid == value.catalogSigningKid else {
                throw TribeRuntimeAuthorityLeaseError.staleRevision
            }
        }
        guard replacement.trustedUtcAtDispatch >= value.trustedUtcAtDispatch,
              replacement.catalogIssuedAt >= value.catalogIssuedAt else {
            throw TribeRuntimeAuthorityLeaseError.staleRevision
        }
        // Deadline is not an anti-rollback high-water mark. A signed refresh may preserve it,
        // extend it, or shorten it for entitlement/profile revocation. parse() already proves the
        // replacement deadline is strictly after effective trusted time for this invocation.
        // The caller must durably commit the exact replacement before this live lease changes.
        // If persistence throws, the old watchdog authority remains byte-for-byte intact.
        try persist(replacement)
        value = replacement
        return replacement
    }

    /// Reconciles an app-process relaunch with the still-running provider. Equal authority is
    /// accepted because this is adoption, not a lease extension; stale/colliding identity is not.
    func reconcileRecovery(configuration: [String: Any], wallUtc: Date = Date(),
                           monotonic: TimeInterval = ProcessInfo.processInfo.systemUptime) throws {
        let replacement = try Self.parse(configuration, wallUtc: wallUtc, monotonic: monotonic)
        lock.lock(); defer { lock.unlock() }
        try Self.evaluate(value, wallUtc: wallUtc, monotonic: monotonic)
        guard replacement.profileId == value.profileId,
              replacement.transport == value.transport,
              replacement.configGeneration == value.configGeneration,
              replacement.bindingGeneration == value.bindingGeneration,
              replacement.policySHA256 == value.policySHA256 else {
            throw TribeRuntimeAuthorityLeaseError.identityChanged
        }
        guard replacement.catalogRevision >= value.catalogRevision else {
            throw TribeRuntimeAuthorityLeaseError.staleRevision
        }
        if replacement.catalogRevision == value.catalogRevision {
            guard replacement.catalogPayloadSHA256 == value.catalogPayloadSHA256,
                  replacement.catalogSigningKid == value.catalogSigningKid else {
                throw TribeRuntimeAuthorityLeaseError.staleRevision
            }
        }
        guard replacement.trustedUtcAtDispatch >= value.trustedUtcAtDispatch,
              replacement.catalogIssuedAt >= value.catalogIssuedAt else {
            throw TribeRuntimeAuthorityLeaseError.staleRevision
        }
        value = replacement
    }

    private static func evaluate(_ lease: TribeRuntimeAuthorityLeaseSnapshot,
                                 wallUtc: Date, monotonic: TimeInterval) throws {
        _ = try TribeRuntimeAuthorityWatchdogPlanner.remaining(
            snapshot: lease, wallUtc: wallUtc, monotonic: monotonic)
    }

    private static func parse(_ root: [String: Any], wallUtc: Date,
                              monotonic: TimeInterval) throws
        -> TribeRuntimeAuthorityLeaseSnapshot {
        guard try TribeNativeDispatchPolicy.validateEnvelope(root),
              let authority = root["runtime_authority_v1"] as? [String: Any],
              let profileId = authority["profile_id"] as? String,
              let transport = authority["transport"] as? String,
              let configGeneration = authority["config_generation"] as? String,
              let bindingGeneration = authority["binding_generation"] as? String,
              let policy = authority["policy_sha256"] as? String,
              let revisionText = authority["catalog_revision"] as? String,
              canonicalDecimal(revisionText), let revision = UInt64(revisionText), revision > 0,
              let payload = authority["catalog_payload_sha256"] as? String,
              let signingKid = authority["catalog_signing_kid"] as? String,
              let nativeExpiry = date(authority["native_profile_expires_at"]),
              let freshness = date(authority["catalog_freshness_deadline"]),
              let entitlement = date(authority["entitlement_deadline"]),
              let trusted = date(authority["trusted_utc_at_dispatch"]),
              let issued = date(authority["catalog_issued_at"]),
              monotonic.isFinite, monotonic >= 0 else {
            throw TribeRuntimeAuthorityLeaseError.malformed
        }
        let deadline = min(nativeExpiry, freshness, entitlement)
        let snapshot = TribeRuntimeAuthorityLeaseSnapshot(
            profileId: profileId, transport: transport,
            configGeneration: configGeneration, bindingGeneration: bindingGeneration,
            policySHA256: policy, catalogRevision: revision,
            catalogPayloadSHA256: payload, catalogSigningKid: signingKid,
            hardDeadline: deadline, trustedUtcAtDispatch: trusted,
            catalogIssuedAt: issued, capturedWallUtc: wallUtc,
            capturedMonotonic: monotonic)
        try evaluate(snapshot, wallUtc: wallUtc, monotonic: monotonic)
        return snapshot
    }

    private static func canonicalDecimal(_ value: String) -> Bool {
        !value.isEmpty && value.count <= 20 && (value == "0" || value.first != "0")
            && value.allSatisfy { $0 >= "0" && $0 <= "9" }
            && UInt64(value).map { String($0) == value } == true
    }

    private static func date(_ value: Any?) -> Date? {
        guard let text = value as? String, text.utf8.count <= 40 else { return nil }
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let parsed = fractional.date(from: text) { return parsed }
        let plain = ISO8601DateFormatter()
        plain.formatOptions = [.withInternetDateTime]
        return plain.date(from: text)
    }
}
