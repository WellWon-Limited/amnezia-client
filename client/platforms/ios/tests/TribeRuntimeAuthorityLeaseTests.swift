import Foundation

private func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
    guard condition() else { fputs("FAIL: \(message)\n", stderr); exit(1) }
}

private func iso(_ value: Date) -> String {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return formatter.string(from: value)
}

private func configuration(now: Date, revision: String = "10",
                           payload: String = String(repeating: "b", count: 64),
                           deadlineOffset: TimeInterval = 3_600,
                           trustedOffset: TimeInterval = 0,
                           issuedOffset: TimeInterval = -60) -> [String: Any] {
    let policy = "cdf8bfa93fa7229db48163015f5923a75bf63124295e1da9edca619fd614f31d"
    let deadline = iso(now.addingTimeInterval(deadlineOffset))
    return [
        "native_envelope_schema": "tribe_catalog_v2_native_v1",
        "protocol": "awg",
        "hostName": "203.0.113.10",
        "dns1": "1.1.1.1",
        "dns2": "8.8.8.8",
        "config_version": 1,
        "splitTunnelType": 0,
        "splitTunnelSites": [String](),
        "appSplitTunnelType": 0,
        "splitTunnelApps": [String](),
        "awg_config_data": [
            "config": "private\n", "client_ip": "10.0.0.2/32",
            "mtu": "1280", "port": 51_820,
        ],
        "runtime_authority_v1": [
            "schema_version": 1,
            "device_audience": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "catalog_revision": revision,
            "catalog_payload_sha256": payload,
            "catalog_signing_kid": "key-1",
            "catalog_source": "network",
            "profile_id": "profile-1",
            "transport": "awg",
            "config_generation": "1",
            "binding_generation": "1",
            "native_profile_expires_at": deadline,
            "catalog_freshness_deadline": deadline,
            "entitlement_deadline": deadline,
            "catalog_issued_at": iso(now.addingTimeInterval(issuedOffset)),
            "trusted_utc_at_dispatch": iso(now.addingTimeInterval(trustedOffset)),
            "policy_schema": "native_dispatch_policy_v1",
            "policy_sha256": policy,
            "protected_tunnel_ips": ["1.1.1.1"],
            "receiver_monotonic_policy": "anchor_on_validated_dispatch_v1",
        ],
    ]
}

private enum PersistenceFailure: Error { case injected }

@main
private struct RuntimeAuthorityLeaseTests {
    static func main() throws {
        let now = Date()
        let lease = try TribeRuntimeAuthorityLease(
            configuration: configuration(now: now), wallUtc: now, monotonic: 100)
        try lease.evaluate(wallUtc: now.addingTimeInterval(120), monotonic: 220)
        expect(lease.snapshot().catalogRevision == 10, "initial revision captured")
        for protected in [[String](), ["1.1.1.1", "1.1.1.1"], ["10.0.0.1"]] {
            var invalid = configuration(now: now)
            var authority = invalid["runtime_authority_v1"] as! [String: Any]
            authority["protected_tunnel_ips"] = protected
            invalid["runtime_authority_v1"] = authority
            do {
                _ = try TribeRuntimeAuthorityLease(
                    configuration: invalid, wallUtc: now, monotonic: 100)
                expect(false, "invalid protected_tunnel_ips accepted: \(protected)")
            } catch TribeNativePolicyError.malformed {
            } catch TribeRuntimeAuthorityLeaseError.malformed {
            }
        }
        try lease.reconcileRecovery(configuration: configuration(now: now),
                                    wallUtc: now.addingTimeInterval(1), monotonic: 101)
        expect(lease.snapshot().catalogRevision == 10,
               "byte-identical relaunch authority reconciled")

        var equalPersisted = false
        try lease.renew(configuration: configuration(now: now),
                        wallUtc: now.addingTimeInterval(1), monotonic: 101) { _ in
            equalPersisted = true
        }
        expect(equalPersisted && abs(lease.snapshot().hardDeadline.timeIntervalSince(
            now.addingTimeInterval(3_600))) < 0.001,
            "equal metadata/deadline refresh is valid while still current")

        do {
            try lease.evaluate(wallUtc: now.addingTimeInterval(-301), monotonic: 101)
            expect(false, "wall-clock rollback accepted")
        } catch TribeRuntimeAuthorityLeaseError.clockRollback {}

        do {
            try lease.evaluate(wallUtc: now.addingTimeInterval(3_601), monotonic: 3_701)
            expect(false, "expired authority accepted")
        } catch TribeRuntimeAuthorityLeaseError.expired {}

        let renewed = configuration(
            now: now, revision: "11", payload: String(repeating: "c", count: 64),
            deadlineOffset: 1_800, trustedOffset: 30, issuedOffset: -30)
        var persistedRevision: UInt64 = 0
        try lease.renew(configuration: renewed,
                        wallUtc: now.addingTimeInterval(30), monotonic: 130) { replacement in
            persistedRevision = replacement.catalogRevision
        }
        expect(persistedRevision == 11, "replacement persisted before commit")
        expect(lease.snapshot().catalogRevision == 11, "newer authority applied")
        expect(abs(lease.snapshot().hardDeadline.timeIntervalSince(
            now.addingTimeInterval(1_800))) < 0.001,
               "signed refresh may shorten the hard deadline for revocation")

        do {
            try lease.renew(configuration: configuration(
                now: now, revision: "12", payload: String(repeating: "e", count: 64),
                deadlineOffset: 9_000, trustedOffset: 60, issuedOffset: -10),
                wallUtc: now.addingTimeInterval(60), monotonic: 160) { _ in
                    throw PersistenceFailure.injected
                }
            expect(false, "renewal survived durable persistence failure")
        } catch PersistenceFailure.injected {}
        expect(lease.snapshot().catalogRevision == 11,
               "durable failure changed the live authority")

        do {
            try lease.renew(configuration: configuration(
                now: now, revision: "10", deadlineOffset: 10_000,
                trustedOffset: 60, issuedOffset: -10),
                wallUtc: now.addingTimeInterval(60), monotonic: 160) { _ in
                    expect(false, "stale renewal reached persistence")
                }
            expect(false, "stale catalog revision renewed")
        } catch TribeRuntimeAuthorityLeaseError.staleRevision {}

        do {
            try lease.renew(configuration: configuration(
                now: now, revision: "11", payload: String(repeating: "d", count: 64),
                deadlineOffset: 10_000, trustedOffset: 60, issuedOffset: -10),
                wallUtc: now.addingTimeInterval(60), monotonic: 160) { _ in
                    expect(false, "colliding renewal reached persistence")
                }
            expect(false, "same revision with colliding payload identity renewed")
        } catch TribeRuntimeAuthorityLeaseError.staleRevision {}

        print("Apple runtime authority lease tests passed")
    }
}
