import Foundation

private func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
    guard condition() else { fputs("FAIL: \(message)\n", stderr); exit(1) }
}

private func iso(_ value: Date) -> String {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return formatter.string(from: value)
}

private func config(_ now: Date, revision: String = "10",
                    payload: String = String(repeating: "b", count: 64),
                    deadline: TimeInterval = 3_600) -> [String: Any] {
    let expiry = iso(now.addingTimeInterval(deadline))
    return [
        "native_envelope_schema": "tribe_catalog_v2_native_v1", "protocol": "awg",
        "hostName": "203.0.113.10", "dns1": "1.1.1.1", "dns2": "8.8.8.8",
        "config_version": 1, "splitTunnelType": 0, "splitTunnelSites": [String](),
        "appSplitTunnelType": 0, "splitTunnelApps": [String](),
        "awg_config_data": ["config": "private\n", "client_ip": "10.0.0.2/32",
                            "mtu": "1280", "port": 51_820],
        "runtime_authority_v1": [
            "schema_version": 1,
            "device_audience": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "catalog_revision": revision, "catalog_payload_sha256": payload,
            "catalog_signing_kid": "key-1", "catalog_source": "network",
            "profile_id": "profile-1", "transport": "awg",
            "config_generation": "1", "binding_generation": "1",
            "native_profile_expires_at": expiry,
            "catalog_freshness_deadline": expiry, "entitlement_deadline": expiry,
            "catalog_issued_at": iso(now.addingTimeInterval(-60)),
            "trusted_utc_at_dispatch": iso(now),
            "policy_schema": "native_dispatch_policy_v1",
            "policy_sha256": "cdf8bfa93fa7229db48163015f5923a75bf63124295e1da9edca619fd614f31d",
            "protected_tunnel_ips": ["1.1.1.1"],
            "receiver_monotonic_policy": "anchor_on_validated_dispatch_v1",
        ],
    ]
}

private func request(_ root: [String: Any], serialized: Data,
                     _ snapshot: TribeRuntimeAuthorityLeaseSnapshot,
                     renewalId: String = "123e4567-e89b-42d3-a456-426614174010") throws
    -> TribeRuntimeAuthorityRenewalRequest {
    let authority = root["runtime_authority_v1"] as! [String: Any]
    return try TribeRuntimeAuthorityRenewalRequest(fields: [
        "type": TribeRuntimeAuthorityRenewalRequest.type, "schema": 1,
        "operation": "7", "session": "9", "renewal_id": renewalId,
        "policy_sha256": authority["policy_sha256"]!,
        "outer_session_id": "provider:123e4567-e89b-42d3-a456-426614174020",
        "expected_runtime_session_id": "123e4567-e89b-42d3-a456-426614174000",
        "config_generation": authority["config_generation"]!,
        "binding_generation": authority["binding_generation"]!,
        "catalog_revision": authority["catalog_revision"]!,
        "catalog_payload_sha256": authority["catalog_payload_sha256"]!,
        "authority_commitment_sha256": TribeRuntimeAuthorityRenewalRequest
            .authorityCommitmentSHA256(serialized),
        "hard_deadline": TribeRuntimeAuthorityRenewalRequest
            .formatDeadline(snapshot.hardDeadline),
    ])
}

@main
private struct RuntimeAuthorityRenewalTests {
    static func main() throws {
        let now = Date()
        let initialBytes = try JSONSerialization.data(
            withJSONObject: config(now), options: [.sortedKeys])
        let initial = try JSONSerialization.jsonObject(with: initialBytes) as! [String: Any]
        let lease = try TribeRuntimeAuthorityLease(
            configuration: initial, wallUtc: now, monotonic: 100)
        let exact = try request(initial, serialized: initialBytes, lease.snapshot())
        try exact.validate(configuration: initial, serializedConfiguration: initialBytes,
                           snapshot: lease.snapshot())
        expect(exact.fields().keys.count == 14, "request is not closed-schema")

        let applied = TribeRuntimeAuthorityRenewalReceipt.applied(exact)
        let parsed = try TribeRuntimeAuthorityRenewalReceipt(fields: applied.fields())
        expect(parsed.fields().keys.count == 16 && parsed.matches(exact),
               "applied receipt did not echo the exact request")

        let wrong = try request(
            initial, serialized: initialBytes, lease.snapshot(),
            renewalId: "123e4567-e89b-42d3-a456-426614174011")
        expect(!parsed.matches(wrong), "wrong renewal id matched an applied receipt")
        var unexpected = applied.fields()
        unexpected["future"] = true
        do {
            _ = try TribeRuntimeAuthorityRenewalReceipt(fields: unexpected)
            expect(false, "receipt with an unknown field was accepted")
        } catch TribeRuntimeAuthorityRenewalError.malformed {}

        let rejected = TribeRuntimeAuthorityRenewalReceipt.rejected(
            exact, reason: "renewal_rejected")
        let parsedRejected = try TribeRuntimeAuthorityRenewalReceipt(fields: rejected.fields())
        expect(parsedRejected.hardDeadline.isEmpty && parsedRejected.matches(exact),
               "failure receipt lost exact identity or exposed a deadline")

        print("Apple runtime authority renewal contract tests passed")
    }
}
