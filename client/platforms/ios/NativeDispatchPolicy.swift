import CoreFoundation
import CryptoKit
import Darwin
import Foundation

enum TribeNativePolicyError: Error {
    case malformed
    case expired
    case digestMismatch
}

/// Swift mirror of NativeDispatchPolicyDigest.cpp. Catalog-v2 profiles are
/// accepted by the privileged Network Extension only when the native policy
/// projection still hashes to the value signed/compiled by the app.
enum TribeNativeDispatchPolicy {
    static let envelopeV2 = "tribe_catalog_v2_native_v1"
    static let envelopeLegacy = "amnezia_legacy_native_v1"
    static let policySchema = "native_dispatch_policy_v1"
    private static let header = Data("tribe-native-dispatch-policy-v1\n".utf8)
    private static let maximumProjectionBytes = 512 * 1024

    /// Returns true for catalog-v2 and false only for the positively-marked
    /// legacy/manual path. Missing or stripped discriminators never downgrade.
    static func validateEnvelope(_ root: [String: Any]) throws -> Bool {
        guard let envelope = root["native_envelope_schema"] as? String else {
            throw TribeNativePolicyError.malformed
        }
        if envelope == envelopeLegacy {
            guard root["runtime_authority_v1"] == nil else {
                throw TribeNativePolicyError.malformed
            }
            return false
        }
        guard envelope == envelopeV2,
              let authority = root["runtime_authority_v1"] as? [String: Any] else {
            throw TribeNativePolicyError.malformed
        }
        try validateAuthority(authority, root: root)
        return true
    }

    /// Hash of the OS-level policy that must remain invariant while one Network Extension keeps
    /// the default routes as a blackhole across an AWG↔Xray inner switch. Bearer/core bytes and
    /// endpoints are intentionally excluded; DNS, split routes and protected verifier routes are
    /// not. Per-app split is rejected because an NE provider cannot prove app-rule readback here.
    static func outerPolicySHA256(_ root: [String: Any]) throws -> String {
        guard try validateEnvelope(root),
              let authority = root["runtime_authority_v1"] as? [String: Any],
              let transport = authority["transport"] as? String,
              let dns1 = root["dns1"] as? String,
              let dns2 = root["dns2"] as? String,
              let splitType = integer(root["splitTunnelType"], minimum: 0, maximum: 2),
              let appSplitType = integer(root["appSplitTunnelType"], minimum: 0, maximum: 0),
              let protected = authority["protected_tunnel_ips"] as? [String],
              !protected.isEmpty else {
            throw TribeNativePolicyError.malformed
        }
        let mtu: String
        if transport == "awg" {
            guard let native = root["awg_config_data"] as? [String: Any],
                  let value = native["mtu"] as? String, value == "1280" else {
                throw TribeNativePolicyError.malformed
            }
            mtu = value
        } else {
            mtu = "1280"
        }
        var bytes = Data("tribe-apple-outer-policy-v1\n".utf8)
        func record(_ name: String, _ value: String) throws {
            guard !value.unicodeScalars.contains(where: { $0.value == 0 }) else {
                throw TribeNativePolicyError.malformed
            }
            let valueBytes = Data(value.utf8)
            bytes.append(Data("\(name):\(valueBytes.count):".utf8))
            bytes.append(valueBytes)
            bytes.append(0x0a)
            guard bytes.count <= maximumProjectionBytes else {
                throw TribeNativePolicyError.malformed
            }
        }
        func list(_ name: String, _ values: [String]) throws {
            let sorted = values.sorted { Data($0.utf8).lexicographicallyPrecedes(Data($1.utf8)) }
            try record("\(name)_count", String(sorted.count))
            for (index, value) in sorted.enumerated() {
                try record("\(name)_\(index)", value)
            }
        }
        try record("dns1", dns1)
        try record("dns2", dns2)
        try record("mtu", mtu)
        try record("split_tunnel_type", splitType)
        try list("split_site", try stringList(root, "splitTunnelSites"))
        try record("app_split_tunnel_type", appSplitType)
        try list("split_app", try stringList(root, "splitTunnelApps"))
        try list("split_dns_suffix", try stringList(root, "splitDnsSuffixes", optional: true))
        try record("split_dns_server", try optionalString(root, "splitDnsServer"))
        try record("dns_forward_on", try optionalString(root, "dnsFwdOn"))
        try record("dns_forward_suffixes", try optionalString(root, "dnsFwdSuffixes"))
        try record("dns_forward_server", try optionalString(root, "dnsFwdServer"))
        try record("dns_forward_warmup", try optionalString(root, "dnsFwdWarmup"))
        try record("kill_switch", try optionalString(root, "killSwitchOption"))
        try list("allowed_dns", try stringList(root, "allowedDnsServers", optional: true))
        try list("protected_tunnel_ip", protected)
        return hexDigest(bytes)
    }

    private static func validateAuthority(_ authority: [String: Any],
                                          root: [String: Any]) throws {
        let expected: Set<String> = [
            "schema_version", "device_audience", "catalog_revision",
            "catalog_payload_sha256", "catalog_signing_kid", "catalog_source",
            "profile_id", "transport", "config_generation", "binding_generation",
            "native_profile_expires_at", "catalog_freshness_deadline",
            "entitlement_deadline", "catalog_issued_at", "trusted_utc_at_dispatch",
            "policy_schema", "policy_sha256", "protected_tunnel_ips",
            "receiver_monotonic_policy",
        ]
        guard Set(authority.keys) == expected,
              integer(authority["schema_version"], minimum: 1, maximum: 1) == "1",
              let audience = authority["device_audience"] as? String,
              audience.utf8.count == 43,
              audience.range(of: "^[A-Za-z0-9_-]{43}$", options: .regularExpression) != nil,
              Data(base64Encoded: audience.replacingOccurrences(of: "-", with: "+")
                    .replacingOccurrences(of: "_", with: "/") + "=")?.count == 32,
              let source = authority["catalog_source"] as? String,
              source == "network" || source == "lkg",
              let transport = authority["transport"] as? String,
              transport == "awg" || transport == "xray",
              root["protocol"] as? String == transport,
              let profileId = safeIdentifier(authority["profile_id"], maximum: 96),
              !profileId.isEmpty,
              safeIdentifier(authority["catalog_signing_kid"], maximum: 96) != nil,
              canonicalDecimal(authority["catalog_revision"], allowZero: false) != nil,
              canonicalDecimal(authority["config_generation"], allowZero: false) != nil,
              canonicalDecimal(authority["binding_generation"], allowZero: false) != nil,
              sha256Text(authority["catalog_payload_sha256"]) != nil,
              let expectedDigest = sha256Text(authority["policy_sha256"]),
              authority["policy_schema"] as? String == policySchema,
              authority["receiver_monotonic_policy"] as? String
                == "anchor_on_validated_dispatch_v1",
              let protectedIps = authority["protected_tunnel_ips"] as? [Any],
              !protectedIps.isEmpty, protectedIps.count <= 64,
              protectedIps.allSatisfy({ value in
                  guard let text = value as? String else { return false }
                  return isPublicEndpointLiteral(text)
              }),
              Set(protectedIps.compactMap { $0 as? String }).count == protectedIps.count,
              let nativeExpiry = utcDate(authority["native_profile_expires_at"]),
              let freshness = utcDate(authority["catalog_freshness_deadline"]),
              let entitlement = utcDate(authority["entitlement_deadline"]),
              let issued = utcDate(authority["catalog_issued_at"]),
              let trusted = utcDate(authority["trusted_utc_at_dispatch"]) else {
            throw TribeNativePolicyError.malformed
        }
        let deadline = min(nativeExpiry, freshness, entitlement)
        let now = Date()
        guard issued <= trusted.addingTimeInterval(300),
              trusted < deadline,
              now >= issued.addingTimeInterval(-300),
              now >= trusted.addingTimeInterval(-300),
              now < deadline else {
            throw TribeNativePolicyError.expired
        }
        guard try digest(root: root, authority: authority, protectedIps: protectedIps)
                == expectedDigest else {
            throw TribeNativePolicyError.digestMismatch
        }
    }

    private static func digest(root: [String: Any], authority: [String: Any],
                               protectedIps: [Any]) throws -> String {
        guard let transport = authority["transport"] as? String,
              let profileId = authority["profile_id"] as? String,
              let configGeneration = authority["config_generation"] as? String,
              let bindingGeneration = authority["binding_generation"] as? String,
              let endpointHost = root["hostName"] as? String,
              let dns1 = root["dns1"] as? String,
              let dns2 = root["dns2"] as? String else {
            throw TribeNativePolicyError.malformed
        }
        let dataKey = transport == "awg" ? "awg_config_data" : "xray_config_data"
        guard let native = root[dataKey] as? [String: Any],
              let nativeConfig = native["config"] as? String else {
            throw TribeNativePolicyError.malformed
        }
        let endpointPort: String
        let mtu: String
        let tunnelAddress: String
        let xrayMemory: String
        if transport == "awg" {
            guard let address = native["client_ip"] as? String,
                  let mtuText = native["mtu"] as? String,
                  Int(mtuText).map({ (576...1500).contains($0) && String($0) == mtuText }) == true,
                  let port = integer(native["port"], minimum: 1, maximum: 65_535) else {
                throw TribeNativePolicyError.malformed
            }
            tunnelAddress = address
            mtu = mtuText
            endpointPort = port
            xrayMemory = "0"
        } else {
            endpointPort = try xrayEndpointPort(nativeConfig)
            tunnelAddress = ""
            mtu = "0"
            guard let memory = integer(root["xray_max_memory_bytes"],
                                       minimum: 8 * 1024 * 1024,
                                       maximum: 1024 * 1024 * 1024) else {
                throw TribeNativePolicyError.malformed
            }
            xrayMemory = memory
        }

        var encoded = header
        func record(_ name: String, _ value: String) throws {
            guard !value.unicodeScalars.contains(where: { $0.value == 0 }) else {
                throw TribeNativePolicyError.malformed
            }
            let bytes = Data(value.utf8)
            guard bytes.count <= 256 * 1024 else { throw TribeNativePolicyError.malformed }
            encoded.append(Data("\(name):\(bytes.count):".utf8))
            encoded.append(bytes)
            encoded.append(0x0a)
            guard encoded.count <= maximumProjectionBytes else {
                throw TribeNativePolicyError.malformed
            }
        }
        func list(_ name: String, _ values: [String]) throws {
            let sorted = values.sorted { Data($0.utf8).lexicographicallyPrecedes(Data($1.utf8)) }
            try record("\(name)_count", String(sorted.count))
            for (index, value) in sorted.enumerated() { try record("\(name)_\(index)", value) }
        }
        func requiredInteger(_ key: String, _ minimum: Int64, _ maximum: Int64) throws -> String {
            guard let value = integer(root[key], minimum: minimum, maximum: maximum) else {
                throw TribeNativePolicyError.malformed
            }
            return value
        }

        try record("transport", transport)
        try record("native_envelope_schema", envelopeV2)
        try record("profile_id", profileId)
        try record("config_generation", configGeneration)
        try record("binding_generation", bindingGeneration)
        try record("endpoint_host", endpointHost)
        try record("endpoint_port", endpointPort)
        try record("tunnel_address", tunnelAddress)
        try record("dns1", dns1)
        try record("dns2", dns2)
        try record("mtu", mtu)
        try record("config_version", requiredInteger("config_version", 0, 9_007_199_254_740_991))
        try record("xray_max_memory_bytes", xrayMemory)
        try record("split_tunnel_type", requiredInteger("splitTunnelType", 0, 2))
        try list("split_site", try stringList(root, "splitTunnelSites"))
        try record("app_split_tunnel_type", requiredInteger("appSplitTunnelType", 0, 2))
        try list("split_app", try stringList(root, "splitTunnelApps"))
        try list("split_dns_suffix", try stringList(root, "splitDnsSuffixes", optional: true))
        try record("split_dns_server", try optionalString(root, "splitDnsServer"))
        try record("dns_forward_on", try optionalString(root, "dnsFwdOn"))
        try record("dns_forward_suffixes", try optionalString(root, "dnsFwdSuffixes"))
        try record("dns_forward_server", try optionalString(root, "dnsFwdServer"))
        try record("dns_forward_warmup", try optionalString(root, "dnsFwdWarmup"))
        try record("kill_switch", try optionalString(root, "killSwitchOption"))
        try list("allowed_dns", try stringList(root, "allowedDnsServers", optional: true))
        try list("protected_tunnel_ip", protectedIps.compactMap { $0 as? String })
        try record("native_config_sha256", hexDigest(Data(nativeConfig.utf8)))
        return hexDigest(encoded)
    }

    private static func xrayEndpointPort(_ config: String) throws -> String {
        guard let core = try JSONSerialization.jsonObject(with: Data(config.utf8)) as? [String: Any],
              let outbounds = core["outbounds"] as? [[String: Any]], outbounds.count == 1,
              let settings = outbounds[0]["settings"] as? [String: Any],
              let vnext = settings["vnext"] as? [[String: Any]], vnext.count == 1,
              let port = integer(vnext[0]["port"], minimum: 1, maximum: 65_535) else {
            throw TribeNativePolicyError.malformed
        }
        return port
    }

    /// Numeric-only public-unicast parser for signed verifier/bootstrap routes.
    /// It never resolves DNS and mirrors Android's reserved-range policy.
    static func isPublicEndpointLiteral(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= 64 else { return false }
        var v4 = in_addr()
        if inet_pton(AF_INET, value, &v4) == 1 {
            var canonical = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            guard inet_ntop(AF_INET, &v4, &canonical,
                            socklen_t(canonical.count)) != nil,
                  String(cString: canonical) == value else { return false }
            let b = withUnsafeBytes(of: &v4) { Array($0) }
            guard b.count == 4 else { return false }
            let first = Int(b[0]), second = Int(b[1]), third = Int(b[2])
            return !(first == 0 || first == 10 || first == 127
              || (first == 100 && (64...127).contains(second))
              || (first == 169 && second == 254)
              || (first == 172 && (16...31).contains(second))
              || (first == 192 && second == 0)
              || (first == 192 && second == 168)
              || (first == 198 && (18...19).contains(second))
              || (first == 198 && second == 51 && third == 100)
              || (first == 203 && second == 0 && third == 113)
              || first >= 224)
        }
        var v6 = in6_addr()
        guard inet_pton(AF_INET6, value, &v6) == 1 else { return false }
        var canonical = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        guard inet_ntop(AF_INET6, &v6, &canonical,
                        socklen_t(canonical.count)) != nil,
              String(cString: canonical) == value else { return false }
        let b = withUnsafeBytes(of: &v6) { Array($0) }
        guard b.count == 16 else { return false }
        let allZero = b.allSatisfy { $0 == 0 }
        let loopback = b.dropLast().allSatisfy { $0 == 0 } && b.last == 1
        let uniqueLocal = (b[0] & 0xfe) == 0xfc
        let linkLocal = b[0] == 0xfe && (b[1] & 0xc0) == 0x80
        let multicast = b[0] == 0xff
        let documentation = b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8
        let orchid = b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x00 && b[3] == 0x20
        let v4Mapped = b.prefix(10).allSatisfy { $0 == 0 } && b[10] == 0xff && b[11] == 0xff
        return !(allZero || loopback || uniqueLocal || linkLocal || multicast
                 || documentation || orchid || v4Mapped)
    }

    private static func integer(_ value: Any?, minimum: Int64, maximum: Int64) -> String? {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID() else { return nil }
        let double = number.doubleValue
        let integer = number.int64Value
        guard double.isFinite, Double(integer) == double,
              integer >= minimum, integer <= maximum else { return nil }
        return String(integer)
    }

    private static func canonicalDecimal(_ value: Any?, allowZero: Bool) -> UInt64? {
        guard let text = value as? String, !text.isEmpty,
              text == "0" || (text.first! >= "1" && text.first! <= "9"),
              text.allSatisfy({ $0 >= "0" && $0 <= "9" }),
              let parsed = UInt64(text), allowZero || parsed > 0 else { return nil }
        return parsed
    }

    private static func stringList(_ root: [String: Any], _ key: String,
                                   optional: Bool = false) throws -> [String] {
        if optional && root[key] == nil { return [] }
        guard let values = root[key] as? [Any], values.count <= 16_384,
              values.allSatisfy({ $0 is String }) else { throw TribeNativePolicyError.malformed }
        return values.compactMap { $0 as? String }
    }

    private static func optionalString(_ root: [String: Any], _ key: String) throws -> String {
        if root[key] == nil { return "" }
        guard let value = root[key] as? String else { throw TribeNativePolicyError.malformed }
        return value
    }

    private static func safeIdentifier(_ value: Any?, maximum: Int) -> String? {
        guard let value = value as? String, !value.isEmpty, value.utf8.count <= maximum,
              value.unicodeScalars.allSatisfy({ scalar in
                  let c = scalar.value
                  return (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a)
                      || (c >= 0x30 && c <= 0x39) || c == 0x2d || c == 0x5f
                      || c == 0x2e
              })
        else { return nil }
        return value
    }

    private static func sha256Text(_ value: Any?) -> String? {
        guard let value = value as? String, value.count == 64,
              value.allSatisfy({ ($0 >= "0" && $0 <= "9")
                                  || ($0 >= "a" && $0 <= "f") }) else { return nil }
        return value
    }

    private static func utcDate(_ value: Any?) -> Date? {
        guard let text = value as? String, text.utf8.count <= 40,
              text.range(of: "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d{1,9})?Z$",
                         options: .regularExpression) != nil else { return nil }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let value = formatter.date(from: text) { return value }
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.date(from: text)
    }

    private static func hexDigest(_ value: Data) -> String {
        SHA256.hash(data: value).map { String(format: "%02x", $0) }.joined()
    }
}
