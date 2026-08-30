import Foundation

// AVPN backend-first (Task 6): server-tunable tun2socks timeouts + network-change reconnect debounce.
// All three are optional — absent key (old GUI-built config, or server default not seeded) decodes to
// nil, and callers fall back to the pre-Task-6 literals, so behavior is byte-for-byte unchanged for any
// config that doesn't carry these keys. Seeded from TuningStore in ios_controller.mm::setupXray()/
// setupSSXray() (client/core/serviceEngine/TuningStore.h, numbers.xray_connect_timeout_ms /
// xray_rw_timeout_ms / network_change_debounce_ms).
struct XrayConfig: Decodable {
    let dns1: String?
    let dns2: String?
    let splitTunnelType: Int?
    let splitTunnelSites: [String]?
    let config: String
    let connectTimeoutMs: Int?
    let readWriteTimeoutMs: Int?
    let networkChangeDebounceMs: Int?
    let maxMemoryBytes: Int64?
    let protectedTunnelIPs: [String]?
    let guardedCatalogV2: Bool?

    private enum CodingKeys: String, CodingKey {
        case dns1
        case dns2
        case splitTunnelType
        case splitTunnelSites
        case config
        case connectTimeoutMs = "xray_connect_timeout_ms"
        case readWriteTimeoutMs = "xray_rw_timeout_ms"
        case networkChangeDebounceMs = "network_change_debounce_ms"
        case maxMemoryBytes = "xray_max_memory_bytes"
        case protectedTunnelIPs
        case guardedCatalogV2
    }
}

extension XrayConfig {
    static func decodeNativeEnvelope(_ data: Data) throws -> XrayConfig {
        guard data.count <= 2 * 1024 * 1024,
              let root = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw TribeNativePolicyError.malformed
        }
        let isV2 = try TribeNativeDispatchPolicy.validateEnvelope(root)
        if !isV2, root["config"] is String {
            return try JSONDecoder().decode(XrayConfig.self, from: data)
        }
        guard let protocolName = root["protocol"] as? String,
              protocolName == "xray",
              let native = root["xray_config_data"] as? [String: Any],
              let coreConfig = native["config"] as? String else {
            throw TribeNativePolicyError.malformed
        }
        var transformed: [String: Any] = ["config": coreConfig]
        transformed["guardedCatalogV2"] = true
        transformed["protectedTunnelIPs"] =
            (root["runtime_authority_v1"] as? [String: Any])?["protected_tunnel_ips"] ?? []
        for key in ["dns1", "dns2", "splitTunnelType", "splitTunnelSites",
                    "xray_connect_timeout_ms", "xray_rw_timeout_ms",
                    "network_change_debounce_ms", "xray_max_memory_bytes"] {
            if let value = root[key], !(value is NSNull) { transformed[key] = value }
        }
        let transformedData = try JSONSerialization.data(withJSONObject: transformed)
        return try JSONDecoder().decode(XrayConfig.self, from: transformedData)
    }
}
