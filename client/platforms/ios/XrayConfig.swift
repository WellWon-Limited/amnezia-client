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

    private enum CodingKeys: String, CodingKey {
        case dns1
        case dns2
        case splitTunnelType
        case splitTunnelSites
        case config
        case connectTimeoutMs = "xray_connect_timeout_ms"
        case readWriteTimeoutMs = "xray_rw_timeout_ms"
        case networkChangeDebounceMs = "network_change_debounce_ms"
    }
}
