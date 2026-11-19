import Network

// AVPN (floor of "tap -> data", 19.11.2026; CONNECT-INVARIANTS §28 extended to the Xray path): the RU split of an
// own Xray session inside the core instead of system routes. With the split as `excludedRoutes` the extension handed
// iOS ~10,800 routes (8,624 IPv4 + 2,174 IPv6 from ru_prefixes.h) on every start, and the VPN profile carried the
// list (~250 KB): own Xray reached the extension's Connected in 1.9-2.1 s against 0.63-0.7 s for a provider profile
// (split off) on the same Wi-Fi (iPhone Air, 18-19.11). With features.ios_userspace_split the app writes the list to
// the App Group file (as for AmneziaWG) and sends no routes; here the list becomes one routing rule of the core -
// destinations in it leave through a `freedom` outbound, whose sockets the existing protect callback binds to the
// physical interface like every dial of the core (protectXraySocket). Everything else goes to the first outbound,
// as before. This is what the Xray and sing-box clients measured in docs/xray-research do (geoip:ru -> direct).
//
// Safe failures, as on the AmneziaWG path: a list that cannot be read, or has no valid range, adds nothing - all
// traffic goes through the tunnel and the start goes on. An invalid line is skipped (one bad CIDR would make the core
// refuse the whole config). Pure apart from reading the file; tests: tests/XrayDirectSplitTests.swift.
enum XrayDirectSplit {
    static let outboundTag = "tribe-direct"

    /// The valid ranges of the list text (one CIDR or bare address per line), in order, without duplicates.
    static func ranges(fromList text: String) -> [String] {
        var seen = Set<String>()
        var out = [String]()
        for raw in text.split(whereSeparator: { $0 == "\n" || $0 == "\r" }) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty, isValidRange(line), seen.insert(line).inserted else { continue }
            out.append(line)
        }
        return out
    }

    static func isValidRange(_ value: String) -> Bool {
        let parts = value.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 1 || parts.count == 2 else { return false }
        let address = String(parts[0])
        let maxPrefix: Int
        if IPv4Address(address) != nil, !address.contains(":") {
            maxPrefix = 32
        } else if address.contains(":"), IPv6Address(address) != nil {
            maxPrefix = 128
        } else {
            return false
        }
        guard parts.count == 2 else { return true }
        guard let prefix = Int(parts[1]), prefix >= 0, prefix <= maxPrefix, String(prefix) == String(parts[1]) else {
            return false
        }
        return true
    }

    /// Adds the direct outbound (last, so the default outbound stays the first one) and the rule (first, so it
    /// is matched before any rule the config already has). false = nothing changed (no ranges).
    @discardableResult
    static func inject(into json: inout [String: Any], ranges: [String]) -> Bool {
        guard !ranges.isEmpty else { return false }
        var outbounds = json["outbounds"] as? [[String: Any]] ?? []
        if !outbounds.contains(where: { ($0["tag"] as? String) == outboundTag }) {
            outbounds.append(["protocol": "freedom", "tag": outboundTag])
        }
        json["outbounds"] = outbounds
        var routing = json["routing"] as? [String: Any] ?? [:]
        var rules = routing["rules"] as? [[String: Any]] ?? []
        rules.removeAll(where: { ($0["outboundTag"] as? String) == outboundTag })
        rules.insert(["type": "field", "ip": ranges, "outboundTag": outboundTag], at: 0)
        routing["rules"] = rules
        json["routing"] = routing
        return true
    }
}
