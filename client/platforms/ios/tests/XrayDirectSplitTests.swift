import Foundation

// AVPN (floor 19.11): host test of XrayDirectSplit.swift - the RU split of an own Xray session as one routing rule of
// the core instead of ~10,800 system routes. Run: tests/run_ios_swift_checks.sh.

private func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
    guard condition() else {
        fputs("FAIL: \(message)\n", stderr)
        exit(1)
    }
    print("ok   - \(message)")
}

@main
struct XrayDirectSplitTests {
    static func main() {
        // The list as the app writes it (writeDirectSplitList: one entry per line, trailing newline).
        let text = "5.8.0.0/16\n2a00:1fa0::/29\n 31.13.0.0/20 \n\nnot-a-cidr\n10.0.0.0/33\n2a00::/129\n1.2.3.4\n5.8.0.0/16\n1.2.3.0/024\n"
        let ranges = XrayDirectSplit.ranges(fromList: text)
        expect(ranges == ["5.8.0.0/16", "2a00:1fa0::/29", "31.13.0.0/20", "1.2.3.4"],
               "valid v4/v6 CIDRs and bare addresses kept in order; garbage, bad prefixes and duplicates dropped")
        expect(XrayDirectSplit.ranges(fromList: "").isEmpty, "an empty list has no range")

        // The own Xray config as XrayConfigBuilder.cpp builds it: one socks inbound, one untagged vless outbound,
        // no routing. The default outbound (the first one) must stay the vless one.
        var own: [String: Any] = [
            "inbounds": [["protocol": "socks", "port": 10808]],
            "outbounds": [["protocol": "vless"]]
        ]
        expect(XrayDirectSplit.inject(into: &own, ranges: ranges), "ranges injected")
        let outbounds = own["outbounds"] as? [[String: Any]] ?? []
        expect(outbounds.count == 2 && (outbounds[0]["protocol"] as? String) == "vless",
               "the vless outbound stays first - everything not in the list goes through the tunnel's exit")
        expect((outbounds[1]["protocol"] as? String) == "freedom" && (outbounds[1]["tag"] as? String) == XrayDirectSplit.outboundTag,
               "a freedom outbound carries the list's destinations (its dials go through the protect callback)")
        let rules = (own["routing"] as? [String: Any])?["rules"] as? [[String: Any]] ?? []
        expect(rules.count == 1 && (rules[0]["ip"] as? [String]) == ranges
                   && (rules[0]["outboundTag"] as? String) == XrayDirectSplit.outboundTag && (rules[0]["type"] as? String) == "field",
               "one ip rule routes the list to the direct outbound")

        // Injecting twice (a core restart on an uplink change rebuilds from the stored config, but be idempotent).
        expect(XrayDirectSplit.inject(into: &own, ranges: ["1.1.1.0/24"]), "second injection")
        let outbounds2 = own["outbounds"] as? [[String: Any]] ?? []
        let rules2 = (own["routing"] as? [String: Any])?["rules"] as? [[String: Any]] ?? []
        expect(outbounds2.count == 2 && rules2.count == 1 && (rules2[0]["ip"] as? [String]) == ["1.1.1.0/24"],
               "no duplicate outbound or rule")

        // A config with routing of its own: our rule goes first, the existing rules stay after it.
        var withRouting: [String: Any] = [
            "outbounds": [["protocol": "vless", "tag": "proxy"], ["protocol": "blackhole", "tag": "block"]],
            "routing": ["domainStrategy": "AsIs", "rules": [["type": "field", "ip": ["geoip:private"], "outboundTag": "block"]]]
        ]
        XrayDirectSplit.inject(into: &withRouting, ranges: ["5.8.0.0/16"])
        let routing = withRouting["routing"] as? [String: Any] ?? [:]
        let rules3 = routing["rules"] as? [[String: Any]] ?? []
        expect(rules3.count == 2 && (rules3[0]["outboundTag"] as? String) == XrayDirectSplit.outboundTag
                   && (rules3[1]["outboundTag"] as? String) == "block" && (routing["domainStrategy"] as? String) == "AsIs",
               "existing routing kept after our rule, its settings untouched")

        // No range (the file unreadable or empty): nothing changes - everything goes through the tunnel.
        var untouched: [String: Any] = ["outbounds": [["protocol": "vless"]]]
        expect(!XrayDirectSplit.inject(into: &untouched, ranges: []) && untouched["routing"] == nil
                   && (untouched["outbounds"] as? [[String: Any]])?.count == 1,
               "no ranges: the config is not touched")

        // The result is valid JSON for the core.
        expect(JSONSerialization.isValidJSONObject(own), "the injected config serializes")
        print("XrayDirectSplitTests: all checks passed")
    }
}
