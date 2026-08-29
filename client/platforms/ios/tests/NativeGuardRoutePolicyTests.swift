import Foundation
import NetworkExtension

private func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
    guard condition() else { fputs("FAIL: \(message)\n", stderr); exit(1) }
}

private func root(_ sites: [String], protected: [String]) -> [String: Any] {
    [
        "dns1": "1.1.1.1", "dns2": "8.8.8.8", "splitTunnelType": 2,
        "splitTunnelSites": sites,
        "runtime_authority_v1": ["protected_tunnel_ips": protected],
    ]
}

@main
private struct NativeGuardRoutePolicyTests {
    static func main() throws {
        let provider = PacketTunnelProvider()
        let settings = try provider.guardNetworkSettings(root(
            ["5.0.0.0/8", "2001:4860:1000::/48"],
            protected: ["1.1.1.1", "2606:4700:4700::1111"]))
        expect(settings.ipv4Settings?.includedRoutes?.count == 1,
               "mode2 must retain the IPv4 default include")
        expect(settings.ipv6Settings?.includedRoutes?.count == 1,
               "mode2 must retain the IPv6 default include")
        expect(settings.ipv4Settings?.excludedRoutes?.count == 1,
               "mode2 IPv4 exclusion missing")
        expect(settings.ipv6Settings?.excludedRoutes?.count == 1,
               "mode2 IPv6 exclusion missing")

        do {
            _ = try provider.guardNetworkSettings(root(
                ["1.0.0.0/8"], protected: ["1.1.1.1"]))
            expect(false, "protected IPv4 was allowed inside a direct exclusion")
        } catch TribeNativeGuardProviderError.invalidPolicy {}
        do {
            _ = try provider.guardNetworkSettings(root(
                ["2606:4700::/32"], protected: ["2606:4700:4700::1111"]))
            expect(false, "protected IPv6 was allowed inside a direct exclusion")
        } catch TribeNativeGuardProviderError.invalidPolicy {}
        do {
            _ = try provider.guardNetworkSettings(root(
                ["5.1.1.1/8"], protected: ["1.1.1.1"]))
            expect(false, "non-network CIDR base was normalized instead of rejected")
        } catch TribeNativeGuardProviderError.invalidPolicy {}
        do {
            _ = try provider.guardNetworkSettings(root(
                ["2001:4860:0:0::/32"], protected: ["2606:4700:4700::1111"]))
            expect(false, "non-canonical IPv6 text was accepted")
        } catch TribeNativeGuardProviderError.invalidPolicy {}

        print("Apple native guard route policy tests passed")
    }
}
