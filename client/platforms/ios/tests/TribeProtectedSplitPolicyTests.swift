import Foundation

private func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
    guard condition() else {
        fputs("FAIL: \(message)\n", stderr)
        exit(1)
    }
}

private func accepts(_ exclusions: [String], _ protected: [String]) -> Bool {
    do {
        try TribeProtectedSplitPolicy.validateMode2(
            exclusions: exclusions, protectedLiterals: protected)
        return true
    } catch {
        return false
    }
}

@main
private struct ProtectedSplitPolicyTests {
    static func main() {
        expect(accepts(
            ["5.136.0.0/13", "2a00:1fa0::/32"],
            ["203.0.113.9", "2001:db8::9"]),
            "canonical direct CIDRs outside protected verifier addresses are accepted")
        expect(!accepts(["203.0.113.0/24"], ["203.0.113.9"]),
               "IPv4 protected verifier cannot be excluded")
        expect(!accepts(["2001:db8::/32"], ["2001:db8::9"]),
               "IPv6 protected verifier cannot be excluded")
        expect(!accepts(["203.0.113.9/24"], ["198.51.100.1"]),
               "host bits in an exclusion are rejected")
        expect(!accepts(["2001:0db8::/32"], ["2001:db9::1"]),
               "noncanonical IPv6 text is rejected")
        expect(!accepts(["5.136.0.0/013"], ["203.0.113.9"]),
               "noncanonical prefix text is rejected")
        expect(!accepts(["5.136.0.0/13"], ["203.000.113.9"]),
               "noncanonical protected literal is rejected")
        expect(!accepts([], ["203.0.113.9"]), "mode 2 requires exclusions")
        expect(!accepts(["5.136.0.0/13"], []), "guarded mode requires protected literals")
        print("Apple protected split-policy tests passed")
    }
}
