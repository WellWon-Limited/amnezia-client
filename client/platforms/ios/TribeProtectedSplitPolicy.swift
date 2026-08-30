import Darwin
import Foundation

enum TribeProtectedSplitPolicyError: Error { case invalid }

/// One canonical overlap proof shared by the outer NE guard and both guarded inner engines.
enum TribeProtectedSplitPolicy {
    static func validateMode2(exclusions: [String], protectedLiterals: [String]) throws {
        guard !exclusions.isEmpty, !protectedLiterals.isEmpty else {
            throw TribeProtectedSplitPolicyError.invalid
        }
        for protected in protectedLiterals {
            guard !protected.contains("/"), try canonicalLiteral(protected) else {
                throw TribeProtectedSplitPolicyError.invalid
            }
            for exclusion in exclusions {
                if try cidr(exclusion, contains: protected) {
                    throw TribeProtectedSplitPolicyError.invalid
                }
            }
        }
        // Validate every exclusion even if there are no same-family protected literals.
        for exclusion in exclusions { _ = try canonicalNetwork(exclusion) }
    }

    private enum Network {
        case v4([UInt8], Int)
        case v6([UInt8], Int)
    }

    private static func canonicalLiteral(_ value: String) throws -> Bool {
        var v4 = in_addr()
        if inet_pton(AF_INET, value, &v4) == 1 {
            var text = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            return inet_ntop(AF_INET, &v4, &text, socklen_t(text.count)) != nil
                && String(cString: text) == value
        }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, value, &v6) == 1 {
            var text = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            return inet_ntop(AF_INET6, &v6, &text, socklen_t(text.count)) != nil
                && String(cString: text) == value
        }
        throw TribeProtectedSplitPolicyError.invalid
    }

    private static func canonicalNetwork(_ value: String) throws -> Network {
        let components = value.split(separator: "/", omittingEmptySubsequences: false)
        guard components.count == 2,
              let prefix = Int(components[1]), String(prefix) == String(components[1]) else {
            throw TribeProtectedSplitPolicyError.invalid
        }
        let address = String(components[0])
        var v4 = in_addr()
        if inet_pton(AF_INET, address, &v4) == 1, (0...32).contains(prefix) {
            var text = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            let bytes = withUnsafeBytes(of: &v4) { Array($0) }
            guard inet_ntop(AF_INET, &v4, &text, socklen_t(text.count)) != nil,
                  String(cString: text) == address,
                  hostBitsAreZero(bytes, prefix: prefix) else {
                throw TribeProtectedSplitPolicyError.invalid
            }
            return .v4(bytes, prefix)
        }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, address, &v6) == 1, (0...128).contains(prefix) {
            var text = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            let bytes = withUnsafeBytes(of: &v6) { Array($0) }
            guard inet_ntop(AF_INET6, &v6, &text, socklen_t(text.count)) != nil,
                  String(cString: text) == address,
                  hostBitsAreZero(bytes, prefix: prefix) else {
                throw TribeProtectedSplitPolicyError.invalid
            }
            return .v6(bytes, prefix)
        }
        throw TribeProtectedSplitPolicyError.invalid
    }

    private static func cidr(_ network: String, contains literal: String) throws -> Bool {
        switch try canonicalNetwork(network) {
        case .v4(let base, let prefix):
            var address = in_addr()
            guard inet_pton(AF_INET, literal, &address) == 1 else { return false }
            return prefixEqual(base, withUnsafeBytes(of: &address) { Array($0) }, prefix: prefix)
        case .v6(let base, let prefix):
            var address = in6_addr()
            guard inet_pton(AF_INET6, literal, &address) == 1 else { return false }
            return prefixEqual(base, withUnsafeBytes(of: &address) { Array($0) }, prefix: prefix)
        }
    }

    private static func hostBitsAreZero(_ bytes: [UInt8], prefix: Int) -> Bool {
        guard prefix >= 0 && prefix <= bytes.count * 8 else { return false }
        for bit in prefix..<(bytes.count * 8) {
            if (bytes[bit / 8] & (UInt8(0x80) >> UInt8(bit % 8))) != 0 { return false }
        }
        return true
    }

    private static func prefixEqual(_ lhs: [UInt8], _ rhs: [UInt8], prefix: Int) -> Bool {
        guard lhs.count == rhs.count, prefix >= 0, prefix <= lhs.count * 8 else { return false }
        let fullBytes = prefix / 8
        if fullBytes > 0 && lhs[0..<fullBytes] != rhs[0..<fullBytes] { return false }
        let remainder = prefix % 8
        if remainder == 0 { return true }
        let mask = UInt8.max << UInt8(8 - remainder)
        return (lhs[fullBytes] & mask) == (rhs[fullBytes] & mask)
    }
}
