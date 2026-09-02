import Network

// NEIPv4Route rejects IPv6 values and requires the destination to be the
// network address, not an arbitrary host inside the prefix.  Keep conversion
// in one testable place for the OpenVPN and Xray Network Extension paths.
struct IPv4RouteSpec: Equatable {
    let destinationAddress: String
    let subnetMask: String

    init?(cidr: String) {
        let parts = cidr.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2,
              let address = IPv4Address(String(parts[0])),
              let prefixLength = UInt8(parts[1]),
              prefixLength <= 32 else {
            return nil
        }

        let bytes = [UInt8](address.rawValue)
        guard bytes.count == 4 else { return nil }
        let addressValue = bytes.reduce(UInt32.zero) { ($0 << 8) | UInt32($1) }
        let mask = prefixLength == 0 ? UInt32.zero : UInt32.max << (32 - UInt32(prefixLength))
        let network = addressValue & mask

        destinationAddress = Self.dottedQuad(network)
        subnetMask = Self.dottedQuad(mask)
    }

    private static func dottedQuad(_ value: UInt32) -> String {
        [24, 16, 8, 0]
            .map { String((value >> UInt32($0)) & 0xff) }
            .joined(separator: ".")
    }
}
