import Foundation
import NetworkExtension

enum TunnelProtoType { case wireguard, openvpn, xray }

enum StubOSLogLevel { case info, error }
enum StubWireGuardLogLevel { case verbose, error
    var osLogLevel: StubOSLogLevel { .info }
}
func wg_log(_ level: StubOSLogLevel, message: String) {
    _ = level; _ = message
}
func wg_log(_ level: StubOSLogLevel, staticMessage: String) {
    _ = level; _ = staticMessage
}

func wgSetSplitDns(_ suffixes: String, _ direct: String, _ tunnel: String,
                   _ client: String, _ enabled: Int32, _ warmup: Int32) -> Int32 {
    _ = suffixes; _ = direct; _ = tunnel; _ = client; _ = enabled; _ = warmup
    return 0
}

enum PacketTunnelProviderError: Error {
    case savedProtocolConfigurationIsInvalid
    case couldNotStartBackend
    case couldNotDetermineFileDescriptor
    case dnsResolutionFailure
    case couldNotSetNetworkSettings
}

final class ErrorNotifier {
    init(activationAttemptId: String?) { _ = activationAttemptId }
    func notify(_ error: Error) { _ = error }
    static func removeLastErrorFile() {}
}

struct IPAddressRange: Hashable {
    let stringRepresentation: String
    init?(from value: String) { stringRepresentation = value }
}

struct StubPeer: Equatable {
    var allowedIPs = [IPAddressRange(from: "0.0.0.0/0")!,
                      IPAddressRange(from: "::/0")!]
    var excludeIPs = [IPAddressRange]()
}

final class TunnelConfiguration: Equatable {
    var peers = [StubPeer()]
    init(fromWgQuickConfig value: String) throws { _ = value }
    static func == (lhs: TunnelConfiguration, rhs: TunnelConfiguration) -> Bool {
        lhs === rhs || lhs.peers == rhs.peers
    }
}

final class WireGuardGuardPreparation {
    let tunnelConfiguration: TunnelConfiguration
    let networkSettings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "test")
    let resolvedEndpointLiterals = ["1.1.1.2"]
    init(_ tunnel: TunnelConfiguration) { tunnelConfiguration = tunnel }
}

struct StubDnsError { let address: String }
enum WireGuardAdapterError: Error {
    case cannotLocateTunnelFileDescriptor
    case dnsResolution([StubDnsError])
    case setNetworkSettings(Error)
    case startWireGuardBackend(Int32)
    case invalidState
}

final class WireGuardAdapter {
    var interfaceName: String? { "utun-test" }
    init(with provider: NEPacketTunnelProvider,
         guardPreparation: WireGuardGuardPreparation? = nil,
         logHandler: @escaping (StubWireGuardLogLevel, String) -> Void) {
        _ = provider; _ = guardPreparation; _ = logHandler
    }
    static func prepareGuardedTunnel(
        tunnelConfiguration: TunnelConfiguration
    ) throws -> WireGuardGuardPreparation { WireGuardGuardPreparation(tunnelConfiguration) }
    func start(tunnelConfiguration: TunnelConfiguration,
               completionHandler: @escaping (WireGuardAdapterError?) -> Void) {
        _ = tunnelConfiguration; _ = completionHandler
    }
    func stop(completionHandler: @escaping (WireGuardAdapterError?) -> Void) {
        _ = completionHandler
    }
    func update(tunnelConfiguration: TunnelConfiguration,
                completionHandler: @escaping (WireGuardAdapterError?) -> Void) {
        _ = tunnelConfiguration; _ = completionHandler
    }
    func getRuntimeConfiguration(completionHandler: @escaping (String?) -> Void) {
        _ = completionHandler
    }
    func rebindListenPort(completionHandler: @escaping (WireGuardAdapterError?) -> Void) {
        _ = completionHandler
    }
}

enum TribeEngineManifest {
    static func awgRuntimeStatusCore() -> [String: Any] { [:] }
}

extension NEProviderStopReason {
    var amneziaDescription: String { "test" }
}

class PacketTunnelProvider: NEPacketTunnelProvider {
    var wgAdapter: WireGuardAdapter?
    let wireguardRuntimeSession = TunnelRuntimeSession()
    var protoType: TunnelProtoType?
    func consumeTribeConfig(
        expectedProtocols: Set<String>
    ) throws -> (data: Data, sessionId: String) {
        _ = expectedProtocols
        throw PacketTunnelProviderError.savedProtocolConfigurationIsInvalid
    }
}
