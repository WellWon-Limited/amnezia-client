import Foundation
import NetworkExtension

typealias libxray_sockcallback = @convention(c) (
    uintptr_t, UnsafeMutableRawPointer?
) -> Int32

func LibXraySetSockCallback(
    _ callback: libxray_sockcallback?, _ context: UnsafeMutableRawPointer?
) -> UnsafeMutablePointer<CChar>? {
    _ = callback; _ = context
    return nil
}

func LibXrayRunXray(_ dataDirectory: OpaquePointer?, _ path: String,
                    _ memoryLimit: Int64) -> UnsafeMutablePointer<CChar>? {
    _ = dataDirectory; _ = path; _ = memoryLimit
    return nil
}

func LibXrayStopXray() -> UnsafeMutablePointer<CChar>? { nil }

enum StubLogLevel { case info, error }
func xrayLog(_ level: StubLogLevel, title: String = "", message: String) {
    _ = level; _ = title; _ = message
}

enum TribeEngineManifest {
    static func xrayRuntimeStatusCore() -> [String: Any] { [:] }
}

enum Socks5Tunnel {
    enum StartError: Error { case failed }
    enum StopResult: Equatable { case stopped, timedOut }
    struct TrafficStats {
        let txPackets: UInt64 = 0
        let txBytes: UInt64 = 0
        let rxPackets: UInt64 = 0
        let rxBytes: UInt64 = 0
    }

    static func start(withConfig path: String,
                      completion: @escaping (Result<Void, StartError>) -> Void,
                      onExit: @escaping (Int32) -> Void) {
        _ = path; _ = completion; _ = onExit
    }
    static func stop(completion: @escaping (StopResult) -> Void) {
        _ = completion
    }
    static func trafficStats() -> TrafficStats? { nil }
}

class PacketTunnelProvider: NEPacketTunnelProvider {
    let xrayRuntimeSession = TunnelRuntimeSession()
    let xrayNativeLifecycleGate = XrayNativeLifecycleGate()
    let xraySocketCallbackRegistry =
        XraySocketCallbackRegistry<XraySocketCallbackContext>()
    let xraySocketProtectionLock = NSLock()
    var xraySocketProtectionGeneration: UInt64 = 0
    var xraySocketProtectionSessionId = ""
    var xraySocketProtectionSucceeded = false
    var xraySocketProtectionFailed = false
    var xrayNetworkChangeDebounceSeconds: TimeInterval = 1
    var activeInterfaceIndex: UInt32 = 1
    let tribeSessionGuard = TribeNativeSessionGuard()
    let tribeGuardQueue = DispatchQueue(label: "test.xray.guard")

    func consumeTribeConfig(
        expectedProtocols: Set<String>
    ) throws -> (data: Data, sessionId: String) {
        _ = expectedProtocols
        throw XrayErrors.noXrayConfig
    }

    func updateActiveInterfaceIndexForCurrentPath() {}
    func currentActiveInterfaceIndex() -> UInt32 { activeInterfaceIndex }
    func cancelAuthorityWatchdog() {}

    func retainXrayCallbackContext(_ context: XraySocketCallbackContext) -> Bool {
        xraySocketCallbackRegistry.install(context, identity: context.identity)
    }

    func retireXrayCallbackContext(identity: XraySocketCallbackIdentity) -> Bool {
        guard let context = xraySocketCallbackRegistry.value(for: identity),
              context.deactivate(expected: identity) else { return false }
        return xraySocketCallbackRegistry.remove(identity: identity) === context
    }
}
