import Foundation
import NetworkExtension

enum TunnelProtoType { case wireguard, openvpn, xray }

final class WireGuardGuardPreparation {
    var networkSettings: NEPacketTunnelNetworkSettings {
        NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "test")
    }
}

struct Constants {
    static let processQueueName = "test"
    static let tribeConfigSchemaKey = "tribe_config_schema"
    static let tribeGuardedSwitchKey = "guarded_inner_switch"
    static let tribeProtocolKey = "tribe_protocol"
    static let tribeConfigReferenceKey = "tribe_config_ref"
    static let tribeSessionIdKey = "tribe_session_id"
    static let tribeGuardOperationKey = "operation"
    static let tribeGuardSessionKey = "session"
    static let tribeGuardPolicyKey = "policy_sha256"
    static let tribeOuterSessionKey = "outer_session_id"
    static let tribeExpectedRuntimeSessionKey = "expected_runtime_session_id"
    static let kMessageKeyAction = "action"
    static let kActionNativeGuardStatus = "native_guard_status_v1"
    static let kActionNativeGuardPrepare = "native_guard_prepare_v1"
    static let kActionNativeSessionActivate = "native_session_activate_v1"
    static let kActionNativeSessionStop = "native_session_stop_v1"
    static let kActionNativeGuardRelease = "native_guard_release_v1"
    static let kActionNativeGuardReconcile = "native_guard_reconcile_v1"
    static let kActionRuntimeAuthorityRenew = "runtime_authority_renew_v1"
    static let tribeAuthorityRenewalRequestKey = "renewal_request"
    static let kActionNativeGuardRecoveryResolve = "native_guard_recovery_resolve_v1"
}

final class ErrorNotifier {
    init(activationAttemptId: String?) { _ = activationAttemptId }
}

enum StubLifecycleError: Error { case failed }

enum TribeEngineManifest {
    static func awgRuntimeStatusCore() -> [String: Any] { [:] }
    static func xrayRuntimeStatusCore() -> [String: Any] { [:] }
}

final class TribeTunnelConfigVault {
    static func consumeConfig(reference: String, protocolName: String,
                              sessionId: String) throws -> Data {
        _ = reference; _ = protocolName; _ = sessionId
        throw StubLifecycleError.failed
    }
}

class PacketTunnelProvider: NEPacketTunnelProvider {
    let tribeSessionGuard = TribeNativeSessionGuard()
    let tribeGuardQueue = DispatchQueue(label: "test.native-guard")
    let xrayRuntimeSession = TunnelRuntimeSession()
    let wireguardRuntimeSession = TunnelRuntimeSession()
    var tribePreparedSession: TribePreparedNativeSession?
    var tribeRuntimeAuthorityLease: TribeRuntimeAuthorityLease?
    var tribeAuthorityWatchdog: DispatchSourceTimer?
    let tribeAuthorityWatchdogFence = TribeRuntimeAuthorityWatchdogFence()
    var protoType: TunnelProtoType?

    func consumeTribeConfig(reference: String, protocolName: String,
                            sessionId: String) throws -> Data {
        try TribeTunnelConfigVault.consumeConfig(reference: reference,
                                                 protocolName: protocolName,
                                                 sessionId: sessionId)
    }

    func startWireguard(activationAttemptId: String?, errorNotifier: ErrorNotifier,
                        guardPreparation: WireGuardGuardPreparation? = nil,
                        handoff: (data: Data, sessionId: String)?,
                        completionHandler: @escaping (Error?) -> Void) {
        _ = activationAttemptId; _ = errorNotifier; _ = guardPreparation; _ = handoff
        completionHandler(nil)
    }

    func prepareGuardedWireguard(_ data: Data) throws -> WireGuardGuardPreparation {
        _ = data
        return WireGuardGuardPreparation()
    }

    func startXray(handoff: (data: Data, sessionId: String)?,
                   completionHandler: @escaping (Error?) -> Void) {
        _ = handoff
        completionHandler(nil)
    }

    func stopWireguardInner(completionHandler: @escaping (Error?) -> Void) {
        completionHandler(nil)
    }

    func stopXray(completionHandler: @escaping (Error?) -> Void) {
        completionHandler(nil)
    }
}
