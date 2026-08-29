import Darwin
import Foundation
import NetworkExtension

enum TribeNativeGuardProviderError: Error {
    case malformedMessage
    case invalidPolicy
    case settingsRejected
    case staleOperation
    case innerLifecycleFailed
}

struct TribePreparedNativeSession {
    let identity: TribeNativeGuardIdentity
    let protocolName: String
    let configuration: Data
    let outerPolicySHA256: String
    let wireGuardPreparation: WireGuardGuardPreparation?
}

private enum TribeNativeGuardRoute {
    case ipv4(NEIPv4Route)
    case ipv6(NEIPv6Route)
}

/// Same-NE ownership bridge for catalog-v2.  The Network Extension owns the routing policy;
/// AWG and Xray are only replaceable inner readers of the already-armed packet flow.
extension PacketTunnelProvider {
    func startInitialNativeGuard(options: [String: NSObject]?,
                                 completionHandler: @escaping (Error?) -> Void) {
        tribeGuardQueue.async { [weak self] in
            guard let self else {
                completionHandler(TribeNativeGuardProviderError.staleOperation)
                return
            }
            do {
                guard let provider = (self.protocolConfiguration as? NETunnelProviderProtocol)?
                        .providerConfiguration,
                      provider.keys.count == 5,
                      provider[Constants.tribeConfigSchemaKey] as? Int == 1,
                      provider[Constants.tribeGuardedSwitchKey] as? Bool == true,
                      let protocolName = provider[Constants.tribeProtocolKey] as? String,
                      let reference = provider[Constants.tribeConfigReferenceKey] as? String,
                      let configSessionId = provider[Constants.tribeSessionIdKey] as? String,
                      let options,
                      Set(options.keys) == Set([
                          Constants.kMessageKeyAction, Constants.tribeGuardOperationKey,
                          Constants.tribeGuardSessionKey, Constants.tribeGuardPolicyKey,
                          Constants.tribeExpectedRuntimeSessionKey,
                      ]),
                      options[Constants.kMessageKeyAction] as? String
                        == Constants.kActionNativeGuardPrepare,
                      let operation = options[Constants.tribeGuardOperationKey] as? String,
                      let session = options[Constants.tribeGuardSessionKey] as? String,
                      let policy = options[Constants.tribeGuardPolicyKey] as? String,
                      let expectedRuntime = options[
                        Constants.tribeExpectedRuntimeSessionKey] as? String else {
                    throw TribeNativeGuardProviderError.malformedMessage
                }
                let identity = try TribeNativeGuardIdentity(
                    operation: operation, session: session, policySHA256: policy,
                    expectedRuntimeSessionId: expectedRuntime)
                guard configSessionId == expectedRuntime else {
                    throw TribeNativeGuardProviderError.malformedMessage
                }
                let data = try self.consumeTribeConfig(
                    reference: reference, protocolName: protocolName,
                    sessionId: configSessionId)
                try self.prepareNativeGuard(identity: identity, protocolName: protocolName,
                                            configuration: data,
                                            completionHandler: completionHandler)
            } catch {
                completionHandler(error)
            }
        }
    }

    func handleNativeGuardMessage(_ message: [String: Any],
                                  completionHandler: @escaping (Data?) -> Void) -> Bool {
        guard let action = message[Constants.kMessageKeyAction] as? String,
              action == Constants.kActionNativeGuardStatus
                || action == Constants.kActionNativeGuardPrepare
                || action == Constants.kActionNativeSessionActivate
                || action == Constants.kActionNativeSessionStop
                || action == Constants.kActionNativeGuardRelease
                || action == Constants.kActionNativeGuardReconcile
                || action == Constants.kActionRuntimeAuthorityRenew
                || action == Constants.kActionNativeGuardRecoveryResolve else {
            return false
        }
        tribeGuardQueue.async { [weak self] in
            guard let self else { completionHandler(nil); return }
            switch action {
            case Constants.kActionNativeGuardStatus:
                let snapshot = self.tribeSessionGuard.snapshot()
                guard Set(message.keys) == Set([Constants.kMessageKeyAction]),
                      let identity = snapshot.identity else {
                    completionHandler(nil)
                    return
                }
                let event = TribeNativeSessionGuard.event(
                    identity: identity,
                    kind: snapshot.phase == .quarantined ? "lost" : "armed",
                    outerSessionId: snapshot.outerSessionId,
                    reason: snapshot.phase == .quarantined ? "guard_quarantined" : "")
                completionHandler(self.guardJSON(event))

            case Constants.kActionNativeGuardPrepare:
                self.handlePrepareMessage(message, completionHandler: completionHandler)

            case Constants.kActionNativeSessionActivate:
                self.handleActivateMessage(message, completionHandler: completionHandler)

            case Constants.kActionNativeSessionStop:
                self.handleStopMessage(message, completionHandler: completionHandler)

            case Constants.kActionNativeGuardRelease:
                self.handleReleaseMessage(message, completionHandler: completionHandler)

            case Constants.kActionNativeGuardReconcile:
                self.handleReconcileMessage(message, completionHandler: completionHandler)

            case Constants.kActionRuntimeAuthorityRenew:
                self.handleAuthorityRenewMessage(message, completionHandler: completionHandler)

            case Constants.kActionNativeGuardRecoveryResolve:
                self.handleRecoveryResolutionMessage(message,
                                                     completionHandler: completionHandler)

            default:
                completionHandler(nil)
            }
        }
        return true
    }

    private func handlePrepareMessage(_ message: [String: Any],
                                      completionHandler: @escaping (Data?) -> Void) {
        let expectedKeys: Set<String> = [
            Constants.kMessageKeyAction, Constants.tribeGuardOperationKey,
            Constants.tribeGuardSessionKey, Constants.tribeGuardPolicyKey,
            Constants.tribeExpectedRuntimeSessionKey, Constants.tribeConfigReferenceKey,
            Constants.tribeProtocolKey, Constants.tribeSessionIdKey,
        ]
        guard Set(message.keys) == expectedKeys,
              let identity = identity(message),
              let protocolName = message[Constants.tribeProtocolKey] as? String,
              let reference = message[Constants.tribeConfigReferenceKey] as? String,
              let configSessionId = message[Constants.tribeSessionIdKey] as? String,
              configSessionId == identity.expectedRuntimeSessionId else {
            completionHandler(nil)
            return
        }
        do {
            let data = try consumeTribeConfig(reference: reference,
                                              protocolName: protocolName,
                                              sessionId: configSessionId)
            let root = try nativeRoot(data, expectedProtocol: protocolName,
                                      expectedPolicy: identity.policySHA256)
            let outerPolicy = try TribeNativeDispatchPolicy.outerPolicySHA256(root)
            let lease = try TribeRuntimeAuthorityLease(configuration: root)
            let material = try guardPreparation(
                root: root, protocolName: protocolName, configuration: data)
            // Reserve before mutating NE settings. This is what makes an ArmRejected receipt proof
            // that this attempted identity acquired no new outer ownership.
            try tribeSessionGuard.beginArm(identity, outerPolicySHA256: outerPolicy)
            setTunnelNetworkSettings(material.settings) { [weak self] settingsError in
                guard let self else { completionHandler(nil); return }
                self.tribeGuardQueue.async {
                    if settingsError != nil {
                        if (try? self.tribeSessionGuard.cancelArm(identity)) != nil {
                            completionHandler(self.guardJSON(TribeNativeSessionGuard.event(
                                identity: identity, kind: "arm_rejected", outerSessionId: "",
                                reason: "settings_rejected")))
                        } else if let lost = try? self.tribeSessionGuard.failArmCommit(
                                    identity, reason: "arm_timeout_ambiguous") {
                            completionHandler(self.guardJSON(lost))
                        } else {
                            completionHandler(nil)
                        }
                        return
                    }
                    do {
                        let armed = try self.tribeSessionGuard.commitArm(identity)
                        self.tribePreparedSession = TribePreparedNativeSession(
                            identity: identity, protocolName: protocolName,
                            configuration: data, outerPolicySHA256: outerPolicy,
                            wireGuardPreparation: material.wireGuard)
                        self.tribeRuntimeAuthorityLease = lease
                        self.installAuthorityWatchdog()
                        completionHandler(self.guardJSON(armed))
                    } catch {
                        // The OS accepted settings, therefore ArmRejected would be a false absence
                        // receipt. Quarantine the exact attempted identity and require recovery.
                        if let lost = try? self.tribeSessionGuard.failArmCommit(
                                identity, reason: "arm_commit_failed") {
                            completionHandler(self.guardJSON(lost))
                        } else {
                            completionHandler(nil)
                        }
                    }
                }
            }
        } catch {
            completionHandler(guardJSON(TribeNativeSessionGuard.event(
                identity: identity, kind: "arm_rejected", outerSessionId: "",
                reason: "prepare_rejected")))
        }
    }

    private func prepareNativeGuard(identity: TribeNativeGuardIdentity,
                                    protocolName: String, configuration: Data,
                                    completionHandler: @escaping (Error?) -> Void) throws {
        let root = try nativeRoot(configuration, expectedProtocol: protocolName,
                                  expectedPolicy: identity.policySHA256)
        let outerPolicy = try TribeNativeDispatchPolicy.outerPolicySHA256(root)
        let lease = try TribeRuntimeAuthorityLease(configuration: root)
        let material = try guardPreparation(
            root: root, protocolName: protocolName, configuration: configuration)
        try tribeSessionGuard.beginArm(identity, outerPolicySHA256: outerPolicy)
        setTunnelNetworkSettings(material.settings) { [weak self] error in
            guard let self else {
                completionHandler(TribeNativeGuardProviderError.staleOperation)
                return
            }
            self.tribeGuardQueue.async {
                guard error == nil else {
                    _ = try? self.tribeSessionGuard.cancelArm(identity)
                    completionHandler(TribeNativeGuardProviderError.settingsRejected)
                    return
                }
                do {
                    _ = try self.tribeSessionGuard.commitArm(identity)
                    self.tribePreparedSession = TribePreparedNativeSession(
                        identity: identity, protocolName: protocolName,
                        configuration: configuration, outerPolicySHA256: outerPolicy,
                        wireGuardPreparation: material.wireGuard)
                    self.tribeRuntimeAuthorityLease = lease
                    self.installAuthorityWatchdog()
                    completionHandler(nil)
                } catch {
                    // Settings are already blocking.  Keep the extension alive as a blackhole;
                    // reporting start failure would let the OS tear them down before ownership
                    // can be reconciled.
                    _ = try? self.tribeSessionGuard.failArmCommit(
                        identity, reason: "arm_commit_failed")
                    completionHandler(TribeNativeGuardProviderError.staleOperation)
                }
            }
        }
    }

    private func guardPreparation(root: [String: Any], protocolName: String,
                                  configuration: Data) throws
        -> (settings: NEPacketTunnelNetworkSettings,
            wireGuard: WireGuardGuardPreparation?) {
        if protocolName == "awg" {
            let preparation = try prepareGuardedWireguard(configuration)
            return (preparation.networkSettings, preparation)
        }
        guard protocolName == "xray" else {
            throw TribeNativeGuardProviderError.invalidPolicy
        }
        return (try guardNetworkSettings(root), nil)
    }

    private func handleActivateMessage(_ message: [String: Any],
                                       completionHandler: @escaping (Data?) -> Void) {
        let expectedKeys: Set<String> = [
            Constants.kMessageKeyAction, Constants.tribeGuardOperationKey,
            Constants.tribeGuardSessionKey, Constants.tribeGuardPolicyKey,
            Constants.tribeExpectedRuntimeSessionKey, Constants.tribeOuterSessionKey,
            Constants.tribeConfigReferenceKey, Constants.tribeProtocolKey,
            Constants.tribeSessionIdKey,
        ]
        guard Set(message.keys) == expectedKeys,
              let identity = identity(message),
              let outer = message[Constants.tribeOuterSessionKey] as? String,
              let protocolName = message[Constants.tribeProtocolKey] as? String,
              let reference = message[Constants.tribeConfigReferenceKey] as? String,
              let configSessionId = message[Constants.tribeSessionIdKey] as? String,
              configSessionId == identity.expectedRuntimeSessionId,
              let prepared = tribePreparedSession,
              prepared.identity == identity,
              prepared.protocolName == protocolName else {
            completionHandler(nil)
            return
        }
        let activationData: Data
        do {
            try tribeRuntimeAuthorityLease?.evaluate()
            guard tribeRuntimeAuthorityLease != nil else {
                throw TribeNativeGuardProviderError.invalidPolicy
            }
            activationData = try consumeTribeConfig(reference: reference,
                                                     protocolName: protocolName,
                                                     sessionId: configSessionId)
            _ = try nativeRoot(activationData, expectedProtocol: protocolName,
                               expectedPolicy: identity.policySHA256)
            guard activationData == prepared.configuration else {
                throw TribeNativeGuardProviderError.invalidPolicy
            }
            try tribeSessionGuard.beginActivation(identity, outer: outer)
        } catch {
            completionHandler(guardJSON(["ok": false, "reason": "activate_rejected"]))
            return
        }

        let finished: (Error?) -> Void = { [weak self] error in
            guard let self else { completionHandler(nil); return }
            self.tribeGuardQueue.async {
                if let error {
                    self.tribePreparedSession = nil
                    self.cancelAuthorityWatchdog()
                    self.tribeSessionGuard.quarantine(
                        expectedRuntimeSessionId: identity.expectedRuntimeSessionId)
                    var response: [String: Any] = [
                        "ok": false, "reason": "inner_start_failed",
                    ]
                    if let lost = self.tribeSessionGuard.lostEvent(
                        reason: "inner_start_failed") {
                        response["guard_event"] = lost
                    }
                    completionHandler(self.guardJSON(response))
                    _ = error
                    return
                }
                do {
                    try self.tribeSessionGuard.markRunning(
                        expectedRuntimeSessionId: identity.expectedRuntimeSessionId)
                    self.tribePreparedSession = nil
                    completionHandler(self.guardJSON([
                        "ok": true,
                        "runtime_session_id": identity.expectedRuntimeSessionId,
                    ]))
                } catch {
                    self.tribeSessionGuard.quarantine(
                        expectedRuntimeSessionId: identity.expectedRuntimeSessionId)
                    completionHandler(self.guardJSON(["ok": false, "reason": "stale_start"]))
                }
            }
        }
        protoType = protocolName == "awg" ? .wireguard : .xray
        if protocolName == "awg" {
            startWireguard(activationAttemptId: nil,
                           errorNotifier: ErrorNotifier(activationAttemptId: nil),
                           guardPreparation: prepared.wireGuardPreparation,
                           handoff: (activationData, identity.expectedRuntimeSessionId),
                           completionHandler: finished)
        } else if protocolName == "xray" {
            startXray(handoff: (activationData, identity.expectedRuntimeSessionId),
                      completionHandler: finished)
        } else {
            finished(TribeNativeGuardProviderError.malformedMessage)
        }
    }

    private func handleStopMessage(_ message: [String: Any],
                                   completionHandler: @escaping (Data?) -> Void) {
        guard Set(message.keys) == Set([
                Constants.kMessageKeyAction, Constants.tribeOuterSessionKey,
                Constants.tribeExpectedRuntimeSessionKey,
              ]),
              let outer = message[Constants.tribeOuterSessionKey] as? String,
              let expectedRuntime = message[Constants.tribeExpectedRuntimeSessionKey] as? String,
              let identity = tribeSessionGuard.snapshot().identity else {
            completionHandler(nil)
            return
        }
        do {
            try tribeSessionGuard.beginStop(outer: outer,
                                             expectedRuntimeSessionId: expectedRuntime)
        } catch {
            completionHandler(guardJSON(["ok": false, "reason": "stale_stop"]))
            return
        }
        let stopped: (Error?) -> Void = { [weak self] error in
            guard let self else { completionHandler(nil); return }
            self.tribeGuardQueue.async {
                if error != nil {
                    var response: [String: Any] = [
                        "ok": false, "reason": "inner_stop_failed",
                    ]
                    if let lost = try? self.tribeSessionGuard.failStop(
                        identity, outer: outer, reason: "inner_stop_failed") {
                        response["guard_event"] = lost
                    }
                    completionHandler(self.guardJSON(response))
                    return
                }
                do {
                    try self.tribeSessionGuard.markStopped(
                        expectedRuntimeSessionId: expectedRuntime)
                    completionHandler(self.guardJSON([
                        "ok": true, "runtime_session_id": expectedRuntime,
                        "runtime_state": "stopped",
                    ]))
                } catch {
                    completionHandler(self.guardJSON(["ok": false, "reason": "stale_stop"]))
                }
            }
        }
        if protoType == .wireguard {
            stopWireguardInner(completionHandler: stopped)
        } else if protoType == .xray {
            stopXray(completionHandler: stopped)
        } else {
            stopped(TribeNativeGuardProviderError.innerLifecycleFailed)
        }
    }

    private func handleReleaseMessage(_ message: [String: Any],
                                      completionHandler: @escaping (Data?) -> Void) {
        guard Set(message.keys) == Set([
                Constants.kMessageKeyAction, Constants.tribeGuardOperationKey,
                Constants.tribeGuardSessionKey, Constants.tribeOuterSessionKey,
              ]),
              let operation = message[Constants.tribeGuardOperationKey] as? String,
              let session = message[Constants.tribeGuardSessionKey] as? String,
              let outer = message[Constants.tribeOuterSessionKey] as? String,
              let current = tribeSessionGuard.snapshot().identity,
              let request = try? TribeNativeGuardIdentity(
                operation: operation, session: session,
                policySHA256: current.policySHA256,
                expectedRuntimeSessionId: current.expectedRuntimeSessionId) else {
            completionHandler(nil)
            return
        }
        guard current == request else { completionHandler(nil); return }
        do {
            // Reserve the exact stopped/never-started owner before the asynchronous OS call.
            // Every replacement transition rejects `.releasing`, so a delayed callback cannot
            // clear routes belonging to a newer guard session.
            try tribeSessionGuard.beginRelease(request, outer: outer)
            cancelAuthorityWatchdog()
        } catch {
            completionHandler(guardJSON(TribeNativeSessionGuard.event(
                identity: current, kind: "release_rejected",
                outerSessionId: outer, reason: "release_rejected")))
            return
        }
        // Clearing settings is the OS receipt that the outer owner no longer captures traffic.
        // Emit Released only after that asynchronous operation succeeds.
        setTunnelNetworkSettings(nil) { [weak self] error in
            guard let self else { completionHandler(nil); return }
            self.tribeGuardQueue.async {
                guard error == nil else {
                    // A failed settings update retains the old outer owner. Roll the reservation
                    // back and re-arm its exact authority deadline before reporting rejection.
                    guard (try? self.tribeSessionGuard.cancelRelease(
                                request, outer: outer)) != nil else {
                        // Without the exact rollback, neither retained nor released ownership is
                        // proven. An empty reply deliberately keeps the app-side release token.
                        completionHandler(nil)
                        return
                    }
                    self.installAuthorityWatchdog()
                    completionHandler(self.guardJSON(TribeNativeSessionGuard.event(
                        identity: current, kind: "release_rejected",
                        outerSessionId: outer, reason: "settings_release_failed")))
                    return
                }
                do {
                    let event = try self.tribeSessionGuard.commitRelease(request, outer: outer)
                    self.tribePreparedSession = nil
                    self.tribeRuntimeAuthorityLease = nil
                    self.cancelAuthorityWatchdog()
                    completionHandler(self.guardJSON(event))
                } catch {
                    // OS settings were cleared but the exact in-memory commit was not proved.
                    // Never forge ReleaseRejected (retained) or Released (absent); reconciliation
                    // remains fail-closed on the app's still-owned release token.
                    completionHandler(nil)
                }
            }
        }
    }

    private func identity(_ message: [String: Any]) -> TribeNativeGuardIdentity? {
        guard let operation = message[Constants.tribeGuardOperationKey] as? String,
              let session = message[Constants.tribeGuardSessionKey] as? String,
              let policy = message[Constants.tribeGuardPolicyKey] as? String,
              let expected = message[Constants.tribeExpectedRuntimeSessionKey] as? String else {
            return nil
        }
        return try? TribeNativeGuardIdentity(operation: operation, session: session,
                                             policySHA256: policy,
                                             expectedRuntimeSessionId: expected)
    }

    private func handleReconcileMessage(_ message: [String: Any],
                                        completionHandler: @escaping (Data?) -> Void) {
        guard let reconciliation = message["reconcile_kind"] as? String,
              let request = identity(message) else {
            completionHandler(nil)
            return
        }
        let common: Set<String> = [
            Constants.kMessageKeyAction, "reconcile_kind",
            Constants.tribeGuardOperationKey, Constants.tribeGuardSessionKey,
            Constants.tribeGuardPolicyKey, Constants.tribeExpectedRuntimeSessionKey,
        ]
        let event: [String: Any]?
        if reconciliation == "arm", Set(message.keys) == common {
            event = tribeSessionGuard.reconcileTimedOutArm(request)
        } else if reconciliation == "release",
                  Set(message.keys) == common.union([Constants.tribeOuterSessionKey]),
                  let outer = message[Constants.tribeOuterSessionKey] as? String {
            event = tribeSessionGuard.reconcileTimedOutRelease(request, outer: outer)
        } else {
            event = nil
        }
        if let event {
            completionHandler(guardJSON(event))
        } else {
            completionHandler(nil)
        }
    }

    private func handleRecoveryResolutionMessage(
        _ message: [String: Any], completionHandler: @escaping (Data?) -> Void
    ) {
        guard let resolution = message["resolution_action"] as? String,
              resolution == "adopt" || resolution == "stop",
              let request = identity(message),
              let outer = message[Constants.tribeOuterSessionKey] as? String,
              let current = tribeSessionGuard.snapshot().identity,
              current == request,
              tribeSessionGuard.snapshot().outerSessionId == outer else {
            completionHandler(nil)
            return
        }
        if resolution == "adopt" {
            handleRecoveryAdopt(message, request: request, outer: outer,
                                completionHandler: completionHandler)
        } else {
            handleRecoveryStop(message, request: request, outer: outer,
                               completionHandler: completionHandler)
        }
    }

    private func handleRecoveryAdopt(
        _ message: [String: Any], request: TribeNativeGuardIdentity, outer: String,
        completionHandler: @escaping (Data?) -> Void
    ) {
        let exactKeys: Set<String> = [
            Constants.kMessageKeyAction, "resolution_action",
            Constants.tribeGuardOperationKey, Constants.tribeGuardSessionKey,
            Constants.tribeGuardPolicyKey, Constants.tribeExpectedRuntimeSessionKey,
            Constants.tribeOuterSessionKey, Constants.tribeConfigReferenceKey,
            Constants.tribeProtocolKey, Constants.tribeSessionIdKey,
        ]
        guard Set(message.keys) == exactKeys,
              let protocolName = message[Constants.tribeProtocolKey] as? String,
              let reference = message[Constants.tribeConfigReferenceKey] as? String,
              let configSessionId = message[Constants.tribeSessionIdKey] as? String,
              configSessionId == request.expectedRuntimeSessionId,
              let lease = tribeRuntimeAuthorityLease else {
            completionHandler(guardJSON(recoveryReceipt(
                request, action: "adopt", kind: "rejected", outer: outer,
                reason: "adoption_rejected")))
            return
        }
        do {
            try tribeSessionGuard.validateRecoveryAdoption(request, outer: outer)
            let runtime = protocolName == "awg" ? wireguardRuntimeSession.snapshot()
                                                : xrayRuntimeSession.snapshot()
            guard (protocolName == "awg" && protoType == .wireguard
                   || protocolName == "xray" && protoType == .xray),
                  runtime.state == .running,
                  runtime.sessionId == request.expectedRuntimeSessionId else {
                throw TribeNativeGuardProviderError.staleOperation
            }
            let data = try consumeTribeConfig(reference: reference,
                                              protocolName: protocolName,
                                              sessionId: configSessionId)
            let root = try nativeRoot(data, expectedProtocol: protocolName,
                                      expectedPolicy: request.policySHA256)
            guard try TribeNativeDispatchPolicy.outerPolicySHA256(root)
                    == tribeSessionGuard.snapshot().outerPolicySHA256 else {
                throw TribeNativeGuardProviderError.invalidPolicy
            }
            try lease.reconcileRecovery(configuration: root)
            installAuthorityWatchdog()
            completionHandler(guardJSON(recoveryReceipt(
                request, action: "adopt", kind: "adopted", outer: outer, reason: "")))
        } catch {
            completionHandler(guardJSON(recoveryReceipt(
                request, action: "adopt", kind: "rejected", outer: outer,
                reason: "adoption_rejected")))
        }
    }

    private func handleRecoveryStop(
        _ message: [String: Any], request: TribeNativeGuardIdentity, outer: String,
        completionHandler: @escaping (Data?) -> Void
    ) {
        let exactKeys: Set<String> = [
            Constants.kMessageKeyAction, "resolution_action",
            Constants.tribeGuardOperationKey, Constants.tribeGuardSessionKey,
            Constants.tribeGuardPolicyKey, Constants.tribeExpectedRuntimeSessionKey,
            Constants.tribeOuterSessionKey,
        ]
        guard Set(message.keys) == exactKeys else {
            completionHandler(nil)
            return
        }
        let finishOuterRelease: (Error?) -> Void = { [weak self] stopError in
            guard let self else { completionHandler(nil); return }
            self.tribeGuardQueue.async {
                guard stopError == nil else {
                    _ = try? self.tribeSessionGuard.failRecoveryStop(
                        request, outer: outer, reason: "recovery_stop_failed")
                    completionHandler(self.guardJSON(self.recoveryReceipt(
                        request, action: "stop", kind: "rejected", outer: outer,
                        reason: "inner_stop_failed")))
                    return
                }
                do {
                    try self.tribeSessionGuard.proveRecoveryStopped(request, outer: outer)
                    try self.tribeSessionGuard.beginRelease(request, outer: outer)
                    self.cancelAuthorityWatchdog()
                } catch {
                    completionHandler(self.guardJSON(self.recoveryReceipt(
                        request, action: "stop", kind: "rejected", outer: outer,
                        reason: "stale_stop")))
                    return
                }
                self.setTunnelNetworkSettings(nil) { [weak self] settingsError in
                    guard let self else { completionHandler(nil); return }
                    self.tribeGuardQueue.async {
                        guard settingsError == nil else {
                            if (try? self.tribeSessionGuard.cancelRelease(
                                    request, outer: outer)) != nil {
                                self.installAuthorityWatchdog()
                            }
                            completionHandler(self.guardJSON(self.recoveryReceipt(
                                request, action: "stop", kind: "rejected", outer: outer,
                                reason: "settings_release_failed")))
                            return
                        }
                        do {
                            let guardEvent = try self.tribeSessionGuard.commitRelease(
                                request, outer: outer)
                            let runtimeStatus: [String: Any]
                            if self.protoType == .wireguard {
                                runtimeStatus = self.wireguardRuntimeSession.payload(
                                    core: TribeEngineManifest.awgRuntimeStatusCore())
                            } else {
                                runtimeStatus = self.xrayRuntimeSession.payload(
                                    core: TribeEngineManifest.xrayRuntimeStatusCore())
                            }
                            self.tribePreparedSession = nil
                            self.tribeRuntimeAuthorityLease = nil
                            self.cancelAuthorityWatchdog()
                            completionHandler(self.guardJSON([
                                "runtime_status": runtimeStatus,
                                "guard_event": guardEvent,
                                "recovery_receipt": self.recoveryReceipt(
                                    request, action: "stop", kind: "stopped_released",
                                    outer: outer, reason: ""),
                            ]))
                        } catch {
                            completionHandler(self.guardJSON(self.recoveryReceipt(
                                request, action: "stop", kind: "rejected", outer: outer,
                                reason: "release_rejected")))
                        }
                    }
                }
            }
        }

        let needsInnerStop: Bool
        do {
            // Reserve before dispatching either native stop. A duplicate recovery command must
            // never rotate an engine generation or overwrite a singleton stop completion.
            needsInnerStop = try tribeSessionGuard.beginRecoveryStop(request, outer: outer)
        } catch {
            let reason = tribeSessionGuard.snapshot().phase == .releasing
                ? "release_in_progress" : "recovery_stop_in_progress"
            completionHandler(guardJSON(recoveryReceipt(
                request, action: "stop", kind: "rejected", outer: outer, reason: reason)))
            return
        }
        if !needsInnerStop {
            finishOuterRelease(nil)
        } else if protoType == .wireguard {
            stopWireguardInner(completionHandler: finishOuterRelease)
        } else if protoType == .xray {
            stopXray(completionHandler: finishOuterRelease)
        } else {
            finishOuterRelease(TribeNativeGuardProviderError.innerLifecycleFailed)
        }
    }

    private func recoveryReceipt(_ identity: TribeNativeGuardIdentity, action: String,
                                 kind: String, outer: String, reason: String) -> [String: Any] {
        [
            "type": "native_session_guard_recovery_v1", "schema": 1,
            "action": action, "kind": kind,
            "operation": identity.operation, "session": identity.session,
            "policy_sha256": identity.policySHA256,
            "outer_session_id": outer,
            "expected_runtime_session_id": identity.expectedRuntimeSessionId,
            "reason": reason,
        ]
    }

    private func handleAuthorityRenewMessage(_ message: [String: Any],
                                             completionHandler: @escaping (Data?) -> Void) {
        let expectedKeys: Set<String> = [
            Constants.kMessageKeyAction, Constants.tribeAuthorityRenewalRequestKey,
            Constants.tribeConfigReferenceKey, Constants.tribeProtocolKey,
            Constants.tribeSessionIdKey,
        ]
        guard Set(message.keys) == expectedKeys,
              let requestFields = message[
                Constants.tribeAuthorityRenewalRequestKey] as? [String: Any],
              let request = try? TribeRuntimeAuthorityRenewalRequest(fields: requestFields),
              let protocolName = message[Constants.tribeProtocolKey] as? String,
              let reference = message[Constants.tribeConfigReferenceKey] as? String,
              let configSessionId = message[Constants.tribeSessionIdKey] as? String,
              configSessionId == request.expectedRuntimeSessionId else {
            completionHandler(nil)
            return
        }
        let reject: (String) -> Void = { [weak self] reason in
            guard let self else { completionHandler(nil); return }
            completionHandler(self.guardJSON(
                TribeRuntimeAuthorityRenewalReceipt.rejected(
                    request, reason: reason).fields()))
        }
        guard let current = tribeSessionGuard.snapshot().identity,
              current.operation == request.operation,
              current.session == request.session,
              current.policySHA256 == request.policySHA256,
              current.expectedRuntimeSessionId == request.expectedRuntimeSessionId,
              tribeSessionGuard.snapshot().outerSessionId == request.outerSessionId,
              tribeSessionGuard.snapshot().phase == .running,
              let lease = tribeRuntimeAuthorityLease else {
            reject("renewal_target_mismatch")
            return
        }
        do {
            let data = try consumeTribeConfig(reference: reference,
                                              protocolName: protocolName,
                                              sessionId: configSessionId)
            let root = try nativeRoot(data, expectedProtocol: protocolName,
                                      expectedPolicy: request.policySHA256)
            guard try TribeNativeDispatchPolicy.outerPolicySHA256(root)
                    == tribeSessionGuard.snapshot().outerPolicySHA256 else {
                throw TribeRuntimeAuthorityLeaseError.identityChanged
            }
            var appliedReceipt: TribeRuntimeAuthorityRenewalReceipt?
            _ = try lease.renew(configuration: root) { replacement in
                try request.validate(configuration: root, serializedConfiguration: data,
                                     snapshot: replacement)
                let receipt = TribeRuntimeAuthorityRenewalReceipt.applied(request)
                do {
                    try TribeRuntimeAuthorityRenewalStore.persist(receipt)
                } catch {
                    throw TribeRuntimeAuthorityRenewalError.persistence
                }
                appliedReceipt = receipt
            }
            guard let appliedReceipt else {
                throw TribeRuntimeAuthorityRenewalError.persistence
            }
            installAuthorityWatchdog()
            completionHandler(guardJSON(appliedReceipt.fields()))
        } catch TribeRuntimeAuthorityRenewalError.persistence {
            reject("durable_persist_failed")
        } catch {
            reject("renewal_rejected")
        }
    }

    private func installAuthorityWatchdog() {
        cancelAuthorityWatchdog()
        guard let lease = tribeRuntimeAuthorityLease else { return }
        let remaining: TimeInterval
        do {
            remaining = try TribeRuntimeAuthorityWatchdogPlanner.remaining(
                snapshot: lease.snapshot(), wallUtc: Date(),
                monotonic: ProcessInfo.processInfo.systemUptime)
        } catch {
            quarantineExpiredAuthority()
            return
        }
        let interval = remaining * 1_000_000_000
        guard interval.isFinite, interval > 0, interval < Double(UInt64.max) else {
            quarantineExpiredAuthority()
            return
        }
        let delayNanos = max(UInt64(1), UInt64(interval.rounded(.up)))
        let now = DispatchTime.now().uptimeNanoseconds
        let sum = now.addingReportingOverflow(delayNanos)
        guard !sum.overflow else {
            quarantineExpiredAuthority()
            return
        }
        let generation = tribeAuthorityWatchdogFence.arm()
        let timer = DispatchSource.makeTimerSource(queue: tribeGuardQueue)
        timer.schedule(deadline: DispatchTime(uptimeNanoseconds: sum.partialValue),
                       leeway: .nanoseconds(0))
        timer.setEventHandler { [weak self] in
            guard let self,
                  self.tribeAuthorityWatchdogFence.consume(generation),
                  self.tribeRuntimeAuthorityLease === lease else { return }
            timer.setEventHandler {}
            timer.cancel()
            if self.tribeAuthorityWatchdog === timer {
                self.tribeAuthorityWatchdog = nil
            }
            do {
                try lease.evaluate()
                // Dispatch timers do not fire early, but sub-millisecond clock conversion and a
                // concurrently refreshed wall observation may leave a positive remainder.
                self.installAuthorityWatchdog()
            } catch {
                self.quarantineExpiredAuthority()
            }
        }
        tribeAuthorityWatchdog = timer
        timer.resume()
    }

    func cancelAuthorityWatchdog() {
        tribeAuthorityWatchdogFence.cancel()
        tribeAuthorityWatchdog?.setEventHandler {}
        tribeAuthorityWatchdog?.cancel()
        tribeAuthorityWatchdog = nil
    }

    private func quarantineExpiredAuthority() {
        let snapshot = tribeSessionGuard.snapshot()
        guard let identity = snapshot.identity, snapshot.phase != .quarantined else { return }
        cancelAuthorityWatchdog()
        _ = tribeSessionGuard.lostEvent(reason: "runtime_authority_expired")
        tribePreparedSession = nil
        let terminal: (Error?) -> Void = { [weak self] error in
            guard let self else { return }
            self.tribeGuardQueue.async {
                if error != nil {
                    _ = self.tribeSessionGuard.lostEvent(
                        reason: "runtime_authority_stop_failed")
                }
            }
        }
        if snapshot.phase == .running || snapshot.phase == .starting {
            if protoType == .wireguard {
                stopWireguardInner(completionHandler: terminal)
            } else if protoType == .xray {
                stopXray(completionHandler: terminal)
            } else {
                terminal(TribeNativeGuardProviderError.innerLifecycleFailed)
            }
        }
        _ = identity
    }

    private func nativeRoot(_ data: Data, expectedProtocol: String,
                            expectedPolicy: String) throws -> [String: Any] {
        guard data.count <= 2 * 1024 * 1024,
              let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              try TribeNativeDispatchPolicy.validateEnvelope(root),
              root["protocol"] as? String == expectedProtocol,
              let authority = root["runtime_authority_v1"] as? [String: Any],
              authority["policy_sha256"] as? String == expectedPolicy else {
            throw TribeNativeGuardProviderError.invalidPolicy
        }
        return root
    }

    // Internal for deterministic host route-policy tests; production callers remain this provider.
    func guardNetworkSettings(_ root: [String: Any]) throws
        -> NEPacketTunnelNetworkSettings {
        guard let dns1 = root["dns1"] as? String,
              let dns2 = root["dns2"] as? String,
              let splitNumber = root["splitTunnelType"] as? NSNumber,
              splitNumber.doubleValue.isFinite,
              Double(splitNumber.intValue) == splitNumber.doubleValue,
              let split = Optional(splitNumber.intValue),
              (0...2).contains(split),
              let authority = root["runtime_authority_v1"] as? [String: Any],
              let protected = authority["protected_tunnel_ips"] as? [String] else {
            throw TribeNativeGuardProviderError.invalidPolicy
        }
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "254.1.1.1")
        settings.mtu = 1280
        let v4 = NEIPv4Settings(addresses: ["198.18.0.1"],
                                subnetMasks: ["255.255.0.0"])
        let v6 = NEIPv6Settings(addresses: ["fd6e:a81b:704f:1211::1"],
                                networkPrefixLengths: [64])
        if split == 0 {
            v4.includedRoutes = [NEIPv4Route.default()]
            v6.includedRoutes = [NEIPv6Route.default()]
        } else if split == 1 {
            guard let sites = root["splitTunnelSites"] as? [String], !sites.isEmpty else {
                throw TribeNativeGuardProviderError.invalidPolicy
            }
            let routes = try (sites + protected).map(parseNativeGuardRoute)
            v4.includedRoutes = routes.compactMap {
                if case .ipv4(let route) = $0 { return route }
                return nil
            }
            v6.includedRoutes = routes.compactMap {
                if case .ipv6(let route) = $0 { return route }
                return nil
            }
        } else {
            guard let sites = root["splitTunnelSites"] as? [String], !sites.isEmpty else {
                throw TribeNativeGuardProviderError.invalidPolicy
            }
            // Mode 2 is full tunnel with explicit direct CIDRs. Protected verifier/bootstrap
            // literals must never fall into those exclusions; reject overlap independently of
            // the C++ compiler instead of relying on ambiguous included-vs-excluded precedence.
            do {
                try TribeProtectedSplitPolicy.validateMode2(
                    exclusions: sites, protectedLiterals: protected)
            } catch {
                throw TribeNativeGuardProviderError.invalidPolicy
            }
            let routes = try sites.map(parseNativeGuardRoute)
            v4.includedRoutes = [NEIPv4Route.default()]
            v6.includedRoutes = [NEIPv6Route.default()]
            v4.excludedRoutes = routes.compactMap {
                if case .ipv4(let route) = $0 { return route }
                return nil
            }
            v6.excludedRoutes = routes.compactMap {
                if case .ipv6(let route) = $0 { return route }
                return nil
            }
        }
        settings.ipv4Settings = v4
        settings.ipv6Settings = v6
        settings.dnsSettings = NEDNSSettings(servers: [dns1, dns2].filter { !$0.isEmpty })
        return settings
    }

    private func parseNativeGuardRoute(_ value: String) throws -> TribeNativeGuardRoute {
        let components = value.split(separator: "/", omittingEmptySubsequences: false)
        guard components.count == 1 || components.count == 2 else {
            throw TribeNativeGuardProviderError.invalidPolicy
        }
        let prefix: Int?
        if components.count == 2 {
            guard let parsed = Int(components[1]), String(parsed) == String(components[1]) else {
                throw TribeNativeGuardProviderError.invalidPolicy
            }
            prefix = parsed
        } else {
            prefix = nil
        }
        let address = String(components[0])
        var v4 = in_addr()
        if inet_pton(AF_INET, address, &v4) == 1 {
            let bits = prefix ?? 32
            guard (0...32).contains(bits) else {
                throw TribeNativeGuardProviderError.invalidPolicy
            }
            var canonical = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            let bytes = withUnsafeBytes(of: &v4) { Array($0) }
            guard inet_ntop(AF_INET, &v4, &canonical,
                            socklen_t(canonical.count)) != nil,
                  String(cString: canonical) == address,
                  nativeGuardHostBitsAreZero(bytes, prefix: bits) else {
                throw TribeNativeGuardProviderError.invalidPolicy
            }
            let mask = bits == 0 ? UInt32(0) : UInt32.max << UInt32(32 - bits)
            let maskAddress = String(format: "%u.%u.%u.%u",
                                     (mask >> 24) & 0xff, (mask >> 16) & 0xff,
                                     (mask >> 8) & 0xff, mask & 0xff)
            return .ipv4(NEIPv4Route(destinationAddress: address, subnetMask: maskAddress))
        }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, address, &v6) == 1 {
            let bits = prefix ?? 128
            guard (0...128).contains(bits) else {
                throw TribeNativeGuardProviderError.invalidPolicy
            }
            var canonical = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            let bytes = withUnsafeBytes(of: &v6) { Array($0) }
            guard inet_ntop(AF_INET6, &v6, &canonical,
                            socklen_t(canonical.count)) != nil,
                  String(cString: canonical) == address,
                  nativeGuardHostBitsAreZero(bytes, prefix: bits) else {
                throw TribeNativeGuardProviderError.invalidPolicy
            }
            return .ipv6(NEIPv6Route(destinationAddress: address,
                                     networkPrefixLength: NSNumber(value: bits)))
        }
        throw TribeNativeGuardProviderError.invalidPolicy
    }

    private func nativeGuardHostBitsAreZero(_ bytes: [UInt8], prefix: Int) -> Bool {
        guard prefix >= 0 && prefix <= bytes.count * 8 else { return false }
        for bit in prefix..<(bytes.count * 8) {
            if (bytes[bit / 8] & (UInt8(0x80) >> UInt8(bit % 8))) != 0 { return false }
        }
        return true
    }

    private func nativeGuardRoute(_ cidr: String, contains literal: String) throws -> Bool {
        let components = cidr.split(separator: "/", omittingEmptySubsequences: false)
        guard components.count == 1 || components.count == 2 else {
            throw TribeNativeGuardProviderError.invalidPolicy
        }
        let base = String(components[0])
        let prefixText = components.count == 2 ? String(components[1]) : nil
        var base4 = in_addr(), host4 = in_addr()
        if inet_pton(AF_INET, base, &base4) == 1 {
            guard inet_pton(AF_INET, literal, &host4) == 1 else { return false }
            let prefix = prefixText.flatMap(Int.init) ?? 32
            guard prefixText == nil || String(prefix) == prefixText,
                  (0...32).contains(prefix) else {
                throw TribeNativeGuardProviderError.invalidPolicy
            }
            let lhs = withUnsafeBytes(of: &base4) { Array($0) }
            let rhs = withUnsafeBytes(of: &host4) { Array($0) }
            return nativeGuardPrefixEqual(lhs, rhs, prefix: prefix)
        }
        var base6 = in6_addr(), host6 = in6_addr()
        guard inet_pton(AF_INET6, base, &base6) == 1 else {
            throw TribeNativeGuardProviderError.invalidPolicy
        }
        guard inet_pton(AF_INET6, literal, &host6) == 1 else { return false }
        let prefix = prefixText.flatMap(Int.init) ?? 128
        guard prefixText == nil || String(prefix) == prefixText,
              (0...128).contains(prefix) else {
            throw TribeNativeGuardProviderError.invalidPolicy
        }
        let lhs = withUnsafeBytes(of: &base6) { Array($0) }
        let rhs = withUnsafeBytes(of: &host6) { Array($0) }
        return nativeGuardPrefixEqual(lhs, rhs, prefix: prefix)
    }

    private func nativeGuardPrefixEqual(_ lhs: [UInt8], _ rhs: [UInt8],
                                        prefix: Int) -> Bool {
        guard lhs.count == rhs.count, prefix >= 0, prefix <= lhs.count * 8 else { return false }
        let full = prefix / 8
        if full > 0 && lhs.prefix(full) != rhs.prefix(full) { return false }
        let remainder = prefix % 8
        if remainder == 0 { return true }
        let mask = UInt8.max << UInt8(8 - remainder)
        return (lhs[full] & mask) == (rhs[full] & mask)
    }

    private func guardJSON(_ object: [String: Any]) -> Data? {
        guard JSONSerialization.isValidJSONObject(object) else { return nil }
        return try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }
}
