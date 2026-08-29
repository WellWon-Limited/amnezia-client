import Foundation
import NetworkExtension

extension PacketTunnelProvider {
    func startWireguard(activationAttemptId: String?,
                        errorNotifier: ErrorNotifier,
                        guardPreparation: WireGuardGuardPreparation? = nil,
                        handoff suppliedHandoff: (data: Data, sessionId: String)? = nil,
                        completionHandler: @escaping (Error?) -> Void) {
        let handoff: (data: Data, sessionId: String)
        do {
            handoff = try suppliedHandoff
                ?? consumeTribeConfig(expectedProtocols: ["awg", "wireguard"])
        } catch {
            wg_log(.error, message: "Can't start, encrypted config handoff missing")
            completionHandler(PacketTunnelProviderError.savedProtocolConfigurationIsInvalid)
            return
        }
        let runtimeGeneration = wireguardRuntimeSession.beginSession(
            protocolName: "awg", sessionId: handoff.sessionId)
        func finishStart(_ error: Error?) {
            _ = wireguardRuntimeSession.transition(
                to: error == nil ? .running : .failed,
                generation: runtimeGeneration
            )
            completionHandler(error)
        }
        do {
            let wgConfig = try WGConfig.decodeNativeEnvelope(handoff.data)
            try wgConfig.validateAwg31Booleans() // AVPN: fail closed before Apple quick/UAPI conversion.
            let wgConfigStr = wgConfig.str

            // AVPN split-DNS форвардер: настроить Go-слой ДО старта адаптера (wgTurnOn читает
            // конфиг форвардера при создании устройства). Выключен → явный сброс (переподключения).
            if wgConfig.dnsFwdEnabled {
                let rc = wgSetSplitDns(wgConfig.dnsFwdSuffixes ?? "",
                                       wgConfig.dnsFwdServer ?? "77.88.8.8",
                                       wgConfig.dns1,
                                       wgConfig.clientIP,
                                       1,
                                       wgConfig.dnsFwdWarmupEnabled ? 1 : 0)
                wg_log(.info, message: "AVPN dnsfwd: enable rc=\(rc) warmup=\(wgConfig.dnsFwdWarmupEnabled)")
            } else {
                _ = wgSetSplitDns("", "", "", "", 0, 0)
            }

            let decodedTunnel = try makeWireguardTunnelConfiguration(wgConfig, wgConfigStr)
            let tunnelConfiguration: TunnelConfiguration
            if wgConfig.guardedCatalogV2 == true {
                guard let guardPreparation,
                      guardPreparation.tunnelConfiguration == decodedTunnel else {
                    throw PacketTunnelProviderError.savedProtocolConfigurationIsInvalid
                }
                tunnelConfiguration = guardPreparation.tunnelConfiguration
            } else {
                guard guardPreparation == nil else {
                    throw PacketTunnelProviderError.savedProtocolConfigurationIsInvalid
                }
                tunnelConfiguration = decodedTunnel
            }

            wg_log(.info, message: "Starting tunnel from the " +
                   (activationAttemptId == nil ? "OS directly, rather than the app" : "app"))

            // Start the tunnel
            wgAdapter = WireGuardAdapter(
                with: self,
                // PREPARE is the sole NetworkExtension settings owner for authenticated
                // catalog-v2 sessions. The immutable preparation freezes endpoint resolution
                // and also fences update/path-resume route mutations after RELEASE.
                guardPreparation: guardPreparation
            ) { logLevel, message in
                wg_log(logLevel.osLogLevel, message: message)
            }

            wgAdapter?.start(tunnelConfiguration: tunnelConfiguration) { [weak self] adapterError in
                guard let self else {
                    finishStart(PacketTunnelProviderError.couldNotStartBackend)
                    return
                }
                guard self.wireguardRuntimeSession.isCurrent(generation: runtimeGeneration) else {
                    // A stop/superseding start won while the adapter activation was pending.
                    // Prove physical teardown; never let a late callback leave AWG behind the
                    // already-completed outer-guard stop receipt.
                    self.wgAdapter?.stop { _ in
                        finishStart(PacketTunnelProviderError.couldNotStartBackend)
                    }
                    return
                }
                guard let adapterError else {
                    let interfaceName = self.wgAdapter?.interfaceName ?? "unknown"
                    wg_log(.info, message: "Tunnel interface is \(interfaceName)")
                    // AVPN: a successful handshake/start is not proof that
                    // the 3.1 wire-format options reached the native engine.
                    // Read them back from UAPI and fail closed on an old or
                    // mismatched Apple adapter.
                    let expected = wgConfig.awg31UapiExpectations
                    guard !expected.isEmpty else {
                        finishStart(nil)
                        return
                    }
                    guard let adapter = self.wgAdapter else {
                        errorNotifier.notify(PacketTunnelProviderError.couldNotStartBackend)
                        finishStart(PacketTunnelProviderError.couldNotStartBackend)
                        return
                    }
                    adapter.getRuntimeConfiguration { settings in
                        guard self.wireguardRuntimeSession.isCurrent(
                            generation: runtimeGeneration) else {
                            adapter.stop { _ in
                                finishStart(PacketTunnelProviderError.couldNotStartBackend)
                            }
                            return
                        }
                        var actual: [String: String] = [:]
                        for line in (settings ?? "").split(separator: "\n") {
                            let parts = line.split(separator: "=", maxSplits: 1).map(String.init)
                            if parts.count == 2 { actual[parts[0]] = parts[1] }
                        }
                        let valid = expected.allSatisfy { actual[$0.key] == $0.value }
                        if valid {
                            wg_log(.info, message: "AVPN AWG 3.1 UAPI capability verified: " +
                                   expected.keys.sorted().joined(separator: ","))
                            finishStart(nil)
                            return
                        }
                        wg_log(.error, message: "AVPN AWG 3.1 UAPI capability mismatch; stopping tunnel")
                        adapter.stop { _ in
                            errorNotifier.notify(PacketTunnelProviderError.couldNotStartBackend)
                            finishStart(PacketTunnelProviderError.couldNotStartBackend)
                        }
                    }
                    return
                }

                switch adapterError {
                case .cannotLocateTunnelFileDescriptor:
                    wg_log(.error, staticMessage: "Starting tunnel failed: could not determine file descriptor")
                    errorNotifier.notify(PacketTunnelProviderError.couldNotDetermineFileDescriptor)
                    finishStart(PacketTunnelProviderError.couldNotDetermineFileDescriptor)
                case .dnsResolution(let dnsErrors):
                    let hostnamesWithDnsResolutionFailure = dnsErrors.map { $0.address }
                        .joined(separator: ", ")
                    wg_log(.error, message:
                            "DNS resolution failed for the following hostnames: \(hostnamesWithDnsResolutionFailure)")
                    errorNotifier.notify(PacketTunnelProviderError.dnsResolutionFailure)
                    finishStart(PacketTunnelProviderError.dnsResolutionFailure)
                case .setNetworkSettings(let error):
                    wg_log(.error, message:
                            "Starting tunnel failed with setTunnelNetworkSettings returning \(error.localizedDescription)")
                    errorNotifier.notify(PacketTunnelProviderError.couldNotSetNetworkSettings)
                    finishStart(PacketTunnelProviderError.couldNotSetNetworkSettings)
                case .startWireGuardBackend(let errorCode):
                    wg_log(.error, message: "Starting tunnel failed with wgTurnOn returning \(errorCode)")
                    errorNotifier.notify(PacketTunnelProviderError.couldNotStartBackend)
                    finishStart(PacketTunnelProviderError.couldNotStartBackend)
                case .invalidState:
                    wg_log(.error, staticMessage: "Starting tunnel failed: adapter lifecycle state is invalid")
                    errorNotifier.notify(PacketTunnelProviderError.couldNotStartBackend)
                    finishStart(PacketTunnelProviderError.couldNotStartBackend)
                }
            }
        } catch {
            wg_log(.error, message: "Can't parse WG config: \(error.localizedDescription)")
            errorNotifier.notify(PacketTunnelProviderError.savedProtocolConfigurationIsInvalid)
            finishStart(PacketTunnelProviderError.savedProtocolConfigurationIsInvalid)
            return
        }
    }

    /// PREPARE-side AWG work. DNS is resolved exactly once before outer ownership is armed; the
    /// same opaque preparation later supplies both UAPI and path-resume endpoint state.
    func prepareGuardedWireguard(_ data: Data) throws -> WireGuardGuardPreparation {
        let wgConfig = try WGConfig.decodeNativeEnvelope(data)
        guard wgConfig.guardedCatalogV2 == true,
              let protected = wgConfig.protectedTunnelIPs, !protected.isEmpty else {
            throw PacketTunnelProviderError.savedProtocolConfigurationIsInvalid
        }
        try wgConfig.validateAwg31Booleans()
        let tunnel = try makeWireguardTunnelConfiguration(wgConfig, wgConfig.str)
        let preparation = try WireGuardAdapter.prepareGuardedTunnel(
            tunnelConfiguration: tunnel)
        let endpoints = preparation.resolvedEndpointLiterals
        guard endpoints.count == tunnel.peers.count,
              endpoints.allSatisfy(TribeNativeDispatchPolicy.isPublicEndpointLiteral) else {
            throw PacketTunnelProviderError.savedProtocolConfigurationIsInvalid
        }
        do {
            try TribeProtectedSplitPolicy.validateMode2(
                exclusions: endpoints.map { $0 + ($0.contains(":") ? "/128" : "/32") },
                protectedLiterals: protected)
        } catch {
            // A verifier/bootstrap address must never share the transport endpoint's direct
            // exclusion; otherwise its signed through-tunnel proof could bypass the guard.
            throw PacketTunnelProviderError.savedProtocolConfigurationIsInvalid
        }
        return preparation
    }

    private func makeWireguardTunnelConfiguration(
        _ wgConfig: WGConfig, _ wgConfigString: String
    ) throws -> TunnelConfiguration {
        let tunnelConfiguration = try TunnelConfiguration(fromWgQuickConfig: wgConfigString)
        guard tunnelConfiguration.peers.count == 1 else {
            throw PacketTunnelProviderError.savedProtocolConfigurationIsInvalid
        }
        let protectedRanges: [IPAddressRange]
        if wgConfig.guardedCatalogV2 == true {
            guard let protected = wgConfig.protectedTunnelIPs, !protected.isEmpty else {
                throw PacketTunnelProviderError.savedProtocolConfigurationIsInvalid
            }
            if wgConfig.splitTunnelType == 2 {
                do {
                    try TribeProtectedSplitPolicy.validateMode2(
                        exclusions: wgConfig.splitTunnelSites,
                        protectedLiterals: protected)
                } catch {
                    throw PacketTunnelProviderError.savedProtocolConfigurationIsInvalid
                }
            }
            protectedRanges = try protected.map { value in
                guard !value.contains("/"), let range = IPAddressRange(from: value) else {
                    throw PacketTunnelProviderError.savedProtocolConfigurationIsInvalid
                }
                return range
            }
        } else {
            protectedRanges = []
        }
        let initialAllowedIPs = Set(tunnelConfiguration.peers[0].allowedIPs
            .map({ $0.stringRepresentation }))
        let hasFullDualStackPolicy = initialAllowedIPs.contains("0.0.0.0/0")
            && initialAllowedIPs.contains("::/0")
        if wgConfig.guardedCatalogV2 == true && wgConfig.splitTunnelType != 0
            && !hasFullDualStackPolicy {
            throw PacketTunnelProviderError.savedProtocolConfigurationIsInvalid
        }
        if hasFullDualStackPolicy {
            if wgConfig.splitTunnelType == 1 {
                guard !wgConfig.splitTunnelSites.isEmpty else {
                    throw PacketTunnelProviderError.savedProtocolConfigurationIsInvalid
                }
                for index in tunnelConfiguration.peers.indices {
                    tunnelConfiguration.peers[index].allowedIPs.removeAll()
                    var allowedIPs = [IPAddressRange]()
                    for value in wgConfig.splitTunnelSites {
                        guard let range = IPAddressRange(from: value) else {
                            throw PacketTunnelProviderError.savedProtocolConfigurationIsInvalid
                        }
                        allowedIPs.append(range)
                    }
                    allowedIPs.append(contentsOf: protectedRanges)
                    tunnelConfiguration.peers[index].allowedIPs = allowedIPs
                }
            } else if wgConfig.splitTunnelType == 2 {
                guard !wgConfig.splitTunnelSites.isEmpty else {
                    throw PacketTunnelProviderError.savedProtocolConfigurationIsInvalid
                }
                for index in tunnelConfiguration.peers.indices {
                    var excludeIPs = [IPAddressRange]()
                    for value in wgConfig.splitTunnelSites {
                        guard let range = IPAddressRange(from: value) else {
                            throw PacketTunnelProviderError.savedProtocolConfigurationIsInvalid
                        }
                        excludeIPs.append(range)
                    }
                    tunnelConfiguration.peers[index].excludeIPs = excludeIPs
                }
            }
        }
        return tunnelConfiguration
    }

    func handleWireguardStatusMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        guard let completionHandler = completionHandler else { return }
        guard let wgAdapter = wgAdapter else {
            completionHandler(try? JSONSerialization.data(
                withJSONObject: wireguardRuntimeSession.payload(
                    core: TribeEngineManifest.awgRuntimeStatusCore()
                ),
                options: []
            ))
            return
        }
        wgAdapter.getRuntimeConfiguration { settings in
            guard let settings = settings else {
                completionHandler(try? JSONSerialization.data(
                    withJSONObject: self.wireguardRuntimeSession.payload(
                        core: TribeEngineManifest.awgRuntimeStatusCore()
                    ),
                    options: []
                ))
                return
            }
            let components = settings.components(separatedBy: "\n")

            var settingsDictionary: [String: String] = [:]
            for component in components {
                let pair = component.components(separatedBy: "=")
                if pair.count == 2 {
                    settingsDictionary[pair[0]] = pair[1]
                }
            }

            let lastHandshakeString = settingsDictionary["last_handshake_time_sec"]
            let lastHandshake: Int64

            if let lastHandshakeValue = lastHandshakeString, let handshakeValue = Int64(lastHandshakeValue) {
                lastHandshake = handshakeValue
            } else {
                lastHandshake = -2  // Return an error if there is no value for `last_handshake_time_sec`
            }

            let rawRx = UInt64(settingsDictionary["rx_bytes"] ?? "0") ?? 0
            let rawTx = UInt64(settingsDictionary["tx_bytes"] ?? "0") ?? 0
            let snapshot = self.wireguardRuntimeSession.snapshot()
            if snapshot.state == .running {
                _ = self.wireguardRuntimeSession.record(
                    TunnelTrafficSample(rxBytes: rawRx, txBytes: rawTx),
                    generation: snapshot.generation
                )
            }
            let response = self.wireguardRuntimeSession.payload(
                core: TribeEngineManifest.awgRuntimeStatusCore(),
                lastHandshakeEpochSec: lastHandshake > 0 ? UInt64(lastHandshake) : nil
            )

            completionHandler(try? JSONSerialization.data(withJSONObject: response, options: []))
        }
    }

    // AVPN (BUG-4 auto-heal): ребайнд UDP-сокета живого туннеля. wgSetConfig("listen_port=0")
    // -> IpcSet -> BindUpdate в awg-go: сокет закрывается и открывается на НОВОМ эфемерном
    // порту (новый 5-tuple flow — лечит сессионный блок ТСПУ; эквивалент режима полёта).
    // Туннель/handshake-стейт не трогаются, пиры не заменяются. Ответ {"ok":Bool} — для лога GUI.
    func handleRebindAppMessage(completionHandler: ((Data?) -> Void)? = nil) {
        guard let completionHandler = completionHandler else { return }
        guard protoType == .wireguard, let wgAdapter = wgAdapter else {
            completionHandler(try? JSONSerialization.data(withJSONObject: ["ok": false], options: []))
            return
        }
        wgAdapter.rebindListenPort { error in
            let ok = (error == nil)
            wg_log(.info, message: "AVPN rebind-heal: listen_port rebind " + (ok ? "done" : "failed (adapter not started)"))
            completionHandler(try? JSONSerialization.data(withJSONObject: ["ok": ok], options: []))
        }
    }

    func handleWireguardAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        guard let completionHandler = completionHandler else { return }
        if messageData.count == 1 && messageData[0] == 0 {
            wgAdapter?.getRuntimeConfiguration { settings in
                var data: Data?
                if let settings {
                    data = settings.data(using: .utf8)!
                }
                completionHandler(data)
            }
        } else if messageData.count >= 1 {
            // Updates the tunnel configuration and responds with the active configuration
            wg_log(.info, message: "Switching tunnel configuration")
            guard let configString = String(data: messageData, encoding: .utf8)
            else {
                completionHandler(nil)
                return
            }

            do {
                let tunnelConfiguration = try TunnelConfiguration(fromWgQuickConfig: configString)
                wgAdapter?.update(tunnelConfiguration: tunnelConfiguration) { [weak self] error in
                    if let error {
                        wg_log(.error, message: "Failed to switch tunnel configuration: \(error.localizedDescription)")
                        completionHandler(nil)
                        return
                    }

                    self?.wgAdapter?.getRuntimeConfiguration { settings in
                        var data: Data?
                        if let settings {
                            data = settings.data(using: .utf8)!
                        }
                        completionHandler(data)
                    }
                }
            } catch {
                completionHandler(nil)
            }
        } else {
            completionHandler(nil)
        }
    }

    func stopWireguard(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        wg_log(.info, message: "Stopping tunnel: reason: \(reason.amneziaDescription)")
        stopWireguardInner { _ in completionHandler() }
    }

    /// Exact inner teardown used during catalog-v2 fallback.  Network settings remain owned by
    /// PacketTunnelProvider; an adapter error is not a teardown receipt.
    func stopWireguardInner(completionHandler: @escaping (Error?) -> Void) {
        let stopGeneration = wireguardRuntimeSession.beginStop()

        guard let wgAdapter else {
            _ = wireguardRuntimeSession.transition(to: .stopped, generation: stopGeneration)
            completionHandler(nil)
            return
        }
        wgAdapter.stop { [weak self] error in
            ErrorNotifier.removeLastErrorFile()

            if let error {
                wg_log(.error, message: "Failed to stop WireGuard adapter: \(error.localizedDescription)")
            }
            _ = self?.wireguardRuntimeSession.transition(
                to: error == nil ? .stopped : .failed,
                generation: stopGeneration
            )
            if error == nil { self?.wgAdapter = nil }
            completionHandler(error)

#if os(macOS)
            // HACK: This is a filthy hack to work around Apple bug 32073323 (dup'd by us as 47526107).
            // Remove it when they finally fix this upstream and the fix has been rolled out to
            // sufficient quantities of users.
            exit(0)
#endif
        }
    }
}
