import Foundation
import NetworkExtension

extension PacketTunnelProvider {
    func startWireguard(activationAttemptId: String?,
                        errorNotifier: ErrorNotifier,
                        completionHandler: @escaping (Error?) -> Void) {
        guard let protocolConfiguration = self.protocolConfiguration as? NETunnelProviderProtocol,
              let providerConfiguration = protocolConfiguration.providerConfiguration,
              let wgConfigData: Data = providerConfiguration[Constants.wireGuardConfigKey] as? Data else {
            wg_log(.error, message: "Can't start, config missing")
            completionHandler(nil)
            return
        }

        do {
            let wgConfig = try JSONDecoder().decode(WGConfig.self, from: wgConfigData)
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

            let tunnelConfiguration = try TunnelConfiguration(fromWgQuickConfig: wgConfigStr)

            if tunnelConfiguration.peers.first!.allowedIPs
                .map({ $0.stringRepresentation })
                .joined(separator: ", ") == "0.0.0.0/0, ::/0" {
                if wgConfig.splitTunnelType == 1 {
                    for index in tunnelConfiguration.peers.indices {
                        tunnelConfiguration.peers[index].allowedIPs.removeAll()
                        var allowedIPs = [IPAddressRange]()

                        for allowedIPString in wgConfig.splitTunnelSites {
                            if let allowedIP = IPAddressRange(from: allowedIPString) {
                                allowedIPs.append(allowedIP)
                            }
                        }

                        tunnelConfiguration.peers[index].allowedIPs = allowedIPs
                    }
                } else if wgConfig.splitTunnelType == 2 {
                    for index in tunnelConfiguration.peers.indices {
                        var excludeIPs = [IPAddressRange]()

                        for excludeIPString in wgConfig.splitTunnelSites {
                            if let excludeIP = IPAddressRange(from: excludeIPString) {
                                excludeIPs.append(excludeIP)
                            }
                        }

                        tunnelConfiguration.peers[index].excludeIPs = excludeIPs
                    }
                }
            }

            wg_log(.info, message: "Starting tunnel from the " +
                   (activationAttemptId == nil ? "OS directly, rather than the app" : "app"))

            // Start the tunnel
            let generation = tribeRuntimeGeneration
            let adapter = WireGuardAdapter(with: self) { [weak self] logLevel, message in
                wg_log(logLevel.osLogLevel, message: message)
                // Persist recovery evidence even with a dead/suspended GUI and disabled ne.log.
                // Never copy arbitrary native log text (it can contain endpoints/config values):
                // only the fixed event label (TribeNEJournal) and the adapter counters.
                guard let event = TribeNEJournal.event(forAdapterLog: message) else { return }
                // Runs on the adapter's workQueue: the counters callback is queued behind this log
                // call, and the journal write itself hops to TribeSharedState.journalQueue (D4).
                self?.wgAdapter?.roamingCounters { counters in
                    TribeSharedState.appGroup?.recordAsync(source: "ne", event: event,
                        fields: ["generation": generation, "counters": counters.asDictionary])
                }
            }
            wgAdapter = adapter

            // AVPN seamless roaming: политика ДО start() (адаптер читает её на своей очереди).
            let roaming = wgConfig.roamingPolicy
            adapter.roamingPolicy = roaming
            wg_log(.info, message: "Tribe roaming policy: keepBackend=\(roaming.keepBackendOnPathLoss) pauseAfter=\(Int(roaming.pauseAfterUnsatisfiedSeconds))s stallProbe=\(Int(roaming.stallProbeSeconds))s stallRebind=\(Int(roaming.stallRebindSeconds))s")

            adapter.start(tunnelConfiguration: tunnelConfiguration) { adapterError in
                guard let adapterError else {
                    let interfaceName = adapter.interfaceName ?? "unknown"
                    wg_log(.info, message: "Tunnel interface is \(interfaceName)")
                    self.startTribeStatsTimer()
                    completionHandler(nil)
                    return
                }

                switch adapterError {
                case .cannotLocateTunnelFileDescriptor:
                    wg_log(.error, staticMessage: "Starting tunnel failed: could not determine file descriptor")
                    errorNotifier.notify(PacketTunnelProviderError.couldNotDetermineFileDescriptor)
                    completionHandler(PacketTunnelProviderError.couldNotDetermineFileDescriptor)
                case .dnsResolution(let dnsErrors):
                    let hostnamesWithDnsResolutionFailure = dnsErrors.map { $0.address }
                        .joined(separator: ", ")
                    wg_log(.error, message:
                            "DNS resolution failed for the following hostnames: \(hostnamesWithDnsResolutionFailure)")
                    errorNotifier.notify(PacketTunnelProviderError.dnsResolutionFailure)
                    completionHandler(PacketTunnelProviderError.dnsResolutionFailure)
                case .setNetworkSettings(let error):
                    wg_log(.error, message:
                            "Starting tunnel failed with setTunnelNetworkSettings returning \(error.localizedDescription)")
                    errorNotifier.notify(PacketTunnelProviderError.couldNotSetNetworkSettings)
                    completionHandler(PacketTunnelProviderError.couldNotSetNetworkSettings)
                case .startWireGuardBackend(let errorCode):
                    wg_log(.error, message: "Starting tunnel failed with wgTurnOn returning \(errorCode)")
                    errorNotifier.notify(PacketTunnelProviderError.couldNotStartBackend)
                    completionHandler(PacketTunnelProviderError.couldNotStartBackend)
                case .invalidState:
                    fatalError()
                }
            }
        } catch {
            wg_log(.error, message: "Can't parse WG config: \(String(describing: error))")
            errorNotifier.notify(PacketTunnelProviderError.savedProtocolConfigurationIsInvalid)
            completionHandler(PacketTunnelProviderError.savedProtocolConfigurationIsInvalid)
            return
        }
    }

    func handleWireguardStatusMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        guard let completionHandler = completionHandler else { return }
        guard let wgAdapter = wgAdapter else {
            completionHandler(nil)
            return
        }
        wgAdapter.getRuntimeConfiguration { settings in
            guard let settings = settings else {
                completionHandler(nil)
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

            // AVPN seamless roaming: счётчики адаптера (path_lost/restored, bumps, rebinds,
            // pauses) — в тот же статус-ответ; движок и диагностика видят, что делал роуминг.
            wgAdapter.roamingCounters { counters in
                var metadata = (self.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?["tribeSessionMetadata"] as? [String: Any] ?? [:]
                metadata["configuration_generation"] = metadata["generation"]
                metadata["generation"] = self.tribeRuntimeGeneration
                let summary = counters.asDictionary.map { "\($0.key)=\($0.value)" }.sorted().joined(separator: " ")
                if summary != self.tribeLastRecoverySummary {
                    self.tribeLastRecoverySummary = summary
                    TribeSharedState.appGroup?.recordAsync(source: "ne", event: "recovery_status", fields: ["generation": metadata["generation"] ?? "legacy", "counters": counters.asDictionary])
                }
                let response: [String: Any] = [
                    "session_metadata": metadata,
                    "rx_bytes": settingsDictionary["rx_bytes"] ?? "0",
                    "tx_bytes": settingsDictionary["tx_bytes"] ?? "0",
                    "last_handshake_time_sec": lastHandshake,
                    "roam": counters.asDictionary.mapValues { Int(clamping: $0) }
                ]

                completionHandler(try? JSONSerialization.data(withJSONObject: response, options: []))
            }
        }
    }

    // AVPN (BUG-4 auto-heal): ребайнд UDP-сокета живого туннеля. wgSetConfig("listen_port=0")
    // -> IpcSet -> BindUpdate в awg-go: сокет закрывается и открывается на НОВОМ эфемерном
    // порту (новый 5-tuple flow — лечит сессионный блок ТСПУ; эквивалент режима полёта), затем
    // keepalive — сервер сразу узнаёт новый порт. Туннель/handshake-стейт не трогаются.
    // AVPN (K4, awg-apple tribe.7+): ответ — {"rebind":"performed"} | {"rebind":"denied",
    // "reason":"budget"|"not_started"|"offline"}; отказ общего бюджета восстановления GUI/NE
    // подписан честно, а не «adapter not started». tribe.8: после listen_port=0 уходит только
    // keepalive (wgSendKeepalives), без второго BindUpdate нового сокета.
    func handleRebindAppMessage(completionHandler: ((Data?) -> Void)? = nil) {
        guard let completionHandler = completionHandler else { return }
        guard protoType == .wireguard, let wgAdapter = wgAdapter else {
            wg_log(.info, message: "AVPN rebind-heal: denied (no WireGuard adapter)")
            completionHandler(try? JSONSerialization.data(withJSONObject: TribeRebindResult.notStarted.responsePayload, options: []))
            return
        }
        wgAdapter.rebindListenPortResult { result in
            wg_log(.info, message: "AVPN rebind-heal: listen_port rebind \(result.logDescription)")
            completionHandler(try? JSONSerialization.data(withJSONObject: result.responsePayload, options: []))
        }
    }

    // AVPN (U6, awg-apple tribe.8): мягкий рестарт бэкенда в NE — wgTurnOff + wgTurnOn с той же
    // TunnelConfiguration на том же TUN-fd, БЕЗ setTunnelNetworkSettings: новое устройство, сокет и
    // handshake, а utun, маршруты и потоки приложений (VoIP) живут. Общий бюджет восстановления
    // GUI/NE (один на эпизод + rolling cap). Ответ: {"soft_restart":"performed"} |
    // {"soft_restart":"denied","reason":"budget"|"not_started"|"offline"|"failed"}.
    func handleSoftRestartAppMessage(completionHandler: ((Data?) -> Void)? = nil) {
        guard let completionHandler = completionHandler else { return }
        guard protoType == .wireguard, let wgAdapter = wgAdapter else {
            wg_log(.info, message: "AVPN soft-restart: denied (no WireGuard adapter)")
            completionHandler(try? JSONSerialization.data(withJSONObject: TribeSoftRestartResult.notStarted.responsePayload, options: []))
            return
        }
        wgAdapter.softRestartBackendResult { result in
            wg_log(.info, message: "AVPN soft-restart: backend \(result.logDescription)")
            completionHandler(try? JSONSerialization.data(withJSONObject: result.responsePayload, options: []))
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
        stopTribeStatsTimer()

        guard let adapter = wgAdapter else {
            ErrorNotifier.removeLastErrorFile()
            completionHandler()
            return
        }
        adapter.stop { error in
            self.clearWgAdapter(ifIdenticalTo: adapter)
            ErrorNotifier.removeLastErrorFile()

            if let error {
                wg_log(.error, message: "Failed to stop WireGuard adapter: \(error.localizedDescription)")
            }
            completionHandler()

#if os(macOS)
            // HACK: This is a filthy hack to work around Apple bug 32073323 (dup'd by us as 47526107).
            // Remove it when they finally fix this upstream and the fix has been rolled out to
            // sufficient quantities of users.
            exit(0)
#endif
        }
    }
}

// MARK: - AVPN (журнал тестирования v2): статистика туннеля в ne.log

extension PacketTunnelProvider {
    /// Раз в 10 с, пока включён файловый лог: байты туда/обратно, возраст последнего рукопожатия,
    /// аплинк. В фоне приложение заморожено — эта строка единственный взгляд изнутри туннеля.
    func startTribeStatsTimer() {
        tribeStatsQueue.async { [weak self] in
            guard let self else { return }
            self.tribeStatsTimer?.cancel()
            let timer = DispatchSource.makeTimerSource(queue: self.tribeStatsQueue)
            timer.schedule(deadline: .now() + 10, repeating: 10, leeway: .seconds(2))
            timer.setEventHandler { [weak self] in self?.logTribeStats() }
            self.tribeStatsTimer = timer
            timer.resume()
        }
    }

    func stopTribeStatsTimer() {
        tribeStatsQueue.async { [weak self] in
            self?.tribeStatsTimer?.cancel()
            self?.tribeStatsTimer = nil
        }
    }

    private func logTribeStats() {
        guard Log.isLoggingEnabled, let adapter = wgAdapter else { return }
        adapter.getRuntimeConfiguration { [weak self] settings in
            guard let settings else { return }
            var rx: UInt64 = 0
            var tx: UInt64 = 0
            var handshake: UInt64 = 0
            for line in settings.split(separator: "\n") {
                if line.hasPrefix("rx_bytes=") {
                    rx += UInt64(line.dropFirst("rx_bytes=".count)) ?? 0
                } else if line.hasPrefix("tx_bytes=") {
                    tx += UInt64(line.dropFirst("tx_bytes=".count)) ?? 0
                } else if line.hasPrefix("last_handshake_time_sec=") {
                    handshake = max(handshake, UInt64(line.dropFirst("last_handshake_time_sec=".count)) ?? 0)
                }
            }
            let now = UInt64(Date().timeIntervalSince1970)
            let age = handshake > 0 && now >= handshake ? "\(now - handshake)s" : "never"
            let uplink = self?.tribeUplinkDescription() ?? "?"
            wg_log(.info, message: "Tribe stats: rx=\(rx) tx=\(tx) hs_age=\(age) uplink=\(uplink)")
        }
    }
}
