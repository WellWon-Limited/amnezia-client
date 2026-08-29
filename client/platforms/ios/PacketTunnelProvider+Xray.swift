import Darwin
import Foundation
import NetworkExtension

enum XrayErrors: Error {
    case noXrayConfig
    case xrayConfigIsWrong
    case cantSaveXrayConfig
    case cantParseListenAndPort
    case missingSocksInbound
    case configTooLarge
    case invalidSplitTunnel
    case cantAcquireLocalPort
    case cantSaveHevSocksConfig
    case supersededSession
    case socketProtectionUnavailable
    case tun2socksStopTimedOut
    case xrayReadinessTimedOut
    case callbackRegistrationFailed
    case callbackClearFailed
    case xrayCoreStartFailed
}

final class XraySocketCallbackContext {
    weak var provider: PacketTunnelProvider?
    let identity: XraySocketCallbackIdentity
    private let fence: XraySocketCallbackFence

    init(provider: PacketTunnelProvider, identity: XraySocketCallbackIdentity) {
        self.provider = provider
        self.identity = identity
        fence = XraySocketCallbackFence(identity: identity)
    }

    func invoke(fd: uintptr_t) -> Bool {
        guard let provider else { return false }
        let runtime = provider.xrayRuntimeSession.snapshot()
        guard fence.accepts(currentGeneration: runtime.generation,
                            currentSessionId: runtime.sessionId) else { return false }
        return provider.sockCallback(fd: fd, identity: identity)
    }

    func deactivate(expected: XraySocketCallbackIdentity) -> Bool {
        guard fence.deactivate(expected: expected) else { return false }
        provider = nil
        return true
    }
}

extension PacketTunnelProvider {
    private enum ParsedXrayRoute {
        case ipv4(NEIPv4Route)
        case ipv6(NEIPv6Route)
    }

    private func parseXrayRoute(_ value: String) throws -> ParsedXrayRoute {
        let components = value.split(separator: "/", omittingEmptySubsequences: false)
        guard components.count == 2, let prefix = Int(components[1]) else {
            throw XrayErrors.invalidSplitTunnel
        }
        let address = String(components[0])
        var v4 = in_addr()
        if inet_pton(AF_INET, address, &v4) == 1, (0...32).contains(prefix) {
            let maskValue: UInt32 = prefix == 0 ? 0 : UInt32.max << UInt32(32 - prefix)
            let bytes = [
                String((maskValue >> 24) & 0xff), String((maskValue >> 16) & 0xff),
                String((maskValue >> 8) & 0xff), String(maskValue & 0xff),
            ]
            return .ipv4(NEIPv4Route(destinationAddress: address,
                                     subnetMask: bytes.joined(separator: ".")))
        }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, address, &v6) == 1, (0...128).contains(prefix) {
            return .ipv6(NEIPv6Route(destinationAddress: address,
                                     networkPrefixLength: NSNumber(value: prefix)))
        }
        throw XrayErrors.invalidSplitTunnel
    }

    /// TCP port chosen by the OS on IPv6 loopback (::1), matching inbound listen address.
    private func acquireFreeLocalPort() throws -> Int {
        let fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP)
        guard fd != -1 else {
            throw XrayErrors.cantAcquireLocalPort
        }
        defer { close(fd) }
        var reuse: Int32 = 1
        _ = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_in6()
        addr.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
        addr.sin6_family = sa_family_t(AF_INET6)
        addr.sin6_port = in_port_t(0).bigEndian
        addr.sin6_addr = in6addr_loopback
        addr.sin6_scope_id = 0
        let bindResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { p in
                bind(fd, p, socklen_t(MemoryLayout<sockaddr_in6>.size))
            }
        }
        guard bindResult == 0 else {
            throw XrayErrors.cantAcquireLocalPort
        }
        var bound = sockaddr_in6()
        var len = socklen_t(MemoryLayout<sockaddr_in6>.size)
        let gr = withUnsafeMutablePointer(to: &bound) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { bp in
                getsockname(fd, bp, &len)
            }
        }
        guard gr == 0 else {
            throw XrayErrors.cantAcquireLocalPort
        }
        return Int(bound.sin6_port.byteSwapped)
    }

    private func applyXraySplitTunnel(_ xrayConfig: XrayConfig,
                                      settings: NEPacketTunnelNetworkSettings) throws {
        guard let splitTunnelType = xrayConfig.splitTunnelType,
              (0...2).contains(splitTunnelType) else {
            throw XrayErrors.invalidSplitTunnel
        }
        var protectedV4: [NEIPv4Route] = []
        var protectedV6: [NEIPv6Route] = []
        if xrayConfig.guardedCatalogV2 == true {
            guard let protected = xrayConfig.protectedTunnelIPs, !protected.isEmpty else {
                throw XrayErrors.invalidSplitTunnel
            }
            for address in protected {
                guard !address.contains("/") else { throw XrayErrors.invalidSplitTunnel }
                let parsed = try parseXrayRoute(address + (address.contains(":") ? "/128" : "/32"))
                switch parsed {
                case .ipv4(let route): protectedV4.append(route)
                case .ipv6(let route): protectedV6.append(route)
                }
            }
            if splitTunnelType == 2 {
                guard let exclusions = xrayConfig.splitTunnelSites else {
                    throw XrayErrors.invalidSplitTunnel
                }
                do {
                    try TribeProtectedSplitPolicy.validateMode2(
                        exclusions: exclusions, protectedLiterals: protected)
                } catch {
                    throw XrayErrors.invalidSplitTunnel
                }
            }
        }
        if splitTunnelType == 0 { return }
        guard let splitTunnelSites = xrayConfig.splitTunnelSites,
              !splitTunnelSites.isEmpty else { throw XrayErrors.invalidSplitTunnel }

        let parsed = try splitTunnelSites.map(parseXrayRoute)
        let ipv4 = parsed.compactMap { route -> NEIPv4Route? in
            if case .ipv4(let value) = route { return value }
            return nil
        }
        let ipv6 = parsed.compactMap { route -> NEIPv6Route? in
            if case .ipv6(let value) = route { return value }
            return nil
        }

        if splitTunnelType == 1 {
            settings.ipv4Settings?.includedRoutes = ipv4 + protectedV4
            settings.ipv6Settings?.includedRoutes = ipv6 + protectedV6
        } else if splitTunnelType == 2 {
            settings.ipv4Settings?.excludedRoutes = ipv4
            settings.ipv6Settings?.excludedRoutes = ipv6
        }
    }

    func startXray(handoff suppliedHandoff: (data: Data, sessionId: String)? = nil,
                   completionHandler: @escaping (Error?) -> Void) {
        let handoff: (data: Data, sessionId: String)
        do {
            handoff = try suppliedHandoff
                ?? consumeTribeConfig(expectedProtocols: ["xray", "ssxray"])
        } catch {
            completionHandler(XrayErrors.noXrayConfig)
            return
        }
        let sessionGeneration = xrayRuntimeSession.beginSession(
            protocolName: "xray", sessionId: handoff.sessionId)
        guard let callbackIdentity = XraySocketCallbackIdentity(
            generation: sessionGeneration,
            sessionId: xrayRuntimeSession.snapshot().sessionId) else {
            completionHandler(XrayErrors.supersededSession)
            return
        }
        resetXraySocketProtection(identity: callbackIdentity)

        func fail(_ error: Error) {
            _ = xrayRuntimeSession.transition(to: .failed, generation: sessionGeneration)
            completionHandler(error)
        }

        let configData = handoff.data
        guard configData.count <= 512 * 1024 else {
            fail(XrayErrors.configTooLarge)
            return
        }

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "254.1.1.1")
        // One conservative MTU for the NE and tun2socks.  The old 9000-byte
        // value assumed jumbo frames and caused avoidable fragmentation.
        settings.mtu = 1280

        settings.ipv4Settings = {
            let settings = NEIPv4Settings(addresses: ["198.18.0.1"], subnetMasks: ["255.255.0.0"])
            settings.includedRoutes = [NEIPv4Route.default()]
            return settings
        }()

        settings.ipv6Settings = {
            let settings = NEIPv6Settings(addresses: ["fd6e:a81b:704f:1211::1"], networkPrefixLengths: [64])
            settings.includedRoutes = [NEIPv6Route.default()]
            return settings
        }()

        do {
            let xrayConfig = try XrayConfig.decodeNativeEnvelope(configData)

            var dnsArray = [String]()
            if let dns1 = xrayConfig.dns1 {
                dnsArray.append(dns1)
            }
            if let dns2 = xrayConfig.dns2 {
                dnsArray.append(dns2)
            }

            settings.dnsSettings = !dnsArray.isEmpty
            ? NEDNSSettings(servers: dnsArray)
            : NEDNSSettings(servers: ["1.1.1.1"])
            try applyXraySplitTunnel(xrayConfig, settings: settings)

            // AVPN backend-first (Task 6): cache the network-change reconnect debounce for this tunnel
            // session (used by scheduleNetworkChangeHandling in PacketTunnelProvider.swift). Fallback
            // 1.0s matches the pre-Task-6 literal byte-for-byte when the key is absent.
            let requestedDebounce = Double(xrayConfig.networkChangeDebounceMs ?? 1000) / 1000.0
            xrayNetworkChangeDebounceSeconds = min(max(requestedDebounce, 0.1), 10.0)

            let xrayConfigData = xrayConfig.config.data(using: .utf8)

            guard let xrayConfigData else {
                xrayLog(.error, message: "Can't encode config to data")
                fail(XrayErrors.xrayConfigIsWrong)
                return
            }
            guard xrayConfigData.count <= 512 * 1024 else {
                fail(XrayErrors.configTooLarge)
                return
            }

            let jsonDict = try JSONSerialization.jsonObject(with: xrayConfigData,
                                                            options: []) as? [String: Any]

            guard var jsonDict else {
                xrayLog(.error, message: "Can't parse address and port for hevSocks")
                fail(XrayErrors.cantParseListenAndPort)
                return
            }

            let port = try acquireFreeLocalPort()
            let address = "::1"

            // Extract existing SOCKS5 credentials or generate new ones per session.
            let socksCredentials = try ensureInboundAuth(
                jsonDict: &jsonDict, port: port, address: address)

            let updatedData = try JSONSerialization.data(withJSONObject: jsonDict, options: [])
            let launchInner = { [weak self] in
                guard let self else { completionHandler(XrayErrors.supersededSession); return }
                guard self.xrayRuntimeSession.isCurrent(generation: sessionGeneration) else {
                    completionHandler(XrayErrors.supersededSession)
                    return
                }
                self.updateActiveInterfaceIndexForCurrentPath()

                // Launch xray
                self.setupAndStartXray(configData: updatedData,
                                       maxMemoryBytes: xrayConfig.maxMemoryBytes,
                                       port: port,
                                       username: socksCredentials.username,
                                       password: socksCredentials.password,
                                       callbackIdentity: callbackIdentity) { xrayError in
                    guard self.xrayRuntimeSession.isCurrent(generation: sessionGeneration) else {
                        completionHandler(XrayErrors.supersededSession)
                        return
                    }
                    if let xrayError {
                        fail(xrayError)
                        return
                    }

                    // Launch hevSocks
                    self.setupAndRunTun2socks(configData: updatedData,
                                              address: address,
                                              port: port,
                                              username: socksCredentials.username,
                                              password: socksCredentials.password,
                                              connectTimeoutMs: xrayConfig.connectTimeoutMs,
                                              readWriteTimeoutMs: xrayConfig.readWriteTimeoutMs,
                                              callbackIdentity: callbackIdentity,
                                              completionHandler: completionHandler)
                }
            }
            if xrayConfig.guardedCatalogV2 == true {
                // PREPARE already installed the authenticated outer guard settings. Issuing a
                // second async NE settings mutation here would let a delayed start completion
                // resurrect routes after exact STOP + RELEASE. Guarded engines only consume the
                // existing packet flow; NetworkExtension settings have one owner.
                launchInner()
            } else {
                setTunnelNetworkSettings(settings) { error in
                    guard self.xrayRuntimeSession.isCurrent(
                        generation: sessionGeneration) else {
                        completionHandler(XrayErrors.supersededSession)
                        return
                    }
                    if let error { fail(error); return }
                    launchInner()
                }
            }
        } catch {
            fail(error)
            return
        }
    }

    func stopXray(completionHandler: @escaping (Error?) -> Void) {
        // Snapshot/invalidate and native close share the same gate as both start legs. Thus a
        // late start either wins completely and is stopped here, or observes the new generation
        // before mutating the process-global native engines.
        let stop = xrayNativeLifecycleGate.withExclusive {
            let active = xrayRuntimeSession.snapshot()
            let callbackIdentity = XraySocketCallbackIdentity(
                generation: active.generation, sessionId: active.sessionId)
            let generation = xrayRuntimeSession.beginStop()
            let callbackTeardownSucceeded = callbackIdentity.map {
                drainStopAndRetireXrayCallback(identity: $0)
            } ?? true
            return (generation, callbackTeardownSucceeded)
        }
        Socks5Tunnel.stop { [weak self] result in
            guard let self else {
                completionHandler(XrayErrors.supersededSession)
                return
            }
            switch result {
            case .stopped:
                guard stop.1 else {
                    _ = self.xrayRuntimeSession.transition(to: .failed, generation: stop.0)
                    completionHandler(XrayErrors.callbackClearFailed)
                    return
                }
                _ = self.xrayRuntimeSession.transition(to: .stopped, generation: stop.0)
                completionHandler(nil)
            case .timedOut:
                _ = self.xrayRuntimeSession.transition(to: .failed, generation: stop.0)
                completionHandler(XrayErrors.tun2socksStopTimedOut)
            }
        }
    }

    func handleXrayStatusMessage(completionHandler: ((Data?) -> Void)? = nil) {
        guard let completionHandler else { return }
        let snapshot = xrayRuntimeSession.snapshot()
        if snapshot.state == .running, let raw = Socks5Tunnel.trafficStats() {
            let sample = TunnelTrafficSample(
                rxBytes: raw.rxBytes,
                txBytes: raw.txBytes,
                rxPackets: raw.rxPackets,
                txPackets: raw.txPackets
            )
            _ = xrayRuntimeSession.record(sample, generation: snapshot.generation)
        }
        let response = xrayRuntimeSession.payload(core: TribeEngineManifest.xrayRuntimeStatusCore())
        completionHandler(try? JSONSerialization.data(withJSONObject: response, options: []))
    }

    func sockCallback(fd: uintptr_t, identity: XraySocketCallbackIdentity) -> Bool {
        let interfaceIndex = currentActiveInterfaceIndex()
        guard interfaceIndex != 0 else {
            recordXraySocketProtection(success: false, identity: identity)
            return false
        }

        var storage = sockaddr_storage()
        var storageLength = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let socketFamily = withUnsafeMutablePointer(to: &storage) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(Int32(fd), $0, &storageLength) == 0 ? Int32($0.pointee.sa_family) : -1
            }
        }
        var boundInterface = interfaceIndex
        let result: Int32
        switch socketFamily {
        case AF_INET:
            result = setsockopt(Int32(fd), IPPROTO_IP, IP_BOUND_IF,
                                &boundInterface, socklen_t(MemoryLayout<UInt32>.size))
        case AF_INET6:
            result = setsockopt(Int32(fd), IPPROTO_IPV6, IPV6_BOUND_IF,
                                &boundInterface, socklen_t(MemoryLayout<UInt32>.size))
        default:
            result = -1
        }
        recordXraySocketProtection(success: result == 0, identity: identity)
        return result == 0
    }

    private struct SocksCredentials {
        let username: String
        let password: String
    }

    private func indexOfSocksInbound(in inboundsArray: [[String: Any]]) -> Int? {
        for (i, inbound) in inboundsArray.enumerated() {
            guard let proto = inbound["protocol"] as? String else { continue }
            if proto.caseInsensitiveCompare("socks") == .orderedSame {
                return i
            }
        }
        return nil
    }

    // Returns existing SOCKS5 credentials from the inbound config, or generates and injects
    // new random ones. Also sets port and address on the socks inbound entry.
    private func ensureInboundAuth(jsonDict: inout [String: Any], port: Int,
                                   address: String) throws -> SocksCredentials {
        var inboundsArray = jsonDict["inbounds"] as? [[String: Any]] ?? []

        if let socksIdx = indexOfSocksInbound(in: inboundsArray) {
            var inbound = inboundsArray[socksIdx]
            inbound["port"] = port
            inbound["listen"] = address

            var settings = inbound["settings"] as? [String: Any] ?? [:]
            if let accounts = settings["accounts"] as? [[String: Any]],
               let first = accounts.first,
               let user = first["user"] as? String, !user.isEmpty,
               let pass = first["pass"] as? String, !pass.isEmpty {
                // Re-use existing credentials, but always enforce auth mode in case the
                // imported config had accounts but auth: "noauth" (or no auth field).
                settings["auth"] = "password"
                inbound["settings"] = settings
                inboundsArray[socksIdx] = inbound
                jsonDict["inbounds"] = inboundsArray
                return SocksCredentials(username: user, password: pass)
            }

            // Generate new random credentials for this session
            let user = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased().prefix(16)
            let pass = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
            settings["auth"] = "password"
            settings["accounts"] = [["user": String(user), "pass": pass]]
            inbound["settings"] = settings
            inboundsArray[socksIdx] = inbound
            jsonDict["inbounds"] = inboundsArray
            return SocksCredentials(username: String(user), password: pass)
        }

        throw XrayErrors.missingSocksInbound
    }

    private func setupAndStartXray(configData: Data,
                                   maxMemoryBytes: Int64?,
                                   port: Int,
                                   username: String,
                                   password: String,
                                   callbackIdentity: XraySocketCallbackIdentity,
                                   completionHandler: @escaping (Error?) -> Void) {
        let sessionGeneration = callbackIdentity.generation
        let configURL: URL
        do {
            configURL = try writeProtectedXrayFile(prefix: "core", suffix: "json", data: configData)
        } catch {
            xrayLog(.error, message: "Can't save xray configuration")
            completionHandler(XrayErrors.cantSaveXrayConfig)
            return
        }

        guard xrayRuntimeSession.isCurrent(generation: sessionGeneration) else {
            try? FileManager.default.removeItem(at: configURL)
            completionHandler(XrayErrors.supersededSession)
            return
        }

        updateActiveInterfaceIndexForCurrentPath()

        let callbackContext = XraySocketCallbackContext(provider: self, identity: callbackIdentity)
        guard retainXrayCallbackContext(callbackContext) else {
            try? FileManager.default.removeItem(at: configURL)
            completionHandler(XrayErrors.callbackRegistrationFailed)
            return
        }
        let ctx = Unmanaged.passUnretained(callbackContext).toOpaque()
        let cb: libxray_sockcallback = { (fd, ctx) in
            guard let ctx = ctx else { return 0 }
            let callbackContext = Unmanaged<XraySocketCallbackContext>.fromOpaque(ctx).takeUnretainedValue()

            return callbackContext.invoke(fd: fd) ? 1 : 0
        }
        var callbackInstalled = false
        let nativeStartError: Error? = xrayNativeLifecycleGate.withExclusive {
            guard xrayRuntimeSession.isCurrent(generation: sessionGeneration) else {
                return XrayErrors.supersededSession
            }
            guard XrayNativeCStringResult.consume(LibXraySetSockCallback(cb, ctx)) else {
                return XrayErrors.callbackRegistrationFailed
            }
            callbackInstalled = true

            // A Network Extension has a much smaller memory budget than the host app. Never
            // disable Go's soft limit; clamp server input to the audited 16..512 MiB envelope.
            let defaultMemory: Int64 = 50 * 1024 * 1024
            let requestedMemory = maxMemoryBytes ?? defaultMemory
            let memoryLimit = min(max(requestedMemory, 16 * 1024 * 1024), 512 * 1024 * 1024)
            return XrayNativeCStringResult.consume(
                LibXrayRunXray(nil, configURL.path, memoryLimit))
                ? nil : XrayErrors.xrayCoreStartFailed
        }
        if let nativeStartError {
            if callbackInstalled {
                _ = drainStopAndRetireXrayCallback(identity: callbackIdentity)
            } else {
                _ = retireXrayCallbackContext(identity: callbackIdentity)
            }
            try? FileManager.default.removeItem(at: configURL)
            completionHandler(nativeStartError)
            return
        }

        // The C ABI return only proves synchronous core setup. Prove that this exact random,
        // password-authenticated listener is alive before the NE reports ready; a competing
        // process that won the close-before-bind race cannot answer the generated credentials.
        // Keep the provider alive until this proof and its exact rollback finish: otherwise the
        // native callback's raw context could outlive its registry owner.
        DispatchQueue.global(qos: .utility).async {
            let ready = self.waitForAuthenticatedSocks(
                port: port, username: username, password: password,
                generation: sessionGeneration)
            try? FileManager.default.removeItem(at: configURL)
            guard self.xrayRuntimeSession.isCurrent(generation: sessionGeneration) else {
                _ = self.drainStopAndRetireXrayCallback(identity: callbackIdentity)
                completionHandler(XrayErrors.supersededSession)
                return
            }
            guard ready else {
                _ = self.drainStopAndRetireXrayCallback(identity: callbackIdentity)
                completionHandler(XrayErrors.xrayReadinessTimedOut)
                return
            }
            completionHandler(nil)
            xrayLog(.info, message: "Xray authenticated listener is ready")
        }
    }

    private func setupAndRunTun2socks(configData: Data,
                                      address: String,
                                      port: Int,
                                      username: String,
                                      password: String,
                                      connectTimeoutMs: Int?,
                                      readWriteTimeoutMs: Int?,
                                      callbackIdentity: XraySocketCallbackIdentity,
                                      completionHandler: @escaping (Error?) -> Void) {
        let sessionGeneration = callbackIdentity.generation
        // AVPN backend-first (Task 6): server-tunable via XrayConfig.connectTimeoutMs/readWriteTimeoutMs
        // (TuningStore numbers.xray_connect_timeout_ms/xray_rw_timeout_ms). Fallbacks are byte-for-byte
        // the pre-Task-6 literals. task-stack-size/limit-nofile intentionally left untouched.
        let connectTimeout = min(max(connectTimeoutMs ?? 5000, 1000), 60_000)
        let readWriteTimeout = min(max(readWriteTimeoutMs ?? 60000, 5000), 600_000)
        let config = """
        tunnel:
          mtu: 1280
        socks5:
          port: \(port)
          address: \(address)
          username: \(username)
          password: \(password)
          udp: 'udp'
        misc:
          task-stack-size: 20480
          connect-timeout: \(connectTimeout)
          read-write-timeout: \(readWriteTimeout)
          log-file: stderr
          log-level: error
          limit-nofile: 65535
        """

        let configurationURL: URL
        do {
            guard let data = config.data(using: .utf8) else {
                throw XrayErrors.cantSaveHevSocksConfig
            }
            configurationURL = try writeProtectedXrayFile(prefix: "tun", suffix: "yml", data: data)
        } catch {
            xrayLog(.info, message: "Cant save hevSocks configuration")
            _ = drainStopAndRetireXrayCallback(identity: callbackIdentity)
            _ = xrayRuntimeSession.transition(to: .failed, generation: sessionGeneration)
            completionHandler(XrayErrors.cantSaveHevSocksConfig)
            return
        }

        let tunStartAccepted = xrayNativeLifecycleGate.withExclusive { () -> Bool in
            guard xrayRuntimeSession.isCurrent(generation: sessionGeneration) else { return false }
            Socks5Tunnel.start(
                withConfig: configurationURL.path,
            completion: { [weak self] result in
                try? FileManager.default.removeItem(at: configurationURL)
                guard let self,
                      self.xrayRuntimeSession.isCurrent(generation: sessionGeneration) else {
                    completionHandler(XrayErrors.supersededSession)
                    return
                }
                switch result {
                case .success:
                    guard self.xrayRuntimeSession.transition(to: .running,
                                                             generation: sessionGeneration) else {
                        completionHandler(XrayErrors.supersededSession)
                        return
                    }
                    xrayLog(.info, message: "Hev socks is ready; socket protection callback is armed")
                    completionHandler(nil)
                case .failure(let error):
                    _ = self.drainStopAndRetireXrayCallback(identity: callbackIdentity)
                    _ = self.xrayRuntimeSession.transition(to: .failed,
                                                           generation: sessionGeneration)
                    xrayLog(.error, message: "Hev socks failed to start safely: \(error)")
                    completionHandler(error)
                }
            },
            onExit: { [weak self] result in
                guard let self,
                      self.xrayRuntimeSession.transition(to: .failed,
                                                         generation: sessionGeneration) else {
                    return
                }
                _ = self.drainStopAndRetireXrayCallback(identity: callbackIdentity)
                xrayLog(.error, message: "Hev socks stopped unexpectedly: \(result)")
            })
            return true
        }
        guard tunStartAccepted else {
            try? FileManager.default.removeItem(at: configurationURL)
            _ = drainStopAndRetireXrayCallback(identity: callbackIdentity)
            completionHandler(XrayErrors.supersededSession)
            return
        }
    }

    private func writeProtectedXrayFile(prefix: String, suffix: String, data: Data) throws -> URL {
        guard !data.isEmpty, data.count <= 512 * 1024 else { throw XrayErrors.configTooLarge }
        guard let cachesDirectory = FileManager.default.urls(
            for: .cachesDirectory, in: .userDomainMask).first else {
            throw XrayErrors.cantSaveXrayConfig
        }
        let directory = cachesDirectory.appendingPathComponent("TribeXray", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        let url = directory.appendingPathComponent(
            "\(prefix)-\(UUID().uuidString.lowercased()).\(suffix)", isDirectory: false)
        try data.write(to: url, options: [.atomic])
        try FileManager.default.setAttributes([
            .posixPermissions: 0o600,
            .protectionKey: FileProtectionType.completeUntilFirstUserAuthentication,
        ], ofItemAtPath: url.path)
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        var mutable = url
        try mutable.setResourceValues(values)
        return url
    }

    private func waitForAuthenticatedSocks(port: Int, username: String, password: String,
                                           generation: UInt64) -> Bool {
        for _ in 0..<30 {
            guard xrayRuntimeSession.isCurrent(generation: generation) else { return false }
            if authenticateSocks(port: port, username: username, password: password) { return true }
            usleep(100_000)
        }
        return false
    }

    private func authenticateSocks(port: Int, username: String, password: String) -> Bool {
        let user = Array(username.utf8)
        let pass = Array(password.utf8)
        guard !user.isEmpty, user.count <= 255, !pass.isEmpty, pass.count <= 255 else { return false }
        let fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        var timeout = timeval(tv_sec: 0, tv_usec: 250_000)
        _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                       socklen_t(MemoryLayout<timeval>.size))
        _ = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                       socklen_t(MemoryLayout<timeval>.size))
        var address = sockaddr_in6()
        address.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
        address.sin6_family = sa_family_t(AF_INET6)
        address.sin6_port = in_port_t(port).bigEndian
        address.sin6_addr = in6addr_loopback
        let connected = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size)) == 0
            }
        }
        guard connected else { return false }
        func writeAll(_ bytes: [UInt8]) -> Bool {
            bytes.withUnsafeBytes { buffer in
                guard let base = buffer.baseAddress else { return false }
                return send(fd, base, buffer.count, 0) == buffer.count
            }
        }
        func readExact(_ count: Int) -> [UInt8]? {
            var result = [UInt8](repeating: 0, count: count)
            let received = result.withUnsafeMutableBytes { buffer in
                recv(fd, buffer.baseAddress, count, MSG_WAITALL)
            }
            return received == count ? result : nil
        }
        guard writeAll([0x05, 0x01, 0x02]), readExact(2) == [0x05, 0x02] else { return false }
        let request = [UInt8(0x01), UInt8(user.count)] + user + [UInt8(pass.count)] + pass
        return writeAll(request) && readExact(2) == [0x01, 0x00]
    }

    private func resetXraySocketProtection(identity: XraySocketCallbackIdentity) {
        xraySocketProtectionLock.lock()
        xraySocketProtectionGeneration = identity.generation
        xraySocketProtectionSessionId = identity.sessionId
        xraySocketProtectionSucceeded = false
        xraySocketProtectionFailed = false
        xraySocketProtectionLock.unlock()
    }

    @discardableResult
    private func drainStopAndRetireXrayCallback(
        identity: XraySocketCallbackIdentity
    ) -> Bool {
        xrayNativeLifecycleGate.withExclusive {
            guard xraySocketCallbackRegistry.value(for: identity) != nil else {
                // First exact teardown already stopped the core and retired this context. A
                // concurrent/stale teardown is idempotent only when no replacement is live.
                return xraySocketCallbackRegistry.count == 0
            }
            return XraySocketCallbackTeardown.execute(
                stopCore: { XrayNativeCStringResult.consume(LibXrayStopXray()) },
                drain: {
                    // Native setter takes an exclusive lock and returns only after every callback
                    // that entered before synchronous core Close has left Swift.
                    XrayNativeCStringResult.consume(LibXraySetSockCallback(nil, nil))
                },
                retireContext: { self.retireXrayCallbackContext(identity: identity) })
        }
    }

    private func recordXraySocketProtection(success: Bool,
                                            identity: XraySocketCallbackIdentity) {
        xraySocketProtectionLock.lock()
        guard xraySocketProtectionGeneration == identity.generation,
              xraySocketProtectionSessionId == identity.sessionId else {
            xraySocketProtectionLock.unlock()
            return
        }
        let wasFailed = xraySocketProtectionFailed
        if success {
            xraySocketProtectionSucceeded = true
        } else {
            xraySocketProtectionFailed = true
        }
        let mustFail = xraySocketProtectionFailed && !wasFailed
        xraySocketProtectionLock.unlock()

        guard mustFail else { return }
        let runtime = xrayRuntimeSession.snapshot()
        let guardSnapshot = tribeSessionGuard.snapshot()
        let action = XraySocketFailureContainmentPolicy.action(
            callback: identity,
            runtimeGeneration: runtime.generation,
            runtimeSessionId: runtime.sessionId,
            guardExpectedRuntimeSessionId: guardSnapshot.identity?.expectedRuntimeSessionId,
            guardPhase: guardSnapshot.phase.rawValue)
        switch action {
        case .ignoreStale:
            return
        case .cancelLegacyProvider:
            guard xrayRuntimeSession.transition(to: .failed,
                                                generation: identity.generation) else { return }
            DispatchQueue.main.async { [weak self] in
                self?.cancelTunnelWithError(XrayErrors.socketProtectionUnavailable)
            }
        case .quarantineGuardedOuter:
            guard xrayRuntimeSession.transition(to: .failed,
                                                generation: identity.generation) else { return }
            quarantineGuardedXraySocketFailure(identity: identity)
        }
    }

    private func quarantineGuardedXraySocketFailure(identity: XraySocketCallbackIdentity) {
        tribeGuardQueue.async { [weak self] in
            guard let self else { return }
            let snapshot = self.tribeSessionGuard.snapshot()
            guard let guardedIdentity = snapshot.identity,
                  guardedIdentity.expectedRuntimeSessionId == identity.sessionId,
                  snapshot.phase == .starting || snapshot.phase == .running else { return }
            self.cancelAuthorityWatchdog()
            _ = self.tribeSessionGuard.lostEvent(reason: "socket_protection_failed")

            // Preserve the already-installed outer NE settings. Only the unsafe inner engines
            // are stopped; exact recovery stop/release remains the sole way to release capture.
            if !self.drainStopAndRetireXrayCallback(identity: identity) {
                xrayLog(.error, message: "Xray callback drain failed; context retained in quarantine")
            }
            Socks5Tunnel.stop { result in
                if result == .timedOut {
                    xrayLog(.error, message: "Xray quarantine: tun2socks stop timed out")
                }
            }
        }
    }
}
