import Foundation
import NetworkExtension

// AVPN upstream nodes (plan provider-pool, release A, lane L3; contract client-envelope-contract.md):
// the provider side of an upstream session - start-envelope decode, the lease renewer's wiring, the
// terminal answer (decision E), the release on stop (contract section 6), the `upstream` status object
// (section 5) and the app message `upstream_lease_set` (section 2). Own file: the upstream Amnezia
// files (PacketTunnelProvider.swift, PacketTunnelProvider+Xray.swift) only call in here at marked
// `// AVPN` points. Nothing here runs for AWG/OpenVPN, nor for an Xray session whose
// tribeSessionMetadata does not say `upstream: 1`.

// All upstream state of one provider (one stored property in PacketTunnelProvider).
final class TribeUpstreamState {
    private let lock = NSLock()
    private var renewerStorage: UpstreamLeaseRenewer?
    private var socksStorage: (port: Int, user: String, pass: String)?
    private var coreStoppedStorage = false
    private var wantsStatsStorage = false
    private var proxyMeterStorage = UpstreamProxyMeterAccumulator()
    private var lastStatsErrorStorage = ""
    private var terminalStorage = UpstreamTerminalMemo()

    var renewer: UpstreamLeaseRenewer? {
        get { lock.lock(); defer { lock.unlock() }; return renewerStorage }
        set { lock.lock(); renewerStorage = newValue; lock.unlock() }
    }

    // The core's SOCKS inbound of the CURRENT core start (port changes on every restart).
    var socks: (port: Int, user: String, pass: String)? {
        get { lock.lock(); defer { lock.unlock() }; return socksStorage }
        set { lock.lock(); socksStorage = newValue; lock.unlock() }
    }

    // This tunnel session's core config carries the stats keys (decided at the tunnel start, kept for
    // core restarts inside the session).
    var wantsStats: Bool {
        get { lock.lock(); defer { lock.unlock() }; return wantsStatsStorage }
        set { lock.lock(); wantsStatsStorage = newValue; lock.unlock() }
    }

    // Session totals of the core's per-outbound counters over core restarts. Returns the totals over
    // `tags` and the error code of a failed read the first time it differs from the last one ("" else).
    func recordProxyRead(_ read: XrayOutboundStatsRead, coreWillStop: Bool,
                         tags: [String]) -> (totals: (rx: Int64, tx: Int64), newError: String) {
        lock.lock()
        defer { lock.unlock() }
        if coreWillStop { proxyMeterStorage.coreWillStop(read) } else { proxyMeterStorage.record(read) }
        let code = read.usable ? "" : (read.errorCode.isEmpty ? "not_running" : read.errorCode)
        let newError = code != lastStatsErrorStorage ? code : ""
        lastStatsErrorStorage = code
        return (proxyMeterStorage.totals(tags: tags), newError)
    }

    func resetProxyMeter() {
        lock.lock()
        proxyMeterStorage = UpstreamProxyMeterAccumulator()
        lastStatsErrorStorage = ""
        lock.unlock()
    }

    // A terminal lease answer stopped the core (decision E): no restart of it on a network change.
    var coreStoppedByLease: Bool {
        get { lock.lock(); defer { lock.unlock() }; return coreStoppedStorage }
        set { lock.lock(); coreStoppedStorage = newValue; lock.unlock() }
    }

    // The terminal answer's code for the rest of the tunnel session (status after the renewer is gone).
    func recordTerminal(code: String) {
        lock.lock(); terminalStorage.record(code); lock.unlock()
    }

    func resetTerminal() {
        lock.lock(); terminalStorage.reset(); lock.unlock()
    }

    var terminalStatus: UpstreamLeaseStatus? {
        lock.lock(); defer { lock.unlock() }; return terminalStorage.status
    }
}

enum UpstreamProviderKeys {
    static let lease = "upstream_lease"
    static let metadata = "tribeSessionMetadata"
    static let actionLeaseSet = "upstream_lease_set"
}

// Requests through the running core's local SOCKS inbound (LibXrayTribeHTTP, ABI
// libxray-tribe-http-v1): the host name goes to the proxy, so the profile's routing decides where the
// request leaves - THROUGH the provider, not around the tunnel (the extension's own sockets bypass it).
final class XrayCoreSocksTransport: UpstreamLeaseTransport {
    static let maxBodyBytes: Int64 = 64 * 1024
    private weak var provider: PacketTunnelProvider?

    init(provider: PacketTunnelProvider) {
        self.provider = provider
    }

    func send(method: String, url: String, headers: [String: String], body: String,
              timeoutMs: Int64) -> UpstreamLeaseWire.HTTPResult {
        // Port and credentials are read per request: a core restart on an uplink change picks a new port.
        guard let provider, provider.xrayRuntimeSession.snapshot().state == .running,
              !provider.tribeUpstream.coreStoppedByLease,
              let socks = provider.tribeUpstream.socks else {
            return UpstreamLeaseWire.HTTPResult(status: 0, body: Data(), errorCode: "core_not_running")
        }
        let headersData = (try? JSONSerialization.data(withJSONObject: headers, options: [.sortedKeys])) ?? Data()
        let headersJSON = String(decoding: headersData, as: UTF8.self)
        let address = "[::1]:\(socks.port)"
        let answer: String = address.withCString { addr in
            socks.user.withCString { user in
                socks.pass.withCString { pass in
                    method.withCString { m in
                        url.withCString { u in
                            headersJSON.withCString { h in
                                body.withCString { b in
                                    guard let raw = LibXrayTribeHTTP(addr, user, pass, m, u, h, b, timeoutMs,
                                                                     Self.maxBodyBytes) else { return "" }
                                    defer { free(raw) }
                                    return String(cString: raw)
                                }
                            }
                        }
                    }
                }
            }
        }
        return UpstreamLeaseWire.parseHTTPResult(answer)
    }
}

// Review E5 of 18.11: a plain HTTPS exchange from the extension's own process. Its sockets do not enter its own
// tunnel, so after the core stopped this is the physical network - the direct path a seat release takes.
// Blocking (called off every state queue), bounded by timeoutMs; no redirects, no cache, no cookies.
final class DirectHTTPTransport: NSObject, UpstreamLeaseTransport, URLSessionTaskDelegate {
    func send(method: String, url: String, headers: [String: String], body: String,
              timeoutMs: Int64) -> UpstreamLeaseWire.HTTPResult {
        guard let u = URL(string: url), u.scheme == "https" else {
            return UpstreamLeaseWire.HTTPResult(status: 0, body: Data(), errorCode: "bad_request")
        }
        var req = URLRequest(url: u, cachePolicy: .reloadIgnoringLocalCacheData,
                             timeoutInterval: Double(max(timeoutMs, 1)) / 1000.0)
        req.httpMethod = method
        for (k, v) in headers { req.setValue(v, forHTTPHeaderField: k) }
        if !body.isEmpty {
            req.httpBody = Data(body.utf8)
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = req.timeoutInterval
        config.timeoutIntervalForResource = req.timeoutInterval
        config.httpShouldSetCookies = false
        let session = URLSession(configuration: config, delegate: self, delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }
        var result = UpstreamLeaseWire.HTTPResult(status: 0, body: Data(), errorCode: "timeout")
        let done = DispatchSemaphore(value: 0)
        session.dataTask(with: req) { data, response, error in
            if let http = response as? HTTPURLResponse {
                result = UpstreamLeaseWire.HTTPResult(status: http.statusCode, body: data ?? Data(), errorCode: "")
            } else if let error = error as NSError? {
                result.errorCode = error.code == NSURLErrorTimedOut ? "timeout" : "transport"
            }
            done.signal()
        }.resume()
        _ = done.wait(timeout: .now() + .milliseconds(Int(timeoutMs) + 200))
        return result
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil) // redirect_refused, as the SOCKS transport
    }
}

extension PacketTunnelProvider {
    // MARK: - start

    // What this start is, from the provider configuration (start envelope, contract section 1).
    func upstreamStartPlan() -> UpstreamStartPlan {
        let provider = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
        guard let profileId = UpstreamLeaseWire.upstreamProfileId(fromMetadata: provider?[UpstreamProviderKeys.metadata]) else {
            return .none
        }
        guard profileId.range(of: "^[A-Za-z0-9_-]{1,64}$", options: .regularExpression) != nil else {
            return .invalid(why: "profile_id")
        }
        guard let raw = provider?[UpstreamProviderKeys.lease], !UpstreamLeaseWire.isAbsent(raw) else {
            return .pending(profileId: profileId)
        }
        let (lease, why) = UpstreamLeaseWire.parseLeaseEnvelope(raw)
        guard let lease else { return .invalid(why: why) }
        return .active(profileId: profileId, lease: lease)
    }

    // The core and hev run: start owning the lease. Called once per tunnel start (not on a core restart).
    func attachUpstreamRenewer(_ plan: UpstreamStartPlan) {
        tribeUpstream.renewer?.stop()
        tribeUpstream.renewer = nil
        tribeUpstream.coreStoppedByLease = false
        tribeUpstream.resetTerminal()
        let profileId: String
        switch plan {
        case .none, .invalid:
            return
        case .pending(let id), .active(let id, _):
            profileId = id
        }
        let renewer = UpstreamLeaseRenewer(
            profileId: profileId,
            transport: XrayCoreSocksTransport(provider: self),
            byteTotals: { [weak self] scope, tags in self?.upstreamMeterTotals(scope: scope, tags: tags) },
            statsAvailable: { [weak self] in
                guard let self, self.tribeUpstream.wantsStats else { return false }
                return Self.readOutboundStats().usable
            },
            onTerminal: { [weak self] code in self?.upstreamLeaseTerminal(code: code) },
            log: { xrayLog(.info, message: $0) })
        tribeUpstream.renewer = renewer
        if case .active(_, let lease) = plan {
            renewer.startActive(lease: lease)
        } else {
            renewer.startPending()
        }
    }

    // Cumulative bytes of the tunnel interface since tunnel start (meter_scope "tunnel"): hev's
    // counters through the session accumulator, which survives core restarts (preservingCounters).
    func upstreamTunnelTotals() -> (rx: Int64, tx: Int64)? {
        let snapshot = xrayRuntimeSession.snapshot()
        if snapshot.state == .running {
            _ = xrayRuntimeSession.record(readHevTrafficSample(), generation: snapshot.generation)
        }
        let counters = xrayRuntimeSession.snapshot().counters
        return (rx: Int64(clamping: counters.rxBytes), tx: Int64(clamping: counters.txBytes))
    }

    // The meter of a lease's scope: "tunnel" = hev (above); "proxy" = the core's counters over `tags`.
    func upstreamMeterTotals(scope: UpstreamMeterScope, tags: [String]) -> (rx: Int64, tx: Int64)? {
        guard scope == .proxy else { return upstreamTunnelTotals() }
        return recordProxyMeter(coreWillStop: false, tags: tags)
    }

    // One LibXrayTribeOutboundStats read (ABI libxray-tribe-stats-v1; malloc'd JSON, freed here).
    static func readOutboundStats() -> XrayOutboundStatsRead {
        guard let raw = LibXrayTribeOutboundStats() else {
            return XrayOutboundStatsRead(running: false, outbounds: [:], errorCode: "no_answer")
        }
        defer { free(raw) }
        return XrayOutboundStatsRead.parse(String(cString: raw))
    }

    @discardableResult
    func recordProxyMeter(coreWillStop: Bool, tags: [String]) -> (rx: Int64, tx: Int64) {
        let result = tribeUpstream.recordProxyRead(Self.readOutboundStats(), coreWillStop: coreWillStop, tags: tags)
        if !result.newError.isEmpty {
            xrayLog(.info, message: "Tribe upstream: outbound stats read failed (\(result.newError))")
        }
        return result.totals
    }

    // Before a core restart on an uplink change: the bytes of the stopping hev go into the session
    // cumulative (hev zeroes its counters on the next start), and the stopping core's per-outbound
    // counters into the proxy meter's base (the next core counts from zero). Only for an upstream session.
    func noteUpstreamBytesBeforeCoreRestart() {
        guard tribeUpstream.renewer != nil else { return }
        _ = upstreamTunnelTotals()
        if tribeUpstream.wantsStats { recordProxyMeter(coreWillStop: true, tags: []) }
    }

    // The provider's core config of this start gets the stats keys (contract section 4) - merged, never
    // replacing its policy. Upstream sessions only (UpstreamMeterPlan.wantsStats).
    func mergeUpstreamStatsKeys(into config: inout [String: Any]) {
        guard tribeUpstream.wantsStats else { return }
        if !XrayStatsConfig.merge(into: &config) {
            tribeUpstream.wantsStats = false
            xrayLog(.error, message: "Tribe upstream: config has a non-object policy/stats; metering tunnel")
        }
    }

    // A fresh tunnel start (not a core restart): this session's metering state.
    func beginUpstreamMeter(_ plan: UpstreamStartPlan) {
        tribeUpstream.resetProxyMeter()
        tribeUpstream.wantsStats = UpstreamMeterPlan.wantsStats(plan)
    }

    // A network change must not restart a core a terminal lease answer stopped (decision E).
    var upstreamBlocksCoreRestart: Bool {
        tribeUpstream.coreStoppedByLease
    }

    // MARK: - terminal answer (decision E)

    // The server ended the lease (not_entitled, over_quota, disabled, lease_gone): stop the core, keep
    // the tunnel interface and hev - traffic stops, nothing leaks around the tunnel, no reconnect and
    // no On-Demand (never armed for Xray, CONNECT-INVARIANTS §27). The app reads `upstream.state =
    // terminal` + code from the next status reply and leaves the node through its dead-session path.
    func upstreamLeaseTerminal(code: String) {
        tribeUpstream.recordTerminal(code: code)
        tribeUpstream.coreStoppedByLease = true
        let stopped: Bool = xrayNativeLifecycleGate.withExclusive {
            tribeScanStopAllIfUsed(reason: "core_stop") // Scanner (plan §2.3): probes end before the core stops
            let active = xrayRuntimeSession.snapshot()
            if let identity = XraySocketCallbackIdentity(generation: active.generation, sessionId: active.sessionId),
               xraySocketCallbackRegistry.value(for: identity) != nil {
                return retireXrayCallback(identity: identity, stopCore: true)
            }
            let coreStopped = XrayNativeCStringResult.consume(LibXrayStopXray())
            let drained = XrayNativeCStringResult.consume(LibXraySetSockCallback(nil, nil))
            return coreStopped && drained
        }
        tribeUpstream.socks = nil
        xrayLog(.error, message: "Tribe upstream: lease ended (\(code)); core stopped, tunnel kept (core_stop_ok=\(stopped))")
        TribeSharedState.appGroup?.recordAsync(source: "ne", event: "upstream_terminal",
                                               fields: ["generation": tribeRuntimeGeneration, "code": code])
    }

    // MARK: - stop (contract section 6)

    // Any stop of an upstream session ends its seat: DELETE with the final report through the tunnel
    // while the core still runs, bounded to 1.5 s, then `then` (the normal stopXray). Nothing is sent
    // after a terminal answer (the renewer is already stopped) or for a session without a lease.
    // Review E5 of 18.11: one release, after the teardown. The final report is read while the core still counts,
    // the core stops, and only then the DELETE goes over the extension's direct path (its own sockets never enter
    // its tunnel) - a provider that failed its data check can no longer swallow the release.
    func stopXrayThenReleaseUpstream(completionHandler: @escaping () -> Void) {
        guard let renewer = tribeUpstream.renewer else {
            stopXray(completionHandler: completionHandler)
            return
        }
        tribeUpstream.renewer = nil
        let prepared = renewer.prepareRelease()
        stopXray {
            guard let prepared else {
                completionHandler()
                return
            }
            renewer.sendRelease(prepared, via: DirectHTTPTransport(), completion: completionHandler)
        }
    }

    // MARK: - status (contract section 5) and the app message (section 2)

    // Adds `upstream` to the Xray status reply of an upstream session (absent for every other session).
    func appendUpstreamStatus(to response: inout [String: Any]) {
        guard let renewer = tribeUpstream.renewer else {
            // Renewer gone after the terminal answer was applied: keep telling the app, code included.
            if let terminal = tribeUpstream.terminalStatus {
                response["upstream"] = terminal.dictionary
            }
            return
        }
        response["upstream"] = renewer.status().dictionary
    }

    // {"action":"upstream_lease_set","upstream_lease":{...}} -> the reply {"upstream":{...}} (the same
    // object as in the status reply). A broken lease leaves the session pending (logged by field name).
    func handleUpstreamLeaseSetMessage(_ message: [String: Any], completionHandler: @escaping (Data?) -> Void) {
        guard protoType == .xray, let renewer = tribeUpstream.renewer else {
            // The same object as the status reply: a session that ended on a terminal answer says so.
            let status = (protoType == .xray ? tribeUpstream.terminalStatus : nil) ?? UpstreamLeaseStatus()
            completionHandler(try? JSONSerialization.data(withJSONObject: ["upstream": status.dictionary]))
            return
        }
        let (lease, why) = UpstreamLeaseWire.parseLeaseEnvelope(message[UpstreamProviderKeys.lease])
        let status: UpstreamLeaseStatus
        if let lease {
            status = renewer.handOver(lease: lease)
        } else {
            xrayLog(.error, message: "Tribe upstream: lease hand-over refused (\(why))")
            status = renewer.status()
        }
        completionHandler(try? JSONSerialization.data(withJSONObject: ["upstream": status.dictionary]))
    }

    // MARK: - start failures that must reach the app (CONNECT-INVARIANTS §22.13)

    func recordXrayStartFailure(_ reason: String) {
        lastXrayStartFailure = reason
        xrayLog(.error, message: "Xray start refused: \(reason)")
        TribeSharedState.appGroup?.recordAsync(source: "ne", event: "xray_start_failed",
                                               fields: ["generation": tribeRuntimeGeneration, "reason": reason])
    }
}
