import Foundation
import NetworkExtension
import HevSocks5Tunnel

// AVPN (build 140, data watch): the provider's glue for the tunnel-side data watch. The rule is in
// the awg-apple package (TribeDataWatch.swift), the I/O in TribeDataWatchRuntime.swift (host
// tested); here is only what needs the provider itself and the Go layer.
extension WireGuardAdapter: TribeDataWatchAdapting {}

extension PacketTunnelProvider {
    /// What the runtime gets from this process: the shared container, the log, the journal ring,
    /// the three calls of the Go layer and the request that bypasses the tunnel.
    func tribeDataWatchDeps() -> TribeDataWatchDeps {
        TribeDataWatchDeps(
            containerDirectory: { TribeSharedState.appGroup?.directory },
            log: { wg_log(.info, message: $0) },
            record: { event, fields in TribeSharedState.appGroup?.recordAsync(source: "ne", event: event, fields: fields) },
            writeState: { state in
                // The extension is the only writer and write() replaces the file atomically: no lock.
                guard let store = TribeSharedState.appGroup else { return }
                TribeSharedState.journalQueue.async { try? store.write(state, TribeWatchPlan.stateFileName) }
            },
            setProbe: { clientIP, resolver, enabled in wgSetTribeProbe(clientIP, resolver, enabled ? 1 : 0) },
            probeStart: { handle, timeoutMs in wgTribeProbeStart(handle, timeoutMs) },
            probeResult: { handle in
                guard let raw = wgTribeProbeResult(handle) else { return nil }
                defer { free(raw) }
                return String(cString: raw)
            },
            uplinkKind: { [weak self] in
                // "satisfied/cellular/exp" -> "cellular"
                let parts = (self?.tribeUplinkDescription() ?? "").split(separator: "/")
                return parts.count > 1 ? String(parts[1]) : "unknown"
            },
            sanityCheck: { [weak self] targets, completion in
                TribeSanityRunner.run(targets, interface: { self?.tribeCurrentPhysicalInterface() }, completion: completion)
            })
    }

    /// Called from startWireguard before the adapter starts: the runtime reads the plan file and
    /// configures the probe through the tunnel in the Go layer (the device wraps the tunnel at
    /// wgTurnOn). The probe's target is the resolver the session already uses; its source is the
    /// client's address inside the tunnel.
    func prepareTribeDataWatch(_ wgConfig: WGConfig) {
        let metadata = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?["tribeSessionMetadata"] as? [String: Any] ?? [:]
        tribeDataWatch.configure(tribeDataWatchDeps())
        tribeDataWatch.prepare(nodeId: Self.tribeLabel(metadata["node_id"]), proto: Self.tribeLabel(metadata["proto"]),
                               generation: tribeRuntimeGeneration, clientIP: wgConfig.clientIP, resolver: wgConfig.dns1)
    }

    /// A number or a short label from the session metadata; never a config value.
    private static func tribeLabel(_ raw: Any?) -> String {
        if let n = raw as? NSNumber { return n.stringValue }
        if let s = raw as? String, !s.isEmpty, s.count <= 16,
           s.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" }) { return s }
        return "unknown"
    }

    /// The Xray path had no statistics line at all, so the extension's memory with Xray was never
    /// measured on a phone (the 50 MB limit decides whether Xray can ever run next to the watch).
    /// Diagnostics only, changes nothing; called by the statistics tick only while the file log is
    /// on (TribeDataWatchRuntime.statsTick).
    func logTribeXrayStats() {
        let snapshot = xrayRuntimeSession.snapshot()
        // The tun2socks counters themselves (the session's own copy moves only on a status request).
        var txPackets = 0, txBytes = 0, rxPackets = 0, rxBytes = 0
        if snapshot.state == .running { hev_socks5_tunnel_stats(&txPackets, &txBytes, &rxPackets, &rxBytes) }
        xrayLog(.info, message: "Tribe stats (xray): rx=\(max(0, rxBytes)) tx=\(max(0, txBytes)) state=\(snapshot.state.rawValue) uplink=\(tribeUplinkDescription()) mem=\(PacketTunnelProvider.tribeFootprintMB())")
    }
}
