import Foundation
import NetworkExtension
import HevSocks5Tunnel

// AVPN (build 140, data watch): the provider's glue for the tunnel-side data watch. The rule is in
// the awg-apple package (TribeDataWatch.swift), the I/O in TribeDataWatchRuntime.swift; here are
// only the two things that need the provider itself.
extension PacketTunnelProvider {
    /// Called from startWireguard before the adapter starts. Reads the plan file and configures
    /// the probe through the tunnel in the Go layer (the device wraps the tunnel at wgTurnOn).
    /// Returns true when the probe is available for this device. With the watch off this is an
    /// explicit reset: the device reads the tunnel exactly as in build 139.
    func prepareTribeDataWatch(_ wgConfig: WGConfig) -> Bool {
        let metadata = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?["tribeSessionMetadata"] as? [String: Any] ?? [:]
        tribeDataWatch.physicalInterface = { [weak self] in self?.tribeCurrentPhysicalInterface() }
        tribeDataWatch.uplinkKind = { [weak self] in
            // "satisfied/cellular/exp" -> "cellular"
            let parts = (self?.tribeUplinkDescription() ?? "").split(separator: "/")
            return parts.count > 1 ? String(parts[1]) : "unknown"
        }
        let wanted = tribeDataWatch.prepare(nodeId: Self.tribeLabel(metadata["node_id"]),
                                           proto: Self.tribeLabel(metadata["proto"]),
                                           generation: tribeRuntimeGeneration)
        // The probe's target is the resolver the session already uses; its source is the client's
        // address inside the tunnel. Not IPv4 -> -1: no probe, the verdict stays unconfirmed.
        let rc = wgSetTribeProbe(wgConfig.clientIP, wgConfig.dns1, wanted ? 1 : 0)
        if wanted {
            wg_log(.info, message: "Tribe watch: probe \(rc == 0 ? "available" : "unavailable")")
        }
        return wanted && rc == 0
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
    /// Diagnostics only: written while the file log is on, changes nothing.
    func logTribeXrayStats() {
        guard Log.isLoggingEnabled else { return }
        let snapshot = xrayRuntimeSession.snapshot()
        // The tun2socks counters themselves (the session's own copy moves only on a status request).
        var txPackets = 0, txBytes = 0, rxPackets = 0, rxBytes = 0
        if snapshot.state == .running { hev_socks5_tunnel_stats(&txPackets, &txBytes, &rxPackets, &rxBytes) }
        xrayLog(.info, message: "Tribe stats (xray): rx=\(max(0, rxBytes)) tx=\(max(0, txBytes)) state=\(snapshot.state.rawValue) uplink=\(tribeUplinkDescription()) mem=\(PacketTunnelProvider.tribeFootprintMB())")
    }
}
