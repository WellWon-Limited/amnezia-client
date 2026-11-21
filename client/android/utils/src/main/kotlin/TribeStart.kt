package org.amnezia.vpn.util

// AVPN (android2 V2, 21.11): which engine leg a start of the VPN service belongs to, and how its build ended. Pure
// (JVM unit tests: src/test TribeStartTest).
//
// The engine's start config carries the number of its leg (`tribeStartLeg`, VpnConnectionTunnelControl on Android);
// the service echoes it in every TUNNEL_BUILD report of that start, so the engine never takes a report of an earlier
// start for the leg in flight. On the phone a start was refused while the service still built the previous one
// ("Tunnel build 7: end, not started") and its "built" ended the running leg's local time: the leg's server was
// judged "no handshake" although its tunnel never began. A start that ends without a tunnel is reported NOT_STARTED.
object TribeStart {
    const val BUILDING = 0
    const val BUILT = 1
    const val NOT_STARTED = 2

    private val legPattern = Regex("\"tribeStartLeg\"\\s*:\\s*(\\d+)")

    // The leg number of a start config; 0 = none (a config that is not an engine start: the saved one an always-on or
    // system restart of the service brings up, an older app's config).
    fun legOf(config: String?): Long =
        config?.let { legPattern.find(it)?.groupValues?.getOrNull(1)?.toLongOrNull() } ?: 0L

    // The report of a build that ended: the tunnel runs (BUILT) or it was never started (NOT_STARTED).
    fun endState(started: Boolean): Int = if (started) BUILT else NOT_STARTED
}
