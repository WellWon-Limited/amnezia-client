package org.amnezia.vpn.util

import org.json.JSONObject

// AVPN (android2 "P7 card after UI kill", 21.11): the identity of the session the VPN service runs, for a UI process that
// comes back to a live tunnel. The engine's start config carries `tribeSessionMetadata` {schema_version, node_id,
// proto, endpoint} (VpnConnectionTunnelControl; an upstream session: XrayConfigBuilder::upstreamSessionMetadata); the
// service keeps it with the start it launched and returns it with every STATUS, as iOS reads it back from the
// tunnel's provider configuration. Without it the adopted session had no identity and the home card named the
// person's pinned server instead of the one carrying the traffic. Pure (JVM unit tests: src/test TribeSessionTest).
object TribeSession {
    const val METADATA_KEY = "tribeSessionMetadata"

    // The session's metadata as the engine sent it (compact JSON), or null when the config has none (an older app's
    // config, an own Xray session) - the engine then treats the identity as unknown.
    fun metadataOf(config: JSONObject?): String? =
        config?.optJSONObject(METADATA_KEY)?.takeIf { it.length() > 0 }?.toString()
}
