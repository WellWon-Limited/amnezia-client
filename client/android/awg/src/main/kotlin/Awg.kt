package org.amnezia.vpn.protocol.awg

import org.amnezia.vpn.protocol.wireguard.Wireguard
import org.amnezia.vpn.protocol.wireguard.WireguardConfig
import org.json.JSONObject
import java.net.InetAddress

class Awg : Wireguard() {

    override val ifName: String = "awg0"

    override fun protocolConfigData(config: JSONObject): JSONObject =
        config.getJSONObject("awg_config_data")

    override fun parseConfig(config: JSONObject, endpointAddress: InetAddress): WireguardConfig {
        val configData = protocolConfigData(config)
        return WireguardConfig.build {
            setUseProtocolExtension(true)
            configExtensionParameters(configData)
            configWireguard(config, configData, endpointAddress)
            configSplitTunneling(config)
            configAppSplitTunneling(config)
            configProtectedTunnelRoutes(config)
        }
    }
}
