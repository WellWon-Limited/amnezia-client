package org.amnezia.vpn

import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import org.json.JSONArray
import org.json.JSONObject

/** Kotlin mirror of NativeDispatchPolicyDigest.cpp. Any encoding drift is fail-closed. */
object NativeDispatchPolicyDigest {
    const val SCHEMA = "native_dispatch_policy_v1"
    private const val HEADER = "tribe-native-dispatch-policy-v1\n"
    private const val MAX_PROJECTION_BYTES = 512 * 1024

    data class Projection(
        val transport: String,
        val nativeEnvelopeSchema: String,
        val profileId: String,
        val configGeneration: String,
        val bindingGeneration: String,
        val endpointHost: String,
        val endpointPort: String,
        val tunnelAddress: String,
        val dns1: String,
        val dns2: String,
        val mtu: String,
        val configVersion: String,
        val xrayMaxMemoryBytes: String,
        val splitTunnelType: String,
        val splitSites: List<String>,
        val appSplitTunnelType: String,
        val splitApps: List<String>,
        val splitDnsSuffixes: List<String>,
        val splitDnsServer: String,
        val dnsForwardOn: String,
        val dnsForwardSuffixes: String,
        val dnsForwardServer: String,
        val dnsForwardWarmup: String,
        val killSwitch: String,
        val allowedDns: List<String>,
        val protectedTunnelIps: List<String>,
        val nativeConfigSha256: String,
    )

    fun sha256(config: JSONObject, authority: RuntimeAuthority): String =
        sha256(extract(config, authority))

    internal fun sha256(projection: Projection): String = MessageDigest.getInstance("SHA-256")
        .digest(encode(projection))
        .joinToString("") { "%02x".format(it.toInt() and 0xff) }

    internal fun encode(projection: Projection): ByteArray {
        val output = ByteArrayOutputStream()
        output.write(HEADER.toByteArray(StandardCharsets.UTF_8))
        fun record(name: String, value: String) {
            require('\u0000' !in value) { "Native dispatch policy contains NUL" }
            val bytes = value.toByteArray(StandardCharsets.UTF_8)
            require(bytes.size <= 256 * 1024) { "Native dispatch policy value is oversized" }
            output.write(name.toByteArray(StandardCharsets.US_ASCII))
            output.write(':'.code)
            output.write(bytes.size.toString().toByteArray(StandardCharsets.US_ASCII))
            output.write(':'.code)
            output.write(bytes)
            output.write('\n'.code)
            require(output.size() <= MAX_PROJECTION_BYTES) { "Native dispatch policy is oversized" }
        }
        fun list(name: String, values: List<String>) {
            val sorted = values.sortedWith(Comparator(::compareUtf8))
            record("${name}_count", sorted.size.toString())
            sorted.forEachIndexed { index, value -> record("${name}_$index", value) }
        }

        record("transport", projection.transport)
        record("native_envelope_schema", projection.nativeEnvelopeSchema)
        record("profile_id", projection.profileId)
        record("config_generation", projection.configGeneration)
        record("binding_generation", projection.bindingGeneration)
        record("endpoint_host", projection.endpointHost)
        record("endpoint_port", projection.endpointPort)
        record("tunnel_address", projection.tunnelAddress)
        record("dns1", projection.dns1)
        record("dns2", projection.dns2)
        record("mtu", projection.mtu)
        record("config_version", projection.configVersion)
        record("xray_max_memory_bytes", projection.xrayMaxMemoryBytes)
        record("split_tunnel_type", projection.splitTunnelType)
        list("split_site", projection.splitSites)
        record("app_split_tunnel_type", projection.appSplitTunnelType)
        list("split_app", projection.splitApps)
        list("split_dns_suffix", projection.splitDnsSuffixes)
        record("split_dns_server", projection.splitDnsServer)
        record("dns_forward_on", projection.dnsForwardOn)
        record("dns_forward_suffixes", projection.dnsForwardSuffixes)
        record("dns_forward_server", projection.dnsForwardServer)
        record("dns_forward_warmup", projection.dnsForwardWarmup)
        record("kill_switch", projection.killSwitch)
        list("allowed_dns", projection.allowedDns)
        list("protected_tunnel_ip", projection.protectedTunnelIps)
        record("native_config_sha256", projection.nativeConfigSha256)
        return output.toByteArray()
    }

    private fun extract(config: JSONObject, authority: RuntimeAuthority): Projection {
        require(authority.policySchema == SCHEMA) { "Native dispatch policy schema mismatch" }
        require(config.optString("protocol", "") == authority.transport) {
            "Native dispatch transport mismatch"
        }
        val dataKey = when (authority.transport) {
            "awg" -> "awg_config_data"
            "xray" -> "xray_config_data"
            else -> throw IllegalArgumentException("Unsupported native dispatch transport")
        }
        val data = config.optJSONObject(dataKey)
            ?: throw IllegalArgumentException("Native dispatch config data missing")
        val nativeConfig = strictString(data, "config")
        val endpointPort = if (authority.transport == "awg") {
            canonicalInteger(data.opt("port"), 1L, 65_535L)
        } else {
            val core = JSONObject(nativeConfig)
            val outbounds = core.optJSONArray("outbounds")
                ?: throw IllegalArgumentException("Xray outbounds missing")
            require(outbounds.length() == 1) { "Xray native dispatch requires one outbound" }
            val settings = outbounds.getJSONObject(0).getJSONObject("settings")
            canonicalInteger(settings.opt("port"), 1L, 65_535L)
        }
        val mtu = if (authority.transport == "awg") {
            val text = strictString(data, "mtu")
            val parsed = text.toLongOrNull()
            require(parsed != null && parsed in 576L..1500L && text == parsed.toString()) {
                "AWG native dispatch MTU invalid"
            }
            text
        } else "0"
        val xrayMemory = if (authority.transport == "xray") {
            canonicalInteger(config.opt("xray_max_memory_bytes"),
                8L * 1024 * 1024, 1024L * 1024 * 1024)
        } else "0"
        return Projection(
            authority.transport,
            strictString(config, RuntimeAuthority.ENVELOPE_KEY).also {
                require(it == RuntimeAuthority.V2_ENVELOPE) { "Native dispatch envelope mismatch" }
            },
            authority.profileId,
            authority.configGeneration.toString(),
            authority.bindingGeneration.toString(),
            strictString(config, "hostName"),
            endpointPort,
            if (authority.transport == "awg") strictString(data, "client_ip") else "",
            strictString(config, "dns1"),
            strictString(config, "dns2"),
            mtu,
            canonicalInteger(config.opt("config_version"), 0L, 9_007_199_254_740_991L),
            xrayMemory,
            canonicalInteger(config.opt("splitTunnelType"), 0L, 2L),
            stringList(config, "splitTunnelSites"),
            canonicalInteger(config.opt("appSplitTunnelType"), 0L, 2L),
            stringList(config, "splitTunnelApps"),
            stringList(config, "splitDnsSuffixes", missingIsEmpty = true),
            optionalString(config, "splitDnsServer"),
            optionalString(config, "dnsFwdOn"),
            optionalString(config, "dnsFwdSuffixes"),
            optionalString(config, "dnsFwdServer"),
            optionalString(config, "dnsFwdWarmup"),
            optionalString(config, "killSwitchOption"),
            stringList(config, "allowedDnsServers", missingIsEmpty = true),
            authority.protectedTunnelIps,
            MessageDigest.getInstance("SHA-256")
                .digest(nativeConfig.toByteArray(StandardCharsets.UTF_8))
                .joinToString("") { "%02x".format(it.toInt() and 0xff) },
        )
    }

    private fun strictString(objectValue: JSONObject, key: String): String {
        val value = objectValue.opt(key)
        require(value is String) { "Native dispatch $key must be a string" }
        return value
    }

    private fun optionalString(objectValue: JSONObject, key: String): String {
        if (!objectValue.has(key)) return ""
        return strictString(objectValue, key)
    }

    private fun stringList(
        objectValue: JSONObject,
        key: String,
        missingIsEmpty: Boolean = false,
    ): List<String> {
        if (!objectValue.has(key) && missingIsEmpty) return emptyList()
        val array = objectValue.optJSONArray(key)
            ?: throw IllegalArgumentException("Native dispatch $key must be an array")
        require(array.length() <= 16_384) { "Native dispatch $key is oversized" }
        return (0 until array.length()).map { index ->
            val value = array.opt(index)
            require(value is String) { "Native dispatch $key entries must be strings" }
            value
        }
    }

    private fun canonicalInteger(value: Any?, minimum: Long, maximum: Long): String {
        require(value is Number) { "Native dispatch integer missing" }
        val number = value.toDouble()
        val integer = number.toLong()
        require(number.isFinite() && integer.toDouble() == number && integer in minimum..maximum) {
            "Native dispatch integer is not canonical"
        }
        return integer.toString()
    }

    private fun compareUtf8(left: String, right: String): Int {
        val a = left.toByteArray(StandardCharsets.UTF_8)
        val b = right.toByteArray(StandardCharsets.UTF_8)
        val common = minOf(a.size, b.size)
        for (index in 0 until common) {
            val comparison = (a[index].toInt() and 0xff) - (b[index].toInt() and 0xff)
            if (comparison != 0) return comparison
        }
        return a.size - b.size
    }
}
