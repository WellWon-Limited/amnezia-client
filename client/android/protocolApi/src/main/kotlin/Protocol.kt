package org.amnezia.vpn.protocol

import android.content.Context
import android.net.IpPrefix
import android.net.VpnService
import android.net.VpnService.Builder
import android.os.Build
import android.os.ParcelFileDescriptor
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import android.system.OsConstants
import androidx.annotation.RequiresApi
import kotlinx.coroutines.flow.MutableStateFlow
import org.amnezia.vpn.util.Log
import org.amnezia.vpn.util.net.InetNetwork
import org.amnezia.vpn.util.net.parsePublicEndpointLiteral
import org.json.JSONArray
import org.json.JSONObject

private const val TAG = "Protocol"

const val VPN_SESSION_NAME = "AmneziaVPN"

private const val SPLIT_TUNNEL_DISABLE = 0
private const val SPLIT_TUNNEL_INCLUDE = 1
private const val SPLIT_TUNNEL_EXCLUDE = 2

abstract class Protocol {

    data class PreparedVpnSession(
        val tunnelConfig: ProtocolConfig,
        val nativeConfig: Any,
        val policyHash: String = tunnelPolicyHash(tunnelConfig),
    )

    /** Returned only after the exact native reader owns its dup and is synchronously ready. */
    data class NativeStartReceipt(val exactSessionToken: String)

    abstract val statistics: Statistics
    protected lateinit var context: Context
    protected lateinit var state: MutableStateFlow<ProtocolState>
    protected lateinit var onError: (String) -> Unit
    protected var isInitialized: Boolean = false

    /** AVPN: compile/runtime engine facts for the versioned service IPC. */
    open val engineManifest: EngineManifest? = null

    /** True only when the engine consumes a dup of a service-owned master TUN. */
    open val supportsSessionOwnedTun: Boolean = false

    fun initialize(context: Context, state: MutableStateFlow<ProtocolState>, onError: (String) -> Unit) {
        this.context = context
        this.state = state
        this.onError = onError
        internalInit()
        isInitialized = true
    }

    protected abstract fun internalInit()

    abstract suspend fun startVpn(config: JSONObject, vpnBuilder: Builder, protect: (Int) -> Boolean)

    abstract fun stopVpn()

    abstract fun reconnectVpn(vpnBuilder: Builder, protect: (Int) -> Boolean)

    open suspend fun prepareVpn(config: JSONObject): PreparedVpnSession =
        throw VpnStartException("Protocol does not support a session-owned TUN")

    /**
     * Ownership of [tunFd] transfers to the protocol at call entry. Implementations must close
     * it on every pre-native failure and must transfer it exactly once to a native ABI that owns
     * the descriptor on every returned-error/throw path. The caller must never close it again.
     */
    open fun startWithTun(
        prepared: PreparedVpnSession,
        tunFd: Int,
        exactSessionToken: String,
        protect: (Int) -> Boolean,
    ): NativeStartReceipt {
        return ParcelFileDescriptor.adoptFd(tunFd).use {
            throw VpnStartException("Protocol does not support a session-owned TUN")
        }
    }

    /**
     * Rolls back a start that threw before a receipt. `true` is a positive native teardown proof;
     * `false` means the outer TUN must remain armed/blackholed and the session quarantined.
     */
    open fun abortInnerStart(exactSessionToken: String): Boolean = false

    open fun stopInner(exactSessionToken: String) {
        throw VpnException("Protocol does not support exact inner teardown")
    }

    /** Applies the immutable outer policy; only AmneziaVpnService may call establish(). */
    fun configureOuterTunnel(config: ProtocolConfig, vpnBuilder: Builder) {
        buildVpnInterface(config, vpnBuilder)
    }

    protected fun ProtocolConfig.Builder.configSplitTunneling(config: JSONObject) {
        if (!allowSplitTunneling) {
            Log.i(TAG, "Global address split tunneling is prohibited, " +
                "only tunneling from the protocol config is used")
            return
        }

        val splitTunnelType = config.optInt("splitTunnelType")
        if (splitTunnelType == SPLIT_TUNNEL_DISABLE) return
        val splitTunnelSites = config.getJSONArray("splitTunnelSites")
        val addressHandlerFunc = when (splitTunnelType) {
            SPLIT_TUNNEL_INCLUDE -> ::includeAddress
            SPLIT_TUNNEL_EXCLUDE -> ::excludeAddress

            else -> throw BadConfigException("Unexpected value of the 'splitTunnelType' parameter: $splitTunnelType")
        }

        for (i in 0 until splitTunnelSites.length()) {
            val address = InetNetwork.parse(splitTunnelSites.getString(i))
            addressHandlerFunc(address)
        }
    }

    protected fun ProtocolConfig.Builder.configAppSplitTunneling(config: JSONObject) {
        val splitTunnelType = config.optInt("appSplitTunnelType")
        if (splitTunnelType == SPLIT_TUNNEL_DISABLE) return
        val splitTunnelApps = config.getJSONArray("splitTunnelApps")
        val appHandlerFunc = when (splitTunnelType) {
            SPLIT_TUNNEL_INCLUDE -> ::includeApplication
            SPLIT_TUNNEL_EXCLUDE -> ::excludeApplication

            else -> throw BadConfigException("Unexpected value of the 'appSplitTunnelType' parameter: $splitTunnelType")
        }

        for (i in 0 until splitTunnelApps.length()) {
            appHandlerFunc(splitTunnelApps.getString(i))
        }
        if (config.optString("native_envelope_schema") == "tribe_catalog_v2_native_v1") {
            val self = context.packageName
            val containsSelf = (0 until splitTunnelApps.length())
                .any { splitTunnelApps.opt(it) == self }
            // The post-tunnel verifier runs in the Tribe UID. A signed v2 policy that bypasses
            // that UID could produce a false receipt over WAN, so ambiguity is rejected.
            if ((splitTunnelType == SPLIT_TUNNEL_INCLUDE && !containsSelf)
                || (splitTunnelType == SPLIT_TUNNEL_EXCLUDE && containsSelf)) {
                throw BadConfigException("Catalog-v2 app split would bypass the tunnel verifier")
            }
        }
    }

    protected fun ProtocolConfig.Builder.configProtectedTunnelRoutes(config: JSONObject) {
        val schema = config.optString("native_envelope_schema")
        if (schema != "tribe_catalog_v2_native_v1") return
        val authority = config.optJSONObject("runtime_authority_v1")
            ?: throw BadConfigException("Catalog-v2 runtime authority missing")
        val values = authority.opt("protected_tunnel_ips")
        if (values !is JSONArray || values.length() == 0 || values.length() > 64) {
            throw BadConfigException("Catalog-v2 protected tunnel IPs missing")
        }
        protectedTunnelRoutesForEnvelope(
            schema, (0 until values.length()).map(values::opt),
        ).forEach(::protectAddress)
    }

    protected open fun buildVpnInterface(config: ProtocolConfig, vpnBuilder: Builder) {
        vpnBuilder.setSession(VPN_SESSION_NAME)

        for (addr in config.addresses) {
            Log.d(TAG, "addAddress: $addr")
            vpnBuilder.addAddress(addr)
        }

        for (addr in config.dnsServers) {
            Log.d(TAG, "addDnsServer: $addr")
            vpnBuilder.addDnsServer(addr)
        }
        // fix for Samsung android ignoring DNS servers outside the VPN route range
        if (Build.BRAND == "samsung") {
            for (addr in config.dnsServers) {
                Log.d(TAG, "addRoute: $addr")
                vpnBuilder.addRoute(InetNetwork(addr))
            }
        }

        config.searchDomain?.let {
            Log.d(TAG, "addSearchDomain: $it")
            vpnBuilder.addSearchDomain(it)
        }

        for ((inetNetwork, include) in config.routes) {
            if (include) {
                Log.d(TAG, "addRoute: $inetNetwork")
                vpnBuilder.addRoute(inetNetwork)
            } else {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    Log.d(TAG, "excludeRoute: $inetNetwork")
                    vpnBuilder.excludeRoute(inetNetwork)
                } else {
                    Log.e(TAG, "Trying to exclude route $inetNetwork on old Android")
                }
            }
        }

        for (app in config.includedApplications) {
            Log.d(TAG, "addAllowedApplication")
            vpnBuilder.addAllowedApplication(app)
        }

        for (app in config.excludedApplications) {
            Log.d(TAG, "addDisallowedApplication")
            vpnBuilder.addDisallowedApplication(app)
        }

        Log.d(TAG, "setMtu: ${config.mtu}")
        vpnBuilder.setMtu(config.mtu)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            config.httpProxy?.let {
                Log.d(TAG, "setHttpProxy: $it")
                vpnBuilder.setHttpProxy(it)
            }
        }

        if (config.allowAllAF) {
            Log.d(TAG, "allowFamily")
            vpnBuilder.allowFamily(OsConstants.AF_INET)
            vpnBuilder.allowFamily(OsConstants.AF_INET6)
        }

        Log.d(TAG, "setBlocking: ${config.blockingMode}")
        vpnBuilder.setBlocking(config.blockingMode)
        vpnBuilder.setUnderlyingNetworks(null)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q)
            vpnBuilder.setMetered(false)
    }
}

/** Pure closed-boundary parser shared with route-policy unit tests. */
internal fun protectedTunnelRoutesForEnvelope(
    schema: String,
    values: List<Any?>?,
): Set<InetNetwork> {
    if (schema != "tribe_catalog_v2_native_v1") return emptySet()
    if (values.isNullOrEmpty() || values.size > 64) {
        throw BadConfigException("Catalog-v2 protected tunnel IPs missing")
    }
    return values.mapTo(linkedSetOf()) { value ->
        val text = value as? String
            ?: throw BadConfigException("Protected tunnel IP is not a string")
        val address = parsePublicEndpointLiteral(text)
            ?: throw BadConfigException("Protected tunnel IP is not canonical public unicast")
        InetNetwork(address)
    }
}

fun tunnelPolicyHash(config: ProtocolConfig): String {
    val canonical = buildList {
        add("schema=1")
        add("addresses=" + config.addresses.map { "${it.address.hostAddress}/${it.mask}" }.sorted().joinToString(","))
        add("dns=" + config.dnsServers.mapNotNull { it.hostAddress }.sorted().joinToString(","))
        add("search=${config.searchDomain.orEmpty()}")
        add("routes=" + config.routes.map {
            "${if (it.include) '+' else '-'}${it.inetNetwork.address.hostAddress}/${it.inetNetwork.mask}"
        }.sorted().joinToString(","))
        add("included_apps=" + config.includedApplications.sorted().joinToString(","))
        add("excluded_apps=" + config.excludedApplications.sorted().joinToString(","))
        add("proxy=${config.httpProxy?.toString().orEmpty()}")
        add("all_af=${config.allowAllAF}")
        add("blocking=${config.blockingMode}")
        add("mtu=${config.mtu}")
    }.joinToString("\n")
    return MessageDigest.getInstance("SHA-256")
        .digest(canonical.toByteArray(StandardCharsets.UTF_8))
        .joinToString("") { "%02x".format(it.toInt() and 0xff) }
}

private fun VpnService.Builder.addAddress(addr: InetNetwork) = addAddress(addr.address, addr.mask)
private fun VpnService.Builder.addRoute(addr: InetNetwork) = addRoute(addr.address, addr.mask)

@RequiresApi(Build.VERSION_CODES.TIRAMISU)
private fun VpnService.Builder.excludeRoute(addr: InetNetwork) = excludeRoute(IpPrefix(addr.address, addr.mask))
