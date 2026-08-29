package org.amnezia.vpn.protocol.wireguard

import android.net.VpnService.Builder
import android.content.Context
import android.os.ParcelFileDescriptor
import java.net.InetAddress
import java.net.UnknownHostException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.amnezia.awg.GoBackend
import org.amnezia.vpn.protocol.Protocol
import org.amnezia.vpn.protocol.EngineManifest
import org.amnezia.vpn.protocol.EmbeddedEngineManifests
import org.amnezia.vpn.protocol.ProtocolState.CONNECTED
import org.amnezia.vpn.protocol.ProtocolState.CONNECTING
import org.amnezia.vpn.protocol.ProtocolState.DISCONNECTED
import org.amnezia.vpn.protocol.Statistics
import org.amnezia.vpn.protocol.VpnException
import org.amnezia.vpn.protocol.VpnStartException
import org.amnezia.vpn.util.LibraryLoader.loadSharedLibrary
import org.amnezia.vpn.util.Log
import org.amnezia.vpn.util.asSequence
import org.amnezia.vpn.util.net.InetEndpoint
import org.amnezia.vpn.util.net.InetNetwork
import org.amnezia.vpn.util.net.parseInetAddress
import org.amnezia.vpn.util.net.isPublicUnicastEndpoint
import org.amnezia.vpn.util.optStringOrNull
import org.json.JSONObject

private const val TAG = "Wireguard"

open class Wireguard : Protocol() {

    override val supportsSessionOwnedTun: Boolean = true

    override val engineManifest: EngineManifest
        get() {
            val runtimeVersion = if (isInitialized) runCatching { GoBackend.awgVersion() }.getOrNull() else null
            return EmbeddedEngineManifests.awg(runtimeVersion)
        }

    private var tunnelHandle: Int = -1
    private var config: WireguardConfig? = null // save config for reconnect
    private var activeSessionToken: String? = null
    private enum class NativeStartStage { IDLE, CALLING_NATIVE, NATIVE_ACTIVE, READY, CLEAN }
    private var nativeStartStage = NativeStartStage.IDLE
    protected open val ifName: String = "amn0"
    private lateinit var scope: CoroutineScope
    private var statusJob: Job? = null

    override val statistics: Statistics
        get() {
            if (tunnelHandle == -1) return Statistics.EMPTY_STATISTICS
            val config = GoBackend.awgProtectedGetConfig(tunnelHandle)
                ?: return Statistics.EMPTY_STATISTICS
            return parseAwgUapiStatistics(config)
        }

    override fun internalInit() {
        if (!isInitialized) loadSharedLibrary(context, "wg-go")
        if (this::scope.isInitialized) {
            scope.cancel()
        }
        scope = CoroutineScope(Dispatchers.IO)
    }

    override suspend fun startVpn(config: JSONObject, vpnBuilder: Builder, protect: (Int) -> Boolean) =
        throw VpnStartException("AWG requires the Tribe session-owned TUN service")

    override suspend fun prepareVpn(config: JSONObject): PreparedVpnSession {
        val configData = protocolConfigData(config)
        val endpoint = resolveEndpoint(configData.getString("hostName").trim())
        val wireguardConfig = parseConfig(config, endpoint)
        return PreparedVpnSession(wireguardConfig, wireguardConfig)
    }

    protected open fun protocolConfigData(config: JSONObject): JSONObject =
        config.getJSONObject("wireguard_config_data")

    protected open fun parseConfig(config: JSONObject, endpointAddress: InetAddress): WireguardConfig {
        val configData = protocolConfigData(config)
        return WireguardConfig.build {
            configWireguard(config, configData, endpointAddress)
            configSplitTunneling(config)
            configAppSplitTunneling(config)
            configProtectedTunnelRoutes(config)
        }
    }

    protected fun WireguardConfig.Builder.configWireguard(
        config: JSONObject,
        configData: JSONObject,
        endpointAddress: InetAddress,
    ) {
        configData.getString("client_ip").split(",").map { address ->
            InetNetwork.parse(address.trim())
        }.forEach(::addAddress)

        config.optStringOrNull("dns1")?.let { dns ->
            addDnsServer(parseInetAddress(dns.trim()))
        }

        config.optStringOrNull("dns2")?.let { dns ->
            addDnsServer(parseInetAddress(dns.trim()))
        }

        val defRoutes = hashSetOf(
            InetNetwork("0.0.0.0", 0),
            InetNetwork("::", 0)
        )
        val routes = hashSetOf<InetNetwork>()
        configData.getJSONArray("allowed_ips").asSequence<String>().map { route ->
            InetNetwork.parse(route.trim())
        }.forEach(routes::add)
        // if the allowed IPs list contains at least one non-default route, disable global split tunneling
        if (routes.any { it !in defRoutes }) disableSplitTunneling()
        addRoutes(routes)

        configData.optStringOrNull("mtu")?.let { setMtu(it.toInt()) }

        val port = configData.getInt("port")
        setEndpoint(InetEndpoint(endpointAddress, port))

        if (configData.optBoolean("isObfuscationEnabled")) {
            setUseProtocolExtension(true)
            configExtensionParameters(configData)
        }

        configData.optStringOrNull("persistent_keep_alive")?.let { setPersistentKeepalive(it) }
        configData.getString("client_priv_key").let { setPrivateKeyHex(it.base64ToHex()) }
        configData.getString("server_pub_key").let { setPublicKeyHex(it.base64ToHex()) }
        configData.optStringOrNull("psk_key")?.let { setPreSharedKeyHex(it.base64ToHex()) }
    }

    protected fun WireguardConfig.Builder.configExtensionParameters(configData: JSONObject) {
        configData.optStringOrNull("Jc")?.let { setJc(it.toInt()) }
        configData.optStringOrNull("Jmin")?.let { setJmin(it.toInt()) }
        configData.optStringOrNull("Jmax")?.let { setJmax(it.toInt()) }
        configData.optStringOrNull("S1")?.let { setS1(it.toInt()) }
        configData.optStringOrNull("S2")?.let { setS2(it.toInt()) }
        configData.optStringOrNull("S3")?.let { setS3(it.toInt()) }
        configData.optStringOrNull("S4")?.let { setS4(it.toInt()) }
        configData.optStringOrNull("H1")?.trim()?.let { if (it.isNotEmpty()) setH1(it) }
        configData.optStringOrNull("H2")?.trim()?.let { if (it.isNotEmpty()) setH2(it) }
        configData.optStringOrNull("H3")?.trim()?.let { if (it.isNotEmpty()) setH3(it) }
        configData.optStringOrNull("H4")?.trim()?.let { if (it.isNotEmpty()) setH4(it) }
        configData.optStringOrNull("I1")?.let { setI1(it) }
        configData.optStringOrNull("I2")?.let { setI2(it) }
        configData.optStringOrNull("I3")?.let { setI3(it) }
        configData.optStringOrNull("I4")?.let { setI4(it) }
        configData.optStringOrNull("I5")?.let { setI5(it) }
        configData.optStringOrNull("HeaderProtectionKey")?.trim()?.takeIf { it.isNotEmpty() }
            ?.let { setHeaderProtectionKey(it.base64ToHex()) }
        configData.optStringOrNull("ContentPaddingAddition")?.trim()?.takeIf { it.isNotEmpty() }
            ?.let { setContentPaddingAddition(it) }
        configData.optStringOrNull("RekeyAfterTime")?.trim()?.takeIf { it.isNotEmpty() }
            ?.let { setRekeyAfterTime(it) }
        configData.optStringOrNull("RekeyTimeout")?.trim()?.takeIf { it.isNotEmpty() }
            ?.let { setRekeyTimeout(it) }
        configData.optStringOrNull("RejectAfterTime")?.trim()?.takeIf { it.isNotEmpty() }
            ?.let { setRejectAfterTime(it) }
        configData.optStringOrNull("KeepaliveTimeout")?.trim()?.takeIf { it.isNotEmpty() }
            ?.let { setKeepaliveTimeout(it) }
        configData.optStringOrNull("MaxHandshakeAttempts")?.trim()?.takeIf { it.isNotEmpty() }
            ?.let { setMaxHandshakeAttempts(it) }
        // AVPN: AWG 3.1 quick-format keys; the builder validates and
        // normalizes them before crossing the native UAPI boundary.
        configData.optStringOrNull("RandomTrailers")?.trim()?.takeIf { it.isNotEmpty() }
            ?.let { setRandomTrailers(it) }
        configData.optStringOrNull("DisableCookies")?.trim()?.takeIf { it.isNotEmpty() }
            ?.let { setDisableCookies(it) }
    }

    override fun startWithTun(
        prepared: PreparedVpnSession,
        tunFd: Int,
        exactSessionToken: String,
        protect: (Int) -> Boolean,
    ): NativeStartReceipt {
        val ownedTun = ParcelFileDescriptor.adoptFd(tunFd)
        try {
            val config = prepared.nativeConfig as? WireguardConfig
                ?: throw VpnStartException("Invalid AWG prepared session")
            if (tunnelHandle != -1 || activeSessionToken != null) {
                throw VpnStartException("AWG inner session is already active")
            }
            requireExactSessionToken(exactSessionToken)
            activeSessionToken = exactSessionToken
            nativeStartStage = NativeStartStage.CALLING_NATIVE
            try {
                start(config, ownedTun, protect)
                this.config = config
                nativeStartStage = NativeStartStage.READY
                return NativeStartReceipt(exactSessionToken)
            } catch (error: Throwable) {
                if (nativeStartStage == NativeStartStage.CLEAN) activeSessionToken = null
                throw error
            }
        } finally {
            // Closes every pre-native path. After detachFd(), the pinned JNI/Go ABI owns and
            // closes the raw descriptor on success and every returned-error path.
            ownedTun.close()
        }
    }

    private fun start(
        config: WireguardConfig,
        ownedTun: ParcelFileDescriptor,
        protect: (Int) -> Boolean,
    ) {
        Log.i(TAG, "awg-go backend ${GoBackend.awgVersion()}")
        val interfaceName = ifName
        val settings = config.toWgUserspaceString()
        // No fallible Kotlin work may occur after this transfer and before the native call.
        val tunFd = ownedTun.detachFd()
        tunnelHandle = GoBackend.awgPrepareProtected(
            interfaceName, tunFd, settings,
        )

        if (tunnelHandle < 0) {
            tunnelHandle = -1
            nativeStartStage = NativeStartStage.CLEAN
            throw VpnStartException("Wireguard tunnel creation error")
        }
        nativeStartStage = NativeStartStage.NATIVE_ACTIVE

        // The Tribe-pinned JNI ABI opens both UDP sockets while Device.Up is blocked before
        // receive routines and peers are started. Both descriptors must be protected before the
        // explicit resume receipt; failure/timeout aborts and closes the exact prepared handle.
        val socketV4 = GoBackend.awgProtectedGetSocketV4(tunnelHandle)
        val socketV6 = GoBackend.awgProtectedGetSocketV6(tunnelHandle)
        if (socketV4 < 0 || socketV6 < 0 || !protect(socketV4) || !protect(socketV6)) {
            GoBackend.awgProtectedTurnOff(tunnelHandle)
            tunnelHandle = -1
            nativeStartStage = NativeStartStage.CLEAN
            throw VpnStartException("Protect VPN interface: permission not granted or revoked")
        }
        if (GoBackend.awgResumeProtected(tunnelHandle) != 0) {
            GoBackend.awgProtectedTurnOff(tunnelHandle)
            tunnelHandle = -1
            nativeStartStage = NativeStartStage.CLEAN
            throw VpnStartException("Protected AWG native start did not reach ready state")
        }
        try {
            verifyAwg31Uapi(config) // AVPN: positive engine-capability check.
        } catch (e: VpnStartException) {
            GoBackend.awgProtectedTurnOff(tunnelHandle)
            tunnelHandle = -1
            nativeStartStage = NativeStartStage.CLEAN
            throw e
        }
        state.value = CONNECTING
        launchStatusJob(activeSessionToken!!, tunnelHandle)
    }

    override fun abortInnerStart(exactSessionToken: String): Boolean {
        requireExactSessionToken(exactSessionToken)
        if (activeSessionToken == null && tunnelHandle == -1
            && nativeStartStage in setOf(NativeStartStage.IDLE, NativeStartStage.CLEAN)) return true
        if (activeSessionToken != exactSessionToken) return false
        if (nativeStartStage == NativeStartStage.CALLING_NATIVE) return false
        return try {
            if (tunnelHandle != -1) turnOffVpn()
            activeSessionToken = null
            nativeStartStage = NativeStartStage.CLEAN
            true
        } catch (_: Throwable) {
            false
        }
    }

    private fun verifyAwg31Uapi(config: WireguardConfig) {
        val expected = buildMap {
            config.randomTrailers?.takeIf { it.isNotBlank() }
                ?.let { put("random_trailers", it.toAwgUapiBool()) }
            config.disableCookies?.takeIf { it.isNotBlank() }
                ?.let { put("disable_cookies", it.toAwgUapiBool()) }
        }
        if (expected.isEmpty()) return

        val actual = GoBackend.awgProtectedGetConfig(tunnelHandle)
            ?.lineSequence()
            ?.mapNotNull { line ->
                val separator = line.indexOf('=')
                if (separator <= 0) null else line.substring(0, separator) to line.substring(separator + 1)
            }
            ?.toMap()
            ?: throw VpnStartException("AWG 3.1 UAPI capability query failed")
        if (expected.any { (key, value) -> actual[key] != value }) {
            throw VpnStartException("AWG 3.1 UAPI capability mismatch")
        }
        Log.i(TAG, "AWG 3.1 UAPI capability verified: ${expected.keys.sorted().joinToString()}")
    }

    private fun launchStatusJob(exactSessionToken: String, exactHandle: Int) {
        Log.d(TAG, "Launch status job")
        statusJob = scope.launch {
            while (true) {
                val lastHandshake = getLastHandshake()
                Log.v(TAG, "lastHandshake=$lastHandshake")
                if (lastHandshake == 0L || lastHandshake == -2L) {
                    delay(1000)
                    continue
                }
                if (activeSessionToken == exactSessionToken && tunnelHandle == exactHandle) {
                    if (lastHandshake > 0L) state.value = CONNECTED
                    else if (lastHandshake == -1L) state.value = DISCONNECTED
                }
                statusJob = null
                break
            }
        }
    }

    private fun getLastHandshake(): Long {
        if (tunnelHandle == -1) {
            Log.e(TAG, "Trying to get config of a non-existent tunnel")
            return -1
        }
        val config = GoBackend.awgProtectedGetConfig(tunnelHandle)
        if (config == null) {
            Log.e(TAG, "Failed to get tunnel config")
            return -2
        }
        val values = parseCanonicalAwgUapi(config, setOf("last_handshake_time_sec"))
        val lastHandshake = values?.get("last_handshake_time_sec")
        if (lastHandshake == null) {
            Log.e(TAG, "Failed to get last_handshake_time_sec")
            return -2
        }
        return lastHandshake
    }

    private fun turnOffVpn() {
        statusJob?.cancel()
        statusJob = null
        val handleToClose = tunnelHandle
        GoBackend.awgProtectedTurnOff(handleToClose)
        // Do not advertise a reusable/stopped engine until the native call
        // returned.  A JNI exception leaves the handle quarantined and the
        // service-level stop_failed path kills the process fail-closed.
        tunnelHandle = -1
        nativeStartStage = NativeStartStage.CLEAN
    }

    override fun stopVpn() {
        if (tunnelHandle == -1) {
            Log.w(TAG, "Tunnel already down")
            return
        }
        turnOffVpn()
        activeSessionToken = null
        nativeStartStage = NativeStartStage.IDLE
        state.value = DISCONNECTED
    }

    override fun stopInner(exactSessionToken: String) {
        requireExactSessionToken(exactSessionToken)
        if (activeSessionToken != exactSessionToken || tunnelHandle == -1) {
            throw VpnException("Stale or absent AWG inner session")
        }
        turnOffVpn()
        activeSessionToken = null
        nativeStartStage = NativeStartStage.IDLE
    }

    override fun reconnectVpn(vpnBuilder: Builder, protect: (Int) -> Boolean) {
        throw VpnException("AWG reconnect must be supervised by the session-owned TUN service")
    }

    private suspend fun resolveEndpoint(hostName: String): InetAddress = try {
        withTimeout(5_000L) {
            withContext(Dispatchers.IO) {
                val addresses = InetAddress.getAllByName(hostName).toList()
                if (addresses.isEmpty() || addresses.any { !it.isPublicUnicastEndpoint() }) {
                    throw UnknownHostException("endpoint is not public unicast")
                }
                addresses.sortedBy { it.hostAddress }.first()
            }
        }
    } catch (error: Exception) {
        throw VpnStartException("Failed to resolve AWG endpoint")
    }

    private fun requireExactSessionToken(value: String) {
        if (value.isBlank() || value.length > 160 || value.any {
                !(it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' ||
                    it == '-' || it == '_' || it == ':' || it == '.')
            }) {
            throw VpnException("Invalid AWG session token")
        }
    }

    companion object {
        /** AVPN: safe pre-connect probe used by the process-wide manifest. */
        fun probeEngineManifest(context: Context): EngineManifest {
            val runtimeVersion = runCatching {
                loadSharedLibrary(context.applicationContext, "wg-go")
                GoBackend.awgVersion()
            }.getOrNull()
            return EmbeddedEngineManifests.awg(runtimeVersion)
        }
    }
}

internal fun parseAwgUapiStatistics(config: String): Statistics {
    val values = parseCanonicalAwgUapi(
        config,
        setOf("rx_bytes", "tx_bytes", "last_handshake_time_sec"),
    ) ?: return Statistics.EMPTY_STATISTICS
    val rx = values["rx_bytes"] ?: return Statistics.EMPTY_STATISTICS
    val tx = values["tx_bytes"] ?: return Statistics.EMPTY_STATISTICS
    val handshake = values["last_handshake_time_sec"] ?: return Statistics.EMPTY_STATISTICS
    return Statistics.build {
        setSource("awg_uapi")
        setRxBytes(rx)
        setTxBytes(tx)
        setLastHandshakeSec(handshake)
    }
}

internal fun parseCanonicalAwgUapi(
    config: String,
    expectedKeys: Set<String>,
): Map<String, Long>? {
    val result = mutableMapOf<String, Long>()
    for (line in config.lineSequence()) {
        val separator = line.indexOf('=')
        if (separator <= 0) continue
        val key = line.substring(0, separator)
        if (key !in expectedKeys) continue
        if (result.containsKey(key)) return null
        val raw = line.substring(separator + 1)
        if (raw.isEmpty() || (raw.length > 1 && raw.first() == '0') || raw.any { !it.isDigit() }) {
            return null
        }
        val parsed = raw.toULongOrNull() ?: return null
        if (parsed > Long.MAX_VALUE.toULong()) return null
        result[key] = parsed.toLong()
    }
    return result
}
