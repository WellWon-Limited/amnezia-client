package org.amnezia.vpn.protocol.xray

import android.content.Context
import android.net.VpnService.Builder
import android.os.ParcelFileDescriptor
import android.system.Os
import java.io.File
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetAddress
import java.net.UnknownHostException
import java.net.ServerSocket
import java.net.Socket
import java.util.UUID
import go.Seq
import org.amnezia.vpn.protocol.BadConfigException
import org.amnezia.vpn.protocol.Protocol
import org.amnezia.vpn.protocol.EngineManifest
import org.amnezia.vpn.protocol.EmbeddedEngineManifests
import org.amnezia.vpn.protocol.ProtocolState.CONNECTED
import org.amnezia.vpn.protocol.ProtocolState.DISCONNECTED
import org.amnezia.vpn.protocol.Statistics
import org.amnezia.vpn.protocol.SessionTrafficAccumulator
import org.amnezia.vpn.protocol.VpnStartException
import org.amnezia.vpn.protocol.VpnException
import org.amnezia.vpn.protocol.xray.libXray.DialerController
import org.amnezia.vpn.protocol.xray.libXray.LibXray
import org.amnezia.vpn.protocol.xray.libXray.Logger
import org.amnezia.vpn.protocol.xray.libXray.Tun2SocksConfig
import org.amnezia.vpn.util.Log
import org.amnezia.vpn.util.net.InetNetwork
import org.amnezia.vpn.util.net.parseInetAddress
import org.amnezia.vpn.util.net.TrafficStats as AndroidTrafficStats
import org.amnezia.vpn.util.net.isPublicUnicastEndpoint
import org.json.JSONArray
import org.json.JSONObject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.amnezia.vpn.protocol.tunnelPolicyHash

private const val TAG = "Xray"

internal fun requiresEndpointRouteExclusion(envelopeSchema: String): Boolean =
    envelopeSchema != "tribe_catalog_v2_native_v1"
private const val LIBXRAY_TAG = "libXray"

private fun findSocksInboundIndex(inbounds: JSONArray): Int {
    for (i in 0 until inbounds.length()) {
        val o = inbounds.optJSONObject(i) ?: continue
        if (o.optString("protocol").equals("socks", ignoreCase = true)) {
            return i
        }
    }
    return -1
}

private fun acquireFreeLocalPort(): Int {
    try {
        ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { return it.localPort }
    } catch (e: Exception) {
        throw VpnStartException(
            "Failed to acquire free TCP port on 127.0.0.1 for SOCKS inbound: ${e.message}"
        )
    }
}

class Xray : Protocol() {

    override val supportsSessionOwnedTun: Boolean = true

    private data class PreparedXray(
        val outerConfig: JSONObject,
        val xrayJson: JSONObject,
        val endpointAddress: InetAddress,
    )

    override val engineManifest: EngineManifest
        get() {
            val runtimeVersion = if (isInitialized) runCatching { LibXray.xrayVersion() }.getOrNull() else null
            return EmbeddedEngineManifests.xray(runtimeVersion)
        }

    @Volatile
    private var isRunning: Boolean = false
    private val trafficStats = AndroidTrafficStats()
    private val trafficAccumulator = SessionTrafficAccumulator("android_os_trafficstats")
    private var activeSessionToken: String? = null
    private enum class NativeStartStage {
        IDLE, CONTROLLERS_ARMED, STARTING_CORE, CORE_READY, STARTING_ADAPTER, READY, CLEAN, AMBIGUOUS
    }
    private var nativeStartStage = NativeStartStage.IDLE

    override val statistics: Statistics
        get() {
            if (!isRunning) return Statistics.EMPTY_STATISTICS
            val raw = trafficStats.snapshot()
            return trafficAccumulator.sample(
                SessionTrafficAccumulator.Raw(raw.rx, raw.tx)
            )
        }

    override fun internalInit() {
        Seq.setContext(context)
        if (!isInitialized) {
            LibXray.initLogger(object : Logger {
                override fun warning(s: String) {
                    // Raw core messages can contain UUID, SNI, credentials or
                    // serialized config.  Release diagnostics are typed only.
                    Log.w(LIBXRAY_TAG, "warning(redacted,len=${s.length})")
                }

                override fun error(s: String) {
                    Log.e(LIBXRAY_TAG, "error(redacted,len=${s.length})")
                }

                override fun write(msg: ByteArray): Long {
                    Log.w(LIBXRAY_TAG, "record(redacted,len=${msg.size})")
                    return msg.size.toLong()
                }
            }).isNotNullOrBlank { _ ->
                Log.w(TAG, "Failed to initialize Xray logger (details redacted)")
            }
        }
    }

    override suspend fun startVpn(config: JSONObject, vpnBuilder: Builder, protect: (Int) -> Boolean) =
        throw VpnStartException("Xray requires the Tribe session-owned TUN service")

    override suspend fun prepareVpn(config: JSONObject): PreparedVpnSession {
        val xrayConfigData = config.optJSONObject("xray_config_data")
            ?: config.optJSONObject("ssxray_config_data")
            ?: throw BadConfigException("config_data not found")
        val xrayJsonConfig = JSONObject(xrayConfigData.optString("config"))

        // Inject auth now; the actual loopback port is selected immediately
        // before core start and tun2socks starts only after Xray owns it.
        ensureInboundAuth(xrayJsonConfig)
        val hostName = config.getString("hostName")
        val endpointAddress = resolveEndpoint(hostName)

        (xrayJsonConfig.optJSONObject("log") ?: JSONObject().also { xrayJsonConfig.put("log", it) })
            .put("loglevel", "warning")
            .put("access", "none") // disable access log

        if (hostName != endpointAddress.hostAddress) {
            val replacements = replaceVlessEndpointAddress(
                xrayJsonConfig,
                hostName,
                endpointAddress.hostAddress ?: throw VpnStartException("Resolved endpoint has no address"),
            )
            if (replacements == 0) {
                throw BadConfigException("Xray endpoint was not found in the VLESS outbound")
            }
        }
        setSocksInboundPort(xrayJsonConfig, 1024)
        val xrayConfig = parseConfig(config, xrayJsonConfig, endpointAddress)
        return PreparedVpnSession(
            xrayConfig,
            PreparedXray(JSONObject(config.toString()), JSONObject(xrayJsonConfig.toString()), endpointAddress),
        )
    }

    override fun startWithTun(
        prepared: PreparedVpnSession,
        tunFd: Int,
        exactSessionToken: String,
        protect: (Int) -> Boolean,
    ): NativeStartReceipt {
        val ownedTun = ParcelFileDescriptor.adoptFd(tunFd)
        try {
            if (isRunning || activeSessionToken != null) {
                throw VpnStartException("Xray inner session is already active")
            }
            requireExactSessionToken(exactSessionToken)
            val native = prepared.nativeConfig as? PreparedXray
                ?: throw VpnStartException("Invalid Xray prepared session")

            val counterEpoch = UUID.randomUUID().toString().lowercase()
            val baseline = trafficStats.snapshot()
            trafficAccumulator.start(
                counterEpoch,
                SessionTrafficAccumulator.Raw(baseline.rx, baseline.tx),
            )
            activeSessionToken = exactSessionToken
            // No native ownership exists until the controller slot is armed inside start().
            nativeStartStage = NativeStartStage.CLEAN
            try {
                start(native, prepared.policyHash, ownedTun, protect)
                isRunning = true
                nativeStartStage = NativeStartStage.READY
                state.value = CONNECTED
                return NativeStartReceipt(exactSessionToken)
            } catch (error: Throwable) {
                if (nativeStartStage == NativeStartStage.CLEAN) activeSessionToken = null
                throw error
            }
        } finally {
            // Closes every validation/core-start failure before the adapter receives the fd.
            // Once detached, the pinned gomobile ABI owns all returned-error/throw paths.
            ownedTun.close()
        }
    }

    private fun parseConfig(
        config: JSONObject,
        xrayJsonConfig: JSONObject,
        endpointAddress: InetAddress,
    ): XrayConfig {
        return XrayConfig.build {
            addAddress(XrayConfig.DEFAULT_IPV4_ADDRESS)
            addAddress(XrayConfig.DEFAULT_IPV6_ADDRESS)

            config.optString("dns1").let {
                if (it.isNotBlank()) addDnsServer(parseInetAddress(it))
            }

            config.optString("dns2").let {
                if (it.isNotBlank()) addDnsServer(parseInetAddress(it))
            }

            addRoute(InetNetwork("0.0.0.0", 0))
            addRoute(InetNetwork("::", 0))
            requireStrictIpv6Capture()
            // Catalog-v2 protects each exact core socket with VpnService.protect(). A broad host
            // exclusion would let unrelated app traffic to the same IP escape during the
            // guarded blackhole window. Keep the legacy exclusion only for old manual profiles.
            if (requiresEndpointRouteExclusion(config.optString("native_envelope_schema"))) {
                excludeRoute(InetNetwork(endpointAddress,
                    if (endpointAddress.address.size == 4) 32 else 128))
            }

            config.optString("mtu").let {
                if (it.isNotBlank()) setMtu(it.toInt())
            }

            // AVPN backend-first (Task 7): server-tunable Xray engine memory limit, seeded by
            // ConnectionController::createConnectionConfiguration() (already clamped to
            // 16 MB..512 MB there). 0/absent (key not sent, e.g. pre-Task-7 backend, or offline
            // fallback) == keep the Builder default (XRAY_DEFAULT_MAX_MEMORY, 50 MB) unchanged.
            config.optLong("xray_max_memory_bytes", 0L).let {
                if (it > 0) setMaxMemory(it)
            }

            val inbounds = xrayJsonConfig.getJSONArray("inbounds")
            val socksIdx = findSocksInboundIndex(inbounds)
            if (socksIdx < 0) {
                throw BadConfigException("socks inbound not found")
            }
            val socksConfig = inbounds.getJSONObject(socksIdx)
            socksConfig.getInt("port").let { setSocksPort(it) }

            val socksSettings = socksConfig.optJSONObject("settings")
            val accounts = socksSettings?.optJSONArray("accounts")
            if (accounts != null && accounts.length() > 0) {
                val account = accounts.getJSONObject(0)
                setSocksUser(account.optString("user"))
                setSocksPass(account.optString("pass"))
            }

            configSplitTunneling(config)
            configAppSplitTunneling(config)
            configProtectedTunnelRoutes(config)
        }
    }

    private fun start(
        prepared: PreparedXray,
        expectedPolicyHash: String,
        ownedTun: ParcelFileDescriptor,
        protect: (Int) -> Boolean,
    ) {
        val assetsPath = context.getDir("assets", Context.MODE_PRIVATE).absolutePath
        LibXray.initXray(assetsPath)
        val geoDir = File(assetsPath, "geo").absolutePath
        var lastFailure: Throwable? = null
        repeat(3) {
            val json = JSONObject(prepared.xrayJson.toString())
            val port = acquireFreeLocalPort()
            setSocksInboundPort(json, port)
            val runtimeConfig = parseConfig(prepared.outerConfig, json, prepared.endpointAddress)
            if (tunnelPolicyHash(runtimeConfig) != expectedPolicyHash) {
                throw VpnStartException("Xray outer policy changed after preparation")
            }
            val configPath = writeEphemeralConfig(json.toString())
            try {
                try {
                    LibXray.registerSocketControllers(DialerController { protect(it.toInt()) })
                        .isNotNullOrBlank { _ ->
                            throw VpnStartException("Failed to arm Xray socket protection")
                        }
                } catch (error: Throwable) {
                    nativeStartStage = if (clearSocketControllersForTeardown()) {
                        NativeStartStage.CLEAN
                    } else {
                        NativeStartStage.AMBIGUOUS
                    }
                    throw error
                }
                nativeStartStage = NativeStartStage.CONTROLLERS_ARMED
                nativeStartStage = NativeStartStage.STARTING_CORE
                val startError = try {
                    LibXray.runXray(geoDir, configPath.absolutePath, runtimeConfig.maxMemory)
                } catch (error: Throwable) {
                    nativeStartStage = if (clearAndStopCoreForStartRollback()) {
                        NativeStartStage.CLEAN
                    } else {
                        NativeStartStage.AMBIGUOUS
                    }
                    throw error
                }
                if (!startError.isNullOrBlank()) {
                    lastFailure = VpnStartException("Xray core start failed")
                    if (!clearAndStopCoreForStartRollback()) {
                        nativeStartStage = NativeStartStage.AMBIGUOUS
                        throw VpnStartException("Xray core start rollback was not proven")
                    }
                    return@repeat
                }
                nativeStartStage = NativeStartStage.CORE_READY
                // The core has synchronously parsed the file and owns the
                // authenticated loopback listener before any TUN packet can
                // reach tun2socks. A port thief can only make start fail.
                if (!probeLoopbackListener(port, runtimeConfig.socksUser, runtimeConfig.socksPass)) {
                    if (!clearAndStopCoreForStartRollback()) {
                        nativeStartStage = NativeStartStage.AMBIGUOUS
                        throw VpnStartException("Xray listener rollback was not proven")
                    }
                    lastFailure = VpnStartException("Xray listener readiness failed")
                    return@repeat
                }
                try {
                    nativeStartStage = NativeStartStage.STARTING_ADAPTER
                    // The pinned gomobile ABI owns/closes the fd from call
                    // entry, including its returned-error path. A JNI throw
                    // is ambiguous and therefore quarantines the process.
                    runTun2Socks(runtimeConfig, ownedTun)
                } catch (error: Throwable) {
                    // The pinned libxray wrapper closes fd on a returned adapter-start error.
                    // A JNI exception remains ambiguous until both exact stop calls return cleanly.
                    val controllersCleared = clearSocketControllersForTeardown()
                    val adapterStopped = stopAdapterForStartRollback()
                    val coreStopped = stopCoreForStartRollback()
                    val rollbackProven = controllersCleared && adapterStopped && coreStopped
                    nativeStartStage = if (rollbackProven) NativeStartStage.CLEAN
                        else NativeStartStage.AMBIGUOUS
                    throw error
                }
                return
            } finally {
                configPath.delete()
            }
        }
        throw VpnStartException("Xray failed to acquire an authenticated loopback listener", lastFailure)
    }

    override fun stopVpn() {
        if (!isRunning) {
            state.value = DISCONNECTED
            return
        }
        try {
            stopNative()
        } catch (error: VpnException) {
            state.value = org.amnezia.vpn.protocol.ProtocolState.UNKNOWN
            throw error
        }
        state.value = DISCONNECTED
    }

    override fun stopInner(exactSessionToken: String) {
        requireExactSessionToken(exactSessionToken)
        if (!isRunning || activeSessionToken != exactSessionToken) {
            throw VpnException("Stale or absent Xray inner session")
        }
        stopNative()
    }

    override fun abortInnerStart(exactSessionToken: String): Boolean {
        requireExactSessionToken(exactSessionToken)
        if (activeSessionToken == null && nativeStartStage in setOf(
                NativeStartStage.IDLE, NativeStartStage.CLEAN,
            )) return true
        if (activeSessionToken != exactSessionToken) return false
        return try {
            val adapterMayExist = nativeStartStage in setOf(
                NativeStartStage.STARTING_ADAPTER,
                NativeStartStage.READY,
                NativeStartStage.AMBIGUOUS,
            )
            val controllersCleared = clearSocketControllersForTeardown()
            val adapterStopped = !adapterMayExist || stopAdapterForStartRollback()
            val coreStopped = stopCoreForStartRollback()
            if (!controllersCleared || !adapterStopped || !coreStopped) return false
            isRunning = false
            activeSessionToken = null
            nativeStartStage = NativeStartStage.CLEAN
            true
        } catch (_: Throwable) {
            nativeStartStage = NativeStartStage.AMBIGUOUS
            false
        }
    }

    override fun reconnectVpn(vpnBuilder: Builder, protect: (Int) -> Boolean) {
        throw VpnException("Xray reconnect must be supervised by the session-owned TUN service")
    }

    private fun stopNative() {
        // Atomically clear and synchronously drain socket protection before stopping either
        // native component. The pinned core propagates the cleared-slot error, so the live
        // teardown window is fail-closed rather than an unprotected dial window. Each JNI leg is
        // isolated so a throw cannot skip adapter/core cleanup; no native error text is exposed.
        val receipt = XrayNativeTeardown.execute(
            clearControllers = { LibXray.clearSocketControllers() },
            stopAdapter = { LibXray.stopTun2Socks() },
            stopCore = { LibXray.stopXray() },
        )
        if (!receipt.proven) {
            nativeStartStage = NativeStartStage.AMBIGUOUS
            throw VpnException("Xray native teardown was not proven")
        }
        isRunning = false
        activeSessionToken = null
        nativeStartStage = NativeStartStage.IDLE
    }

    private fun stopAdapterForStartRollback(): Boolean =
        runCatching { LibXray.stopTun2Socks().isNullOrBlank() }.getOrDefault(false)

    private fun clearSocketControllersForTeardown(): Boolean =
        runCatching { LibXray.clearSocketControllers().isNullOrBlank() }.getOrDefault(false)

    private fun stopCoreForStartRollback(): Boolean =
        runCatching { LibXray.stopXray().isNullOrBlank() }.getOrDefault(false).also { stopped ->
            if (stopped && nativeStartStage != NativeStartStage.STARTING_ADAPTER) {
                nativeStartStage = NativeStartStage.CLEAN
            }
        }

    private fun clearAndStopCoreForStartRollback(): Boolean {
        val controllersCleared = clearSocketControllersForTeardown()
        val coreStopped = stopCoreForStartRollback()
        return controllersCleared && coreStopped
    }

    private fun runTun2Socks(config: XrayConfig, ownedTun: ParcelFileDescriptor) {
        val proxyUrl = "socks5://${config.socksUser}:${config.socksPass}@127.0.0.1:${config.socksPort}"
        val fd = ownedTun.fd
        val tun2SocksConfig = Tun2SocksConfig().apply {
            mtu = config.mtu.toLong()
            proxy = proxyUrl
            device = "fd://$fd"
            logLevel = "warn"
        }
        // Construct the complete adapter config before transferring ownership. No fallible
        // Kotlin work may occur between detachFd() and the native call.
        val transferredFd = ownedTun.detachFd()
        LibXray.startTun2Socks(tun2SocksConfig, transferredFd.toLong()).isNotNullOrBlank { _ ->
            throw VpnStartException("Failed to start Xray packet adapter")
        }
    }

    // Ensures SOCKS5 auth is present on the socks inbound settings.
    // Re-uses existing credentials if already configured; otherwise generates random ones.
    private fun ensureInboundAuth(xrayConfig: JSONObject) {
        val inbounds = xrayConfig.optJSONArray("inbounds") ?: return
        val socksIdx = findSocksInboundIndex(inbounds)
        if (socksIdx < 0) return

        val inbound = inbounds.getJSONObject(socksIdx)
        val settings = inbound.optJSONObject("settings") ?: JSONObject().also { inbound.put("settings", it) }
        val accounts = settings.optJSONArray("accounts")
        if (accounts != null && accounts.length() > 0) {
            val account = accounts.getJSONObject(0)
            if (account.optString("user").isNotEmpty() && account.optString("pass").isNotEmpty()) {
                // Ensure auth mode is enforced even for imported configs that had accounts
                // but auth: "noauth" (or no auth field).
                settings.put("auth", "password")
                inbound.put("settings", settings)
                inbounds.put(socksIdx, inbound)
                return
            }
        }

        val user = UUID.randomUUID().toString().replace("-", "").substring(0, 16)
        val pass = UUID.randomUUID().toString().replace("-", "")
        settings.put("auth", "password")
        settings.put("accounts", JSONArray().put(JSONObject().put("user", user).put("pass", pass)))
        inbound.put("settings", settings)
        inbounds.put(socksIdx, inbound)
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
        throw VpnStartException("Failed to resolve Xray endpoint")
    }

    private fun setSocksInboundPort(config: JSONObject, port: Int) {
        val inbounds = config.optJSONArray("inbounds")
            ?: throw BadConfigException("inbounds not found")
        val index = findSocksInboundIndex(inbounds)
        if (index < 0) throw BadConfigException("socks inbound not found")
        inbounds.getJSONObject(index).put("port", port)
    }

    private fun writeEphemeralConfig(config: String): File {
        require(config.toByteArray().size <= 2 * 1024 * 1024) { "Xray config is oversized" }
        val directory = File(context.noBackupFilesDir, "xray-runtime").apply {
            if (!exists() && !mkdirs()) throw VpnStartException("Unable to create Xray runtime directory")
            Os.chmod(absolutePath, 0x1C0) // 0700
        }
        val destination = File(directory, "${UUID.randomUUID()}.json")
        val temporary = File(directory, ".${destination.name}.tmp")
        try {
            temporary.outputStream().use { output ->
                output.write(config.toByteArray())
                output.flush()
                output.fd.sync()
            }
            Os.chmod(temporary.absolutePath, 0x180) // 0600
            if (!temporary.renameTo(destination)) {
                throw VpnStartException("Unable to atomically stage Xray config")
            }
            return destination
        } catch (error: Throwable) {
            temporary.delete()
            destination.delete()
            throw error
        }
    }

    private fun probeLoopbackListener(port: Int, username: String, password: String): Boolean = runCatching {
        val user = username.toByteArray(Charsets.UTF_8)
        val pass = password.toByteArray(Charsets.UTF_8)
        require(user.isNotEmpty() && user.size <= 255 && pass.isNotEmpty() && pass.size <= 255)
        Socket().use { socket ->
            socket.connect(java.net.InetSocketAddress("127.0.0.1", port), 500)
            socket.soTimeout = 500
            val output = DataOutputStream(socket.getOutputStream())
            val input = DataInputStream(socket.getInputStream())
            output.write(byteArrayOf(0x05, 0x01, 0x02))
            output.flush()
            require(input.readUnsignedByte() == 0x05 && input.readUnsignedByte() == 0x02)
            output.writeByte(0x01)
            output.writeByte(user.size)
            output.write(user)
            output.writeByte(pass.size)
            output.write(pass)
            output.flush()
            require(input.readUnsignedByte() == 0x01 && input.readUnsignedByte() == 0x00)
        }
        true
    }.getOrDefault(false)

    private fun requireExactSessionToken(value: String) {
        if (value.isBlank() || value.length > 160 || value.any {
                !(it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' ||
                    it == '-' || it == '_' || it == ':' || it == '.')
            }) {
            throw VpnException("Invalid Xray session token")
        }
    }

    // Never perform a textual replacement over the serialized config: the
    // endpoint host may equal Reality serverName/SNI or occur in spider paths.
    // Only the exact current VLESS outbound address field is eligible.
    private fun replaceVlessEndpointAddress(config: JSONObject, hostName: String, ipAddress: String): Int {
        val outbounds = config.optJSONArray("outbounds") ?: return 0
        var replacements = 0
        for (outboundIndex in 0 until outbounds.length()) {
            val outbound = outbounds.optJSONObject(outboundIndex) ?: continue
            if (outbound.optString("protocol") != "vless") continue
            val settings = outbound.optJSONObject("settings") ?: continue
            if (settings.optString("address") == hostName) {
                settings.put("address", ipAddress)
                replacements += 1
            }
        }
        return replacements
    }

    companion object {
        val instance: Xray by lazy { Xray() }

        /** AVPN: safe pre-connect probe used by the process-wide manifest. */
        fun probeEngineManifest(context: Context): EngineManifest {
            val runtimeVersion = runCatching {
                Seq.setContext(context.applicationContext)
                LibXray.xrayVersion()
            }.getOrNull()
            return EmbeddedEngineManifests.xray(runtimeVersion)
        }
    }
}

private fun String?.isNotNullOrBlank(block: (String) -> Unit) {
    if (!this.isNullOrBlank()) {
        block(this)
    }
}
