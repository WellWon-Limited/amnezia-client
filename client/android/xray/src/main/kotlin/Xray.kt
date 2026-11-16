package org.amnezia.vpn.protocol.xray

import android.content.Context
import android.net.TrafficStats
import android.net.VpnService.Builder
import android.os.Build
import android.os.Process
import java.io.File
import java.io.IOException
import java.net.InetAddress
import java.net.NetworkInterface
import java.net.ServerSocket
import java.util.UUID
import java.util.concurrent.atomic.AtomicLong
import go.Seq
import org.amnezia.vpn.protocol.BadConfigException
import org.amnezia.vpn.protocol.Protocol
import org.amnezia.vpn.protocol.ProtocolState.CONNECTED
import org.amnezia.vpn.protocol.ProtocolState.DISCONNECTED
import org.amnezia.vpn.protocol.Statistics
import org.amnezia.vpn.protocol.VpnStartException
import org.amnezia.vpn.protocol.xray.libXray.DialerController
import org.amnezia.vpn.protocol.xray.libXray.LibXray
import org.amnezia.vpn.protocol.xray.libXray.Logger
import org.amnezia.vpn.protocol.xray.libXray.Tun2SocksConfig
import org.amnezia.vpn.protocol.xray.upstream.UpstreamByteTotals
import org.amnezia.vpn.protocol.xray.upstream.UpstreamEnvelopeException
import org.amnezia.vpn.protocol.xray.upstream.UpstreamLeaseSession
import org.amnezia.vpn.protocol.xray.upstream.UpstreamMeter
import org.amnezia.vpn.protocol.xray.upstream.UpstreamMeterScope
import org.amnezia.vpn.protocol.xray.scan.XrayScanHost
import org.amnezia.vpn.util.Log
import org.amnezia.vpn.util.net.InetNetwork
import org.amnezia.vpn.util.net.ip
import org.amnezia.vpn.util.net.parseInetAddress
import org.json.JSONArray
import org.json.JSONObject

private const val TAG = "Xray"
private const val LIBXRAY_TAG = "libXray"
// AVPN: the interface name TrafficStats is asked for when the tunnel's own name cannot be resolved.
private const val DEFAULT_TUN_INTERFACE = "tun0"

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

    @Volatile
    private var isRunning: Boolean = false

    // AVPN: the native pieces this session may have started. stopVpn (and a failed start) tear down exactly
    // these, each at most once, so a second stop is a no-op. Guarded by nativeLock.
    private val nativeLock = Any()
    private var controllersArmed = false
    private var coreMayRun = false
    private var tun2SocksMayRun = false

    // AVPN (decisions A-4, A-5): cumulative tunnel bytes of this session (XrayConfig.kt XrayTunnelCounters).
    // One accumulator for the engine's health loop (statistics -> STATISTICS_UPDATE) and the seat meter.
    private val tunnelCounters = XrayTunnelCounters()
    private val counterSource =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) XrayTunnelCounters.Source.INTERFACE
        else XrayTunnelCounters.Source.UID

    @Volatile
    private var tunInterface: String = DEFAULT_TUN_INTERFACE

    // AVPN (decision A-1, android-ipc-contract.md, android-lease-api.md): the seat-lease owner of an upstream
    // session lives in this process (the activity process may be killed while the service keeps the tunnel).
    // null for AWG, own Xray nodes and imported configs. A generation number drops status callbacks of a
    // session that already ended.
    private val upstreamLock = Any()
    @Volatile
    private var upstream: UpstreamLeaseSession? = null
    private val upstreamGeneration = AtomicLong(0)
    private var lastUpstreamSignature: String? = null

    // AVPN (contract section 4): the core's per-outbound counters of an upstream session whose config got the
    // stats keys (UpstreamStatsPlan.wantsStats + XrayStatsConfig.merge) and whose libXray speaks the
    // expected stats ABI. Read only in this process (the one that runs the core).
    @Volatile
    private var statsWanted = false
    private val proxyMeter = UpstreamProxyMeterAccumulator()

    // Set by the service before startVpn: receives the ServiceEvent.UPSTREAM_STATUS payload
    // ({"upstream":{contract section 5}}) of a CHANGED upstream status (android-ipc-contract.md section 3
    // rule 1). Called from the lease session's callback thread.
    @Volatile
    var upstreamStatusSink: ((String) -> Unit)? = null

    override val statistics: Statistics
        get() {
            if (!isRunning) return Statistics.EMPTY_STATISTICS
            val bytes = sampleTunnelBytes()
            return Statistics.build {
                setRxBytes(bytes.rx)
                setTxBytes(bytes.tx)
            }
        }

    // AVPN (android-ipc-contract.md section 6): while an upstream session runs, core log lines and native
    // error texts are withheld - they can carry the provider's hosts or config fragments. Own nodes and
    // imported configs log as before.
    @Volatile
    private var withholdCoreText = false

    private fun nativeText(text: String): String =
        if (withholdCoreText) "(withheld, ${text.length} chars)" else text

    override fun internalInit() {
        Seq.setContext(context)
        if (!isInitialized) {
            LibXray.initLogger(object : Logger {
                override fun warning(s: String) = Log.w(LIBXRAY_TAG, nativeText(s))

                override fun error(s: String) = Log.e(LIBXRAY_TAG, nativeText(s))

                override fun write(msg: ByteArray): Long {
                    Log.w(LIBXRAY_TAG, if (withholdCoreText) "(withheld, ${msg.size} bytes)" else String(msg))
                    return msg.size.toLong()
                }
            }).isNotNullOrBlank { err ->
                Log.w(TAG, "Failed to initialize logger: $err")
            }
        }
    }

    override suspend fun startVpn(config: JSONObject, vpnBuilder: Builder, protect: (Int) -> Boolean) {
        if (isRunning) {
            Log.w(TAG, "XRay already running")
            return
        }

        val xrayConfigData = config.optJSONObject("xray_config_data")
            ?: config.optJSONObject("ssxray_config_data")
            ?: throw BadConfigException("config_data not found")
        val xrayJsonConfig = JSONObject(xrayConfigData.optString("config"))

        // AVPN (upstream nodes): an upstream session is accounted from its start; a malformed lease fails the
        // start (never provider traffic without a seat). Created before the tunnel, started after it is up.
        val session = openUpstreamSession(config)
        var goLimitBytes = 0L // the Go soft limit of this session (the scan host's pools, ScanCapsPolicy)
        try {
            // Inject SOCKS5 auth before starting xray. Re-uses existing credentials if present.
            ensureInboundAuth(xrayJsonConfig)
            // AVPN (contract section 4): the stats keys, merged AFTER the sanitizer (C++) and never replacing
            // the provider's policy; only for an upstream session that may meter "proxy".
            statsWanted = session != null && UpstreamStatsPlan.wantsStats(config) &&
                LibXray.TribeStatsABI == TRIBE_STATS_ABI && XrayStatsConfig.merge(xrayJsonConfig)
            proxyMeter.reset()
            val xrayConfig = parseConfig(config, xrayJsonConfig, upstreamSession = session != null)

            var xrayJsonConfigString = xrayJsonConfig.toString()
            config.getString("hostName").let { hostName ->
                val ipAddress = parseInetAddress(hostName).ip
                if (hostName != ipAddress) {
                    xrayJsonConfigString = xrayJsonConfigString.replace(hostName, ipAddress)
                }
            }

            // AVPN (decision A-6): the cut geo pair on disk (XrayGeoInstall); a geo file the config needs and
            // the directory lacks fails the start by name (§22.13) before the tunnel exists.
            val geoDir = installGeoData(xrayJsonConfigString)

            tunnelCounters.reset(counterSource)
            tunInterface = DEFAULT_TUN_INTERFACE
            start(xrayConfig, xrayJsonConfigString, geoDir, vpnBuilder, protect)
            goLimitBytes = xrayConfig.maxMemory
        } catch (e: Throwable) {
            closeUpstreamSession(session)
            teardownNative()
            throw e
        }

        session?.start()
        // AVPN (Scanner, lane A3): probes are admitted only while this core runs (decision A-7); the scan's own
        // protector is VpnService.protect, the Go soft limit bounds its pools (ScanCapsPolicy).
        runCatching { scanHost?.open(protect, goLimitBytes) }.onFailure {
            Log.w(TAG, "Scan host not opened: ${it.javaClass.simpleName}")
        }
        state.value = CONNECTED
        isRunning = true
    }

    private fun parseConfig(config: JSONObject, xrayJsonConfig: JSONObject, upstreamSession: Boolean): XrayConfig {
        return XrayConfig.build {
            addAddress(XrayConfig.DEFAULT_IPV4_ADDRESS)

            config.optString("dns1").let {
                if (it.isNotBlank()) addDnsServer(parseInetAddress(it))
            }

            config.optString("dns2").let {
                if (it.isNotBlank()) addDnsServer(parseInetAddress(it))
            }

            addRoute(InetNetwork("0.0.0.0", 0))
            addRoute(InetNetwork("2000::0", 3))
            config.getString("hostName").let {
                excludeRoute(InetNetwork(it, 32))
            }

            config.optString("mtu").let {
                if (it.isNotBlank()) setMtu(it.toInt())
            }

            // AVPN (upstream nodes, contract section 3): Go soft memory limit. `xray_tunables.memory_limit_mib`
            // (clamped 20..40 MiB, XrayTunables) wins; without it the behaviour before: the backend-first
            // `xray_max_memory_bytes` (Task 7, clamped 16..512 MB by ConnectionController) when > 0, else the
            // Builder default XRAY_DEFAULT_MAX_MEMORY (50 MB).
            val tunables = XrayTunables.fromJson(config.optJSONObject(XrayTunables.ENVELOPE_KEY))
            val maxMemory = XrayTunables.goMemoryLimitBytes(tunables, config.optLong("xray_max_memory_bytes", 0L))
            setMaxMemory(maxMemory)
            if (tunables != null) {
                // hev_* have no consumer on Android (tun2socks, not hev): logged for the journal only.
                Log.i(TAG, "xray tunables: memory_mib=${tunables.memoryLimitMiB} max_memory=$maxMemory " +
                    "hev(unused)=${tunables.hevTcpBufferSize}/${tunables.hevMaxSessionCount}/${tunables.hevTaskStackSize}")
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
            // AVPN (upstream nodes, decision A-3): renewals and the app's provisional acquire must go THROUGH
            // the tunnel, so this app's own package is never left outside it by an app-split list.
            configAppSplitTunneling(
                if (upstreamSession) UpstreamAppSplit.withOwnPackageInTunnel(config, context.packageName) else config
            )
        }
    }

    private fun start(
        config: XrayConfig,
        configJson: String,
        geoDir: File,
        vpnBuilder: Builder,
        protect: (Int) -> Boolean,
    ) {
        buildVpnInterface(config, vpnBuilder)

        // AVPN (libxray patch 0003): one call arms the single process-wide protect slot for dialers and
        // listeners (replaces registerDialerController + registerListenerController); cleared on stop.
        DialerController { protect(it.toInt()) }.also {
            synchronized(nativeLock) { controllersArmed = true }
            LibXray.registerSocketControllers(it).isNotNullOrBlank { err ->
                throw VpnStartException("Failed to register socket controllers: $err")
            }
        }

        vpnBuilder.establish().use { tunFd ->
            if (tunFd == null) {
                throw VpnStartException("Create VPN interface: permission not granted or revoked")
            }
            tunInterface = resolveTunInterface(config)
            Log.d(TAG, "Run tun2Socks")
            runTun2Socks(config, tunFd.detachFd())

            Log.d(TAG, "Run XRay")
            Log.i(TAG, "xray ${LibXray.xrayVersion()}")
            val assetsPath = context.getDir("assets", Context.MODE_PRIVATE).absolutePath
            LibXray.initXray(assetsPath)
            // AVPN (A-6): the verified on-disk pair (XrayGeoInstall), never the old getDir("assets")/geo (empty
            // since the AAR embeds no geo) and never "" (libXray sets xray.location.asset even to "").
            val datDir = geoDir.absolutePath
            val configPath = File(context.cacheDir, "config.json")
            Log.v(TAG, "xray.location.asset: $datDir")
            Log.v(TAG, "config: $configPath")
            try {
                configPath.writeText(configJson)
            } catch (e: IOException) {
                throw VpnStartException("Failed to write xray config: ${e.message}")
            }
            synchronized(nativeLock) { coreMayRun = true }
            try {
                LibXray.runXray(datDir, configPath.absolutePath, config.maxMemory).isNotNullOrBlank { err ->
                    throw VpnStartException("Failed to start xray: ${nativeText(err)}")
                }
            } finally {
                // AVPN: the core parsed the file synchronously; a provider's config does not stay on disk.
                if (withholdCoreText) configPath.delete()
            }
        }
    }

    override fun stopVpn() {
        // AVPN (Scanner, lane A3): every scan ends (bounded) and the host closes BEFORE anything of the tunnel
        // changes - before the seat release, before the core stops.
        stopScans("tunnel_stop")
        // AVPN (contract section 6): an upstream session releases its seat through the tunnel BEFORE the core
        // stops, bounded (release 1.5 s + 100 ms, outer wait 2 s); nothing is sent after a terminal answer or
        // while pending. stopVpn runs on the connection scope (IO), never on the main thread.
        detachUpstreamSession()?.let { session ->
            runCatching { session.releaseBlocking() }.onFailure {
                Log.w(TAG, "Upstream release failed: ${it.javaClass.simpleName}")
            }
            runCatching { session.close() }
        }
        teardownNative()

        isRunning = false
        state.value = DISCONNECTED
    }

    override fun reconnectVpn(vpnBuilder: Builder, protect: (Int) -> Boolean) {
        state.value = CONNECTED
    }

    // AVPN: socket controllers first (patch 0003: in-flight protect() calls drain, every later core dial fails
    // closed instead of dialling unprotected), then the core, then the packet adapter - each only if this
    // session may have started it, each leg isolated so a throw cannot skip the next one.
    private fun teardownNative() {
        synchronized(nativeLock) {
            if (controllersArmed) {
                controllersArmed = false
                runCatching { LibXray.clearSocketControllers() }.fold(
                    onSuccess = { err -> err.isNotNullOrBlank { Log.e(TAG, "Failed to clear socket controllers: $it") } },
                    onFailure = { Log.e(TAG, "Failed to clear socket controllers: ${it.javaClass.simpleName}") },
                )
            }
            if (coreMayRun) {
                coreMayRun = false
                runCatching { LibXray.stopXray() }.fold(
                    onSuccess = { err -> err.isNotNullOrBlank { Log.e(TAG, "Failed to stop XRay: ${nativeText(it)}") } },
                    onFailure = { Log.e(TAG, "Failed to stop XRay: ${it.javaClass.simpleName}") },
                )
            }
            if (tun2SocksMayRun) {
                tun2SocksMayRun = false
                runCatching { LibXray.stopTun2Socks() }.fold(
                    onSuccess = { err -> err.isNotNullOrBlank { Log.e(TAG, "Failed to stop tun2Socks: ${nativeText(it)}") } },
                    onFailure = { Log.e(TAG, "Failed to stop tun2Socks: ${it.javaClass.simpleName}") },
                )
            }
        }
    }

    private fun runTun2Socks(config: XrayConfig, fd: Int) {
        val proxyUrl = "socks5://${config.socksUser}:${config.socksPass}@127.0.0.1:${config.socksPort}"
        val tun2SocksConfig = Tun2SocksConfig().apply {
            mtu = config.mtu.toLong()
            proxy = proxyUrl
            device = "fd://$fd"
            logLevel = "warn"
        }
        synchronized(nativeLock) { tun2SocksMayRun = true }
        LibXray.startTun2Socks(tun2SocksConfig, fd.toLong()).isNotNullOrBlank { err ->
            throw VpnStartException("Failed to start tun2socks: ${nativeText(err)}")
        }
    }

    // Ensures SOCKS5 auth is present on the socks inbound settings.
    // Re-uses existing credentials if already configured; otherwise generates random ones.
    private fun ensureInboundAuth(xrayConfig: JSONObject) {
        val inbounds = xrayConfig.optJSONArray("inbounds") ?: return
        val socksIdx = findSocksInboundIndex(inbounds)
        if (socksIdx < 0) return

        val inbound = inbounds.getJSONObject(socksIdx)
        inbound.put("port", acquireFreeLocalPort())
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

    // ---- AVPN: tunnel byte counters (decisions A-4, A-5) ----------------------------------------------

    // The tunnel interface is normally tun0; right after another VPN session of this app it can get another
    // number, so the name is looked up by this session's own address once the interface exists.
    private fun resolveTunInterface(config: XrayConfig): String {
        val address = config.addresses.firstOrNull()?.address ?: return DEFAULT_TUN_INTERFACE
        return runCatching { NetworkInterface.getByInetAddress(address)?.name }.getOrNull()
            ?.takeIf { it.isNotBlank() } ?: DEFAULT_TUN_INTERFACE
    }

    private fun sampleTunnelBytes(): XrayTunnelCounters.Bytes {
        val raw = when (counterSource) {
            XrayTunnelCounters.Source.INTERFACE -> {
                val iface = tunInterface
                XrayTunnelCounters.Bytes(TrafficStats.getRxBytes(iface), TrafficStats.getTxBytes(iface))
            }
            XrayTunnelCounters.Source.UID -> {
                val uid = Process.myUid()
                XrayTunnelCounters.Bytes(TrafficStats.getUidRxBytes(uid), TrafficStats.getUidTxBytes(uid))
            }
        }
        return tunnelCounters.record(raw)
    }

    // One per-outbound read of the core running in THIS process (another process has its own Go runtime).
    private fun readOutboundStats(): XrayOutboundStatsRead =
        XrayOutboundStatsRead.parse(runCatching { LibXray.tribeOutboundStatsJSON() }.getOrNull())

    // The lease session's byte source (the lease lane's meter seam). "tunnel": the same accumulator as
    // STATISTICS_UPDATE, so the health loop and the seat report see one set of counters. "proxy": the core's
    // counters summed over the lease's meter_tags. proxyAvailable is read once when a lease is adopted
    // (UpstreamMeterPlan.scope): the stats keys are in this core's config AND a read answers usable.
    private val sessionMeter = object : UpstreamMeter {
        override val proxyAvailable: Boolean
            get() = statsWanted && readOutboundStats().usable

        override fun totals(scope: UpstreamMeterScope, tags: List<String>): UpstreamByteTotals {
            val bytes = if (scope == UpstreamMeterScope.PROXY) {
                proxyMeter.record(readOutboundStats())
                proxyMeter.totals(tags)
            } else {
                sampleTunnelBytes()
            }
            return UpstreamByteTotals(bytes.rx, bytes.tx)
        }
    }

    // ---- AVPN: geo data (decision A-6) ------------------------------------------------------------------

    // Installs the cut pair from the APK assets into filesDir/xray-geo (sha256-checked) and returns that
    // directory. A config that needs a geo file the directory does not hold fails the start, before the
    // tunnel, with the code `xray_geo_unavailable` (and the installer's own code when it failed); a config
    // without geo rules starts even when the install failed (logged) - there is nothing it would read.
    private fun installGeoData(coreConfig: String): File {
        val dir = File(context.filesDir, XrayGeoInstall.DISK_DIR)
        val result = XrayGeoInstall.install(dir) { name ->
            runCatching { context.assets.open("${XrayGeoInstall.ASSET_DIR}/$name") }.getOrNull()
        }
        val missing = XrayGeoAssets.missing(coreConfig, result.files)
        if (missing.isNotEmpty()) {
            val reason = result.error.ifEmpty { "not_in_pair" }
            throw VpnStartException("$GEO_START_ERROR: $reason; needs ${missing.joinToString(",")}")
        }
        if (result.ok) Log.i(TAG, "xray geo data: ${dir.name} ok") else Log.w(TAG, "xray geo data: ${result.error} (config needs none)")
        return dir
    }

    // ---- AVPN: upstream seat lease (decision A-1; android-ipc-contract.md, android-lease-api.md) ----------

    private fun openUpstreamSession(config: JSONObject): UpstreamLeaseSession? {
        val generation = upstreamGeneration.incrementAndGet()
        synchronized(upstreamLock) { lastUpstreamSignature = null }
        // Withheld from here (a malformed upstream envelope too) until the next start decides again; the
        // teardown of an upstream session is still withheld.
        withholdCoreText = config.has("tribeSessionMetadata")
        val session = try {
            UpstreamLeaseSession.fromEnvelope(
                config,
                meter = sessionMeter,
                onStatus = { status -> onUpstreamStatus(generation, status) },
                log = { Log.i(TAG, it) },
            )
        } catch (e: UpstreamEnvelopeException) {
            // `why` is a field name, never a value.
            throw BadConfigException("upstream lease invalid: ${e.why}")
        }
        upstream = session
        withholdCoreText = session != null
        if (session != null) Log.i(TAG, "upstream session (lease ${if (config.has("upstream_lease")) "present" else "pending"})")
        return session
    }

    private fun detachUpstreamSession(): UpstreamLeaseSession? {
        upstreamGeneration.incrementAndGet()
        val session = upstream
        upstream = null
        return session
    }

    private fun closeUpstreamSession(session: UpstreamLeaseSession?) {
        if (session == null) return
        if (upstream === session) detachUpstreamSession()
        runCatching { session.close() }
    }

    // Status from the session's worker thread. Terminal (android-ipc-contract.md section 4, iOS decision E):
    // the core stops FIRST and the tunnel interface stays (traffic stops, nothing leaks around the tunnel);
    // the VpnService is not torn down here - the engine leaves the node through its existing path. Then the
    // status goes out, only when what the engine acts on changed.
    private fun onUpstreamStatus(generation: Long, status: JSONObject) {
        if (generation != upstreamGeneration.get()) return
        if (status.optString("state") == "terminal") stopCoreForTerminalLease()
        if (generation != upstreamGeneration.get()) return
        if (!recordUpstreamSignature(status)) return
        upstreamStatusSink?.invoke(UpstreamLeaseSession.statusEventOf(status))
    }

    private fun recordUpstreamSignature(status: JSONObject): Boolean {
        val signature = UpstreamStatusChange.signature(status)
        synchronized(upstreamLock) {
            if (signature == lastUpstreamSignature) return false
            lastUpstreamSignature = signature
            return true
        }
    }

    // The core and its socket controllers only; tun2socks keeps the tun fd, so tun0 and the VpnService stay
    // (no reconnect restarts the core: reconnectVpn never starts it). Idempotent.
    private fun stopCoreForTerminalLease() {
        stopScans("lease_terminal") // outside nativeLock: the stop-all is bounded but may take seconds
        synchronized(nativeLock) {
            if (!coreMayRun && !controllersArmed) return
            if (controllersArmed) {
                controllersArmed = false
                runCatching { LibXray.clearSocketControllers() }
            }
            if (coreMayRun) {
                coreMayRun = false
                if (statsWanted) proxyMeter.coreWillStop(readOutboundStats())
                val stopped = runCatching { LibXray.stopXray().isNullOrBlank() }.getOrDefault(false)
                Log.e(TAG, "Upstream lease ended: core stopped, tunnel kept (core_stop_ok=$stopped)")
            }
        }
    }

    // ServiceEvent.UPSTREAM_STATUS payload of the running upstream session; null = no upstream session (own
    // nodes: nothing is sent, android-ipc-contract.md section 3 rule 4).
    fun upstreamStatusEvent(): String? {
        val session = upstream ?: return null
        val status = session.status()
        recordUpstreamSignature(status)
        return UpstreamLeaseSession.statusEventOf(status)
    }

    // Action.UPSTREAM_LEASE_SET with the iOS provider message verbatim (contract section 2). Returns the
    // UPSTREAM_STATUS reply: the session's status after the hand-over (a malformed message leaves it pending),
    // or state "none" when no upstream session runs.
    fun upstreamLeaseSetMessage(message: String?): String {
        val session = upstream ?: return UpstreamLeaseSession.statusEventOf(UpstreamStatusChange.none())
        val reply = session.onLeaseSetMessage(message ?: "")
        runCatching { JSONObject(reply).optJSONObject("upstream") }.getOrNull()?.let { recordUpstreamSignature(it) }
        return reply
    }

    // ---- AVPN: the Scanner's probe host (lane A3) ---------------------------------------------------------------

    @Volatile
    private var scanHostOrNull: XrayScanHost? = null

    // Receives the probe host's state payload {"open","gen"} on every change (set by the service; any thread).
    @Volatile
    var scanStateSink: ((String) -> Unit)? = null

    // Created on first use once this protocol is initialized (it needs the service context), only in the process
    // that runs it (:amneziaXrayService); null before that.
    val scanHost: XrayScanHost?
        get() = scanHostOrNull ?: if (!isInitialized) null else synchronized(this) {
            scanHostOrNull ?: XrayScanHost(context).also { host ->
                host.onStateChanged = { state -> scanStateSink?.invoke(state) }
                scanHostOrNull = host
            }
        }

    private fun stopScans(reason: String) {
        val host = scanHostOrNull ?: return
        runCatching { host.stopAllAndClose(reason) }.onFailure {
            Log.w(TAG, "Scan stop-all failed: ${it.javaClass.simpleName}")
        }
    }

    companion object {
        val instance: Xray by lazy { Xray() }

        // The stats ABI this code reads (libxray tribe.2 patch 0009, LibXray.TribeStatsABI).
        private const val TRIBE_STATS_ABI = "libxray-tribe-stats-v1"

        // Start-failure code of a missing geo file (CONNECT-INVARIANTS §22.13), first word of the error text.
        const val GEO_START_ERROR = "xray_geo_unavailable"
    }
}

private fun String?.isNotNullOrBlank(block: (String) -> Unit) {
    if (!this.isNullOrBlank()) {
        block(this)
    }
}
