package org.amnezia.vpn.protocol.xray

import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import java.security.MessageDigest
import org.amnezia.vpn.protocol.ProtocolConfig
import org.amnezia.vpn.util.net.InetNetwork
import org.json.JSONArray
import org.json.JSONObject

private const val XRAY_DEFAULT_MTU = 1500
internal const val XRAY_DEFAULT_MAX_MEMORY: Long = 50 shl 20 // 50 MB

class XrayConfig protected constructor(
    protocolConfigBuilder: ProtocolConfig.Builder,
    val socksPort: Int,
    val socksUser: String,
    val socksPass: String,
    val maxMemory: Long,
) : ProtocolConfig(protocolConfigBuilder) {

    protected constructor(builder: Builder) : this(
        builder,
        builder.socksPort,
        builder.socksUser,
        builder.socksPass,
        builder.maxMemory
    )

    class Builder : ProtocolConfig.Builder(false) {
        internal var socksPort: Int = 0
            private set

        internal var socksUser: String = ""
            private set

        internal var socksPass: String = ""
            private set

        internal var maxMemory: Long = XRAY_DEFAULT_MAX_MEMORY
            private set

        override var mtu: Int = XRAY_DEFAULT_MTU

        fun setSocksPort(port: Int) = apply { socksPort = port }

        fun setSocksUser(user: String) = apply { socksUser = user }

        fun setSocksPass(pass: String) = apply { socksPass = pass }

        fun setMaxMemory(maxMemory: Long) = apply { this.maxMemory = maxMemory }

        override fun build(): XrayConfig = configBuild().run { XrayConfig(this@Builder) }
    }

    companion object {
        internal val DEFAULT_IPV4_ADDRESS: InetNetwork = InetNetwork("10.0.42.2", 30)

        inline fun build(block: Builder.() -> Unit): XrayConfig = Builder().apply(block).build()
    }
}

// AVPN (upstream nodes, contract section 3; Kotlin twin of client/platforms/ios/XrayTunables.swift):
// the server-tunable sizes of the Xray path, read from the root key `xray_tunables` of the start
// envelope (VpnConnectionTunnelControl.cpp / XrayConfigBuilder::buildUpstream; values come from the
// /v1/config numbers and are clamped by the app first - here again, defence in depth). Rule per key:
// ABSENT = the behaviour before; PRESENT = clamped to the same ranges as iOS; present but not a number
// (string, null, bool) = the key's default. Pure: no Android types, JVM-testable.
//
// On Android only memory_limit_mib has a consumer (the Go soft memory limit of LibXray.runXray). The hev_*
// keys are parsed for parity but unused: the packet adapter here is amnezia-tun2socks inside libXray
// (gVisor), not hev-socks5-tunnel, and it has no equivalent of hev's per-session buffer, session cap or
// task stack (its TCP send/receive buffers are window sizes, a different knob).
data class XrayTunables(
    val memoryLimitMiB: Int? = null,
    val hevTcpBufferSize: Int? = null,
    val hevMaxSessionCount: Int? = null,
    val hevTaskStackSize: Int? = null,
) {
    companion object {
        const val ENVELOPE_KEY = "xray_tunables"

        // Go soft memory limit of the core: 20..40 MiB, default 30 (UpstreamNode.h::xrayMemoryLimitMiBFrom).
        val MEMORY_LIMIT_RANGE = 20..40
        const val MEMORY_LIMIT_DEFAULT_MIB = 30
        // hev-socks5-tunnel `misc` keys; same ranges and defaults as XrayTunables.swift.
        val TCP_BUFFER_RANGE = 4096..65536
        const val TCP_BUFFER_DEFAULT = 4096
        val MAX_SESSION_RANGE = 128..65535
        const val MAX_SESSION_DEFAULT = 1200
        val TASK_STACK_RANGE = 20480..131072
        const val TASK_STACK_DEFAULT = 24576

        private const val KEY_MEMORY = "memory_limit_mib"
        private const val KEY_TCP_BUFFER = "hev_tcp_buffer_size"
        private const val KEY_MAX_SESSION = "hev_max_session_count"
        private const val KEY_TASK_STACK = "hev_task_stack_size"

        // The `xray_tunables` object of the envelope; null when the key is absent or not an object.
        fun fromJson(tunables: JSONObject?): XrayTunables? =
            tunables?.let { obj -> parse(has = obj::has, get = obj::opt) }

        // `has(key)` = the key is present (with any value, null included); `get(key)` = its raw value.
        fun parse(has: (String) -> Boolean, get: (String) -> Any?): XrayTunables {
            fun value(key: String, range: IntRange, default: Int): Int? {
                if (!has(key)) return null
                val raw = get(key)
                // JSON booleans are not numbers here (Swift's decoder refuses them as Double too).
                val number = (raw as? Number)?.toDouble() ?: return default
                if (!number.isFinite()) return default
                return clamp(number, range)
            }
            return XrayTunables(
                memoryLimitMiB = value(KEY_MEMORY, MEMORY_LIMIT_RANGE, MEMORY_LIMIT_DEFAULT_MIB),
                hevTcpBufferSize = value(KEY_TCP_BUFFER, TCP_BUFFER_RANGE, TCP_BUFFER_DEFAULT),
                hevMaxSessionCount = value(KEY_MAX_SESSION, MAX_SESSION_RANGE, MAX_SESSION_DEFAULT),
                hevTaskStackSize = value(KEY_TASK_STACK, TASK_STACK_RANGE, TASK_STACK_DEFAULT),
            )
        }

        // Same rule as XrayTunables.swift clamp: below -> floor, above -> ceiling, else truncated.
        fun clamp(raw: Double, range: IntRange): Int = when {
            raw < range.first -> range.first
            raw > range.last -> range.last
            else -> raw.toInt()
        }

        // maxMemory argument of LibXray.runXray. memory_limit_mib present -> that many MiB. Absent -> the
        // Android behaviour before: `xray_max_memory_bytes` of the envelope when > 0 (clamped 16..512 MB by
        // ConnectionController::createConnectionConfiguration), else the 50 MB default (XRAY_DEFAULT_MAX_MEMORY).
        // iOS uses Int64.max when absent; Android never ran without a limit, so it keeps its own "before".
        fun goMemoryLimitBytes(tunables: XrayTunables?, legacyMaxMemoryBytes: Long): Long {
            tunables?.memoryLimitMiB?.let { return it.toLong() shl 20 }
            return if (legacyMaxMemoryBytes > 0) legacyMaxMemoryBytes else XRAY_DEFAULT_MAX_MEMORY
        }
    }
}

// AVPN (decision A-6): the geo pair the core reads. Since libxray 1.0.3-tribe.2 (patch 0010) the AAR embeds
// no geo files, and the core stats `<datDir>/<file>` on disk before opening it, so libXray's APK-asset
// reader is never consulted: the files must exist on disk. Source: the pinned, cut pair of
// recipes/tribe-xray-geo (geosite private, category-ru, tiktok, speedtest, youtube; geoip private, ru), the
// same bytes iOS and macOS ship, packed by client/cmake/android.cmake as APK assets
// tribe-geo/{geosite.dat,geoip.dat,SHA256SUMS}. install() makes a directory on disk hold both files with the
// hashes SHA256SUMS names: a file already there with the right hash is kept, any other is copied from the
// asset into a temp file in the same directory, verified, then renamed into place (never a half file).
// The directory is the core's datDir (never empty). A config that needs a geo file this directory does not
// hold fails the start by name (XrayGeoAssets.missing, §22.13), never starts without geo data.
object XrayGeoInstall {
    const val ASSET_DIR = "tribe-geo"
    const val SUMS_FILE = "SHA256SUMS"
    const val DISK_DIR = "xray-geo"
    val PAIR: List<String> = listOf("geoip.dat", "geosite.dat")

    // Error codes (prefix before ':'), journal and start-failure text only.
    const val ERR_SUMS = "geo_sums_missing"
    const val ERR_ASSET = "geo_asset_missing"
    const val ERR_HASH = "geo_hash_mismatch"
    const val ERR_IO = "geo_io"

    // `files` = the pair members verified in the directory; `error` = "" when both are there.
    data class Result(val files: Set<String>, val error: String) {
        val ok: Boolean
            get() = error.isEmpty()
    }

    private val sumsLine = Regex("""^([0-9a-fA-F]{64})\s+\*?(\S+)$""")

    // sha256sum format, "<64 hex>  <name>" per line (recipes/tribe-xray-geo tool/main.go).
    fun parseSums(text: String): Map<String, String> =
        text.lineSequence()
            .mapNotNull { sumsLine.matchEntire(it.trim()) }
            .associate { it.groupValues[2] to it.groupValues[1].lowercase() }

    fun sha256(file: File): String? = runCatching {
        if (!file.isFile) return null
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
                val n = input.read(buffer)
                if (n < 0) break
                digest.update(buffer, 0, n)
            }
        }
        digest.digest().joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }.getOrNull()

    // `open(name)`: the asset `tribe-geo/<name>`; null (or a throw) = not in the APK.
    fun install(dir: File, open: (String) -> InputStream?): Result {
        val sums = runCatching { open(SUMS_FILE)?.use { String(it.readBytes(), Charsets.UTF_8) } }.getOrNull()
            ?.let(::parseSums) ?: return Result(emptySet(), ERR_SUMS)
        if (!dir.isDirectory && !dir.mkdirs()) return Result(emptySet(), ERR_IO)
        val installed = sortedSetOf<String>()
        for (name in PAIR) {
            val want = sums[name] ?: return Result(installed, "$ERR_SUMS:$name")
            val target = File(dir, name)
            if (sha256(target) == want) {
                installed += name
                continue
            }
            val temp = File(dir, ".$name.tmp")
            val copied = runCatching {
                val input = open(name) ?: return@runCatching false
                input.use { source ->
                    FileOutputStream(temp).use { sink ->
                        source.copyTo(sink)
                        sink.fd.sync()
                    }
                }
                true
            }
            if (copied.getOrNull() != true) {
                temp.delete()
                return Result(installed, if (copied.isSuccess) "$ERR_ASSET:$name" else "$ERR_IO:$name")
            }
            if (sha256(temp) != want) {
                temp.delete()
                return Result(installed, "$ERR_HASH:$name")
            }
            if (!temp.renameTo(target)) {
                temp.delete()
                return Result(installed, "$ERR_IO:$name")
            }
            installed += name
        }
        return Result(installed, "")
    }
}

// AVPN (contract section 4; Kotlin twin of client/platforms/ios/UpstreamProxyMeter.swift): metering scope
// "proxy" - bytes summed over the lease's `meter_tags` from the running core's own per-outbound counters
// (LibXray.tribeOutboundStatsJSON, ABI libxray-tribe-stats-v1, libxray tribe.2 patches 0007 + 0009). Only
// `meter_tags` are summed: the server lists the user-facing proxy outbounds; dialerProxy hops (they count
// the same bytes again) and direct outbounds are left out by the server. Which scope a lease meters is
// decided by the envelope (UpstreamMeterPlan.scope): "proxy" only when the lease asks for it, names tags and
// the core really has counters; else "tunnel".
object UpstreamStatsPlan {
    // Whether the core of this start gets the stats keys (iOS UpstreamMeterPlan.wantsStats): a provisional
    // start (its lease, handed over later, may ask for "proxy"), or an active lease asking for "proxy" with
    // tags. Own Xray / AWG never get here.
    fun wantsStats(envelope: JSONObject): Boolean {
        val lease = envelope.optJSONObject("upstream_lease") ?: return true
        val tags = lease.optJSONArray("meter_tags")
        return lease.optString("meter_scope") == "proxy" && tags != null && tags.length() > 0
    }
}

object XrayStatsConfig {
    // Merges `"stats": {}` and policy.system.statsOutboundUplink/Downlink = true into a core config. Every
    // existing key is kept (an existing `stats` object as it is, policy.levels, other `system` keys);
    // idempotent. false = `policy` / `policy.system` / `stats` is not an object (left untouched: the
    // counters stay off and the session meters "tunnel").
    fun merge(config: JSONObject): Boolean {
        if (config.has("stats") && config.opt("stats") !is JSONObject) return false
        if (config.has("policy") && config.opt("policy") !is JSONObject) return false
        val policy = config.optJSONObject("policy") ?: JSONObject()
        if (policy.has("system") && policy.opt("system") !is JSONObject) return false
        val system = policy.optJSONObject("system") ?: JSONObject()
        if (!config.has("stats")) config.put("stats", JSONObject())
        system.put("statsOutboundUplink", true)
        system.put("statsOutboundDownlink", true)
        policy.put("system", system)
        config.put("policy", policy)
        return true
    }
}

data class XrayOutboundTraffic(val uplink: Long = 0L, val downlink: Long = 0L)

// One answer of LibXray.tribeOutboundStatsJSON():
// {"running":bool,"outbounds":{"<tag>":{"uplink":n,"downlink":n}},"error":"","error_code":""}.
data class XrayOutboundStatsRead(
    val running: Boolean = false,
    val outbounds: Map<String, XrayOutboundTraffic> = emptyMap(),
    val errorCode: String = "",
) {
    // Counters of a running core that has its stats feature.
    val usable: Boolean
        get() = running && errorCode.isEmpty()

    companion object {
        fun parse(json: String?): XrayOutboundStatsRead {
            val o = runCatching { JSONObject(json ?: "") }.getOrNull()
                ?: return XrayOutboundStatsRead(errorCode = "bad_answer")
            val outbounds = mutableMapOf<String, XrayOutboundTraffic>()
            o.optJSONObject("outbounds")?.let { all ->
                for (tag in all.keys()) {
                    val c = all.optJSONObject(tag) ?: continue
                    outbounds[tag] = XrayOutboundTraffic(counter(c.opt("uplink")), counter(c.opt("downlink")))
                }
            }
            return XrayOutboundStatsRead(
                running = o.opt("running") as? Boolean ?: false,
                outbounds = outbounds,
                errorCode = o.optString("error_code"),
            )
        }

        // A non-negative integer counter; anything else reads as 0 (the Swift parser's jsonInt(0, max) ?? 0).
        private fun counter(value: Any?): Long {
            val n = value as? Number ?: return 0L
            val d = n.toDouble()
            if (!d.isFinite() || d < 0 || d != Math.floor(d)) return 0L
            return n.toLong()
        }
    }
}

// Per-tag session totals over core instances (UpstreamProxyMeterAccumulator.swift). The core counts from zero
// on every start; the base keeps what instances that ended counted, so a session total only grows. A failed
// read changes nothing. Thread-safe.
class UpstreamProxyMeterAccumulator {
    private val base = mutableMapOf<String, XrayOutboundTraffic>()
    private val current = mutableMapOf<String, XrayOutboundTraffic>()

    // A fresh tunnel session: nothing counted yet.
    @Synchronized
    fun reset() {
        base.clear()
        current.clear()
    }

    // A read of the running instance. A counter below the last read: the core restarted without a read
    // before its stop - the last read moves to the base (nothing already counted is lost).
    @Synchronized
    fun record(read: XrayOutboundStatsRead) {
        if (!read.usable) return
        for ((tag, value) in read.outbounds) {
            val last = current[tag] ?: XrayOutboundTraffic()
            if (value.uplink < last.uplink || value.downlink < last.downlink) {
                base[tag] = add(base[tag] ?: XrayOutboundTraffic(), last)
            }
            current[tag] = value
        }
    }

    // Just before the core stops: its final read, then its counters become base.
    @Synchronized
    fun coreWillStop(read: XrayOutboundStatsRead) {
        record(read)
        for ((tag, value) in current) base[tag] = add(base[tag] ?: XrayOutboundTraffic(), value)
        current.clear()
    }

    // Totals over exactly `tags` (a tag outside the list never counts): rx = downlink, tx = uplink.
    @Synchronized
    fun totals(tags: Collection<String>): XrayTunnelCounters.Bytes {
        var rx = 0L
        var tx = 0L
        for (tag in tags.toSet()) {
            val t = add(base[tag] ?: XrayOutboundTraffic(), current[tag] ?: XrayOutboundTraffic())
            rx = sat(rx, t.downlink)
            tx = sat(tx, t.uplink)
        }
        return XrayTunnelCounters.Bytes(rx, tx)
    }

    private fun add(a: XrayOutboundTraffic, b: XrayOutboundTraffic) =
        XrayOutboundTraffic(sat(a.uplink, b.uplink), sat(a.downlink, b.downlink))

    private fun sat(a: Long, b: Long): Long {
        val r = a + b
        return if (r < 0 || r < a) Long.MAX_VALUE else r
    }
}

// AVPN: geo files a core config would open (Kotlin twin of XrayGeoAssets in XrayTunables.swift, itself the
// twin of service/server/xrayassets.h): geosite.dat for `geosite:`, geoip.dat for `geoip:`, <file> for
// `ext:<file>:<code>` / `ext-ip:` / `ext-domain:` / `ext-site:`. A rule whose file is not in the chosen
// geo directory fails the start with a named reason (CONNECT-INVARIANTS §22.13), never a fallback.
object XrayGeoAssets {
    private val geoRegex = Regex("""(?:^|[^A-Za-z0-9_-])(geosite|geoip):""")
    private val extRegex = Regex("""(?:^|[^A-Za-z0-9_-])ext(?:-ip|-domain|-site)?:([^:"\\]+):""")

    fun files(config: String): List<String> {
        val files = sortedSetOf<String>()
        geoRegex.findAll(config).forEach { files += it.groupValues[1] + ".dat" }
        extRegex.findAll(config).forEach { files += it.groupValues[1] }
        return files.toList()
    }

    // Files from files(config) that are not plain names listed in `available`; a path or `..` is missing.
    fun missing(config: String, available: Set<String>): List<String> =
        files(config).filter { name ->
            val plain = name.isNotEmpty() && name != "." && name != ".." && !name.contains('/') && !name.contains('\\')
            !plain || name !in available
        }
}

// AVPN (decisions A-4, A-5): cumulative tunnel bytes since this tunnel's start, from the OS counters
// (android.net.TrafficStats). One accumulator per session feeds both the engine's health loop
// (STATISTICS_UPDATE) and the seat-lease meter (meter_scope "tunnel"), so both see the same numbers.
// Engine contract (CONNECT-INVARIANTS §17.1): rx/tx are cumulative from tunnel start and never go back;
// VpnProtocol::setBytesChanged diffs them as unsigned values, so a smaller value would wrap.
// Source, fixed per session by API level (the same choice as utils/net/TrafficStats.kt and the lease
// lane's TunnelInterfaceMeter): INTERFACE = TrafficStats.getRx/TxBytes(iface), API 31+, the interface is
// created by establish() and counts from 0; UID = the app UID's counters below 31 (monotonic since boot,
// so the first valid sample is the baseline; an approximation: the core's encrypted bytes plus the app's
// own traffic). A negative read (TrafficStats.UNSUPPORTED) changes nothing; a counter that went back was
// restarted by the system and counts from 0 again. Thread-safe.
class XrayTunnelCounters {
    enum class Source { INTERFACE, UID }

    data class Bytes(val rx: Long, val tx: Long) {
        companion object {
            val ZERO = Bytes(0L, 0L)
        }
    }

    private var last: Bytes? = Bytes.ZERO
    private var total = Bytes.ZERO

    // A fresh tunnel start, before establish(): totals back to zero.
    @Synchronized
    fun reset(source: Source) {
        last = if (source == Source.INTERFACE) Bytes.ZERO else null
        total = Bytes.ZERO
    }

    @Synchronized
    fun totals(): Bytes = total

    @Synchronized
    fun record(raw: Bytes?): Bytes {
        if (raw == null || raw.rx < 0 || raw.tx < 0) return total
        val previous = last
        last = raw
        if (previous == null) return total
        val drx = if (raw.rx >= previous.rx) raw.rx - previous.rx else raw.rx
        val dtx = if (raw.tx >= previous.tx) raw.tx - previous.tx else raw.tx
        total = Bytes(total.rx + drx, total.tx + dtx)
        return total
    }
}

// AVPN (android-ipc-contract.md section 3, rule 1): UPSTREAM_STATUS goes out on a change of what the engine
// acts on, never on byte ticks. The key of a contract section 5 object: state, code, seq, revision,
// config_changed, meter_scope (renewed_ms_ago, expires_in_ms and the byte totals move on every read).
object UpstreamStatusChange {
    private val KEYS = listOf("state", "code", "seq", "revision", "config_changed", "meter_scope")

    fun signature(status: JSONObject): String =
        KEYS.joinToString("|") { key -> status.opt(key)?.toString() ?: "" }

    // The status object when no upstream session runs (the reply to a late upstream_lease_set), key for key
    // as contract section 5 with the iOS UpstreamLeaseStatus() defaults.
    fun none(): JSONObject = JSONObject()
        .put("state", "none")
        .put("code", "")
        .put("seq", 0L)
        .put("renewed_ms_ago", -1L)
        .put("expires_in_ms", 0L)
        .put("revision", 0L)
        .put("config_changed", false)
        .put("applied_bytes", 0L)
        .put("shadow_bytes", 0L)
        .put("meter_scope", "tunnel")
}

// AVPN (upstream nodes, decision A-3; android-lease-api.md precondition): the renewals of the seat lease
// (this process) and the app's provisional acquire (contract section 2) must go THROUGH the tunnel, so an
// upstream session never leaves this app's own package outside it. Protocol.configAppSplitTunneling reads
// `appSplitTunnelType` (1 = only the listed apps use the VPN, 2 = the listed apps bypass it) and
// `splitTunnelApps`; the user's list is otherwise kept as it is. Returns a copy of `config` when it changes.
object UpstreamAppSplit {
    private const val TYPE_KEY = "appSplitTunnelType"
    private const val APPS_KEY = "splitTunnelApps"
    private const val INCLUDE = 1
    private const val EXCLUDE = 2

    fun withOwnPackageInTunnel(config: JSONObject, ownPackage: String): JSONObject {
        val type = config.optInt(TYPE_KEY)
        if (type != INCLUDE && type != EXCLUDE) return config
        val apps = config.optJSONArray(APPS_KEY) ?: return config
        val names = (0 until apps.length()).map { apps.optString(it) }
        val adjusted = when (type) {
            INCLUDE -> if (ownPackage in names) names else names + ownPackage
            else -> names.filter { it != ownPackage }
        }
        if (adjusted == names) return config
        return JSONObject(config.toString()).put(APPS_KEY, JSONArray(adjusted))
    }
}
