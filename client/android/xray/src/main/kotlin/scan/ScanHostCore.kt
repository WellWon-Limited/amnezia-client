package org.amnezia.vpn.protocol.xray.scan

import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock

// AVPN (Scanner, lane A3; plan ~/avpn-build/plans/provider-pool/scanner-client-plan.md v2.2 §2.2-§2.2c, §2.5,
// §2.11a; API note scanner-api-note.md (a)): the probe host of tribe-scan-v1 inside :amneziaXrayService - the Kotlin
// twin of client/platforms/ios/TribeScanHost.swift. The Go engine (libxray tribe.3, LibXray.tribeScanMessage, ABI
// libxray-tribe-scan-v1) answers every contract message; this layer relays them and adds only what this process
// alone knows:
//  - host options with EVERY relayed message: this process's generation element (`gen`, source "xray_service";
//    the engine stamps progress and access attempts with it) and the tunnel-change epoch (`host_epoch`);
//  - scan_caps pools lowered to the memory headroom of this moment (the Go engine has no memory guard on Android:
//    its AvailableMB is nil), and `gen` added to scan_caps / scan_progress when the engine left it out;
//  - the tunnel-change epoch (review lessons of the iOS and desktop hosts): every stop-all bumps it under the
//    same lock the start path checks it with; a start captures it ON RECEIPT and re-checks it immediately before
//    the engine call (`tunnel_changed` when it moved); after the tunnel stopped the host stays closed (`no_vpn`)
//    until the next successful tunnel start; a stop-all that did not confirm the stop keeps it closed;
//  - stop-all waits for a start in flight (bounded) and for the engine (bounded): a tunnel change is never
//    blocked for ever.
// Nothing here stops, restarts or reconfigures the tunnel, and nothing reaches the tunnel's socket controllers or
// its protect-failure path: probe sockets go through the scan's own protector (XrayScanHost). Reply bytes stay the
// engine's bytes (a host addition is a splice, ScanJson). Logs carry actions, scan ids, codes and sizes only -
// never a config, a host or a token. Pure Kotlin + org.json, JVM-tested (src/test/kotlin/scan).

// The engine seam (production: LibXray; tests: a stub).
interface ScanEngine {
    fun message(request: String, hostOptions: String): String
    fun stopAll(waitMs: Long): String
}

// This process's element of the strict network generation tuple (ScanNetworkGeneration.h): a random 64-bit epoch
// per monitor start, a counter of the underlying network's changes.
data class ScanNetElement(val epoch: Long, val counter: Long) {
    val epochHex: String
        get() = java.lang.Long.toHexString(epoch).padStart(16, '0')

    // Wire form (ScanNetworkGeneration.h::scanNetSourceToJson): the epoch is a 16-hex string.
    val json: String
        get() = "{\"source\":\"$SOURCE\",\"epoch\":\"$epochHex\",\"counter\":${maxOf(0L, counter)}}"

    companion object {
        const val SOURCE = "xray_service"
    }
}

// The counter grows on every change of the underlying network's signature (the first one is the baseline) and
// never goes back. Thread-safe.
class ScanPathGeneration(val epoch: Long) {
    private var counter = 0L
    private var last: String? = null

    @Synchronized
    fun observe(signature: String): Boolean {
        val previous = last
        last = signature
        if (previous == null || previous == signature) return false
        counter++
        return true
    }

    @Synchronized
    fun element(): ScanNetElement = ScanNetElement(epoch, counter)
}

// The pools this process can afford now. Probes run in the TUNNEL's Go runtime, whose soft limit is the session's
// maxMemory (30 MiB for an upstream session, 50 MB otherwise, Xray.kt / XrayTunables): the scan may use what the
// tunnel core leaves of it; and the device must keep headroom above the low-memory threshold (ActivityManager
// MemoryInfo), or the system may kill this service - and the tunnel with it. Legs first (the main probes; one
// shared instance + about 1 MB per probe in flight, from the iOS measurements of recipes/awg-apple/README.md), a
// full instance only from what is left. Conservative numbers; device gate GA-mem replaces them.
object ScanCapsPolicy {
    const val START_FLOOR_MB = 96.0     // device headroom below which no probe instance starts (scan_start: memory)
    const val RUN_FLOOR_MB = 64.0       // device headroom a running scan must leave
    const val GO_TUNNEL_MB = 20.0       // what the tunnel's own core keeps of the Go soft limit
    const val LEG_INSTANCE_MB = 3.5     // one shared leg instance
    const val PER_LEG_MB = 1.0          // one leg probe in flight
    const val FULL_INSTANCE_MB = 8.0    // one full-profile instance

    data class Pools(val full: Int = 0, val leg: Int = 0)

    // null headroom and null limit (not measurable, e.g. the JVM test) = the engine's pools as they are.
    fun pools(engine: Pools, deviceSpareMb: Double?, goLimitMb: Double?): Pools {
        if (deviceSpareMb == null && goLimitMb == null) return engine
        if (deviceSpareMb != null && (!deviceSpareMb.isFinite() || deviceSpareMb < START_FLOOR_MB)) return Pools()
        val fromDevice = deviceSpareMb?.let { it - RUN_FLOOR_MB } ?: Double.MAX_VALUE
        val fromGo = goLimitMb?.let { it - GO_TUNNEL_MB } ?: Double.MAX_VALUE
        val budget = minOf(fromDevice, fromGo)
        val legs = if (budget >= LEG_INSTANCE_MB + PER_LEG_MB) {
            minOf(engine.leg, ((budget - LEG_INSTANCE_MB) / PER_LEG_MB).toInt())
        } else 0
        val left = budget - (if (legs > 0) LEG_INSTANCE_MB + legs * PER_LEG_MB else 0.0)
        val full = if (left >= FULL_INSTANCE_MB) engine.full else 0
        return Pools(maxOf(0, full), maxOf(0, legs))
    }

    fun startAllowed(deviceSpareMb: Double?): Boolean =
        deviceSpareMb == null || (deviceSpareMb.isFinite() && deviceSpareMb >= START_FLOOR_MB)
}

class ScanHostCore(
    private val engine: ScanEngine,
    private val element: () -> ScanNetElement,
    private val deviceSpareMb: () -> Double?,
    private val log: (String) -> Unit = {},
    private val gateWaitMs: Long = GATE_WAIT_MS,
) {
    companion object {
        val RELAYED = setOf("scan_caps", "scan_start", "scan_add", "scan_poll", "scan_freeze", "scan_cancel")

        // Host-local action of the app adapter's IScanHost::stopAll (not a contract action; the engine never sees it).
        const val STOP_ALL_ACTION = "scan_stop_all"
        const val STOP_ALL_WAIT_MS = 2000L
        // How long a stop-all waits for a scan_start that is inside the engine, and a start for a stop-all in
        // progress. Bounded: a tunnel change is delayed at most this plus STOP_ALL_WAIT_MS.
        const val GATE_WAIT_MS = 4000L
        // A request is one IPC Bundle string; candidates carry configs (12 at most per start, contract limit).
        const val MAX_REQUEST_CHARS = 512 * 1024

        const val UNKNOWN_ACTION = "{\"error\":\"unknown_action\"}"
        const val NO_VPN = "{\"error\":\"no_vpn\"}"
        const val BAD_JSON = "{\"error\":\"bad_request\",\"detail\":\"json\"}"
        const val TOO_LARGE = "{\"error\":\"ipc_refused\",\"detail\":\"too_large\"}"
        const val QUEUE_FULL = "{\"error\":\"ipc_refused\",\"detail\":\"queue_full\"}"
        const val TUNNEL_CHANGED = "{\"error\":\"tunnel_changed\"}"
        const val MEMORY = "{\"error\":\"memory\",\"detail\":\"device_headroom\"}"

        // The reply bound of one relayed message on the app side (AndroidScanHost.h keeps the same table).
        fun replyBoundMs(action: String): Long = when (action) {
            "scan_start" -> 6000L
            "scan_add" -> 3500L
            "scan_cancel", STOP_ALL_ACTION -> 3000L
            else -> 2000L
        }

        fun safeToken(s: String?): String {
            if (s.isNullOrEmpty() || s.length > 64) return "#"
            return if (s.all { it.isLetterOrDigit() && it.code < 128 || it in "._:-" }) s else "#"
        }

        fun replyKind(reply: String): String {
            val o = ScanJson.topLevel(reply) ?: return "raw/${reply.length}"
            o.value("error")?.let { return "error/" + safeToken(ScanJson.string(reply, it)) }
            val t = o.value("type") ?: return "untyped/${reply.length}"
            return safeToken(ScanJson.string(reply, t)) + "/" + reply.length
        }
    }

    private val state = Any()
    private var open = false
    private var epoch = 0L
    private var goLimitMb: Double? = null
    private val gate = ReentrantLock()

    // The tunnel core runs and the scan protector is armed (Xray.kt): new scans are admitted.
    fun open(goLimitBytes: Long) {
        synchronized(state) {
            open = true
            goLimitMb = if (goLimitBytes > 0) goLimitBytes / (1024.0 * 1024.0) else null
        }
    }

    fun isOpen(): Boolean = synchronized(state) { open }

    // The epoch a request belongs to: read on receipt, before it waits in the worker queue.
    fun receive(): Long = synchronized(state) { epoch }

    // The host options of one relayed message.
    fun hostOptions(receivedEpoch: Long): String = "{\"gen\":${element().json},\"host_epoch\":$receivedEpoch}"

    // One message, on the host's single worker thread (XrayScanHost).
    fun handle(request: String, receivedEpoch: Long): String {
        if (request.length > MAX_REQUEST_CHARS) {
            log("Tribe scan: request refused: too large (${request.length} chars)")
            return TOO_LARGE
        }
        val o = ScanJson.topLevel(request) ?: return BAD_JSON
        val action = o.value("action")?.let { ScanJson.string(request, it) }
        if (action == STOP_ALL_ACTION) {
            val stopped = stopAll("app")
            return "{\"type\":\"scan_stop_all_ack\",\"stopped\":$stopped}"
        }
        if (action == null || action !in RELAYED) {
            log("Tribe scan: unknown action ${safeToken(action)}")
            return UNKNOWN_ACTION
        }
        if (request.indexOf('\u0000') >= 0) return BAD_JSON
        return when (action) {
            "scan_start" -> start(request, receivedEpoch)
            "scan_add" -> add(request, receivedEpoch)
            else -> {
                val reply = engine.message(request, hostOptions(receivedEpoch))
                if (action != "scan_poll") log("Tribe scan: $action reply=${replyKind(reply)}")
                decorate(reply)
            }
        }
    }

    private fun start(request: String, receivedEpoch: Long): String {
        val scanId = requestScanId(request)
        if (!ScanCapsPolicy.startAllowed(deviceSpareMb())) {
            log("Tribe scan: start scan=${safeToken(scanId)} refused: memory headroom")
            return MEMORY
        }
        if (!gate.tryLock(gateWaitMs, TimeUnit.MILLISECONDS)) {
            log("Tribe scan: start scan=${safeToken(scanId)} refused: a stop-all holds the gate")
            return TUNNEL_CHANGED
        }
        try {
            synchronized(state) {
                if (!open) {
                    log("Tribe scan: start scan=${safeToken(scanId)} refused: no_vpn")
                    return NO_VPN
                }
                if (epoch != receivedEpoch) {
                    log("Tribe scan: start scan=${safeToken(scanId)} refused: tunnel changed since receipt")
                    return TUNNEL_CHANGED
                }
            }
            val reply = engine.message(request, hostOptions(receivedEpoch))
            log("Tribe scan: start scan=${safeToken(scanId)} request_chars=${request.length} reply=${replyKind(reply)}")
            return decorate(reply)
        } finally {
            gate.unlock()
        }
    }

    // A scan_add may launch probe instances: never interleaved with a stop-all, never after the tunnel changed.
    private fun add(request: String, receivedEpoch: Long): String {
        if (!gate.tryLock(gateWaitMs, TimeUnit.MILLISECONDS)) return TUNNEL_CHANGED
        try {
            synchronized(state) {
                if (!open) return NO_VPN
                if (epoch != receivedEpoch) return TUNNEL_CHANGED
            }
            val reply = engine.message(request, hostOptions(receivedEpoch))
            log("Tribe scan: add request_chars=${request.length} reply=${replyKind(reply)}")
            return decorate(reply)
        } finally {
            gate.unlock()
        }
    }

    // Ends every running scan (engine reason tunnel_stopped) and waits (bounded) for its probe instances. The epoch
    // moves FIRST, under the state lock the start path checks it with: a start not yet past its check is refused;
    // a start inside the engine is waited for (GATE_WAIT_MS at most), then the engine's stop-all ends it. A result
    // other than {"stopped":true} closes the host for new scans until the next open().
    fun stopAll(reason: String): Boolean {
        synchronized(state) { epoch++ }
        val locked = runCatching { gate.tryLock(gateWaitMs, TimeUnit.MILLISECONDS) }.getOrDefault(false)
        val reply = try {
            runCatching { engine.stopAll(STOP_ALL_WAIT_MS) }.getOrDefault("")
        } finally {
            if (locked) gate.unlock()
        }
        val o = ScanJson.topLevel(reply)
        val stopped = o?.value("stopped")?.let { ScanJson.isLiteral(reply, it, "true") } ?: false
        if (!stopped) synchronized(state) { open = false }
        log("Tribe scan: stop-all reason=${safeToken(reason)} stopped=$stopped gate=$locked")
        return stopped
    }

    // Before the tunnel stops (stopVpn, a terminal lease, the service ends): every scan ends, the host closes.
    fun stopAllAndClose(reason: String): Boolean {
        val stopped = stopAll(reason)
        synchronized(state) { open = false }
        return stopped
    }

    // ---- reply additions --------------------------------------------------------------------------------------

    fun decorate(reply: String): String {
        val o = ScanJson.topLevel(reply) ?: return reply
        if (o.value("error") != null) return reply
        val type = o.value("type")?.let { ScanJson.string(reply, it) } ?: return reply
        return when (type) {
            "scan_caps" -> ScanJson.apply(reply, capsEdits(o, reply))
            "scan_progress" ->
                if (ScanJson.isAbsentOrNull(o, reply, "gen")) ScanJson.apply(reply, ScanJson.setMembers(o, listOf("gen" to element().json)))
                else reply
            else -> reply
        }
    }

    private fun capsEdits(o: ScanJson.Obj, b: String): List<ScanJson.Edit> {
        fun pool(key: String): Int = o.value(key)?.let { ScanJson.int(b, it) }?.toInt() ?: 0
        val engine = ScanCapsPolicy.Pools(full = pool("max_full_concurrent"), leg = pool("max_leg_concurrent"))
        val engineAwg = pool("max_awg_concurrent")
        val headroom = deviceSpareMb()
        val limit = synchronized(state) { goLimitMb }
        val now = ScanCapsPolicy.pools(engine, headroom, limit)
        val pairs = ArrayList<Pair<String, String>>()
        // Android offers no awg_mini (plan §2.5: no AmneziaWG runner in this process): the pool is 0 whatever the
        // engine says.
        if (now != engine || engineAwg != 0) {
            pairs += "max_full_concurrent" to "${now.full}"
            pairs += "max_leg_concurrent" to "${now.leg}"
            pairs += "max_awg_concurrent" to "0"
            o.value("kinds")?.let { kr ->
                val kinds = runCatching { org.json.JSONArray(b.substring(kr.first, kr.last + 1)) }.getOrNull()
                if (kinds != null) {
                    val keep = (0 until kinds.length()).map { kinds.optString(it) }.filter {
                        !((it == "xray_full" && now.full == 0) || (it == "xray_leg" && now.leg == 0) || it == "awg_mini")
                    }
                    pairs += "kinds" to org.json.JSONArray(keep).toString()
                }
            }
            if (now.leg == 0) pairs += "dns_plan" to "false"
            if (now.full == 0) pairs += "can_verify_composite" to "false"
            if (headroom != null && now != engine) pairs += "mem_available_mb" to "${maxOf(0, headroom.toInt())}"
        }
        if (ScanJson.isAbsentOrNull(o, b, "gen")) pairs += "gen" to element().json
        return ScanJson.setMembers(o, pairs)
    }

    private fun requestScanId(request: String): String? {
        val o = ScanJson.topLevel(request) ?: return null
        return o.value("scan_id")?.let { ScanJson.string(request, it) }
    }
}
