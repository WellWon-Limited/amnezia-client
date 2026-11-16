package org.amnezia.vpn.protocol.xray.scan

import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import org.json.JSONArray
import org.json.JSONObject

// AVPN (Scanner, lane A3): the probe host relay of :amneziaXrayService (ScanHostCore, ScanJson) with a stub engine.
// Covered: the byte-for-byte replay of every request and reply of the shared scan_host_vectors.json (the C++
// contract's vectors, client/core/serviceEngine/tests/vectors) through the relay; host options (`gen` +
// `host_epoch`) with every relayed message; local answers (unknown action, not JSON, too large); the tunnel-change
// epoch (captured on receipt, re-checked before the engine; stop-all bumps it; closed host = no_vpn; an unconfirmed
// stop-all keeps it closed); stop-all waits for a start inside the engine and is never blocked for ever; caps
// lowered by memory headroom / Go limit, awg_mini never offered; `gen` spliced into caps / progress only when
// absent; the generation counter; and a source gate: the scan code never touches the tunnel's socket controllers.
// Not covered: the byte_gate vectors (the Go engine's gate, replayed by Go), the Android glue (XrayScanHost:
// protector, worker, network monitor - compiled here, exercised on a device).
class ScanHostCoreTest {

    private class StubEngine(var reply: String = "{\"type\":\"scan_ack\",\"scan_id\":\"v\",\"accepted\":0,\"mem_mb\":null}") : ScanEngine {
        val calls = ArrayList<Pair<String, String>>()
        var stopReply = "{\"stopped\":true}"
        var stopCalls = 0
        var startGate: CountDownLatch? = null
        var startEntered: CountDownLatch? = null
        override fun message(request: String, hostOptions: String): String {
            synchronized(calls) { calls += request to hostOptions }
            if (request.contains("\"scan_start\"")) {
                startEntered?.countDown()
                startGate?.await(10, TimeUnit.SECONDS)
            }
            return reply
        }
        override fun stopAll(waitMs: Long): String { stopCalls++; return stopReply }
    }

    private val element = ScanNetElement(0x5eed5eed5eed5eedL, 3)

    private fun core(engine: ScanEngine, spare: Double? = null, gateWaitMs: Long = 4000L, openIt: Boolean = true) =
        ScanHostCore(engine, { element }, { spare }, {}, gateWaitMs).also { if (openIt) it.open(0L) }

    // ---- shared vectors -------------------------------------------------------------------------------------

    private fun vectorsFile(): File {
        System.getenv("TRIBE_UPSTREAM_VECTORS")?.let { dir -> File(dir, "scan_host_vectors.json").takeIf { it.isFile }?.let { return it } }
        var d: File? = File(System.getProperty("user.dir")).absoluteFile
        while (d != null) {
            for (rel in listOf("client/core/serviceEngine/tests/vectors", "core/serviceEngine/tests/vectors")) {
                val f = File(File(d, rel), "scan_host_vectors.json")
                if (f.isFile) return f
            }
            d = d.parentFile
        }
        error("scan_host_vectors.json not found (set TRIBE_UPSTREAM_VECTORS)")
    }

    // Deterministic compact JSON (sorted keys) - the bytes the test feeds in.
    private fun encode(v: Any?): String = when (v) {
        null, JSONObject.NULL -> "null"
        is JSONObject -> v.keys().asSequence().sorted().joinToString(",", "{", "}") { quote(it) + ":" + encode(v.get(it)) }
        is JSONArray -> (0 until v.length()).joinToString(",", "[", "]") { encode(v.get(it)) }
        is String -> quote(v)
        is Boolean -> v.toString()
        is Number -> JSONObject.numberToString(v)
        else -> error("unexpected ${v.javaClass}")
    }

    private fun quote(s: String): String {
        val sb = StringBuilder("\"")
        for (c in s) {
            when {
                c == '"' -> sb.append("\\\"")
                c == '\\' -> sb.append("\\\\")
                c < ' ' -> sb.append(String.format("\\u%04x", c.code))
                else -> sb.append(c)
            }
        }
        return sb.append('"').toString()
    }

    private fun vectorText(v: Any?): String = if (v is String) v else encode(v)

    @Test
    fun replaysEveryRequestByteForByte() {
        val root = JSONObject(vectorsFile().readText())
        assertEquals("tribe-scan-v1", root.getString("version"))
        val requests = root.getJSONArray("requests")
        var relayed = 0
        var local = 0
        for (i in 0 until requests.length()) {
            val v = requests.getJSONObject(i)
            val name = v.getString("name")
            val input = vectorText(v.get("json"))
            val expectError = v.getJSONObject("expect").optString("error")
            val engine = StubEngine()
            val c = core(engine)
            val epoch = c.receive()
            val out = c.handle(input, epoch)
            val action = runCatching { JSONObject(input).optString("action") }.getOrNull()
            if (action != null && action in ScanHostCore.RELAYED) {
                relayed++
                assertEquals(1, engine.calls.size, "request $name relayed once")
                assertEquals(input, engine.calls[0].first, "request $name: the engine got the vector bytes unchanged")
                assertEquals("{\"gen\":${element.json},\"host_epoch\":$epoch}", engine.calls[0].second, "request $name: host options")
                assertEquals(engine.reply, out, "request $name: the engine's answer unchanged")
            } else {
                local++
                assertTrue(engine.calls.isEmpty(), "request $name: answered here")
                val err = JSONObject(out).getString("error")
                assertEquals(expectError, err, "request $name: the local answer is the vector's error")
            }
        }
        assertEquals(requests.length(), relayed + local)
        assertTrue(relayed >= 15, "relayed $relayed")
        assertTrue(local >= 3, "local $local")
    }

    @Test
    fun replaysEveryReplyByteForByteOrWithTheGenSplice() {
        val root = JSONObject(vectorsFile().readText())
        val replies = root.getJSONArray("replies")
        var unchanged = 0
        var spliced = 0
        for (i in 0 until replies.length()) {
            val v = replies.getJSONObject(i)
            val name = v.getString("name")
            val input = vectorText(v.get("json"))
            val engine = StubEngine(input)
            val c = core(engine) // no headroom data, no Go limit: the engine's pools as they are
            val out = c.handle("{\"action\":\"scan_poll\",\"scan_id\":\"s\",\"since\":0}", c.receive())
            val o = ScanJson.topLevel(input)
            val type = o?.value("type")?.let { ScanJson.string(input, it) }
            val awg = o?.value("max_awg_concurrent")?.let { ScanJson.int(input, it) } ?: 0L
            if (o == null || o.value("error") != null || (type != "scan_caps" && type != "scan_progress")) {
                unchanged++
                assertEquals(input, out, "reply $name: relayed byte for byte")
                continue
            }
            if (!ScanJson.isAbsentOrNull(o, input, "gen") && !(type == "scan_caps" && awg > 0)) {
                unchanged++
                assertEquals(input, out, "reply $name: the engine's own gen kept, byte for byte")
                continue
            }
            spliced++
            if (type == "scan_caps" && awg > 0) {
                val caps = JSONObject(out)
                assertEquals(0, caps.getInt("max_awg_concurrent"), "reply $name: no awg_mini on Android")
                assertFalse(caps.optJSONArray("kinds")?.toString()?.contains("awg_mini") ?: false, "reply $name: kind dropped")
            } else if (o.value("gen") == null) {
                val close = input.lastIndexOf('}')
                val sep = if (o.members.isEmpty()) "" else ","
                assertEquals(input.substring(0, close) + sep + "\"gen\":${element.json}" + input.substring(close), out,
                    "reply $name: exactly the engine's bytes + gen")
            }
            val gen = JSONObject(out).getJSONObject("gen")
            assertEquals("xray_service", gen.getString("source"))
            assertEquals(element.epochHex, gen.getString("epoch"))
            assertEquals(3, gen.getInt("counter"))
        }
        assertTrue(unchanged >= 20 && spliced >= 4, "replies: $unchanged unchanged, $spliced spliced")
    }

    // ---- local answers --------------------------------------------------------------------------------------

    @Test
    fun localAnswers() {
        val engine = StubEngine()
        val c = core(engine)
        assertEquals(ScanHostCore.UNKNOWN_ACTION, c.handle("{\"action\":\"scan_teleport\"}", c.receive()))
        assertEquals(ScanHostCore.UNKNOWN_ACTION, c.handle("{\"action\":\"status\"}", c.receive()))
        assertEquals(ScanHostCore.UNKNOWN_ACTION, c.handle("{\"scan_id\":\"x\"}", c.receive()))
        assertEquals(ScanHostCore.BAD_JSON, c.handle("{nope", c.receive()))
        assertEquals(ScanHostCore.BAD_JSON, c.handle("{\"action\":\"scan_poll\"} trailing", c.receive()))
        val big = "{\"action\":\"scan_start\",\"pad\":\"" + "x".repeat(ScanHostCore.MAX_REQUEST_CHARS) + "\"}"
        assertEquals(ScanHostCore.TOO_LARGE, c.handle(big, c.receive()))
        assertTrue(engine.calls.isEmpty(), "nothing of it reached the engine")
        assertEquals(6000L, ScanHostCore.replyBoundMs("scan_start"))
        assertEquals(3500L, ScanHostCore.replyBoundMs("scan_add"))
        assertEquals(3000L, ScanHostCore.replyBoundMs("scan_cancel"))
        assertEquals(2000L, ScanHostCore.replyBoundMs("scan_poll"))
    }

    // ---- the tunnel-change epoch ----------------------------------------------------------------------------

    private val start = "{\"action\":\"scan_start\",\"scan_id\":\"scan-1\"}"

    @Test
    fun closedHostAnswersNoVpnAndNeverStarts() {
        val engine = StubEngine()
        val c = core(engine, openIt = false)
        assertEquals(ScanHostCore.NO_VPN, c.handle(start, c.receive()))
        assertTrue(engine.calls.isEmpty())
        c.open(50L shl 20)
        assertEquals(engine.reply, c.handle(start, c.receive()), "open: relayed")
        c.stopAllAndClose("tunnel_stop")
        assertEquals(ScanHostCore.NO_VPN, c.handle(start, c.receive()), "after the tunnel stopped: closed until the next open")
        assertEquals(1, engine.calls.size)
    }

    @Test
    fun aStartReceivedBeforeAStopAllIsRefused() {
        val engine = StubEngine()
        val c = core(engine)
        val received = c.receive()        // the start arrives ...
        assertTrue(c.stopAll("node_switch"))  // ... a tunnel change happens while it waits in the queue ...
        c.open(0L)                         // ... and the tunnel is up again
        assertEquals(ScanHostCore.TUNNEL_CHANGED, c.handle(start, received), "the old start never reaches the engine")
        assertTrue(engine.calls.isEmpty())
        val fresh = c.receive()
        assertEquals(engine.reply, c.handle(start, fresh), "a start received after the change runs")
        assertEquals("{\"gen\":${element.json},\"host_epoch\":$fresh}", engine.calls.single().second, "host_epoch = the receipt epoch")
        assertTrue(fresh > received)
        // scan_add belongs to the epoch too.
        assertEquals(ScanHostCore.TUNNEL_CHANGED, c.handle("{\"action\":\"scan_add\",\"scan_id\":\"scan-1\"}", received))
    }

    @Test
    fun anUnconfirmedStopAllKeepsTheHostClosed() {
        // The engine's real "not stopped" shape: flat top-level live counts (amnezia-libxray 0012 StopAllJSON).
        val engine = StubEngine().apply {
            stopReply = "{\"stopped\":false,\"instances\":1,\"jobs\":2,\"closers\":1,\"attempts\":3,\"awg\":4,\"children\":5}"
        }
        val c = core(engine)
        assertFalse(c.stopAll("app"))
        assertFalse(c.isOpen())
        assertEquals(ScanHostCore.NO_VPN, c.handle(start, c.receive()))
        engine.stopReply = ""
        c.open(0L)
        assertEquals("{\"type\":\"scan_stop_all_ack\",\"stopped\":false}", c.handle("{\"action\":\"scan_stop_all\"}", c.receive()),
            "no answer = not stopped")
        assertFalse(c.isOpen())
    }

    @Test
    fun stopAllWaitsForAStartInsideTheEngineButNotForEver() {
        val engine = StubEngine().apply { startGate = CountDownLatch(1); startEntered = CountDownLatch(1) }
        val c = core(engine, gateWaitMs = 300L)
        var startReply = ""
        val t = thread { startReply = c.handle(start, c.receive()) }
        assertTrue(engine.startEntered!!.await(5, TimeUnit.SECONDS))
        val t0 = System.nanoTime()
        val stopped = c.stopAll("tunnel_stop") // the start is stuck inside the engine: wait 300 ms, then stop anyway
        val waitedMs = (System.nanoTime() - t0) / 1_000_000
        assertTrue(stopped)
        assertTrue(waitedMs in 250..3000, "bounded wait $waitedMs ms")
        assertEquals(1, engine.stopCalls)
        engine.startGate!!.countDown()
        t.join(5000)
        assertEquals(engine.reply, startReply)
        // A start that arrives while the stop-all holds the gate gives up after the bound and is refused.
        val slowStop = object : ScanEngine {
            val inStop = CountDownLatch(1)
            val release = CountDownLatch(1)
            override fun message(request: String, hostOptions: String) = "{\"type\":\"scan_ack\"}"
            override fun stopAll(waitMs: Long): String { inStop.countDown(); release.await(5, TimeUnit.SECONDS); return "{\"stopped\":true}" }
        }
        val c2 = core(slowStop, gateWaitMs = 200L)
        val e = c2.receive()
        val stopper = thread { c2.stopAll("tunnel_stop") }
        assertTrue(slowStop.inStop.await(5, TimeUnit.SECONDS))
        assertEquals(ScanHostCore.TUNNEL_CHANGED, c2.handle(start, e))
        slowStop.release.countDown()
        stopper.join(5000)
    }

    // ---- memory -----------------------------------------------------------------------------------------------

    @Test
    fun poolsByHeadroomAndGoLimit() {
        val engine = ScanCapsPolicy.Pools(full = 1, leg = 4)
        assertEquals(engine, ScanCapsPolicy.pools(engine, null, null), "nothing measurable: the engine's pools")
        assertEquals(ScanCapsPolicy.Pools(), ScanCapsPolicy.pools(engine, 95.9, null), "below the start floor: nothing")
        assertEquals(ScanCapsPolicy.Pools(), ScanCapsPolicy.pools(engine, Double.NaN, null))
        assertEquals(engine, ScanCapsPolicy.pools(engine, 500.0, 50.0 * 1.048576), "own session (50 MB), plenty of memory")
        assertEquals(ScanCapsPolicy.Pools(full = 0, leg = 4), ScanCapsPolicy.pools(engine, 500.0, 30.0 * 1.048576),
            "upstream session (30 MiB): legs only")
        assertEquals(ScanCapsPolicy.Pools(full = 0, leg = 2), ScanCapsPolicy.pools(engine, 64.0 + 32.0, 20.0 + 5.5),
            "tight Go limit: two legs")
        assertEquals(ScanCapsPolicy.Pools(full = 0, leg = 0), ScanCapsPolicy.pools(engine, 200.0, 20.0 + 4.0), "no room for a leg instance")
        assertFalse(ScanCapsPolicy.startAllowed(50.0))
        assertTrue(ScanCapsPolicy.startAllowed(null))
        assertTrue(ScanCapsPolicy.startAllowed(96.0))
    }

    @Test
    fun capsLoweredAndStartRefusedOnLowMemory() {
        val caps = "{\"type\":\"scan_caps\",\"version\":\"tribe-scan-v1\",\"kinds\":[\"xray_full\",\"xray_leg\"],\"max_full_concurrent\":1,\"max_leg_concurrent\":4,\"dns_plan\":true,\"can_verify_composite\":false,\"needs_vpn\":true}"
        val engine = StubEngine(caps)
        val low = core(engine, spare = 80.0)
        val out = JSONObject(low.handle("{\"action\":\"scan_caps\"}", low.receive()))
        assertEquals(0, out.getInt("max_full_concurrent"))
        assertEquals(0, out.getInt("max_leg_concurrent"))
        assertEquals(0, out.getJSONArray("kinds").length())
        assertFalse(out.getBoolean("dns_plan"))
        assertEquals(80, out.getInt("mem_available_mb"))
        assertEquals(ScanHostCore.MEMORY, low.handle(start, low.receive()), "no headroom: the start is refused here")
        val upstream = core(StubEngine(caps), spare = 1000.0).apply { open(30L shl 20) }
        val up = JSONObject(upstream.handle("{\"action\":\"scan_caps\"}", upstream.receive()))
        assertEquals(0, up.getInt("max_full_concurrent"))
        assertEquals(4, up.getInt("max_leg_concurrent"))
        assertEquals(listOf("xray_leg"), (0 until up.getJSONArray("kinds").length()).map { up.getJSONArray("kinds").getString(it) })
        assertTrue(up.getBoolean("dns_plan"))
        // Unchanged pools: only gen is added, every other byte stays.
        val plenty = core(StubEngine(caps), spare = 1000.0).apply { open(50L shl 20) }
        assertEquals(caps.dropLast(1) + ",\"gen\":${element.json}}", plenty.handle("{\"action\":\"scan_caps\"}", plenty.receive()))
    }

    // ---- JSON splice + generation -------------------------------------------------------------------------------

    @Test
    fun spliceAndGeneration() {
        val s = "{\"a\":1, \"b\":{\"x\":[1,{\"y\":\"}\"}]}, \"c\":\"q\\\"}\"}"
        val o = assertNotNull(ScanJson.topLevel(s))
        assertEquals(listOf("a", "b", "c"), o.members.map { it.key })
        assertEquals("{\"a\":2, \"b\":{\"x\":[1,{\"y\":\"}\"}]}, \"c\":\"q\\\"}\",\"d\":true}",
            ScanJson.apply(s, ScanJson.setMembers(o, listOf("a" to "2", "d" to "true"))))
        assertEquals("{\"d\":1}", ScanJson.apply("{}", ScanJson.setMembers(ScanJson.topLevel("{}")!!, listOf("d" to "1"))))
        assertEquals(null, ScanJson.topLevel("[1]"))
        assertEquals(null, ScanJson.topLevel("{\"a\":1}{"))
        val g = ScanPathGeneration(0x0123L)
        assertFalse(g.observe("wifi|wlan0|a"), "the first signature is the baseline")
        assertFalse(g.observe("wifi|wlan0|a"))
        assertTrue(g.observe("cellular|rmnet0|b"))
        assertTrue(g.observe(""))
        assertEquals(ScanNetElement(0x0123L, 2), g.element())
        assertEquals("{\"source\":\"xray_service\",\"epoch\":\"0000000000000123\",\"counter\":2}", g.element().json)
        assertEquals("ffffffffffffffff", ScanNetElement(-1L, 0).epochHex)
    }

    // ---- source gate (plan §2.2a: the scan never touches the tunnel's socket slot or failure path) -------------

    @Test
    fun theScanCodeNeverTouchesTheTunnelsControllers() {
        val dir = generateSequence(File(System.getProperty("user.dir")).absoluteFile) { it.parentFile }
            .map { File(it, "src/main/kotlin/scan") }.firstOrNull { it.isDirectory }
            ?: File(vectorsFile().parentFile, "../../../../android/xray/src/main/kotlin/scan")
        val files = dir.listFiles { f -> f.name.endsWith(".kt") }.orEmpty()
        assertTrue(files.size >= 3, "scan sources at $dir")
        for (f in files) {
            val text = f.readText().lines().filterNot { it.trimStart().startsWith("//") }.joinToString("\n")
            for (forbidden in listOf("registerDialerController", "registerListenerController", "registerSocketControllers",
                    "clearSocketControllers", "stopXray", "runXray", "stopTun2Socks", "establish(")) {
                assertFalse(text.contains(forbidden), "${f.name} must not call $forbidden")
            }
        }
    }
}
