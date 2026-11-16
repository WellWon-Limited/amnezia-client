package org.amnezia.vpn.protocol.xray.upstream

import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.json.JSONObject

// AVPN upstream nodes (lane A2): the renewer with a fake clock, a fake HTTP layer and a manual timer -
// renew cadence, the 60 s timer cap, retry rules, terminal vs retryable codes, the bounded release, a sleep
// jump past the TTL, the hand-over - plus the entry class and the real HTTPS transport against a local
// server (plain http on 127.0.0.1; https is enforced where api_base is parsed).
class UpstreamLeaseRenewerTest {

    private class FakeTransport : UpstreamLeaseTransport {
        data class Request(val method: String, val url: String, val headers: Map<String, String>, val body: String, val timeoutMs: Long)

        private val lock = Any()
        private val queued = ArrayDeque<UpstreamHttpResult>()
        private val requests = mutableListOf<Request>()
        @Volatile var delayMs = 0L
        @Volatile var holdPost: CountDownLatch? = null

        fun answer(status: Int, body: String) = synchronized(lock) { queued.addLast(UpstreamHttpResult(status, body.toByteArray())) }

        override fun send(method: String, url: String, headers: Map<String, String>, body: String, timeoutMs: Long): UpstreamHttpResult {
            val r = synchronized(lock) {
                requests += Request(method, url, headers, body, timeoutMs)
                if (method == "DELETE") UpstreamHttpResult(204) else queued.removeFirstOrNull() ?: UpstreamHttpResult(errorCode = "timeout")
            }
            if (method == "POST") holdPost?.await(5, TimeUnit.SECONDS)
            if (delayMs > 0) Thread.sleep(delayMs)
            return r
        }

        val snapshot: List<Request> get() = synchronized(lock) { requests.toList() }
    }

    private class TestClock {
        private val v = AtomicLong(5_000_000)
        val now: Long get() = v.get()
        fun advance(ms: Long) = v.addAndGet(ms)
    }

    private class FakeMeter(var proxy: Boolean = false) : UpstreamMeter {
        @Volatile var rx = 0L
        @Volatile var tx = 0L
        val calls = mutableListOf<Pair<UpstreamMeterScope, List<String>>>()
        override val proxyAvailable: Boolean get() = proxy
        fun set(r: Long, t: Long) { rx = r; tx = t }
        override fun totals(scope: UpstreamMeterScope, tags: List<String>): UpstreamByteTotals = synchronized(calls) {
            calls += scope to tags
            if (scope == UpstreamMeterScope.PROXY) UpstreamByteTotals(777, 33) else UpstreamByteTotals(rx, tx)
        }
    }

    private class ManualScheduler : UpstreamLeaseScheduler {
        val delays = mutableListOf<Long>()
        private var pending: Runnable? = null
        override fun schedule(delayMs: Long, task: Runnable): UpstreamTimerCancel {
            synchronized(this) {
                delays += delayMs
                pending = task
            }
            return UpstreamTimerCancel { synchronized(this) { if (pending === task) pending = null } }
        }
        val armed: Boolean get() = synchronized(this) { pending != null }
        // Runs the armed timer task, as the executor would.
        fun fire() {
            val t = synchronized(this) { pending.also { pending = null } }
            t?.run()
        }
    }

    private class Statuses {
        private val list = mutableListOf<UpstreamLeaseStatus>()
        fun add(s: UpstreamLeaseStatus) = synchronized(list) { list += s }
        val all: List<UpstreamLeaseStatus> get() = synchronized(list) { list.toList() }
    }

    private class Rig(scope: Boolean = false) {
        val transport = FakeTransport()
        val clock = TestClock()
        val meter = FakeMeter(scope)
        val timer = ManualScheduler()
        val statuses = Statuses()
        val renewer = UpstreamLeaseRenewer("3f9c2a7b1d4e8f60", transport, meter, { clock.now }, statuses::add,
            scheduler = timer)

        // The timer fires after `ms` of fake time; waits for the renewal it may have sent.
        fun after(ms: Long) {
            clock.advance(ms)
            timer.fire()
            renewer.drainForTest()
        }
    }

    private fun renewBody(seq: Long, status: String = "ok", epoch: Long = 7, expires: String = "2025-11-14T11:18:20.000Z") =
        """{"applied_bytes":0,"config_changed":false,"expires_at":"$expires","lease_id":"$K_LEASE","renew_after_s":300,"seq":$seq,"shadow_bytes":1234,"status":"$status","traffic_accounting_epoch":$epoch,"upstream_revision":100}"""

    @Test
    fun renewerFlow() {
        val r = Rig()
        r.renewer.startActive(lease(seq = 5, epoch = 7))
        var st = r.renewer.status()
        assertTrue(st.state == "active" && st.seq == 5L && st.renewedMsAgo == -1L && st.expiresInMs == 900_000L &&
            st.meterScope == UpstreamMeterScope.TUNNEL, "status active $st")
        assertEquals(60_000L, r.renewer.lastTimerDelayMs, "timer capped at 60 s ahead (renewal due in 300 s)")
        r.meter.set(2048, 512)
        r.after(240_000)
        r.after(59_000)
        assertTrue(r.transport.snapshot.isEmpty(), "not due before renew_after_s")
        assertEquals(1_000L, r.renewer.lastTimerDelayMs, "re-armed to the exact due time")
        r.transport.answer(200, renewBody(6))
        r.after(1_000)
        val reqs = r.transport.snapshot
        assertEquals(1, reqs.size, "one renewal")
        val q = reqs.first()
        assertEquals("POST", q.method)
        assertEquals("https://t.example.net/v1/upstream/lease/$K_LEASE/renew", q.url)
        assertEquals("Bearer tlr1.TOKEN", q.headers["Authorization"], "lease-scoped token, never the device token")
        assertEquals("application/json", q.headers["Content-Type"])
        assertEquals("""{"epoch":7,"meter_scope":"tunnel","rx_bytes_delta":2048,"seq":6,"tx_bytes_delta":512}""", q.body)
        assertEquals(UpstreamLeaseRenewer.RENEW_TIMEOUT_MS, q.timeoutMs, "bounded timeout")
        st = r.renewer.status()
        assertTrue(st.seq == 6L && st.renewedMsAgo == 0L && st.shadowBytes == 1234L, "status after renewal $st")
        assertEquals(setOf("state", "code", "seq", "renewed_ms_ago", "expires_in_ms", "revision", "config_changed",
            "applied_bytes", "shadow_bytes", "meter_scope"), st.toJson().keySet(), "status keys = contract section 5")
        // A transport failure: retried 15 s later with the same report.
        r.meter.set(4096, 1024)
        r.after(300_000)
        r.after(14_999)
        assertEquals(2, r.transport.snapshot.size, "no retry before 15 s")
        r.transport.answer(404, """{"code":"lease_gone"}""")
        r.after(1)
        val all = r.transport.snapshot
        assertEquals(3, all.size, "renewal + retry")
        assertEquals(all[1].body, all[2].body, "retry resends the same report")
        assertTrue(all[2].body.contains("\"seq\":7"), "seq 7")
        val last = r.statuses.all.last()
        assertTrue(last.state == "terminal" && last.code == "lease_gone", "terminal reported through onStatus: $last")
        st = r.renewer.status()
        assertTrue(st.state == "terminal" && st.code == "lease_gone" && st.expiresInMs == 0L, "status terminal $st")
        assertTrue(r.renewer.isTerminal)
        assertFalse(r.timer.armed, "no timer after a terminal answer")
        r.clock.advance(1_000_000)
        r.renewer.fireForTest()
        val released = CountDownLatch(1)
        r.renewer.release { released.countDown() }
        assertTrue(released.await(1, TimeUnit.SECONDS), "release completion after terminal")
        assertEquals(3, r.transport.snapshot.size, "nothing sent after terminal (no renew, no release)")
        assertEquals("terminal", r.renewer.status().state, "the terminal code stays readable after the end")
    }

    @Test
    fun renewCadenceAndTimerCap() {
        val r = Rig()
        r.renewer.startActive(lease(seq = 0, renewAfter = 300))
        for (cycle in 1..3) {
            for (k in 1..4) {
                r.after(60_000)
                assertEquals(cycle - 1, r.transport.snapshot.size, "cycle $cycle: nothing at ${k * 60} s")
            }
            r.transport.answer(200, renewBody(cycle.toLong()))
            r.after(60_000)
            assertEquals(cycle, r.transport.snapshot.size, "cycle $cycle: renewal at 300 s")
            assertTrue(r.transport.snapshot.last().body.contains("\"seq\":$cycle"), "seq $cycle")
        }
        assertTrue(r.timer.delays.all { it in 0..UpstreamLeaseRenewer.MAX_TIMER_AHEAD_MS }, "every timer <= 60 s: ${r.timer.delays}")
        assertEquals(3L, r.renewer.status().seq)
    }

    @Test
    fun retryableCodesAreRetriedTerminalCodesEnd() {
        for (code in listOf("no_seat", "rate_limited", "upstream_unavailable")) {
            val r = Rig()
            r.renewer.startActive(lease())
            r.transport.answer(if (code == "rate_limited") 429 else if (code == "no_seat") 409 else 503,
                """{"code":"$code","retry_after_s":42}""")
            r.after(300_000)
            assertEquals(1, r.transport.snapshot.size, "$code: sent")
            r.after(41_999)
            assertEquals(1, r.transport.snapshot.size, "$code: retry_after honoured (not before 42 s)")
            r.transport.answer(200, renewBody(6))
            r.after(1)
            assertEquals(2, r.transport.snapshot.size, "$code: retried at 42 s")
            assertEquals(r.transport.snapshot[0].body, r.transport.snapshot[1].body, "$code: same report")
            assertTrue(r.statuses.all.none { it.state == "terminal" } && r.renewer.status().state == "active", "$code never terminal")
            r.renewer.stop()
        }
        for ((code, http) in listOf("not_entitled" to 403, "over_quota" to 410, "disabled" to 410, "lease_gone" to 404)) {
            val r = Rig()
            r.renewer.startActive(lease())
            r.transport.answer(http, """{"code":"$code"}""")
            r.after(300_000)
            val st = r.renewer.status()
            assertTrue(st.state == "terminal" && st.code == code, "$code is terminal: $st")
            assertEquals("terminal", r.statuses.all.last().state, "$code reported")
            r.after(3_600_000)
            assertEquals(1, r.transport.snapshot.size, "$code: nothing sent after it")
        }
        // An unknown body (a block page) is never terminal; three 422 in a row are (renew_rejected).
        val r = Rig()
        r.renewer.startActive(lease())
        r.transport.answer(403, "<html>blocked</html>")
        r.after(300_000)
        assertEquals("active", r.renewer.status().state, "a 403 block page is transient")
        repeat(3) { r.transport.answer(422, """{"code":"invalid_request"}""") }
        r.after(15_000)
        r.after(30_000)
        r.after(60_000)
        assertEquals(4, r.transport.snapshot.size)
        assertEquals("renew_rejected", r.renewer.status().code, "three rejected renewals in a row end the session")
    }

    @Test
    fun releaseIsBounded() {
        val r = Rig()
        r.renewer.startActive(lease(seq = 1, epoch = 3))
        r.meter.set(900, 90)
        val done = CountDownLatch(1)
        r.renewer.release { done.countDown() }
        assertTrue(done.await(3, TimeUnit.SECONDS), "release completes")
        val q = r.transport.snapshot.last()
        assertEquals("DELETE", q.method)
        assertEquals("https://t.example.net/v1/upstream/lease/$K_LEASE", q.url)
        assertEquals("""{"epoch":3,"meter_scope":"tunnel","rx_bytes_delta":900,"seq":2,"tx_bytes_delta":90}""", q.body, "final report")
        assertEquals(1_500L, q.timeoutMs, "release bounded to 1.5 s")
        // A hanging network: the completion still runs at the bound.
        val slow = Rig()
        slow.transport.delayMs = 5_000
        slow.renewer.startActive(lease())
        val t0 = System.nanoTime()
        val done2 = CountDownLatch(1)
        slow.renewer.release { done2.countDown() }
        assertTrue(done2.await(3, TimeUnit.SECONDS), "bounded release")
        val elapsedMs = (System.nanoTime() - t0) / 1_000_000
        assertTrue(elapsedMs in 1_400..2_500, "release gave up at ~1.6 s, took $elapsedMs ms")
        // Pending session, stopped before the hand-over: nothing to release.
        val none = Rig()
        none.renewer.startPending()
        val done3 = CountDownLatch(1)
        none.renewer.release { done3.countDown() }
        assertTrue(done3.await(1, TimeUnit.SECONDS) && none.transport.snapshot.isEmpty(), "no release without a lease")
        // A second release is a no-op that still completes.
        val done4 = CountDownLatch(1)
        r.renewer.release { done4.countDown() }
        assertTrue(done4.await(1, TimeUnit.SECONDS) && r.transport.snapshot.size == 1, "release once")
    }

    @Test
    fun releaseWithRenewalInFlightMergesTheReport() {
        val r = Rig()
        r.renewer.startActive(lease(seq = 4))
        r.meter.set(100, 10)
        val hold = CountDownLatch(1)
        r.transport.holdPost = hold
        r.transport.answer(200, renewBody(5))
        r.clock.advance(300_000)
        r.timer.fire() // the renewal is now in flight, blocked in the transport
        r.meter.set(150, 15)
        val done = CountDownLatch(1)
        r.renewer.release { done.countDown() }
        assertTrue(done.await(3, TimeUnit.SECONDS), "the release does not wait for the renewal in flight")
        val delete = r.transport.snapshot.first { it.method == "DELETE" }
        assertEquals("""{"epoch":7,"meter_scope":"tunnel","rx_bytes_delta":150,"seq":5,"tx_bytes_delta":15}""", delete.body,
            "the in-doubt report under its own seq, newer bytes added")
        hold.countDown()
        r.renewer.drainForTest()
        assertEquals("none", r.renewer.status().state, "the late renewal answer is ignored after the release")
    }

    @Test
    fun sleepJumpPastTheTtl() {
        val r = Rig()
        r.renewer.startActive(lease(seq = 3))
        r.meter.set(100, 10)
        r.transport.answer(200, renewBody(4))
        r.after(300_000)
        assertEquals(4L, r.renewer.status().seq)
        // The device sleeps 2 h (elapsedRealtime keeps counting, the executor did not fire).
        r.meter.set(900, 90)
        r.after(2 * 3_600_000)
        val sent = r.transport.snapshot
        assertEquals(2, sent.size, "one report at wake-up, never an acquire")
        assertEquals("""{"epoch":7,"meter_scope":"tunnel","rx_bytes_delta":800,"seq":5,"tx_bytes_delta":80}""", sent[1].body)
        assertEquals(0L, r.renewer.lastTimerDelayMs, "past the deadline the failed report goes out once more at once")
        assertEquals(0L, r.renewer.status().expiresInMs, "the lease looks expired on the sleep-proof clock")
        r.transport.answer(404, """{"code":"lease_gone"}""")
        r.after(0)
        assertEquals(sent[1].body, r.transport.snapshot[2].body, "same report")
        assertEquals("lease_gone", r.renewer.status().code, "the server freed the seat while asleep: terminal, reported only")
    }

    @Test
    fun pendingHandOverAndScope() {
        val r = Rig()
        r.renewer.startPending()
        var st = r.renewer.status()
        assertTrue(st.state == "pending" && st.renewedMsAgo == -1L, "pending status")
        r.renewer.drainForTest()
        assertEquals("pending", r.statuses.all.last().state, "pending reported")
        assertFalse(r.timer.armed, "nothing to send while pending")
        r.meter.set(10_000, 1_000)
        r.clock.advance(20_000)
        st = r.renewer.handOver(lease(seq = 0, scope = UpstreamMeterScope.PROXY))
        assertEquals("active", st.state, "handed over")
        assertEquals(UpstreamMeterScope.TUNNEL, st.meterScope, "proxy without meter_tags / a per-outbound meter -> tunnel")
        st = r.renewer.handOver(lease(seq = 40))
        assertEquals(0L, st.seq, "a second hand-over is ignored")
        r.transport.answer(200, renewBody(1))
        r.after(300_000)
        assertEquals("""{"epoch":7,"meter_scope":"tunnel","rx_bytes_delta":10000,"seq":1,"tx_bytes_delta":1000}""",
            r.transport.snapshot.first().body, "first report has the bytes since tunnel start")
        r.renewer.stop()
        // A per-outbound meter (the later lane-A0 source) with tags: scope proxy, the meter asked with the tags.
        val p = Rig(scope = true)
        p.renewer.startActive(lease(seq = 0, scope = UpstreamMeterScope.PROXY, tags = listOf("proxy")))
        assertEquals(UpstreamMeterScope.PROXY, p.renewer.status().meterScope)
        p.transport.answer(200, renewBody(1))
        p.after(300_000)
        assertEquals("""{"epoch":7,"meter_scope":"proxy","rx_bytes_delta":777,"seq":1,"tx_bytes_delta":33}""", p.transport.snapshot.last().body)
        assertTrue(synchronized(p.meter.calls) { p.meter.calls.all { it == UpstreamMeterScope.PROXY to listOf("proxy") } }, "proxy read over meter_tags")
        p.renewer.stop()
    }

    @Test
    fun sessionEntryClass() {
        val meter = FakeMeter()
        assertNull(UpstreamLeaseSession.fromEnvelope(JSONObject().put("protocol", "xray"), meter, {}), "own Xray: no session")
        assertNull(UpstreamLeaseSession.fromEnvelope(JSONObject().put("tribeSessionMetadata", JSONObject().put("proto", "awg")), meter, {}),
            "AWG: no session")
        val bad = assertFailsWith<UpstreamEnvelopeException> {
            UpstreamLeaseSession.fromEnvelope(JSONObject()
                .put("tribeSessionMetadata", JSONObject().put("upstream", 1).put("profile_id", "p"))
                .put("upstream_lease", JSONObject().put("lease_id", "short")), meter, {})
        }
        assertEquals("lease_id", bad.why, "a malformed lease fails the start, by field name")
        assertEquals("profile_id", assertFailsWith<UpstreamEnvelopeException> {
            UpstreamLeaseSession.fromEnvelope(JSONObject().put("tribeSessionMetadata", JSONObject().put("upstream", 1)), meter, {})
        }.why)
        UpstreamLeaseSession.fromEnvelope(JSONObject().put("tribeSessionMetadata", JSONObject().put("upstream", 1).put("profile_id", "p")),
            meter, {})?.close() ?: error("pending session expected")

        val transport = FakeTransport()
        val clock = TestClock()
        val timer = ManualScheduler()
        val seen = mutableListOf<JSONObject>()
        val session = UpstreamLeaseSession("p", null, meter, { synchronized(seen) { seen += it } }, transport = transport,
            nowMs = { clock.now }, scheduler = timer)
        session.start()
        assertEquals("pending", session.status().getString("state"))
        val wire = JSONObject().put("lease_id", K_LEASE).put("renew_token", "tlr1.TOKEN").put("api_base", "https://t.example.net/")
            .put("renew_after_s", 300).put("ttl_s", 900).put("expires_in_ms", 899_000).put("seq", 2).put("epoch", 7)
            .put("revision", 100).put("meter_scope", "tunnel")
        assertEquals("pending", session.onLeaseSet(JSONObject().put("lease_id", "x")).getString("state"), "a malformed hand-over changes nothing")
        val after = session.onLeaseSet(wire)
        assertTrue(after.getString("state") == "active" && after.getLong("seq") == 2L && after.getLong("expires_in_ms") == 899_000L,
            "handed over: $after")
        session.renewerForTest.drainForTest()
        assertTrue(synchronized(seen) { seen.map { it.getString("state") } }.containsAll(listOf("pending", "active")), "statuses delivered as JSON")
        session.releaseBlocking()
        assertEquals("DELETE", transport.snapshot.single().method, "user disconnect releases once")
        assertFalse(session.isTerminal)
    }

    @Test
    fun statusPushedOnlyWhenSomethingTheEngineActsOnChanged() {
        val r = Rig()
        r.renewer.startActive(lease(seq = 5))
        r.renewer.drainForTest()
        assertEquals(listOf("active"), r.statuses.all.map { it.state }, "one push on adopt")
        r.after(300_000) // transport failure: nothing the engine acts on changed
        r.after(15_000)
        assertEquals(1, r.statuses.all.size, "no push on failures or ticks")
        r.transport.answer(200, renewBody(6))
        r.after(30_000)
        assertEquals(listOf(5L, 6L), r.statuses.all.map { it.seq }, "a push when seq moved")
        r.transport.answer(200, renewBody(7).replace("\"config_changed\":false", "\"config_changed\":true"))
        r.after(300_000)
        assertTrue(r.statuses.all.last().configChanged && r.statuses.all.size == 3, "a push when config_changed flipped")
    }

    @Test
    fun ipcPayloadsOfTheP1Contract() {
        val transport = FakeTransport()
        val clock = TestClock()
        val session = UpstreamLeaseSession("p", null, FakeMeter(), {}, transport = transport, nowMs = { clock.now },
            scheduler = ManualScheduler())
        // android-ipc-contract.md section 2: the iOS provider message verbatim, before start() too.
        val bad = JSONObject(session.onLeaseSetMessage("""{"action":"something_else"}"""))
        assertEquals(setOf("upstream"), bad.keySet(), "reply = {upstream: status}")
        assertEquals("pending", bad.getJSONObject("upstream").getString("state"), "a malformed message keeps pending")
        assertEquals("pending", JSONObject(session.onLeaseSetMessage("not json")).getJSONObject("upstream").getString("state"))
        val message = """{"action":"upstream_lease_set","upstream_lease":{"lease_id":"$K_LEASE","renew_token":"tlr1.TOKEN","api_base":"https://t.example.net","renew_after_s":300,"ttl_s":900,"expires_in_ms":900000,"seq":1,"epoch":7,"revision":1763123456789,"meter_scope":"tunnel","meter_tags":["proxy"]}}"""
        val reply = JSONObject(session.onLeaseSetMessage(message)).getJSONObject("upstream")
        assertEquals(setOf("state", "code", "seq", "renewed_ms_ago", "expires_in_ms", "revision", "config_changed",
            "applied_bytes", "shadow_bytes", "meter_scope"), reply.keySet(), "contract section 5 keys")
        assertTrue(reply.getString("state") == "active" && reply.getLong("seq") == 1L && reply.getLong("revision") == 1_763_123_456_789L &&
            reply.getString("meter_scope") == "tunnel" && reply.get("seq") is Number && reply.get("config_changed") is Boolean,
            "handed over, integers as numbers: $reply")
        assertEquals(reply.toString(), JSONObject(session.statusEvent()).getJSONObject("upstream").toString(), "pull = the same object")
        session.close()
    }

    // A minimal HTTP/1.1 server on a raw ServerSocket (android.jar on the unit-test compile classpath has no
    // com.sun.net.httpserver): one request per connection, Content-Length bodies, Connection: close.
    private class TinyHttpServer(private val handler: (Req) -> Resp) : AutoCloseable {
        data class Req(val method: String, val path: String, val headers: Map<String, String>, val body: String)
        class Resp(val status: Int, val headers: Map<String, String> = emptyMap(), val body: String = "", val delayMs: Long = 0)

        private val socket = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
        private val pool = Executors.newCachedThreadPool()
        val port: Int get() = socket.localPort

        init {
            thread(isDaemon = true, name = "tiny-http-accept") {
                while (!socket.isClosed) {
                    val c = try { socket.accept() } catch (e: Exception) { break }
                    pool.execute { runCatching { serve(c) } }
                }
            }
        }

        private fun readLine(input: BufferedInputStream): String? {
            val out = ByteArrayOutputStream()
            while (true) {
                val b = input.read()
                if (b < 0) return if (out.size() == 0) null else out.toString("ISO-8859-1")
                if (b == '\n'.code) return out.toString("ISO-8859-1").trimEnd('\r')
                out.write(b)
            }
        }

        private fun serve(c: Socket) {
            c.use { serveOn(c) }
        }

        private fun serveOn(c: Socket) {
            val input = BufferedInputStream(c.getInputStream())
            val parts = (readLine(input) ?: return).split(" ")
            val headers = mutableMapOf<String, String>()
            while (true) {
                val line = readLine(input) ?: break
                if (line.isEmpty()) break
                val i = line.indexOf(':')
                if (i > 0) headers[line.substring(0, i).trim().lowercase()] = line.substring(i + 1).trim()
            }
            val len = headers["content-length"]?.toInt() ?: 0
            val body = ByteArray(len)
            var read = 0
            while (read < len) {
                val n = input.read(body, read, len - read)
                if (n < 0) break
                read += n
            }
            val resp = handler(Req(parts[0], parts[1], headers, String(body, 0, read, Charsets.UTF_8)))
            if (resp.delayMs > 0) Thread.sleep(resp.delayMs)
            val out = resp.body.toByteArray()
            val head = StringBuilder("HTTP/1.1 ${resp.status} X\r\n")
            for ((k, v) in resp.headers) head.append("$k: $v\r\n")
            head.append("Content-Length: ${out.size}\r\nConnection: close\r\n\r\n")
            c.getOutputStream().apply {
                write(head.toString().toByteArray(Charsets.ISO_8859_1))
                write(out)
                flush()
            }
        }

        override fun close() {
            socket.close()
            pool.shutdownNow()
        }
    }

    @Test
    fun httpsTransportAgainstALocalServer() {
        val seen = mutableListOf<TinyHttpServer.Req>()
        TinyHttpServer { req ->
            synchronized(seen) { seen += req }
            when {
                req.path.endsWith("/renew") -> TinyHttpServer.Resp(200, mapOf("X-Tribe-Api" to "1"), renewBody(6))
                req.path == "/gone" -> TinyHttpServer.Resp(404, body = """{"code":"lease_gone"}""")
                req.path == "/slow" -> TinyHttpServer.Resp(204, delayMs = 3_000)
                req.path == "/redirect" -> TinyHttpServer.Resp(302, mapOf("Location" to "/other"))
                else -> TinyHttpServer.Resp(204)
            }
        }.use { server ->
            val base = "http://127.0.0.1:${server.port}"
            val t = HttpsUpstreamTransport()
            val headers = mapOf("Authorization" to "Bearer tlr1.T", "Content-Type" to "application/json")
            val ok = t.send("POST", "$base/v1/upstream/lease/$K_LEASE/renew", headers, """{"seq":6}""", 5_000)
            assertTrue(ok.status == 200 && ok.fromTribeApi, "200 with X-Tribe-Api: $ok")
            assertEquals(UpstreamReplyKind.GRANTED, UpstreamLeaseWire.classifyRenewReply(ok.status, ok.body).kind, "body read")
            val del = t.send("DELETE", "$base/v1/upstream/lease/$K_LEASE", headers, """{"seq":7}""", 1_500)
            assertEquals(204, del.status)
            val gone = t.send("POST", "$base/gone", headers, "{}", 5_000)
            assertEquals(UpstreamErrorCode.LEASE_GONE, UpstreamLeaseWire.classifyRenewReply(gone.status, gone.body).error.code,
                "4xx body read from the error stream")
            val t0 = System.nanoTime()
            val slow = t.send("POST", "$base/slow", headers, "{}", 500)
            val ms = (System.nanoTime() - t0) / 1_000_000
            assertTrue(slow.status == 0 && slow.errorCode == "timeout" && ms < 1_500, "bounded: $slow in $ms ms")
            val redirect = t.send("POST", "$base/redirect", headers, "{}", 5_000)
            assertEquals(302, redirect.status, "redirects are never followed")
            val closedPort = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { it.localPort }
            val refused = t.send("POST", "http://127.0.0.1:$closedPort/x", headers, "{}", 2_000)
            assertTrue(refused.status == 0 && refused.errorCode.isNotEmpty(), "no server: transport failure $refused")
            val got = synchronized(seen) { seen.toList() }
            val post = got.first { it.path.endsWith("/renew") }
            assertTrue(post.method == "POST" && post.headers["authorization"] == "Bearer tlr1.T" &&
                post.headers["content-type"] == "application/json" && post.body == """{"seq":6}""", "request as sent: $post")
            val delete = got.first { it.method == "DELETE" }
            assertEquals("""{"seq":7}""", delete.body, "DELETE carries the final report")
            assertNotNull(got.firstOrNull { it.path == "/redirect" })
            assertTrue(got.none { it.path == "/other" }, "redirect target never requested")
        }
    }
}
