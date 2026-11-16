package org.amnezia.vpn.protocol.xray.upstream

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.json.JSONArray
import org.json.JSONObject

// AVPN upstream nodes (lane A2): wire and envelope cases of the Swift twin (testWire, testEnvelope,
// testMeterTagsEnvelope) plus the Kotlin-only pieces (byte meter, scope plan).
class UpstreamLeaseWireTest {

    @Test
    fun meterBodyAndRenewClassification() {
        assertEquals("""{"epoch":7,"meter_scope":"tunnel","rx_bytes_delta":10,"seq":6,"tx_bytes_delta":2}""",
            UpstreamLeaseWire.meterBody(UpstreamMeterReport(6, 10, 2, UpstreamMeterScope.TUNNEL, 7)))
        assertEquals("""{"epoch":0,"meter_scope":"proxy","rx_bytes_delta":0,"seq":1,"tx_bytes_delta":1099511627776}""",
            UpstreamLeaseWire.meterBody(UpstreamMeterReport(1, -5, Long.MAX_VALUE, UpstreamMeterScope.PROXY, 0)),
            "meter body clamps, epoch always sent (lab D2)")
        val bad = UpstreamLeaseWire.classifyRenewReply(422, """{"code":"invalid_request"}""".toByteArray())
        assertTrue(bad.kind == UpstreamReplyKind.REFUSED && bad.error.code == UpstreamErrorCode.INVALID_REQUEST &&
            !bad.error.code.isTerminal, "422 invalid_request")
        assertTrue(UpstreamLeaseWire.renewRejected(bad), "invalid_request rejected")
        assertTrue(UpstreamLeaseWire.renewRejected(UpstreamLeaseWire.classifyRenewReply(422, "{}".toByteArray())), "bare 422 rejected")
        assertFalse(UpstreamLeaseWire.renewRejected(UpstreamLeaseWire.classifyRenewReply(0, ByteArray(0))), "transport not rejected")
        assertFalse(UpstreamLeaseWire.renewRejected(UpstreamLeaseWire.classifyRenewReply(400, "{}".toByteArray())), "400 not rejected")
        assertEquals(UpstreamErrorCode.LEASE_GONE,
            UpstreamLeaseWire.classifyRenewReply(404, """{"code":"lease_gone","reason":"seat_taken"}""".toByteArray()).error.code)
        assertEquals("seat_taken",
            UpstreamLeaseWire.parseError("""{"code":"lease_gone","reason":"seat_taken"}""".toByteArray()).reason, "reason kept for the log")
        assertEquals("", UpstreamLeaseWire.parseError("""{"code":"lease_gone","reason":"Bad Reason"}""".toByteArray()).reason)
        assertEquals("http_403", UpstreamLeaseWire.classifyRenewReply(403, "<html>blocked</html>".toByteArray()).why,
            "a block page is never terminal")
    }

    @Test
    fun timesAndBases() {
        assertEquals(1_763_118_200_000L, UpstreamLeaseWire.parseTimeMs("2025-11-14T11:03:20.000Z"), "iso time")
        assertEquals(1_763_118_200_000L, UpstreamLeaseWire.parseTimeMs("2025-11-14T14:03:20+03:00"), "iso offset")
        assertEquals(1_763_118_200_123L, UpstreamLeaseWire.parseTimeMs("2025-11-14T11:03:20.1234Z"), "fraction: first 3 digits")
        assertEquals(1_763_118_180_000L, UpstreamLeaseWire.parseTimeMs("2025-11-14T11:03Z"), "seconds optional")
        assertEquals(951_782_400_000L, UpstreamLeaseWire.parseTimeMs("2000-02-29T00:00:00Z"), "leap day")
        assertNull(UpstreamLeaseWire.parseTimeMs("2025-02-29T00:00:00Z"), "no 29 Feb in 2025")
        assertNull(UpstreamLeaseWire.parseTimeMs("garbage"), "bad time")
        assertNull(UpstreamLeaseWire.parseTimeMs(12345), "not a string")
        assertEquals("https://t.example.net", UpstreamLeaseWire.apiBaseNormalized("https://t.example.net/"), "base trailing slash")
        assertEquals("https://t.example.net/api", UpstreamLeaseWire.apiBaseNormalized("https://t.example.net/api//"))
        assertTrue(UpstreamLeaseWire.apiBaseNormalized("http://t.example.net").isEmpty(), "base http refused")
        assertTrue(UpstreamLeaseWire.apiBaseNormalized("https://u:p@t.example.net").isEmpty(), "base userinfo refused")
        assertTrue(UpstreamLeaseWire.apiBaseNormalized("https://t.example.net/?q=1").isEmpty(), "base query refused")
        assertTrue(UpstreamLeaseWire.apiBaseNormalized("https://t.example.net/#f").isEmpty(), "base fragment refused")
        assertTrue(UpstreamLeaseWire.apiBaseNormalized("https:///path").isEmpty(), "base without host refused")
    }

    private fun envelope() = JSONObject()
        .put("lease_id", K_LEASE).put("renew_token", "tlr1.AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-abcde")
        .put("api_base", "https://t.example.net/").put("renew_after_s", 300).put("ttl_s", 900)
        .put("expires_in_ms", 900_000).put("seq", 1).put("epoch", 7).put("revision", 1_763_123_456_789L)
        .put("meter_scope", "tunnel")

    private fun refusedField(key: String, value: Any?): String {
        val d = envelope()
        if (value == null) d.remove(key) else d.put(key, value)
        return UpstreamLeaseWire.parseLeaseEnvelope(d).second
    }

    @Test
    fun startEnvelope() {
        val (ok, why) = UpstreamLeaseWire.parseLeaseEnvelope(envelope())
        assertTrue(ok != null && why.isEmpty(), "valid envelope ($why)")
        assertTrue(ok!!.apiBase == "https://t.example.net" && ok.revision == 1_763_123_456_789L &&
            ok.meterScope == UpstreamMeterScope.TUNNEL, "envelope fields")
        assertEquals("renew_token", refusedField("renew_token", null), "token required")
        assertEquals("renew_token", refusedField("renew_token", "tlr1.has space"), "token charset")
        assertEquals("api_base", refusedField("api_base", "http://x"), "https only")
        assertEquals("lease_id", refusedField("lease_id", "short"), "lease id")
        assertEquals("seq", refusedField("seq", true), "bool is not a number")
        assertEquals("seq", refusedField("seq", 1.5), "fraction refused")
        assertEquals("seq", refusedField("seq", "1"), "string is not a number")
        assertEquals("epoch", refusedField("epoch", 0), "epoch >= 1")
        assertEquals("meter_scope", refusedField("meter_scope", "bytes"), "scope enum")
        assertEquals("ttl_s", refusedField("ttl_s", 0), "ttl >= 1")
        assertEquals(UpstreamMeterScope.TUNNEL, UpstreamLeaseWire.parseLeaseEnvelope(envelope().apply { remove("meter_scope") }).first?.meterScope,
            "absent scope = tunnel")
        assertEquals(UpstreamMeterScope.TUNNEL, UpstreamLeaseWire.parseLeaseEnvelope(envelope().put("meter_scope", JSONObject.NULL)).first?.meterScope,
            "null scope = tunnel")
        assertEquals("not_object", UpstreamLeaseWire.parseLeaseEnvelope("x").second, "not an object")
        // Exact on the wire as the C++ app writes it (QJsonDocument compact, doubles for integers).
        val fromCpp = JSONObject("""{"api_base":"https://t.example.net","epoch":7,"expires_in_ms":899000,"lease_id":"$K_LEASE","meter_scope":"tunnel","renew_after_s":300,"renew_token":"tlr1.x","revision":1763123456789,"seq":1,"ttl_s":900}""")
        assertEquals(899_000L, UpstreamLeaseWire.parseLeaseEnvelope(fromCpp).first?.expiresInMs)
    }

    @Test
    fun meterTagsEnvelope() {
        val d = envelope().put("meter_scope", "proxy").put("meter_tags", JSONArray(listOf("proxy", "proxy-b", "proxy")))
        val (e, why) = UpstreamLeaseWire.parseLeaseEnvelope(d)
        assertTrue(e?.meterTags == listOf("proxy", "proxy-b") && e.meterScope == UpstreamMeterScope.PROXY, "meter_tags parsed, deduplicated ($why)")
        assertEquals("meter_tags", UpstreamLeaseWire.parseLeaseEnvelope(d.put("meter_tags", JSONArray(listOf(1)))).second, "non-string tag")
        assertEquals("meter_tags", UpstreamLeaseWire.parseLeaseEnvelope(d.put("meter_tags", JSONArray(listOf("")))).second, "empty tag")
        assertEquals("meter_tags", UpstreamLeaseWire.parseLeaseEnvelope(d.put("meter_tags", "proxy")).second, "not a list")
        d.remove("meter_tags")
        assertEquals(emptyList(), UpstreamLeaseWire.parseLeaseEnvelope(d).first?.meterTags, "absent = no tags")
    }

    @Test
    fun sessionMetadata() {
        assertNull(UpstreamLeaseWire.upstreamProfileId(JSONObject().put("node_id", "9").put("proto", "awg")), "AWG metadata")
        assertNull(UpstreamLeaseWire.upstreamProfileId(JSONObject().put("upstream", 0)), "upstream 0")
        assertNull(UpstreamLeaseWire.upstreamProfileId(null), "no metadata (own Xray)")
        assertEquals("3f9c2a7b1d4e8f60",
            UpstreamLeaseWire.upstreamProfileId(JSONObject().put("upstream", 1).put("profile_id", "3f9c2a7b1d4e8f60")), "upstream 1")
        assertEquals("p", UpstreamLeaseWire.upstreamProfileId(JSONObject().put("upstream", true).put("profile_id", "p")), "upstream true")
    }

    @Test
    fun scopePlanAndTunnelMeter() {
        for (requested in UpstreamMeterScope.entries) {
            for (tags in listOf(emptyList(), listOf("proxy"))) {
                for (available in listOf(false, true)) {
                    val want = if (requested == UpstreamMeterScope.PROXY && tags.isNotEmpty() && available) UpstreamMeterScope.PROXY else UpstreamMeterScope.TUNNEL
                    assertEquals(want, UpstreamMeterPlan.scope(requested, tags, available), "scope($requested, ${tags.size}, $available)")
                }
            }
        }
        var raw: UpstreamByteTotals? = UpstreamByteTotals(1000, 500)
        val uid = TunnelInterfaceMeter.forTest(UpstreamByteTotals(1000, 500)) { raw }
        assertEquals(UpstreamByteTotals(0, 0), uid.totals(UpstreamMeterScope.TUNNEL, emptyList()), "UID counters: from the baseline")
        raw = UpstreamByteTotals(4000, 800)
        assertEquals(UpstreamByteTotals(3000, 300), uid.totals(UpstreamMeterScope.TUNNEL, emptyList()))
        raw = UpstreamByteTotals(10, 20)
        assertEquals(UpstreamByteTotals(10, 20), uid.totals(UpstreamMeterScope.TUNNEL, emptyList()), "below the baseline = restarted")
        raw = null
        assertNull(uid.totals(UpstreamMeterScope.TUNNEL, emptyList()), "no read")
        assertNull(TunnelInterfaceMeter.valid(-1, 5), "TrafficStats.UNSUPPORTED")
        val iface = TunnelInterfaceMeter.forTest(null) { UpstreamByteTotals(77, 7) }
        assertEquals(UpstreamByteTotals(77, 7), iface.totals(UpstreamMeterScope.TUNNEL, emptyList()), "tun0 counters as they are")
        assertFalse(iface.proxyAvailable, "the tunnel meter never claims proxy")
    }
}
