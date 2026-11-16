package org.amnezia.vpn.protocol.xray.runtime

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.amnezia.vpn.protocol.xray.UpstreamProxyMeterAccumulator
import org.amnezia.vpn.protocol.xray.UpstreamStatsPlan
import org.amnezia.vpn.protocol.xray.XrayOutboundStatsRead
import org.amnezia.vpn.protocol.xray.XrayOutboundTraffic
import org.amnezia.vpn.protocol.xray.XrayStatsConfig
import org.amnezia.vpn.protocol.xray.XrayTunnelCounters.Bytes
import org.amnezia.vpn.protocol.xray.upstream.UpstreamMeterPlan
import org.amnezia.vpn.protocol.xray.upstream.UpstreamMeterScope
import org.json.JSONObject

// AVPN (contract section 4): metering scope "proxy" - the Kotlin twin of the proxy-meter parts of
// client/platforms/ios/UpstreamProxyMeter.swift (stats keys merge, answer parse, per-tag accumulator), plus
// which scope a session ends up with on Android.
class XrayProxyMeterTest {

    // ---- stats keys ----

    @Test
    fun mergeKeepsTheProvidersPolicy() {
        val config = JSONObject("""{"policy":{"levels":{"0":{"handshake":5}},"system":{"statsInboundUplink":true}},"outbounds":[]}""")
        assertTrue(XrayStatsConfig.merge(config))
        assertEquals(0, config.getJSONObject("stats").length(), "an empty stats object added")
        val system = config.getJSONObject("policy").getJSONObject("system")
        assertTrue(system.getBoolean("statsOutboundUplink") && system.getBoolean("statsOutboundDownlink"))
        assertTrue(system.getBoolean("statsInboundUplink"), "other system keys kept")
        assertEquals(5, config.getJSONObject("policy").getJSONObject("levels").getJSONObject("0").getInt("handshake"), "levels kept")
        val again = config.toString()
        assertTrue(XrayStatsConfig.merge(config))
        assertEquals(JSONObject(again).toString(), config.toString(), "idempotent")
    }

    @Test
    fun mergeOnAnEmptyConfigAndExistingStats() {
        val empty = JSONObject("""{"outbounds":[]}""")
        assertTrue(XrayStatsConfig.merge(empty))
        assertTrue(empty.getJSONObject("policy").getJSONObject("system").getBoolean("statsOutboundDownlink"))
        val withStats = JSONObject("""{"stats":{"x":1}}""")
        assertTrue(XrayStatsConfig.merge(withStats))
        assertEquals(1, withStats.getJSONObject("stats").getInt("x"), "an existing stats object stays as it is")
    }

    @Test
    fun aNonObjectPolicyIsLeftAlone() {
        listOf("""{"policy":"x"}""", """{"policy":{"system":[1]}}""", """{"stats":true}""").forEach { raw ->
            val config = JSONObject(raw)
            assertFalse(XrayStatsConfig.merge(config), raw)
            assertEquals(JSONObject(raw).toString(), config.toString(), "untouched: $raw")
        }
    }

    // ---- answers ----

    @Test
    fun parsesTheAnswer() {
        val read = XrayOutboundStatsRead.parse(
            """{"running":true,"outbounds":{"proxy":{"uplink":100,"downlink":2000},"direct":{"uplink":5,"downlink":6},""" +
                """"bad":{"uplink":-1,"downlink":"7"}},"error":"","error_code":""}"""
        )
        assertTrue(read.usable)
        assertEquals(XrayOutboundTraffic(100, 2000), read.outbounds["proxy"])
        assertEquals(XrayOutboundTraffic(0, 0), read.outbounds["bad"], "a negative or non-number counter reads as 0")
        assertFalse(XrayOutboundStatsRead.parse("""{"running":true,"outbounds":{},"error":"x","error_code":"stats_disabled"}""").usable)
        assertFalse(XrayOutboundStatsRead.parse("""{"running":false,"outbounds":{}}""").usable, "no core in this process")
        assertEquals("bad_answer", XrayOutboundStatsRead.parse("not json").errorCode)
        assertEquals("bad_answer", XrayOutboundStatsRead.parse(null).errorCode)
    }

    // ---- accumulator ----

    private fun read(vararg tags: Pair<String, Pair<Long, Long>>) = XrayOutboundStatsRead(
        running = true,
        outbounds = tags.associate { (tag, c) -> tag to XrayOutboundTraffic(uplink = c.first, downlink = c.second) },
    )

    @Test
    fun sumsOnlyTheMeterTags() {
        val m = UpstreamProxyMeterAccumulator()
        m.record(read("proxy" to (100L to 2000L), "hop" to (100L to 2000L), "direct" to (9L to 9L)))
        assertEquals(Bytes(2000, 100), m.totals(listOf("proxy")), "rx = downlink, tx = uplink; dialer hop not billed")
        assertEquals(Bytes(2000, 100), m.totals(listOf("proxy", "proxy")), "a tag counts once")
        assertEquals(Bytes(0, 0), m.totals(emptyList()))
    }

    @Test
    fun totalsOnlyGrowOverCoreInstances() {
        val m = UpstreamProxyMeterAccumulator()
        m.record(read("proxy" to (10L to 100L)))
        m.coreWillStop(read("proxy" to (20L to 200L)))
        assertEquals(Bytes(200, 20), m.totals(listOf("proxy")))
        m.record(read("proxy" to (1L to 5L)))
        assertEquals(Bytes(205, 21), m.totals(listOf("proxy")), "the next instance counts from zero on top")
        m.record(read("proxy" to (0L to 1L)))
        assertEquals(Bytes(206, 21), m.totals(listOf("proxy")), "a restart without a stop read keeps what was counted")
        m.record(XrayOutboundStatsRead(running = false))
        assertEquals(Bytes(206, 21), m.totals(listOf("proxy")), "a failed read changes nothing")
        m.reset()
        assertEquals(Bytes(0, 0), m.totals(listOf("proxy")), "a new session")
    }

    // ---- which scope a session meters ----

    @Test
    fun statsKeysOnlyWhereProxyMayBeMetered() {
        assertTrue(UpstreamStatsPlan.wantsStats(JSONObject("""{"tribeSessionMetadata":{"upstream":1}}""")), "provisional start")
        assertTrue(UpstreamStatsPlan.wantsStats(JSONObject("""{"upstream_lease":{"meter_scope":"proxy","meter_tags":["proxy"]}}""")))
        assertFalse(UpstreamStatsPlan.wantsStats(JSONObject("""{"upstream_lease":{"meter_scope":"tunnel","meter_tags":["proxy"]}}""")),
            "Android's C++ asks for tunnel today")
        assertFalse(UpstreamStatsPlan.wantsStats(JSONObject("""{"upstream_lease":{"meter_scope":"proxy","meter_tags":[]}}""")))
    }

    @Test
    fun scopeFollowsTheEnvelope() {
        assertEquals(UpstreamMeterScope.TUNNEL, UpstreamMeterPlan.scope(UpstreamMeterScope.TUNNEL, listOf("proxy"), proxyAvailable = true),
            "never upgraded to proxy on the service's own")
        assertEquals(UpstreamMeterScope.PROXY, UpstreamMeterPlan.scope(UpstreamMeterScope.PROXY, listOf("proxy"), proxyAvailable = true))
        assertEquals(UpstreamMeterScope.TUNNEL, UpstreamMeterPlan.scope(UpstreamMeterScope.PROXY, listOf("proxy"), proxyAvailable = false),
            "no counters: tunnel")
    }
}
