package org.amnezia.vpn.protocol.xray.runtime

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertSame
import kotlin.test.assertTrue
import org.amnezia.vpn.protocol.xray.UpstreamAppSplit
import org.amnezia.vpn.protocol.xray.UpstreamStatusChange
import org.amnezia.vpn.protocol.xray.XrayTunnelCounters
import org.amnezia.vpn.protocol.xray.XrayTunnelCounters.Bytes
import org.json.JSONArray
import org.json.JSONObject

// AVPN: the pure parts of the Xray service runtime - tunnel byte counters (decisions A-4, A-5), the
// UPSTREAM_STATUS change rule (android-ipc-contract.md section 3) and the own-package app-split rule of an
// upstream session (decision A-3).
class XrayRuntimeHelpersTest {

    // ---- counters ----

    @Test
    fun interfaceCountersStartAtZeroAndAccumulate() {
        val c = XrayTunnelCounters()
        c.reset(XrayTunnelCounters.Source.INTERFACE)
        assertEquals(Bytes(0, 0), c.totals())
        assertEquals(Bytes(1000, 200), c.record(Bytes(1000, 200)), "tun counters count from establish()")
        assertEquals(Bytes(1500, 260), c.record(Bytes(1500, 260)))
        assertEquals(Bytes(1500, 260), c.record(Bytes(-1, -1)), "UNSUPPORTED changes nothing")
        assertEquals(Bytes(1500, 260), c.record(null))
        assertEquals(Bytes(1600, 300), c.record(Bytes(1600, 300)))
    }

    @Test
    fun uidCountersBaselineOnTheFirstSample() {
        val c = XrayTunnelCounters()
        c.reset(XrayTunnelCounters.Source.UID)
        assertEquals(Bytes(0, 0), c.record(Bytes(9_000_000, 4_000_000)), "since-boot counters: first read is the baseline")
        assertEquals(Bytes(500, 100), c.record(Bytes(9_000_500, 4_000_100)))
        assertEquals(Bytes(500, 100), c.record(Bytes(9_000_500, -1)), "one direction unsupported = no read")
    }

    @Test
    fun aCounterThatWentBackRestartedFromZero() {
        val c = XrayTunnelCounters()
        c.reset(XrayTunnelCounters.Source.INTERFACE)
        c.record(Bytes(1000, 1000))
        assertEquals(Bytes(1300, 1050), c.record(Bytes(300, 50)), "never a negative step (unsigned wrap in C++)")
        var last = c.totals()
        listOf(Bytes(10, 10), Bytes(5, 5), Bytes(0, 0), Bytes(7, 1)).forEach { raw ->
            val now = c.record(raw)
            assertTrue(now.rx >= last.rx && now.tx >= last.tx, "monotonic")
            last = now
        }
    }

    @Test
    fun resetStartsANewSession() {
        val c = XrayTunnelCounters()
        c.reset(XrayTunnelCounters.Source.INTERFACE)
        c.record(Bytes(5000, 5000))
        c.reset(XrayTunnelCounters.Source.INTERFACE)
        assertEquals(Bytes(0, 0), c.totals())
        assertEquals(Bytes(10, 20), c.record(Bytes(10, 20)))
    }

    // ---- UPSTREAM_STATUS change rule ----

    private fun status(state: String = "active", seq: Long = 3, renewedMsAgo: Long = 41_000, applied: Long = 10) =
        UpstreamStatusChange.none()
            .put("state", state)
            .put("seq", seq)
            .put("renewed_ms_ago", renewedMsAgo)
            .put("expires_in_ms", 859_000L)
            .put("applied_bytes", applied)

    @Test
    fun byteTicksAreNotAChange() {
        val a = UpstreamStatusChange.signature(status())
        assertEquals(a, UpstreamStatusChange.signature(status(renewedMsAgo = 1, applied = 99_999)))
        assertNotEquals(a, UpstreamStatusChange.signature(status(seq = 4)), "seq")
        assertNotEquals(a, UpstreamStatusChange.signature(status(state = "terminal")), "state")
        assertNotEquals(a, UpstreamStatusChange.signature(status().put("code", "over_quota")), "code")
        assertNotEquals(a, UpstreamStatusChange.signature(status().put("revision", 7L)), "revision")
        assertNotEquals(a, UpstreamStatusChange.signature(status().put("config_changed", true)), "config_changed")
        assertNotEquals(a, UpstreamStatusChange.signature(status().put("meter_scope", "proxy")), "meter_scope")
    }

    @Test
    fun noneIsTheContractObject() {
        val none = UpstreamStatusChange.none()
        assertEquals(
            setOf("state", "code", "seq", "renewed_ms_ago", "expires_in_ms", "revision", "config_changed",
                "applied_bytes", "shadow_bytes", "meter_scope"),
            none.keySet()
        )
        assertEquals("none", none.getString("state"))
        assertEquals(-1L, none.getLong("renewed_ms_ago"))
        assertEquals("tunnel", none.getString("meter_scope"))
        assertTrue(none.get("seq") is Number && none.get("config_changed") is Boolean, "plain JSON types, never strings")
    }

    // ---- own package in the tunnel ----

    private fun envelope(type: Int, vararg apps: String) =
        JSONObject().put("appSplitTunnelType", type).put("splitTunnelApps", JSONArray(apps.toList()))

    private fun apps(config: JSONObject) =
        config.getJSONArray("splitTunnelApps").let { a -> (0 until a.length()).map { a.getString(it) } }

    @Test
    fun includeListGetsTheOwnPackage() {
        val config = envelope(1, "org.telegram.messenger")
        val out = UpstreamAppSplit.withOwnPackageInTunnel(config, "com.tribevpn.client")
        assertEquals(listOf("org.telegram.messenger", "com.tribevpn.client"), apps(out))
        assertEquals(listOf("org.telegram.messenger"), apps(config), "the envelope itself is not changed")
        val already = envelope(1, "com.tribevpn.client")
        assertSame(already, UpstreamAppSplit.withOwnPackageInTunnel(already, "com.tribevpn.client"))
    }

    @Test
    fun excludeListLosesTheOwnPackage() {
        val config = envelope(2, "com.tribevpn.client", "ru.sberbankmobile")
        assertEquals(listOf("ru.sberbankmobile"), apps(UpstreamAppSplit.withOwnPackageInTunnel(config, "com.tribevpn.client")))
        val other = envelope(2, "ru.sberbankmobile")
        assertSame(other, UpstreamAppSplit.withOwnPackageInTunnel(other, "com.tribevpn.client"))
    }

    @Test
    fun noAppSplitIsUntouched() {
        val all = envelope(0)
        assertSame(all, UpstreamAppSplit.withOwnPackageInTunnel(all, "com.tribevpn.client"))
        val noKeys = JSONObject().put("hostName", "192.0.2.1")
        assertSame(noKeys, UpstreamAppSplit.withOwnPackageInTunnel(noKeys, "com.tribevpn.client"))
    }
}
