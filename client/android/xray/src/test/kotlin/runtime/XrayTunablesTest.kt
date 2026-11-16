package org.amnezia.vpn.protocol.xray.runtime

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import org.amnezia.vpn.protocol.xray.XrayTunables
import org.json.JSONObject

// AVPN (upstream nodes, contract section 3): the Kotlin twin of testTunables() in
// client/platforms/ios/tests/UpstreamLeaseTests.swift - same inputs, same expectations - plus the
// Android "before" of the memory limit (xray_max_memory_bytes, then 50 MB).
class XrayTunablesTest {

    private fun tunablesOf(envelope: String): XrayTunables? =
        XrayTunables.fromJson(JSONObject(envelope).optJSONObject(XrayTunables.ENVELOPE_KEY))

    private val mib = 1024L * 1024L
    private val legacyDefault = 50L shl 20

    @Test
    fun absentKeyIsTheBehaviourBefore() {
        val legacy = tunablesOf("""{"config":"{}","xray_connect_timeout_ms":5000}""")
        assertNull(legacy, "old envelope: no tunables")
        assertEquals(legacyDefault, XrayTunables.goMemoryLimitBytes(legacy, 0L), "absent = 50 MB default")
        assertEquals(64 * mib, XrayTunables.goMemoryLimitBytes(legacy, 64 * mib), "absent = xray_max_memory_bytes")
        assertEquals(legacyDefault, XrayTunables.goMemoryLimitBytes(legacy, -1L), "non-positive legacy = default")
    }

    @Test
    fun emptyObjectIsTheBehaviourBefore() {
        val empty = tunablesOf("""{"config":"{}","xray_tunables":{}}""")
        assertEquals(XrayTunables(), empty)
        assertEquals(legacyDefault, XrayTunables.goMemoryLimitBytes(empty, 0L), "empty tunables = before")
        assertEquals(64 * mib, XrayTunables.goMemoryLimitBytes(empty, 64 * mib), "empty tunables keep the legacy key")
    }

    @Test
    fun fullObject() {
        val full = tunablesOf(
            """{"config":"{}","xray_tunables":{"memory_limit_mib":30,"hev_tcp_buffer_size":4096,""" +
                """"hev_max_session_count":1200,"hev_task_stack_size":24576}}"""
        )
        assertEquals(XrayTunables(30, 4096, 1200, 24576), full)
        assertEquals(30 * mib, XrayTunables.goMemoryLimitBytes(full, 0L), "30 MiB")
        assertEquals(30 * mib, XrayTunables.goMemoryLimitBytes(full, 64 * mib), "memory_limit_mib wins over the legacy key")
    }

    @Test
    fun clampedToTheIosRanges() {
        val clamped = tunablesOf(
            """{"config":"{}","xray_tunables":{"memory_limit_mib":100,"hev_tcp_buffer_size":1,""" +
                """"hev_max_session_count":1e9,"hev_task_stack_size":8}}"""
        )
        assertEquals(XrayTunables(40, 4096, 65535, 20480), clamped, "clamped")
        val low = tunablesOf("""{"config":"{}","xray_tunables":{"memory_limit_mib":5}}""")
        assertEquals(20, low?.memoryLimitMiB, "memory floor 20")
        assertEquals(20 * mib, XrayTunables.goMemoryLimitBytes(low, 0L))
        val fraction = tunablesOf("""{"config":"{}","xray_tunables":{"memory_limit_mib":25.9}}""")
        assertEquals(25, fraction?.memoryLimitMiB, "truncated like Swift Int(Double)")
    }

    @Test
    fun presentButInvalidIsTheDefault() {
        val invalid = tunablesOf(
            """{"config":"{}","xray_tunables":{"memory_limit_mib":"lots","hev_tcp_buffer_size":null}}"""
        )
        assertEquals(30, invalid?.memoryLimitMiB, "present but invalid = default 30")
        assertEquals(4096, invalid?.hevTcpBufferSize, "present but null = default")
        assertNull(invalid?.hevMaxSessionCount, "absent stays absent")
        assertNull(invalid?.hevTaskStackSize, "absent stays absent")
        val bool = tunablesOf("""{"config":"{}","xray_tunables":{"memory_limit_mib":true,"hev_max_session_count":false}}""")
        assertEquals(30, bool?.memoryLimitMiB, "a boolean is not a number")
        assertEquals(1200, bool?.hevMaxSessionCount, "a boolean is not a number")
    }

    @Test
    fun notAnObjectIsAbsent() {
        assertNull(tunablesOf("""{"config":"{}","xray_tunables":"30"}"""))
        assertNull(tunablesOf("""{"config":"{}","xray_tunables":[30]}"""))
        assertNull(tunablesOf("""{"config":"{}","xray_tunables":null}"""))
    }

    @Test
    fun parseWithoutJson() {
        val map = mapOf<String, Any?>("memory_limit_mib" to 33, "hev_task_stack_size" to null)
        val t = XrayTunables.parse(has = map::containsKey, get = map::get)
        assertEquals(XrayTunables(memoryLimitMiB = 33, hevTaskStackSize = 24576), t)
        assertEquals(40, XrayTunables.clamp(40.0, XrayTunables.MEMORY_LIMIT_RANGE), "upper bound kept")
        assertEquals(20, XrayTunables.clamp(20.0, XrayTunables.MEMORY_LIMIT_RANGE), "lower bound kept")
        val nan = mapOf<String, Any?>("memory_limit_mib" to Double.NaN, "hev_tcp_buffer_size" to Double.POSITIVE_INFINITY)
        val parsed = XrayTunables.parse(nan::containsKey, nan::get)
        assertEquals(30, parsed.memoryLimitMiB, "NaN = default")
        assertEquals(4096, parsed.hevTcpBufferSize, "infinity = default")
    }
}
