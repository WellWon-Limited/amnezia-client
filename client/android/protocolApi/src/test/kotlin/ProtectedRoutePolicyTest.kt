package org.amnezia.vpn.protocol

import org.amnezia.vpn.util.net.InetNetwork
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class ProtectedRoutePolicyTest {
    private val protectedV4 = InetNetwork("1.1.1.1", 32)
    private val protectedV6 = InetNetwork("2606:4700:4700::1111", 128)
    private val input = setOf(
        Route(InetNetwork("0.0.0.0", 0), true),
        Route(InetNetwork("::", 0), true),
        Route(InetNetwork("1.0.0.0", 8), false),
        Route(InetNetwork("2606:4700::", 32), false),
    )

    @Test
    fun preAndroid13ReincludesProtectedHostsAfterSubnetSubtraction() {
        val result = processRoutesForPlatform(
            input, setOf(protectedV4, protectedV6), strictIpv6Capture = true, sdkInt = 32)
        assertTrue(result.contains(Route(protectedV4, true)))
        assertTrue(result.contains(Route(protectedV6, true)))
        assertTrue(result.none { !it.include }, "pre-33 route set must contain only includes")
    }

    @Test
    fun android13UsesMoreSpecificProtectedIncludes() {
        val result = processRoutesForPlatform(
            input, setOf(protectedV4, protectedV6), strictIpv6Capture = true, sdkInt = 33)
        assertTrue(result.contains(Route(InetNetwork("1.0.0.0", 8), false)))
        assertTrue(result.contains(Route(InetNetwork("2606:4700::", 32), false)))
        assertTrue(result.contains(Route(protectedV4, true)))
        assertTrue(result.contains(Route(protectedV6, true)))
    }

    @Test
    fun catalogProtectedIpsAreRequiredCanonicalPublicLiterals() {
        assertEquals(
            setOf(protectedV4, protectedV6),
            protectedTunnelRoutesForEnvelope(
                "tribe_catalog_v2_native_v1",
                listOf("1.1.1.1", "2606:4700:4700::1111"),
            ),
        )
        listOf<List<Any?>?>(
            null, emptyList(), listOf("localhost"), listOf("10.0.0.1"),
            listOf("01.1.1.1"), listOf("2606:4700:4700::ABCD"), listOf(7),
        ).forEach { values ->
            assertFailsWith<BadConfigException> {
                protectedTunnelRoutesForEnvelope("tribe_catalog_v2_native_v1", values)
            }
        }
        assertEquals(
            emptySet(),
            protectedTunnelRoutesForEnvelope("amnezia_legacy_native_v1", null),
        )
    }
}
