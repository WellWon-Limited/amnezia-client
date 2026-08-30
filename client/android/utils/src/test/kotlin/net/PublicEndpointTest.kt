package org.amnezia.vpn.util.net

import java.net.InetAddress
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PublicEndpointTest {
    @Test
    fun acceptsCanonicalPublicUnicast() {
        assertTrue(InetAddress.getByName("8.8.8.8").isPublicUnicastEndpoint())
        assertTrue(InetAddress.getByName("2606:4700:4700::1111").isPublicUnicastEndpoint())
    }

    @Test
    fun rejectsLocalPrivateReservedAndDocumentationRanges() {
        listOf(
            "0.0.0.0", "10.0.0.1", "100.64.0.1", "127.0.0.1",
            "169.254.1.1", "172.16.0.1", "192.0.2.1", "192.168.1.1",
            "198.18.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1",
            "::", "::1", "fc00::1", "fe80::1", "ff02::1", "2001:db8::1",
        ).forEach { address ->
            assertFalse(
                InetAddress.getByName(address).isPublicUnicastEndpoint(),
                "reserved endpoint accepted: $address",
            )
        }
    }

    @Test
    fun protectedRouteParserNeverResolvesHostnamesOrPrivateAddresses() {
        assertNotNull(parsePublicEndpointLiteral("8.8.8.8"))
        assertNotNull(parsePublicEndpointLiteral("2606:4700:4700::1111"))
        listOf("localhost", "example.com", "127.0.0.1", "10.0.0.1", "::1", "fc00::1",
            " 8.8.8.8", "8.8.8.8 ", "01.1.1.1", "8.8.8.08",
            "2606:4700:4700:0:0:0:0:1111", "2606:4700:4700::ABCD")
            .forEach { assertNull(parsePublicEndpointLiteral(it), it) }
    }
}
