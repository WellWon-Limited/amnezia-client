package org.amnezia.vpn

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class NativeDispatchPolicyDigestTest {
    @Test
    fun cxxAwgGoldenVectorIsByteIdentical() {
        val projection = NativeDispatchPolicyDigest.Projection(
            transport = "awg",
            nativeEnvelopeSchema = RuntimeAuthority.V2_ENVELOPE,
            profileId = "fi-awg",
            configGeneration = "9",
            bindingGeneration = "3",
            endpointHost = "awg-fi.example.net",
            endpointPort = "51820",
            tunnelAddress = "10.77.0.2/32",
            dns1 = "1.1.1.1",
            dns2 = "1.0.0.1",
            mtu = "1280",
            configVersion = "0",
            xrayMaxMemoryBytes = "0",
            splitTunnelType = "2",
            splitSites = listOf("5.136.0.0/13"),
            appSplitTunnelType = "2",
            splitApps = listOf("org.example.direct"),
            splitDnsSuffixes = emptyList(),
            splitDnsServer = "",
            dnsForwardOn = "1",
            dnsForwardSuffixes = "ru,xn--p1ai",
            dnsForwardServer = "77.88.8.8",
            dnsForwardWarmup = "0",
            killSwitch = "true",
            allowedDns = listOf("1.1.1.1"),
            protectedTunnelIps = listOf("1.1.1.1"),
            nativeConfigSha256 =
                "9c63ebc66087f03029727de62dc671d3b75dc1c922cf83a76b38f6028aa3aa64",
        )
        assertEquals(
            "b805559232d851644e2595c599e2b147e9a2fda83b110fd0106030c986826b9c",
            NativeDispatchPolicyDigest.sha256(projection),
        )
        val encoded = NativeDispatchPolicyDigest.encode(projection).toString(Charsets.UTF_8)
        assertTrue(encoded.startsWith(
            "tribe-native-dispatch-policy-v1\ntransport:3:awg\n" +
                "native_envelope_schema:26:tribe_catalog_v2_native_v1\n",
        ))
        assertTrue(encoded.endsWith(
            "native_config_sha256:64:" + projection.nativeConfigSha256 + "\n",
        ))
    }
}
