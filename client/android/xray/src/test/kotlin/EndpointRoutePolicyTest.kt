package org.amnezia.vpn.protocol.xray

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class EndpointRoutePolicyTest {
    @Test
    fun catalogV2UsesExactSocketProtectionWithoutBroadWanExclusion() {
        assertFalse(requiresEndpointRouteExclusion("tribe_catalog_v2_native_v1"))
        assertTrue(requiresEndpointRouteExclusion("amnezia_legacy_native_v1"))
        assertTrue(requiresEndpointRouteExclusion(""))
    }
}
