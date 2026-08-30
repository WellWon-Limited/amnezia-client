package org.amnezia.vpn

import kotlin.test.Test
import kotlin.test.assertEquals

class VaultPrivacyContractTest {
    @Test
    fun vpnProfileAadKeepsDomainPackageAndExactRecordBinding() {
        assertEquals(
            listOf(
                "tribe-vpn-profile-v2",
                "com.tribevpn.client",
                "recovery",
                "active",
                "generation-7",
                "dispatch-sha256",
                "tunnel-sha256",
            ),
            AndroidVpnConfigVault.aadComponents(
                packageName = "com.tribevpn.client",
                purpose = "recovery",
                recordId = "active",
                sessionGeneration = "generation-7",
                dispatchPolicySha256 = "dispatch-sha256",
                tunnelPolicySha256 = "tunnel-sha256",
            ),
        )
    }

    @Test
    fun catalogMetadataAadKeepsDomainPackageAndFixedRecordBinding() {
        assertEquals(
            listOf(
                "tribe-catalog-secure-metadata-v2",
                "com.tribevpn.client",
                "metadata.v2",
            ),
            CatalogSecureMetadataVault.aadComponents("com.tribevpn.client"),
        )
    }
}
