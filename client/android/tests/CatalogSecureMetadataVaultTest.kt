package org.amnezia.vpn

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class CatalogSecureMetadataVaultTest {
    private fun metadata(
        storageRevision: ULong = 7uL,
        pendingRevision: ULong = 8uL,
        pendingDigest: ByteArray = ByteArray(32) { 0x33 },
    ) = CatalogSecureMetadataVault.Metadata(
        key32 = ByteArray(32) { index -> index.toByte() },
        storageRevision = storageRevision,
        authenticatedRecordSha256 = ByteArray(32) { 0x22 },
        cleared = false,
        pendingRevision = pendingRevision,
        pendingRecordSha256 = pendingDigest,
    )

    @Test
    fun plaintextCodecRoundTripsExactRollbackState() {
        val expected = metadata()
        val encoded = CatalogSecureMetadataVault.encode(expected)
        val decoded = CatalogSecureMetadataVault.decode(encoded)

        assertContentEquals(expected.key32, decoded.key32)
        assertEquals(expected.storageRevision, decoded.storageRevision)
        assertContentEquals(
            expected.authenticatedRecordSha256,
            decoded.authenticatedRecordSha256,
        )
        assertEquals(expected.cleared, decoded.cleared)
        assertEquals(expected.pendingRevision, decoded.pendingRevision)
        assertContentEquals(expected.pendingRecordSha256, decoded.pendingRecordSha256)
    }

    @Test
    fun malformedOrTamperedRollbackStateFailsClosed() {
        assertFailsWith<IllegalArgumentException> {
            CatalogSecureMetadataVault.validate(metadata(pendingRevision = 9uL))
        }
        assertFailsWith<IllegalArgumentException> {
            CatalogSecureMetadataVault.validate(
                metadata(pendingRevision = 0uL, pendingDigest = ByteArray(32)),
            )
        }

        val encoded = CatalogSecureMetadataVault.encode(metadata())
        encoded[4] = 2
        assertFailsWith<IllegalArgumentException> {
            CatalogSecureMetadataVault.decode(encoded)
        }
    }

    @Test
    fun initialClearedStateIsTheOnlyZeroRevisionForm() {
        val initial = CatalogSecureMetadataVault.Metadata(
            key32 = ByteArray(32) { 0x44 },
            storageRevision = 0uL,
            authenticatedRecordSha256 = byteArrayOf(),
            cleared = true,
            pendingRevision = 0uL,
            pendingRecordSha256 = byteArrayOf(),
        )
        val decoded = CatalogSecureMetadataVault.decode(
            CatalogSecureMetadataVault.encode(initial),
        )
        assertTrue(initial.sameAs(decoded))

        assertFailsWith<IllegalArgumentException> {
            CatalogSecureMetadataVault.validate(initial.copy(cleared = false))
        }
    }
}
