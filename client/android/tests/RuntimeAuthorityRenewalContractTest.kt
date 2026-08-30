package org.amnezia.vpn

import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.json.JSONObject

class RuntimeAuthorityRenewalContractTest {
    private fun authorityFields(
        revision: String = "10",
        payload: String = "b".repeat(64),
        trusted: String = "2026-08-28T10:00:00.000Z",
        deadline: String = "2026-08-28T11:00:00.000Z",
    ): Map<String, Any?> = linkedMapOf(
        "schema_version" to 1,
        "device_audience" to "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "catalog_revision" to revision,
        "catalog_payload_sha256" to payload,
        "catalog_signing_kid" to "key-1",
        "catalog_source" to "network",
        "profile_id" to "profile-1",
        "transport" to "awg",
        "config_generation" to "1",
        "binding_generation" to "1",
        "native_profile_expires_at" to deadline,
        "catalog_freshness_deadline" to deadline,
        "entitlement_deadline" to deadline,
        "catalog_issued_at" to "2026-08-28T09:59:00.000Z",
        "trusted_utc_at_dispatch" to trusted,
        "policy_schema" to NativeDispatchPolicyDigest.SCHEMA,
        "policy_sha256" to "a".repeat(64),
        "protected_tunnel_ips" to listOf("1.1.1.1"),
        "receiver_monotonic_policy" to RuntimeAuthority.MONOTONIC_POLICY,
    )

    private fun request(
        renewalId: String = "123e4567-e89b-42d3-a456-426614174010",
    ): RuntimeAuthorityRenewalContract.Request {
        val fields = authorityFields()
        val authority = RuntimeAuthority.fromFields(fields)
        val commitment = RuntimeAuthorityRenewalContract.authorityCommitmentSha256(
            JSONObject(fields).toString(),
        )
        return RuntimeAuthorityRenewalContract.Request(
            operation = "7", session = "9", renewalId = renewalId,
            policySha256 = authority.dispatchPolicySha256,
            outerSessionId = "android:123e4567-e89b-42d3-a456-426614174020",
            expectedRuntimeSessionId = "123e4567-e89b-42d3-a456-426614174000",
            configGeneration = authority.configGeneration.toString(),
            bindingGeneration = authority.bindingGeneration.toString(),
            catalogRevision = authority.catalogRevision.toString(),
            catalogPayloadSha256 = authority.catalogPayloadSha256,
            authorityCommitmentSha256 = commitment,
            hardDeadline = RuntimeAuthorityRenewalContract.formatDeadline(authority.hardDeadline),
        )
    }

    @Test
    fun exactSuccessFailureAndWrongReceiptAreDistinguished() {
        val expected = RuntimeAuthorityRenewalContract.parseRequest(request().json())
        val applied = RuntimeAuthorityRenewalContract.parseReceipt(
            RuntimeAuthorityRenewalContract.applied(expected).json(),
        )
        assertEquals("applied", applied.kind)
        assertTrue(RuntimeAuthorityRenewalContract.receiptMatchesRequest(applied, expected))
        assertFalse(RuntimeAuthorityRenewalContract.receiptMatchesRequest(
            applied,
            request("123e4567-e89b-42d3-a456-426614174011"),
        ))

        val rejected = RuntimeAuthorityRenewalContract.parseReceipt(
            RuntimeAuthorityRenewalContract.rejected(expected, "renewal_rejected").json(),
        )
        assertEquals("", rejected.hardDeadline)
        assertTrue(RuntimeAuthorityRenewalContract.receiptMatchesRequest(rejected, expected))

        val unexpected = JSONObject(RuntimeAuthorityRenewalContract.applied(expected).json())
            .put("future", true)
        assertFailsWith<IllegalArgumentException> {
            RuntimeAuthorityRenewalContract.parseReceipt(unexpected.toString())
        }
    }

    @Test
    fun staleAuthorityAndDurableFailureCannotCommit() {
        val current = RuntimeAuthority.fromFields(authorityFields())
        val effectiveNow = Instant.parse("2026-08-28T10:10:00Z")
        assertTrue(current.acceptsRenewal(
            RuntimeAuthority.fromFields(authorityFields()), effectiveNow,
        ))
        assertFalse(current.acceptsRenewal(RuntimeAuthority.fromFields(authorityFields(
            revision = "9", deadline = "2026-08-28T12:00:00.000Z",
        )), effectiveNow))
        assertTrue(current.acceptsRenewal(RuntimeAuthority.fromFields(authorityFields(
            revision = "11", payload = "c".repeat(64),
            trusted = "2026-08-28T10:05:00.000Z",
            deadline = "2026-08-28T10:30:00.000Z",
        )), effectiveNow))
        assertFalse(current.acceptsRenewal(RuntimeAuthority.fromFields(authorityFields(
            revision = "11", payload = "c".repeat(64),
            trusted = "2026-08-28T10:01:00.000Z",
            deadline = "2026-08-28T10:05:00.000Z",
        )), effectiveNow))

        var live = "old"
        val order = mutableListOf<String>()
        RuntimeAuthorityRenewalContract.commitPersistFirst(
            "new",
            persist = { order += "persist:$it" },
            commit = { order += "commit:$it"; live = it },
        )
        assertEquals(listOf("persist:new", "commit:new"), order)
        assertEquals("new", live)

        live = "old"
        assertFailsWith<IllegalStateException> {
            RuntimeAuthorityRenewalContract.commitPersistFirst(
                "new",
                persist = { throw IllegalStateException("disk full") },
                commit = { live = it },
            )
        }
        assertEquals("old", live)
    }

    @Test
    fun serviceEventIsAppendOnly() {
        assertEquals(ServiceEvent.entries.lastIndex,
                     ServiceEvent.RUNTIME_AUTHORITY_RENEWAL.ordinal)
    }
}
