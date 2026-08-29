package org.amnezia.vpn

import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RuntimeAuthorityTest {
    private fun fields(
        revision: String = "7",
        payload: String = "a".repeat(64),
        trusted: String = "2026-08-28T10:00:00Z",
        freshness: String = "2026-08-28T11:00:00Z",
    ): Map<String, Any?> = mapOf(
        "schema_version" to 1,
        "device_audience" to "A".repeat(43),
        "catalog_revision" to revision,
        "catalog_payload_sha256" to payload,
        "catalog_signing_kid" to "catalog-key-1",
        "catalog_source" to "network",
        "profile_id" to "profile-1",
        "transport" to "awg",
        "config_generation" to "9",
        "binding_generation" to "3",
        "native_profile_expires_at" to "2026-08-28T12:00:00Z",
        "catalog_freshness_deadline" to freshness,
        "entitlement_deadline" to "2026-08-28T13:00:00Z",
        "catalog_issued_at" to "2026-08-28T09:59:00Z",
        "trusted_utc_at_dispatch" to trusted,
        "policy_schema" to NativeDispatchPolicyDigest.SCHEMA,
        "policy_sha256" to "b".repeat(64),
        "protected_tunnel_ips" to listOf("1.1.1.1"),
        "receiver_monotonic_policy" to RuntimeAuthority.MONOTONIC_POLICY,
    )

    @Test
    fun strictShapeAndCanonicalGenerations() {
        assertEquals(7uL, RuntimeAuthority.fromFields(fields()).catalogRevision)
        assertFailsWith<IllegalArgumentException> {
            RuntimeAuthority.fromFields(fields() + ("unexpected" to true))
        }
        assertFailsWith<IllegalArgumentException> {
            RuntimeAuthority.fromFields(fields(revision = "07"))
        }
        assertFailsWith<IllegalArgumentException> {
            RuntimeAuthority.fromFields(fields(revision = "1١"))
        }
        assertFailsWith<IllegalArgumentException> {
            RuntimeAuthority.fromFields(fields() - "entitlement_deadline")
        }
        assertFailsWith<IllegalArgumentException> {
            RuntimeAuthority.fromFields(fields() + ("profile_id" to "profile-тест"))
        }
        assertFailsWith<IllegalArgumentException> {
            RuntimeAuthority.fromFields(fields() + ("catalog_signing_kid" to "key-ключ"))
        }
        assertFailsWith<IllegalArgumentException> {
            RuntimeAuthority.fromFields(fields() + ("protected_tunnel_ips" to emptyList<String>()))
        }
        assertFailsWith<IllegalArgumentException> {
            RuntimeAuthority.fromFields(fields() +
                ("protected_tunnel_ips" to listOf("1.1.1.1", "1.1.1.1")))
        }
        assertFailsWith<IllegalArgumentException> {
            RuntimeAuthority.fromFields(fields() + ("protected_tunnel_ips" to listOf("10.0.0.1")))
        }
    }

    @Test
    fun strippedV2AuthorityCannotDowngradeButExplicitLegacyIsRecognized() {
        assertEquals(
            RuntimeAuthority.Companion.EnvelopeClass.LEGACY,
            RuntimeAuthority.classifyEnvelope(RuntimeAuthority.LEGACY_ENVELOPE, false),
        )
        assertFailsWith<IllegalArgumentException> {
            RuntimeAuthority.classifyEnvelope(RuntimeAuthority.V2_ENVELOPE, false)
        }
        assertFailsWith<IllegalArgumentException> {
            RuntimeAuthority.classifyEnvelope(null, false)
        }
    }

    @Test
    fun sameBootMonotonicExpiryAndRollbackAreFailClosed() {
        val authority = RuntimeAuthority.fromFields(fields())
        val anchor = RuntimeAuthorityAnchor(
            Instant.parse("2026-08-28T10:00:00Z").toEpochMilli(),
            Instant.parse("2026-08-28T10:00:00Z").toEpochMilli(),
            10_000L,
            "boot-a",
        )
        assertTrue(AndroidAuthorityClock.evaluate(authority, anchor, RuntimeClockObservation(
            Instant.parse("2026-08-28T10:10:00Z").toEpochMilli(), 610_000L, "boot-a",
        )).accepted)
        assertEquals("wall_clock_rollback", AndroidAuthorityClock.evaluate(
            authority,
            anchor,
            RuntimeClockObservation(
                Instant.parse("2026-08-28T09:40:00Z").toEpochMilli(), 610_000L, "boot-a",
            ),
        ).reason)
        assertEquals("authority_expired", AndroidAuthorityClock.evaluate(
            authority,
            anchor,
            RuntimeClockObservation(
                Instant.parse("2026-08-28T11:00:00Z").toEpochMilli(), 3_610_000L, "boot-a",
            ),
        ).reason)
    }

    @Test
    fun crossBootRequiresTrustedNetworkTimeAndHonorsDeadline() {
        val authority = RuntimeAuthority.fromFields(fields())
        val anchor = RuntimeAuthorityAnchor(
            Instant.parse("2026-08-28T10:00:00Z").toEpochMilli(),
            Instant.parse("2026-08-28T10:00:00Z").toEpochMilli(),
            10_000L,
            "boot-a",
        )
        assertEquals("cross_boot_time_ambiguous", AndroidAuthorityClock.evaluate(
            authority, anchor, RuntimeClockObservation(0L, 1_000L, "boot-b"),
        ).reason)
        assertTrue(AndroidAuthorityClock.evaluate(
            authority,
            anchor,
            RuntimeClockObservation(
                0L, 1_000L, "boot-b",
                Instant.parse("2026-08-28T10:30:00Z").toEpochMilli(),
            ),
        ).accepted)
        assertEquals("authority_expired", AndroidAuthorityClock.evaluate(
            authority,
            anchor,
            RuntimeClockObservation(
                0L, 1_000L, "boot-b",
                Instant.parse("2026-08-28T11:00:00Z").toEpochMilli(),
            ),
        ).reason)
    }

    @Test
    fun renewalSeparatesCatalogHighWaterFromRevocableDeadline() {
        val current = RuntimeAuthority.fromFields(fields())
        val effectiveNow = Instant.parse("2026-08-28T10:10:00Z")
        assertFalse(current.acceptsRenewal(RuntimeAuthority.fromFields(
            fields(revision = "7", payload = "c".repeat(64), freshness = "2026-08-28T11:10:00Z"),
        ), effectiveNow))
        assertTrue(current.acceptsRenewal(RuntimeAuthority.fromFields(fields()), effectiveNow))
        assertTrue(current.acceptsRenewal(RuntimeAuthority.fromFields(
            fields(revision = "8", payload = "c".repeat(64), trusted = "2026-08-28T10:05:00Z",
                freshness = "2026-08-28T10:30:00Z"),
        ), effectiveNow))
        assertFalse(current.acceptsRenewal(RuntimeAuthority.fromFields(
            fields(revision = "8", payload = "c".repeat(64), trusted = "2026-08-28T10:01:00Z",
                freshness = "2026-08-28T10:05:00Z"),
        ), effectiveNow))
    }

    @Test
    fun exactOneShotWatchdogFencesRenewalAndLateWake() {
        val authority = RuntimeAuthority.fromFields(fields())
        assertEquals(30 * 60 * 1000L, RuntimeAuthorityWatchdogPlanner.remainingMillis(
            authority, Instant.parse("2026-08-28T10:30:00Z"),
        ))
        assertFailsWith<IllegalArgumentException> {
            RuntimeAuthorityWatchdogPlanner.remainingMillis(
                authority, Instant.parse("2026-08-28T11:00:00Z"),
            )
        }
        assertEquals(1L, RuntimeAuthorityWatchdogPlanner.remainingMillis(
            authority, Instant.parse("2026-08-28T10:59:59.999999999Z"),
        ))

        val fence = RuntimeAuthorityWatchdogFence()
        val prior = fence.arm(7L, authority)
        val renewed = fence.arm(7L, authority)
        assertFalse(fence.consume(prior))
        assertTrue(fence.consume(renewed))
        assertFalse(fence.consume(renewed))
    }

    @Test
    fun expiryDurabilityFailureStillStopsExactlyOnceAndNeverReleases() {
        var stopCalls = 0
        var markedStopped = 0
        var durabilityFailures = 0
        val outcome = RuntimeAuthorityExpiryCoordinator.execute(
            persistQuarantine = { error("disk full") },
            stopInner = { stopCalls++ },
            markStopped = { markedStopped++ },
            persistStoppedState = { error("disk still full") },
            onDurabilityFailure = { durabilityFailures++ },
        )
        assertFalse(outcome.quarantinePersisted)
        assertTrue(outcome.stopSucceeded)
        assertFalse(outcome.stoppedStatePersisted)
        assertEquals(1, stopCalls)
        assertEquals(1, markedStopped)
        assertEquals(1, durabilityFailures)
    }

    @Test
    fun expiryDurableQuarantineSurvivesNativeStopFailure() {
        var quarantineWrites = 0
        var stopCalls = 0
        var markCalls = 0
        var stoppedWrites = 0
        var durabilityFailures = 0
        val outcome = RuntimeAuthorityExpiryCoordinator.execute(
            persistQuarantine = { quarantineWrites++ },
            stopInner = { stopCalls++; error("native stop failed") },
            markStopped = { markCalls++ },
            persistStoppedState = { stoppedWrites++ },
            onDurabilityFailure = { durabilityFailures++ },
        )
        assertTrue(outcome.quarantinePersisted)
        assertFalse(outcome.stopSucceeded)
        assertFalse(outcome.stoppedStatePersisted)
        assertEquals(1, quarantineWrites)
        assertEquals(1, stopCalls)
        assertEquals(0, markCalls)
        assertEquals(0, stoppedWrites)
        assertEquals(0, durabilityFailures)
    }

    @Test
    fun expiryDoubleFailureWipesUntrustworthyDurabilityOnce() {
        var stopCalls = 0
        var markCalls = 0
        var stoppedWrites = 0
        var durabilityFailures = 0
        val outcome = RuntimeAuthorityExpiryCoordinator.execute(
            persistQuarantine = { error("disk full") },
            stopInner = { stopCalls++; error("native stop failed") },
            markStopped = { markCalls++ },
            persistStoppedState = { stoppedWrites++ },
            onDurabilityFailure = { durabilityFailures++ },
        )
        assertFalse(outcome.quarantinePersisted)
        assertFalse(outcome.stopSucceeded)
        assertFalse(outcome.stoppedStatePersisted)
        assertEquals(1, stopCalls)
        assertEquals(0, markCalls)
        assertEquals(0, stoppedWrites)
        assertEquals(1, durabilityFailures)
    }

    @Test
    fun expiryCleanPathExecutesEveryReceiptLegExactlyOnce() {
        var quarantineWrites = 0
        var stopCalls = 0
        var markCalls = 0
        var stoppedWrites = 0
        var durabilityFailures = 0
        val outcome = RuntimeAuthorityExpiryCoordinator.execute(
            persistQuarantine = { quarantineWrites++ },
            stopInner = { stopCalls++ },
            markStopped = { markCalls++ },
            persistStoppedState = { stoppedWrites++ },
            onDurabilityFailure = { durabilityFailures++ },
        )
        assertTrue(outcome.quarantinePersisted)
        assertTrue(outcome.stopSucceeded)
        assertTrue(outcome.stoppedStatePersisted)
        assertEquals(1, quarantineWrites)
        assertEquals(1, stopCalls)
        assertEquals(1, markCalls)
        assertEquals(1, stoppedWrites)
        assertEquals(0, durabilityFailures)
    }
}
