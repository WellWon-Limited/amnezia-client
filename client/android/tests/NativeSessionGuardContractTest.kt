package org.amnezia.vpn

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class NativeSessionGuardContractTest {
    private val runtime = "123e4567-e89b-42d3-a456-426614174000"
    private val identity = NativeSessionGuardContract.RequestIdentity("7", "11", runtime)
    private val policy = "a".repeat(64)
    private val outer = "service-epoch:123e4567-e89b-42d3-a456-426614174001"

    @Test
    fun armedAndReleasedEventsAreClosedAndEchoExactIdentity() {
        for (kind in listOf("armed", "released", "lost")) {
            val event = NativeSessionGuardContract.eventFields(
                identity, kind, policy, outer,
            )
            assertEquals(setOf(
                "type", "schema", "operation", "session", "kind", "policy_sha256",
                "outer_session_id", "expected_runtime_session_id", "reason",
            ), event.keys)
            assertEquals("7", event["operation"])
            assertEquals("11", event["session"])
            assertEquals(runtime, event["expected_runtime_session_id"])
            assertEquals(policy, event["policy_sha256"])
            assertEquals(outer, event["outer_session_id"])
        }
    }

    @Test
    fun malformedCountersUuidHashAndOwnerFailClosed() {
        assertFalse(NativeSessionGuardContract.isCanonicalCounter("0"))
        assertFalse(NativeSessionGuardContract.isCanonicalCounter("01"))
        assertFalse(NativeSessionGuardContract.isCanonicalCounter("1١"))
        assertFalse(NativeSessionGuardContract.isCanonicalCounter("18446744073709551616"))
        assertTrue(NativeSessionGuardContract.isCanonicalCounter("18446744073709551615"))
        assertFailsWith<IllegalArgumentException> {
            NativeSessionGuardContract.RequestIdentity("01", "1", runtime)
        }
        assertFailsWith<IllegalArgumentException> {
            NativeSessionGuardContract.RequestIdentity("1", "1", runtime.uppercase())
        }
        assertFailsWith<IllegalArgumentException> {
            NativeSessionGuardContract.requireOuterSessionId("outer-тест")
        }
        assertFailsWith<IllegalArgumentException> {
            NativeSessionGuardContract.eventJson(identity, "armed", "A".repeat(64), outer)
        }
        assertFailsWith<IllegalArgumentException> {
            NativeSessionGuardContract.eventJson(identity, "released", policy, "")
        }
        val fractionalSchema = NativeSessionGuardContract.eventFields(
            identity, "lost", policy, outer,
        ).toMutableMap().apply { put("schema", 1.5) }
        assertFailsWith<IllegalArgumentException> {
            NativeSessionGuardContract.parseEventFields(fractionalSchema)
        }
    }

    @Test
    fun pendingChannelLossAndRecoveryReceiptsNeverMasqueradeAsRejection() {
        val lost = NativeSessionGuardContract.eventFields(
            identity, "lost", policy, outer, "service_channel_lost",
        )
        val parsed = NativeSessionGuardContract.parseEventFields(lost)
        assertEquals("lost", parsed["kind"])
        assertEquals(outer, parsed["outer_session_id"])

        val adopted = NativeSessionGuardContract.recoveryReceiptFields(
            identity, "adopt", "adopted", policy, outer,
        )
        assertEquals(setOf(
            "type", "schema", "action", "kind", "operation", "session",
            "policy_sha256", "outer_session_id", "expected_runtime_session_id", "reason",
        ), adopted.keys)
        assertEquals("adopted", adopted["kind"])
        assertFailsWith<IllegalArgumentException> {
            NativeSessionGuardContract.recoveryReceiptFields(
                identity, "adopt", "stopped_released", policy, outer,
            )
        }
    }
}
