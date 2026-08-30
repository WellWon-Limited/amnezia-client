package org.amnezia.vpn

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AndroidSessionGuardTest {
    private val owner = "boot-epoch:7"
    private val policy = "a".repeat(64)

    @Test
    fun connectSwitchDisconnectKeepsOuterBlackhole() {
        val guard = AndroidSessionGuard()
        guard.arm(owner, policy)
        assertTrue(guard.snapshot().blackholed)
        guard.beginInnerStart(owner, "inner:1", policy)
        guard.markInnerReady(owner, "inner:1", policy)
        guard.beginInnerStop(owner, "inner:1")
        guard.confirmInnerStopped(owner, "inner:1")
        assertTrue(guard.snapshot().blackholed)
        guard.validateReplacement(owner, policy)
        guard.beginInnerStart(owner, "inner:2", policy)
        guard.markInnerReady(owner, "inner:2", policy)
        guard.beginInnerStop(owner, "inner:2")
        guard.confirmInnerStopped(owner, "inner:2")
        guard.disarm(owner)
        assertFalse(guard.snapshot().armed)
    }

    @Test
    fun staleStopAndPolicyMismatchFailClosed() {
        val guard = AndroidSessionGuard()
        guard.arm(owner, policy)
        guard.beginInnerStart(owner, "inner:2", policy)
        guard.markInnerReady(owner, "inner:2", policy)
        assertFailsWith<IllegalArgumentException> { guard.beginInnerStop(owner, "inner:1") }
        guard.beginInnerStop(owner, "inner:2")
        guard.confirmInnerStopped(owner, "inner:2")
        assertFailsWith<IllegalArgumentException> {
            guard.validateReplacement(owner, "b".repeat(64))
        }
        assertTrue(guard.snapshot().blackholed)
    }

    @Test
    fun coreCrashCannotDisarmOrAdoptForeignSession() {
        val guard = AndroidSessionGuard()
        guard.arm(owner, policy)
        guard.beginInnerStart(owner, "inner:1", policy)
        guard.markInnerReady(owner, "inner:1", policy)
        guard.markInnerCrash(owner, "inner:1")
        assertEquals("blackhole", guard.snapshot().state)
        assertFalse(guard.canAdopt("new-epoch:7", policy))
        assertFailsWith<IllegalArgumentException> { guard.disarm("new-epoch:7") }
    }

    @Test
    fun partialStartRequiresPositiveAbortReceiptOrQuarantine() {
        val clean = AndroidSessionGuard()
        clean.arm(owner, policy)
        clean.beginInnerStart(owner, "inner:1", policy)
        clean.confirmInnerStartAborted(owner, "inner:1")
        assertTrue(clean.snapshot().blackholed)

        val ambiguous = AndroidSessionGuard()
        ambiguous.arm(owner, policy)
        ambiguous.beginInnerStart(owner, "inner:2", policy)
        ambiguous.quarantineInnerStart(owner, "inner:2")
        assertEquals("quarantined", ambiguous.snapshot().state)
        assertFailsWith<IllegalArgumentException> { ambiguous.disarm(owner) }
        assertFailsWith<IllegalArgumentException> {
            ambiguous.beginInnerStart(owner, "inner:3", policy)
        }
    }

    @Test
    fun authorityDeadlineQuarantinesBeforeStopAndRequiresExactRecoveryProof() {
        val guard = AndroidSessionGuard()
        guard.arm(owner, policy)
        guard.beginInnerStart(owner, "inner:deadline", policy)
        guard.markInnerReady(owner, "inner:deadline", policy)
        guard.quarantineActiveInner(owner, "inner:deadline")
        assertEquals("quarantined", guard.snapshot().state)
        assertEquals("inner:deadline", guard.snapshot().activeInnerToken)
        assertFailsWith<IllegalArgumentException> { guard.disarm(owner) }

        guard.confirmQuarantinedInnerStopped(owner, "inner:deadline")
        assertEquals("quarantined", guard.snapshot().state)
        assertTrue(guard.snapshot().activeInnerToken == null)
        guard.proveQuarantinedInnerStopped(owner)
        assertTrue(guard.snapshot().blackholed)
        guard.disarm(owner)
        assertFalse(guard.snapshot().armed)
    }

    @Test
    fun thrownStopQuarantinesOnlyTheExactStoppingOwnerAndCanRetryToBlackhole() {
        val guard = AndroidSessionGuard()
        guard.arm(owner, policy)
        guard.beginInnerStart(owner, "inner:stop-failure", policy)
        guard.markInnerReady(owner, "inner:stop-failure", policy)
        guard.beginInnerStop(owner, "inner:stop-failure")

        assertFailsWith<IllegalArgumentException> {
            guard.quarantineStoppingInner("foreign:7", "inner:stop-failure")
        }
        assertFailsWith<IllegalArgumentException> {
            guard.quarantineStoppingInner(owner, "inner:stale")
        }
        assertEquals("stopping", guard.snapshot().state)

        guard.quarantineStoppingInner(owner, "inner:stop-failure")
        assertEquals("quarantined", guard.snapshot().state)
        assertEquals("inner:stop-failure", guard.snapshot().activeInnerToken)
        assertFailsWith<IllegalArgumentException> {
            guard.quarantineStoppingInner(owner, "inner:stop-failure")
        }

        // A repeated exact stop with a positive native receipt retains quarantine until
        // the explicit proof transition returns the still-established outer TUN to blackhole.
        guard.confirmQuarantinedInnerStopped(owner, "inner:stop-failure")
        guard.proveQuarantinedInnerStopped(owner)
        assertTrue(guard.snapshot().blackholed)
    }

    @Test
    fun replacementTransfersOnlyAnExactBlackholeWithIdenticalOuterPolicy() {
        val guard = AndroidSessionGuard()
        guard.arm(owner, policy)
        guard.replaceBlackhole(owner, "boot-epoch:8", policy)
        assertFalse(guard.canAdopt(owner, policy))
        assertTrue(guard.canAdopt("boot-epoch:8", policy))
        assertTrue(guard.snapshot().blackholed)

        assertFailsWith<IllegalArgumentException> {
            guard.replaceBlackhole(owner, "boot-epoch:9", policy)
        }
        assertFailsWith<IllegalArgumentException> {
            guard.replaceBlackhole("boot-epoch:8", "boot-epoch:9", "b".repeat(64))
        }
        assertTrue(guard.canAdopt("boot-epoch:8", policy))
    }

    @Test
    fun awgToXrayPolicyChangeCommitsOnlyAfterSeamlessTunHandover() {
        val awgPolicy = "a".repeat(64)
        val xrayPolicy = "b".repeat(64)
        val guard = AndroidSessionGuard()
        guard.arm(owner, awgPolicy)
        guard.beginInnerStart(owner, "awg-runtime", awgPolicy)
        guard.markInnerReady(owner, "awg-runtime", awgPolicy)
        guard.beginInnerStop(owner, "awg-runtime")
        guard.confirmInnerStopped(owner, "awg-runtime")

        // Validation alone models Builder.establish() failure. Android promises the old
        // interface is untouched, so ownership/policy must remain byte-exact.
        guard.validateBlackholeTunHandover(owner, "boot-epoch:8", xrayPolicy)
        assertTrue(guard.canAdopt(owner, awgPolicy))
        assertFalse(guard.canAdopt("boot-epoch:8", xrayPolicy))

        // A non-null replacement descriptor is the commit point. The new TUN has no inner
        // reader yet and therefore remains a blackhole until the exact Xray receipt.
        guard.commitBlackholeTunHandover(owner, "boot-epoch:8", xrayPolicy)
        assertFalse(guard.canAdopt(owner, awgPolicy))
        assertTrue(guard.canAdopt("boot-epoch:8", xrayPolicy))
        guard.beginInnerStart("boot-epoch:8", "xray-runtime", xrayPolicy)
        guard.markInnerReady("boot-epoch:8", "xray-runtime", xrayPolicy)
        guard.beginInnerStop("boot-epoch:8", "xray-runtime")
        guard.confirmInnerStopped("boot-epoch:8", "xray-runtime")
        guard.disarm("boot-epoch:8")
        assertFalse(guard.snapshot().armed)
    }

    @Test
    fun delayedNMinusTwoStopCannotTouchReplacement() {
        val guard = AndroidSessionGuard()
        guard.arm(owner, policy)
        guard.beginInnerStart(owner, "runtime:1", policy)
        guard.markInnerReady(owner, "runtime:1", policy)
        guard.beginInnerStop(owner, "runtime:1")
        guard.confirmInnerStopped(owner, "runtime:1")
        guard.replaceBlackhole(owner, "boot-epoch:8", policy)
        guard.beginInnerStart("boot-epoch:8", "runtime:3", policy)
        guard.markInnerReady("boot-epoch:8", "runtime:3", policy)

        assertFailsWith<IllegalArgumentException> {
            guard.beginInnerStop(owner, "runtime:1")
        }
        assertFailsWith<IllegalArgumentException> {
            guard.beginInnerStop("boot-epoch:8", "runtime:1")
        }
        assertEquals("runtime:3", guard.snapshot().activeInnerToken)
        assertEquals("running", guard.snapshot().state)
    }

    @Test
    fun osRevokeDropsOnlyTheExactOuterOwnerFromAnyInnerState() {
        val guard = AndroidSessionGuard()
        guard.arm(owner, policy)
        guard.beginInnerStart(owner, "runtime:1", policy)
        assertFailsWith<IllegalArgumentException> { guard.markOuterLost("foreign:1") }
        assertTrue(guard.snapshot().armed)
        guard.markOuterLost(owner)
        assertFalse(guard.snapshot().armed)
    }
}
