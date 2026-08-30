package org.amnezia.vpn

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class GuardedServiceTerminationTest {
    @Test
    fun exactProofCompletesBeforeCallerContinuesWithScopeCancellation() {
        val trace = mutableListOf<String>()
        val proven = GuardedServiceTermination.proveWithin(1_000) {
            trace += "exact_stop"
            true
        }
        trace += "scope_cancel"

        assertTrue(proven)
        assertTrue(trace == listOf("exact_stop", "scope_cancel"))
    }

    @Test
    fun falseThrowAndTimeoutAreAllAmbiguous() {
        assertFalse(GuardedServiceTermination.proveWithin(1_000) { false })
        assertFalse(GuardedServiceTermination.proveWithin(1_000) {
            throw IllegalStateException("stop failure injection")
        })

        val entered = CountDownLatch(1)
        val interrupted = CountDownLatch(1)
        assertFalse(GuardedServiceTermination.proveWithin(25) {
            entered.countDown()
            try {
                Thread.sleep(30_000)
                true
            } catch (_: InterruptedException) {
                interrupted.countDown()
                false
            }
        })
        assertTrue(entered.await(1, TimeUnit.SECONDS))
        assertTrue(interrupted.await(1, TimeUnit.SECONDS))
    }
}
