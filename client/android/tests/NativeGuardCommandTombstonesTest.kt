package org.amnezia.vpn

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class NativeGuardCommandTombstonesTest {
    @Test
    fun stopDeliveredBeforeDelayedActivatePermanentlyCancelsExactInner() {
        val gate = NativeGuardCommandTombstones()
        gate.requestStop("outer:1", "runtime-1")
        assertFalse(gate.activationAllowed("outer:1", "runtime-1"))
        assertTrue(gate.activationAllowed("outer:1", "runtime-2"))
        assertTrue(gate.activationAllowed("outer:2", "runtime-1"))
    }

    @Test
    fun onlyExactReleaseClearsTheStopTombstone() {
        val gate = NativeGuardCommandTombstones()
        gate.requestStop("outer:1", "runtime-1")
        gate.clearAfterRelease("outer:1", "runtime-2")
        assertFalse(gate.activationAllowed("outer:1", "runtime-1"))
        gate.clearAfterRelease("outer:1", "runtime-1")
        assertTrue(gate.activationAllowed("outer:1", "runtime-1"))
    }
}
