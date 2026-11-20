package org.amnezia.vpn.util.net

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

// AVPN (Android uplink, review round 20 R1): the physical uplink is the NOT_VPN set - empty = no network,
// whatever our own tunnel does. The defect it replaces: the default-network monitor said "down" on every
// teardown of our tunnel, and a real loss during a connect could not be told from that.
class PhysicalUplinkTest {

    @Test
    fun unknownUntilSnapshotOrCallback() {
        val u = PhysicalUplink()
        assertNull(u.up) // C++ keeps its own "until the first event - up"
    }

    @Test
    fun snapshotGivesTheInitialValue() {
        val down = PhysicalUplink()
        assertTrue(down.onSnapshot(0))
        assertEquals(false, down.up) // the app started with no physical network: known down, not "up"
        val up = PhysicalUplink()
        assertTrue(up.onSnapshot(2))
        assertEquals(true, up.up)
    }

    @Test
    fun upIsTheSetNotEmpty() {
        val u = PhysicalUplink()
        assertTrue(u.onSet(1))
        assertEquals(true, u.up)
        assertFalse(u.onSet(2)) // a second network (Wi-Fi + cellular): no change to tell
        assertFalse(u.onSet(1)) // one of them lost: still up
        assertTrue(u.onSet(0))  // the last physical network lost (Wi-Fi off, out of coverage): down, told
        assertEquals(false, u.up)
        assertFalse(u.onSet(0))
        assertTrue(u.onSet(1))  // back: told
        assertEquals(true, u.up)
    }

    @Test
    fun snapshotNeverOverridesACallback() {
        val u = PhysicalUplink()
        u.onSet(1)
        assertFalse(u.onSnapshot(0)) // a snapshot taken a moment earlier must not hide the callback's fact
        assertEquals(true, u.up)
        u.onSet(0)
        assertFalse(u.onSnapshot(3))
        assertEquals(false, u.up)
    }
}
