package org.amnezia.vpn.util

import kotlin.test.Test
import kotlin.test.assertEquals

// AVPN (android2 V2, 21.11): a build report names the engine leg of its start; a start without a tunnel is not "built".
class TribeStartTest {

    @Test
    fun legComesFromTheStartConfig() {
        assertEquals(7L, TribeStart.legOf("""{"protocol":"awg","tribeStartLeg":7,"awg_config_data":{}}"""))
        assertEquals(12L, TribeStart.legOf("""{"a":1, "tribeStartLeg" : 12}"""))
    }

    @Test
    fun noLegIsZero() {
        assertEquals(0L, TribeStart.legOf(null)) // the saved config of a service restart
        assertEquals(0L, TribeStart.legOf("""{"protocol":"awg"}""")) // a config of an older app
        assertEquals(0L, TribeStart.legOf("not json"))
    }

    @Test
    fun aStartWithoutTunnelIsNotBuilt() {
        assertEquals(TribeStart.BUILT, TribeStart.endState(started = true))
        assertEquals(TribeStart.NOT_STARTED, TribeStart.endState(started = false))
        assertEquals(setOf(0, 1, 2), setOf(TribeStart.BUILDING, TribeStart.BUILT, TribeStart.NOT_STARTED))
    }
}
