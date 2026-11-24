package org.amnezia.vpn.util

import kotlin.test.Test
import kotlin.test.assertEquals

// AVPN (android4 G4, 21.11): connected, Home, the person ends the VPN from the notification; the service ends while the
// activity is unbound. On return the app rebound only to a RUNNING service, so it never learned the tunnel was gone
// («Connected, Германия 1» with no tunnel), and the first tap's stop went nowhere (10 s until attempt_stop_unconfirmed).
class ServiceReachTest {

    @Test
    fun foregroundReturnLearnsTheTruth() {
        // the service runs: rebind and take its status (the existing path)
        assertEquals(ServiceReach.OnForeground.REBIND, ServiceReach.onForeground(knownService = true, running = true, startInFlight = false))
        // it does not run: the tunnel is gone - told at once
        assertEquals(ServiceReach.OnForeground.GONE, ServiceReach.onForeground(knownService = true, running = false, startInFlight = false))
        // a start intent of ours is in flight (the service may not be foreground yet): bind, the status decides
        assertEquals(ServiceReach.OnForeground.REBIND, ServiceReach.onForeground(knownService = true, running = false, startInFlight = true))
        // never connected through this app: nothing to learn
        assertEquals(ServiceReach.OnForeground.NOTHING, ServiceReach.onForeground(knownService = false, running = false, startInFlight = false))
    }

    @Test
    fun aStopWithNoServiceIsNeverSentIntoTheVoid() {
        // nothing runs: the stop is already true - settled as Disconnected at once
        assertEquals(ServiceReach.UnsentStop.ALREADY_STOPPED, ServiceReach.unsentStop(running = false))
        // the service runs but is not bound (the activity was stopped): bind and deliver it on that bind
        assertEquals(ServiceReach.UnsentStop.BIND_AND_SEND, ServiceReach.unsentStop(running = true))
    }
}
