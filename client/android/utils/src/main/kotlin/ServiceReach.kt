package org.amnezia.vpn.util

// AVPN (android4 G4, 21.11): what the activity does when it cannot reach the VPN service through a bind. Pure (JVM unit
// tests: src/test ServiceReachTest).
//
// Connected, Home (onStop unbinds), the person ends the VPN from the notification: the service stops and is destroyed
// while no client is bound. Back in the app, onStart rebound only to a service that runs (AmneziaVpnService.isRunning),
// so there was no bind and no status: the app kept «Connected» with no tunnel, and the first tap's stop went into the
// void (logged "not sent") until the engine gave the stop up 10 s later. Upstream told Qt "service disconnected" on
// every onStop (forgetting a live connection on each trip to the background - what AVPN 6d387f91a removed).
// Rule: on return the app always learns the service's true state - a running service (or one our start intent is
// bringing up) is rebound and asked for its status; a service that does not run means there is no tunnel: the app is
// told DISCONNECTED at once (the same event a bound service sends). A stop with no service to give it to is never
// dropped: nothing running = the stop is already true (DISCONNECTED at once); a running, unbound service is bound and
// the stop delivered on that bind.
object ServiceReach {
    enum class OnForeground { REBIND, GONE, NOTHING }

    // knownService: the activity knows the service class of the last session (vpnProto); running: that service runs as a
    // foreground service; startInFlight: a start intent of ours was accepted and no bind has completed since.
    fun onForeground(knownService: Boolean, running: Boolean, startInFlight: Boolean): OnForeground = when {
        !knownService -> OnForeground.NOTHING
        running || startInFlight -> OnForeground.REBIND
        else -> OnForeground.GONE
    }

    enum class UnsentStop { ALREADY_STOPPED, BIND_AND_SEND }

    // A stop with no service bound or binding and no start intent in flight.
    fun unsentStop(running: Boolean): UnsentStop = if (running) UnsentStop.BIND_AND_SEND else UnsentStop.ALREADY_STOPPED
}
