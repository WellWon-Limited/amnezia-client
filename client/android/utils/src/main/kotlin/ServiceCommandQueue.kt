package org.amnezia.vpn.util

// AVPN (android3 runs a, f, 21.11): the order of the activity's commands to the VPN service while it is not bound yet.
//
// The first start after an app start goes as an intent (startForegroundService -> onStartCommand: Android keeps it until
// the service runs); the bind follows. Every other command goes through the service's messenger, which does not exist
// until the bind completes - and IpcMessenger.send() on a missing messenger did nothing. On the phone the engine's
// stop (Wi-Fi lost 1.3 s after the tap) was sent 0.25 s before the bind completed and vanished; the service ran the
// queued start and its tunnel came up behind a «Connect» screen. Upstream Amnezia sends the stop the same way
// (AmneziaActivity.disconnectFromVpn -> vpnServiceMessenger.send) - its UI never stops that early.
//
// Rule: while a bind is in progress, a command is kept and delivered in order when the bind completes (the start intent
// was handled by the service before its onBind, so the stop lands after it); a start that comes while a command waits
// goes behind it as a message instead of a second intent (a newer start must not overtake an older stop). With no
// service bound or being bound there is nothing to deliver to: the caller logs the drop. Pure (JVM unit tests:
// src/test ServiceCommandQueueTest).
//
// The queue belongs to ONE bind (review R1, 21.11): what it keeps is for the service instance being bound now. When that
// bind is given up (the activity stops and unbinds, the binding dies, the service went away, bindService refused) the
// kept commands are moot and dropped - a stop for a service that no longer exists has nothing to stop. A start with no
// bind in progress therefore never waits: it goes as the start intent, which creates and starts the service. Before,
// a stop kept across onStop made every later Connect wait behind it for a bind that never completed.
class ServiceCommandQueue<T> {
    enum class Disposition { SEND, QUEUED, NO_SERVICE }

    private val pending = ArrayDeque<T>()

    val waiting: Int get() = pending.size

    // A messenger command. bound: the messenger is set; binding: a bind was asked and has not completed.
    fun offer(command: T, bound: Boolean, binding: Boolean): Disposition = when {
        bound && pending.isEmpty() -> Disposition.SEND
        bound || binding -> Disposition.QUEUED.also { pending.addLast(command) }
        else -> Disposition.NO_SERVICE
    }

    // A start that is not bound: true = it waits behind a command kept for the bind in progress (sent as a message on
    // that bind), false = it goes as the service's start intent, as before (no bind in progress: nothing it could wait for).
    fun startWaits(start: T, bound: Boolean, binding: Boolean): Boolean {
        if (bound || !binding || pending.isEmpty()) return false
        pending.addLast(start)
        return true
    }

    // The bind completed: the commands to send now, in the order they were given.
    fun onBound(): List<T> = pending.toList().also { pending.clear() }

    // The bind is given up (unbound, the binding died, the service went away, the bind was refused): the commands kept
    // for it are dropped - returned for the caller's log.
    fun clear(): List<T> = pending.toList().also { pending.clear() }
}
