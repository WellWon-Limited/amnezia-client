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

    // A start that is not bound: true = it waits behind a pending command (send it as a message on the bind), false = it
    // goes as the service's start intent, as before.
    fun startWaits(start: T, bound: Boolean): Boolean {
        if (bound || pending.isEmpty()) return false
        pending.addLast(start)
        return true
    }

    // The bind completed: the commands to send now, in the order they were given.
    fun onBound(): List<T> = pending.toList().also { pending.clear() }

    // The service went away for good (unbound on purpose, another service class): nothing waits for it any more.
    fun clear(): List<T> = pending.toList().also { pending.clear() }
}
