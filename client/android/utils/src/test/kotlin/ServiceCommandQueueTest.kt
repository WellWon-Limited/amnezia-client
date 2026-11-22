package org.amnezia.vpn.util

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// AVPN (android3 runs a, f, 21.11): a command given before the service is bound is never lost and keeps its order.
class ServiceCommandQueueTest {
    private sealed interface Cmd
    private data class Start(val leg: Int) : Cmd
    private object Stop : Cmd { override fun toString() = "Stop" }

    @Test
    fun stopBeforeTheBindReachesTheServiceAfterTheStart() {
        val q = ServiceCommandQueue<Cmd>()
        // the first start goes as the service's intent (nothing waits): the activity binds
        assertFalse(q.startWaits(Start(1), bound = false, binding = false))
        // the engine stops 1.3 s later, the bind has not completed: kept, not dropped
        assertEquals(ServiceCommandQueue.Disposition.QUEUED, q.offer(Stop, bound = false, binding = true))
        assertEquals(1, q.waiting)
        // the bind completes: the stop goes now (the start intent was handled before onBind)
        assertEquals(listOf<Cmd>(Stop), q.onBound())
        assertEquals(0, q.waiting)
        assertEquals(ServiceCommandQueue.Disposition.SEND, q.offer(Stop, bound = true, binding = false))
    }

    @Test
    fun aNewerStartWaitsBehindTheStop() {
        val q = ServiceCommandQueue<Cmd>()
        assertFalse(q.startWaits(Start(1), bound = false, binding = false))
        q.offer(Stop, bound = false, binding = true)
        assertTrue(q.startWaits(Start(2), bound = false, binding = true)) // not a second intent ahead of the stop
        assertEquals(listOf(Stop, Start(2)), q.onBound())
    }

    @Test
    fun boundCommandsKeepTheirOrderBehindWaitingOnes() {
        val q = ServiceCommandQueue<Cmd>()
        q.offer(Stop, bound = false, binding = true)
        // bound, but something still waits (the flush has not run): behind it, never ahead
        assertEquals(ServiceCommandQueue.Disposition.QUEUED, q.offer(Start(3), bound = true, binding = false))
        assertEquals(listOf(Stop, Start(3)), q.onBound())
    }

    @Test
    fun noServiceAtAll() {
        val q = ServiceCommandQueue<Cmd>()
        assertEquals(ServiceCommandQueue.Disposition.NO_SERVICE, q.offer(Stop, bound = false, binding = false))
        assertEquals(0, q.waiting)
        q.offer(Stop, bound = false, binding = true)
        assertEquals(listOf<Cmd>(Stop), q.clear())
        assertEquals(emptyList(), q.onBound())
    }

    // Review R1 (21.11): Connect, Stop before the bind completed, the app went to the background (onStop unbinds), the
    // service ended later (the notification's «Отключиться»). The kept Stop is for a bind that was given up - it is
    // dropped, and the next Connect goes as the start intent (which creates the service), never behind the old Stop.
    @Test
    fun aGivenUpBindKeepsNothingAndTheNextStartGoesAsTheIntent() {
        val q = ServiceCommandQueue<Cmd>()
        assertFalse(q.startWaits(Start(1), bound = false, binding = false))
        assertEquals(ServiceCommandQueue.Disposition.QUEUED, q.offer(Stop, bound = false, binding = true))
        assertEquals(listOf<Cmd>(Stop), q.clear()) // onStop: the bind is given up
        assertFalse(q.startWaits(Start(2), bound = false, binding = false)) // as the intent
        assertEquals(0, q.waiting)
        // even a leftover command never holds a start when no bind is in progress
        q.offer(Stop, bound = false, binding = true)
        assertFalse(q.startWaits(Start(3), bound = false, binding = false))
        // bound: a start is the messenger's, never "waiting"
        assertFalse(q.startWaits(Start(4), bound = true, binding = false))
    }

    // Review R3 (21.11): Connect (the start intent accepted by Android), Stop while the first bind is still in progress,
    // the app to the background at once (onStop unbinds). A stop kept for the bind died with it and the tunnel came up.
    // A stop that cancels an accepted start intent belongs to that start: it goes the same way, as an intent - never
    // kept for a bind, so nothing of it outlives a bind (R1 stays fixed).
    @Test
    fun aStopAfterAnAcceptedStartIntentGoesAsAnIntent() {
        val q = ServiceCommandQueue<Cmd>()
        assertFalse(q.startWaits(Start(1), bound = false, binding = false)) // the start intent
        assertEquals(ServiceCommandQueue.Disposition.AS_INTENT,
                     q.offer(Stop, bound = false, binding = true, afterStartIntent = true))
        assertEquals(0, q.waiting) // nothing kept: the unbind has nothing to drop
        assertEquals(emptyList(), q.clear())
        // a later start is not held behind it: it goes as the next intent, after the stop intent
        assertFalse(q.startWaits(Start(2), bound = false, binding = true))
        // not bound and no bind: the start intent is still the stop's way
        assertEquals(ServiceCommandQueue.Disposition.AS_INTENT,
                     q.offer(Stop, bound = false, binding = false, afterStartIntent = true))
        // bound: the messenger, as before
        assertEquals(ServiceCommandQueue.Disposition.SEND,
                     q.offer(Stop, bound = true, binding = false, afterStartIntent = true))
        // no start intent of ours: as before (kept for the bind in progress / nothing to send to)
        assertEquals(ServiceCommandQueue.Disposition.NO_SERVICE, q.offer(Stop, bound = false, binding = false))
    }
}
