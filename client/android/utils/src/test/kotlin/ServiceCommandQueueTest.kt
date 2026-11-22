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
        assertFalse(q.startWaits(Start(1), bound = false))
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
        assertFalse(q.startWaits(Start(1), bound = false))
        q.offer(Stop, bound = false, binding = true)
        assertTrue(q.startWaits(Start(2), bound = false)) // not a second intent ahead of the stop
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
}
