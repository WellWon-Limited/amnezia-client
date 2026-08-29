package org.amnezia.vpn

import java.util.concurrent.ConcurrentHashMap

/**
 * Durable-for-the-service-lifetime STOP intent gate. Binder and foreground-service deliveries can
 * arrive before a previously dispatched ACTIVATE. Once STOP is observed, that exact inner UUID
 * may never start again; only an exact outer RELEASE clears the tombstone.
 */
class NativeGuardCommandTombstones {
    private val stopped = ConcurrentHashMap.newKeySet<String>()

    fun requestStop(outerSessionId: String, expectedRuntimeSessionId: String) {
        stopped += key(outerSessionId, expectedRuntimeSessionId)
    }

    fun activationAllowed(outerSessionId: String, expectedRuntimeSessionId: String): Boolean =
        key(outerSessionId, expectedRuntimeSessionId) !in stopped

    fun clearAfterRelease(outerSessionId: String, expectedRuntimeSessionId: String) {
        stopped.remove(key(outerSessionId, expectedRuntimeSessionId))
    }

    private fun key(outerSessionId: String, expectedRuntimeSessionId: String): String =
        "$outerSessionId\u0000$expectedRuntimeSessionId"
}
