package org.amnezia.vpn

import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/** Runs the final native-stop proof without allowing Service destruction to wait forever. */
internal object GuardedServiceTermination {
    fun proveWithin(timeoutMillis: Long, proof: () -> Boolean): Boolean {
        require(timeoutMillis > 0) { "Termination proof timeout must be positive" }
        val executor = Executors.newSingleThreadExecutor { runnable ->
            Thread(runnable, "tribe-vpn-termination-proof").apply { isDaemon = true }
        }
        val future = executor.submit<Boolean> { proof() }
        return try {
            future.get(timeoutMillis, TimeUnit.MILLISECONDS)
        } catch (_: TimeoutException) {
            false
        } catch (_: ExecutionException) {
            false
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            false
        } finally {
            // The native call may ignore interruption. The caller treats a non-result as
            // ambiguous and kills the dedicated VPN process; this daemon cannot keep it alive.
            future.cancel(true)
            executor.shutdownNow()
        }
    }
}
