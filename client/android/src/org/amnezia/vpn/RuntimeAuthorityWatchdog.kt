package org.amnezia.vpn

import java.time.Duration
import java.time.Instant

object RuntimeAuthorityWatchdogPlanner {
    fun remainingMillis(authority: RuntimeAuthority, effectiveNow: Instant): Long {
        require(effectiveNow < authority.hardDeadline) { "Runtime authority is expired" }
        val remaining = Duration.between(effectiveNow, authority.hardDeadline)
        val wholeMillis = Math.multiplyExact(remaining.seconds, 1_000L)
        // delay() has millisecond resolution. Ceil every positive fractional millisecond so
        // the watchdog can be late and re-evaluate, but can never quarantine before deadline.
        val fractionalMillis = if (remaining.nano == 0) 0L
            else (remaining.nano.toLong() + 999_999L) / 1_000_000L
        return Math.addExact(wholeMillis, fractionalMillis).also {
            require(it > 0) { "Runtime authority deadline is below timer resolution" }
        }
    }
}

/** Deterministic fail-safe ordering for expiry: a durable-write failure never skips stop. */
object RuntimeAuthorityExpiryCoordinator {
    data class Outcome(
        val quarantinePersisted: Boolean,
        val stopSucceeded: Boolean,
        val stoppedStatePersisted: Boolean,
    )

    fun execute(
        persistQuarantine: () -> Unit,
        stopInner: () -> Unit,
        markStopped: () -> Unit,
        persistStoppedState: () -> Unit,
        onDurabilityFailure: () -> Unit,
    ): Outcome {
        val quarantinePersisted = runCatching(persistQuarantine).isSuccess
        val stopSucceeded = runCatching(stopInner).isSuccess
        val stoppedStatePersisted = if (stopSucceeded) {
            runCatching {
                markStopped()
                persistStoppedState()
            }.isSuccess
        } else {
            false
        }
        if (!quarantinePersisted || (stopSucceeded && !stoppedStatePersisted)) {
            runCatching(onDurabilityFailure)
        }
        return Outcome(quarantinePersisted, stopSucceeded, stoppedStatePersisted)
    }
}

/** Generation + service-session + authority identity fence for one exact coroutine timer. */
class RuntimeAuthorityWatchdogFence {
    data class Token internal constructor(
        internal val generation: ULong,
        val serviceSessionId: Long,
        val catalogRevision: ULong,
        val hardDeadline: Instant,
    )

    private var generation = 0uL
    private var current: Token? = null

    @Synchronized
    fun arm(serviceSessionId: Long, authority: RuntimeAuthority): Token {
        generation = next(generation)
        return Token(generation, serviceSessionId, authority.catalogRevision,
                     authority.hardDeadline).also { current = it }
    }

    @Synchronized
    fun cancel() {
        generation = next(generation)
        current = null
    }

    @Synchronized
    fun consume(token: Token): Boolean {
        if (current != token) return false
        generation = next(generation)
        current = null
        return true
    }

    private fun next(value: ULong): ULong = if (value == ULong.MAX_VALUE) 1uL else value + 1uL
}
