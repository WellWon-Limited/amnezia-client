package org.amnezia.vpn

/**
 * Bounded bearer-free ledger for exact timeout reconciliation.
 *
 * A timeout never cancels a platform command.  The service records only two facts that can safely
 * be replayed: an exact PREPARE was fenced before it acquired ownership, or an exact RELEASE was
 * durably committed.  Missing/mismatched entries remain ambiguous and therefore produce no
 * terminal receipt.
 */
class NativeGuardReconciliationJournal(
    records: List<Record> = emptyList(),
    private val capacity: Int = MAX_RECORDS,
) {
    enum class Outcome(val wireValue: String) {
        ARM_REJECTED("arm_rejected"),
        RELEASED("released");

        companion object {
            fun fromWireValue(value: String): Outcome = entries.single { it.wireValue == value }
        }
    }

    data class Record(
        val operation: String,
        val session: String,
        val policySha256: String,
        val outerSessionId: String,
        val expectedRuntimeSessionId: String,
        val outcome: Outcome,
    ) {
        init {
            NativeSessionGuardContract.RequestIdentity(
                operation, session, expectedRuntimeSessionId,
            )
            NativeSessionGuardContract.requirePolicySha256(policySha256)
            NativeSessionGuardContract.requireOuterSessionId(outerSessionId)
        }

        fun identity(): NativeSessionGuardContract.RequestIdentity =
            NativeSessionGuardContract.RequestIdentity(
                operation, session, expectedRuntimeSessionId,
            )

        private fun key(): String = listOf(
            operation, session, policySha256, outerSessionId, expectedRuntimeSessionId,
        ).joinToString("\u0000")

        fun sameIdentity(other: Record): Boolean = key() == other.key()
    }

    private val entries = ArrayDeque<Record>()

    init {
        require(capacity in 1..MAX_RECORDS) { "Invalid guard reconciliation capacity" }
        require(records.size <= capacity) { "Oversized guard reconciliation journal" }
        records.forEach(::remember)
        require(entries.size == records.size) { "Duplicate guard reconciliation identity" }
    }

    fun rememberArmRejected(
        identity: NativeSessionGuardContract.RequestIdentity,
        policySha256: String,
        outerSessionId: String,
    ) = remember(record(identity, policySha256, outerSessionId, Outcome.ARM_REJECTED))

    fun rememberReleased(
        identity: NativeSessionGuardContract.RequestIdentity,
        policySha256: String,
        outerSessionId: String,
    ) = remember(record(identity, policySha256, outerSessionId, Outcome.RELEASED))

    fun outcome(
        identity: NativeSessionGuardContract.RequestIdentity,
        policySha256: String,
        outerSessionId: String,
    ): Outcome? {
        val candidate = record(identity, policySha256, outerSessionId, Outcome.ARM_REJECTED)
        return entries.firstOrNull(candidate::sameIdentity)?.outcome
    }

    fun blocksPrepare(
        identity: NativeSessionGuardContract.RequestIdentity,
        policySha256: String,
        outerSessionId: String,
    ): Boolean = outcome(identity, policySha256, outerSessionId) != null

    fun blocksActivation(
        identity: NativeSessionGuardContract.RequestIdentity,
        outerSessionId: String,
    ): Boolean = entries.any {
        it.outcome == Outcome.ARM_REJECTED
            && it.operation == identity.operation
            && it.session == identity.session
            && it.outerSessionId == outerSessionId
            && it.expectedRuntimeSessionId == identity.expectedRuntimeSessionId
    }

    fun snapshot(): List<Record> = entries.toList()

    private fun remember(record: Record) {
        entries.removeAll(record::sameIdentity)
        while (entries.size >= capacity) entries.removeFirst()
        entries.addLast(record)
    }

    private fun record(
        identity: NativeSessionGuardContract.RequestIdentity,
        policySha256: String,
        outerSessionId: String,
        outcome: Outcome,
    ) = Record(
        identity.operation,
        identity.session,
        policySha256,
        outerSessionId,
        identity.expectedRuntimeSessionId,
        outcome,
    )

    companion object {
        const val MAX_RECORDS = 16
    }
}
