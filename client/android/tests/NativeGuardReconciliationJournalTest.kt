package org.amnezia.vpn

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

class NativeGuardReconciliationJournalTest {
    private val policy = "a".repeat(64)
    private val outer = "android:123e4567-e89b-42d3-a456-426614174001"

    private fun identity(index: Int) = NativeSessionGuardContract.RequestIdentity(
        index.toString(),
        (index + 100).toString(),
        "123e4567-e89b-42d3-a456-${index.toString().padStart(12, '0')}",
    )

    @Test
    fun onlyExactArmTombstoneBlocksLatePrepareAndActivation() {
        val journal = NativeGuardReconciliationJournal()
        val exact = identity(1)
        journal.rememberArmRejected(exact, policy, outer)
        assertTrue(journal.blocksPrepare(exact, policy, outer))
        assertTrue(journal.blocksActivation(exact, outer))
        assertFalse(journal.blocksPrepare(identity(2), policy, outer))
        assertFalse(journal.blocksPrepare(exact, "b".repeat(64), outer))
        assertFalse(journal.blocksPrepare(exact, policy, "$outer-other"))
    }

    @Test
    fun releaseProofRequiresExactDurableIdentity() {
        val journal = NativeGuardReconciliationJournal()
        val exact = identity(3)
        assertNull(journal.outcome(exact, policy, outer))
        journal.rememberReleased(exact, policy, outer)
        assertEquals(
            NativeGuardReconciliationJournal.Outcome.RELEASED,
            journal.outcome(exact, policy, outer),
        )
        assertNull(journal.outcome(identity(4), policy, outer))
        assertNull(journal.outcome(exact, policy, "$outer-other"))
    }

    @Test
    fun journalIsBoundedNewestFirstAndRejectsDuplicateRestore() {
        val journal = NativeGuardReconciliationJournal(capacity = 2)
        journal.rememberArmRejected(identity(1), policy, outer)
        journal.rememberReleased(identity(2), policy, outer)
        journal.rememberReleased(identity(3), policy, outer)
        assertEquals(listOf("2", "3"), journal.snapshot().map { it.operation })

        val duplicate = journal.snapshot().first()
        assertFailsWith<IllegalArgumentException> {
            NativeGuardReconciliationJournal(listOf(duplicate, duplicate))
        }
    }
}
