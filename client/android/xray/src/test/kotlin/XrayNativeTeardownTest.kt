package org.amnezia.vpn.protocol.xray

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class XrayNativeTeardownTest {
    @Test
    fun allThreeLegsRunInFailClosedOrder() {
        val trace = mutableListOf<String>()
        val receipt = XrayNativeTeardown.execute(
            clearControllers = { trace += "clear"; null },
            stopAdapter = { trace += "adapter"; "adapter_error" },
            stopCore = { trace += "core"; null },
        )

        assertEquals(listOf("clear", "adapter", "core"), trace)
        assertTrue(receipt.controllers.proven)
        assertEquals(XrayNativeLegFailure.RETURNED_ERROR, receipt.adapter.failure)
        assertTrue(receipt.core.proven)
        assertFalse(receipt.proven)
    }

    @Test
    fun thrownLegsCannotSkipLaterNativeCleanup() {
        val trace = mutableListOf<String>()
        val receipt = XrayNativeTeardown.execute(
            clearControllers = {
                trace += "clear"
                throw IllegalStateException("clear JNI failure injection")
            },
            stopAdapter = {
                trace += "adapter"
                throw IllegalStateException("adapter JNI failure injection")
            },
            stopCore = { trace += "core"; "core_error" },
        )

        assertEquals(listOf("clear", "adapter", "core"), trace)
        assertEquals(XrayNativeLegFailure.THREW, receipt.controllers.failure)
        assertEquals(XrayNativeLegFailure.THREW, receipt.adapter.failure)
        assertEquals(XrayNativeLegFailure.RETURNED_ERROR, receipt.core.failure)
        assertFalse(receipt.proven)
    }
}
