package org.amnezia.vpn.protocol.xray

internal enum class XrayNativeLegFailure {
    RETURNED_ERROR,
    THREW,
}

internal data class XrayNativeLegReceipt(
    val proven: Boolean,
    val failure: XrayNativeLegFailure? = null,
)

internal data class XrayNativeTeardownReceipt(
    val controllers: XrayNativeLegReceipt,
    val adapter: XrayNativeLegReceipt,
    val core: XrayNativeLegReceipt,
) {
    val proven: Boolean
        get() = controllers.proven && adapter.proven && core.proven
}

/** Every native teardown leg is attempted exactly once even when an earlier JNI call throws. */
internal object XrayNativeTeardown {
    fun execute(
        clearControllers: () -> String?,
        stopAdapter: () -> String?,
        stopCore: () -> String?,
    ): XrayNativeTeardownReceipt {
        val controllers = executeLeg(clearControllers)
        val adapter = executeLeg(stopAdapter)
        val core = executeLeg(stopCore)
        return XrayNativeTeardownReceipt(controllers, adapter, core)
    }

    private fun executeLeg(operation: () -> String?): XrayNativeLegReceipt = try {
        if (operation().isNullOrBlank()) {
            XrayNativeLegReceipt(proven = true)
        } else {
            XrayNativeLegReceipt(proven = false, XrayNativeLegFailure.RETURNED_ERROR)
        }
    } catch (_: Throwable) {
        XrayNativeLegReceipt(proven = false, XrayNativeLegFailure.THREW)
    }
}
