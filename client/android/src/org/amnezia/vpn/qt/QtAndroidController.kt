package org.amnezia.vpn.qt

import org.amnezia.vpn.protocol.ProtocolState
import org.amnezia.vpn.protocol.Status

/**
 * JNI functions of the AndroidController class from android_controller.cpp,
 * called by events in the Android part of the client
 */
object QtAndroidController {

    fun onStatus(status: Status) = onStatus(status.state)
    fun onStatus(protocolState: ProtocolState) = onStatus(protocolState.ordinal)

    external fun onStatus(stateCode: Int)
    external fun onServiceDisconnected()
    external fun onServiceError()

    external fun onVpnPermissionRejected()
    external fun onNotificationStateChanged()
    external fun onVpnStateChanged(stateCode: Int)
    external fun onStatisticsUpdate(rxBytes: Long, txBytes: Long, lastHandshakeSec: Long) // AVPN: + handshake
    external fun onRuntimeStatus(json: String) // AVPN: tunnel_runtime_status_v1.
    external fun onEngineManifest(json: String) // AVPN: both embedded engines, schema v1.
    external fun onSessionGuardEvent(json: String)
    external fun onSessionGuardRecoveryReceipt(json: String)
    external fun onRuntimeAuthorityRenewalReceipt(json: String)

    external fun onFileOpened(uri: String)

    external fun onConfigImported(data: String)

    external fun onAuthResult(result: Boolean)

    external fun decodeQrCode(data: String): Boolean

    external fun onImeInsetsChanged(heightDp: Int)
    external fun onSystemBarsInsetsChanged(navBarHeightDp: Int, statusBarHeightDp: Int)

    external fun onActivityPaused()
    external fun onActivityResumed()
}
