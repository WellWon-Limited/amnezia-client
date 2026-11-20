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
    // AVPN (Android permission prompt): 0 = the system "allow VPN configuration" dialog is on screen, 1 = closed and
    // granted, 2 = closed, denied or cancelled. Registered by AndroidController::initialize as an optional native.
    external fun onVpnPermissionPrompt(state: Int)
    // AVPN (local build): the VPN service builds the tunnel interface of its start number `seq` (state 0) or has built
    // it (1). Registered by AndroidController::initialize as an optional native.
    external fun onTunnelBuild(state: Int, seq: Int)
    external fun onNotificationStateChanged()
    external fun onVpnStateChanged(stateCode: Int)
    external fun onStatisticsUpdate(rxBytes: Long, txBytes: Long, lastHandshakeSec: Long) // AVPN: + handshake
    // AVPN (upstream nodes, android-ipc-contract.md section 3): {"upstream":{...}} of the Xray service,
    // registered by AndroidController::initialize as "(Ljava/lang/String;)V".
    external fun onUpstreamStatus(json: String)
    // AVPN (Scanner, lane A3): the probe host's reply to request `id`, and its state {"open","gen"}; registered by
    // AndroidController::initialize as "(JLjava/lang/String;)V" / "(Ljava/lang/String;)V", optional natives.
    external fun onScanReply(id: Long, reply: String)
    external fun onScanHostState(json: String)

    external fun onFileOpened(uri: String)

    external fun onConfigImported(data: String)

    external fun onAuthResult(result: Boolean)

    external fun decodeQrCode(data: String): Boolean

    external fun onImeInsetsChanged(heightDp: Int)
    external fun onSystemBarsInsetsChanged(navBarHeightDp: Int, statusBarHeightDp: Int)

    external fun onActivityPaused()
    external fun onActivityResumed()
}