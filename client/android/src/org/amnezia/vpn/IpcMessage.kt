package org.amnezia.vpn

import org.amnezia.vpn.util.TribeStart
import android.os.Bundle
import android.os.Message
import kotlin.enums.enumEntries

sealed interface IpcMessage {
    companion object {
        @OptIn(ExperimentalStdlibApi::class)
        inline fun <reified T> extractFromMessage(msg: Message): T
            where T : Enum<T>,
                  T : IpcMessage {
            val values = enumEntries<T>()
            if (msg.what !in values.indices) {
                throw IllegalArgumentException("IPC action or event not found for the message: $msg")
            }
            return values[msg.what]
        }
    }
}

// Both enums are ordinal-coded (Message.what = ordinal): never reorder, append only.
enum class ServiceEvent : IpcMessage {
    STATUS_CHANGED,
    STATUS,
    STATISTICS_UPDATE,
    ERROR,
    // AVPN (upstream nodes, android-ipc-contract.md section 3): {"upstream":{contract section 5}} in
    // MSG_UPSTREAM_STATUS; only for a session with tribeSessionMetadata.upstream == 1.
    UPSTREAM_STATUS,
    // AVPN (Scanner, lane A3): the engine's reply to one Action.SCAN_MESSAGE - MSG_SCAN_ID (the request's id, the
    // reply is bound to it) + MSG_SCAN_REPLY (tribe-scan-v1 JSON, relayed unchanged by the app).
    SCAN_REPLY,
    // AVPN (Scanner, lane A3): the Xray service's probe host {"open":bool,"gen":{...}} in MSG_SCAN_STATE; on every
    // change and after STATUS; Xray sessions only.
    SCAN_HOST_STATE,
    // AVPN (local build, emulator round 20.11): the service builds the tunnel interface of a start (MSG_TUNNEL_BUILD_STATE
    // TUNNEL_BUILDING, from the start command) or has built it (TUNNEL_BUILT: establish() returned and the backend runs),
    // or the start ended without a tunnel (TUNNEL_NOT_STARTED, android2 V2); MSG_TUNNEL_BUILD_SEQ numbers the starts,
    // MSG_TUNNEL_BUILD_LEG is the engine leg the start config named (TribeStart.legOf, 0 = none). To every client; a
    // client that registers during a build gets TUNNEL_BUILDING at once.
    TUNNEL_BUILD
}

enum class Action : IpcMessage {
    REGISTER_CLIENT,
    UNREGISTER_CLIENT,
    CONNECT,
    DISCONNECT,
    REQUEST_STATUS,
    NOTIFICATION_PERMISSION_GRANTED,
    SET_SAVE_LOGS,
    // AVPN (upstream nodes, android-ipc-contract.md section 2): the app's late seat hand-over, the iOS
    // provider message {"action":"upstream_lease_set","upstream_lease":{...}} verbatim in
    // MSG_UPSTREAM_LEASE_SET; always answered with UPSTREAM_STATUS to replyTo.
    UPSTREAM_LEASE_SET,
    // AVPN (Scanner, lane A3): one tribe-scan-v1 message of the app (MSG_SCAN_ID, MSG_SCAN_REQUEST); always answered
    // with ServiceEvent.SCAN_REPLY carrying the same id, to replyTo.
    SCAN_MESSAGE
}

// AVPN (upstream nodes, android-ipc-contract.md sections 2-3): Bundle string keys.
const val MSG_UPSTREAM_LEASE_SET = "UPSTREAM_LEASE_SET"
const val MSG_UPSTREAM_STATUS = "UPSTREAM_STATUS"

// AVPN (Scanner, lane A3): Bundle keys of SCAN_MESSAGE / SCAN_REPLY / SCAN_HOST_STATE.
const val MSG_SCAN_ID = "SCAN_ID"
const val MSG_SCAN_REQUEST = "SCAN_REQUEST"
const val MSG_SCAN_REPLY = "SCAN_REPLY"
const val MSG_SCAN_STATE = "SCAN_STATE"

// AVPN (local build): Bundle keys and states of TUNNEL_BUILD (the states are QtAndroidController.onTunnelBuild's).
const val MSG_TUNNEL_BUILD_STATE = "TUNNEL_BUILD_STATE"
const val MSG_TUNNEL_BUILD_SEQ = "TUNNEL_BUILD_SEQ"
const val MSG_TUNNEL_BUILD_LEG = "TUNNEL_BUILD_LEG"

// AVPN (android2 P7): STATUS / STATUS_CHANGED carry the tribeSessionMetadata of the session the service runs (JSON,
// absent when it has none); the activity hands it to C++ before the state (QtAndroidController.onSessionMetadata).
const val MSG_SESSION_METADATA = "SESSION_METADATA"
const val TUNNEL_BUILDING = TribeStart.BUILDING
const val TUNNEL_BUILT = TribeStart.BUILT
const val TUNNEL_NOT_STARTED = TribeStart.NOT_STARTED

fun <T> T.packToMessage(): Message
    where T : Enum<T>, T : IpcMessage = Message.obtain().also { it.what = ordinal }

fun <T> T.packToMessage(block: Bundle.() -> Unit): Message
    where T : Enum<T>, T : IpcMessage = packToMessage().also { it.data = Bundle().apply(block) }

inline fun <reified T> Message.extractIpcMessage(): T
    where T : Enum<T>, T : IpcMessage = IpcMessage.extractFromMessage<T>(this)
