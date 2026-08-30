package org.amnezia.vpn

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

enum class ServiceEvent : IpcMessage {
    STATUS_CHANGED,
    STATUS,
    STATISTICS_UPDATE,
    ERROR,
    NATIVE_SESSION_GUARD,
    NATIVE_SESSION_GUARD_RECOVERY,
    // Append-only ABI: an older Activity rejects this ordinal instead of decoding another event.
    RUNTIME_AUTHORITY_RENEWAL
}

enum class Action : IpcMessage {
    REGISTER_CLIENT,
    UNREGISTER_CLIENT,
    CONNECT,
    DISCONNECT,
    REQUEST_STATUS,
    NOTIFICATION_PERMISSION_GRANTED,
    SET_SAVE_LOGS,
    // Additive ordinal: older services reject instead of interpreting it as another operation.
    RENEW_RUNTIME_AUTHORITY,
    PREPARE_NATIVE_SESSION_GUARD,
    RELEASE_NATIVE_SESSION_GUARD,
    ACTIVATE_NATIVE_SESSION,
    STOP_NATIVE_SESSION,
    REQUEST_NATIVE_SESSION_GUARD_RECOVERY,
    RESOLVE_NATIVE_SESSION_GUARD_RECOVERY,
    // Append-only timeout reconciliation ABI. Responses reuse NATIVE_SESSION_GUARD.
    RECONCILE_NATIVE_SESSION_GUARD_ARM,
    RECONCILE_NATIVE_SESSION_GUARD_RELEASE
}

fun <T> T.packToMessage(): Message
    where T : Enum<T>, T : IpcMessage = Message.obtain().also { it.what = ordinal }

fun <T> T.packToMessage(block: Bundle.() -> Unit): Message
    where T : Enum<T>, T : IpcMessage = packToMessage().also { it.data = Bundle().apply(block) }

inline fun <reified T> Message.extractIpcMessage(): T
    where T : Enum<T>, T : IpcMessage = IpcMessage.extractFromMessage<T>(this)
