package org.amnezia.vpn

import java.util.UUID
import org.json.JSONObject

/** Closed, bearer-free IPC contract between the C++ reducer and the single TribeVpnService. */
object NativeSessionGuardContract {
    const val TYPE = "native_session_guard_v1"
    const val SCHEMA = 1

    const val MSG_OPERATION = "NATIVE_GUARD_OPERATION_V1"
    const val MSG_SESSION = "NATIVE_GUARD_SESSION_V1"
    const val MSG_POLICY_SHA256 = "NATIVE_GUARD_POLICY_SHA256_V1"
    const val MSG_OUTER_SESSION_ID = "NATIVE_GUARD_OUTER_SESSION_ID_V1"
    const val MSG_EXPECTED_RUNTIME_SESSION_ID = "NATIVE_GUARD_EXPECTED_RUNTIME_SESSION_ID_V1"
    const val MSG_EVENT_JSON = "NATIVE_GUARD_EVENT_JSON_V1"
    const val MSG_RECOVERY_ACTION = "NATIVE_GUARD_RECOVERY_ACTION_V1"
    const val MSG_RECOVERY_RECEIPT_JSON = "NATIVE_GUARD_RECOVERY_RECEIPT_JSON_V1"

    const val ACTION_PREPARE = "org.amnezia.vpn.action.prepare_native_session_guard.v1"
    const val ACTION_ACTIVATE = "org.amnezia.vpn.action.activate_native_session.v1"
    const val ACTION_STOP_INNER = "org.amnezia.vpn.action.stop_native_session.v1"
    const val ACTION_RELEASE = "org.amnezia.vpn.action.release_native_session_guard.v1"
    const val ACTION_RECONCILE_ARM =
        "org.amnezia.vpn.action.reconcile_native_session_guard_arm.v1"
    const val ACTION_RECONCILE_RELEASE =
        "org.amnezia.vpn.action.reconcile_native_session_guard_release.v1"
    const val ACTION_RECOVERY_STATUS = "org.amnezia.vpn.action.native_session_guard_recovery_status.v1"
    const val ACTION_RECOVERY_RESOLVE = "org.amnezia.vpn.action.native_session_guard_recovery_resolve.v1"

    data class RequestIdentity(
        val operation: String,
        val session: String,
        val expectedRuntimeSessionId: String,
    ) {
        init {
            require(isCanonicalCounter(operation)) { "Invalid native guard operation" }
            require(isCanonicalCounter(session)) { "Invalid native guard session" }
            require(isCanonicalUuid(expectedRuntimeSessionId)) {
                "Invalid expected native runtime session identity"
            }
        }
    }

    fun requirePolicySha256(value: String): String = value.also {
        require(it.length == 64 && it.all { c -> c in '0'..'9' || c in 'a'..'f' }) {
            "Invalid native dispatch policy digest"
        }
    }

    fun requireOuterSessionId(value: String): String = value.also {
        require(it.isNotBlank() && it.length <= 200 && it.all { c ->
            c in 'a'..'z' || c in 'A'..'Z' || c in '0'..'9' ||
                c == '-' || c == '_' || c == ':' || c == '.'
        }) { "Invalid outer VPN session identity" }
    }

    fun eventJson(
        identity: RequestIdentity,
        kind: String,
        policySha256: String,
        outerSessionId: String = "",
        reason: String = "",
    ): String = JSONObject(eventFields(
        identity, kind, policySha256, outerSessionId, reason,
    )).toString()

    fun parseEvent(value: String): Map<String, String> {
        val root = JSONObject(value)
        val keys = root.keys().asSequence().toSet()
        return parseEventFields(keys.associateWith(root::get))
    }

    internal fun parseEventFields(root: Map<String, Any?>): Map<String, String> {
        require(root.keys == setOf(
            "type", "schema", "operation", "session", "kind", "policy_sha256",
            "outer_session_id", "expected_runtime_session_id", "reason",
        )) { "Invalid native guard event shape" }
        val schema = root["schema"]
        require(root["type"] == TYPE && schema is Int && schema == SCHEMA) {
            "Invalid native guard event schema"
        }
        val identity = RequestIdentity(
            root["operation"] as? String ?: "", root["session"] as? String ?: "",
            root["expected_runtime_session_id"] as? String ?: "",
        )
        val kind = root["kind"] as? String ?: ""
        val policy = requirePolicySha256(root["policy_sha256"] as? String ?: "")
        val outer = root["outer_session_id"] as? String ?: ""
        val reason = root["reason"] as? String ?: ""
        // Reuse the producer validation, including kind/owner/reason constraints.
        eventFields(identity, kind, policy, outer, reason)
        return linkedMapOf(
            "operation" to identity.operation,
            "session" to identity.session,
            "kind" to kind,
            "policy_sha256" to policy,
            "outer_session_id" to outer,
            "expected_runtime_session_id" to identity.expectedRuntimeSessionId,
            "reason" to reason,
        )
    }

    fun recoveryReceiptJson(
        identity: RequestIdentity,
        action: String,
        kind: String,
        policySha256: String,
        outerSessionId: String,
        reason: String = "",
    ): String = JSONObject(recoveryReceiptFields(
        identity, action, kind, policySha256, outerSessionId, reason,
    )).toString()

    internal fun recoveryReceiptFields(
        identity: RequestIdentity,
        action: String,
        kind: String,
        policySha256: String,
        outerSessionId: String,
        reason: String = "",
    ): Map<String, Any> {
        require((action == "adopt" && kind in setOf("adopted", "rejected"))
            || (action == "stop" && kind in setOf("stopped_released", "rejected"))) {
            "Invalid native guard recovery result"
        }
        requirePolicySha256(policySha256)
        requireOuterSessionId(outerSessionId)
        require(reason.length <= 96 && reason.all { it.code in 0x20..0x7e }) {
            "Invalid native guard recovery reason"
        }
        return linkedMapOf(
            "type" to "native_session_guard_recovery_v1",
            "schema" to SCHEMA,
            "action" to action,
            "kind" to kind,
            "operation" to identity.operation,
            "session" to identity.session,
            "policy_sha256" to policySha256,
            "outer_session_id" to outerSessionId,
            "expected_runtime_session_id" to identity.expectedRuntimeSessionId,
            "reason" to reason,
        )
    }

    internal fun eventFields(
        identity: RequestIdentity,
        kind: String,
        policySha256: String,
        outerSessionId: String = "",
        reason: String = "",
    ): Map<String, Any> {
        require(kind in setOf(
            "armed", "arm_rejected", "released", "release_rejected", "lost",
        )) { "Invalid native guard event kind" }
        requirePolicySha256(policySha256)
        require(reason.length <= 96 && reason.all { it.code in 0x20..0x7e }) {
            "Invalid native guard reason"
        }
        if (kind == "armed" || kind == "released" || kind == "lost") {
            requireOuterSessionId(outerSessionId)
        } else {
            require(outerSessionId.isEmpty() || runCatching {
                requireOuterSessionId(outerSessionId)
            }.isSuccess) { "Invalid rejected guard owner" }
        }
        return linkedMapOf(
            "type" to TYPE,
            "schema" to SCHEMA,
            "operation" to identity.operation,
            "session" to identity.session,
            "kind" to kind,
            "policy_sha256" to policySha256,
            "outer_session_id" to outerSessionId,
            "expected_runtime_session_id" to identity.expectedRuntimeSessionId,
            "reason" to reason,
        )
    }

    fun isCanonicalCounter(value: String): Boolean =
        value.length in 1..20
            && value.firstOrNull() in '1'..'9'
            && value.all { it in '0'..'9' }
            && value.toULongOrNull() != null

    fun isCanonicalUuid(value: String): Boolean = runCatching {
        value.length == 36 && value == value.lowercase()
            && UUID.fromString(value).toString() == value
    }.getOrDefault(false)
}
