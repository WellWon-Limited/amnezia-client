package org.amnezia.vpn

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.UUID
import org.json.JSONObject

/** Exact, bearer-free request/receipt contract for renewing one live catalog-v2 authority. */
object RuntimeAuthorityRenewalContract {
    const val REQUEST_TYPE = "runtime_authority_renewal_request_v1"
    const val RECEIPT_TYPE = "runtime_authority_renewal_v1"
    const val SCHEMA = 1

    const val MSG_REQUEST_JSON = "RUNTIME_AUTHORITY_RENEWAL_REQUEST_JSON_V1"
    const val MSG_RECEIPT_JSON = "RUNTIME_AUTHORITY_RENEWAL_RECEIPT_JSON_V1"

    private val deadlineFormatter = DateTimeFormatter
        .ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
        .withZone(ZoneOffset.UTC)

    private val requestKeys = setOf(
        "type", "schema", "operation", "session", "renewal_id", "policy_sha256",
        "outer_session_id", "expected_runtime_session_id", "config_generation",
        "binding_generation", "catalog_revision", "catalog_payload_sha256",
        "authority_commitment_sha256", "hard_deadline",
    )
    private val receiptKeys = requestKeys + setOf("kind", "reason")

    data class Request(
        val operation: String,
        val session: String,
        val renewalId: String,
        val policySha256: String,
        val outerSessionId: String,
        val expectedRuntimeSessionId: String,
        val configGeneration: String,
        val bindingGeneration: String,
        val catalogRevision: String,
        val catalogPayloadSha256: String,
        val authorityCommitmentSha256: String,
        val hardDeadline: String,
    ) {
        fun fields(): Map<String, Any> = linkedMapOf(
            "type" to REQUEST_TYPE,
            "schema" to SCHEMA,
            "operation" to operation,
            "session" to session,
            "renewal_id" to renewalId,
            "policy_sha256" to policySha256,
            "outer_session_id" to outerSessionId,
            "expected_runtime_session_id" to expectedRuntimeSessionId,
            "config_generation" to configGeneration,
            "binding_generation" to bindingGeneration,
            "catalog_revision" to catalogRevision,
            "catalog_payload_sha256" to catalogPayloadSha256,
            "authority_commitment_sha256" to authorityCommitmentSha256,
            "hard_deadline" to hardDeadline,
        )

        fun json(): String = JSONObject(fields()).toString()
    }

    data class Receipt(
        val kind: String,
        val request: Request,
        val hardDeadline: String,
        val reason: String,
    ) {
        fun fields(): Map<String, Any> = linkedMapOf(
            "type" to RECEIPT_TYPE,
            "schema" to SCHEMA,
            "kind" to kind,
            "operation" to request.operation,
            "session" to request.session,
            "renewal_id" to request.renewalId,
            "policy_sha256" to request.policySha256,
            "outer_session_id" to request.outerSessionId,
            "expected_runtime_session_id" to request.expectedRuntimeSessionId,
            "config_generation" to request.configGeneration,
            "binding_generation" to request.bindingGeneration,
            "catalog_revision" to request.catalogRevision,
            "catalog_payload_sha256" to request.catalogPayloadSha256,
            "authority_commitment_sha256" to request.authorityCommitmentSha256,
            "hard_deadline" to hardDeadline,
            "reason" to reason,
        )

        fun json(): String = JSONObject(fields()).toString()
    }

    fun requestFromConfig(
        config: JSONObject,
        serializedConfig: String,
        operation: String,
        session: String,
        outerSessionId: String,
        expectedRuntimeSessionId: String,
        renewalId: String,
        expectedCommitmentSha256: String,
    ): Request {
        val authority = RuntimeAuthority.fromConfig(config)
            ?: throw IllegalArgumentException("Runtime authority missing")
        val commitment = authorityCommitmentSha256(serializedConfig)
        require(commitment == expectedCommitmentSha256) {
            "Runtime authority commitment mismatch"
        }
        return validatedRequest(Request(
            operation = operation,
            session = session,
            renewalId = renewalId,
            policySha256 = authority.dispatchPolicySha256,
            outerSessionId = outerSessionId,
            expectedRuntimeSessionId = expectedRuntimeSessionId,
            configGeneration = authority.configGeneration.toString(),
            bindingGeneration = authority.bindingGeneration.toString(),
            catalogRevision = authority.catalogRevision.toString(),
            catalogPayloadSha256 = authority.catalogPayloadSha256,
            authorityCommitmentSha256 = commitment,
            hardDeadline = formatDeadline(authority.hardDeadline),
        ))
    }

    fun parseRequest(json: String): Request {
        val root = JSONObject(json)
        require(root.keys().asSequence().toSet() == requestKeys) {
            "Runtime authority renewal request shape mismatch"
        }
        require(root.opt("schema") is Number
            && (root.opt("schema") as Number).toDouble() == 1.0
            && (root.opt("schema") as Number).toLong() == 1L
            && root.getString("type") == REQUEST_TYPE) {
            "Runtime authority renewal request version mismatch"
        }
        return validatedRequest(Request(
            root.getString("operation"),
            root.getString("session"),
            root.getString("renewal_id"),
            root.getString("policy_sha256"),
            root.getString("outer_session_id"),
            root.getString("expected_runtime_session_id"),
            root.getString("config_generation"),
            root.getString("binding_generation"),
            root.getString("catalog_revision"),
            root.getString("catalog_payload_sha256"),
            root.getString("authority_commitment_sha256"),
            root.getString("hard_deadline"),
        ))
    }

    fun applied(request: Request): Receipt = Receipt(
        kind = "applied", request = request, hardDeadline = request.hardDeadline, reason = "",
    )

    fun rejected(request: Request, reason: String): Receipt {
        require(safeReason(reason) && reason.isNotEmpty()) { "Invalid renewal rejection reason" }
        return Receipt(kind = "rejected", request = request, hardDeadline = "", reason = reason)
    }

    fun parseReceipt(json: String): Receipt {
        val root = JSONObject(json)
        require(root.keys().asSequence().toSet() == receiptKeys) {
            "Runtime authority renewal receipt shape mismatch"
        }
        require(root.opt("schema") is Number
            && (root.opt("schema") as Number).toDouble() == 1.0
            && (root.opt("schema") as Number).toLong() == 1L
            && root.getString("type") == RECEIPT_TYPE) {
            "Runtime authority renewal receipt version mismatch"
        }
        val request = validatedRequest(Request(
            root.getString("operation"), root.getString("session"),
            root.getString("renewal_id"), root.getString("policy_sha256"),
            root.getString("outer_session_id"), root.getString("expected_runtime_session_id"),
            root.getString("config_generation"), root.getString("binding_generation"),
            root.getString("catalog_revision"), root.getString("catalog_payload_sha256"),
            root.getString("authority_commitment_sha256"),
            // Rejected receipts deliberately carry no renewed deadline. Validate the remaining
            // identity first and validate the result-specific deadline below.
            root.getString("hard_deadline"),
        ), validateDeadline = root.getString("hard_deadline").isNotEmpty())
        val kind = root.getString("kind")
        val reason = root.getString("reason")
        val hardDeadline = root.getString("hard_deadline")
        require((kind == "applied" && reason.isEmpty()
            && hardDeadline == request.hardDeadline)
            || (kind == "rejected" && hardDeadline.isEmpty()
                && reason.isNotEmpty() && safeReason(reason))) {
            "Invalid runtime authority renewal result"
        }
        return Receipt(kind, request, hardDeadline, reason)
    }

    fun receiptMatchesRequest(receipt: Receipt, expected: Request): Boolean =
        receipt.request.copy(hardDeadline = expected.hardDeadline) == expected
            && (receipt.kind != "applied" || receipt.hardDeadline == expected.hardDeadline)

    /** The caller updates live memory only if the durable write completed without throwing. */
    internal inline fun <T> commitPersistFirst(
        replacement: T,
        persist: (T) -> Unit,
        commit: (T) -> Unit,
    ) {
        persist(replacement)
        commit(replacement)
    }

    /** SHA-256 over the exact UTF-8 config bytes dispatched by QJsonDocument, before JSON parsing. */
    fun authorityCommitmentSha256(serializedConfig: String): String =
        MessageDigest.getInstance("SHA-256")
            .digest(serializedConfig.toByteArray(StandardCharsets.UTF_8))
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }

    fun formatDeadline(value: Instant): String = deadlineFormatter.format(value)

    private fun validatedRequest(request: Request, validateDeadline: Boolean = true): Request {
        require(canonicalCounter(request.operation) && canonicalCounter(request.session))
        require(canonicalUuid(request.renewalId)
            && canonicalUuid(request.expectedRuntimeSessionId))
        require(safeOuter(request.outerSessionId))
        require(sha256(request.policySha256) && sha256(request.catalogPayloadSha256)
            && sha256(request.authorityCommitmentSha256))
        require(canonicalGeneration(request.configGeneration)
            && canonicalGeneration(request.bindingGeneration)
            && canonicalGeneration(request.catalogRevision))
        if (validateDeadline) require(canonicalDeadline(request.hardDeadline))
        return request
    }

    private fun canonicalCounter(value: String): Boolean =
        value.length in 1..20 && value.firstOrNull() in '1'..'9'
            && value.all { it in '0'..'9' } && value.toULongOrNull() != null

    private fun canonicalGeneration(value: String): Boolean =
        value.length in 1..20 && (value == "0" || value.firstOrNull() in '1'..'9')
            && value.all { it in '0'..'9' } && value.toULongOrNull() != null

    private fun canonicalUuid(value: String): Boolean = runCatching {
        value.length == 36 && value == value.lowercase()
            && UUID.fromString(value).toString() == value
    }.getOrDefault(false)

    private fun sha256(value: String): Boolean =
        value.length == 64 && value.all { it in '0'..'9' || it in 'a'..'f' }

    private fun safeOuter(value: String): Boolean = value.length in 1..200 && value.all {
        it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9'
            || it == '-' || it == '_' || it == ':' || it == '.'
    }

    private fun safeReason(value: String): Boolean =
        value.length <= 96 && value.all { it.code in 0x20..0x7e }

    private fun canonicalDeadline(value: String): Boolean = runCatching {
        value.length == 24 && formatDeadline(Instant.parse(value)) == value
    }.getOrDefault(false)
}
