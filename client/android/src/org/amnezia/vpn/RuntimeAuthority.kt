package org.amnezia.vpn

import android.os.Build
import android.os.SystemClock
import java.io.File
import java.time.DateTimeException
import java.time.Instant
import java.util.Base64
import java.security.MessageDigest
import org.json.JSONArray
import org.json.JSONObject
import org.amnezia.vpn.util.net.parsePublicEndpointLiteral

/**
 * Local, versioned proof that the signed catalog was still authoritative when a native profile
 * was dispatched.  The object is produced by the trusted C++ catalog coordinator; Android never
 * manufactures missing fields and never treats an encrypted profile alone as reconnect authority.
 */
data class RuntimeAuthority(
    val deviceAudience: String,
    val catalogRevision: ULong,
    val catalogPayloadSha256: String,
    val catalogSigningKid: String,
    val catalogSource: String,
    val profileId: String,
    val transport: String,
    val configGeneration: ULong,
    val bindingGeneration: ULong,
    val nativeProfileExpiresAt: Instant,
    val catalogFreshnessDeadline: Instant,
    val entitlementDeadline: Instant,
    val catalogIssuedAt: Instant,
    val trustedUtcAtDispatch: Instant,
    val policySchema: String,
    val dispatchPolicySha256: String,
    val protectedTunnelIps: List<String>,
) {
    val hardDeadline: Instant = minOf(
        nativeProfileExpiresAt,
        catalogFreshnessDeadline,
        entitlementDeadline,
    )

    fun acceptsRenewal(next: RuntimeAuthority, effectiveNow: Instant): Boolean =
        next.deviceAudience == deviceAudience
            && next.profileId == profileId
            && next.transport == transport
            && next.configGeneration == configGeneration
            && next.bindingGeneration == bindingGeneration
            && next.dispatchPolicySha256 == dispatchPolicySha256
            && next.catalogRevision >= catalogRevision
            && (next.catalogRevision != catalogRevision
                || (next.catalogPayloadSha256 == catalogPayloadSha256
                    && next.catalogSigningKid == catalogSigningKid))
            && next.catalogIssuedAt >= catalogIssuedAt
            && next.trustedUtcAtDispatch >= trustedUtcAtDispatch
            // Deadline is revocation authority, not a monotonic high-water mark. Equal, shorter,
            // and longer replacements are valid while the new exact deadline is still current.
            && effectiveNow < next.hardDeadline

    companion object {
        const val ROOT_KEY = "runtime_authority_v1"
        const val ENVELOPE_KEY = "native_envelope_schema"
        const val V2_ENVELOPE = "tribe_catalog_v2_native_v1"
        const val LEGACY_ENVELOPE = "amnezia_legacy_native_v1"
        const val MONOTONIC_POLICY = "anchor_on_validated_dispatch_v1"
        private const val CLOCK_SKEW_SECONDS = 300L
        private val exactKeys = setOf(
            "schema_version",
            "device_audience",
            "catalog_revision",
            "catalog_payload_sha256",
            "catalog_signing_kid",
            "catalog_source",
            "profile_id",
            "transport",
            "config_generation",
            "binding_generation",
            "native_profile_expires_at",
            "catalog_freshness_deadline",
            "entitlement_deadline",
            "catalog_issued_at",
            "trusted_utc_at_dispatch",
            "policy_schema",
            "policy_sha256",
            "protected_tunnel_ips",
            "receiver_monotonic_policy",
        )

        internal enum class EnvelopeClass { LEGACY, CATALOG_V2 }

        internal fun classifyEnvelope(value: Any?, hasAuthority: Boolean): EnvelopeClass = when (value) {
            LEGACY_ENVELOPE -> {
                require(!hasAuthority) { "Legacy VPN envelope contains v2 authority" }
                EnvelopeClass.LEGACY
            }
            V2_ENVELOPE -> {
                require(hasAuthority) { "Catalog-v2 runtime authority was stripped" }
                EnvelopeClass.CATALOG_V2
            }
            else -> throw IllegalArgumentException("VPN native envelope discriminator missing")
        }

        /** Returns null only for a legacy/manual profile with no authority object. */
        fun fromConfig(config: JSONObject): RuntimeAuthority? {
            val envelopeClass = classifyEnvelope(config.opt(ENVELOPE_KEY), config.has(ROOT_KEY))
            if (envelopeClass == EnvelopeClass.LEGACY) return null
            val value = config.opt(ROOT_KEY)
            require(value is JSONObject) { "Runtime authority must be an object" }
            val fields = buildMap<String, Any?> {
                val keys = value.keys()
                while (keys.hasNext()) {
                    val key = keys.next()
                    val fieldValue = value.opt(key)
                    put(key, if (fieldValue is JSONArray) {
                        (0 until fieldValue.length()).map { fieldValue.opt(it) }
                    } else fieldValue)
                }
            }
            val authority = fromFields(fields)
            require(config.optString("protocol", "") == authority.transport) {
                "Runtime authority transport mismatch"
            }
            require(NativeDispatchPolicyDigest.sha256(config, authority)
                == authority.dispatchPolicySha256) {
                "Runtime authority policy digest mismatch"
            }
            return authority
        }

        /** Framework-light entry point used by deterministic host tests. */
        fun fromFields(fields: Map<String, Any?>): RuntimeAuthority {
            require(fields.keys == exactKeys) { "Runtime authority shape mismatch" }
            val schema = fields["schema_version"]
            require(schema is Number && schema.toLong() == 1L && schema.toDouble() == 1.0) {
                "Unsupported runtime authority schema"
            }
            fun string(name: String, maximum: Int = 256): String {
                val value = fields[name] as? String
                    ?: throw IllegalArgumentException("Runtime authority $name must be a string")
                require(value.isNotBlank() && value.length <= maximum && value.indexOf('\u0000') < 0) {
                    "Invalid runtime authority $name"
                }
                return value
            }
            fun generation(name: String): ULong {
                val value = string(name, 20)
                require(value == "0" || (value.first() in '1'..'9'
                    && value.all { it in '0'..'9' })) {
                    "Non-canonical runtime authority $name"
                }
                return value.toULongOrNull()
                    ?: throw IllegalArgumentException("Runtime authority $name overflow")
            }
            fun sha256(name: String): String = string(name, 64).also { value ->
                require(value.length == 64 && value.all { it in '0'..'9' || it in 'a'..'f' }) {
                    "Invalid runtime authority $name"
                }
            }
            fun safeId(name: String, maximum: Int = 128): String = string(name, maximum).also {
                require(it.all { c ->
                    c in 'a'..'z' || c in 'A'..'Z' || c in '0'..'9' ||
                        c == '-' || c == '_' || c == '.'
                }) {
                    "Invalid runtime authority $name"
                }
            }
            fun instant(name: String): Instant {
                val value = string(name, 40)
                require(UTC_INSTANT.matches(value)) { "Runtime authority $name is not canonical UTC" }
                return try {
                    Instant.parse(value)
                } catch (_: DateTimeException) {
                    throw IllegalArgumentException("Invalid runtime authority $name")
                }
            }

            val audience = string("device_audience", 43)
            require(audience.length == 43 && BASE64URL.matches(audience)) {
                "Invalid runtime authority audience"
            }
            val decodedAudience = try {
                Base64.getUrlDecoder().decode("$audience=")
            } catch (_: IllegalArgumentException) {
                throw IllegalArgumentException("Invalid runtime authority audience")
            }
            require(decodedAudience.size == 32) { "Invalid runtime authority audience" }

            val source = string("catalog_source", 7)
            require(source == "network" || source == "lkg") { "Invalid catalog source" }
            val transport = string("transport", 8)
            require(transport == "awg" || transport == "xray") {
                "Invalid runtime authority transport"
            }
            require(string("receiver_monotonic_policy", 64) == MONOTONIC_POLICY) {
                "Unsupported runtime authority clock policy"
            }
            val policySchema = string("policy_schema", 64)
            require(policySchema == NativeDispatchPolicyDigest.SCHEMA) {
                "Unsupported native dispatch policy schema"
            }
            val protectedValue = fields["protected_tunnel_ips"]
            require(protectedValue is List<*> && protectedValue.isNotEmpty()
                && protectedValue.size <= 64) {
                "Invalid protected tunnel IP list"
            }
            val protectedIps = protectedValue.map { item ->
                require(item is String && parsePublicEndpointLiteral(item) != null) {
                    "Invalid protected tunnel IP"
                }
                item
            }
            require(protectedIps.toSet().size == protectedIps.size) {
                "Duplicate protected tunnel IP"
            }

            val nativeDeadline = instant("native_profile_expires_at")
            val freshnessDeadline = instant("catalog_freshness_deadline")
            val entitlementDeadline = instant("entitlement_deadline")
            val issuedAt = instant("catalog_issued_at")
            val trustedAtDispatch = instant("trusted_utc_at_dispatch")
            val hardDeadline = minOf(nativeDeadline, freshnessDeadline, entitlementDeadline)
            require(!hardDeadline.isAfter(entitlementDeadline))
            require(issuedAt <= trustedAtDispatch.plusSeconds(CLOCK_SKEW_SECONDS)) {
                "Runtime authority predates catalog issuance"
            }
            require(trustedAtDispatch < hardDeadline) { "Runtime authority is already expired" }

            return RuntimeAuthority(
                audience,
                generation("catalog_revision"),
                sha256("catalog_payload_sha256"),
                safeId("catalog_signing_kid", 96),
                source,
                safeId("profile_id", 96),
                transport,
                generation("config_generation"),
                generation("binding_generation"),
                nativeDeadline,
                freshnessDeadline,
                entitlementDeadline,
                issuedAt,
                trustedAtDispatch,
                policySchema,
                sha256("policy_sha256"),
                protectedIps,
            )
        }

        /** Exact non-authority configuration identity used by renewal; bearer bytes are hashed. */
        fun configIdentitySha256(config: JSONObject): String {
            val canonical = canonicalJson(config, depth = 0, skipRootAuthority = true)
            return MessageDigest.getInstance("SHA-256")
                .digest(canonical.toByteArray(Charsets.UTF_8))
                .joinToString("") { "%02x".format(it.toInt() and 0xff) }
        }

        private fun canonicalJson(value: Any?, depth: Int, skipRootAuthority: Boolean = false): String {
            require(depth <= 32) { "VPN config nesting is excessive" }
            return when (value) {
                null, JSONObject.NULL -> "null"
                is String -> JSONObject.quote(value)
                is Boolean -> value.toString()
                is Number -> JSONObject.numberToString(value)
                is JSONArray -> buildString {
                    require(value.length() <= 16_384) { "VPN config array is oversized" }
                    append('[')
                    for (index in 0 until value.length()) {
                        if (index != 0) append(',')
                        append(canonicalJson(value.opt(index), depth + 1))
                    }
                    append(']')
                }
                is JSONObject -> buildString {
                    val keys = value.keys().asSequence().toList().sorted()
                        .filterNot { skipRootAuthority && it == ROOT_KEY }
                    require(keys.size <= 16_384) { "VPN config object is oversized" }
                    append('{')
                    keys.forEachIndexed { index, key ->
                        if (index != 0) append(',')
                        append(JSONObject.quote(key)).append(':')
                        append(canonicalJson(value.opt(key), depth + 1))
                    }
                    append('}')
                }
                else -> throw IllegalArgumentException("Unsupported VPN config JSON value")
            }
        }

        private val BASE64URL = Regex("^[A-Za-z0-9_-]{43}$")
        private val UTC_INSTANT = Regex(
            "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d{1,9})?Z$",
        )
    }
}

data class RuntimeAuthorityAnchor(
    val trustedEpochMillis: Long,
    val observedWallMillis: Long,
    val elapsedRealtimeMillis: Long,
    val bootId: String,
) {
    companion object {
        fun capture(authority: RuntimeAuthority): RuntimeAuthorityAnchor {
            val boot = AndroidAuthorityClock.currentBootId()
                ?: throw SecurityException("Runtime authority boot identity unavailable")
            return RuntimeAuthorityAnchor(
                authority.trustedUtcAtDispatch.toEpochMilli(),
                System.currentTimeMillis(),
                SystemClock.elapsedRealtime(),
                boot,
            )
        }

        fun reanchor(
            authority: RuntimeAuthority,
            effectiveNow: Instant,
            observation: RuntimeClockObservation,
        ): RuntimeAuthorityAnchor {
            val boot = observation.bootId
                ?: throw SecurityException("Runtime authority boot identity unavailable")
            require(effectiveNow >= authority.trustedUtcAtDispatch
                && effectiveNow < authority.hardDeadline) { "Invalid runtime authority re-anchor" }
            return RuntimeAuthorityAnchor(
                effectiveNow.toEpochMilli(),
                observation.wallMillis,
                observation.elapsedRealtimeMillis,
                boot,
            )
        }
    }
}

data class RuntimeClockObservation(
    val wallMillis: Long,
    val elapsedRealtimeMillis: Long,
    val bootId: String?,
    /** OS-maintained network time for cross-boot recovery; never app/device wall time. */
    val trustedNetworkMillis: Long? = null,
)

data class RuntimeAuthorityVerdict(
    val accepted: Boolean,
    val effectiveNow: Instant? = null,
    val reason: String = "",
)

object AndroidAuthorityClock {
    private const val CLOCK_ROLLBACK_TOLERANCE_MILLIS = 5 * 60 * 1000L

    fun observe(): RuntimeClockObservation = RuntimeClockObservation(
        System.currentTimeMillis(),
        SystemClock.elapsedRealtime(),
        currentBootId(),
        trustedNetworkTimeMillis(),
    )

    fun evaluate(
        authority: RuntimeAuthority,
        anchor: RuntimeAuthorityAnchor,
        observation: RuntimeClockObservation,
    ): RuntimeAuthorityVerdict {
        val boot = observation.bootId
            ?: return RuntimeAuthorityVerdict(false, reason = "boot_identity_unavailable")
        val effectiveMillis = if (boot == anchor.bootId) {
            if (observation.elapsedRealtimeMillis < anchor.elapsedRealtimeMillis) {
                return RuntimeAuthorityVerdict(false, reason = "monotonic_clock_rollback")
            }
            if (observation.wallMillis + CLOCK_ROLLBACK_TOLERANCE_MILLIS < anchor.observedWallMillis) {
                return RuntimeAuthorityVerdict(false, reason = "wall_clock_rollback")
            }
            val elapsed = observation.elapsedRealtimeMillis - anchor.elapsedRealtimeMillis
            maxOf(anchor.trustedEpochMillis + elapsed, observation.wallMillis)
        } else {
            val networkTime = observation.trustedNetworkMillis
                ?: return RuntimeAuthorityVerdict(false, reason = "cross_boot_time_ambiguous")
            if (networkTime + CLOCK_ROLLBACK_TOLERANCE_MILLIS < anchor.trustedEpochMillis) {
                return RuntimeAuthorityVerdict(false, reason = "trusted_clock_rollback")
            }
            networkTime
        }
        val effective = Instant.ofEpochMilli(effectiveMillis)
        if (effective < authority.catalogIssuedAt.minusSeconds(300)) {
            return RuntimeAuthorityVerdict(false, effective, "authority_not_yet_valid")
        }
        if (effective >= authority.hardDeadline) {
            return RuntimeAuthorityVerdict(false, effective, "authority_expired")
        }
        return RuntimeAuthorityVerdict(true, effective)
    }

    internal fun currentBootId(): String? = runCatching {
        File("/proc/sys/kernel/random/boot_id").useLines { lines -> lines.firstOrNull()?.trim() }
            ?.takeIf { BOOT_ID.matches(it) }
    }.getOrNull()

    private fun trustedNetworkTimeMillis(): Long? {
        if (Build.VERSION.SDK_INT < 33) return null
        return runCatching { SystemClock.currentNetworkTimeClock().millis() }.getOrNull()
    }

    private val BOOT_ID = Regex(
        "^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    )
}
