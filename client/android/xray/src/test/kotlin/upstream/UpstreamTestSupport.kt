package org.amnezia.vpn.protocol.xray.upstream

import java.io.File
import org.json.JSONArray
import org.json.JSONObject

// Shared helpers of the upstream lease JVM tests (lane A2).

internal object UpstreamVectors {
    // client/core/serviceEngine/tests/vectors, recorded from the C++ code (upstream_vectors_check.cpp).
    // Override: env TRIBE_UPSTREAM_VECTORS. Otherwise found by walking up from the test's working dir.
    val dir: File by lazy {
        System.getenv("TRIBE_UPSTREAM_VECTORS")?.let { return@lazy File(it) }
        var d: File? = File(System.getProperty("user.dir")).absoluteFile
        while (d != null) {
            val candidate = File(d, "client/core/serviceEngine/tests/vectors")
            if (File(candidate, "upstream_lease_vectors.json").isFile) return@lazy candidate
            val inClient = File(d, "core/serviceEngine/tests/vectors")
            if (File(inClient, "upstream_lease_vectors.json").isFile) return@lazy inClient
            d = d.parentFile
        }
        error("upstream vectors not found above ${System.getProperty("user.dir")}")
    }

    fun load(name: String): JSONObject = JSONObject(File(dir, name).readText(Charsets.UTF_8))
}

// A JSON value as one canonical string: object keys sorted, integral numbers as integers, so two trees
// compare equal exactly when the C++ QJsonObject comparison would.
internal fun canon(v: Any?): String = when (v) {
    null, JSONObject.NULL -> "null"
    is JSONObject -> v.keySet().sorted().joinToString(",", "{", "}") { JSONObject.quote(it) + ":" + canon(v.opt(it)) }
    is JSONArray -> (0 until v.length()).joinToString(",", "[", "]") { canon(v.opt(it)) }
    is Map<*, *> -> v.keys.map { it.toString() }.sorted().joinToString(",", "{", "}") { JSONObject.quote(it) + ":" + canon(v[it]) }
    is List<*> -> v.joinToString(",", "[", "]") { canon(it) }
    is Boolean -> v.toString()
    is String -> JSONObject.quote(v)
    is Number -> {
        val d = v.toDouble()
        if (d.isFinite() && Math.floor(d) == d && Math.abs(d) < 9.3e18) d.toLong().toString() else d.toString()
    }
    else -> JSONObject.quote(v.toString())
}

internal fun i64(v: Any?): Long = (v as? Number)?.toDouble()?.toLong() ?: 0L
internal fun int(v: Any?, def: Int = 0): Int = (v as? Number)?.toInt() ?: def
internal fun str(v: Any?): String = v as? String ?: ""
internal fun bool(v: Any?): Boolean = v as? Boolean ?: false

internal fun JSONArray.objects(): List<JSONObject> = (0 until length()).map { getJSONObject(it) }

// A small check counter that keeps going after a failure and reports every mismatch at the end.
internal class Checks(private val label: String) {
    var total = 0
        private set
    val failures = mutableListOf<String>()

    fun check(ok: Boolean, message: () -> String) {
        total += 1
        if (!ok) failures += message()
    }

    fun assertAll() {
        if (failures.isNotEmpty()) {
            throw AssertionError("$label: ${failures.size} of $total checks failed:\n" + failures.take(20).joinToString("\n"))
        }
    }
}

internal const val K_LEASE = "leaseAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
internal const val K_T = 1_000_000L
internal const val K_S0 = 1_763_117_000_000L

internal fun lease(seq: Long = 5, epoch: Long = 7, renewAfter: Int = 300, ttl: Int = 900, expiresIn: Long = 900_000,
                   scope: UpstreamMeterScope = UpstreamMeterScope.TUNNEL, tags: List<String> = emptyList()) =
    UpstreamLeaseEnvelope(K_LEASE, "tlr1.TOKEN", "https://t.example.net", renewAfter, ttl, expiresIn, seq, epoch, 100,
        scope, tags)

internal fun renewOk(seq: Long, expiresServer: Long, rebaseline: Boolean = false, epoch: Long = 7,
                     configChanged: Boolean = false, revision: Long = 100, applied: Long = 0, shadow: Long = 0) =
    UpstreamRenewReply(UpstreamReplyKind.GRANTED,
        UpstreamRenewal(rebaseline, K_LEASE, expiresServer, 300, seq, revision, epoch, configChanged, applied, shadow))

internal fun refused(code: String, retryAfter: Int = -1) =
    UpstreamRenewReply(UpstreamReplyKind.REFUSED, error = UpstreamErrorReply(UpstreamErrorCode.from(code), retryAfter, 0))

internal fun transportFailure() = UpstreamRenewReply(why = "transport")
