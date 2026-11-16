package org.amnezia.vpn.protocol.xray.upstream

import java.net.URI
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import org.json.JSONArray
import org.json.JSONObject

// AVPN upstream nodes (plan provider-pool, release C, lane A2): wire formats of the seat lease - the
// Kotlin twin of client/platforms/ios/UpstreamLeaseWire.swift (renew / release, start envelope) plus the
// acquire half and the signature check of client/core/serviceEngine/{UpstreamLeaseWire.h,SignedContext.h}.
// Pure (org.json, java.security; no Android imports): replayed on the JVM against
// client/core/serviceEngine/tests/vectors/upstream_{wire,signature}_vectors.json. `why` strings are the
// C++ ones, exactly.
//
// The Android service never parses an acquire answer (the app process acquires, decision A-1); the
// acquire classifier is here so the shared vectors replay in full. Its signature check takes an
// Ed25519Verifier: JcaEd25519Verifier uses the platform's own "Ed25519" (JDK 15+; on Android only where
// the platform provider has it - not guaranteed at minSdk 28) and fails closed when it is missing.
//
// Secrets: renew_token, scan_token and the profile config are never logged; callers log codes and field
// names only.

fun interface Ed25519Verifier {
    fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean
}

object JcaEd25519Verifier : Ed25519Verifier {
    // DER SubjectPublicKeyInfo prefix of a raw 32-byte Ed25519 key (RFC 8410).
    private val SPKI_PREFIX = byteArrayOf(0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00)

    override fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean = try {
        val key = KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(SPKI_PREFIX + publicKey))
        Signature.getInstance("Ed25519").run {
            initVerify(key)
            update(message)
            verify(signature)
        }
    } catch (e: Exception) {
        false // no provider, bad key, bad signature: never accepted
    }
}

object UpstreamLeaseWire {
    // Contract cap of one delta (UpstreamMeter.*_bytes_delta maximum, 1 TiB).
    const val MAX_DELTA_BYTES: Long = 1_099_511_627_776L
    // Largest integer a JSON number carries exactly (2^53 - 1); kUpstreamMaxRevision.
    const val MAX_INTEGER: Long = 9_007_199_254_740_991L
    // SignedContext.h kUpstreamLeaseSigContext.
    const val LEASE_SIG_CONTEXT = "tribe-upstream-lease-v1"
    // Response header the backend puts on EVERY answer of the upstream routes (UpstreamLeaseWire.h).
    const val TRIBE_API_HEADER = "X-Tribe-Api"

    private val LEASE_ID_RE = Regex("^[A-Za-z0-9_-]{32,64}$")
    private val VISIBLE_128_RE = Regex("^[\\x21-\\x7e]{1,128}$")
    private val VISIBLE_32_RE = Regex("^[\\x21-\\x7e]{1,32}$")
    private val PROBE_PATH_RE = Regex("^/[A-Za-z0-9_/.-]{1,63}$")
    private val SHA256_RE = Regex("^[0-9a-fA-F]{64}$")
    private val REASON_RE = Regex("^[a-z][a-z0-9_.-]{0,63}$")
    private val CONTEXT_RE = Regex("^[a-z0-9][a-z0-9.-]{2,63}$")
    private val ISO_RE = Regex("""^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:[.,](\d+))?)?(Z|[+-]\d{2}:?\d{2})?$""")

    // ---- JSON primitives (QJsonValue semantics) ---------------------------------------------------------

    fun isAbsent(value: Any?): Boolean = value === null || value === JSONObject.NULL

    // A JSON number (never a bool) with no fraction part, inside [lo, hi].
    fun jsonInt(value: Any?, lo: Long, hi: Long): Long? {
        if (value !is Number) return null
        val d = value.toDouble()
        if (!d.isFinite() || Math.floor(d) != d || d < lo.toDouble() || d > hi.toDouble()) return null
        return d.toLong()
    }

    fun jsonBool(value: Any?): Boolean? = value as? Boolean

    fun jsonString(value: Any?): String = value as? String ?: ""

    fun jsonObject(body: ByteArray): JSONObject? {
        if (body.isEmpty()) return null
        return try {
            JSONObject(String(body, Charsets.UTF_8))
        } catch (e: Exception) {
            null
        }
    }

    // ---- validators -------------------------------------------------------------------------------------

    fun leaseIdValid(id: String): Boolean = LEASE_ID_RE.matches(id)

    // An opaque header-safe token (visible ASCII, 1..1024 characters).
    fun renewTokenValid(token: String): Boolean =
        token.length in 1..1024 && token.all { it.code in 0x21..0x7e }

    // An https URL with a host, no user info, query or fragment; without trailing slashes. "" = invalid.
    fun apiBaseNormalized(s: String): String {
        if ('?' in s || '#' in s) return ""
        val u = try {
            URI(s)
        } catch (e: Exception) {
            return ""
        }
        if (u.scheme?.lowercase() != "https" || u.host.isNullOrEmpty() || u.rawUserInfo != null ||
            u.rawQuery != null || u.rawFragment != null) return ""
        return s.trimEnd('/')
    }

    // ISO 8601 date-time as Qt::ISODateWithMs reads it (seconds and fraction optional, offset Z or
    // +hh:mm / +hhmm). A value without an offset is read as UTC (the server always sends Z, and only
    // differences of two server times are used). No java.time: pure arithmetic, any API level.
    fun parseTimeMs(value: Any?): Long? {
        val text = value as? String ?: return null
        val m = ISO_RE.matchEntire(text) ?: return null
        val g = m.groupValues
        val year = g[1].toInt()
        val month = g[2].toInt()
        val day = g[3].toInt()
        val hour = g[4].toInt()
        val minute = g[5].toInt()
        val second = if (g[6].isEmpty()) 0 else g[6].toInt()
        if (month !in 1..12 || day !in 1..31 || hour !in 0..23 || minute !in 0..59 || second !in 0..59) return null
        if (day > daysInMonth(year, month)) return null // 31 Feb etc.
        val millis = if (g[7].isEmpty()) 0 else (g[7] + "000").take(3).toInt()
        var offsetS = 0
        val tz = g[8]
        if (tz.isNotEmpty() && tz != "Z") {
            val sign = if (tz.startsWith("-")) -1 else 1
            val digits = tz.drop(1).replace(":", "")
            if (digits.length != 4) return null
            val hh = digits.take(2).toInt()
            val mm = digits.takeLast(2).toInt()
            if (hh > 23 || mm > 59) return null
            offsetS = sign * (hh * 3600 + mm * 60)
        }
        val seconds = daysFromCivil(year, month, day) * 86_400L + hour * 3600L + minute * 60L + second
        return seconds * 1000 + millis - offsetS * 1000L
    }

    private fun daysInMonth(year: Int, month: Int): Int = when (month) {
        2 -> if ((year % 4 == 0 && year % 100 != 0) || year % 400 == 0) 29 else 28
        4, 6, 9, 11 -> 30
        else -> 31
    }

    // Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant's days_from_civil).
    private fun daysFromCivil(year: Int, month: Int, day: Int): Long {
        val y = (if (month <= 2) year - 1 else year).toLong()
        val era = (if (y >= 0) y else y - 399) / 400
        val yoe = y - era * 400
        val mp = (month + (if (month > 2) -3 else 9)).toLong()
        val doy = (153 * mp + 2) / 5 + day - 1
        val doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
        return era * 146_097 + doe - 719_468
    }

    // ---- renew / release --------------------------------------------------------------------------------

    // Renew / release body (UpstreamMeter); keys in the order QJsonDocument writes them. `epoch` is ALWAYS
    // sent, also as 0: the backend requires the field (a missing one is a 422; lab 14.11 D2).
    fun meterBody(m: UpstreamMeterReport): String {
        val rx = m.rxDelta.coerceIn(0L, MAX_DELTA_BYTES)
        val tx = m.txDelta.coerceIn(0L, MAX_DELTA_BYTES)
        val epoch = m.epoch.coerceIn(0L, MAX_INTEGER)
        return "{\"epoch\":$epoch,\"meter_scope\":\"${m.scope.wire}\",\"rx_bytes_delta\":$rx,\"seq\":${m.seq},\"tx_bytes_delta\":$tx}"
    }

    fun parseRenewal(body: ByteArray): Pair<UpstreamRenewal?, String> {
        val o = jsonObject(body) ?: return null to "not_object"
        val status = jsonString(o.opt("status"))
        val rebaseline = when (status) {
            "rebaseline" -> true
            "ok" -> false
            else -> return null to "status"
        }
        val leaseId = jsonString(o.opt("lease_id"))
        if (!leaseIdValid(leaseId)) return null to "lease_id"
        val expires = parseTimeMs(o.opt("expires_at")) ?: return null to "expires_at"
        val renewAfter = jsonInt(o.opt("renew_after_s"), 0, 86_400) ?: return null to "renew_after_s"
        val seq = jsonInt(o.opt("seq"), 0, MAX_INTEGER) ?: return null to "seq"
        val rev = jsonInt(o.opt("upstream_revision"), 0, MAX_INTEGER) ?: return null to "upstream_revision"
        val epoch = jsonInt(o.opt("traffic_accounting_epoch"), 1, MAX_INTEGER) ?: return null to "traffic_accounting_epoch"
        val changed = jsonBool(o.opt("config_changed")) ?: return null to "config_changed"
        val applied = jsonInt(o.opt("applied_bytes"), 0, MAX_INTEGER) ?: return null to "applied_bytes"
        var shadowBytes = 0L
        val shadow = o.opt("shadow_bytes")
        if (!isAbsent(shadow)) shadowBytes = jsonInt(shadow, 0, MAX_INTEGER) ?: return null to "shadow_bytes"
        return UpstreamRenewal(rebaseline, leaseId, expires, renewAfter.toInt(), seq, rev, epoch, changed, applied,
            shadowBytes) to ""
    }

    // An error body. Only the body's code counts - the HTTP status alone never makes an answer terminal.
    fun parseError(body: ByteArray): UpstreamErrorReply {
        val o = jsonObject(body) ?: JSONObject()
        val code = o.opt("code")
        val reason = o.opt("reason")
        return UpstreamErrorReply(
            code = if (code is String) UpstreamErrorCode.from(code) else UpstreamErrorCode.UNKNOWN,
            retryAfterS = jsonInt(o.opt("retry_after_s"), 0, 86_400)?.toInt() ?: -1,
            upstreamRevision = jsonInt(o.opt("upstream_revision"), 1, MAX_INTEGER) ?: 0,
            reason = if (reason is String && REASON_RE.matches(reason)) reason else "",
        )
    }

    // httpStatus 0 = no HTTP answer (transport failure / timeout).
    fun classifyRenewReply(httpStatus: Int, body: ByteArray): UpstreamRenewReply {
        if (httpStatus <= 0) return UpstreamRenewReply(why = "transport")
        if (httpStatus < 200 || httpStatus >= 300) {
            val e = parseError(body)
            if (e.code == UpstreamErrorCode.UNKNOWN) return UpstreamRenewReply(error = e, why = "http_$httpStatus")
            return UpstreamRenewReply(kind = UpstreamReplyKind.REFUSED, error = e)
        }
        val (renewal, why) = parseRenewal(body)
        renewal ?: return UpstreamRenewReply(why = why)
        return UpstreamRenewReply(kind = UpstreamReplyKind.GRANTED, renewal = renewal)
    }

    // A renewal our server refused as a malformed request (422 `invalid_request`, or a 422 without a known
    // code): a contract bug, counted by the machine (UpstreamLeaseMachine.RENEW_REJECTED_LIMIT).
    fun renewRejected(r: UpstreamRenewReply): Boolean =
        (r.kind == UpstreamReplyKind.REFUSED && r.error.code == UpstreamErrorCode.INVALID_REQUEST) ||
            (r.kind == UpstreamReplyKind.FAILED && r.why == "http_422")

    // ---- acquire (the app's half; the vectors replay it) ------------------------------------------------

    fun upstreamFromTribeApi(headerValue: String?): Boolean = headerValue?.trim() == "1"

    // Tags of the proxy outbounds (meter_scope proxy), computed by the server: at most 64 distinct tags of
    // 1..128 visible characters. Absent/null = empty. null = malformed.
    fun parseGrantMeterTags(value: Any?): List<String>? {
        if (isAbsent(value)) return emptyList()
        if (value !is JSONArray || value.length() > 64) return null
        val out = ArrayList<String>()
        for (i in 0 until value.length()) {
            val t = value.opt(i) as? String ?: return null
            if (!VISIBLE_128_RE.matches(t) || t in out) return null
            out += t
        }
        return out
    }

    // The optional `probe` object. Absent/null -> (true, null); present but malformed -> (false, null).
    fun parseProbeGrant(value: Any?): Pair<Boolean, UpstreamProbeGrant?> {
        if (isAbsent(value)) return true to null
        val o = value as? JSONObject ?: return false to null
        val tok = o.opt("scan_token") as? String ?: return false to null
        if (!VISIBLE_128_RE.matches(tok)) return false to null
        val expires = jsonInt(o.opt("expires_in_s"), 1, 86_400) ?: return false to null
        var asn = 0L
        val asnValue = o.opt("access_asn")
        if (!isAbsent(asnValue)) asn = jsonInt(asnValue, 1, 4_294_967_295L) ?: return false to null
        var net = ""
        val netValue = o.opt("access_net_token")
        if (!isAbsent(netValue)) {
            net = netValue as? String ?: return false to null
            if (!VISIBLE_32_RE.matches(net)) return false to null
        }
        var path = "/v1/probe"
        val pathValue = o.opt("path")
        if (!isAbsent(pathValue)) {
            path = pathValue as? String ?: return false to null
            if (!PROBE_PATH_RE.matches(path) || ".." in path) return false to null
        }
        return true to UpstreamProbeGrant(tok, expires.toInt(), asn, net, path)
    }

    // A lease answer body that already passed the signature check: `type`, every field, and that
    // config_sha256 is the sha256 of the config bytes. why = the field name only.
    fun parseLeaseGrant(body: ByteArray): Pair<UpstreamLeaseGrant?, String> {
        val o = jsonObject(body) ?: return null to "not_object"
        if (jsonString(o.opt("type")) != "upstream_lease") return null to "type"
        val leaseId = jsonString(o.opt("lease_id"))
        if (!leaseIdValid(leaseId)) return null to "lease_id"
        val profileId = jsonString(o.opt("profile_id"))
        if (profileId.isEmpty()) return null to "profile_id"
        val kind = when (jsonString(o.opt("kind"))) {
            "session" -> UpstreamLeaseKind.SESSION
            "probe" -> UpstreamLeaseKind.PROBE
            else -> return null to "kind"
        }
        val expires = parseTimeMs(o.opt("expires_at")) ?: return null to "expires_at"
        val ttl = jsonInt(o.opt("ttl_s"), 1, 86_400) ?: return null to "ttl_s"
        val renewAfter = jsonInt(o.opt("renew_after_s"), 0, 86_400) ?: return null to "renew_after_s"
        val seq = jsonInt(o.opt("seq"), 0, MAX_INTEGER) ?: return null to "seq"
        val config = o.opt("config") as? String
        if (config.isNullOrEmpty()) return null to "config"
        val sha = jsonString(o.opt("config_sha256")).lowercase()
        if (!SHA256_RE.matches(sha)) return null to "config_sha256"
        if (sha256Hex(config.toByteArray(Charsets.UTF_8)) != sha) return null to "config_sha256_mismatch"
        val rev = jsonInt(o.opt("upstream_revision"), 0, MAX_INTEGER) ?: return null to "upstream_revision"
        val epoch = jsonInt(o.opt("traffic_accounting_epoch"), 1, MAX_INTEGER) ?: return null to "traffic_accounting_epoch"
        // Optional (absent on an older server). Present but malformed = a broken signed answer: refused.
        var token = ""
        val tokValue = o.opt("renew_token")
        if (!isAbsent(tokValue)) {
            token = tokValue as? String ?: return null to "renew_token"
            if (!renewTokenValid(token)) return null to "renew_token"
        }
        var base = ""
        val baseValue = o.opt("tunnel_api_base")
        if (!isAbsent(baseValue)) {
            base = (baseValue as? String)?.let { apiBaseNormalized(it) } ?: ""
            if (base.isEmpty()) return null to "tunnel_api_base"
        }
        var changed = false
        val changedValue = o.opt("config_changed")
        if (!isAbsent(changedValue)) changed = jsonBool(changedValue) ?: return null to "config_changed"
        val (probeOk, probe) = parseProbeGrant(o.opt("probe"))
        if (!probeOk) return null to "probe"
        val tags = parseGrantMeterTags(o.opt("meter_tags")) ?: return null to "meter_tags"
        return UpstreamLeaseGrant(leaseId, profileId, kind, expires, ttl.toInt(), renewAfter.toInt(), seq, config, sha,
            rev, epoch, token, base, changed, probe, tags) to ""
    }

    // httpStatus 0 = no HTTP answer. pubKeyHex = the /v1/config key. fromTribeApi = the answer carried
    // `X-Tribe-Api: 1`; it changes no classification, only mayStartProvisional.
    fun classifyAcquireReply(httpStatus: Int, body: ByteArray, sigB64: String, pubKeyHex: String,
                             fromTribeApi: Boolean = false,
                             verifier: Ed25519Verifier = JcaEd25519Verifier): UpstreamAcquireReply {
        val tribe = httpStatus > 0 && fromTribeApi
        if (httpStatus <= 0) return UpstreamAcquireReply(why = "transport", fromTribeApi = tribe)
        if (httpStatus < 200 || httpStatus >= 300) {
            val e = parseError(body)
            if (e.code == UpstreamErrorCode.UNKNOWN) {
                return UpstreamAcquireReply(error = e, why = "http_$httpStatus", fromTribeApi = tribe)
            }
            return UpstreamAcquireReply(kind = UpstreamReplyKind.REFUSED, error = e, fromTribeApi = tribe)
        }
        if (!verifyDetachedWithContext(pubKeyHex, LEASE_SIG_CONTEXT, body, sigB64, verifier)) {
            return UpstreamAcquireReply(why = "signature", fromTribeApi = tribe)
        }
        val (grant, why) = parseLeaseGrant(body)
        grant ?: return UpstreamAcquireReply(why = why, fromTribeApi = tribe)
        return UpstreamAcquireReply(kind = UpstreamReplyKind.GRANTED, grant = grant, fromTribeApi = tribe)
    }

    // May the engine bring the tunnel up from a standby pack entry after this DIRECT acquire answer?
    // (UpstreamLeaseWire.h mayStartProvisional.)
    fun mayStartProvisional(direct: UpstreamAcquireReply): Boolean {
        if (direct.kind != UpstreamReplyKind.FAILED || direct.fromTribeApi) return false
        return direct.why == "transport" || direct.why == "signature" || direct.why.startsWith("http_")
    }

    // ---- signature (SignedContext.h, Ed25519Verify.cpp) --------------------------------------------------

    // The exact bytes the signature covers: ASCII(context) || 0x0A || body. Empty context = the body
    // itself. An invalid context gives an empty array (and verification fails).
    fun signingInput(body: ByteArray, context: String): ByteArray {
        if (context.isEmpty()) return body
        if (!CONTEXT_RE.matches(context)) return ByteArray(0)
        return context.toByteArray(Charsets.US_ASCII) + 0x0A.toByte() + body
    }

    // Strict: exactly 64 hex characters for the key, strict base64 decoding to exactly 64 bytes.
    fun verifyDetached(pubHex: String, message: ByteArray, sigB64: String,
                       verifier: Ed25519Verifier = JcaEd25519Verifier): Boolean {
        val key = hexDecode(pubHex) ?: return false
        if (key.size != 32) return false
        val sig = try {
            Base64.getDecoder().decode(sigB64)
        } catch (e: IllegalArgumentException) {
            return false
        }
        if (sig.size != 64) return false
        return verifier.verify(key, message, sig)
    }

    fun verifyDetachedWithContext(pubHex: String, context: String, body: ByteArray, sigB64: String,
                                  verifier: Ed25519Verifier = JcaEd25519Verifier): Boolean {
        if (context.isEmpty()) return verifyDetached(pubHex, body, sigB64, verifier)
        val message = signingInput(body, context)
        if (message.isEmpty()) return false
        return verifyDetached(pubHex, message, sigB64, verifier)
    }

    fun sha256Hex(bytes: ByteArray): String = hex(MessageDigest.getInstance("SHA-256").digest(bytes))

    fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun hexDecode(s: String): ByteArray? {
        if (s.length % 2 != 0) return null
        val out = ByteArray(s.length / 2)
        for (i in out.indices) {
            val hi = Character.digit(s[2 * i], 16)
            val lo = Character.digit(s[2 * i + 1], 16)
            if (hi < 0 || lo < 0) return null
            out[i] = ((hi shl 4) or lo).toByte()
        }
        return out
    }

    // ---- start envelope (contract sections 1-2) ---------------------------------------------------------

    // `upstream_lease` from the start envelope or the app message `upstream_lease_set`.
    // why = the field name only (never a value).
    fun parseLeaseEnvelope(value: Any?): Pair<UpstreamLeaseEnvelope?, String> {
        val o = value as? JSONObject ?: return null to "not_object"
        val leaseId = jsonString(o.opt("lease_id"))
        if (!leaseIdValid(leaseId)) return null to "lease_id"
        val token = jsonString(o.opt("renew_token"))
        if (!renewTokenValid(token)) return null to "renew_token"
        val base = apiBaseNormalized(jsonString(o.opt("api_base")))
        if (base.isEmpty()) return null to "api_base"
        val renewAfter = jsonInt(o.opt("renew_after_s"), 0, 86_400) ?: return null to "renew_after_s"
        val ttl = jsonInt(o.opt("ttl_s"), 1, 86_400) ?: return null to "ttl_s"
        val expiresIn = jsonInt(o.opt("expires_in_ms"), 0, MAX_INTEGER) ?: return null to "expires_in_ms"
        val seq = jsonInt(o.opt("seq"), 0, MAX_INTEGER) ?: return null to "seq"
        val epoch = jsonInt(o.opt("epoch"), 1, MAX_INTEGER) ?: return null to "epoch"
        val revision = jsonInt(o.opt("revision"), 0, MAX_INTEGER) ?: return null to "revision"
        var scope = UpstreamMeterScope.TUNNEL
        val scopeValue = o.opt("meter_scope")
        if (!isAbsent(scopeValue)) {
            scope = (scopeValue as? String)?.let { UpstreamMeterScope.fromWire(it) } ?: return null to "meter_scope"
        }
        // meter_tags (added 14.11 evening): the only outbound tags summed for scope "proxy"; absent or empty
        // = the owner meters "tunnel".
        val tags = ArrayList<String>()
        val tagsValue = o.opt("meter_tags")
        if (!isAbsent(tagsValue)) {
            if (tagsValue !is JSONArray || tagsValue.length() > 64) return null to "meter_tags"
            for (i in 0 until tagsValue.length()) {
                val tag = tagsValue.opt(i) as? String ?: return null to "meter_tags"
                val utf8 = tag.toByteArray(Charsets.UTF_8).size
                if (utf8 !in 1..128 || tag.any { it.code < 0x20 || it.code == 0x7f }) return null to "meter_tags"
                if (tag !in tags) tags += tag
            }
        }
        return UpstreamLeaseEnvelope(leaseId, token, base, renewAfter.toInt(), ttl.toInt(), expiresIn, seq, epoch,
            revision, scope, tags) to ""
    }

    // `tribeSessionMetadata` of an upstream session: {upstream: 1, profile_id, config_sha256, ...}.
    // null = not an upstream session (AWG, own Xray): nothing of this lane applies.
    fun upstreamProfileId(metadata: Any?): String? {
        val o = metadata as? JSONObject ?: return null
        val flag = o.opt("upstream")
        val on = jsonInt(flag, 0, 1) == 1L || jsonBool(flag) == true
        if (!on) return null
        return jsonString(o.opt("profile_id"))
    }
}
