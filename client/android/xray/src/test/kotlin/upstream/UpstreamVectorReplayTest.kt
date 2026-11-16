package org.amnezia.vpn.protocol.xray.upstream

import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.EdECPrivateKeySpec
import java.security.spec.NamedParameterSpec
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.json.JSONArray
import org.json.JSONObject

// AVPN upstream nodes (lane A2): replays ALL three shared vector files recorded from the C++ code
// (client/core/serviceEngine/tests/vectors, upstream_vectors_check.cpp) against the Kotlin twin, with the
// C++ replayer's own serialization key for key:
//  - upstream_lease_vectors.json: every scenario, the app_only (provisional) ones included, through the
//    REACQUIRE machine (the C++ behaviour), plus the eligible ones again through adopt() (RENEW_UNTIL_GONE,
//    the service path), as the Swift twin does;
//  - upstream_wire_vectors.json: every case, acquire (signature, grant, mayStartProvisional) and renew;
//  - upstream_signature_vectors.json: every case, every field.
// The check count is built like the C++ CHECKs so the totals compare one to one (C++: 505 on 16.11).
class UpstreamVectorReplayTest {

    // ---- lease machine serialization (upstream_vectors_check.cpp actionJson / stateJson / expectJson) -----

    private fun meterJson(m: UpstreamMeterReport) = JSONObject()
        .put("seq", m.seq).put("rx", m.rxDelta).put("tx", m.txDelta).put("scope", m.scope.wire).put("epoch", m.epoch)

    private fun actionJson(a: UpstreamLeaseAction): JSONObject {
        val o = JSONObject().put("kind", a.kind.wire)
        when (a.kind) {
            UpstreamLeaseActionKind.SEND_ACQUIRE -> o.put("request_id", a.requestId).put("profile_id", a.profileId)
                .put("lease_kind", a.leaseKind.wire).put("standby", a.standby).put("config_sha256", a.configSha256)
                .put("renew_token", a.route.renewToken).put("api_base", a.route.apiBase)
            UpstreamLeaseActionKind.SEND_RENEW, UpstreamLeaseActionKind.SEND_RELEASE -> o.put("request_id", a.requestId)
                .put("lease_id", a.leaseId).put("meter", meterJson(a.meter)).put("renew_token", a.route.renewToken)
                .put("api_base", a.route.apiBase)
            UpstreamLeaseActionKind.LEASE_READY -> o.put("provisional", a.provisional).put("lease_id", a.leaseId)
                .put("renew_token", a.route.renewToken).put("api_base", a.route.apiBase)
            UpstreamLeaseActionKind.LEASE_CONFIRMED -> o.put("lease_id", a.leaseId)
                .put("renew_token", a.route.renewToken).put("api_base", a.route.apiBase)
            UpstreamLeaseActionKind.LEAVE_NODE, UpstreamLeaseActionKind.TRY_NEXT_CANDIDATE -> o.put("reason", a.reason)
            UpstreamLeaseActionKind.REVISION_CHANGED -> o.put("upstream_revision", a.upstreamRevision)
            else -> Unit
        }
        return o
    }

    private fun stateJson(m: UpstreamLeaseMachine) = JSONObject()
        .put("phase", m.phase.wire).put("lease_id", m.leaseId).put("last_seq", m.lastAcceptedSeq)
        .put("epoch", m.accountingEpoch).put("known_revision", m.knownRevision).put("deadline_ms", m.deadlineMs)
        .put("report_in_doubt", m.reportInDoubt).put("unreported_rx", m.unreportedRx)
        .put("unreported_tx", m.unreportedTx).put("meter_scope", m.meterScope.wire)
        .put("renew_token", m.route.renewToken).put("api_base", m.route.apiBase)

    private fun expectJson(s: UpstreamLeaseStep?, m: UpstreamLeaseMachine) = JSONObject()
        .put("actions", JSONArray().apply { s?.actions?.forEach { put(actionJson(it)) } })
        .put("wake_at_ms", s?.wakeAtMs ?: JSONObject.NULL)
        .put("state", stateJson(m))

    // ---- recorded inputs ----------------------------------------------------------------------------------

    private fun scopeFrom(s: String) = if (s == "proxy") UpstreamMeterScope.PROXY else UpstreamMeterScope.TUNNEL
    private fun kindFrom(s: String) = if (s == "probe") UpstreamLeaseKind.PROBE else UpstreamLeaseKind.SESSION

    private fun errorFrom(e: JSONObject) = UpstreamErrorReply(UpstreamErrorCode.from(str(e.opt("code"))),
        int(e.opt("retry_after_s"), -1), i64(e.opt("upstream_revision")))

    private fun acquireFrom(o: JSONObject): UpstreamAcquireReply = when (str(o.opt("kind"))) {
        "granted" -> {
            val g = o.getJSONObject("grant")
            UpstreamAcquireReply(UpstreamReplyKind.GRANTED, UpstreamLeaseGrant(
                leaseId = str(g.opt("lease_id")), profileId = str(g.opt("profile_id")), kind = kindFrom(str(g.opt("kind"))),
                expiresAtMs = i64(g.opt("expires_at_ms")), ttlS = int(g.opt("ttl_s")),
                renewAfterS = int(g.opt("renew_after_s")), seq = i64(g.opt("seq")),
                upstreamRevision = i64(g.opt("upstream_revision")),
                accountingEpoch = i64(g.opt("traffic_accounting_epoch")), renewToken = str(g.opt("renew_token")),
                tunnelApiBase = str(g.opt("tunnel_api_base")), configSha256 = str(g.opt("config_sha256")),
                configChanged = bool(g.opt("config_changed"))))
        }
        "refused" -> UpstreamAcquireReply(UpstreamReplyKind.REFUSED, error = errorFrom(o.getJSONObject("error")))
        else -> UpstreamAcquireReply(why = str(o.opt("why")))
    }

    private fun renewFrom(o: JSONObject): UpstreamRenewReply = when (str(o.opt("kind"))) {
        "granted" -> {
            val w = o.getJSONObject("renewal")
            UpstreamRenewReply(UpstreamReplyKind.GRANTED, UpstreamRenewal(
                rebaseline = str(w.opt("status")) == "rebaseline", leaseId = str(w.opt("lease_id")),
                expiresAtMs = i64(w.opt("expires_at_ms")), renewAfterS = int(w.opt("renew_after_s")),
                seq = i64(w.opt("seq")), upstreamRevision = i64(w.opt("upstream_revision")),
                accountingEpoch = i64(w.opt("traffic_accounting_epoch")), configChanged = bool(w.opt("config_changed")),
                appliedBytes = i64(w.opt("applied_bytes")), shadowBytes = i64(w.opt("shadow_bytes"))))
        }
        "refused" -> UpstreamRenewReply(UpstreamReplyKind.REFUSED, error = errorFrom(o.getJSONObject("error")))
        else -> UpstreamRenewReply(why = str(o.opt("why")))
    }

    // Applies one recorded event; returns its expectation object (actual behaviour). null = unknown event.
    private fun apply(m: UpstreamLeaseMachine, step: JSONObject): JSONObject? {
        val a = step.optJSONObject("args") ?: JSONObject()
        val now = i64(step.opt("now_ms"))
        val s = when (str(step.opt("event"))) {
            "start" -> m.start(str(a.opt("profile_id")), kindFrom(str(a.opt("kind"))), scopeFrom(str(a.opt("meter_scope"))),
                i64(a.opt("known_revision")), now)
            "start_provisional" -> m.startProvisional(str(a.opt("profile_id")), scopeFrom(str(a.opt("meter_scope"))),
                str(a.opt("config_sha256")), str(a.opt("tunnel_api_base")), i64(a.opt("known_revision")),
                i64(a.opt("confirm_budget_ms")), now)
            "tunnel_up" -> m.tunnelUp(now)
            "acquire_reply" -> m.onAcquireReply(i64(a.opt("request_id")), acquireFrom(a.getJSONObject("reply")), now)
            "renew_reply" -> m.onRenewReply(i64(a.opt("request_id")), renewFrom(a.getJSONObject("reply")), now)
            "tick" -> m.tick(now)
            "disconnect" -> m.disconnect(now)
            "tunnel_bytes" -> {
                m.onTunnelBytes(i64(a.opt("rx")), i64(a.opt("tx")))
                return expectJson(null, m)
            }
            "baseline_bytes" -> {
                m.baselineBytes(i64(a.opt("rx")), i64(a.opt("tx")))
                return expectJson(null, m)
            }
            else -> return null
        }
        return expectJson(s, m)
    }

    private fun timing(doc: JSONObject): UpstreamLeaseTiming {
        val t = doc.getJSONObject("timing")
        return UpstreamLeaseTiming(int(t.opt("max_ttl_s")), int(t.opt("min_renew_s")), int(t.opt("default_renew_s")),
            int(t.opt("retry_base_s")), int(t.opt("retry_max_s")), int(t.opt("max_retry_after_s")))
    }

    // ---- upstream_lease_vectors.json ----------------------------------------------------------------------

    @Test
    fun leaseVectors() {
        val doc = UpstreamVectors.load("upstream_lease_vectors.json")
        val c = Checks("lease vectors")
        c.check(int(doc.opt("schema")) == 1) { "schema 1" }
        c.check(timing(doc) == UpstreamLeaseTiming()) { "timing block = UpstreamLeaseTiming defaults: ${timing(doc)}" }
        val scenarios = doc.getJSONArray("scenarios").objects()
        c.check(scenarios.size >= 30) { "at least 30 scenarios" }
        var steps = 0
        var appOnly = 0
        for (sc in scenarios) {
            if (bool(sc.opt("app_only"))) appOnly += 1
            val m = UpstreamLeaseMachine(timing(doc), UpstreamExpiryPolicy.REACQUIRE)
            for ((i, step) in sc.getJSONArray("steps").objects().withIndex()) {
                val actual = apply(m, step)
                val expected = step.getJSONObject("expect")
                steps += 1
                val ok = actual != null && canon(actual) == canon(expected)
                c.check(ok) {
                    "${str(sc.opt("name"))} step $i (${str(step.opt("event"))}):\n  expected ${canon(expected)}\n  actual   ${canon(actual)}"
                }
                if (!ok) break // the rest of the scenario follows from a wrong state (as the C++ replayer)
            }
        }
        c.check(steps >= 200) { "at least 200 steps" }
        println("lease vectors: ${scenarios.size} scenarios ($appOnly app_only, replayed too) / $steps steps replayed; checks ${c.total}")
        c.assertAll()
        assertEquals(53, scenarios.size, "scenario count of the recording (16.11)")
        assertEquals(421, steps, "step count of the recording (16.11)")
    }

    // The service path against the recorded C++ behaviour (Swift replayThroughAdopt): scenarios that start
    // with a granted session acquire and never acquire again are replayed through adopt() (RENEW_UNTIL_GONE)
    // instead of start + acquire_reply; request ids are one lower (adopt sends no acquire).
    @Test
    fun leaseVectorsThroughAdopt() {
        val doc = UpstreamVectors.load("upstream_lease_vectors.json")
        val t = timing(doc)
        val c = Checks("adopt replay")
        val replayed = mutableListOf<String>()
        var notEligible = 0
        scenarios@ for (sc in doc.getJSONArray("scenarios").objects()) {
            if (bool(sc.opt("app_only"))) continue
            val steps = sc.getJSONArray("steps").objects()
            val args = steps.getOrNull(0)?.optJSONObject("args")
            val reply = steps.getOrNull(1)?.optJSONObject("args")?.optJSONObject("reply")
            val grant = reply?.optJSONObject("grant")
            if (steps.size <= 2 || str(steps[0].opt("event")) != "start" || args == null || str(args.opt("kind")) != "session" ||
                str(steps[1].opt("event")) != "acquire_reply" || str(reply?.opt("kind")) != "granted" || grant == null ||
                str(grant.opt("profile_id")) != str(args.opt("profile_id")) || str(grant.opt("kind")) != "session") {
                notEligible += 1
                continue
            }
            for (step in steps.drop(2)) {
                val kinds = step.getJSONObject("expect").getJSONArray("actions").objects().map { str(it.opt("kind")) }
                if ("send_acquire" in kinds || str(step.opt("event")) == "acquire_reply") {
                    notEligible += 1
                    continue@scenarios
                }
            }
            val startNow = i64(steps[0].opt("now_ms"))
            val replyNow = i64(steps[1].opt("now_ms"))
            val env = UpstreamLeaseEnvelope(
                leaseId = str(grant.opt("lease_id")), renewToken = str(grant.opt("renew_token")),
                apiBase = str(grant.opt("tunnel_api_base")), renewAfterS = int(grant.opt("renew_after_s")),
                ttlS = int(grant.opt("ttl_s")),
                expiresInMs = startNow + minOf(int(grant.opt("ttl_s")), t.maxTtlS).toLong() * 1000 - replyNow,
                seq = i64(grant.opt("seq")), epoch = i64(grant.opt("traffic_accounting_epoch")),
                revision = maxOf(i64(args.opt("known_revision")), i64(grant.opt("upstream_revision"))),
                meterScope = scopeFrom(str(args.opt("meter_scope"))))
            val m = UpstreamLeaseMachine(t, UpstreamExpiryPolicy.RENEW_UNTIL_GONE)
            m.adopt(env, str(args.opt("profile_id")), replyNow)
            val name = str(sc.opt("name"))
            for ((index, step) in steps.withIndex().drop(2)) {
                val shifted = JSONObject(step.toString())
                shifted.optJSONObject("args")?.let { a -> if (a.has("request_id")) a.put("request_id", i64(a.opt("request_id")) - 1) }
                val actual = apply(m, shifted) ?: continue
                val expected = JSONObject(step.getJSONObject("expect").toString())
                expected.getJSONArray("actions").objects().forEach { a ->
                    if (a.has("request_id")) a.put("request_id", i64(a.opt("request_id")) - 1)
                }
                if (name == "clock_skew_and_backwards") {
                    // Known divergence (Swift too): the envelope has no server expires_at, so adopt() anchors the
                    // server clock at the first renewal (sent + ttl) instead of at the grant. With a skewed server
                    // clock the local deadline differs by the skew - bounded here to 1 s.
                    val diff = Math.abs(i64(actual.getJSONObject("state").opt("deadline_ms")) -
                        i64(expected.getJSONObject("state").opt("deadline_ms")))
                    c.check(diff <= 1000) { "adopt $name step $index: deadline off by $diff ms" }
                    actual.getJSONObject("state").remove("deadline_ms")
                    expected.getJSONObject("state").remove("deadline_ms")
                }
                c.check(canon(actual) == canon(expected)) {
                    "adopt $name step $index:\n  expected ${canon(expected)}\n  actual   ${canon(actual)}"
                }
            }
            replayed += name
        }
        println("adopt replay (service path vs C++ recording): ${replayed.size} scenarios [${replayed.joinToString(", ")}]; $notEligible not eligible; checks ${c.total}")
        c.assertAll()
        assertTrue(replayed.size >= 10, "adopt replay covers at least 10 scenarios, got ${replayed.size}")
    }

    // ---- upstream_wire_vectors.json -----------------------------------------------------------------------

    private fun errorJson(e: UpstreamErrorReply) = JSONObject()
        .put("code", e.code.wire).put("retry_after_s", e.retryAfterS).put("upstream_revision", e.upstreamRevision)

    private fun kindName(k: UpstreamReplyKind) = when (k) {
        UpstreamReplyKind.GRANTED -> "granted"
        UpstreamReplyKind.REFUSED -> "refused"
        UpstreamReplyKind.FAILED -> "failed"
    }

    private fun acquireResultJson(r: UpstreamAcquireReply): JSONObject {
        val o = JSONObject().put("kind", kindName(r.kind)).put("may_start_provisional", UpstreamLeaseWire.mayStartProvisional(r))
        when (r.kind) {
            UpstreamReplyKind.FAILED -> o.put("why", r.why)
            UpstreamReplyKind.REFUSED -> o.put("error", errorJson(r.error))
            UpstreamReplyKind.GRANTED -> {
                val g = r.grant
                o.put("grant", JSONObject().put("lease_id", g.leaseId).put("profile_id", g.profileId)
                    .put("kind", g.kind.wire).put("expires_at_ms", g.expiresAtMs).put("ttl_s", g.ttlS)
                    .put("renew_after_s", g.renewAfterS).put("seq", g.seq).put("config", g.config)
                    .put("config_sha256", g.configSha256).put("upstream_revision", g.upstreamRevision)
                    .put("traffic_accounting_epoch", g.accountingEpoch).put("renew_token", g.renewToken)
                    .put("tunnel_api_base", g.tunnelApiBase).put("config_changed", g.configChanged))
            }
        }
        return o
    }

    private fun renewResultJson(r: UpstreamRenewReply): JSONObject {
        val o = JSONObject().put("kind", kindName(r.kind))
        when (r.kind) {
            UpstreamReplyKind.FAILED -> o.put("why", r.why)
            UpstreamReplyKind.REFUSED -> o.put("error", errorJson(r.error))
            UpstreamReplyKind.GRANTED -> {
                val w = r.renewal
                o.put("renewal", JSONObject().put("status", if (w.rebaseline) "rebaseline" else "ok")
                    .put("lease_id", w.leaseId).put("expires_at_ms", w.expiresAtMs).put("renew_after_s", w.renewAfterS)
                    .put("seq", w.seq).put("upstream_revision", w.upstreamRevision)
                    .put("traffic_accounting_epoch", w.accountingEpoch).put("config_changed", w.configChanged)
                    .put("applied_bytes", w.appliedBytes).put("shadow_bytes", w.shadowBytes))
            }
        }
        return o
    }

    @Test
    fun wireVectors() {
        val doc = UpstreamVectors.load("upstream_wire_vectors.json")
        val pub = str(doc.opt("pub_key_hex"))
        val c = Checks("wire vectors")
        c.check(str(doc.opt("context")) == UpstreamLeaseWire.LEASE_SIG_CONTEXT) { "context" }
        val cases = doc.getJSONArray("cases").objects()
        c.check(cases.size >= 30) { "at least 30 cases" }
        var acquire = 0
        var renew = 0
        for (case in cases) {
            val body = str(case.opt("body")).toByteArray(Charsets.UTF_8)
            val status = int(case.opt("http_status"))
            val actual = if (str(case.opt("op")) == "acquire") {
                acquire += 1
                acquireResultJson(UpstreamLeaseWire.classifyAcquireReply(status, body, str(case.opt("sig")), pub,
                    bool(case.opt("tribe_api"))))
            } else {
                renew += 1
                renewResultJson(UpstreamLeaseWire.classifyRenewReply(status, body))
            }
            val expected = case.getJSONObject("expect")
            c.check(canon(actual) == canon(expected)) {
                "wire ${str(case.opt("name"))}:\n  expected ${canon(expected)}\n  actual   ${canon(actual)}"
            }
        }
        println("wire vectors: ${cases.size} cases replayed ($acquire acquire, $renew renew); checks ${c.total}")
        c.assertAll()
        assertEquals(55, cases.size, "case count of the recording (16.11)")
    }

    // ---- upstream_signature_vectors.json ------------------------------------------------------------------

    @Test
    fun signatureVectors() {
        val doc = UpstreamVectors.load("upstream_signature_vectors.json")
        val pub = str(doc.opt("pub_key_hex"))
        val seedHex = str(doc.opt("seed_hex"))
        val c = Checks("signature vectors")
        // The key is the one derived from the published test seed - never a real key.
        val seed = MessageDigest.getInstance("SHA-256").digest("tribe-upstream-test-vectors-NOT-A-REAL-KEY".toByteArray())
        val priv = KeyFactory.getInstance("Ed25519").generatePrivate(EdECPrivateKeySpec(NamedParameterSpec.ED25519, seed))
        val probe = "seed-to-public-key".toByteArray()
        val probeSig = Signature.getInstance("Ed25519").run { initSign(priv); update(probe); sign() }
        val seedMatchesPub = UpstreamLeaseWire.verifyDetached(pub, probe, java.util.Base64.getEncoder().encodeToString(probeSig))
        c.check(seedMatchesPub && seedHex == UpstreamLeaseWire.hex(seed)) { "pub_key_hex / seed_hex = the published test seed" }
        c.check(pub != "67bddcb248215a35ee2d8c2145ce415071ba02c5bcf888e35cc4491957aac78f" &&
            pub != "95da1bd9062653d9c185c3ca5cae995516a8e353abccd3cf98cd12cd2f3a075a") { "never a real key" }
        val cases = doc.getJSONArray("cases").objects()
        c.check(cases.size >= 3) { "at least 3 cases" }
        var fields = 0
        for (case in cases) {
            val body = str(case.opt("body")).toByteArray(Charsets.UTF_8)
            val ctx = str(case.opt("context"))
            val sig = str(case.opt("sig"))
            val name = str(case.opt("name"))
            val actual = mapOf(
                "signing_input_hex" to UpstreamLeaseWire.hex(UpstreamLeaseWire.signingInput(body, ctx)),
                "verifies_with_context" to UpstreamLeaseWire.verifyDetachedWithContext(pub, ctx, body, sig),
                "verifies_bare" to UpstreamLeaseWire.verifyDetached(pub, body, sig),
            )
            for ((key, value) in actual) {
                fields += 1
                c.check(canon(case.opt(key)) == canon(value)) { "signature $name field $key: expected ${case.opt(key)}, actual $value" }
            }
        }
        println("signature vectors: ${cases.size} cases / $fields fields replayed; checks ${c.total}")
        c.assertAll()
        assertEquals(7, cases.size, "case count of the recording (16.11)")
    }
}
