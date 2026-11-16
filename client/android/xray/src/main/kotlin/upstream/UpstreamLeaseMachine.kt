package org.amnezia.vpn.protocol.xray.upstream

// AVPN upstream nodes (plan provider-pool, release C, lane A2): the seat lease of one upstream session as
// a pure state machine - the Kotlin twin of client/platforms/ios/UpstreamLeaseMachine.swift and of
// client/core/serviceEngine/UpstreamLeaseMachine.h. No Android imports, no timers, no I/O, no clock reads:
// events go in (answers of its own requests, cumulative tunnel byte counters, `nowMs`), actions come out
// (send renew / release, leave the node with a code, restart the byte counters, revision / config
// changed). Every step says when it wants the next tick (wakeAtMs); the owner (UpstreamLeaseRenewer.kt)
// calls tick(now) at or after that moment.
//
// Two modes (expiry policy), as in the Swift twin:
//  - REACQUIRE = byte-for-byte the C++ machine, including the provisional (standby pack) start of the app
//    process. Only used to replay the shared vectors (src/test) against the C++ recording.
//  - RENEW_UNTIL_GONE = the Android Xray service (decision A-1). It never acquires (the app process does,
//    with the device token and the signature key). It starts from a granted lease (adopt) and, when the
//    lease's TTL passed without a successful renewal, keeps sending the SAME report (same seq) - once at
//    the deadline itself, then on the normal backoff - until the server answers. A renewal answer keeps
//    the session; `lease_gone` (or another terminal code) ends it (LEAVE_NODE). Transport failures alone
//    never end it (the server frees the seat at TTL; accepted by the owner 13.11).
//
// Clock (contract section 7): `nowMs` = milliseconds of a clock that keeps running while the device sleeps
// (Android: SystemClock.elapsedRealtime()). A `nowMs` earlier than the last one is read as the last one.
// Upstream Amnezia has no counterpart.

enum class UpstreamLeaseKind(val wire: String) {
    SESSION("session"),
    PROBE("probe"),
}

enum class UpstreamMeterScope(val wire: String) {
    PROXY("proxy"),
    TUNNEL("tunnel");

    companion object {
        fun fromWire(s: String): UpstreamMeterScope? = entries.firstOrNull { it.wire == s }
    }
}

enum class UpstreamErrorCode(val wire: String) {
    NOT_ENTITLED("not_entitled"),
    OVER_QUOTA("over_quota"),
    DISABLED("disabled"),
    LEASE_GONE("lease_gone"),
    NO_SEAT("no_seat"),
    RATE_LIMITED("rate_limited"),
    UPSTREAM_UNAVAILABLE("upstream_unavailable"),
    INVALID_REQUEST("invalid_request"), // 422: a contract bug, never terminal by itself
    UNKNOWN("unknown");

    // The four answers after which the session leaves the upstream node at once (D6).
    val isTerminal: Boolean
        get() = this == NOT_ENTITLED || this == OVER_QUOTA || this == DISABLED || this == LEASE_GONE

    companion object {
        fun from(code: String): UpstreamErrorCode = entries.firstOrNull { it != UNKNOWN && it.wire == code } ?: UNKNOWN
    }
}

data class UpstreamErrorReply(
    val code: UpstreamErrorCode = UpstreamErrorCode.UNKNOWN,
    val retryAfterS: Int = -1,       // -1 = not given
    val upstreamRevision: Long = 0,  // 0 = not given
    val reason: String = "",         // optional server detail; journal only, never decides
)

// The data-check grant inside a lease answer (`probe`, backend 14.11). Parsed only so a malformed signed
// answer is refused as a whole, exactly as the C++ app does; the Android service never uses it.
data class UpstreamProbeGrant(
    val scanToken: String = "",      // secret, never log
    val expiresInS: Int = 0,
    val accessAsn: Long = 0,
    val accessNetToken: String = "",
    val path: String = "/v1/probe",
)

data class UpstreamLeaseGrant(
    val leaseId: String = "",
    val profileId: String = "",
    val kind: UpstreamLeaseKind = UpstreamLeaseKind.SESSION,
    val expiresAtMs: Long = 0,       // server clock; only differences between two server times are used
    val ttlS: Int = 0,
    val renewAfterS: Int = 0,
    val seq: Long = 0,
    val config: String = "",         // secret, never log
    val configSha256: String = "",
    val upstreamRevision: Long = 0,
    val accountingEpoch: Long = 0,
    val renewToken: String = "",     // secret, never log
    val tunnelApiBase: String = "",
    val configChanged: Boolean = false,
    val probe: UpstreamProbeGrant? = null,
    val meterTags: List<String> = emptyList(),
)

data class UpstreamRenewal(
    val rebaseline: Boolean = false,
    val leaseId: String = "",
    val expiresAtMs: Long = 0,
    val renewAfterS: Int = 0,
    val seq: Long = 0,
    val upstreamRevision: Long = 0,
    val accountingEpoch: Long = 0,
    val configChanged: Boolean = false,
    val appliedBytes: Long = 0,
    val shadowBytes: Long = 0,
)

// One metering report (renew body, release body); the Swift `UpstreamMeter`. `epoch` = the accounting
// epoch the owner believes when the report is SENT (the server's exact fence); 0 = unknown, still sent.
data class UpstreamMeterReport(
    val seq: Long = 0,
    val rxDelta: Long = 0,
    val txDelta: Long = 0,
    val scope: UpstreamMeterScope = UpstreamMeterScope.TUNNEL,
    val epoch: Long = 0,
)

enum class UpstreamReplyKind { GRANTED, REFUSED, FAILED }

data class UpstreamAcquireReply(
    val kind: UpstreamReplyKind = UpstreamReplyKind.FAILED,
    val grant: UpstreamLeaseGrant = UpstreamLeaseGrant(),
    val error: UpstreamErrorReply = UpstreamErrorReply(),
    val why: String = "",
    val fromTribeApi: Boolean = false, // the answer carried `X-Tribe-Api: 1`
)

data class UpstreamRenewReply(
    val kind: UpstreamReplyKind = UpstreamReplyKind.FAILED,
    val renewal: UpstreamRenewal = UpstreamRenewal(),
    val error: UpstreamErrorReply = UpstreamErrorReply(),
    val why: String = "",
)

data class UpstreamLeaseRoute(
    val renewToken: String = "",     // secret, never log
    val apiBase: String = "",
)

enum class UpstreamLeaseActionKind(val wire: String) {
    SEND_ACQUIRE("send_acquire"),
    SEND_RENEW("send_renew"),
    SEND_RELEASE("send_release"),
    LEASE_READY("lease_ready"),
    LEASE_CONFIRMED("lease_confirmed"),
    LEAVE_NODE("leave_node"),
    TRY_NEXT_CANDIDATE("try_next_candidate"),
    RESTART_BYTE_COUNTERS("restart_byte_counters"),
    CONFIG_CHANGED("config_changed"),
    REVISION_CHANGED("revision_changed"),
}

data class UpstreamLeaseAction(
    val kind: UpstreamLeaseActionKind,
    val requestId: Long = 0,
    val profileId: String = "",
    val leaseKind: UpstreamLeaseKind = UpstreamLeaseKind.SESSION,
    val leaseId: String = "",
    val meter: UpstreamMeterReport = UpstreamMeterReport(),
    val route: UpstreamLeaseRoute = UpstreamLeaseRoute(),
    val provisional: Boolean = false,
    val standby: Boolean = false,
    val configSha256: String = "",
    val reason: String = "",
    val detail: String = "",
    val upstreamRevision: Long = 0,
)

class UpstreamLeaseStep {
    val actions: MutableList<UpstreamLeaseAction> = mutableListOf()
    var wakeAtMs: Long = -1 // call tick() at or after this moment; -1 = nothing scheduled

    fun find(kind: UpstreamLeaseActionKind): UpstreamLeaseAction? = actions.firstOrNull { it.kind == kind }
}

enum class UpstreamLeasePhase(val wire: String) {
    IDLE("idle"),
    ACQUIRING("acquiring"),
    ACTIVE("active"),
    RELEASED("released"),
    LEFT("left"),
    FAILED("failed"),
    PROVISIONAL("provisional"),
}

data class UpstreamLeaseTiming(
    val maxTtlS: Int = 3600,       // kUpstreamLeaseTtlMaxS
    val minRenewS: Int = 30,       // kUpstreamRenewMinS
    val defaultRenewS: Int = 300,  // kUpstreamRenewDefaultS
    val retryBaseS: Int = 15,
    val retryMaxS: Int = 120,
    val maxRetryAfterS: Int = 900,
)

enum class UpstreamExpiryPolicy {
    REACQUIRE,        // the C++ machine (vector replay)
    RENEW_UNTIL_GONE, // the Android Xray service
}

// The granted lease as the service receives it (start envelope `upstream_lease`, contract section 1, or
// the app message `upstream_lease_set`).
data class UpstreamLeaseEnvelope(
    val leaseId: String = "",
    val renewToken: String = "",   // secret, never log
    val apiBase: String = "",      // normalized: https, host, no user info / query / fragment, no trailing /
    val renewAfterS: Int = 0,
    val ttlS: Int = 0,
    val expiresInMs: Long = 0,     // relative to the envelope's creation, anchored at receipt
    val seq: Long = 0,
    val epoch: Long = 0,
    val revision: Long = 0,
    val meterScope: UpstreamMeterScope = UpstreamMeterScope.TUNNEL,
    val meterTags: List<String> = emptyList(),
)

// Lab 14.11 D3 (C++ upstreamEarlyRetryDelayMs): spacing before the n-th early retry of a provisional seat
// confirmation: 300, 600, 1200, 2000, 2000, ... ms.
internal fun upstreamEarlyRetryDelayMs(retryNumber: Int): Long {
    val n = retryNumber.coerceIn(1, 16)
    return minOf(300L shl (n - 1), 2000L)
}

class UpstreamLeaseMachine(
    val timing: UpstreamLeaseTiming = UpstreamLeaseTiming(),
    val expiryPolicy: UpstreamExpiryPolicy,
) {
    private enum class Inflight { NONE, ACQUIRE, RENEW }

    // Everything a new session starts from scratch (reset() replaces it as a whole).
    private class State {
        var phase = UpstreamLeasePhase.IDLE
        var profileId = ""
        var kind = UpstreamLeaseKind.SESSION
        var meterScope = UpstreamMeterScope.TUNNEL
        var route = UpstreamLeaseRoute()
        var knownRevision = 0L
        var leaseId = ""
        var lastAcceptedSeq = 0L
        var accountingEpoch = 0L
        var frozen = UpstreamMeterReport()
        var frozenValid = false
        var unreportedRx = 0L
        var unreportedTx = 0L
        var lastRx = 0L
        var lastTx = 0L
        var ttlS = 0
        var anchorLocalMs = 0L
        var anchorServerMs = 0L
        var hasServerAnchor = false
        var deadlineMs = 0L
        var nextRenewMs = -1L
        var retryAtMs = 0L
        var failures = 0
        var renewRejectedInRow = 0
        var inflight = Inflight.NONE
        var inflightId = 0L
        var requestSentMs = 0L
        var ready = false
        var configChangedNoted = false
        var expiryAttempted = false
        // Provisional start (C++ startProvisional / tunnelUp; app process only, replayed by the vectors).
        var standbySha = ""
        var confirmBudgetMs = 0L
        var confirmDeadlineMs = 0L
        var tunnelUp = false
        // Owner-side status (contract section 5); not part of the C++ state.
        var lastRenewOkMs = -1L
        var appliedBytesTotal = 0L
        var shadowBytesTotal = 0L
        var leaveReason = ""
    }

    private var st = State()
    // Kept across sessions (reset): request ids stay unique, a cancelled acquire's late grant is still
    // given back, the clock never goes back.
    private var nextId = 0L
    private var cancelledAcquireId = 0L
    private var cancelledScope = UpstreamMeterScope.TUNNEL
    private var lastNow = 0L

    val phase: UpstreamLeasePhase get() = st.phase
    val provisional: Boolean get() = st.phase == UpstreamLeasePhase.PROVISIONAL
    val profileId: String get() = st.profileId
    val kind: UpstreamLeaseKind get() = st.kind
    val meterScope: UpstreamMeterScope get() = st.meterScope
    val route: UpstreamLeaseRoute get() = st.route
    val knownRevision: Long get() = st.knownRevision
    val leaseId: String get() = st.leaseId
    val lastAcceptedSeq: Long get() = st.lastAcceptedSeq
    val accountingEpoch: Long get() = st.accountingEpoch
    val deadlineMs: Long get() = st.deadlineMs
    val reportInDoubt: Boolean get() = st.frozenValid
    val unreportedRx: Long get() = st.unreportedRx
    val unreportedTx: Long get() = st.unreportedTx
    val renewRejectedInRow: Int get() = st.renewRejectedInRow
    val configChangedNoted: Boolean get() = st.configChangedNoted
    val lastRenewOkMs: Long get() = st.lastRenewOkMs
    val appliedBytesTotal: Long get() = st.appliedBytesTotal
    val shadowBytesTotal: Long get() = st.shadowBytesTotal
    val leaveReason: String get() = st.leaveReason

    // ---- events ----------------------------------------------------------------------------------------

    // A new session on profileId (the C++ start). Ignored while a session runs.
    fun start(profileId: String, kind: UpstreamLeaseKind, scope: UpstreamMeterScope, knownRevision: Long,
              nowMs: Long): UpstreamLeaseStep {
        val s = UpstreamLeaseStep()
        if (busy) return s
        reset()
        val now = clock(nowMs)
        st.profileId = profileId
        st.kind = kind
        st.meterScope = scope
        st.knownRevision = knownRevision
        st.phase = UpstreamLeasePhase.ACQUIRING
        sendAcquire(now, s)
        return s
    }

    // The C++ provisional start from a standby-pack entry (app process only; replayed by the vectors).
    fun startProvisional(profileId: String, scope: UpstreamMeterScope, packConfigSha256: String,
                         tunnelApiBase: String, knownRevision: Long, confirmBudgetMs: Long,
                         nowMs: Long): UpstreamLeaseStep {
        val s = UpstreamLeaseStep()
        if (busy) return s
        reset()
        clock(nowMs)
        st.profileId = profileId
        st.kind = UpstreamLeaseKind.SESSION
        st.meterScope = scope
        st.knownRevision = knownRevision
        st.standbySha = packConfigSha256
        st.route = UpstreamLeaseRoute(apiBase = tunnelApiBase)
        st.confirmBudgetMs = maxOf(0L, confirmBudgetMs)
        st.phase = UpstreamLeasePhase.PROVISIONAL
        s.actions += UpstreamLeaseAction(UpstreamLeaseActionKind.LEASE_READY, provisional = true, route = st.route)
        push(s, UpstreamLeaseActionKind.RESTART_BYTE_COUNTERS)
        return s
    }

    // The provisional tunnel is up: confirm the seat through it (C++ tunnelUp).
    fun tunnelUp(nowMs: Long): UpstreamLeaseStep {
        val s = UpstreamLeaseStep()
        val now = clock(nowMs)
        if (st.phase != UpstreamLeasePhase.PROVISIONAL || st.tunnelUp) return s
        st.tunnelUp = true
        st.confirmDeadlineMs = now + st.confirmBudgetMs
        sendAcquire(now, s)
        return s
    }

    // The service's start: the lease was granted to the app (acquire, signature and sanitizer there).
    // Same state as start() + a granted acquire at `nowMs`, with the local deadline = now + expires_in_ms
    // (the server's expires_at is not in the envelope: the first renewal answer anchors the server
    // clock). No LEASE_READY / RESTART_BYTE_COUNTERS: the counters already start at tunnel bring-up, and
    // bytes carried before a late hand-over belong to the first report.
    fun adopt(lease: UpstreamLeaseEnvelope, profileId: String, nowMs: Long): UpstreamLeaseStep {
        val s = UpstreamLeaseStep()
        if (busy && st.phase != UpstreamLeasePhase.PROVISIONAL) return s
        // reset() zeroes the byte baseline too: the counters are cumulative since tunnel start, so the
        // next read after a late hand-over counts everything carried while pending (Swift, unchanged).
        reset()
        val now = clock(nowMs)
        st.profileId = profileId
        st.kind = UpstreamLeaseKind.SESSION
        st.meterScope = lease.meterScope
        st.knownRevision = lease.revision
        st.leaseId = lease.leaseId
        st.route = UpstreamLeaseRoute(lease.renewToken, lease.apiBase)
        st.accountingEpoch = lease.epoch
        st.lastAcceptedSeq = lease.seq
        st.ttlS = minOf(lease.ttlS, timing.maxTtlS)
        st.requestSentMs = now
        val maxMs = timing.maxTtlS.toLong() * 1000
        st.anchorLocalMs = now + lease.expiresInMs.coerceIn(0L, maxMs)
        st.hasServerAnchor = false
        st.deadlineMs = st.anchorLocalMs
        st.nextRenewMs = now + renewDelayMs(lease.renewAfterS)
        st.retryAtMs = 0
        st.failures = 0
        st.expiryAttempted = false
        st.phase = UpstreamLeasePhase.ACTIVE
        st.ready = true
        s.wakeAtMs = wake(now)
        return s
    }

    // The service before the hand-over of a provisional start: running, bytes counted from bring-up,
    // nothing to send.
    fun beginPending(profileId: String, nowMs: Long) {
        if (busy) return
        reset()
        clock(nowMs)
        st.profileId = profileId
        st.phase = UpstreamLeasePhase.PROVISIONAL
    }

    fun onAcquireReply(requestId: Long, reply: UpstreamAcquireReply, nowMs: Long): UpstreamLeaseStep {
        val s = UpstreamLeaseStep()
        val now = clock(nowMs)
        if (st.inflight != Inflight.ACQUIRE || requestId != st.inflightId) {
            // A lease granted to an acquire cancelled by disconnect(): give the seat back at once.
            if (requestId != 0L && requestId == cancelledAcquireId && reply.kind == UpstreamReplyKind.GRANTED) {
                cancelledAcquireId = 0
                nextId += 1
                s.actions += UpstreamLeaseAction(
                    UpstreamLeaseActionKind.SEND_RELEASE,
                    requestId = nextId,
                    leaseId = reply.grant.leaseId,
                    meter = UpstreamMeterReport(reply.grant.seq + 1, 0, 0, cancelledScope, reply.grant.accountingEpoch),
                    route = UpstreamLeaseRoute(reply.grant.renewToken, reply.grant.tunnelApiBase),
                )
            }
            return s
        }
        st.inflight = Inflight.NONE
        if (st.phase == UpstreamLeasePhase.PROVISIONAL) return onProvisionalReply(reply, now)
        if (reply.kind == UpstreamReplyKind.GRANTED &&
            (reply.grant.profileId != st.profileId || reply.grant.kind != st.kind)) {
            return onAcquireProblem(UpstreamAcquireReply(why = "mismatch"), now)
        }
        if (reply.kind != UpstreamReplyKind.GRANTED) return onAcquireProblem(reply, now)
        val g = reply.grant
        noteRevision(g.upstreamRevision, s)
        if (st.ready) {
            // A re-acquire after the TTL passed. An unanswered report of the same lease is kept only when
            // the server's seq shows it was not applied; on another lease it is in doubt: dropped.
            if (st.frozenValid && !(g.leaseId == st.leaseId && g.seq < st.frozen.seq)) st.frozenValid = false
            st.lastAcceptedSeq = if (g.leaseId == st.leaseId) maxOf(st.lastAcceptedSeq, g.seq) else g.seq
            if (g.accountingEpoch != st.accountingEpoch) {
                st.unreportedRx = 0
                st.unreportedTx = 0
                st.frozenValid = false
                push(s, UpstreamLeaseActionKind.RESTART_BYTE_COUNTERS)
            }
        } else {
            st.lastAcceptedSeq = g.seq
            st.frozenValid = false
            st.unreportedRx = 0
            st.unreportedTx = 0
            st.lastRx = 0
            st.lastTx = 0
            s.actions += UpstreamLeaseAction(
                UpstreamLeaseActionKind.LEASE_READY,
                leaseId = g.leaseId,
                route = UpstreamLeaseRoute(g.renewToken, g.tunnelApiBase),
            )
            push(s, UpstreamLeaseActionKind.RESTART_BYTE_COUNTERS)
        }
        st.leaseId = g.leaseId
        st.route = UpstreamLeaseRoute(g.renewToken, g.tunnelApiBase)
        st.accountingEpoch = g.accountingEpoch
        st.ttlS = minOf(g.ttlS, timing.maxTtlS)
        st.anchorLocalMs = st.requestSentMs + st.ttlS.toLong() * 1000
        st.anchorServerMs = g.expiresAtMs
        st.hasServerAnchor = true
        st.deadlineMs = st.anchorLocalMs
        st.nextRenewMs = if (st.kind == UpstreamLeaseKind.SESSION) now + renewDelayMs(g.renewAfterS) else -1
        st.retryAtMs = 0
        st.failures = 0
        st.expiryAttempted = false
        st.phase = UpstreamLeasePhase.ACTIVE
        st.ready = true
        s.wakeAtMs = wake(now)
        return s
    }

    fun onRenewReply(requestId: Long, reply: UpstreamRenewReply, nowMs: Long): UpstreamLeaseStep {
        val s = UpstreamLeaseStep()
        val now = clock(nowMs)
        if (st.inflight != Inflight.RENEW || requestId != st.inflightId) return s
        st.inflight = Inflight.NONE
        noteRevision(if (reply.kind == UpstreamReplyKind.GRANTED) reply.renewal.upstreamRevision else reply.error.upstreamRevision, s)
        if (reply.kind == UpstreamReplyKind.REFUSED && reply.error.code.isTerminal) {
            leave(s, reply.error.code.wire, reply.error.reason)
            return s
        }
        // Lab 14.11 D2: renewals rejected as malformed in a row end the session.
        if (UpstreamLeaseWire.renewRejected(reply)) {
            st.renewRejectedInRow += 1
            if (st.renewRejectedInRow >= RENEW_REJECTED_LIMIT) {
                leave(s, "renew_rejected")
                return s
            }
        } else if (!(reply.kind == UpstreamReplyKind.FAILED && reply.why == "transport")) {
            st.renewRejectedInRow = 0 // any other HTTP answer breaks the row
        }
        if (reply.kind != UpstreamReplyKind.GRANTED || reply.renewal.leaseId != st.leaseId) {
            // No usable answer: the same report is resent later, under the same seq.
            scheduleRetry(now, if (reply.kind == UpstreamReplyKind.REFUSED) reply.error.retryAfterS else -1)
            s.wakeAtMs = wake(now)
            return s
        }
        val w = reply.renewal
        st.lastAcceptedSeq = maxOf(st.lastAcceptedSeq, maxOf(if (st.frozenValid) st.frozen.seq else 0L, w.seq))
        st.frozenValid = false
        if (w.rebaseline) {
            st.unreportedRx = 0
            st.unreportedTx = 0
            push(s, UpstreamLeaseActionKind.RESTART_BYTE_COUNTERS)
        }
        st.accountingEpoch = w.accountingEpoch
        if (!st.hasServerAnchor) {
            // adopt() had no server time: this answer's expires_at is the server's view of "sent + ttl".
            st.anchorLocalMs = st.requestSentMs + st.ttlS.toLong() * 1000
            st.anchorServerMs = w.expiresAtMs
            st.hasServerAnchor = true
        }
        val moved = st.anchorLocalMs + (w.expiresAtMs - st.anchorServerMs)
        st.deadlineMs = minOf(moved, st.requestSentMs + timing.maxTtlS.toLong() * 1000)
        st.nextRenewMs = now + renewDelayMs(w.renewAfterS)
        st.retryAtMs = 0
        st.failures = 0
        st.expiryAttempted = false
        st.lastRenewOkMs = now
        st.appliedBytesTotal = saturatingAdd(st.appliedBytesTotal, maxOf(0L, w.appliedBytes))
        st.shadowBytesTotal = saturatingAdd(st.shadowBytesTotal, maxOf(0L, w.shadowBytes))
        if (w.configChanged && !st.configChangedNoted) {
            st.configChangedNoted = true
            push(s, UpstreamLeaseActionKind.CONFIG_CHANGED)
        }
        s.wakeAtMs = wake(now)
        return s
    }

    // Cumulative byte counters of the running tunnel (any moment, any rate). A counter that went back is
    // read as restarted from 0.
    fun onTunnelBytes(rxTotal: Long, txTotal: Long) {
        if (st.phase != UpstreamLeasePhase.ACTIVE && st.phase != UpstreamLeasePhase.PROVISIONAL) return
        val rx = maxOf(0L, rxTotal)
        val tx = maxOf(0L, txTotal)
        st.unreportedRx = saturatingAdd(st.unreportedRx, if (rx >= st.lastRx) rx - st.lastRx else rx)
        st.unreportedTx = saturatingAdd(st.unreportedTx, if (tx >= st.lastTx) tx - st.lastTx else tx)
        st.lastRx = rx
        st.lastTx = tx
    }

    // After RESTART_BYTE_COUNTERS, for an owner whose counters cannot restart: the current totals become
    // the baseline (nothing counted).
    fun baselineBytes(rxTotal: Long, txTotal: Long) {
        st.lastRx = maxOf(0L, rxTotal)
        st.lastTx = maxOf(0L, txTotal)
    }

    fun tick(nowMs: Long): UpstreamLeaseStep {
        val s = UpstreamLeaseStep()
        val now = clock(nowMs)
        if (st.phase == UpstreamLeasePhase.PROVISIONAL && st.tunnelUp && st.inflight == Inflight.NONE) {
            if (now >= st.confirmDeadlineMs) {
                leave(s, "standby_unconfirmed")
            } else if (now >= st.retryAtMs) {
                sendAcquire(now, s)
            }
        }
        if (st.phase == UpstreamLeasePhase.ACTIVE && st.inflight == Inflight.NONE) {
            if (now >= st.deadlineMs && expiryPolicy == UpstreamExpiryPolicy.REACQUIRE) {
                // The lease is dead: a session re-acquires (never renews a dead lease) - once at once, then
                // on the backoff; a probe ends.
                if (st.kind == UpstreamLeaseKind.SESSION && (!st.expiryAttempted || now >= st.retryAtMs)) {
                    st.expiryAttempted = true
                    sendAcquire(now, s)
                }
            } else if (now >= st.deadlineMs && st.frozenValid && !st.expiryAttempted) {
                // RENEW_UNTIL_GONE: the report pending at the deadline goes out once at once (the seat is
                // unaccounted from this moment), then on the backoff.
                st.expiryAttempted = true
                sendRenew(now, s)
            } else if (st.frozenValid) {
                if (now >= st.retryAtMs) sendRenew(now, s)
            } else if (st.nextRenewMs >= 0 && now >= st.nextRenewMs) { // a probe has no schedule (-1)
                // A retry resends this report unchanged (same seq and deltas).
                st.frozen = UpstreamMeterReport(st.lastAcceptedSeq + 1, st.unreportedRx, st.unreportedTx,
                    st.meterScope, st.accountingEpoch)
                st.frozenValid = true
                st.unreportedRx = 0
                st.unreportedTx = 0
                sendRenew(now, s)
            }
        }
        s.wakeAtMs = wake(now)
        return s
    }

    fun disconnect(nowMs: Long): UpstreamLeaseStep {
        val s = UpstreamLeaseStep()
        clock(nowMs)
        if (st.phase == UpstreamLeasePhase.ACTIVE && st.leaseId.isNotEmpty()) {
            nextId += 1
            val meter = if (st.frozenValid) {
                UpstreamMeterReport(st.frozen.seq, saturatingAdd(st.frozen.rxDelta, st.unreportedRx),
                    saturatingAdd(st.frozen.txDelta, st.unreportedTx), st.meterScope, st.accountingEpoch)
            } else {
                UpstreamMeterReport(st.lastAcceptedSeq + 1, st.unreportedRx, st.unreportedTx, st.meterScope,
                    st.accountingEpoch)
            }
            s.actions += UpstreamLeaseAction(UpstreamLeaseActionKind.SEND_RELEASE, requestId = nextId,
                leaseId = st.leaseId, meter = meter, route = st.route)
        } else if ((st.phase == UpstreamLeasePhase.ACQUIRING || st.phase == UpstreamLeasePhase.PROVISIONAL) &&
            st.inflight == Inflight.ACQUIRE) {
            cancelledAcquireId = st.inflightId
            cancelledScope = st.meterScope
        }
        if (busy) st.phase = UpstreamLeasePhase.RELEASED
        st.inflight = Inflight.NONE
        st.ready = false
        return s
    }

    // ---- private ---------------------------------------------------------------------------------------

    private val busy: Boolean
        get() = st.phase == UpstreamLeasePhase.ACQUIRING || st.phase == UpstreamLeasePhase.ACTIVE ||
            st.phase == UpstreamLeasePhase.PROVISIONAL

    private fun reset() {
        st = State()
    }

    private fun clock(nowMs: Long): Long {
        val now = if (nowMs < lastNow) lastNow else nowMs
        lastNow = now
        return now
    }

    private fun push(s: UpstreamLeaseStep, kind: UpstreamLeaseActionKind, reason: String = "") {
        s.actions += UpstreamLeaseAction(kind, reason = reason)
    }

    private fun noteRevision(rev: Long, s: UpstreamLeaseStep) {
        if (rev > st.knownRevision) {
            st.knownRevision = rev
            s.actions += UpstreamLeaseAction(UpstreamLeaseActionKind.REVISION_CHANGED, upstreamRevision = rev)
        }
    }

    private fun sendAcquire(now: Long, s: UpstreamLeaseStep) {
        st.inflight = Inflight.ACQUIRE
        nextId += 1
        st.inflightId = nextId
        st.requestSentMs = now
        val provisional = st.phase == UpstreamLeasePhase.PROVISIONAL
        s.actions += UpstreamLeaseAction(
            UpstreamLeaseActionKind.SEND_ACQUIRE,
            requestId = st.inflightId,
            profileId = st.profileId,
            leaseKind = st.kind,
            standby = provisional,
            configSha256 = if (provisional) st.standbySha else "",
            route = if (provisional) st.route else UpstreamLeaseRoute(),
        )
    }

    private fun sendRenew(now: Long, s: UpstreamLeaseStep) {
        st.inflight = Inflight.RENEW
        nextId += 1
        st.inflightId = nextId
        st.requestSentMs = now
        // The epoch the owner believes NOW (C++ sendRenew).
        st.frozen = st.frozen.copy(epoch = st.accountingEpoch)
        s.actions += UpstreamLeaseAction(UpstreamLeaseActionKind.SEND_RENEW, requestId = st.inflightId,
            leaseId = st.leaseId, meter = st.frozen, route = st.route)
    }

    private fun leave(s: UpstreamLeaseStep, reason: String, detail: String = "") {
        st.phase = UpstreamLeasePhase.LEFT
        st.inflight = Inflight.NONE
        st.ready = false
        st.leaveReason = reason
        s.actions += UpstreamLeaseAction(UpstreamLeaseActionKind.LEAVE_NODE, reason = reason, detail = detail)
    }

    // A provisional session's answer to its standby acquire (C++ onProvisionalReply).
    private fun onProvisionalReply(r: UpstreamAcquireReply, now: Long): UpstreamLeaseStep {
        val s = UpstreamLeaseStep()
        noteRevision(if (r.kind == UpstreamReplyKind.GRANTED) r.grant.upstreamRevision else r.error.upstreamRevision, s)
        val ours = r.kind == UpstreamReplyKind.GRANTED && r.grant.profileId == st.profileId &&
            r.grant.kind == UpstreamLeaseKind.SESSION
        if (ours) {
            val g = r.grant
            st.lastAcceptedSeq = g.seq
            st.frozenValid = false // bytes carried since bring-up stay in the unreported counters
            st.leaseId = g.leaseId
            st.route = UpstreamLeaseRoute(g.renewToken, g.tunnelApiBase.ifEmpty { st.route.apiBase })
            st.accountingEpoch = g.accountingEpoch
            st.ttlS = minOf(g.ttlS, timing.maxTtlS)
            st.anchorLocalMs = st.requestSentMs + st.ttlS.toLong() * 1000
            st.anchorServerMs = g.expiresAtMs
            st.hasServerAnchor = true
            st.deadlineMs = st.anchorLocalMs
            st.nextRenewMs = now + renewDelayMs(g.renewAfterS)
            st.retryAtMs = 0
            st.failures = 0
            st.expiryAttempted = false
            st.phase = UpstreamLeasePhase.ACTIVE
            st.ready = true
            s.actions += UpstreamLeaseAction(UpstreamLeaseActionKind.LEASE_CONFIRMED, leaseId = st.leaseId, route = st.route)
            if (g.configSha256 != st.standbySha || g.configChanged) {
                st.configChangedNoted = true
                push(s, UpstreamLeaseActionKind.CONFIG_CHANGED)
            }
            s.wakeAtMs = wake(now)
            return s
        }
        val refused = r.kind == UpstreamReplyKind.REFUSED
        if (refused && r.error.code == UpstreamErrorCode.NO_SEAT) {
            leave(s, "no_seat_standby")
            return s
        }
        if (refused && r.error.code.isTerminal) {
            leave(s, r.error.code.wire)
            return s
        }
        // Transient (or a grant that is not ours): retried inside the confirm budget, on the short early
        // spacing (lab 14.11 D3) unless the server named its own retry_after_s.
        if (now >= st.confirmDeadlineMs) {
            leave(s, "standby_unconfirmed")
            return s
        }
        val retryAfterS = if (refused) r.error.retryAfterS else -1
        if (retryAfterS > 0) {
            scheduleRetry(now, retryAfterS)
        } else {
            st.failures += 1
            st.retryAtMs = now + upstreamEarlyRetryDelayMs(st.failures)
        }
        s.wakeAtMs = wake(now)
        return s
    }

    private fun onAcquireProblem(r: UpstreamAcquireReply, now: Long): UpstreamLeaseStep {
        val s = UpstreamLeaseStep()
        noteRevision(r.error.upstreamRevision, s)
        val refused = r.kind == UpstreamReplyKind.REFUSED
        if (refused && r.error.code.isTerminal) {
            leave(s, r.error.code.wire, r.error.reason)
            return s
        }
        if (!st.ready) {
            // Before bring-up nobody waits for a retry: the owner moves on to the next candidate.
            st.phase = UpstreamLeasePhase.FAILED
            push(s, UpstreamLeaseActionKind.TRY_NEXT_CANDIDATE,
                if (refused) r.error.code.wire else if (r.why == "transport") "transport" else "invalid_answer")
            return s
        }
        // A re-acquire during a working session. no_seat: the seat went to someone else while the lease was
        // dead - running on would exceed the paid seat count: leave. Anything transient: retried.
        if (refused && r.error.code == UpstreamErrorCode.NO_SEAT) {
            leave(s, "no_seat_reacquire")
            return s
        }
        scheduleRetry(now, if (refused) r.error.retryAfterS else -1)
        s.wakeAtMs = wake(now)
        return s
    }

    private fun scheduleRetry(now: Long, retryAfterS: Int) {
        st.failures += 1
        val delayS: Long = if (retryAfterS > 0) {
            retryAfterS.coerceIn(1, timing.maxRetryAfterS).toLong()
        } else {
            minOf(timing.retryBaseS.toLong() shl minOf(st.failures - 1, 10), timing.retryMaxS.toLong())
        }
        st.retryAtMs = now + delayS * 1000
    }

    private fun renewDelayMs(renewAfterS: Int): Long {
        val hi = maxOf(1, st.ttlS / 2)
        val lo = minOf(timing.minRenewS, hi)
        val v = if (renewAfterS > 0) renewAfterS else timing.defaultRenewS
        return v.coerceIn(lo, hi).toLong() * 1000
    }

    private fun wake(now: Long): Long {
        if (st.phase == UpstreamLeasePhase.PROVISIONAL && st.tunnelUp && st.inflight == Inflight.NONE) {
            return minOf(st.confirmDeadlineMs, maxOf(now, st.retryAtMs))
        }
        if (st.phase != UpstreamLeasePhase.ACTIVE || st.inflight != Inflight.NONE) return -1
        if (expiryPolicy == UpstreamExpiryPolicy.RENEW_UNTIL_GONE) {
            // Nothing happens AT the deadline unless a report is pending (sent once at once there).
            if (st.frozenValid) {
                if (st.expiryAttempted) return maxOf(now, st.retryAtMs)
                return if (now >= st.deadlineMs) now else minOf(maxOf(now, st.retryAtMs), st.deadlineMs)
            }
            return if (st.nextRenewMs >= 0) st.nextRenewMs else -1
        }
        if (now >= st.deadlineMs) {
            if (st.kind != UpstreamLeaseKind.SESSION) return -1
            return if (st.expiryAttempted) maxOf(now, st.retryAtMs) else now
        }
        var next = st.deadlineMs
        if (st.frozenValid) {
            next = minOf(next, maxOf(now, st.retryAtMs))
        } else if (st.nextRenewMs >= 0) {
            next = minOf(next, st.nextRenewMs)
        }
        return next
    }

    companion object {
        // kUpstreamRenewRejectedLimit in UpstreamLeaseMachine.h.
        const val RENEW_REJECTED_LIMIT = 3

        internal fun saturatingAdd(a: Long, b: Long): Long {
            val r = a + b
            return if (((a xor r) and (b xor r)) < 0) (if (a < 0) Long.MIN_VALUE else Long.MAX_VALUE) else r
        }
    }
}
