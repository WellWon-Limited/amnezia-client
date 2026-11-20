import Foundation

// AVPN upstream nodes (plan provider-pool, release A, lane L3): the seat lease of one upstream session
// as a pure state machine - the Swift twin of client/core/serviceEngine/UpstreamLeaseMachine.h (the
// Network Extension links no Qt). Foundation-only, no timers, no I/O, no clock reads: events go in
// (answers of its own requests, cumulative tunnel byte counters, `now`), actions come out (send
// renew / release, leave the node with a code, restart the byte counters, revision / config changed).
// Every step says when it wants the next tick (wakeAtMs); the owner (UpstreamLeaseRenewer.swift)
// calls tick(now) at or after that moment.
//
// Two modes (expiry policy):
//  - .reacquire = byte-for-byte the C++ machine (session start, acquire, re-acquire after the TTL).
//    Only used to replay the shared vectors (tests/UpstreamLeaseVectorTests.swift) against the C++
//    recording, so the two implementations can never drift.
//  - .renewUntilGone = the extension. The extension never acquires (it has no device token and no
//    signing key; acquire and re-acquire are app-side on iOS). It starts from a granted lease
//    (adopt) and, when the lease's TTL passed without a successful renewal, it keeps sending the SAME
//    report (same seq) - once at the deadline itself, then on the normal backoff - until the server
//    answers. A renewal answer keeps the session; `lease_gone` (or another terminal code) ends it
//    (LeaveNode). Transport failures alone never end it (the server frees the seat at TTL; that gap
//    is accepted, owner 13.11). `no_seat_reacquire` therefore never comes from the extension.
//
// Clock (contract section 7): `now` = milliseconds of a clock that keeps running while the device
// sleeps (ContinuousClock / CLOCK_MONOTONIC_RAW). A `now` earlier than the last one is read as the
// last one. Upstream Amnezia has no counterpart.

enum UpstreamLeaseKind: String {
    case session
    case probe
}

enum UpstreamMeterScope: String {
    case proxy
    case tunnel
}

enum UpstreamErrorCode: String {
    case notEntitled = "not_entitled"
    case overQuota = "over_quota"
    case disabled
    case leaseGone = "lease_gone"
    case noSeat = "no_seat"
    case rateLimited = "rate_limited"
    case upstreamUnavailable = "upstream_unavailable"
    case invalidRequest = "invalid_request" // 422: a contract bug, never terminal by itself
    case unknown

    init(code: String) {
        self = UpstreamErrorCode(rawValue: code) ?? .unknown
    }

    // The four answers after which the session leaves the upstream node at once (D6).
    var isTerminal: Bool {
        self == .notEntitled || self == .overQuota || self == .disabled || self == .leaseGone
    }
}

struct UpstreamErrorReply: Equatable {
    var code: UpstreamErrorCode = .unknown
    var retryAfterS: Int = -1          // -1 = not given
    var upstreamRevision: Int64 = 0    // 0 = not given
}

struct UpstreamLeaseGrant: Equatable {
    var leaseId = ""
    var profileId = ""
    var kind: UpstreamLeaseKind = .session
    var expiresAtMs: Int64 = 0         // server clock; only differences between two server times are used
    var ttlS: Int = 0
    var renewAfterS: Int = 0
    var seq: Int64 = 0
    var upstreamRevision: Int64 = 0
    var accountingEpoch: Int64 = 0
    var renewToken = ""
    var tunnelApiBase = ""
    var configSha256 = ""
    var configChanged = false
}

struct UpstreamRenewal: Equatable {
    var rebaseline = false
    var leaseId = ""
    var expiresAtMs: Int64 = 0
    var renewAfterS: Int = 0
    var seq: Int64 = 0
    var upstreamRevision: Int64 = 0
    var accountingEpoch: Int64 = 0
    var configChanged = false
    var appliedBytes: Int64 = 0
    var shadowBytes: Int64 = 0
}

struct UpstreamMeter: Equatable {
    var seq: Int64 = 0
    var rxDelta: Int64 = 0
    var txDelta: Int64 = 0
    var scope: UpstreamMeterScope = .tunnel
    // The traffic accounting epoch the owner believes (envelope `epoch`, replaced by a rebaseline
    // answer); the server's exact fence (contract addition 14.11). 0 = unknown, not sent.
    var epoch: Int64 = 0
}

enum UpstreamReplyKind {
    case granted
    case refused
    case failed
}

struct UpstreamAcquireReply {
    var kind: UpstreamReplyKind = .failed
    var grant = UpstreamLeaseGrant()
    var error = UpstreamErrorReply()
    var why = ""
}

struct UpstreamRenewReply: Equatable {
    var kind: UpstreamReplyKind = .failed
    var renewal = UpstreamRenewal()
    var error = UpstreamErrorReply()
    var why = ""
}

struct UpstreamLeaseRoute: Equatable {
    var renewToken = ""
    var apiBase = ""
}

enum UpstreamLeaseActionKind: String {
    case sendAcquire = "send_acquire"
    case sendRenew = "send_renew"
    case sendRelease = "send_release"
    case leaseReady = "lease_ready"
    case leaseConfirmed = "lease_confirmed"
    case leaveNode = "leave_node"
    case tryNextCandidate = "try_next_candidate"
    case restartByteCounters = "restart_byte_counters"
    case configChanged = "config_changed"
    case revisionChanged = "revision_changed"
}

struct UpstreamLeaseAction: Equatable {
    var kind: UpstreamLeaseActionKind
    var requestId: UInt64 = 0
    var profileId = ""
    var leaseKind: UpstreamLeaseKind = .session
    var leaseId = ""
    var meter = UpstreamMeter()
    var route = UpstreamLeaseRoute()
    var provisional = false
    var standby = false
    var configSha256 = ""
    var reason = ""
    var upstreamRevision: Int64 = 0
}

struct UpstreamLeaseStep {
    var actions: [UpstreamLeaseAction] = []
    var wakeAtMs: Int64 = -1           // call tick() at or after this moment; -1 = nothing scheduled

    func find(_ kind: UpstreamLeaseActionKind) -> UpstreamLeaseAction? {
        actions.first { $0.kind == kind }
    }
}

enum UpstreamLeasePhase: String {
    case idle
    case acquiring
    case active
    case released
    case left
    case failed
    case provisional
}

struct UpstreamLeaseTiming {
    var maxTtlS = 3600       // kUpstreamLeaseTtlMaxS
    var minRenewS = 30       // kUpstreamRenewMinS
    var defaultRenewS = 300  // kUpstreamRenewDefaultS
    var retryBaseS = 15
    var retryMaxS = 120
    var maxRetryAfterS = 900
}

enum UpstreamExpiryPolicy {
    case reacquire       // the C++ machine (vector replay)
    case renewUntilGone  // the iOS extension
}

// The granted lease as the extension receives it (start envelope `upstream_lease`, contract section 1,
// or the app message `upstream_lease_set`).
struct UpstreamLeaseEnvelope: Equatable {
    var leaseId = ""
    var renewToken = ""
    var apiBase = ""             // normalized: https, host, no user info / query / fragment, no trailing /
    var renewAfterS = 0
    var ttlS = 0
    var expiresInMs: Int64 = 0   // relative to the envelope's creation, anchored at receipt
    var seq: Int64 = 0
    var epoch: Int64 = 0
    var revision: Int64 = 0
    var meterScope: UpstreamMeterScope = .tunnel
    var meterTags: [String] = [] // scope "proxy": the outbound tags summed (UpstreamProxyMeter.swift)
}

struct UpstreamLeaseMachine {
    let timing: UpstreamLeaseTiming
    let expiryPolicy: UpstreamExpiryPolicy

    init(timing: UpstreamLeaseTiming = UpstreamLeaseTiming(), expiryPolicy: UpstreamExpiryPolicy) {
        self.timing = timing
        self.expiryPolicy = expiryPolicy
    }

    private enum Inflight { case none, acquire, renew }

    private(set) var phase: UpstreamLeasePhase = .idle
    private(set) var profileId = ""
    private(set) var kind: UpstreamLeaseKind = .session
    private(set) var meterScope: UpstreamMeterScope = .tunnel
    private var cancelledScope: UpstreamMeterScope = .tunnel
    private(set) var route = UpstreamLeaseRoute()
    private(set) var knownRevision: Int64 = 0
    private(set) var leaseId = ""
    private(set) var lastAcceptedSeq: Int64 = 0
    private(set) var accountingEpoch: Int64 = 0
    private var frozen = UpstreamMeter()
    private var frozenValid = false
    private(set) var unreportedRx: Int64 = 0
    private(set) var unreportedTx: Int64 = 0
    private var lastRx: Int64 = 0
    private var lastTx: Int64 = 0
    private var ttlS = 0
    private var anchorLocalMs: Int64 = 0
    private var anchorServerMs: Int64 = 0
    private var hasServerAnchor = false
    private(set) var deadlineMs: Int64 = 0
    private var nextRenewMs: Int64 = -1
    private var retryAtMs: Int64 = 0
    private var failures = 0
    private(set) var renewRejectedInRow = 0 // kUpstreamRenewRejectedLimit in UpstreamLeaseMachine.h
    static let renewRejectedLimit = 3
    private var inflight: Inflight = .none
    private var inflightId: UInt64 = 0
    private var nextId: UInt64 = 0
    private var cancelledAcquireId: UInt64 = 0
    private var requestSentMs: Int64 = 0
    private var ready = false
    private(set) var configChangedNoted = false
    private var expiryAttempted = false
    private var lastNow: Int64 = 0
    // Owner-side status (contract section 5); not part of the C++ state.
    private(set) var lastRenewOkMs: Int64 = -1
    private(set) var appliedBytesTotal: Int64 = 0
    private(set) var shadowBytesTotal: Int64 = 0
    private(set) var leaveReason = ""
    // The session left the node (a terminal answer) while it held a lease: the final report of its bytes is still owed to the
    // server (it meters a release carrying the tenure's token even after the lease ended). "No more renewals" (phase .left) is
    // not "nothing left to release"; disconnect() pays it once.
    private(set) var releaseOwed = false

    var reportInDoubt: Bool { frozenValid }

    // MARK: - events

    // A new session on profileId (the C++ start). Ignored while a session runs.
    mutating func start(profileId: String, kind: UpstreamLeaseKind, scope: UpstreamMeterScope,
                        knownRevision: Int64, nowMs: Int64) -> UpstreamLeaseStep {
        var s = UpstreamLeaseStep()
        if busy { return s }
        reset()
        let now = clock(nowMs)
        self.profileId = profileId
        self.kind = kind
        meterScope = scope
        self.knownRevision = knownRevision
        phase = .acquiring
        sendAcquire(now, &s)
        return s
    }

    // The extension's start: the lease was granted to the app (it went through acquire, signature and
    // sanitizer there). Same state as start() + a granted acquire at `nowMs`, with the local deadline
    // = now + expires_in_ms (the server's own expires_at is not in the envelope: the first renewal
    // answer anchors the server clock). No LeaseReady/RestartByteCounters: the owner's counters already
    // start at tunnel bring-up, and bytes carried before a late hand-over belong to the first report.
    mutating func adopt(lease: UpstreamLeaseEnvelope, profileId: String, nowMs: Int64) -> UpstreamLeaseStep {
        var s = UpstreamLeaseStep()
        if busy && phase != .provisional { return s }
        reset()
        let now = clock(nowMs)
        self.profileId = profileId
        kind = .session
        meterScope = lease.meterScope
        knownRevision = lease.revision
        leaseId = lease.leaseId
        route = UpstreamLeaseRoute(renewToken: lease.renewToken, apiBase: lease.apiBase)
        accountingEpoch = lease.epoch
        lastAcceptedSeq = lease.seq
        ttlS = min(lease.ttlS, timing.maxTtlS)
        requestSentMs = now
        let maxMs = Int64(timing.maxTtlS) * 1000
        anchorLocalMs = now + max(0, min(lease.expiresInMs, maxMs))
        hasServerAnchor = false
        deadlineMs = anchorLocalMs
        nextRenewMs = now + renewDelayMs(lease.renewAfterS)
        retryAtMs = 0
        failures = 0
        expiryAttempted = false
        phase = .active
        ready = true
        s.wakeAtMs = wake(now)
        return s
    }

    // The extension before the hand-over of a provisional start: running, bytes counted from bring-up,
    // nothing to send.
    mutating func beginPending(profileId: String, nowMs: Int64) {
        if busy { return }
        reset()
        _ = clock(nowMs)
        self.profileId = profileId
        phase = .provisional
    }

    mutating func onAcquireReply(requestId: UInt64, reply r: UpstreamAcquireReply, nowMs: Int64) -> UpstreamLeaseStep {
        var s = UpstreamLeaseStep()
        let now = clock(nowMs)
        if inflight != .acquire || requestId != inflightId {
            // A lease granted to an acquire cancelled by disconnect(): give the seat back at once.
            if requestId != 0 && requestId == cancelledAcquireId && r.kind == .granted {
                cancelledAcquireId = 0
                nextId += 1
                var a = UpstreamLeaseAction(kind: .sendRelease)
                a.requestId = nextId
                a.leaseId = r.grant.leaseId
                a.meter = UpstreamMeter(seq: r.grant.seq + 1, rxDelta: 0, txDelta: 0, scope: cancelledScope,
                                        epoch: r.grant.accountingEpoch)
                a.route = UpstreamLeaseRoute(renewToken: r.grant.renewToken, apiBase: r.grant.tunnelApiBase)
                s.actions.append(a)
            }
            return s
        }
        inflight = .none
        if r.kind == .granted && (r.grant.profileId != profileId || r.grant.kind != kind) {
            var bad = UpstreamAcquireReply()
            bad.why = "mismatch"
            return onAcquireProblem(bad, now)
        }
        if r.kind != .granted {
            return onAcquireProblem(r, now)
        }
        let g = r.grant
        noteRevision(g.upstreamRevision, &s)
        if ready {
            // A re-acquire after the TTL passed. An unanswered report of the same lease is kept only
            // when the server's seq shows it was not applied; on another lease it is in doubt: dropped.
            if frozenValid && !(g.leaseId == leaseId && g.seq < frozen.seq) {
                frozenValid = false
            }
            lastAcceptedSeq = (g.leaseId == leaseId) ? max(lastAcceptedSeq, g.seq) : g.seq
            if g.accountingEpoch != accountingEpoch {
                unreportedRx = 0
                unreportedTx = 0
                frozenValid = false
                Self.push(&s, .restartByteCounters)
            }
        } else {
            lastAcceptedSeq = g.seq
            frozenValid = false
            unreportedRx = 0
            unreportedTx = 0
            lastRx = 0
            lastTx = 0
            var ready = UpstreamLeaseAction(kind: .leaseReady)
            ready.leaseId = g.leaseId
            ready.route = UpstreamLeaseRoute(renewToken: g.renewToken, apiBase: g.tunnelApiBase)
            s.actions.append(ready)
            Self.push(&s, .restartByteCounters)
        }
        leaseId = g.leaseId
        route = UpstreamLeaseRoute(renewToken: g.renewToken, apiBase: g.tunnelApiBase)
        accountingEpoch = g.accountingEpoch
        ttlS = min(g.ttlS, timing.maxTtlS)
        anchorLocalMs = requestSentMs + Int64(ttlS) * 1000
        anchorServerMs = g.expiresAtMs
        hasServerAnchor = true
        deadlineMs = anchorLocalMs
        nextRenewMs = (kind == .session) ? now + renewDelayMs(g.renewAfterS) : -1
        retryAtMs = 0
        failures = 0
        expiryAttempted = false
        phase = .active
        ready = true
        s.wakeAtMs = wake(now)
        return s
    }

    mutating func onRenewReply(requestId: UInt64, reply r: UpstreamRenewReply, nowMs: Int64) -> UpstreamLeaseStep {
        var s = UpstreamLeaseStep()
        let now = clock(nowMs)
        if inflight != .renew || requestId != inflightId { return s }
        inflight = .none
        noteRevision(r.kind == .granted ? r.renewal.upstreamRevision : r.error.upstreamRevision, &s)
        if r.kind == .refused && r.error.code.isTerminal {
            releaseOwed = !leaseId.isEmpty
            leave(&s, r.error.code.rawValue)
            return s
        }
        // Lab 14.11 D2 (C++ twin): renewals rejected as malformed in a row end the session.
        if UpstreamLeaseWire.renewRejected(r) {
            renewRejectedInRow += 1
            if renewRejectedInRow >= Self.renewRejectedLimit {
                releaseOwed = !leaseId.isEmpty
                leave(&s, "renew_rejected")
                return s
            }
        } else if !(r.kind == .failed && r.why == "transport") {
            renewRejectedInRow = 0 // any other HTTP answer breaks the row
        }
        if r.kind != .granted || r.renewal.leaseId != leaseId {
            // No usable answer: the same report is resent later, under the same seq.
            scheduleRetry(now, r.kind == .refused ? r.error.retryAfterS : -1)
            s.wakeAtMs = wake(now)
            return s
        }
        let w = r.renewal
        lastAcceptedSeq = max(lastAcceptedSeq, max(frozenValid ? frozen.seq : 0, w.seq))
        frozenValid = false
        if w.rebaseline {
            unreportedRx = 0
            unreportedTx = 0
            Self.push(&s, .restartByteCounters)
        }
        accountingEpoch = w.accountingEpoch
        if !hasServerAnchor {
            // adopt() had no server time: this answer's expires_at is the server's view of
            // "sent + ttl" for this request.
            anchorLocalMs = requestSentMs + Int64(ttlS) * 1000
            anchorServerMs = w.expiresAtMs
            hasServerAnchor = true
        }
        let moved = anchorLocalMs + (w.expiresAtMs - anchorServerMs)
        deadlineMs = min(moved, requestSentMs + Int64(timing.maxTtlS) * 1000)
        nextRenewMs = now + renewDelayMs(w.renewAfterS)
        retryAtMs = 0
        failures = 0
        expiryAttempted = false
        lastRenewOkMs = now
        appliedBytesTotal = Self.saturatingAdd(appliedBytesTotal, max(0, w.appliedBytes))
        shadowBytesTotal = Self.saturatingAdd(shadowBytesTotal, max(0, w.shadowBytes))
        if w.configChanged && !configChangedNoted {
            configChangedNoted = true
            Self.push(&s, .configChanged)
        }
        s.wakeAtMs = wake(now)
        return s
    }

    // Cumulative byte counters of the running tunnel (any moment, any rate). A counter that went back
    // is read as restarted from 0.
    mutating func onTunnelBytes(rxTotal: Int64, txTotal: Int64) {
        if phase != .active && phase != .provisional && !(phase == .left && releaseOwed) { return }
        let rx = max(0, rxTotal)
        let tx = max(0, txTotal)
        unreportedRx = Self.saturatingAdd(unreportedRx, rx >= lastRx ? rx - lastRx : rx)
        unreportedTx = Self.saturatingAdd(unreportedTx, tx >= lastTx ? tx - lastTx : tx)
        lastRx = rx
        lastTx = tx
    }

    // After RestartByteCounters, for an owner whose counters cannot restart: the current totals become
    // the baseline (nothing counted).
    mutating func baselineBytes(rxTotal: Int64, txTotal: Int64) {
        lastRx = max(0, rxTotal)
        lastTx = max(0, txTotal)
    }

    mutating func tick(nowMs: Int64) -> UpstreamLeaseStep {
        var s = UpstreamLeaseStep()
        let now = clock(nowMs)
        if phase == .active && inflight == .none {
            if now >= deadlineMs && expiryPolicy == .reacquire {
                // The lease is dead: a session re-acquires (never renews a dead lease) - once at once,
                // then on the backoff; a probe ends.
                if kind == .session && (!expiryAttempted || now >= retryAtMs) {
                    expiryAttempted = true
                    sendAcquire(now, &s)
                }
            } else if now >= deadlineMs && frozenValid && !expiryAttempted {
                // renewUntilGone: the report pending at the deadline goes out once at once (the seat is
                // unaccounted from this moment), then on the backoff.
                expiryAttempted = true
                sendRenew(now, &s)
            } else if frozenValid {
                if now >= retryAtMs { sendRenew(now, &s) }
            } else if nextRenewMs >= 0 && now >= nextRenewMs { // a probe has no schedule (-1)
                // A retry resends this report unchanged (same seq, deltas and epoch).
                frozen = UpstreamMeter(seq: lastAcceptedSeq + 1, rxDelta: unreportedRx, txDelta: unreportedTx,
                                       scope: meterScope, epoch: accountingEpoch)
                frozenValid = true
                unreportedRx = 0
                unreportedTx = 0
                sendRenew(now, &s)
            }
        }
        s.wakeAtMs = wake(now)
        return s
    }

    mutating func disconnect(nowMs: Int64) -> UpstreamLeaseStep {
        var s = UpstreamLeaseStep()
        _ = clock(nowMs)
        if (phase == .active || (phase == .left && releaseOwed)) && !leaseId.isEmpty {
            releaseOwed = false
            nextId += 1
            var a = UpstreamLeaseAction(kind: .sendRelease)
            a.requestId = nextId
            a.leaseId = leaseId
            a.meter = frozenValid
                ? UpstreamMeter(seq: frozen.seq, rxDelta: Self.saturatingAdd(frozen.rxDelta, unreportedRx),
                                txDelta: Self.saturatingAdd(frozen.txDelta, unreportedTx), scope: meterScope,
                                epoch: accountingEpoch)
                : UpstreamMeter(seq: lastAcceptedSeq + 1, rxDelta: unreportedRx, txDelta: unreportedTx, scope: meterScope,
                                epoch: accountingEpoch)
            a.route = route
            s.actions.append(a)
        } else if (phase == .acquiring || phase == .provisional) && inflight == .acquire {
            cancelledAcquireId = inflightId
            cancelledScope = meterScope
        }
        if busy { phase = .released }
        inflight = .none
        ready = false
        return s
    }

    // MARK: - private

    private var busy: Bool { phase == .acquiring || phase == .active || phase == .provisional }

    // A fresh session. Request ids stay unique across sessions, and a cancelled acquire's late grant is
    // still given back.
    private mutating func reset() {
        let keepNextId = nextId
        let keepCancelled = cancelledAcquireId
        let keepCancelledScope = cancelledScope
        let keepLastNow = lastNow
        self = UpstreamLeaseMachine(timing: timing, expiryPolicy: expiryPolicy)
        nextId = keepNextId
        cancelledAcquireId = keepCancelled
        cancelledScope = keepCancelledScope
        lastNow = keepLastNow
    }

    private mutating func clock(_ nowMs: Int64) -> Int64 {
        let now = nowMs < lastNow ? lastNow : nowMs
        lastNow = now
        return now
    }

    private static func push(_ s: inout UpstreamLeaseStep, _ kind: UpstreamLeaseActionKind, reason: String = "") {
        var a = UpstreamLeaseAction(kind: kind)
        a.reason = reason
        s.actions.append(a)
    }

    private mutating func noteRevision(_ rev: Int64, _ s: inout UpstreamLeaseStep) {
        if rev > knownRevision {
            knownRevision = rev
            var a = UpstreamLeaseAction(kind: .revisionChanged)
            a.upstreamRevision = rev
            s.actions.append(a)
        }
    }

    private mutating func sendAcquire(_ now: Int64, _ s: inout UpstreamLeaseStep) {
        inflight = .acquire
        nextId += 1
        inflightId = nextId
        requestSentMs = now
        var a = UpstreamLeaseAction(kind: .sendAcquire)
        a.requestId = inflightId
        a.profileId = profileId
        a.leaseKind = kind
        s.actions.append(a)
    }

    private mutating func sendRenew(_ now: Int64, _ s: inout UpstreamLeaseStep) {
        inflight = .renew
        nextId += 1
        inflightId = nextId
        requestSentMs = now
        var a = UpstreamLeaseAction(kind: .sendRenew)
        a.requestId = inflightId
        a.leaseId = leaseId
        a.meter = frozen
        a.route = route
        s.actions.append(a)
    }

    private mutating func leave(_ s: inout UpstreamLeaseStep, _ reason: String) {
        phase = .left
        inflight = .none
        ready = false
        leaveReason = reason
        Self.push(&s, .leaveNode, reason: reason)
    }

    private mutating func onAcquireProblem(_ r: UpstreamAcquireReply, _ now: Int64) -> UpstreamLeaseStep {
        var s = UpstreamLeaseStep()
        noteRevision(r.error.upstreamRevision, &s)
        let refused = r.kind == .refused
        if refused && r.error.code.isTerminal {
            leave(&s, r.error.code.rawValue)
            return s
        }
        if !ready {
            // Before bring-up nobody waits for a retry: the owner moves on to the next candidate.
            phase = .failed
            Self.push(&s, .tryNextCandidate,
                      reason: refused ? r.error.code.rawValue : (r.why == "transport" ? "transport" : "invalid_answer"))
            return s
        }
        // A re-acquire during a working session. no_seat: the seat went to someone else while the lease
        // was dead - running on would exceed the paid seat count: leave. Anything transient: retried.
        if refused && r.error.code == .noSeat {
            leave(&s, "no_seat_reacquire")
            return s
        }
        scheduleRetry(now, refused ? r.error.retryAfterS : -1)
        s.wakeAtMs = wake(now)
        return s
    }

    private mutating func scheduleRetry(_ now: Int64, _ retryAfterS: Int) {
        failures += 1
        let delayS: Int64
        if retryAfterS > 0 {
            delayS = Int64(max(1, min(retryAfterS, timing.maxRetryAfterS)))
        } else {
            delayS = min(Int64(timing.retryBaseS) << Int64(min(failures - 1, 10)), Int64(timing.retryMaxS))
        }
        retryAtMs = now + delayS * 1000
    }

    private func renewDelayMs(_ renewAfterS: Int) -> Int64 {
        let hi = max(1, ttlS / 2)
        let lo = min(timing.minRenewS, hi)
        let v = renewAfterS > 0 ? renewAfterS : timing.defaultRenewS
        return Int64(max(lo, min(v, hi))) * 1000
    }

    private func wake(_ now: Int64) -> Int64 {
        if phase != .active || inflight != .none { return -1 }
        if expiryPolicy == .renewUntilGone {
            // Nothing happens AT the deadline unless a report is pending (sent once at once there).
            if frozenValid {
                if expiryAttempted { return max(now, retryAtMs) }
                return now >= deadlineMs ? now : min(max(now, retryAtMs), deadlineMs)
            }
            return nextRenewMs >= 0 ? nextRenewMs : -1
        }
        if now >= deadlineMs {
            if kind != .session { return -1 }
            return expiryAttempted ? max(now, retryAtMs) : now
        }
        var next = deadlineMs
        if frozenValid {
            next = min(next, max(now, retryAtMs))
        } else if nextRenewMs >= 0 {
            next = min(next, nextRenewMs)
        }
        return next
    }

    private static func saturatingAdd(_ a: Int64, _ b: Int64) -> Int64 {
        let r = a.addingReportingOverflow(b)
        return r.overflow ? Int64.max : r.partialValue
    }
}
