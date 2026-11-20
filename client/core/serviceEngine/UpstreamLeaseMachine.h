// client/core/serviceEngine/UpstreamLeaseMachine.h
// AVPN serviceEngine - the seat lease of one upstream session as a pure state machine, plus the thin
// I/O interface its owner implements. [header-only, QtCore values; no timers, no I/O, no globals]
//
// Plan provider-pool v2, D6 (seats) and D13 (metering); contract UpstreamLease / UpstreamRenewal /
// UpstreamMeter / UpstreamError. The tunnel owner (iOS NE, macOS daemon or engine process, later
// Android VpnService) owns one machine per upstream session. Events go in - the classified answers of
// its own requests (UpstreamLeaseWire.h), the tunnel byte counters, the clock, the disconnect - and
// actions come out: send acquire / renew / release, "the lease is ready, bring the tunnel up", "leave the
// node now" with a reason code, "try the next candidate", "restart the byte counters", "the profile
// changed / the upstream revision moved". The machine has no timer: every step says when it wants the
// next tick (wakeAtMs), the owner calls tick(now) at or after that moment from a timer it already has.
//
// Rules (each one a test in tests/upstream_lease_check.cpp):
//  - seq starts at the value the server returned and only grows; every renewal reports seq + 1.
//  - A renewal that got no answer (transport, timeout, malformed) is retried with the SAME seq and the
//    SAME deltas; bytes counted meanwhile wait for the next seq. The server is idempotent by
//    (lease, seq), so nothing is lost and nothing is counted twice.
//  - Renewals follow renew_after_s (clamped to 30 s .. ttl/2); probe leases are never renewed.
//  - Transport failures alone never make the machine leave a working node: it keeps retrying (15 s
//    doubling to 120 s, or the server's retry_after_s). The server frees the seat after TTL; that gap
//    is accepted (owner, 13.11). Once the lease's TTL has passed without a successful renewal, the next
//    contact is a fresh acquire, never a renewal of the dead lease: one attempt AT the deadline itself
//    (whatever retry was pending - the seat is unaccounted from that moment), then the normal backoff.
//  - not_entitled, over_quota, disabled, lease_gone: leave the node at once (LeaveNode + the code).
//    no_seat (and a 429/503/transport failure) before the tunnel is up: try the next candidate.
//    During a session (a re-acquire after the TTL passed while the API was unreachable): no_seat means
//    the seat went to someone else and the paid seat count must not be exceeded - LeaveNode with
//    reason "no_seat_reacquire" (decision of 14.11); 429/503/transport are retried, the session stays.
//  - A renewal our server rejected as malformed (422 invalid_request, upstreamRenewRejected) is retried
//    like a transient failure, but kUpstreamRenewRejectedLimit such answers in a row (no other HTTP answer
//    in between; a transport failure does not break the row) end the session: LeaveNode "renew_rejected"
//    - a contract bug must not look like a network blip and silently let the lease expire (lab 14.11 D2).
//  - Provisional start (startProvisional, decision of 14.11): the direct acquire failed by transport
//    (mayStartProvisional) and a usable standby-pack entry exists (UpstreamStandbyPack.h). The machine
//    says LeaseReady{provisional} at once - the owner brings the tunnel up from the PACK config, there is no
//    lease id yet - and on tunnelUp() sends the acquire THROUGH the tunnel ("standby": true + the entry's
//    sha, route {"", pack tunnel_api_base}). Grant -> LeaseConfirmed and the normal Active session; the
//    bytes carried so far are not lost (counters started at bring-up, the first report includes them);
//    a grant with another sha or config_changed -> ConfigChanged, the running session stays. no_seat ->
//    LeaveNode(no_seat_standby); terminal codes -> LeaveNode(code); anything transient -> retried until the
//    confirm budget (from tunnelUp) runs out -> LeaveNode(standby_unconfirmed). The spacing is the SHORT
//    early one (300 ms doubling to 2 s, or the server's retry_after_s): the profile may refuse every
//    connection in its first seconds (lab 14.11 D3), so one early refusal never decides.
//    disconnect() before a grant releases nothing (a late grant is given back, as for any cancelled
//    acquire).
//  - Every report carries the session's meter scope (start()); it never changes for a lease. Every report
//    also carries `epoch` = the accounting epoch the machine believes now (the grant's, replaced by the
//    one of a rebaseline answer or a re-acquire): the server's exact fence - a report with another epoch
//    is not charged. A cancelled acquire's late grant is released with that grant's own epoch. The lease's
//    renew_token and tunnel_api_base ride on LeaseReady, SendRenew and SendRelease (LeaseAction::route).
//  - rebaseline: zero bytes of the report were charged; the counters restart from now, the new epoch is
//    kept. config_changed: reported once; the running session is never interrupted for it.
//  - The deadline is measured on the device's own clock from the moment the acquire was SENT (+ ttl_s),
//    later renewals move it by the difference of two server times - a wrong device clock cannot make a
//    lease look dead or alive. A value of `now` earlier than the last one is read as the last one.
//
// Clock for `now` (wiring lane): milliseconds of a clock that never goes back and KEEPS RUNNING WHILE THE
// DEVICE SLEEPS - the server's TTL runs during sleep too, so a clock that stops would make a dead lease
// look alive after the lid opens.
//  - macOS / iOS, C++ (app, daemon): clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) / 1000000 (the same
//    counter as mach_continuous_time(); CLOCK_MONOTONIC also counts sleep). Measured 14.11.2026 on a Mac
//    that had slept ~90 h since boot: Qt 6.11.1 QElapsedTimer and libc++ std::chrono::steady_clock
//    followed this counter too, but that is an implementation detail of the Qt/libc++ version - call the
//    Darwin API directly. NOT CLOCK_UPTIME_RAW / mach_absolute_time() (they stop during sleep).
//  - iOS extension, Swift: clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) / 1_000_000 (or ContinuousClock on
//    iOS 16+). NOT DispatchTime.now() or ProcessInfo.processInfo.systemUptime: measured on the same Mac,
//    both equal CLOCK_UPTIME_RAW and stop during sleep (CACurrentMediaTime is mach_absolute_time too).
//  - Android: SystemClock.elapsedRealtime(), not uptimeMillis().
//  - A late answer to an older request (another request id) is ignored; a lease granted to an acquire
//    that was cancelled by disconnect() is released at once (a new start never adopts a cancelled request: it has its own
//    nonce and sends its own). Ordering of acquires and releases is the owner's (UpstreamLeaseOwner.h).
//  - Release on disconnect carries the final deltas: an unanswered report is resent under its own seq
//    with the newer bytes added (if the server had applied it, the duplicate applies nothing and the
//    newer bytes are lost - the only case of under-counting, never double counting).
//
// Upstream Amnezia has no counterpart (no seats, no backend leases).
#pragma once

#include "DataCheckRetry.h"
#include "UpstreamLeaseWire.h"
#include "UpstreamNode.h"

#include <QHash>
#include <QString>
#include <QVector>

namespace avpn {

// Renewals in a row that our server rejected as malformed before the session leaves the node.
inline constexpr int kUpstreamRenewRejectedLimit = 3;

// Lab 14.11 D3: the first seconds of a provider profile may refuse every connection. Spacing before the
// n-th early retry (n >= 1): 300, 600, 1200, 2000, 2000, ... ms - used by the provisional seat confirmation
// below and by the data check (UpstreamEngine.h::decideUpstreamEarlyRetry). The spacing is the one rule of every
// data check through a fresh tunnel (DataCheckRetry.h), the own-server whoami included.
inline constexpr qint64 kUpstreamEarlyRetryBaseMs = kDataCheckRetryBaseMs;
inline constexpr qint64 kUpstreamEarlyRetryCapMs = kDataCheckRetryCapMs;

inline qint64 upstreamEarlyRetryDelayMs(int retryNumber)
{
    return dataCheckRetryDelayMs(retryNumber);
}

struct UpstreamLeaseTiming {
    int maxTtlS = kUpstreamLeaseTtlMaxS;    // a lease is never trusted longer than this after its request
    int minRenewS = kUpstreamRenewMinS;     // floor of renew_after_s (never above ttl/2)
    int defaultRenewS = kUpstreamRenewDefaultS; // a session lease that names no renew_after_s
    int retryBaseS = 15;                    // transport retry: 15, 30, 60, 120, 120, ...
    int retryMaxS = 120;
    int maxRetryAfterS = 900;               // cap of the server's retry_after_s

    static UpstreamLeaseTiming fromTuning()
    {
        UpstreamLeaseTiming t;
        t.defaultRenewS = upstreamRenewIntervalSTuned();
        return t;
    }
};

enum class LeaseActionKind {
    SendAcquire,         // profileId, leaseKind, requestId
    SendRenew,           // leaseId, meter, requestId
    SendRelease,         // leaseId, meter, requestId (fire and forget: the server always answers 204)
    LeaseReady,          // the first grant of this session: the config may go to the core (route);
                         // provisional = no lease yet, bring the tunnel up from the standby-pack config
    LeaseConfirmed,      // a provisional session got its lease (leaseId, route): now accounted
    LeaveNode,           // terminal: leave the node now (reason = the server's code)
    TryNextCandidate,    // before bring-up only: this candidate is not usable now (reason)
    RestartByteCounters, // counters restart from now (new lease, rebaseline, a new accounting epoch)
    ConfigChanged,       // the profile config changed on the server: applies at the next connect
    RevisionChanged,     // upstreamRevision moved past the known one: refetch the subscription
};

// How requests of one lease are sent: its own token and the API base inside the tunnel. Empty fields =
// the server did not send them (older server): the device token and the usual API base apply.
struct LeaseRoute {
    QString renewToken;
    QString apiBase;
    bool operator==(const LeaseRoute &o) const { return renewToken == o.renewToken && apiBase == o.apiBase; }
};

// Decision of 18.11 (UpstreamLeaseWire.h::upstreamReleaseDue): a release goes over the app's direct API path - the
// lease's bearer stays, its tunnel_api_base does not.
inline LeaseRoute upstreamReleaseRoute(const LeaseRoute &leaseRoute)
{
    LeaseRoute r = leaseRoute;
    r.apiBase.clear();
    return r;
}

struct LeaseAction {
    LeaseActionKind kind = LeaseActionKind::SendAcquire;
    quint64 requestId = 0;
    QString profileId;
    LeaseKind leaseKind = LeaseKind::Session;
    QString leaseId;
    UpstreamMeter meter;
    LeaseRoute route;            // LeaseReady, LeaseConfirmed, SendAcquire (standby), SendRenew, SendRelease
    bool provisional = false;    // LeaseReady of a provisional start
    bool standby = false;        // SendAcquire through the tunnel for a provisional session
    QString configSha256;        // SendAcquire with standby: the pack entry's sha
    QString reason;
    QString detail;              // LeaveNode: the server's optional reason (switch log only; never decides)
    qint64 upstreamRevision = 0;
};

struct LeaseStep {
    QVector<LeaseAction> actions;
    qint64 wakeAtMs = -1; // call tick() at or after this moment; -1 = nothing scheduled
    // The step belongs to no state of the session: the answer of a request the session does not wait for (a cancelled older start's
    // acquire, a renewal of an ended session) or a call that was ignored (tunnelUp twice, start while a session runs). It may carry
    // release actions for the lease IT names and nothing else; wakeAtMs is meaningless in it (-1 does not mean "nothing scheduled" for
    // the session). The owner never lets an inert step write the session's state (round 12 R1: it did, and the -1 cancelled the
    // renewals of the current start).
    bool inert = false;

    const LeaseAction *find(LeaseActionKind k) const
    {
        for (const LeaseAction &a : actions)
            if (a.kind == k)
                return &a;
        return nullptr;
    }
    bool has(LeaseActionKind k) const { return find(k) != nullptr; }
};

enum class LeasePhase {
    Idle,      // nothing started
    Acquiring, // the first acquire is in flight
    Active,    // a lease is held (possibly past its TTL, re-acquiring)
    Released,  // disconnect() ended the session
    Left,      // a terminal answer ended the session
    Failed,    // the first acquire did not succeed: the owner tries another candidate
    Provisional, // running from a standby-pack entry, the seat not confirmed yet
};

// I/O the owner implements (HTTPS through the running tunnel for renewals - D6). Each acquire/renew is
// answered later through the owner: onAcquireReply(requestId, classifyAcquireReply(...)) /
// onRenewReply(requestId, classifyRenewReply(...)); a release needs no answer.
class IUpstreamLeaseIo
{
public:
    virtual ~IUpstreamLeaseIo() = default;
    // standbyConfigSha256 non-empty = a standby acquire (upstreamAcquireBody), sent THROUGH the tunnel via
    // route.apiBase; empty = the normal direct acquire (route empty).
    // sessionNonce: the nonce of the START this acquire belongs to (UpstreamLeaseWire.h::kUpstreamAcquireNonceField); the
    // owner decides it, the machine knows nothing of it.
    // sessionOrder: the start's order, sent with the nonce (UpstreamLeaseWire.h::kUpstreamAcquireOrderField); -1 = none.
    virtual void acquire(quint64 requestId, const QString &profileId, LeaseKind kind,
                         const QString &standbyConfigSha256, const LeaseRoute &route,
                         const QString &sessionNonce, qint64 sessionOrder) = 0;
    virtual void renew(quint64 requestId, const QString &leaseId, const UpstreamMeter &meter,
                       const LeaseRoute &route) = 0;
    virtual void release(quint64 requestId, const QString &leaseId, const UpstreamMeter &meter,
                         const LeaseRoute &route) = 0;
    // A release over the route given (a working tunnel's API base), not forced to the direct path (row S2).
    // The meter is the pending release's final report (the owner's ledger owns it; seq < 1 = none).
    virtual void releaseVia(quint64 requestId, const QString &leaseId, const UpstreamMeter &meter, const LeaseRoute &route)
    {
        release(requestId, leaseId, meter, route);
    }
    // An acquire request of this profile is still alive (answered or not: its HTTP request has not ended).
    virtual bool acquireAlive(const QString & /*profileId*/) const { return false; }
};

// Sends the Send* actions of a step through io; returns the other actions for the owner to apply.
inline QVector<LeaseAction> dispatchLeaseIo(const LeaseStep &step, IUpstreamLeaseIo &io)
{
    QVector<LeaseAction> rest;
    for (const LeaseAction &a : step.actions) {
        switch (a.kind) {
        case LeaseActionKind::SendAcquire:
            io.acquire(a.requestId, a.profileId, a.leaseKind, a.configSha256, a.route, QString(), -1); // the machine knows no nonce
            break;
        case LeaseActionKind::SendRenew: io.renew(a.requestId, a.leaseId, a.meter, a.route); break;
        case LeaseActionKind::SendRelease: io.release(a.requestId, a.leaseId, a.meter, a.route); break;
        default: rest << a; break;
        }
    }
    return rest;
}

class UpstreamLeaseMachine
{
public:
    explicit UpstreamLeaseMachine(const UpstreamLeaseTiming &t = UpstreamLeaseTiming()) : m_t(t) {}

    // A new session on profileId. scope = what this session's byte counters measure (sent in every
    // report, never changed for a lease). knownRevision = the subscription's upstream_revision (answers
    // that carry a newer one produce RevisionChanged). Ignored while a session runs (disconnect first).
    LeaseStep start(const QString &profileId, LeaseKind kind, MeterScope scope, qint64 knownRevision, qint64 nowMs)
    {
        LeaseStep s;
        if (busy()) {
            s.inert = true;
            return s;
        }
        reset();
        nowMs = clock(nowMs);
        m_profileId = profileId;
        m_kind = kind;
        m_scope = scope;
        m_knownRevision = knownRevision;
        m_phase = LeasePhase::Acquiring;
        sendAcquire(nowMs, s);
        return s;
    }

    // A session from a standby-pack entry (see the header). packConfigSha256 = the entry's sha;
    // tunnelApiBase = the pack's tunnel_api_base (requests through the tunnel); confirmBudgetMs = how long
    // after tunnelUp() the seat may stay unconfirmed (from the data-check budget). Always a session lease.
    LeaseStep startProvisional(const QString &profileId, MeterScope scope, const QString &packConfigSha256,
                               const QString &tunnelApiBase, qint64 knownRevision, qint64 confirmBudgetMs,
                               qint64 nowMs)
    {
        LeaseStep s;
        if (busy()) {
            s.inert = true;
            return s;
        }
        reset();
        clock(nowMs);
        m_profileId = profileId;
        m_kind = LeaseKind::Session;
        m_scope = scope;
        m_knownRevision = knownRevision;
        m_standbySha = packConfigSha256;
        m_route = LeaseRoute{QString(), tunnelApiBase};
        m_confirmBudgetMs = qMax<qint64>(0, confirmBudgetMs);
        m_phase = LeasePhase::Provisional;
        LeaseAction ready;
        ready.kind = LeaseActionKind::LeaseReady;
        ready.provisional = true;
        ready.route = m_route;
        s.actions << ready;
        push(s, LeaseActionKind::RestartByteCounters);
        return s;
    }

    // The provisional tunnel is up: confirm the seat through it.
    LeaseStep tunnelUp(qint64 nowMs)
    {
        LeaseStep s;
        nowMs = clock(nowMs);
        if (m_phase != LeasePhase::Provisional || m_tunnelUp) {
            s.inert = true;
            return s;
        }
        m_tunnelUp = true;
        m_confirmDeadlineMs = nowMs + m_confirmBudgetMs;
        sendAcquire(nowMs, s);
        return s;
    }

    LeaseStep onAcquireReply(quint64 requestId, const AcquireReply &r, qint64 nowMs)
    {
        LeaseStep s;
        nowMs = clock(nowMs);
        if (m_inflight != Inflight::Acquire || requestId != m_inflightId) {
            s.inert = true;
            // A lease granted to an acquire cancelled by disconnect(): give the seat back at once. EVERY cancelled
            // acquire is remembered until its own answer (review F2 of 17.11: one remembered id let a quick
            // B -> C -> D lose B's late grant - a paid seat held to its expiry).
            const auto it = m_cancelledAcquires.constFind(requestId);
            if (requestId != 0 && it != m_cancelledAcquires.constEnd()) {
                const MeterScope scope = it.value().scope;
                m_cancelledAcquires.remove(requestId);
                if (r.kind == LeaseReplyKind::Granted) {
                    LeaseAction a;
                    a.kind = LeaseActionKind::SendRelease;
                    a.requestId = ++m_nextId;
                    a.profileId = r.grant.profileId; // whose seat it is (the owner orders acquires by it)
                    a.leaseId = r.grant.leaseId;
                    a.meter = UpstreamMeter{r.grant.seq + 1, 0, 0, scope, r.grant.accountingEpoch};
                    a.route = LeaseRoute{r.grant.renewToken, r.grant.tunnelApiBase};
                    s.actions << a;
                }
            }
            return s;
        }
        m_inflight = Inflight::None;
        if (m_phase == LeasePhase::Provisional)
            return onProvisionalReply(r, nowMs);
        if (r.kind == LeaseReplyKind::Granted
            && (r.grant.profileId != m_profileId || r.grant.kind != m_kind)) {
            AcquireReply bad;
            bad.why = QStringLiteral("mismatch");
            return onAcquireProblem(bad, nowMs);
        }
        if (r.kind != LeaseReplyKind::Granted)
            return onAcquireProblem(r, nowMs);

        const UpstreamLeaseGrant &g = r.grant;
        noteRevision(g.upstreamRevision, s);
        if (m_ready) {
            // A re-acquire after the TTL passed. An unanswered report of the same lease is kept only
            // when the server's seq shows it was not applied; on another lease it is in doubt: dropped.
            if (m_frozenValid && !(g.leaseId == m_leaseId && g.seq < m_frozen.seq))
                m_frozenValid = false;
            m_lastSeq = (g.leaseId == m_leaseId) ? qMax(m_lastSeq, g.seq) : g.seq;
            if (g.accountingEpoch != m_epoch) {
                m_unRx = m_unTx = 0;
                m_frozenValid = false;
                push(s, LeaseActionKind::RestartByteCounters);
            }
        } else {
            m_lastSeq = g.seq;
            m_frozenValid = false;
            m_unRx = m_unTx = 0;
            m_lastRx = m_lastTx = 0;
            LeaseAction ready;
            ready.kind = LeaseActionKind::LeaseReady;
            ready.leaseId = g.leaseId;
            ready.route = LeaseRoute{g.renewToken, g.tunnelApiBase};
            s.actions << ready;
            push(s, LeaseActionKind::RestartByteCounters);
        }
        m_leaseId = g.leaseId;
        m_route = LeaseRoute{g.renewToken, g.tunnelApiBase};
        m_epoch = g.accountingEpoch;
        m_ttlS = qMin(g.ttlS, m_t.maxTtlS);
        m_anchorLocalMs = m_requestSentMs + qint64(m_ttlS) * 1000;
        m_anchorServerMs = g.expiresAtMs;
        m_deadlineMs = m_anchorLocalMs;
        m_nextRenewMs = (m_kind == LeaseKind::Session) ? nowMs + renewDelayMs(g.renewAfterS) : -1;
        m_retryAtMs = 0;
        m_failures = 0;
        m_expiryAttempted = false;
        m_phase = LeasePhase::Active;
        m_ready = true;
        s.wakeAtMs = wake(nowMs);
        return s;
    }

    LeaseStep onRenewReply(quint64 requestId, const RenewReply &r, qint64 nowMs)
    {
        LeaseStep s;
        nowMs = clock(nowMs);
        if (m_inflight != Inflight::Renew || requestId != m_inflightId) {
            s.inert = true;
            return s;
        }
        m_inflight = Inflight::None;
        noteRevision(r.kind == LeaseReplyKind::Granted ? r.renewal.upstreamRevision : r.error.upstreamRevision, s);
        if (r.kind == LeaseReplyKind::Refused && isTerminalUpstreamError(r.error.code)) {
            leave(s, QLatin1String(upstreamErrorCodeName(r.error.code)), r.error.reason);
            return s;
        }
        if (upstreamRenewRejected(r)) {
            if (++m_renewRejected >= kUpstreamRenewRejectedLimit) {
                leave(s, QStringLiteral("renew_rejected"));
                return s;
            }
        } else if (!(r.kind == LeaseReplyKind::Failed && r.why == QLatin1String("transport"))) {
            m_renewRejected = 0; // any other HTTP answer breaks the row
        }
        if (r.kind != LeaseReplyKind::Granted || r.renewal.leaseId != m_leaseId) {
            // No usable answer: the same report is resent later, under the same seq.
            scheduleRetry(nowMs, r.kind == LeaseReplyKind::Refused ? r.error.retryAfterS : -1);
            s.wakeAtMs = wake(nowMs);
            return s;
        }
        const UpstreamRenewal &w = r.renewal;
        m_lastSeq = qMax(m_lastSeq, qMax(m_frozenValid ? m_frozen.seq : 0, w.seq));
        m_frozenValid = false;
        if (w.rebaseline) {
            m_unRx = m_unTx = 0;
            push(s, LeaseActionKind::RestartByteCounters);
        }
        m_epoch = w.accountingEpoch;
        const qint64 moved = m_anchorLocalMs + (w.expiresAtMs - m_anchorServerMs);
        m_deadlineMs = qMin(moved, m_requestSentMs + qint64(m_t.maxTtlS) * 1000);
        m_nextRenewMs = nowMs + renewDelayMs(w.renewAfterS);
        m_retryAtMs = 0;
        m_failures = 0;
        if (w.configChanged && !m_configChangedNoted) {
            m_configChangedNoted = true;
            push(s, LeaseActionKind::ConfigChanged);
        }
        s.wakeAtMs = wake(nowMs);
        return s;
    }

    // Cumulative byte counters of the running tunnel (any moment, any rate). A counter that went back
    // is read as restarted from 0.
    void onTunnelBytes(qint64 rxTotal, qint64 txTotal)
    {
        if (m_phase != LeasePhase::Active && m_phase != LeasePhase::Provisional)
            return;
        rxTotal = qMax<qint64>(0, rxTotal);
        txTotal = qMax<qint64>(0, txTotal);
        m_unRx += rxTotal >= m_lastRx ? rxTotal - m_lastRx : rxTotal;
        m_unTx += txTotal >= m_lastTx ? txTotal - m_lastTx : txTotal;
        m_lastRx = rxTotal;
        m_lastTx = txTotal;
    }
    // After RestartByteCounters, for an owner whose counters cannot restart: the current totals become
    // the baseline (nothing counted).
    void baselineBytes(qint64 rxTotal, qint64 txTotal)
    {
        m_lastRx = qMax<qint64>(0, rxTotal);
        m_lastTx = qMax<qint64>(0, txTotal);
    }

    LeaseStep tick(qint64 nowMs)
    {
        LeaseStep s;
        nowMs = clock(nowMs);
        if (m_phase == LeasePhase::Provisional && m_tunnelUp && m_inflight == Inflight::None) {
            if (nowMs >= m_confirmDeadlineMs)
                leave(s, QStringLiteral("standby_unconfirmed"));
            else if (nowMs >= m_retryAtMs)
                sendAcquire(nowMs, s);
        }
        if (m_phase == LeasePhase::Active && m_inflight == Inflight::None) {
            if (nowMs >= m_deadlineMs) {
                // The lease is dead: a session re-acquires (never renews a dead lease) - once at once,
                // then on the backoff; a probe ends.
                if (m_kind == LeaseKind::Session && (!m_expiryAttempted || nowMs >= m_retryAtMs)) {
                    m_expiryAttempted = true;
                    sendAcquire(nowMs, s);
                }
            } else if (m_frozenValid) {
                if (nowMs >= m_retryAtMs)
                    sendRenew(nowMs, s);
            } else if (m_nextRenewMs >= 0 && nowMs >= m_nextRenewMs) { // a probe has no schedule (-1)
                m_frozen = UpstreamMeter{m_lastSeq + 1, m_unRx, m_unTx, m_scope, m_epoch};
                m_frozenValid = true;
                m_unRx = m_unTx = 0;
                sendRenew(nowMs, s);
            }
        }
        s.wakeAtMs = wake(nowMs);
        return s;
    }

    LeaseStep disconnect(qint64 nowMs)
    {
        LeaseStep s;
        clock(nowMs);
        if (m_phase == LeasePhase::Active && !m_leaseId.isEmpty()) {
            LeaseAction a;
            a.kind = LeaseActionKind::SendRelease;
            a.requestId = ++m_nextId;
            a.profileId = m_profileId;
            a.leaseId = m_leaseId;
            a.meter = m_frozenValid ? UpstreamMeter{m_frozen.seq, m_frozen.rxDelta + m_unRx, m_frozen.txDelta + m_unTx, m_scope, m_epoch}
                                    : UpstreamMeter{m_lastSeq + 1, m_unRx, m_unTx, m_scope, m_epoch};
            a.route = m_route;
            s.actions << a;
        } else if ((m_phase == LeasePhase::Acquiring || m_phase == LeasePhase::Provisional)
                   && m_inflight == Inflight::Acquire) {
            m_cancelledAcquires.insert(m_inflightId, CancelledAcquire{m_scope, m_profileId, m_kind, m_requestSentMs});
        }
        if (busy())
            m_phase = LeasePhase::Released;
        m_inflight = Inflight::None;
        m_ready = false;
        return s;
    }

    LeasePhase phase() const { return m_phase; }
    bool provisional() const { return m_phase == LeasePhase::Provisional; }
    const QString &profileId() const { return m_profileId; }
    const QString &leaseId() const { return m_leaseId; }
    LeaseKind kind() const { return m_kind; }
    MeterScope meterScope() const { return m_scope; }
    const LeaseRoute &route() const { return m_route; }
    qint64 lastAcceptedSeq() const { return m_lastSeq; }
    qint64 accountingEpoch() const { return m_epoch; }
    qint64 knownRevision() const { return m_knownRevision; }
    qint64 deadlineMs() const { return m_deadlineMs; }
    bool reportInDoubt() const { return m_frozenValid; }
    qint64 unreportedRx() const { return m_unRx; }
    qint64 unreportedTx() const { return m_unTx; }
    int renewRejectedInRow() const { return m_renewRejected; }
    int cancelledAcquiresPending() const { return int(m_cancelledAcquires.size()); }
    bool cancelledAcquireOf(const QString &profileId) const
    {
        for (const CancelledAcquire &c : m_cancelledAcquires)
            if (c.profileId == profileId)
                return true;
        return false;
    }
    // The acquire this session has out (0 = none) - what disconnect() would cancel.
    quint64 acquireInFlight() const { return m_inflight == Inflight::Acquire ? m_inflightId : 0; }
    // Any request (acquire or renewal) is out: the session's wake time is then unset by design - the answer reschedules it.
    bool requestInFlight() const { return m_inflight != Inflight::None; }
    bool provisionalTunnelUp() const { return m_phase == LeasePhase::Provisional && m_tunnelUp; }
    qint64 requestSentMs() const { return m_requestSentMs; }

private:
    enum class Inflight { None, Acquire, Renew };

    bool busy() const
    {
        return m_phase == LeasePhase::Acquiring || m_phase == LeasePhase::Active || m_phase == LeasePhase::Provisional;
    }

    // A fresh session. Request ids stay unique across sessions (a late answer of the old one is never
    // taken for the new one), and a cancelled acquire's late grant is still given back.
    void reset()
    {
        const quint64 nextId = m_nextId;
        const QHash<quint64, CancelledAcquire> cancelled = m_cancelledAcquires;
        const qint64 lastNow = m_lastNow;
        *this = UpstreamLeaseMachine(m_t);
        m_nextId = nextId;
        m_cancelledAcquires = cancelled;
        m_lastNow = lastNow;
    }

    // A provisional session's answer to its standby acquire.
    LeaseStep onProvisionalReply(const AcquireReply &r, qint64 nowMs)
    {
        LeaseStep s;
        noteRevision(r.kind == LeaseReplyKind::Granted ? r.grant.upstreamRevision : r.error.upstreamRevision, s);
        const bool ours = r.kind == LeaseReplyKind::Granted && r.grant.profileId == m_profileId
                          && r.grant.kind == LeaseKind::Session;
        if (ours) {
            const UpstreamLeaseGrant &g = r.grant;
            m_lastSeq = g.seq;
            m_frozenValid = false; // bytes carried since bring-up stay in the unreported counters
            m_leaseId = g.leaseId;
            m_route = LeaseRoute{g.renewToken, g.tunnelApiBase.isEmpty() ? m_route.apiBase : g.tunnelApiBase};
            m_epoch = g.accountingEpoch;
            m_ttlS = qMin(g.ttlS, m_t.maxTtlS);
            m_anchorLocalMs = m_requestSentMs + qint64(m_ttlS) * 1000;
            m_anchorServerMs = g.expiresAtMs;
            m_deadlineMs = m_anchorLocalMs;
            m_nextRenewMs = nowMs + renewDelayMs(g.renewAfterS);
            m_retryAtMs = 0;
            m_failures = 0;
            m_expiryAttempted = false;
            m_phase = LeasePhase::Active;
            m_ready = true;
            LeaseAction c;
            c.kind = LeaseActionKind::LeaseConfirmed;
            c.leaseId = m_leaseId;
            c.route = m_route;
            s.actions << c;
            if (g.configSha256 != m_standbySha || g.configChanged) {
                m_configChangedNoted = true;
                push(s, LeaseActionKind::ConfigChanged);
            }
            s.wakeAtMs = wake(nowMs);
            return s;
        }
        const bool refused = r.kind == LeaseReplyKind::Refused;
        if (refused && r.error.code == UpstreamErrorCode::NoSeat) {
            leave(s, QStringLiteral("no_seat_standby"));
            return s;
        }
        if (refused && isTerminalUpstreamError(r.error.code)) {
            leave(s, QLatin1String(upstreamErrorCodeName(r.error.code)));
            return s;
        }
        // Transient (or a grant that is not ours): retried inside the confirm budget, on the short early
        // spacing (lab 14.11 D3) unless the server named its own retry_after_s.
        if (nowMs >= m_confirmDeadlineMs) {
            leave(s, QStringLiteral("standby_unconfirmed"));
            return s;
        }
        const int retryAfterS = refused ? r.error.retryAfterS : -1;
        if (retryAfterS > 0) {
            scheduleRetry(nowMs, retryAfterS);
        } else {
            ++m_failures;
            m_retryAtMs = nowMs + upstreamEarlyRetryDelayMs(m_failures);
        }
        s.wakeAtMs = wake(nowMs);
        return s;
    }

    qint64 clock(qint64 nowMs)
    {
        if (nowMs < m_lastNow)
            nowMs = m_lastNow;
        m_lastNow = nowMs;
        return nowMs;
    }

    static void push(LeaseStep &s, LeaseActionKind k, const QString &reason = QString())
    {
        LeaseAction a;
        a.kind = k;
        a.reason = reason;
        s.actions << a;
    }

    void noteRevision(qint64 rev, LeaseStep &s)
    {
        if (rev > m_knownRevision) {
            m_knownRevision = rev;
            LeaseAction a;
            a.kind = LeaseActionKind::RevisionChanged;
            a.upstreamRevision = rev;
            s.actions << a;
        }
    }

    void sendAcquire(qint64 nowMs, LeaseStep &s)
    {
        m_inflight = Inflight::Acquire;
        m_inflightId = ++m_nextId;
        m_requestSentMs = nowMs;
        LeaseAction a;
        a.kind = LeaseActionKind::SendAcquire;
        a.requestId = m_inflightId;
        a.profileId = m_profileId;
        a.leaseKind = m_kind;
        if (m_phase == LeasePhase::Provisional) {
            a.standby = true;
            a.configSha256 = m_standbySha;
            a.route = m_route;
        }
        s.actions << a;
    }

    void sendRenew(qint64 nowMs, LeaseStep &s)
    {
        m_inflight = Inflight::Renew;
        m_inflightId = ++m_nextId;
        m_requestSentMs = nowMs;
        LeaseAction a;
        a.kind = LeaseActionKind::SendRenew;
        a.requestId = m_inflightId;
        a.leaseId = m_leaseId;
        m_frozen.epoch = m_epoch; // the epoch the device believes NOW (a retry after a rebaseline carries the new one)
        a.meter = m_frozen;
        a.route = m_route;
        s.actions << a;
    }

    void leave(LeaseStep &s, const QString &reason, const QString &detail = QString())
    {
        m_phase = LeasePhase::Left;
        m_inflight = Inflight::None;
        m_ready = false;
        push(s, LeaseActionKind::LeaveNode, reason);
        s.actions.last().detail = detail;
    }

    LeaseStep onAcquireProblem(const AcquireReply &r, qint64 nowMs)
    {
        LeaseStep s;
        noteRevision(r.error.upstreamRevision, s);
        const bool refused = r.kind == LeaseReplyKind::Refused;
        if (refused && isTerminalUpstreamError(r.error.code)) {
            leave(s, QLatin1String(upstreamErrorCodeName(r.error.code)), r.error.reason);
            return s;
        }
        if (!m_ready) {
            // Before bring-up nobody waits for a retry: the owner moves on to the next candidate.
            m_phase = LeasePhase::Failed;
            push(s, LeaseActionKind::TryNextCandidate,
                 refused ? QLatin1String(upstreamErrorCodeName(r.error.code))
                         : (r.why == QLatin1String("transport") ? QStringLiteral("transport")
                                                                : QStringLiteral("invalid_answer")));
            return s;
        }
        // A re-acquire during a working session. no_seat: the seat went to someone else while the lease
        // was dead - running on would exceed the paid seat count: leave. Anything transient: retried.
        if (refused && r.error.code == UpstreamErrorCode::NoSeat) {
            leave(s, QStringLiteral("no_seat_reacquire"));
            return s;
        }
        scheduleRetry(nowMs, refused ? r.error.retryAfterS : -1);
        s.wakeAtMs = wake(nowMs);
        return s;
    }

    void scheduleRetry(qint64 nowMs, int retryAfterS)
    {
        ++m_failures;
        qint64 delayS;
        if (retryAfterS > 0)
            delayS = qBound(1, retryAfterS, m_t.maxRetryAfterS);
        else
            delayS = qMin<qint64>(qint64(m_t.retryBaseS) << qMin(m_failures - 1, 10), m_t.retryMaxS);
        m_retryAtMs = nowMs + delayS * 1000;
    }

    qint64 renewDelayMs(int renewAfterS) const
    {
        const int hi = qMax(1, m_ttlS / 2);
        const int lo = qMin(m_t.minRenewS, hi);
        const int v = renewAfterS > 0 ? renewAfterS : m_t.defaultRenewS;
        return qint64(qBound(lo, v, hi)) * 1000;
    }

    qint64 wake(qint64 nowMs) const
    {
        if (m_phase == LeasePhase::Provisional && m_tunnelUp && m_inflight == Inflight::None)
            return qMin(m_confirmDeadlineMs, qMax(nowMs, m_retryAtMs));
        if (m_phase != LeasePhase::Active || m_inflight != Inflight::None)
            return -1;
        if (nowMs >= m_deadlineMs) {
            if (m_kind != LeaseKind::Session)
                return -1;
            return m_expiryAttempted ? qMax(nowMs, m_retryAtMs) : nowMs;
        }
        qint64 next = m_deadlineMs;
        if (m_frozenValid)
            next = qMin(next, qMax(nowMs, m_retryAtMs));
        else if (m_nextRenewMs >= 0)
            next = qMin(next, m_nextRenewMs);
        return next;
    }

    UpstreamLeaseTiming m_t;
    LeasePhase m_phase = LeasePhase::Idle;
    QString m_profileId;
    LeaseKind m_kind = LeaseKind::Session;
    MeterScope m_scope = MeterScope::Tunnel;
    // Cancelled acquires until their answer: a late grant is released. No cap: none is ever forgotten (review F2).
    struct CancelledAcquire {
        MeterScope scope = MeterScope::Tunnel;
        QString profileId;
        LeaseKind kind = LeaseKind::Session;
        qint64 sentMs = 0;
    };
    QHash<quint64, CancelledAcquire> m_cancelledAcquires;
    LeaseRoute m_route;
    qint64 m_knownRevision = 0;
    QString m_leaseId;
    qint64 m_lastSeq = 0;
    qint64 m_epoch = 0;
    UpstreamMeter m_frozen;
    bool m_frozenValid = false;
    qint64 m_unRx = 0, m_unTx = 0, m_lastRx = 0, m_lastTx = 0;
    int m_ttlS = 0;
    qint64 m_anchorLocalMs = 0, m_anchorServerMs = 0, m_deadlineMs = 0;
    qint64 m_nextRenewMs = -1, m_retryAtMs = 0;
    int m_failures = 0;
    int m_renewRejected = 0; // renewals in a row rejected as malformed (upstreamRenewRejected)
    Inflight m_inflight = Inflight::None;
    quint64 m_inflightId = 0, m_nextId = 0;
    qint64 m_requestSentMs = 0;
    bool m_ready = false;
    bool m_configChangedNoted = false;
    bool m_expiryAttempted = false; // the one immediate re-acquire at the deadline was sent
    QString m_standbySha;           // provisional: the pack entry's config sha
    qint64 m_confirmBudgetMs = 0, m_confirmDeadlineMs = 0;
    bool m_tunnelUp = false;
    qint64 m_lastNow = 0;
};

} // namespace avpn
