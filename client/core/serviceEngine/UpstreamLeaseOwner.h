// client/core/serviceEngine/UpstreamLeaseOwner.h
// AVPN serviceEngine - the app-side owner of one upstream session's seat lease: drives the pure
// UpstreamLeaseMachine and turns its actions into what the tunnel adapter does. [header-only, QtCore;
// no timers, no network - the I/O is IUpstreamLeaseIo, the clock is the caller's `now`]
//
// Decisions A, B and the contract (client-envelope-contract.md §1, §2, §4-§7):
//  - begin(stub): the DIRECT acquire (route empty = the app's usual API base, the tunnel is down). Grant ->
//    BringUp (the signed lease config; the adapter sanitizes and starts the core). A transport failure
//    (mayStartProvisional) with a usable standby entry -> BringUp{provisional} from the pack; then
//    tunnelUp() acquires THROUGH the tunnel ("standby": true) and LeaseConfirmed hands the seat over.
//    Anything else before bring-up -> StartFailed{code}: the engine excludes the node for the attempt
//    (no_seat included - "try the next candidate") and the adapter reports a tunnel Error.
//  - keepOwnership (macOS GUI process, decision B): renewals and the release stay here - tick(now) from
//    the facade's existing tick at wakeAtMs(), bytes from the runtime status cumulatives, Leave{code} on a
//    terminal answer, the record for adoption after a GUI restart. Without it (iOS / macOS NE: the
//    extension renews, decision B) the owner is done once the lease is in the envelope (direct) or handed
//    over (HandOver, provisional) - it never renews or releases a lease it handed over.
//  - Byte counters (contract §4): cumulative since tunnel start. RestartByteCounters of a fresh bring-up
//    needs nothing (the adapter's counters start at 0 with the tunnel); a rebaseline or an adoption
//    re-bases on the current totals (counters that cannot restart), so the next report carries only the
//    bytes after it.
//  - Every session end (disconnect, a new begin) ends the machine's session too, so the next start() is never
//    ignored; the release goes out from here per upstreamAppReleasesSeat (below).
//  - prepare(stub) (seat first): the acquire runs while another node's tunnel is up; the grant is held and
//    reported (Prepared), brought up only by the next up() of that node (bringUpPrepared).
// Never logs: lease ids, tokens, configs, hosts - events carry codes only.
//
// Upstream Amnezia has no counterpart. Tests: tests/upstream_engine_check.cpp.
#pragma once

#include "UpstreamEngine.h"
#include "UpstreamLeaseMachine.h"

#include <QHash>
#include <QJsonArray>
#include <QJsonObject>
#include <QVector>

#include <optional>

namespace avpn {

enum class UpstreamOwnerEventKind {
    BringUp,          // config (+ provisional): start the core now
    StartFailed,      // code: before bring-up, this node cannot run now (exclude for the attempt)
    Leave,            // code: a running session must leave the node (dead-session path)
    LeaseConfirmed,   // a provisional session got its seat
    HandOver,         // lease (contract §1 upstream_lease) for the tunnel owner (iOS: upstream_lease_set)
    Persist,          // record (keepOwnership): write the lease record
    ClearRecord,      // the session ended: drop the record
    RevisionChanged,  // revision: refetch the subscription once
    ConfigChanged,    // the profile changed on the server: applies at the next connect, never interrupts
    Prepared,         // config: a seat taken BEFORE the switch (prepare) is in hand - check the profile, then switch
    PrepareFailed,    // code: the seat taken before the switch was not granted - the live tunnel stays
    // leaseId + route: the seat of a session the tunnel owner held (handed over, the tunnel came up). The tunnel
    // owner releases it first, inside its own stop, with the final byte report; this process gives it back again
    // once the stop is confirmed, without a report (upstreamAppReleasesSeat below).
    ReleaseAfterStop,
};

// Who gives a session's seat back when the session ends (D3 of the owner's iPhone 16.11, build 140: refused seats
// were never released and stayed paid until their 15-minute expiry). The GUI owner (macOS, keepOwnership) always
// does. Elsewhere the lease travels in the tunnel's envelope and the tunnel owner (iOS extension, Android Xray
// service) releases it on its own stop - but only a tunnel that came up has it: a session that ends before the
// tunnel reported up (the profile refused, the bridge refused, the start watchdog, a stop while connecting) is
// still this process's to release at once, with its report.
// The seat is ALSO this process's when the tunnel owner had it (device round of 19.11, iPhone Air: a provider
// session stopped 0.6 s after Connected kept its seat until the 15-minute expiry; the extension's one release is
// bounded to 1.5 s after its core stopped and 17 of 30 stops ran into that bound). This process acquired the seat
// and owns it until the stop is confirmed: endSession() hands out ReleaseAfterStop, sent after the confirmed
// teardown, i.e. after the extension's own release. A release sent twice is harmless: the server's DELETE is
// idempotent and a report at or below the last seq applies nothing.
inline bool upstreamAppReleasesSeat(bool keepOwnership, bool handedOver, bool tunnelReportedUp)
{
    return keepOwnership || !handedOver || !tunnelReportedUp;
}

struct UpstreamOwnerEvent {
    UpstreamOwnerEventKind kind = UpstreamOwnerEventKind::BringUp;
    QString code;
    QString detail;          // Leave / StartFailed: the server's optional reason (switch log only)
    bool provisional = false;
    QByteArray config;       // BringUp: the profile config (secret)
    QString configSha256;    // BringUp
    QJsonObject lease;       // BringUp (absent on provisional) / HandOver: upstream_lease
    quint64 prepareId = 0;   // Prepared / PrepareFailed: the prepare() they answer (prepareSerial at its start)
    QString leaseId;         // ReleaseAfterStop (secret: never logged)
    quint64 requestId = 0;   // ReleaseAfterStop: the release's request id (registered by the owner; onReleaseDone ends it)
    LeaseRoute route;        // ReleaseAfterStop: the lease's bearer (the release goes over the direct path)
    UpstreamLeaseRecord record;
    qint64 revision = 0;
};

class UpstreamLeaseOwner
{
public:
    struct Options {
        bool keepOwnership = false;
        MeterScope scope = MeterScope::Tunnel;
        qint64 provisionalConfirmBudgetMs = 18000;
    };

    explicit UpstreamLeaseOwner(IUpstreamLeaseIo *io = nullptr, const UpstreamLeaseTiming &t = UpstreamLeaseTiming())
        : m_io(io), m_timing(t), m_machine(t) {}

    void setIo(IUpstreamLeaseIo *io) { m_io = io; }
    void setOptions(const Options &o) { m_opt = o; }
    const Options &options() const { return m_opt; }

    // A bring-up of an upstream stub (VpnConnectionTunnelControl::up). standby = the pack entry to start
    // from if the direct acquire fails by transport (none = no provisional start). nowWallMs only feeds
    // the record (wall-clock expiry estimate); deadlines use nowMs (sleep-proof clock, contract §7).
    QVector<UpstreamOwnerEvent> begin(const SubscriptionNode &stub, qint64 knownRevision,
                                      const std::optional<StandbyCandidate> &standby, qint64 nowMs,
                                      qint64 nowWallMs = 0)
    {
        return startSession(stub, knownRevision, standby, nowMs, nowWallMs, /*prepareOnly=*/false);
    }

    // Seat first (D4 of the owner's iPhone 16.11): a working tunnel of another node is up and the user picked this
    // provider node. The acquire goes out now - on the app's usual API base, i.e. THROUGH the live tunnel - and a
    // grant is not brought up but reported as Prepared{config}: the adapter checks the profile and the facade only
    // then switches; a refusal (PrepareFailed{code}, or the profile check) leaves the live tunnel alone. The next
    // up() of the same node brings the held seat up (bringUpPrepared); anything else ends it (disconnect() releases
    // it: nothing was handed over). No standby start: the live tunnel is the path.
    QVector<UpstreamOwnerEvent> prepare(const SubscriptionNode &stub, qint64 knownRevision, qint64 nowMs,
                                        qint64 nowWallMs = 0)
    {
        return startSession(stub, knownRevision, std::nullopt, nowMs, nowWallMs, /*prepareOnly=*/true);
    }

    // A session taken by prepare() for nodeId that up() may bring up now: still held, and its lease (if granted
    // already) not past the deadline. false = start afresh (begin() ends the stale one first).
    bool preparedUsable(const QString &nodeId, qint64 nowMs) const
    {
        return preparing() && m_nodeId == nodeId && (!m_prepared || m_machine.deadlineMs() > nowMs);
    }
    bool preparing() const { return m_active && m_prepareOnly; }
    // The identity of the session the last begin()/prepare() started: Prepared / PrepareFailed carry it, so an
    // answer is only ever matched to the very prepare() it answers (review F5 of 17.11: a queued success of an
    // earlier prepare of the same node switched the tunnel before the new prepare's grant existed).
    quint64 prepareSerial() const { return m_sessionSerial; }

    // up() of the prepared node: the held grant becomes the session's BringUp now; an acquire still in flight
    // brings up on its grant like begin()'s would.
    QVector<UpstreamOwnerEvent> bringUpPrepared(qint64 nowMs)
    {
        QVector<UpstreamOwnerEvent> ev;
        if (!preparing())
            return ev;
        m_prepareOnly = false;
        if (m_prepared)
            readyEvents(nowMs, ev);
        return ev;
    }

    // macOS: a restarted GUI found the daemon's Xray tunnel alive and a record of the session: confirm the
    // seat through the tunnel (standby acquire of the same profile = the existing lease) within what is
    // left of the lease. Counters re-base on the first sample (the daemon's totals include old bytes).
    QVector<UpstreamOwnerEvent> adopt(const UpstreamLeaseRecord &r, qint64 nowMs, qint64 nowWallMs)
    {
        QVector<UpstreamOwnerEvent> ev;
        if (!upstreamRecordAdoptable(r, nowWallMs))
            return ev;
        ev << endSession(nowMs);
        resetSession();
        m_nodeId = r.nodeId;
        m_profileId = r.profileId;
        m_stubSha = r.configSha256;
        m_wallAtStart = nowWallMs;
        m_monoAtStart = nowMs;
        m_adoptedStartedWallMs = r.startedWallMs;
        m_active = true;
        m_adopted = true;
        m_tunnelIsUp = true;
        m_rebasePending = true;
        apply(m_machine.startProvisional(r.profileId, upstreamEffectiveScope(r.scope, r.meterTags), r.configSha256,
                                         upstreamApiBaseNormalized(r.apiBase),
                                         r.revision, upstreamAdoptConfirmBudgetMs(r, nowWallMs), nowMs),
              nowMs, ev, /*silentReady=*/true);
        apply(m_machine.tunnelUp(nowMs), nowMs, ev);
        return ev;
    }

    // The platform reported the tunnel of this session up.
    QVector<UpstreamOwnerEvent> tunnelUp(qint64 nowMs)
    {
        QVector<UpstreamOwnerEvent> ev;
        if (!m_active)
            return ev;
        m_bringUp = false;
        m_tunnelIsUp = true;
        if (m_machine.provisional())
            apply(m_machine.tunnelUp(nowMs), nowMs, ev);
        if (unsentCount() > 0 && !tunnelBase().isEmpty())
            flushUnsent(LeaseRoute{QString(), tunnelBase()}, nowMs); // the tunnel's API base works now
        return ev;
    }

    QVector<UpstreamOwnerEvent> onAcquireReply(quint64 requestId, const AcquireReply &r, qint64 nowMs)
    {
        QVector<UpstreamOwnerEvent> ev;
        m_lastNowMs = nowMs;
        if (requestId == m_lastAcquireRequest) {
            m_lastAcquire = r;
            if (r.kind == LeaseReplyKind::Granted) {
                m_grant = r.grant;
                m_grantSentMs = m_lastAcquireSentMs;
            }
        }
        if (r.kind == LeaseReplyKind::Granted) {
            noteToken(r.grant.renewToken, requestId);
            // A grant of the profile ends the take-back: the new session owns the id (or the server already ended the
            // old one and made a new lease); either way the old release is no longer anyone's to send.
            for (const QString &id : m_releases.keys()) {
                const PendingRelease &p = m_releases[id];
                if ((p.state == RelState::Withdrawn && p.profile == r.grant.profileId)
                    || (p.state == RelState::Unsent && id == r.grant.leaseId)) // the server handed the id back: a session owns it now
                    m_releases.remove(id);
            }
        }
        apply(m_machine.onAcquireReply(requestId, r, nowMs), nowMs, ev); // a grant nobody took over: released
        if (requestId != 0 && requestId == m_orphanAcquire) {
            m_orphanAcquire = 0;
            m_orphanProfile.clear();
            startQueuedIfFree(nowMs, ev);
        }
        reinstateWithdrawn();
        // ANY answer of the API proves the route it came by (round 9 R3): a refusal or an HTTP error status is an answer
        // like a grant; only a transport failure proves nothing. Releases that could not be carried go out by that route.
        if (requestId == m_lastAcquireRequest && unsentCount() > 0 && !(r.kind == LeaseReplyKind::Failed && r.why == QLatin1String("transport"))) {
            if (!m_lastAcquireStandby)
                flushUnsent(LeaseRoute{}, nowMs);
            else if (!tunnelBase().isEmpty())
                flushUnsent(LeaseRoute{QString(), tunnelBase()}, nowMs);
        }
        return ev;
    }

    QVector<UpstreamOwnerEvent> onRenewReply(quint64 requestId, const RenewReply &r, qint64 nowMs, qint64 nowWallMs = 0)
    {
        QVector<UpstreamOwnerEvent> ev;
        const LeaseStep s = m_machine.onRenewReply(requestId, r, nowMs);
        if (r.kind == LeaseReplyKind::Granted && !s.has(LeaseActionKind::LeaveNode)) {
            m_renewedAtMs = nowMs;
            m_lastRenewal = r.renewal;
            m_hasRenewal = true;
            m_appliedTotal += qMax<qint64>(0, r.renewal.appliedBytes);
            m_shadowTotal += qMax<qint64>(0, r.renewal.shadowBytes);
            if (m_opt.keepOwnership && m_machine.phase() == LeasePhase::Active)
                ev << persistEvent(nowMs, nowWallMs);
        }
        apply(s, nowMs, ev);
        return ev;
    }

    // Cumulative counters of the running tunnel (any rate). The first sample after an adoption or a
    // rebaseline re-bases instead of counting.
    void onBytes(qint64 rxTotal, qint64 txTotal)
    {
        // A seat held for a switch carries no traffic yet: what the running tunnel counts is another session's
        // (review F6 of 17.11: the old Xray tunnel's whole cumulative would have been reported for the provider).
        if (m_prepareOnly)
            return;
        m_lastRx = rxTotal;
        m_lastTx = txTotal;
        m_haveBytes = true;
        if (m_rebasePending) {
            m_machine.baselineBytes(rxTotal, txTotal);
            m_rebasePending = false;
            return;
        }
        m_machine.onTunnelBytes(rxTotal, txTotal);
    }

    QVector<UpstreamOwnerEvent> tick(qint64 nowMs)
    {
        QVector<UpstreamOwnerEvent> ev;
        if (!m_active || !ownsRenewals())
            return ev;
        // A seat held for a switch is never renewed: its first renewal falling due means the switch did not
        // come - give it back (the switch takes seconds; renew_after_s is at least kUpstreamRenewMinS).
        if (m_prepareOnly && m_prepared && m_wakeAtMs >= 0 && nowMs >= m_wakeAtMs)
            return endSession(nowMs);
        apply(m_machine.tick(nowMs), nowMs, ev);
        return ev;
    }

    // A user disconnect / the adapter's down(): release (keepOwnership: the final report goes through the
    // tunnel before the core stops - the adapter defers its stop until the release answered, bounded);
    // a cancelled acquire's late grant is given back by the machine. true in releaseSent() = wait for it.
    QVector<UpstreamOwnerEvent> disconnect(qint64 nowMs)
    {
        return endSession(nowMs);
    }

    bool releaseSent() const { return m_releaseSent; }
    bool active() const { return m_active; }
    bool ownsRenewals() const { return m_opt.keepOwnership || !m_handedOver; }
    bool provisionalPending() const { return m_active && m_machine.provisional(); }
    bool adopted() const { return m_adopted; }
    const QString &nodeId() const { return m_nodeId; }
    const QString &profileId() const { return m_profileId; }
    LeasePhase phase() const { return m_machine.phase(); }
    const UpstreamLeaseMachine &machine() const { return m_machine; }
    qint64 wakeAtMs() const { return (m_active && ownsRenewals()) ? m_wakeAtMs : -1; }

    // The probe grant of the current lease while it is valid (expires_in_s from the acquire's send time).
    UpstreamProbeGrant probeGrant(qint64 nowMs) const
    {
        if (!m_active || !m_grant.probe.present)
            return UpstreamProbeGrant();
        if (nowMs - m_grantSentMs >= qint64(m_grant.probe.expiresInS) * 1000)
            return UpstreamProbeGrant();
        return m_grant.probe;
    }
    QString leaseId() const { return m_machine.leaseId(); }
    QString tunnelApiBase() const { return m_machine.route().apiBase; }

    // Contract §1 upstream_lease for the envelope / the hand-over. expires_in_ms is relative to now.
    QJsonObject leaseJson(qint64 nowMs) const
    {
        if (m_machine.leaseId().isEmpty())
            return QJsonObject();
        const int ttl = m_grant.ttlS > 0 ? qMin(m_grant.ttlS, kUpstreamLeaseTtlMaxS) : kUpstreamLeaseTtlDefaultS;
        return QJsonObject{
            {QStringLiteral("lease_id"), m_machine.leaseId()},
            {QStringLiteral("renew_token"), m_machine.route().renewToken},
            {QStringLiteral("api_base"), m_machine.route().apiBase},
            {QStringLiteral("renew_after_s"), m_hasRenewal ? m_lastRenewal.renewAfterS : m_grant.renewAfterS},
            {QStringLiteral("ttl_s"), ttl},
            {QStringLiteral("expires_in_ms"), double(qMax<qint64>(0, m_machine.deadlineMs() - nowMs))},
            {QStringLiteral("seq"), double(m_machine.lastAcceptedSeq())},
            {QStringLiteral("epoch"), double(m_machine.accountingEpoch())},
            {QStringLiteral("revision"), double(m_machine.knownRevision())},
            {QStringLiteral("meter_scope"), meterScopeName(envelopeScope())},
            {QStringLiteral("meter_tags"), QJsonArray::fromStringList(currentMeterTags())},
        };
    }

    // The scope the session reports: the owner's own machine (macOS) or, for the extension, the build's
    // capability narrowed by the lease's meter_tags.
    MeterScope envelopeScope() const
    {
        return m_opt.keepOwnership ? m_machine.meterScope() : upstreamEffectiveScope(m_opt.scope, currentMeterTags());
    }
    QStringList currentMeterTags() const
    {
        if (!m_grant.meterTags.isEmpty())
            return m_grant.meterTags;
        return m_standby ? m_standby->meterTags : QStringList();
    }

    // Contract §5 status object (the macOS in-process owner mirrors the iOS extension's).
    QJsonObject statusJson(qint64 nowMs) const
    {
        QString state = QStringLiteral("none");
        switch (m_machine.phase()) {
        case LeasePhase::Acquiring:
        case LeasePhase::Provisional: state = QStringLiteral("pending"); break;
        case LeasePhase::Active: state = QStringLiteral("active"); break;
        case LeasePhase::Left: state = QStringLiteral("terminal"); break;
        default: break;
        }
        return QJsonObject{
            {QStringLiteral("state"), state},
            {QStringLiteral("code"), state == QLatin1String("terminal") ? m_leftCode : QString()},
            {QStringLiteral("seq"), double(m_machine.lastAcceptedSeq())},
            {QStringLiteral("renewed_ms_ago"), double(m_renewedAtMs < 0 ? -1 : qMax<qint64>(0, nowMs - m_renewedAtMs))},
            {QStringLiteral("expires_in_ms"), double(m_machine.phase() == LeasePhase::Active
                                                         ? qMax<qint64>(0, m_machine.deadlineMs() - nowMs) : 0)},
            {QStringLiteral("revision"), double(m_machine.knownRevision())},
            {QStringLiteral("config_changed"), m_configChanged},
            {QStringLiteral("applied_bytes"), double(m_appliedTotal)},
            {QStringLiteral("shadow_bytes"), double(m_shadowTotal)},
            {QStringLiteral("meter_scope"), meterScopeName(m_machine.meterScope())},
        };
    }

private:
    // The machine itself is kept: its start() keeps request ids unique across sessions (a late answer of
    // the old session is never taken for the new one) and still gives back a cancelled acquire's grant.
    void resetSession()
    {
        m_nodeId.clear();
        m_profileId.clear();
        m_stubSha.clear();
        m_standby.reset();
        m_grant = UpstreamLeaseGrant();
        m_lastAcquire = AcquireReply();
        m_lastRenewal = UpstreamRenewal();
        m_hasRenewal = false;
        m_active = m_bringUp = m_tunnelIsUp = m_handedOver = m_adopted = m_rebasePending = m_bringUpSent = m_requestSent = false;
        m_provisionalBase.clear();
        m_prepareOnly = m_prepared = false;
        m_releaseSent = false;
        m_configChanged = false;
        m_haveBytes = false;
        m_lastRx = m_lastTx = 0;
        m_leftCode.clear();
        m_renewedAtMs = -1;
        m_wakeAtMs = -1;
        m_appliedTotal = m_shadowTotal = 0;
        m_lastAcquireRequest = 0;
    }

    QVector<UpstreamOwnerEvent> endSession(qint64 nowMs)
    {
        QVector<UpstreamOwnerEvent> ev;
        m_lastNowMs = nowMs;
        m_releaseSent = false;
        if (!m_active)
            return ev;
        // The machine's session ends with the owner's, ALWAYS (owner's iPhone 16.11, build 140: after a refused
        // profile the machine stayed Active, so the next start() was ignored - "acquiring a seat", no request,
        // the 15 s start watchdog - and its dead lease was "released" only at the following stop). Who sends the
        // release is upstreamAppReleasesSeat: a lease that never reached a running tunnel is still this process's.
        const quint64 out = m_machine.acquireInFlight();
        if (out != 0) {
            m_orphanAcquire = out; // stays this owner's until its answer (startBlocked)
            m_orphanProfile = m_machine.profileId();
        }
        m_startQueued = false;
        const LeaseStep s = m_machine.disconnect(nowMs);
        if (upstreamAppReleasesSeat(m_opt.keepOwnership, m_handedOver, m_tunnelIsUp)) {
            m_releaseSent = s.has(LeaseActionKind::SendRelease);
            noteReleasesSent(s);
            if (m_io)
                dispatchStep(s);
        } else if (const LeaseAction *a = s.find(LeaseActionKind::SendRelease)) {
            // The tunnel owner releases first, on its own stop, with the final report; this process again once
            // that stop is confirmed (the adapter holds it until then).
            UpstreamOwnerEvent r;
            r.kind = UpstreamOwnerEventKind::ReleaseAfterStop;
            r.leaseId = a->leaseId;
            r.route = a->route;
            r.requestId = a->requestId;
            // Review R5 of 19.11: this release is ours like any other - registered, so a start of its profile takes it
            // back (and a late answer of it is known).
            registerRelease(a->profileId, a->leaseId, a->route, a->requestId);
            ev << r;
        }
        if (m_opt.keepOwnership) {
            UpstreamOwnerEvent c;
            c.kind = UpstreamOwnerEventKind::ClearRecord;
            ev << c;
        }
        // Keep the machine (a cancelled acquire's late grant is still released by it) but mark the
        // session over: only late answers reach it from now on.
        m_active = false;
        reinstateWithdrawn();
        return ev;
    }

    UpstreamOwnerEvent persistEvent(qint64 nowMs, qint64 nowWallMs) const
    {
        UpstreamOwnerEvent p;
        p.kind = UpstreamOwnerEventKind::Persist;
        UpstreamLeaseRecord &r = p.record;
        r.nodeId = m_nodeId;
        r.profileId = m_profileId;
        r.configSha256 = m_grant.configSha256.isEmpty() ? m_stubSha : m_grant.configSha256;
        r.apiBase = m_machine.route().apiBase;
        r.leaseId = m_machine.leaseId();
        const qint64 wall = nowWallMs > 0 ? nowWallMs : m_wallAtStart + qMax<qint64>(0, nowMs - m_monoAtStart);
        r.expiresWallMs = wall + qMax<qint64>(0, m_machine.deadlineMs() - nowMs);
        r.savedWallMs = wall;
        r.startedWallMs = m_adopted ? m_adoptedStartedWallMs : m_wallAtStart;
        r.revision = m_machine.knownRevision();
        r.scope = m_machine.meterScope();
        r.meterTags = currentMeterTags();
        return p;
    }

    // silentReady: the LeaseReady of an adoption (the tunnel already runs) is not a bring-up.
    void apply(const LeaseStep &s, qint64 nowMs, QVector<UpstreamOwnerEvent> &ev, bool silentReady = false)
    {
        m_lastNowMs = nowMs;
        // Sends first (the machine expects them dispatched); the acquire's send time anchors the probe
        // grant's own expiry.
        for (const LeaseAction &a : s.actions) {
            if (a.kind == LeaseActionKind::SendAcquire) {
                m_lastAcquireRequest = a.requestId;
                m_lastAcquireSentMs = nowMs;
                m_lastAcquireStandby = a.standby;
            }
            if (a.kind == LeaseActionKind::SendRelease) {
                m_releaseSent = true;
                registerRelease(a.profileId, a.leaseId, a.route, a.requestId);
            }
        }
        QVector<LeaseAction> rest;
        if (m_io)
            rest = dispatchStep(s);
        else
            for (const LeaseAction &a : s.actions)
                if (a.kind != LeaseActionKind::SendAcquire && a.kind != LeaseActionKind::SendRenew
                    && a.kind != LeaseActionKind::SendRelease)
                    rest << a;
        m_wakeAtMs = s.wakeAtMs;
        for (const LeaseAction &a : rest) {
            switch (a.kind) {
            case LeaseActionKind::LeaseReady: {
                if (silentReady)
                    break;
                if (a.provisional) {
                    UpstreamOwnerEvent b;
                    b.kind = UpstreamOwnerEventKind::BringUp;
                    b.provisional = true;
                    if (m_standby) {
                        b.config = m_standby->config;
                        b.configSha256 = m_standby->configSha256;
                    }
                    ev << b;
                    m_bringUpSent = true;
                    m_requestSent = true;
                    break;
                }
                if (m_prepareOnly) {
                    // Seat first: held, not brought up - the adapter checks the profile, the facade switches.
                    m_prepared = true;
                    UpstreamOwnerEvent p;
                    p.kind = UpstreamOwnerEventKind::Prepared;
                    p.prepareId = m_sessionSerial;
                    p.config = m_grant.config;
                    p.configSha256 = m_grant.configSha256;
                    ev << p;
                    break;
                }
                readyEvents(nowMs, ev);
                break;
            }
            case LeaseActionKind::LeaseConfirmed: {
                UpstreamOwnerEvent c;
                c.kind = UpstreamOwnerEventKind::LeaseConfirmed;
                ev << c;
                if (unsentCount() > 0 && !tunnelBase().isEmpty())
                    flushUnsent(LeaseRoute{QString(), tunnelBase()}, nowMs); // the seat was confirmed through the tunnel
                if (m_opt.keepOwnership) {
                    ev << persistEvent(nowMs, 0);
                } else {
                    UpstreamOwnerEvent h;
                    h.kind = UpstreamOwnerEventKind::HandOver;
                    h.lease = leaseJson(nowMs);
                    ev << h;
                    m_handedOver = true;
                }
                break;
            }
            case LeaseActionKind::TryNextCandidate: {
                // Before bring-up. A transport failure with a usable standby entry: provisional start.
                if (m_bringUp && m_standby && mayStartProvisional(m_lastAcquire)) {
                    const StandbyCandidate sc = *m_standby;
                    m_provisionalBase = sc.tunnelApiBase;
                    apply(m_machine.startProvisional(m_profileId, machineScope(), sc.configSha256, sc.tunnelApiBase,
                                                     qMax(m_machine.knownRevision(), sc.packRevision),
                                                     m_opt.provisionalConfirmBudgetMs, nowMs),
                          nowMs, ev);
                    break;
                }
                failStart(ev, a.reason);
                break;
            }
            case LeaseActionKind::LeaveNode: {
                m_leftCode = a.reason;
                if (m_bringUp && !m_tunnelIsUp && !m_machine.provisional() && m_machine.leaseId().isEmpty()) {
                    failStart(ev, a.reason, a.detail); // a terminal refusal of the first acquire
                    break;
                }
                UpstreamOwnerEvent l;
                l.kind = UpstreamOwnerEventKind::Leave;
                l.code = a.reason;
                l.detail = a.detail;
                ev << l;
                if (m_opt.keepOwnership) {
                    UpstreamOwnerEvent c;
                    c.kind = UpstreamOwnerEventKind::ClearRecord;
                    ev << c;
                }
                m_active = false;
                reinstateWithdrawn();
                break;
            }
            case LeaseActionKind::RestartByteCounters:
                // A fresh bring-up: the adapter's counters start with the tunnel. Later (rebaseline, a new
                // epoch on a re-acquire): re-base on the current totals.
                if (m_tunnelIsUp || m_adopted) {
                    if (m_haveBytes) {
                        m_machine.baselineBytes(m_lastRx, m_lastTx);
                        m_rebasePending = false;
                    } else {
                        m_rebasePending = true;
                    }
                }
                break;
            case LeaseActionKind::ConfigChanged: {
                m_configChanged = true;
                UpstreamOwnerEvent c;
                c.kind = UpstreamOwnerEventKind::ConfigChanged;
                ev << c;
                break;
            }
            case LeaseActionKind::RevisionChanged: {
                UpstreamOwnerEvent r;
                r.kind = UpstreamOwnerEventKind::RevisionChanged;
                r.revision = a.upstreamRevision;
                ev << r;
                break;
            }
            default:
                break;
            }
        }
    }

    // The machine's own meter scope: the macOS GUI owner reports itself and has no per-outbound read
    // (the daemon exposes utun counters only) - always "tunnel"; elsewhere the machine never reports a
    // byte (the extension does), its scope only labels a cancelled grant's zero release.
    MeterScope machineScope() const
    {
        return m_opt.keepOwnership ? MeterScope::Tunnel : m_opt.scope;
    }

    // The BringUp of a granted (not provisional) session: the lease travels in the envelope.
    void readyEvents(qint64 nowMs, QVector<UpstreamOwnerEvent> &ev)
    {
        UpstreamOwnerEvent b;
        b.kind = UpstreamOwnerEventKind::BringUp;
        b.config = m_grant.config;
        b.configSha256 = m_grant.configSha256;
        b.lease = leaseJson(nowMs);
        if (!m_opt.keepOwnership)
            m_handedOver = true; // renewals belong to the tunnel owner from now (its envelope carries the lease)
        ev << b;
        m_bringUpSent = true;
        m_requestSent = true;
        if (m_opt.keepOwnership)
            ev << persistEvent(nowMs, 0);
    }

    QVector<UpstreamOwnerEvent> startSession(const SubscriptionNode &stub, qint64 knownRevision,
                                             const std::optional<StandbyCandidate> &standby, qint64 nowMs,
                                             qint64 nowWallMs, bool prepareOnly)
    {
        QVector<UpstreamOwnerEvent> ev;
        ev << endSession(nowMs); // a previous session (should already be released by down())
        if (!stub.upstream.has_value())
            return ev;
        resetSession();
        ++m_sessionSerial;
        m_nodeId = stub.nodeId;
        m_profileId = stub.upstream->profileId;
        m_stubSha = stub.upstream->configSha256;
        m_standby = standby;
        m_wallAtStart = nowWallMs;
        m_monoAtStart = nowMs;
        m_active = true;
        m_bringUp = true;
        m_prepareOnly = prepareOnly;
        // One acquisition in flight (review N1 of 17.11): the cancelled acquire of the SAME profile becomes this
        // session's own (the server would answer a second one with the same seat, and the first one's answer would
        // then release it); with any other request in the way the start waits (startQueuedIfFree).
        if (m_orphanAcquire != 0 && m_orphanProfile == m_profileId
            && m_machine.startTakingOver(m_orphanAcquire, m_profileId, LeaseKind::Session, machineScope(), knownRevision,
                                         nowMs)) {
            m_lastAcquireRequest = m_orphanAcquire;
            m_lastAcquireSentMs = m_machine.requestSentMs();
            m_orphanAcquire = 0;
            m_orphanProfile.clear();
        } else if (startBlocked()) {
            m_startQueued = true;
            m_queuedRevision = knownRevision;
        } else {
            apply(m_machine.start(m_profileId, LeaseKind::Session, machineScope(), knownRevision, nowMs), nowMs, ev);
        }
        return ev;
    }

public:
    // ===== Lease id ledger (reviews R4, R5 of 19.11 and F3, F4, F9 of round 2, R1 + R6 of round 9: ONE question - who
    // holds lease id L right now, and who must release it) =====
    // The server hands the SAME lease id back to the same device for the same profile (upstream_pool.acquire_lease:
    // "Idempotent re-acquire ... same lease") and ROTATES the renew token on that re-acquire. A DELETE carries the renew
    // token of the grant it releases and the server ends the lease ONLY when that token is the lease's current one
    // (anything else is a no-op, the answer is 204 either way). So a release of an old session can never end the seat of
    // a newer one, and a START NEVER WAITS FOR A RELEASE - not for one in flight either (a local timeout of a DELETE
    // proves nothing about what the server does with it later). The token lives in the release's route (LeaseRoute
    // renewToken: the grant's own) and is put on the wire in ONE place, UpstreamLeaseClient::sendRelease.
    // The pending releases are ONE structure keyed by lease id (m_releases): at most one release per id, a second one for
    // the same id replaces the first when its token is not older (noteToken: the acquire's request id orders tokens).
    //   state            meaning                                   how it is known
    //   requested        an acquire of the profile is alive        machine in flight / orphan / client's HTTP request
    //   held             a live session uses L                     m_active && machine.leaseId() == L (holdsLease)
    //   Out              our DELETE of L is out or being resent    m_releases[L].state, until onReleaseDone
    //                    (seatReleaseNext: about 20 s at most)
    //   Withdrawn        a start of the profile took it back       m_releases[L].state (S1)
    //   Unsent           gave up over its route, kept for the      m_releases[L].state (S2)
    //                    next route that works
    //   Deferred         a late grant waits for the newer acquire   m_releases[L].state (lateGrant / acquireEnded)
    //                    of the profile to end
    //   gone             answered / given up / never sent          no entry
    //   event                                     transition                                      who sends the DELETE
    //   session end (stop, switch, refusal)       held -> Out                                      machine (SendRelease)
    //   stop with the tunnel owner holding L      held -> Out after the confirmed stop            endSession (ReleaseAfterStop)
    //   a Disconnected nobody asked for           held -> Out AT ONCE (tunnelLost)                tunnelLost
    //   a refused permission (Android), start     held -> Out at once, nothing to wait for        abortStart
    //     never reached the native service
    //   a grant nobody waits for (late/orphan)    L held by a live session: stays. Another acquire  lateGrant / acquireEnded
    //                                             of the profile alive: judged at its end.
    //                                             Otherwise: Out at once (with THAT grant's token).
    //   granted, tunnel never came up (G2):       the seat's lifetime starts at the GRANT. A native Disconnected after
    //     Disconnected / start error / leg        the start was asked for (tunnelLost), a start that never reached the
    //     timeout / attempt ended before          native service or an attempt that ended before Connected (abortStart,
    //     Connected                               via ITunnelControl::startRefused), a stop (disconnect): -> Out at once -
    //                                             the extension has no release handler yet, so the app releases
    //                                             (upstreamAppReleasesSeat)
    //   ANY acquire of profile P (direct, standby confirmation in tunnelUp(), provisional re-acquire in tick() - all
    //     come out of the machine as SendAcquire and leave through sendAcquire)
    //                                             goes out AT ONCE; every pending release of P (Out, on the wire or not) is
    //                                             WITHDRAWN (S1): its resends stop, a DELETE already on the wire carries the
    //                                             old token and is a no-op once the server rotated it
    //   Withdrawn release of L (S1)               a grant of P ends it (the session owns the id, or the server already ended
    //                                             L); no acquire of P alive and no session holds L (the take-back was for
    //                                             nothing: refusal, failure, the session ended) -> Out again
    //                                             (reinstateWithdrawn); a resend of it is never sent (releaseWanted)
    //   Unsent release (S2)                       bounded by the lease's TTL and kUnsentMaxSends sends, sent over a route that
    //                                             works - the tunnel's API base once a session is up / confirmed, or the route
    //                                             that ANSWERED an acquire (any answer, not only a grant: R3; a transport
    //                                             failure proves nothing) - never while an acquire of the profile is alive,
    //                                             never for an id a session holds or was handed again
    // Every release is registered in m_releases BEFORE the DELETE leaves.

    // A grant that arrived after the attempt stopped waiting (UpstreamLeaseClient::onLateGrant).
    // route = the late grant's own token (and the base it came by); acquireId = the request that was answered.
    QVector<UpstreamOwnerEvent> lateGrant(const QString &profileId, const QString &leaseId, const LeaseRoute &route,
                                          bool newerAcquireOut, quint64 acquireId = 0)
    {
        QVector<UpstreamOwnerEvent> ev;
        noteToken(route.renewToken, acquireId);
        if (holdsLease(leaseId))
            return ev; // the live session's seat
        if (newerAcquireOut) {
            // judged when the newer request ends; kept in the ledger like every release (one per lease id, newest token)
            if (registerRelease(profileId, leaseId, route, 0))
                m_releases[leaseId].state = RelState::Deferred;
            return ev;
        }
        releaseThroughLedger(profileId, leaseId, route); // replaces a withdrawn release of the same id: one chain
        return acquireEnded(profileId, leaseId, false); // nothing else is out: a deferred seat of an earlier request is judged now
    }

    // An acquire request of the profile ended (any outcome).
    QVector<UpstreamOwnerEvent> acquireEnded(const QString &profileId, const QString &grantedLeaseId, bool stillOut)
    {
        (void)grantedLeaseId; // a session's grant is told by holdsLease; a released one met its deferred twin in the ledger
        QVector<UpstreamOwnerEvent> ev;
        if (!stillOut) {
            reinstateWithdrawn(); // the last request of the profile ended: a take-back for nothing comes back
            if (unsentCount() > 0 && m_active && m_tunnelIsUp && !tunnelBase().isEmpty())
                flushUnsent(LeaseRoute{QString(), tunnelBase()}, m_lastNowMs); // the way is clear now
        }
        if (stillOut)
            return ev;
        for (const QString &id : m_releases.keys()) {
            PendingRelease &d = m_releases[id];
            if (d.state != RelState::Deferred || d.profile != profileId)
                continue;
            if (holdsLease(id)) {
                m_releases.remove(id); // the live session took the same seat over
                continue;
            }
            // Not a session's: released with ITS token. When the request that just ended was granted the same lease (and
            // was released itself) the two met in the ledger and the newer token won - one release per id.
            sendOut(d, d.route);
        }
        return ev;
    }

    // The native tunnel of the running session is gone and the app did not ask for it (Disconnected from the
    // system, iOS Settings): the session ends now; its release is not waited for any later stop.
    QVector<UpstreamOwnerEvent> tunnelLost(qint64 nowMs)
    {
        // A seat's lifetime starts at the GRANT: a Disconnected after the native start was asked for, before any
        // Connected (iOS: network settings or Xray failed in the extension, which has no release handler yet), ends
        // it too - the app releases (upstreamAppReleasesSeat: the tunnel never reported up). Review G2 of round 3.
        if (!m_active || m_prepareOnly || !(m_tunnelIsUp || m_bringUpSent))
            return {};
        return endSession(nowMs);
    }

    // The start never reached the native service (the person refused the VPN permission, Android): whatever seat
    // the session holds goes back at once - there is no stop to wait for.
    QVector<UpstreamOwnerEvent> abortStart(qint64 nowMs)
    {
        if (!m_active || m_prepareOnly || m_tunnelIsUp)
            return {};
        return endSession(nowMs);
    }

    // ONE acquisition in flight per owner, decided by seat identity (review round 2 of 17.11, N1 + F2):
    //  - an acquire cancelled by a session's end stays out until its answer; meanwhile a new session's acquire
    //    waits (a newer pick replaces the waiting one) - unless it is for the same profile: then it takes the
    //    cancelled request over.
    // A release never holds a start (round 9 R1). The cancelled acquire's answer is the machine's: a grant nobody took
    // over is released. Cost: a pick that follows another within one acquire round trip waits for that answer (B -> C -> D:
    // D goes out when B is answered, at most the acquire bound upstreamAcquireTimeoutMsTuned later).
    bool startBlocked() const { return m_orphanAcquire != 0; }
    // The live session holds this lease id (a late or orphan answer of the same id must not release it).
    bool holdsLease(const QString &leaseId) const
    {
        return m_active && !leaseId.isEmpty() && m_machine.phase() == LeasePhase::Active && m_machine.leaseId() == leaseId;
    }
    bool startQueued() const { return m_active && m_startQueued; }
    // The live session of this profile can start from a standby-pack entry (so it does not wait the full lease share).
    bool hasStandbyFor(const QString &profileId) const
    {
        return m_active && !m_prepareOnly && m_standby.has_value() && m_profileId == profileId;
    }
    bool requestSent() const { return m_requestSent; }
    int unsentCount() const { return countIn(RelState::Unsent); }
    int withdrawnCount() const { return countIn(RelState::Withdrawn); }
    int requestsOutstanding() const { return (m_orphanAcquire ? 1 : 0) + countIn(RelState::Out); }
    int pendingReleases() const { return int(m_releases.size()); } // at most one per lease id

    // The client asks before it resends a release (UpstreamLeaseClient::releaseWanted): false = the release was taken
    // back by a newer start of its profile or replaced by a newer one of the same lease id - no resend, no answer.
    bool releaseWanted(quint64 requestId, qint64 /*nowMs*/, QVector<UpstreamOwnerEvent> & /*ev*/)
    {
        return outByRequest(requestId) != nullptr;
    }

    // A release this owner sent ended (UpstreamLeaseClient::onReleaseDone: answered, timed out or given up).
    // confirmed = the server answered it; false = it never did within the release rule's budget (row S2: the release
    // is kept - bounded by the lease's TTL and a few sends - for the next route that works).
    QVector<UpstreamOwnerEvent> onReleaseDone(quint64 requestId, qint64 nowMs, bool confirmed = true)
    {
        QVector<UpstreamOwnerEvent> ev;
        m_lastNowMs = nowMs;
        PendingRelease *p = outByRequest(requestId);
        if (!p)
            return ev; // withdrawn or replaced meanwhile: not this request's any more
        if (!confirmed && p->tries < kUnsentMaxSends && p->deadlineMs > nowMs && countIn(RelState::Unsent) < 8) {
            p->state = RelState::Unsent;
            p->requestId = 0;
        } else {
            m_releases.remove(p->leaseId);
        }
        return ev;
    }

private:

    // THE one place where an acquire leaves this owner (the direct acquire, the standby confirmation of tunnelUp() and the
    // provisional re-acquire of tick() all come out of the machine as SendAcquire). It goes AT ONCE (round 9 R1): the
    // server answers an acquire of the profile the device holds with the SAME lease and a rotated token, and a DELETE
    // ends the lease only for its current token - so a release of the profile still pending, on the wire or not, is the
    // old session's and harmless; it is WITHDRAWN (its resends stop: the seat is needed again, the new session owns the id
    // if the server hands it back and gives it back itself when it ends). A withdrawn release whose session never got a
    // grant is sent again (reinstateWithdrawn).
    void withdrawReleasesOf(const QString &profileId)
    {
        for (auto it = m_releases.begin(); it != m_releases.end(); ++it)
            if (it->state == RelState::Out && it->profile == profileId) {
                it->state = RelState::Withdrawn;
                it->requestId = 0;
            }
    }
    // A taken-back release comes back only when the take-back turned out to be for nothing: no acquire of the profile
    // is alive any more (its answer may still carry the old id - the server would then be asked to end a seat that
    // answer is about to give to a session) and no session holds the id. Called wherever one of those facts changes.
    void reinstateWithdrawn()
    {
        for (const QString &id : m_releases.keys()) {
            PendingRelease &x = m_releases[id];
            if (x.state != RelState::Withdrawn)
                continue;
            if (m_orphanAcquire != 0 || (m_active && m_machine.acquireInFlight() != 0) || (m_io && m_io->acquireAlive(x.profile))
                || holdsLease(x.leaseId))
                continue;
            sendOut(x, x.route);
        }
    }
    void sendAcquire(const LeaseAction &a)
    {
        withdrawReleasesOf(a.profileId);
        m_requestSent = true; // something really left for the server: evidence about the path may follow
        if (m_io)
            m_io->acquire(a.requestId, a.profileId, a.leaseKind, a.configSha256, a.route);
    }
    // Like dispatchLeaseIo (UpstreamLeaseMachine.h) but acquires go through sendAcquire; returns the other actions.
    QVector<LeaseAction> dispatchStep(const LeaseStep &step)
    {
        QVector<LeaseAction> rest;
        for (const LeaseAction &a : step.actions) {
            switch (a.kind) {
            case LeaseActionKind::SendAcquire: sendAcquire(a); break;
            case LeaseActionKind::SendRenew: m_io->renew(a.requestId, a.leaseId, a.meter, a.route); break;
            case LeaseActionKind::SendRelease: m_io->release(a.requestId, a.leaseId, a.meter, a.route); break;
            default: rest << a; break;
            }
        }
        return rest;
    }

    // Row S2: releases that never reached the server over the route they were sent on go out again when a route that
    // works shows up - the tunnel's API base of a session that came up, or the route an acquire was ANSWERED by. Never
    // for a lease a live session holds, never past the lease's TTL (the server has freed the seat by itself), at most
    // kUnsentMaxSends sends in all. They are registered like every release (a start of the profile takes them back).
    void flushUnsent(const LeaseRoute &via, qint64 nowMs)
    {
        for (const QString &id : m_releases.keys()) {
            PendingRelease &u = m_releases[id];
            if (u.state != RelState::Unsent)
                continue;
            if (u.deadlineMs <= nowMs || holdsLease(u.leaseId)) {
                m_releases.remove(id); // gone by itself, or somebody owns the id now
                continue;
            }
            if (m_orphanAcquire != 0 || (m_active && m_machine.acquireInFlight() != 0)
                || (m_io && m_io->acquireAlive(u.profile)))
                continue; // an acquire of the profile may be handed this very id: wait for its answer
            u.tries += 1;
            u.deadlineMs = qMax(u.deadlineMs, nowMs); // keeps the original bound
            LeaseRoute r = u.route;
            r.apiBase = via.apiBase; // empty = the direct path
            sendOut(u, r, /*via=*/true);
        }
    }
    // The API base that is reachable through the running tunnel: the lease's tunnel_api_base, or the standby pack's.
    QString tunnelBase() const
    {
        return !m_machine.route().apiBase.isEmpty() ? m_machine.route().apiBase : m_provisionalBase;
    }
    qint64 leaseTtlMs() const
    {
        return qint64(m_grant.ttlS > 0 ? m_grant.ttlS : 900) * 1000;
    }

    // ---- the pending releases (one per lease id) ----
    enum class RelState { Out, Withdrawn, Unsent, Deferred }; // Deferred: a late grant waits for the newer acquire's end
    struct PendingRelease {
        QString profile, leaseId;
        LeaseRoute route;      // the grant's own renew token travels in it
        qint64 deadlineMs = 0; // the lease's own TTL from now: after it the server has freed the seat anyway
        int tries = 0;         // sends of this release over a later route (row S2)
        RelState state = RelState::Out;
        quint64 requestId = 0; // Out: the id the client knows it by
        quint64 order = 0;     // how new route.renewToken is (noteToken)
    };
    int countIn(RelState st) const
    {
        int n = 0;
        for (const PendingRelease &p : m_releases)
            n += p.state == st ? 1 : 0;
        return n;
    }
    PendingRelease *outByRequest(quint64 requestId)
    {
        if (requestId == 0)
            return nullptr;
        for (auto it = m_releases.begin(); it != m_releases.end(); ++it)
            if (it->state == RelState::Out && it->requestId == requestId)
                return &it.value();
        return nullptr;
    }
    // Tokens are ordered by the acquire request that was answered with them (request ids grow with the send order; the
    // server rotates in the order it processes them): a late grant of an OLDER acquire must not replace the release of a
    // newer grant of the same lease.
    void noteToken(const QString &token, quint64 acquireId)
    {
        if (token.isEmpty() || acquireId == 0)
            return;
        if (m_tokenOrder.size() > 64)
            m_tokenOrder.clear();
        m_tokenOrder.insert(token, qMax(acquireId, m_tokenOrder.value(token, 0)));
    }
    // Registers a release as Out under `requestId` (0: the caller sends it itself through sendOut). One per lease id: a
    // second one replaces the first (the first one's resends stop: releaseWanted finds no such request any more) unless the
    // first one's token is newer. false = refused, the existing one stays.
    bool registerRelease(const QString &profileId, const QString &leaseId, const LeaseRoute &route, quint64 requestId)
    {
        PendingRelease p;
        p.profile = profileId;
        p.leaseId = leaseId;
        p.route = route;
        p.deadlineMs = m_lastNowMs + leaseTtlMs();
        p.requestId = requestId;
        p.order = m_tokenOrder.value(route.renewToken, 0);
        const auto old = m_releases.constFind(leaseId);
        if (old != m_releases.constEnd() && old->order > p.order)
            return false;
        m_releases.insert(leaseId, p);
        return true;
    }
    // Sends the pending release (a new request id, the route given - its own token inside).
    void sendOut(PendingRelease &p, const LeaseRoute &route, bool via = false)
    {
        p.state = RelState::Out;
        p.requestId = (quint64(1) << 62) | ++m_ownSerial;
        if (!m_io)
            return;
        if (via)
            m_io->releaseVia(p.requestId, p.leaseId, route);
        else
            m_io->release(p.requestId, p.leaseId, UpstreamMeter{}, route);
    }

    // A release of this owner outside the machine's own actions: registered first, then sent (the request id is in
    // the high range so it never meets the machine's counter).
    void releaseThroughLedger(const QString &profileId, const QString &leaseId, const LeaseRoute &route)
    {
        if (!m_io || !registerRelease(profileId, leaseId, route, 0))
            return;
        sendOut(m_releases[leaseId], route);
    }

    void noteReleasesSent(const LeaseStep &s)
    {
        for (const LeaseAction &a : s.actions)
            if (a.kind == LeaseActionKind::SendRelease)
                registerRelease(a.profileId, a.leaseId, a.route, a.requestId);
    }

    // The waiting session's acquire goes out once nothing is in its way.
    void startQueuedIfFree(qint64 nowMs, QVector<UpstreamOwnerEvent> &ev)
    {
        if (!m_active || !m_startQueued || startBlocked())
            return;
        m_startQueued = false;
        apply(m_machine.start(m_profileId, LeaseKind::Session, machineScope(), m_queuedRevision, nowMs), nowMs, ev);
    }

    void failStart(QVector<UpstreamOwnerEvent> &ev, const QString &code, const QString &detail = QString())
    {
        UpstreamOwnerEvent f;
        f.kind = m_prepareOnly ? UpstreamOwnerEventKind::PrepareFailed : UpstreamOwnerEventKind::StartFailed;
        f.prepareId = m_sessionSerial;
        f.detail = detail;
        f.code = code.isEmpty() ? QStringLiteral("unknown") : code;
        ev << f;
        m_active = false;
        reinstateWithdrawn();
    }

    IUpstreamLeaseIo *m_io = nullptr;
    UpstreamLeaseTiming m_timing;
    UpstreamLeaseMachine m_machine;
    Options m_opt;
    QString m_nodeId, m_profileId, m_stubSha, m_leftCode;
    std::optional<StandbyCandidate> m_standby;
    UpstreamLeaseGrant m_grant;
    AcquireReply m_lastAcquire;
    UpstreamRenewal m_lastRenewal;
    bool m_hasRenewal = false;
    quint64 m_lastAcquireRequest = 0;
    qint64 m_lastAcquireSentMs = 0, m_grantSentMs = 0, m_wallAtStart = 0, m_monoAtStart = 0;
    qint64 m_adoptedStartedWallMs = 0;
    bool m_requestSent = false; // an acquire or the native start really went out in this session (upstreamRequestSent)
    bool m_bringUpSent = false; // the native start was asked for (BringUp event): a Disconnected can now be this session's
    bool m_active = false, m_bringUp = false, m_tunnelIsUp = false, m_handedOver = false, m_adopted = false;
    bool m_rebasePending = false, m_releaseSent = false, m_configChanged = false, m_haveBytes = false;
    quint64 m_sessionSerial = 0; // never reset: one value per begin()/prepare()
    // Requests that outlive their session (never reset with it - startBlocked):
    quint64 m_orphanAcquire = 0;          // the acquire a session's end cancelled, until its answer
    QString m_orphanProfile;
    quint64 m_ownSerial = 0;
    QHash<QString, PendingRelease> m_releases; // ONE pending release per lease id (Out / Withdrawn / Unsent)
    QHash<QString, quint64> m_tokenOrder;      // renew token -> the acquire request it answered (newest wins a collision)
    static constexpr int kUnsentMaxSends = 3;
    qint64 m_lastNowMs = 0;       // the owner's last clock reading (a deadline for a release made without one)
    bool m_lastAcquireStandby = false;
    QString m_provisionalBase; // the standby pack entry's tunnel_api_base of the running provisional session
    bool m_startQueued = false;            // this session's acquire waits (startBlocked)
    qint64 m_queuedRevision = 0;
    bool m_prepareOnly = false; // prepare(): a seat taken before the switch, not brought up yet
    bool m_prepared = false;    // ... and granted (Prepared was reported)
    qint64 m_lastRx = 0, m_lastTx = 0;
    qint64 m_renewedAtMs = -1, m_wakeAtMs = -1;
    qint64 m_appliedTotal = 0, m_shadowTotal = 0;
};

} // namespace avpn
