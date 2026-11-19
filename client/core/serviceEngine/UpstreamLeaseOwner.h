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
        return ev;
    }

    QVector<UpstreamOwnerEvent> onAcquireReply(quint64 requestId, const AcquireReply &r, qint64 nowMs)
    {
        QVector<UpstreamOwnerEvent> ev;
        if (requestId == m_lastAcquireRequest) {
            m_lastAcquire = r;
            if (r.kind == LeaseReplyKind::Granted) {
                m_grant = r.grant;
                m_grantSentMs = m_lastAcquireSentMs;
            }
        }
        apply(m_machine.onAcquireReply(requestId, r, nowMs), nowMs, ev); // a grant nobody took over: released
        if (requestId != 0 && requestId == m_orphanAcquire) {
            m_orphanAcquire = 0;
            m_orphanProfile.clear();
            startQueuedIfFree(nowMs, ev);
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
        m_active = m_bringUp = m_tunnelIsUp = m_handedOver = m_adopted = m_rebasePending = m_bringUpSent = false;
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
        m_releaseSent = false;
        if (!m_active)
            return ev;
        // The machine's session ends with the owner's, ALWAYS (owner's iPhone 16.11, build 140: after a refused
        // profile the machine stayed Active, so the next start() was ignored - "acquiring a seat", no request,
        // the 15 s start watchdog - and its dead lease was "released" only at the following stop). Who sends the
        // release is upstreamAppReleasesSeat: a lease that never reached a running tunnel is still this process's.
        quint64 out = m_machine.acquireInFlight();
        for (int i = m_gatedAcquires.size() - 1; i >= 0; --i) // never sent: nothing will answer it
            if (m_gatedAcquires[i].requestId == out) {
                m_gatedAcquires.removeAt(i);
                out = 0;
            }
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
            // Review R5 of 19.11: this release is ours like any other - registered, so an acquire of its profile
            // waits for it (the server hands the same lease id back, and the release would then end the new session).
            m_releasesOut.insert(a->requestId, a->profileId);
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
        // Sends first (the machine expects them dispatched); the acquire's send time anchors the probe
        // grant's own expiry.
        for (const LeaseAction &a : s.actions) {
            if (a.kind == LeaseActionKind::SendAcquire) {
                m_lastAcquireRequest = a.requestId;
                m_lastAcquireSentMs = nowMs;
            }
            if (a.kind == LeaseActionKind::SendRelease) {
                m_releaseSent = true;
                m_releasesOut.insert(a.requestId, a.profileId);
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
    // ===== Lease id ledger (reviews R4, R5 of 19.11 and F3, F4, F9 of round 2: ONE question - who holds lease id L
    // right now, and who must release it) =====
    // The server hands the SAME lease id back to the same device for the same profile (upstream_pool.acquire_lease:
    // "Idempotent re-acquire ... same lease") and DELETE ends the lease whoever sends it. So an id has exactly one
    // fate at a time and every DELETE is a decision of THIS owner; nothing else sends one.
    //   state            meaning                                   how it is known
    //   requested        an acquire of the profile is alive        machine in flight / orphan / client's HTTP request
    //   held             a live session uses L                     m_active && machine.leaseId() == L (holdsLease)
    //   release pending  our DELETE of L is out or being resent    m_releasesOut (request id -> profile), until
    //                    (seatReleaseNext: about 20 s at most)     onReleaseDone
    //   gone             answered / given up / never sent          nothing
    //   event                                     transition                                      who sends the DELETE
    //   session end (stop, switch, refusal)       held -> release pending                          machine (SendRelease)
    //   stop with the tunnel owner holding L      held -> release pending after the confirmed stop endSession (ReleaseAfterStop)
    //   a Disconnected nobody asked for           held -> release pending AT ONCE (tunnelLost)      tunnelLost
    //   a refused permission (Android), start     held -> release pending at once, nothing to       abortStart
    //     never reached the native service        wait for
    //   a grant nobody waits for (late/orphan)    L held by a live session: stays. Another acquire  lateGrant / acquireEnded
    //                                             of the profile alive: judged at its end.
    //                                             Otherwise: release pending at once.
    //   granted, tunnel never came up (G2):       the seat's lifetime starts at the GRANT. A native Disconnected after
    //     Disconnected / start error / leg        the start was asked for (tunnelLost), a start that never reached the
    //     timeout / attempt ended before          native service or an attempt that ended before Connected (abortStart,
    //     Connected                               via ITunnelControl::startRefused), a stop (disconnect): -> release
    //                                             pending at once - the extension has no release handler yet, so the app
    //                                             releases (upstreamAppReleasesSeat)
    //   ANY acquire of profile P (direct, standby confirmation in tunnelUp(), provisional re-acquire in tick() - all
    //     come out of the machine as SendAcquire and leave through sendAcquire, the one gate (G1))
    //                                             goes out only when no release of P is pending     sendAcquire (held, sent by
    //                                                                                               onReleaseDone; dropped
    //                                                                                               with its session)
    // Every row registers its request id in m_releasesOut BEFORE the DELETE leaves; the wait is bounded by the
    // release rule (seatReleaseNext) and never on an event that already happened.

    // A grant that arrived after the attempt stopped waiting (UpstreamLeaseClient::onLateGrant).
    QVector<UpstreamOwnerEvent> lateGrant(const QString &profileId, const QString &leaseId, const LeaseRoute &route,
                                          bool newerAcquireOut)
    {
        QVector<UpstreamOwnerEvent> ev;
        if (holdsLease(leaseId))
            return ev; // the live session's seat
        if (newerAcquireOut) {
            m_deferredSeat.insert(profileId, DeferredSeat{leaseId, route});
            return ev;
        }
        releaseThroughLedger(profileId, leaseId, route);
        return acquireEnded(profileId, leaseId, false); // nothing else is out: a deferred seat of an earlier request is judged now
    }

    // An acquire request of the profile ended (any outcome).
    QVector<UpstreamOwnerEvent> acquireEnded(const QString &profileId, const QString &grantedLeaseId, bool stillOut)
    {
        QVector<UpstreamOwnerEvent> ev;
        const auto it = m_deferredSeat.find(profileId);
        if (it == m_deferredSeat.end() || stillOut)
            return ev;
        const DeferredSeat d = it.value();
        m_deferredSeat.erase(it);
        if (d.leaseId == grantedLeaseId || holdsLease(d.leaseId))
            return ev; // the newer request took the same seat over
        releaseThroughLedger(profileId, d.leaseId, d.route);
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
    //    cancelled request over;
    //  - a release this owner sent stays out until it ends (onReleaseDone); an acquire of THAT profile waits for
    //    it - the server answers an acquire of a profile it holds for the device with the existing lease, which the
    //    release in flight would then end.
    // The cancelled acquire's answer is the machine's: a grant nobody took over is released. Cost: a pick that
    // follows another within one acquire round trip waits for that answer (B -> C -> D: D goes out when B is
    // answered, at most the acquire bound upstreamAcquireTimeoutMsTuned later); a pick of the profile whose seat
    // was just given back waits for that release (at most its 1.5 s bound per try).
    bool startBlocked() const
    {
        if (m_orphanAcquire != 0)
            return true;
        for (auto it = m_releasesOut.constBegin(); it != m_releasesOut.constEnd(); ++it)
            if (it.value() == m_profileId)
                return true;
        return false;
    }
    // The live session holds this lease id (a late or orphan answer of the same id must not release it).
    bool holdsLease(const QString &leaseId) const
    {
        return m_active && !leaseId.isEmpty() && m_machine.phase() == LeasePhase::Active && m_machine.leaseId() == leaseId;
    }
    bool startQueued() const { return m_active && m_startQueued; }
    int gatedAcquires() const { return int(m_gatedAcquires.size()); }
    int requestsOutstanding() const { return (m_orphanAcquire ? 1 : 0) + int(m_releasesOut.size()); }

    // A release this owner sent ended (UpstreamLeaseClient::onReleaseDone: answered, timed out or given up).
    QVector<UpstreamOwnerEvent> onReleaseDone(quint64 requestId, qint64 nowMs)
    {
        QVector<UpstreamOwnerEvent> ev;
        if (m_releasesOut.remove(requestId)) {
            flushGatedAcquires();
            startQueuedIfFree(nowMs, ev);
        }
        return ev;
    }

private:

    // THE one place where an acquire leaves this owner (review G1 of round 3: the direct acquire, the standby
    // confirmation of tunnelUp() and the provisional re-acquire of tick() all come out of the machine as SendAcquire
    // and all pass this gate). The gate: no release of the same profile is pending - the server would answer with
    // the lease that release is about to end. A gated acquire is sent by onReleaseDone, or dropped with its session.
    bool releasePendingFor(const QString &profileId) const
    {
        for (auto it = m_releasesOut.constBegin(); it != m_releasesOut.constEnd(); ++it)
            if (it.value() == profileId)
                return true;
        return false;
    }
    void sendAcquire(const LeaseAction &a)
    {
        if (releasePendingFor(a.profileId)) {
            m_gatedAcquires.append(a);
            return;
        }
        if (m_io)
            m_io->acquire(a.requestId, a.profileId, a.leaseKind, a.configSha256, a.route);
    }
    void flushGatedAcquires()
    {
        const QVector<LeaseAction> gated = std::exchange(m_gatedAcquires, {});
        for (const LeaseAction &a : gated)
            sendAcquire(a); // still blocked ones queue again
    }
    // Like dispatchLeaseIo (UpstreamLeaseMachine.h) but acquires go through the gate; returns the other actions.
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

    // A release of this owner outside the machine's own actions: registered first, then sent (the request id is in
    // the high range so it never meets the machine's counter).
    void releaseThroughLedger(const QString &profileId, const QString &leaseId, const LeaseRoute &route)
    {
        if (!m_io)
            return;
        const quint64 id = (quint64(1) << 62) | ++m_ownSerial;
        m_releasesOut.insert(id, profileId);
        m_io->release(id, leaseId, UpstreamMeter{}, route);
    }

    void noteReleasesSent(const LeaseStep &s)
    {
        for (const LeaseAction &a : s.actions)
            if (a.kind == LeaseActionKind::SendRelease)
                m_releasesOut.insert(a.requestId, a.profileId);
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
    bool m_bringUpSent = false; // the native start was asked for (BringUp event): a Disconnected can now be this session's
    bool m_active = false, m_bringUp = false, m_tunnelIsUp = false, m_handedOver = false, m_adopted = false;
    bool m_rebasePending = false, m_releaseSent = false, m_configChanged = false, m_haveBytes = false;
    quint64 m_sessionSerial = 0; // never reset: one value per begin()/prepare()
    // Requests that outlive their session (never reset with it - startBlocked):
    quint64 m_orphanAcquire = 0;          // the acquire a session's end cancelled, until its answer
    QString m_orphanProfile;
    struct DeferredSeat {
        QString leaseId;
        LeaseRoute route;
    };
    QHash<QString, DeferredSeat> m_deferredSeat; // profile -> a late grant judged when the newer acquire ends
    quint64 m_ownSerial = 0;
    QVector<LeaseAction> m_gatedAcquires; // acquires held back by releasePendingFor (sendAcquire)
    QHash<quint64, QString> m_releasesOut; // releases sent (request id -> profile), until onReleaseDone
    bool m_startQueued = false;            // this session's acquire waits (startBlocked)
    qint64 m_queuedRevision = 0;
    bool m_prepareOnly = false; // prepare(): a seat taken before the switch, not brought up yet
    bool m_prepared = false;    // ... and granted (Prepared was reported)
    qint64 m_lastRx = 0, m_lastTx = 0;
    qint64 m_renewedAtMs = -1, m_wakeAtMs = -1;
    qint64 m_appliedTotal = 0, m_shadowTotal = 0;
};

} // namespace avpn
