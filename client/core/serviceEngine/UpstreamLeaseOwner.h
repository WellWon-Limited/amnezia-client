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
#include <QSet>
#include <QVector>

#include <functional>
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
    // Where the last start order is kept (the app's settings): load / save of one number; survives a relaunch.
    void setOrderStore(std::function<qint64()> load, std::function<void(qint64)> save) { m_order.setStore(std::move(load), std::move(save)); }
    // The server's floor for the start orders (an acquire answer of the API that carries min_session_order): the counter is raised
    // to at least it; the running start keeps its own order (the denied start fails as any terminal refusal does).
    void raiseOrderFloor(qint64 floorOrder) { m_order.raiseFloor(floorOrder); }
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
        m_sessionOrder = m_order.next(nowWallMs);
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
        // A `stale_session` denial (HTTP 404 lease_gone, reason stale_session: the nonce's tenure ended, or its order is behind a newer
        // start's) is never the answer the CURRENT start waits for: its requests carry its own fresh nonce and order. If one comes
        // anyway it is a refusal like any terminal one (the machine leaves / the leg fails with lease_gone). The answer of an older
        // start's request is not the machine's request any more - nothing to release, nothing to tell.
        const LeaseStep s = m_machine.onAcquireReply(requestId, r, nowMs);
        if (s.inert) {
            applyInert(s, nowMs); // an older start's answer: its own lease is released, the current session is not touched
            return ev;
        }
        apply(s, nowMs, ev);
        return ev;
    }

    // ANY answer of the API proves the route it came by (round 9 R3): a refusal or an HTTP error status is an answer like a
    // grant; only a transport failure proves nothing. Releases that could not be carried go out by that route. THE one place
    // that decides it (round 10 R4): UpstreamLeaseClient calls it for every acquire request that got an HTTP answer, whichever
    // path the answer takes to the owner (in time, after the attempt stopped waiting, a grant or not), after the owner has
    // seen the answer. Before, only the in-time path flushed: a refusal that landed after the hedge reached acquireEnded() alone.
    void routeProved(quint64 requestId, qint64 nowMs)
    {
        const auto it = m_acquireViaTunnel.find(requestId);
        if (it == m_acquireViaTunnel.end())
            return;
        const bool viaTunnel = it.value();
        m_acquireViaTunnel.erase(it);
        m_lastNowMs = nowMs;
        if (unsentCount() == 0)
            return;
        if (!viaTunnel)
            flushUnsent(LeaseRoute{}, nowMs);
        else if (!tunnelBase().isEmpty())
            flushUnsent(LeaseRoute{QString(), tunnelBase()}, nowMs);
    }

    QVector<UpstreamOwnerEvent> onRenewReply(quint64 requestId, const RenewReply &r, qint64 nowMs, qint64 nowWallMs = 0)
    {
        QVector<UpstreamOwnerEvent> ev;
        const LeaseStep s = m_machine.onRenewReply(requestId, r, nowMs);
        if (s.inert)
            return ev; // a renewal the session does not wait for (its session ended): nothing of the current one changes
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
    // The nonce of the current start (tests; a secret-ish value: never logged).
    const QString &sessionNonce() const { return m_nonce; }
    qint64 sessionOrder() const { return m_sessionOrder; }
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
        // THE nonce of this START (UpstreamLeaseWire.h::kUpstreamAcquireNonceField, contract 1.19.0): made here, where every start is
        // made (begin, prepare, adopt), fresh each time, and carried by every acquire of the start - the direct request, the seat
        // confirmation through the tunnel, a retry. The server gives one nonce ONE tenure of a seat (one lease id, one renew token);
        // another start takes the seat over with a new lease, and a nonce whose lease ended is refused (stale_session) for good.
        // Never reused by a later start, never made per request.
        m_nonce = upstreamNewSessionNonce();
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
        const LeaseStep s = m_machine.disconnect(nowMs); // an acquire in flight stays the machine's (cancelled) until its answer
        if (upstreamAppReleasesSeat(m_opt.keepOwnership, m_handedOver, m_tunnelIsUp)) {
            m_releaseSent = s.has(LeaseActionKind::SendRelease);
            const QSet<quint64> merged = registerReleasesOf(s);
            if (m_io)
                dispatchStep(s, merged);
        } else if (const LeaseAction *a = s.find(LeaseActionKind::SendRelease)) {
            // The tunnel owner releases first, on its own stop, with the final report; this process again once
            // that stop is confirmed (the adapter holds it until then). Registered like every release (one per lease): when the
            // lease already has a pending release - the final report may be in it - this one merges into it and nothing is sent.
            UpstreamOwnerEvent r;
            r.kind = UpstreamOwnerEventKind::ReleaseAfterStop;
            r.leaseId = a->leaseId;
            r.route = a->route;
            r.requestId = a->requestId;
            if (registerRelease(a->profileId, a->leaseId, a->route, a->requestId, UpstreamMeter{}))
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
        judgeDeferred(m_profileId); // the session's own late grant that never got confirmed: released now
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

    // An INERT step (LeaseStep::inert: the answer of a request the current start does not own, or an ignored call) never writes the
    // session's state (schedule, release flag, phase-driven events). The only thing such a step may do is give back the lease IT names:
    // its releases go through the ledger and out, nothing else is looked at (round 12 R1). The answer paths call this directly; apply()
    // routes any other inert step here as its first act.
    void applyInert(const LeaseStep &s, qint64 nowMs)
    {
        m_lastNowMs = nowMs;
        const QSet<quint64> merged = registerReleasesOf(s);
        if (!m_io)
            return;
        for (const LeaseAction &a : s.actions) {
            if (a.kind != LeaseActionKind::SendRelease || merged.contains(a.requestId))
                continue;
            const auto it = m_releases.constFind(a.leaseId);
            m_io->release(a.requestId, a.leaseId, it != m_releases.constEnd() ? it->meter() : a.meter, a.route);
        }
    }

    // silentReady: the LeaseReady of an adoption (the tunnel already runs) is not a bring-up.
    void apply(const LeaseStep &s, qint64 nowMs, QVector<UpstreamOwnerEvent> &ev, bool silentReady = false)
    {
        if (s.inert) {
            applyInert(s, nowMs);
            return;
        }
        m_lastNowMs = nowMs;
        // Sends first (the machine expects them dispatched); the acquire's send time anchors the probe
        // grant's own expiry.
        for (const LeaseAction &a : s.actions) {
            if (a.kind == LeaseActionKind::SendAcquire) {
                m_lastAcquireRequest = a.requestId;
                m_lastAcquireSentMs = nowMs;
            }
        }
        if (s.has(LeaseActionKind::SendRelease))
            m_releaseSent = true;
        const QSet<quint64> merged = registerReleasesOf(s);
        QVector<LeaseAction> rest;
        if (m_io)
            rest = dispatchStep(s, merged);
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
                judgeDeferred(m_profileId); // the session's own late grant is the seat it just confirmed: dropped
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
                judgeDeferred(m_profileId);
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
        m_sessionOrder = m_order.next(nowWallMs); // created with the nonce: one order per start, strictly increasing, persisted
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
        // A start always has its own nonce and sends its own request at once: a request of an older start that is still in flight is
        // left to finish (a late answer of an older start - the machine releases its grant, a refusal is ignored), whatever its profile.
        apply(m_machine.start(m_profileId, LeaseKind::Session, machineScope(), knownRevision, nowMs), nowMs, ev);
        return ev;
    }

public:
    // ===== Lease id ledger (reviews R4, R5 of 19.11 and F3, F4, F9 of round 2, rounds 9-11: ONE question - who holds lease id L
    // right now, and who must release it) =====
    // The server's rule (contract 1.19.0): ONE session nonce names ONE tenure of a seat. The same nonce -> the same lease id and the
    // same renew token, extended, in any order of requests (a renewal never rotates the token). Another nonce -> that start takes the
    // seat over: the old lease ENDS (replaced) and a NEW lease id with a new token is made. A nonce whose lease ended as released or
    // replaced is stale: its acquire is refused (stale_session) and changes nothing; one whose lease expired is not stale (a new
    // lease id). A DELETE ends the lease only with its current token. So: a lease id belongs to exactly one start and has one token
    // (one pending release per lease id, no ordering of tokens); a start never waits for a release and never needs to withdraw one -
    // an old DELETE can only end the old start's own lease; a late acquire of an older start takes nothing.
    //   state            meaning                                   how it is known
    //   requested        an acquire of the profile is alive        machine in flight / orphan / client's HTTP request
    //   held             a live session uses L                     m_active && machine.leaseId() == L (holdsLease)
    //   Out              our DELETE of L is out, held for a stop    m_releases[L].state, until onReleaseDone
    //                    or being resent (seatReleaseNext: about 20 s at most)
    //   Unsent           gave up over its route, kept for the      m_releases[L].state (S2)
    //                    next route that works
    //   Deferred         a late grant waits for the acquire of      m_releases[L].state (lateGrant / acquireEnded)
    //                    the profile that is alive to end
    //   gone             answered / given up / never sent          no entry
    //   event                                     transition                                      who sends the DELETE
    //   session end (stop, switch, refusal)       held -> Out                                      machine (SendRelease)
    //   stop with the tunnel owner holding L      held -> Out after the confirmed stop            endSession (ReleaseAfterStop)
    //   a Disconnected nobody asked for           held -> Out AT ONCE (tunnelLost)                tunnelLost
    //   a refused permission (Android), start     held -> Out at once, nothing to wait for        abortStart
    //     never reached the native service
    //   a grant nobody waits for (late/orphan)    L held by a live session: stays. The session's own start, not confirmed:
    //                                             kept. Another acquire of the profile alive: judged at its end. Otherwise: Out
    //                                             at once (with THAT grant's token).                lateGrant / acquireEnded
    //   granted, tunnel never came up (G2):       the seat's lifetime starts at the GRANT. A native Disconnected after
    //     Disconnected / start error / leg        the start was asked for (tunnelLost), a start that never reached the
    //     timeout / attempt ended before          native service or an attempt that ended before Connected (abortStart,
    //     Connected                               via ITunnelControl::startRefused), a stop (disconnect): -> Out at once -
    //                                             the extension has no release handler yet, so the app releases
    //                                             (upstreamAppReleasesSeat)
    //   Unsent release (S2)                       bounded by the lease's TTL and kUnsentMaxSends sends, sent over a route that
    //                                             works - the tunnel's API base once a session is up / confirmed, or the route
    //                                             that ANSWERED an acquire (an answer of the API: the answer carries its mark; a
    //                                             transport failure or a foreign answer proves nothing) - never while an acquire of
    //                                             the profile is alive, never for an id a session holds
    // Every release is registered in m_releases BEFORE the DELETE leaves. The entry owns the final report (PendingRelease).

    // A grant that arrived after the attempt stopped waiting (UpstreamLeaseClient::onLateGrant).
    // route = the late grant's own token (and the base it came by); acquireId = the request that was answered.
    QVector<UpstreamOwnerEvent> lateGrant(const QString &profileId, const QString &leaseId, const LeaseRoute &route,
                                          bool newerAcquireOut, quint64 acquireId = 0)
    {
        QVector<UpstreamOwnerEvent> ev;
        if (holdsLease(leaseId))
            return ev; // the live session's seat, answered twice (one start, one lease, one token): nothing to release
        const QString nonce = m_acquireNonce.value(acquireId);
        if (ownStart(acquireId)) {
            // The grant of THIS start's own request (the direct acquire that outlived the hedge), and the session has no lease
            // yet (provisional: its confirmation through the tunnel is still to come). The server gives one start one lease and one
            // token, so it is the very lease the confirmation will get: releasing it now would end the seat the session is about
            // to confirm. It is the session's: judged when the session confirms (held: dropped) or ends (released).
            deferRelease(profileId, leaseId, route, nonce);
            return ev;
        }
        if (newerAcquireOut) {
            // judged when the newer request ends (a start that took a cancelled request over is ONE start with it: the same lease
            // may still be handed to the session); kept in the ledger like every release, one per lease id
            deferRelease(profileId, leaseId, route, nonce);
            return ev;
        }
        releaseThroughLedger(profileId, leaseId, route, nonce); // a lease of a start nobody continues: given back at once
        return acquireEnded(profileId, leaseId, false); // nothing else is out: a deferred seat of an earlier request is judged now
    }

    // An acquire request of the profile ended (any outcome).
    QVector<UpstreamOwnerEvent> acquireEnded(const QString &profileId, const QString &grantedLeaseId, bool stillOut)
    {
        (void)grantedLeaseId; // a session's grant is told by holdsLease; a released one met its deferred twin in the ledger
        QVector<UpstreamOwnerEvent> ev;
        if (stillOut)
            return ev;
        if (unsentCount() > 0 && m_active && m_tunnelIsUp && !tunnelBase().isEmpty())
            flushUnsent(LeaseRoute{QString(), tunnelBase()}, m_lastNowMs); // the way is clear now
        judgeDeferred(profileId, /*checkAlive=*/false); // the client knows: no request of the profile is alive any more
        return ev;
    }

    // Some acquire of the profile is alive: the cancelled one, the machine's own, or an HTTP request the client still holds.
    bool acquireOfProfileAlive(const QString &profileId) const
    {
        return m_machine.cancelledAcquireOf(profileId) || (m_active && m_machine.acquireInFlight() != 0)
               || (m_io && m_io->acquireAlive(profileId));
    }

    // Deferred releases of the profile are decided here: held by the live session -> dropped (it took the same seat over);
    // the live session's own start, not confirmed yet -> kept; otherwise released with ITS token.
    void judgeDeferred(const QString &profileId, bool checkAlive = true)
    {
        for (const QString &id : m_releases.keys()) {
            PendingRelease &d = m_releases[id];
            if (d.state != RelState::Deferred || d.profile != profileId)
                continue;
            if (holdsLease(d.leaseId)) {
                m_releases.remove(id); // the live session took this very seat over (one start, one lease)
                continue;
            }
            if (m_active && !m_nonce.isEmpty() && d.nonce == m_nonce)
                continue; // the session's own seat, not confirmed yet
            if (checkAlive && acquireOfProfileAlive(profileId))
                continue; // another acquire of the profile is alive: judged when it ends
            sendOut(d, d.route);
        }
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

    // Nothing holds a start: not a release (round 9 R1), not a cancelled acquire of an older start (it is left to finish, the
    // machine releases its grant - the server gives the new start another lease and ends the old one as replaced).
    // The live session holds this lease id (a late or orphan answer of the same id must not release it).
    bool holdsLease(const QString &leaseId) const
    {
        return m_active && !leaseId.isEmpty() && m_machine.phase() == LeasePhase::Active && m_machine.leaseId() == leaseId;
    }
    // The live session of this profile can start from a standby-pack entry (so it does not wait the full lease share).
    bool hasStandbyFor(const QString &profileId) const
    {
        return m_active && !m_prepareOnly && m_standby.has_value() && m_profileId == profileId;
    }
    bool requestSent() const { return m_requestSent; }
    int unsentCount() const { return countIn(RelState::Unsent); }
    int requestsOutstanding() const { return m_machine.cancelledAcquiresPending() + countIn(RelState::Out); }
    int pendingReleases() const { return int(m_releases.size()); } // at most one per lease id

    // The client asks before it resends a release (UpstreamLeaseClient::releaseWanted): false = the release was replaced by a
    // newer request for the same lease id (it took over the chain) or is gone - no resend, no answer.
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
            return ev; // replaced meanwhile: not this request's any more
        if (!confirmed && p->tries < kUnsentMaxSends && p->deadlineMs > nowMs && countIn(RelState::Unsent) < 8) {
            p->state = RelState::Unsent;
            p->requestId = 0;
        } else {
            const QString id = p->leaseId; // a copy: the entry is destroyed by the removal
            m_releases.remove(id);
        }
        return ev;
    }

private:

    // THE one place where an acquire leaves this owner (the direct acquire, the standby confirmation of tunnelUp() and the
    // provisional re-acquire of tick() all come out of the machine as SendAcquire). It goes AT ONCE and waits for no release: a
    // release of the profile that is still pending is the old session's, and the server gives the new start another lease (the
    // old one ends as replaced), so the old DELETE can only end what is already the old session's - it is left to run (and to
    // carry its final report if the new acquire has not been processed yet).
    void sendAcquire(const LeaseAction &a)
    {
        m_requestSent = true; // something really left for the server: evidence about the path may follow
        emitAcquire(a.requestId, a.profileId, a.leaseKind, a.configSha256, a.route, a.standby);
    }
    // THE one call that puts an acquire on the wire: the session's nonce on it, and what its answer will be asked about (which
    // START it belongs to, which route it proves).
    void emitAcquire(quint64 requestId, const QString &profileId, LeaseKind kind, const QString &sha, const LeaseRoute &route,
                     bool viaTunnel)
    {
        noteAcquireNonce(requestId, m_nonce);
        noteAcquireRoute(requestId, viaTunnel);
        if (m_io)
            m_io->acquire(requestId, profileId, kind, sha, route, m_nonce, m_sessionOrder);
    }
    // Like dispatchLeaseIo (UpstreamLeaseMachine.h) but acquires go through sendAcquire; returns the other actions.
    // `merged` = the releases of the step that were folded into a pending release of the same lease (registerReleasesOf): not sent.
    QVector<LeaseAction> dispatchStep(const LeaseStep &step, const QSet<quint64> &merged)
    {
        QVector<LeaseAction> rest;
        for (const LeaseAction &a : step.actions) {
            switch (a.kind) {
            case LeaseActionKind::SendAcquire: sendAcquire(a); break;
            case LeaseActionKind::SendRenew: m_io->renew(a.requestId, a.leaseId, a.meter, a.route); break;
            case LeaseActionKind::SendRelease:
                if (!merged.contains(a.requestId)) {
                    const auto it = m_releases.constFind(a.leaseId);
                    m_io->release(a.requestId, a.leaseId, it != m_releases.constEnd() ? it->meter() : a.meter, a.route); // the ledger's report
                }
                break;
            default: rest << a; break;
            }
        }
        return rest;
    }

    // Row S2: releases that never reached the server over the route they were sent on go out again when a route that
    // works shows up - the tunnel's API base of a session that came up, or the route an acquire was ANSWERED by. Never
    // for a lease a live session holds, never past the lease's TTL (the server has freed the seat by itself), at most
    // kUnsentMaxSends sends in all (with the report the entry owns).
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
            if (acquireOfProfileAlive(u.profile))
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
    enum class RelState { Out, Unsent, Deferred }; // Deferred: a late grant waits for the newer acquire's end
    // ONE pending release per lease id. The entry OWNS the final meter report of the lease: it is attached when the entry is made (or
    // later, once) and no insert for the same lease ever drops or replaces it - whoever sends the DELETE (the first try, a resend, a
    // flush over a later route) takes the report from here, not from the caller (round 11 R2: a late answer of the session's own
    // start used to replace the held release that carried it with one that carried none).
    class PendingRelease {
    public:
        PendingRelease() = default;
        PendingRelease(const QString &profileId, const QString &lease, const QString &startNonce, const LeaseRoute &r,
                       const UpstreamMeter &m, qint64 deadline, quint64 request)
            : profile(profileId), leaseId(lease), nonce(startNonce), route(r), deadlineMs(deadline), requestId(request), m_meter(m) {}
        QString profile, leaseId;
        QString nonce;         // the start whose request was granted this lease (a late grant: m_acquireNonce); empty = not known
        LeaseRoute route;      // the grant's own renew token travels in it (a lease has one token for its whole life)
        qint64 deadlineMs = 0; // the lease's own TTL from now: after it the server has freed the seat anyway
        int tries = 0;         // sends of this release over a later route (row S2)
        RelState state = RelState::Out;
        quint64 requestId = 0; // Out: the id the client knows it by
        const UpstreamMeter &meter() const { return m_meter; } // seq < 1: no report (upstreamReleaseBody sends none)
        bool hasReport() const { return m_meter.seq >= 1; }
        // The only way a report changes: attached when there is none. true = this call brought the entry its report.
        bool absorbReport(const UpstreamMeter &m)
        {
            if (hasReport() || m.seq < 1)
                return false;
            m_meter = m;
            return true;
        }
    private:
        UpstreamMeter m_meter;
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
    void noteAcquireRoute(quint64 requestId, bool viaTunnel)
    {
        if (m_acquireViaTunnel.size() > 256)
            m_acquireViaTunnel.clear();
        m_acquireViaTunnel.insert(requestId, viaTunnel);
    }
    void noteAcquireNonce(quint64 requestId, const QString &nonce)
    {
        if (m_acquireNonce.size() > 256)
            m_acquireNonce.clear();
        m_acquireNonce.insert(requestId, nonce);
    }
    // The request belongs to the live session's own start: its grant is the session's seat (a late answer of the same start).
    bool ownStart(quint64 acquireId) const
    {
        const auto n = m_acquireNonce.constFind(acquireId);
        return m_active && !m_nonce.isEmpty() && n != m_acquireNonce.constEnd() && n.value() == m_nonce;
    }
    // Registers a release as Out under `requestId` (0: the caller sends it itself through sendOut). ONE entry per lease id: an
    // insert for a lease that already has one MERGES into it - the entry keeps (or gains) the report, and when it is already out
    // (on the wire, being resent, or held for the stop) and gains nothing, nothing more is sent (false). When the insert brings the
    // entry a report it lacked, or the entry waits (unsent, deferred), the insert takes the chain over under its request id (the
    // old chain's resends stop: releaseWanted finds no such request) and the caller sends (true).
    bool registerRelease(const QString &profileId, const QString &leaseId, const LeaseRoute &route, quint64 requestId,
                         const UpstreamMeter &meter, const QString &nonce = QString())
    {
        const auto it = m_releases.find(leaseId);
        if (it == m_releases.end()) {
            m_releases.insert(leaseId, PendingRelease(profileId, leaseId, nonce, route, meter, m_lastNowMs + leaseTtlMs(), requestId));
            return true;
        }
        PendingRelease &e = it.value();
        const bool gained = e.absorbReport(meter);
        if (e.state == RelState::Out && !gained)
            return false;
        e.state = RelState::Out;
        e.requestId = requestId;
        return true;
    }
    // A late grant of a lease nobody can release yet: kept in the ledger as Deferred (judgeDeferred decides). An entry that is
    // already out is left alone.
    void deferRelease(const QString &profileId, const QString &leaseId, const LeaseRoute &route, const QString &nonce)
    {
        if (registerRelease(profileId, leaseId, route, 0, UpstreamMeter{}, nonce))
            m_releases[leaseId].state = RelState::Deferred;
    }
    // The releases of a machine step, registered (the machine's own report goes into the entry). The request ids of those that
    // merged into an entry already out are returned: they are not sent.
    QSet<quint64> registerReleasesOf(const LeaseStep &s)
    {
        QSet<quint64> merged;
        for (const LeaseAction &a : s.actions)
            if (a.kind == LeaseActionKind::SendRelease && !registerRelease(a.profileId, a.leaseId, a.route, a.requestId, a.meter))
                merged.insert(a.requestId);
        return merged;
    }
    // Sends the pending release (a new request id, the route given - its own token inside; the report is the entry's).
    void sendOut(PendingRelease &p, const LeaseRoute &route, bool via = false)
    {
        p.state = RelState::Out;
        p.requestId = (quint64(1) << 62) | ++m_ownSerial;
        if (!m_io)
            return;
        if (via)
            m_io->releaseVia(p.requestId, p.leaseId, p.meter(), route);
        else
            m_io->release(p.requestId, p.leaseId, p.meter(), route);
    }

    // A release of this owner outside the machine's own actions: registered first, then sent (the request id is in
    // the high range so it never meets the machine's counter).
    void releaseThroughLedger(const QString &profileId, const QString &leaseId, const LeaseRoute &route, const QString &nonce)
    {
        if (!m_io || !registerRelease(profileId, leaseId, route, 0, UpstreamMeter{}, nonce))
            return;
        sendOut(m_releases[leaseId], route);
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
        judgeDeferred(m_profileId);
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
    quint64 m_ownSerial = 0;
    QHash<QString, PendingRelease> m_releases; // ONE pending release per lease id (Out / Unsent / Deferred); it owns the final report
    QHash<quint64, QString> m_acquireNonce;    // acquire request id -> the nonce (start) that sent it
    QString m_nonce;                           // the session nonce of the current start (resetSession)
    qint64 m_sessionOrder = -1;                // its order: strictly increasing across starts, persisted (m_order)
    UpstreamSessionOrder m_order;
    static constexpr int kUnsentMaxSends = 3;
    qint64 m_lastNowMs = 0;       // the owner's last clock reading (a deadline for a release made without one)
    QHash<quint64, bool> m_acquireViaTunnel;   // acquire request id -> sent through the tunnel (the route its answer proves)
    QString m_provisionalBase; // the standby pack entry's tunnel_api_base of the running provisional session
    bool m_prepareOnly = false; // prepare(): a seat taken before the switch, not brought up yet
    bool m_prepared = false;    // ... and granted (Prepared was reported)
    qint64 m_lastRx = 0, m_lastTx = 0;
    qint64 m_renewedAtMs = -1, m_wakeAtMs = -1;
    qint64 m_appliedTotal = 0, m_shadowTotal = 0;
};

} // namespace avpn
