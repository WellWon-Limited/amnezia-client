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
// Never logs: lease ids, tokens, configs, hosts - events carry codes only.
//
// Upstream Amnezia has no counterpart. Tests: tests/upstream_engine_check.cpp.
#pragma once

#include "UpstreamEngine.h"
#include "UpstreamLeaseMachine.h"

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
};

struct UpstreamOwnerEvent {
    UpstreamOwnerEventKind kind = UpstreamOwnerEventKind::BringUp;
    QString code;
    QString detail;          // Leave / StartFailed: the server's optional reason (switch log only)
    bool provisional = false;
    QByteArray config;       // BringUp: the profile config (secret)
    QString configSha256;    // BringUp
    QJsonObject lease;       // BringUp (absent on provisional) / HandOver: upstream_lease
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
        QVector<UpstreamOwnerEvent> ev;
        ev << endSession(nowMs); // a previous session (should already be released by down())
        if (!stub.upstream.has_value())
            return ev;
        resetSession();
        m_nodeId = stub.nodeId;
        m_profileId = stub.upstream->profileId;
        m_stubSha = stub.upstream->configSha256;
        m_standby = standby;
        m_wallAtStart = nowWallMs;
        m_monoAtStart = nowMs;
        m_active = true;
        m_bringUp = true;
        apply(m_machine.start(m_profileId, LeaseKind::Session, machineScope(), knownRevision, nowMs), nowMs, ev);
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
        apply(m_machine.onAcquireReply(requestId, r, nowMs), nowMs, ev);
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
        m_active = m_bringUp = m_tunnelIsUp = m_handedOver = m_adopted = m_rebasePending = false;
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
        if (ownsRenewals()) {
            const LeaseStep s = m_machine.disconnect(nowMs);
            m_releaseSent = s.has(LeaseActionKind::SendRelease);
            if (m_io)
                dispatchLeaseIo(s, *m_io);
        }
        // A handed-over lease belongs to the extension: nothing is sent from here.
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
            if (a.kind == LeaseActionKind::SendRelease)
                m_releaseSent = true;
        }
        QVector<LeaseAction> rest;
        if (m_io)
            rest = dispatchLeaseIo(s, *m_io);
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
                UpstreamOwnerEvent b;
                b.kind = UpstreamOwnerEventKind::BringUp;
                b.provisional = a.provisional;
                if (a.provisional && m_standby) {
                    b.config = m_standby->config;
                    b.configSha256 = m_standby->configSha256;
                } else {
                    b.config = m_grant.config;
                    b.configSha256 = m_grant.configSha256;
                    b.lease = leaseJson(nowMs);
                    if (!m_opt.keepOwnership)
                        m_handedOver = true; // the lease travels in the envelope: the extension owns it
                }
                ev << b;
                if (!a.provisional && m_opt.keepOwnership)
                    ev << persistEvent(nowMs, 0);
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

    void failStart(QVector<UpstreamOwnerEvent> &ev, const QString &code, const QString &detail = QString())
    {
        UpstreamOwnerEvent f;
        f.kind = UpstreamOwnerEventKind::StartFailed;
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
    bool m_active = false, m_bringUp = false, m_tunnelIsUp = false, m_handedOver = false, m_adopted = false;
    bool m_rebasePending = false, m_releaseSent = false, m_configChanged = false, m_haveBytes = false;
    qint64 m_lastRx = 0, m_lastTx = 0;
    qint64 m_renewedAtMs = -1, m_wakeAtMs = -1;
    qint64 m_appliedTotal = 0, m_shadowTotal = 0;
};

} // namespace avpn
