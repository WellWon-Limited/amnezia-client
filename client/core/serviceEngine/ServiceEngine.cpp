#include "ServiceEngine.h"
#include "ConnectTunables.h" // AVPN (BUG-4 auto-heal): rebindHealMaxTriesTuned — кламп кап попыток; xray-пороги
#include "NodeRotation.h" // AVPN: healthAggregate/isRuNode/nextLiveNodeId (чистая логика, тестируется автономно)
#include "SubscriptionParser.h"
#include "TransportPick.h" // AVPN awg31-xray-v1: locations x transports, exit RTT for the bars
#include "UpstreamLeaseWire.h" // R1: the server's refusal codes (startFailureOutcome)
#include "path/PathId.h"

#include <QDateTime>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QDebug>
#include <QTimeZone>
#include <algorithm>

// [IN-FORK] токен/хранилище для startFlow:
#include "core/repositories/secureAppSettingsRepository.h"

namespace avpn {

// AVPN (live-node picker): healthAggregate (агрегат backend-health, пустой = живой) и isRuNode
// (RU — только ручной pin, вне любого авто-выбора) переехали в NodeRotation.h — общие для
// pick*/ротации и покрыты автономным тестом tests/node_rotation_check.cpp. См. spec §13-14, §14.3.

// AVPN (RU-нода): закреплена ли сейчас РФ-нода. Используется для гейта RU-direct-сплита (T2).
bool ServiceEngine::pinnedNodeIsRu() const
{
    if (m_pinnedNodeId.isEmpty())
        return false;
    for (const SubscriptionNode &n : m_pool.nodes())
        if (n.nodeId == m_pinnedNodeId)
            return isRuNode(n);
    return false;
}

const SubscriptionNode *ServiceEngine::findNode(const QString &nodeId) const
{
    if (nodeId.isEmpty())
        return nullptr;
    for (const SubscriptionNode &n : m_merged)
        if (n.nodeId == nodeId)
            return &n;
    return nullptr;
}

bool ServiceEngine::anySupportedNode() const
{
    for (const SubscriptionNode &n : m_merged)
        if (isSupportedProtoNode(n) && healthAggregate(n) > 0.0)
            return true;
    return false;
}

QString ServiceEngine::currentNodeProto() const
{
    const SubscriptionNode *n = findNode(m_currentNodeId);
    return n ? protoOf(*n) : QString();
}

QString ServiceEngine::currentLocation() const
{
    const SubscriptionNode *n = findNode(m_currentNodeId);
    return n ? locationKeyOf(*n) : QString();
}

QString ServiceEngine::pinnedLocation() const
{
    const SubscriptionNode *n = findNode(m_pinnedNodeId);
    return n ? locationKeyOf(*n) : QString();
}

void ServiceEngine::appendSwitchLog(const QString &lineIn)
{
    // AVPN (фикс-волна 2026-09-22, GAP-3 / U10): метка времени UTC (ISO, мс, часы движка nowMs())
    // и дубль в Qt-лог с префиксом [avpn switch] — причины свитчей/failover попадают в лог-файл и в
    // хвост лога краш-/диаг-отчёта (кольцо switchLog всего 20 строк и без времени жалобу не разобрать).
    const QString line = QDateTime::fromMSecsSinceEpoch(nowMs(), QTimeZone::UTC).toString(Qt::ISODateWithMs)
                       + QLatin1Char(' ') + lineIn;
    qInfo().noquote() << "[avpn switch]" << line;
    m_switchLog.append(line);
    if (m_switchLog.size() > 20)
        m_switchLog.removeFirst();
}

qint64 ServiceEngine::nowMs() const
{
    return m_nowMsFn ? m_nowMsFn() : QDateTime::currentMSecsSinceEpoch();
}

// --- AVPN (фикс-волна 2026-09-22, B9): кэш RTT с возрастом замера на КАЖДУЮ ноду -------------------

void ServiceEngine::setMeasuredRtt(const QHash<QString, int> &rtt)
{
    const qint64 now = nowMs();
    QHash<QString, RttSample> fresh;
    for (auto it = rtt.constBegin(); it != rtt.constEnd(); ++it) {
        if (it.value() >= 0) {
            fresh.insert(it.key(), RttSample{it.value(), now});
            m_rttLastKnown.insert(it.key(), RttSample{it.value(), now});
        } else if (m_rttFresh.contains(it.key())) {
            // «нет ответа в этом раунде» не затирает замер моложе TTL (один потерянный пакет не
            // должен выкидывать ноду из ранжирования — корень «US вместо EE»).
            const RttSample prev = m_rttFresh.value(it.key());
            if (prev.ms >= 0 && now - prev.atMs <= kRttTtlMs)
                fresh.insert(it.key(), prev);
        }
    }
    m_rttFresh = fresh;
    m_rttSetAtMs = now;
}

void ServiceEngine::mergeMeasuredRtt(const QHash<QString, int> &rtt)
{
    const qint64 now = nowMs();
    for (auto it = rtt.constBegin(); it != rtt.constEnd(); ++it) {
        if (it.value() < 0)
            continue; // нет ответа — прошлый замер живёт до своего TTL
        m_rttFresh.insert(it.key(), RttSample{it.value(), now});
        m_rttLastKnown.insert(it.key(), RttSample{it.value(), now});
    }
    m_rttSetAtMs = now;
}

qint64 ServiceEngine::measuredRttAgeMs() const
{
    return m_rttSetAtMs < 0 ? -1 : qMax<qint64>(0, nowMs() - m_rttSetAtMs);
}

QHash<QString, int> ServiceEngine::measuredRtt() const
{
    const qint64 now = nowMs();
    QHash<QString, int> out;
    for (auto it = m_rttFresh.constBegin(); it != m_rttFresh.constEnd(); ++it)
        if (it.value().ms >= 0 && now - it.value().atMs <= kRttTtlMs)
            out.insert(it.key(), it.value().ms);
    return out;
}

QHash<QString, int> ServiceEngine::lastKnownRtt() const
{
    QHash<QString, int> out;
    for (auto it = m_rttLastKnown.constBegin(); it != m_rttLastKnown.constEnd(); ++it)
        if (it.value().ms >= 0)
            out.insert(it.key(), it.value().ms);
    return out;
}

qint64 ServiceEngine::lastKnownRttAgeMs(const QString &nodeId) const
{
    if (!m_rttLastKnown.contains(nodeId))
        return -1;
    return qMax<qint64>(0, nowMs() - m_rttLastKnown.value(nodeId).atMs);
}

QHash<QString, int> ServiceEngine::rankingRtt(const QHash<QString, int> &raw) const
{
    return avpn::rankingRtt(m_pool.nodes(), raw, xrayExitRttPenaltyMsTuned());
}

QHash<QString, int> ServiceEngine::exitRtt(const QHash<QString, int> &raw) const
{
    return avpn::exitRtt(m_pool.nodes(), raw);
}

void ServiceEngine::rebuildCandidates()
{
    m_merged = m_pool.nodes();
    for (const SubscriptionNode &n : m_packCandidates) {
        bool dup = false;
        for (const SubscriptionNode &p : m_pool.nodes())
            if (p.nodeId == n.nodeId)
                dup = true;
        if (!dup)
            m_merged << n;
    }
}

int ServiceEngine::offerScanNodes(const QJsonArray &nodes)
{
    const qint64 rev = upstreamRevision();
    if (rev != m_scanOfferedRevision) {
        m_scanOffered.clear();
        m_scanOfferedRevision = rev;
    }
    if (rev <= 0 || nodes.isEmpty())
        return int(m_scanOffered.size());
    // The subscription's own parser, with the revision in force: the same validation as a delivered stub.
    const QJsonObject body{ { QStringLiteral("version"), 1 }, { QStringLiteral("upstream_revision"), double(rev) },
                            { QStringLiteral("nodes"), nodes } };
    Subscription parsed;
    QString err;
    if (!SubscriptionParser::parse(QJsonDocument(body).toJson(QJsonDocument::Compact), parsed, err))
        return int(m_scanOffered.size());
    for (SubscriptionNode n : parsed.nodes) {
        if (!isUpstreamNode(n))
            continue; // only provider stubs: our own nodes come with the subscription
        bool delivered = false;
        for (const SubscriptionNode &p : m_pool.nodes())
            delivered = delivered || p.nodeId == n.nodeId;
        if (delivered)
            continue;
        n.upstream->scanOffered = true;
        for (int i = int(m_scanOffered.size()) - 1; i >= 0; --i)
            if (m_scanOffered.at(i).nodeId == n.nodeId)
                m_scanOffered.removeAt(i);
        m_scanOffered << n;
    }
    while (m_scanOffered.size() > kMaxScanOffered)
        m_scanOffered.removeFirst();
    return int(m_scanOffered.size());
}

QList<SubscriptionNode> ServiceEngine::scanOfferedNodes()
{
    if (upstreamRevision() != m_scanOfferedRevision) {
        m_scanOffered.clear();
        m_scanOfferedRevision = upstreamRevision();
    }
    return m_scanOffered;
}

void ServiceEngine::setStandbyCandidates(const QList<SubscriptionNode> &nodes)
{
    // The node the session runs on keeps its record while it runs (identity for health and leave).
    QList<SubscriptionNode> next = nodes;
    for (const SubscriptionNode &old : m_packCandidates) {
        if (old.nodeId != m_currentNodeId)
            continue;
        bool kept = false;
        for (const SubscriptionNode &n : next)
            kept = kept || n.nodeId == old.nodeId;
        if (!kept)
            next << old;
    }
    m_packCandidates = next;
    rebuildCandidates();
}

bool ServiceEngine::currentNodeIsUpstream() const
{
    const SubscriptionNode *n = findNode(m_currentNodeId);
    return n && isUpstreamNode(*n);
}

bool ServiceEngine::leaveUpstreamNode(const QString &code, const QString &detail)
{
    if (m_state != EngineState::Connected && m_state != EngineState::Verifying)
        return false;
    if (!currentNodeIsUpstream())
        return false;
    appendSwitchLog(QStringLiteral("upstream lease %1%2 on %3: leaving the node")
                        .arg(code, detail.isEmpty() ? QString() : QStringLiteral(" (%1)").arg(detail), m_currentNodeId));
    // R1: only the server's own refusal is the path's outcome (a lease that could not be confirmed is not)
    loseLiveSession(startFailureOutcome(code), /*tunnelGone=*/false, /*restart=*/true,
                    QStringLiteral("upstream lease %1").arg(code));
    return true;
}

void ServiceEngine::noteStartRefused(const QString &nodeId, const QString &code)
{
    if (nodeId.isEmpty() || m_owner.phase() != path::AttemptPhase::Starting || m_owner.currentPath().id.id != nodeId)
        return;
    const path::PathOutcome o = startFailureOutcome(code);
    appendSwitchLog(QStringLiteral("upstream start refused on %1 code=%2 outcome=%3")
                        .arg(nodeId, code, QLatin1String(path::pathOutcomeName(o))));
    // Inconclusive: the leg ends and the attempt walks on, nothing is recorded against the path.
    feedOwner(path::AttemptEvent::pathFailed(nowMs(), m_owner.currentLeg(), o));
}

// R1 (device round 4): only the server's own answer about this profile is the path's outcome. A transport failure
// or timeout of OUR control plane (the lease request), a retry-later answer (429, 503), a request our server
// rejected as malformed and every local failure (envelope, bridge, invoke) say nothing about the path.
// Lane C (C4, checked): a lease `transport` failure (no answer from the direct API) falls to the default below -
// Inconclusive: no evidence about the path. With the control plane unreachable C1 no longer attempts those paths at
// all; one that still fails this way (state Unknown) stays evidence-free (covered: path_integration_check).
path::PathOutcome ServiceEngine::startFailureOutcome(const QString &codeIn)
{
    const QString code = codeIn.section(QLatin1Char('/'), 0, 0);
    switch (upstreamErrorCodeFrom(code)) {
    case UpstreamErrorCode::NoSeat: return path::PathOutcome::NoSeat;
    case UpstreamErrorCode::Disabled:
    case UpstreamErrorCode::NotEntitled:
    case UpstreamErrorCode::OverQuota: return path::PathOutcome::Refused;
    default: break;
    }
    return path::PathOutcome::Inconclusive;
}

void ServiceEngine::markUpStarted()
{
    m_upStartedMs = nowMs(); // 5.1.109: the engine clock (tests) - QDateTime in the app
    m_probeFailStreak = 0;
}

// ---- Path engine, stage 1 (design 2026-11-17) ----------------------------------------------------------------

path::AttemptTimings ServiceEngine::attemptTimings() const
{
    return m_timingsForTest ? *m_timingsForTest : attemptTimingsTuned();
}

QList<path::PathCandidate> ServiceEngine::pathPool() const
{
    // Kill switch transport_auto_pick=false (as before this design): Xray paths are not offered to an automatic
    // choice; a person's exact choice still reaches them.
    const bool autoXray = TuningStore::flag(QStringLiteral("transport_auto_pick"), true)
                       || m_choice.kind == path::UserChoice::Kind::ExactPath;
    QList<path::PathCandidate> out;
    for (const SubscriptionNode &n : m_merged) {
        if (!isSupportedProtoNode(n) || healthAggregate(n) <= 0.0)
            continue;
        if (!autoXray && isXrayProto(protoOf(n)))
            continue;
        // Contract 1.14.0: a scan-offered profile is a path only when the person chose it (exact row or preferred
        // server); Auto keeps to the delivered stubs.
        if (n.upstream.has_value() && n.upstream->scanOffered && !m_choice.pathIds.contains(n.nodeId))
            continue;
        path::PathCandidate c = path::pathCandidateFromNode(n);
        if (c.kind == path::PathKind::Provider && !c.standbyEntry && m_hasStandbyEntry)
            c.standbyEntry = m_hasStandbyEntry(n); // lane C: a usable pack entry lets the profile start without the API
        out << c;
    }
    return out;
}

path::SelectionContext ServiceEngine::ownerContext() const
{
    path::SelectionContext c;
    c.pool = pathPool();
    c.ledger = &m_ledger;
    c.wallNowMs = nowMs();
    c.controlPlane = controlPlane();
    // Lane C (C3): a cellular network with no proof whose direct control plane is unreachable - the servers built for
    // restricted networks (white-list provider profiles that start from the standby pack) lead. Through the crowd
    // prior; any evidence of this network outranks it (PathSelect.h::restrictedNetworkPrior).
    c.crowd = path::restrictedNetworkPrior(c.pool, m_ledger.viewOf(m_net.current().local, c.pool, c.wallNowMs),
                                           c.controlPlane, m_net.current().cellular());
    // Paths whose probe failed in the race of this tap: the worst prior for this attempt, so the walk tries the
    // servers the race has not seen fail first (device round 19.11, LTE: the race saw three first candidates fail,
    // proved nothing, and the walk then spent 6 s on each of the same three).
    for (const QString &id : m_raceFailed)
        c.crowd.insert(id, 0.0);
    // Paths the race is probing right now: the walk prefers a candidate nobody is probing. Raising a path whose probe
    // is in flight cancels that probe, and the host can only stop its whole scan - every other probe starts again
    // from zero (device round 19.11, LTE: the blind leg at 2.8 s and the next one 3 s later each reset the scan, the
    // race ended with nothing proven although a working server was being probed). An answer moves the path where it
    // belongs: proven -> working (it leads), failed -> m_raceFailed.
    if (m_race.running())
        for (const QString &id : m_race.inFlightPathIds())
            c.crowd.insert(id, 0.0);
    return c;
}

void ServiceEngine::attemptJournal(const QString &line)
{
    appendSwitchLog(line);
    m_attemptJournal << line;
    if (m_attemptJournal.size() > 64)
        m_attemptJournal.removeFirst();
}

// Every event to the owner goes through here; effects may produce events (a start refused synchronously), which
// are queued and handled after the current batch - never re-entrantly.
void ServiceEngine::feedOwner(const path::AttemptEvent &ev)
{
    m_ownerQueue << ev;
    if (m_inOwner)
        return;
    m_inOwner = true;
    while (!m_ownerQueue.isEmpty()) {
        const path::AttemptEvent e = m_ownerQueue.takeFirst();
        const QList<path::AttemptEffect> effects = m_owner.handle(e, ownerContext());
        for (quint64 a = m_stampedAttempt + 1; a <= m_owner.attempt(); ++a) {
            m_attemptEpochs.insert(a, m_intentEpoch); // H3: an attempt begun by this event serves the intent in force
            m_attemptModes.insert(a, int(transportMode())); // K1: ... and began under the mode in force now
        }
        m_stampedAttempt = qMax(m_stampedAttempt, m_owner.attempt());
        applyOwnerEffects(effects);
    }
    m_inOwner = false;
    if (std::exchange(m_ownerQueueRaceStop, false))
        applyRaceEffects(m_race.stop(nowMs()));
}

void ServiceEngine::applyOwnerEffects(const QList<path::AttemptEffect> &effects)
{
    for (const path::AttemptEffect &e : effects) {
        switch (e.type) {
        case path::EffectType::StartPath: {
            const SubscriptionNode *n = findNode(e.path.id.id);
            // pick=proof: the path a race proof named (AttemptOwner.h "Lead"); pick=order: the head of the order
            attemptJournal(QStringLiteral("attempt_leg attempt=%1 net_gen=%2 leg=%3 node=%4 kind=%5 timeout_ms=%6 "
                                          "checked=%7/%8 pick=%9")
                               .arg(e.stamp.attempt).arg(e.stamp.network).arg(e.stamp.leg).arg(e.path.id.id)
                               .arg(QLatin1String(path::pathKindName(e.path.kind))).arg(e.timeoutMs)
                               .arg(m_owner.progressDone()).arg(m_owner.progressTotal())
                               .arg(e.lead ? QStringLiteral("proof") : QStringLiteral("order")));
            // the leg's own path leaves the race before its tunnel starts (CONNECT-INVARIANTS §32 p. 3)
            m_raisedPaths.insert(e.path.id.id); // also while the race still waits for its session
            if (m_race.running())
                applyRaceEffects(m_race.legStarted(nowMs(), e.path.id.id));
            m_state = EngineState::Connecting;
            if (m_currentNodeId != e.path.id.id)
                resetHealSession(e.path.id.id);
            m_currentNodeId = e.path.id.id;
            m_sessionHintNodeId.clear();
            m_sessionHintProto.clear();
            m_sessionHintEndpoint.clear();
            markUpStarted();
            m_health.reset();
            if (n && m_tunnel)
                m_tunnel->beginNativeOp(e.stamp.leg); // review E2: the leg travels through the native stream
            const TunnelResult r = (n && m_tunnel) ? m_tunnel->up(m_pool.subscription(), *n)
                                                   : TunnelResult::fail(QStringLiteral("node not in the pool"));
            if (!r.ok) {
                appendSwitchLog(QStringLiteral("start of %1 failed: %2").arg(e.path.id.id, r.error));
                m_ownerQueue << path::AttemptEvent::pathFailed(nowMs(), e.stamp, path::PathOutcome::Inconclusive,
                                                               /*tunnelGone=*/true);
            }
            break;
        }
        case path::EffectType::RunDataCheck:
            m_state = EngineState::Verifying; // the facade runs the one data check through the raised tunnel
            m_health.reset();
            m_checkStarved = false;
            if (e.recheck) {
                // the previous check is void (it spanned a suspension, or could not decide): the facade runs it
                // again on the same tunnel; nothing was recorded for it
                m_checkRerun = true;
                attemptJournal(QStringLiteral("attempt_recheck leg=%1 node=%2").arg(e.stamp.leg).arg(e.path.id.id));
            }
            break;
        case path::EffectType::StopPath:
            m_rebindAwaiting = false;
            m_health.reset();
            if (m_facadeStop)
                break; // the facade takes the tunnel down itself (its stop protocol) - the phase is its own
            m_state = EngineState::Switching;
            if (m_tunnel)
                m_tunnel->down();
            break;
        case path::EffectType::Report: {
            // S3: evidence about a path is only for something really sent to it. A provider leg whose own bookkeeping
            // (or a local refusal) kept the lease request and the native start from ever leaving says nothing.
            path::PathOutcome outcome = e.report.outcome;
            const SubscriptionNode *reported = findNode(e.report.path.id);
            if (outcome == path::PathOutcome::NoHandshake && reported && isUpstreamNode(*reported) && m_tunnel
                && !m_tunnel->upstreamRequestSent()) {
                outcome = path::PathOutcome::Inconclusive;
                attemptJournal(QStringLiteral("leg_nothing_sent node=%1 (no lease request and no tunnel start went out - no evidence about the path)")
                                   .arg(e.report.path.id));
            }
            if (outcome == path::PathOutcome::NoHandshake)
                ++m_legStartFailures;
            if (reported && m_net.isCurrent(e.report.networkGeneration)
                && m_ledger.record(e.report.network, e.report.path, outcome, nowMs(), e.report.connectMs,
                                   e.report.ttfbMs))
                m_ledgerDirty = true;
            attemptJournal(QStringLiteral("path_outcome net=%1 net_gen=%2 node=%3 rev=%4 outcome=%5 connect_ms=%6 ttfb_ms=%7 state=%8")
                               .arg(e.report.network).arg(e.report.networkGeneration).arg(e.report.path.id,
                                    e.report.path.revision, QLatin1String(path::pathOutcomeName(outcome)))
                               .arg(e.report.connectMs).arg(e.report.ttfbMs)
                               .arg(QLatin1String(path::pathStateName(
                                   m_ledger.view(e.report.network, e.report.path, nowMs()).state))));
            break;
        }
        case path::EffectType::Yield:
            attemptJournal(e.phase == path::AttemptPhase::Starting
                               ? QStringLiteral("leg_preempted_for_proof node=%1 to=%2 phase=starting (raised blind, not up)")
                                     .arg(e.path.id.id, e.toPath)
                               : QStringLiteral("leg_preempted_for_proof node=%1 to=%2 (no first byte, a proven path waits)")
                                     .arg(e.path.id.id, e.toPath));
            m_checkStarved = false;
            break;
        case path::EffectType::StopUnconfirmed:
            attemptJournal(QStringLiteral("attempt_stop_unconfirmed leg=%1 node=%2 (platform, not recorded)")
                               .arg(e.stamp.leg).arg(e.path.id.id));
            m_facadeStop = false;
            break;
        case path::EffectType::Show:
            if (e.phase == path::AttemptPhase::Idle)
                m_facadeStop = false;
            break;
        case path::EffectType::Finish: {
            const path::AttemptResult &r = e.result;
            attemptJournal(QStringLiteral("attempt_result attempt=%1 net_gen=%2 result=%3 reason=%4 node=%5 paths=%6 ms=%7 fallback=%8")
                               .arg(r.attempt).arg(m_net.current().generation)
                               .arg(r.connected ? QStringLiteral("connected") : QStringLiteral("failed"))
                               .arg(QLatin1String(path::failReasonName(r.reason)))
                               .arg(r.connected ? r.path.id.id : QStringLiteral("-"))
                               .arg(r.paths).arg(r.elapsedMs).arg(int(r.fallbackNotice)));
            m_lastResult = r;
            m_lastResult->intentEpoch = m_attemptEpochs.value(r.attempt, m_intentEpoch);
            m_attemptEpochs.remove(r.attempt);
            m_lastResult->startMode = m_attemptModes.value(r.attempt, -1);
            m_attemptModes.remove(r.attempt);
            if (!r.connected && m_tunnel)
                m_tunnel->startRefused(); // an attempt that ends before Connected holds no seat (G2): idempotent, no StopPath needed
            m_raceWait.reset(); // a race still waiting for its session is not needed any more
            if (m_race.running()) // the attempt has its result: the spares are not needed any more
                m_ownerQueueRaceStop = true;
            if (r.connected) {
                m_state = EngineState::Connected;
                if (findNode(r.path.id.id)) // an adopted session of an unknown node keeps its identity unknown
                    m_currentNodeId = r.path.id.id;
                m_health.reset();
                m_probeFailStreak = 0;
            } else if (r.reason == path::FailReason::StoppedByUser) {
                // the person stopped or replaced it - what happens next is theirs (requestStop / a new attempt)
            } else {
                m_state = EngineState::Error;
                m_currentNodeId.clear();
            }
            break;
        }
        }
        if (e.type != path::EffectType::StopPath && m_owner.phase() != path::AttemptPhase::Stopping)
            m_facadeStop = false;
    }
}

void ServiceEngine::observeNetwork(const path::NetworkObservation &o)
{
    if (!m_net.observe(o))
        return;
    attemptJournal(QStringLiteral("network key=%1 coarse=%2 net_gen=%3")
                       .arg(m_net.current().local.isEmpty() ? QStringLiteral("-") : m_net.current().local,
                            m_net.current().coarse.isEmpty() ? QStringLiteral("-") : m_net.current().coarse)
                       .arg(m_net.current().generation));
    if (m_race.running())
        applyRaceEffects(m_race.networkChanged(nowMs(), m_net.current()));
    if (m_raceWait)
        endRaceWait("network_changed"); // its session was asked for the old network
    prepareProber(); // the host warms up for the new network (caps, probe session)
    feedOwner(path::AttemptEvent::networkChanged(nowMs(), m_net.current()));
}

void ServiceEngine::attemptTick()
{
    m_owner.setTimings(attemptTimings());
    if (m_raceWait)
        pollRaceWait();
    if (m_race.running())
        applyRaceEffects(m_race.tick(nowMs()));
    feedOwner(path::AttemptEvent::tick(nowMs()));
}

// ---- Stage 2: the probe race (path/PathRace.h) ------------------------------------------------------------------

// The server switch of the race, one per platform family: the race was measured on iPhone only (rounds 17-19.11), so
// a desktop build turns it on by its own switch, after its own device round.
QString ServiceEngine::raceFlagKey()
{
#if defined(Q_OS_IOS)
    return QStringLiteral("path_race");
#else
    return QStringLiteral("path_race_desktop");
#endif
}

bool ServiceEngine::raceAllowed() const
{
    return m_prober && m_prober->caps().available && TuningStore::flag(raceFlagKey(), false)
        && m_choice.kind != path::UserChoice::Kind::ExactPath; // an exact node is the person's: nothing to race
}

void ServiceEngine::prepareProber()
{
    if (m_prober && m_net.current().usable() && controlPlane() != ApiReach::Unreachable)
        m_prober->prepare(m_net.current());
}

// Lane C (C1): the paths the choice leaves out because they cannot start on this network - one journal line per
// attempt with the count and the reason, never a path outcome. They return by themselves when the control plane answers.
void ServiceEngine::journalControlPlaneSkips()
{
    if (controlPlane() != ApiReach::Unreachable || m_choice.kind == path::UserChoice::Kind::ExactPath)
        return;
    int skipped = 0;
    for (const path::PathCandidate &c : pathPool())
        if (path::needsControlPlane(c) && path::modeAllows(c.kind, transportMode()))
            ++skipped;
    if (skipped > 0)
        attemptJournal(QStringLiteral("paths_skipped reason=no_control count=%1").arg(skipped));
}

void ServiceEngine::beginRaceForTap()
{
    m_raceFailed.clear(); // per tap
    m_raceWait.reset(); // a race of an older tap never begins under this one
    m_raisedPaths.clear();
    prepareProber(); // idempotent: a fresh session is kept (not asked for while the control plane is unreachable)
    m_race.setTimings(m_raceTimingsForTest ? *m_raceTimingsForTest : raceTimingsTuned());
    const path::SelectionContext ctx = ownerContext();
    path::SelectInput in;
    in.pool = ctx.pool;
    in.evidence = m_ledger.viewOf(m_net.current().local, ctx.pool, ctx.wallNowMs);
    in.choice = m_choice;
    in.mode = transportMode();
    in.controlPlane = ctx.controlPlane;
    in.crowd = ctx.crowd;
    const QList<path::RankedPath> order = path::selectPaths(in);
    if (order.isEmpty())
        return; // the owner reports "no candidate" itself
    // (a) a path proven on this network leads: it starts at once, the race runs over the rest beside it - and when it
    // carried data here recently there is no race at all (B3c: the race only where nothing works or it just failed)
    const bool known = order.first().view.state == path::PathState::Working;
    const path::RaceTimings rt = m_race.timings();
    if (known && order.first().view.strength == path::EvidenceStrength::Data
        && nowMs() - order.first().view.lastSuccessMs <= qint64(rt.knownFreshMin) * 60000) {
        attemptJournal(QStringLiteral("race_skipped known=%1 fresh").arg(order.first().path.id.id));
        return;
    }
    QList<path::PathCandidate> race;
    for (int i = known ? 1 : 0; i < order.size(); ++i)
        race << order.at(i).path;
    race = path::raceSpread(race); // one of each kind before the second of any: the byte cap covers different kinds
    qint64 bytesLeft = m_probeBytesLeft ? m_probeBytesLeft() : -1;
    // B3d: on cellular one race spends at most cellularMaxBytes (the Scanner's hour budget stays its own)
    if (m_net.current().cellular())
        bytesLeft = bytesLeft < 0 ? rt.cellularMaxBytes : std::min<qint64>(bytesLeft, rt.cellularMaxBytes);
    m_raceFirst = !known;
    const path::ProberCaps pc = m_prober->caps();
    const bool noControl = controlPlane() == ApiReach::Unreachable;
    if (!pc.ready) {
        // Lane C (C2): the race's session (GET /v1/scan/manifest) comes over the direct API; with that unreachable on
        // this network it cannot come - the owner starts at once, no wait, no manifest bytes (device round 10: 3.0 s
        // of wait and 34 KB of the cellular cap per tap).
        if (noControl) {
            attemptJournal(QStringLiteral("race_done reason=no_control proven=0 waited_ms=0"));
            m_raceFirst = false; // the owner walks at once
            return;
        }
        // Device round 19.11 (LTE, right after launch): the session was not there, four probes "started" that never
        // left the app, 386 KB of the 393 KB cap were reserved for them and the owner walked blind. A probe that
        // cannot leave is not started: the race waits for the session within its own wait, or does not run.
        if (!pc.preparing) {
            attemptJournal(QStringLiteral("race_done reason=no_session proven=0 waited_ms=0"));
            m_raceFirst = false; // the owner walks at once
            return;
        }
        RaceWait w;
        w.race = race;
        w.bytesLeft = bytesLeft;
        w.sinceMs = nowMs();
        w.boundMs = rt.hedgeAfterMs();
        w.knownId = known ? order.first().path.id.id : QString();
        m_raceWait = w;
        attemptJournal(QStringLiteral("race_wait_session known=%1 candidates=%2 bound_ms=%3")
                           .arg(known ? order.first().path.id.id : QStringLiteral("-")).arg(race.size()).arg(w.boundMs));
        return;
    }
    launchRace(race, bytesLeft, known ? order.first().path.id.id : QString(), 0);
    if (m_raceFirst && !m_race.running())
        m_raceFirst = false; // nothing could be raced: the owner walks at once
}

void ServiceEngine::launchRace(const QList<path::PathCandidate> &asked, qint64 bytesLeft, const QString &knownId, qint64 waitedMs)
{
    const bool known = !knownId.isEmpty();
    // A path the owner raised (or is raising) in this attempt is never probed - one rule for a pending race too: the
    // list a race waited with may be stale by the time its session arrives.
    QList<path::PathCandidate> race;
    for (const path::PathCandidate &pc : asked)
        if (!m_raisedPaths.contains(pc.id.id))
            race << pc;
    // The owner's wait for a first proof counts from the tap: a session that came late shortens it.
    if (!known && waitedMs > 0) {
        path::RaceTimings t = m_race.timings();
        t.hedgeMs = int(std::max<qint64>(1, t.hedgeAfterMs() - waitedMs));
        m_race.setTimings(t);
    }
    // wait_ms: how long the owner waits for a first proof before a blind start (0 = a known path starts at once)
    attemptJournal(QStringLiteral("race_begin known=%1 candidates=%2 bytes_left=%3 wait_ms=%4")
                       .arg(known ? knownId : QStringLiteral("-")).arg(race.size()).arg(bytesLeft)
                       .arg(known ? 0 : m_race.timings().hedgeAfterMs()));
    applyRaceEffects(m_race.begin(nowMs(), race, m_net.current(), m_prober->caps(), bytesLeft, m_prober->costs()));
}

void ServiceEngine::pollRaceWait()
{
    if (!m_raceWait || !m_prober)
        return;
    const path::ProberCaps pc = m_prober->caps();
    const qint64 waited = nowMs() - m_raceWait->sinceMs;
    if (pc.ready) {
        const RaceWait w = *m_raceWait;
        m_raceWait.reset();
        launchRace(w.race, w.bytesLeft, w.knownId, waited);
        if (m_raceFirst && !m_race.running())
            startOwnerAfterRace("not_raced"); // nothing could be raced: the owner walks now
        return;
    }
    if (controlPlane() == ApiReach::Unreachable)
        endRaceWait("no_control"); // lane C (C2): the session cannot come over a dead direct API
    else if (!pc.preparing || waited >= m_raceWait->boundMs)
        endRaceWait("no_session");
}

// The race of this tap never began: no probe was started, nothing is reserved. The owner starts at once.
void ServiceEngine::endRaceWait(const char *reason)
{
    const qint64 waited = m_raceWait ? nowMs() - m_raceWait->sinceMs : 0;
    m_raceWait.reset();
    attemptJournal(QStringLiteral("race_done reason=%1 proven=0 waited_ms=%2").arg(QLatin1String(reason)).arg(waited));
    startOwnerAfterRace(reason);
}

void ServiceEngine::onProbeResult(const path::ProbeStamp &stamp, path::PathOutcome outcome, qint64 bytesSeen)
{
    Q_UNUSED(bytesSeen) // informational (the prober's journal line has it); the race's bytes come through spendProbeBytes
    applyRaceEffects(m_race.probeDone(nowMs(), stamp, outcome));
}

bool ServiceEngine::failedInTunnelHere(const QString &nodeId) const
{
    const SubscriptionNode *n = findNode(nodeId);
    if (!n || !m_net.current().usable())
        return false;
    const path::LedgerEntry *e = m_ledger.entry(m_net.current().local, path::derivePathId(*n).id);
    return e && e->revision == path::derivePathId(*n).revision && e->failStreak > 0 && e->noDataMs > 0
        && e->noDataMs >= e->dataOkMs;
}

bool ServiceEngine::recordProbeProof(const QString &nodeId, const QString &source)
{
    const SubscriptionNode *n = findNode(nodeId);
    if (!n || !m_net.current().usable())
        return false;
    const path::PathId id = path::derivePathId(*n);
    if (!m_ledger.record(m_net.current().local, id, path::PathOutcome::ProbeOk, nowMs()))
        return false;
    m_ledgerDirty = true;
    attemptJournal(QStringLiteral("path_outcome net=%1 net_gen=%2 node=%3 rev=%4 outcome=probe_ok source=%5 state=%6")
                       .arg(m_net.current().local).arg(m_net.current().generation).arg(id.id, id.revision, source,
                            QLatin1String(path::pathStateName(m_ledger.view(m_net.current().local, id, nowMs()).state))));
    return true;
}

void ServiceEngine::noteCheckStarved(bool starved)
{
    m_checkStarved = starved;
    if (starved) // T1: a starving check of a leg goes when a proven path waits - the race's first proof leads
        feedOwner(path::AttemptEvent::proofReady(nowMs(), true, m_race.winner()));
}

void ServiceEngine::startOwnerAfterRace(const char *why, const QString &lead)
{
    if (!m_raceFirst)
        return;
    m_raceFirst = false;
    m_raceStartedOwner = true;
    attemptJournal(QStringLiteral("race_owner_start why=%1 lead=%2")
                       .arg(QLatin1String(why), lead.isEmpty() ? QStringLiteral("-") : lead));
    m_owner.setTimings(attemptTimings());
    feedOwner(path::AttemptEvent::userStart(nowMs(), m_choice, transportMode(), m_net.current(), lead));
}

void ServiceEngine::applyRaceEffects(const QList<path::RaceEffect> &effects)
{
    for (const path::RaceEffect &e : effects) {
        switch (e.type) {
        case path::RaceEffectType::StartProbe:
            attemptJournal(QStringLiteral("race_probe race=%1 probe=%2 node=%3 kind=%4")
                               .arg(e.stamp.race).arg(e.stamp.probe).arg(e.path.id.id)
                               .arg(QLatin1String(path::pathKindName(e.path.kind))));
            if (m_prober)
                m_prober->start(e.stamp, e.path, e.timeoutMs);
            break;
        case path::RaceEffectType::CancelProbe:
            if (m_prober) {
                m_prober->cancel(e.stamp);
                if (!m_prober->holdsAfterCancel())
                    m_race.settled(e.stamp); // nothing runs on after a cancel: its hold ends now
            }
            break;
        case path::RaceEffectType::Report:
            if (findNode(e.path.id.id) && m_net.isCurrent(e.networkGeneration)
                && m_ledger.record(e.network, e.path.id, e.outcome, nowMs(), e.ms))
                m_ledgerDirty = true;
            attemptJournal(QStringLiteral("path_outcome net=%1 net_gen=%2 node=%3 rev=%4 outcome=%5 source=race probe_ms=%6 state=%7")
                               .arg(e.network).arg(e.networkGeneration).arg(e.path.id.id, e.path.id.revision,
                                    QLatin1String(path::pathOutcomeName(e.outcome)))
                               .arg(e.ms)
                               .arg(QLatin1String(path::pathStateName(m_ledger.view(e.network, e.path.id, nowMs()).state))));
            // a proof while a leg is in flight: a leg whose check starves yields to it (the owner decides)
            if (m_owner.running())
                feedOwner(path::AttemptEvent::proofReady(nowMs(), m_checkStarved, e.path.id.id));
            break;
        case path::RaceEffectType::Failed:
            m_raceFailed.insert(e.path.id.id);
            attemptJournal(QStringLiteral("race_probe_failed node=%1 outcome=%2")
                               .arg(e.path.id.id, QLatin1String(path::pathOutcomeName(e.outcome))));
            break;
        case path::RaceEffectType::Winner:
            // only a path the ledger now holds as working wins (a tunnel no-data outranks the probe)
            if (m_ledger.view(m_net.current().local, e.path.id, nowMs()).state == path::PathState::Working) {
                m_race.acceptWinner(e.path.id.id);
                attemptJournal(QStringLiteral("race_winner node=%1").arg(e.path.id.id));
                startOwnerAfterRace("winner", e.path.id.id);
            }
            break;
        case path::RaceEffectType::Hedge:
            startOwnerAfterRace("hedge"); // nothing proven by hedgeAfterMs: the first choice starts blind, the race runs on
            break;
        case path::RaceEffectType::Done:
            if (m_prober)
                m_prober->raceEnded(e.stamp.race); // its host scan ends once (cancelled probes were already told)
            attemptJournal(QStringLiteral("race_done reason=%1 proven=%2")
                               .arg(QLatin1String(path::raceDoneReasonName(e.reason))).arg(m_race.proven()));
            if (e.reason != path::RaceDoneReason::Stopped)
                startOwnerAfterRace(path::raceDoneReasonName(e.reason));
            break;
        }
    }
}

void ServiceEngine::loseLiveSession(path::PathOutcome outcome, bool tunnelGone, bool restart, const QString &why)
{
    attemptJournal(QStringLiteral("live_lost node=%1 outcome=%2 tunnel_gone=%3 failover=%4 why=%5")
                       .arg(m_currentNodeId.isEmpty() ? QStringLiteral("?") : m_currentNodeId,
                            QLatin1String(path::pathOutcomeName(outcome)))
                       .arg(int(tunnelGone)).arg(int(restart)).arg(why));
    m_owner.setTimings(attemptTimings());
    if (restart)
        m_attemptAfterLiveLoss = true; // until the next start asked from outside (connect)
    if (m_owner.phase() == path::AttemptPhase::Connected) {
        feedOwner(path::AttemptEvent::liveLost(nowMs(), outcome, tunnelGone, restart, m_choice, transportMode(),
                                               m_net.current()));
        return;
    }
    // A live tunnel the owner does not hold (an adopted session whose check is not finished, or none at all):
    // a restart is a fresh attempt; the tunnel, if up, goes down first through the owner's own start rule.
    if (restart && !m_owner.running())
        feedOwner(path::AttemptEvent::userStart(nowMs(), m_choice, transportMode(), m_net.current()));
}

QString ServiceEngine::pathStateHere(const QString &nodeId) const
{
    const SubscriptionNode *n = findNode(nodeId);
    if (!n || !m_net.current().usable())
        return QStringLiteral("unknown");
    return QLatin1String(path::pathStateName(m_ledger.view(m_net.current().local, path::derivePathId(*n), nowMs()).state));
}

QSet<QString> ServiceEngine::pathsFailedHere() const
{
    QSet<QString> out;
    if (!m_net.current().usable())
        return out;
    for (const SubscriptionNode &n : m_merged) {
        const path::PathView v = m_ledger.view(m_net.current().local, path::derivePathId(n), nowMs());
        if (v.state == path::PathState::Suspect || v.state == path::PathState::Dead)
            out.insert(n.nodeId);
    }
    return out;
}

QString ServiceEngine::bestWorkingPathHere() const
{
    QString best;
    qint64 bestAt = 0;
    if (!m_net.current().usable())
        return best;
    for (const SubscriptionNode &n : m_merged) {
        const path::PathView v = m_ledger.view(m_net.current().local, path::derivePathId(n), nowMs());
        if (v.state == path::PathState::Working && v.lastSuccessMs > bestAt) {
            best = n.nodeId;
            bestAt = v.lastSuccessMs;
        }
    }
    return best;
}

// The node the next connect() would raise first: the owner's own order (PathSelect) for the choice, the mode in
// force and the ledger of this network - no side effect. For the Connect card's badge and the Scanner's view.
const SubscriptionNode *ServiceEngine::nextCandidate() const
{
    path::SelectInput in;
    in.pool = pathPool();
    if (m_net.current().usable())
        in.evidence = m_ledger.viewOf(m_net.current().local, in.pool, nowMs());
    in.choice = m_choice;
    in.mode = transportMode();
    const QList<path::RankedPath> order = path::selectPaths(in);
    return order.isEmpty() ? nullptr : findNode(order.first().path.id.id);
}

bool ServiceEngine::hasConnectablePin() const
{
    const SubscriptionNode *pinned = findNode(m_pinnedNodeId);
    if (!pinned)
        return false;
    const LocationTransports lt = locationTransportsFor(locationKeyOf(*pinned), transportMode());
    return lt.anyAllowed;
}

bool ServiceEngine::loadSubscription(const QByteArray &json, QString &error)
{
    Subscription sub;
    if (!SubscriptionParser::parse(json, sub, error))
        return false;
    return applyLoadedSubscription(sub);
}

bool ServiceEngine::applyLoadedSubscription(const Subscription &sub)
{
    // AVPN (фикс-волна 2026-09-22, K5/B1): серверная pool_revision = max(issuance_changed_at) по
    // флоту — НЕ монотонна (удаление ноды опускает максимум). Отвергать «старую» ревизию значило
    // навсегда заморозить пул на LKG до чужого штампа. Порядок ответов держит фасад (sequence).
    // Ревью CL-B (REV-3): сохраняем пул только для ТОГО ЖЕ аккаунта (address = стабильный /32
    // устройства). После redeem/transfer новый аккаунт в окне readiness отдаёт nodes:[] со своим
    // address — старый пул с чужим /32 держать нельзя (connect поднял бы туннель на чужих ключах).
    if (sub.nodes.isEmpty() && !m_pool.nodes().isEmpty()
        && sub.address == m_pool.subscription().address) {
        // Пустая выдача (degraded, окно readiness, демоция нод) при рабочем пуле: только аккаунтные
        // поля. Пул, pin, RTT и pending-reseed сохраняются — в базе 3c8cc74e пустое тело пул не трогало.
        updateAccountFields(sub, /*includeRevision=*/false);
        return true;
    }
    if (!m_pool.nodes().isEmpty() && samePoolContent(sub)) {
        // Содержимое совпало с пулом: без применения/лога; устаревший pending (сервер уже вернул
        // текущее состояние) снимаем; пул подтверждён свежим телом — флаг LKG снимается (LKG-путь
        // loadSubscriptionFromLkg выставит его обратно сам).
        updateAccountFields(sub, /*includeRevision=*/true);
        m_pendingReseed.reset();
        m_lkgActive = false;
        return true;
    }
    // Bootstrap can finish while a tunnel is already alive. It obeys the same identity
    // checks as periodic refresh; it must never replace credentials under a live session.
    if (!reseedApplicableNow(sub)) {
        m_pendingReseed = sub;
        updateAccountFields(sub, /*includeRevision=*/false);
    } else {
        applyReseedNow(sub);
    }
    return true;
}

// AVPN (LKG, C-7): тот же парс-путь, но данные из дискового кэша → снапшот честно помечен stale.
bool ServiceEngine::loadSubscriptionFromLkg(const QByteArray &json, QString &error)
{
    if (!loadSubscription(json, error))
        return false;
    m_lkgActive = true;
    return true;
}

bool ServiceEngine::lkgWriteAllowed(const Subscription &body, const QByteArray &diskLkg)
{
    if (!body.nodes.isEmpty())
        return true;
    // Пустое тело: затирать можно только LKG без нод или LKG другого аккаунта (другой address).
    bool lkgBlocks = false;
    if (!diskLkg.isEmpty()) {
        Subscription prev;
        QString perr;
        lkgBlocks = SubscriptionParser::parse(diskLkg, prev, perr) && !prev.nodes.isEmpty()
                 && prev.address == body.address;
    }
    return shouldPersistLkgBody(/*bodyHasNodes=*/false, /*lkgHasNodes=*/lkgBlocks);
}

QStringList ServiceEngine::subscriptionIssues() const
{
    return SubscriptionParser::validate(m_pool.subscription());
}

// --- AVPN awg31-xray-v1: reseed пула на живом приложении (спека §2.3, инвариант §4.4) ---------------

bool ServiceEngine::sameNodeIdentity(const SubscriptionNode &a, const SubscriptionNode &b)
{
    if (a.nodeId != b.nodeId || protoOf(a) != protoOf(b) || a.endpoint != b.endpoint)
        return false;
    // Upstream nodes (point 3, R2): a stub has no endpoint and no xray params - its identity is the
    // profile and the config digest (a new sha = the provider rotated its servers: the running session
    // is "changed", the new config applies at the next bring-up).
    if (a.upstream.has_value() || b.upstream.has_value())
        return sameUpstreamIdentity(a, b);
    if (isXrayProto(protoOf(a))) {
        if (!a.xray.has_value() || !b.xray.has_value())
            return false;
        return a.xray->uuid == b.xray->uuid && a.xray->publicKey == b.xray->publicKey
               && a.xray->shortId == b.xray->shortId && a.xray->serverName == b.xray->serverName;
    }
    // Compare the effective runtime config, including PSK, AWG obfuscation, DNS and MTU.
    // Values stay in memory and are never written to diagnostics.
    return AwgConfigBuilder::buildInner({}, a, {}) == AwgConfigBuilder::buildInner({}, b, {});
}

bool ServiceEngine::sameNodeContent(const SubscriptionNode &a, const SubscriptionNode &b)
{
    if (!sameNodeIdentity(a, b))
        return false;
    if (a.upstream.has_value() && b.upstream.has_value()) {
        const UpstreamStub &x = *a.upstream, &y = *b.upstream;
        if (x.tier != y.tier || x.priority != y.priority || x.probeClass != y.probeClass
            || x.protocols != y.protocols || x.requiredGeo != y.requiredGeo || x.sizeBytes != y.sizeBytes
            || a.dns != b.dns)
            return false;
    }
    return a.weight == b.weight && a.manualOnly == b.manualOnly && a.transportRank == b.transportRank
        && a.health == b.health && a.hostId == b.hostId && a.location == b.location
        && a.name == b.name && a.region == b.region && a.countryCode == b.countryCode;
}

bool ServiceEngine::samePoolContent(const Subscription &sub) const
{
    const Subscription &cur = m_pool.subscription();
    if (sub.address != cur.address || sub.nodes.size() != cur.nodes.size())
        return false;
    for (const SubscriptionNode &n : sub.nodes) {
        const SubscriptionNode *mine = findNode(n.nodeId);
        if (!mine || !sameNodeContent(*mine, n))
            return false;
    }
    return true;
}

void ServiceEngine::updateAccountFields(const Subscription &sub, bool includeRevision)
{
    m_pool.updateAccount(sub, includeRevision);
}

bool ServiceEngine::reseedApplicableNow(const Subscription &sub) const
{
    if (m_state == EngineState::Disconnected || m_state == EngineState::Error)
        return true;
    if (sub.address != m_pool.subscription().address)
        return false;
    // AVPN (фикс-волна 2026-09-22, B3): адоптированный туннель без identity (нода сессии не найдена
    // в пуле) — живой туннель пул не использует, его нечем «сломать»: reseed применим (иначе пул
    // замерзал до терминала), после применения — попытка опознать ноду по endpoint сессии.
    if ((m_state == EngineState::Connected || m_state == EngineState::Verifying) && m_currentNodeId.isEmpty())
        return true;
    // Не терминал: текущая нода (и цель незавершённого свитча) обязаны быть в новом пуле без
    // изменений — иначе живой туннель/секвенс свитча остался бы без своей ноды.
    const auto unchanged = [this, &sub](const QString &id) {
        const SubscriptionNode *cur = findNode(id);
        if (!cur)
            return false;
        for (const SubscriptionNode &n : sub.nodes)
            if (n.nodeId == id)
                return sameNodeIdentity(*cur, n);
        return false;
    };
    if (m_currentNodeId.isEmpty() || !unchanged(m_currentNodeId))
        return false;
    return true;
}

void ServiceEngine::applyReseedNow(const Subscription &sub)
{
    const Subscription old = m_pool.subscription();
    const QString oldPinLoc = pinnedLocation();
    const QString oldPin = m_pinnedNodeId;
    QSet<QString> oldIds, newIds;
    for (const SubscriptionNode &n : old.nodes)
        oldIds.insert(n.nodeId);
    for (const SubscriptionNode &n : sub.nodes)
        newIds.insert(n.nodeId);

    // Смена состава/identity (не только метаданных health/weight) — повод для записи в switchLog.
    bool identityChanged = (oldIds != newIds) || old.address != sub.address;
    if (!identityChanged) {
        for (const SubscriptionNode &n : sub.nodes) {
            const auto o = std::find_if(old.nodes.cbegin(), old.nodes.cend(),
                [&n](const SubscriptionNode &x) { return x.nodeId == n.nodeId; });
            if (o == old.nodes.cend() || !sameNodeIdentity(*o, n)) { identityChanged = true; break; }
        }
    }

    m_pool.setSubscription(sub);
    rebuildCandidates();
    m_lkgActive = false;
    m_pendingReseed.reset();

    // RTT-кэш и сессионные провалы исчезнувших узлов — сбросить (иначе стейл-замер ранжировал бы
    // призрака, а провал — держал бы новый узел с тем же id в чёрном списке).
    const auto pruneRtt = [&old, &sub](QHash<QString, RttSample> &cache) {
        for (auto it = cache.begin(); it != cache.end();) {
            const auto oldNode = std::find_if(old.nodes.cbegin(), old.nodes.cend(),
                [&it](const SubscriptionNode &n) { return n.nodeId == it.key(); });
            const auto newNode = std::find_if(sub.nodes.cbegin(), sub.nodes.cend(),
                [&it](const SubscriptionNode &n) { return n.nodeId == it.key(); });
            if (oldNode == old.nodes.cend() || newNode == sub.nodes.cend()
                || !sameNodeIdentity(*oldNode, *newNode))
                it = cache.erase(it);
            else
                ++it;
        }
    };
    pruneRtt(m_rttFresh);
    pruneRtt(m_rttLastKnown);

    // Ревалидация pin по ЛОКАЦИИ: узел исчез → сосед той же локации (представитель), иначе снять.
    // Актуальный pin фасад берёт из pinnedNodeId() (A7: персистит его, старый id не восстанавливает).
    // 5.1.109 (review R1): the representative only among nodes the effective transport mode allows -
    // a pinned Xray listener removed in mode "Xray" used to move the pin to the AWG node of the same
    // location (the card showed it, Connect raised another country's Xray). None allowed while the
    // location still has connectable nodes -> the pin is dropped, the facade persists and journals it.
    m_pinDroppedForTransport.clear();
    if (!m_pinnedNodeId.isEmpty() && !newIds.contains(m_pinnedNodeId)) {
        const TransportMode mode = transportMode();
        QList<const SubscriptionNode *> loc;
        bool locationConnectable = false;
        for (const SubscriptionNode &n : m_pool.nodes()) {
            if (oldPinLoc.isEmpty() || locationKeyOf(n) != oldPinLoc || !isSupportedProtoNode(n))
                continue;
            locationConnectable = true;
            if (transportAllowed(n, mode))
                loc.append(&n);
        }
        const SubscriptionNode *rep = locationRepresentative(loc);
        if (!rep && locationConnectable)
            m_pinDroppedForTransport = m_pinnedNodeId;
        m_pinnedNodeId = rep ? rep->nodeId : QString();
    }

    if (identityChanged || old.poolRevision != sub.poolRevision) {
        int added = 0, removed = 0;
        for (const QString &id : newIds)
            if (!oldIds.contains(id))
                ++added;
        for (const QString &id : oldIds)
            if (!newIds.contains(id))
                ++removed;
        appendSwitchLog(QStringLiteral("reseed pool rev %1→%2: +%3 -%4 (state %5)")
                            .arg(old.poolRevision).arg(sub.poolRevision).arg(added).arg(removed)
                            .arg(debugSnapshot().state));
        if (oldPin != m_pinnedNodeId)
            appendSwitchLog(QStringLiteral("pin %1→%2 (location %3)")
                                .arg(oldPin, m_pinnedNodeId.isEmpty() ? QStringLiteral("auto") : m_pinnedNodeId,
                                     oldPinLoc));
    }
    // A5/B3: адоптированная сессия без identity — опознать по endpoint из подсказки.
    tryIdentifyCurrentNode();
}

ReseedResult ServiceEngine::reseedPool(const Subscription &sub)
{
    if (sub.nodes.isEmpty())
        return ReseedResult::Rejected;           // пустое тело не затирает пул
    if (sub.poolRevision <= 0)
        return ReseedResult::Rejected;           // старый бэк/LKG без ревизии — reseed не по чему
    // AVPN (фикс-волна 2026-09-22, K5/B2): меньшая ревизия допустима — pool_revision не монотонна
    // (delete_node опускает max); порядок ответов держит фасад по m_subscriptionSequence.
    // Совпадение по содержимому → Unchanged: только аккаунтные поля, без лога (раньше равная ревизия
    // каждые ~20 с писала «reseed» и за ~7 мин вымывала из switchLog запись о реальном failover).
    if (samePoolContent(sub)) {
        updateAccountFields(sub, /*includeRevision=*/true);
        m_pendingReseed.reset();                 // сервер вернул текущее — отложенное тело устарело
        return ReseedResult::Unchanged;
    }
    if (!reseedApplicableNow(sub)) {
        m_pendingReseed = sub;                   // применим при переходе в терминал (applyPendingReseed)
        updateAccountFields(sub, /*includeRevision=*/false);
        return ReseedResult::Deferred;
    }
    applyReseedNow(sub);
    return ReseedResult::Applied;
}

bool ServiceEngine::applyPendingReseed()
{
    if (!m_pendingReseed.has_value())
        return false;
    if (!reseedApplicableNow(*m_pendingReseed))
        return false;
    const Subscription sub = *m_pendingReseed;
    applyReseedNow(sub);
    return true;
}

// AVPN (фикс-волна 2026-09-22, A5/B3): опознать ноду адоптированной сессии по подсказке
// {node_id, proto, endpoint} из sessionMetadata: точное совпадение id+endpoint(+proto), иначе
// ЕДИНСТВЕННАЯ нода пула с тем же endpoint и proto. Неоднозначно/нет — identity остаётся неизвестной.
bool ServiceEngine::tryIdentifyCurrentNode()
{
    // Upstream nodes (point 11): a stub session has no endpoint - it is identified by its node id
    // ("up:<profile>") alone, proto xray; there is no endpoint-only fallback for it.
    const bool upstreamHint = m_sessionHintNodeId.startsWith(QLatin1String("up:"));
    if (!m_currentNodeId.isEmpty() || (m_sessionHintEndpoint.isEmpty() && !upstreamHint))
        return false;
    if (m_state != EngineState::Connected && m_state != EngineState::Verifying)
        return false;
    const QString hintProto = m_sessionHintProto.isEmpty() ? QStringLiteral("awg") : m_sessionHintProto;
    const SubscriptionNode *match = nullptr;
    if (upstreamHint) {
        const SubscriptionNode *byId = findNode(m_sessionHintNodeId);
        if (!byId || !isUpstreamNode(*byId) || protoOf(*byId) != hintProto)
            return false;
        match = byId;
    }
    if (!match)
        if (const SubscriptionNode *byId = findNode(m_sessionHintNodeId))
            if (byId->endpoint == m_sessionHintEndpoint && protoOf(*byId) == hintProto)
                match = byId;
    if (!match) {
        int hits = 0;
        for (const SubscriptionNode &n : m_pool.nodes()) {
            if (n.endpoint == m_sessionHintEndpoint && protoOf(n) == hintProto) {
                match = &n;
                ++hits;
            }
        }
        if (hits != 1)
            match = nullptr;
    }
    if (!match)
        return false;
    m_currentNodeId = match->nodeId;
    resetHealSession(m_currentNodeId);
    appendSwitchLog(QStringLiteral("identity resolved: %1 by endpoint").arg(m_currentNodeId));
    m_sessionHintNodeId.clear();
    m_sessionHintProto.clear();
    m_sessionHintEndpoint.clear();
    // 5.1.109 (S4.1): nothing for the mode gate here. The transport of an adopted session is judged
    // from its HINT the moment the hint exists (adoptTunnelConnected) - before its node is found in
    // the pool; resolving the identity later (also inside a pool refresh) matches on that same
    // hinted proto and tells the gate nothing new.
    return true;
}

bool ServiceEngine::enroll(QNetworkAccessManager *nam, const QString &baseUrl,
                           SecureAppSettingsRepository *store, QString &error)
{
    TrialResponse tr;
    if (!Enrollment::enroll(nam, baseUrl, m_identity, store, tr, error))
        return false;
    m_token = tr.subscriptionToken;
    m_accountId = tr.accountId;
    return true;
}

// A user start (the facade's guardedStart): one attempt of the owner for the user's choice. The first leg is
// raised here (up() is queued - Connected arrives through onTunnelConnected); the rest of the walk runs on the
// tunnel callbacks, the data check and the tick. false = the attempt ended at once (no candidate, no network).
bool ServiceEngine::connect(QString &error)
{
    if (!m_tunnel) {
        error = QStringLiteral("no tunnel adapter set");
        m_state = EngineState::Error;
        return false;
    }
    m_modeGate.sessionStartedByUs(); // 5.1.109 (S4.1): never re-judged as an adopted session
    m_attemptAfterLiveLoss = false;
    m_owner.setTimings(attemptTimings());
    m_state = EngineState::Selecting;
    m_lastResult.reset();
    // Stage 2: with a probe host, a known working path starts at once and the spares are raced beside it; with
    // none known, the race runs first and the owner starts with its first proven path as the lead (or blind when the
    // race's wait, PathRace.h hedgeAfterMs, is over or the race ends).
    journalControlPlaneSkips();
    if (raceAllowed()) {
        m_raceStartedOwner = false;
        beginRaceForTap();
        if (m_raceFirst)
            return true;
        if (m_raceStartedOwner) // the race ended at once (nothing it could pay) and started the owner itself
            return m_owner.running() || m_lastResult.value_or(path::AttemptResult{}).connected;
    }
    feedOwner(path::AttemptEvent::userStart(nowMs(), m_choice, transportMode(), m_net.current()));
    if (m_owner.running())
        return true;
    // Ended at once: the facade shows the result.
    const path::AttemptResult r = m_lastResult.value_or(path::AttemptResult{});
    if (r.reason == path::FailReason::NoCandidate && m_modeGate.inForce() != TransportMode::Auto && anySupportedNode())
        error = QStringLiteral("no_transport: no '%1' candidates in pool").arg(transportModeToString(m_modeGate.inForce()));
    else if (r.reason == path::FailReason::NoNetwork)
        error = QStringLiteral("no_network");
    else if (r.reason == path::FailReason::ExactNodeFailed)
        error = QStringLiteral("exact_unavailable");
    else
        error = QStringLiteral("no nodes available");
    m_state = EngineState::Error;
    return false;
}

bool ServiceEngine::ensureSubscription(QNetworkAccessManager *nam, const QString &baseUrl,
                                       SecureAppSettingsRepository *store, QString &error) // AVPN
{
    // 1) токен: из хранилища, иначе enroll (genkey + POST /v1/trial)
    QString token = Enrollment::loadToken(); // AVPN: SecureQSettings-backed
    const bool tokenFromStore = !token.isEmpty();
    if (!tokenFromStore) {
        if (!enroll(nam, baseUrl, store, error))
            return false;
        token = m_token;
    } else {
        m_token = token;
        // ключи всё равно нужны для конфига туннеля
        if (!m_identity.ensureKeys(store, error))
            return false;
    }

    // 2) GET /v1/subscription с авто-хилом 401 (стейл-токен после ротации secret на бэкенде):
    //    Ok? грузим. Unauthorized на токен ИЗ СТОРА и ещё не лечили → clearToken + ре-энролл + ретрай
    //    РОВНО один раз. Сеть/лимит/HTTP — токен не виноват, не трогаем (важно для LKG-кэша).
    bool reEnrolled = false;
    for (;;) {
        QByteArray body;
        FetchOutcome outcome = FetchOutcome::HttpError;
        if (Enrollment::fetchSubscription(nam, baseUrl, token, body, error, &outcome)) {
            Subscription sub;
            if (!SubscriptionParser::parse(body, sub, error)) // 3) распарсить (NodePool + лимиты/expiresAt)
                return false;
            applyLoadedSubscription(sub);
            // AVPN (LKG): персистим ТОЛЬКО валидное тело. Ревью CL-B (REV-4, K5): пустое тело
            // (degraded/окно readiness) не затирает дисковый LKG с нодами того же аккаунта — иначе
            // после перезапуска пустой список серверов (жалоба 4); правило = shouldPersistLkgBody фасада.
            if (lkgWriteAllowed(sub, sub.nodes.isEmpty() ? Enrollment::loadLkgSubscription() : QByteArray()))
                Enrollment::saveLkgSubscription(body);
            return true;
        }

        if (Enrollment::decideAuthRecovery(outcome, tokenFromStore, reEnrolled)
            != AuthRecoveryAction::ReEnrollThenRetry)
            return false; // error уже выставлен fetchSubscription

        Enrollment::clearToken();            // токен мёртв — выкинуть стейл
        if (!enroll(nam, baseUrl, store, error))
            return false;
        token = m_token;                     // свежевыданный токен
        reEnrolled = true;                   // больше не лечим (decideAuthRecovery → Fail) — без петли
    }
}

bool ServiceEngine::startFlow(QNetworkAccessManager *nam, const QString &baseUrl,
                              SecureAppSettingsRepository *store, QString &error)
{
    // токен → GET /v1/subscription (с авто-хилом 401) → load → connect.
    if (!ensureSubscription(nam, baseUrl, store, error))
        return false;
    return connect(error);
}

bool ServiceEngine::bootstrap(QNetworkAccessManager *nam, const QString &baseUrl,
                              SecureAppSettingsRepository *store, QString &error) // AVPN
{
    // Тихая прогрузка подписки без подъёма туннеля (Task 11). Состояние движка не меняем —
    // остаёмся Disconnected; наполняем только NodePool/Subscription для живого бейджа. БЕЗ connect().
    return ensureSubscription(nam, baseUrl, store, error);
}

bool ServiceEngine::tick(qint64 nowEpoch)
{
    // AVPN (фикс-волна 2026-09-22, K5/B3): раньше гейт m_currentNodeId.isEmpty() выключал DEAD-детект
    // адоптированного туннеля без identity (нода сессии не в пуле) — туннель в чёрной дыре жил вечно.
    if (m_state != EngineState::Connected || !m_tunnel)
        return false;
    m_lastTickEpoch = nowEpoch;
    const TunnelStats stats = m_tunnel->readStats();
    // AVPN awg31-xray-v1: для xray handshake отсутствует по определению (адаптер эпоху не сеет,
    // 0 = неизвестно → hsStale) — DEAD = tx растёт, rx стоит N циклов (те же пороги); вторая
    // половина критерия — провал живой пробы через туннель (feedProbeResult).
    if (m_health.feed(stats, nowEpoch)) {
        // health-DEAD: туннель ещё «поднят» → лестница лечения (rebind → переподъём → другая нода)
        return onDead(/*tunnelStillUp=*/true, m_currentNodeId.isEmpty()
                                                  ? QStringLiteral("dead (unknown identity)")
                                                  : QStringLiteral("dead (failover)"));
    }
    noteHealthyTick(stats, nowEpoch);
    return false;
}

// Ревью CL-B (REV-1): шаг лечения (rebind/переподъём) — отсчёт восстановления бюджета заново.
void ServiceEngine::noteHealStep()
{
    m_healStepEpoch = m_lastTickEpoch > 0 ? m_lastTickEpoch : QDateTime::currentSecsSinceEpoch();
    m_healthySinceEpoch = 0;
}

// Ревью CL-B (REV-1): бюджет лечения возвращается после heal_budget_restore_s НЕПРЕРЫВНО здорового
// туннеля на той же ноде: есть доказательство живого data-plane (rx растёт или handshake свежее
// шага лечения) и ни одного плохого цикла. Кап на эпизод остаётся (нужно ≥60 с здоровья — без
// тесной петли). Простой (ни rx, ни handshake) бюджет не возвращает — доказательства нет.
void ServiceEngine::noteHealthyTick(const TunnelStats &stats, qint64 nowEpoch)
{
    const qint64 prevRx = m_tickPrevRx;
    if (stats.valid)
        m_tickPrevRx = stats.rxBytes;
    // Волна-2 (ревью 5.1.95): рост rx на текущей ноде — доказательство живого data-plane, не
    // зависящее от окна/пробы фасада. Раньше стрик провалов сбрасывала только удачная проба
    // (feedProbeResult), а она с 5.1.95 в фоне редкая: 4 failover за долгую сессию накапливались в
    // «сдаёмся» при исправном туннеле.
    // GAPFIX-2: отсрочки rebind "offline" — тоже часть сессии лечения (попытка возвращена, отказ не
    // поставлен, но кап kRebindOfflineDeferMax на эпизод копился бы всю сессию на ноде: через N часов
    // здорового туннеля очередной offline засчитывался отказом → переподъём/failover EE→US).
    const bool spent = m_rebindHealTries > 0 || m_sameNodeReupTries > 0 || m_rebindDenied
                    || m_rebindOfflineDefers > 0;
    if (!spent || m_healStepEpoch <= 0 || !stats.valid)
        return;
    if (m_health.badCycles() > 0) {
        m_healthySinceEpoch = 0; // плохой цикл — здоровый отрезок начинается заново
        return;
    }
    const bool rxGrew = prevRx >= 0 && stats.rxBytes > prevRx;
    const bool freshHandshake = stats.latestHandshakeEpoch > m_healStepEpoch;
    if (m_healthySinceEpoch <= 0) {
        if (rxGrew || freshHandshake)
            m_healthySinceEpoch = nowEpoch;
        return;
    }
    const qint64 healthyFor = nowEpoch - m_healthySinceEpoch;
    if (healthyFor < healBudgetRestoreSTuned())
        return;
    appendSwitchLog(QStringLiteral("heal budget restored on %1 after %2s healthy (rebind %3, re-up %4)")
                        .arg(m_currentNodeId.isEmpty() ? QStringLiteral("?") : m_currentNodeId)
                        .arg(healthyFor).arg(m_rebindHealTries).arg(m_sameNodeReupTries));
    resetHealSession(m_currentNodeId);
}

void ServiceEngine::noteNetworkChange(qint64 nowEpoch)
{
    m_probeFailStreak = 0; // failures of the old path say nothing about the new one (fourth review of 141, H2)
    m_health.noteNetworkChange(nowEpoch >= 0 ? nowEpoch : QDateTime::currentSecsSinceEpoch());
}

bool ServiceEngine::onRebindResult(bool performed, const QString &reason)
{
    if (!m_rebindAwaiting)
        return false; // поздний/чужой ответ (после смены ноды/стопа) — не наш шаг лечения
    m_rebindAwaiting = false;
    if (performed)
        return true;
    // GAP-2: NE не ребайндил, потому что его путь unsatisfied (телефон офлайн: лифт, лестница, смена
    // Wi-Fi↔LTE) — нода ни при чём. Раньше это засчитывалось провалом шага 1 и ускоряло уход EE→US.
    // Попытку возвращаем, отказ не ставим, считаем ожиданием сети (окно grace, как noteNetworkChange).
    if (reason == QLatin1String("offline") && m_rebindOfflineDefers < kRebindOfflineDeferMax) {
        ++m_rebindOfflineDefers;
        if (m_rebindHealTries > 0)
            --m_rebindHealTries;
        m_health.noteNetworkChange(m_lastTickEpoch > 0 ? m_lastTickEpoch : QDateTime::currentSecsSinceEpoch());
        appendSwitchLog(QStringLiteral("rebind-heal deferred on %1: tunnel path offline (not counted, %2/%3)")
                            .arg(m_currentNodeId.isEmpty() ? QStringLiteral("?") : m_currentNodeId)
                            .arg(m_rebindOfflineDefers).arg(kRebindOfflineDeferMax));
        return true;
    }
    // NE не сделал rebind (бюджет / адаптер не запущен / нет ответа): шаг 1 провален — следующий
    // DEAD-цикл сразу идёт на переподъём/другую ноду, без лишних циклов ожидания.
    m_rebindDenied = true;
    appendSwitchLog(QStringLiteral("rebind-heal denied by tunnel on %1%2")
                        .arg(m_currentNodeId.isEmpty() ? QStringLiteral("?") : m_currentNodeId,
                             reason.isEmpty() ? QString() : QStringLiteral(" (%1)").arg(reason)));
    return true;
}

void ServiceEngine::resetHealSession(const QString &nodeId)
{
    m_healNodeId = nodeId;
    m_rebindHealTries = 0;
    m_sameNodeReupTries = 0;
    m_rebindAwaiting = false;
    m_rebindDenied = false;
    m_rebindOfflineDefers = 0;
    m_healStepEpoch = 0;
    m_healthySinceEpoch = 0;
}

bool ServiceEngine::notifyConnectionLost()
{
    if (m_state != EngineState::Connected)
        return false;
    return onDead(/*tunnelStillUp=*/false, QStringLiteral("dead (failover)")); // реальный обрыв: туннель уже опущен → up() сразу
}

// AVPN awg31-xray-v1: живая проба через туннель (QualityProbe фасада) — xray-половина DEAD-критерия.
bool ServiceEngine::feedProbeResult(bool ok)
{
    if (m_state != EngineState::Connected)
        return false;
    if (ok) {
        // AVPN (независимое ревью волны, MAJOR-1): удачная проба ЧЕРЕЗ туннель — доказательство
        // живого data-plane, поэтому бюджет провалов возвращается ОБОИМ транспортам (у awg своей
        // фазы verify нет; без этого редкие смерти нод за часы работы копились бы в ложное
        // «сдаёмся»).
        m_probeFailStreak = 0;
        return false;
    }
    // Xray has no handshake: the live probe alone is its DEAD criterion. An AmneziaWG session ends on the probe only
    // when its own handshake agrees and no network change is being healed (HealthLoop::probeDeadCorroborated): a
    // healthy tunnel whose probe addresses are unreachable is never torn down.
    ++m_probeFailStreak;
    if (currentNodeIsXray()) {
        if (m_probeFailStreak < xrayProbeFailCyclesTuned())
            return false;
    } else {
        const qint64 nowEpoch = QDateTime::currentSecsSinceEpoch();
        if (!HealthLoop::probeDeadCorroborated(m_probeFailStreak, awgProbeFailCyclesTuned(),
                                               m_health.inNetworkGrace(nowEpoch), m_health.latestHandshakeEpoch(),
                                               nowEpoch, awgProbeDeadHandshakeAgeSTuned()))
            return false;
    }
    m_probeFailStreak = 0;
    return onDead(/*tunnelStillUp=*/true, QStringLiteral("probe failed (failover)"));
}

// The platform reports the tunnel up. For a leg of the owner that is its TunnelUp: the data check follows
// (Verifying) - "Connected" only after data passed through THIS tunnel.
bool ServiceEngine::onTunnelConnected() // AVPN
{
    if (m_owner.phase() == path::AttemptPhase::Starting) {
        m_health.reset();
        m_probeFailStreak = 0;
        feedOwner(path::AttemptEvent::tunnelUp(nowMs(), m_owner.currentLeg()));
        return true;
    }
    // A Connected of a leg being stopped (a late answer of the platform) is not a session: nothing to adopt.
    return m_owner.phase() == path::AttemptPhase::Stopping && !m_facadeStop;
}

bool ServiceEngine::verifySucceeded(int ttfbMs) // AVPN awg31-xray-v1
{
    if (m_state != EngineState::Verifying)
        return false;
    if (m_owner.phase() == path::AttemptPhase::Checking) {
        feedOwner(path::AttemptEvent::dataChecked(nowMs(), m_owner.currentLeg(), path::PathOutcome::DataOk, ttfbMs));
        return m_state == EngineState::Connected;
    }
    // the re-check of a live session (the extension's data watch): it carries data
    m_state = EngineState::Connected;
    m_health.reset();
    m_probeFailStreak = 0;
    return true;
}

// The check could not decide (the app was suspended mid-check, no answer at all): not a proof either way. A leg
// of the owner is not connected on it (nothing recorded, the walk goes on); a live session stays as it is.
bool ServiceEngine::verifyInconclusive() // plan v3 step 5 (review)
{
    if (m_state != EngineState::Verifying)
        return false;
    if (m_owner.phase() == path::AttemptPhase::Checking) {
        feedOwner(path::AttemptEvent::dataChecked(nowMs(), m_owner.currentLeg(), path::PathOutcome::Inconclusive));
        return true;
    }
    m_state = EngineState::Connected;
    m_health.reset();
    m_probeFailStreak = 0;
    return true;
}

bool ServiceEngine::reenterVerifying() // AVPN (iOS data watch, build 141)
{
    if (m_state != EngineState::Connected || m_currentNodeId.isEmpty())
        return false;
    m_state = EngineState::Verifying; // the facade re-checks the live session; a failure is a lost live session
    return true;
}

bool ServiceEngine::verifyFailed(const QString &reason) // AVPN awg31-xray-v1
{
    if (m_state != EngineState::Verifying)
        return false;
    if (m_owner.phase() == path::AttemptPhase::Checking) {
        appendSwitchLog(QStringLiteral("data check failed on %1: %2").arg(m_currentNodeId, reason));
        feedOwner(path::AttemptEvent::dataChecked(nowMs(), m_owner.currentLeg(), path::PathOutcome::NoData));
        return true;
    }
    // the re-check of a live session found no data: proven dead here, the failover attempt walks on without it
    loseLiveSession(path::PathOutcome::NoData, /*tunnelGone=*/false, /*restart=*/true, reason);
    return true;
}

bool ServiceEngine::adoptTunnelConnected(const QString &nodeId, const QString &proto,
                                         const QString &endpoint)
{
    // AVPN (фикс-волна 2026-09-22, A5/B3): нода сессии не найдена (или endpoint/proto уже другие —
    // пул сменился после подъёма) → identity НЕИЗВЕСТНА, но факт «туннель жив» адоптируем; health
    // работает и без identity (tick), подсказку запоминаем для опознания после reseed.
    bool identified = false;
    const bool hintGiven = !nodeId.isEmpty() || !endpoint.isEmpty();
    // 5.1.109 (S4.1, review of 3dbe0361f): the transport of the session as its HINT tells it - known
    // even while the node itself is not in the pool (empty proto in a hint = awg, as below); no hint =
    // unknown. Before, the facade asked currentNodeProto(), which is empty until the identity is
    // resolved - and the resolution inside a pool refresh was not looked at: a live AmneziaWG session
    // stayed under "Xray" and its first DEAD moved it to another country with no re-up of its node.
    const QString sessionProto = hintGiven ? (proto.isEmpty() ? QStringLiteral("awg") : proto) : QString();
    if (hintGiven) {
        const auto *node = findNode(nodeId);
        // S2 (device round 5): a provider stub has no endpoint of its own (the profile's server is in its lease) -
        // it is identified by its node id and proto alone, as tryIdentifyCurrentNode does.
        if (node && protoOf(*node) == (proto.isEmpty() ? QStringLiteral("awg") : proto)
            && (node->endpoint == endpoint || isUpstreamNode(*node))) {
            if (m_currentNodeId != nodeId)
                resetHealSession(nodeId);
            m_currentNodeId = nodeId;
            identified = true;
            m_sessionHintNodeId.clear();
            m_sessionHintProto.clear();
            m_sessionHintEndpoint.clear();
        } else {
            m_sessionHintNodeId = nodeId;
            m_sessionHintProto = proto;
            m_sessionHintEndpoint = endpoint;
        }
    }
    // Android-адопт (см. ServiceEngine.h): восстановление факта «туннель жив» после фейкового
    // Disconnected. Из любой фазы, кроме уже-Connected. AVPN awg31-xray-v1: из Verifying тоже не
    // «воскрешаем» — «Подключено» по xray только после пробы (фасад перезапускает верификацию).
    if (m_state == EngineState::Connected || m_state == EngineState::Verifying) {
        if (!identified)
            tryIdentifyCurrentNode();
        if (hintGiven)
            judgeAdoptedSession(sessionProto, /*adoptedNow=*/false); // the hint arrived after the adoption
        return false;
    }
    if (hintGiven && !identified) {
        m_currentNodeId.clear(); // старая нода движка не доказана — health работает без identity
        resetHealSession(QString());
    }
    m_health.reset();
    resetHealSession(m_currentNodeId); // AVPN BUG-4 / B6: адопт = новая сессия наблюдения и лечения
    m_probeFailStreak = 0;
    // 5.1.109 (S4.1): a live session this process did not start. The mode in force for it is decided
    // by the gate: a known transport the mode excludes -> Auto; the session found at startup takes
    // the stored choice unless its known transport contradicts it (TransportModeGate.h).
    judgeAdoptedSession(sessionProto, /*adoptedNow=*/true);
    // Path engine (coordinator decision 6 of 18.11): the live tunnel becomes the leg of a new attempt of the
    // owner, already up - one in-tunnel data check decides (Verifying; the facade runs it). A session whose node
    // is not in the pool is a leg too (its outcome is not recorded: no path to record it for).
    path::PathCandidate leg;
    if (const SubscriptionNode *n = findNode(m_currentNodeId)) {
        leg = path::pathCandidateFromNode(*n);
    } else {
        leg.id = path::PathId{ m_sessionHintNodeId.isEmpty() ? QStringLiteral("adopted") : m_sessionHintNodeId, QString() };
        leg.kind = isXrayProto(sessionProto) ? path::PathKind::OwnXray : path::PathKind::OwnAwg;
    }
    m_owner.setTimings(attemptTimings());
    // Review E7 of 18.11: a live tunnel the facade decided to adopt supersedes whatever the owner still holds
    // (a start the native refused to run over its live profile, a stop of a leg that never ran): that attempt
    // ends (stopped by the person's own tap or the system - nothing recorded) and the live tunnel goes into the
    // owner's Checking like every other leg. Connected only after its data check.
    if (m_owner.running() || m_owner.phase() != path::AttemptPhase::Idle) {
        attemptJournal(QStringLiteral("attempt_superseded_by_live_session phase=%1")
                           .arg(QLatin1String(path::attemptPhaseName(m_owner.phase()))));
        m_facadeStop = true; // nothing of ours runs natively: no down()
        if (m_owner.running() || m_owner.phase() == path::AttemptPhase::Starting
            || m_owner.phase() == path::AttemptPhase::Checking || m_owner.phase() == path::AttemptPhase::Connected)
            feedOwner(path::AttemptEvent::userStop(nowMs()));
        if (m_owner.phase() == path::AttemptPhase::Stopping)
            feedOwner(path::AttemptEvent::stopConfirmed(nowMs(), m_owner.stoppingLeg()));
        m_facadeStop = false;
    }
    m_state = EngineState::Verifying;
    feedOwner(path::AttemptEvent::adopted(nowMs(), leg, m_choice, transportMode(), m_net.current()));
    if (m_owner.phase() != path::AttemptPhase::Checking) {
        // not reachable after the supersede above; never Connected without a check
        attemptJournal(QStringLiteral("adopt_refused phase=%1").arg(QLatin1String(path::attemptPhaseName(m_owner.phase()))));
        m_state = EngineState::Disconnected;
        return false;
    }
    if (m_tunnel)
        m_tunnel->adoptNativeOp(m_owner.currentLeg().leg); // its native events are this leg's from now on
    return true;
}

bool ServiceEngine::nativeEventStale(quint64 nativeLeg) const
{
    switch (m_owner.phase()) {
    case path::AttemptPhase::Starting:
    case path::AttemptPhase::Checking:
        return nativeLeg != m_owner.currentLeg().leg;
    case path::AttemptPhase::Stopping:
        return nativeLeg < m_owner.stoppingLeg().leg;
    case path::AttemptPhase::Connected:
    case path::AttemptPhase::Idle:
        return false;
    }
    return false;
}

// tunnelGone: the platform's Error proves the tunnel is down (desktop); on iOS / macOS NE it does not.
bool ServiceEngine::onTunnelError(bool tunnelGone) // AVPN
{
    m_rebindAwaiting = false;
    const EngineState before = m_state;
    switch (m_owner.phase()) {
    case path::AttemptPhase::Starting:
    case path::AttemptPhase::Checking:
        // a leg of the owner did not come up (its outcome, if the adapter knew one, came via noteStartRefused)
        feedOwner(path::AttemptEvent::pathFailed(nowMs(), m_owner.currentLeg(), path::PathOutcome::Inconclusive,
                                                 tunnelGone));
        return m_state != before;
    case path::AttemptPhase::Stopping:
        if (tunnelGone)
            return onTunnelDisconnected();
        return false;
    case path::AttemptPhase::Connected:
        loseLiveSession(path::PathOutcome::Inconclusive, /*tunnelGone=*/true, /*restart=*/false, QStringLiteral("tunnel error"));
        break;
    case path::AttemptPhase::Idle:
        break;
    }
    if (m_state == EngineState::Error)
        return false;
    m_state = EngineState::Error;
    return true;
}

bool ServiceEngine::onTunnelDisconnected() // AVPN
{
    const EngineState before = m_state;
    switch (m_owner.phase()) {
    case path::AttemptPhase::Stopping:
        // GAP-1: between two runtimes a deferred pool body is applied before the next leg is chosen.
        applyPendingReseedBetweenRuntimes();
        feedOwner(path::AttemptEvent::stopConfirmed(nowMs(), m_owner.stoppingLeg()));
        if (!m_owner.running() && m_owner.phase() == path::AttemptPhase::Idle && m_state != EngineState::Error) {
            m_state = EngineState::Disconnected;
            m_currentNodeId.clear();
        }
        return m_state != before;
    case path::AttemptPhase::Starting:
    case path::AttemptPhase::Checking:
        feedOwner(path::AttemptEvent::pathFailed(nowMs(), m_owner.currentLeg(), path::PathOutcome::Inconclusive,
                                                 /*tunnelGone=*/true));
        return m_state != before;
    case path::AttemptPhase::Connected:
        loseLiveSession(path::PathOutcome::Inconclusive, /*tunnelGone=*/true, /*restart=*/false,
                        QStringLiteral("tunnel down"));
        break;
    case path::AttemptPhase::Idle:
        break;
    }
    if (m_state == EngineState::Disconnected || m_state == EngineState::Selecting)
        return false;
    m_state = EngineState::Disconnected;
    m_currentNodeId.clear();
    return true;
}

bool ServiceEngine::onPermissionDenied()
{
    if (m_owner.phase() != path::AttemptPhase::Starting)
        return false;
    const EngineState before = m_state;
    attemptJournal(QStringLiteral("permission_denied node=%1 (the attempt ends, nothing recorded)")
                       .arg(m_owner.currentPath().id.id));
    feedOwner(path::AttemptEvent::permissionDenied(nowMs(), m_owner.currentLeg()));
    if (m_tunnel)
        m_tunnel->startRefused(); // the attempt ends with no StopPath: the seat taken for it goes back here (review F9)
    return m_state != before;
}

// The facade takes the tunnel down (the user's stop, a restart for another choice): the owner's attempt ends
// StoppedByUser once the stop is confirmed (onTunnelDisconnected); the ledger is not touched.
void ServiceEngine::requestStop() // AVPN
{
    m_sessionHintNodeId.clear();
    m_sessionHintProto.clear();
    m_sessionHintEndpoint.clear();
    resetHealSession(QString());
    m_raceFirst = false; // the person stops: a race in front of the owner ends without starting it
    m_raceWait.reset();
    if (m_race.running())
        applyRaceEffects(m_race.stop(nowMs()));
    if (m_owner.running() || m_owner.phase() != path::AttemptPhase::Idle) {
        m_facadeStop = true;
        feedOwner(path::AttemptEvent::userStop(nowMs()));
    }
    // Намеренный стоп: фаза гасится до down(), чтобы Disconnected не запустил failover.
    m_state = EngineState::Disconnected;
    m_currentNodeId.clear();
    m_health.reset();
    m_rebindHealTries = 0; // AVPN BUG-4
    m_probeFailStreak = 0;
}

bool ServiceEngine::onDead(bool tunnelStillUp, const QString &reasonIn)
{
    const QString reason = reasonIn.isEmpty() ? QStringLiteral("dead (failover)") : reasonIn;
    // AVPN (фикс-волна 2026-09-22, B3): health-DEAD и для туннеля с неизвестной identity.
    const bool healthDead = reason == QLatin1String("dead (failover)")
                         || reason == QLatin1String("dead (unknown identity)");
    const bool unknownIdentity = m_currentNodeId.isEmpty();
    // --- Шаг 1 (B6): rebind ---------------------------------------------------------------------
    // AVPN (BUG-4 auto-heal, 2026-07-22): сессионный блок ТСПУ вешается на 5-tuple/CGNAT-flow —
    // «данные не проходят» на одном телефоне при живом втором на том же операторе, режим полёта
    // (= новый flow) лечит. Перед failover пробуем то же самое БЕЗ участия юзера: ребайнд сокета
    // (новый локальный порт) на ТЕКУЩЕЙ ноде. Только для health-DEAD при живом туннеле (реальный
    // обрыв = туннель уже опущен, ребайндить нечего). Грейс не нужен: m_health.reset() очищает
    // детект, повторный DEAD (не помогло) придёт через cyclesToDead плохих тиков (~8-12с) — как
    // раз окно ре-хендшейка WG (REKEY_TIMEOUT 5с) с нового порта. Кап попыток на ноду-сессию —
    // rebindHealMaxTriesTuned (кламп §17.2), kill-switch features.rebind_heal.
    // AVPN awg31-xray-v1: только для awg (у xray нет WG-сокета — heal бессмыслен) и только по
    // health-DEAD (не по провалу verify/probe — там уже доказано, что data-plane мёртв).
    // AVPN (фикс-волна 2026-09-22, B7): NE сообщил отказ (onRebindResult(false)) — шаг пропускаем.
    if (tunnelStillUp && m_tunnel && !currentNodeIsXray() && healthDead
        && TuningStore::flag(QStringLiteral("rebind_heal"), true)
        && !m_rebindDenied
        && m_rebindHealTries < rebindHealMaxTriesTuned()
        && m_tunnel->rebindSocket()) {
        ++m_rebindHealTries;
        ++m_rebindHealTotal;
        m_rebindAwaiting = true;
        noteHealStep();
        appendSwitchLog(QStringLiteral("rebind-heal try %1 on %2 (dead data-plane)")
                            .arg(m_rebindHealTries)
                            .arg(unknownIdentity ? QStringLiteral("?") : m_currentNodeId));
        m_health.reset();
        return false; // остаёмся Connected: либо оживёт (rx/handshake), либо DEAD вернётся → шаг 2/3
    }
    m_rebindAwaiting = false;
    // GAP-1 (U7): дальше текущий рантайм гасится - отложенный reseed (сменилась identity текущей ноды: порт,
    // awg_params, pubkey) применяем СЕЙЧАС: the failover attempt reads the new pool. GAPFIX-1: a new config of
    // the current node is an untried path (another revision) - it is not blamed for the old one.
    std::optional<SubscriptionNode> deadConfig;
    if (!unknownIdentity)
        if (const SubscriptionNode *cur = findNode(m_currentNodeId))
            deadConfig = *cur;
    bool untriedConfig = false;
    if (applyPendingReseedBetweenRuntimes() && deadConfig.has_value()) {
        const SubscriptionNode *now = findNode(m_currentNodeId);
        untriedConfig = now && !sameNodeIdentity(*deadConfig, *now);
    }
    // Step 2 (B6) through the owner: the first health DEAD of a session (roaming, mesh Wi-Fi, a NAT rebind of the
    // operator) does not blame the node - it stays "working" here, so the failover attempt raises it again first.
    // Once the re-up budget of the node is spent (dead_reup_max_tries, kill switch dead_reup_same_node), or the
    // data check / live probe proved no data, the node is recorded as failed here and the attempt walks on.
    const bool reup = (tunnelStillUp && healthDead && !unknownIdentity
                       && TuningStore::flag(QStringLiteral("dead_reup_same_node"), true)
                       && m_sameNodeReupTries < deadReupMaxTriesTuned())
                   || untriedConfig;
    if (reup) {
        ++m_sameNodeReupTries;
        noteHealStep();
        appendSwitchLog(QStringLiteral("re-up same node %1 first (dead data-plane, try %2)")
                            .arg(m_currentNodeId).arg(m_sameNodeReupTries));
    }
    // A tunnel that went away by itself proves nothing about the path; a dead data plane on a live tunnel does.
    const path::PathOutcome outcome = (reup || !tunnelStillUp) ? path::PathOutcome::Inconclusive
                                                               : path::PathOutcome::NoData;
    loseLiveSession(outcome, !tunnelStillUp, /*restart=*/true, reason);
    return true;
}

bool ServiceEngine::applyPendingReseedBetweenRuntimes()
{
    // Пустое тело (другой аккаунт в окне readiness, REV-3) здесь не применяем — его разбирает
    // терминальный путь фасада, как раньше; живой туннель пул не использует, между рантаймами
    // подменить пул безопасно (applyReseedNow — только память: pin по локации, RTT, провалы).
    if (!m_pendingReseed.has_value() || m_pendingReseed->nodes.isEmpty())
        return false;
    const Subscription sub = *m_pendingReseed;
    applyReseedNow(sub);
    m_reseedAppliedInSwitch = true;
    return true;
}

DebugSnapshot ServiceEngine::debugSnapshot() const
{
    DebugSnapshot s;
    switch (m_state) {
    case EngineState::Disconnected: s.state = QStringLiteral("disconnected"); break;
    case EngineState::Selecting:    s.state = QStringLiteral("selecting"); break;
    case EngineState::Connecting:   s.state = QStringLiteral("connecting"); break;
    case EngineState::Verifying:    s.state = QStringLiteral("verifying"); break; // AVPN awg31-xray-v1
    case EngineState::Connected:    s.state = QStringLiteral("connected"); break;
    case EngineState::Switching:    s.state = QStringLiteral("switching"); break;
    case EngineState::Error:        s.state = QStringLiteral("error"); break;
    }
    s.currentNodeId = m_currentNodeId;
    const Subscription &sub = m_pool.subscription();
    s.subStatus = (sub.status == SubStatus::Degraded) ? QStringLiteral("degraded")
                                                      : QStringLiteral("active");
    s.trafficUsed = sub.trafficUsed;
    s.trafficLimit = sub.trafficLimit;
    s.expiresAt = sub.expiresAt; // AVPN: для AvpnEngineQml::daysLeft()
    s.graceUntil = sub.graceUntil; // AVPN (diag-report): grace-окно в диагностику
    s.lkgStale = m_lkgActive; // AVPN (LKG, C-7): пул из дискового кэша, свежий фетч ещё не доехал
    // AVPN awg31-xray-v1: транспорт/режим/фаза верификации/ревизия пула.
    s.activeProto = currentNodeProto();
    s.transportMode = transportModeToString(transportMode()); // 5.1.109: effective, as the UI
    s.verifying = (m_state == EngineState::Verifying);
    s.poolRevision = sub.poolRevision;
    s.reseedPending = m_pendingReseed.has_value();

    // реальные рантайм-статы туннеля
    if (m_tunnel) {
        const TunnelStats st = m_tunnel->readStats();
        s.rxBytes = st.rxBytes;
        s.txBytes = st.txBytes;
        s.latestHandshakeAgeSec = (st.latestHandshakeEpoch > 0)
            ? (QDateTime::currentSecsSinceEpoch() - st.latestHandshakeEpoch)
            : -1;
    }

    const QString curLoc = currentLocation();
    QHash<QString, QStringList> transportsByLoc; // кэш на снапшот: локация → транспорты
    for (const SubscriptionNode &n : m_merged) { // upstream nodes: pack candidates after the subscription's
        NodeDebugRow row;
        row.nodeId = n.nodeId;
        row.region = n.region;
        row.name = n.name;         // AVPN: имя сервера (опц.)
        row.countryCode = n.countryCode; // AVPN: ISO-3166 alpha-2 → флаг-эмодзи в UI
        row.endpoint = n.endpoint; // AVPN: реальный host:port для UI
        row.proto = protoOf(n);    // AVPN (diag-report): протокол ноды (пусто = awg)
        // AVPN AWG 3.0/3.1: "1"/"2"/"3"/"3.1" → метка «Amnezia vN» в пикере; у xray версии AWG нет.
        row.protoVersion = isXrayProto(row.proto) ? QString() : n.awg.protocolMajor();
        row.manualOnly = isManualOnlyNode(n); // AVPN (Доктор): manual/RU — вне авто-очередей
        // AVPN (diag-report): измеренный off-tunnel ICMP RTT из кэша m_measuredRtt (probeNodeRtt);
        // нет замера → 0 (осталось легаси-значением scoreMs).
        row.scoreMs = qMax(0, m_rttFresh.value(n.nodeId).ms);
        // AVPN (live-node picker): обогащаем строку backend-данными (weight + health-агрегат). Источник
        // правды — подписка; TCP-RTT не показываем (AWG = UDP). alive/current → акцент/бары в шторке.
        const double agg = healthAggregate(n);
        row.weight = n.weight;
        row.healthAgg = agg;
        row.alive = agg > 0.0;
        row.current = (n.nodeId == m_currentNodeId);
        row.healthy = row.alive; // легаси-поле: теперь = alive (backend), не заглушка true
        row.reason = (n.nodeId == m_currentNodeId) ? QStringLiteral("current") : QString();
        // AVPN awg31-xray-v1 (§2.3, пикер «локации × транспорты»).
        const QString loc = locationKeyOf(n);
        row.hostId = n.hostId;
        row.location = loc;
        if (!transportsByLoc.contains(loc))
            transportsByLoc.insert(loc, locationTransports(m_merged, loc));
        row.transports = transportsByLoc.value(loc);
        row.transportRank = n.transportRank;
        row.transportSupported = isSupportedProtoNode(n);
        // Upstream nodes (point 16): the row is a provider profile - its tier and display name parts for the
        // UI lane. The server's label reaches the row ONLY when the admin set it (label_custom); a fallback
        // such as "NL 1" never does - the facade builds «<country> <n>» (UpstreamNode.h::upstreamDisplayName).
        row.upstream = isUpstreamNode(n);
        row.upstreamTier = upstreamTierOf(n);
        row.packSourced = n.upstream.has_value() && n.upstream->packSourced;
        if (row.upstream) {
            row.upstreamOrdinal = n.upstream->ordinal;
            row.upstreamLabelCustom = n.upstream->labelCustom;
            row.upstreamKind = upstreamRowKind(n.upstream->kind, n.countryCode);
            if (!row.upstreamLabelCustom)
                row.name.clear();
        }
        // A provider profile runs only on the Xray engine: its card always carries the Xray badge (coordinator 18.11
        // (d): a whitelist row's card had none - a profile without a country is never "the current location").
        row.activeProto = row.upstream ? QStringLiteral("xray")
                                       : (!curLoc.isEmpty() && loc == curLoc) ? s.activeProto : QString();
        s.pool << row;
    }
    s.switchLog = m_switchLog;
    return s;
}

// AVPN (live-node picker): «Выбрать» — пользователь явно выбрал ноду в шторке. ТОЛЬКО закрепляем
// её (m_pinnedNodeId); НЕ коннектим и НЕ свитчим. Модель «выбор = задать цель, коннект — кнопкой»:
// следующий connect() (orb «Connect») поднимет закреплённую ноду (он уже отдаёт приоритет
// m_pinnedNodeId). Если сейчас онлайн другой узел — туннель гасит мост (AvpnEngineQml::switchToNode)
// через requestStop()+down(), чтобы НЕ делать back-to-back up() без реального Disconnected (iOS-storm,
// «Operation Cancelled»/«Network error»). Авто-логика с закреплённой ради скорости не уходит; при её
// смерти onDead() уведёт на лучшую живую и ОСТАНЕТСЯ там (назад вручную). Spec §23-26.
// AVPN awg31-xray-v1: pin — ПО ЛОКАЦИИ (см. ServiceEngine.h).
bool ServiceEngine::setPinnedNode(const QString &nodeId, QString &error) // AVPN
{
    if (nodeId.isEmpty()) {
        error = QStringLiteral("empty nodeId");
        return false;
    }
    // Узел должен существовать в подписке (иначе нечего закреплять/поднимать).
    const SubscriptionNode *found = findNode(nodeId);
    if (!found) {
        error = QStringLiteral("node not in subscription: %1").arg(nodeId);
        return false;
    }
    // Локация тапнутого узла: есть ли в ней ХОТЬ ОДИН поднимаемый узел (любой proto) и есть ли
    // узел, разрешённый ручным режимом. Строки ТЕХНИЧЕСКИЕ (лог/тесты); человеческий текст для
    // тоста — на границе фасада (AvpnEngineQml::humanPinError), маппится по стабильному префиксу.
    const QString loc = locationKeyOf(*found);
    const LocationTransports lt = locationTransportsFor(loc, m_modeGate.inForce());
    const bool anySupported = lt.anySupported, anyAllowed = lt.anyAllowed;
    if (!anySupported) {
        // Task 10: нода с неподдерживаемым протоколом непригодна и для РУЧНОГО pin (в отличие от
        // manual_only) — коннект к ней невозможен, честная ошибка вместо вечного Connecting.
        error = QStringLiteral("unsupported_proto: node %1 proto '%2'").arg(nodeId, protoOf(*found));
        return false;
    }
    if (!anyAllowed) {
        error = QStringLiteral("no_transport: location %1 has no '%2' transport")
                    .arg(loc, transportModeToString(m_modeGate.inForce()));
        return false;
    }
    m_pinnedNodeId = nodeId;
    // The person picked this server of the list: a preferred server - the transports of its host first, then the
    // best available path with a notice (owner decision of 17.11); the facade narrows a Scanner row to its exact path.
    QStringList paths;
    for (const SubscriptionNode &n : m_merged)
        if (locationKeyOf(n) == loc)
            paths << n.nodeId;
    m_choice = path::UserChoice::preferServer(found->countryCode, paths);
    return true;
}

ServiceEngine::LocationTransports ServiceEngine::locationTransportsFor(const QString &loc,
                                                                      TransportMode mode) const
{
    LocationTransports lt;
    for (const SubscriptionNode &n : m_merged) {
        if (locationKeyOf(n) != loc || !isSupportedProtoNode(n))
            continue;
        lt.anySupported = true;
        if (transportAllowed(n, mode))
            lt.anyAllowed = true;
    }
    return lt;
}

// 5.1.109: the rule of setPinnedNode's no_transport refusal for an existing pin (see ServiceEngine.h).
bool ServiceEngine::pinLacksTransport(TransportMode mode) const
{
    const SubscriptionNode *pinned = findNode(m_pinnedNodeId);
    if (!pinned)
        return false;
    const LocationTransports lt = locationTransportsFor(locationKeyOf(*pinned), mode);
    return lt.anySupported && !lt.anyAllowed;
}

// ---- 5.1.109 (S4.1): the transport mode in force follows the stored choice by the rule of
// TransportModeGate.h. Here - what that rule cannot know: whether Xray is usable right now, the
// engine phase, and the pin. ----

ServiceEngine::ModeChange ServiceEngine::applyGateOutcome(const TransportModeGate::Outcome &o)
{
    ModeChange c;
    c.changed = o.modeChanged;
    c.from = o.from;
    c.to = o.to;
    c.storeChoice = o.storeChoice;
    c.storedMode = o.storedMode;
    c.idleEntered = o.idleEntered;
    // A pin the admitted mode cannot serve is un-applied: the engine drops it and the SAVED one stays
    // (the facade does not store anything), as the order "mode first, then restorePin" gave before
    // 139 - it comes back when the pool or the mode can serve it again. An admission never erases
    // the saved pin: that is the user's tap only (review of df7f49db8).
    if (o.pin == TransportModeGate::Pin::Unapply && pinLacksTransport(transportMode())) {
        c.pinUnapplied = m_pinnedNodeId;
        m_modeGate.note(QStringLiteral("pin_not_applied why=transport_mode mode=%1 node=%2")
                            .arg(transportModeToString(transportMode()), m_pinnedNodeId));
        m_pinnedNodeId.clear();
    }
    return c;
}

ModeActivity ServiceEngine::withEnginePhase(ModeActivity a) const
{
    a.engineBusy = m_state != EngineState::Disconnected && m_state != EngineState::Error;
    return a;
}

ServiceEngine::ModeChange ServiceEngine::loadTransportModeChoice(const QString &stored, bool byChoiceBuild)
{
    return applyGateOutcome(m_modeGate.load(stored, byChoiceBuild, xrayClientSupported()));
}

ServiceEngine::ModeChange ServiceEngine::noteModeActivity(const ModeActivity &a, const QString &why)
{
    return applyGateOutcome(m_modeGate.observe(withEnginePhase(a), xrayClientSupported(), why));
}

ServiceEngine::ModeChange ServiceEngine::noteStartupObserved(const ModeActivity &a)
{
    return applyGateOutcome(m_modeGate.startupObserved(withEnginePhase(a), xrayClientSupported()));
}

bool ServiceEngine::nextXrayRuntimeGate(bool readyNow, bool present, const ModeActivity &a) const
{
    return m_modeGate.nextRuntimeGate(readyNow, present, withEnginePhase(a));
}

// The transport of a session this process did not start, as its hint tells it: "awg" | "xray"; empty =
// no hint, unknown. The gate decides (a known transport the mode excludes -> Auto for the session;
// the session found at startup takes the stored choice unless its known transport contradicts it).
void ServiceEngine::judgeAdoptedSession(const QString &sessionProto, bool adoptedNow)
{
    applyGateOutcome(adoptedNow ? m_modeGate.sessionAdopted(sessionProto, xrayClientSupported())
                                : m_modeGate.sessionTransportKnown(sessionProto, xrayClientSupported()));
}

// AVPN (live-node picker): «Обновить подключение» - the next live location becomes the choice; a start (or the
// facade's restart) raises it through the owner.
bool ServiceEngine::rotateNext(QString &error) // AVPN
{
    const QString targetId = nextLiveNodeId();
    if (targetId.isEmpty()) {
        error = QStringLiteral("not enough live nodes to rotate");
        return false;
    }
    m_pinnedNodeId = targetId;
    QStringList paths;
    if (const SubscriptionNode *t = findNode(targetId))
        for (const SubscriptionNode &n : m_merged)
            if (locationKeyOf(n) == locationKeyOf(*t))
                paths << n.nodeId;
    m_choice = path::UserChoice::preferServer(findNode(targetId) ? findNode(targetId)->countryCode : QString(), paths);
    if (m_state == EngineState::Connected || m_state == EngineState::Verifying || m_state == EngineState::Switching)
        return true; // the facade restarts the live session on the new choice
    return connect(error);
}

// AVPN: следующая живая локация после текущей — чистая версия rotateNext (без свитча/connect). Фасад
// использует для «Обновить подключение» через единый reconcile-контур. Логика (вкл. исключение
// RU-нод из кольца — §14.3, ручной режим транспорта) — в NodeRotation.h, тест tests/node_rotation_check.cpp.
QString ServiceEngine::nextLiveNodeId() const
{
    return avpn::nextLiveNodeId(m_pool.nodes(), m_currentNodeId, transportMode()); // 5.1.109: effective
}

} // namespace avpn
