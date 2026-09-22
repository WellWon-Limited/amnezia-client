#include "ServiceEngine.h"
#include "ConnectTunables.h" // AVPN (BUG-4 auto-heal): rebindHealMaxTriesTuned — кламп кап попыток; xray-пороги
#include "NodeRanking.h"  // AVPN (выбор по скорости): fastestMeasuredNodeId
#include "NodeRotation.h" // AVPN: healthAggregate/isRuNode/nextLiveNodeId (чистая логика, тестируется автономно)
#include "SubscriptionParser.h"
#include "TransportPick.h" // AVPN awg31-xray-v1: локации × транспорты, история

#include <QDateTime>
#include <QDebug>
#include <QRandomGenerator> // AVPN: рандомизация авто-выбора среди равных нод (иначе всегда первая = Польша)
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
    for (const SubscriptionNode &n : m_pool.nodes())
        if (n.nodeId == nodeId)
            return &n;
    return nullptr;
}

bool ServiceEngine::anySupportedNode() const
{
    for (const SubscriptionNode &n : m_pool.nodes())
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

// Failover: свежий замер поверх последнего известного (без TTL). В connected замеры запрещены
// (пакет к чужой ноде ушёл бы в туннель), и за 120 с свежий кэш пустеет — без этого failover
// выбирал бы локацию монетой по весам.
QHash<QString, int> ServiceEngine::failoverRtt() const
{
    QHash<QString, int> out = lastKnownRtt();
    const QHash<QString, int> fresh = measuredRtt();
    for (auto it = fresh.constBegin(); it != fresh.constEnd(); ++it)
        out.insert(it.key(), it.value());
    return out;
}

void ServiceEngine::markUpStarted()
{
    m_upStartedMs = QDateTime::currentMSecsSinceEpoch();
    m_okRecorded = false;
    m_failRecorded = false;
    m_probeFailStreak = 0;
}

// AVPN awg31-xray-v1: исход подъёма текущей ноды → локальная история транспортов (см. ServiceEngine.h).
bool ServiceEngine::recordTransportOutcome(bool ok)
{
    const SubscriptionNode *n = findNode(m_currentNodeId);
    if (!n)
        return false;
    if (ok && m_okRecorded)
        return false;
    if (!ok && m_failRecorded)
        return false;
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    const qint64 elapsed = now - m_upStartedMs;
    const int ttf = (ok && m_upStartedMs > 0)
        ? int(elapsed < 0 ? 0 : (elapsed > qint64(TransportHistory::kMaxTtfMs) ? qint64(TransportHistory::kMaxTtfMs) : elapsed))
        : -1;
    m_transportHistory.record(locationKeyOf(*n), protoOf(*n), ok, ttf, now);
    m_historyDirty = true;
    (ok ? m_okRecorded : m_failRecorded) = true;
    return true;
}

void ServiceEngine::noteDataPlaneFailure()
{
    recordTransportOutcome(false);
    if (!m_currentNodeId.isEmpty())
        m_failedThisSession.insert(m_currentNodeId);
    // AVPN (независимое ревью волны, MAJOR-1): счётчик ПОДРЯД идущих провалов data-plane за
    // сессию — кап против вечной карусели failover (см. onDead).
    ++m_dataPlaneFailStreak;
}

// AVPN (live-node picker): выбор по max weight среди ЖИВЫХ нод, исключая exclA/exclB. Без I/O.
// manual_only-ноды (вкл. RU) — в отдельный fallback-ярус: берём их ТОЛЬКО если живых обычных нет
// (не рвём коннект). Легаси-цепочка (kill-switch transport_auto_pick=false): xray сюда не попадает
// (isAutoEligibleNode) — авто = только awg, как до волны awg31-xray-v1.
const SubscriptionNode *ServiceEngine::pickByWeight(const QString &exclA, const QString &exclB) const // AVPN
{
    const QList<SubscriptionNode> &all = m_pool.nodes();
    // AVPN (фикс «авто всегда Польша»): AWG = UDP-only ⇒ TCP-ping не достукивается ⇒ сюда падаем почти
    // всегда. Раньше брали ПЕРВЫЙ узел с max weight (n.weight > best — строгое «>»), т.е. при равных
    // весах детерминированно первый в JSON-порядке = Польша; Финляндия не выбиралась НИКОГДА. Теперь:
    // собираем верхний «ярус» (узлы у максимального weight) среди живых и выбираем СЛУЧАЙНО — авто
    // реально распределяет/чередует равноценные ноды.
    QList<const SubscriptionNode *> tier, ruTier;
    double maxW = -1.0, maxWru = -1.0;
    for (const SubscriptionNode &n : all) {
        if (!exclA.isEmpty() && n.nodeId == exclA)
            continue;
        if (!exclB.isEmpty() && n.nodeId == exclB)
            continue;
        if (!isAutoEligibleNode(n) || !transportAllowed(n, m_transportMode)) // Task 10 + awg31: авто-пригодность
            continue;
        if (healthAggregate(n) <= 0.0) // мёртв по backend-данным (пустой health = живой)
            continue;
        if (isManualOnlyNode(n)) {     // manual_only/RU — отдельный fallback-ярус (не в основном выборе)
            if (n.weight > maxWru + 1e-9) { maxWru = n.weight; ruTier.clear(); ruTier.append(&n); }
            else if (n.weight >= maxWru - 1e-9) { ruTier.append(&n); }
            continue;
        }
        if (n.weight > maxW + 1e-9) {   // новый максимум — ярус обнуляем
            maxW = n.weight;
            tier.clear();
            tier.append(&n);
        } else if (n.weight >= maxW - 1e-9) { // в пределах максимума — добавляем в ярус
            tier.append(&n);
        }
    }
    const QList<const SubscriptionNode *> &pick = tier.isEmpty() ? ruTier : tier; // fallback на RU если не-RU нет
    if (pick.isEmpty())
        return nullptr;
    if (pick.size() == 1)
        return pick.first();
    const int idx = static_cast<int>(QRandomGenerator::global()->bounded(pick.size()));
    return pick.at(idx);
}

// AVPN (выбор по скорости): среди ЖИВЫХ нод (excl) с кэшем off-tunnel ICMP RTT — нода с минимальным RTT.
// Без I/O (использует уже накопленный m_measuredRtt — CONNECT-INVARIANTS §1). nullptr = ни одна не измерена.
const SubscriptionNode *ServiceEngine::pickByMeasuredRtt(const QString &exclA, const QString &exclB) const
{
    const QList<SubscriptionNode> &nodes = m_pool.nodes();
    QList<RankRow> rows, ruRows;
    for (const SubscriptionNode &n : nodes) {
        if (!exclA.isEmpty() && n.nodeId == exclA)
            continue;
        if (!exclB.isEmpty() && n.nodeId == exclB)
            continue;
        if (!isAutoEligibleNode(n) || !transportAllowed(n, m_transportMode)) // Task 10 + awg31: авто-пригодность
            continue;
        if (healthAggregate(n) <= 0.0) // мёртв по backend-данным (пустой health = живой)
            continue;
        (isManualOnlyNode(n) ? ruRows : rows).append({ n.nodeId, measuredRtt().value(n.nodeId, -1) });
    }
    const QString id = fastestMeasuredNodeId(rows.isEmpty() ? ruRows : rows); // fallback на RU если не-RU нет
    if (id.isEmpty())
        return nullptr;
    for (const SubscriptionNode &n : nodes)
        if (n.nodeId == id)
            return &n;
    return nullptr;
}

// AVPN awg31-xray-v1: выбор транспорта по локациям (см. TransportPick.h и ServiceEngine.h).
const SubscriptionNode *ServiceEngine::pickTransport(const QString &preferLocation, const QString &preferNodeId,
                                                     const QString &exclA, bool withExclusions,
                                                     bool useLastKnownRtt) const
{
    TransportPickInput in;
    in.mode = m_transportMode;
    in.exclA = exclA;
    if (withExclusions)
        in.excluded = m_failedThisSession;
    in.preferLocation = preferLocation;
    in.preferNodeId = preferNodeId;
    // Случайный индекс в ярусе равного weight — авто реально чередует равноценные локации.
    const auto randomIndex = [](int size) {
        return static_cast<int>(QRandomGenerator::global()->bounded(size));
    };
    return pickTransportNode(m_pool.nodes(), useLastKnownRtt ? failoverRtt() : measuredRtt(),
                             m_transportHistory, in, randomIndex);
}

const SubscriptionNode *ServiceEngine::pinnedCandidate() const
{
    const SubscriptionNode *pinned = findNode(m_pinnedNodeId);
    if (!pinned) return nullptr;
    const QString loc = locationKeyOf(*pinned);
    const SubscriptionNode *candidate = pickTransport(loc, m_pinnedNodeId, QString(), true);
    if (!candidate && !m_failedThisSession.isEmpty())
        candidate = pickTransport(loc, m_pinnedNodeId, QString(), false);
    return candidate;
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
    if (m_state == EngineState::Connected && m_currentNodeId.isEmpty() && m_pendingSwitchNodeId.isEmpty())
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
    if (!m_pendingSwitchNodeId.isEmpty() && !unchanged(m_pendingSwitchNodeId))
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
    m_failedThisSession.intersect(newIds);

    // Ревалидация pin по ЛОКАЦИИ: узел исчез → сосед той же локации (представитель), иначе снять.
    // Актуальный pin фасад берёт из pinnedNodeId() (A7: персистит его, старый id не восстанавливает).
    if (!m_pinnedNodeId.isEmpty() && !newIds.contains(m_pinnedNodeId)) {
        QList<const SubscriptionNode *> loc;
        for (const SubscriptionNode &n : m_pool.nodes())
            if (!oldPinLoc.isEmpty() && locationKeyOf(n) == oldPinLoc && isSupportedProtoNode(n))
                loc.append(&n);
        const SubscriptionNode *rep = locationRepresentative(loc);
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
    if (!m_currentNodeId.isEmpty() || m_sessionHintEndpoint.isEmpty())
        return false;
    if (m_state != EngineState::Connected && m_state != EngineState::Verifying)
        return false;
    const QString hintProto = m_sessionHintProto.isEmpty() ? QStringLiteral("awg") : m_sessionHintProto;
    const SubscriptionNode *match = nullptr;
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

bool ServiceEngine::connect(QString &error)
{
    if (!m_tunnel) {
        error = QStringLiteral("no tunnel adapter set");
        m_state = EngineState::Error;
        return false;
    }
    m_state = EngineState::Selecting;
    // AVPN (независимое ревью волны, MAJOR-2): сохранённый режим «Xray» при выключенном
    // features.xray_client отсекал бы ВСЕ кандидаты (no_transport) — приводим к Auto.
    normalizeTransportMode();
    // AVPN (фикс-волна 2026-09-22, B4/B5): повтор после прерванного внутреннего свитча (фасад A8/A9).
    const InterruptedSwitch interrupted = m_interrupted;
    m_interrupted = InterruptedSwitch{};
    // AVPN (независимое ревью волны, MAJOR-1): явное действие пользователя = новая сессия
    // наблюдения за data-plane (бюджет провалов возвращается). Ревью CL-B (REV-2): повтор
    // прерванного свитча — НЕ действие пользователя: стрик провалов сохраняется (кап карусели).
    if (!interrupted.active) {
        m_dataPlaneFailStreak = 0;
        m_dataPlaneExhausted = false;
    }
    // AVPN awg31-xray-v1: kill-switch автоматики транспортов. Выключен → авто-пути = легаси-цепочка
    // «измеренный RTT → weight» ТОЛЬКО по awg (xray — ручной режим/pin).
    const bool autoPick = TuningStore::flag(QStringLiteral("transport_auto_pick"), true);
    std::optional<SubscriptionNode> candidate; // AVPN: optional — закрепление/weight-фолбэк ниже
    // AVPN (live-node picker): если пользователь закрепил ноду — стартуем с неё (она есть и жива).
    // Закрепление имеет приоритет над авто-скорингом: «движок не уходит ради скорости» (spec §23-25).
    // AVPN awg31-xray-v1: pin — ПО ЛОКАЦИИ: транспорт внутри закреплённой локации выбирает
    // pickTransport (transport_rank + история + ручной режим + сессионные провалы). Стейл-pin
    // (локация мертва/без поднимаемых узлов) → падаем в авто-выбор вместо заведомо мёртвого up().
    // AVPN (фикс-волна 2026-09-22, B4/B5): повтор после прерванного внутреннего свитча (фасад A8/A9) —
    // сначала сохранённая цель (прервано в фазе down: её ещё не пробовали; при смерти закреплённой
    // failover pin не учитывает — spec §24-26). Одноразово: запись снимается при любом исходе.
    if (interrupted.active && !interrupted.target.isEmpty()) {
        const SubscriptionNode *t = findNode(interrupted.target);
        if (t && isSupportedProtoNode(*t) && transportAllowed(*t, m_transportMode)
            && healthAggregate(*t) > 0.0 && !m_failedThisSession.contains(t->nodeId))
            candidate = *t;
    }
    if (!candidate)
        if (const SubscriptionNode *pinned = pinnedCandidate())
            candidate = *pinned;
    if (!candidate && (autoPick || m_transportMode != TransportMode::Auto)) {
        // AVPN awg31-xray-v1: локация — по измеренному off-tunnel RTT (кэш AvpnEngineQml::probeNodeRtt),
        // без замеров — weight-ярус (случайно среди равных); транспорт внутри — ранг + история. Без I/O.
        // Ревью CL-B (REV-2): повтор прерванного свитча идёт без нового раунда замеров (в connected
        // они запрещены, свежий кэш за 120 с пуст) — ранжируем по failoverRtt (свежий поверх
        // последнего известного), а не монетой по весам.
        const bool lastKnown = interrupted.active;
        const SubscriptionNode *c = pickTransport(QString(), QString(), QString(), /*withExclusions=*/true, lastKnown);
        if (!c && !m_failedThisSession.isEmpty())
            c = pickTransport(QString(), QString(), QString(), /*withExclusions=*/false, lastKnown);
        if (c)
            candidate = *c;
    }
    if (!candidate && !autoPick && m_transportMode == TransportMode::Auto) {
        // Легаси-цепочка (как до волны awg31-xray-v1; авто = только awg):
        // AVPN (выбор по скорости): «Авто (быстрейший)» — приоритет ноде с МИНИМАЛЬНЫМ ИЗМЕРЕННЫМ RTT
        // (off-tunnel ICMP, кэш из AvpnEngineQml::probeNodeRtt). Это и есть настоящий «быстрейший». Пусто
        // (кэш холодный / ICMP-фильтр) → pickByWeight (backend-weight). Без I/O.
        if (const SubscriptionNode *fast = pickByMeasuredRtt(QString(), QString())) // AVPN
            candidate = *fast;
        // All direct measurements are asynchronous in the facade. The legacy kill-switch
        // must not reintroduce nested event loops or TCP probes against AWG's UDP listener.
        if (!candidate) {
            // MVP-фолбэк (спайк §9.3): AWG-порт UDP-only → TCP-ping может не пройти ни до одной ноды
            // (фильтр выкинет всё). Не отказываем: берём живую ноду с максимальным weight (бэкенд).
            if (const SubscriptionNode *best = pickByWeight(QString(), QString())) // AVPN
                candidate = *best;
        }
    }
    if (!candidate) {
        // AVPN awg31-xray-v1: ручной режим отфильтровал всё → честная техническая ошибка
        // (человеческий текст — AvpnEngineQml::humanEngineError); иначе штатное «нет нод».
        if (m_transportMode != TransportMode::Auto && anySupportedNode())
            error = QStringLiteral("no_transport: no '%1' candidates in pool")
                        .arg(transportModeToString(m_transportMode));
        else
            error = QStringLiteral("no nodes available");
        m_state = EngineState::Error;
        return false;
    }
    m_state = EngineState::Connecting;
    m_currentNodeId = candidate->nodeId; // AVPN: фиксируем выбранную ноду уже на фазе Connecting
    // явный старт = новая сессия лечения (B6). Ревью CL-B (REV-2): повтор прерванного свитча на ту же
    // ноду бюджет лечения не возвращает (иначе DEAD→переподъём→Error→повтор крутился бы вечно).
    if (!interrupted.active || m_currentNodeId != m_healNodeId)
        resetHealSession(m_currentNodeId);
    m_sessionHintNodeId.clear();
    m_sessionHintProto.clear();
    m_sessionHintEndpoint.clear();
    markUpStarted();
    const TunnelResult r = m_tunnel->up(m_pool.subscription(), *candidate);
    if (!r.ok) {
        error = r.error;
        m_state = EngineState::Error;
        return false;
    }
    // AVPN: up() ставит туннель в очередь VpnConnection (async) — НЕ объявляем Connected здесь.
    // Реальный переход Connecting→Connected/Error приходит из VpnConnection::connectionStateChanged
    // через AvpnEngineQml → onTunnelConnected()/onTunnelError() (правдивый статус, не маска успеха).
    m_health.reset();
    return true;
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

void ServiceEngine::noteSwitchInterrupted(const QString &cause)
{
    // Фаза down: цель ещё не пробовали — сохраняем для повтора. Ревью CL-B (REV-2): и для переподъёма
    // той же ноды (шаг 2 лестницы) — нода не провалилась, а повтор без цели после >120 с connected
    // выбирал бы локацию монетой по весам (свежий RTT-кэш пуст) → «US вместо EE».
    // Фаза up: цель провалила подъём — в сессионные провалы/историю, повтор пойдёт мимо неё.
    // Ревью CL-B (REV-6): кроме переподъёма в окне grace смены сети — сеть ещё не готова (роуминг),
    // это не доказательство смерти ноды: цель сохраняем, в провалы не пишем (причина — в switchLog).
    InterruptedSwitch rec;
    rec.active = true;
    rec.cause = cause;
    QString note;
    if (m_switchUpPhase) {
        rec.reason = m_pendingSwitchIsReup ? QStringLiteral("dead (re-up same node)") : m_upPhaseReason;
        if (m_pendingSwitchIsReup && m_health.inNetworkGrace(nowMs() / 1000)) {
            rec.target = m_currentNodeId;
            note = QStringLiteral(" (re-up in network grace: node not blamed)");
        } else {
            noteDataPlaneFailure(); // m_currentNodeId уже = цель (continuePendingSwitch)
        }
    } else {
        rec.reason = m_pendingSwitchReason;
        rec.target = m_pendingSwitchNodeId;
    }
    m_interrupted = rec;
    appendSwitchLog(QStringLiteral("switch interrupted (%1): retry %2%3")
                        .arg(cause, rec.target.isEmpty() ? QStringLiteral("auto") : rec.target, note));
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
        m_dataPlaneFailStreak = 0;
        m_dataPlaneExhausted = false;
        m_probeFailStreak = 0;
        return false;
    }
    if (!currentNodeIsXray())
        return false; // у awg критерий DEAD — handshake/rx в HealthLoop, не проба
    if (++m_probeFailStreak < xrayProbeFailCyclesTuned())
        return false;
    m_probeFailStreak = 0;
    return onDead(/*tunnelStillUp=*/true, QStringLiteral("probe failed (failover)"));
}

// AVPN: правдивые переходы из реального состояния VpnConnection (см. ServiceEngine.h).
bool ServiceEngine::onTunnelConnected() // AVPN
{
    // Подтверждаем Connected ТОЛЬКО из фаз подъёма/свитча — не «воскрешаем» Disconnected/Error.
    if (m_state == EngineState::Connecting || m_state == EngineState::Switching
        || m_state == EngineState::Selecting) {
        m_health.reset();
        // AVPN BUG-4: свежий подъём НОВОЙ ноды = новый бюджет heal-попыток. B6: переподъём той же
        // ноды (шаг 2 лестницы) бюджет НЕ возвращает — иначе rebind→переподъём крутились бы вечно.
        if (m_currentNodeId != m_healNodeId)
            resetHealSession(m_currentNodeId);
        m_switchStartedMs = -1;
        m_switchUpPhase = false;
        m_pendingSwitchIsReup = false;
        m_probeFailStreak = 0;
        // AVPN awg31-xray-v1 (инвариант §4.3): xray поднят платформой (процесс/сокет/маршруты), но
        // «Подключено» — только после первой удачной пробы ЧЕРЕЗ туннель. Фасад ведёт пробу
        // (бюджет xray_verify_timeout_ms) и зовёт verifySucceeded()/verifyFailed().
        m_state = currentNodeIsXray() ? EngineState::Verifying : EngineState::Connected;
        return true;
    }
    return false;
}

bool ServiceEngine::verifySucceeded() // AVPN awg31-xray-v1
{
    if (m_state != EngineState::Verifying)
        return false;
    m_state = EngineState::Connected;
    m_health.reset();
    m_probeFailStreak = 0;
    // AVPN (независимое ревью волны, MAJOR-1): доказанный трафик через туннель = data-plane жив.
    m_dataPlaneFailStreak = 0;
    m_dataPlaneExhausted = false;
    recordTransportOutcome(true); // «реальный трафик» для xray = прошедшая проба
    return true;
}

bool ServiceEngine::verifyFailed() // AVPN awg31-xray-v1
{
    if (m_state != EngineState::Verifying)
        return false;
    // Туннель платформа считает поднятым → двухфазный свитч (down → Disconnected → up на другой
    // транспорт той же локации, потом соседняя). Ребайнд-heal для xray не имеет смысла (нет WG-сокета).
    onDead(/*tunnelStillUp=*/true, QStringLiteral("verify failed (failover)"));
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
    if (hintGiven) {
        const auto *node = findNode(nodeId);
        if (node && protoOf(*node) == (proto.isEmpty() ? QStringLiteral("awg") : proto)
            && node->endpoint == endpoint) {
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
        return false;
    }
    if (hintGiven && !identified) {
        m_currentNodeId.clear(); // старая нода движка не доказана — health работает без identity
        resetHealSession(QString());
    }
    m_state = EngineState::Connected;
    m_health.reset();
    resetHealSession(m_currentNodeId); // AVPN BUG-4 / B6: адопт = новая сессия наблюдения и лечения
    m_probeFailStreak = 0;
    m_dataPlaneFailStreak = 0; // AVPN (ревью волны, MAJOR-1): то же для бюджета провалов data-plane
    m_dataPlaneExhausted = false;
    m_pendingSwitchNodeId.clear();
    m_pendingSwitchReason.clear();
    m_switchStartedMs = -1;
    m_switchUpPhase = false;
    m_pendingSwitchIsReup = false;
    m_interrupted = InterruptedSwitch{}; // туннель жив — повтор прерванного свитча не нужен
    return true;
}

bool ServiceEngine::onTunnelError() // AVPN
{
    // Error does not prove that the previous runtime is down.
    // AVPN (фикс-волна 2026-09-22, B5/H9): Error во время НАШЕГО свитча/failover — цель не теряем
    // молча: фиксируем прерывание (hasInterruptedSwitch), решение (повтор после подтверждённого
    // down, анти-зацикливание) принимает фасад.
    if (m_state == EngineState::Switching)
        noteSwitchInterrupted(m_switchUpPhase ? QStringLiteral("error_up") : QStringLiteral("error_down"));
    m_pendingSwitchNodeId.clear();
    m_pendingSwitchReason.clear();
    m_switchStartedMs = -1;
    m_switchUpPhase = false;
    m_pendingSwitchIsReup = false;
    m_rebindAwaiting = false;
    if (m_state == EngineState::Error)
        return false;
    m_state = EngineState::Error;
    return true;
}

bool ServiceEngine::onTunnelDisconnected() // AVPN
{
    // AVPN (двухфазный свитч): Disconnected во время свитча — это ОЖИДАЕМЫЙ обрыв от down();
    // теперь, когда туннель реально опущен, поднимаем up() на целевую ноду (iOS-safe секвенс).
    if (m_state == EngineState::Switching && !m_pendingSwitchNodeId.isEmpty())
        return continuePendingSwitch();
    // Реактивный failover уже покрыт notifyConnectionLost() (Connected→свитч). Здесь — только
    // честное отражение «отключено», когда движок НЕ в фазе подъёма (иначе это промежуточный
    // Disconnecting перед reconnect — не сбрасываем). Verifying — как Connected (туннель был поднят).
    if (m_state == EngineState::Disconnected || m_state == EngineState::Connecting
        || m_state == EngineState::Switching || m_state == EngineState::Selecting)
        return false;
    m_state = EngineState::Disconnected;
    m_currentNodeId.clear();
    return true;
}

void ServiceEngine::requestStop() // AVPN
{
    m_switchStartedMs = -1;
    m_switchUpPhase = false;
    m_pendingSwitchIsReup = false;
    m_interrupted = InterruptedSwitch{}; // явный стоп: повтор прерванного свитча не нужен
    m_sessionHintNodeId.clear();
    m_sessionHintProto.clear();
    m_sessionHintEndpoint.clear();
    resetHealSession(QString());
    // Намеренный стоп: гасим фазу до down(), чтобы Disconnected не запустил failover.
    // Pending-свитч отменяем тоже (ревью 2026-07-11): юзер остановил — недоигранный
    // continuePendingSwitch не должен мочь воскреснуть ни на каком последующем колбэке.
    m_state = EngineState::Disconnected;
    m_currentNodeId.clear();
    m_pendingSwitchNodeId.clear();
    m_pendingSwitchReason.clear();
    m_health.reset();
    m_rebindHealTries = 0; // AVPN BUG-4
    // AVPN awg31-xray-v1: новая сессия пользователя — сессионные провалы транспортов и стрик проб забыты.
    m_failedThisSession.clear();
    m_probeFailStreak = 0;
    m_dataPlaneFailStreak = 0;  // AVPN (ревью волны, MAJOR-1): явный стоп = новая сессия наблюдения
    m_dataPlaneExhausted = false;
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
    // GAP-1 (U7): дальше текущий рантайм гасится (шаг 2/3) — отложенный reseed (сменилась identity
    // текущей ноды: порт, awg_params, pubkey) применяем СЕЙЧАС, до выбора: переподъём «той же ноды»
    // по старому конфигу поднимался мёртвым и уводил на шаг 3 (EE→US). Локацию берём ДО применения:
    // если нода исчезла из пула, шаг 3 всё равно предпочитает её локацию.
    const QString deadLocation = currentLocation();
    std::optional<SubscriptionNode> deadConfig;
    if (!unknownIdentity) {
        if (const SubscriptionNode *cur = findNode(m_currentNodeId))
            deadConfig = *cur;
    }
    // GAPFIX-1: бюджет переподъёма — на КОНФИГ ноды, не на nodeId. Если отложенный reseed сменил
    // identity текущей ноды (тот же nodeId, другой порт/awg_params/pubkey), умер СТАРЫЙ конфиг, новый
    // ещё не пробовали: шаг 2 уже мог быть потрачен на старом (rebind выкл / отказ NE → шаг 2 через
    // ~12 с, раньше каденса refresh ~20 с) — и тогда шаг 3 писал провал ноде 9 и уводил EE→US.
    // Новый конфиг = новая нода для сессии лечения: бюджет переподъёма заново, провал не пишем.
    bool untriedConfig = false;
    if (applyPendingReseedBetweenRuntimes() && deadConfig.has_value()) {
        const SubscriptionNode *now = findNode(m_currentNodeId);
        if (now && !sameNodeIdentity(*deadConfig, *now)) {
            untriedConfig = true;
            if (m_sameNodeReupTries > 0)
                appendSwitchLog(QStringLiteral("node %1 config changed by reseed — re-up budget reset")
                                    .arg(m_currentNodeId));
            m_sameNodeReupTries = 0;
        }
    }
    // --- Шаг 2 (B6): полный переподъём ТОЙ ЖЕ ноды -----------------------------------------------
    // Ложный/временный DEAD (роуминг, mesh-Wi-Fi, NAT-ребинд оператора) не должен уводить EE→US:
    // сначала новый рантайм на той же ноде (новый сокет, свежий handshake), и только если и он
    // умрёт — другая нода. Кап — deadReupMaxTriesTuned на ноду-сессию, kill-switch
    // features.dead_reup_same_node. Identity неизвестна — поднимать нечего, сразу шаг 3.
    if (tunnelStillUp && healthDead && !unknownIdentity
        && TuningStore::flag(QStringLiteral("dead_reup_same_node"), true)
        && m_sameNodeReupTries < deadReupMaxTriesTuned()) {
        normalizeTransportMode();
        const SubscriptionNode *cur = findNode(m_currentNodeId);
        if (cur && isSupportedProtoNode(*cur) && healthAggregate(*cur) > 0.0
            && transportAllowed(*cur, m_transportMode)) {
            ++m_sameNodeReupTries;
            noteHealStep();
            appendSwitchLog(QStringLiteral("re-up same node %1 (dead data-plane, try %2)")
                                .arg(m_currentNodeId).arg(m_sameNodeReupTries));
            if (requestSwitch(m_currentNodeId, /*tunnelUp=*/true, QStringLiteral("dead (re-up same node)")))
                return true;
        }
    }
    // --- Шаг 3: другая нода ------------------------------------------------------------------------
    // AVPN awg31-xray-v1: провал data-plane текущей ноды — в историю транспортов и в сессионный
    // список (failover не ходит по кругу awg↔xray одной локации).
    // GAPFIX-1: новый (не опробованный) конфиг текущей ноды провалом не считаем — умер старый.
    if (!untriedConfig)
        noteDataPlaneFailure();
    // AVPN (независимое ревью волны, MAJOR-1): кап подряд идущих провалов data-plane за сессию.
    // Мёртвый data-plane (captive portal, ТСПУ, «интернета нет вообще») одинаково валит ЛЮБОГО
    // кандидата, а третья ветка выбора ниже (withExclusions=false) осознанно игнорирует
    // m_failedThisSession — без капа цикл up → verifying → verifyFailed → down → up крутится
    // вечно и молча. Исчерпали — честный Error; намерение снимает фасад (§13).
    if (m_dataPlaneFailStreak >= dataPlaneFailMaxTriesTuned()) {
        m_dataPlaneExhausted = true;
        appendSwitchLog(QStringLiteral("data-plane dead: %1 failures in a row — giving up")
                            .arg(m_dataPlaneFailStreak));
        m_state = EngineState::Error;
        return false;
    }
    // AVPN (ревью волны, MAJOR-2): kill-switch xray_client мог погаснуть уже в этой сессии.
    normalizeTransportMode();
    m_state = EngineState::Switching;
    // выбрать лучшего кандидата, ИСКЛЮЧАЯ текущую (мёртвую) ноду. СТРОГО БЕЗ I/O (CONNECT-INVARIANTS §1):
    // onDead зовётся из health-tick/notifyConnectionLost на GUI-потоке БЕЗ гарда m_inSyncNetCall —
    // прежний Selector::pick крутил вложенный QEventLoop TCP-пинга до 3с, и queued Disconnected успевал
    // войти в reconcile ПОВЕРХ этого стека (back-to-back up→down, запрещено §2). При AWG (UDP-only)
    // TCP-пинг всё равно пуст почти всегда. Приоритет как в connect(): измеренный RTT → weight.
    // Закрепление НЕ учитываем (spec §24-26): при смерти закреплённой уходим на лучшую живую.
    // AVPN awg31-xray-v1 (§2.3): сначала ДРУГОЙ ТРАНСПОРТ ТОЙ ЖЕ ЛОКАЦИИ (исключая провалившиеся в
    // этой сессии), потом соседняя локация; kill-switch transport_auto_pick=false → легаси (только awg).
    // AVPN (фикс-волна 2026-09-22, B9): RTT — последний известный (свежий кэш в connected пуст:
    // замеры запрещены, TTL 120 с) с пометкой возраста в switchLog, не монета по весам.
    // B3: identity неизвестна → локации нет, exclA пуст — авто-выбор из всего пула.
    std::optional<SubscriptionNode> candidate;
    const bool autoPick = TuningStore::flag(QStringLiteral("transport_auto_pick"), true);
    if (autoPick || m_transportMode != TransportMode::Auto) {
        const QString loc = deadLocation.isEmpty() ? currentLocation() : deadLocation;
        const SubscriptionNode *c = nullptr;
        if (!loc.isEmpty())
            c = pickTransport(loc, QString(), m_currentNodeId, /*withExclusions=*/true, /*lastKnownRtt=*/true);
        if (!c)
            c = pickTransport(QString(), QString(), m_currentNodeId, /*withExclusions=*/true, /*lastKnownRtt=*/true);
        if (!c && !m_failedThisSession.isEmpty())
            c = pickTransport(QString(), QString(), m_currentNodeId, /*withExclusions=*/false, /*lastKnownRtt=*/true);
        if (c)
            candidate = *c;
    } else {
        if (const SubscriptionNode *fast = pickByMeasuredRtt(m_currentNodeId, QString())) // AVPN
            candidate = *fast;
        if (!candidate) {
            if (const SubscriptionNode *best = pickByWeight(m_currentNodeId, QString())) // AVPN
                candidate = *best;
        }
    }
    if (!candidate) {
        m_state = EngineState::Error;
        return false;
    }
    QString switchReason = reason;
    if (!measuredRtt().contains(candidate->nodeId)) {
        const qint64 age = lastKnownRttAgeMs(candidate->nodeId);
        if (age >= 0)
            switchReason += QStringLiteral(" rtt_age=%1s").arg(age / 1000);
    }
    // AVPN: через двухфазный секвенс-свитч (без back-to-back down+up — iOS-safe; без failover-гонки).
    return requestSwitch(candidate->nodeId, tunnelStillUp, switchReason);
}

// AVPN (фикс iOS-шторма свитча): двухфазный секвенс-свитч — см. объявление в ServiceEngine.h.
bool ServiceEngine::requestSwitch(const QString &targetNodeId, bool tunnelUp, const QString &reason)
{
    if (!m_tunnel) { m_state = EngineState::Error; return false; }
    // Task 10: цель с неподдерживаемым proto = «нет такой ноды» — up() на неё заведомо мёртв
    // (страховка последнего рубежа: все выборные пути её уже отфильтровали).
    bool found = false;
    for (const SubscriptionNode &n : m_pool.nodes())
        if (n.nodeId == targetNodeId) { found = isSupportedProtoNode(n); break; }
    if (!found)
        return false;
    m_pendingSwitchNodeId = targetNodeId;
    m_pendingSwitchReason = reason;
    m_pendingSwitchIsReup = (reason == QLatin1String("dead (re-up same node)"));
    m_state = EngineState::Switching;       // гард: transient Disconnected/Error от down() не триггерит failover
    // AVPN (фикс-волна 2026-09-22, B4): часы фазы down (до реального Disconnected старого рантайма).
    m_switchStartedMs = nowMs();
    m_switchUpPhase = false;
    m_rebindAwaiting = false;
    m_interrupted = InterruptedSwitch{};
    m_health.reset();
    if (tunnelUp) {
        m_tunnel->down();                   // ждём реальный Disconnected → continuePendingSwitch() поднимет up()
        return true;
    }
    return continuePendingSwitch();         // туннель уже опущен → up() сразу
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

bool ServiceEngine::continuePendingSwitch() // AVPN
{
    if (m_pendingSwitchNodeId.isEmpty())
        return false;
    // GAP-1 (U7): старый рантайм уже опущен — отложенный reseed (пришёл в фазе down или при Connected
    // с изменённой identity цели/текущей) применяем ДО up(): цель поднимается по актуальному конфигу.
    {
        const SubscriptionNode *before = findNode(m_pendingSwitchNodeId);
        const QString targetLocation = before ? locationKeyOf(*before) : QString();
        if (applyPendingReseedBetweenRuntimes()) {
            const SubscriptionNode *t = findNode(m_pendingSwitchNodeId);
            if (!t || !isSupportedProtoNode(*t) || healthAggregate(*t) <= 0.0
                || !transportAllowed(*t, m_transportMode)) {
                // Цель исчезла/выведена новым пулом → шаг 3 с предпочтением её локации.
                const QString gone = m_pendingSwitchNodeId;
                const SubscriptionNode *c = nullptr;
                if (!targetLocation.isEmpty())
                    c = pickTransport(targetLocation, QString(), gone, /*withExclusions=*/true, /*lastKnownRtt=*/true);
                if (!c)
                    c = pickTransport(QString(), QString(), gone, /*withExclusions=*/true, /*lastKnownRtt=*/true);
                if (!c && !m_failedThisSession.isEmpty())
                    c = pickTransport(QString(), QString(), gone, /*withExclusions=*/false, /*lastKnownRtt=*/true);
                if (c) {
                    appendSwitchLog(QStringLiteral("switch target %1 gone after reseed → %2").arg(gone, c->nodeId));
                    m_pendingSwitchNodeId = c->nodeId;
                    if (m_pendingSwitchIsReup)
                        m_pendingSwitchReason = QStringLiteral("dead (failover)");
                    m_pendingSwitchIsReup = false;
                }
            }
        }
    }
    SubscriptionNode target;
    bool found = false;
    for (const SubscriptionNode &n : m_pool.nodes())
        if (n.nodeId == m_pendingSwitchNodeId) { target = n; found = true; break; }
    if (!found || !m_tunnel) {
        noteSwitchInterrupted(QStringLiteral("error_down"));
        m_pendingSwitchNodeId.clear();
        m_pendingSwitchReason.clear();
        m_switchStartedMs = -1;
        m_state = EngineState::Error;
        return true;
    }
    const QString from = m_currentNodeId;
    const QString tid = m_pendingSwitchNodeId;
    const QString reason = m_pendingSwitchReason;
    m_pendingSwitchNodeId.clear();
    m_pendingSwitchReason.clear();
    m_currentNodeId = tid; // AVPN awg31-xray-v1: до up() — история/провал пишутся по фактической цели
    // AVPN (фикс-волна 2026-09-22, B4/H8): часы перезапускаются на фазу up — её бюджет не меньше
    // сторожа коннекта (раньше 15 с делили обе фазы, и легальный медленный failover на сотовой рвался).
    m_switchStartedMs = nowMs();
    m_switchUpPhase = true;
    m_upPhaseReason = reason;
    markUpStarted();
    const TunnelResult r = m_tunnel->up(m_pool.subscription(), target); // прямой up() (без повторного down)
    if (!r.ok) {
        appendSwitchLog(QStringLiteral("switch %1→%2 FAILED: %3").arg(from, tid, r.error));
        noteSwitchInterrupted(QStringLiteral("error_up"));
        m_switchStartedMs = -1;
        m_switchUpPhase = false;
        m_state = EngineState::Error;
        return true;
    }
    appendSwitchLog(QStringLiteral("switch %1→%2: %3").arg(from, tid, reason));
    m_health.reset();
    // остаёмся Switching; onTunnelConnected() подтвердит Connected, когда туннель реально поднимется.
    return true;
}

bool ServiceEngine::expireSwitch(int timeoutMs)
{
    if (m_state != EngineState::Switching || m_switchStartedMs < 0)
        return false;
    // AVPN (фикс-волна 2026-09-22, K5/B4): бюджет — на ТЕКУЩУЮ фазу; фаза up — не меньше сторожа коннекта.
    const qint64 budget = m_switchUpPhase ? qMax<qint64>(timeoutMs, reconcileWatchdogMsTuned())
                                          : qMax<qint64>(0, timeoutMs);
    if (nowMs() - m_switchStartedMs < budget)
        return false;
    const QString phase = m_switchUpPhase ? QStringLiteral("up") : QStringLiteral("down");
    noteSwitchInterrupted(m_switchUpPhase ? QStringLiteral("deadline_up") : QStringLiteral("deadline_down"));
    appendSwitchLog(QStringLiteral("switch deadline (%1 phase): awaiting confirmed native status").arg(phase));
    m_pendingSwitchNodeId.clear();
    m_pendingSwitchReason.clear();
    m_switchStartedMs = -1;
    m_switchUpPhase = false;
    m_pendingSwitchIsReup = false;
    m_state = EngineState::Error;
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
    s.transportMode = transportModeToString(m_transportMode);
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
    for (const SubscriptionNode &n : sub.nodes) {
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
            transportsByLoc.insert(loc, locationTransports(sub.nodes, loc));
        row.transports = transportsByLoc.value(loc);
        row.transportRank = n.transportRank;
        row.transportSupported = isSupportedProtoNode(n);
        row.activeProto = (!curLoc.isEmpty() && loc == curLoc) ? s.activeProto : QString();
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
    bool anySupported = false, anyAllowed = false;
    for (const SubscriptionNode &n : m_pool.nodes()) {
        if (locationKeyOf(n) != loc || !isSupportedProtoNode(n))
            continue;
        anySupported = true;
        if (transportAllowed(n, m_transportMode))
            anyAllowed = true;
    }
    if (!anySupported) {
        // Task 10: нода с неподдерживаемым протоколом непригодна и для РУЧНОГО pin (в отличие от
        // manual_only) — коннект к ней невозможен, честная ошибка вместо вечного Connecting.
        error = QStringLiteral("unsupported_proto: node %1 proto '%2'").arg(nodeId, protoOf(*found));
        return false;
    }
    if (!anyAllowed) {
        error = QStringLiteral("no_transport: location %1 has no '%2' transport")
                    .arg(loc, transportModeToString(m_transportMode));
        return false;
    }
    m_pinnedNodeId = nodeId;
    m_interrupted = InterruptedSwitch{}; // явный выбор пользователя важнее повтора прерванного свитча
    return true;
}

// AVPN (live-node picker): round-robin «Обновить подключение» — по ЛОКАЦИЯМ (NodeRotation.h::
// nextLiveNodeId: представитель следующей живой локации; транспорт внутри выбирает connect()).
bool ServiceEngine::rotateNext(QString &error) // AVPN
{
    // Ручная ротация ≠ «закрепить»: снимаем закрепление, иначе offline-ветка ниже (m_currentNodeId=target
    // → connect()) перебивается приоритетом m_pinnedNodeId в connect() и ротация молча no-op'ит на pin.
    m_pinnedNodeId.clear(); // AVPN
    m_interrupted = InterruptedSwitch{}; // явное действие пользователя
    const QString targetId = nextLiveNodeId();
    if (targetId.isEmpty()) {
        error = QStringLiteral("not enough live nodes to rotate");
        return false;
    }
    // Закрепление снято выше — это ручная ротация, а не «закрепить» (switchToNode).
    if (m_state == EngineState::Connected || m_state == EngineState::Switching
        || m_state == EngineState::Verifying) {
        // Онлайн — двухфазный секвенс-свитч на следующую локацию (iOS-safe, без шторма).
        if (!requestSwitch(targetId, /*tunnelUp=*/true, QStringLiteral("rotate (manual)"))) {
            error = QStringLiteral("rotate failed");
            return false;
        }
        return true;
    }

    // Оффлайн — стартуем туннель с выбранной локации: закрепляем её представителя на время
    // подъёма (connect() выберет транспорт внутри), затем снимаем pin (ротация — не «закрепить»).
    m_pinnedNodeId = targetId;
    const bool ok = connect(error);
    m_pinnedNodeId.clear();
    return ok;
}

// AVPN: следующая живая локация после текущей — чистая версия rotateNext (без свитча/connect). Фасад
// использует для «Обновить подключение» через единый reconcile-контур. Логика (вкл. исключение
// RU-нод из кольца — §14.3, ручной режим транспорта) — в NodeRotation.h, тест tests/node_rotation_check.cpp.
QString ServiceEngine::nextLiveNodeId() const
{
    return avpn::nextLiveNodeId(m_pool.nodes(), m_currentNodeId, m_transportMode);
}

} // namespace avpn
