#include "ServiceEngine.h"
#include "ConnectTunables.h" // AVPN (BUG-4 auto-heal): rebindHealMaxTriesTuned — кламп кап попыток; xray-пороги
#include "NodeRanking.h"  // AVPN (выбор по скорости): fastestMeasuredNodeId
#include "NodeRotation.h" // AVPN: healthAggregate/isRuNode/nextLiveNodeId (чистая логика, тестируется автономно)
#include "SubscriptionParser.h"
#include "TransportPick.h" // AVPN awg31-xray-v1: локации × транспорты, история

#include <QDateTime>
#include <QRandomGenerator> // AVPN: рандомизация авто-выбора среди равных нод (иначе всегда первая = Польша)

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

void ServiceEngine::appendSwitchLog(const QString &line)
{
    m_switchLog.append(line);
    if (m_switchLog.size() > 20)
        m_switchLog.removeFirst();
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
        (isManualOnlyNode(n) ? ruRows : rows).append({ n.nodeId, m_measuredRtt.value(n.nodeId, -1) }); // manual/RU — в fallback
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
                                                     const QString &exclA, bool withExclusions) const
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
    return pickTransportNode(m_pool.nodes(), m_measuredRtt, m_transportHistory, in, randomIndex);
}

bool ServiceEngine::loadSubscription(const QByteArray &json, QString &error)
{
    Subscription sub;
    if (!SubscriptionParser::parse(json, sub, error))
        return false;
    m_pool.setSubscription(sub);
    m_lkgActive = false; // AVPN (LKG): свежие данные с сервера — кэш больше не «маска»
    // AVPN awg31-xray-v1: полная перезагрузка пула (bootstrap/refreshPool) перекрывает отложенный
    // reseed; сессионные провалы узлов старого пула больше не актуальны.
    m_pendingReseed.reset();
    m_failedThisSession.clear();
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
    return a.serverPubkey == b.serverPubkey;
}

bool ServiceEngine::reseedApplicableNow(const Subscription &sub) const
{
    if (m_state == EngineState::Disconnected || m_state == EngineState::Error)
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
    QSet<QString> oldIds, newIds;
    for (const SubscriptionNode &n : old.nodes)
        oldIds.insert(n.nodeId);
    for (const SubscriptionNode &n : sub.nodes)
        newIds.insert(n.nodeId);

    m_pool.setSubscription(sub);
    m_lkgActive = false;
    m_pendingReseed.reset();

    // RTT-кэш и сессионные провалы исчезнувших узлов — сбросить (иначе стейл-замер ранжировал бы
    // призрака, а провал — держал бы новый узел с тем же id в чёрном списке).
    for (auto it = m_measuredRtt.begin(); it != m_measuredRtt.end();) {
        if (!newIds.contains(it.key()))
            it = m_measuredRtt.erase(it);
        else
            ++it;
    }
    m_failedThisSession.intersect(newIds);

    // Ревалидация pin по ЛОКАЦИИ: узел исчез → сосед той же локации (представитель), иначе снять.
    if (!m_pinnedNodeId.isEmpty() && !newIds.contains(m_pinnedNodeId)) {
        QList<const SubscriptionNode *> loc;
        for (const SubscriptionNode &n : m_pool.nodes())
            if (!oldPinLoc.isEmpty() && locationKeyOf(n) == oldPinLoc && isSupportedProtoNode(n))
                loc.append(&n);
        const SubscriptionNode *rep = locationRepresentative(loc);
        m_pinnedNodeId = rep ? rep->nodeId : QString();
    }

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
}

ReseedResult ServiceEngine::reseedPool(const Subscription &sub)
{
    if (sub.nodes.isEmpty())
        return ReseedResult::Rejected;           // пустое тело не затирает пул
    if (sub.poolRevision <= 0)
        return ReseedResult::Rejected;           // старый бэк/LKG без ревизии — reseed не по чему
    if (sub.poolRevision == m_pool.subscription().poolRevision)
        return ReseedResult::Rejected;           // та же выдача
    if (!reseedApplicableNow(sub)) {
        m_pendingReseed = sub;                   // применим при переходе в терминал (applyPendingReseed)
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
    // AVPN awg31-xray-v1: kill-switch автоматики транспортов. Выключен → авто-пути = легаси-цепочка
    // «измеренный RTT → Selector::pick → weight» ТОЛЬКО по awg (xray — ручной режим/pin).
    const bool autoPick = TuningStore::flag(QStringLiteral("transport_auto_pick"), true);
    std::optional<SubscriptionNode> candidate; // AVPN: optional — закрепление/weight-фолбэк ниже
    // AVPN (live-node picker): если пользователь закрепил ноду — стартуем с неё (она есть и жива).
    // Закрепление имеет приоритет над авто-скорингом: «движок не уходит ради скорости» (spec §23-25).
    // AVPN awg31-xray-v1: pin — ПО ЛОКАЦИИ: транспорт внутри закреплённой локации выбирает
    // pickTransport (transport_rank + история + ручной режим + сессионные провалы). Стейл-pin
    // (локация мертва/без поднимаемых узлов) → падаем в авто-выбор вместо заведомо мёртвого up().
    if (!m_pinnedNodeId.isEmpty()) {
        if (const SubscriptionNode *pinned = findNode(m_pinnedNodeId)) {
            const QString loc = locationKeyOf(*pinned);
            const SubscriptionNode *c = pickTransport(loc, m_pinnedNodeId, QString(), /*withExclusions=*/true);
            if (!c && !m_failedThisSession.isEmpty())
                c = pickTransport(loc, m_pinnedNodeId, QString(), /*withExclusions=*/false);
            if (c)
                candidate = *c;
        }
    }
    if (!candidate && (autoPick || m_transportMode != TransportMode::Auto)) {
        // AVPN awg31-xray-v1: локация — по измеренному off-tunnel RTT (кэш AvpnEngineQml::probeNodeRtt),
        // без замеров — weight-ярус (случайно среди равных); транспорт внутри — ранг + история. Без I/O.
        const SubscriptionNode *c = pickTransport(QString(), QString(), QString(), /*withExclusions=*/true);
        if (!c && !m_failedThisSession.isEmpty())
            c = pickTransport(QString(), QString(), QString(), /*withExclusions=*/false);
        if (c)
            candidate = *c;
    }
    if (!candidate && !autoPick && m_transportMode == TransportMode::Auto) {
        // Легаси-цепочка (как до волны awg31-xray-v1; авто = только awg):
        // AVPN (выбор по скорости): «Авто (быстрейший)» — приоритет ноде с МИНИМАЛЬНЫМ ИЗМЕРЕННЫМ RTT
        // (off-tunnel ICMP, кэш из AvpnEngineQml::probeNodeRtt). Это и есть настоящий «быстрейший». Пусто
        // (кэш холодный / UDP-фильтр) → ниже Selector::pick (TCP) → pickByWeight (backend-weight). Без I/O.
        if (const SubscriptionNode *fast = pickByMeasuredRtt(QString(), QString())) // AVPN
            candidate = *fast;
        if (!candidate)
            // AVPN: случайный seed для джиттера среди near-best (иначе seed=0 → всегда первый кандидат).
            candidate = m_selector.pick(m_pool, m_currentNodeId, 75,
                                        QRandomGenerator::global()->generate()); // C-4: TCP-ping → score → choose
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
            if (!loadSubscription(body, error)) // 3) распарсить (NodePool + лимиты/expiresAt)
                return false;
            Enrollment::saveLkgSubscription(body); // AVPN (LKG): персистим ТОЛЬКО валидное тело
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
    if (m_state != EngineState::Connected || !m_tunnel)
        return false;
    const TunnelStats stats = m_tunnel->readStats();
    // AVPN awg31-xray-v1: для xray handshake отсутствует по определению (адаптер эпоху не сеет,
    // 0 = неизвестно → hsStale) — DEAD = tx растёт, rx стоит N циклов (те же пороги); вторая
    // половина критерия — провал живой пробы через туннель (feedProbeResult).
    if (m_health.feed(stats, nowEpoch))
        return onDead(/*tunnelStillUp=*/true, QStringLiteral("dead (failover)")); // health-DEAD: туннель ещё «поднят» → down→ждём→up
    return false;
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
    if (m_state != EngineState::Connected || !currentNodeIsXray())
        return false;
    if (ok) {
        m_probeFailStreak = 0;
        return false;
    }
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
        m_rebindHealTries = 0; // AVPN BUG-4: свежий подъём = новый бюджет heal-попыток
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

bool ServiceEngine::adoptTunnelConnected() // AVPN
{
    // Android-адопт (см. ServiceEngine.h): восстановление факта «туннель жив» после фейкового
    // Disconnected. Из любой фазы, кроме уже-Connected. AVPN awg31-xray-v1: из Verifying тоже не
    // «воскрешаем» — «Подключено» по xray только после пробы (фасад перезапускает верификацию).
    if (m_state == EngineState::Connected || m_state == EngineState::Verifying)
        return false;
    m_state = EngineState::Connected;
    m_health.reset();
    m_rebindHealTries = 0; // AVPN BUG-4: адопт = новая сессия наблюдения
    m_probeFailStreak = 0;
    return true;
}

bool ServiceEngine::onTunnelError() // AVPN
{
    // AVPN: ошибка в фазе down() свитча (iOS иногда рапортует Error вместо чистого Disconnected при
    // тиар-дауне) — это ожидаемо, продолжаем секвенс (up() на целевую), а не валимся в Error.
    if (m_state == EngineState::Switching && !m_pendingSwitchNodeId.isEmpty())
        return continuePendingSwitch();
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
}

bool ServiceEngine::onDead(bool tunnelStillUp, const QString &reasonIn)
{
    const QString reason = reasonIn.isEmpty() ? QStringLiteral("dead (failover)") : reasonIn;
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
    if (tunnelStillUp && m_tunnel && !currentNodeIsXray()
        && reason == QLatin1String("dead (failover)")
        && TuningStore::flag(QStringLiteral("rebind_heal"), true)
        && m_rebindHealTries < rebindHealMaxTriesTuned()
        && m_tunnel->rebindSocket()) {
        ++m_rebindHealTries;
        ++m_rebindHealTotal;
        appendSwitchLog(QStringLiteral("rebind-heal try %1 on %2 (dead data-plane)")
                            .arg(m_rebindHealTries).arg(m_currentNodeId));
        m_health.reset();
        return false; // остаёмся Connected: либо оживёт (rx/handshake), либо DEAD вернётся → failover
    }
    // AVPN awg31-xray-v1: провал data-plane текущей ноды — в историю транспортов и в сессионный
    // список (failover не ходит по кругу awg↔xray одной локации).
    noteDataPlaneFailure();
    m_state = EngineState::Switching;
    // выбрать лучшего кандидата, ИСКЛЮЧАЯ текущую (мёртвую) ноду. СТРОГО БЕЗ I/O (CONNECT-INVARIANTS §1):
    // onDead зовётся из health-tick/notifyConnectionLost на GUI-потоке БЕЗ гарда m_inSyncNetCall —
    // прежний Selector::pick крутил вложенный QEventLoop TCP-пинга до 3с, и queued Disconnected успевал
    // войти в reconcile ПОВЕРХ этого стека (back-to-back up→down, запрещено §2). При AWG (UDP-only)
    // TCP-пинг всё равно пуст почти всегда. Приоритет как в connect(): измеренный RTT → weight.
    // Закрепление НЕ учитываем (spec §24-26): при смерти закреплённой уходим на лучшую живую.
    // AVPN awg31-xray-v1 (§2.3): сначала ДРУГОЙ ТРАНСПОРТ ТОЙ ЖЕ ЛОКАЦИИ (исключая провалившиеся в
    // этой сессии), потом соседняя локация; kill-switch transport_auto_pick=false → легаси (только awg).
    std::optional<SubscriptionNode> candidate;
    const bool autoPick = TuningStore::flag(QStringLiteral("transport_auto_pick"), true);
    if (autoPick || m_transportMode != TransportMode::Auto) {
        const QString loc = currentLocation();
        const SubscriptionNode *c = nullptr;
        if (!loc.isEmpty())
            c = pickTransport(loc, QString(), m_currentNodeId, /*withExclusions=*/true);
        if (!c)
            c = pickTransport(QString(), QString(), m_currentNodeId, /*withExclusions=*/true);
        if (!c && !m_failedThisSession.isEmpty())
            c = pickTransport(QString(), QString(), m_currentNodeId, /*withExclusions=*/false);
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
    // AVPN: через двухфазный секвенс-свитч (без back-to-back down+up — iOS-safe; без failover-гонки).
    return requestSwitch(candidate->nodeId, tunnelStillUp, reason);
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
    m_state = EngineState::Switching;       // гард: transient Disconnected/Error от down() не триггерит failover
    m_health.reset();
    if (tunnelUp) {
        m_tunnel->down();                   // ждём реальный Disconnected → continuePendingSwitch() поднимет up()
        return true;
    }
    return continuePendingSwitch();         // туннель уже опущен → up() сразу
}

bool ServiceEngine::continuePendingSwitch() // AVPN
{
    if (m_pendingSwitchNodeId.isEmpty())
        return false;
    SubscriptionNode target;
    bool found = false;
    for (const SubscriptionNode &n : m_pool.nodes())
        if (n.nodeId == m_pendingSwitchNodeId) { target = n; found = true; break; }
    const QString from = m_currentNodeId;
    const QString tid = m_pendingSwitchNodeId;
    const QString reason = m_pendingSwitchReason;
    m_pendingSwitchNodeId.clear();
    m_pendingSwitchReason.clear();
    if (!found || !m_tunnel) { m_state = EngineState::Error; return true; }
    m_currentNodeId = tid; // AVPN awg31-xray-v1: до up() — история/провал пишутся по фактической цели
    markUpStarted();
    const TunnelResult r = m_tunnel->up(m_pool.subscription(), target); // прямой up() (без повторного down)
    if (!r.ok) {
        appendSwitchLog(QStringLiteral("switch %1→%2 FAILED: %3").arg(from, tid, r.error));
        m_state = EngineState::Error;
        return true;
    }
    appendSwitchLog(QStringLiteral("switch %1→%2: %3").arg(from, tid, reason));
    m_health.reset();
    // остаёмся Switching; onTunnelConnected() подтвердит Connected, когда туннель реально поднимется.
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
        row.scoreMs = m_measuredRtt.value(n.nodeId, 0);
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
    return true;
}

// AVPN (live-node picker): round-robin «Обновить подключение» — по ЛОКАЦИЯМ (NodeRotation.h::
// nextLiveNodeId: представитель следующей живой локации; транспорт внутри выбирает connect()).
bool ServiceEngine::rotateNext(QString &error) // AVPN
{
    // Ручная ротация ≠ «закрепить»: снимаем закрепление, иначе offline-ветка ниже (m_currentNodeId=target
    // → connect()) перебивается приоритетом m_pinnedNodeId в connect() и ротация молча no-op'ит на pin.
    m_pinnedNodeId.clear(); // AVPN
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
