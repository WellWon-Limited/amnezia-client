#include "ServiceEngine.h"
#include "NodeRanking.h" // AVPN (выбор по скорости): fastestMeasuredNodeId
#include "SubscriptionParser.h"

#include <QDateTime>
#include <QRandomGenerator> // AVPN: рандомизация авто-выбора среди равных нод (иначе всегда первая = Польша)

// [IN-FORK] токен/хранилище для startFlow:
#include "core/repositories/secureAppSettingsRepository.h"

namespace avpn {

// AVPN (live-node picker): агрегат backend-health узла в [0..1]. Пустой health = 1.0 (живой) — бэкенд
// провижинит узлы /v1/subscription уже живыми, отсутствие телеметрии не значит «мёртв». Среднее по
// всем target'ам (telegram/google/…). См. spec §13-14.
static double healthAggregate(const SubscriptionNode &n) // AVPN
{
    if (n.health.isEmpty())
        return 1.0;
    double sum = 0.0;
    for (auto it = n.health.constBegin(); it != n.health.constEnd(); ++it)
        sum += it.value();
    return sum / static_cast<double>(n.health.size());
}

// AVPN (RU-нода): российская нода (countryCode==RU) обслуживает ТОЛЬКО РФ-сайты (full-tunnel через РФ) —
// в общем VPN на ней не работает ничего. Поэтому её ИСКЛЮЧАЕМ из АВТО-выбора/failover (иначе часто цепляется
// как ближайшая по RTT). Ручной форс (pin) её оставляет — для сценария «за границей зайти на РФ-сайт».
static bool isRuNode(const SubscriptionNode &n)
{
    return n.countryCode.compare(QStringLiteral("RU"), Qt::CaseInsensitive) == 0;
}

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

// AVPN (live-node picker): выбор по max weight среди ЖИВЫХ нод, исключая exclA/exclB. Без I/O.
// RU-ноды — в отдельный fallback-ярус: берём их ТОЛЬКО если живых НЕ-RU нет (не рвём коннект).
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
        if (healthAggregate(n) <= 0.0) // мёртв по backend-данным (пустой health = живой)
            continue;
        if (isRuNode(n)) {             // RU — отдельный fallback-ярус (не в основном выборе)
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
        if (healthAggregate(n) <= 0.0) // мёртв по backend-данным (пустой health = живой)
            continue;
        (isRuNode(n) ? ruRows : rows).append({ n.nodeId, m_measuredRtt.value(n.nodeId, -1) }); // RU — в fallback
    }
    const QString id = fastestMeasuredNodeId(rows.isEmpty() ? ruRows : rows); // fallback на RU если не-RU нет
    if (id.isEmpty())
        return nullptr;
    for (const SubscriptionNode &n : nodes)
        if (n.nodeId == id)
            return &n;
    return nullptr;
}

bool ServiceEngine::loadSubscription(const QByteArray &json, QString &error)
{
    Subscription sub;
    if (!SubscriptionParser::parse(json, sub, error))
        return false;
    m_pool.setSubscription(sub);
    return true;
}

QStringList ServiceEngine::subscriptionIssues() const
{
    return SubscriptionParser::validate(m_pool.subscription());
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
    std::optional<SubscriptionNode> candidate; // AVPN: optional — закрепление/weight-фолбэк ниже
    // AVPN (live-node picker): если пользователь закрепил ноду — стартуем с неё (она есть и жива).
    // Закрепление имеет приоритет над авто-скорингом: «движок не уходит ради скорости» (spec §23-25).
    if (!m_pinnedNodeId.isEmpty()) {
        for (const SubscriptionNode &n : m_pool.nodes())
            if (n.nodeId == m_pinnedNodeId && healthAggregate(n) > 0.0) {
                candidate = n;
                break;
            }
    }
    if (!candidate) {
        // AVPN (выбор по скорости): «Авто (быстрейший)» — приоритет ноде с МИНИМАЛЬНЫМ ИЗМЕРЕННЫМ RTT
        // (off-tunnel ICMP, кэш из AvpnEngineQml::probeNodeRtt). Это и есть настоящий «быстрейший». Пусто
        // (кэш холодный / UDP-фильтр) → ниже Selector::pick (TCP) → pickByWeight (backend-weight). Без I/O.
        if (const SubscriptionNode *fast = pickByMeasuredRtt(QString(), QString())) // AVPN
            candidate = *fast;
    }
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
    if (!candidate) {
        error = QStringLiteral("no nodes available");
        m_state = EngineState::Error;
        return false;
    }
    m_state = EngineState::Connecting;
    m_currentNodeId = candidate->nodeId; // AVPN: фиксируем выбранную ноду уже на фазе Connecting
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
        if (Enrollment::fetchSubscription(nam, baseUrl, token, body, error, &outcome))
            return loadSubscription(body, error); // 3) распарсить (NodePool + лимиты/expiresAt)

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
    if (m_health.feed(stats, nowEpoch))
        return onDead(/*tunnelStillUp=*/true); // health-DEAD: туннель ещё «поднят» → down→ждём→up
    return false;
}

bool ServiceEngine::notifyConnectionLost()
{
    if (m_state != EngineState::Connected)
        return false;
    return onDead(/*tunnelStillUp=*/false); // реальный обрыв: туннель уже опущен → up() сразу
}

// AVPN: правдивые переходы из реального состояния VpnConnection (см. ServiceEngine.h).
bool ServiceEngine::onTunnelConnected() // AVPN
{
    // Подтверждаем Connected ТОЛЬКО из фаз подъёма/свитча — не «воскрешаем» Disconnected/Error.
    if (m_state == EngineState::Connecting || m_state == EngineState::Switching
        || m_state == EngineState::Selecting) {
        m_state = EngineState::Connected;
        m_health.reset();
        return true;
    }
    return false;
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
    // Disconnecting перед reconnect — не сбрасываем).
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
    m_state = EngineState::Disconnected;
    m_currentNodeId.clear();
    m_health.reset();
}

bool ServiceEngine::onDead(bool tunnelStillUp)
{
    m_state = EngineState::Switching;
    // выбрать лучшего кандидата, ИСКЛЮЧАЯ текущую (мёртвую) ноду
    std::optional<SubscriptionNode> candidate =
        m_selector.pick(m_pool, QString(), 75, QRandomGenerator::global()->generate(), 3000, m_currentNodeId);
    if (!candidate) {
        // weight-фолбэк зеркалит connect() — чинит авто-failover при AWG-UDP, когда TCP-ping не
        // достукивается ни до одной ноды. Закрепление НЕ учитываем (spec §24-26): при смерти
        // закреплённой уходим на лучшую живую и остаёмся там — назад сам не прыгаем.
        if (const SubscriptionNode *best = pickByWeight(m_currentNodeId, QString())) // AVPN
            candidate = *best;
    }
    if (!candidate) {
        m_state = EngineState::Error;
        return false;
    }
    // AVPN: через двухфазный секвенс-свитч (без back-to-back down+up — iOS-safe; без failover-гонки).
    return requestSwitch(candidate->nodeId, tunnelStillUp, QStringLiteral("dead (failover)"));
}

// AVPN (фикс iOS-шторма свитча): двухфазный секвенс-свитч — см. объявление в ServiceEngine.h.
bool ServiceEngine::requestSwitch(const QString &targetNodeId, bool tunnelUp, const QString &reason)
{
    if (!m_tunnel) { m_state = EngineState::Error; return false; }
    bool found = false;
    for (const SubscriptionNode &n : m_pool.nodes())
        if (n.nodeId == targetNodeId) { found = true; break; }
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
    const TunnelResult r = m_tunnel->up(m_pool.subscription(), target); // прямой up() (без повторного down)
    if (!r.ok) {
        m_switchLog.append(QStringLiteral("switch %1→%2 FAILED: %3").arg(from, tid, r.error));
        m_state = EngineState::Error;
        return true;
    }
    m_switchLog.append(QStringLiteral("switch %1→%2: %3").arg(from, tid, reason));
    if (m_switchLog.size() > 20)
        m_switchLog.removeFirst();
    m_currentNodeId = tid;
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
    s.lkgStale = false; // TODO(C-7): отражать stale-LKG при offline-подъёме

    // реальные рантайм-статы туннеля
    if (m_tunnel) {
        const TunnelStats st = m_tunnel->readStats();
        s.rxBytes = st.rxBytes;
        s.txBytes = st.txBytes;
        s.latestHandshakeAgeSec = (st.latestHandshakeEpoch > 0)
            ? (QDateTime::currentSecsSinceEpoch() - st.latestHandshakeEpoch)
            : -1;
    }

    for (const SubscriptionNode &n : sub.nodes) {
        NodeDebugRow row;
        row.nodeId = n.nodeId;
        row.region = n.region;
        row.name = n.name;         // AVPN: имя сервера (опц.)
        row.countryCode = n.countryCode; // AVPN: ISO-3166 alpha-2 → флаг-эмодзи в UI
        row.endpoint = n.endpoint; // AVPN: реальный host:port для UI
        // AVPN (live-node picker): обогащаем строку backend-данными (weight + health-агрегат). Источник
        // правды — подписка; TCP-RTT не показываем (AWG = UDP). alive/current → акцент/бары в шторке.
        const double agg = healthAggregate(n);
        row.weight = n.weight;
        row.healthAgg = agg;
        row.alive = agg > 0.0;
        row.current = (n.nodeId == m_currentNodeId);
        row.healthy = row.alive; // легаси-поле: теперь = alive (backend), не заглушка true
        row.reason = (n.nodeId == m_currentNodeId) ? QStringLiteral("current") : QString();
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
bool ServiceEngine::setPinnedNode(const QString &nodeId, QString &error) // AVPN
{
    if (nodeId.isEmpty()) {
        error = QStringLiteral("empty nodeId");
        return false;
    }
    // Узел должен существовать в подписке (иначе нечего закреплять/поднимать).
    bool found = false;
    for (const SubscriptionNode &n : m_pool.nodes())
        if (n.nodeId == nodeId) { found = true; break; }
    if (!found) {
        error = QStringLiteral("node not in subscription: %1").arg(nodeId);
        return false;
    }
    m_pinnedNodeId = nodeId;
    return true;
}

// AVPN (live-node picker): round-robin «Обновить подключение». Список ЖИВЫХ нод (health-агрегат > 0;
// пустой health = живой), детерминированная сортировка (weight↓ / health↓ / nodeId↑ — устойчивая,
// без джиттера). Круговой индекс от текущей → следующая (заворот); 2 узла → пинг-понг.
bool ServiceEngine::rotateNext(QString &error) // AVPN
{
    // Ручная ротация ≠ «закрепить»: снимаем закрепление, иначе offline-ветка ниже (m_currentNodeId=target
    // → connect()) перебивается приоритетом m_pinnedNodeId в connect() и ротация молча no-op'ит на pin.
    m_pinnedNodeId.clear(); // AVPN
    QList<SubscriptionNode> live;
    for (const SubscriptionNode &n : m_pool.nodes())
        if (healthAggregate(n) > 0.0)
            live.append(n);
    if (live.size() < 2) {
        error = QStringLiteral("not enough live nodes to rotate");
        return false;
    }
    std::sort(live.begin(), live.end(), [](const SubscriptionNode &a, const SubscriptionNode &b) {
        if (a.weight != b.weight)
            return a.weight > b.weight;               // weight↓
        const double ha = healthAggregate(a), hb = healthAggregate(b);
        if (ha != hb)
            return ha > hb;                           // health↓
        return a.nodeId < b.nodeId;                   // nodeId↑ (tie-break — против застревания)
    });

    int cur = -1;
    for (int i = 0; i < live.size(); ++i)
        if (live.at(i).nodeId == m_currentNodeId) { cur = i; break; }
    const int next = (cur < 0) ? 0 : (cur + 1) % live.size();
    const SubscriptionNode target = live.at(next); // копия по значению

    // Закрепление снято выше — это ручная ротация, а не «закрепить» (switchToNode).
    if (m_state == EngineState::Connected || m_state == EngineState::Switching) {
        // Онлайн — двухфазный секвенс-свитч на следующую ноду (iOS-safe, без шторма).
        if (!requestSwitch(target.nodeId, /*tunnelUp=*/true, QStringLiteral("rotate (manual)"))) {
            error = QStringLiteral("rotate failed");
            return false;
        }
        return true;
    }

    // Оффлайн — стартуем туннель с выбранной ноды. m_pinnedNodeId уже снят выше (ручная ротация);
    // укажем currentNodeId, чтобы connect() стартовал с выбранной (без приоритета закрепления).
    m_currentNodeId = target.nodeId;
    return connect(error);
}

// AVPN: следующая живая нода после текущей — чистая версия rotateNext (без свитча/connect). Фасад
// использует для «Обновить подключение» через единый reconcile-контур. Та же сортировка, что rotateNext.
QString ServiceEngine::nextLiveNodeId() const
{
    QList<SubscriptionNode> live;
    for (const SubscriptionNode &n : m_pool.nodes())
        if (healthAggregate(n) > 0.0)
            live.append(n);
    if (live.size() < 2)
        return QString();
    std::sort(live.begin(), live.end(), [](const SubscriptionNode &a, const SubscriptionNode &b) {
        if (a.weight != b.weight)
            return a.weight > b.weight;
        const double ha = healthAggregate(a), hb = healthAggregate(b);
        if (ha != hb)
            return ha > hb;
        return a.nodeId < b.nodeId;
    });
    int cur = -1;
    for (int i = 0; i < live.size(); ++i)
        if (live.at(i).nodeId == m_currentNodeId) { cur = i; break; }
    const int next = (cur < 0) ? 0 : (cur + 1) % live.size();
    return live.at(next).nodeId;
}

} // namespace avpn
