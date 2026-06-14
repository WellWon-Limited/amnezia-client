#include "ServiceEngine.h"
#include "SubscriptionParser.h"

#include <QDateTime>

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

// AVPN (live-node picker): выбор по max weight среди ЖИВЫХ нод, исключая exclA/exclB. Без I/O.
const SubscriptionNode *ServiceEngine::pickByWeight(const QString &exclA, const QString &exclB) const // AVPN
{
    const QList<SubscriptionNode> &all = m_pool.nodes();
    const SubscriptionNode *best = nullptr;
    for (const SubscriptionNode &n : all) {
        if (!exclA.isEmpty() && n.nodeId == exclA)
            continue;
        if (!exclB.isEmpty() && n.nodeId == exclB)
            continue;
        if (healthAggregate(n) <= 0.0) // мёртв по backend-данным (пустой health = живой)
            continue;
        if (!best || n.weight > best->weight)
            best = &n;
    }
    return best;
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
    if (!candidate)
        candidate = m_selector.pick(m_pool, m_currentNodeId); // C-4: TCP-ping → score → choose
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

bool ServiceEngine::startFlow(QNetworkAccessManager *nam, const QString &baseUrl,
                              SecureAppSettingsRepository *store, QString &error)
{
    // 1) токен: из хранилища, иначе enroll (genkey + POST /v1/trial)
    QString token = Enrollment::loadToken(); // AVPN: SecureQSettings-backed
    if (token.isEmpty()) {
        if (!enroll(nam, baseUrl, store, error))
            return false;
        token = m_token;
    } else {
        m_token = token;
        // ключи всё равно нужны для конфига туннеля
        if (!m_identity.ensureKeys(store, error))
            return false;
    }
    // 2) GET /v1/subscription
    QByteArray body;
    if (!Enrollment::fetchSubscription(nam, baseUrl, token, body, error))
        return false;
    // 3) распарсить + 4) подключиться
    if (!loadSubscription(body, error))
        return false;
    return connect(error);
}

bool ServiceEngine::bootstrap(QNetworkAccessManager *nam, const QString &baseUrl,
                              SecureAppSettingsRepository *store, QString &error) // AVPN
{
    // Тихая прогрузка подписки без подъёма туннеля (Task 11). Состояние движка не меняем —
    // остаёмся Disconnected; наполняем только NodePool/Subscription для живого бейджа.
    // 1) токен: из хранилища, иначе enroll (genkey + POST /v1/trial)
    QString token = Enrollment::loadToken(); // AVPN: SecureQSettings-backed
    if (token.isEmpty()) {
        if (!enroll(nam, baseUrl, store, error))
            return false; // оффлайн/без сети — мягко (вызывающий не считает фатальным)
        token = m_token;
    } else {
        m_token = token;
    }
    // 2) GET /v1/subscription
    QByteArray body;
    if (!Enrollment::fetchSubscription(nam, baseUrl, token, body, error))
        return false;
    // 3) распарсить (NodePool + лимиты/expiresAt для бейджа). БЕЗ connect().
    return loadSubscription(body, error);
}

bool ServiceEngine::tick(qint64 nowEpoch)
{
    if (m_state != EngineState::Connected || !m_tunnel)
        return false;
    const TunnelStats stats = m_tunnel->readStats();
    if (m_health.feed(stats, nowEpoch))
        return onDead();
    return false;
}

bool ServiceEngine::notifyConnectionLost()
{
    if (m_state != EngineState::Connected)
        return false;
    return onDead();
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
    if (m_state == EngineState::Error)
        return false;
    m_state = EngineState::Error;
    return true;
}

bool ServiceEngine::onTunnelDisconnected() // AVPN
{
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

bool ServiceEngine::onDead()
{
    m_state = EngineState::Switching;
    // выбрать лучшего кандидата, ИСКЛЮЧАЯ текущую (мёртвую) ноду
    std::optional<SubscriptionNode> candidate =
        m_selector.pick(m_pool, QString(), 75, 0, 3000, m_currentNodeId);
    if (!candidate) {
        // AVPN (live-node picker): weight-фолбэк зеркалит connect() — чинит авто-failover при AWG-UDP,
        // когда TCP-ping не достукивается ни до одной ноды. Берём живую ноду с max weight, исключая
        // мёртвую (текущую). Закрепление НЕ учитываем (spec §24-26): при смерти закреплённой уходим на
        // лучшую живую и остаёмся там — назад сам не прыгаем.
        if (const SubscriptionNode *best = pickByWeight(m_currentNodeId, QString())) // AVPN
            candidate = *best;
    }
    if (!candidate) {
        m_state = EngineState::Error;
        return false;
    }
    const QString from = m_currentNodeId;
    const TunnelResult r = m_switcher.switchTo(m_pool.subscription(), *candidate); // applyPeer (MVP: down+up)
    if (!r.ok) {
        m_switchLog.append(QStringLiteral("switch %1→%2 FAILED: %3")
                               .arg(from, candidate->nodeId, r.error));
        m_state = EngineState::Error;
        return false;
    }
    m_switchLog.append(QStringLiteral("switch %1→%2: dead (no rx, tx grew)").arg(from, candidate->nodeId));
    if (m_switchLog.size() > 20)
        m_switchLog.removeFirst();
    m_currentNodeId = candidate->nodeId;
    m_health.reset();
    m_state = EngineState::Connected;
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

// AVPN (live-node picker): «Закрепить» — пользователь явно выбрал ноду. Запоминаем закрепление и
// либо переключаемся на неё (если онлайн — Switcher), либо стартуем connect() с неё (он уже учитывает
// m_pinnedNodeId). Авто-логика после этого с закреплённой ради скорости не уходит; при её смерти —
// onDead() уведёт на лучшую живую и ОСТАНЕТСЯ там (назад вручную). Spec §23-26.
bool ServiceEngine::switchToNode(const QString &nodeId, QString &error) // AVPN
{
    if (nodeId.isEmpty()) {
        error = QStringLiteral("empty nodeId");
        return false;
    }
    m_pinnedNodeId = nodeId;

    // Найти выбранную ноду в подписке (копия по значению — НЕ кэшируем указатель через сетевой вызов).
    SubscriptionNode target;
    bool found = false;
    for (const SubscriptionNode &n : m_pool.nodes())
        if (n.nodeId == nodeId) { target = n; found = true; break; }
    if (!found) {
        error = QStringLiteral("node not in subscription: %1").arg(nodeId);
        return false;
    }

    if (m_state == EngineState::Connected) {
        // Онлайн — in-place peer swap на закреплённую ноду.
        const QString from = m_currentNodeId;
        const TunnelResult r = m_switcher.switchTo(m_pool.subscription(), target);
        if (!r.ok) {
            m_switchLog.append(QStringLiteral("switch %1→%2 FAILED: %3").arg(from, nodeId, r.error));
            error = r.error;
            m_state = EngineState::Error;
            return false;
        }
        m_switchLog.append(QStringLiteral("switch %1→%2: pinned (manual)").arg(from, nodeId));
        if (m_switchLog.size() > 20)
            m_switchLog.removeFirst();
        m_currentNodeId = nodeId;
        m_health.reset();
        m_state = EngineState::Connected;
        return true;
    }

    // Оффлайн — поднять туннель с закреплённой ноды (connect() уже отдаёт приоритет m_pinnedNodeId).
    return connect(error);
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
    if (m_state == EngineState::Connected) {
        const QString from = m_currentNodeId;
        const TunnelResult r = m_switcher.switchTo(m_pool.subscription(), target);
        if (!r.ok) {
            m_switchLog.append(QStringLiteral("switch %1→%2 FAILED: %3").arg(from, target.nodeId, r.error));
            error = r.error;
            m_state = EngineState::Error;
            return false;
        }
        m_switchLog.append(QStringLiteral("switch %1→%2: rotate (manual)").arg(from, target.nodeId));
        if (m_switchLog.size() > 20)
            m_switchLog.removeFirst();
        m_currentNodeId = target.nodeId;
        m_health.reset();
        m_state = EngineState::Connected;
        return true;
    }

    // Оффлайн — стартуем туннель с выбранной ноды. m_pinnedNodeId уже снят выше (ручная ротация);
    // укажем currentNodeId, чтобы connect() стартовал с выбранной (без приоритета закрепления).
    m_currentNodeId = target.nodeId;
    return connect(error);
}

} // namespace avpn
