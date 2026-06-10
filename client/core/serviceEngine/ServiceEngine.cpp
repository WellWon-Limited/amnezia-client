#include "ServiceEngine.h"
#include "SubscriptionParser.h"

#include <QDateTime>

// [IN-FORK] токен/хранилище для startFlow:
#include "core/repositories/secureAppSettingsRepository.h"

namespace avpn {

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
    const auto candidate = m_selector.pick(m_pool, m_currentNodeId); // C-4: TCP-ping → score → choose
    if (!candidate) {
        error = QStringLiteral("no nodes available");
        m_state = EngineState::Error;
        return false;
    }
    m_state = EngineState::Connecting;
    const TunnelResult r = m_tunnel->up(m_pool.subscription(), *candidate);
    if (!r.ok) {
        error = r.error;
        m_state = EngineState::Error;
        return false;
    }
    m_currentNodeId = candidate->nodeId;
    m_health.reset();
    m_state = EngineState::Connected;
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

bool ServiceEngine::onDead()
{
    m_state = EngineState::Switching;
    // выбрать лучшего кандидата, ИСКЛЮЧАЯ текущую (мёртвую) ноду
    const auto candidate = m_selector.pick(m_pool, QString(), 75, 0, 3000, m_currentNodeId);
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
        row.healthy = true; // TODO(C-4 proactive): хранить измеренный score/health пула
        row.reason = (n.nodeId == m_currentNodeId) ? QStringLiteral("current") : QString();
        s.pool << row;
    }
    s.switchLog = m_switchLog;
    return s;
}

} // namespace avpn
