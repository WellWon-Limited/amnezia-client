#include "AvpnEngineQml.h"

#include "core/repositories/secureAppSettingsRepository.h"
#include "vpnConnection.h"

#include <QDateTime>
#include <QVariantList>

namespace avpn {

AvpnEngineQml::AvpnEngineQml(VpnConnection *conn, SecureAppSettingsRepository *store,
                             QNetworkAccessManager *nam, QObject *parent)
    : QObject(parent), m_tunnel(conn, this), m_store(store), m_nam(nam), m_conn(conn)
{
    m_engine.setTunnel(&m_tunnel);

    // health-loop driver: периодический tick (3–5с).
    m_healthTimer.setInterval(4000);
    connect(&m_healthTimer, &QTimer::timeout, this, &AvpnEngineQml::onTick);

    // реактивный failover: смена состояния туннеля.
    if (m_conn)
        connect(m_conn, &VpnConnection::connectionStateChanged,
                this, &AvpnEngineQml::onConnectionStateChanged, Qt::QueuedConnection);
}

QString AvpnEngineQml::state() const
{
    return debugSnapshot().value(QStringLiteral("state")).toString();
}

void AvpnEngineQml::onTick()
{
    if (m_engine.tick(QDateTime::currentSecsSinceEpoch()))
        emit changed(); // произошёл свитч
}

void AvpnEngineQml::onConnectionStateChanged()
{
    // Если туннель неожиданно отвалился, а движок считает себя подключённым → немедленный свитч.
    if (m_engine.notifyConnectionLost())
        emit changed();
    emit changed();
}

void AvpnEngineQml::start()
{
    if (m_busy)
        return;
    m_busy = true;
    emit changed();

    // Ключи клиента (zero-knowledge) → отдать туннель-адаптеру для сборки конфига.
    QString err;
    if (m_engine.identityEnsureKeys(m_store, err))
        m_tunnel.setClientKeys(m_engine.clientKeys());

    if (!m_engine.startFlow(m_nam, m_baseUrl, m_store, err)) {
        m_busy = false;
        emit error(err);
        emit changed();
        return;
    }
    m_healthTimer.start();
    m_busy = false;
    emit changed();
}

void AvpnEngineQml::stop()
{
    m_healthTimer.stop();
    m_tunnel.down();
    emit changed();
}

void AvpnEngineQml::reprobe()
{
    QString err;
    if (m_engine.connect(err))
        emit changed();
    else
        emit error(err);
}

void AvpnEngineQml::manualSwitch()
{
    if (m_engine.notifyConnectionLost())
        emit changed();
}

void AvpnEngineQml::resetLkg()
{
    Enrollment::clearToken(); // AVPN: SecureQSettings-backed
    emit changed();
}

QVariantMap AvpnEngineQml::debugSnapshot() const
{
    const DebugSnapshot s = m_engine.debugSnapshot();
    QVariantMap m;
    m["state"] = s.state;
    m["currentNodeId"] = s.currentNodeId;
    m["latestHandshakeAgeSec"] = static_cast<qlonglong>(s.latestHandshakeAgeSec);
    m["rxBytes"] = static_cast<qlonglong>(s.rxBytes);
    m["txBytes"] = static_cast<qlonglong>(s.txBytes);
    m["subStatus"] = s.subStatus;
    m["lkgStale"] = s.lkgStale;
    m["trafficUsed"] = static_cast<qlonglong>(s.trafficUsed);
    m["trafficLimit"] = static_cast<qlonglong>(s.trafficLimit);

    QVariantList pool;
    for (const NodeDebugRow &r : s.pool) {
        QVariantMap n;
        n["nodeId"] = r.nodeId;
        n["region"] = r.region;
        n["scoreMs"] = r.scoreMs;
        n["healthy"] = r.healthy;
        n["reason"] = r.reason;
        pool.append(n);
    }
    m["pool"] = pool;

    QVariantList log;
    for (const QString &l : s.switchLog)
        log.append(l);
    m["switchLog"] = log;
    return m;
}

} // namespace avpn
