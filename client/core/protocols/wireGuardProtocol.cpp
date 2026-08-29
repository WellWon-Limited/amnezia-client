#include <QCoreApplication>
#include <QFileInfo>
#include <QProcess>
#include <QTcpSocket>
#include <QThread>
#include <QJsonObject>
#include <QJsonValue>
#include <QSet>
#include <QUuid>

#include "wireGuardProtocol.h"
#include "core/utils/networkUtilities.h"

#include "mozilla/localsocketcontroller.h"

namespace {

bool canonicalDecimal(const QJsonValue &value)
{
    if (!value.isString()) return false;
    const QString text = value.toString();
    if (text.isEmpty() || text.size() > 20
            || (text.size() > 1 && text.startsWith(QLatin1Char('0')))) return false;
    for (const QChar ch : text) {
        if (ch < QLatin1Char('0') || ch > QLatin1Char('9')) return false;
    }
    bool ok = false;
    const quint64 parsed = text.toULongLong(&ok, 10);
    return ok && QString::number(parsed) == text;
}

bool canonicalUuid(const QString &value)
{
    const QUuid uuid(value);
    return !uuid.isNull()
            && uuid.toString(QUuid::WithoutBraces).toLower() == value;
}

} // namespace

WireguardProtocol::WireguardProtocol(const QJsonObject &configuration, QObject *parent)
    : WireguardProtocol(configuration, QString{}, parent)
{
}

WireguardProtocol::WireguardProtocol(const QJsonObject &configuration,
                                     const QString &expectedRuntimeSessionId,
                                     QObject *parent)
    : VpnProtocol(configuration, parent),
      m_expectedRuntimeSessionId(expectedRuntimeSessionId)
{
    m_impl.reset(new LocalSocketController());
    connect(m_impl.get(), &ControllerImpl::connected, this,
            [this](const QString &pubkey, const QDateTime &connectionTimestamp) {
                Q_UNUSED(pubkey);
                Q_UNUSED(connectionTimestamp);
                // Exact catalog-v2 ownership is established only by a typed
                // runtime receipt carrying the preallocated session UUID.
                if (m_expectedRuntimeSessionId.isEmpty())
                    setConnectionState(Vpn::ConnectionState::Connected);
            });
    connect(m_impl.get(), &ControllerImpl::statusUpdated, this,
            [this](const QString& serverIpv4Gateway,
                   const QString& deviceIpv4Address, uint64_t txBytes,
                   uint64_t rxBytes) {
                const QString previousGateway = m_vpnGateway;
                const QString previousLocal = m_vpnLocalAddress;

                if (!serverIpv4Gateway.isEmpty()) {
                    m_vpnGateway = serverIpv4Gateway;
                }
                if (!deviceIpv4Address.isEmpty()) {
                    m_vpnLocalAddress = deviceIpv4Address;
                }

                if ((!m_vpnGateway.isEmpty() && m_vpnGateway != previousGateway) ||
                    (!m_vpnLocalAddress.isEmpty() && m_vpnLocalAddress != previousLocal)) {
                    emit tunnelAddressesUpdated(m_vpnGateway, m_vpnLocalAddress);
                }
            });

    connect(m_impl.get(), &ControllerImpl::disconnected, this,
            [this]() {
                if (m_expectedRuntimeSessionId.isEmpty())
                    setConnectionState(Vpn::ConnectionState::Disconnected);
                else
                    setLastError(ErrorCode::AmneziaServiceConnectionFailed);
            });
    if (auto *local = qobject_cast<LocalSocketController *>(m_impl.get())) {
        connect(local, &LocalSocketController::runtimeStatusChanged,
                this, &WireguardProtocol::consumeExactRuntimeStatus);
    }
    connect(m_impl.get(), &ControllerImpl::initialized, this,
            [this](bool status, bool, const QDateTime &) {
                if (!m_exactAdoptRequested) return;
                auto *local = qobject_cast<LocalSocketController *>(m_impl.get());
                if (!status || !local
                        || !local->adoptExactSession(m_expectedRuntimeSessionId)) {
                    setLastError(ErrorCode::AmneziaServiceConnectionFailed);
                    return;
                }
                m_exactAdoptRequested = false;
            });
    m_impl->initialize(nullptr, nullptr);
}

WireguardProtocol::~WireguardProtocol()
{
    WireguardProtocol::stop();
    QThread::msleep(200);
}

void WireguardProtocol::stop()
{
    stopMzImpl();
    return;
}

ErrorCode WireguardProtocol::startMzImpl()
{
    QString protocolName = m_rawConfig.value("protocol").toString();
    QJsonObject vpnConfigData = m_rawConfig.value(protocolName + "_config_data").toObject();
    vpnConfigData[configKey::hostName] = NetworkUtilities::getIPAddress(vpnConfigData.value(configKey::hostName).toString());
    m_rawConfig.insert(protocolName + "_config_data", vpnConfigData);
    m_rawConfig[configKey::hostName] = NetworkUtilities::getIPAddress(m_rawConfig[configKey::hostName].toString());

    if (!m_expectedRuntimeSessionId.isEmpty()) {
        auto *local = qobject_cast<LocalSocketController *>(m_impl.get());
        if (!local || !canonicalUuid(m_expectedRuntimeSessionId)
                || !local->activateExactSession(m_rawConfig,
                                                m_expectedRuntimeSessionId)) {
            return ErrorCode::AmneziaServiceConnectionFailed;
        }
        setConnectionState(Vpn::ConnectionState::Connecting);
    } else {
        m_impl->activate(m_rawConfig);
    }
    return ErrorCode::NoError;
}

ErrorCode WireguardProtocol::stopMzImpl()
{
    if (!m_expectedRuntimeSessionId.isEmpty()) {
        if (m_exactStopRequested) return ErrorCode::NoError;
        auto *local = qobject_cast<LocalSocketController *>(m_impl.get());
        if (!local || !local->deactivateExactSession(m_expectedRuntimeSessionId)) {
            setLastError(ErrorCode::AmneziaServiceConnectionFailed);
            return ErrorCode::AmneziaServiceConnectionFailed;
        }
        m_exactStopRequested = true;
        setConnectionState(Vpn::ConnectionState::Disconnecting);
    } else {
        m_impl->deactivate();
    }
    return ErrorCode::NoError;
}


ErrorCode WireguardProtocol::start()
{
    return startMzImpl();
}

QJsonObject WireguardProtocol::runtimeStatus() const
{
    return m_runtimeStatus;
}

QString WireguardProtocol::runtimeSessionId() const
{
    return m_expectedRuntimeSessionId;
}

bool WireguardProtocol::adoptExactSession()
{
    if (!canonicalUuid(m_expectedRuntimeSessionId)) return false;
    auto *local = qobject_cast<LocalSocketController *>(m_impl.get());
    if (!local) return false;
    if (local->isReady()) return local->adoptExactSession(m_expectedRuntimeSessionId);
    m_exactAdoptRequested = true;
    return true;
}

void WireguardProtocol::consumeExactRuntimeStatus(const QJsonObject &status)
{
    if (m_expectedRuntimeSessionId.isEmpty()) return;
    const QJsonObject core = status.value(QStringLiteral("core")).toObject();
    const QJsonObject counters = status.value(QStringLiteral("counters")).toObject();
    const QString state = status.value(QStringLiteral("runtime_state")).toString();
    const QString sessionId = status.value(QStringLiteral("session_id")).toString();
    const bool stateValid = state == QLatin1String("starting")
            || state == QLatin1String("running")
            || state == QLatin1String("stopping")
            || state == QLatin1String("stopped")
            || state == QLatin1String("failed");
    bool countersValid = true;
    for (const char *field : {"rx_bytes", "tx_bytes", "rx_packets", "tx_packets",
                              "rx_bytes_delta", "tx_bytes_delta", "rx_packets_delta",
                              "tx_packets_delta", "reset_count"}) {
        countersValid = countersValid
                && canonicalDecimal(counters.value(QLatin1String(field)));
    }
    const bool valid = status.value(QStringLiteral("type"))
                    == QLatin1String("tunnel_runtime_status_v1")
            && status.value(QStringLiteral("schema")).isDouble()
            && status.value(QStringLiteral("schema")).toDouble() == 1.0
            && status.value(QStringLiteral("protocol")) == QLatin1String("awg")
            && sessionId == m_expectedRuntimeSessionId && canonicalUuid(sessionId)
            && stateValid && countersValid
            && core.value(QStringLiteral("adapter")) == QLatin1String("awg-go")
            && core.value(QStringLiteral("abi")) == QLatin1String("awg-uapi-v3.1")
            && core.value(QStringLiteral("version")).isString()
            && core.value(QStringLiteral("runtime_version_probed")).isBool()
            && counters.value(QStringLiteral("available")).isBool()
            && counters.value(QStringLiteral("epoch")) == sessionId;
    if (!valid) {
        qWarning() << "Rejected malformed/stale exact AWG runtime receipt";
        return;
    }

    m_runtimeStatus = status;
    emit runtimeStatusChanged(status);
    if (state == QLatin1String("running")) {
        setConnectionState(Vpn::ConnectionState::Connected);
    } else if (state == QLatin1String("stopping")) {
        setConnectionState(Vpn::ConnectionState::Disconnecting);
    } else if (state == QLatin1String("stopped")) {
        setConnectionState(Vpn::ConnectionState::Disconnected);
    } else if (state == QLatin1String("failed")) {
        setLastError(ErrorCode::InternalError);
    }
}
