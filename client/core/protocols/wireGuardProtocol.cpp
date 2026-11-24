#include <QCoreApplication>
#include <QFileInfo>
#include <QProcess>
#include <QTcpSocket>
#include <QThread>

#include "wireGuardProtocol.h"
#include "core/utils/networkUtilities.h"

#include "mozilla/localsocketcontroller.h"

WireguardProtocol::WireguardProtocol(const QJsonObject &configuration, QObject *parent)
    : VpnProtocol(configuration, parent)
{
    m_impl.reset(new LocalSocketController());
    connect(m_impl.get(), &ControllerImpl::connected, this,
            [this](const QString &pubkey, const QDateTime &connectionTimestamp) {
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

    connect(m_impl.get(), &ControllerImpl::daemonSocketLost, this, &WireguardProtocol::daemonSocketLost);
    connect(m_impl.get(), &ControllerImpl::disconnected, this,
            [this]() { setConnectionState(Vpn::ConnectionState::Disconnected); });
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

    m_impl->activate(m_rawConfig);
    return ErrorCode::NoError;
}

ErrorCode WireguardProtocol::stopMzImpl()
{
    if (m_impl) // AVPN (BUG-6): released to the daemon at quit - nothing to stop from here
        m_impl->deactivate();
    return ErrorCode::NoError;
}

// AVPN (BUG-6, macOS, round mac-B: quit with AmneziaWG connected tore the tunnel down - the app's teardown destroyed
// this protocol and ~WireguardProtocol's stop() sent "deactivate", although ~AmneziaApplication no longer calls
// disconnectFromVpn). The controller goes without a word to the daemon: ~LocalSocketController closes the socket, the
// daemon keeps the interface, the next launch adopts it (probeDaemonTunnelOnStartup).
void WireguardProtocol::releaseSessionToDaemon()
{
    if (!m_impl)
        return;
    m_impl->disconnect(this);
    m_impl.reset();
}


ErrorCode WireguardProtocol::start()
{
    return startMzImpl();
}

// AVPN (волна-3): см. wireGuardProtocol.h.
void WireguardProtocol::requestStatus()
{
    if (m_impl)
        m_impl->checkStatus();
}
