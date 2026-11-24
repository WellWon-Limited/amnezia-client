#include "xrayProtocol.h"

#include "core/protocols/protocolUtils.h"
#include "core/utils/constants/configKeys.h"
#include "core/utils/constants/protocolConstants.h"
#include "core/utils/ipcClient.h"
#include "core/utils/networkUtilities.h"
#include "core/utils/serialization/serialization.h"
#include "ipc.h"

#include <QCryptographicHash>
#include <QJsonDocument>
#include <QTimer>
#include <QJsonObject>
#include <QNetworkInterface>
#include <QRegularExpression>
#include <QThread>
#include <QtCore/qlogging.h>
#include <QtCore/qobjectdefs.h>
#include <QtCore/qprocess.h>

#include <exception>
#include <utility>

#ifdef Q_OS_MACOS
static const QString tunName = "utun22";
#else
static const QString tunName = "tun2";
#endif

#ifdef Q_OS_WIN
// AVPN (upstream nodes, release C): the envelope of an upstream (provider) node says so in
// tribeSessionMetadata.upstream (serviceEngine XrayConfigBuilder::buildUpstream).
static bool avpnUpstreamSession(const QJsonObject &rawConfig)
{
    return rawConfig.value(QStringLiteral("tribeSessionMetadata")).toObject().value(QStringLiteral("upstream")).toInt() == 1;
}

// AVPN (upstream nodes, release C): the default-route interface (the service's own choice for the core's
// sockets); no such interface -> the route lookup as for an own node. The peer rules keep vpnServer =
// 192.0.2.1: the service appends it to its permits and needs a valid address; a TEST-NET-1 permit is inert,
// and the core's sockets need none (the firewall permits Tribe-service.exe by app id).
static int avpnUpstreamUplinkIndex(const QString &displayHost)
{
    const int idx = NetworkUtilities::getGatewayAndIface().second.index();
    return idx > 0 ? idx : NetworkUtilities::AdapterIndexTo(QHostAddress(displayHost));
}
#endif

XrayProtocol::XrayProtocol(const QJsonObject &configuration, QObject *parent) : VpnProtocol(configuration, parent)
{
    m_vpnGateway = amnezia::protocols::xray::defaultLocalAddr;
    m_vpnLocalAddress = amnezia::protocols::xray::defaultLocalAddr;
    m_routeGateway = NetworkUtilities::getGatewayAndIface().first;

    m_routeMode = static_cast<amnezia::RouteMode>(configuration.value(amnezia::configKey::splitTunnelType).toInt());
    m_remoteAddress = NetworkUtilities::getIPAddress(m_rawConfig.value(amnezia::configKey::hostName).toString());

    const QString primaryDns = configuration.value(amnezia::configKey::dns1).toString();
    m_dnsServers.push_back(QHostAddress(primaryDns));
    if (primaryDns != amnezia::protocols::dns::amneziaDnsIp) {
        const QString secondaryDns = configuration.value(amnezia::configKey::dns2).toString();
        m_dnsServers.push_back(QHostAddress(secondaryDns));
    }

    QJsonObject xrayConfiguration = configuration.value(ProtocolUtils::key_proto_config_data(Proto::Xray)).toObject();
    if (xrayConfiguration.isEmpty()) {
        xrayConfiguration = configuration.value(ProtocolUtils::key_proto_config_data(Proto::SSXray)).toObject();
    }

    if (xrayConfiguration.isEmpty()) {
        qWarning() << "Xray config wrapper is empty";
        m_xrayConfig = {};
    }

    m_xrayConfig = QJsonDocument::fromJson(xrayConfiguration.value(amnezia::configKey::config).toString().toUtf8()).object();
    if (m_xrayConfig.isEmpty()) {
        qWarning() << "Xray config string is not a valid JSON object";
        m_xrayConfig = {};
    }
}

XrayProtocol::~XrayProtocol()
{
    qDebug() << "XrayProtocol::~XrayProtocol()";
    // AVPN: the session ends with the object, but nothing is emitted from a destructor - a receiver may be the
    // VpnConnection that is being destroyed itself.
    endSession(false);
}

ErrorCode XrayProtocol::start()
{
    qDebug() << "XrayProtocol::start()";
    const quint64 session = ++m_session; // AVPN: see the header
    m_sessionOpen = true;

    // Inject SOCKS5 auth into the inbound before starting xray.
    // Re-uses existing credentials if the config already has them (e.g. imported config).
    amnezia::serialization::inbounds::InboundCredentials creds;
    try {
        creds = amnezia::serialization::inbounds::EnsureInboundAuth(m_xrayConfig);
    } catch (const std::exception &e) {
        qCritical() << "EnsureInboundAuth failed:" << e.what();
        return ErrorCode::InternalError;
    }
    m_socksUser = creds.username;
    m_socksPassword = creds.password;
    m_socksPort = creds.port;

    QString xrayConfigStr = QJsonDocument(m_xrayConfig).toJson(QJsonDocument::Compact);
    if (xrayConfigStr.isEmpty()) {
        qCritical() << "Xray config is empty";
        return ErrorCode::XrayExecutableCrashed;
    }

    // Fix fingerprint: old configs may contain "Mozilla/5.0" which xray-core rejects.
    // Replace with the correct default at runtime so stale stored configs still work.
    if (xrayConfigStr.contains("Mozilla/5.0", Qt::CaseInsensitive)) {
        xrayConfigStr.replace("Mozilla/5.0", amnezia::protocols::xray::defaultFingerprint,
                              Qt::CaseInsensitive);
        qDebug() << "XrayProtocol: patched legacy fingerprint to"
                 << amnezia::protocols::xray::defaultFingerprint;
    }

    // Fix inbound listen address: old configs may use "10.33.0.2" which doesn't exist
    // until TUN is created. xray must listen on 127.0.0.1 so tun2socks can connect.
    if (xrayConfigStr.contains(amnezia::protocols::xray::defaultLocalAddr)) {
        xrayConfigStr.replace(amnezia::protocols::xray::defaultLocalAddr,
                              amnezia::protocols::xray::defaultLocalListenAddr);
        qDebug() << "XrayProtocol: patched legacy inbound listen address to 127.0.0.1";
    }

    return IpcClient::withInterface(
            [&](QSharedPointer<IpcInterfaceReplica> iface) {
                const QPointer<XrayProtocol> self(this); // AVPN
                auto xrayStart = iface->xrayStart(xrayConfigStr);
                const bool started = xrayStart.waitForFinished() && xrayStart.returnValue();
                // AVPN: the wait ran the event loop - a stop that came meanwhile has ended this start.
                if (!self || m_session != session)
                    return ErrorCode::NoError;
                if (!started) {
                    qCritical() << "Failed to start xray";
                    return ErrorCode::XrayExecutableCrashed;
                }
                return startTun2Socks(session);
            },
            []() { return ErrorCode::AmneziaServiceConnectionFailed; });
}

void XrayProtocol::stop()
{
    qDebug() << "XrayProtocol::stop()";
    endSession(true);
}

// AVPN (review F1): a failure of the running session ends it and reports the error - only when this object
// outlived the teardown (its IPC waits run the event loop; a disconnect delivered there destroys the protocol).
void XrayProtocol::failSession(ErrorCode error)
{
    if (endSession(true))
        setLastError(error);
}

bool XrayProtocol::endSession(bool reportDisconnected)
{
    // AVPN (macOS quit and crash 24.11.2026): the session ends here, first of all for its own continuations
    // (reads, routing, retries) and for the tun2socks replica - its signals used to reach this object while
    // the teardown below waited on the service, and its finished handler re-entered stop(). The service is torn
    // down once per started session: a second stop (~XrayProtocol after a failover stop) only reports
    // Disconnected; it used to stop the core twice.
    ++m_session;
    const bool tearDown = std::exchange(m_sessionOpen, false);
    if (m_tun2socksReader) {
        m_tun2socksReader->stop();
        m_tun2socksReader->deleteLater();
        m_tun2socksReader = nullptr;
    }
    if (m_tun2socksProcess)
        QObject::disconnect(m_tun2socksProcess.data(), nullptr, this, nullptr);

    const QPointer<XrayProtocol> self(this);
    if (tearDown) {
        IpcClient::withInterface([](QSharedPointer<IpcInterfaceReplica> iface) {
            auto disableKillSwitch = iface->disableKillSwitch();
            if (!disableKillSwitch.waitForFinished() || !disableKillSwitch.returnValue())
                qWarning() << "Failed to disable killswitch";

            auto StartRoutingIpv6 = iface->StartRoutingIpv6();
            if (!StartRoutingIpv6.waitForFinished() || !StartRoutingIpv6.returnValue())
                qWarning() << "Failed to start routing ipv6";

            auto restoreResolvers = iface->restoreResolvers();
            if (!restoreResolvers.waitForFinished() || !restoreResolvers.returnValue())
                qWarning() << "Failed to restore resolvers";

            auto deleteTun = iface->deleteTun(tunName);
            if (!deleteTun.waitForFinished() || !deleteTun.returnValue())
                qWarning() << "Failed to delete tun";

            auto xrayStop = iface->xrayStop();
            if (!xrayStop.waitForFinished() || !xrayStop.returnValue())
                qWarning() << "Failed to stop xray";
        });
        if (!self)
            return false; // AVPN: destroyed by a call the waits above delivered
    }

    if (m_tun2socksProcess) {
        // AVPN: taken out first - a stop that a wait below delivers finds nothing left to end.
        const QSharedPointer<IpcProcessInterfaceReplica> process = std::exchange(m_tun2socksProcess, {});
#ifndef Q_OS_WIN
        // AVPN (macOS quit 24.11.2026): terminate() + close() end the child in the service (SIGTERM, then
        // QProcess::close: SIGKILL and reap) - nothing is awaited from the child. One bounded round trip
        // (waitForFinished(0) returns at once in the service) only makes sure both requests left this process
        // before the replica and its socket go. The former waitForFinished(1000) ran on the main thread on quit
        // (~XrayProtocol after the VpnConnection thread had stopped): no reply could come, the default 30 s
        // passed, and the kill() after it never left this process - tun2socks stayed as an orphan of the
        // service. A replica of another thread cannot send at all, so it is not used: the service ends the
        // child itself when this process's connection to it closes (IpcServer::onProcessControllerLost).
        if (QThread::currentThread() == process->thread()) {
            process->terminate();
            process->close();
            auto delivered = process->waitForFinished(0);
            delivered.waitForFinished(tun2socksStopReplyMs);
        }
#else
        // terminate does not do anything useful on Windows
        // so just kill the process
        process->kill();
        process->close();
#endif
    }
    if (!self)
        return false; // AVPN: destroyed by a call the wait above delivered

    if (reportDisconnected)
        setConnectionState(Vpn::ConnectionState::Disconnected);
    return true;
}

ErrorCode XrayProtocol::startTun2Socks(quint64 session)
{
    const QPointer<XrayProtocol> self(this); // AVPN
    QSharedPointer<IpcProcessInterfaceReplica> process = IpcClient::CreatePrivilegedProcess();
    // AVPN: creating the replica waits on the service (the event loop runs): a stop that came meanwhile has
    // ended this session - the replica is dropped unstarted, the service has no child for it.
    if (!self || m_session != session)
        return ErrorCode::NoError;
    if (!process || !process->waitForSource()) {
        return ErrorCode::AmneziaServiceConnectionFailed;
    }
    if (m_tun2socksReader) { // AVPN: the reader of the previous tun2socks of this session (a retry)
        m_tun2socksReader->stop();
        m_tun2socksReader->deleteLater();
    }
    m_tun2socksProcess = process;
    m_tun2socksStackUp = false;

    const QString proxyUrl = QString("socks5://%1:%2@127.0.0.1:%3").arg(m_socksUser, m_socksPassword, QString::number(m_socksPort));

    m_tun2socksProcess->setProgram(PermittedProcess::Tun2Socks);
    m_tun2socksProcess->setArguments({ "-device", QString("tun://%1").arg(tunName), "-proxy", proxyUrl });

    // AVPN (macOS crash 24.11.2026): one read in flight, no nested event loop (tun2socksOutputReader.h).
    m_tun2socksReader = new avpn::ProcessStderrReader(
            m_tun2socksProcess.data(),
            [this, session](const QList<QByteArray> &lines) { onTun2SocksLines(session, lines); }, this);

    connect(
            m_tun2socksProcess.data(), &IpcProcessInterfaceReplica::finished, this,
            [this, session](int exitCode, QProcess::ExitStatus exitStatus) {
                onTun2SocksFinished(session, exitCode, exitStatus);
            },
            Qt::QueuedConnection);

    m_tun2socksProcess->start();
    return ErrorCode::NoError;
}

void XrayProtocol::onTun2SocksLines(quint64 session, const QList<QByteArray> &lines)
{
    if (m_session != session)
        return;
    // AVPN: the proxy URL carries the per-session socks credentials; the log keeps only the scheme.
    static const QRegularExpression socksUserInfo(QStringLiteral("socks5://[^@\\s\"]*@"));
    bool stackUp = false;
    for (const QByteArray &raw : lines) {
        const QString line = QString::fromUtf8(raw);
        if (!line.contains("[TCP]") && !line.contains("[UDP]"))
            qDebug() << "[tun2socks]:" << QString(line).replace(socksUserInfo, QStringLiteral("socks5://"));
        if (line.contains("[STACK] tun://") && line.contains("<-> socks5://"))
            stackUp = true;
    }
    // AVPN: the routing is set up once per tun2socks process. The output is still read after that (the former
    // disconnect named readyReadStandardOutput and never took effect): the service's QProcess drains the pipe
    // into memory whether anyone reads it or not, and a read empties that buffer.
    if (!stackUp || m_tun2socksStackUp)
        return;
    m_tun2socksStackUp = true;
    const QPointer<XrayProtocol> self(this);
    const ErrorCode res = setupRouting(session);
    if (!self || m_session != session)
        return; // stopped (or destroyed) while the routing was being set up
    if (res != ErrorCode::NoError) {
        failSession(res);
    } else {
        setConnectionState(Vpn::ConnectionState::Connected);
    }
}

void XrayProtocol::onTun2SocksFinished(quint64 session, int exitCode, QProcess::ExitStatus exitStatus)
{
    if (m_session != session || !m_tun2socksProcess)
        return;
    // Check stdout for "resource busy" — the TUN device was not yet released
    // by the previous tun2socks instance. Retry after a short delay.
    // AVPN: read without waiting - a wait here ran the event loop inside this queued slot.
    auto *watcher = new QRemoteObjectPendingCallWatcher(m_tun2socksProcess->readAllStandardOutput(), this);
    connect(watcher, &QRemoteObjectPendingCallWatcher::finished, this,
            [this, watcher, session, exitCode, exitStatus](QRemoteObjectPendingCallWatcher *) {
                watcher->deleteLater();
                const bool resourceBusy = watcher->error() == QRemoteObjectPendingCall::NoError
                        && watcher->returnValue().toByteArray().contains("resource busy");
                onTun2SocksExit(session, resourceBusy, exitCode, exitStatus);
            });
}

void XrayProtocol::onTun2SocksExit(quint64 session, bool resourceBusy, int exitCode, QProcess::ExitStatus exitStatus)
{
    if (m_session != session)
        return;
    if (resourceBusy && m_tun2socksRetryCount < maxTun2SocksRetries) {
        m_tun2socksRetryCount++;
        qWarning() << QString("Tun2socks: TUN resource busy, retrying (%1/%2) in %3ms...")
                              .arg(m_tun2socksRetryCount)
                              .arg(maxTun2SocksRetries)
                              .arg(tun2socksRetryDelayMs);
        QTimer::singleShot(tun2socksRetryDelayMs, this, [this, session]() {
            if (m_session != session)
                return;
            const QPointer<XrayProtocol> self(this);
            const ErrorCode err = startTun2Socks(session);
            if (!self || m_session != session)
                return;
            if (err != ErrorCode::NoError)
                failSession(err);
        });
        return;
    }

    m_tun2socksRetryCount = 0;

    if (exitStatus == QProcess::ExitStatus::CrashExit) {
        qCritical() << "Tun2socks process crashed!";
    } else {
        qCritical() << QString("Tun2socks process was closed with %1 exit code").arg(exitCode);
    }
    failSession(ErrorCode::Tun2SockExecutableCrashed);
}

ErrorCode XrayProtocol::setupRouting(quint64 session)
{
    return IpcClient::withInterface(
            [this, session](QSharedPointer<IpcInterfaceReplica> iface) -> ErrorCode {
                // AVPN: each wait below runs the event loop; a stop that came during one has torn the session
                // down already (its calls are queued after ours on the same connection) - the next step would
                // put the kill switch, DNS or routes back on a session that is over.
                const QPointer<XrayProtocol> self(this);
                const auto ended = [&]() { return !self || m_session != session; };
#ifdef Q_OS_WIN
                // AVPN (upstream nodes, release C): a provider session has no single server - hostName is the
                // display constant 192.0.2.1 and the real dial addresses live inside the Xray config. Its uplink
                // is the default-route interface, the one Tribe-service pins every core socket to
                // (service/server/xray.cpp Xray::startXray -> IP_UNICAST_IF), not a route lookup of a
                // documentation address. Own nodes: unchanged.
                const int inetAdapterIndex = avpnUpstreamSession(m_rawConfig)
                    ? avpnUpstreamUplinkIndex(m_remoteAddress)
                    : NetworkUtilities::AdapterIndexTo(QHostAddress(m_remoteAddress));
#endif
                auto createTun = iface->createTun(tunName, amnezia::protocols::xray::defaultLocalAddr);
                if (!createTun.waitForFinished() || !createTun.returnValue()) {
                    qCritical() << "Failed to assign IP address for TUN";
                    return ErrorCode::InternalError;
                }

                if (ended()) return ErrorCode::NoError; // AVPN
                auto updateResolvers = iface->updateResolvers(tunName, m_dnsServers);
                if (!updateResolvers.waitForFinished() || !updateResolvers.returnValue()) {
                    qCritical() << "Failed to set DNS resolvers for TUN";
                    return ErrorCode::InternalError;
                }

#ifdef Q_OS_WIN
                int vpnAdapterIndex = -1;
                QList<QNetworkInterface> netInterfaces = QNetworkInterface::allInterfaces();
                for (auto &netInterface : netInterfaces) {
                    for (auto &address : netInterface.addressEntries()) {
                        if (m_vpnLocalAddress == address.ip().toString())
                            vpnAdapterIndex = netInterface.index();
                    }
                }
#else
                static const int vpnAdapterIndex = 0;
#endif
                if (ended()) return ErrorCode::NoError; // AVPN
                const bool killSwitchEnabled = QVariant(m_rawConfig.value(configKey::killSwitchOption).toString()).toBool();
                if (killSwitchEnabled) {
                    if (vpnAdapterIndex != -1) {
                        QJsonObject config = m_rawConfig;
                        config.insert("vpnServer", m_remoteAddress);

                        auto enableKillSwitch = IpcClient::Interface()->enableKillSwitch(config, vpnAdapterIndex);
                        if (!enableKillSwitch.waitForFinished() || !enableKillSwitch.returnValue()) {
                            qCritical() << "Failed to enable killswitch";
                            return ErrorCode::InternalError;
                        }
                    } else
                        qWarning() << "Failed to get vpnAdapterIndex. Killswitch disabled";
                }

                if (ended()) return ErrorCode::NoError; // AVPN
                if (m_routeMode == amnezia::RouteMode::VpnAllSites) {
                    static const QStringList subnets = { "1.0.0.0/8",  "2.0.0.0/7",  "4.0.0.0/6",  "8.0.0.0/5",
                                                         "16.0.0.0/4", "32.0.0.0/3", "64.0.0.0/2", "128.0.0.0/1" };

                    auto routeAddList = iface->routeAddList(m_vpnGateway, subnets);
                    if (!routeAddList.waitForFinished() || routeAddList.returnValue() != subnets.count()) {
                        qCritical() << "Failed to set routes for TUN";
                        return ErrorCode::InternalError;
                    }
                }

                if (ended()) return ErrorCode::NoError; // AVPN
                auto StopRoutingIpv6 = iface->StopRoutingIpv6();
                if (!StopRoutingIpv6.waitForFinished() || !StopRoutingIpv6.returnValue()) {
                    qCritical() << "Failed to disable IPv6 routing";
                    return ErrorCode::InternalError;
                }

#ifdef Q_OS_WIN
                if (ended()) return ErrorCode::NoError; // AVPN
                if (inetAdapterIndex != -1 && vpnAdapterIndex != -1) {
                    QJsonObject config = m_rawConfig;
                    config.insert("inetAdapterIndex", inetAdapterIndex);
                    config.insert("vpnAdapterIndex", vpnAdapterIndex);
                    config.insert("vpnGateway", m_vpnGateway);
                    config.insert("vpnServer", m_remoteAddress);

                    auto enablePeerTraffic = iface->enablePeerTraffic(config);
                    if (!enablePeerTraffic.waitForFinished() || !enablePeerTraffic.returnValue()) {
                        qCritical() << "Failed to enable peer traffic";
                        return ErrorCode::InternalError;
                    }
                } else
                    qWarning() << "Failed to get adapter indexes. Split-tunneling disabled";
#endif
                return ErrorCode::NoError;
            },
            []() { return ErrorCode::AmneziaServiceConnectionFailed; });
}
