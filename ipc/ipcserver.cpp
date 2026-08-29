#include "ipcserver.h"

#include <QDateTime>
#include <QDebug>
#include <QFileInfo>
#include <QHostAddress>
#include <QJsonObject>
#include <QLocalServer>
#include <QLocalSocket>
#include <QObject>
#include <QRemoteObjectHost>
#include <QRemoteObjectNode>
#include <QString>
#include <QStringList>
#include <QRegularExpression>
#include <QProcess>
#include <QSet>
#include <QTimer>

#include "logger.h"
#include "router.h"
#include "killswitch.h"
#include "xray.h"
#include "daemon/daemon.h"

#ifdef Q_OS_MACOS
#include "openvpndnssecurity.h"
#endif

#ifdef Q_OS_WIN
    #include "tapcontroller_win.h"
#endif

namespace {

bool boundedJson(const QJsonObject &object, qsizetype maxBytes = 256 * 1024)
{
    return !object.isEmpty()
            && QJsonDocument(object).toJson(QJsonDocument::Compact).size() <= maxBytes;
}

bool validAddressOrPrefix(const QString &value)
{
    if (value.isEmpty() || value.size() > 96) {
        return false;
    }
    if (!QHostAddress(value).isNull()) {
        return true;
    }
    const auto subnet = QHostAddress::parseSubnet(value);
    return !subnet.first.isNull() && subnet.second >= 0;
}

bool validRouteRequest(const QString &gateway, const QStringList &routes)
{
    if (QHostAddress(gateway).isNull() || routes.isEmpty() || routes.size() > 4096) {
        return false;
    }
    for (const QString &route : routes) {
        if (!validAddressOrPrefix(route)) {
            return false;
        }
    }
    return true;
}

bool validTunName(const QString &name)
{
#ifdef Q_OS_MACOS
    return name == QLatin1String("utun22");
#else
    static const QRegularExpression pattern(
            QStringLiteral(R"(^(?:utun|tun)[0-9]{1,3}$)"));
    return pattern.match(name).hasMatch();
#endif
}

QJsonObject recoveryReceiptFromEvent(const QJsonObject &event,
                                     const QString &action,
                                     const QString &kind,
                                     const QString &reason)
{
    return {
        {QStringLiteral("type"), QStringLiteral("native_session_guard_recovery_v1")},
        {QStringLiteral("schema"), 1}, {QStringLiteral("action"), action},
        {QStringLiteral("kind"), kind},
        {QStringLiteral("operation"), event.value(QStringLiteral("operation"))},
        {QStringLiteral("session"), event.value(QStringLiteral("session"))},
        {QStringLiteral("policy_sha256"), event.value(QStringLiteral("policy_sha256"))},
        {QStringLiteral("outer_session_id"), event.value(QStringLiteral("outer_session_id"))},
        {QStringLiteral("expected_runtime_session_id"),
         event.value(QStringLiteral("expected_runtime_session_id"))},
        {QStringLiteral("reason"), reason},
    };
}

bool recoveryGuardEventShape(const QJsonObject &event)
{
    static const QSet<QString> keys{
        QStringLiteral("type"), QStringLiteral("schema"), QStringLiteral("operation"),
        QStringLiteral("session"), QStringLiteral("kind"),
        QStringLiteral("policy_sha256"), QStringLiteral("outer_session_id"),
        QStringLiteral("expected_runtime_session_id"), QStringLiteral("reason")};
    const QStringList actual = event.keys();
    const QString kind = event.value(QStringLiteral("kind")).toString();
    return QSet<QString>(actual.cbegin(), actual.cend()) == keys
            && event.value(QStringLiteral("type"))
                   == QLatin1String("native_session_guard_v1")
            && event.value(QStringLiteral("schema")).isDouble()
            && event.value(QStringLiteral("schema")).toDouble() == 1.0
            && (kind == QLatin1String("armed") || kind == QLatin1String("lost"));
}

} // namespace


IpcServer::IpcServer(QObject *parent) : IpcInterfaceSource(parent)
#ifdef Q_OS_MACOS
    , m_nativeSessionGuard(
          MacosNativeSessionGuard::Backend{
              [](const QJsonObject &policy) {
                  return KillSwitch::instance()->armNativeSessionGuard(policy);
              },
              []() { return KillSwitch::instance()->releaseNativeSessionGuard(); },
              []() {
                  return KillSwitch::instance()->quarantineNativeSessionGuard();
              },
          },
          QStringLiteral("/Library/Application Support/TribeVPN/guard/"
                         "native-session-guard-v1.json"))
#endif
{
    m_operationClock.start();
    connect(&m_pingHelper, &PingHelper::connectionLose, this, &IpcServer::connectionLose);
}

void IpcServer::setAuthenticatedPeer(
        const amnezia::ipcsecurity::PeerIdentity &identity,
        const QByteArray &sessionCapability, const QString &runtimeDirectory)
{
    m_authenticatedPeer = identity;
    m_parentCapability = sessionCapability;
    m_runtimeDirectory = runtimeDirectory;
    m_operationTimes.clear();
    m_operationClock.restart();
}

void IpcServer::clearAuthenticatedPeer(const QByteArray &sessionCapability)
{
    if (!amnezia::ipcsecurity::constantTimeEqual(
                sessionCapability, m_parentCapability)) {
        return;
    }
#ifdef Q_OS_MACOS
    // Child readers are stopped below, but PF and the exact durable outer lease survive the GUI.
    // A replacement app must resolve the quarantined helper session explicitly.
    m_nativeSessionGuard.authenticatedChannelLost();
    m_channelChildrenStopProven = true;
#endif
    QList<int> stoppedDescriptors;
    for (auto descriptor = m_processes.begin(); descriptor != m_processes.end();
         ++descriptor) {
        descriptor->ipcProcess->kill();
#ifdef Q_OS_MACOS
        const bool childStopped = descriptor->ipcProcess->waitForFinished(3000)
                || descriptor->ipcProcess->state() == QProcess::NotRunning;
        m_channelChildrenStopProven = m_channelChildrenStopProven && childStopped;
        if (childStopped) stoppedDescriptors.append(descriptor.key());
        else {
            qCritical() << "Privileged child did not stop after GUI loss";
            KillSwitch::instance()->disableAllTraffic();
        }
#else
        stoppedDescriptors.append(descriptor.key());
#endif
        descriptor->ipcProcess->close();
        descriptor->localServer->close();
        if (!descriptor->endpoint.isEmpty()) {
            QLocalServer::removeServer(descriptor->endpoint);
        }
    }
    for (const int descriptorId : stoppedDescriptors) {
        removeProcessDescriptor(descriptorId);
    }
    m_authenticatedPeer = {};
    m_parentCapability.clear();
    m_runtimeDirectory.clear();
    m_operationTimes.clear();
}

bool IpcServer::hasAuthenticatedPeer() const
{
#ifdef Q_OS_MACOS
    return m_authenticatedPeer.uid != 0 && m_authenticatedPeer.pid > 1
            && amnezia::ipcsecurity::isCanonicalCapability(m_parentCapability)
            && !m_runtimeDirectory.isEmpty();
#else
    return true;
#endif
}

bool IpcServer::allowOperation(int cost)
{
    if (!hasAuthenticatedPeer() || cost <= 0 || cost > 240) {
        return false;
    }
    const qint64 now = m_operationClock.elapsed();
    while (!m_operationTimes.isEmpty()
           && now - m_operationTimes.head() > 60'000) {
        m_operationTimes.dequeue();
    }
    if (m_operationTimes.size() + cost > 240) {
        qWarning() << "Privileged IPC operation rate exceeded";
        return false;
    }
    for (int index = 0; index < cost; ++index) {
        m_operationTimes.enqueue(now);
    }
    return true;
}

void IpcServer::removeProcessDescriptor(int descriptorId)
{
    auto descriptor = m_processes.find(descriptorId);
    if (descriptor == m_processes.end()) {
        return;
    }
#ifdef Q_OS_MACOS
    if (descriptor->ipcProcess->state() != QProcess::NotRunning) {
        return;
    }
    QString dnsError;
    if (!restoreProcessDns(*descriptor, &dnsError)) {
        qCritical() << "OpenVPN child DNS recovery failed:" << dnsError;
        KillSwitch::instance()->disableAllTraffic();
        const QString session = descriptor->ipcProcess->openVpnDnsSession();
        descriptor->ipcProcess->clearOpenVpnDnsSession();
        retryOpenVpnDnsRecovery(session);
    }
#endif
    descriptor->localServer->close();
    if (!descriptor->endpoint.isEmpty()) {
        QLocalServer::removeServer(descriptor->endpoint);
    }
    m_processes.erase(descriptor);
}

#ifdef Q_OS_MACOS
bool IpcServer::restoreProcessDns(ProcessDescriptor &descriptor, QString *error)
{
    const QString session = descriptor.ipcProcess->openVpnDnsSession();
    if (session.isEmpty()) return true;
    if (descriptor.ipcProcess->state() != QProcess::NotRunning) {
        if (error) *error = QStringLiteral("openvpn_dns_child_still_running");
        return false;
    }
    if (!amnezia::openvpndnssecurity::recoverSession(session, error)) {
        return false;
    }
    descriptor.ipcProcess->clearOpenVpnDnsSession();
    return true;
}

void IpcServer::retryOpenVpnDnsRecovery(const QString &session, int attempt)
{
    if (!amnezia::openvpndnssecurity::validSessionToken(session)) return;
    QString error;
    const bool dnsRecovered = amnezia::openvpndnssecurity::recoverSession(
            session, &error);
    bool childStillRunning = false;
    for (auto descriptor = m_processes.cbegin();
         descriptor != m_processes.cend(); ++descriptor) {
        if (descriptor->ipcProcess->state() != QProcess::NotRunning) {
            childStillRunning = true;
            break;
        }
    }
    if (dnsRecovered && !childStillRunning
            && KillSwitch::instance()->disableKillSwitch()) {
        return;
    }
    if (dnsRecovered) {
        error = childStillRunning
                ? QStringLiteral("privileged_child_still_running")
                : QStringLiteral("emergency_pf_release_failed");
    }
    if (!KillSwitch::instance()->disableAllTraffic()) {
        qCritical() << "Unable to prove emergency PF quarantine";
    }
    qCritical() << "Retrying fail-closed OpenVPN DNS recovery:" << error;
    const int boundedAttempt = qMin(attempt, 8);
    const int delay = qMin(30'000, 250 * (1 << boundedAttempt));
    QTimer::singleShot(delay, this, [this, session, attempt]() {
        retryOpenVpnDnsRecovery(session, qMin(attempt + 1, 1000));
    });
}

void IpcServer::failClosedOpenVpnDns(const QString &error)
{
    qCritical() << "OpenVPN DNS enforcement failed closed:" << error;
    if (!KillSwitch::instance()->disableAllTraffic()) {
        qCritical() << "Unable to prove emergency PF quarantine";
    }
    for (auto descriptor = m_processes.begin(); descriptor != m_processes.end();
         ++descriptor) {
        if (descriptor->ipcProcess->isOpenVpnProcess()
                && descriptor->ipcProcess->state() != QProcess::NotRunning) {
            descriptor->ipcProcess->kill();
            if (!descriptor->ipcProcess->waitForFinished(5000)
                    || descriptor->ipcProcess->state()
                            != QProcess::NotRunning) {
                qCritical() << "OpenVPN child survived fail-closed kill";
            }
        }
    }
}

void IpcServer::shutdownPrivilegedChildren()
{
    QList<int> stoppedDescriptors;
    bool allChildrenStopped = true;
    for (auto descriptor = m_processes.begin(); descriptor != m_processes.end();
         ++descriptor) {
        if (descriptor->ipcProcess->state() != QProcess::NotRunning) {
            descriptor->ipcProcess->kill();
            descriptor->ipcProcess->waitForFinished(5000);
        }
        if (descriptor->ipcProcess->state() == QProcess::NotRunning) {
            stoppedDescriptors.append(descriptor.key());
        } else {
            qCritical() << "Privileged child survived daemon shutdown kill";
            KillSwitch::instance()->disableAllTraffic();
            allChildrenStopped = false;
        }
    }
    for (const int descriptorId : stoppedDescriptors) {
        removeProcessDescriptor(descriptorId);
    }

    // Never restore global DNS while any privileged tunnel child may still be
    // carrying traffic.  Once every child is proven dead, make one final
    // synchronous recovery pass: timers queued by removeProcessDescriptor()
    // cannot be relied upon while the Qt event loop is being torn down.
    if (allChildrenStopped) {
        QString recoveryError;
        if (!amnezia::openvpndnssecurity::recover(&recoveryError)) {
            qCritical() << "Tribe DNS shutdown recovery failed:" << recoveryError;
            KillSwitch::instance()->disableAllTraffic();
        }
    }
}
#endif

int IpcServer::createPrivilegedProcess()
{
#ifdef Q_OS_MACOS
    // Predictable unauthenticated child endpoints are forbidden in production.
    return -1;
#else
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::createPrivilegedProcess";
#endif

    m_localpid++;

    ProcessDescriptor pd(this);

    pd.localServer->setSocketOptions(QLocalServer::WorldAccessOption);

    if (!pd.localServer->listen(amnezia::getIpcProcessUrl(m_localpid))) {
        qDebug() << QString("Unable to start the server: %1.").arg(pd.localServer->errorString());
        return -1;
    }

    // Make sure any connections are handed to QtRO
    QObject::connect(pd.localServer.data(), &QLocalServer::newConnection, this, [pd]() {
        qDebug() << "IpcServer new connection";
        if (pd.serverNode) {
            pd.serverNode->addHostSideConnection(pd.localServer->nextPendingConnection());
            pd.serverNode->enableRemoting(pd.ipcProcess.data());
        }
    });

    QObject::connect(pd.serverNode.data(), &QRemoteObjectHost::error, this,
                     [pd](QRemoteObjectNode::ErrorCode errorCode) { qDebug() << "QRemoteObjectHost::error" << errorCode; });

    QObject::connect(pd.serverNode.data(), &QRemoteObjectHost::destroyed, this, [pd]() { qDebug() << "QRemoteObjectHost::destroyed"; });

    m_processes.insert(m_localpid, pd);

    return m_localpid;
#endif
}

QJsonObject IpcServer::createPrivilegedProcessV2(
        const QString &parentCapability)
{
#ifndef Q_OS_MACOS
    Q_UNUSED(parentCapability);
    return {};
#else
    const QByteArray supplied = parentCapability.toLatin1();
    if (!allowOperation(8)
            || !amnezia::ipcsecurity::isCanonicalCapability(supplied)
            || !amnezia::ipcsecurity::constantTimeEqual(
                    supplied, m_parentCapability)
            || m_processes.size() >= 8) {
        return {};
    }

    const int descriptorId = ++m_localpid;
    ProcessDescriptor descriptor(this);
    descriptor.capability = amnezia::ipcsecurity::randomCapability();
    descriptor.endpoint = m_runtimeDirectory + QStringLiteral("/process-%1.sock")
            .arg(QString::fromLatin1(descriptor.capability.left(22)));
    QString securityError;
    if (!amnezia::ipcsecurity::removeVerifiedStaleSocket(
                descriptor.endpoint, m_authenticatedPeer.uid, &securityError)) {
        qWarning() << "Rejected child IPC endpoint:" << securityError;
        return {};
    }
    descriptor.localServer->setSocketOptions(QLocalServer::UserAccessOption);
    if (!descriptor.localServer->listen(descriptor.endpoint)
            || !amnezia::ipcsecurity::secureSocketFile(
                    descriptor.endpoint, m_authenticatedPeer.uid,
                    m_authenticatedPeer.gid, &securityError)) {
        descriptor.localServer->close();
        QLocalServer::removeServer(descriptor.endpoint);
        qWarning() << "Unable to create secure child IPC endpoint";
        return {};
    }
    descriptor.ipcProcess->setAuthorizedPeerUid(m_authenticatedPeer.uid);
    descriptor.ipcProcess->setRuntimeDirectory(m_runtimeDirectory);
    m_processes.insert(descriptorId, descriptor);

    connect(descriptor.ipcProcess.data(), &IpcServerProcess::finished, this,
            [this, descriptorId](int, QProcess::ExitStatus) {
        // Capture and resolve the immutable DNS owner synchronously while the
        // finished signal is being delivered.  Only QObject/map destruction is
        // deferred; no later IPC mutation can erase the recovery capability.
        auto descriptor = m_processes.find(descriptorId);
        if (descriptor != m_processes.end()
                && descriptor->ipcProcess->state() == QProcess::NotRunning) {
            QString dnsError;
            if (!restoreProcessDns(*descriptor, &dnsError)) {
                qCritical() << "OpenVPN terminal DNS recovery failed:"
                            << dnsError;
                if (!KillSwitch::instance()->disableAllTraffic()) {
                    qCritical() << "Unable to prove emergency PF quarantine";
                }
                const QString session =
                        descriptor->ipcProcess->openVpnDnsSession();
                descriptor->ipcProcess->clearOpenVpnDnsSession();
                retryOpenVpnDnsRecovery(session);
            }
        }
        QTimer::singleShot(0, this, [this, descriptorId]() {
            removeProcessDescriptor(descriptorId);
        });
    });

    connect(descriptor.localServer.data(), &QLocalServer::newConnection, this,
            [this, descriptorId]() {
        auto descriptorIt = m_processes.find(descriptorId);
        if (descriptorIt == m_processes.end()) {
            return;
        }
        while (descriptorIt->localServer->hasPendingConnections()) {
            QLocalSocket *socket = descriptorIt->localServer->nextPendingConnection();
            if (!socket) {
                continue;
            }
            QString securityError;
            amnezia::ipcsecurity::PeerPolicy policy;
            policy.expected = m_authenticatedPeer;
            policy.identifier = QStringLiteral(TRIBE_MAC_GUI_IDENTIFIER);
            policy.teamIdentifier = QStringLiteral(TRIBE_MAC_TEAM_IDENTIFIER);
            amnezia::ipcsecurity::PeerIdentity childIdentity;
            QByteArray childSession;
            if (descriptorIt->capabilityConsumed
                    || !amnezia::ipcsecurity::authorizeSocket(
                            socket, policy, &childIdentity, &securityError)
                    || childIdentity.pid != m_authenticatedPeer.pid
                    || !amnezia::ipcsecurity::performServerHandshake(
                            socket, descriptorIt->capability,
                            &childSession, &securityError)) {
                qWarning() << "Rejected child IPC peer:" << securityError;
                socket->abort();
                socket->deleteLater();
                continue;
            }
            descriptorIt->capabilityConsumed = true;
            descriptorIt->localServer->close();
            QLocalServer::removeServer(descriptorIt->endpoint);
            socket->setReadBufferSize(
                    amnezia::ipcsecurity::kMaxQtRoReadBufferBytes);
            descriptorIt->serverNode->addHostSideConnection(socket);
            descriptorIt->serverNode->enableRemoting(
                    descriptorIt->ipcProcess.data());
            connect(socket, &QLocalSocket::disconnected, this,
                    [this, descriptorId]() {
                auto descriptor = m_processes.find(descriptorId);
                if (descriptor != m_processes.end()
                        && descriptor->ipcProcess->state() == QProcess::NotRunning) {
                    QTimer::singleShot(0, this, [this, descriptorId]() {
                        removeProcessDescriptor(descriptorId);
                    });
                }
            });
        }
    });

    QJsonObject result;
    result.insert(QStringLiteral("schema"), 1);
    result.insert(QStringLiteral("endpoint"), descriptor.endpoint);
    result.insert(QStringLiteral("capability"),
                  QString::fromLatin1(descriptor.capability));
    return result;
#endif
}

int IpcServer::routeAddList(const QString &gw, const QStringList &ips)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::routeAddList";
#endif

    if (!allowOperation() || !validRouteRequest(gw, ips)) {
        return -1;
    }
    return Router::routeAddList(gw, ips);
}

bool IpcServer::clearSavedRoutes()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::clearSavedRoutes";
#endif

    return allowOperation() && Router::clearSavedRoutes();
}

bool IpcServer::routeDeleteList(const QString &gw, const QStringList &ips)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::routeDeleteList";
#endif

    return allowOperation() && validRouteRequest(gw, ips)
            && Router::routeDeleteList(gw, ips);
}

bool IpcServer::flushDns()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::flushDns";
#endif

    return allowOperation() && Router::flushDns();
}

void IpcServer::resetIpStack()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::resetIpStack";
#endif

    if (allowOperation()) {
        Router::resetIpStack();
    }
}

bool IpcServer::checkAndInstallDriver()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::checkAndInstallDriver";
#endif

#ifdef Q_OS_WIN
    return allowOperation() && TapController::checkAndSetup();
#else
    return allowOperation();
#endif
}

QStringList IpcServer::getTapList()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::getTapList";
#endif

#ifdef Q_OS_WIN
    return allowOperation() ? TapController::getTapList() : QStringList{};
#else
    if (!allowOperation()) {
        return {};
    }
    return QStringList();
#endif
}

void IpcServer::cleanUp()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::cleanUp";
#endif

    if (!allowOperation()) {
        return;
    }
    Logger::deInit();
    Logger::cleanUp();
}

void IpcServer::clearLogs()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::clearLogs";
#endif

    if (allowOperation()) {
        Logger::clearLogs(true);
    }
}

bool IpcServer::createTun(const QString &dev, const QString &subnet)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::createTun";
#endif

    return allowOperation() && validTunName(dev)
            && validAddressOrPrefix(subnet) && Router::createTun(dev, subnet);
}

bool IpcServer::deleteTun(const QString &dev)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::deleteTun";
#endif

    return allowOperation() && validTunName(dev) && Router::deleteTun(dev);
}

bool IpcServer::updateResolvers(const QString &ifname, const QList<QHostAddress> &resolvers)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::updateResolvers";
#endif

    if (!allowOperation() || !validTunName(ifname)
            || resolvers.isEmpty() || resolvers.size() > 4) {
        return false;
    }
    for (const QHostAddress &resolver : resolvers) {
        if (resolver.isNull()) {
            return false;
        }
    }
    return Router::updateResolvers(ifname, resolvers);
}

bool IpcServer::restoreResolvers()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::restoreResolvers";
#endif

    return allowOperation() && Router::restoreResolvers();
}

bool IpcServer::StartRoutingIpv6()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::StartRoutingIpv6";
#endif

    return allowOperation() && Router::StartRoutingIpv6();
}

bool IpcServer::StopRoutingIpv6()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::StopRoutingIpv6";
#endif

    return allowOperation() && Router::StopRoutingIpv6();
}

void IpcServer::setLogsEnabled(bool enabled)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::setLogsEnabled";
#endif

    if (!allowOperation()) {
        return;
    }
    if (enabled) {
        Logger::init(true);
    } else {
        Logger::deInit();
    }
}

bool IpcServer::startNetworkCheck(const QString& serverIpv4Gateway, const QString& deviceIpv4Address)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::startNetworkCheck";
#endif

    if (!allowOperation() || QHostAddress(serverIpv4Gateway).protocol()
                != QAbstractSocket::IPv4Protocol
            || QHostAddress(deviceIpv4Address).protocol()
                != QAbstractSocket::IPv4Protocol) {
        return false;
    }
    m_pingHelper.start(serverIpv4Gateway, deviceIpv4Address);
    return true;
}

bool IpcServer::stopNetworkCheck()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::stopNetworkCheck";
#endif

    if (!allowOperation()) {
        return false;
    }
    m_pingHelper.stop();
    return true;
}

bool IpcServer::resetKillSwitchAllowedRange(QStringList ranges)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::resetKillSwitchAllowedRange";
#endif

    if (!allowOperation() || ranges.size() > 4096) {
        return false;
    }
    for (const QString &range : ranges) {
        if (!validAddressOrPrefix(range)) {
            return false;
        }
    }
    return KillSwitch::instance()->resetAllowedRange(ranges);
}

bool IpcServer::addKillSwitchAllowedRange(QStringList ranges)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::addKillSwitchAllowedRange";
#endif

    if (!allowOperation() || ranges.size() > 4096) {
        return false;
    }
    for (const QString &range : ranges) {
        if (!validAddressOrPrefix(range)) {
            return false;
        }
    }
    return KillSwitch::instance()->addAllowedRange(ranges);
}

bool IpcServer::disableAllTraffic()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::disableAllTraffic";
#endif

    return allowOperation() && KillSwitch::instance()->disableAllTraffic();
}

bool IpcServer::enableKillSwitch(const QJsonObject &configStr, int vpnAdapterIndex)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::enableKillSwitch";
#endif

    return allowOperation() && vpnAdapterIndex >= 0 && vpnAdapterIndex < 65536
            && boundedJson(configStr)
            && KillSwitch::instance()->enableKillSwitch(configStr, vpnAdapterIndex);
}

bool IpcServer::disableKillSwitch()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::disableKillSwitch";
#endif

    if (!allowOperation()) return false;
#ifdef Q_OS_MACOS
    for (auto descriptor = m_processes.cbegin();
         descriptor != m_processes.cend(); ++descriptor) {
        if (descriptor->ipcProcess->state() != QProcess::NotRunning) {
            qWarning() << "Refusing PF release while privileged child is running";
            return false;
        }
    }
#endif
    return KillSwitch::instance()->disableKillSwitch();
}

bool IpcServer::enablePeerTraffic(const QJsonObject &configStr)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::enablePeerTraffic";
#endif

    return allowOperation() && boundedJson(configStr)
            && KillSwitch::instance()->enablePeerTraffic(configStr);
}

bool IpcServer::refreshKillSwitch(bool enabled)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::refreshKillSwitch";
#endif

    return allowOperation() && KillSwitch::instance()->refresh(enabled);
}

bool IpcServer::xrayStart(const QString& cfg)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::xrayStart";
#endif

#ifdef Q_OS_MACOS
    Q_UNUSED(cfg);
    return false;
#else
    return allowOperation() && cfg.toUtf8().size() <= 512 * 1024
            && Xray::getInstance().startXray(cfg);
#endif
}

bool IpcServer::xrayStop()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::xrayStop";
#endif

#ifdef Q_OS_MACOS
    return false;
#else
    return allowOperation() && Xray::getInstance().stopXray();
#endif
}

bool IpcServer::xrayStartSession(const QString& sessionId, const QString& cfg)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::xrayStartSession";
#endif
    QJsonParseError parseError;
    const QByteArray encoded = cfg.toUtf8();
    const QJsonDocument document = QJsonDocument::fromJson(encoded, &parseError);
    return allowOperation(4) && encoded.size() <= 512 * 1024
            && parseError.error == QJsonParseError::NoError && document.isObject()
            && Xray::getInstance().startXraySession(sessionId, cfg);
}

bool IpcServer::xrayStopSession(const QString& sessionId)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::xrayStopSession";
#endif
    return allowOperation(2)
            && Xray::getInstance().stopXraySession(sessionId);
}

QJsonObject IpcServer::xrayRuntimeStatusV1(const QString& sessionId)
{
    return allowOperation() ? Xray::getInstance().runtimeStatusV1(sessionId)
                            : QJsonObject{};
}

QJsonObject IpcServer::nativeSessionGuardPrepareV1(const QJsonObject &request)
{
#ifdef Q_OS_MACOS
    return allowOperation(6) && boundedJson(request, 512 * 1024)
        ? m_nativeSessionGuard.prepare(request) : QJsonObject{};
#else
    Q_UNUSED(request)
    return {};
#endif
}

QJsonObject IpcServer::nativeSessionGuardClaimInnerV1(const QJsonObject &request)
{
#ifdef Q_OS_MACOS
    return allowOperation(2) && boundedJson(request)
        ? m_nativeSessionGuard.claimInner(request) : QJsonObject{};
#else
    Q_UNUSED(request)
    return {};
#endif
}

QJsonObject IpcServer::nativeSessionGuardBeginStopV1(const QJsonObject &request)
{
#ifdef Q_OS_MACOS
    return allowOperation(2) && boundedJson(request)
        ? m_nativeSessionGuard.beginStop(request) : QJsonObject{};
#else
    Q_UNUSED(request)
    return {};
#endif
}

QJsonObject IpcServer::nativeSessionGuardMarkRunningV1(const QJsonObject &request)
{
#ifdef Q_OS_MACOS
    return allowOperation(2) && boundedJson(request)
        ? m_nativeSessionGuard.markRunning(request) : QJsonObject{};
#else
    Q_UNUSED(request)
    return {};
#endif
}

QJsonObject IpcServer::nativeSessionGuardMarkStoppedV1(const QJsonObject &request)
{
#ifdef Q_OS_MACOS
    return allowOperation(2) && boundedJson(request)
        ? m_nativeSessionGuard.markStopped(request) : QJsonObject{};
#else
    Q_UNUSED(request)
    return {};
#endif
}

QJsonObject IpcServer::nativeSessionGuardRenewAuthorityV1(const QJsonObject &request)
{
#ifdef Q_OS_MACOS
    return allowOperation(4) && boundedJson(request, 512 * 1024)
        ? m_nativeSessionGuard.renewAuthority(request) : QJsonObject{};
#else
    Q_UNUSED(request)
    return {};
#endif
}

QJsonObject IpcServer::nativeSessionGuardReleaseV1(const QJsonObject &request)
{
#ifdef Q_OS_MACOS
    return allowOperation(4) && boundedJson(request)
        ? m_nativeSessionGuard.release(request) : QJsonObject{};
#else
    Q_UNUSED(request)
    return {};
#endif
}

QJsonObject IpcServer::nativeSessionGuardStatusV1()
{
#ifdef Q_OS_MACOS
    if (!allowOperation()) return {};
    const QJsonObject event = m_nativeSessionGuard.currentGuardEvent();
    return {
        {QStringLiteral("type"), QStringLiteral("native_session_guard_status_v1")},
        {QStringLiteral("schema"), 1},
        {QStringLiteral("state"), event.isEmpty() ? QStringLiteral("idle")
                                                   : QStringLiteral("owned")},
        {QStringLiteral("event"), event.isEmpty() ? QJsonValue::Null
                                                   : QJsonValue(event)},
    };
#else
    return {};
#endif
}

QJsonObject IpcServer::nativeSessionGuardRecoveryResolveV1(
        const QJsonObject &request)
{
#ifdef Q_OS_MACOS
    static const QSet<QString> keys{
        QStringLiteral("type"), QStringLiteral("schema"), QStringLiteral("action"),
        QStringLiteral("event"), QStringLiteral("configuration")};
    const QStringList actual = request.keys();
    if (!allowOperation(8) || !boundedJson(request, 512 * 1024)
        || QSet<QString>(actual.cbegin(), actual.cend()) != keys
        || request.value(QStringLiteral("type"))
               != QLatin1String("native_session_guard_recovery_resolve_v1")
        || !request.value(QStringLiteral("schema")).isDouble()
        || request.value(QStringLiteral("schema")).toDouble() != 1.0
        || !request.value(QStringLiteral("event")).isObject()
        || !request.value(QStringLiteral("configuration")).isObject()) return {};
    const QString action = request.value(QStringLiteral("action")).toString();
    const QJsonObject event = request.value(QStringLiteral("event")).toObject();
    const QJsonObject configuration = request.value(
        QStringLiteral("configuration")).toObject();
    const QJsonObject current = m_nativeSessionGuard.currentGuardEvent();
    if (!recoveryGuardEventShape(event) || current.isEmpty()
        || current.value(QStringLiteral("operation"))
               != event.value(QStringLiteral("operation"))
        || current.value(QStringLiteral("session"))
               != event.value(QStringLiteral("session"))
        || current.value(QStringLiteral("policy_sha256"))
               != event.value(QStringLiteral("policy_sha256"))
        || current.value(QStringLiteral("outer_session_id"))
               != event.value(QStringLiteral("outer_session_id"))
        || current.value(QStringLiteral("expected_runtime_session_id"))
               != event.value(QStringLiteral("expected_runtime_session_id"))) {
        return recoveryReceiptFromEvent(event, action, QStringLiteral("rejected"),
                                        QStringLiteral("recovery_identity_rejected"));
    }
    const QString runtimeId = current.value(
        QStringLiteral("expected_runtime_session_id")).toString();
    const QString protocol = m_nativeSessionGuard.protocol();
    auto identityRequest = [&](const QString &type) {
        return QJsonObject{
            {QStringLiteral("type"), type}, {QStringLiteral("schema"), 1},
            {QStringLiteral("operation"), current.value(QStringLiteral("operation"))},
            {QStringLiteral("session"), current.value(QStringLiteral("session"))},
            {QStringLiteral("policy_sha256"), current.value(QStringLiteral("policy_sha256"))},
            {QStringLiteral("outer_session_id"),
             current.value(QStringLiteral("outer_session_id"))},
            {QStringLiteral("expected_runtime_session_id"),
             current.value(QStringLiteral("expected_runtime_session_id"))},
        };
    };
    if (action == QLatin1String("adopt")) {
        QString error;
        if (!m_nativeSessionGuard.validateRecoveryConfiguration(configuration, &error))
            return recoveryReceiptFromEvent(current, action, QStringLiteral("rejected"),
                                            QStringLiteral("recovery_policy_rejected"));
        // The GUI owns normal-mac tun2socks. After channel loss it has been
        // positively killed, so an Xray core alone is never an adoptable tunnel.
        if (protocol != QLatin1String("awg"))
            return recoveryReceiptFromEvent(current, action, QStringLiteral("rejected"),
                                            QStringLiteral("xray_gui_adapter_not_adoptable"));
        const QJsonObject status = Daemon::instance()->runtimeStatusV1(runtimeId);
        if (status.value(QStringLiteral("runtime_state")) != QLatin1String("running"))
            return recoveryReceiptFromEvent(current, action, QStringLiteral("rejected"),
                                            QStringLiteral("native_runtime_not_running"));
        return m_nativeSessionGuard.adoptRecovered(identityRequest(
            QStringLiteral("native_session_guard_recover_adopt_v1")), configuration);
    }
    if (action != QLatin1String("stop") || !configuration.isEmpty()) return {};
    return m_nativeSessionGuard.stopAndReleaseRecovered(
        identityRequest(QStringLiteral("native_session_guard_recover_stop_v1")),
        [&]() {
            if (protocol == QLatin1String("awg")) {
                const QJsonObject before = Daemon::instance()->runtimeStatusV1(runtimeId);
                const bool stopped = before.value(QStringLiteral("runtime_state"))
                           == QLatin1String("stopped")
                        || Daemon::instance()->deactivateExactSession(runtimeId);
                const QJsonObject after = Daemon::instance()->runtimeStatusV1(runtimeId);
                return stopped && after.value(QStringLiteral("runtime_state"))
                           == QLatin1String("stopped");
            }
            if (protocol != QLatin1String("xray") || !m_channelChildrenStopProven)
                return false;
            const QJsonObject before = Xray::getInstance().runtimeStatusV1(runtimeId);
            const bool coreStopped = before.value(QStringLiteral("runtime_state"))
                        == QLatin1String("stopped")
                    || Xray::getInstance().stopXraySession(runtimeId);
            const QJsonObject after = Xray::getInstance().runtimeStatusV1(runtimeId);
            if (!coreStopped || after.value(QStringLiteral("runtime_state"))
                    != QLatin1String("stopped")) return false;
            // PF is still armed. Remove only the fixed catalog-v2 inner resources;
            // any failed postcondition keeps the durable outer lease quarantined.
            return Router::clearSavedRoutes()
                    && Router::deleteTun(QStringLiteral("utun22"))
                    && Router::restoreResolvers() && Router::StartRoutingIpv6();
        });
#else
    Q_UNUSED(request)
    return {};
#endif
}
