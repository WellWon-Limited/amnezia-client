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

#include "logger.h"
#include "router.h"
#include "killswitch.h"
#include "xray.h"

#ifdef Q_OS_WIN
    #include "tapcontroller_win.h"
#endif


IpcServer::IpcServer(QObject *parent) : IpcInterfaceSource(parent)
{
    connect(&m_pingHelper, &PingHelper::connectionLose, this, &IpcServer::connectionLose);
    // AVPN (Scanner): the service's NetworkWatcher feeds the probe host's path generation too
    // (localserver.cpp forwards it into these signals); a wake-up = the path was down meanwhile.
    connect(this, &IpcServer::networkChanged, this, [this]() { m_scanHost.notePathEvent(false); });
    connect(this, &IpcServer::wakeup, this, [this]() { m_scanHost.notePathEvent(true); });
}

#ifndef Q_OS_WIN
IpcServer::~IpcServer()
{
    // AVPN: the descriptors' sockets close as m_processes goes; that is not a lost client (the service's
    // shutdown is unchanged: launchd/systemd end the children with the job).
    m_closing = true;
}
#endif

int IpcServer::createPrivilegedProcess()
{
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
    QObject::connect(pd.localServer.data(), &QLocalServer::newConnection, this, [this, pd]() {
        qDebug() << "IpcServer new connection";
        QLocalSocket *socket = pd.localServer->nextPendingConnection();
        if (pd.serverNode) {
            pd.serverNode->addHostSideConnection(socket);
            pd.serverNode->enableRemoting(pd.ipcProcess.data());
        }
#ifndef Q_OS_WIN
        // AVPN (macOS/Linux): this connection controls the child; when the last one closes (the client stopped
        // it, quit or crashed) the child is not left running with nobody able to stop it.
        if (socket) {
            IpcServerProcess *process = pd.ipcProcess.data();
            process->controllerConnected();
            QObject::connect(socket, &QLocalSocket::disconnected, this,
                             [this, process]() { onProcessControllerLost(process); }, Qt::SingleShotConnection);
        }
#endif
    });

    QObject::connect(pd.serverNode.data(), &QRemoteObjectHost::error, this,
                     [pd](QRemoteObjectNode::ErrorCode errorCode) { qDebug() << "QRemoteObjectHost::error" << errorCode; });

    QObject::connect(pd.serverNode.data(), &QRemoteObjectHost::destroyed, this, [pd]() { qDebug() << "QRemoteObjectHost::destroyed"; });

    m_processes.insert(m_localpid, pd);

    return m_localpid;
}

#ifndef Q_OS_WIN
// AVPN (macOS quit/crash with own Xray up, 24.11.2026): a tun2socks whose client went away without stopping it
// (the app crashed, or quit while its VpnConnection thread could no longer reach the service) leaves the Xray
// session of that client behind: the core, the kill switch, the resolvers, the routes and the TUN device - on
// the owner's Mac for hours after a crash, with no app to show or stop it and the next start failing on the
// busy device. The session cannot be adopted by the next launch (the GUI owns its control: the tun2socks
// replica, the routes, DNS and the kill switch are set from there), so it ends the way XrayProtocol::stop ends
// it - in the same order, then what VpnConnection does on Disconnected. disableKillSwitch keeps a strict kill
// switch (KillSwitch::disableKillSwitch). A client that stops its session asks for the end (terminate/close)
// before it lets the replica go, so this runs only for a lost client.
void IpcServer::onProcessControllerLost(IpcServerProcess *process)
{
    if (m_closing)
        return;
    // AVPN (review F2): only a child of the session that is still open ends it; an older client's child (a newer
    // xrayStart came first) is ended alone and never touches the newer session's state.
    const avpn::LostControllerStep step = avpn::decideLostController(
            process->controllerLost(), process->program() == amnezia::PermittedProcess::Tun2Socks,
            process->xrayGeneration(), avpn::XraySessionLedger::service());
    if (step == avpn::LostControllerStep::Nothing)
        return;
    const bool xraySession = step == avpn::LostControllerStep::EndSessionThenChild;
    if (xraySession) {
        qWarning() << "IpcServer: tun2socks lost its client without a stop - ending its Xray session";
        disableKillSwitch();
        StartRoutingIpv6();
        restoreResolvers();
        const QString device = process->tunDevice();
        if (!device.isEmpty())
            deleteTun(device);
        xrayStop();
    }
    process->endChild(); // after the teardown, as XrayProtocol::stop ends it
    if (xraySession) {
        clearSavedRoutes();
        flushDns();
    }
}
#endif

int IpcServer::routeAddList(const QString &gw, const QStringList &ips)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::routeAddList";
#endif

    return Router::routeAddList(gw, ips);
}

bool IpcServer::clearSavedRoutes()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::clearSavedRoutes";
#endif

    return Router::clearSavedRoutes();
}

bool IpcServer::routeDeleteList(const QString &gw, const QStringList &ips)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::routeDeleteList";
#endif

    return Router::routeDeleteList(gw, ips);
}

bool IpcServer::flushDns()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::flushDns";
#endif

    return Router::flushDns();
}

void IpcServer::resetIpStack()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::resetIpStack";
#endif

    Router::resetIpStack();
}

bool IpcServer::checkAndInstallDriver()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::checkAndInstallDriver";
#endif

#ifdef Q_OS_WIN
    return TapController::checkAndSetup();
#else
    return true;
#endif
}

QStringList IpcServer::getTapList()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::getTapList";
#endif

#ifdef Q_OS_WIN
    return TapController::getTapList();
#else
    return QStringList();
#endif
}

void IpcServer::cleanUp()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::cleanUp";
#endif

    Logger::deInit();
    Logger::cleanUp();
}

void IpcServer::clearLogs()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::clearLogs";
#endif

    Logger::clearLogs(true);
}

bool IpcServer::createTun(const QString &dev, const QString &subnet)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::createTun";
#endif

    const bool created = Router::createTun(dev, subnet);
#ifdef Q_OS_MACOS
    // AVPN (pf state ownership): a tun brought up for the session being built; the session's kill switch
    // takes it and passes only it (KillSwitch::tunnelCreated, killswitch.h).
    if (created)
        KillSwitch::instance()->tunnelCreated(dev);
#endif
    return created;
}

bool IpcServer::deleteTun(const QString &dev)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::deleteTun";
#endif

    return Router::deleteTun(dev);
}

bool IpcServer::updateResolvers(const QString &ifname, const QList<QHostAddress> &resolvers)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::updateResolvers";
#endif

#ifdef Q_OS_MACOS
    // AVPN (diag): the resolvers a tunnel session hands the system (the queries the Xray core sees).
    QStringList resolverList;
    for (const QHostAddress &resolver : resolvers)
        resolverList.append(resolver.toString());
    qDebug().noquote() << "[dns] resolvers for" << ifname << ":" << resolverList.join(QStringLiteral(", "));
#endif
    return Router::updateResolvers(ifname, resolvers);
}

bool IpcServer::restoreResolvers()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::restoreResolvers";
#endif

    return Router::restoreResolvers();
}

bool IpcServer::StartRoutingIpv6()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::StartRoutingIpv6";
#endif

    return Router::StartRoutingIpv6();
}

bool IpcServer::StopRoutingIpv6()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::StopRoutingIpv6";
#endif

    return Router::StopRoutingIpv6();
}

void IpcServer::setLogsEnabled(bool enabled)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::setLogsEnabled";
#endif

    if (enabled) {
        Logger::init(true);
    } else {
        Logger::deInit();
    }
    Xray::getInstance().setDiagnosticsEnabled(enabled); // AVPN: core failures in the service log (xraysession.h)
}

bool IpcServer::startNetworkCheck(const QString& serverIpv4Gateway, const QString& deviceIpv4Address)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::startNetworkCheck";
#endif

    m_pingHelper.start(serverIpv4Gateway, deviceIpv4Address);
    return true;
}

bool IpcServer::stopNetworkCheck()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::stopNetworkCheck";
#endif

    m_pingHelper.stop();
    return true;
}

bool IpcServer::resetKillSwitchAllowedRange(QStringList ranges)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::resetKillSwitchAllowedRange";
#endif

    return KillSwitch::instance()->resetAllowedRange(ranges);
}

bool IpcServer::addKillSwitchAllowedRange(QStringList ranges)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::addKillSwitchAllowedRange";
#endif

    return KillSwitch::instance()->addAllowedRange(ranges);
}

bool IpcServer::disableAllTraffic()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::disableAllTraffic";
#endif

    m_scanHost.stopAllBeforeTunnelChange("kill_switch_block_all"); // AVPN (Scanner)
    return KillSwitch::instance()->disableAllTraffic();
}

bool IpcServer::enableKillSwitch(const QJsonObject &configStr, int vpnAdapterIndex)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::enableKillSwitch";
#endif

    m_scanHost.stopAllBeforeTunnelChange("kill_switch_on"); // AVPN (Scanner)
    return KillSwitch::instance()->enableKillSwitch(configStr, vpnAdapterIndex);
}

bool IpcServer::disableKillSwitch()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::disableKillSwitch";
#endif

    m_scanHost.stopAllBeforeTunnelChange("kill_switch_off"); // AVPN (Scanner)
    return KillSwitch::instance()->disableKillSwitch();
}

bool IpcServer::enablePeerTraffic(const QJsonObject &configStr)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::enablePeerTraffic";
#endif

    return KillSwitch::instance()->enablePeerTraffic(configStr);
}

bool IpcServer::refreshKillSwitch(bool enabled)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::refreshKillSwitch";
#endif

    m_scanHost.stopAllBeforeTunnelChange("kill_switch_refresh"); // AVPN (Scanner)
    return KillSwitch::instance()->refresh(enabled);
}

bool IpcServer::xrayStart(const QString& cfg)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::xrayStart";
#endif

    m_scanHost.stopAllBeforeTunnelChange("xray_start"); // AVPN (Scanner)
#ifndef Q_OS_WIN
    avpn::XraySessionLedger::service().onCoreStart(); // AVPN (review F2): a new session from here on
#endif
    return Xray::getInstance().startXray(cfg);
}

bool IpcServer::xrayStop()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::xrayStop";
#endif

    m_scanHost.stopAllBeforeTunnelChange("xray_stop"); // AVPN (Scanner)
#ifndef Q_OS_WIN
    avpn::XraySessionLedger::service().onCoreStop(); // AVPN (review F2): the session is over
#endif
    return Xray::getInstance().stopXray();
}

// AVPN
QJsonObject IpcServer::xrayRuntimeStatus(const QString& iface)
{
    return Xray::getInstance().runtimeStatus(iface);
}
