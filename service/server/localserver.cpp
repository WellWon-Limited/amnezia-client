#include "localserver.h"

#include <QCoreApplication>
#include <QDebug>
#include <QFileInfo>
#include <QLocalServer>
#include <QLocalSocket>
#include <QObject>
#include <QSharedPointer>
#include <QString>

#include "ipc.h"
#include "killswitch.h"
#include "logger.h"

#ifdef Q_OS_WIN
    #include "tapcontroller_win.h"
#endif

namespace {
Logger logger("WgDaemonServer");
}

LocalServer::LocalServer(QObject *parent) : QObject(parent),
    m_ipcServer(this)
#ifdef Q_OS_MACOS
    , m_openVpnDnsMonitor(
          [this](const QString &error) {
              m_ipcServer.failClosedOpenVpnDns(error);
          }, this)
#endif
{
    // Create the server and listen outside of QtRO
    m_server = QSharedPointer<QLocalServer>(new QLocalServer(this));
#ifdef Q_OS_MACOS
    QString securityError;
    if (!amnezia::ipcsecurity::consolePeerPolicy(&m_peerPolicy, &securityError)
            || !amnezia::ipcsecurity::prepareRuntimeDirectory(
                    m_peerPolicy.expected.uid, m_peerPolicy.expected.gid, &securityError)) {
        qCritical() << "Secure IPC initialization failed:" << securityError;
        return;
    }
    m_controlSocketPath = amnezia::ipcsecurity::controlSocketPath(
            m_peerPolicy.expected.uid);
    if (!amnezia::ipcsecurity::removeVerifiedStaleSocket(
                m_controlSocketPath, m_peerPolicy.expected.uid, &securityError)) {
        qCritical() << "Secure IPC endpoint rejected:" << securityError;
        return;
    }
    m_server->setSocketOptions(QLocalServer::UserAccessOption);
#else
    m_server->setSocketOptions(QLocalServer::WorldAccessOption);
    m_controlSocketPath = amnezia::getIpcServiceUrl();
#endif

    if (!m_server->listen(m_controlSocketPath)) {
        qDebug() << QString("Unable to start the server: %1.").arg(m_server->errorString());
        return;
    }
#ifdef Q_OS_MACOS
    if (!m_openVpnDnsMonitor.start(&securityError)) {
        qCritical() << "OpenVPN DNS monitor initialization failed:"
                    << securityError;
        m_server->close();
        QLocalServer::removeServer(m_controlSocketPath);
        return;
    }
    if (!amnezia::ipcsecurity::secureSocketFile(
                m_controlSocketPath, m_peerPolicy.expected.uid,
                m_peerPolicy.expected.gid, &securityError)) {
        qCritical() << "Secure IPC socket permissions failed:" << securityError;
        m_server->close();
        QLocalServer::removeServer(m_controlSocketPath);
        return;
    }
#endif

    QObject::connect(m_server.data(), &QLocalServer::newConnection, this, [this]() {
        while (m_server->hasPendingConnections()) {
            QLocalSocket *socket = m_server->nextPendingConnection();
            if (!socket) {
                continue;
            }
#ifdef Q_OS_MACOS
            QString securityError;
            amnezia::ipcsecurity::PeerIdentity identity;
            QByteArray sessionCapability;
            const bool secondClient = m_authenticatedSocket
                    && m_authenticatedSocket->state() != QLocalSocket::UnconnectedState;
            if (secondClient
                    || !amnezia::ipcsecurity::authorizeSocket(
                            socket, m_peerPolicy, &identity, &securityError)
                    || !amnezia::ipcsecurity::performServerHandshake(
                            socket, {}, &sessionCapability, &securityError)) {
                qWarning() << "Rejected privileged IPC peer:"
                           << (secondClient ? QStringLiteral("second_client") : securityError);
                socket->abort();
                socket->deleteLater();
                continue;
            }
            socket->setReadBufferSize(amnezia::ipcsecurity::kMaxQtRoReadBufferBytes);
            m_authenticatedSocket = socket;
            m_ipcServer.setAuthenticatedPeer(identity, sessionCapability,
                                             amnezia::ipcsecurity::runtimeDirectory(
                                                     identity.uid));
            connect(socket, &QLocalSocket::disconnected, this,
                    [this, socket, sessionCapability]() {
                if (m_authenticatedSocket == socket) {
                    m_authenticatedSocket.clear();
                    m_ipcServer.clearAuthenticatedPeer(sessionCapability);
                }
            });
#endif
            qDebug() << "LocalServer authenticated connection";
            m_serverNode.addHostSideConnection(socket);

            if (!m_isRemotingEnabled) {
                m_isRemotingEnabled = true;
                m_serverNode.enableRemoting(&m_ipcServer);
            }
        }
    });

    // Init Mozilla Wireguard Daemon
    if (!server.initialize()) {
        logger.error() << "Failed to initialize the server";
        return;
    }

    m_networkWatcher.initialize();
    connect(&m_networkWatcher, &NetworkWatcher::networkChanged, &m_ipcServer, &IpcServer::networkChanged);
    connect(&m_networkWatcher, &NetworkWatcher::wakeup, &m_ipcServer, &IpcServer::wakeup);
#ifdef Q_OS_MACOS
    connect(&m_networkWatcher, &NetworkWatcher::networkChanged,
            &m_openVpnDnsMonitor,
            &amnezia::openvpndnssecurity::OpenVpnDnsMonitor::reconcileNow);
    connect(&m_networkWatcher, &NetworkWatcher::wakeup,
            &m_openVpnDnsMonitor,
            &amnezia::openvpndnssecurity::OpenVpnDnsMonitor::reconcileNow);
#endif
#ifdef Q_OS_MACOS
    QString guardRestoreError;
    if (!m_ipcServer.restoreNativeSessionGuardAfterDaemonStart(
                &guardRestoreError)) {
        qCritical() << "Native outer guard restore is fail-closed:" << guardRestoreError;
        return;
    }
#endif
    const bool killSwitchInitialized = KillSwitch::instance()->init();
    if (!killSwitchInitialized) {
        qCritical() << "Kill switch initialization failed";
        return;
    }
#ifdef Q_OS_MACOS
    m_consoleUserWatchdog.setInterval(2000);
    connect(&m_consoleUserWatchdog, &QTimer::timeout, this, [this]() {
        amnezia::ipcsecurity::PeerPolicy currentPolicy;
        QString policyError;
        if (!amnezia::ipcsecurity::consolePeerPolicy(
                    &currentPolicy, &policyError)
                || currentPolicy.expected.uid != m_peerPolicy.expected.uid
                || currentPolicy.expected.gid != m_peerPolicy.expected.gid) {
            qCritical() << "Console user changed; restarting secure IPC:"
                        << policyError;
            if (m_server) m_server->close();
            QCoreApplication::exit(75);
        }
    });
    m_consoleUserWatchdog.start();
#endif

#ifdef Q_OS_LINUX
    // Signal handling for a proper shutdown.
    QObject::connect(qApp, &QCoreApplication::aboutToQuit,
                     []() { LinuxDaemon::instance()->deactivate(); });
#endif

#ifdef Q_OS_MAC
    // Signal handling for a proper shutdown.
    QObject::connect(qApp, &QCoreApplication::aboutToQuit,
                     []() { MacOSDaemon::instance()->deactivate(); });
#endif

#ifdef Q_OS_WIN
    // Signal handling for a proper shutdown.
    QObject::connect(qApp, &QCoreApplication::aboutToQuit,
                     []() { WindowsDaemon::instance()->deactivate(); });
#endif
    m_ready = true;
}

bool LocalServer::isReady() const
{
    return m_ready;
}

LocalServer::~LocalServer()
{
#ifdef Q_OS_MACOS
    // Shutdown order is part of the DNS ownership contract: child death,
    // session-scoped restore, then monitor teardown.
    m_ipcServer.shutdownPrivilegedChildren();
    m_openVpnDnsMonitor.stop();
#endif
    qDebug() << "Local server stopped";
}
