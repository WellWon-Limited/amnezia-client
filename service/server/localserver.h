#ifndef LOCALSERVER_H
#define LOCALSERVER_H

#include <QObject>
#include <QPointer>
#include <QProcess>
#include <QSharedPointer>
#include <QStringList>
#include <QTimer>
#include <QVector>

#include "ipcserver.h"
#include "ipcsecurity.h"
#ifdef Q_OS_MACOS
#include "openvpndnssecurity.h"
#endif

#include "../../client/daemon/daemonlocalserver.h"
#include "../../client/mozilla/networkwatcher.h"

#ifdef Q_OS_WIN
#include "windows/daemon/windowsdaemon.h"
#endif

#ifdef Q_OS_LINUX
#include "linux/daemon/linuxdaemon.h"
#endif

#ifdef Q_OS_MAC
#include "macos/daemon/macosdaemon.h"
#endif

class QLocalServer;
class QLocalSocket;
class QProcess;

class LocalServer : public QObject
{
    Q_OBJECT

public:
    explicit LocalServer(QObject* parent = nullptr);
    ~LocalServer();
    bool isReady() const;
    QSharedPointer<QLocalServer> m_server;
    IpcServer m_ipcServer;
#ifdef Q_OS_MACOS
    amnezia::openvpndnssecurity::OpenVpnDnsMonitor m_openVpnDnsMonitor;
    QTimer m_consoleUserWatchdog;
#endif
    QRemoteObjectHost m_serverNode;
    bool m_isRemotingEnabled = false;
    QPointer<QLocalSocket> m_authenticatedSocket;
    amnezia::ipcsecurity::PeerPolicy m_peerPolicy;
    QString m_controlSocketPath;

    NetworkWatcher m_networkWatcher;
#ifdef Q_OS_LINUX
    DaemonLocalServer server{qApp};
    LinuxDaemon daemon;
#endif
#ifdef Q_OS_WIN
    DaemonLocalServer server{qApp};
    WindowsDaemon daemon;
#endif
#ifdef Q_OS_MAC
    DaemonLocalServer server{qApp};
    MacOSDaemon daemon;
#endif

private:
    bool m_ready = false;
};

#endif // LOCALSERVER_H
