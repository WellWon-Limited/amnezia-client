#ifndef XRAYPROTOCOL_H
#define XRAYPROTOCOL_H

#include "QProcess"
#include <QtCore/qsharedpointer.h>
#include <QHostAddress>
#include <QList>

#include "core/utils/errorCodes.h"
#include "core/utils/routeModes.h"
#include "core/utils/commonStructs.h"
#include "core/utils/ipcClient.h"
#include "tun2socksOutputReader.h" // AVPN
#include "vpnProtocol.h"

#include <QPointer>

class XrayProtocol : public VpnProtocol
{
public:
    XrayProtocol(const QJsonObject &configuration, QObject *parent = nullptr);
    virtual ~XrayProtocol() override;

    ErrorCode start() override;
    void stop() override;

private:
    // AVPN: every step that runs the event loop (an IPC wait) may see this session stopped or this object
    // destroyed when it returns - the steps take the session they belong to and give up when it is over.
    ErrorCode setupRouting(quint64 session);
    ErrorCode startTun2Socks(quint64 session);
    void onTun2SocksLines(quint64 session, const QList<QByteArray> &lines);
    void onTun2SocksFinished(quint64 session, int exitCode, QProcess::ExitStatus exitStatus);
    void onTun2SocksExit(quint64 session, bool resourceBusy, int exitCode, QProcess::ExitStatus exitStatus);

    // AVPN: start() and stop() each begin a new value; a continuation of an older one is dropped.
    quint64 m_session = 0;
    // AVPN: start() ran and stop() has not torn the service down yet.
    bool m_sessionOpen = false;
    // AVPN: the routing of the running tun2socks is set up (its "[STACK]" line came).
    bool m_tun2socksStackUp = false;
    QPointer<avpn::ProcessStderrReader> m_tun2socksReader;

    QJsonObject m_xrayConfig;
    amnezia::RouteMode m_routeMode;
    QList<QHostAddress> m_dnsServers;
    QString m_remoteAddress;

    QString m_socksUser;
    QString m_socksPassword;
    int m_socksPort = 10808;

    QSharedPointer<IpcProcessInterfaceReplica> m_tun2socksProcess;
    int m_tun2socksRetryCount = 0;
    static constexpr int maxTun2SocksRetries = 5;
    static constexpr int tun2socksRetryDelayMs = 400;
    static constexpr int tun2socksStopReplyMs = 1000; // AVPN: the bound of the one round trip in stop()
};

#endif // XRAYPROTOCOL_H
