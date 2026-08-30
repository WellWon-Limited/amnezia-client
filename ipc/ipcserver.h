#ifndef IPCSERVER_H
#define IPCSERVER_H

#include <QLocalServer>
#include <QObject>
#include <QRemoteObjectNode>
#include <QJsonObject>
#include <QElapsedTimer>
#include <QQueue>
#include "../client/daemon/interfaceconfig.h"
#include "../client/mozilla/pinghelper.h"

#include "ipc.h"
#include "ipcserverprocess.h"
#include "ipcsecurity.h"

#ifdef Q_OS_MACOS
#include "../client/platforms/macos/daemon/macosnativesessionguard.h"
#endif

#include "rep_ipc_interface_source.h"

class IpcServer : public IpcInterfaceSource
{
public:
    explicit IpcServer(QObject *parent = nullptr);
    virtual int createPrivilegedProcess() override;
    virtual QJsonObject createPrivilegedProcessV2(
            const QString &parentCapability) override;

    void setAuthenticatedPeer(const amnezia::ipcsecurity::PeerIdentity &identity,
                              const QByteArray &sessionCapability,
                              const QString &runtimeDirectory);
    void clearAuthenticatedPeer(const QByteArray &sessionCapability);
#ifdef Q_OS_MACOS
    bool restoreNativeSessionGuardAfterDaemonStart(QString *error)
    { return m_nativeSessionGuard.restoreAfterDaemonStart(error); }
    void failClosedOpenVpnDns(const QString &error);
    void shutdownPrivilegedChildren();
#endif

    virtual int routeAddList(const QString &gw, const QStringList &ips) override;
    virtual bool clearSavedRoutes() override;
    virtual bool routeDeleteList(const QString &gw, const QStringList &ips) override;
    virtual bool flushDns() override;
    virtual void resetIpStack() override;
    virtual bool checkAndInstallDriver() override;
    virtual QStringList getTapList() override;
    virtual void cleanUp() override;
    virtual void clearLogs() override;
    virtual void setLogsEnabled(bool enabled) override;
    virtual bool createTun(const QString &dev, const QString &subnet) override;
    virtual bool deleteTun(const QString &dev) override;
    virtual bool StartRoutingIpv6() override;
    virtual bool StopRoutingIpv6() override;
    virtual bool disableAllTraffic() override;
    virtual bool addKillSwitchAllowedRange(QStringList ranges) override;
    virtual bool resetKillSwitchAllowedRange(QStringList ranges) override;
    virtual bool enablePeerTraffic(const QJsonObject &configStr) override;
    virtual bool enableKillSwitch(const QJsonObject &excludeAddr, int vpnAdapterIndex) override;
    virtual bool disableKillSwitch() override;
    virtual bool refreshKillSwitch( bool enabled ) override;
    virtual bool updateResolvers(const QString& ifname, const QList<QHostAddress>& resolvers) override;
    virtual bool restoreResolvers() override;
    virtual bool xrayStart(const QString& cfg) override;
    virtual bool xrayStop() override;
    virtual bool xrayStartSession(const QString& sessionId, const QString& cfg) override;
    virtual bool xrayStopSession(const QString& sessionId) override;
    virtual QJsonObject xrayRuntimeStatusV1(const QString& sessionId) override;
    virtual QJsonObject nativeSessionGuardPrepareV1(const QJsonObject &request) override;
    virtual QJsonObject nativeSessionGuardClaimInnerV1(const QJsonObject &request) override;
    virtual QJsonObject nativeSessionGuardBeginStopV1(const QJsonObject &request) override;
    virtual QJsonObject nativeSessionGuardMarkRunningV1(const QJsonObject &request) override;
    virtual QJsonObject nativeSessionGuardMarkStoppedV1(const QJsonObject &request) override;
    virtual QJsonObject nativeSessionGuardRenewAuthorityV1(
            const QJsonObject &request) override;
    virtual QJsonObject nativeSessionGuardReleaseV1(const QJsonObject &request) override;
    virtual QJsonObject nativeSessionGuardStatusV1() override;
    virtual QJsonObject nativeSessionGuardRecoveryResolveV1(
            const QJsonObject &request) override;
    virtual bool startNetworkCheck(const QString& serverIpv4Gateway, const QString& deviceIpv4Address) override;
    virtual bool stopNetworkCheck() override;

private:
    struct ProcessDescriptor;
    int m_localpid = 0;

    bool allowOperation(int cost = 1);
    bool hasAuthenticatedPeer() const;
    void removeProcessDescriptor(int descriptorId);
#ifdef Q_OS_MACOS
    bool restoreProcessDns(ProcessDescriptor &descriptor, QString *error);
    void retryOpenVpnDnsRecovery(const QString &session, int attempt = 0);
#endif

    struct ProcessDescriptor {
        ProcessDescriptor (QObject *parent = nullptr) {
            serverNode = QSharedPointer<QRemoteObjectHost>(new QRemoteObjectHost(parent));
            ipcProcess = QSharedPointer<IpcServerProcess>(new IpcServerProcess(parent));
            localServer = QSharedPointer<QLocalServer>(new QLocalServer(parent));
        }

        QSharedPointer<IpcServerProcess> ipcProcess;
        QSharedPointer<QRemoteObjectHost> serverNode;
        QSharedPointer<QLocalServer> localServer;
        QString endpoint;
        QByteArray capability;
        bool capabilityConsumed = false;
    };

    QMap<int, ProcessDescriptor> m_processes;
    PingHelper m_pingHelper;
    amnezia::ipcsecurity::PeerIdentity m_authenticatedPeer;
    QByteArray m_parentCapability;
    QString m_runtimeDirectory;
    QQueue<qint64> m_operationTimes;
    QElapsedTimer m_operationClock;
#ifdef Q_OS_MACOS
    MacosNativeSessionGuard m_nativeSessionGuard;
    bool m_channelChildrenStopProven = true;
#endif
};

#endif // IPCSERVER_H
