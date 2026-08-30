#ifndef XRAYPROTOCOL_H
#define XRAYPROTOCOL_H

#include <QHostAddress>
#include <QJsonObject>
#include <QList>
#include <QMetaObject>
#include <QProcess>
#include <QTimer>
#include <QtCore/qsharedpointer.h>

#include "core/utils/errorCodes.h"
#include "core/utils/routeModes.h"
#include "core/utils/commonStructs.h"
#include "core/utils/ipcClient.h"
#include "vpnProtocol.h"

class XrayProtocol : public VpnProtocol
{
    Q_OBJECT

public:
    XrayProtocol(const QJsonObject &configuration, QObject *parent = nullptr);
    XrayProtocol(const QJsonObject &configuration,
                 const QString &expectedRuntimeSessionId,
                 bool externallyGuarded,
                 QObject *parent = nullptr);
    virtual ~XrayProtocol() override;

    ErrorCode start() override;
    void stop() override;

    QJsonObject runtimeStatus() const;
    QString runtimeSessionId() const;

signals:
    void runtimeStatusChanged(const QJsonObject &status);

private:
    ErrorCode setupRouting();
    ErrorCode startTun2Socks(const QString &sessionId, quint64 generation);
    bool stopTun2Socks(const QSharedPointer<IpcProcessInterfaceReplica> &process);
    bool cleanupRouting();
    QJsonObject queryRuntimeStatus(const QString &sessionId) const;
    bool acceptRuntimeStatus(const QJsonObject &status, const QString &sessionId,
                             bool updateCounters, bool publish = true);
    void pollRuntimeStatus(const QString &sessionId, quint64 generation);
    void failCurrentSession(ErrorCode error, const QString &sessionId, quint64 generation);
    bool isCurrentSession(const QString &sessionId, quint64 generation,
                          const IpcProcessInterfaceReplica *process = nullptr) const;

    QJsonObject m_xrayConfig;
    amnezia::RouteMode m_routeMode;
    QList<QHostAddress> m_dnsServers;
    QString m_remoteAddress;

    QString m_socksUser;
    QString m_socksPassword;
    int m_socksPort = 10808;

    QSharedPointer<IpcProcessInterfaceReplica> m_tun2socksProcess;
    QMetaObject::Connection m_tunReadyConnection;
    QMetaObject::Connection m_tunFinishedConnection;
    QTimer m_runtimeTimer;
    QJsonObject m_runtimeStatus;
    QString m_runtimeSessionId;
    QString m_counterEpoch;
    quint64 m_operationGeneration = 0;
    quint64 m_lastRawRx = 0;
    quint64 m_lastRawTx = 0;
    quint64 m_normalizedRx = 0;
    quint64 m_normalizedTx = 0;
    quint64 m_lastResetCount = 0;
    bool m_haveRawCounters = false;
    bool m_tunReadySeen = false;
    bool m_stopping = false;
    bool m_externallyGuarded = false;
    int m_tun2socksRetryCount = 0;
    static constexpr int maxTun2SocksRetries = 5;
    static constexpr int tun2socksRetryDelayMs = 400;
};

#endif // XRAYPROTOCOL_H
