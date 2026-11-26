#ifndef VPNCONNECTION_H
#define VPNCONNECTION_H

#include <QObject>
#include <QMetaObject>
#include <QString>
#include <QScopedPointer>
#include <QRemoteObjectNode>
#include <QTimer>

#include "core/protocols/vpnProtocol.h"
#include "core/utils/errorCodes.h"
#include "core/utils/routeModes.h"
#include "core/utils/commonStructs.h"
#include "core/repositories/secureServersRepository.h"
#include "core/repositories/secureAppSettingsRepository.h"

#ifdef AMNEZIA_DESKTOP
#include "core/utils/ipcClient.h"
#endif

#ifdef Q_OS_ANDROID
#include "core/protocols/androidVpnProtocol.h"
#endif

using namespace amnezia;

class VpnConnection : public QObject
{
    Q_OBJECT

public:
    explicit VpnConnection(SecureServersRepository* serversRepository, SecureAppSettingsRepository* appSettingsRepository, QObject* parent = nullptr);
    ~VpnConnection() override;

    static QString bytesPerSecToText(quint64 bytes);

    ErrorCode lastError() const;
    Vpn::ConnectionState connectionState() const;

    QSharedPointer<VpnProtocol> vpnProtocol() const;

    const QString &remoteAddress() const;
    void addSitesRoutes(const QString &gw, amnezia::RouteMode mode);

#ifdef Q_OS_ANDROID
    void restoreConnection();
#endif
    // AVPN (round 58 review, finding 3; Android): the service holds a session this object has no protocol for - one the
    // engine adopted or takes over from a STATUS snapshot after an earlier stop in this process (the protocol is dropped
    // at the end of every disconnect and restored only by the first snapshot, initConnectionState). Without it the
    // engine's stop was dropped here (disconnectFromVpn: no protocol = "already Disconnected") and the service's live
    // states reached nobody. Wired back the way the first snapshot does (restoreConnection), only when missing. No-op
    // elsewhere.
    Q_INVOKABLE void ensureAndroidProtocol();

public slots:
    void setRepositories(SecureServersRepository* serversRepository, SecureAppSettingsRepository* appSettingsRepository);
    void connectToVpn(const QString &serverId, DockerContainer container, const QJsonObject &vpnConfiguration);
    void reconnectToVpn();
    void disconnectFromVpn();

    void onKillSwitchModeChanged(bool enabled);
    // AVPN (round mac-D3, macOS): the lease on the person's intent in the service (KillSwitch::setHold): while the
    // intent is on and the kill switch setting is on, a stop of a session keeps the block for the next one.
    void syncKillSwitchHold(bool intentOn, const QStringList &controlPlaneAddrs);
    void disconnectSlots();

    void setConnectionState(Vpn::ConnectionState state);

private:
    int m_killSwitchHoldSent = -1; // AVPN (round mac-D3): the last lease sent (-1 = none yet), for the log only

signals:
    void bytesChanged(quint64 receivedBytes, quint64 sentBytes);
    void connectionStateChanged(Vpn::ConnectionState state);
    void vpnProtocolError(amnezia::ErrorCode error);

    void serviceIsNotReady();
    // AVPN (волна-3): §16-сторож не дождался ответа демона на status — демон мёртв/перезапускается.
    // Движок держит намерение (класс Component), подключение повторится, когда служба вернётся.
    void daemonLost();

protected slots:
    void onBytesChanged(quint64 receivedBytes, quint64 sentBytes);
    void onConnectionStateChanged(Vpn::ConnectionState state);

protected:
    QSharedPointer<VpnProtocol> m_vpnProtocol;

private:
    SecureServersRepository* m_serversRepository;
    SecureAppSettingsRepository* m_appSettingsRepository;

    QJsonObject m_vpnConfiguration;
    QJsonObject m_routeMode;
    QString m_remoteAddress;

    // Only for iOS for now, check counters
    QTimer m_checkTimer;

#ifdef Q_OS_ANDROID
   AndroidVpnProtocol* androidVpnProtocol = nullptr;

   AndroidVpnProtocol* createDefaultAndroidVpnProtocol();
   void createAndroidConnections();
#endif

   Vpn::ConnectionState m_connectionState;

   // AVPN (IPC-stall/2×deactivate fix, 2026-07-10): true ТОЛЬКО на время синхронного stop()
   // старого протокола внутри connectToVpn() — его транзитный Disconnected (эхо) не должен
   // приходить ПОСЛЕ уже выставленного Connecting (движок принимал эхо за терминал и передёргивал
   // старт заново → 2×deactivate/activate на один клик). Десктоп-only путь (см. setConnectionState).
   bool m_swallowTransitionalDisconnected = false;
   // AVPN (IPC-stall fix): поколение реконнекта — сторож в reconnectToVpn() действует только на
   // СВОЁ окно Reconnecting (иначе таймер прошлого реконнекта мог бы уронить следующий).
   quint64 m_reconnectGeneration = 0;
   // AVPN (волна-3): §16-сторож сначала спрашивает демона (status). Любое эхо статистики после
   // запроса = демон жив (statusUpdated → bytesChanged); остаёмся в Reconnecting и перевзводимся
   // (≤ 3 раз). Молчит 3 с → мёртв → честный Disconnected + daemonLost().
   bool m_reconnectProbing = false;
   bool m_reconnectProbeAnswered = false;
   int  m_reconnectRearms = 0;
   void armReconnectWatchdog(quint64 generation);
   // AVPN (волна «как апстрим», 2026-09-28): контейнер ПОСЛЕДНЕГО connectToVpn. Сервисный путь
   // Tribe не заводит сервер в репозиторий Amnezia → defaultServerId даёт None, и на каждом
   // Connected шла ветка «не-AWG»: 8,7 тыс. `Critical, trying to add invalid route` + 2178 резолвов
   // IPv6-CIDR (лог Mac 26–28.09). Фолбэк на фактический контейнер коннекта = семантика апстрима.
   DockerContainer m_connectContainer = DockerContainer::None;

   void createProtocolConnections();

   void appendSplitTunnelingConfig();
   void appendKillSwitchConfig();
};

#endif // VPNCONNECTION_H
