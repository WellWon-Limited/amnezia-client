#ifndef VPNCONNECTION_H
#define VPNCONNECTION_H

#include <QObject>
#include <QMetaObject>
#include <QJsonObject>
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
    // AVPN v2: validated platform runtime identity bridge. Empty/false on platforms whose native
    // core cannot yet prove opaque session ownership.
    QJsonObject nativeRuntimeStatus() const;
    // Closed-schema, pre-connect inventory generated from the same package lock as native targets.
    QJsonObject nativeEngineManifest() const;
    bool requestNativeSessionGuardArm(const QJsonObject &configuration,
                                      const QString &operation, const QString &session,
                                      const QString &policyHashHex,
                                      const QString &expectedRuntimeSessionId);
    bool activateNativeSession(const QJsonObject &configuration,
                               const QString &operation, const QString &session,
                               const QString &outerSessionId,
                               const QString &expectedRuntimeSessionId);
    // Dispatch-only. Completion is the closed-schema nativeRuntimeAuthorityRenewalReceipt signal;
    // a true return must never be interpreted as durable application.
    bool renewNativeRuntimeAuthority(const QJsonObject &configuration,
                                     const QString &operation, const QString &session,
                                     const QString &outerSessionId,
                                     const QString &expectedRuntimeSessionId,
                                     const QString &renewalId,
                                     const QString &authorityCommitmentHex);
    bool stopNativeSession(const QString &outerSessionId,
                           const QString &expectedRuntimeSessionId);
    bool requestNativeSessionGuardRelease(const QString &operation, const QString &session,
                                          const QString &outerSessionId);
    bool requestNativeSessionGuardReconcileArm(
        const QString &operation, const QString &session, const QString &policyHashHex,
        const QString &expectedRuntimeSessionId);
    bool requestNativeSessionGuardReconcileRelease(
        const QString &operation, const QString &session, const QString &policyHashHex,
        const QString &outerSessionId, const QString &expectedRuntimeSessionId);
    bool nativeSessionGuardRecoveryPending() const;
    QJsonObject nativeSessionGuardRecoveryEvent() const;
    bool requestNativeSessionGuardRecoveryResolution(
        const QJsonObject &exactRecoveryEvent, const QString &action,
        const QJsonObject &validatedPreparedConfiguration = {});
    QString nativeRuntimeSessionId() const;
    // Capability is protocol-specific: production desktop currently proves
    // Xray sessions, while Apple NE and Android prove both bundled engines.
    bool nativeRuntimeIdentitySupported(Proto proto) const;
    bool nativeRuntimeIdentitySupported() const;
    // A method surface is not proof. This stays false for a transport until its outer guard,
    // exact runtime identity, secure handoff and teardown receipts pass the release artifact and
    // real-device gate for that platform flavor.
    bool nativeSessionGuardSupported(Proto proto) const;
    void addSitesRoutes(const QString &gw, amnezia::RouteMode mode);

#ifdef Q_OS_ANDROID
    void restoreConnection();
#endif

public slots:
    void setRepositories(SecureServersRepository* serversRepository, SecureAppSettingsRepository* appSettingsRepository);
    void connectToVpn(const QString &serverId, DockerContainer container, const QJsonObject &vpnConfiguration);
    // AVPN v2: configuration already contains an immutable, sanitized local route/DNS policy.
    // This path must not reread or mutate repositories after the final dispatch gate.
    void connectToVpnWithPreparedPolicy(const QString &serverId, DockerContainer container,
                                        const QJsonObject &vpnConfiguration);
    void reconnectToVpn();
    void disconnectFromVpn();

    void onKillSwitchModeChanged(bool enabled);
    void disconnectSlots();

    void setConnectionState(Vpn::ConnectionState state);

signals:
    void bytesChanged(quint64 receivedBytes, quint64 sentBytes);
    void connectionStateChanged(Vpn::ConnectionState state);
    void nativeRuntimeStatusChanged(QJsonObject status); // AVPN v2: session-scoped status only.
    void nativeRuntimeAuthorityRenewalReceipt(QJsonObject receipt);
    void nativeEngineManifestChanged(QJsonObject manifest);
    void nativeSessionGuardEvent(QJsonObject event);
    void nativeSessionGuardRecoveryRequired(QJsonObject event);
    void nativeSessionGuardRecoveryResolved(QJsonObject receipt);
    void vpnProtocolError(amnezia::ErrorCode error);

    void serviceIsNotReady();

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

   // AVPN: a newly constructed connection has no native owner.  Leaving this scalar
   // uninitialized made the clean-install ownership gate nondeterministic before the first signal.
   Vpn::ConnectionState m_connectionState = Vpn::Disconnected;

   // AVPN (IPC-stall/2×deactivate fix, 2026-07-10): true ТОЛЬКО на время синхронного stop()
   // старого протокола внутри connectToVpn() — его транзитный Disconnected (эхо) не должен
   // приходить ПОСЛЕ уже выставленного Connecting (движок принимал эхо за терминал и передёргивал
   // старт заново → 2×deactivate/activate на один клик). Десктоп-only путь (см. setConnectionState).
   bool m_swallowTransitionalDisconnected = false;
   // AVPN (IPC-stall fix): поколение реконнекта — сторож в reconnectToVpn() действует только на
   // СВОЁ окно Reconnecting (иначе таймер прошлого реконнекта мог бы уронить следующий).
   quint64 m_reconnectGeneration = 0;
   // AVPN v2: authoritative container for the currently dispatched native profile. Tribe profile
   // ids are not SecureServersRepository ids, so repository lookup cannot drive AWG/Xray routing.
   DockerContainer m_activeContainer = DockerContainer::None;
   bool m_hasPreparedConnectionPolicy = false; // AVPN v2: exact config owns route policy.
   QJsonObject m_nativeEngineManifest;
   // Normal-macOS catalog-v2 state is owned durably by the authenticated root helper.  These
   // values are only the GUI's exact mirror; process loss is reconciled from helper status before
   // another connection can be dispatched.
   QJsonObject m_desktopNativeGuardEvent;
   QJsonObject m_desktopNativeGuardConfiguration;
   QJsonObject m_desktopNativeGuardRecoveryEvent;
   bool m_desktopNativeGuardRecoveryPending = false;

   void createProtocolConnections();

   void connectToVpnImpl(const QString &serverId, DockerContainer container,
                         const QJsonObject &vpnConfiguration, bool hasPreparedPolicy);
   void addPreparedSitesRoutes(const QString &gw);
   void requestDesktopEngineManifest();
   void requestDesktopNativeGuardRecoveryStatus();
   void consumeDesktopNativeRuntimeStatus(const QJsonObject &status);

   void appendSplitTunnelingConfig();
   void appendKillSwitchConfig();
};

#endif // VPNCONNECTION_H
