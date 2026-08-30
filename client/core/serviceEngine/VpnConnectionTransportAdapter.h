// Tribe serviceEngine v2 — concrete AWG/Xray adapters over the existing native VpnConnection.
#pragma once

#include "NativeConnectionPolicy.h"
#include "NativeProfileCompiler.h"
#include "NativeRuntimeIdentity.h"
#include "NativeSessionGuardEvent.h"

#include <QObject>
#include <QPointer>

class VpnConnection;
class SecureAppSettingsRepository;

namespace avpn {

// Production C++ bridge between the pure reducer guard contract and VpnConnection's typed native
// PREPARE/RELEASE channel. Presence of this class is not readiness evidence: product wiring must
// still gate on a platform implementation that can emit the closed-schema receipts.
class VpnConnectionSessionGuard final : public QObject, public IConnectionSessionGuard {
public:
    explicit VpnConnectionSessionGuard(VpnConnection *connection,
                                       QObject *parent = nullptr);

    void setObserver(IConnectionSessionGuardObserver *observer) override
    { m_observer = observer; }
    void clearObserver(IConnectionSessionGuardObserver *expected) override
    { if (m_observer == expected) m_observer = nullptr; }
    bool prepareAndArm(const PreparedTransportStart &prepared,
                       TransportOperationToken operation,
                       QString &error) override;
    bool releaseExact(TransportOperationToken operation,
                      const QString &outerSessionId,
                      QString &error) override;
    bool isArmedFor(TransportOperationToken operation,
                    const QString &outerSessionId = {}) const override;
    bool reconcileTimedOutArmExact(const PreparedTransportStart &prepared,
                                   TransportOperationToken operation,
                                   QString &error) override;
    bool reconcileTimedOutReleaseExact(TransportOperationToken operation,
                                       const QString &outerSessionId,
                                       QString &error) override;
    bool completeRecoveryReleasedExact(const ConnectionGuardEvent &identity) override;

private:
    void consumeNativeEvent(const QJsonObject &event);

    QPointer<VpnConnection> m_connection;
    IConnectionSessionGuardObserver *m_observer = nullptr;
    TransportOperationToken m_pendingArm;
    QByteArray m_pendingPolicySha256;
    QString m_pendingExpectedRuntimeSessionId;
    TransportOperationToken m_armedToken;
    QByteArray m_armedPolicySha256;
    QString m_armedOuterSessionId;
    QString m_armedExpectedRuntimeSessionId;
    TransportOperationToken m_pendingRelease;
    ConnectionGuardEvent m_recoveryIdentity;
};

class VpnConnectionTransportAdapter final : public QObject, public ITransportAdapter {
public:
    VpnConnectionTransportAdapter(VpnConnection *connection,
                                  TransportKind transport,
                                  NativeProfileCompileOptions options,
                                  SecureAppSettingsRepository *settings,
                                  QObject *parent = nullptr,
                                  IConnectionClock *clock = nullptr);

    TransportKind transport() const override { return m_transport; }
    amnezia::DockerContainer nativeContainer() const override;
    QSet<QString> supportedProfileKinds() const override;
    bool validateAndCompile(const CatalogCandidate &candidate,
                            CompiledNativeProfile &compiled,
                            QString &error) const override;
    bool prepareStart(const CompiledNativeProfile &compiled,
                      TransportOperationToken operation,
                      PreparedTransportStart &prepared,
                      QString &error) override;
    void setObserver(ITransportAdapterObserver *observer) override { m_observer = observer; }
    void clearObserver(ITransportAdapterObserver *expected) override
    { if (m_observer == expected) m_observer = nullptr; }
    bool start(const PreparedTransportStart &prepared,
               TransportOperationToken operation,
               QString &error) override;
    TransportAuthorityRenewalResult renewRuntimeAuthority(
        const CatalogCandidate &candidate, const CatalogRuntimeAuthority &authority,
        TransportOperationToken operation, TransportAuthorityRenewalDispatch &dispatch,
        QString &error) override;
    void stop(TransportOperationToken operation) override;
    TransportTelemetry telemetry() const override;

    void setAwgKeys(const ClientKeys &keys) { m_options.awgKeys = keys; }
    bool setProtectedTunnelIpLiterals(const QStringList &literals, QString &error);
    TransportOperationToken activeToken() const { return m_activeToken; }

private:
    friend class BundledNativeTransportAdapters;
    enum class Phase { Idle, Starting, Running, Stopping };
    void onNativeRuntimeStatus(const QJsonObject &statusObject);
    void onNativeRuntimeAuthorityRenewalReceipt(const QJsonObject &receipt);
    void deliver(TransportEventKind kind, const QString &reason = {},
                 TransportOperationToken token = {}, const QString &renewalId = {},
                 const QByteArray &authorityCommitmentSha256 = {},
                 const QDateTime &appliedHardDeadlineUtc = {});
    NativeConnectionPolicySnapshot snapshotConnectionPolicy(
        const CompiledNativeProfile &compiled) const;
    bool ownsNativeSession() const { return m_phase != Phase::Idle && m_activeToken.isValid(); }

    QPointer<VpnConnection> m_connection;
    TransportKind m_transport = TransportKind::Unknown;
    NativeProfileCompileOptions m_options;
    QPointer<SecureAppSettingsRepository> m_settings;
    ITransportAdapterObserver *m_observer = nullptr;
    TransportOperationToken m_activeToken;
    Phase m_phase = Phase::Idle;
    CompiledNativeProfile m_activeProfile;
    QJsonObject m_activeFinalConfiguration;
    QByteArray m_activeDispatchPolicySha256;
    QString m_activeOuterSessionId;
    QString m_expectedRuntimeSessionId;
    QString m_lastError;
    bool m_splitOn = false;
    bool m_dnsMaskApplied = false;
    IConnectionClock *m_clock = nullptr; // non-owning; coordinator-owned trusted UTC source
    NativeRuntimeIdentityGate m_runtimeIdentity;
    bool m_nativeDispatchReady = false;
    struct PendingAuthorityRenewal {
        TransportOperationToken operation;
        QString renewalId;
        QByteArray authorityCommitmentSha256;
        QDateTime requestedHardDeadlineUtc;
        CompiledNativeProfile compiled;
        QJsonObject finalConfiguration;
        bool isValid() const
        {
            return operation.isValid() && !renewalId.isEmpty()
                   && authorityCommitmentSha256.size() == 32
                   && requestedHardDeadlineUtc.isValid();
        }
    };
    PendingAuthorityRenewal m_pendingAuthorityRenewal;
};

class IProtectedTransportAdapters {
public:
    virtual ~IProtectedTransportAdapters() = default;
    virtual bool setProtectedTunnelIpLiterals(const QStringList &literals,
                                              QString &error) = 0;
};

// Owns the two concrete adapters while TransportAdapterRegistry keeps non-owning pointers.
class BundledNativeTransportAdapters final : public QObject,
                                             public IProtectedTransportAdapters {
public:
    BundledNativeTransportAdapters(VpnConnection *connection,
                                   NativeProfileCompileOptions options,
                                   SecureAppSettingsRepository *settings,
                                   QObject *parent = nullptr,
                                   IConnectionClock *clock = nullptr);

    bool registerInto(TransportAdapterRegistry &registry, QString &error);
    // Auto requires both exact runtime-identity bridges. A forced mode may register only its
    // proved transport; unavailable transports remain absent/fail-closed.
    bool registerForMode(TransportAdapterRegistry &registry, ConnectionMode mode,
                         QString &error);
    void setAwgKeys(const ClientKeys &keys);
    bool setProtectedTunnelIpLiterals(const QStringList &literals,
                                      QString &error) override;
    VpnConnectionTransportAdapter *awg() const { return m_awg; }
    VpnConnectionTransportAdapter *xray() const { return m_xray; }

private:
    VpnConnectionTransportAdapter *m_awg = nullptr;
    VpnConnectionTransportAdapter *m_xray = nullptr;
};

} // namespace avpn
