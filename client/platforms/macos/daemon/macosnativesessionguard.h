#ifndef MACOSNATIVESESSIONGUARD_H
#define MACOSNATIVESESSIONGUARD_H

#include <QDateTime>
#include <QJsonObject>
#include <QMutex>
#include <QString>

#include <functional>
#include <memory>

// Root-helper owned outer-session state for catalog-v2 on normal macOS builds.
// The helper arms PF before either native core starts and keeps that policy installed while the
// GUI replaces an AWG/Xray inner.  This class intentionally knows nothing about QtRO or the GUI;
// IpcServer is the authenticated transport and supplies the real PF callbacks.
class MacosNativeSessionGuard final
{
public:
    struct Backend {
        std::function<bool(const QJsonObject &)> armPolicy;
        std::function<bool()> releasePolicy;
        std::function<bool()> quarantinePolicy;
    };

    // The production default is a QTimer driven by QElapsedTimer. Tests inject a deterministic
    // single-shot scheduler and independent wall/monotonic clocks. `cancel` must prevent a queued
    // callback from being newly entered after it returns; callbacks already running are fenced by
    // the guard's lifetime gate and generation.
    struct AuthorityWatchdog {
        std::function<QDateTime()> wallUtcNow;
        std::function<qint64()> monotonicMilliseconds;
        std::function<bool(qint64, std::function<void()>)> scheduleOnce;
        std::function<void()> cancel;

        bool isComplete() const
        {
            return wallUtcNow && monotonicMilliseconds && scheduleOnce && cancel;
        }
    };

    enum class Phase {
        Idle,
        Armed,
        Starting,
        Running,
        Stopping,
        Quarantined,
    };

    explicit MacosNativeSessionGuard(Backend backend = {}, QString leasePath = {},
                                     AuthorityWatchdog watchdog = {});
    ~MacosNativeSessionGuard();

    // Called after the helper has initialized its PF backend.  A durable non-idle lease is always
    // restored as Quarantined and re-arms the stored non-bearer firewall projection before IPC is
    // made available. Corrupt state invokes the fail-closed backend and never becomes Idle.
    bool restoreAfterDaemonStart(QString *error = nullptr);

    QJsonObject prepare(const QJsonObject &request);
    QJsonObject claimInner(const QJsonObject &request);
    QJsonObject beginStop(const QJsonObject &request);
    QJsonObject markRunning(const QJsonObject &request);
    QJsonObject markStopped(const QJsonObject &request);
    QJsonObject renewAuthority(const QJsonObject &request);
    QJsonObject release(const QJsonObject &request);

    // Losing the authenticated GUI never removes PF.  A replacement GUI must resolve the exact
    // persisted helper identity by adopt-or-stop before catalog-v2 becomes available again.
    void authenticatedChannelLost();
    QJsonObject currentGuardEvent() const;

    bool validateRecoveryConfiguration(const QJsonObject &configuration,
                                       QString *error = nullptr) const;
    QJsonObject adoptRecovered(const QJsonObject &request,
                               const QJsonObject &configuration);
    QJsonObject stopAndReleaseRecovered(const QJsonObject &request,
                                        const std::function<bool()> &exactStop);

    Phase phase() const;
    QString protocol() const;
    QString expectedRuntimeSessionId() const;
    QString outerSessionId() const;

    // Independent platform encoder.  It mirrors native_dispatch_policy_v1 and is exercised with
    // the same golden files as C++/Kotlin/Swift.  No serviceEngine object is linked into root.
    static bool policyDigest(const QJsonObject &configuration, QString &digestHex,
                             QString *error = nullptr);

private:
    struct Identity {
        QString operation;
        QString session;
        QString policySha256;
        QString outerSessionId;
        QString expectedRuntimeSessionId;
    };

    static bool parsePrepare(const QJsonObject &request, Identity &identity,
                             QJsonObject &configuration, QString &protocol,
                             QJsonObject &firewallPolicy, QString &error);
    static bool parseIdentityRequest(const QJsonObject &request, const QString &type,
                                     bool requireOuter, Identity &identity,
                                     QString *protocol, QString &error);
    static QJsonObject event(const Identity &identity, const QString &kind,
                             const QString &reason = {});
    static QJsonObject recoveryReceipt(const Identity &identity, const QString &action,
                                       const QString &kind, const QString &reason = {});
    static QJsonObject commandReceipt(const QString &action, const Identity &identity,
                                      bool accepted, const QString &reason);
    static QJsonObject authorityRenewalReceipt(
        const QJsonObject &request, const QString &kind,
        const QString &hardDeadline, const QString &reason);
    bool sameIdentity(const Identity &identity, bool requireOuter) const;
    bool persistLease(QString *error = nullptr) const;
    bool clearLease(QString *error = nullptr) const;
    bool loadLease(Identity &identity, QString &protocol, QJsonObject &firewallPolicy,
                   QJsonObject &runtimeAuthority, QString &nonAuthorityConfigurationSha256,
                   QString &error) const;
    bool recoveryConfigurationMatchesLocked(const QJsonObject &configuration,
                                            QJsonObject &authority,
                                            QString &nonAuthorityConfigurationSha256,
                                            QString &error) const;
    bool armAuthorityWatchdogLocked(const QJsonObject &authority, QString &error);
    bool authorityWatchdogCoversLocked(const QJsonObject &authority,
                                       Phase requiredPhase,
                                       quint64 generation) const;
    bool scheduleAuthorityWatchdogTickLocked(quint64 generation, qint64 delayMs,
                                             QString &error);
    void cancelAuthorityWatchdogLocked();
    void authorityWatchdogFired(quint64 generation);
    void expireAuthorityLocked(const QString &reason);

    struct DefaultAuthorityWatchdog;
    struct WatchdogLifetime;

    mutable QMutex m_mutex;
    Backend m_backend;
    Phase m_phase = Phase::Idle;
    Identity m_identity;
    QString m_protocol;
    QJsonObject m_firewallPolicy;
    QJsonObject m_runtimeAuthority;
    QString m_nonAuthorityConfigurationSha256;
    QString m_leasePath;
    AuthorityWatchdog m_watchdog;
    std::unique_ptr<DefaultAuthorityWatchdog> m_defaultWatchdog;
    std::shared_ptr<WatchdogLifetime> m_watchdogLifetime;
    quint64 m_watchdogGeneration = 0;
    bool m_watchdogArmed = false;
    QDateTime m_watchdogTrustedUtc;
    QDateTime m_watchdogHardDeadlineUtc;
    qint64 m_watchdogMonotonicAnchorMs = 0;
    qint64 m_watchdogDeadlineMonotonicMs = 0;
};

#endif // MACOSNATIVESESSIONGUARD_H
