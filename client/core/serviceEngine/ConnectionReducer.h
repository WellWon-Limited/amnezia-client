// Tribe serviceEngine v2 — single-owner, event-driven multi-transport connection reducer.
#pragma once

#include "CandidateSelector.h"
#include "CatalogTrust.h"
#include "TransportAdapter.h"

#include <QStringList>

#include <optional>

namespace avpn {

enum class ConnectionPhase {
    Idle = 0,
    SelectingCandidate,
    ArmingGuard,
    StartingTransport,
    TunnelReady,
    VerifyingDns,
    VerifyingTraffic,
    ConnectedHealthy,
    VerificationUnknown,
    StoppingOld,
    Disconnecting,
    ReleasingGuard,
    Failed,
};

enum class ConnectionFailureStage {
    None = 0,
    Policy,
    Compile,
    TransportStart,
    TransportRuntime,
    TransportTimeout,
    TransportStopTimeout,
    VerificationDns,
    VerificationTraffic,
    VerificationEgress,
    VerificationFreeze,
    VerificationTimeout,
    VerificationAuthority,
    VerificationTrust,
};

// Typed terminal ownership hand-off to the coordinator. This is deliberately separate from the
// redacted diagnostic reason: control flow must never depend on presentation/log strings.
enum class ConnectionTerminalDisposition {
    None = 0,
    CatalogStale,
};

enum class VerificationDisposition {
    Verified = 0,
    CandidateFailed,
    InfrastructureUnavailable,
    // The authenticated account/device authority rejected this session. The tunnel must be
    // serialized to Stopped and must not be retained as a yellow/unknown connection.
    AuthorityRejected,
    // The accepted catalog/binding is no longer authoritative. Stop before coordinator refresh.
    CatalogStale,
    // A purpose-separated receipt signature/keyset proof could not be trusted. Stop and refresh
    // root-anchored trust state; never retry indefinitely on the live tunnel.
    TrustRefreshRequired,
};

enum class VerificationRetryDirective {
    None = 0,
    RetrySameAuthority,
    RefreshCatalog,
};

enum class PostTunnelVerificationStage {
    Dns = 0,
    Traffic,
};

struct VerificationToken {
    TransportOperationToken transportOperation;
    quint64 attempt = 0;
    bool isValid() const { return transportOperation.isValid() && attempt != 0; }
    friend bool operator==(const VerificationToken &left, const VerificationToken &right)
    {
        return left.transportOperation == right.transportOperation
               && left.attempt == right.attempt;
    }
    friend bool operator!=(const VerificationToken &left, const VerificationToken &right)
    {
        return !(left == right);
    }
};

struct PostTunnelVerificationResult {
    VerificationToken verification;
    VerificationDisposition disposition = VerificationDisposition::CandidateFailed;
    ConnectionFailureStage failureStage = ConnectionFailureStage::VerificationTraffic;
    QString typedReason;
    QString observedEgressId;
    qint64 latencyMs = -1;
    int retryAfterSeconds = 0;
    // Earliest expiry across the independent receipt quorum. Green must be re-proved before it;
    // the signed short lifetime is never stretched by a local timer.
    QDateTime verifiedUntilUtc;
    VerificationRetryDirective retryDirective = VerificationRetryDirective::None;
};

enum class ConnectionLifecycleWaitKind {
    None = 0,
    GuardArm,
    TransportStart,
    TransportStop,
    GuardRelease,
    Verification,
};

// Immutable identity captured by the coordinator's one-shot lifecycle deadline. Equality is the
// renewal fence: duplicate snapshots never extend a deadline, while every actual phase/session/
// policy/verification transition creates a new generation.
struct ConnectionLifecycleWait {
    ConnectionLifecycleWaitKind kind = ConnectionLifecycleWaitKind::None;
    TransportOperationToken session;
    VerificationToken verification;
    QByteArray nativeDispatchPolicySha256;

    bool isValid() const
    {
        switch (kind) {
        case ConnectionLifecycleWaitKind::GuardArm:
        case ConnectionLifecycleWaitKind::GuardRelease:
            return session.isValid() && nativeDispatchPolicySha256.size() == 32
                   && !verification.isValid();
        case ConnectionLifecycleWaitKind::TransportStart:
        case ConnectionLifecycleWaitKind::TransportStop:
            return session.isValid() && nativeDispatchPolicySha256.isEmpty()
                   && !verification.isValid();
        case ConnectionLifecycleWaitKind::Verification:
            return verification.isValid() && session == verification.transportOperation
                   && nativeDispatchPolicySha256.isEmpty();
        case ConnectionLifecycleWaitKind::None:
            break;
        }
        return false;
    }
    friend bool operator==(const ConnectionLifecycleWait &left,
                           const ConnectionLifecycleWait &right)
    {
        return left.kind == right.kind && left.session == right.session
               && left.verification == right.verification
               && left.nativeDispatchPolicySha256 == right.nativeDispatchPolicySha256;
    }
    friend bool operator!=(const ConnectionLifecycleWait &left,
                           const ConnectionLifecycleWait &right)
    { return !(left == right); }
};

class IPostTunnelVerificationObserver {
public:
    virtual ~IPostTunnelVerificationObserver() = default;
    // Stage callbacks are deferred and carry the same immutable attempt token as the result.
    // They are observability/state gates only; neither stage is a success receipt.
    virtual void onPostTunnelVerificationStage(VerificationToken verification,
                                               PostTunnelVerificationStage stage) = 0;
    virtual void onPostTunnelVerification(const PostTunnelVerificationResult &result) = 0;
};

class IPostTunnelVerifier {
public:
    virtual ~IPostTunnelVerifier() = default;
    virtual void setObserver(IPostTunnelVerificationObserver *observer) = 0;
    virtual bool start(const CatalogCandidate &candidate,
                       VerificationToken verification,
                       QString &error) = 0;
    virtual void cancel(VerificationToken verification) = 0;
    virtual void clearObserver(IPostTunnelVerificationObserver *expected) = 0;
};

struct ConnectionRuntimeSnapshot {
    ConnectionPhase phase = ConnectionPhase::Idle;
    quint64 operation = 0;
    TransportOperationToken session;
    VerificationToken verification;
    ConnectionLifecycleWait lifecycleWait;
    QString profileId;
    QString locationId;
    TransportKind transport = TransportKind::Unknown;
    quint64 configGeneration = 0;
    quint64 bindingGeneration = 0;
    QDateTime nativeProfileExpiresAt;
    QDateTime catalogFreshnessDeadline;
    QDateTime entitlementDeadline;
    QDateTime verifiedAtUtc;
    QDateTime verifiedUntilUtc;
    int attemptsUsed = 0;
    VerificationRetryDirective verificationRetryDirective =
        VerificationRetryDirective::None;
    int verificationRetryAfterSeconds = 0;
    bool guardArmed = false;
    bool guardOwnershipAmbiguous = false;
    bool hasAcceptedV2 = false;
    ConnectionFailureStage lastFailureStage = ConnectionFailureStage::None;
    ConnectionTerminalDisposition terminalDisposition = ConnectionTerminalDisposition::None;
    QString lastTypedReason;
    QStringList timeline; // bounded, redacted: never endpoints, UUIDs, keys, or native JSON
};

class IConnectionReducerObserver {
public:
    virtual ~IConnectionReducerObserver() = default;
    virtual void onConnectionReducerSnapshot(const ConnectionRuntimeSnapshot &snapshot) = 0;
};

class IConnectionRuntimeReducer {
public:
    virtual ~IConnectionRuntimeReducer() = default;
    virtual void setObserver(IConnectionReducerObserver *observer) = 0;
    virtual void clearObserver(IConnectionReducerObserver *expected) = 0;
    virtual bool connectAcceptedCatalog(
        const Catalog &catalog, QList<CatalogCandidate> immutableCompatibleCandidates,
        const QHash<QString, CandidateHistory> &history, CandidateSelectionRequest request,
        const CatalogRuntimeAuthority &authority, QString &error) = 0;
    virtual bool reconcileAcceptedCatalog(
        const Catalog &catalog, QList<CatalogCandidate> immutableCompatibleCandidates,
        const QHash<QString, CandidateHistory> &history, CandidateSelectionRequest request,
        const CatalogRuntimeAuthority &authority, QString &error) = 0;
    virtual void disconnect() = 0;
    virtual bool retryVerification(QString &error) = 0;
    virtual void onAuthorityDeadline(TransportOperationToken operation) = 0;
    virtual void onVerificationFreshnessDeadline(VerificationToken verification) = 0;
    virtual void onTransportTimeout(TransportOperationToken operation) = 0;
    virtual void onGuardArmTimeout(TransportOperationToken operation,
                                   QByteArray nativeDispatchPolicySha256) = 0;
    virtual void onGuardReleaseTimeout(TransportOperationToken operation) = 0;
    virtual void onStopTimeout(TransportOperationToken operation) = 0;
    virtual void onVerificationTimeout(VerificationToken verification) = 0;
    virtual void onGuardRecoveryReleased(const ConnectionGuardEvent &identity) = 0;
    virtual const QHash<QString, CandidateHistory> &updatedHistory() const = 0;
};

class ConnectionReducer final : public ITransportAdapterObserver,
                                public IPostTunnelVerificationObserver,
                                public IConnectionSessionGuardObserver,
                                public IConnectionRuntimeReducer {
public:
    ConnectionReducer(TransportAdapterRegistry *registry,
                      IPostTunnelVerifier *verifier,
                      IConnectionSessionGuard *guard,
                      IConnectionClock *clock = nullptr);
    ~ConnectionReducer();

    void setObserver(IConnectionReducerObserver *observer) override { m_observer = observer; }
    void clearObserver(IConnectionReducerObserver *expected) override
    { if (m_observer == expected) m_observer = nullptr; }

    // `catalog` must already have crossed CatalogAcceptance. Calling this permanently closes the
    // in-memory legacy gate even if all candidates are incompatible or connection later fails.
    bool connectAcceptedCatalog(const Catalog &catalog,
                                QList<CatalogCandidate> immutableCompatibleCandidates,
                                const QHash<QString, CandidateHistory> &history,
                                CandidateSelectionRequest request,
                                const CatalogRuntimeAuthority &authority,
                                QString &error) override;
    // Reconciles a newer accepted catalog. Exact same native material may renew authority in place;
    // any material/policy change follows the ordinary serialized Stopped -> start path.
    bool reconcileAcceptedCatalog(const Catalog &catalog,
                                  QList<CatalogCandidate> immutableCompatibleCandidates,
                                  const QHash<QString, CandidateHistory> &history,
                                  CandidateSelectionRequest request,
                                  const CatalogRuntimeAuthority &authority,
                                  QString &error) override;
    void disconnect() override;
    bool retryVerification(QString &error) override;

    void onTransportEvent(const TransportEvent &event) override;
    void onConnectionSessionGuardEvent(const ConnectionGuardEvent &event) override;
    void onPostTunnelVerificationStage(VerificationToken verification,
                                       PostTunnelVerificationStage stage) override;
    void onPostTunnelVerification(const PostTunnelVerificationResult &result) override;
    void onTransportTimeout(TransportOperationToken operation) override;
    void onGuardArmTimeout(TransportOperationToken operation,
                           QByteArray nativeDispatchPolicySha256) override;
    void onGuardReleaseTimeout(TransportOperationToken operation) override;
    void onStopTimeout(TransportOperationToken operation) override;
    // Timer owners must capture the immutable verification-attempt token. A transport token alone
    // cannot distinguish a cancelled verifier attempt from a retry on the same live tunnel.
    void onVerificationTimeout(VerificationToken verification) override;
    void onGuardRecoveryReleased(const ConnectionGuardEvent &identity) override;
    // Timer/wake owners capture the exact session token. Early/stale callbacks are harmless;
    // crossing any authority deadline serializes a hard stop and never attempts fallback.
    void onAuthorityDeadline(TransportOperationToken operation) override;
    void onVerificationFreshnessDeadline(VerificationToken verification) override;

    ConnectionRuntimeSnapshot snapshot() const;
    ConnectionPhase phase() const { return m_phase; }
    bool hasAcceptedV2() const { return m_hasAcceptedV2; }
    bool legacyV1Allowed() const { return !m_hasAcceptedV2; }
    const QHash<QString, CandidateHistory> &updatedHistory() const override
    { return m_workingHistory; }

private:
    struct AuthorityRenewalTarget {
        Catalog catalog;
        QList<CatalogCandidate> candidates;
        QHash<QString, CandidateHistory> history;
        CandidateSelectionRequest request;
        CatalogRuntimeAuthority authority;
        CatalogCandidate replacement;
        TransportAuthorityRenewalDispatch dispatch;
    };

    bool startNext(QString &error);
    bool beginVerification(QString &error);
    QList<RankedCandidate> rankRemaining() const;
    void markProfileAttemptFailed(const CatalogCandidate &candidate,
                                  bool startedTransportPathFailure);
    void failActive(ConnectionFailureStage stage, const QString &typedReason);
    void stopActiveTerminal(
        ConnectionFailureStage stage, const QString &typedReason,
        ConnectionTerminalDisposition disposition = ConnectionTerminalDisposition::None);
    void handleStopped(TransportOperationToken operation);
    void finishDisconnected();
    void setFailure(ConnectionFailureStage stage, const QString &typedReason);
    void addTimeline(const QString &entry);
    void notifyObserver();
    void clearActive();
    bool releaseGuardWithoutNativeOwner(QString &error);
    void handleGuardArmRejected(const QString &typedReason);
    bool activatePendingAfterGuard(QString &error);
    void finishAfterGuardReleased();
    QDateTime eventNowUtc() const;
    void commitAuthorityRenewal(AuthorityRenewalTarget target);
    void clearAuthorityRenewalTransactions();

    TransportAdapterRegistry *m_registry = nullptr;
    IPostTunnelVerifier *m_verifier = nullptr;
    IConnectionSessionGuard *m_guard = nullptr;
    IConnectionClock *m_clock = nullptr;
    ConnectionPhase m_phase = ConnectionPhase::Idle;
    bool m_hasAcceptedV2 = false;
    bool m_disconnectRequested = false;
    bool m_terminalStopRequested = false;
    // A live inner session has been stopped for replacement/fallback. Until another inner start
    // dispatch is accepted, the exact outer blocking owner is the only fail-closed network owner
    // and must survive bounded candidate exhaustion. Only an explicit Disconnect (or an audited
    // terminal-authority path) may release it.
    bool m_failClosedBarrierUntilInnerStart = false;
    bool m_guardArmed = false;
    TransportOperationToken m_guardToken;
    QString m_guardOuterSessionId;
    QByteArray m_guardPolicySha256;
    QString m_guardExpectedRuntimeSessionId;
    bool m_guardOwnershipAmbiguous = false;
    enum class GuardAmbiguityKind { None, Arm, Release, Lost };
    GuardAmbiguityKind m_guardAmbiguityKind = GuardAmbiguityKind::None;
    TransportOperationToken m_quarantinedGuardToken;
    QByteArray m_quarantinedGuardPolicySha256;
    QString m_quarantinedExpectedRuntimeSessionId;
    QString m_quarantinedGuardOuterSessionId;
    ITransportAdapter *m_pendingAdapter = nullptr;
    CatalogCandidate m_pendingCandidate;
    PreparedTransportStart m_pendingPrepared;
    TransportOperationToken m_pendingToken;
    TransportOperationToken m_previousGuardTokenAtArm;
    TransportOperationToken m_releasingGuardToken;
    ConnectionPhase m_phaseAfterGuardRelease = ConnectionPhase::Failed;
    quint64 m_operationCounter = 0;
    quint64 m_sessionCounter = 0;
    quint64 m_verificationAttemptCounter = 0;
    quint64 m_operation = 0;
    QList<CatalogCandidate> m_candidates;
    // Redacted snapshot identity for a candidate that failed before a native session token existed
    // (compiler/policy rejection). The full object never leaves core; snapshot() exposes only its
    // profile/location/transport/generations so the coordinator can enqueue a typed outcome.
    CatalogCandidate m_lastAttemptedCandidate;
    QHash<QString, CandidateHistory> m_workingHistory;
    CandidateSelectionRequest m_selectionRequest;
    int m_attemptsUsed = 0;
    int m_maxAttempts = 0;
    int m_profileCooldownS = 300;
    QDateTime m_catalogFreshnessDeadline;
    QDateTime m_entitlementExpiresAt;
    CatalogRuntimeAuthority m_runtimeAuthority;
    ITransportAdapter *m_activeAdapter = nullptr;
    CatalogCandidate m_activeCandidate;
    TransportOperationToken m_activeToken;
    VerificationToken m_activeVerification;
    ITransportAdapter *m_stoppingAdapter = nullptr;
    CatalogCandidate m_stoppingCandidate;
    TransportOperationToken m_stoppingToken;
    ConnectionFailureStage m_lastFailureStage = ConnectionFailureStage::None;
    ConnectionTerminalDisposition m_terminalDisposition =
        ConnectionTerminalDisposition::None;
    QString m_lastTypedReason;
    QStringList m_timeline;
    QDateTime m_verifiedAtUtc;
    QDateTime m_verifiedUntilUtc;
    VerificationRetryDirective m_verificationRetryDirective =
        VerificationRetryDirective::None;
    int m_verificationRetryAfterSeconds = 0;
    std::optional<AuthorityRenewalTarget> m_pendingAuthorityRenewal;
    std::optional<AuthorityRenewalTarget> m_queuedAuthorityRenewal;
    IConnectionReducerObserver *m_observer = nullptr;
};

} // namespace avpn
