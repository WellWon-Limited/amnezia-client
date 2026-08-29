// Tribe catalog v2 — event-driven product coordinator. No nested loops, no QML authority.
#pragma once

#include "CatalogAcceptance.h"
#include "CatalogConnectionFacade.h"
#include "CatalogKeysetClient.h"
#include "CatalogOutcomeClient.h"
#include "CatalogResolveClient.h"
#include "CatalogSecureStore.h"
#include "CatalogTrustedClock.h"
#include "NativeSessionGuardEvent.h"
#include "PostTunnelReceiptVerifier.h"
#include "RuntimeEngineManifest.h"
#include "VpnConnectionTransportAdapter.h"

#include <QObject>
#include <QPointer>
#include <QUrl>

#include <functional>
#include <optional>

class QTimer;
class QSettings;

namespace avpn {

struct ConnectionLifecycleDeadlineArm {
    quint64 generation = 0;
    ConnectionLifecycleWait wait;
    bool isValid() const { return generation != 0 && wait.isValid(); }
};

// Pure generation fence used by the Qt scheduler and deterministic host tests. `replace` returns
// no arm for duplicate snapshots, so observer chatter cannot silently renew a lifecycle deadline.
class ConnectionLifecycleDeadlineFence {
public:
    std::optional<ConnectionLifecycleDeadlineArm> replace(
        const ConnectionLifecycleWait &wait);
    bool consume(const ConnectionLifecycleDeadlineArm &arm,
                 const ConnectionLifecycleWait &current);
    void clear();
    quint64 generation() const { return m_generation; }

private:
    quint64 m_generation = 0;
    ConnectionLifecycleWait m_wait;
    bool m_active = false;
};

bool dispatchConnectionLifecycleTimeout(IConnectionRuntimeReducer *reducer,
                                        const ConnectionLifecycleWait &wait);

struct VerificationRetryDeadlineKey {
    TransportOperationToken session;
    VerificationRetryDirective directive = VerificationRetryDirective::None;
    int retryAfterSeconds = 0;
    quint64 configGeneration = 0;
    quint64 bindingGeneration = 0;
    quint64 catalogRevision = 0;
    quint64 pathEpoch = 0;
    QDateTime nativeProfileExpiresAt;
    QDateTime catalogFreshnessDeadline;
    QDateTime entitlementDeadline;
    bool isValid() const
    {
        return session.isValid() && directive != VerificationRetryDirective::None
               && retryAfterSeconds >= 1 && retryAfterSeconds <= 300
               && configGeneration != 0 && bindingGeneration != 0
               && catalogRevision != 0 && pathEpoch != 0
               && nativeProfileExpiresAt.isValid()
               && catalogFreshnessDeadline.isValid() && entitlementDeadline.isValid();
    }
    friend bool operator==(const VerificationRetryDeadlineKey &left,
                           const VerificationRetryDeadlineKey &right)
    {
        return left.session == right.session && left.directive == right.directive
            && left.retryAfterSeconds == right.retryAfterSeconds
            && left.configGeneration == right.configGeneration
            && left.bindingGeneration == right.bindingGeneration
            && left.catalogRevision == right.catalogRevision && left.pathEpoch == right.pathEpoch
            && left.nativeProfileExpiresAt == right.nativeProfileExpiresAt
            && left.catalogFreshnessDeadline == right.catalogFreshnessDeadline
            && left.entitlementDeadline == right.entitlementDeadline;
    }
    friend bool operator!=(const VerificationRetryDeadlineKey &left,
                           const VerificationRetryDeadlineKey &right)
    { return !(left == right); }
};

struct VerificationRetryDeadlineArm {
    quint64 generation = 0;
    VerificationRetryDeadlineKey key;
    bool isValid() const { return generation != 0 && key.isValid(); }
};

class VerificationRetryDeadlineFence {
public:
    std::optional<VerificationRetryDeadlineArm> replace(
        const VerificationRetryDeadlineKey &key);
    bool consume(const VerificationRetryDeadlineArm &arm,
                 const VerificationRetryDeadlineKey &current);
    void clear();
private:
    quint64 m_generation = 0;
    VerificationRetryDeadlineKey m_key;
    bool m_active = false;
};

// Schedules renewal while the current signed receipt still covers the session.  Keeping this pure
// makes the five-minute survival invariant deterministic in host tests (receipt max lifetime is
// itself five minutes, so an at-expiry refresh can never prove continuous coverage).
qint64 proactiveReceiptRefreshDelayMs(const QDateTime &nowUtc,
                                      const QDateTime &verifiedUntilUtc,
                                      int configuredSafetyMarginSeconds);

struct ReceiptRefreshDeadlineKey {
    VerificationToken verification;
    quint64 configGeneration = 0;
    quint64 bindingGeneration = 0;
    QDateTime verifiedUntilUtc;
    bool isValid() const
    {
        return verification.isValid() && configGeneration != 0 && bindingGeneration != 0
               && verifiedUntilUtc.isValid();
    }
    friend bool operator==(const ReceiptRefreshDeadlineKey &left,
                           const ReceiptRefreshDeadlineKey &right)
    {
        return left.verification == right.verification
               && left.configGeneration == right.configGeneration
               && left.bindingGeneration == right.bindingGeneration
               && left.verifiedUntilUtc == right.verifiedUntilUtc;
    }
    friend bool operator!=(const ReceiptRefreshDeadlineKey &left,
                           const ReceiptRefreshDeadlineKey &right)
    { return !(left == right); }
};

struct ReceiptRefreshDeadlineArm {
    quint64 generation = 0;
    ReceiptRefreshDeadlineKey key;
    bool isValid() const { return generation != 0 && key.isValid(); }
};

class ReceiptRefreshDeadlineFence {
public:
    std::optional<ReceiptRefreshDeadlineArm> replace(
        const ReceiptRefreshDeadlineKey &key);
    bool consume(const ReceiptRefreshDeadlineArm &arm,
                 const ReceiptRefreshDeadlineKey &current);
    void clear();
private:
    quint64 m_generation = 0;
    ReceiptRefreshDeadlineKey m_key;
    bool m_active = false;
};

class ICatalogRuntimeInventory {
public:
    virtual ~ICatalogRuntimeInventory() = default;
    // Facts come only from the package/runtime manifest and generated lock. Implementations must
    // fail closed when pre-connect evidence is unavailable; no settings/QML version strings.
    virtual bool snapshot(CatalogResolveRequest &request,
                          PlatformCapabilities &capabilities,
                          QVariantList &redactedEngineVersions,
                          QString &error) const = 0;
};

struct CatalogCoordinatorConfig {
    QUrl apiBaseUrl;
    QHash<QString, QString> bundledRootPublicKeysHex;
    std::function<QByteArray()> bearerTokenProvider;
    CatalogNetworkClass initialNetworkClass = CatalogNetworkClass::Unknown;
    quint32 deterministicSelectionSeed = 0;
    bool platformGuardAndRuntimeReady = false;
    bool durableAntiDowngradeRequired = true;
    int keysetTimeoutMs = 10000;
    int resolveTimeoutMs = 15000;
    int retryLimit = 3;
    int refreshSafetyMarginS = 30;
    // Existing application preferences backend. Only versioned, non-secret user intent is kept
    // here; catalog/runtime authority remains exclusively in the encrypted monotonic store.
    QSettings *userIntentSettings = nullptr;
};

class CatalogCoordinator final : public QObject,
                                 public ICatalogKeysetFetchObserver,
                                 public ICatalogResolveObserver,
                                 public ICatalogOutcomeUploadObserver,
                                 public IConnectionReducerObserver,
                                 public ICatalogConnectionActions {
public:
    CatalogCoordinator(CatalogCoordinatorConfig config,
                       ICatalogRuntimeInventory *inventory,
                       ICatalogKeysetClient *keysetClient,
                       ICatalogResolveClient *resolveClient,
                       ICatalogLkgStore *secureStore,
                       CatalogTrustedClock *clock,
                       IReceiptAuthorityVerifier *verifier,
                       IProtectedTransportAdapters *adapters,
                       IConnectionRuntimeReducer *reducer,
                       CatalogConnectionFacade *facade,
                       QObject *parent = nullptr);
    ~CatalogCoordinator() override;

    // Loads the encrypted monotonic record and validates it through root/keyset/catalog trust.
    // Network discovery remains opt-in through refreshOnline/requestConnect so legacy v1 is not
    // closed merely because a new binary contains this facade.
    bool initialize(QString &error);
    bool refreshOnline(QString &error);
    // ConfigService edge-walk hook. Changing the authenticated control-plane origin fences any
    // in-flight operation before publishing the new origin; stale replies remain token-rejected.
    bool updateApiBaseUrl(const QUrl &apiBaseUrl, QString &error);
    void setOutcomeClient(ICatalogOutcomeClient *client);
    // `pathToken` is a volatile OS path generation/hash, never persisted or uploaded. Duplicate
    // callbacks for the same class+token are a no-op; material same-class changes require a new
    // token so cooldown/history scopes are not accidentally reused.
    void networkPathChanged(CatalogNetworkClass networkClass,
                            const QString &pathToken = {});
    // Reachability is presentation/liveness evidence, not candidate quality evidence.  Offline
    // immediately revokes green and any five-minute observation without cooling the candidate;
    // the following online material-path event allocates a fresh epoch and re-verifies.
    void networkReachabilityChanged(bool online);
    void applicationResumed();
    // Migration barrier for a legacy native owner discovered before catalog-v2 becomes
    // authoritative.  Connect intent is retained, but no resolve/native dispatch may begin until
    // AvpnEngineQml observes an exact legacy Disconnected terminal state.
    void setExternalNativeOwnershipBlocked(bool blocked);
    // Level-triggered relaunch ownership latch. A platform can discover an already-armed outer
    // guard before the reducer exists; this typed event permanently closes legacy and blocks every
    // new inner start until an exact asynchronous adopt-or-stop receipt is implemented/accepted.
    bool nativeSessionGuardRecoveryRequired(const QJsonObject &event);
    bool nativeSessionGuardRecoveryResolved(const QJsonObject &receipt);
    void clearAfterLogout();
    // Immutable timer hook; public for deterministic scheduler tests. Stale session/generation/path
    // callbacks are no-ops and can never update a replacement profile's quality history.
    void onSurvivalCheckpoint(TransportOperationToken session,
                              QString profileId, quint64 configGeneration,
                              quint64 bindingGeneration, quint64 pathEpoch,
                              quint64 observationGeneration);
    void onVerificationRetryDeadline(VerificationRetryDeadlineArm arm);

    bool authoritativeV2() const { return m_authoritativeV2; }
    bool productionReady() const
    { return m_initialized && m_productionReady && !m_nativeGuardRecoveryPending; }
    bool nativeSessionGuardRecoveryPending() const
    { return m_nativeGuardRecoveryPending; }
    // True only for reducer/recovery identity that can own an outer guard or inner native session.
    // The legacy composition boundary uses this to distinguish a late surviving v1 callback from
    // the generic connection-state notifications emitted by an exact v2 operation.
    bool ownsNativeRuntime() const
    {
        return m_nativeGuardRecoveryPending || m_lastSnapshot.session.isValid()
               || m_lastSnapshot.guardArmed || m_lastSnapshot.guardOwnershipAmbiguous;
    }
    CatalogConnectionFacade *facade() const { return m_facade; }

    void onCatalogKeysetFetchResult(const CatalogKeysetFetchResult &result) override;
    void onCatalogResolveResult(const CatalogResolveResult &result) override;
    void onCatalogOutcomeUploadResult(const CatalogOutcomeUploadResult &result) override;
    void onConnectionReducerSnapshot(const ConnectionRuntimeSnapshot &snapshot) override;

    bool requestConnectionMode(ConnectionMode mode, QString &error) override;
    bool requestLocationMode(const QString &locationMode, QString &error) override;
    bool requestCatalogRefresh(QString &error) override;
    bool requestConnect(QString &error) override;
    void requestDisconnect() override;
    bool requestVerificationRetry(QString &error) override;
    bool requestReselect(QString &error) override;
    bool requestDoctor(QString &error) override;

private:
    bool validateBuildTrust(QString &error) const;
    bool restoreRecord(const CatalogLkgRecord &record, QString &error);
    bool beginResolve(QString &error);
    bool beginIntentScopedResolve(QString &error);
    bool acceptCatalog(const QByteArray &envelope, CatalogSource source,
                       const QString &expectedNonce, bool requestConnect,
                       QString &error, bool persistAcceptance = true,
                       std::optional<CatalogResolveSelection> expectedSelection = std::nullopt,
                       bool requireSelectionEcho = false);
    bool configureAcceptedCatalog(bool reconcile, QString &error);
    bool persistCurrentState(QString &error);
    bool persistAuthoritySnapshot(const CatalogKeysetTrustState &keysetTrust,
                                  const QByteArray &catalogEnvelope,
                                  QString &error);
    void failClosedAuthorityPersistence(const QString &reason);
    bool persistUserIntent(ConnectionMode mode, const QString &locationMode,
                           QString &error) const;
    void restoreUserIntent();
    void revalidatePinnedLocation();
    CatalogResolveSelection requestedCatalogSelection() const;
    bool acceptedCatalogSelectionMatchesIntent() const;
    void fenceDiscoveryForIntentChange();
    bool refreshLiveIntent(QString &error);
    bool validateIntentPair(ConnectionMode mode, const QString &locationMode,
                            QString &error) const;
    bool canRetryVerificationNow() const;
    void finishLogoutAfterExactTeardown();
    void fenceDiscoveryForCatalogStale();
    void queueCatalogStaleRefresh();
    void cancelCatalogStaleReconnect();
    void beginSurvivalObservation(const ConnectionRuntimeSnapshot &snapshot);
    void cancelSurvivalObservation(bool recordFailure);
    void closeLegacyAuthoritatively(const QString &reason);
    void scheduleResolveRetry(int seconds);
    void scheduleRefresh();
    void scheduleRuntimeTimers(const ConnectionRuntimeSnapshot &snapshot);
    ReceiptRefreshDeadlineKey receiptRefreshKey(
        const ConnectionRuntimeSnapshot &snapshot) const;
    void scheduleReceiptRefresh(const ConnectionRuntimeSnapshot &snapshot);
    void onReceiptRefreshDeadline(ReceiptRefreshDeadlineArm arm);
    void scheduleLifecycleDeadline(const ConnectionRuntimeSnapshot &snapshot);
    void onLifecycleDeadline(ConnectionLifecycleDeadlineArm arm);
    VerificationRetryDeadlineKey verificationRetryKey(
        const ConnectionRuntimeSnapshot &snapshot) const;
    void scheduleVerificationRetry(const ConnectionRuntimeSnapshot &snapshot);
    void updateFacadeCatalogView();
    void terminal(const QString &reason);
    QHash<QString, CandidateHistory> pathHistory() const;
    CandidateSelectionRequest selectionRequest() const;
    QStringList receiptProtectedIps() const;
    bool enqueueOutcome(const ConnectionRuntimeSnapshot &snapshot,
                        CatalogOutcomeStage stage, bool verifiedSuccess,
                        const QString &errorCode = {},
                        std::optional<bool> survived5m = std::nullopt,
                        qint64 sessionMs = -1);
    void flushOutcomes();
    const CatalogCandidate *candidateForOutcome(
        const ConnectionRuntimeSnapshot &snapshot) const;

    CatalogCoordinatorConfig m_config;
    ICatalogRuntimeInventory *m_inventory = nullptr;
    ICatalogKeysetClient *m_keysetClient = nullptr;
    ICatalogResolveClient *m_resolveClient = nullptr;
    ICatalogOutcomeClient *m_outcomeClient = nullptr;
    ICatalogLkgStore *m_secureStore = nullptr;
    CatalogTrustedClock *m_clock = nullptr;
    IReceiptAuthorityVerifier *m_verifier = nullptr;
    IProtectedTransportAdapters *m_adapters = nullptr;
    IConnectionRuntimeReducer *m_reducer = nullptr;
    CatalogConnectionFacade *m_facade = nullptr;
    QTimer *m_retryTimer = nullptr;
    QTimer *m_refreshTimer = nullptr;
    QTimer *m_authorityTimer = nullptr;
    QTimer *m_logoutTimer = nullptr;
    QTimer *m_outcomeRetryTimer = nullptr;
    ConnectionLifecycleDeadlineFence m_lifecycleDeadlineFence;
    VerificationRetryDeadlineFence m_verificationRetryDeadlineFence;
    ReceiptRefreshDeadlineFence m_receiptRefreshDeadlineFence;

    bool m_initialized = false;
    bool m_productionReady = false;
    bool m_authoritativeV2 = false;
    bool m_pendingConnect = false;
    bool m_refreshInFlight = false;
    bool m_reconcileNextAcceptance = false;
    bool m_userWantsConnected = false;
    bool m_retryVerificationAfterRefresh = false;
    bool m_configureAfterVerification = false;
    // Volatile fail-stop after a root-authority transition could not be made durable. Restart may
    // retry from the last authenticated disk record; this process may neither reconnect nor issue
    // further discovery/native work under a key the root has just omitted or revoked.
    bool m_authorityPersistenceFailed = false;
    bool m_keysetResolveAfterTeardown = false;
    // A typed 409 receipt invalidates use of the current LKG for future starts. Discovery is
    // fenced immediately, then exactly one fresh resolve is queued only after inner stop + outer
    // guard release. OFF/logout/recovery cancel reconnect intent but retain this refresh barrier.
    bool m_catalogStaleNeedsRefresh = false;
    bool m_catalogStaleRefreshQueued = false;
    quint64 m_catalogStaleStopOperation = 0;
    quint64 m_catalogStaleHandledOperation = 0;
    bool m_logoutPending = false;
    bool m_nativeGuardRecoveryPending = false;
    bool m_externalNativeOwnershipBlocked = false;
    bool m_networkReachabilityKnown = false;
    bool m_networkOnline = true;
    ConnectionGuardEvent m_nativeGuardRecoveryIdentity;
    int m_retryCount = 0;
    quint64 m_keysetOperation = 0;
    quint64 m_outcomeOperation = 0;
    QString m_outcomeEventId;
    QSet<QString> m_outcomeQuarantined;
    CatalogResolveAttempt m_resolveAttempt;
    CatalogResolveRequest m_runtimeRequest;
    PlatformCapabilities m_capabilities;
    CatalogKeysetTrustState m_keysetTrust;
    CatalogAcceptedKeyrings m_keyrings;
    CatalogTrustState m_catalogTrust;
    CatalogRuntimeState m_runtimeState;
    CatalogNetworkPathScope m_networkPath;
    QString m_networkPathToken;
    Catalog m_catalog;
    QList<CatalogCandidate> m_candidates;
    CatalogRuntimeAuthority m_runtimeAuthority;
    QByteArray m_catalogEnvelope;
    // An expired but fully root/signature/rollback-validated atomic LKG remains durable authority,
    // never a connection candidate. Online recovery must fetch a fresh root-signed keyset first.
    bool m_catalogLkgExpired = false;
    QString m_catalogAuthoritySigningKeyId;
    quint64 m_catalogAuthorityKeyEpoch = 0;
    ConnectionMode m_mode = ConnectionMode::Auto;
    QString m_locationMode = QStringLiteral("auto");
    QStringList m_appliedProtectedIps;
    // One-shot user reselect fence. Kept across an asynchronous verifier/teardown boundary and
    // cleared immediately after the reducer has copied the filtered immutable candidate list.
    QString m_reselectExcludedProfileId;
    ConnectionRuntimeSnapshot m_lastSnapshot;
    TransportOperationToken m_outcomeSession;
    QDateTime m_outcomeSessionStartedUtc;
    bool m_connectedOutcomeRecorded = false;
    bool m_unknownOutcomeRecorded = false;
    TransportOperationToken m_survivalSession;
    QString m_survivalProfileId;
    quint64 m_survivalConfigGeneration = 0;
    quint64 m_survivalBindingGeneration = 0;
    quint64 m_survivalPathEpoch = 0;
    quint64 m_survivalGeneration = 0;
    QDateTime m_survivalStartedAtUtc;
    QDateTime m_survivalCoverageUntilUtc;
};

} // namespace avpn
