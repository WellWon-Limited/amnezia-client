#include "CatalogCoordinator.h"

#include "SignedEnvelope.h"
#include "CatalogUserIntent.h"

#include <QDateTime>
#include <QHostAddress>
#include <QRegularExpression>
#include <QSet>
#include <QTimer>

#include <algorithm>
#include <limits>
#include <utility>

namespace avpn {
namespace {

int boundedDelayMs(qint64 seconds)
{
    return int(qBound<qint64>(qint64(1), seconds,
                              qint64(std::numeric_limits<int>::max() / 1000)) * 1000);
}

bool supportedRootKey(const QString &kid, const QString &hex)
{
    if (!canonicalSigningKeyId(kid) || hex.size() != 64) return false;
    for (const QChar ch : hex)
        if (!ch.isDigit() && (ch.toLower() < QLatin1Char('a')
                              || ch.toLower() > QLatin1Char('f'))) return false;
    return QByteArray::fromHex(hex.toLatin1()).size() == 32;
}

bool activeConnectionPhase(ConnectionPhase phase)
{
    return phase != ConnectionPhase::Idle && phase != ConnectionPhase::Failed;
}

CatalogOutcomeStage outcomeStage(ConnectionFailureStage stage)
{
    switch (stage) {
    case ConnectionFailureStage::Policy:
        return CatalogOutcomeStage::Policy;
    case ConnectionFailureStage::Compile:
        return CatalogOutcomeStage::Compile;
    case ConnectionFailureStage::TransportStart:
        return CatalogOutcomeStage::TransportStart;
    case ConnectionFailureStage::TransportRuntime:
    case ConnectionFailureStage::TransportTimeout:
    case ConnectionFailureStage::TransportStopTimeout:
        return CatalogOutcomeStage::TransportRuntime;
    case ConnectionFailureStage::VerificationDns:
        return CatalogOutcomeStage::VerificationDns;
    case ConnectionFailureStage::VerificationTraffic:
    case ConnectionFailureStage::VerificationTimeout:
    case ConnectionFailureStage::VerificationFreeze:
        return CatalogOutcomeStage::VerificationTraffic;
    case ConnectionFailureStage::VerificationEgress:
    case ConnectionFailureStage::VerificationAuthority:
    case ConnectionFailureStage::VerificationTrust:
        return CatalogOutcomeStage::VerificationEgress;
    case ConnectionFailureStage::None:
        break;
    }
    return CatalogOutcomeStage::TransportRuntime;
}

QString outcomeErrorCode(const QString &reason)
{
    static const QRegularExpression safe(QStringLiteral("^[a-z][a-z0-9_.-]{0,95}$"));
    return safe.match(reason).hasMatch() ? reason : QStringLiteral("connection_failed");
}

void applyCoordinatorCapabilities(bool verifierReady,
                                  CatalogResolveRequest &request,
                                  PlatformCapabilities &capabilities)
{
    static const QString receiptCap = QStringLiteral("probe.egress_receipt_v1");
    static const QString directoryCap =
        QStringLiteral("catalog.location_directory_v1");
    request.capabilities.append(directoryCap);
    request.capabilities.removeDuplicates();
    capabilities.capabilities.insert(directoryCap);
    request.capabilities.removeAll(receiptCap);
    capabilities.capabilities.remove(receiptCap);
    if (verifierReady) request.capabilities.append(receiptCap);
    request.capabilities.removeDuplicates();
    std::sort(request.capabilities.begin(), request.capabilities.end());
    if (verifierReady) capabilities.capabilities.insert(receiptCap);
}

bool catalogSignerWasValidInPersistedKeyset(const Catalog &catalog,
                                            const CatalogKeysetManifest &manifest)
{
    const bool revoked = std::any_of(
        manifest.revocations.cbegin(), manifest.revocations.cend(),
        [&catalog](const CatalogKeysetRevocation &item) {
            return item.purpose == CatalogSigningPurpose::Catalog
                && item.kid == catalog.signingKeyId;
        });
    if (revoked) return false;
    return std::any_of(
        manifest.keys.cbegin(), manifest.keys.cend(),
        [&catalog](const CatalogKeysetEntry &entry) {
            return entry.purpose == CatalogSigningPurpose::Catalog
                && entry.kid == catalog.signingKeyId
                && entry.keyEpoch == catalog.keyEpoch
                && catalog.issuedAt >= entry.notBefore
                && catalog.issuedAt < entry.notAfter;
        });
}

bool catalogSignerRevokedByManifest(const QString &kid,
                                    const CatalogKeysetManifest &manifest)
{
    return !kid.isEmpty() && std::any_of(
        manifest.revocations.cbegin(), manifest.revocations.cend(),
        [&kid](const CatalogKeysetRevocation &item) {
            return item.purpose == CatalogSigningPurpose::Catalog && item.kid == kid;
        });
}

bool catalogReceiptAuthoritiesWereValidInKeyset(
    const Catalog &catalog, const CatalogKeysetManifest &manifest)
{
    if (!catalog.receiptProviderPolicy) return true;
    const QList<ReceiptProviderDescriptor> &providers =
        catalog.receiptProviderPolicy->providers;
    if (providers.isEmpty()) return false;
    for (const ReceiptProviderDescriptor &provider : providers) {
        const bool revoked = std::any_of(
            manifest.revocations.cbegin(), manifest.revocations.cend(),
            [&provider](const CatalogKeysetRevocation &item) {
                return item.purpose == CatalogSigningPurpose::Receipt
                    && item.kid == provider.receiptKid
                    && item.authorityId == provider.trustDomain;
            });
        const bool declaredForIssuance = std::any_of(
            manifest.keys.cbegin(), manifest.keys.cend(),
            [&catalog, &provider](const CatalogKeysetEntry &entry) {
                return entry.purpose == CatalogSigningPurpose::Receipt
                    && entry.kid == provider.receiptKid
                    && entry.authorityId == provider.trustDomain
                    && entry.keyEpoch == provider.receiptKeyEpoch
                    && catalog.issuedAt >= entry.notBefore
                    && catalog.issuedAt < entry.notAfter;
            });
        if (revoked || !declaredForIssuance) return false;
    }
    return true;
}

bool catalogReceiptAuthoritiesCurrentlyUsable(
    const Catalog &catalog, const CatalogAcceptedKeyrings &keyrings)
{
    if (!catalog.receiptProviderPolicy) return true;
    const QList<ReceiptProviderDescriptor> &providers =
        catalog.receiptProviderPolicy->providers;
    if (providers.isEmpty()) return false;
    return std::all_of(
        providers.cbegin(), providers.cend(), [&keyrings](const auto &provider) {
            return keyrings.receiptPublicKeysHex.contains(provider.receiptKid)
                && keyrings.receiptKeyEpochs.value(provider.receiptKid)
                       == provider.receiptKeyEpoch
                && keyrings.receiptAuthorityIds.value(provider.receiptKid)
                       == provider.trustDomain;
        });
}

bool runtimeMayOwnNativeSession(const ConnectionRuntimeSnapshot &snapshot)
{
    return activeConnectionPhase(snapshot.phase) || snapshot.session.isValid()
        || snapshot.guardArmed || snapshot.guardOwnershipAmbiguous;
}

} // namespace

std::optional<ConnectionLifecycleDeadlineArm>
ConnectionLifecycleDeadlineFence::replace(const ConnectionLifecycleWait &wait)
{
    if (!wait.isValid()) {
        clear();
        return std::nullopt;
    }
    // Keep a consumed wait as a tombstone until the reducer actually leaves that wait.  Timeout
    // handlers for fail-closed stop/release deliberately retain their owner token; their emitted
    // Failed snapshot must not start an endless sequence of fresh timeout/reconcile commands.
    if (wait == m_wait)
        return std::nullopt;
    if (++m_generation == 0) ++m_generation;
    m_wait = wait;
    m_active = true;
    return ConnectionLifecycleDeadlineArm{m_generation, wait};
}

bool ConnectionLifecycleDeadlineFence::consume(
    const ConnectionLifecycleDeadlineArm &arm, const ConnectionLifecycleWait &current)
{
    if (!m_active || !arm.isValid() || arm.generation != m_generation
        || arm.wait != m_wait || current != m_wait)
        return false;
    m_active = false;
    return true;
}

void ConnectionLifecycleDeadlineFence::clear()
{
    if (!m_active && !m_wait.isValid()) return;
    if (++m_generation == 0) ++m_generation;
    m_active = false;
    m_wait = {};
}

bool dispatchConnectionLifecycleTimeout(IConnectionRuntimeReducer *reducer,
                                        const ConnectionLifecycleWait &wait)
{
    if (!reducer || !wait.isValid()) return false;
    switch (wait.kind) {
    case ConnectionLifecycleWaitKind::GuardArm:
        reducer->onGuardArmTimeout(wait.session, wait.nativeDispatchPolicySha256);
        return true;
    case ConnectionLifecycleWaitKind::TransportStart:
        reducer->onTransportTimeout(wait.session);
        return true;
    case ConnectionLifecycleWaitKind::TransportStop:
        reducer->onStopTimeout(wait.session);
        return true;
    case ConnectionLifecycleWaitKind::GuardRelease:
        reducer->onGuardReleaseTimeout(wait.session);
        return true;
    case ConnectionLifecycleWaitKind::Verification:
        reducer->onVerificationTimeout(wait.verification);
        return true;
    case ConnectionLifecycleWaitKind::None:
        break;
    }
    return false;
}

std::optional<VerificationRetryDeadlineArm>
VerificationRetryDeadlineFence::replace(const VerificationRetryDeadlineKey &key)
{
    if (!key.isValid()) {
        clear();
        return std::nullopt;
    }
    if (m_active && key == m_key) return std::nullopt;
    if (++m_generation == 0) ++m_generation;
    m_key = key;
    m_active = true;
    return VerificationRetryDeadlineArm{m_generation, key};
}

bool VerificationRetryDeadlineFence::consume(
    const VerificationRetryDeadlineArm &arm, const VerificationRetryDeadlineKey &current)
{
    if (!m_active || !arm.isValid() || arm.generation != m_generation
        || arm.key != m_key || current != m_key)
        return false;
    m_active = false;
    m_key = {};
    return true;
}

void VerificationRetryDeadlineFence::clear()
{
    if (!m_active && !m_key.isValid()) return;
    if (++m_generation == 0) ++m_generation;
    m_active = false;
    m_key = {};
}

qint64 proactiveReceiptRefreshDelayMs(const QDateTime &nowUtc,
                                      const QDateTime &verifiedUntilUtc,
                                      int configuredSafetyMarginSeconds)
{
    if (!nowUtc.isValid() || !verifiedUntilUtc.isValid()) return 1;
    const qint64 remainingMs = qMax<qint64>(
        1, nowUtc.toUTC().msecsTo(verifiedUntilUtc.toUTC()));
    const qint64 configuredSafetyMs =
        qBound(5, configuredSafetyMarginSeconds, 120) * 1000LL;
    const qint64 safetyMs = qMin(configuredSafetyMs,
                                 qMax<qint64>(1000, remainingMs / 3));
    return qBound<qint64>(qint64(1), remainingMs - safetyMs,
                          qint64(std::numeric_limits<int>::max()));
}

std::optional<ReceiptRefreshDeadlineArm>
ReceiptRefreshDeadlineFence::replace(const ReceiptRefreshDeadlineKey &key)
{
    if (!key.isValid()) {
        clear();
        return std::nullopt;
    }
    if (m_active && key == m_key) return std::nullopt;
    if (++m_generation == 0) ++m_generation;
    m_key = key;
    m_active = true;
    return ReceiptRefreshDeadlineArm{m_generation, key};
}

bool ReceiptRefreshDeadlineFence::consume(
    const ReceiptRefreshDeadlineArm &arm, const ReceiptRefreshDeadlineKey &current)
{
    if (!m_active || !arm.isValid() || arm.generation != m_generation
        || arm.key != m_key || current != m_key)
        return false;
    m_active = false;
    m_key = {};
    return true;
}

void ReceiptRefreshDeadlineFence::clear()
{
    if (!m_active && !m_key.isValid()) return;
    if (++m_generation == 0) ++m_generation;
    m_active = false;
    m_key = {};
}

CatalogCoordinator::CatalogCoordinator(
    CatalogCoordinatorConfig config, ICatalogRuntimeInventory *inventory,
    ICatalogKeysetClient *keysetClient, ICatalogResolveClient *resolveClient,
    ICatalogLkgStore *secureStore, CatalogTrustedClock *clock,
    IReceiptAuthorityVerifier *verifier, IProtectedTransportAdapters *adapters,
    IConnectionRuntimeReducer *reducer, CatalogConnectionFacade *facade, QObject *parent)
    : QObject(parent), m_config(std::move(config)), m_inventory(inventory),
      m_keysetClient(keysetClient), m_resolveClient(resolveClient),
      m_secureStore(secureStore), m_clock(clock), m_verifier(verifier),
      m_adapters(adapters), m_reducer(reducer), m_facade(facade),
      m_retryTimer(new QTimer(this)), m_refreshTimer(new QTimer(this)),
      m_authorityTimer(new QTimer(this)),
      m_logoutTimer(new QTimer(this)),
      m_outcomeRetryTimer(new QTimer(this))
{
    for (QTimer *timer : {m_retryTimer, m_refreshTimer, m_authorityTimer,
                          m_logoutTimer,
                          m_outcomeRetryTimer})
        timer->setSingleShot(true);
    if (m_keysetClient) m_keysetClient->setObserver(this);
    if (m_resolveClient) m_resolveClient->setObserver(this);
    if (m_reducer) m_reducer->setObserver(this);
    if (m_facade) m_facade->setActions(this);

    connect(m_retryTimer, &QTimer::timeout, this, [this]() {
        QString ignored;
        refreshOnline(ignored);
    });
    connect(m_refreshTimer, &QTimer::timeout, this, [this]() {
        m_reconcileNextAcceptance = m_userWantsConnected
                                    && activeConnectionPhase(m_lastSnapshot.phase);
        QString ignored;
        refreshOnline(ignored);
    });
    connect(m_authorityTimer, &QTimer::timeout, this, [this]() {
        if (m_reducer && m_lastSnapshot.session.isValid())
            m_reducer->onAuthorityDeadline(m_lastSnapshot.session);
    });
    connect(m_logoutTimer, &QTimer::timeout, this, [this]() {
        // Never reopen legacy or clear rollback authority when exact native/guard teardown cannot
        // be proved. The app remains fail-closed until a later exact Idle+Released event/restart.
        if (m_logoutPending)
            terminal(QStringLiteral("logout_teardown_timeout"));
    });
    connect(m_outcomeRetryTimer, &QTimer::timeout, this,
            [this]() { flushOutcomes(); });
}

CatalogCoordinator::~CatalogCoordinator()
{
    if (m_keysetClient) {
        if (m_keysetOperation) m_keysetClient->cancel(m_keysetOperation);
        m_keysetClient->clearObserver(this);
    }
    if (m_resolveClient) {
        if (m_resolveAttempt.operation) m_resolveClient->cancel(m_resolveAttempt.operation);
        m_resolveClient->clearObserver(this);
    }
    if (m_outcomeClient) {
        if (m_outcomeOperation) m_outcomeClient->cancel(m_outcomeOperation);
        m_outcomeClient->clearObserver(this);
    }
    if (m_reducer) m_reducer->clearObserver(this);
    if (m_facade) m_facade->clearActions(this);
}

void CatalogCoordinator::setOutcomeClient(ICatalogOutcomeClient *client)
{
    if (m_outcomeClient == client) return;
    if (m_outcomeClient) {
        if (m_outcomeOperation) m_outcomeClient->cancel(m_outcomeOperation);
        m_outcomeClient->clearObserver(this);
    }
    m_outcomeClient = client;
    m_outcomeOperation = 0;
    m_outcomeEventId.clear();
    if (m_outcomeClient) {
        m_outcomeClient->setObserver(this);
        QTimer::singleShot(0, this, [this]() { flushOutcomes(); });
    }
}

bool CatalogCoordinator::validateBuildTrust(QString &error) const
{
    error.clear();
    if (!m_config.apiBaseUrl.isValid()
        || m_config.apiBaseUrl.scheme() != QLatin1String("https")
        || m_config.apiBaseUrl.host().isEmpty()
        || !m_config.apiBaseUrl.userInfo().isEmpty()
        || !m_config.apiBaseUrl.query().isEmpty()
        || !m_config.apiBaseUrl.fragment().isEmpty()
        || (!m_config.apiBaseUrl.path().isEmpty()
            && m_config.apiBaseUrl.path() != QLatin1String("/"))
        || m_config.bundledRootPublicKeysHex.isEmpty()
        || m_config.bundledRootPublicKeysHex.size() > 4) {
        error = QStringLiteral("catalog v2 build trust/base URL unavailable");
        return false;
    }
    QSet<QString> keyBytes;
    for (auto it = m_config.bundledRootPublicKeysHex.constBegin();
         it != m_config.bundledRootPublicKeysHex.constEnd(); ++it) {
        const QString normalized = it.value().toLower();
        if (!supportedRootKey(it.key(), normalized) || keyBytes.contains(normalized)) {
            error = QStringLiteral("catalog v2 bundled root set invalid");
            return false;
        }
        keyBytes.insert(normalized);
    }
    return true;
}

bool CatalogCoordinator::initialize(QString &error)
{
    error.clear();
    if (m_initialized) {
        if (m_nativeGuardRecoveryPending && error.isEmpty())
            error = QStringLiteral("native_guard_recovery_required");
        return productionReady();
    }
    const bool foundationReady = validateBuildTrust(error) && m_inventory && m_keysetClient
                                 && m_resolveClient && m_clock && m_facade
                                 && (!m_config.durableAntiDowngradeRequired || m_secureStore);
    m_productionReady = foundationReady && m_verifier && m_adapters && m_reducer
                        && m_config.platformGuardAndRuntimeReady;
    if (!foundationReady) {
        if (error.isEmpty())
            error = QStringLiteral("catalog_v2_trust_or_secure_runtime_unavailable");
        if (m_facade) {
            m_facade->setV2AuthorityState(false);
            m_facade->setCoordinatorStage(QStringLiteral("idle"), error);
        }
        return false;
    }

    // Preferences are deliberately restored independently of the encrypted authority record.
    // They express requested UI policy only and must never resurrect an active native transport.
    restoreUserIntent();

    CatalogLkgRecord record;
    const CatalogLkgLoadStatus status = m_secureStore->load(record, error);
    if (status == CatalogLkgLoadStatus::Error) {
        // With durable anti-downgrade enabled, an unreadable/locked/corrupt authority store cannot
        // prove that v2 was never accepted. Fail closed in the presentation path; only a clean
        // NotFound first-install record permits legacy bootstrap.
        if (m_config.durableAntiDowngradeRequired) {
            m_authoritativeV2 = true;
            m_facade->setV2AuthorityState(true);
        }
        terminal(QStringLiteral("catalog_secure_store_unavailable"));
        return false;
    }

    // The anti-downgrade bit is authenticated by the secure record and must reach the facade
    // before any fallible engine-manifest/compatibility work. Otherwise a temporarily unavailable
    // platform manifest after an accepted-v2 restart would make QML expose unsigned legacy v1.
    // Full catalog restore still happens only after local capabilities have been proven below.
    if (status == CatalogLkgLoadStatus::Loaded) {
        m_authoritativeV2 = m_authoritativeV2
                            || record.authoritativeV2EndpointSeen
                            || record.trustState.hasAcceptedV2;
        m_facade->setV2AuthorityState(m_authoritativeV2);
    }

    // Local engine evidence is required even for an encrypted LKG: without it the compatibility
    // boundary would evaluate a valid cached profile against an empty/default capability set.
    // This is a local generated/runtime manifest read only; it performs no network request.
    QVariantList versions;
    CatalogResolveRequest request;
    PlatformCapabilities capabilities;
    if (!m_inventory->snapshot(request, capabilities, versions, error)) {
        terminal(QStringLiteral("runtime_engine_manifest_unavailable"));
        return false;
    }
    m_runtimeRequest = std::move(request);
    m_capabilities = std::move(capabilities);
    applyCoordinatorCapabilities(m_productionReady, m_runtimeRequest, m_capabilities);
    // The first contact remains unscoped for N-1 compatibility. Only a previously accepted,
    // signed directory may authorize sending selection intent; OFF presentation refreshes remain
    // unscoped so browsing preferences cannot allocate a trail of credential bindings.
    if (m_catalog.locationDirectory.has_value() && m_userWantsConnected
        && (m_pendingConnect || m_reconcileNextAcceptance
            || activeConnectionPhase(m_lastSnapshot.phase)))
        m_runtimeRequest.selection = requestedCatalogSelection();
    else
        m_runtimeRequest.selection.reset();
    m_facade->setEngineVersions(std::move(versions));

    // A clean install has no signed high-water yet, but keyset verification still requires a
    // wall+monotonic anchor. restoreRecord() immediately reapplies any persisted high-water and its
    // rollback check below; this empty bootstrap does not override durable clock authority.
    if (!m_clock->restore({}, error)) {
        terminal(QStringLiteral("catalog_trusted_clock_unavailable"));
        return false;
    }

    if (status == CatalogLkgLoadStatus::Loaded) {
        if (!restoreRecord(record, error)) {
            terminal(QStringLiteral("catalog_secure_record_invalid"));
            return false;
        }
        // Every authenticated relaunch advances the persisted observed-wall high-water before the
        // runtime becomes usable. This closes expired-boot -> wall-rollback -> offline-resurrection
        // even when the record restored only a schema-v4 authority tombstone.
        QString advanceError;
        if (!persistCurrentState(advanceError)) {
            error = advanceError;
            failClosedAuthorityPersistence(QStringLiteral("catalog_authority_persist_failed"));
            return false;
        }
    }
    if (!m_networkPath.isValid()
        && !allocateCatalogNetworkPathScope(m_runtimeState,
                                             m_config.initialNetworkClass,
                                             m_networkPath, error)) {
        terminal(QStringLiteral("network_path_epoch_unavailable"));
        return false;
    }
    m_initialized = true;
    if (m_facade) m_facade->setV2AuthorityState(m_authoritativeV2);
    if (m_nativeGuardRecoveryPending) {
        // A relaunch event may arrive before initialization. Once the encrypted store and local
        // clock/path state are ready, durably record the anti-downgrade tombstone before returning
        // the intentionally unavailable connect runtime.
        QString persistError;
        if (status != CatalogLkgLoadStatus::Loaded
            && !persistCurrentState(persistError)) {
            error = persistError;
            failClosedAuthorityPersistence(
                QStringLiteral("catalog_authority_persist_failed"));
            return false;
        }
        if (error.isEmpty()) error = QStringLiteral("native_guard_recovery_required");
        terminal(QStringLiteral("native_guard_recovery_required"));
        return false;
    }
    if (!m_productionReady) {
        error = QStringLiteral("catalog_v2_platform_guard_unavailable");
        m_facade->setCoordinatorStage(QStringLiteral("idle"), error);
    }
    flushOutcomes();
    return productionReady();
}

bool CatalogCoordinator::restoreRecord(const CatalogLkgRecord &record, QString &error)
{
    error.clear();
    m_authoritativeV2 = m_authoritativeV2
                        || record.authoritativeV2EndpointSeen
                        || record.trustState.hasAcceptedV2;
    if (m_authoritativeV2 && m_facade)
        m_facade->setV2AuthorityState(true);
    if (!record.runtimeState.isEmpty()
        && !parseCatalogRuntimeState(record.runtimeState, m_runtimeState, error))
        return false;
    if (m_runtimeState.trustedClock.highestSignedIssuedAtUtc.isValid()
        && !m_clock->restore(m_runtimeState.trustedClock, error))
        return false;
    m_catalogTrust = record.trustState;
    CatalogKeysetManifest persistedKeysetManifest;
    CatalogKeyring persistedCatalogVerificationKeyring;
    bool persistedKeysetConnectable = false;
    if (!record.acceptedKeysetState.isEmpty()) {
        if (!parseCatalogKeysetTrustState(record.acceptedKeysetState,
                                          m_keysetTrust, error)
            || m_keysetTrust.acceptedEnvelope.isEmpty()) return false;
        const CatalogKeysetAcceptance accepted = acceptCatalogKeysetEnvelope(
            m_keysetTrust.acceptedEnvelope, m_config.bundledRootPublicKeysHex,
            m_keysetTrust, m_clock->nowUtc(), {},
            CatalogKeysetAcceptanceMode::PersistedRecovery);
        if ((!accepted.accepted && !accepted.recoverableExpired)
            || accepted.nextState != m_keysetTrust) {
            error = accepted.detail;
            if (error.isEmpty())
                error = QStringLiteral("persisted keyset high-water mismatch");
            return false;
        }
        m_keysetTrust = accepted.nextState;
        persistedKeysetManifest = accepted.manifest;
        persistedCatalogVerificationKeyring =
            accepted.persistedCatalogVerificationKeyring;
        if (accepted.accepted) {
            m_keyrings = accepted.keyrings;
            persistedKeysetConnectable = true;
        } else {
            // Retain root-authenticated epoch/revocation history, but expose no expired key as
            // online catalog or connection authority. A new request must start at the root.
            m_keyrings = {};
        }
    }
    if (record.verifiedEnvelope.isEmpty()) {
        m_catalogLkgExpired = m_catalogTrust.hasAcceptedV2;
        m_catalogAuthoritySigningKeyId.clear();
        m_catalogAuthorityKeyEpoch = 0;
        return m_authoritativeV2;
    }
    const CatalogAcceptanceResult recovery = acceptCatalogEnvelope(
        record.verifiedEnvelope, persistedCatalogVerificationKeyring,
        m_capabilities, m_catalogTrust, CatalogSource::LastKnownGood,
        m_clock->nowUtc(), {});
    const bool normalLifecycleExpiry =
        recovery.error == CatalogAcceptanceError::Trust
        && (recovery.trustError == CatalogTrustError::Expired
            || recovery.trustError == CatalogTrustError::EntitlementExpired);
    if ((!recovery.authoritative && !normalLifecycleExpiry)
        || !catalogSignerWasValidInPersistedKeyset(recovery.catalog,
                                                    persistedKeysetManifest)
        || !catalogReceiptAuthoritiesWereValidInKeyset(
            recovery.catalog, persistedKeysetManifest)) {
        error = recovery.detail.isEmpty()
            ? QStringLiteral("persisted catalog LKG authentication failed")
            : recovery.detail;
        return false;
    }
    const bool signerCurrentlyUsable = persistedKeysetConnectable
        && m_keyrings.catalog.publicKeysHex.contains(recovery.catalog.signingKeyId)
        && m_keyrings.catalog.keyEpochs.value(recovery.catalog.signingKeyId)
               == recovery.catalog.keyEpoch
        && catalogReceiptAuthoritiesCurrentlyUsable(recovery.catalog, m_keyrings);
    if (!normalLifecycleExpiry && signerCurrentlyUsable) {
        // Preserve the established valid-LKG path exactly: it remains eligible for offline use
        // and is persisted through the ordinary acceptance boundary.
        return acceptCatalog(record.verifiedEnvelope, CatalogSource::LastKnownGood,
                             {}, false, error, false);
    }
    // Expired keyset, expired entitlement/catalog, or a no-longer-current signer all enter the
    // same non-connectable quarantine. initialize() immediately replaces this authenticated old
    // pair with a schema-v4 high-water tombstone that preserves monotonic trust but no credentials;
    // discovery must then start from a fresh bundled-root keyset.
    m_catalogEnvelope.clear();
    m_catalogLkgExpired = true;
    m_catalogAuthoritySigningKeyId = recovery.catalog.signingKeyId;
    m_catalogAuthorityKeyEpoch = recovery.catalog.keyEpoch;
    m_catalog = {};
    m_candidates.clear();
    m_runtimeAuthority = {};
    return true;
}

bool CatalogCoordinator::refreshOnline(QString &error)
{
    error.clear();
    if (!m_initialized && !initialize(error)) return false;
    if (m_authorityPersistenceFailed) {
        error = QStringLiteral("catalog_authority_persist_failed");
        return false;
    }
    if (m_catalogStaleStopOperation != 0
        && (activeConnectionPhase(m_lastSnapshot.phase)
            || m_lastSnapshot.session.isValid() || m_lastSnapshot.guardArmed
            || m_lastSnapshot.guardOwnershipAmbiguous)) {
        error = QStringLiteral("catalog_stale_teardown_pending");
        return false;
    }
    if (m_externalNativeOwnershipBlocked) {
        error = QStringLiteral("legacy_native_teardown_pending");
        return false;
    }
    if (!m_productionReady || m_refreshInFlight || m_retryTimer->isActive()) {
        if (error.isEmpty()) error = QStringLiteral("catalog_refresh_unavailable_or_inflight");
        return false;
    }
    QByteArray authProbe = m_config.bearerTokenProvider
                               ? m_config.bearerTokenProvider() : QByteArray{};
    const bool authenticated = !authProbe.trimmed().isEmpty();
    authProbe.fill('\0');
    if (!authenticated) {
        error = QStringLiteral("catalog_auth_not_ready");
        return false;
    }
    QVariantList versions;
    CatalogResolveRequest request;
    PlatformCapabilities capabilities;
    if (!m_inventory->snapshot(request, capabilities, versions, error)) {
        terminal(QStringLiteral("runtime_engine_manifest_unavailable"));
        return false;
    }
    m_runtimeRequest = std::move(request);
    m_capabilities = std::move(capabilities);
    applyCoordinatorCapabilities(m_productionReady, m_runtimeRequest, m_capabilities);
    if (m_catalog.locationDirectory.has_value() && m_userWantsConnected
        && (m_pendingConnect || m_reconcileNextAcceptance
            || activeConnectionPhase(m_lastSnapshot.phase)))
        m_runtimeRequest.selection = requestedCatalogSelection();
    else
        m_runtimeRequest.selection.reset();
    m_facade->setEngineVersions(std::move(versions));
    m_facade->setCoordinatorStage(QStringLiteral("resolving"));
    m_refreshInFlight = true;
    quint64 operation = 0;
    if (!m_keysetClient->start(m_config.apiBaseUrl, operation, error)) {
        m_refreshInFlight = false;
        terminal(QStringLiteral("keyset_request_dispatch_unavailable"));
        return false;
    }
    m_keysetOperation = operation;
    return true;
}

bool CatalogCoordinator::updateApiBaseUrl(const QUrl &apiBaseUrl, QString &error)
{
    error.clear();
    const QUrl previous = m_config.apiBaseUrl;
    m_config.apiBaseUrl = apiBaseUrl;
    if (!validateBuildTrust(error)) {
        m_config.apiBaseUrl = previous;
        return false;
    }
    if (previous == apiBaseUrl) return true;

    // Fence before cancel: Qt may synchronously complete an aborted reply. Result handlers compare
    // immutable operation IDs, and clearing them first makes those callbacks stale by construction.
    const quint64 keysetOperation = std::exchange(m_keysetOperation, 0);
    const quint64 resolveOperation = std::exchange(m_resolveAttempt.operation, 0);
    const quint64 outcomeOperation = std::exchange(m_outcomeOperation, 0);
    m_outcomeEventId.clear();
    m_refreshInFlight = false;
    m_retryTimer->stop();
    m_outcomeRetryTimer->stop();
    if (keysetOperation && m_keysetClient) m_keysetClient->cancel(keysetOperation);
    if (resolveOperation && m_resolveClient) m_resolveClient->cancel(resolveOperation);
    if (outcomeOperation && m_outcomeClient) m_outcomeClient->cancel(outcomeOperation);

    // A live accepted session is not torn down merely because the control-plane edge changed.
    // Refresh is queued so the current event/cancel stack has unwound, and only if the user or an
    // authoritative cached installation still has a reason to contact v2.
    if (m_initialized && (m_pendingConnect || m_userWantsConnected || m_authoritativeV2)) {
        QTimer::singleShot(0, this, [this]() {
            QString ignored;
            refreshOnline(ignored);
        });
    }
    return true;
}

void CatalogCoordinator::onCatalogKeysetFetchResult(
    const CatalogKeysetFetchResult &result)
{
    if (!m_refreshInFlight || result.operation == 0
        || result.operation != m_keysetOperation) return;
    m_keysetOperation = 0;
    if (result.kind == CatalogKeysetFetchKind::Artifact) {
        const CatalogKeysetAcceptance accepted = acceptCatalogKeysetEnvelope(
            result.envelope, m_config.bundledRootPublicKeysHex,
            m_keysetTrust, m_clock->nowUtc());
        if (!accepted.accepted) {
            m_refreshInFlight = false;
            terminal(QStringLiteral("keyset_trust_rejected"));
            return;
        }
        // Plan the complete root-authority transition against immutable old state before writing
        // anything. A crash may observe exactly one of two records: new keyset + still-valid LKG,
        // or new keyset + schema-v4 authority high-water tombstone. It must never observe a new
        // keyset paired with an envelope whose signer that keyset omitted or revoked.
        const bool hadCatalogAuthority = m_catalogTrust.hasAcceptedV2;
        bool keepCatalogEnvelope = !m_catalogEnvelope.isEmpty() && !m_catalogLkgExpired;
        bool quarantineCatalog = hadCatalogAuthority && !keepCatalogEnvelope;
        bool transitionInvalid = false;
        if (keepCatalogEnvelope) {
            const bool signerRevoked = catalogSignerRevokedByManifest(
                m_catalogAuthoritySigningKeyId, accepted.manifest);
            const bool signerRetainedForEnvelope =
                !signerRevoked
                && catalogSignerWasValidInPersistedKeyset(m_catalog,
                                                           accepted.manifest);
            const bool receiptAuthoritiesRetainedForEnvelope =
                catalogReceiptAuthoritiesWereValidInKeyset(
                    m_catalog, accepted.manifest);
            if (!signerRetainedForEnvelope
                || !receiptAuthoritiesRetainedForEnvelope) {
                // Root-authenticated omission and explicit revocation are both authoritative
                // non-connectable transitions, not local corruption/reinstall failures.
                keepCatalogEnvelope = false;
                quarantineCatalog = true;
            } else {
                const CatalogAcceptanceResult revalidated = acceptCatalogEnvelope(
                    m_catalogEnvelope,
                    accepted.persistedCatalogVerificationKeyring,
                    m_capabilities, m_catalogTrust,
                    CatalogSource::LastKnownGood, m_clock->nowUtc(), {});
                const bool normalLifecycleExpiry =
                    revalidated.error == CatalogAcceptanceError::Trust
                    && (revalidated.trustError == CatalogTrustError::Expired
                        || revalidated.trustError
                               == CatalogTrustError::EntitlementExpired);
                const bool signerCurrentlyUsable =
                    accepted.keyrings.catalog.publicKeysHex.contains(
                        m_catalogAuthoritySigningKeyId)
                    && accepted.keyrings.catalog.keyEpochs.value(
                           m_catalogAuthoritySigningKeyId)
                           == m_catalogAuthorityKeyEpoch
                    && catalogReceiptAuthoritiesCurrentlyUsable(
                        m_catalog, accepted.keyrings);
                if (normalLifecycleExpiry || !signerCurrentlyUsable) {
                    keepCatalogEnvelope = false;
                    quarantineCatalog = true;
                } else if (!revalidated.authoritative) {
                    // The signer is still declared for this exact issuance window, so signature,
                    // binding or rollback failure is corruption/authority collision, not rotation.
                    transitionInvalid = true;
                }
            }
        }
        if (transitionInvalid) {
            failClosedAuthorityPersistence(
                QStringLiteral("catalog_lkg_transition_invalid"));
            return;
        }

        // The root-signed monotonic keyset is rollback/revocation authority in its own right.
        // A clean first install has no old v2 authority, so its keyset is stored atomically with
        // the first network catalog acceptance instead of creating an authority-only half state.
        if (m_authoritativeV2 || hadCatalogAuthority) {
            QString persistError;
            if (!persistAuthoritySnapshot(
                    accepted.nextState,
                    keepCatalogEnvelope ? m_catalogEnvelope : QByteArray{},
                    persistError)) {
                failClosedAuthorityPersistence(
                    QStringLiteral("keyset_authority_persist_failed"));
                return;
            }
        }
        m_keysetTrust = accepted.nextState;
        m_keyrings = accepted.keyrings;
        if (quarantineCatalog) {
            const bool liveRuntime = runtimeMayOwnNativeSession(m_lastSnapshot);
            if (liveRuntime)
                m_pendingConnect = m_userWantsConnected;
            m_catalogEnvelope.clear();
            m_catalogLkgExpired = true;
            m_catalogAuthoritySigningKeyId.clear();
            m_catalogAuthorityKeyEpoch = 0;
            m_catalog = {};
            m_candidates.clear();
            m_runtimeAuthority = {};
            if (m_facade)
                m_facade->clearCatalog(
                    QStringLiteral("catalog_signer_authority_rotated"));
            if (liveRuntime && m_reducer) {
                // Discovery cannot race the old native owner. Resume it only after the reducer
                // proves exact Idle with no inner session and no outer/ambiguous guard owner.
                m_keysetResolveAfterTeardown = true;
                m_reducer->disconnect();
                return;
            }
        }
        QString error;
        if (!beginResolve(error)) {
            m_refreshInFlight = false;
            terminal(QStringLiteral("catalog_resolve_dispatch_unavailable"));
        }
        return;
    }
    m_refreshInFlight = false;
    if (result.kind == CatalogKeysetFetchKind::TemporarilyUnavailable) {
        if (!m_catalogStaleNeedsRefresh && !m_catalogEnvelope.isEmpty()
            && !m_catalogLkgExpired
            && m_pendingConnect
            && acceptedCatalogSelectionMatchesIntent()) {
            QString lkgError;
            if (!configureAcceptedCatalog(false, lkgError)) {
                terminal(QStringLiteral("catalog_lkg_unusable"));
                return;
            }
        }
        scheduleResolveRetry(result.retryAfterS);
        return;
    }
    if (!m_catalogEnvelope.isEmpty() && !m_catalogLkgExpired) {
        updateFacadeCatalogView();
        if (m_pendingConnect) {
            if (m_catalogStaleNeedsRefresh) {
                scheduleResolveRetry(result.retryAfterS > 0 ? result.retryAfterS : 5);
                return;
            }
            if (!acceptedCatalogSelectionMatchesIntent()) {
                scheduleResolveRetry(result.retryAfterS > 0 ? result.retryAfterS : 5);
                return;
            }
            QString lkgError;
            if (!configureAcceptedCatalog(false, lkgError))
                terminal(QStringLiteral("catalog_lkg_unusable"));
        } else if (m_retryVerificationAfterRefresh && canRetryVerificationNow()) {
            QString retryError;
            if (m_reducer->retryVerification(retryError))
                m_retryVerificationAfterRefresh = false;
        }
        return;
    }
    terminal(result.kind == CatalogKeysetFetchKind::NetworkUnavailable
                 ? QStringLiteral("keyset_network_unavailable")
                 : QStringLiteral("keyset_protocol_error"));
}

bool CatalogCoordinator::beginResolve(QString &error)
{
    error.clear();
    QByteArray bearer = m_config.bearerTokenProvider
                            ? m_config.bearerTokenProvider() : QByteArray{};
    if (bearer.trimmed().isEmpty()) {
        bearer.fill('\0');
        error = QStringLiteral("catalog_auth_not_ready");
        return false;
    }
    CatalogResolveAttempt attempt;
    const bool started = m_resolveClient->start(m_config.apiBaseUrl, bearer,
                                                 m_runtimeRequest, attempt, error);
    bearer.fill('\0');
    if (!started) return false;
    m_resolveAttempt = attempt;
    return true;
}

bool CatalogCoordinator::beginIntentScopedResolve(QString &error)
{
    error.clear();
    static const QString directoryCap =
        QStringLiteral("catalog.location_directory_v1");
    if (!m_catalog.locationDirectory.has_value()
        || !m_runtimeRequest.capabilities.contains(directoryCap)
        || !m_capabilities.capabilities.contains(directoryCap)) {
        error = QStringLiteral("catalog_scoped_selection_not_proven");
        return false;
    }
    m_runtimeRequest.selection = requestedCatalogSelection();
    m_facade->setCoordinatorStage(QStringLiteral("resolving"));
    m_refreshInFlight = true;
    if (!beginResolve(error)) {
        m_refreshInFlight = false;
        return false;
    }
    return true;
}

void CatalogCoordinator::onCatalogResolveResult(const CatalogResolveResult &result)
{
    if (!m_refreshInFlight || result.operation == 0
        || result.operation != m_resolveAttempt.operation
        || result.requestNonce != m_resolveAttempt.requestNonce) return;
    // Copy the immutable request binding before clearing/cancelling any coordinator state. The
    // response must be checked against the selection actually sent, never the latest UI intent.
    const CatalogResolveAttempt completedAttempt = m_resolveAttempt;
    m_resolveAttempt = {};
    m_refreshInFlight = false;
    if (result.authoritativeV2Endpoint) {
        closeLegacyAuthoritatively(result.serverCode);
        // Authenticated endpoint evidence closes legacy even if the signed payload below is
        // corrupt, rolled back, expired, or crashes acceptance. Make that monotonic fact durable
        // first; a failed write is sticky fail-stop and cannot fall through to native work.
        QString persistError;
        if (!persistCurrentState(persistError)) {
            failClosedAuthorityPersistence(
                QStringLiteral("catalog_authority_persist_failed"));
            return;
        }
    }

    if (result.kind == CatalogResolveResultKind::SignedCatalog) {
        QString error;
        const bool wantConnect = m_pendingConnect
                                 || (m_userWantsConnected
                                     && (activeConnectionPhase(m_lastSnapshot.phase)
                                         || m_reconcileNextAcceptance));
        const std::optional<CatalogResolveSelection> expectedSelection =
            completedAttempt.scopedSelectionSent
                ? std::optional<CatalogResolveSelection>(
                      completedAttempt.expectedSelection)
                : std::nullopt;
        if (!acceptCatalog(result.signedEnvelope, CatalogSource::Network,
                           result.requestNonce, false, error, true,
                           expectedSelection,
                           completedAttempt.scopedSelectionSent)) {
            if (!m_authorityPersistenceFailed) {
                if (m_lastSnapshot.session.isValid()
                    && activeConnectionPhase(m_lastSnapshot.phase))
                    m_facade->onConnectionReducerSnapshot(m_lastSnapshot);
                else
                    terminal(QStringLiteral("catalog_acceptance_rejected"));
            }
            return;
        }
        m_retryCount = 0;
        if (wantConnect && m_catalog.locationDirectory.has_value()
            && !acceptedCatalogSelectionMatchesIntent()) {
            // Persist the unscoped signed directory as display/LKG authority, but never start its
            // credential shortlist for a non-default persisted intent. Fetch the exact scoped
            // shortlist under the same freshly verified keyset before any native transition.
            if (!beginIntentScopedResolve(error)) {
                if (m_lastSnapshot.session.isValid()
                    && activeConnectionPhase(m_lastSnapshot.phase))
                    m_facade->onConnectionReducerSnapshot(m_lastSnapshot);
                else
                    terminal(QStringLiteral("catalog_resolve_dispatch_unavailable"));
            }
            return;
        }
        if (wantConnect) {
            if (!validateIntentPair(m_mode, m_locationMode, error)
                || !configureAcceptedCatalog(
                    activeConnectionPhase(m_lastSnapshot.phase), error)) {
                if (m_lastSnapshot.session.isValid()
                    && activeConnectionPhase(m_lastSnapshot.phase))
                    m_facade->onConnectionReducerSnapshot(m_lastSnapshot);
                else if (!error.isEmpty())
                    terminal(error);
                return;
            }
        }
        m_reconcileNextAcceptance = false;
        scheduleRefresh();
        return;
    }

    switch (result.kind) {
    case CatalogResolveResultKind::Preparing:
    case CatalogResolveResultKind::RateLimited:
    case CatalogResolveResultKind::TemporarilyUnavailable:
        scheduleResolveRetry(result.retryAfterS > 0 ? result.retryAfterS : 5);
        return;
    case CatalogResolveResultKind::NetworkUnavailable:
        if (m_catalogStaleNeedsRefresh) {
            scheduleResolveRetry(result.retryAfterS > 0 ? result.retryAfterS : 5);
            return;
        }
        if (!m_catalogEnvelope.isEmpty() && !m_catalogLkgExpired) {
            updateFacadeCatalogView();
            if (m_pendingConnect) {
                if (!acceptedCatalogSelectionMatchesIntent()) {
                    scheduleResolveRetry(result.retryAfterS > 0 ? result.retryAfterS : 5);
                } else {
                    QString ignored;
                    configureAcceptedCatalog(false, ignored);
                }
            } else if (m_retryVerificationAfterRefresh && canRetryVerificationNow()) {
                QString retryError;
                if (m_reducer->retryVerification(retryError))
                    m_retryVerificationAfterRefresh = false;
            }
            return;
        }
        terminal(QStringLiteral("catalog_network_unavailable"));
        return;
    case CatalogResolveResultKind::ProtocolError:
        terminal(QStringLiteral("catalog_protocol_error"));
        return;
    default:
        terminal(result.serverCode.isEmpty()
                     ? QStringLiteral("catalog_authority_denied") : result.serverCode);
        return;
    }
}

bool CatalogCoordinator::acceptCatalog(const QByteArray &envelope, CatalogSource source,
                                       const QString &expectedNonce, bool requestConnect,
                                       QString &error, bool persistAcceptance,
                                       std::optional<CatalogResolveSelection> expectedSelection,
                                       bool requireSelectionEcho)
{
    error.clear();
    CatalogRequestBinding requestBinding;
    requestBinding.expectedRequestNonce = expectedNonce;
    requestBinding.expectedSelection = std::move(expectedSelection);
    requestBinding.requireSelectionEcho = requireSelectionEcho;
    const CatalogAcceptanceResult accepted = acceptCatalogEnvelope(
        envelope, m_keyrings.catalog, m_capabilities, m_catalogTrust,
        source, m_clock->nowUtc(), std::move(requestBinding));
    if (!accepted.authoritative) {
        error = accepted.detail;
        return false;
    }
    closeLegacyAuthoritatively(QStringLiteral("catalog_v2_accepted"));
    m_catalog = accepted.catalog;
    m_candidates = accepted.candidates;
    // A pin remains explicit user intent even when a refreshed directory temporarily omits it.
    // The facade renders a retained-unavailable row; neither control-plane failure nor rollout
    // churn may silently move the user to another country.
    revalidatePinnedLocation();
    m_catalogTrust = accepted.nextTrustState;
    m_runtimeAuthority = accepted.runtimeAuthority;
    m_catalogEnvelope = envelope;
    m_catalogLkgExpired = false;
    m_catalogAuthoritySigningKeyId = m_catalog.signingKeyId;
    m_catalogAuthorityKeyEpoch = m_catalog.keyEpoch;
    if (!m_clock->observeAcceptedSignedTime(m_catalog.issuedAt, error))
        return false;
    m_runtimeState.trustedClock = m_clock->stateForPersistence();
    if (persistAcceptance && !persistCurrentState(error)) {
        // acceptCatalog has already advanced in-memory monotonic authority. A failed atomic
        // replace cannot fall back to that ephemeral catalog or let an existing native owner run
        // under it; the process stays sticky fail-closed until a durable relaunch recovery.
        failClosedAuthorityPersistence(
            QStringLiteral("catalog_authority_persist_failed"));
        return false;
    }
    if (source == CatalogSource::Network)
        m_catalogStaleNeedsRefresh = false;
    updateFacadeCatalogView();
    if (!accepted.connectable) {
        error = accepted.detail;
        m_facade->setCoordinatorStage(QStringLiteral("failed"),
                                      QStringLiteral("no_compatible_candidate"));
        return true; // authoritative but intentionally not connectable
    }
    if (requestConnect)
    {
        const bool configured = configureAcceptedCatalog(
            activeConnectionPhase(m_lastSnapshot.phase), error);
        if (configured && m_retryVerificationAfterRefresh
            && m_lastSnapshot.session.isValid()) {
            QString retryError;
            if (m_reducer->retryVerification(retryError))
                m_retryVerificationAfterRefresh = false;
        }
        return configured;
    }
    return true;
}

QStringList CatalogCoordinator::receiptProtectedIps() const
{
    QSet<QString> unique;
    if (m_catalog.receiptProviderPolicy) {
        for (const ReceiptProviderDescriptor &provider
             : m_catalog.receiptProviderPolicy->providers)
            for (const QString &literal : provider.bootstrapIps)
                unique.insert(literal);
    }
    QStringList result = unique.values();
    std::sort(result.begin(), result.end());
    return result;
}

bool CatalogCoordinator::configureAcceptedCatalog(bool reconcile, QString &error)
{
    error.clear();
    if (m_externalNativeOwnershipBlocked) {
        m_pendingConnect = m_userWantsConnected;
        if (m_facade)
            m_facade->setCoordinatorStage(QStringLiteral("disconnecting"),
                                          QStringLiteral("legacy_native_teardown_pending"));
        return true;
    }
    if (m_nativeGuardRecoveryPending) {
        error = QStringLiteral("native_guard_recovery_required");
        return false;
    }
    if (m_catalogStaleNeedsRefresh) {
        m_pendingConnect = m_userWantsConnected;
        error = QStringLiteral("catalog_stale_refresh_required");
        return false;
    }
    if (!m_productionReady || m_candidates.isEmpty()) {
        error = QStringLiteral("catalog_v2_no_connectable_runtime");
        return false;
    }
    QList<CatalogCandidate> connectionCandidates = m_candidates;
    if (!m_reselectExcludedProfileId.isEmpty()) {
        connectionCandidates.erase(
            std::remove_if(connectionCandidates.begin(), connectionCandidates.end(),
                           [this](const CatalogCandidate &candidate) {
                               return candidate.profileId == m_reselectExcludedProfileId;
                           }),
            connectionCandidates.end());
        if (connectionCandidates.isEmpty()) {
            error = QStringLiteral("no_alternative_candidate");
            m_reselectExcludedProfileId.clear();
            return false;
        }
    }
    ReceiptVerifierAuthority receiptAuthority;
    if (!buildReceiptVerifierAuthority(m_catalog, m_keyrings,
                                       receiptAuthority, error))
        return false;
    const QStringList protectedIps = receiptProtectedIps();
    if (protectedIps.isEmpty()) {
        error = QStringLiteral("receipt_protected_route_snapshot_empty");
        return false;
    }
    if (protectedIps != m_appliedProtectedIps) {
        if (activeConnectionPhase(m_lastSnapshot.phase)) {
            m_pendingConnect = true;
            m_reducer->disconnect();
            error = QStringLiteral("protected_route_policy_reconcile_pending");
            return true;
        }
        if (!m_adapters->setProtectedTunnelIpLiterals(protectedIps, error))
            return false;
        m_appliedProtectedIps = protectedIps;
    }
    if (!m_verifier->setAuthority(std::move(receiptAuthority), error)) {
        if (m_lastSnapshot.phase == ConnectionPhase::VerifyingDns
            || m_lastSnapshot.phase == ConnectionPhase::VerifyingTraffic) {
            const bool sameMaterial = std::any_of(
                m_candidates.cbegin(), m_candidates.cend(),
                [&](const CatalogCandidate &candidate) {
                    return candidate.profileId == m_lastSnapshot.profileId
                           && candidate.transport == m_lastSnapshot.transport
                           && candidate.nativeProfile.configGeneration
                                  == m_lastSnapshot.configGeneration
                           && candidate.nativeProfile.bindingGeneration
                                  == m_lastSnapshot.bindingGeneration;
                });
            if (sameMaterial) {
                // Do not tear down an identical live session merely because the old receipt
                // attempt is finishing. The verifier resets itself before reducer delivery; queue
                // authority swap/reconcile at that exact result boundary.
                m_configureAfterVerification = true;
                error.clear();
                return true;
            }
        }
        if (activeConnectionPhase(m_lastSnapshot.phase)) {
            m_pendingConnect = true;
            m_reducer->disconnect();
            return true;
        }
        return false;
    }
    CandidateSelectionRequest request = selectionRequest();
    const QHash<QString, CandidateHistory> history = pathHistory();
    m_pendingConnect = false;
    m_facade->setCoordinatorStage(reconcile ? QStringLiteral("renewing")
                                            : QStringLiteral("selecting"));
    const bool dispatched = reconcile
        ? m_reducer->reconcileAcceptedCatalog(m_catalog, connectionCandidates, history,
                                              request, m_runtimeAuthority, error)
        : m_reducer->connectAcceptedCatalog(m_catalog, connectionCandidates, history,
                                            request, m_runtimeAuthority, error);
    m_reselectExcludedProfileId.clear();
    return dispatched;
}

QHash<QString, CandidateHistory> CatalogCoordinator::pathHistory() const
{
    return candidateHistoryForPath(m_runtimeState, m_networkPath, m_candidates);
}

CandidateSelectionRequest CatalogCoordinator::selectionRequest() const
{
    CandidateSelectionRequest request;
    request.mode = m_mode;
    request.fixedLocationId = m_locationMode == QLatin1String("auto")
                                  ? QString() : m_locationMode;
    request.nowUtc = m_clock->nowUtc();
    request.deterministicSeed = m_config.deterministicSelectionSeed;
    request.maximumCandidates = m_catalog.policy.maxAttempts;
    if (!m_lastSnapshot.profileId.isEmpty()) {
        request.currentProfileId = m_lastSnapshot.profileId;
        request.previousProfileId = m_lastSnapshot.profileId;
        request.previousLocationId = m_lastSnapshot.locationId;
        request.previousTransport = m_lastSnapshot.transport;
    }
    return request;
}

bool CatalogCoordinator::persistCurrentState(QString &error)
{
    if (m_authorityPersistenceFailed) {
        error = QStringLiteral("catalog_authority_persist_failed");
        return false;
    }
    return persistAuthoritySnapshot(
        m_keysetTrust,
        m_catalogLkgExpired ? QByteArray{} : m_catalogEnvelope,
        error);
}

bool CatalogCoordinator::persistAuthoritySnapshot(
    const CatalogKeysetTrustState &keysetTrust,
    const QByteArray &catalogEnvelope,
    QString &error)
{
    error.clear();
    if (!m_secureStore) {
        error = QStringLiteral("secure catalog store unavailable");
        return false;
    }
    QByteArray keysetState, runtimeState;
    m_runtimeState.trustedClock = m_clock->stateForPersistence();
    if (keysetTrust.highestEpoch != 0) {
        if (!serializeCatalogKeysetTrustState(keysetTrust, keysetState, error))
            return false;
    } else if (keysetTrust != CatalogKeysetTrustState{}) {
        error = QStringLiteral("empty keyset trust state is inconsistent");
        return false;
    }
    if (!serializeCatalogRuntimeState(m_runtimeState, runtimeState, error))
        return false;
    CatalogLkgRecord record;
    record.authoritativeV2EndpointSeen = m_authoritativeV2;
    if (m_catalogTrust.hasAcceptedV2) {
        record.verifiedEnvelope = catalogEnvelope;
        record.trustState = m_catalogTrust;
    }
    record.acceptedKeysetState = std::move(keysetState);
    record.runtimeState = std::move(runtimeState);
    return m_secureStore->replaceAtomically(record, error);
}

void CatalogCoordinator::failClosedAuthorityPersistence(const QString &reason)
{
    if (m_authorityPersistenceFailed) {
        terminal(reason);
        return;
    }
    m_authorityPersistenceFailed = true;
    const quint64 keysetOperation = std::exchange(m_keysetOperation, 0);
    const quint64 resolveOperation = std::exchange(m_resolveAttempt.operation, 0);
    const quint64 outcomeOperation = std::exchange(m_outcomeOperation, 0);
    m_resolveAttempt.requestNonce.clear();
    m_outcomeEventId.clear();
    if (keysetOperation && m_keysetClient) m_keysetClient->cancel(keysetOperation);
    if (resolveOperation && m_resolveClient) m_resolveClient->cancel(resolveOperation);
    if (outcomeOperation && m_outcomeClient) m_outcomeClient->cancel(outcomeOperation);
    m_refreshInFlight = false;
    m_keysetResolveAfterTeardown = false;
    m_retryTimer->stop();
    m_refreshTimer->stop();
    m_authorityTimer->stop();
    m_outcomeRetryTimer->stop();
    m_receiptRefreshDeadlineFence.clear();
    m_verificationRetryDeadlineFence.clear();
    m_pendingConnect = false;
    m_reconcileNextAcceptance = false;
    m_retryVerificationAfterRefresh = false;
    m_configureAfterVerification = false;
    cancelCatalogStaleReconnect();
    cancelSurvivalObservation(false);
    m_catalogLkgExpired = true;
    m_catalogEnvelope.clear();
    m_keyrings = {};
    m_catalog = {};
    m_candidates.clear();
    m_runtimeAuthority = {};
    m_catalogAuthoritySigningKeyId.clear();
    m_catalogAuthorityKeyEpoch = 0;
    if (m_facade) {
        m_facade->clearCatalog(reason);
        m_facade->setV2AuthorityState(m_authoritativeV2);
    }
    const bool runtimeMayStillExist = runtimeMayOwnNativeSession(m_lastSnapshot);
    if (runtimeMayStillExist && m_reducer)
        m_reducer->disconnect();
    terminal(reason);
}

void CatalogCoordinator::closeLegacyAuthoritatively(const QString &)
{
    m_authoritativeV2 = true;
    if (m_facade) m_facade->setV2AuthorityState(true);
}

void CatalogCoordinator::scheduleResolveRetry(int seconds)
{
    if (++m_retryCount > qBound(1, m_config.retryLimit, 5)) {
        terminal(QStringLiteral("catalog_retry_exhausted"));
        return;
    }
    m_retryTimer->start(boundedDelayMs(qBound(1, seconds, 300)));
    m_facade->setCoordinatorStage(QStringLiteral("preparing"));
}

void CatalogCoordinator::scheduleRefresh()
{
    if (!m_catalog.refreshAfter.isValid()) return;
    QDateTime deadline = m_catalog.refreshAfter.toUTC();
    if (m_catalog.receiptProviderPolicy
        && m_catalog.receiptProviderPolicy->verificationTokenExpiresAt.isValid())
        deadline = qMin(deadline,
                        m_catalog.receiptProviderPolicy->verificationTokenExpiresAt.toUTC());
    deadline = deadline.addSecs(-qBound(5, m_config.refreshSafetyMarginS, 120));
    const qint64 seconds = qMax<qint64>(1, m_clock->nowUtc().secsTo(deadline));
    m_refreshTimer->start(boundedDelayMs(seconds));
}

void CatalogCoordinator::scheduleRuntimeTimers(
    const ConnectionRuntimeSnapshot &snapshot)
{
    m_authorityTimer->stop();
    scheduleLifecycleDeadline(snapshot);
    scheduleVerificationRetry(snapshot);
    scheduleReceiptRefresh(snapshot);
    if (!snapshot.session.isValid()) return;
    QDateTime authorityDeadline = snapshot.nativeProfileExpiresAt;
    for (const QDateTime &deadline : {snapshot.catalogFreshnessDeadline,
                                      snapshot.entitlementDeadline})
        if (deadline.isValid() && (!authorityDeadline.isValid()
                                   || deadline < authorityDeadline))
            authorityDeadline = deadline;
    if (authorityDeadline.isValid())
        m_authorityTimer->start(boundedDelayMs(
            qMax<qint64>(1, m_clock->nowUtc().secsTo(authorityDeadline))));
}

ReceiptRefreshDeadlineKey CatalogCoordinator::receiptRefreshKey(
    const ConnectionRuntimeSnapshot &snapshot) const
{
    if (!m_userWantsConnected || m_logoutPending || m_nativeGuardRecoveryPending
        || (m_networkReachabilityKnown && !m_networkOnline)
        || snapshot.phase != ConnectionPhase::ConnectedHealthy)
        return {};
    return {snapshot.verification, snapshot.configGeneration,
            snapshot.bindingGeneration, snapshot.verifiedUntilUtc.toUTC()};
}

void CatalogCoordinator::scheduleReceiptRefresh(
    const ConnectionRuntimeSnapshot &snapshot)
{
    const auto arm = m_receiptRefreshDeadlineFence.replace(receiptRefreshKey(snapshot));
    if (!arm) return;
    const qint64 delayMs = proactiveReceiptRefreshDelayMs(
        m_clock->nowUtc(), arm->key.verifiedUntilUtc, m_config.refreshSafetyMarginS);
    QTimer::singleShot(int(delayMs), this, [this, captured = *arm]() {
        onReceiptRefreshDeadline(captured);
    });
}

void CatalogCoordinator::onReceiptRefreshDeadline(ReceiptRefreshDeadlineArm arm)
{
    if (!m_reducer || !m_receiptRefreshDeadlineFence.consume(
            arm, receiptRefreshKey(m_lastSnapshot)))
        return;
    m_reducer->onVerificationFreshnessDeadline(arm.key.verification);
}

VerificationRetryDeadlineKey CatalogCoordinator::verificationRetryKey(
    const ConnectionRuntimeSnapshot &snapshot) const
{
    if (!m_userWantsConnected || m_logoutPending || m_nativeGuardRecoveryPending
        || (m_networkReachabilityKnown && !m_networkOnline)
        || snapshot.phase != ConnectionPhase::VerificationUnknown
        || snapshot.verificationRetryDirective == VerificationRetryDirective::None
        || !m_networkPath.isValid())
        return {};
    return {snapshot.session, snapshot.verificationRetryDirective,
            qBound(1, snapshot.verificationRetryAfterSeconds, 300),
            snapshot.configGeneration, snapshot.bindingGeneration,
            m_catalog.catalogRevision, m_networkPath.epoch,
            snapshot.nativeProfileExpiresAt.toUTC(),
            snapshot.catalogFreshnessDeadline.toUTC(),
            snapshot.entitlementDeadline.toUTC()};
}

void CatalogCoordinator::scheduleVerificationRetry(
    const ConnectionRuntimeSnapshot &snapshot)
{
    const auto arm = m_verificationRetryDeadlineFence.replace(
        verificationRetryKey(snapshot));
    if (!arm) return;
    QTimer::singleShot(arm->key.retryAfterSeconds * 1000, this,
        [this, captured = *arm]() { onVerificationRetryDeadline(captured); });
}

void CatalogCoordinator::onVerificationRetryDeadline(VerificationRetryDeadlineArm arm)
{
    if (!m_reducer || !m_verificationRetryDeadlineFence.consume(
            arm, verificationRetryKey(m_lastSnapshot)))
        return;
    if (arm.key.directive == VerificationRetryDirective::RefreshCatalog
        || !canRetryVerificationNow()) {
        m_retryVerificationAfterRefresh = true;
        QString ignored;
        if (!refreshOnline(ignored) && !m_refreshInFlight)
            scheduleVerificationRetry(m_lastSnapshot);
        return;
    }
    QString ignored;
    if (!m_reducer->retryVerification(ignored))
        scheduleVerificationRetry(m_lastSnapshot);
}

void CatalogCoordinator::scheduleLifecycleDeadline(
    const ConnectionRuntimeSnapshot &snapshot)
{
    const auto arm = m_lifecycleDeadlineFence.replace(snapshot.lifecycleWait);
    if (!arm) return;
    const bool verification = arm->wait.kind == ConnectionLifecycleWaitKind::Verification;
    const int delayMs = verification
        ? qBound(2000, m_catalog.policy.verifyTimeoutMs, 30000)
        : qBound(3000, m_catalog.policy.connectTimeoutMs, 60000);
    QTimer::singleShot(delayMs, this, [this, captured = *arm]() {
        onLifecycleDeadline(captured);
    });
}

void CatalogCoordinator::onLifecycleDeadline(ConnectionLifecycleDeadlineArm arm)
{
    if (!m_reducer
        || !m_lifecycleDeadlineFence.consume(arm, m_lastSnapshot.lifecycleWait))
        return;
    dispatchConnectionLifecycleTimeout(m_reducer, arm.wait);
}

void CatalogCoordinator::updateFacadeCatalogView()
{
    const bool awg = std::any_of(m_candidates.cbegin(), m_candidates.cend(),
        [](const CatalogCandidate &candidate) { return candidate.transport == TransportKind::Awg; });
    const bool xray = std::any_of(m_candidates.cbegin(), m_candidates.cend(),
        [](const CatalogCandidate &candidate) { return candidate.transport == TransportKind::Xray; });
    m_facade->setCatalogView(m_catalog, m_candidates, pathHistory(),
                             awg, xray, m_productionReady, m_clock->nowUtc());
    m_facade->setV2AuthorityState(m_authoritativeV2);
}

void CatalogCoordinator::fenceDiscoveryForCatalogStale()
{
    // Fence operation identities before cancel: an abort is allowed to complete synchronously.
    const quint64 keysetOperation = std::exchange(m_keysetOperation, 0);
    const quint64 resolveOperation = std::exchange(m_resolveAttempt.operation, 0);
    m_resolveAttempt.requestNonce.clear();
    m_refreshInFlight = false;
    m_reconcileNextAcceptance = false;
    m_retryTimer->stop();
    m_refreshTimer->stop();
    if (keysetOperation && m_keysetClient) m_keysetClient->cancel(keysetOperation);
    if (resolveOperation && m_resolveClient) m_resolveClient->cancel(resolveOperation);
}

void CatalogCoordinator::queueCatalogStaleRefresh()
{
    if (!m_catalogStaleNeedsRefresh || m_catalogStaleRefreshQueued
        || m_refreshInFlight || m_logoutPending || m_nativeGuardRecoveryPending
        || m_externalNativeOwnershipBlocked || !m_userWantsConnected)
        return;
    // Never resolve/reconnect until both exact ownership tokens have disappeared.
    if (activeConnectionPhase(m_lastSnapshot.phase) || m_lastSnapshot.session.isValid()
        || m_lastSnapshot.guardArmed || m_lastSnapshot.guardOwnershipAmbiguous)
        return;
    m_pendingConnect = true;
    m_retryTimer->stop();
    m_catalogStaleRefreshQueued = true;
    QTimer::singleShot(0, this, [this]() {
        if (!m_catalogStaleRefreshQueued) return;
        m_catalogStaleRefreshQueued = false;
        if (!m_catalogStaleNeedsRefresh || m_logoutPending
            || m_nativeGuardRecoveryPending || m_externalNativeOwnershipBlocked
            || !m_userWantsConnected || activeConnectionPhase(m_lastSnapshot.phase)
            || m_lastSnapshot.session.isValid() || m_lastSnapshot.guardArmed
            || m_lastSnapshot.guardOwnershipAmbiguous)
            return;
        QString error;
        if (!refreshOnline(error) && !m_refreshInFlight)
            terminal(QStringLiteral("catalog_stale_refresh_unavailable"));
    });
}

void CatalogCoordinator::cancelCatalogStaleReconnect()
{
    m_catalogStaleStopOperation = 0;
    m_catalogStaleRefreshQueued = false;
}

void CatalogCoordinator::onConnectionReducerSnapshot(
    const ConnectionRuntimeSnapshot &snapshot)
{
    const ConnectionRuntimeSnapshot previous = m_lastSnapshot;
    m_lastSnapshot = snapshot;

    if (m_authorityPersistenceFailed) {
        // Continue only the reducer's exact stop/release lifecycle. No late green, telemetry,
        // history persistence, verification retry or queued configure callback may outlive a
        // failed authority commit.
        if (m_facade) {
            m_facade->onConnectionReducerSnapshot(snapshot);
            m_facade->invalidateVerificationPresentation(
                QStringLiteral("catalog_authority_persist_failed"));
            m_facade->clearCatalog(
                QStringLiteral("catalog_authority_persist_failed"));
        }
        scheduleLifecycleDeadline(snapshot);
        if (m_logoutPending && snapshot.phase == ConnectionPhase::Idle
            && !snapshot.session.isValid() && !snapshot.guardArmed
            && !snapshot.guardOwnershipAmbiguous)
            finishLogoutAfterExactTeardown();
        return;
    }

    if (snapshot.terminalDisposition == ConnectionTerminalDisposition::CatalogStale
        && snapshot.operation != 0
        && snapshot.operation != m_catalogStaleHandledOperation) {
        m_catalogStaleNeedsRefresh = true;
        if (m_catalogStaleStopOperation == 0) {
            m_catalogStaleStopOperation = snapshot.operation;
            fenceDiscoveryForCatalogStale();
        }
    }

    if (snapshot.session.isValid() && snapshot.session != m_outcomeSession) {
        m_outcomeSession = snapshot.session;
        m_outcomeSessionStartedUtc = m_clock->nowUtc();
        m_connectedOutcomeRecorded = false;
        m_unknownOutcomeRecorded = false;
    }
    if (snapshot.phase == ConnectionPhase::ConnectedHealthy
        && !m_connectedOutcomeRecorded) {
        const qint64 elapsed = m_outcomeSessionStartedUtc.isValid()
            ? qBound<qint64>(qint64(0),
                             m_outcomeSessionStartedUtc.msecsTo(m_clock->nowUtc()),
                             qint64(86400000))
            : -1;
        if (enqueueOutcome(snapshot, CatalogOutcomeStage::Connected, true,
                           {}, std::nullopt, elapsed))
            m_connectedOutcomeRecorded = true;
    } else if (snapshot.phase == ConnectionPhase::VerificationUnknown
               && !m_unknownOutcomeRecorded) {
        if (enqueueOutcome(snapshot, CatalogOutcomeStage::VerificationUnknown,
                           false, {}))
            m_unknownOutcomeRecorded = true;
    } else if (snapshot.phase == ConnectionPhase::Failed
               && previous.phase != ConnectionPhase::Failed
               && snapshot.lastFailureStage != ConnectionFailureStage::None) {
        enqueueOutcome(snapshot, outcomeStage(snapshot.lastFailureStage), false,
                       outcomeErrorCode(snapshot.lastTypedReason));
    } else if (snapshot.phase == ConnectionPhase::Idle
               && previous.session.isValid()
               && previous.phase != ConnectionPhase::Failed) {
        const qint64 elapsed = m_outcomeSessionStartedUtc.isValid()
            ? qBound<qint64>(qint64(0),
                             m_outcomeSessionStartedUtc.msecsTo(m_clock->nowUtc()),
                             qint64(86400000))
            : -1;
        enqueueOutcome(previous, CatalogOutcomeStage::Disconnected, false,
                       {}, std::nullopt, elapsed);
        m_outcomeSession = {};
        m_outcomeSessionStartedUtc = {};
        m_connectedOutcomeRecorded = false;
        m_unknownOutcomeRecorded = false;
    }
    m_facade->onConnectionReducerSnapshot(snapshot);
    // A late/duplicate native callback cannot repaint a provably-offline tunnel green.  This is
    // presentation invalidation only: no candidate failure/cooldown is inferred from reachability.
    if (m_networkReachabilityKnown && !m_networkOnline)
        m_facade->invalidateVerificationPresentation(
            QStringLiteral("verification_unknown_network_offline"));
    scheduleRuntimeTimers(snapshot);

    if (m_logoutPending) {
        if (snapshot.phase == ConnectionPhase::Idle && !snapshot.guardArmed)
            finishLogoutAfterExactTeardown();
        return;
    }

    if (m_keysetResolveAfterTeardown) {
        const bool exactReleased = snapshot.phase == ConnectionPhase::Idle
            && !snapshot.session.isValid() && !snapshot.guardArmed
            && !snapshot.guardOwnershipAmbiguous;
        if (exactReleased) {
            m_keysetResolveAfterTeardown = false;
            QString error;
            if (!beginResolve(error)) {
                m_refreshInFlight = false;
                terminal(QStringLiteral("catalog_resolve_dispatch_unavailable"));
            }
        }
        // Never run generic Idle reconnect/configure logic with the quarantined catalog. The
        // accepted root transition owns this exact teardown-to-resolve barrier.
        return;
    }

    const bool exactCatalogStaleTeardown = m_catalogStaleStopOperation != 0
        && snapshot.operation == m_catalogStaleStopOperation
        && snapshot.terminalDisposition == ConnectionTerminalDisposition::CatalogStale
        && snapshot.phase == ConnectionPhase::Failed && !snapshot.session.isValid()
        && !snapshot.guardArmed && !snapshot.guardOwnershipAmbiguous;
    if (exactCatalogStaleTeardown) {
        m_catalogStaleHandledOperation = m_catalogStaleStopOperation;
        m_catalogStaleStopOperation = 0;
        if (m_userWantsConnected)
            queueCatalogStaleRefresh();
    }

    if (snapshot.phase == ConnectionPhase::ConnectedHealthy) {
        beginSurvivalObservation(snapshot);
    } else if (m_survivalSession.isValid()) {
        const bool sameSession = snapshot.session == m_survivalSession;
        const bool verificationStillCovered = sameSession
            && (snapshot.phase == ConnectionPhase::VerifyingDns
                || snapshot.phase == ConnectionPhase::VerifyingTraffic)
            && m_survivalCoverageUntilUtc.isValid()
            && m_clock->nowUtc() < m_survivalCoverageUntilUtc;
        if (!verificationStillCovered) {
            const bool failedEarly = sameSession && m_userWantsConnected
                && (snapshot.phase == ConnectionPhase::Failed
                    || (snapshot.phase == ConnectionPhase::StoppingOld
                        && snapshot.lastFailureStage != ConnectionFailureStage::None));
            cancelSurvivalObservation(failedEarly);
        }
    }

    if (m_networkPath.isValid() && !m_candidates.isEmpty()
        && (snapshot.phase == ConnectionPhase::ConnectedHealthy
            || snapshot.phase == ConnectionPhase::Failed
            || snapshot.phase == ConnectionPhase::Idle)) {
        QString persistError;
        if (mergeCandidateHistoryForPath(m_runtimeState, m_networkPath,
                                         m_reducer->updatedHistory(), persistError)) {
            persistCurrentState(persistError);
            updateFacadeCatalogView();
        }
    }
    if (snapshot.phase == ConnectionPhase::Idle && m_pendingConnect) {
        if (m_catalogLkgExpired && m_refreshInFlight)
            return; // exact rotation barrier already owns the single in-flight resolve
        if (m_catalogStaleNeedsRefresh) {
            queueCatalogStaleRefresh();
        } else if (!acceptedCatalogSelectionMatchesIntent()) {
            // An old unscoped/LKG shortlist must never win the Idle callback race while an exact
            // fixed/forced resolve is pending or awaiting retry.
            if (!m_refreshInFlight && !m_retryTimer->isActive()) {
                QString ignored;
                refreshOnline(ignored);
            }
        } else {
            QString ignored;
            configureAcceptedCatalog(false, ignored);
        }
    }
    if (m_configureAfterVerification
        && snapshot.phase != ConnectionPhase::VerifyingDns
        && snapshot.phase != ConnectionPhase::VerifyingTraffic
        && snapshot.session.isValid()) {
        m_configureAfterVerification = false;
        QTimer::singleShot(0, this, [this]() {
            if (!m_logoutPending && m_userWantsConnected) {
                QString ignored;
                configureAcceptedCatalog(true, ignored);
            }
        });
    }
    Q_UNUSED(previous)
}

bool CatalogCoordinator::validateIntentPair(ConnectionMode mode,
                                             const QString &locationMode,
                                             QString &error) const
{
    error.clear();
    const bool usable = std::any_of(
        m_candidates.cbegin(), m_candidates.cend(), [&](const CatalogCandidate &candidate) {
            const bool locationOk = locationMode == QLatin1String("auto")
                                    || candidate.locationId == locationMode;
            const bool transportOk = mode == ConnectionMode::Auto
                || (mode == ConnectionMode::ForceAwg
                    && candidate.transport == TransportKind::Awg)
                || (mode == ConnectionMode::ForceXray
                    && candidate.transport == TransportKind::Xray);
            return locationOk && transportOk;
        });
    if (!usable)
        error = QStringLiteral("mode_location_pair_unavailable");
    return usable;
}

bool CatalogCoordinator::persistUserIntent(ConnectionMode mode,
                                           const QString &locationMode,
                                           QString &error) const
{
    const CatalogUserIntent intent{
        mode, locationMode == QLatin1String("auto") ? QString() : locationMode};
    return persistCatalogUserIntent(m_config.userIntentSettings, intent, error);
}

void CatalogCoordinator::restoreUserIntent()
{
    const CatalogUserIntent intent = loadCatalogUserIntent(m_config.userIntentSettings);
    m_mode = intent.mode;
    m_locationMode = intent.pinnedLocationId.isEmpty()
                         ? QStringLiteral("auto") : intent.pinnedLocationId;
    if (m_facade) m_facade->restoreUserIntent(m_mode, intent.pinnedLocationId);
}

void CatalogCoordinator::revalidatePinnedLocation()
{
    // Deliberately do not mutate or persist the pin here. A missing directory row is a temporary
    // availability fact, not user consent to switch country. rebuildLocations() renders the
    // retained pin as unavailable until a later signed directory restores it.
    if (m_facade)
        m_facade->restoreUserIntent(
            m_mode, m_locationMode == QLatin1String("auto")
                        ? QString() : m_locationMode);
}

CatalogResolveSelection CatalogCoordinator::requestedCatalogSelection() const
{
    return {m_mode, m_locationMode == QLatin1String("auto")
                        ? QString() : m_locationMode};
}

bool CatalogCoordinator::acceptedCatalogSelectionMatchesIntent() const
{
    // N-1 catalogs have no signed directory/selection echo and retain the legacy bounded
    // shortlist semantics. Directory-aware catalogs are usable only for the exact echoed intent.
    return !m_catalog.locationDirectory.has_value()
        || m_catalog.locationDirectory->selection == requestedCatalogSelection();
}

void CatalogCoordinator::fenceDiscoveryForIntentChange()
{
    const quint64 keysetOperation = std::exchange(m_keysetOperation, 0);
    const quint64 resolveOperation = std::exchange(m_resolveAttempt.operation, 0);
    m_resolveAttempt = {};
    m_refreshInFlight = false;
    m_retryTimer->stop();
    m_refreshTimer->stop();
    if (keysetOperation && m_keysetClient) m_keysetClient->cancel(keysetOperation);
    if (resolveOperation && m_resolveClient) m_resolveClient->cancel(resolveOperation);
}

bool CatalogCoordinator::refreshLiveIntent(QString &error)
{
    error.clear();
    if (!m_userWantsConnected || !activeConnectionPhase(m_lastSnapshot.phase))
        return true; // OFF browsing persists UI intent and performs zero resolves/native work.
    if (!m_catalog.locationDirectory.has_value())
        return configureAcceptedCatalog(true, error); // bounded N-1 fallback

    m_pendingConnect = false;
    m_reconcileNextAcceptance = true;
    fenceDiscoveryForIntentChange();
    QString refreshError;
    if (!refreshOnline(refreshError)) {
        // The old reducer-owned inner and outer guard remain authoritative. A later path/resume or
        // explicit Connect retries the scoped intent; control-plane failure is never a reason to
        // disconnect or repaint the current location as the requested one.
        if (m_lastSnapshot.session.isValid())
            m_facade->onConnectionReducerSnapshot(m_lastSnapshot);
    }
    return true;
}

bool CatalogCoordinator::requestConnectionMode(ConnectionMode mode, QString &error)
{
    error.clear();
    if (m_authorityPersistenceFailed) {
        error = QStringLiteral("catalog_authority_persist_failed");
        return false;
    }
    if (m_nativeGuardRecoveryPending) {
        error = QStringLiteral("native_guard_recovery_required");
        return false;
    }
    if (m_logoutPending) { error = QStringLiteral("logout_in_progress"); return false; }
    if (catalogUserIntentModeName(mode).isEmpty()) {
        error = QStringLiteral("invalid_connection_mode");
        return false;
    }
    if (m_mode == mode) return true;
    if (!persistUserIntent(mode, m_locationMode, error)) return false;
    m_mode = mode;
    if (m_facade)
        m_facade->restoreUserIntent(
            m_mode, m_locationMode == QLatin1String("auto")
                        ? QString() : m_locationMode);
    return refreshLiveIntent(error);
}

bool CatalogCoordinator::requestLocationMode(const QString &locationMode,
                                             QString &error)
{
    error.clear();
    if (m_authorityPersistenceFailed) {
        error = QStringLiteral("catalog_authority_persist_failed");
        return false;
    }
    if (m_nativeGuardRecoveryPending) {
        error = QStringLiteral("native_guard_recovery_required");
        return false;
    }
    if (m_logoutPending) { error = QStringLiteral("logout_in_progress"); return false; }
    if (locationMode != QLatin1String("auto")) {
        if (!canonicalCatalogUserIntentLocationId(locationMode)) {
            error = QStringLiteral("invalid_location_mode");
            return false;
        }
        const bool exists = m_catalog.locationDirectory.has_value()
            ? std::any_of(
                m_catalog.locationDirectory->locations.cbegin(),
                m_catalog.locationDirectory->locations.cend(),
                [&](const CatalogDirectoryLocation &location) {
                    return location.id == locationMode;
                })
            : std::any_of(
                m_catalog.locations.cbegin(), m_catalog.locations.cend(),
                [&](const CatalogLocation &location) {
                    return location.id == locationMode;
                });
        // A previously retained pin may remain selected while absent. New arbitrary values never
        // become intent unless a signed directory/base catalog has introduced them.
        if (!exists && m_locationMode != locationMode) {
            error = QStringLiteral("location_unavailable");
            return false;
        }
    }
    if (m_locationMode == locationMode) return true;
    if (!persistUserIntent(m_mode, locationMode, error)) return false;
    m_locationMode = locationMode;
    if (m_facade)
        m_facade->restoreUserIntent(
            m_mode, m_locationMode == QLatin1String("auto")
                        ? QString() : m_locationMode);
    return refreshLiveIntent(error);
}

bool CatalogCoordinator::requestCatalogRefresh(QString &error)
{
    error.clear();
    if (m_authorityPersistenceFailed) {
        error = QStringLiteral("catalog_authority_persist_failed");
        return false;
    }
    if (m_nativeGuardRecoveryPending) {
        error = QStringLiteral("native_guard_recovery_required");
        return false;
    }
    if (m_logoutPending) {
        error = QStringLiteral("logout_in_progress");
        return false;
    }
    // A list refresh is presentation/control-plane work only. Unlike requestConnect(), this must
    // never arm the guard, dispatch a native profile, or change the user's ON/OFF intent.
    return refreshOnline(error);
}

bool CatalogCoordinator::requestConnect(QString &error)
{
    error.clear();
    if (m_authorityPersistenceFailed) {
        error = QStringLiteral("catalog_authority_persist_failed");
        return false;
    }
    if (m_nativeGuardRecoveryPending) {
        error = QStringLiteral("native_guard_recovery_required");
        return false;
    }
    if (m_logoutPending) {
        error = QStringLiteral("logout_in_progress");
        return false;
    }
    if (!m_productionReady) {
        error = QStringLiteral("catalog_v2_platform_guard_unavailable");
        return false;
    }
    // A clean install has no signed catalog yet, so there is deliberately no candidate set on
    // which to validate the intent.  Connecting is the opt-in action that starts discovery; the
    // pair is validated only after an authoritative catalog has been accepted.  This must happen
    // before returning from the empty-catalog branch so an in-flight OFF can fence the response.
    m_userWantsConnected = true;
    m_pendingConnect = true;
    if (m_externalNativeOwnershipBlocked) {
        m_facade->setCoordinatorStage(QStringLiteral("disconnecting"),
                                      QStringLiteral("legacy_native_teardown_pending"));
        return true;
    }
    if (m_catalogStaleNeedsRefresh) {
        if (activeConnectionPhase(m_lastSnapshot.phase)
            || m_lastSnapshot.session.isValid() || m_lastSnapshot.guardArmed
            || m_lastSnapshot.guardOwnershipAmbiguous)
            return true;
        m_retryTimer->stop();
        if (m_refreshInFlight || m_catalogStaleRefreshQueued)
            return true;
        queueCatalogStaleRefresh();
        return true;
    }
    if (m_catalogEnvelope.isEmpty() || m_catalogLkgExpired) {
        if (m_refreshInFlight || m_retryTimer->isActive())
            return true; // idempotent opt-in while the exact discovery operation is pending
        return refreshOnline(error);
    }
    if (!acceptedCatalogSelectionMatchesIntent()) {
        m_reconcileNextAcceptance = activeConnectionPhase(m_lastSnapshot.phase);
        if (m_refreshInFlight || m_retryTimer->isActive())
            return true;
        return refreshOnline(error);
    }
    if (!validateIntentPair(m_mode, m_locationMode, error)) {
        m_pendingConnect = false;
        m_userWantsConnected = false;
        return false;
    }
    return configureAcceptedCatalog(activeConnectionPhase(m_lastSnapshot.phase), error);
}

void CatalogCoordinator::requestDisconnect()
{
    m_userWantsConnected = false;
    m_pendingConnect = false;
    cancelCatalogStaleReconnect();
    m_reconcileNextAcceptance = false;
    m_retryVerificationAfterRefresh = false;
    m_reselectExcludedProfileId.clear();
    cancelSurvivalObservation(false);
    if (m_keysetResolveAfterTeardown)
        return; // existing exact rotation stop continues; OFF only cancels reconnect intent
    if (m_nativeGuardRecoveryPending) {
        // A pre-existing native owner is not represented by reducer tokens. Generic disconnect
        // would falsely report Idle (or broadly tear down an unrelated legacy session), so wait
        // for the exact platform recovery transaction instead.
        terminal(QStringLiteral("native_guard_recovery_required"));
        return;
    }
    if (m_reducer) m_reducer->disconnect();
}

bool CatalogCoordinator::requestVerificationRetry(QString &error)
{
    error.clear();
    if (m_authorityPersistenceFailed) {
        error = QStringLiteral("catalog_authority_persist_failed");
        return false;
    }
    if (m_nativeGuardRecoveryPending) {
        error = QStringLiteral("native_guard_recovery_required");
        return false;
    }
    if (m_logoutPending) {
        error = QStringLiteral("logout_in_progress");
        return false;
    }
    if (!canRetryVerificationNow()) {
        m_retryVerificationAfterRefresh = true;
        error = QStringLiteral("verification_authority_refresh_required");
        QString ignored;
        refreshOnline(ignored);
        return false;
    }
    return m_reducer && m_reducer->retryVerification(error);
}

bool CatalogCoordinator::requestReselect(QString &error)
{
    error.clear();
    if (m_authorityPersistenceFailed) {
        error = QStringLiteral("catalog_authority_persist_failed");
        return false;
    }
    if (m_nativeGuardRecoveryPending) {
        error = QStringLiteral("native_guard_recovery_required");
        return false;
    }
    if (m_logoutPending) {
        error = QStringLiteral("logout_in_progress");
        return false;
    }
    if (!m_productionReady || !m_userWantsConnected
        || (m_lastSnapshot.phase != ConnectionPhase::ConnectedHealthy
            && m_lastSnapshot.phase != ConnectionPhase::VerificationUnknown)
        || m_lastSnapshot.profileId.isEmpty()) {
        error = QStringLiteral("reselect_unavailable_or_busy");
        return false;
    }
    const bool alternative = std::any_of(
        m_candidates.cbegin(), m_candidates.cend(), [&](const CatalogCandidate &candidate) {
            if (candidate.profileId == m_lastSnapshot.profileId) return false;
            const bool locationOk = m_locationMode == QLatin1String("auto")
                                    || candidate.locationId == m_locationMode;
            const bool transportOk = m_mode == ConnectionMode::Auto
                || (m_mode == ConnectionMode::ForceAwg
                    && candidate.transport == TransportKind::Awg)
                || (m_mode == ConnectionMode::ForceXray
                    && candidate.transport == TransportKind::Xray);
            return locationOk && transportOk;
        });
    if (!alternative) {
        error = QStringLiteral("no_alternative_candidate");
        return false; // keep the healthy current session; never disconnect into an empty set
    }
    m_reselectExcludedProfileId = m_lastSnapshot.profileId;
    if (!configureAcceptedCatalog(true, error)) {
        m_reselectExcludedProfileId.clear();
        return false;
    }
    return true;
}

bool CatalogCoordinator::requestDoctor(QString &error)
{
    error.clear();
    if (m_authorityPersistenceFailed) {
        error = QStringLiteral("catalog_authority_persist_failed");
        return false;
    }
    if (m_nativeGuardRecoveryPending) {
        error = QStringLiteral("native_guard_recovery_required");
        return false;
    }
    if (!m_authoritativeV2) {
        error = QStringLiteral("catalog_v2_not_authoritative");
        return false;
    }
    if (!m_lastSnapshot.session.isValid()) {
        error = QStringLiteral("doctor_requires_live_v2_session");
        return false;
    }
    // V2 Doctor is deliberately non-mutating except for an authenticated receipt recheck. It
    // exposes the reducer's redacted timeline/core evidence through the facade and never invokes
    // legacy start/rotate/cancel methods while the catalog owns the tunnel.
    return requestVerificationRetry(error);
}

void CatalogCoordinator::networkPathChanged(CatalogNetworkClass networkClass,
                                             const QString &pathToken)
{
    if (!m_productionReady) return;
    if (m_networkReachabilityKnown && !m_networkOnline)
        return; // medium churn while offline is not a usable/material online path
    if (pathToken.size() > 128 || pathToken.contains(QLatin1Char('\0'))
        || pathToken.contains(QLatin1Char('\r'))
        || pathToken.contains(QLatin1Char('\n'))) {
        terminal(QStringLiteral("network_path_token_invalid"));
        return;
    }
    if (m_networkPath.isValid() && m_networkPath.networkClass == networkClass
        && ((pathToken.isEmpty() && m_networkPathToken.isEmpty())
            || (!pathToken.isEmpty() && pathToken == m_networkPathToken)))
        return; // duplicate OS callback is not a material path change
    cancelSurvivalObservation(false);
    m_receiptRefreshDeadlineFence.clear();
    m_verificationRetryDeadlineFence.clear();
    QString error;
    CatalogNetworkPathScope next;
    if (!allocateCatalogNetworkPathScope(m_runtimeState, networkClass, next, error)) {
        terminal(QStringLiteral("network_path_epoch_unavailable"));
        return;
    }
    m_networkPath = next;
    m_networkPathToken = pathToken;
    m_facade->updateTrustedPresentationNow(m_clock->nowUtc());
    m_facade->invalidateVerificationPresentation(
        QStringLiteral("verification_stale_after_network_change"));
    if (m_lastSnapshot.session.isValid()) {
        m_retryVerificationAfterRefresh = true;
    }
    persistCurrentState(error);
    refreshOnline(error);
}

void CatalogCoordinator::networkReachabilityChanged(bool online)
{
    if (m_networkReachabilityKnown && m_networkOnline == online) return;
    m_networkReachabilityKnown = true;
    m_networkOnline = online;
    if (!m_productionReady || online) return;

    // QNetworkInformation offline is local liveness evidence only.  Revoke UI green and all
    // timers whose positive result depends on continuous reachability, but preserve the current
    // candidate/history and native owner.  Offline→online is followed by networkPathChanged(),
    // which creates a new path epoch and drives signed catalog/receipt refresh.
    cancelSurvivalObservation(false);
    m_receiptRefreshDeadlineFence.clear();
    m_verificationRetryDeadlineFence.clear();
    m_facade->updateTrustedPresentationNow(m_clock->nowUtc());
    m_facade->invalidateVerificationPresentation(
        QStringLiteral("verification_unknown_network_offline"));
}

void CatalogCoordinator::applicationResumed()
{
    if (!m_productionReady) return;
    cancelSurvivalObservation(false);
    m_receiptRefreshDeadlineFence.clear();
    m_verificationRetryDeadlineFence.clear();
    m_facade->updateTrustedPresentationNow(m_clock->nowUtc());
    m_facade->invalidateVerificationPresentation();
    if (m_lastSnapshot.session.isValid()) {
        m_retryVerificationAfterRefresh = true;
    }
    QString ignored;
    refreshOnline(ignored);
}

void CatalogCoordinator::setExternalNativeOwnershipBlocked(bool blocked)
{
    if (m_externalNativeOwnershipBlocked == blocked) return;
    m_externalNativeOwnershipBlocked = blocked;
    if (blocked) {
        if (m_facade)
            m_facade->setCoordinatorStage(QStringLiteral("disconnecting"),
                                          QStringLiteral("legacy_native_teardown_pending"));
        return;
    }
    // Never re-enter AvpnEngineQml's VpnConnection state callback.  Resume the retained v2 intent
    // only after the exact legacy terminal signal has unwound to the event loop.
    if (m_userWantsConnected || m_pendingConnect) {
        QTimer::singleShot(0, this, [this]() {
            if (m_externalNativeOwnershipBlocked || m_logoutPending
                || m_nativeGuardRecoveryPending || !m_userWantsConnected)
                return;
            QString ignored;
            requestConnect(ignored);
        });
    } else if (m_authoritativeV2) {
        QTimer::singleShot(0, this, [this]() {
            if (m_externalNativeOwnershipBlocked || m_logoutPending
                || m_nativeGuardRecoveryPending) return;
            QString ignored;
            refreshOnline(ignored);
        });
    } else if (m_facade) {
        m_facade->setCoordinatorStage(QStringLiteral("idle"));
    }
}

bool CatalogCoordinator::nativeSessionGuardRecoveryRequired(const QJsonObject &event)
{
    ConnectionGuardEvent parsed;
    QString parseError;
    const bool valid = parseNativeSessionGuardEvent(event, parsed, parseError)
                       && (parsed.kind == ConnectionGuardEventKind::Armed
                           || parsed.kind == ConnectionGuardEventKind::Lost);
    // The signal itself is level-triggered platform evidence that an outer owner may survive this
    // process. Even malformed detail must fail closed; it merely prevents automatic adoption and
    // forces the exact-stop recovery path once the platform API is available.
    m_nativeGuardRecoveryPending = true;
    m_nativeGuardRecoveryIdentity = valid ? parsed : ConnectionGuardEvent{};
    m_userWantsConnected = false;
    m_pendingConnect = false;
    m_keysetResolveAfterTeardown = false;
    const quint64 keysetOperation = std::exchange(m_keysetOperation, 0);
    const quint64 resolveOperation = std::exchange(m_resolveAttempt.operation, 0);
    m_resolveAttempt.requestNonce.clear();
    m_refreshInFlight = false;
    m_retryTimer->stop();
    if (keysetOperation && m_keysetClient) m_keysetClient->cancel(keysetOperation);
    if (resolveOperation && m_resolveClient) m_resolveClient->cancel(resolveOperation);
    cancelCatalogStaleReconnect();
    m_reconcileNextAcceptance = false;
    m_retryVerificationAfterRefresh = false;
    m_reselectExcludedProfileId.clear();
    cancelSurvivalObservation(false);
    closeLegacyAuthoritatively(QStringLiteral("native_guard_recovery_required"));
    if (m_facade) {
        m_facade->invalidateVerificationPresentation(
            QStringLiteral("native_guard_recovery_required"));
        m_facade->setCoordinatorStage(
            QStringLiteral("failed"), valid
                ? QStringLiteral("native_guard_recovery_required")
                : QStringLiteral("native_guard_recovery_event_invalid"));
    }
    // Persist the anti-downgrade latch if initialization already established the secure store.
    // A failed replace is sticky: the platform owner may still exist, and neither the parsed event
    // nor its v2 anti-downgrade fact may be forgotten by letting this process continue.
    if (m_initialized) {
        QString persistError;
        if (!persistCurrentState(persistError)) {
            failClosedAuthorityPersistence(
                QStringLiteral("catalog_authority_persist_failed"));
            return false;
        }
    }
    return valid;
}

bool CatalogCoordinator::nativeSessionGuardRecoveryResolved(const QJsonObject &receipt)
{
    if (!m_nativeGuardRecoveryPending || !m_nativeGuardRecoveryIdentity.operation.isValid())
        return false;
    if (m_authorityPersistenceFailed)
        return false;
    NativeGuardRecoveryReceipt parsed;
    QString parseError;
    if (!parseNativeSessionGuardRecoveryReceipt(receipt, parsed, parseError))
        return false;
    const ConnectionGuardEvent &expected = m_nativeGuardRecoveryIdentity;
    const ConnectionGuardEvent &actual = parsed.identity;
    const bool exactIdentity = actual.operation == expected.operation
        && actual.nativeDispatchPolicySha256 == expected.nativeDispatchPolicySha256
        && actual.outerSessionId == expected.outerSessionId
        && actual.expectedRuntimeSessionId == expected.expectedRuntimeSessionId;
    if (!exactIdentity || parsed.action != NativeGuardRecoveryAction::Stop)
        return false;
    if (parsed.kind == NativeGuardRecoveryKind::Rejected) {
        terminal(QStringLiteral("native_guard_recovery_stop_rejected"));
        return false;
    }
    if (parsed.kind != NativeGuardRecoveryKind::StoppedReleased)
        return false;

    // Make the monotonic v2 tombstone durable before acknowledging the platform receipt or
    // clearing the level-triggered owner latch. A crash/failure at this boundary must relaunch
    // into recovery, never into an apparently clean legacy-capable process.
    if (m_initialized) {
        QString persistError;
        if (!persistCurrentState(persistError)) {
            failClosedAuthorityPersistence(
                QStringLiteral("catalog_authority_persist_failed"));
            return false;
        }
    }

    // This exact receipt proves both inner ownership and the outer route guard are gone. Keep the
    // v2 anti-downgrade tombstone, but unblock the ordinary coordinator runtime; unsigned v1 never
    // reappears merely because recovery completed.
    if (m_reducer) m_reducer->onGuardRecoveryReleased(actual);
    m_nativeGuardRecoveryPending = false;
    m_nativeGuardRecoveryIdentity = {};
    if (m_logoutPending) {
        finishLogoutAfterExactTeardown();
    } else if (m_facade) {
        m_facade->setCoordinatorStage(QStringLiteral("idle"));
        updateFacadeCatalogView();
    }
    return true;
}

void CatalogCoordinator::clearAfterLogout()
{
    if (m_nativeGuardRecoveryPending) {
        m_logoutPending = true;
        m_userWantsConnected = false;
        m_pendingConnect = false;
        cancelCatalogStaleReconnect();
        terminal(QStringLiteral("native_guard_recovery_required"));
        return;
    }
    if (m_logoutPending) return;
    m_logoutPending = true;
    m_userWantsConnected = false;
    m_pendingConnect = false;
    cancelCatalogStaleReconnect();
    m_reconcileNextAcceptance = false;
    m_retryVerificationAfterRefresh = false;
    m_configureAfterVerification = false;
    m_keysetResolveAfterTeardown = false;
    cancelSurvivalObservation(false);
    if (m_keysetOperation) m_keysetClient->cancel(m_keysetOperation);
    if (m_resolveAttempt.operation) m_resolveClient->cancel(m_resolveAttempt.operation);
    if (m_outcomeOperation && m_outcomeClient) m_outcomeClient->cancel(m_outcomeOperation);
    m_keysetOperation = 0;
    m_resolveAttempt = {};
    m_outcomeOperation = 0;
    m_outcomeEventId.clear();
    m_refreshInFlight = false;
    for (QTimer *timer : {m_retryTimer, m_refreshTimer, m_authorityTimer,
                          m_outcomeRetryTimer}) timer->stop();
    m_receiptRefreshDeadlineFence.clear();
    m_facade->setCoordinatorStage(QStringLiteral("disconnecting"),
                                  QStringLiteral("logout_in_progress"));
    if (m_reducer) m_reducer->disconnect();
    if (m_lastSnapshot.phase == ConnectionPhase::Idle
        && !m_lastSnapshot.session.isValid() && !m_lastSnapshot.guardArmed
        && !m_lastSnapshot.guardOwnershipAmbiguous)
        finishLogoutAfterExactTeardown();
    else
        m_logoutTimer->start(30000);
}

bool CatalogCoordinator::canRetryVerificationNow() const
{
    if (!m_clock || !m_catalog.receiptProviderPolicy || !m_lastSnapshot.session.isValid())
        return false;
    const QDateTime now = m_clock->nowUtc().toUTC();
    const QDateTime safety = now.addSecs(qBound(5, m_config.refreshSafetyMarginS, 120));
    const ReceiptProviderPolicy &policy = *m_catalog.receiptProviderPolicy;
    return now.isValid() && policy.verificationTokenExpiresAt.isValid()
           && policy.verificationTokenExpiresAt.toUTC() > safety
           && m_lastSnapshot.nativeProfileExpiresAt.isValid()
           && m_lastSnapshot.nativeProfileExpiresAt.toUTC() > safety
           && m_lastSnapshot.catalogFreshnessDeadline.isValid()
           && m_lastSnapshot.catalogFreshnessDeadline.toUTC() > safety
           && m_lastSnapshot.entitlementDeadline.isValid()
           && m_lastSnapshot.entitlementDeadline.toUTC() > safety;
}

void CatalogCoordinator::finishLogoutAfterExactTeardown()
{
    if (!m_logoutPending || m_lastSnapshot.phase != ConnectionPhase::Idle
        || m_lastSnapshot.session.isValid() || m_lastSnapshot.guardArmed
        || m_lastSnapshot.guardOwnershipAmbiguous)
        return;
    m_logoutTimer->stop();
    QString error;
    if (m_secureStore && !m_secureStore->clear(error)) {
        // The rollback tombstone/key custody is part of logout. Never expose legacy v1 when a
        // partial secure-store wipe might permit an older accepted-v2 record to resurrect.
        terminal(QStringLiteral("logout_secure_wipe_failed"));
        return;
    }
    if (m_verifier) m_verifier->clearAuthority();
    m_authoritativeV2 = false;
    m_catalog = {};
    m_candidates.clear();
    m_catalogEnvelope.clear();
    m_catalogLkgExpired = false;
    m_catalogAuthoritySigningKeyId.clear();
    m_catalogAuthorityKeyEpoch = 0;
    m_catalogTrust = {};
    m_keysetTrust = {};
    m_keyrings = {};
    m_runtimeState = {};
    m_networkPath = {};
    m_networkPathToken.clear();
    m_appliedProtectedIps.clear();
    m_catalogStaleNeedsRefresh = false;
    m_catalogStaleStopOperation = 0;
    m_catalogStaleHandledOperation = 0;
    m_catalogStaleRefreshQueued = false;
    m_authorityPersistenceFailed = false;
    m_keysetResolveAfterTeardown = false;
    m_outcomeQuarantined.clear();
    m_mode = ConnectionMode::Auto;
    m_locationMode = QStringLiteral("auto");
    QString ignored;
    persistUserIntent(m_mode, m_locationMode, ignored);
    m_logoutPending = false;
    m_facade->clearV2AuthorityAfterSecureLogout();
    m_facade->setCoordinatorStage(QStringLiteral("idle"));
}

void CatalogCoordinator::beginSurvivalObservation(
    const ConnectionRuntimeSnapshot &snapshot)
{
    const QDateTime now = m_clock->nowUtc().toUTC();
    if (!snapshot.session.isValid() || snapshot.profileId.isEmpty()
        || snapshot.configGeneration == 0 || snapshot.bindingGeneration == 0
        || !m_networkPath.isValid() || !snapshot.verifiedUntilUtc.isValid()
        || snapshot.verifiedUntilUtc.toUTC() <= now)
        return;
    const bool sameObservation = m_survivalSession == snapshot.session
        && m_survivalProfileId == snapshot.profileId
        && m_survivalConfigGeneration == snapshot.configGeneration
        && m_survivalBindingGeneration == snapshot.bindingGeneration
        && m_survivalPathEpoch == m_networkPath.epoch;
    if (sameObservation && m_survivalCoverageUntilUtc.isValid()
        && now < m_survivalCoverageUntilUtc) {
        // An exact same-session receipt arrived before the old proof expired: extend continuous
        // coverage without restarting the original five-minute observation.
        m_survivalCoverageUntilUtc = snapshot.verifiedUntilUtc.toUTC();
        return;
    }
    // Same identity after a proof gap is a new observation. Its old queued timer is fenced by the
    // generation captured below and cannot award survival early.
    cancelSurvivalObservation(false);
    m_survivalSession = snapshot.session;
    m_survivalProfileId = snapshot.profileId;
    m_survivalConfigGeneration = snapshot.configGeneration;
    m_survivalBindingGeneration = snapshot.bindingGeneration;
    m_survivalPathEpoch = m_networkPath.epoch;
    m_survivalStartedAtUtc = now;
    m_survivalCoverageUntilUtc = snapshot.verifiedUntilUtc.toUTC();
    if (++m_survivalGeneration == 0) ++m_survivalGeneration;
    const quint64 capturedGeneration = m_survivalGeneration;
    const TransportOperationToken capturedSession = m_survivalSession;
    const QString capturedProfile = m_survivalProfileId;
    const quint64 capturedConfig = m_survivalConfigGeneration;
    const quint64 capturedBinding = m_survivalBindingGeneration;
    const quint64 capturedPath = m_survivalPathEpoch;
    QTimer::singleShot(5 * 60 * 1000, this,
        [this, capturedSession, capturedProfile, capturedConfig, capturedBinding,
         capturedPath, capturedGeneration]() {
            onSurvivalCheckpoint(capturedSession, capturedProfile, capturedConfig,
                                 capturedBinding, capturedPath, capturedGeneration);
        });
}

void CatalogCoordinator::cancelSurvivalObservation(bool recordFailure)
{
    if (!m_survivalSession.isValid()) return;
    if (recordFailure && m_networkPath.isValid()
        && m_networkPath.epoch == m_survivalPathEpoch) {
        QHash<QString, CandidateHistory> history = pathHistory();
        CandidateHistory &item = history[m_survivalProfileId];
        if (item.configGeneration == m_survivalConfigGeneration
            && item.bindingGeneration == m_survivalBindingGeneration) {
            item.survival5mEwma = item.survival5mEwma < 0.0
                                      ? 0.0 : qBound(0.0, item.survival5mEwma * 0.8, 1.0);
            QString error;
            if (mergeCandidateHistoryForPath(m_runtimeState, m_networkPath, history, error))
                persistCurrentState(error);
        }
    }
    m_survivalSession = {};
    m_survivalProfileId.clear();
    m_survivalConfigGeneration = 0;
    m_survivalBindingGeneration = 0;
    m_survivalPathEpoch = 0;
    m_survivalStartedAtUtc = {};
    m_survivalCoverageUntilUtc = {};
    if (++m_survivalGeneration == 0) ++m_survivalGeneration;
}

void CatalogCoordinator::onSurvivalCheckpoint(
    TransportOperationToken session, QString profileId, quint64 configGeneration,
    quint64 bindingGeneration, quint64 pathEpoch, quint64 observationGeneration)
{
    // A stale timer from another session/generation/path is a strict no-op and must not disturb a
    // newer observation.
    if (!session.isValid() || session != m_survivalSession
        || profileId != m_survivalProfileId
        || configGeneration != m_survivalConfigGeneration
        || bindingGeneration != m_survivalBindingGeneration
        || pathEpoch != m_survivalPathEpoch
        || observationGeneration == 0
        || observationGeneration != m_survivalGeneration)
        return;
    const QDateTime now = m_clock->nowUtc().toUTC();
    if (!m_survivalStartedAtUtc.isValid()
        || now < m_survivalStartedAtUtc.addSecs(5 * 60))
        return; // public/test scheduler hook cannot award survival before the exact duration
    // The exact timer fired, but five minutes of continuously authoritative green traffic were
    // not proven (receipt expired/unknown, path moved, or ownership changed). Clear this stopped
    // timer without recording a candidate failure; a later fresh receipt starts a new full window.
    if (!m_networkPath.isValid() || pathEpoch != m_networkPath.epoch
        || m_lastSnapshot.session != session
        || m_lastSnapshot.profileId != profileId
        || m_lastSnapshot.configGeneration != configGeneration
        || m_lastSnapshot.bindingGeneration != bindingGeneration
        || m_lastSnapshot.phase != ConnectionPhase::ConnectedHealthy
        || !m_lastSnapshot.verifiedUntilUtc.isValid()
        || m_lastSnapshot.verifiedUntilUtc.toUTC() <= now
        || !m_survivalCoverageUntilUtc.isValid()
        || m_survivalCoverageUntilUtc <= now) {
        cancelSurvivalObservation(false);
        return;
    }
    QHash<QString, CandidateHistory> history = pathHistory();
    CandidateHistory &item = history[profileId];
    if (item.configGeneration != configGeneration
        || item.bindingGeneration != bindingGeneration)
        return;
    item.survival5mEwma = item.survival5mEwma < 0.0
                              ? 1.0
                              : qBound(0.0, item.survival5mEwma * 0.8 + 0.2, 1.0);
    QString error;
    if (mergeCandidateHistoryForPath(m_runtimeState, m_networkPath, history, error)
        && persistCurrentState(error))
        updateFacadeCatalogView();
    enqueueOutcome(m_lastSnapshot, CatalogOutcomeStage::Connected, true, {}, true,
                   5 * 60 * 1000);
    cancelSurvivalObservation(false);
}

const CatalogCandidate *CatalogCoordinator::candidateForOutcome(
    const ConnectionRuntimeSnapshot &snapshot) const
{
    const auto it = std::find_if(
        m_candidates.cbegin(), m_candidates.cend(),
        [&](const CatalogCandidate &candidate) {
            return candidate.profileId == snapshot.profileId
                   && candidate.transport == snapshot.transport
                   && candidate.nativeProfile.configGeneration
                          == snapshot.configGeneration
                   && candidate.nativeProfile.bindingGeneration
                          == snapshot.bindingGeneration;
        });
    return it == m_candidates.cend() ? nullptr : &*it;
}

bool CatalogCoordinator::enqueueOutcome(
    const ConnectionRuntimeSnapshot &snapshot, CatalogOutcomeStage stage,
    bool verifiedSuccess, const QString &errorCode,
    std::optional<bool> survived5m, qint64 sessionMs)
{
    if (!m_clock || !m_authoritativeV2 || !m_networkPath.isValid()
        || !canonicalCatalogOpaque32(m_catalog.deviceAudience)
        || m_catalog.catalogRevision == 0
        || (!snapshot.session.isValid() && snapshot.phase != ConnectionPhase::Failed))
        return false;
    const CatalogCandidate *candidate = candidateForOutcome(snapshot);
    if (!candidate || candidate->verification.context.isEmpty()) return false;
    CatalogOutcomeEvent event;
    event.eventId = newCatalogOutcomeEventId();
    event.deviceAudience = m_catalog.deviceAudience;
    event.profileId = candidate->profileId;
    event.configGeneration = candidate->nativeProfile.configGeneration;
    event.bindingGeneration = candidate->nativeProfile.bindingGeneration;
    event.catalogRevision = m_catalog.catalogRevision;
    event.context = candidate->verification.context;
    event.transport = candidate->transport;
    event.networkClass = m_networkPath.networkClass;
    event.stage = stage;
    event.errorCode = errorCode;
    if (verifiedSuccess && !survived5m.has_value() && sessionMs >= 0)
        event.connectMs = int(qMin<qint64>(sessionMs, 86400000));
    else
        event.sessionMs = sessionMs;
    event.verifiedSuccess = verifiedSuccess;
    event.survived5m = survived5m;
    event.queuedAtUtc = m_clock->nowUtc();
    QString error;
    if (!appendCatalogOutcome(m_runtimeState, std::move(event), error)) return false;
    // Telemetry is advisory and never gates or tears down a connection. Persistence failure leaves
    // the in-memory queue intact for this process but is deliberately not promoted to terminal.
    persistCurrentState(error);
    flushOutcomes();
    return true;
}

void CatalogCoordinator::flushOutcomes()
{
    // Zero-delay flush callbacks can already be queued when an authority commit fail-stops the
    // coordinator.  The persistence latch is therefore the final fence as well as the timers/
    // in-flight-operation cancellation performed by failClosedAuthorityPersistence().
    if (m_authorityPersistenceFailed || !m_outcomeClient || m_outcomeOperation || m_logoutPending
        || m_runtimeState.pendingOutcomes.isEmpty()) return;
    const auto it = std::find_if(
        m_runtimeState.pendingOutcomes.cbegin(), m_runtimeState.pendingOutcomes.cend(),
        [this](const CatalogOutcomeEvent &event) {
            return !m_outcomeQuarantined.contains(event.eventId);
        });
    if (it == m_runtimeState.pendingOutcomes.cend()) return;
    QByteArray token = m_config.bearerTokenProvider
        ? m_config.bearerTokenProvider() : QByteArray{};
    if (token.trimmed().isEmpty()) {
        token.fill('\0');
        return;
    }
    quint64 operation = 0;
    QString error;
    const bool started = m_outcomeClient->start(
        m_config.apiBaseUrl, token, *it, operation, error);
    token.fill('\0');
    if (!started) {
        m_outcomeRetryTimer->start(30000);
        return;
    }
    m_outcomeOperation = operation;
    m_outcomeEventId = it->eventId;
}

void CatalogCoordinator::onCatalogOutcomeUploadResult(
    const CatalogOutcomeUploadResult &result)
{
    if (!m_outcomeOperation || result.operation != m_outcomeOperation
        || result.eventId != m_outcomeEventId) return;
    m_outcomeOperation = 0;
    m_outcomeEventId.clear();
    if (result.kind == CatalogOutcomeUploadKind::Acknowledged) {
        const auto it = std::find_if(
            m_runtimeState.pendingOutcomes.begin(), m_runtimeState.pendingOutcomes.end(),
            [&](const CatalogOutcomeEvent &event) { return event.eventId == result.eventId; });
        if (it != m_runtimeState.pendingOutcomes.end()) {
            m_runtimeState.pendingOutcomes.erase(it); // ACK-only durable deletion
            QString ignored;
            persistCurrentState(ignored);
        }
        m_outcomeQuarantined.remove(result.eventId);
        QTimer::singleShot(0, this, [this]() { flushOutcomes(); });
        return;
    }
    if (result.kind == CatalogOutcomeUploadKind::StaleAuthority
        || result.kind == CatalogOutcomeUploadKind::ProtocolError) {
        // Do not delete without an ACK. Quarantine only for this process so one permanently stale
        // record cannot head-of-line block newer evidence; a restart retries it from encrypted LKG.
        m_outcomeQuarantined.insert(result.eventId);
        QTimer::singleShot(0, this, [this]() { flushOutcomes(); });
        return;
    }
    const int delay = result.retryAfterS > 0 ? result.retryAfterS : 30;
    m_outcomeRetryTimer->start(boundedDelayMs(qBound(1, delay, 300)));
}

void CatalogCoordinator::terminal(const QString &reason)
{
    if (m_facade)
        m_facade->setCoordinatorStage(QStringLiteral("failed"), reason.left(96));
}

} // namespace avpn
