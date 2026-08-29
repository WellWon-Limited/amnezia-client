#include "ConnectionReducer.h"
#include "SignedEnvelope.h"

#include <QUuid>

#include <optional>
#include <utility>

namespace avpn {
namespace {

quint64 nextNonZero(quint64 &counter)
{
    ++counter;
    if (counter == 0)
        ++counter;
    return counter;
}

bool safeSigningKeyId(const QString &value)
{
    return canonicalSigningKeyId(value);
}

QString newExpectedRuntimeSessionId()
{
    // A fresh UUID is allocated in the app before PREPARE. It is neither derived from reusable
    // operation counters nor accepted TOFU-style from a platform callback, so process restart and
    // delayed-service-event collisions stay fenced.
    return QUuid::createUuid().toString(QUuid::WithoutBraces).toLower();
}

bool safeOpaqueSessionId(const QString &value)
{
    if (value.isEmpty() || value.size() > 256
        || value.contains(QLatin1Char('\0')) || value.contains(QLatin1Char('\r'))
        || value.contains(QLatin1Char('\n')))
        return false;
    return true;
}

bool validAcceptedRuntime(const Catalog &catalog,
                          const CandidateSelectionRequest &request,
                          const CatalogRuntimeAuthority &authority)
{
    return catalog.schemaVersion == 2 && catalog.catalogRevision != 0
           && request.nowUtc.isValid() && catalog.payloadSha256.size() == 32
           && authority.deviceAudience == catalog.deviceAudience
           && authority.catalogRevision == catalog.catalogRevision
           && authority.payloadSha256 == catalog.payloadSha256
           && authority.freshnessDeadline.isValid()
           && authority.freshnessDeadline.toUTC() > request.nowUtc.toUTC()
           && authority.entitlementDeadline.isValid()
           && authority.entitlementDeadline.toUTC()
                  == catalog.entitlementExpiresAt.toUTC()
           && authority.entitlementDeadline.toUTC() > request.nowUtc.toUTC()
           && safeSigningKeyId(catalog.signingKeyId)
           && authority.catalogSigningKeyId == catalog.signingKeyId
           && catalog.issuedAt.isValid() && authority.issuedAt.isValid()
           && authority.issuedAt.toUTC() == catalog.issuedAt.toUTC();
}

} // namespace

ConnectionReducer::ConnectionReducer(TransportAdapterRegistry *registry,
                                     IPostTunnelVerifier *verifier,
                                     IConnectionSessionGuard *guard,
                                     IConnectionClock *clock)
    : m_registry(registry), m_verifier(verifier), m_guard(guard), m_clock(clock)
{
    if (m_verifier)
        m_verifier->setObserver(this);
    if (m_guard)
        m_guard->setObserver(this);
}

ConnectionReducer::~ConnectionReducer()
{
    m_observer = nullptr;
    if (m_verifier) {
        if (m_activeVerification.isValid())
            m_verifier->cancel(m_activeVerification);
        m_verifier->clearObserver(this);
    }
    if (m_guard)
        m_guard->clearObserver(this);
    // Registry/adapters outlive the reducer by contract. Detach with expected-owner comparison so
    // deferred native callbacks cannot target freed reducer memory.
    if (m_registry) {
        for (const TransportKind transport : {TransportKind::Awg, TransportKind::Xray})
            if (ITransportAdapter *adapter = m_registry->adapter(transport))
                adapter->clearObserver(this);
    }
}

bool ConnectionReducer::connectAcceptedCatalog(
    const Catalog &catalog, QList<CatalogCandidate> immutableCompatibleCandidates,
    const QHash<QString, CandidateHistory> &history, CandidateSelectionRequest request,
    const CatalogRuntimeAuthority &authority, QString &error)
{
    error.clear();
    clearAuthorityRenewalTransactions();
    // Acceptance is monotonic even for an intentionally empty/incompatible catalog: unsigned v1
    // must not resurrect a revoked/unsupported device binding after this point.
    m_hasAcceptedV2 = true;
    if (!m_registry || !m_verifier || !m_guard
        || !validAcceptedRuntime(catalog, request, authority)) {
        error = QStringLiteral("accepted catalog runtime dependencies or lifetime are invalid");
        // A bad authoritative replacement must never leave an older v2 session running without
        // a provable guard/authority. Serialize its exact stop before releasing the outer guard.
        if (m_activeAdapter && m_activeToken.isValid()) {
            stopActiveTerminal(ConnectionFailureStage::Policy,
                               QStringLiteral("catalog_runtime_policy"));
        } else {
            setFailure(ConnectionFailureStage::Policy,
                       QStringLiteral("catalog_runtime_policy"));
        }
        return false;
    }
    if (m_guardOwnershipAmbiguous) {
        error = QStringLiteral("platform guard ownership recovery required");
        setFailure(ConnectionFailureStage::Policy,
                   QStringLiteral("guard_ownership_ambiguous"));
        return false;
    }
    if (m_pendingToken.isValid() || m_releasingGuardToken.isValid()) {
        // An outer-policy transaction cannot be superseded by overwriting its pending identity.
        // Mark the current request for teardown and let the coordinator retry only after an exact
        // arm/release receipt. This keeps stale callbacks fenced and never starts old material.
        m_hasAcceptedV2 = true;
        m_disconnectRequested = true;
        error = QStringLiteral("catalog reconcile waiting for session guard transaction");
        addTimeline(QStringLiteral("catalog update queued behind guard transaction"));
        return false;
    }

    m_terminalDisposition = ConnectionTerminalDisposition::None;
    m_maxAttempts = qBound(1, qMin(request.maximumCandidates, catalog.policy.maxAttempts), 5);
    request.maximumCandidates = m_maxAttempts;
    m_candidates = std::move(immutableCompatibleCandidates);
    m_lastAttemptedCandidate = {};
    m_workingHistory = history;
    m_selectionRequest = request;
    m_attemptsUsed = 0;
    m_profileCooldownS = qBound(10, catalog.policy.profileCooldownS, 86400);
    m_catalogFreshnessDeadline = authority.freshnessDeadline.toUTC();
    m_entitlementExpiresAt = authority.entitlementDeadline.toUTC();
    m_runtimeAuthority = authority;
    m_disconnectRequested = false;
    m_terminalStopRequested = false;
    m_lastFailureStage = ConnectionFailureStage::None;
    m_lastTypedReason.clear();
    m_verifiedAtUtc = {};
    m_verifiedUntilUtc = {};
    m_operation = nextNonZero(m_operationCounter);
    addTimeline(QStringLiteral("operation %1 catalog accepted").arg(m_operation));

    if (rankRemaining().isEmpty()) {
        error = QStringLiteral("no compatible candidates after policy filters");
        setFailure(ConnectionFailureStage::Policy, QStringLiteral("no_candidate"));
        m_terminalStopRequested = true;
        // An authoritative empty/incompatible replacement cannot leave an older credential/core
        // running. Preserve exact-session teardown serialization even though there is no fallback.
        if (m_activeAdapter && m_activeToken.isValid()) {
            if (m_verifier && m_activeVerification.isValid())
                m_verifier->cancel(m_activeVerification);
            m_stoppingAdapter = m_activeAdapter;
            m_stoppingCandidate = m_activeCandidate;
            m_stoppingToken = m_activeToken;
            clearActive();
            m_phase = ConnectionPhase::StoppingOld;
            addTimeline(QStringLiteral("old session stopping for authoritative no-candidate"));
            m_stoppingAdapter->stop(m_stoppingToken);
        } else if (m_stoppingAdapter && m_stoppingToken.isValid()) {
            m_phase = ConnectionPhase::StoppingOld;
            addTimeline(QStringLiteral("authoritative no-candidate waiting for old stop"));
        } else {
            QString releaseError;
            if (!releaseGuardWithoutNativeOwner(releaseError)) {
                error = releaseError;
                setFailure(ConnectionFailureStage::Policy,
                           QStringLiteral("guard_release_failed"));
            }
            m_terminalStopRequested = false;
        }
        return false;
    }

    // Connect/reselect while another session is active is cancellation + serialized teardown.
    // Never start a second full tunnel before the exact old session reports Stopped.
    if (m_activeAdapter && m_activeToken.isValid()) {
        if (m_verifier)
            if (m_activeVerification.isValid())
                m_verifier->cancel(m_activeVerification);
        m_failClosedBarrierUntilInnerStart = true;
        m_stoppingAdapter = m_activeAdapter;
        m_stoppingCandidate = m_activeCandidate;
        m_stoppingToken = m_activeToken;
        clearActive();
        m_phase = ConnectionPhase::StoppingOld;
        addTimeline(QStringLiteral("old session stopping for replacement"));
        m_stoppingAdapter->stop(m_stoppingToken);
        return true;
    }
    // A previous operation is already stopping. Replace only the desired immutable snapshot; its
    // Stopped callback remains the sole gate that may start this newest operation.
    if (m_stoppingAdapter && m_stoppingToken.isValid()) {
        m_phase = ConnectionPhase::StoppingOld;
        addTimeline(QStringLiteral("replacement intent superseded while stopping"));
        return true;
    }
    return startNext(error);
}

bool ConnectionReducer::reconcileAcceptedCatalog(
    const Catalog &catalog, QList<CatalogCandidate> immutableCompatibleCandidates,
    const QHash<QString, CandidateHistory> &history, CandidateSelectionRequest request,
    const CatalogRuntimeAuthority &authority, QString &error)
{
    error.clear();
    m_hasAcceptedV2 = true;
    if (!m_registry || !m_verifier || !m_guard
        || !validAcceptedRuntime(catalog, request, authority)) {
        error = QStringLiteral("accepted catalog reconcile authority is invalid");
        if (m_activeAdapter && m_activeToken.isValid())
            stopActiveTerminal(ConnectionFailureStage::Policy,
                               QStringLiteral("catalog_reconcile_policy"));
        else
            setFailure(ConnectionFailureStage::Policy,
                       QStringLiteral("catalog_reconcile_policy"));
        return false;
    }

    // No live session (or an already serialized teardown) uses the normal connect path. This also
    // keeps one immutable desired snapshot when multiple refreshes arrive while StoppingOld.
    if (!m_activeAdapter || !m_activeToken.isValid())
        return connectAcceptedCatalog(catalog, std::move(immutableCompatibleCandidates),
                                      history, request, authority, error);

    const QDateTime now = eventNowUtc();
    if (!now.isValid() || m_catalogFreshnessDeadline <= now
        || m_entitlementExpiresAt <= now
        || !m_activeCandidate.nativeProfile.expiresAt.isValid()
        || m_activeCandidate.nativeProfile.expiresAt.toUTC() <= now) {
        error = QStringLiteral("live runtime authority expired before reconcile");
        stopActiveTerminal(ConnectionFailureStage::Policy,
                           QStringLiteral("runtime_authority_expired"));
        return false;
    }
    if (!m_guardArmed
        || !m_guard->isArmedFor(m_activeToken, m_guardOuterSessionId)) {
        m_guardArmed = false;
        error = QStringLiteral("session guard lost before catalog reconcile");
        stopActiveTerminal(ConnectionFailureStage::Policy, QStringLiteral("guard_lost"));
        return false;
    }

    // Reducer-produced evidence for the current network-path scope wins over an older persisted
    // snapshot supplied by the coordinator. The merged map is also used for no-flap comparison.
    QHash<QString, CandidateHistory> mergedHistory = history;
    for (auto it = m_workingHistory.constBegin(); it != m_workingHistory.constEnd(); ++it)
        mergedHistory.insert(it.key(), it.value());

    std::optional<CatalogCandidate> replacement;
    for (const CatalogCandidate &candidate : immutableCompatibleCandidates) {
        if (candidate.profileId == m_activeCandidate.profileId
            && candidate.transport == m_activeCandidate.transport
            && candidate.profileKind == m_activeCandidate.profileKind
            && candidate.nativeProfile.configGeneration
                   == m_activeCandidate.nativeProfile.configGeneration
            && candidate.nativeProfile.bindingGeneration
                   == m_activeCandidate.nativeProfile.bindingGeneration) {
            replacement = candidate;
            break;
        }
    }
    if (!replacement.has_value()) {
        addTimeline(QStringLiteral("catalog material changed; serialized restart required"));
        return connectAcceptedCatalog(catalog, std::move(immutableCompatibleCandidates),
                                      history, request, authority, error);
    }

    // A forced transport/location intent is authoritative. It must not be silently ignored merely
    // because the old profile still exists in the refreshed catalog.
    const bool currentAllowedByIntent = modeAllowsTransport(request.mode, replacement->transport)
        && (request.fixedLocationId.isEmpty()
            || request.fixedLocationId == replacement->locationId);
    if (!currentAllowedByIntent) {
        addTimeline(QStringLiteral("catalog intent changed; serialized restart required"));
        return connectAcceptedCatalog(catalog, std::move(immutableCompatibleCandidates),
                                      mergedHistory, request, authority, error);
    }

    // A healthy current session is sticky. After the signed minimum dwell it may move only when a
    // compatible challenger has generation-scoped, locally verified traffic evidence and clears a
    // meaningful hysteresis threshold. Server health/capacity hints alone never churn a green TUN.
    if (m_phase == ConnectionPhase::ConnectedHealthy && m_verifiedAtUtc.isValid()) {
        CandidateSelectionRequest qualityRequest = request;
        qualityRequest.nowUtc = now;
        qualityRequest.previousProfileId.clear();
        qualityRequest.previousLocationId.clear();
        qualityRequest.previousTransport = TransportKind::Unknown;
        qualityRequest.previousFailureDomain.clear();
        qualityRequest.failedProfileIds.clear();
        qualityRequest.failedFailureDomains.clear();
        qualityRequest.maximumCandidates = 5;
        const QList<RankedCandidate> ranked = rankCandidates(
            immutableCompatibleCandidates, mergedHistory, qualityRequest);
        if (!ranked.isEmpty() && ranked.first().candidate.profileId != replacement->profileId) {
            const CatalogCandidate &challenger = ranked.first().candidate;
            const CandidateHistory currentHistory = mergedHistory.value(replacement->profileId);
            const CandidateHistory challengerHistory = mergedHistory.value(challenger.profileId);
            const qint64 connectedForS = qMax<qint64>(
                0, m_verifiedAtUtc.toUTC().secsTo(now));
            if (hasVerifiedLocalQualityEvidence(challenger, challengerHistory)
                && hasVerifiedLocalQualityEvidence(*replacement, currentHistory)
                && !keepHealthyCurrent(verifiedLocalQualityScore(currentHistory),
                                       verifiedLocalQualityScore(challengerHistory),
                                       connectedForS, catalog.policy.minimumDwellS)) {
                addTimeline(QStringLiteral(
                    "verified challenger crossed dwell/hysteresis; serialized switch"));
                return connectAcceptedCatalog(catalog,
                                              std::move(immutableCompatibleCandidates),
                                              mergedHistory, request, authority, error);
            }
        }
    }

    AuthorityRenewalTarget target{
        catalog, immutableCompatibleCandidates, mergedHistory, request,
        authority, *replacement, {},
    };
    if (m_pendingAuthorityRenewal.has_value()) {
        const CatalogRuntimeAuthority &pending = m_pendingAuthorityRenewal->authority;
        if (authority.catalogRevision < pending.catalogRevision
            || (authority.catalogRevision == pending.catalogRevision
                && authority.payloadSha256 != pending.payloadSha256)) {
            error = QStringLiteral("authority renewal supersession is stale or colliding");
            stopActiveTerminal(ConnectionFailureStage::Policy,
                               QStringLiteral("runtime_authority_supersession_rejected"));
            return false;
        }
        // Preserve only the newest accepted desired snapshot.  The in-flight receipt can commit
        // only its exact authority; the queued target is reconciled immediately afterwards.
        m_queuedAuthorityRenewal = std::move(target);
        addTimeline(QStringLiteral("newer catalog queued behind exact authority receipt"));
        return true;
    }

    QString renewError;
    TransportAuthorityRenewalDispatch dispatch;
    const TransportAuthorityRenewalResult renewed =
        m_activeAdapter->renewRuntimeAuthority(*replacement, authority,
                                               m_activeToken, dispatch, renewError);
    if (renewed == TransportAuthorityRenewalResult::Rejected) {
        error = renewError.isEmpty() ? QStringLiteral("native authority renewal rejected")
                                     : renewError;
        stopActiveTerminal(ConnectionFailureStage::Policy,
                           QStringLiteral("runtime_authority_renewal_rejected"));
        return false;
    }
    if (renewed == TransportAuthorityRenewalResult::RestartRequired) {
        addTimeline(QStringLiteral("platform authority renewal unavailable; serialized restart"));
        return connectAcceptedCatalog(target.catalog, std::move(target.candidates),
                                      target.history, target.request,
                                      target.authority, error);
    }
    if (renewed == TransportAuthorityRenewalResult::NoChange) {
        commitAuthorityRenewal(std::move(target));
        return true;
    }
    if (renewed != TransportAuthorityRenewalResult::Dispatched
        || !dispatch.isValid()) {
        error = QStringLiteral("native authority renewal returned an invalid dispatch receipt");
        stopActiveTerminal(ConnectionFailureStage::Policy,
                           QStringLiteral("runtime_authority_dispatch_invalid"));
        return false;
    }
    target.dispatch = dispatch;
    m_pendingAuthorityRenewal = std::move(target);
    addTimeline(QStringLiteral("awaiting durable native authority receipt"));
    return true;
}

void ConnectionReducer::commitAuthorityRenewal(AuthorityRenewalTarget target)
{
    // The exact native session has durably accepted this authority (or it was byte-identical).
    // Preserve guard/session/traffic verification while atomically advancing trusted metadata.
    m_candidates = std::move(target.candidates);
    m_workingHistory = std::move(target.history);
    m_selectionRequest = target.request;
    m_selectionRequest.maximumCandidates = qBound(
        1, qMin(target.request.maximumCandidates, target.catalog.policy.maxAttempts), 5);
    m_maxAttempts = m_selectionRequest.maximumCandidates;
    m_profileCooldownS = qBound(10, target.catalog.policy.profileCooldownS, 86400);
    m_catalogFreshnessDeadline = target.authority.freshnessDeadline.toUTC();
    m_entitlementExpiresAt = target.authority.entitlementDeadline.toUTC();
    m_runtimeAuthority = target.authority;
    m_activeCandidate = target.replacement;
    for (const QDateTime &deadline : {
             m_activeCandidate.nativeProfile.expiresAt.toUTC(),
             m_catalogFreshnessDeadline, m_entitlementExpiresAt}) {
        if (deadline.isValid() && m_verifiedUntilUtc.isValid()
            && deadline < m_verifiedUntilUtc)
            m_verifiedUntilUtc = deadline;
    }
    addTimeline(QStringLiteral("catalog authority renewed on exact live session"));

    if (m_queuedAuthorityRenewal.has_value() && m_activeAdapter
        && m_activeToken.isValid() && !m_disconnectRequested) {
        AuthorityRenewalTarget queued = std::move(*m_queuedAuthorityRenewal);
        m_queuedAuthorityRenewal.reset();
        QString ignored;
        reconcileAcceptedCatalog(queued.catalog, std::move(queued.candidates),
                                 queued.history, queued.request,
                                 queued.authority, ignored);
    }
}

void ConnectionReducer::clearAuthorityRenewalTransactions()
{
    m_pendingAuthorityRenewal.reset();
    m_queuedAuthorityRenewal.reset();
}

bool ConnectionReducer::startNext(QString &error)
{
    error.clear();
    m_phase = ConnectionPhase::SelectingCandidate;
    while (m_attemptsUsed < m_maxAttempts) {
        const QList<RankedCandidate> ranked = rankRemaining();
        if (ranked.isEmpty())
            break;
        const CatalogCandidate candidate = ranked.first().candidate;
        m_lastAttemptedCandidate = candidate;
        ++m_attemptsUsed; // compile and start-dispatch rejection both consume the bounded budget
        CompiledNativeProfile compiled;
        QString compileError;
        if (!m_registry->compile(candidate, compiled, compileError)) {
            // A typed/compiler rejection is profile-local. It says nothing about the Host or
            // transport path, so do not poison its failure domain or rewrite fallback affinity.
            markProfileAttemptFailed(candidate, false);
            setFailure(ConnectionFailureStage::Compile, QStringLiteral("profile_compile_rejected"));
            addTimeline(QStringLiteral("candidate %1 compile rejected").arg(candidate.profileId));
            continue;
        }
        compiled.runtimeAuthority = {
            m_runtimeAuthority.source,
            m_runtimeAuthority.deviceAudience,
            m_runtimeAuthority.catalogRevision,
            m_runtimeAuthority.payloadSha256,
            m_runtimeAuthority.catalogSigningKeyId,
            candidate.profileId,
            candidate.transport,
            candidate.nativeProfile.configGeneration,
            candidate.nativeProfile.bindingGeneration,
            candidate.nativeProfile.expiresAt.toUTC(),
            m_runtimeAuthority.freshnessDeadline.toUTC(),
            m_runtimeAuthority.entitlementDeadline.toUTC(),
            m_runtimeAuthority.issuedAt.toUTC(),
            {},
        };
        ITransportAdapter *adapter = m_registry->adapter(candidate.transport);
        if (!adapter) {
            markProfileAttemptFailed(candidate, false);
            setFailure(ConnectionFailureStage::Compile, QStringLiteral("adapter_missing"));
            continue;
        }
        const TransportOperationToken token{m_operation, nextNonZero(m_sessionCounter)};
        PreparedTransportStart prepared;
        QString prepareError;
        if (!adapter->prepareStart(compiled, token, prepared, prepareError)) {
            markProfileAttemptFailed(candidate, false);
            addTimeline(QStringLiteral("candidate %1 native policy preparation rejected")
                            .arg(candidate.profileId));
            setFailure(ConnectionFailureStage::Compile,
                       QStringLiteral("native_policy_prepare_rejected"));
            continue;
        }
        if (prepared.compiled.profileId != compiled.profileId
            || prepared.compiled.transport != compiled.transport
            || prepared.compiled.runtimeAuthority.profileId != candidate.profileId
            || prepared.compiled.runtimeAuthority.configGeneration
                   != candidate.nativeProfile.configGeneration
            || prepared.compiled.runtimeAuthority.bindingGeneration
                   != candidate.nativeProfile.bindingGeneration
            || prepared.finalConfiguration.isEmpty()
            || prepared.nativeDispatchPolicySha256.size() != 32) {
            markProfileAttemptFailed(candidate, false);
            addTimeline(QStringLiteral("candidate %1 prepared policy identity rejected")
                            .arg(candidate.profileId));
            setFailure(ConnectionFailureStage::Compile,
                       QStringLiteral("native_policy_identity_rejected"));
            continue;
        }
        // The app, not the native service and not the first runtime callback, chooses the exact
        // inner-session identity before PREPARE. The platform guard must echo it on every receipt
        // and ACTIVATE must publish runtime status only under this UUID.
        if (!prepared.expectedRuntimeSessionId.isEmpty()
            || !prepared.outerSessionId.isEmpty()) {
            markProfileAttemptFailed(candidate, false);
            setFailure(ConnectionFailureStage::Compile,
                       QStringLiteral("native_policy_identity_prepopulated"));
            continue;
        }
        prepared.expectedRuntimeSessionId = newExpectedRuntimeSessionId();
        if (prepared.expectedRuntimeSessionId.isEmpty()) {
            markProfileAttemptFailed(candidate, false);
            setFailure(ConnectionFailureStage::Policy,
                       QStringLiteral("runtime_session_identity_unavailable"));
            continue;
        }
        // Guard setup is necessarily asynchronous on every supported platform. Publish immutable
        // pending identity before request dispatch so even a (contract-violating) synchronous fake
        // callback is fenced correctly. The adapter MUST NOT start before an exact Armed receipt.
        m_pendingAdapter = adapter;
        m_pendingCandidate = candidate;
        m_pendingPrepared = prepared;
        m_pendingToken = token;
        m_previousGuardTokenAtArm = m_guardToken;
        m_phase = ConnectionPhase::ArmingGuard;
        addTimeline(QStringLiteral("prepared policy awaiting session guard receipt"));
        QString guardError;
        if (!m_guard->prepareAndArm(prepared, token, guardError)) {
            // A rejected dispatch promises no new ownership and no callback. The previous guard,
            // if any, stays continuously armed while the reducer re-ranks another candidate.
            if (m_pendingToken == token)
                handleGuardArmRejected(guardError.isEmpty()
                                           ? QStringLiteral("guard_arm_dispatch_rejected")
                                           : guardError);
            error = guardError.isEmpty()
                        ? QStringLiteral("connection session guard request rejected")
                        : guardError;
            return m_phase != ConnectionPhase::Failed;
        }
        return true;
    }
    error = QStringLiteral("all bounded candidates failed before verification");
    m_lastFailureStage = m_lastFailureStage == ConnectionFailureStage::None
                             ? ConnectionFailureStage::Policy : m_lastFailureStage;
    if (m_lastTypedReason.isEmpty())
        m_lastTypedReason = QStringLiteral("attempts_exhausted");
    QString releaseError;
    m_phaseAfterGuardRelease = ConnectionPhase::Failed;
    if (m_failClosedBarrierUntilInnerStart && m_guardArmed && m_guardToken.isValid()
        && m_guard && m_guard->isArmedFor(m_guardToken, m_guardOuterSessionId)) {
        // A live switch/fallback already stopped its old inner owner. Releasing the continuously
        // held outer barrier merely because every replacement failed would turn a typed Failed
        // state into an unguarded traffic leak. Retain it until a later accepted Connect succeeds
        // or the user explicitly disconnects and receives an exact release receipt.
        setFailure(ConnectionFailureStage::Policy, m_lastTypedReason);
        addTimeline(QStringLiteral("replacement exhausted; outer barrier retained fail-closed"));
        return false;
    }
    if (!releaseGuardWithoutNativeOwner(releaseError)) {
        if (!releaseError.isEmpty()) error = releaseError;
        setFailure(ConnectionFailureStage::Policy, QStringLiteral("guard_release_failed"));
        return false;
    }
    return false;
}

bool ConnectionReducer::beginVerification(QString &error)
{
    error.clear();
    if (!m_verifier || !m_activeAdapter || !m_activeToken.isValid()) {
        error = QStringLiteral("verification runtime unavailable");
        return false;
    }
    m_activeVerification = {
        m_activeToken,
        nextNonZero(m_verificationAttemptCounter),
    };
    m_phase = ConnectionPhase::VerifyingDns;
    return m_verifier->start(m_activeCandidate, m_activeVerification, error);
}

QList<RankedCandidate> ConnectionReducer::rankRemaining() const
{
    if (m_attemptsUsed >= m_maxAttempts)
        return {};
    CandidateSelectionRequest request = m_selectionRequest;
    request.nowUtc = eventNowUtc();
    if (!request.nowUtc.isValid()
        || !m_catalogFreshnessDeadline.isValid()
        || m_catalogFreshnessDeadline <= request.nowUtc
        || !m_entitlementExpiresAt.isValid() || m_entitlementExpiresAt <= request.nowUtc)
        return {};
    request.maximumCandidates = qBound(1, m_maxAttempts - m_attemptsUsed, 5);
    QList<CatalogCandidate> unexpired;
    for (const CatalogCandidate &candidate : m_candidates)
        if (candidate.nativeProfile.expiresAt.isValid()
            && candidate.nativeProfile.expiresAt.toUTC() > request.nowUtc)
            unexpired.append(candidate);
    return rankCandidates(std::move(unexpired), m_workingHistory, request);
}

void ConnectionReducer::onConnectionSessionGuardEvent(const ConnectionGuardEvent &event)
{
    if (!event.operation.isValid())
        return;
    if (m_guardOwnershipAmbiguous && event.operation == m_quarantinedGuardToken) {
        const bool exactQuarantine = event.nativeDispatchPolicySha256
                                         == m_quarantinedGuardPolicySha256
                                     && event.expectedRuntimeSessionId
                                         == m_quarantinedExpectedRuntimeSessionId;
        if (!exactQuarantine) return;
        if (m_guardAmbiguityKind == GuardAmbiguityKind::Arm
            && event.kind == ConnectionGuardEventKind::Armed) {
            if (!safeOpaqueSessionId(event.outerSessionId) || !m_guard
                || !m_guard->isArmedFor(event.operation, event.outerSessionId))
                return;
            m_guardArmed = true;
            m_guardToken = event.operation;
            m_guardOuterSessionId = event.outerSessionId;
            m_guardPolicySha256 = event.nativeDispatchPolicySha256;
            m_guardExpectedRuntimeSessionId = event.expectedRuntimeSessionId;
            m_guardOwnershipAmbiguous = false;
            m_guardAmbiguityKind = GuardAmbiguityKind::None;
            m_quarantinedGuardToken = {};
            m_quarantinedGuardPolicySha256.clear();
            m_quarantinedExpectedRuntimeSessionId.clear();
            m_quarantinedGuardOuterSessionId.clear();
            m_phaseAfterGuardRelease = m_disconnectRequested
                                           ? ConnectionPhase::Idle : ConnectionPhase::Failed;
            QString ignored;
            if (!releaseGuardWithoutNativeOwner(ignored)) {
                setFailure(ConnectionFailureStage::Policy,
                           QStringLiteral("guard_recovery_release_failed"));
            }
            return;
        }
        if (m_guardAmbiguityKind == GuardAmbiguityKind::Arm
            && event.kind == ConnectionGuardEventKind::ArmRejected) {
            // Only exact ArmRejected proves the timed-out identity acquired no outer policy.
            if (m_guard && m_guard->isArmedFor(event.operation, event.outerSessionId))
                return;
            m_guardOwnershipAmbiguous = false;
            m_guardAmbiguityKind = GuardAmbiguityKind::None;
            m_quarantinedGuardToken = {};
            m_quarantinedGuardPolicySha256.clear();
            m_quarantinedExpectedRuntimeSessionId.clear();
            m_quarantinedGuardOuterSessionId.clear();
            if (m_disconnectRequested)
                finishDisconnected();
            else
                notifyObserver();
            return;
        }
        if (event.kind == ConnectionGuardEventKind::Lost) {
            // Lost is positive evidence of an unresolved/quarantined owner, not absence. Retain the
            // exact identity until stopped_released recovery proves both inner and outer are gone.
            if (!safeOpaqueSessionId(event.outerSessionId)) return;
            m_guardAmbiguityKind = GuardAmbiguityKind::Lost;
            m_quarantinedGuardOuterSessionId = event.outerSessionId;
            notifyObserver();
            return;
        }
        if (m_guardAmbiguityKind == GuardAmbiguityKind::Release
            && (event.kind == ConnectionGuardEventKind::Released
                || event.kind == ConnectionGuardEventKind::ReleaseRejected)) {
            // The exact terminal release receipt resolves timeout ambiguity. Keep all ordinary
            // release fields intact so the normal receipt path below performs the state transition.
            m_guardOwnershipAmbiguous = false;
            m_guardAmbiguityKind = GuardAmbiguityKind::None;
            m_quarantinedGuardToken = {};
            m_quarantinedGuardPolicySha256.clear();
            m_quarantinedExpectedRuntimeSessionId.clear();
            m_quarantinedGuardOuterSessionId.clear();
        } else {
            return;
        }
    }
    if (event.kind == ConnectionGuardEventKind::Armed) {
        if (event.operation != m_pendingToken || !m_pendingAdapter
            || (m_phase != ConnectionPhase::ArmingGuard
                && !(m_phase == ConnectionPhase::Disconnecting && m_disconnectRequested))
            || m_pendingPrepared.nativeDispatchPolicySha256.size() != 32)
            return; // stale/duplicate receipt from a superseded guard request
        const bool identityOk = event.nativeDispatchPolicySha256
                                    == m_pendingPrepared.nativeDispatchPolicySha256
                                && safeOpaqueSessionId(event.outerSessionId)
                                && safeOpaqueSessionId(event.expectedRuntimeSessionId)
                                && event.expectedRuntimeSessionId
                                       == m_pendingPrepared.expectedRuntimeSessionId
                                && m_guard
                                && m_guard->isArmedFor(event.operation,
                                                       event.outerSessionId);
        if (!identityOk) {
            // A prior process/reducer can reuse small operation counters, but it cannot predict the
            // fresh app UUID. Treat a wrong echo as stale and keep waiting for the exact receipt;
            // the immutable arm timeout quarantines any truly ambiguous platform ownership.
            return;
        }
        m_guardArmed = true;
        m_guardToken = event.operation;
        m_guardOuterSessionId = event.outerSessionId;
        m_guardPolicySha256 = event.nativeDispatchPolicySha256;
        m_guardExpectedRuntimeSessionId = event.expectedRuntimeSessionId;
        m_pendingPrepared.outerSessionId = event.outerSessionId;
        QString error;
        if (!activatePendingAfterGuard(error) && m_phase != ConnectionPhase::ArmingGuard
            && m_phase != ConnectionPhase::ReleasingGuard
            && m_phase != ConnectionPhase::StartingTransport) {
            if (!error.isEmpty())
                setFailure(ConnectionFailureStage::Policy,
                           QStringLiteral("guard_activation_failed"));
        }
        return;
    }
    if (event.kind == ConnectionGuardEventKind::ArmRejected) {
        if (event.operation != m_pendingToken || !m_pendingAdapter
            || (m_phase != ConnectionPhase::ArmingGuard
                && !(m_phase == ConnectionPhase::Disconnecting && m_disconnectRequested))
            || event.nativeDispatchPolicySha256
                   != m_pendingPrepared.nativeDispatchPolicySha256
            || event.expectedRuntimeSessionId
                   != m_pendingPrepared.expectedRuntimeSessionId)
            return;
        handleGuardArmRejected(event.typedReason.isEmpty()
                                   ? QStringLiteral("guard_arm_rejected")
                                   : event.typedReason);
        return;
    }
    if (event.kind == ConnectionGuardEventKind::Released) {
        if (event.operation != m_releasingGuardToken
            || event.outerSessionId != m_guardOuterSessionId
            || event.nativeDispatchPolicySha256 != m_guardPolicySha256
            || event.expectedRuntimeSessionId != m_guardExpectedRuntimeSessionId)
            return;
        if (m_guard && m_guard->isArmedFor(event.operation, m_guardOuterSessionId)) {
            setFailure(ConnectionFailureStage::Policy,
                       QStringLiteral("guard_release_receipt_invalid"));
            addTimeline(QStringLiteral("guard claimed release but remains armed"));
            return;
        }
        m_guardArmed = false;
        m_guardToken = {};
        m_guardOuterSessionId.clear();
        m_guardPolicySha256.clear();
        m_guardExpectedRuntimeSessionId.clear();
        m_releasingGuardToken = {};
        finishAfterGuardReleased();
        return;
    }
    if (event.kind == ConnectionGuardEventKind::ReleaseRejected) {
        if (event.operation != m_releasingGuardToken
            || event.outerSessionId != m_guardOuterSessionId
            || event.nativeDispatchPolicySha256 != m_guardPolicySha256
            || event.expectedRuntimeSessionId != m_guardExpectedRuntimeSessionId)
            return;
        m_releasingGuardToken = {};
        m_guardArmed = m_guard
                       && m_guard->isArmedFor(event.operation, m_guardOuterSessionId);
        setFailure(ConnectionFailureStage::Policy,
                   event.typedReason.isEmpty()
                       ? QStringLiteral("guard_release_rejected")
                       : event.typedReason);
        addTimeline(QStringLiteral("exact session guard release rejected"));
        return;
    }
    if (event.kind == ConnectionGuardEventKind::Lost
        && (event.operation == m_guardToken || event.operation == m_pendingToken
            || event.operation == m_activeToken || event.operation == m_stoppingToken)) {
        const bool pendingLoss = event.operation == m_pendingToken
                                 && m_pendingToken.isValid();
        if (pendingLoss) {
            if (event.nativeDispatchPolicySha256
                    != m_pendingPrepared.nativeDispatchPolicySha256
                || event.expectedRuntimeSessionId
                    != m_pendingPrepared.expectedRuntimeSessionId)
                return;
        } else if (event.operation == m_guardToken) {
            if (event.outerSessionId != m_guardOuterSessionId
                || event.nativeDispatchPolicySha256 != m_guardPolicySha256
                || event.expectedRuntimeSessionId != m_guardExpectedRuntimeSessionId)
                return;
        }
        m_guardOwnershipAmbiguous = true;
        m_guardAmbiguityKind = GuardAmbiguityKind::Lost;
        m_quarantinedGuardToken = event.operation;
        m_quarantinedGuardPolicySha256 = event.nativeDispatchPolicySha256;
        m_quarantinedExpectedRuntimeSessionId = event.expectedRuntimeSessionId;
        m_quarantinedGuardOuterSessionId = event.outerSessionId;
        m_guardArmed = false;
        if (event.operation == m_pendingToken) {
            m_pendingAdapter = nullptr;
            m_pendingCandidate = {};
            m_pendingPrepared = {};
            m_pendingToken = {};
            m_previousGuardTokenAtArm = {};
        }
        setFailure(ConnectionFailureStage::Policy,
                   event.typedReason.isEmpty() ? QStringLiteral("guard_lost")
                                               : event.typedReason);
        addTimeline(QStringLiteral("platform reported exact guard ownership lost"));
        if (m_activeAdapter && m_activeToken.isValid()) {
            m_terminalStopRequested = true;
            m_stoppingAdapter = m_activeAdapter;
            m_stoppingCandidate = m_activeCandidate;
            m_stoppingToken = m_activeToken;
            clearActive();
            m_phase = ConnectionPhase::StoppingOld;
            m_stoppingAdapter->stop(m_stoppingToken);
        }
    }
}

bool ConnectionReducer::activatePendingAfterGuard(QString &error)
{
    error.clear();
    if (!m_pendingAdapter || !m_pendingToken.isValid() || !m_guard
        || !m_guard->isArmedFor(m_pendingToken, m_guardOuterSessionId)
        || m_guardToken != m_pendingToken || !m_guardArmed) {
        error = QStringLiteral("exact armed guard is unavailable for native activation");
        return false;
    }
    ITransportAdapter *adapter = m_pendingAdapter;
    const CatalogCandidate candidate = m_pendingCandidate;
    const PreparedTransportStart prepared = m_pendingPrepared;
    const TransportOperationToken token = m_pendingToken;
    m_pendingAdapter = nullptr;
    m_pendingCandidate = {};
    m_pendingPrepared = {};
    m_pendingToken = {};
    m_previousGuardTokenAtArm = {};
    addTimeline(QStringLiteral("session guard armed for prepared policy"));

    if (m_disconnectRequested) {
        m_phaseAfterGuardRelease = ConnectionPhase::Idle;
        return releaseGuardWithoutNativeOwner(error);
    }

    m_activeAdapter = adapter;
    m_activeCandidate = candidate;
    m_activeToken = token;
    adapter->setObserver(this);
    m_phase = ConnectionPhase::StartingTransport;
    QString startError;
    if (!adapter->start(prepared, token, startError)) {
        markProfileAttemptFailed(candidate, false);
        addTimeline(QStringLiteral("candidate %1 start dispatch rejected")
                        .arg(candidate.profileId));
        setFailure(ConnectionFailureStage::TransportStart,
                   QStringLiteral("transport_start_dispatch"));
        clearActive();
        return startNext(error);
    }
    m_failClosedBarrierUntilInnerStart = false;
    addTimeline(QStringLiteral("candidate %1 transport starting").arg(candidate.profileId));
    return true;
}

void ConnectionReducer::handleGuardArmRejected(const QString &typedReason)
{
    if (!m_pendingToken.isValid())
        return;
    const TransportOperationToken rejected = m_pendingToken;
    const CatalogCandidate candidate = m_pendingCandidate;
    m_pendingAdapter = nullptr;
    m_pendingCandidate = {};
    m_pendingPrepared = {};
    m_pendingToken = {};

    // Rejected replacement is valid only if the platform did not arm the rejected identity and
    // the previous outer owner stayed intact. Anything else is an ambiguous fail-closed state.
    if (m_guard && m_guard->isArmedFor(rejected)) {
        setFailure(ConnectionFailureStage::Policy,
                   QStringLiteral("guard_rejected_but_armed"));
        addTimeline(QStringLiteral("guard rejection ownership contradiction"));
        return;
    }
    m_guardArmed = m_previousGuardTokenAtArm.isValid() && m_guard
                   && m_guard->isArmedFor(m_previousGuardTokenAtArm,
                                           m_guardOuterSessionId);
    m_guardToken = m_guardArmed ? m_previousGuardTokenAtArm
                                : TransportOperationToken{};
    if (!m_guardArmed) {
        m_guardOuterSessionId.clear();
        m_guardPolicySha256.clear();
        m_guardExpectedRuntimeSessionId.clear();
    }
    m_previousGuardTokenAtArm = {};
    markProfileAttemptFailed(candidate, false);
    setFailure(ConnectionFailureStage::Policy,
               typedReason.isEmpty() ? QStringLiteral("guard_arm_rejected") : typedReason);
    addTimeline(QStringLiteral("prepared session guard request rejected"));
    if (m_disconnectRequested) {
        finishDisconnected();
        return;
    }
    QString ignored;
    startNext(ignored);
}

void ConnectionReducer::markProfileAttemptFailed(const CatalogCandidate &candidate,
                                                  bool startedTransportPathFailure)
{
    if (candidate.profileId.isEmpty())
        return;
    m_selectionRequest.failedProfileIds.insert(candidate.profileId);
    CandidateHistory &history = m_workingHistory[candidate.profileId];
    if (!candidateHistoryMatches(candidate, history))
        history = CandidateHistory{};
    history.configGeneration = candidate.nativeProfile.configGeneration;
    history.bindingGeneration = candidate.nativeProfile.bindingGeneration;
    history.cooldownUntil = eventNowUtc().addSecs(m_profileCooldownS);
    if (!startedTransportPathFailure)
        return;

    // A real started-profile failure changes fallback affinity, but it is not proof that the
    // shared host/failure-domain itself is dead: AWG may be filtered while Xray on the same
    // universal node remains usable. Only an external multi-path/host evidence owner may populate
    // `failedFailureDomains`; the reducer never infers that from one transport attempt.
    m_selectionRequest.previousProfileId = candidate.profileId;
    m_selectionRequest.previousLocationId = candidate.locationId;
    m_selectionRequest.previousTransport = candidate.transport;
    m_selectionRequest.previousFailureDomain = candidate.failureDomain;
    history.verifiedSuccessEwma = history.verifiedSuccessEwma < 0.0
                                      ? 0.0
                                      : qBound(0.0, history.verifiedSuccessEwma * 0.8, 1.0);
}

void ConnectionReducer::disconnect()
{
    // Double Disconnect is idempotent. A new operation invalidates every non-stop callback.
    if (m_disconnectRequested && (m_phase == ConnectionPhase::Disconnecting
                                  || m_stoppingToken.isValid()))
        return;
    m_disconnectRequested = true;
    m_terminalStopRequested = false;
    m_terminalDisposition = ConnectionTerminalDisposition::None;
    clearAuthorityRenewalTransactions();
    m_candidates.clear();
    m_attemptsUsed = 0;
    m_operation = nextNonZero(m_operationCounter);
    if (m_guardOwnershipAmbiguous) {
        setFailure(ConnectionFailureStage::Policy,
                   QStringLiteral("guard_ownership_ambiguous"));
        addTimeline(QStringLiteral("disconnect waiting for exact guard ownership recovery"));
        return;
    }
    if (m_activeVerification.isValid() && m_verifier)
        m_verifier->cancel(m_activeVerification);
    if (m_pendingToken.isValid()) {
        // Guard request cancellation is receipt-driven: there is no safe generic abort because a
        // platform may already be committing the outer TUN/PF transaction. Wait for exact
        // Armed/Rejected, then release without ever starting the inner transport.
        m_phase = ConnectionPhase::Disconnecting;
        addTimeline(QStringLiteral("disconnect waiting for pending guard receipt"));
        return;
    }
    if (m_activeAdapter && m_activeToken.isValid()) {
        m_stoppingAdapter = m_activeAdapter;
        m_stoppingCandidate = m_activeCandidate;
        m_stoppingToken = m_activeToken;
        clearActive();
        m_phase = ConnectionPhase::Disconnecting;
        addTimeline(QStringLiteral("explicit disconnect stopping active session"));
        m_stoppingAdapter->stop(m_stoppingToken);
        return;
    }
    if (m_stoppingAdapter && m_stoppingToken.isValid()) {
        m_phase = ConnectionPhase::Disconnecting;
        addTimeline(QStringLiteral("explicit disconnect waiting for existing stop"));
        return;
    }
    finishDisconnected();
}

bool ConnectionReducer::retryVerification(QString &error)
{
    error.clear();
    if (!m_verifier || !m_activeAdapter || !m_activeToken.isValid()
        || (m_phase != ConnectionPhase::VerificationUnknown
            && m_phase != ConnectionPhase::TunnelReady
            && m_phase != ConnectionPhase::ConnectedHealthy)) {
        error = QStringLiteral("no live unverified session");
        return false;
    }
    if (m_activeVerification.isValid())
        m_verifier->cancel(m_activeVerification);
    const VerificationRetryDirective retryDirective = m_verificationRetryDirective;
    const int retryAfterSeconds = m_verificationRetryAfterSeconds;
    m_verificationRetryDirective = VerificationRetryDirective::None;
    m_verificationRetryAfterSeconds = 0;
    if (!beginVerification(error)) {
        m_phase = ConnectionPhase::VerificationUnknown;
        m_verificationRetryDirective = retryDirective == VerificationRetryDirective::None
            ? VerificationRetryDirective::RetrySameAuthority : retryDirective;
        m_verificationRetryAfterSeconds = retryAfterSeconds > 0 ? retryAfterSeconds : 5;
        if (error.isEmpty()) error = QStringLiteral("verifier dispatch unavailable");
        addTimeline(QStringLiteral("post-tunnel verification retry dispatch unavailable"));
        return false;
    }
    addTimeline(QStringLiteral("post-tunnel verification retry"));
    return true;
}

void ConnectionReducer::onTransportEvent(const TransportEvent &event)
{
    if (!event.operation.isValid())
        return;
    if (event.kind == TransportEventKind::Stopped
        && event.operation == m_stoppingToken) {
        handleStopped(event.operation);
        return;
    }
    // Every other callback must match both current operation and concrete session.
    if (!m_activeAdapter || event.operation != m_activeToken
        || event.operation.operation != m_operation)
        return;
    if (event.kind == TransportEventKind::AuthorityRenewed
        || event.kind == TransportEventKind::AuthorityRenewalRejected
        || event.kind == TransportEventKind::AuthorityRenewalTimedOut) {
        if (!m_pendingAuthorityRenewal.has_value()) return;
        const TransportAuthorityRenewalDispatch &pending =
            m_pendingAuthorityRenewal->dispatch;
        if (!pending.isValid() || event.renewalId != pending.renewalId
            || event.authorityCommitmentSha256
                   != pending.authorityCommitmentSha256)
            return;
        if (event.kind == TransportEventKind::AuthorityRenewed) {
            if (!event.appliedHardDeadlineUtc.isValid()
                || event.appliedHardDeadlineUtc.toUTC()
                       != pending.requestedHardDeadlineUtc.toUTC())
                return;
            AuthorityRenewalTarget applied = std::move(*m_pendingAuthorityRenewal);
            m_pendingAuthorityRenewal.reset();
            commitAuthorityRenewal(std::move(applied));
            return;
        }
        if (event.kind == TransportEventKind::AuthorityRenewalRejected) {
            clearAuthorityRenewalTransactions();
            stopActiveTerminal(
                ConnectionFailureStage::Policy,
                event.typedReason.isEmpty()
                    ? QStringLiteral("runtime_authority_renewal_rejected")
                    : event.typedReason);
            return;
        }

        // Timeout/dispatch loss is not proof of a hostile native state.  Keep the old authority
        // effective and perform the ordinary exact Stopped -> replacement sequence using the
        // newest accepted desired snapshot. A late receipt is fenced by the cleared renewal id.
        AuthorityRenewalTarget restart = m_queuedAuthorityRenewal.has_value()
            ? std::move(*m_queuedAuthorityRenewal)
            : std::move(*m_pendingAuthorityRenewal);
        clearAuthorityRenewalTransactions();
        addTimeline(QStringLiteral("authority receipt unavailable; serialized restart"));
        QString ignored;
        connectAcceptedCatalog(restart.catalog, std::move(restart.candidates),
                               restart.history, restart.request,
                               restart.authority, ignored);
        return;
    }
    if (event.kind == TransportEventKind::TunnelReady) {
        if (m_phase != ConnectionPhase::StartingTransport)
            return;
        m_phase = ConnectionPhase::TunnelReady;
        addTimeline(QStringLiteral("transport ready; verification required"));
        QString verifyError;
        if (!beginVerification(verifyError)) {
            // A missing verifier can never turn green. Keep the protected tunnel yellow and allow
            // a later retry instead of flapping every candidate for a global verifier outage.
            m_phase = ConnectionPhase::VerificationUnknown;
            m_lastFailureStage = ConnectionFailureStage::VerificationTraffic;
            m_lastTypedReason = QStringLiteral("verifier_dispatch_unavailable");
        }
        return;
    }
    if (event.kind == TransportEventKind::StartRejected) {
        markProfileAttemptFailed(m_activeCandidate, false);
        setFailure(ConnectionFailureStage::TransportStart,
                   event.typedReason.isEmpty() ? QStringLiteral("transport_start_rejected")
                                               : event.typedReason);
        clearActive();
        QString ignored;
        startNext(ignored);
        return;
    }
    if (event.kind == TransportEventKind::RuntimeError) {
        failActive(ConnectionFailureStage::TransportRuntime,
                   event.typedReason.isEmpty() ? QStringLiteral("transport_runtime")
                                               : event.typedReason);
        return;
    }
    // Defensive path for an adapter that reports terminal Stopped without RuntimeError first.
    if (event.kind == TransportEventKind::Stopped) {
        if (m_activeVerification.isValid() && m_verifier)
            m_verifier->cancel(m_activeVerification);
        markProfileAttemptFailed(m_activeCandidate, true);
        setFailure(ConnectionFailureStage::TransportRuntime,
                   QStringLiteral("unexpected_transport_stop"));
        clearActive();
        QString ignored;
        startNext(ignored);
    }
}

void ConnectionReducer::onPostTunnelVerificationStage(
    VerificationToken verification, PostTunnelVerificationStage stage)
{
    if (!m_activeAdapter || verification != m_activeVerification
        || verification.transportOperation != m_activeToken
        || verification.transportOperation.operation != m_operation)
        return;
    if (stage == PostTunnelVerificationStage::Dns) {
        // A duplicate DNS callback is harmless, but a regression from traffic to DNS is stale or
        // a verifier bug and must not rewind externally visible state.
        if (m_phase == ConnectionPhase::VerifyingDns)
            addTimeline(QStringLiteral("post-tunnel DNS verification"));
        return;
    }
    if (stage == PostTunnelVerificationStage::Traffic
        && m_phase == ConnectionPhase::VerifyingDns) {
        m_phase = ConnectionPhase::VerifyingTraffic;
        addTimeline(QStringLiteral("post-tunnel HTTPS/egress verification"));
    }
}

void ConnectionReducer::onPostTunnelVerification(
    const PostTunnelVerificationResult &result)
{
    if (!m_activeAdapter || result.verification != m_activeVerification
        || result.verification.transportOperation != m_activeToken
        || result.verification.transportOperation.operation != m_operation
        || (m_phase != ConnectionPhase::VerifyingDns
            && m_phase != ConnectionPhase::VerifyingTraffic))
        return;
    if (result.disposition == VerificationDisposition::Verified) {
        if (m_phase != ConnectionPhase::VerifyingTraffic) {
            // A verifier that skips its DNS→traffic stage contract is globally suspect. Retain
            // the guarded tunnel as unknown; do not poison an otherwise healthy candidate.
            m_phase = ConnectionPhase::VerificationUnknown;
            m_lastFailureStage = ConnectionFailureStage::VerificationTraffic;
            m_lastTypedReason = QStringLiteral("verifier_stage_protocol");
            addTimeline(QStringLiteral("verification stage contract rejected"));
            return;
        }
        if (!m_activeCandidate.verification.expectedEgressIds.contains(result.observedEgressId)) {
            failActive(ConnectionFailureStage::VerificationEgress,
                       QStringLiteral("unexpected_egress"));
            return;
        }
        const QDateTime verifiedNow = eventNowUtc();
        QDateTime proofDeadline = result.verifiedUntilUtc.toUTC();
        for (const QDateTime &authorityDeadline : {
                 m_activeCandidate.nativeProfile.expiresAt.toUTC(),
                 m_catalogFreshnessDeadline.toUTC(), m_entitlementExpiresAt.toUTC()}) {
            if (authorityDeadline.isValid()
                && (!proofDeadline.isValid() || authorityDeadline < proofDeadline))
                proofDeadline = authorityDeadline;
        }
        if (!verifiedNow.isValid() || !proofDeadline.isValid()
            || proofDeadline <= verifiedNow) {
            m_phase = ConnectionPhase::VerificationUnknown;
            m_lastFailureStage = ConnectionFailureStage::VerificationAuthority;
            m_lastTypedReason = QStringLiteral("receipt_freshness_invalid");
            addTimeline(QStringLiteral("verification receipt freshness rejected"));
            return;
        }
        if (!m_guardArmed || !m_guard
            || !m_guard->isArmedFor(m_activeToken, m_guardOuterSessionId)) {
            m_guardArmed = false;
            failActive(ConnectionFailureStage::Policy, QStringLiteral("guard_lost"));
            return;
        }
        m_phase = ConnectionPhase::ConnectedHealthy;
        m_verifiedAtUtc = verifiedNow;
        // Green can never outlive any credential/catalog/account authority even if a compromised
        // or misconfigured receipt provider signs a longer freshness interval.
        m_verifiedUntilUtc = proofDeadline;
        m_lastFailureStage = ConnectionFailureStage::None;
        m_lastTypedReason.clear();
        m_verificationRetryDirective = VerificationRetryDirective::None;
        m_verificationRetryAfterSeconds = 0;
        CandidateHistory &history = m_workingHistory[m_activeCandidate.profileId];
        if (!candidateHistoryMatches(m_activeCandidate, history))
            history = CandidateHistory{};
        history.configGeneration = m_activeCandidate.nativeProfile.configGeneration;
        history.bindingGeneration = m_activeCandidate.nativeProfile.bindingGeneration;
        history.cooldownUntil = {};
        history.lastVerifiedAtUtc = verifiedNow;
        history.verifiedSuccessEwma = history.verifiedSuccessEwma < 0.0
                                          ? 1.0
                                          : qBound(0.0, history.verifiedSuccessEwma * 0.8 + 0.2, 1.0);
        if (result.latencyMs >= 0) {
            history.verifiedStartLatencyMs = history.verifiedStartLatencyMs < 0.0
                                                 ? double(result.latencyMs)
                                                 : history.verifiedStartLatencyMs * 0.8
                                                       + double(result.latencyMs) * 0.2;
        }
        // The bounded attempt budget belongs to one acquisition episode, not the whole lifetime
        // of a healthy session. Once real traffic is independently verified, begin a fresh failure
        // generation so a runtime drop hours later can still use the full bounded fallback set;
        // generation-scoped cooldown history continues to prevent immediate thrash.
        m_attemptsUsed = 0;
        m_selectionRequest.failedProfileIds.clear();
        m_selectionRequest.failedFailureDomains.clear();
        addTimeline(QStringLiteral("post-tunnel receipt verified"));
        return;
    }
    if (result.disposition == VerificationDisposition::InfrastructureUnavailable) {
        m_phase = ConnectionPhase::VerificationUnknown;
        m_lastFailureStage = result.failureStage;
        m_lastTypedReason = result.typedReason.isEmpty()
                                ? QStringLiteral("verifier_infrastructure_unknown")
                                : result.typedReason;
        m_verificationRetryDirective = result.retryDirective
                == VerificationRetryDirective::None
            ? VerificationRetryDirective::RetrySameAuthority : result.retryDirective;
        m_verificationRetryAfterSeconds = qBound(
            1, result.retryAfterSeconds > 0 ? result.retryAfterSeconds : 5, 300);
        addTimeline(QStringLiteral("verification infrastructure unavailable; tunnel retained"));
        return;
    }
    if (result.disposition == VerificationDisposition::AuthorityRejected) {
        stopActiveTerminal(ConnectionFailureStage::VerificationAuthority,
                           result.typedReason.isEmpty()
                               ? QStringLiteral("receipt_authority_rejected")
                               : result.typedReason);
        return;
    }
    if (result.disposition == VerificationDisposition::CatalogStale) {
        stopActiveTerminal(ConnectionFailureStage::VerificationAuthority,
                           result.typedReason.isEmpty()
                               ? QStringLiteral("receipt_catalog_stale")
                               : result.typedReason,
                           ConnectionTerminalDisposition::CatalogStale);
        return;
    }
    if (result.disposition == VerificationDisposition::TrustRefreshRequired) {
        stopActiveTerminal(ConnectionFailureStage::VerificationTrust,
                           result.typedReason.isEmpty()
                               ? QStringLiteral("receipt_trust_refresh_required")
                               : result.typedReason);
        return;
    }
    const bool stageMatches = (m_phase == ConnectionPhase::VerifyingDns
                               && result.failureStage == ConnectionFailureStage::VerificationDns)
                              || (m_phase == ConnectionPhase::VerifyingTraffic
                                  && result.failureStage != ConnectionFailureStage::VerificationDns);
    if (!stageMatches) {
        m_phase = ConnectionPhase::VerificationUnknown;
        m_lastFailureStage = ConnectionFailureStage::VerificationTraffic;
        m_lastTypedReason = QStringLiteral("verifier_stage_protocol");
        addTimeline(QStringLiteral("verification failure stage contract rejected"));
        return;
    }
    failActive(result.failureStage, result.typedReason.isEmpty()
                                        ? QStringLiteral("post_tunnel_verification_failed")
                                        : result.typedReason);
}

void ConnectionReducer::onTransportTimeout(TransportOperationToken operation)
{
    if (operation == m_activeToken && operation.operation == m_operation
        && m_phase == ConnectionPhase::StartingTransport)
        failActive(ConnectionFailureStage::TransportTimeout,
                   QStringLiteral("transport_start_timeout"));
}

void ConnectionReducer::onGuardArmTimeout(
    TransportOperationToken operation, QByteArray nativeDispatchPolicySha256)
{
    if (operation != m_pendingToken || !m_pendingAdapter
        || nativeDispatchPolicySha256 != m_pendingPrepared.nativeDispatchPolicySha256)
        return;
    // A timeout cannot prove whether the platform committed the outer guard. Never start native,
    // release broadly, or attempt another policy. A late exact receipt remains ignored by the
    // failed operation and platform recovery must explicitly resolve ownership.
    const PreparedTransportStart timedOutPrepared = m_pendingPrepared;
    m_guardOwnershipAmbiguous = true;
    m_guardAmbiguityKind = GuardAmbiguityKind::Arm;
    m_quarantinedGuardToken = operation;
    m_quarantinedGuardPolicySha256 = nativeDispatchPolicySha256;
    m_quarantinedExpectedRuntimeSessionId =
        m_pendingPrepared.expectedRuntimeSessionId;
    m_quarantinedGuardOuterSessionId.clear();
    m_pendingAdapter = nullptr;
    m_pendingCandidate = {};
    m_pendingPrepared = {};
    m_pendingToken = {};
    setFailure(ConnectionFailureStage::Policy, QStringLiteral("guard_arm_timeout"));
    addTimeline(QStringLiteral("session guard arm timed out; ownership ambiguous"));
    QString ignored;
    if (m_guard)
        m_guard->reconcileTimedOutArmExact(timedOutPrepared, operation, ignored);
}

void ConnectionReducer::onGuardReleaseTimeout(TransportOperationToken operation)
{
    if (operation != m_releasingGuardToken)
        return;
    m_guardOwnershipAmbiguous = true;
    m_guardAmbiguityKind = GuardAmbiguityKind::Release;
    m_quarantinedGuardToken = operation;
    m_quarantinedGuardPolicySha256 = m_guardPolicySha256;
    m_quarantinedExpectedRuntimeSessionId = m_guardExpectedRuntimeSessionId;
    m_quarantinedGuardOuterSessionId = m_guardOuterSessionId;
    m_guardArmed = m_guard && m_guard->isArmedFor(operation, m_guardOuterSessionId);
    setFailure(ConnectionFailureStage::Policy, QStringLiteral("guard_release_timeout"));
    addTimeline(QStringLiteral("session guard release timed out; remains fail closed"));
    QString ignored;
    if (m_guard)
        m_guard->reconcileTimedOutReleaseExact(operation, m_guardOuterSessionId, ignored);
}

void ConnectionReducer::onStopTimeout(TransportOperationToken operation)
{
    if (operation != m_stoppingToken)
        return;
    // Fail closed: the old native core may still own routes/sockets, so never start a replacement
    // and never release the session guard merely because a timer elapsed.
    setFailure(ConnectionFailureStage::TransportStopTimeout,
               QStringLiteral("transport_stop_timeout"));
    addTimeline(QStringLiteral("transport stop timed out; replacement blocked"));
}

void ConnectionReducer::onVerificationTimeout(VerificationToken verification)
{
    if (verification == m_activeVerification
        && verification.transportOperation == m_activeToken
        && verification.transportOperation.operation == m_operation
        && (m_phase == ConnectionPhase::VerifyingDns
            || m_phase == ConnectionPhase::VerifyingTraffic)) {
        const bool dns = m_phase == ConnectionPhase::VerifyingDns;
        failActive(dns ? ConnectionFailureStage::VerificationDns
                       : ConnectionFailureStage::VerificationTimeout,
                   dns ? QStringLiteral("post_tunnel_dns_timeout")
                       : QStringLiteral("post_tunnel_verification_timeout"));
    }
}

void ConnectionReducer::onGuardRecoveryReleased(const ConnectionGuardEvent &identity)
{
    if (!m_guardOwnershipAmbiguous || !identity.operation.isValid()
        || identity.operation != m_quarantinedGuardToken
        || identity.nativeDispatchPolicySha256 != m_quarantinedGuardPolicySha256
        || identity.expectedRuntimeSessionId != m_quarantinedExpectedRuntimeSessionId
        || identity.outerSessionId != m_quarantinedGuardOuterSessionId
        || !m_guard || !m_guard->completeRecoveryReleasedExact(identity))
        return;
    m_guardOwnershipAmbiguous = false;
    m_guardAmbiguityKind = GuardAmbiguityKind::None;
    m_quarantinedGuardToken = {};
    m_quarantinedGuardPolicySha256.clear();
    m_quarantinedExpectedRuntimeSessionId.clear();
    m_quarantinedGuardOuterSessionId.clear();
    if (m_guardToken == identity.operation) {
        m_guardToken = {};
        m_guardOuterSessionId.clear();
        m_guardPolicySha256.clear();
        m_guardExpectedRuntimeSessionId.clear();
    }
    if (m_releasingGuardToken == identity.operation)
        m_releasingGuardToken = {};
    m_guardArmed = false;
    if (m_disconnectRequested && !m_activeToken.isValid() && !m_stoppingToken.isValid()
        && !m_pendingToken.isValid()) {
        m_disconnectRequested = false;
        m_terminalStopRequested = false;
        m_phase = ConnectionPhase::Idle;
        addTimeline(QStringLiteral("exact recovery released quarantined session guard"));
    } else {
        notifyObserver();
    }
}

void ConnectionReducer::onAuthorityDeadline(TransportOperationToken operation)
{
    if (!operation.isValid() || operation != m_activeToken
        || operation.operation != m_operation || !m_activeAdapter)
        return;
    const QDateTime now = eventNowUtc();
    const QDateTime nativeDeadline = m_activeCandidate.nativeProfile.expiresAt.toUTC();
    if (now.isValid() && nativeDeadline.isValid() && m_catalogFreshnessDeadline.isValid()
        && m_entitlementExpiresAt.isValid() && now < nativeDeadline
        && now < m_catalogFreshnessDeadline && now < m_entitlementExpiresAt)
        return; // stale/early timer after an in-place authority renewal
    stopActiveTerminal(ConnectionFailureStage::Policy,
                       QStringLiteral("runtime_authority_expired"));
}

void ConnectionReducer::onVerificationFreshnessDeadline(VerificationToken verification)
{
    if (!verification.isValid() || verification != m_activeVerification
        || verification.transportOperation != m_activeToken
        || m_phase != ConnectionPhase::ConnectedHealthy)
        return;
    // The coordinator schedules this before expiry. Keeping the previous verifiedUntil while the
    // same-session retry is in flight preserves continuous coverage and the original 5m survival
    // fence; the presentation remains green only until that immutable old deadline.
    QString error;
    if (!retryVerification(error)) {
        m_phase = ConnectionPhase::VerificationUnknown;
        m_lastFailureStage = ConnectionFailureStage::VerificationTraffic;
        m_lastTypedReason = QStringLiteral("receipt_reverification_unavailable");
        addTimeline(QStringLiteral("receipt freshness elapsed; re-verification unavailable"));
    }
}

void ConnectionReducer::failActive(ConnectionFailureStage stage, const QString &typedReason)
{
    setFailure(stage, typedReason);
    if (!m_activeAdapter || !m_activeToken.isValid()) {
        QString ignored;
        startNext(ignored);
        return;
    }
    if (m_verifier && m_activeVerification.isValid())
        m_verifier->cancel(m_activeVerification);
    markProfileAttemptFailed(m_activeCandidate, true);
    m_failClosedBarrierUntilInnerStart = true;
    m_stoppingAdapter = m_activeAdapter;
    m_stoppingCandidate = m_activeCandidate;
    m_stoppingToken = m_activeToken;
    clearActive();
    m_phase = ConnectionPhase::StoppingOld;
    addTimeline(QStringLiteral("failed session stopping before fallback"));
    m_stoppingAdapter->stop(m_stoppingToken);
}

void ConnectionReducer::stopActiveTerminal(
    ConnectionFailureStage stage, const QString &typedReason,
    ConnectionTerminalDisposition disposition)
{
    m_terminalDisposition = disposition;
    setFailure(stage, typedReason);
    m_terminalStopRequested = true;
    m_candidates.clear();
    if (m_verifier && m_activeVerification.isValid())
        m_verifier->cancel(m_activeVerification);
    if (!m_activeAdapter || !m_activeToken.isValid()) {
        QString ignored;
        m_phaseAfterGuardRelease = ConnectionPhase::Failed;
        releaseGuardWithoutNativeOwner(ignored);
        m_terminalStopRequested = false;
        return;
    }
    m_stoppingAdapter = m_activeAdapter;
    m_stoppingCandidate = m_activeCandidate;
    m_stoppingToken = m_activeToken;
    clearActive();
    m_phase = ConnectionPhase::StoppingOld;
    addTimeline(QStringLiteral("terminal verification authority failure stopping session"));
    m_stoppingAdapter->stop(m_stoppingToken);
}

void ConnectionReducer::handleStopped(TransportOperationToken operation)
{
    if (operation != m_stoppingToken)
        return;
    const bool guardStillOwnsStoppedPolicy = m_guardArmed
                                             && m_guardToken == operation && m_guard
                                             && m_guard->isArmedFor(operation,
                                                                    m_guardOuterSessionId);
    m_stoppingAdapter = nullptr;
    m_stoppingCandidate = CatalogCandidate{};
    m_stoppingToken = {};
    addTimeline(QStringLiteral("old session stopped"));
    if (!guardStillOwnsStoppedPolicy) {
        // Losing the outer blocking owner is a security boundary, not a normal candidate failure.
        // Do not silently recreate it and continue because traffic may already have escaped during
        // the gap. Require a fresh user/coordinator operation after platform recovery.
        m_guardArmed = false;
        m_guardToken = {};
        m_disconnectRequested = false;
        m_terminalStopRequested = false;
        setFailure(ConnectionFailureStage::Policy, QStringLiteral("guard_lost"));
        addTimeline(QStringLiteral("session guard ownership lost; fallback blocked"));
        return;
    }
    if (m_disconnectRequested) {
        finishDisconnected();
        return;
    }
    if (m_terminalStopRequested) {
        QString releaseError;
        m_phaseAfterGuardRelease = ConnectionPhase::Failed;
        if (!releaseGuardWithoutNativeOwner(releaseError)) {
            setFailure(ConnectionFailureStage::Policy,
                       QStringLiteral("guard_release_failed"));
            addTimeline(QStringLiteral("terminal stop guard release failed"));
            return;
        }
        return;
    }
    QString ignored;
    startNext(ignored);
}

void ConnectionReducer::finishDisconnected()
{
    clearActive();
    m_stoppingAdapter = nullptr;
    m_stoppingCandidate = CatalogCandidate{};
    m_stoppingToken = {};
    QString releaseError;
    m_phaseAfterGuardRelease = ConnectionPhase::Idle;
    if (!releaseGuardWithoutNativeOwner(releaseError)) {
        setFailure(ConnectionFailureStage::Policy,
                   QStringLiteral("guard_release_failed"));
        addTimeline(QStringLiteral("disconnect guard release failed"));
        return;
    }
}

void ConnectionReducer::setFailure(ConnectionFailureStage stage, const QString &typedReason)
{
    m_lastFailureStage = stage;
    m_lastTypedReason = typedReason;
    m_phase = ConnectionPhase::Failed;
    notifyObserver();
}

void ConnectionReducer::addTimeline(const QString &entry)
{
    m_timeline.append(entry.left(160));
    while (m_timeline.size() > 64)
        m_timeline.removeFirst();
    notifyObserver();
}

void ConnectionReducer::notifyObserver()
{
    if (m_observer)
        m_observer->onConnectionReducerSnapshot(snapshot());
}

void ConnectionReducer::clearActive()
{
    clearAuthorityRenewalTransactions();
    m_activeAdapter = nullptr;
    m_activeCandidate = CatalogCandidate{};
    m_activeToken = {};
    m_activeVerification = {};
    m_verifiedAtUtc = {};
    m_verifiedUntilUtc = {};
    m_verificationRetryDirective = VerificationRetryDirective::None;
    m_verificationRetryAfterSeconds = 0;
}

bool ConnectionReducer::releaseGuardWithoutNativeOwner(QString &error)
{
    error.clear();
    if (m_guardOwnershipAmbiguous) {
        error = QStringLiteral("session guard ownership is quarantined");
        return false;
    }
    if (!m_guardArmed && !m_guardToken.isValid()) {
        finishAfterGuardReleased();
        return true;
    }
    if (!m_guard || m_activeAdapter || m_activeToken.isValid()
        || m_stoppingAdapter || m_stoppingToken.isValid()
        || m_pendingAdapter || m_pendingToken.isValid()) {
        error = QStringLiteral("session guard cannot release while native ownership is possible");
        return false;
    }
    const TransportOperationToken token = m_guardToken;
    if (!token.isValid() || !m_guard->isArmedFor(token, m_guardOuterSessionId)) {
        m_guardArmed = false;
        m_guardToken = {};
        error = QStringLiteral("session guard ownership is ambiguous");
        return false;
    }
    m_releasingGuardToken = token;
    m_phase = ConnectionPhase::ReleasingGuard;
    addTimeline(QStringLiteral("awaiting exact session guard release receipt"));
    if (m_guardOuterSessionId.isEmpty()
        || !m_guard->releaseExact(token, m_guardOuterSessionId, error)) {
        m_releasingGuardToken = {};
        m_guardArmed = m_guard->isArmedFor(token, m_guardOuterSessionId);
        if (error.isEmpty()) error = QStringLiteral("session guard exact release failed");
        return false;
    }
    // Completion is asynchronous. A synchronous test double may already have delivered Released.
    return true;
}

void ConnectionReducer::finishAfterGuardReleased()
{
    const ConnectionPhase target = m_phaseAfterGuardRelease;
    m_phaseAfterGuardRelease = ConnectionPhase::Failed;
    m_failClosedBarrierUntilInnerStart = false;
    if (target == ConnectionPhase::Idle) {
        m_disconnectRequested = false;
        m_terminalStopRequested = false;
        m_phase = ConnectionPhase::Idle;
        addTimeline(QStringLiteral("session disconnected; guard released"));
        return;
    }
    m_terminalStopRequested = false;
    m_phase = ConnectionPhase::Failed;
    if (m_lastFailureStage == ConnectionFailureStage::None)
        m_lastFailureStage = ConnectionFailureStage::Policy;
    if (m_lastTypedReason.isEmpty())
        m_lastTypedReason = QStringLiteral("attempts_exhausted");
    addTimeline(QStringLiteral("terminal state reached; guard released"));
}

QDateTime ConnectionReducer::eventNowUtc() const
{
    const QDateTime value = m_clock ? m_clock->nowUtc() : QDateTime::currentDateTimeUtc();
    return value.isValid() ? value.toUTC() : QDateTime();
}

ConnectionRuntimeSnapshot ConnectionReducer::snapshot() const
{
    ConnectionRuntimeSnapshot out;
    out.phase = m_phase;
    out.operation = m_operation;
    out.session = m_activeToken.isValid() ? m_activeToken
                  : m_stoppingToken.isValid() ? m_stoppingToken
                  : m_pendingToken.isValid() ? m_pendingToken
                                             : m_releasingGuardToken;
    out.verification = m_activeVerification;
    if (m_pendingToken.isValid() && m_pendingAdapter
        && m_pendingPrepared.nativeDispatchPolicySha256.size() == 32) {
        out.lifecycleWait = {ConnectionLifecycleWaitKind::GuardArm, m_pendingToken, {},
                             m_pendingPrepared.nativeDispatchPolicySha256};
    } else if (m_releasingGuardToken.isValid() && m_guardPolicySha256.size() == 32) {
        out.lifecycleWait = {ConnectionLifecycleWaitKind::GuardRelease,
                             m_releasingGuardToken, {}, m_guardPolicySha256};
    } else if (m_stoppingToken.isValid() && m_stoppingAdapter) {
        out.lifecycleWait = {ConnectionLifecycleWaitKind::TransportStop,
                             m_stoppingToken, {}, {}};
    } else if (m_phase == ConnectionPhase::StartingTransport
               && m_activeToken.isValid() && m_activeAdapter) {
        out.lifecycleWait = {ConnectionLifecycleWaitKind::TransportStart,
                             m_activeToken, {}, {}};
    } else if ((m_phase == ConnectionPhase::VerifyingDns
                || m_phase == ConnectionPhase::VerifyingTraffic)
               && m_activeVerification.isValid()) {
        out.lifecycleWait = {ConnectionLifecycleWaitKind::Verification,
                             m_activeVerification.transportOperation,
                             m_activeVerification, {}};
    }
    const CatalogCandidate candidate = m_activeToken.isValid() ? m_activeCandidate
                                        : m_stoppingToken.isValid() ? m_stoppingCandidate
                                        : m_pendingToken.isValid() ? m_pendingCandidate
                                        : m_phase == ConnectionPhase::Failed
                                              ? m_lastAttemptedCandidate
                                              : CatalogCandidate{};
    out.profileId = candidate.profileId;
    out.locationId = candidate.locationId;
    out.transport = candidate.transport;
    out.configGeneration = candidate.nativeProfile.configGeneration;
    out.bindingGeneration = candidate.nativeProfile.bindingGeneration;
    out.nativeProfileExpiresAt = candidate.nativeProfile.expiresAt.toUTC();
    out.catalogFreshnessDeadline = m_catalogFreshnessDeadline;
    out.entitlementDeadline = m_entitlementExpiresAt;
    out.verifiedAtUtc = m_verifiedAtUtc;
    out.verifiedUntilUtc = m_verifiedUntilUtc;
    out.attemptsUsed = m_attemptsUsed;
    out.verificationRetryDirective = m_verificationRetryDirective;
    out.verificationRetryAfterSeconds = m_verificationRetryAfterSeconds;
    out.guardArmed = m_guardArmed && m_guard && m_guardToken.isValid()
                     && m_guard->isArmedFor(m_guardToken, m_guardOuterSessionId);
    out.guardOwnershipAmbiguous = m_guardOwnershipAmbiguous;
    out.hasAcceptedV2 = m_hasAcceptedV2;
    out.lastFailureStage = m_lastFailureStage;
    out.terminalDisposition = m_terminalDisposition;
    out.lastTypedReason = m_lastTypedReason;
    out.timeline = m_timeline;
    return out;
}

} // namespace avpn
