#include "VpnConnectionTransportAdapter.h"

#include "BypassListService.h"
#include "TuningStore.h"

#include "vpnConnection.h"
#include "core/repositories/secureAppSettingsRepository.h"

#include <QJsonArray>
#include <QCryptographicHash>
#include <QHostAddress>
#include <QMetaObject>
#include <QPointer>
#include <QJsonDocument>
#include <QSet>
#include <QSettings>
#include <QThread>
#include <QTimer>
#include <QUuid>

#include <algorithm>
#include <utility>

namespace avpn {
namespace {

bool canonicalRuntimeUuid(const QString &value)
{
    const QUuid uuid(value);
    return !uuid.isNull() && uuid.toString(QUuid::WithoutBraces).toLower() == value;
}

bool safeGuardOpaque(const QString &value, bool mayBeEmpty = false)
{
    if (value.isEmpty()) return mayBeEmpty;
    if (value.size() > 200) return false;
    for (const QChar ch : value) {
        const ushort code = ch.unicode();
        const bool asciiAlphaNumeric = (code >= 'A' && code <= 'Z')
            || (code >= 'a' && code <= 'z') || (code >= '0' && code <= '9');
        if (!asciiAlphaNumeric && ch != QLatin1Char('-') && ch != QLatin1Char('_')
            && ch != QLatin1Char(':') && ch != QLatin1Char('.')) return false;
    }
    return true;
}

bool canonicalDecimal(const QString &value, bool allowZero = false)
{
    if (value.isEmpty() || value.size() > 20
        || (value.size() > 1 && value.startsWith(QLatin1Char('0')))
        || (!allowZero && value == QLatin1String("0"))) return false;
    for (const QChar ch : value)
        if (ch < QLatin1Char('0') || ch > QLatin1Char('9')) return false;
    bool ok = false;
    const quint64 parsed = value.toULongLong(&ok, 10);
    return ok && QString::number(parsed) == value;
}

bool lowerSha256Text(const QString &value)
{
    if (value.size() != 64) return false;
    for (const QChar ch : value)
        if (!((ch >= QLatin1Char('0') && ch <= QLatin1Char('9'))
              || (ch >= QLatin1Char('a') && ch <= QLatin1Char('f')))) return false;
    return true;
}

bool safeAsciiReason(const QString &value)
{
    if (value.size() > 96) return false;
    for (const QChar ch : value)
        if (ch.unicode() < 0x20 || ch.unicode() > 0x7e) return false;
    return true;
}

QDateTime authorityHardDeadline(const NativeRuntimeAuthority &authority)
{
    return std::min({authority.nativeProfileExpiresAt.toUTC(),
                     authority.catalogFreshnessDeadline.toUTC(),
                     authority.entitlementDeadline.toUTC()});
}

QJsonObject withoutRuntimeAuthority(QJsonObject configuration)
{
    configuration.remove(QStringLiteral("runtime_authority_v1"));
    return configuration;
}

} // namespace

VpnConnectionSessionGuard::VpnConnectionSessionGuard(VpnConnection *connection,
                                                       QObject *parent)
    : QObject(parent), m_connection(connection)
{
    if (connection) {
        connect(connection, &VpnConnection::nativeSessionGuardEvent, this,
                [this](const QJsonObject &event) { consumeNativeEvent(event); },
                Qt::QueuedConnection);
    }
}

bool VpnConnectionSessionGuard::prepareAndArm(const PreparedTransportStart &prepared,
                                               TransportOperationToken operation,
                                               QString &error)
{
    error.clear();
    if (!m_connection || !operation.isValid() || m_pendingArm.isValid()
        || m_pendingRelease.isValid() || prepared.finalConfiguration.isEmpty()
        || m_recoveryIdentity.operation.isValid()
        || prepared.nativeDispatchPolicySha256.size() != 32
        || !canonicalRuntimeUuid(prepared.expectedRuntimeSessionId)
        || !prepared.outerSessionId.isEmpty()) {
        error = QStringLiteral("native session guard PREPARE identity invalid or busy");
        return false;
    }
    m_pendingArm = operation;
    m_pendingPolicySha256 = prepared.nativeDispatchPolicySha256;
    m_pendingExpectedRuntimeSessionId = prepared.expectedRuntimeSessionId;
    const bool accepted = m_connection->requestNativeSessionGuardArm(
        prepared.finalConfiguration, QString::number(operation.operation),
        QString::number(operation.session),
        QString::fromLatin1(prepared.nativeDispatchPolicySha256.toHex()),
        prepared.expectedRuntimeSessionId);
    if (!accepted) {
        m_pendingArm = {};
        m_pendingPolicySha256.clear();
        m_pendingExpectedRuntimeSessionId.clear();
        error = QStringLiteral("native session guard PREPARE dispatch rejected");
    }
    return accepted;
}

bool VpnConnectionSessionGuard::releaseExact(TransportOperationToken operation,
                                              const QString &outerSessionId,
                                              QString &error)
{
    error.clear();
    if (!m_connection || !operation.isValid() || m_pendingArm.isValid()
        || m_pendingRelease.isValid() || operation != m_armedToken
        || outerSessionId != m_armedOuterSessionId
        || !safeGuardOpaque(outerSessionId)) {
        error = QStringLiteral("native session guard RELEASE identity invalid or busy");
        return false;
    }
    m_pendingRelease = operation;
    const bool accepted = m_connection->requestNativeSessionGuardRelease(
        QString::number(operation.operation), QString::number(operation.session),
        outerSessionId);
    if (!accepted) {
        m_pendingRelease = {};
        error = QStringLiteral("native session guard RELEASE dispatch rejected");
    }
    return accepted;
}

bool VpnConnectionSessionGuard::isArmedFor(TransportOperationToken operation,
                                            const QString &outerSessionId) const
{
    return operation.isValid() && operation == m_armedToken
           && !m_armedOuterSessionId.isEmpty()
           && (outerSessionId.isEmpty() || outerSessionId == m_armedOuterSessionId);
}

bool VpnConnectionSessionGuard::reconcileTimedOutArmExact(
    const PreparedTransportStart &prepared, TransportOperationToken operation,
    QString &error)
{
    error.clear();
    if (!m_connection || operation != m_pendingArm
        || prepared.nativeDispatchPolicySha256 != m_pendingPolicySha256
        || prepared.expectedRuntimeSessionId != m_pendingExpectedRuntimeSessionId
        || m_pendingRelease.isValid() || m_recoveryIdentity.operation.isValid()) {
        error = QStringLiteral("timed-out guard PREPARE identity mismatch");
        return false;
    }
    const bool accepted = m_connection->requestNativeSessionGuardReconcileArm(
        QString::number(operation.operation), QString::number(operation.session),
        QString::fromLatin1(m_pendingPolicySha256.toHex()),
        m_pendingExpectedRuntimeSessionId);
    if (!accepted)
        error = QStringLiteral("timed-out guard PREPARE reconciliation rejected");
    return accepted;
}

bool VpnConnectionSessionGuard::reconcileTimedOutReleaseExact(
    TransportOperationToken operation, const QString &outerSessionId, QString &error)
{
    error.clear();
    if (!m_connection || operation != m_pendingRelease || operation != m_armedToken
        || outerSessionId != m_armedOuterSessionId || !safeGuardOpaque(outerSessionId)
        || m_recoveryIdentity.operation.isValid()) {
        error = QStringLiteral("timed-out guard RELEASE identity mismatch");
        return false;
    }
    const bool accepted = m_connection->requestNativeSessionGuardReconcileRelease(
        QString::number(operation.operation), QString::number(operation.session),
        QString::fromLatin1(m_armedPolicySha256.toHex()), outerSessionId,
        m_armedExpectedRuntimeSessionId);
    if (!accepted)
        error = QStringLiteral("timed-out guard RELEASE reconciliation rejected");
    return accepted;
}

bool VpnConnectionSessionGuard::completeRecoveryReleasedExact(
    const ConnectionGuardEvent &identity)
{
    if (!identity.operation.isValid())
        return false;
    const auto exact = [&identity](TransportOperationToken token, const QByteArray &policy,
                                   const QString &outer, const QString &expected) {
        return identity.operation == token
            && identity.nativeDispatchPolicySha256 == policy
            && identity.outerSessionId == outer
            && identity.expectedRuntimeSessionId == expected;
    };
    if (!exact(m_recoveryIdentity.operation,
               m_recoveryIdentity.nativeDispatchPolicySha256,
               m_recoveryIdentity.outerSessionId,
               m_recoveryIdentity.expectedRuntimeSessionId))
        return false;
    m_recoveryIdentity = {};
    if (identity.operation == m_pendingArm) {
        m_pendingArm = {};
        m_pendingPolicySha256.clear();
        m_pendingExpectedRuntimeSessionId.clear();
    }
    if (identity.operation == m_armedToken) {
        m_armedToken = {};
        m_armedPolicySha256.clear();
        m_armedOuterSessionId.clear();
        m_armedExpectedRuntimeSessionId.clear();
    }
    if (identity.operation == m_pendingRelease)
        m_pendingRelease = {};
    return true;
}

void VpnConnectionSessionGuard::consumeNativeEvent(const QJsonObject &event)
{
    ConnectionGuardEvent parsed;
    QString parseError;
    if (!parseNativeSessionGuardEvent(event, parsed, parseError)) return;
    const TransportOperationToken token = parsed.operation;
    const ConnectionGuardEventKind eventKind = parsed.kind;
    const QByteArray policy = parsed.nativeDispatchPolicySha256;
    const QString outer = parsed.outerSessionId;
    const QString expected = parsed.expectedRuntimeSessionId;
    const QString reason = parsed.typedReason;

    if (eventKind == ConnectionGuardEventKind::Armed
        || eventKind == ConnectionGuardEventKind::ArmRejected) {
        if (token != m_pendingArm || policy != m_pendingPolicySha256
            || expected != m_pendingExpectedRuntimeSessionId
            || (eventKind == ConnectionGuardEventKind::Armed && !safeGuardOpaque(outer))
            || (eventKind == ConnectionGuardEventKind::ArmRejected
                && !safeGuardOpaque(outer, true)))
            return;
        m_pendingArm = {};
        m_pendingPolicySha256.clear();
        m_pendingExpectedRuntimeSessionId.clear();
        if (eventKind == ConnectionGuardEventKind::Armed) {
            m_armedToken = token;
            m_armedPolicySha256 = policy;
            m_armedOuterSessionId = outer;
            m_armedExpectedRuntimeSessionId = expected;
        }
    } else if (eventKind == ConnectionGuardEventKind::Released
               || eventKind == ConnectionGuardEventKind::ReleaseRejected) {
        if (token != m_pendingRelease || token != m_armedToken
            || policy != m_armedPolicySha256 || outer != m_armedOuterSessionId
            || expected != m_armedExpectedRuntimeSessionId)
            return;
        m_pendingRelease = {};
        if (eventKind == ConnectionGuardEventKind::Released) {
            m_armedToken = {};
            m_armedPolicySha256.clear();
            m_armedOuterSessionId.clear();
            m_armedExpectedRuntimeSessionId.clear();
        }
    } else { // Lost
        const bool activeLoss = token == m_armedToken && policy == m_armedPolicySha256
                                && outer == m_armedOuterSessionId
                                && expected == m_armedExpectedRuntimeSessionId;
        const bool pendingLoss = token == m_pendingArm && policy == m_pendingPolicySha256
                                 && expected == m_pendingExpectedRuntimeSessionId
                                 && safeGuardOpaque(outer, true);
        if (!activeLoss && !pendingLoss) return;
        m_recoveryIdentity = parsed;
        m_pendingArm = {};
        m_pendingPolicySha256.clear();
        m_pendingExpectedRuntimeSessionId.clear();
        m_pendingRelease = {};
        m_armedToken = {};
        m_armedPolicySha256.clear();
        m_armedOuterSessionId.clear();
        m_armedExpectedRuntimeSessionId.clear();
    }
    if (m_observer)
        m_observer->onConnectionSessionGuardEvent(parsed);
}

VpnConnectionTransportAdapter::VpnConnectionTransportAdapter(
    VpnConnection *connection, TransportKind transport, NativeProfileCompileOptions options,
    SecureAppSettingsRepository *settings, QObject *parent, IConnectionClock *clock)
    : QObject(parent), m_connection(connection), m_transport(transport),
      m_options(std::move(options)), m_settings(settings), m_clock(clock)
{
    if (connection) {
        connect(connection, &VpnConnection::nativeRuntimeAuthorityRenewalReceipt, this,
                &VpnConnectionTransportAdapter::onNativeRuntimeAuthorityRenewalReceipt,
                Qt::QueuedConnection);
    }
}

amnezia::DockerContainer VpnConnectionTransportAdapter::nativeContainer() const
{
    return nativeContainerForTransport(m_transport);
}

QSet<QString> VpnConnectionTransportAdapter::supportedProfileKinds() const
{
    if (m_transport == TransportKind::Awg)
        return {QStringLiteral("awg31")};
    if (m_transport == TransportKind::Xray)
        return {QStringLiteral("xray_vless_reality_vision_tcp")};
    return {};
}

bool VpnConnectionTransportAdapter::validateAndCompile(const CatalogCandidate &candidate,
                                                        CompiledNativeProfile &compiled,
                                                        QString &error) const
{
    if (candidate.transport != m_transport) {
        compiled = CompiledNativeProfile{};
        error = QStringLiteral("candidate sent to wrong transport adapter");
        return false;
    }
    return NativeProfileCompiler::compile(candidate, m_options, compiled, error);
}

bool VpnConnectionTransportAdapter::prepareStart(const CompiledNativeProfile &compiled,
                                                 TransportOperationToken operation,
                                                 PreparedTransportStart &prepared,
                                                 QString &error)
{
    prepared = {};
    error.clear();
    const QDateTime now = m_clock ? m_clock->nowUtc().toUTC()
                                  : QDateTime::currentDateTimeUtc();
    if (!operation.isValid() || m_phase != Phase::Idle
        || QThread::currentThread() != thread() || !m_settings
        || m_settings->thread() != QThread::currentThread()
        || compiled.transport != m_transport || compiled.container != nativeContainer()
        || !hasExpectedNativeEnvelope(compiled, m_transport)
        || !now.isValid() || compiled.expiresAt.toUTC() <= now) {
        error = QStringLiteral("native start policy cannot be prepared on this owner");
        return false;
    }
    CompiledNativeProfile dispatchProfile = compiled;
    dispatchProfile.runtimeAuthority.trustedUtcAtDispatch = now;
    const NativeConnectionPolicySnapshot policy = snapshotConnectionPolicy(dispatchProfile);
    PreparedNativeConnectionPolicy nativePolicy;
    if (!NativeConnectionPolicyCompiler::compile(
            dispatchProfile, policy, nativePolicy, error)
        || !NativeConnectionPolicyCompiler::sanitizeForDispatch(
            dispatchProfile, policy, nativePolicy.configuration, error)) {
        if (error.isEmpty()) error = QStringLiteral("native connection policy rejected");
        return false;
    }
    const QString digestText = nativePolicy.configuration
                                   .value(QStringLiteral("runtime_authority_v1"))
                                   .toObject().value(QStringLiteral("policy_sha256")).toString();
    const QByteArray digest = QByteArray::fromHex(digestText.toLatin1());
    if (digest.size() != 32 || QString::fromLatin1(digest.toHex()) != digestText) {
        error = QStringLiteral("native dispatch policy digest missing/noncanonical");
        return false;
    }
    prepared.compiled = std::move(dispatchProfile);
    prepared.finalConfiguration = std::move(nativePolicy.configuration);
    prepared.nativeDispatchPolicySha256 = digest;
    return true;
}

bool VpnConnectionTransportAdapter::setProtectedTunnelIpLiterals(
    const QStringList &literals, QString &error)
{
    error.clear();
    if (QThread::currentThread() != thread() || m_phase != Phase::Idle
        || literals.isEmpty() || literals.size() > 64) {
        error = QStringLiteral("protected route snapshot unavailable/busy");
        return false;
    }
    QSet<QString> unique;
    for (const QString &literal : literals) {
        QHostAddress address;
        if (!address.setAddress(literal) || address.toString() != literal
            || !address.isGlobal() || unique.contains(literal)) {
            error = QStringLiteral("protected route snapshot contains invalid IP");
            return false;
        }
        unique.insert(literal);
    }
    m_options.protectedTunnelIpLiterals = literals;
    return true;
}

bool VpnConnectionTransportAdapter::start(const PreparedTransportStart &prepared,
                                           TransportOperationToken operation,
                                           QString &error)
{
    error.clear();
    const CompiledNativeProfile &compiled = prepared.compiled;
    if (!m_connection || !operation.isValid()) {
        error = QStringLiteral("native connection or operation token unavailable");
        return false;
    }
    if (m_phase != Phase::Idle) {
        error = QStringLiteral("transport adapter is not stopped");
        return false;
    }
    if (compiled.transport != m_transport || compiled.container != nativeContainer()
        || compiled.profileId.isEmpty() || !compiled.expiresAt.isValid()
        || compiled.expiresAt.toUTC()
               <= (m_clock ? m_clock->nowUtc().toUTC() : QDateTime::currentDateTimeUtc())
        || !hasExpectedNativeEnvelope(compiled, m_transport)
        || prepared.nativeDispatchPolicySha256.size() != 32
        || prepared.outerSessionId.isEmpty() || prepared.outerSessionId.size() > 256
        || QUuid(prepared.expectedRuntimeSessionId).isNull()
        || QUuid(prepared.expectedRuntimeSessionId)
                .toString(QUuid::WithoutBraces).toLower()
               != prepared.expectedRuntimeSessionId
        || prepared.finalConfiguration.value(QStringLiteral("native_envelope_schema"))
               != QLatin1String("tribe_catalog_v2_native_v1")
        || prepared.finalConfiguration.value(QStringLiteral("runtime_authority_v1"))
               .toObject().value(QStringLiteral("policy_sha256")).toString()
               != QString::fromLatin1(prepared.nativeDispatchPolicySha256.toHex())) {
        error = QStringLiteral("compiled transport envelope mismatch at start");
        return false;
    }

    m_activeToken = operation;
    m_activeProfile = compiled;
    m_activeFinalConfiguration = prepared.finalConfiguration;
    m_activeDispatchPolicySha256 = prepared.nativeDispatchPolicySha256;
    m_pendingAuthorityRenewal = {};
    m_phase = Phase::Starting;
    m_lastError.clear();
    m_nativeDispatchReady = false;
    m_runtimeIdentity.clear();
    m_activeOuterSessionId = prepared.outerSessionId;
    m_expectedRuntimeSessionId = prepared.expectedRuntimeSessionId;

    // AVPN: the existing VpnConnection owns platform dispatch and adds the same app/site split and
    // kill-switch configuration for AWG and Xray. Container selection is no longer hardcoded.
    // The functor runs on VpnConnection's thread. Native callbacks are accepted only after this
    // boundary and only through the platform's opaque runtime session identity; generic connection
    // state/sequence events cannot prove which AWG/Xray core owns the routes.
    const QPointer<VpnConnectionTransportAdapter> self(this);
    const QPointer<VpnConnection> connection = m_connection;
    const QDateTime expiresAt = compiled.expiresAt.toUTC();
    const QDateTime freshnessDeadline =
        compiled.runtimeAuthority.catalogFreshnessDeadline.toUTC();
    const QDateTime entitlementDeadline = compiled.runtimeAuthority.entitlementDeadline.toUTC();
    const QJsonObject finalConfiguration = prepared.finalConfiguration;
    const QString outerSessionId = prepared.outerSessionId;
    const QString expectedRuntimeSessionId = prepared.expectedRuntimeSessionId;
    const TransportOperationToken token = operation;
    const bool queued = QMetaObject::invokeMethod(m_connection,
        [self, connection, compiled, finalConfiguration, outerSessionId,
         expectedRuntimeSessionId, expiresAt, freshnessDeadline, entitlementDeadline, token]() {
            if (!self || !connection || self->m_phase != Phase::Starting
                || self->m_activeToken != token)
                return;
            const QDateTime now = self->m_clock ? self->m_clock->nowUtc().toUTC()
                                                : QDateTime::currentDateTimeUtc();
            if (!now.isValid() || expiresAt <= now || freshnessDeadline <= now
                || entitlementDeadline <= now) {
                self->m_phase = Phase::Idle;
                self->m_activeToken = {};
                self->m_activeProfile = {};
                self->m_activeFinalConfiguration = {};
                self->m_activeDispatchPolicySha256.clear();
                self->m_pendingAuthorityRenewal = {};
                self->m_activeOuterSessionId.clear();
                self->m_expectedRuntimeSessionId.clear();
                self->deliver(TransportEventKind::StartRejected,
                              QStringLiteral("native_profile_expired_at_dispatch"), token);
                return;
            }
            self->m_splitOn = finalConfiguration.value(QStringLiteral("splitTunnelType")).toInt()
                              == amnezia::RouteMode::VpnAllExceptSites;
            self->m_dnsMaskApplied = finalConfiguration.contains(QStringLiteral("splitDnsServer"))
                                     || finalConfiguration.value(QStringLiteral("dns1"))
                                            != compiled.vpnConfiguration.value(QStringLiteral("dns1"));
            // AVPN: catalog-v2 never enters the legacy VpnConnection start path. ACTIVATE consumes
            // the exact pre-armed outer lease and the app-generated runtime UUID. A false return is
            // defined as zero inner ownership; the outer blackhole remains owned by the reducer.
            const bool accepted = connection->activateNativeSession(
                finalConfiguration, QString::number(token.operation),
                QString::number(token.session), outerSessionId,
                expectedRuntimeSessionId);
            if (!accepted) {
                self->m_phase = Phase::Idle;
                self->m_activeToken = {};
                self->m_activeProfile = {};
                self->m_activeFinalConfiguration = {};
                self->m_activeDispatchPolicySha256.clear();
                self->m_pendingAuthorityRenewal = {};
                self->m_activeOuterSessionId.clear();
                self->m_expectedRuntimeSessionId.clear();
                self->deliver(TransportEventKind::StartRejected,
                              QStringLiteral("native_activate_dispatch_rejected"), token);
                return;
            }
            self->m_runtimeIdentity.resetForDispatch(self->m_transport,
                                                     expectedRuntimeSessionId);
            self->m_nativeDispatchReady = true;
        }, Qt::QueuedConnection);
    if (!queued) {
        m_phase = Phase::Idle;
        m_nativeDispatchReady = false;
        m_runtimeIdentity.clear();
        m_activeToken = {};
        m_activeProfile = {};
        m_activeFinalConfiguration = {};
        m_activeDispatchPolicySha256.clear();
        m_pendingAuthorityRenewal = {};
        m_activeOuterSessionId.clear();
        m_expectedRuntimeSessionId.clear();
        error = QStringLiteral("activateNativeSession invoke failed");
        return false;
    }
    return true;
}

TransportAuthorityRenewalResult VpnConnectionTransportAdapter::renewRuntimeAuthority(
    const CatalogCandidate &candidate, const CatalogRuntimeAuthority &authority,
    TransportOperationToken operation, TransportAuthorityRenewalDispatch &dispatch,
    QString &error)
{
    dispatch = {};
    error.clear();
    const QDateTime now = m_clock ? m_clock->nowUtc().toUTC()
                                  : QDateTime::currentDateTimeUtc();
    if (!m_connection || QThread::currentThread() != thread()
        || m_phase != Phase::Running || !m_nativeDispatchReady
        || !operation.isValid() || operation != m_activeToken
        || m_pendingAuthorityRenewal.isValid()
        || m_activeFinalConfiguration.isEmpty()
        || m_activeDispatchPolicySha256.size() != 32) {
        error = QStringLiteral("native authority renewal identity unavailable or busy");
        return TransportAuthorityRenewalResult::Rejected;
    }
    if (candidate.transport != m_transport
        || candidate.profileId != m_activeProfile.profileId
        || candidate.nativeProfile.configGeneration != m_activeProfile.configGeneration
        || candidate.nativeProfile.bindingGeneration != m_activeProfile.bindingGeneration
        || authority.deviceAudience != m_activeProfile.runtimeAuthority.deviceAudience
        || authority.catalogRevision < m_activeProfile.runtimeAuthority.catalogRevision
        || (authority.catalogRevision == m_activeProfile.runtimeAuthority.catalogRevision
            && authority.payloadSha256
                   != m_activeProfile.runtimeAuthority.catalogPayloadSha256)
        || authority.payloadSha256.size() != 32 || !now.isValid()
        || !authority.freshnessDeadline.isValid()
        || !authority.entitlementDeadline.isValid()
        || !authority.issuedAt.isValid()) {
        error = QStringLiteral("native authority renewal changed immutable identity");
        return TransportAuthorityRenewalResult::Rejected;
    }

    CompiledNativeProfile compiled;
    if (!validateAndCompile(candidate, compiled, error))
        return TransportAuthorityRenewalResult::Rejected;
    if (compiled.vpnConfiguration != m_activeProfile.vpnConfiguration) {
        // Same generation with different bearer/native bytes violates catalog immutability.  A
        // reconnect would merely dispatch the unversioned mutation, so fail closed instead.
        error = QStringLiteral("native profile bytes changed without generation advance");
        return TransportAuthorityRenewalResult::Rejected;
    }
    compiled.runtimeAuthority = {
        authority.source,
        authority.deviceAudience,
        authority.catalogRevision,
        authority.payloadSha256,
        authority.catalogSigningKeyId,
        candidate.profileId,
        candidate.transport,
        candidate.nativeProfile.configGeneration,
        candidate.nativeProfile.bindingGeneration,
        candidate.nativeProfile.expiresAt.toUTC(),
        authority.freshnessDeadline.toUTC(),
        authority.entitlementDeadline.toUTC(),
        authority.issuedAt.toUTC(),
        now,
    };
    const QDateTime hardDeadline = authorityHardDeadline(compiled.runtimeAuthority);
    if (!hardDeadline.isValid() || hardDeadline <= now) {
        error = QStringLiteral("native authority renewal is already expired");
        return TransportAuthorityRenewalResult::Rejected;
    }

    const NativeConnectionPolicySnapshot policy = snapshotConnectionPolicy(compiled);
    PreparedNativeConnectionPolicy nativePolicy;
    if (!NativeConnectionPolicyCompiler::compile(compiled, policy, nativePolicy, error)
        || !NativeConnectionPolicyCompiler::sanitizeForDispatch(
            compiled, policy, nativePolicy.configuration, error)) {
        if (error.isEmpty()) error = QStringLiteral("renewal policy compilation rejected");
        return TransportAuthorityRenewalResult::RestartRequired;
    }
    const QString policyText = nativePolicy.configuration
                                   .value(QStringLiteral("runtime_authority_v1"))
                                   .toObject().value(QStringLiteral("policy_sha256")).toString();
    if (QByteArray::fromHex(policyText.toLatin1()) != m_activeDispatchPolicySha256
        || withoutRuntimeAuthority(nativePolicy.configuration)
               != withoutRuntimeAuthority(m_activeFinalConfiguration)) {
        error = QStringLiteral("local/native policy changed during authority renewal");
        return TransportAuthorityRenewalResult::RestartRequired;
    }
    if (nativePolicy.configuration == m_activeFinalConfiguration) {
        dispatch.requestedHardDeadlineUtc = hardDeadline;
        return TransportAuthorityRenewalResult::NoChange;
    }

    const QByteArray serialized = QJsonDocument(nativePolicy.configuration)
                                      .toJson(QJsonDocument::Compact);
    const QByteArray commitment = QCryptographicHash::hash(serialized,
                                                            QCryptographicHash::Sha256);
    const QString renewalId = QUuid::createUuid()
                                  .toString(QUuid::WithoutBraces).toLower();
    dispatch = {renewalId, commitment, hardDeadline};
    if (!dispatch.isValid()) {
        dispatch = {};
        error = QStringLiteral("native authority renewal identity generation failed");
        return TransportAuthorityRenewalResult::Rejected;
    }

    m_pendingAuthorityRenewal = {
        operation, renewalId, commitment, hardDeadline, compiled,
        nativePolicy.configuration,
    };
    const QPointer<VpnConnectionTransportAdapter> self(this);
    const QPointer<VpnConnection> connection = m_connection;
    const QString outerSessionId = m_activeOuterSessionId;
    const QString expectedRuntimeSessionId = m_expectedRuntimeSessionId;
    const QJsonObject configuration = nativePolicy.configuration;
    const bool queued = QMetaObject::invokeMethod(m_connection,
        [self, connection, configuration, operation, outerSessionId,
         expectedRuntimeSessionId, renewalId, commitment]() {
            if (!self || !connection || !self->m_pendingAuthorityRenewal.isValid()
                || self->m_pendingAuthorityRenewal.operation != operation
                || self->m_pendingAuthorityRenewal.renewalId != renewalId)
                return;
            if (!connection->renewNativeRuntimeAuthority(
                    configuration, QString::number(operation.operation),
                    QString::number(operation.session), outerSessionId,
                    expectedRuntimeSessionId, renewalId,
                    QString::fromLatin1(commitment.toHex()))) {
                self->m_pendingAuthorityRenewal = {};
                self->deliver(TransportEventKind::AuthorityRenewalTimedOut,
                              QStringLiteral("native_authority_dispatch_rejected"), operation,
                              renewalId, commitment);
            }
        }, Qt::QueuedConnection);
    if (!queued) {
        m_pendingAuthorityRenewal = {};
        dispatch = {};
        error = QStringLiteral("renewNativeRuntimeAuthority invoke failed");
        return TransportAuthorityRenewalResult::Rejected;
    }

    // Native iOS/Android/macOS channels are asynchronous.  A missing/malformed receipt never
    // extends authority; the reducer serializes a restart while the old deadline remains active.
    QTimer::singleShot(8000, this, [self, operation, renewalId, commitment]() {
        if (!self || !self->m_pendingAuthorityRenewal.isValid()
            || self->m_pendingAuthorityRenewal.operation != operation
            || self->m_pendingAuthorityRenewal.renewalId != renewalId)
            return;
        self->m_pendingAuthorityRenewal = {};
        self->deliver(TransportEventKind::AuthorityRenewalTimedOut,
                      QStringLiteral("native_authority_receipt_timeout"), operation,
                      renewalId, commitment);
    });
    return TransportAuthorityRenewalResult::Dispatched;
}

void VpnConnectionTransportAdapter::stop(TransportOperationToken operation)
{
    // A stale stop is a no-op by design: it must never tear down a replacement session.
    if (!m_connection || !operation.isValid() || operation != m_activeToken
        || m_phase == Phase::Idle || m_phase == Phase::Stopping)
        return;
    // A stop supersedes authority renewal. The native request may still complete, but its receipt
    // is fenced by the cleared renewal identity and cannot mutate the stopping/replacement state.
    m_pendingAuthorityRenewal = {};
    m_phase = Phase::Stopping;
    const QPointer<VpnConnectionTransportAdapter> self(this);
    const QPointer<VpnConnection> connection = m_connection;
    const QString outerSessionId = m_activeOuterSessionId;
    const QString expectedRuntimeSessionId = m_expectedRuntimeSessionId;
    const bool queued = QMetaObject::invokeMethod(m_connection,
        [self, connection, operation, outerSessionId, expectedRuntimeSessionId]() {
            if (!self || !connection || self->m_phase != Phase::Stopping
                || self->m_activeToken != operation)
                return;
            // AVPN: stop only the exact inner catalog-v2 session. The independently owned outer
            // guard stays blocking until reducer receives `stopped` and requests exact RELEASE.
            if (!connection->stopNativeSession(outerSessionId,
                                               expectedRuntimeSessionId)) {
                self->m_lastError = QStringLiteral("native_exact_stop_dispatch_rejected");
                self->m_phase = Phase::Running;
                self->deliver(TransportEventKind::RuntimeError,
                              QStringLiteral("native_stop_dispatch"), operation);
            }
        }, Qt::QueuedConnection);
    if (!queued) {
        m_lastError = QStringLiteral("stopNativeSession invoke failed");
        m_phase = Phase::Running; // permit the reducer's bounded retry/timeout cleanup path
        deliver(TransportEventKind::RuntimeError, QStringLiteral("native_stop_dispatch"));
    }
}

void VpnConnectionTransportAdapter::onNativeRuntimeAuthorityRenewalReceipt(
    const QJsonObject &receipt)
{
    if (!m_pendingAuthorityRenewal.isValid() || m_phase != Phase::Running
        || !m_activeToken.isValid()) return;
    static const QSet<QString> exactKeys{
        QStringLiteral("type"), QStringLiteral("schema"), QStringLiteral("kind"),
        QStringLiteral("operation"), QStringLiteral("session"),
        QStringLiteral("renewal_id"), QStringLiteral("policy_sha256"),
        QStringLiteral("outer_session_id"),
        QStringLiteral("expected_runtime_session_id"),
        QStringLiteral("config_generation"), QStringLiteral("binding_generation"),
        QStringLiteral("catalog_revision"), QStringLiteral("catalog_payload_sha256"),
        QStringLiteral("authority_commitment_sha256"),
        QStringLiteral("hard_deadline"), QStringLiteral("reason"),
    };
    const QStringList receiptKeys = receipt.keys();
    if (QSet<QString>(receiptKeys.cbegin(), receiptKeys.cend()) != exactKeys
        || receipt.value(QStringLiteral("type"))
               != QLatin1String("runtime_authority_renewal_v1")
        || !receipt.value(QStringLiteral("schema")).isDouble()
        || receipt.value(QStringLiteral("schema")).toDouble() != 1.0)
        return;

    const QString kind = receipt.value(QStringLiteral("kind")).toString();
    const QString operationText = receipt.value(QStringLiteral("operation")).toString();
    const QString sessionText = receipt.value(QStringLiteral("session")).toString();
    const QString renewalId = receipt.value(QStringLiteral("renewal_id")).toString();
    const QString policy = receipt.value(QStringLiteral("policy_sha256")).toString();
    const QString outer = receipt.value(QStringLiteral("outer_session_id")).toString();
    const QString expectedRuntime = receipt.value(
        QStringLiteral("expected_runtime_session_id")).toString();
    const QString configGeneration = receipt.value(
        QStringLiteral("config_generation")).toString();
    const QString bindingGeneration = receipt.value(
        QStringLiteral("binding_generation")).toString();
    const QString catalogRevision = receipt.value(
        QStringLiteral("catalog_revision")).toString();
    const QString catalogPayload = receipt.value(
        QStringLiteral("catalog_payload_sha256")).toString();
    const QString commitmentText = receipt.value(
        QStringLiteral("authority_commitment_sha256")).toString();
    const QString hardDeadlineText = receipt.value(QStringLiteral("hard_deadline")).toString();
    const QString reason = receipt.value(QStringLiteral("reason")).toString();
    const QUuid renewalUuid(renewalId);
    const QByteArray commitment = QByteArray::fromHex(commitmentText.toLatin1());
    const PendingAuthorityRenewal pending = m_pendingAuthorityRenewal;
    const NativeRuntimeAuthority &authority = pending.compiled.runtimeAuthority;
    if ((kind != QLatin1String("applied") && kind != QLatin1String("rejected"))
        || !canonicalDecimal(operationText) || !canonicalDecimal(sessionText)
        || operationText != QString::number(pending.operation.operation)
        || sessionText != QString::number(pending.operation.session)
        || renewalUuid.isNull()
        || renewalUuid.toString(QUuid::WithoutBraces).toLower() != renewalId
        || renewalId != pending.renewalId
        || !lowerSha256Text(policy)
        || policy != QString::fromLatin1(m_activeDispatchPolicySha256.toHex())
        || !safeGuardOpaque(outer) || outer != m_activeOuterSessionId
        || !canonicalRuntimeUuid(expectedRuntime)
        || expectedRuntime != m_expectedRuntimeSessionId
        || !canonicalDecimal(configGeneration)
        || configGeneration != QString::number(pending.compiled.configGeneration)
        || !canonicalDecimal(bindingGeneration)
        || bindingGeneration != QString::number(pending.compiled.bindingGeneration)
        || !canonicalDecimal(catalogRevision)
        || catalogRevision != QString::number(authority.catalogRevision)
        || !lowerSha256Text(catalogPayload)
        || catalogPayload != QString::fromLatin1(authority.catalogPayloadSha256.toHex())
        || !lowerSha256Text(commitmentText)
        || commitment != pending.authorityCommitmentSha256
        || !safeAsciiReason(reason))
        return;

    if (kind == QLatin1String("rejected")) {
        if (!hardDeadlineText.isEmpty() || reason.isEmpty()) return;
        m_pendingAuthorityRenewal = {};
        deliver(TransportEventKind::AuthorityRenewalRejected,
                reason, pending.operation, renewalId, commitment);
        return;
    }

    QDateTime hardDeadline = QDateTime::fromString(hardDeadlineText, Qt::ISODateWithMs);
    if (!hardDeadline.isValid()) hardDeadline = QDateTime::fromString(
        hardDeadlineText, Qt::ISODate);
    hardDeadline = hardDeadline.toUTC();
    if (!hardDeadline.isValid() || !reason.isEmpty()
        || hardDeadline != pending.requestedHardDeadlineUtc.toUTC()) return;

    // The platform has durably persisted this exact envelope.  Only now may local telemetry and
    // the reducer advance to the renewed authority.
    m_activeProfile = pending.compiled;
    m_activeFinalConfiguration = pending.finalConfiguration;
    m_pendingAuthorityRenewal = {};
    deliver(TransportEventKind::AuthorityRenewed, QString(), pending.operation,
            renewalId, commitment, hardDeadline);
}

void VpnConnectionTransportAdapter::onNativeRuntimeStatus(const QJsonObject &statusObject)
{
    if (!m_nativeDispatchReady || m_phase == Phase::Idle || !m_activeToken.isValid())
        return;
    NativeRuntimeStatus status;
    if (m_runtimeIdentity.consume(statusObject, status)
        != NativeRuntimeStatusDisposition::Accepted)
        return;
    if (status.state == QLatin1String("running")) {
        if (m_phase == Phase::Starting) {
            m_phase = Phase::Running;
            // Native ready is intentionally only an intermediate gate. The reducer still requires
            // post-tunnel DNS/HTTPS verification before ConnectedHealthy.
            deliver(TransportEventKind::TunnelReady);
        }
        return;
    }
    if (m_phase == Phase::Stopping) {
        if (status.state == QLatin1String("failed")) {
            // AVPN: failed is diagnostic, not teardown proof. Replacement remains gated on the
            // exact same opaque native session reporting `stopped`.
            m_lastError = QStringLiteral("native_error_while_stopping");
            return;
        }
        if (status.state != QLatin1String("stopped"))
            return;
        const TransportOperationToken stoppedToken = m_activeToken;
        m_phase = Phase::Idle;
        m_nativeDispatchReady = false;
        m_runtimeIdentity.clear();
        m_activeToken = {};
        m_activeProfile = {};
        m_activeFinalConfiguration = {};
        m_activeDispatchPolicySha256.clear();
        m_pendingAuthorityRenewal = {};
        m_activeOuterSessionId.clear();
        m_expectedRuntimeSessionId.clear();
        deliver(TransportEventKind::Stopped, QString(), stoppedToken);
        return;
    }
    if (status.state == QLatin1String("starting")
        || status.state == QLatin1String("reconnecting")
        || status.state == QLatin1String("unknown"))
        return;
    if (status.state == QLatin1String("stopping")) {
        m_lastError = QStringLiteral("unexpected_native_stopping");
        deliver(TransportEventKind::RuntimeError, m_lastError);
        return;
    }
    if (status.state == QLatin1String("failed")) {
        m_lastError = QStringLiteral("native_runtime_error");
        deliver(TransportEventKind::RuntimeError, m_lastError);
        return;
    }
    if (status.state == QLatin1String("stopped")) {
        // The native terminal arrived before a separate error callback. Deliver both deferred and
        // ordered: reducer first transitions to stopping, then the same session proves teardown.
        const TransportOperationToken stoppedToken = m_activeToken;
        m_lastError = QStringLiteral("unexpected_native_disconnect");
        m_phase = Phase::Idle;
        m_nativeDispatchReady = false;
        m_runtimeIdentity.clear();
        m_activeToken = {};
        m_activeProfile = {};
        m_activeFinalConfiguration = {};
        m_activeDispatchPolicySha256.clear();
        m_pendingAuthorityRenewal = {};
        m_activeOuterSessionId.clear();
        m_expectedRuntimeSessionId.clear();
        deliver(TransportEventKind::RuntimeError, m_lastError, stoppedToken);
        deliver(TransportEventKind::Stopped, QString(), stoppedToken);
    }
}

void VpnConnectionTransportAdapter::deliver(
    TransportEventKind kind, const QString &reason, TransportOperationToken token,
    const QString &renewalId, const QByteArray &authorityCommitmentSha256,
    const QDateTime &appliedHardDeadlineUtc)
{
    if (!token.isValid())
        token = m_activeToken;
    ITransportAdapterObserver *const observer = m_observer;
    if (!observer || !token.isValid())
        return;
    // AVPN: even dispatch/stop errors are deferred. A reducer may call stop() from inside its own
    // callback; delivering synchronously here would re-enter and corrupt its serialized state.
    const QPointer<VpnConnectionTransportAdapter> self(this);
    QMetaObject::invokeMethod(this,
        [self, observer, token, kind, reason, renewalId,
         authorityCommitmentSha256, appliedHardDeadlineUtc]() {
        if (self && self->m_observer == observer)
            observer->onTransportEvent({token, kind, reason, renewalId,
                                        authorityCommitmentSha256,
                                        appliedHardDeadlineUtc});
    }, Qt::QueuedConnection);
}

NativeConnectionPolicySnapshot VpnConnectionTransportAdapter::snapshotConnectionPolicy(
    const CompiledNativeProfile &compiled) const
{
    NativeConnectionPolicySnapshot snapshot;
    const bool ruLocation = compiled.locationCountry == QLatin1String("RU");
    QSettings settings;
    const bool masterOn = settings.value(QStringLiteral("AvpnBypass/masterOn"), true).toBool();
    const bool liAutoOn = settings.value(QStringLiteral("AvpnBypass/liAutoOn"), true).toBool();
    const bool dnsMaskOn = settings.value(QStringLiteral("AvpnBypass/dnsMaskOn"), true).toBool();
    const bool dnsFwdOn = settings.value(QStringLiteral("AvpnBypass/dnsFwd"), true).toBool();
    snapshot.ruDirectRequested = (masterOn || liAutoOn) && !ruLocation;
    snapshot.dnsMaskRequested = dnsMaskOn;
    snapshot.dnsForwardRequested = dnsFwdOn;
    snapshot.dnsForwardWarmup =
        TuningStore::flag(QStringLiteral("dns_fwd_warmup"), true);
    snapshot.protectedTunnelIpLiterals = m_options.protectedTunnelIpLiterals;

    if (m_settings) {
        const QVariantMap routes =
            m_settings->vpnSites(amnezia::RouteMode::VpnAllExceptSites);
        for (auto it = routes.constBegin(); it != routes.constEnd(); ++it) {
            QStringList values;
            if (it.key().contains(QLatin1Char('/')))
                values.append(it.key());
            else
                values = SecureAppSettingsRepository::siteIpList(it.value());
            for (QString value : values) {
                QHostAddress literal;
                if (!value.contains(QLatin1Char('/')) && literal.setAddress(value))
                    value = literal.toString()
                            + (literal.protocol() == QAbstractSocket::IPv4Protocol
                                   ? QStringLiteral("/32") : QStringLiteral("/128"));
#if defined(AMNEZIA_DESKTOP) && !defined(Q_OS_ANDROID) \
    && !defined(Q_OS_IOS) && !defined(MACOS_NE)
                QHostAddress routeAddress;
                if (routeAddress.setAddress(value.section(QLatin1Char('/'), 0, 0))
                    && routeAddress.protocol() == QAbstractSocket::IPv6Protocol)
                    continue; // desktop daemon route contract remains IPv4-only
#endif
                snapshot.routeExclusions.append(value);
            }
        }
        snapshot.routeExclusions.removeDuplicates();

        snapshot.appsSplitEnabled = m_settings->isAppsSplitTunnelingEnabled();
        snapshot.appsRouteMode = m_settings->appsRouteMode();
        for (const InstalledAppInfo &app : m_settings->vpnApps(snapshot.appsRouteMode))
            snapshot.splitApps.append(app.appPath.isEmpty() ? app.packageName : app.appPath);
        snapshot.splitApps.removeDuplicates();

#ifdef AMNEZIA_DESKTOP
        snapshot.includeDesktopKillSwitch = true;
        snapshot.killSwitchEnabled = m_settings->isKillSwitchEnabled();
        snapshot.allowedDnsServers = m_settings->getAllowedDnsServers();
#endif
    }

    const BypassLists bypass = BypassListStore::get();
    snapshot.splitDnsSuffixes = bypass.valid ? bypass.splitDnsSuffixes
                                             : defaultSplitDnsSuffixes();
    snapshot.splitDnsServer = bypass.valid ? bypass.splitDnsServer
                                           : defaultSplitDnsServer();
    snapshot.maskDnsServers = bypass.valid && bypass.maskDns.size() >= 2
                                  ? bypass.maskDns : defaultMaskDns();
    return snapshot;
}

TransportTelemetry VpnConnectionTransportAdapter::telemetry() const
{
    TransportTelemetry telemetry;
    telemetry.runtimeUp = m_phase == Phase::Running;
    switch (m_phase) {
    case Phase::Idle: telemetry.coreState = QStringLiteral("idle"); break;
    case Phase::Starting: telemetry.coreState = QStringLiteral("starting"); break;
    case Phase::Running: telemetry.coreState = QStringLiteral("running"); break;
    case Phase::Stopping: telemetry.coreState = QStringLiteral("stopping"); break;
    }
    telemetry.adapterError = m_lastError;
    telemetry.redactedDetail = {
        {QStringLiteral("transport"), transportKindName(m_transport)},
        {QStringLiteral("profile_kind"), m_transport == TransportKind::Awg
             ? QStringLiteral("awg31") : QStringLiteral("xray_vless_reality_vision_tcp")},
        {QStringLiteral("config_generation"), double(m_activeProfile.configGeneration)},
        {QStringLiteral("binding_generation"), double(m_activeProfile.bindingGeneration)},
        {QStringLiteral("split_on"), m_splitOn},
        {QStringLiteral("dns_mask"), m_dnsMaskApplied},
    };
    return telemetry;
}

BundledNativeTransportAdapters::BundledNativeTransportAdapters(
    VpnConnection *connection, NativeProfileCompileOptions options,
    SecureAppSettingsRepository *settings, QObject *parent, IConnectionClock *clock)
    : QObject(parent)
{
    NativeProfileCompileOptions xrayOptions = options;
    xrayOptions.awgKeys = {}; // Xray adapter must not retain unrelated WireGuard private material.
    m_awg = new VpnConnectionTransportAdapter(connection, TransportKind::Awg,
                                               options, settings, this, clock);
    m_xray = new VpnConnectionTransportAdapter(connection, TransportKind::Xray,
                                                std::move(xrayOptions), settings, this, clock);
    if (connection) {
        // AVPN: use the validated opaque native session ID, never signal ordering as identity.
        // A terminal from the previous core after replacement dispatch is therefore provably stale.
        connect(connection, &VpnConnection::nativeRuntimeStatusChanged, this,
                [this](const QJsonObject &status) {
                    const TransportKind transport = transportKindFromName(
                        status.value(QStringLiteral("protocol")).toString());
                    VpnConnectionTransportAdapter *adapter = transport == TransportKind::Awg
                        ? m_awg : transport == TransportKind::Xray ? m_xray : nullptr;
                    if (adapter && adapter->ownsNativeSession())
                        adapter->onNativeRuntimeStatus(status);
                }, Qt::QueuedConnection);
    }
}

bool BundledNativeTransportAdapters::registerInto(TransportAdapterRegistry &registry,
                                                   QString &error)
{
    return registerForMode(registry, ConnectionMode::Auto, error);
}

bool BundledNativeTransportAdapters::registerForMode(TransportAdapterRegistry &registry,
                                                      ConnectionMode mode,
                                                      QString &error)
{
    error.clear();
    VpnConnection *connection = m_awg->m_connection;
    if (!connection) {
        error = QStringLiteral("native connection unavailable");
        return false;
    }
    const bool needAwg = mode != ConnectionMode::ForceXray;
    const bool needXray = mode != ConnectionMode::ForceAwg;
    if ((needAwg && (!connection->nativeRuntimeIdentitySupported(Proto::Awg)
                     || !connection->nativeSessionGuardSupported(Proto::Awg)))
        || (needXray && (!connection->nativeRuntimeIdentitySupported(Proto::Xray)
                         || !connection->nativeSessionGuardSupported(Proto::Xray)))) {
        error = QStringLiteral("required native runtime identity/session guard is unavailable");
        return false;
    }
    if ((needAwg && registry.adapter(TransportKind::Awg))
        || (needXray && registry.adapter(TransportKind::Xray))) {
        error = QStringLiteral("requested transport registry slot is already occupied");
        return false;
    }
    if (needAwg && !registry.add(m_awg, error)) return false;
    if (needXray && !registry.add(m_xray, error)) return false;
    return true;
}

void BundledNativeTransportAdapters::setAwgKeys(const ClientKeys &keys)
{
    m_awg->setAwgKeys(keys);
}

bool BundledNativeTransportAdapters::setProtectedTunnelIpLiterals(
    const QStringList &literals, QString &error)
{
    if (!m_awg->setProtectedTunnelIpLiterals(literals, error)) return false;
    if (!m_xray->setProtectedTunnelIpLiterals(literals, error)) {
        // Both adapters are Idle by contract here. Clear the first snapshot rather than leave a
        // half-applied route policy; empty is itself fail-closed when RU split is requested.
        m_awg->m_options.protectedTunnelIpLiterals.clear();
        return false;
    }
    return true;
}

} // namespace avpn
