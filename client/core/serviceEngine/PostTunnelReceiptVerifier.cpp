#include "PostTunnelReceiptVerifier.h"

#include "CatalogResolve.h"
#include "SignedEnvelope.h"

#include <QCryptographicHash>
#include <QElapsedTimer>
#include <QHostAddress>
#include <QHostInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QNetworkProxy>
#include <QRandomGenerator>
#include <QRegularExpression>
#include <QSslConfiguration>
#include <QSslSocket>
#include <QTimer>

#include <algorithm>
#include <cmath>
#include <cstring>
#include <utility>

namespace avpn {
namespace {

QByteArray randomBytes(int count)
{
    QByteArray bytes(count, Qt::Uninitialized);
    for (int offset = 0; offset < count; offset += int(sizeof(quint32))) {
        const quint32 word = QRandomGenerator::system()->generate();
        const int chunk = qMin(int(sizeof(word)), count - offset);
        memcpy(bytes.data() + offset, &word, size_t(chunk));
    }
    return bytes;
}

QString freshNonce()
{
    return QString::fromLatin1(randomBytes(32).toBase64(
        QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
}

bool safeProviderId(const QString &value)
{
    static const QRegularExpression id(QStringLiteral("^[a-z][a-z0-9.-]{2,63}$"));
    return id.match(value).hasMatch();
}

bool safeProfileId(const QString &value)
{
    static const QRegularExpression id(QStringLiteral("^[A-Za-z0-9][A-Za-z0-9._:-]{0,95}$"));
    return id.match(value).hasMatch();
}

bool safeVerificationContext(const QString &value)
{
    static const QRegularExpression id(
        QStringLiteral("^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$"));
    return id.match(value).hasMatch();
}

bool safeEgressId(const QString &value)
{
    // Egress/failure-domain identifiers deliberately allow hierarchy separators.  They are a
    // different contract from profile IDs and verification contexts.
    static const QRegularExpression id(
        QStringLiteral("^[A-Za-z0-9][A-Za-z0-9._:/-]{0,95}$"));
    return id.match(value).hasMatch();
}

bool exactKeys(const QJsonObject &object, const QSet<QString> &keys)
{
    if (object.size() != keys.size()) return false;
    for (auto it = object.constBegin(); it != object.constEnd(); ++it)
        if (!keys.contains(it.key())) return false;
    return true;
}

bool utcField(const QJsonObject &object, const QString &key, QDateTime &out)
{
    if (!object.value(key).isString()) return false;
    const QString text = object.value(key).toString();
    if (!text.endsWith(QLatin1Char('Z'))) return false;
    out = QDateTime::fromString(text, Qt::ISODateWithMs);
    if (!out.isValid()) out = QDateTime::fromString(text, Qt::ISODate);
    if (!out.isValid()) return false;
    out = out.toUTC();
    return true;
}

bool uintField(const QJsonObject &object, const QString &key, quint64 &out)
{
    const QJsonValue value = object.value(key);
    if (!value.isDouble()) return false;
    const double number = value.toDouble();
    if (!std::isfinite(number) || number < 1 || number > 9007199254740991.0
        || std::floor(number) != number) return false;
    out = quint64(number); return true;
}

bool canonicalToken(const QJsonValue &value, QByteArray &decoded, int minimum, int maximum)
{
    if (!value.isString() || value.toString().contains(QLatin1Char('='))) return false;
    const QByteArray encoded = value.toString().toLatin1();
    if (QString::fromLatin1(encoded) != value.toString()) return false;
    const auto result = QByteArray::fromBase64Encoding(
        encoded, QByteArray::Base64UrlEncoding | QByteArray::AbortOnBase64DecodingErrors);
    if (result.decodingStatus != QByteArray::Base64DecodingStatus::Ok
        || result.decoded.size() < minimum || result.decoded.size() > maximum
        || result.decoded.toBase64(QByteArray::Base64UrlEncoding
                                   | QByteArray::OmitTrailingEquals) != encoded) return false;
    decoded = result.decoded; return true;
}

bool exactNoStore(const QNetworkReply *reply)
{
    const QList<QByteArray> cacheParts = reply->rawHeader(QByteArrayLiteral("Cache-Control"))
                                             .toLower().split(',');
    QSet<QByteArray> cache;
    for (QByteArray part : cacheParts) {
        part = part.trimmed();
        if (!part.isEmpty()) cache.insert(part);
    }
    return cacheParts.size() == 4
           && cache == QSet<QByteArray>{QByteArrayLiteral("private"),
                                       QByteArrayLiteral("no-store"),
                                       QByteArrayLiteral("no-cache"),
                                       QByteArrayLiteral("max-age=0")}
           && reply->rawHeader(QByteArrayLiteral("Pragma")).trimmed().toLower()
                  == QByteArrayLiteral("no-cache")
           && reply->rawHeader(QByteArrayLiteral("Content-Encoding")).trimmed().toLower()
                  == QByteArrayLiteral("identity");
}

bool retryAfterHeader(const QNetworkReply *reply, int &seconds)
{
    const QByteArray raw = reply->rawHeader(QByteArrayLiteral("Retry-After")).trimmed();
    bool ok = false;
    const int value = raw.toInt(&ok);
    if (!ok || value < 1 || value > 300 || raw != QByteArray::number(value)) return false;
    seconds = value;
    return true;
}

bool noRetryAfterHeader(const QNetworkReply *reply)
{
    return !reply->hasRawHeader(QByteArrayLiteral("Retry-After"));
}

struct ReceiptHttpFailure {
    VerificationDisposition disposition = VerificationDisposition::AuthorityRejected;
    QString reason;
    int retryAfterSeconds = 0;
};

bool parseReceiptHttpFailure(int status, const QByteArray &body, const QNetworkReply *reply,
                             ReceiptHttpFailure &out)
{
    QJsonDocument document;
    QString error;
    if (!parseStrictJsonDocument(body, document, error, 4096) || !document.isObject())
        return false;
    const QJsonObject object = document.object();
    const bool hasRetry = object.contains(QStringLiteral("retry_after"));
    const QSet<QString> expected = hasRetry
        ? QSet<QString>{QStringLiteral("code"), QStringLiteral("retry_after")}
        : QSet<QString>{QStringLiteral("code")};
    if (!exactKeys(object, expected) || !object.value(QStringLiteral("code")).isString())
        return false;
    int bodyRetry = 0;
    if (hasRetry) {
        const QJsonValue value = object.value(QStringLiteral("retry_after"));
        if (!value.isDouble() || value.toDouble() < 1 || value.toDouble() > 300
            || std::floor(value.toDouble()) != value.toDouble()) return false;
        bodyRetry = value.toInt();
    }
    int headerRetry = 0;
    const QString code = object.value(QStringLiteral("code")).toString();
    if (status == 400 && code == QLatin1String("invalid_request") && !hasRetry
        && noRetryAfterHeader(reply)) {
        out = {VerificationDisposition::AuthorityRejected,
               QStringLiteral("receipt_invalid_request"), 0};
        return true;
    }
    if (status == 401 && code == QLatin1String("auth_invalid") && !hasRetry
        && noRetryAfterHeader(reply)) {
        out = {VerificationDisposition::AuthorityRejected,
               QStringLiteral("receipt_auth_invalid"), 0};
        return true;
    }
    if (status == 410 && code == QLatin1String("device_revoked") && !hasRetry
        && noRetryAfterHeader(reply)) {
        out = {VerificationDisposition::AuthorityRejected,
               QStringLiteral("receipt_device_revoked"), 0};
        return true;
    }
    static const QSet<QString> staleCodes{
        QStringLiteral("binding_stale"), QStringLiteral("audience_mismatch"),
        QStringLiteral("context_mismatch"), QStringLiteral("generation_mismatch")};
    if (status == 409 && staleCodes.contains(code) && !hasRetry
        && noRetryAfterHeader(reply)) {
        out = {VerificationDisposition::CatalogStale,
               QStringLiteral("receipt_%1").arg(code), 0};
        return true;
    }
    if (status == 429 && code == QLatin1String("rate_limited") && hasRetry
        && retryAfterHeader(reply, headerRetry) && headerRetry == bodyRetry) {
        out = {VerificationDisposition::InfrastructureUnavailable,
               QStringLiteral("receipt_rate_limited"), bodyRetry};
        return true;
    }
    if (status == 503 && code == QLatin1String("temporarily_unavailable")
        && ((hasRetry && retryAfterHeader(reply, headerRetry) && headerRetry == bodyRetry)
            || (!hasRetry && noRetryAfterHeader(reply)))) {
        out = {VerificationDisposition::InfrastructureUnavailable,
               QStringLiteral("receipt_temporarily_unavailable"), bodyRetry};
        return true;
    }
    return false;
}

bool safeAuthority(const ReceiptVerifierAuthority &authority)
{
    if (authority.verificationToken.isEmpty() || authority.verificationToken.size() > 4096
        || authority.verificationToken.contains('\r') || authority.verificationToken.contains('\n')
        || !canonicalCatalogOpaque32(authority.deviceAudience)
        || authority.catalogRevision == 0 || authority.catalogRevision > 9007199254740991ULL
        || authority.keysetEpoch == 0 || authority.keysetEpoch > 9007199254740991ULL
        || !authority.expiresAt.isValid()
        || authority.providers.size() != 2) return false;
    static const QRegularExpression publicKey(QStringLiteral("^[0-9A-Fa-f]{64}$"));
    QSet<QString> ids, trustDomains, hosts, keyBytes, allIps;
    for (const ReceiptVerificationProvider &provider : authority.providers) {
        if (!safeProviderId(provider.id) || ids.contains(provider.id)
            || !safeProviderId(provider.trustDomain)
            || trustDomains.contains(provider.trustDomain)
            || !provider.endpoint.isValid()
            || provider.endpoint.scheme() != QLatin1String("https")
            || provider.endpoint.host().isEmpty() || hosts.contains(provider.endpoint.host())
            || !provider.endpoint.userInfo().isEmpty() || !provider.endpoint.query().isEmpty()
            || !provider.endpoint.fragment().isEmpty()
            || provider.endpoint.path() != QLatin1String("/v2/verify/receipt")
            || provider.receiptPublicKeysHex.size() != 1
            || provider.protectedAuthorityIps.isEmpty()
            || provider.protectedAuthorityIps.size() > 64) return false;
        ids.insert(provider.id);
        trustDomains.insert(provider.trustDomain);
        hosts.insert(provider.endpoint.host());
        for (auto it = provider.receiptPublicKeysHex.constBegin();
             it != provider.receiptPublicKeysHex.constEnd(); ++it) {
            const QString normalizedKey = it.value().toLower();
            if (!canonicalSigningKeyId(it.key()) || !publicKey.match(it.value()).hasMatch()
                || keyBytes.contains(normalizedKey)) return false;
            keyBytes.insert(normalizedKey);
        }
        for (const QString &literal : provider.protectedAuthorityIps) {
            QHostAddress address;
            if (!address.setAddress(literal) || address.toString() != literal
                || !address.isGlobal() || allIps.contains(literal)) return false;
            allIps.insert(literal);
        }
    }
    return true;
}

} // namespace

bool buildReceiptVerifierAuthority(const Catalog &acceptedCatalog,
                                   const CatalogAcceptedKeyrings &acceptedKeyrings,
                                   ReceiptVerifierAuthority &authority,
                                   QString &error)
{
    authority = {};
    error.clear();
    if (!acceptedCatalog.receiptProviderPolicy.has_value()
        || !canonicalCatalogOpaque32(acceptedCatalog.deviceAudience)
        || acceptedCatalog.catalogRevision == 0
        || acceptedCatalog.catalogRevision > 9007199254740991ULL) {
        error = QStringLiteral("accepted catalog receipt policy is unavailable");
        return false;
    }
    const ReceiptProviderPolicy &policy = *acceptedCatalog.receiptProviderPolicy;
    if (policy.schemaVersion != 1 || policy.quorum != 2 || policy.providers.size() != 2
        || policy.verificationToken.isEmpty()
        || !policy.verificationTokenExpiresAt.isValid()) {
        error = QStringLiteral("accepted catalog receipt policy is incomplete");
        return false;
    }
    ReceiptVerifierAuthority built;
    built.verificationToken = policy.verificationToken;
    built.deviceAudience = acceptedCatalog.deviceAudience;
    built.catalogRevision = acceptedCatalog.catalogRevision;
    built.keysetEpoch = acceptedKeyrings.manifestEpoch;
    built.expiresAt = qMin(acceptedCatalog.expiresAt.toUTC(),
                           policy.verificationTokenExpiresAt.toUTC());
    for (const ReceiptProviderDescriptor &descriptor : policy.providers) {
        const auto key = acceptedKeyrings.receiptPublicKeysHex.constFind(descriptor.receiptKid);
        if (key == acceptedKeyrings.receiptPublicKeysHex.constEnd()
            || acceptedKeyrings.receiptKeyEpochs.value(descriptor.receiptKid, 0)
                   != descriptor.receiptKeyEpoch
            || acceptedKeyrings.receiptAuthorityIds.value(descriptor.receiptKid)
                   != descriptor.trustDomain) {
            built.verificationToken.fill('\0');
            error = QStringLiteral("receipt provider key is not active in accepted keyset");
            return false;
        }
        QUrl endpoint(descriptor.baseUrl, QUrl::StrictMode);
        endpoint.setPath(QStringLiteral("/v2/verify/receipt"));
        ReceiptVerificationProvider provider;
        provider.id = descriptor.id;
        provider.trustDomain = descriptor.trustDomain;
        provider.endpoint = endpoint;
        provider.receiptPublicKeysHex.insert(descriptor.receiptKid, *key);
        provider.protectedAuthorityIps = QSet<QString>(descriptor.bootstrapIps.cbegin(),
                                                       descriptor.bootstrapIps.cend());
        built.providers.append(std::move(provider));
    }
    if (!safeAuthority(built)) {
        built.verificationToken.fill('\0');
        error = QStringLiteral("receipt authority failed final policy validation");
        return false;
    }
    authority = std::move(built);
    return true;
}

PostTunnelReceiptVerifier::PostTunnelReceiptVerifier(
    IConnectionClock *trustedClock, QObject *parent, int timeoutMs, int minimumProbeBytes,
    ReceiptNetworkFactory networkFactory, ReceiptDnsLookup dnsLookup,
    ReceiptDnsAbort dnsAbort)
    : QObject(parent), m_timer(new QTimer(this)), m_clock(trustedClock),
      m_timeoutMs(qBound(3000, timeoutMs, 30000)),
      m_minimumProbeBytes(qBound(32768, minimumProbeBytes, 65536)),
      m_networkFactory(std::move(networkFactory)), m_dnsLookup(std::move(dnsLookup)),
      m_dnsAbort(std::move(dnsAbort))
{
    if (!m_networkFactory) {
        m_networkFactory = [](QObject *owner) {
            auto *manager = new QNetworkAccessManager(owner);
            manager->setProxy(QNetworkProxy::NoProxy);
            manager->setStrictTransportSecurityEnabled(true);
            return manager;
        };
    }
    if (!m_dnsLookup) {
        m_dnsLookup = [](const QString &host, QObject *owner, ReceiptDnsCallback callback) {
            return QHostInfo::lookupHost(host, owner,
                [callback = std::move(callback)](const QHostInfo &info) {
                    callback(info);
                });
        };
    }
    if (!m_dnsAbort)
        m_dnsAbort = [](int lookupId) { QHostInfo::abortHostLookup(lookupId); };
    m_timer->setSingleShot(true);
    connect(m_timer, &QTimer::timeout, this, [this]() {
        if (!m_active.isValid()) return;
        if (m_providerInfrastructureUnavailable && !m_observedEgressIds.isEmpty()) {
            // Once one independent provider was provably unavailable, failure to complete the
            // remaining quorum says nothing candidate-specific.  Keep the tunnel yellow and retry
            // later; never cool/rotate a healthy candidate because verifier infrastructure split.
            complete(VerificationDisposition::InfrastructureUnavailable,
                     ConnectionFailureStage::VerificationTimeout,
                     m_providerInfrastructureReason.isEmpty()
                         ? QStringLiteral("receipt_provider_infrastructure_unavailable")
                         : m_providerInfrastructureReason);
            return;
        }
        // Once native TunnelReady has been proved, a global receipt deadline with no traffic
        // proof is candidate-path evidence (blocked DNS/NAT/TLS), not a verifier control-plane
        // outage. Typed provider 429/503 below remain the yellow/unknown infrastructure class.
        complete(VerificationDisposition::CandidateFailed,
                 ConnectionFailureStage::VerificationTimeout,
                 QStringLiteral("receipt_timeout"));
    });
}

PostTunnelReceiptVerifier::~PostTunnelReceiptVerifier()
{
    if (m_active.isValid()) cancel(m_active);
    clearAuthority();
    m_observer = nullptr;
}

bool PostTunnelReceiptVerifier::setAuthority(ReceiptVerifierAuthority authority, QString &error)
{
    error.clear();
    if (m_active.isValid() || !safeAuthority(authority)) {
        error = QStringLiteral("receipt authority invalid or verifier busy"); return false;
    }
    clearAuthority();
    m_authority = std::move(authority);
    return true;
}

void PostTunnelReceiptVerifier::clearAuthority()
{
    m_authority.verificationToken.fill('\0');
    m_authority = {};
}

bool PostTunnelReceiptVerifier::start(const CatalogCandidate &candidate,
                                      VerificationToken verification, QString &error)
{
    error.clear();
    if (!m_clock || !m_clock->nowUtc().isValid()
        || m_clock->nowUtc().toUTC() >= m_authority.expiresAt.toUTC() || m_active.isValid()
        || !verification.isValid() || !safeAuthority(m_authority)
        || !safeProfileId(candidate.profileId) || candidate.nativeProfile.bindingGeneration == 0
        || !safeVerificationContext(candidate.verification.context)
        || candidate.verification.expectedEgressIds.isEmpty()
        || candidate.verification.expectedEgressIds.size() > 16) {
        error = QStringLiteral("receipt verifier prerequisites unavailable");
        return false;
    }
    QSet<QString> egress;
    for (const QString &id : candidate.verification.expectedEgressIds) {
        if (!safeEgressId(id) || egress.contains(id)) {
            error = QStringLiteral("receipt egress allowlist invalid"); return false;
        }
        egress.insert(id);
    }
    m_active = verification;
    if (++m_callbackEpoch == 0) ++m_callbackEpoch;
    m_candidate = candidate;
    m_phase = Phase::ResolvingDns;
    m_providerIndex = 0;
    m_observedEgressIds.clear();
    m_providerInfrastructureUnavailable = false;
    m_providerInfrastructureReason.clear();
    m_receiptExpiresAt = {};
    m_elapsed.restart();
    m_timer->start(m_timeoutMs);
    stage(PostTunnelVerificationStage::Dns);
    beginProvider(0);
    if (m_lookupId < 0) {
        ++m_callbackEpoch;
        resetActive();
        error = QStringLiteral("receipt DNS dispatch failed");
        return false;
    }
    return true;
}

void PostTunnelReceiptVerifier::beginProvider(int providerIndex)
{
    if (!m_active.isValid() || providerIndex < 0
        || providerIndex >= m_authority.providers.size()) return;
    m_providerIndex = providerIndex;
    m_providerIpAttempts.clear();
    m_providerIpAttemptIndex = -1;
    m_phase = Phase::ResolvingDns;
    const QString host = m_authority.providers.at(providerIndex).endpoint.host();
    m_lookupId = m_dnsLookup(host, this,
        [this, verification = m_active, providerIndex](const QHostInfo &info) {
            onDnsResolved(info.lookupId(), verification, providerIndex, info);
        });
}

void PostTunnelReceiptVerifier::cancel(VerificationToken verification)
{
    if (!verification.isValid() || verification != m_active) return;
    if (++m_callbackEpoch == 0) ++m_callbackEpoch;
    resetActive();
}

void PostTunnelReceiptVerifier::onDnsResolved(int lookupId, VerificationToken verification,
                                               int providerIndex, const QHostInfo &info)
{
    if (verification != m_active || m_phase != Phase::ResolvingDns
        || lookupId != m_lookupId || providerIndex != m_providerIndex) return;
    m_lookupId = -1;
    const ReceiptVerificationProvider provider = m_authority.providers.at(providerIndex);
    QSet<QString> resolved;
    if (info.error() != QHostInfo::NoError || info.addresses().isEmpty()) {
        m_providerInfrastructureUnavailable = true;
        m_providerInfrastructureReason = QStringLiteral("receipt_dns_unavailable");
        if (providerIndex + 1 < m_authority.providers.size()) {
            beginProvider(providerIndex + 1);
            if (m_lookupId < 0)
                complete(VerificationDisposition::InfrastructureUnavailable,
                         ConnectionFailureStage::VerificationDns,
                         QStringLiteral("receipt_dns_dispatch_unavailable"));
        } else {
            complete(m_observedEgressIds.isEmpty()
                         ? VerificationDisposition::CandidateFailed
                         : VerificationDisposition::InfrastructureUnavailable,
                     ConnectionFailureStage::VerificationDns,
                     m_observedEgressIds.isEmpty()
                         ? QStringLiteral("receipt_all_providers_unavailable")
                         : m_providerInfrastructureReason);
        }
        return;
    }
    for (const QHostAddress &address : info.addresses()) {
        const QString literal = address.toString();
        // Only the intersection with the signed, pre-routed bootstrap snapshot is eligible.
        // DNS answers outside it are never followed and cannot expand routes at runtime.
        if (address.isGlobal() && !literal.isEmpty()
            && provider.protectedAuthorityIps.contains(literal))
            resolved.insert(literal);
    }
    if (resolved.isEmpty()) {
        complete(VerificationDisposition::InfrastructureUnavailable,
                 ConnectionFailureStage::VerificationDns,
                 QStringLiteral("receipt_dns_snapshot_changed"), {}, -1, 5,
                 VerificationRetryDirective::RefreshCatalog);
        return;
    }
    QStringList v4, v6;
    for (const QString &literal : resolved) {
        QHostAddress address(literal);
        (address.protocol() == QAbstractSocket::IPv6Protocol ? v6 : v4).append(literal);
    }
    std::sort(v4.begin(), v4.end());
    std::sort(v6.begin(), v6.end());
    m_providerIpAttempts.clear();
    // Deterministic family interleave avoids permanently preferring one family while preserving
    // a single bounded global verification deadline. Providers start on opposite families.
    const bool startV6 = providerIndex % 2 == 0 && !v6.isEmpty();
    int v4Index = 0, v6Index = 0;
    bool takeV6 = startV6;
    while (v4Index < v4.size() || v6Index < v6.size()) {
        if (takeV6 && v6Index < v6.size()) m_providerIpAttempts.append(v6.at(v6Index++));
        else if (!takeV6 && v4Index < v4.size()) m_providerIpAttempts.append(v4.at(v4Index++));
        else if (v6Index < v6.size()) m_providerIpAttempts.append(v6.at(v6Index++));
        else m_providerIpAttempts.append(v4.at(v4Index++));
        takeV6 = !takeV6;
    }
    m_providerIpAttemptIndex = 0;
    beginProviderIpAttempt(providerIndex);
}

void PostTunnelReceiptVerifier::beginProviderIpAttempt(int providerIndex)
{
    if (!m_active.isValid() || providerIndex != m_providerIndex
        || m_providerIpAttemptIndex < 0
        || m_providerIpAttemptIndex >= m_providerIpAttempts.size()) {
        m_providerInfrastructureUnavailable = true;
        m_providerInfrastructureReason =
            QStringLiteral("receipt_all_bootstrap_ips_unavailable");
        if (providerIndex + 1 < m_authority.providers.size()) {
            beginProvider(providerIndex + 1);
            if (m_lookupId < 0)
                complete(VerificationDisposition::InfrastructureUnavailable,
                         ConnectionFailureStage::VerificationDns,
                         QStringLiteral("receipt_dns_dispatch_unavailable"));
        } else {
            complete(m_observedEgressIds.isEmpty()
                         ? VerificationDisposition::CandidateFailed
                         : VerificationDisposition::InfrastructureUnavailable,
                     ConnectionFailureStage::VerificationTraffic,
                     m_observedEgressIds.isEmpty()
                         ? QStringLiteral("receipt_all_providers_unavailable")
                         : m_providerInfrastructureReason);
        }
        return;
    }
    const ReceiptVerificationProvider provider = m_authority.providers.at(providerIndex);
    const QString pinnedIp = m_providerIpAttempts.at(m_providerIpAttemptIndex);
    const VerificationToken verification = m_active;
    const QString nonce = freshNonce();
    const QJsonObject body{
        {QStringLiteral("schema_version"), 1},
        {QStringLiteral("nonce"), nonce},
        {QStringLiteral("provider_id"), provider.id},
        {QStringLiteral("device_audience"), m_authority.deviceAudience},
        {QStringLiteral("profile_id"), m_candidate.profileId},
        {QStringLiteral("binding_generation"),
         double(m_candidate.nativeProfile.bindingGeneration)},
        {QStringLiteral("config_generation"),
         double(m_candidate.nativeProfile.configGeneration)},
        {QStringLiteral("context"), m_candidate.verification.context},
        {QStringLiteral("min_probe_bytes"), m_minimumProbeBytes},
    };
    // Connect to the exact protected IP snapshot while keeping TLS SNI/certificate verification
    // and HTTP Host bound to the signed authority FQDN. This closes the QHostInfo→QNAM re-resolve
    // TOCTOU and proves the peer route was one compiled into the local tunnel policy.
    QUrl pinnedEndpoint = provider.endpoint;
    pinnedEndpoint.setHost(pinnedIp);
    QNetworkRequest request(pinnedEndpoint);
    QByteArray hostHeader = provider.endpoint.host().toLatin1();
    if (provider.endpoint.port(-1) != -1 && provider.endpoint.port(-1) != 443)
        hostHeader += ':' + QByteArray::number(provider.endpoint.port());
    request.setRawHeader(QByteArrayLiteral("Host"), hostHeader);
    QSslConfiguration ssl = QSslConfiguration::defaultConfiguration();
    ssl.setPeerVerifyMode(QSslSocket::VerifyPeer);
    request.setSslConfiguration(ssl);
    request.setPeerVerifyName(provider.endpoint.host());
    request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
    request.setRawHeader(QByteArrayLiteral("Accept"), QByteArrayLiteral("application/json"));
    request.setRawHeader(QByteArrayLiteral("Authorization"),
                         QByteArrayLiteral("Bearer ") + m_authority.verificationToken);
    request.setRawHeader(QByteArrayLiteral("Cache-Control"), QByteArrayLiteral("no-store"));
    request.setRawHeader(QByteArrayLiteral("Pragma"), QByteArrayLiteral("no-cache"));
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                         QNetworkRequest::ManualRedirectPolicy);
    request.setAttribute(QNetworkRequest::Http2AllowedAttribute, false);
    request.setTransferTimeout(m_timeoutMs);
    m_phase = Phase::RequestingReceipt;
    if (providerIndex == 0 && m_providerIpAttemptIndex == 0)
        stage(PostTunnelVerificationStage::Traffic);
    QNetworkAccessManager *network = m_networkFactory(this);
    if (!network || network->parent() != this) {
        if (network) network->deleteLater();
        complete(VerificationDisposition::InfrastructureUnavailable,
                 ConnectionFailureStage::VerificationTraffic,
                 QStringLiteral("receipt_ephemeral_network_unavailable"));
        return;
    }
    network->setProxy(QNetworkProxy::NoProxy);
    m_network = network;
    QNetworkReply *reply = m_network->post(
        request, QJsonDocument(body).toJson(QJsonDocument::Compact));
    if (!reply) {
        complete(VerificationDisposition::InfrastructureUnavailable,
                 ConnectionFailureStage::VerificationTraffic,
                 QStringLiteral("receipt_dispatch_unavailable"));
        return;
    }
    m_reply = reply;
    m_responseBody.clear();
    reply->setReadBufferSize(192 * 1024 + 1);
    reply->setProperty("receipt_pinned_ip", pinnedIp);
    reply->setProperty("receipt_authority_host", provider.endpoint.host());
    connect(reply, &QIODevice::readyRead, this,
            [this, reply, verification, providerIndex]() {
                consumeReplyBody(reply, verification, providerIndex);
            });
    connect(reply, &QNetworkReply::finished, this,
            [this, reply, verification, providerIndex, nonce]() {
                onReplyFinished(reply, verification, providerIndex, nonce);
            });
}

void PostTunnelReceiptVerifier::onReplyFinished(QNetworkReply *reply,
                                                 VerificationToken verification,
                                                 int providerIndex, QString requestNonce)
{
    if (!reply || reply != m_reply || verification != m_active
        || m_phase != Phase::RequestingReceipt || providerIndex != m_providerIndex) {
        if (reply) reply->deleteLater();
        return;
    }
    if (!consumeReplyBody(reply, verification, providerIndex))
        return;
    m_reply.clear();
    QPointer<QNetworkAccessManager> finishedNetwork = m_network;
    m_network.clear();
    const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    const bool redirect = reply->attribute(QNetworkRequest::RedirectionTargetAttribute).isValid()
                          || (status >= 300 && status < 400);
    const QString pinnedIp = reply->property("receipt_pinned_ip").toString();
    QHostAddress replyAddress;
    const bool pinnedPeer = replyAddress.setAddress(reply->url().host())
                            && replyAddress.toString() == pinnedIp;
    const QVariant length = reply->header(QNetworkRequest::ContentLengthHeader);
    const bool oversized = length.isValid() && length.toLongLong() > 192 * 1024;
    QByteArray envelope = oversized ? QByteArray() : std::move(m_responseBody);
    const bool transportOk = reply->error() == QNetworkReply::NoError;
    const bool httpReached = status >= 100 && status <= 599;
    const bool headersOk = exactNoStore(reply);
    const QByteArray contentType = reply->rawHeader(QByteArrayLiteral("Content-Type"))
                                       .trimmed().toLower();
    ReceiptHttpFailure httpFailure;
    if (!httpReached) {
        reply->deleteLater();
        if (finishedNetwork) finishedNetwork->deleteLater();
        envelope.fill('\0');
        if (++m_providerIpAttemptIndex < m_providerIpAttempts.size()) {
            beginProviderIpAttempt(providerIndex);
            return;
        }
        m_providerInfrastructureUnavailable = true;
        m_providerInfrastructureReason =
            QStringLiteral("receipt_all_bootstrap_ips_unavailable");
        if (providerIndex + 1 < m_authority.providers.size()) {
            beginProvider(providerIndex + 1);
            if (m_lookupId < 0)
                complete(VerificationDisposition::InfrastructureUnavailable,
                         ConnectionFailureStage::VerificationDns,
                         QStringLiteral("receipt_dns_dispatch_unavailable"));
        } else {
            complete(m_observedEgressIds.isEmpty()
                         ? VerificationDisposition::CandidateFailed
                         : VerificationDisposition::InfrastructureUnavailable,
                     ConnectionFailureStage::VerificationTraffic,
                     m_observedEgressIds.isEmpty()
                         ? QStringLiteral("receipt_all_providers_unavailable")
                         : m_providerInfrastructureReason);
        }
        return;
    }
    // Qt reports ordinary HTTP 4xx/5xx responses through Content*/Server*
    // QNetworkReply errors.  A status code is nevertheless proof that the
    // pinned provider answered; parse its closed typed-error contract before
    // considering transport retries.  Requiring NoError here made the 409,
    // 429 and 503 policy branches unreachable in production.
    const bool typedFailure = status != 200 && !redirect && pinnedPeer && headersOk
                              && contentType == QByteArrayLiteral("application/json")
                              && !envelope.isEmpty() && envelope.size() <= 4096
                              && parseReceiptHttpFailure(status, envelope, reply, httpFailure);
    reply->deleteLater();
    if (finishedNetwork) finishedNetwork->deleteLater();
    if (typedFailure) {
        complete(httpFailure.disposition,
                 httpFailure.disposition == VerificationDisposition::InfrastructureUnavailable
                     ? ConnectionFailureStage::VerificationTraffic
                     : ConnectionFailureStage::VerificationAuthority,
                 httpFailure.reason, {}, -1, httpFailure.retryAfterSeconds);
        return;
    }
    // Once any HTTP response was received, an unrecognized/malformed non-200
    // response is an authority protocol violation, not evidence that every
    // signed bootstrap IP is unreachable.  Only a 200 response may continue
    // into the success-envelope path below.
    if (status != 200) {
        envelope.fill('\0');
        complete(VerificationDisposition::AuthorityRejected,
                 ConnectionFailureStage::VerificationAuthority,
                 QStringLiteral("receipt_http_protocol_invalid"));
        return;
    }
    if (!transportOk) {
        envelope.fill('\0');
        if (++m_providerIpAttemptIndex < m_providerIpAttempts.size()) {
            beginProviderIpAttempt(providerIndex);
            return;
        }
        complete(VerificationDisposition::CandidateFailed,
                 ConnectionFailureStage::VerificationTraffic,
                 QStringLiteral("receipt_all_bootstrap_ips_unavailable"));
        return;
    }
    if (!transportOk || redirect || !pinnedPeer || status != 200 || !headersOk
        || contentType != QByteArrayLiteral("application/json")
        || envelope.isEmpty() || envelope.size() > 192 * 1024) {
        complete(VerificationDisposition::AuthorityRejected,
                 ConnectionFailureStage::VerificationAuthority,
                 QStringLiteral("receipt_http_protocol_invalid"));
        return;
    }
    VerifiedSignedEnvelope verified;
    QString verifyError;
    SignedEnvelopeLimits limits;
    limits.maximumEnvelopeBytes = 192 * 1024;
    limits.maximumPayloadBytes = 128 * 1024;
    if (!verifyPurposeSignedEnvelope(envelope, QByteArrayLiteral("tribe-receipt-v1\n"),
                                     m_authority.providers.at(providerIndex).receiptPublicKeysHex,
                                     verified, verifyError,
                                     limits)) {
        complete(VerificationDisposition::TrustRefreshRequired,
                 ConnectionFailureStage::VerificationTrust,
                 QStringLiteral("receipt_signature_invalid"));
        return;
    }
    QJsonDocument document;
    if (!parseStrictJsonDocument(verified.exactPayload, document, verifyError,
                                 limits.maximumPayloadBytes) || !document.isObject()) {
        complete(VerificationDisposition::TrustRefreshRequired,
                 ConnectionFailureStage::VerificationTrust,
                 QStringLiteral("receipt_payload_invalid"));
        return;
    }
    const QJsonObject payload = document.object();
    const QSet<QString> keys{
        QStringLiteral("schema_version"), QStringLiteral("nonce"),
        QStringLiteral("provider_id"), QStringLiteral("device_audience"),
        QStringLiteral("profile_id"),
        QStringLiteral("binding_generation"), QStringLiteral("config_generation"),
        QStringLiteral("context"),
        QStringLiteral("observed_egress_id"), QStringLiteral("issued_at"),
        QStringLiteral("expires_at"), QStringLiteral("probe_bytes"),
        QStringLiteral("probe_sha256")};
    quint64 bindingGeneration = 0, configGeneration = 0;
    QDateTime issuedAt, expiresAt;
    QByteArray probe, expectedHash;
    const QString egress = payload.value(QStringLiteral("observed_egress_id")).toString();
    const QDateTime now = m_clock->nowUtc().toUTC();
    const bool fieldsOk = exactKeys(payload, keys)
        && payload.value(QStringLiteral("schema_version")).isDouble()
        && payload.value(QStringLiteral("schema_version")).toDouble() == 1.0
        && payload.value(QStringLiteral("nonce")).toString() == requestNonce
        && payload.value(QStringLiteral("provider_id")).toString()
               == m_authority.providers.at(providerIndex).id
        && payload.value(QStringLiteral("device_audience")).toString()
               == m_authority.deviceAudience
        && payload.value(QStringLiteral("profile_id")).toString() == m_candidate.profileId
        && uintField(payload, QStringLiteral("binding_generation"), bindingGeneration)
        && bindingGeneration == m_candidate.nativeProfile.bindingGeneration
        && uintField(payload, QStringLiteral("config_generation"), configGeneration)
        && configGeneration == m_candidate.nativeProfile.configGeneration
        && payload.value(QStringLiteral("context")).toString()
               == m_candidate.verification.context
        && safeEgressId(egress) && utcField(payload, QStringLiteral("issued_at"), issuedAt)
        && utcField(payload, QStringLiteral("expires_at"), expiresAt)
        && now.isValid()
        && issuedAt <= now.addSecs(kReceiptMaximumFutureIssuedSkewSeconds)
        && expiresAt > now
        && issuedAt < expiresAt
        && issuedAt.secsTo(expiresAt) <= kReceiptMaximumLifetimeSeconds
        && canonicalToken(payload.value(QStringLiteral("probe_bytes")), probe,
                          m_minimumProbeBytes, 65536)
        && canonicalToken(payload.value(QStringLiteral("probe_sha256")), expectedHash, 32, 32)
        && QCryptographicHash::hash(probe, QCryptographicHash::Sha256) == expectedHash;
    if (!fieldsOk) {
        complete(VerificationDisposition::CatalogStale,
                 ConnectionFailureStage::VerificationAuthority,
                 QStringLiteral("receipt_binding_invalid"));
        return;
    }
    if (!m_authority.expiresAt.isValid() || m_authority.expiresAt.toUTC() <= now) {
        complete(VerificationDisposition::InfrastructureUnavailable,
                 ConnectionFailureStage::VerificationAuthority,
                 QStringLiteral("receipt_authority_expired_during_probe"));
        return;
    }
    const QDateTime providerProofDeadline = qMin(expiresAt,
                                                 m_authority.expiresAt.toUTC());
    if (providerProofDeadline <= now) {
        complete(VerificationDisposition::InfrastructureUnavailable,
                 ConnectionFailureStage::VerificationAuthority,
                 QStringLiteral("receipt_freshness_elapsed_during_probe"));
        return;
    }
    m_receiptExpiresAt = !m_receiptExpiresAt.isValid()
                             ? providerProofDeadline
                             : qMin(m_receiptExpiresAt, providerProofDeadline);
    if (!m_candidate.verification.expectedEgressIds.contains(egress)) {
        complete(VerificationDisposition::CandidateFailed,
                 ConnectionFailureStage::VerificationEgress,
                 QStringLiteral("receipt_egress_mismatch"), egress);
        return;
    }
    m_observedEgressIds.append(egress);
    if (providerIndex + 1 < m_authority.providers.size()) {
        beginProvider(providerIndex + 1);
        if (m_lookupId < 0)
            complete(VerificationDisposition::InfrastructureUnavailable,
                     ConnectionFailureStage::VerificationDns,
                     QStringLiteral("receipt_dns_dispatch_unavailable"));
        return;
    }
    if (m_providerInfrastructureUnavailable) {
        complete(VerificationDisposition::InfrastructureUnavailable,
                 ConnectionFailureStage::VerificationTraffic,
                 m_providerInfrastructureReason.isEmpty()
                     ? QStringLiteral("receipt_provider_infrastructure_unavailable")
                     : m_providerInfrastructureReason);
        return;
    }
    if (m_observedEgressIds.size() != 2
        || m_observedEgressIds.at(0) != m_observedEgressIds.at(1)) {
        complete(VerificationDisposition::CandidateFailed,
                 ConnectionFailureStage::VerificationEgress,
                 QStringLiteral("receipt_quorum_disagreed"));
        return;
    }
    complete(VerificationDisposition::Verified, ConnectionFailureStage::None,
             QString(), m_observedEgressIds.first(), m_elapsed.elapsed());
}

bool PostTunnelReceiptVerifier::consumeReplyBody(QNetworkReply *reply,
                                                 VerificationToken verification,
                                                 int providerIndex)
{
    constexpr qint64 maximum = 192 * 1024;
    if (!reply || reply != m_reply || verification != m_active
        || m_phase != Phase::RequestingReceipt || providerIndex != m_providerIndex)
        return false;
    while (reply->bytesAvailable() > 0) {
        const qint64 remaining = maximum + 1 - m_responseBody.size();
        if (remaining <= 0) {
            complete(VerificationDisposition::AuthorityRejected,
                     ConnectionFailureStage::VerificationAuthority,
                     QStringLiteral("receipt_body_oversized"));
            return false;
        }
        const QByteArray chunk = reply->read(qMin(remaining, reply->bytesAvailable()));
        if (chunk.isEmpty() && reply->bytesAvailable() > 0) {
            complete(VerificationDisposition::CandidateFailed,
                     ConnectionFailureStage::VerificationTraffic,
                     QStringLiteral("receipt_body_read_failed"));
            return false;
        }
        m_responseBody += chunk;
        if (m_responseBody.size() > maximum) {
            complete(VerificationDisposition::AuthorityRejected,
                     ConnectionFailureStage::VerificationAuthority,
                     QStringLiteral("receipt_body_oversized"));
            return false;
        }
    }
    return true;
}

void PostTunnelReceiptVerifier::complete(VerificationDisposition disposition,
                                         ConnectionFailureStage failureStage,
                                         const QString &reason, const QString &egress,
                                         qint64 latencyMs, int retryAfterSeconds,
                                         VerificationRetryDirective retryDirective)
{
    if (!m_active.isValid()) return;
    const VerificationToken token = m_active;
    const QDateTime verifiedUntil = disposition == VerificationDisposition::Verified
                                        ? m_receiptExpiresAt.toUTC() : QDateTime();
    resetActive();
    if (disposition == VerificationDisposition::InfrastructureUnavailable
        && retryDirective == VerificationRetryDirective::None)
        retryDirective = VerificationRetryDirective::RetrySameAuthority;
    const PostTunnelVerificationResult result{
        token, disposition, failureStage, reason, egress, latencyMs, retryAfterSeconds,
        verifiedUntil, retryDirective};
    QTimer::singleShot(0, this, [this, result]() {
        if (m_observer) m_observer->onPostTunnelVerification(result);
    });
}

void PostTunnelReceiptVerifier::stage(PostTunnelVerificationStage value)
{
    const VerificationToken token = m_active;
    const quint64 epoch = m_callbackEpoch;
    QTimer::singleShot(0, this, [this, token, value, epoch]() {
        if (m_observer && epoch == m_callbackEpoch)
            m_observer->onPostTunnelVerificationStage(token, value);
    });
}

void PostTunnelReceiptVerifier::resetActive()
{
    m_timer->stop();
    if (m_lookupId >= 0 && m_dnsAbort) m_dnsAbort(m_lookupId);
    m_lookupId = -1;
    if (m_reply) {
        QNetworkReply *reply = m_reply;
        m_reply.clear();
        disconnect(reply, nullptr, this, nullptr);
        reply->abort();
        reply->deleteLater();
    }
    if (m_network) {
        QNetworkAccessManager *network = m_network;
        m_network.clear();
        network->deleteLater();
    }
    m_active = {};
    m_candidate = {};
    m_phase = Phase::Idle;
    m_providerIndex = -1;
    m_providerIpAttempts.clear();
    m_providerIpAttemptIndex = -1;
    m_observedEgressIds.clear();
    m_providerInfrastructureUnavailable = false;
    m_providerInfrastructureReason.clear();
    m_receiptExpiresAt = {};
    m_responseBody.fill('\0');
    m_responseBody.clear();
}

} // namespace avpn
