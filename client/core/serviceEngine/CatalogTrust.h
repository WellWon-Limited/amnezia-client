// Tribe serviceEngine v2 — pure anti-downgrade, freshness and LKG policy.
#pragma once

#include "dto/Catalog.h"

#include <QByteArray>
#include <QDateTime>
#include <QHash>
#include <QString>

namespace avpn {

enum class CatalogSource {
    Network = 0,
    LastKnownGood,
};

struct CatalogTrustState {
    bool hasAcceptedV2 = false;
    QString deviceAudience; // opaque signed value, atomically pinned with this trust state
    quint64 highestCatalogRevision = 0;
    quint64 highestDeviceRevocationEpoch = 0;
    quint64 highestKeyEpoch = 0;
    quint64 highestPolicyRevision = 0;
    QHash<QString, quint64> highestConfigGenerationByProfile;
    QHash<QString, quint64> highestBindingGenerationByProfile;
    QByteArray payloadSha256AtHighestRevision;
};

struct CatalogTrustLimits {
    int allowedClockSkewS = 300;
    int maximumOfflineGraceS = 72 * 60 * 60;
};

enum class CatalogTrustError {
    None = 0,
    InvalidClock,
    InvalidPayloadDigest,
    InvalidPersistedState,
    MissingLkgTrustState,
    FutureIssuedAt,
    Expired,
    EntitlementExpired,
    RevisionDowngrade,
    RevisionCollision,
    RevocationEpochDowngrade,
    KeyEpochDowngrade,
    PolicyRevisionDowngrade,
    ConfigGenerationDowngrade,
    BindingGenerationDowngrade,
    AudienceMismatch,
};

struct CatalogTrustVerdict {
    bool accepted = false;
    CatalogTrustError error = CatalogTrustError::None;
    QString detail;
    CatalogTrustState nextState;
    QDateTime freshnessDeadline;
};

struct CatalogRuntimeAuthority {
    CatalogSource source = CatalogSource::Network;
    QString deviceAudience;
    quint64 catalogRevision = 0;
    QByteArray payloadSha256;
    QDateTime freshnessDeadline;
    QDateTime entitlementDeadline;
    QString catalogSigningKeyId;
    QDateTime issuedAt;
};

inline bool canonicalCatalogTrustAudience(const QString &value)
{
    const QByteArray encoded = value.toLatin1();
    if (encoded.size() != 43 || QString::fromLatin1(encoded) != value)
        return false;
    const auto decoded = QByteArray::fromBase64Encoding(
        encoded, QByteArray::Base64UrlEncoding | QByteArray::AbortOnBase64DecodingErrors);
    return decoded.decodingStatus == QByteArray::Base64DecodingStatus::Ok
           && decoded.decoded.size() == 32
           && decoded.decoded.toBase64(QByteArray::Base64UrlEncoding
                                       | QByteArray::OmitTrailingEquals) == encoded;
}

inline QDateTime catalogFreshnessDeadline(const Catalog &catalog, CatalogSource source,
                                          CatalogTrustLimits limits = {})
{
    const int clockSkewS = qBound(0, limits.allowedClockSkewS, 15 * 60);
    const int localGraceS = qBound(0, limits.maximumOfflineGraceS, 7 * 24 * 60 * 60);
    QDateTime deadline = catalog.expiresAt.toUTC().addSecs(clockSkewS);
    if (source == CatalogSource::LastKnownGood) {
        const int signedGraceS = qBound(0, catalog.policy.offlineGraceS, localGraceS);
        deadline = deadline.addSecs(signedGraceS);
    }
    return deadline;
}

inline CatalogRuntimeAuthority runtimeAuthorityForAcceptedCatalog(
    const Catalog &catalog, CatalogSource source, const CatalogTrustVerdict &verdict)
{
    return {source, catalog.deviceAudience, catalog.catalogRevision, catalog.payloadSha256,
            verdict.freshnessDeadline, catalog.entitlementExpiresAt.toUTC(),
            catalog.signingKeyId, catalog.issuedAt.toUTC()};
}

inline CatalogTrustVerdict evaluateCatalogTrust(const Catalog &catalog,
                                                const CatalogTrustState &current,
                                                CatalogSource source,
                                                const QDateTime &nowUtc,
                                                CatalogTrustLimits limits = {})
{
    CatalogTrustVerdict verdict;
    verdict.nextState = current;
    const QDateTime now = nowUtc.toUTC();
    const int clockSkewS = qBound(0, limits.allowedClockSkewS, 15 * 60);

    auto reject = [&](CatalogTrustError code, const QString &detail) {
        verdict.error = code;
        verdict.detail = detail;
        return verdict;
    };

    if (!nowUtc.isValid())
        return reject(CatalogTrustError::InvalidClock,
                      QStringLiteral("trusted wall clock is unavailable"));
    if (catalog.payloadSha256.size() != 32)
        return reject(CatalogTrustError::InvalidPayloadDigest,
                      QStringLiteral("catalog payload digest is missing"));
    if (current.hasAcceptedV2
        && (!canonicalCatalogTrustAudience(current.deviceAudience)
            || current.highestCatalogRevision == 0
            || current.payloadSha256AtHighestRevision.size() != 32))
        return reject(CatalogTrustError::InvalidPersistedState,
                      QStringLiteral("persisted catalog trust state is incomplete"));
    if (!current.hasAcceptedV2
        && (!current.deviceAudience.isEmpty() || current.highestCatalogRevision != 0
            || current.highestDeviceRevocationEpoch != 0
            || current.highestKeyEpoch != 0 || current.highestPolicyRevision != 0
            || !current.payloadSha256AtHighestRevision.isEmpty()
            || !current.highestConfigGenerationByProfile.isEmpty()
            || !current.highestBindingGenerationByProfile.isEmpty()))
        return reject(CatalogTrustError::InvalidPersistedState,
                      QStringLiteral("persisted catalog trust state is inconsistent"));
    if (source == CatalogSource::LastKnownGood && !current.hasAcceptedV2)
        return reject(CatalogTrustError::MissingLkgTrustState,
                      QStringLiteral("LKG cannot be used without its atomic trust state"));

    if (catalog.issuedAt > now.addSecs(clockSkewS))
        return reject(CatalogTrustError::FutureIssuedAt,
                      QStringLiteral("catalog issued_at is in the future"));

    const QDateTime freshnessDeadline = catalogFreshnessDeadline(catalog, source, limits);
    verdict.freshnessDeadline = freshnessDeadline;

    // Monotonic authority is checked even for expired persisted material. Otherwise an old or
    // collision payload could disguise a rollback as normal cold-start expiry and reach online
    // recovery without proving the durable high-water/tombstones it is supposed to preserve.
    if (current.hasAcceptedV2) {
        if (catalog.deviceAudience != current.deviceAudience)
            return reject(CatalogTrustError::AudienceMismatch,
                          QStringLiteral("catalog device audience mismatch"));
        if (catalog.catalogRevision < current.highestCatalogRevision)
            return reject(CatalogTrustError::RevisionDowngrade,
                          QStringLiteral("catalog revision downgrade"));
        if (catalog.catalogRevision == current.highestCatalogRevision
            && !current.payloadSha256AtHighestRevision.isEmpty()
            && catalog.payloadSha256 != current.payloadSha256AtHighestRevision) {
            return reject(CatalogTrustError::RevisionCollision,
                          QStringLiteral("different payload reused an accepted catalog revision"));
        }
        if (catalog.deviceRevocationEpoch < current.highestDeviceRevocationEpoch)
            return reject(CatalogTrustError::RevocationEpochDowngrade,
                          QStringLiteral("device revocation epoch downgrade"));
        if (catalog.keyEpoch < current.highestKeyEpoch)
            return reject(CatalogTrustError::KeyEpochDowngrade,
                          QStringLiteral("catalog key epoch downgrade"));
        if (catalog.policyRevision < current.highestPolicyRevision)
            return reject(CatalogTrustError::PolicyRevisionDowngrade,
                          QStringLiteral("catalog policy revision downgrade"));
        for (const CatalogLocation &location : catalog.locations) {
            for (const CatalogCandidate &candidate : location.candidates) {
                if (candidate.nativeProfile.configGeneration
                    < current.highestConfigGenerationByProfile.value(candidate.profileId, 0))
                    return reject(CatalogTrustError::ConfigGenerationDowngrade,
                                  QStringLiteral("native config generation downgrade"));
                if (candidate.nativeProfile.bindingGeneration
                    < current.highestBindingGenerationByProfile.value(candidate.profileId, 0))
                    return reject(CatalogTrustError::BindingGenerationDowngrade,
                                  QStringLiteral("device binding generation downgrade"));
            }
        }
    }

    // A signed entitlement is the hard authority. Offline grace may extend catalog freshness,
    // never the paid/revoked entitlement itself. These normal lifecycle failures are deliberately
    // classified only after all persisted monotonic invariants have passed.
    if (now >= catalog.entitlementExpiresAt)
        return reject(CatalogTrustError::EntitlementExpired,
                      QStringLiteral("catalog entitlement has expired"));
    if (now >= freshnessDeadline)
        return reject(CatalogTrustError::Expired,
                      source == CatalogSource::LastKnownGood
                          ? QStringLiteral("catalog LKG is outside signed offline grace")
                          : QStringLiteral("network catalog has expired"));

    verdict.accepted = true;
    verdict.nextState.hasAcceptedV2 = true;
    verdict.nextState.deviceAudience = catalog.deviceAudience;
    verdict.nextState.highestCatalogRevision =
        qMax(current.highestCatalogRevision, catalog.catalogRevision);
    verdict.nextState.highestDeviceRevocationEpoch =
        qMax(current.highestDeviceRevocationEpoch, catalog.deviceRevocationEpoch);
    verdict.nextState.highestKeyEpoch = qMax(current.highestKeyEpoch, catalog.keyEpoch);
    verdict.nextState.highestPolicyRevision =
        qMax(current.highestPolicyRevision, catalog.policyRevision);
    for (const CatalogLocation &location : catalog.locations) {
        for (const CatalogCandidate &candidate : location.candidates) {
            verdict.nextState.highestConfigGenerationByProfile[candidate.profileId] = qMax(
                current.highestConfigGenerationByProfile.value(candidate.profileId, 0),
                candidate.nativeProfile.configGeneration);
            verdict.nextState.highestBindingGenerationByProfile[candidate.profileId] = qMax(
                current.highestBindingGenerationByProfile.value(candidate.profileId, 0),
                candidate.nativeProfile.bindingGeneration);
        }
    }
    if (catalog.catalogRevision > current.highestCatalogRevision
        || current.payloadSha256AtHighestRevision.isEmpty()) {
        verdict.nextState.payloadSha256AtHighestRevision = catalog.payloadSha256;
    }
    return verdict;
}

// The storage implementation must provide an atomic encrypted write. Deliberately no QSettings
// implementation lives here: current SecureQSettings encrypts only an allow-listed legacy key,
// while a v2 catalog contains Xray bearer credentials and must fail closed if secure storage is
// unavailable. Every load is fed back through signature + trust verification.
struct CatalogLkgRecord {
    // Durable monotonic endpoint tombstone. It may be true without a connectable envelope after a
    // schema-valid authenticated 403/410/426/etc.; this alone permanently closes unsigned v1.
    bool authoritativeV2EndpointSeen = false;
    // Schema v4 may intentionally keep this empty while retaining a non-empty safe trustState:
    // that credential-free authority tombstone preserves every accepted high-water after expiry,
    // signer omission/revocation, or a crash between key rotation and fresh resolve. Such a
    // catalog high-water tombstone is valid only with a parsed root-keyset state and complete
    // signed+observed trusted clock. A pre-catalog endpoint-only tombstone has empty trustState and
    // may canonically omit both artifacts.
    QByteArray verifiedEnvelope;
    CatalogTrustState trustState;
    // Exact accepted root-signed keyset state, serialized by CatalogKeyset. It is intentionally
    // opaque here to keep the trust/store boundary acyclic and is authenticated in the same AEAD
    // record as the envelope and audience/revision state.
    QByteArray acceptedKeysetState;
    // Bounded, redacted generation-scoped selector history and idempotent outcome queue. This is
    // opaque to the trust layer, but belongs in the same authenticated record so a file replay
    // cannot selectively resurrect an old cooldown/outcome view.
    QByteArray runtimeState;
};

enum class CatalogLkgLoadStatus {
    Empty = 0,
    Loaded,
    Error,
};

class ICatalogLkgStore {
public:
    virtual ~ICatalogLkgStore() = default;
    // Envelope and monotonic trust state form one authenticated-encrypted record. Loading only
    // one half after a crash would reopen revision/epoch rollback, so implementations must never
    // expose partial state.
    virtual CatalogLkgLoadStatus load(CatalogLkgRecord &record, QString &error) const = 0;
    virtual bool replaceAtomically(const CatalogLkgRecord &record, QString &error) = 0;
    virtual bool clear(QString &error) = 0;
};

} // namespace avpn
