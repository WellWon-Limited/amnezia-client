#include "CatalogKeyset.h"

#include "SignedEnvelope.h"

#include <QCryptographicHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>

#include <algorithm>
#include <cmath>

namespace avpn {
namespace {

constexpr quint64 kMaxSafeJsonInteger = 9007199254740991ULL;

QString purposeName(CatalogSigningPurpose purpose)
{
    return purpose == CatalogSigningPurpose::Catalog ? QStringLiteral("catalog")
                                                      : QStringLiteral("receipt");
}

bool parsePurpose(const QJsonValue &value, CatalogSigningPurpose &purpose)
{
    if (!value.isString()) return false;
    if (value.toString() == QLatin1String("catalog")) {
        purpose = CatalogSigningPurpose::Catalog;
        return true;
    }
    if (value.toString() == QLatin1String("receipt")) {
        purpose = CatalogSigningPurpose::Receipt;
        return true;
    }
    return false;
}

QString keyIdentity(CatalogSigningPurpose purpose, const QString &kid,
                    const QString &authority = {})
{
    return purpose == CatalogSigningPurpose::Catalog
        ? purposeName(purpose) + QLatin1Char('/') + kid
        : purposeName(purpose) + QLatin1Char('/') + authority + QLatin1Char('/') + kid;
}

bool uintField(const QJsonObject &object, const QString &key, quint64 &out)
{
    const QJsonValue value = object.value(key);
    if (!value.isDouble()) return false;
    const double number = value.toDouble();
    if (!std::isfinite(number) || number < 1 || number > double(kMaxSafeJsonInteger)
        || std::floor(number) != number) return false;
    out = quint64(number); return true;
}

bool utcField(const QJsonObject &object, const QString &key, QDateTime &out)
{
    if (!object.value(key).isString()) return false;
    const QString text = object.value(key).toString();
    if (!text.endsWith(QLatin1Char('Z'))) return false;
    out = QDateTime::fromString(text, Qt::ISODateWithMs);
    if (!out.isValid()) out = QDateTime::fromString(text, Qt::ISODate);
    if (!out.isValid()) return false;
    out = out.toUTC(); return true;
}

bool safeAuthorityId(const QString &value)
{
    static const QRegularExpression re(QStringLiteral("^[a-z][a-z0-9.-]{2,63}$"));
    return re.match(value).hasMatch();
}

bool safeKeyIdentity(const QString &value)
{
    const QStringList parts = value.split(QLatin1Char('/'));
    if (parts.size() == 2 && parts.at(0) == QLatin1String("catalog"))
        return canonicalSigningKeyId(parts.at(1));
    return parts.size() == 3 && parts.at(0) == QLatin1String("receipt")
           && safeAuthorityId(parts.at(1)) && canonicalSigningKeyId(parts.at(2));
}

bool safeReason(const QString &value)
{
    static const QRegularExpression re(QStringLiteral("^[a-z][a-z0-9_.-]{0,63}$"));
    return re.match(value).hasMatch();
}

bool canonicalPublicKey(const QString &value, QString &hex, QByteArray &fingerprint)
{
    const QByteArray encoded = value.toLatin1();
    if (encoded.size() != 43 || QString::fromLatin1(encoded) != value
        || value.contains(QLatin1Char('='))) return false;
    const auto decoded = QByteArray::fromBase64Encoding(
        encoded, QByteArray::Base64UrlEncoding | QByteArray::AbortOnBase64DecodingErrors);
    if (decoded.decodingStatus != QByteArray::Base64DecodingStatus::Ok
        || decoded.decoded.size() != 32
        || decoded.decoded.toBase64(QByteArray::Base64UrlEncoding
                                    | QByteArray::OmitTrailingEquals) != encoded) return false;
    hex = QString::fromLatin1(decoded.decoded.toHex());
    fingerprint = QCryptographicHash::hash(decoded.decoded, QCryptographicHash::Sha256);
    return true;
}

bool exactKeys(const QJsonObject &object, const QSet<QString> &keys)
{
    if (object.size() != keys.size()) return false;
    for (auto it = object.constBegin(); it != object.constEnd(); ++it)
        if (!keys.contains(it.key())) return false;
    return true;
}

CatalogKeysetAcceptance reject(CatalogKeysetError error, const QString &detail)
{
    CatalogKeysetAcceptance result; result.error = error; result.detail = detail; return result;
}

bool safeCurrentState(const CatalogKeysetTrustState &state, int maximum)
{
    if (state.highestEpoch == 0)
        return state.payloadSha256AtHighestEpoch.isEmpty() && state.acceptedEnvelope.isEmpty()
               && state.keyFingerprints.isEmpty() && state.keyEpochs.isEmpty()
               && state.keyAuthorities.isEmpty() && state.revokedIdentities.isEmpty();
    if (state.highestEpoch > kMaxSafeJsonInteger
        || state.payloadSha256AtHighestEpoch.size() != 32 || state.acceptedEnvelope.isEmpty()
        || state.keyFingerprints.isEmpty() || state.keyFingerprints.size() > maximum
        || QSet<QString>(state.keyFingerprints.keyBegin(), state.keyFingerprints.keyEnd())
               != QSet<QString>(state.keyEpochs.keyBegin(), state.keyEpochs.keyEnd())
        || QSet<QString>(state.keyFingerprints.keyBegin(), state.keyFingerprints.keyEnd())
               != QSet<QString>(state.keyAuthorities.keyBegin(), state.keyAuthorities.keyEnd())
        || state.revokedIdentities.size() > maximum) return false;
    for (auto it = state.keyFingerprints.constBegin(); it != state.keyFingerprints.constEnd(); ++it)
        if (!safeKeyIdentity(it.key()) || it.value().size() != 32
            || state.keyEpochs.value(it.key()) == 0
            || state.keyEpochs.value(it.key()) > kMaxSafeJsonInteger
            || (!state.keyAuthorities.value(it.key()).isEmpty()
                && !safeAuthorityId(state.keyAuthorities.value(it.key())))
            || (it.key().startsWith(QLatin1String("receipt/"))
                != !state.keyAuthorities.value(it.key()).isEmpty())) return false;
    for (const QString &item : state.revokedIdentities)
        if (!safeKeyIdentity(item)) return false;
    return true;
}

bool decodeCanonical(const QJsonValue &value, QByteArray &out, int exact, int maximum = -1)
{
    if (!value.isString() || value.toString().contains(QLatin1Char('='))) return false;
    const QByteArray encoded = value.toString().toLatin1();
    if (QString::fromLatin1(encoded) != value.toString()) return false;
    const auto decoded = QByteArray::fromBase64Encoding(
        encoded, QByteArray::Base64UrlEncoding | QByteArray::AbortOnBase64DecodingErrors);
    if (decoded.decodingStatus != QByteArray::Base64DecodingStatus::Ok
        || (exact >= 0 && decoded.decoded.size() != exact)
        || (maximum >= 0 && decoded.decoded.size() > maximum)
        || decoded.decoded.toBase64(QByteArray::Base64UrlEncoding
                                    | QByteArray::OmitTrailingEquals) != encoded) return false;
    out = decoded.decoded; return true;
}

} // namespace

CatalogKeysetAcceptance acceptCatalogKeysetEnvelope(
    const QByteArray &envelope, const QHash<QString, QString> &bundledRootKeysHex,
    const CatalogKeysetTrustState &current, const QDateTime &trustedNowUtc,
    CatalogKeysetLimits limits, CatalogKeysetAcceptanceMode mode)
{
    const int trackedLimit = qBound(1, limits.maximumTrackedKeys, 256);
    if (!trustedNowUtc.isValid() || bundledRootKeysHex.isEmpty())
        return reject(CatalogKeysetError::Time,
                      QStringLiteral("trusted keyset clock/root unavailable"));
    if (!safeCurrentState(current, trackedLimit))
        return reject(CatalogKeysetError::PersistedState,
                      QStringLiteral("keyset trust state is inconsistent"));
    VerifiedSignedEnvelope verified;
    QString verifyError;
    SignedEnvelopeLimits envelopeLimits;
    envelopeLimits.maximumEnvelopeBytes = qBound(4096, limits.maximumEnvelopeBytes, 512 * 1024);
    envelopeLimits.maximumPayloadBytes = envelopeLimits.maximumEnvelopeBytes;
    if (!verifyPurposeSignedEnvelope(envelope, QByteArrayLiteral("tribe-keyset-v1\n"),
                                     bundledRootKeysHex, verified, verifyError, envelopeLimits))
        return reject(CatalogKeysetError::Signature, verifyError);
    QJsonDocument document;
    if (!parseStrictJsonDocument(verified.exactPayload, document, verifyError,
                                 envelopeLimits.maximumPayloadBytes) || !document.isObject())
        return reject(CatalogKeysetError::Parse, QStringLiteral("keyset payload JSON invalid"));
    const QJsonObject root = document.object();
    const QSet<QString> rootKeys{QStringLiteral("schema_version"), QStringLiteral("keyset_epoch"),
                                 QStringLiteral("issued_at"), QStringLiteral("not_before"),
                                 QStringLiteral("expires_at"), QStringLiteral("keys"),
                                 QStringLiteral("revoked")};
    CatalogKeysetManifest manifest;
    quint64 schemaVersion = 0;
    if (!exactKeys(root, rootKeys)
        || !uintField(root, QStringLiteral("schema_version"), schemaVersion)
        || schemaVersion != 1
        || !uintField(root, QStringLiteral("keyset_epoch"), manifest.epoch)
        || !utcField(root, QStringLiteral("issued_at"), manifest.issuedAt)
        || !utcField(root, QStringLiteral("not_before"), manifest.notBefore)
        || !utcField(root, QStringLiteral("expires_at"), manifest.expiresAt)
        || !root.value(QStringLiteral("keys")).isArray()
        || !root.value(QStringLiteral("revoked")).isArray())
        return reject(CatalogKeysetError::Parse, QStringLiteral("keyset payload fields invalid"));
    const QDateTime now = trustedNowUtc.toUTC();
    const int skew = qBound(0, limits.allowedClockSkewS, 15 * 60);
    if (manifest.issuedAt > manifest.notBefore || manifest.notBefore >= manifest.expiresAt
        || manifest.issuedAt > now.addSecs(skew) || manifest.notBefore > now.addSecs(skew))
        return reject(CatalogKeysetError::Time, QStringLiteral("keyset validity window rejected"));
    const bool manifestExpired = manifest.expiresAt <= now;
    if (manifestExpired && mode == CatalogKeysetAcceptanceMode::Online)
        return reject(CatalogKeysetError::Expired, QStringLiteral("keyset has expired"));
    const QJsonArray keys = root.value(QStringLiteral("keys")).toArray();
    const QJsonArray revoked = root.value(QStringLiteral("revoked")).toArray();
    if (keys.isEmpty() || keys.size() > qBound(1, limits.maximumKeys, 128)
        || revoked.size() > qBound(0, limits.maximumRevocations, 256))
        return reject(CatalogKeysetError::Parse, QStringLiteral("keyset arrays outside bounds"));

    CatalogKeysetTrustState next = current;
    QSet<QString> manifestIds;
    QSet<quint64> catalogEpochs;
    QHash<QString, QSet<quint64>> receiptEpochsByAuthority;
    QHash<QString, int> receiptCountByAuthority;
    QSet<QString> globalKids;
    int catalogKeyCount = 0;
    int receiptKeyCount = 0;
    QString previousIdentity;
    const QSet<QString> entryRequired{QStringLiteral("purpose"), QStringLiteral("kid"),
                                      QStringLiteral("public_key"), QStringLiteral("key_epoch"),
                                      QStringLiteral("not_before"), QStringLiteral("not_after")};
    const QSet<QString> entryOptional{QStringLiteral("authority_id")};
    for (const QJsonValue &value : keys) {
        if (!value.isObject())
            return reject(CatalogKeysetError::Parse, QStringLiteral("keyset entry shape invalid"));
        const QJsonObject object = value.toObject();
        for (const QString &field : entryRequired)
            if (!object.contains(field))
                return reject(CatalogKeysetError::Parse,
                              QStringLiteral("keyset entry shape invalid"));
        for (auto field = object.constBegin(); field != object.constEnd(); ++field)
            if (!entryRequired.contains(field.key()) && !entryOptional.contains(field.key()))
                return reject(CatalogKeysetError::Parse,
                              QStringLiteral("keyset entry shape invalid"));
        CatalogKeysetEntry entry;
        entry.kid = object.value(QStringLiteral("kid")).toString();
        entry.authorityId = object.value(QStringLiteral("authority_id")).toString();
        QString publicHex;
        QByteArray fingerprint;
        if (!parsePurpose(object.value(QStringLiteral("purpose")), entry.purpose)
            || !canonicalSigningKeyId(entry.kid)
            || !canonicalPublicKey(object.value(QStringLiteral("public_key")).toString(),
                                   publicHex, fingerprint)
            || !uintField(object, QStringLiteral("key_epoch"), entry.keyEpoch)
            || entry.keyEpoch > manifest.epoch
            || !utcField(object, QStringLiteral("not_before"), entry.notBefore)
            || !utcField(object, QStringLiteral("not_after"), entry.notAfter)
            || entry.notBefore >= entry.notAfter || entry.notBefore < manifest.notBefore
            || entry.notAfter > manifest.expiresAt
            || (entry.purpose == CatalogSigningPurpose::Catalog
                && object.contains(QStringLiteral("authority_id")))
            || (entry.purpose == CatalogSigningPurpose::Receipt
                && (!object.contains(QStringLiteral("authority_id"))
                    || !safeAuthorityId(entry.authorityId))))
            return reject(CatalogKeysetError::Parse, QStringLiteral("keyset entry value invalid"));
        if (globalKids.contains(entry.kid))
            return reject(CatalogKeysetError::Parse,
                          QStringLiteral("signing kids must be globally unique"));
        globalKids.insert(entry.kid);
        const QString itemIdentity = keyIdentity(entry.purpose, entry.kid, entry.authorityId);
        if (manifestIds.contains(itemIdentity)
            || (!previousIdentity.isEmpty() && itemIdentity <= previousIdentity))
            return reject(CatalogKeysetError::Parse,
                          QStringLiteral("keyset entries are duplicate/noncanonical order"));
        previousIdentity = itemIdentity;
        manifestIds.insert(itemIdentity);
        QSet<quint64> &purposeEpochs = entry.purpose == CatalogSigningPurpose::Catalog
            ? catalogEpochs : receiptEpochsByAuthority[entry.authorityId];
        if (purposeEpochs.contains(entry.keyEpoch))
            return reject(CatalogKeysetError::EpochCollision,
                          QStringLiteral("duplicate key epoch within signing purpose"));
        purposeEpochs.insert(entry.keyEpoch);
        if (entry.purpose == CatalogSigningPurpose::Catalog) ++catalogKeyCount;
        else {
            ++receiptKeyCount;
            ++receiptCountByAuthority[entry.authorityId];
        }
        if (next.keyFingerprints.contains(itemIdentity)
            && (next.keyFingerprints.value(itemIdentity) != fingerprint
                || next.keyEpochs.value(itemIdentity) != entry.keyEpoch
                || next.keyAuthorities.value(itemIdentity) != entry.authorityId))
            return reject(CatalogKeysetError::EpochCollision,
                          QStringLiteral("signing kid bytes/epoch reused"));
        for (auto existing = next.keyFingerprints.constBegin();
             existing != next.keyFingerprints.constEnd(); ++existing)
            if (existing.key() != itemIdentity && existing.value() == fingerprint)
                return reject(CatalogKeysetError::EpochCollision,
                              QStringLiteral("signing key bytes reused across identities/purposes"));
        next.keyFingerprints.insert(itemIdentity, fingerprint);
        next.keyEpochs.insert(itemIdentity, entry.keyEpoch);
        next.keyAuthorities.insert(itemIdentity, entry.authorityId);
        entry.publicKeyHex = publicHex;
        manifest.keys.append(entry);
    }
    if (catalogKeyCount < 1 || catalogKeyCount > 2
        || receiptKeyCount < 2 || receiptKeyCount > 4
        || receiptCountByAuthority.size() != 2)
        return reject(CatalogKeysetError::Parse,
                      QStringLiteral("keyset requires one/two keys per exact signing authority"));
    for (auto count = receiptCountByAuthority.constBegin();
         count != receiptCountByAuthority.constEnd(); ++count)
        if (count.value() < 1 || count.value() > 2)
            return reject(CatalogKeysetError::Parse,
                          QStringLiteral("receipt authority key overlap is outside bounds"));
    if (next.keyFingerprints.size() > trackedLimit)
        return reject(CatalogKeysetError::PersistedState,
                      QStringLiteral("monotonic key history exceeds local bound"));

    QSet<QString> manifestRevoked;
    previousIdentity.clear();
    const QSet<QString> revokeRequired{QStringLiteral("purpose"), QStringLiteral("kid"),
                                       QStringLiteral("revoked_at"), QStringLiteral("reason_code")};
    const QSet<QString> revokeOptional{QStringLiteral("authority_id")};
    for (const QJsonValue &value : revoked) {
        if (!value.isObject())
            return reject(CatalogKeysetError::Parse, QStringLiteral("revocation shape invalid"));
        const QJsonObject object = value.toObject();
        for (const QString &field : revokeRequired)
            if (!object.contains(field))
                return reject(CatalogKeysetError::Parse,
                              QStringLiteral("revocation shape invalid"));
        for (auto field = object.constBegin(); field != object.constEnd(); ++field)
            if (!revokeRequired.contains(field.key()) && !revokeOptional.contains(field.key()))
                return reject(CatalogKeysetError::Parse,
                              QStringLiteral("revocation shape invalid"));
        CatalogKeysetRevocation item;
        item.kid = object.value(QStringLiteral("kid")).toString();
        item.authorityId = object.value(QStringLiteral("authority_id")).toString();
        item.reasonCode = object.value(QStringLiteral("reason_code")).toString();
        if (!parsePurpose(object.value(QStringLiteral("purpose")), item.purpose)
            || !canonicalSigningKeyId(item.kid) || !safeReason(item.reasonCode)
            || (item.purpose == CatalogSigningPurpose::Catalog
                && object.contains(QStringLiteral("authority_id")))
            || (item.purpose == CatalogSigningPurpose::Receipt
                && (!object.contains(QStringLiteral("authority_id"))
                    || !safeAuthorityId(item.authorityId)))
            || !utcField(object, QStringLiteral("revoked_at"), item.revokedAt)
            || item.revokedAt > manifest.issuedAt || item.revokedAt > now.addSecs(skew))
            return reject(CatalogKeysetError::Parse, QStringLiteral("revocation value invalid"));
        const QString itemIdentity = keyIdentity(item.purpose, item.kid, item.authorityId);
        if (manifestRevoked.contains(itemIdentity)
            || (!previousIdentity.isEmpty() && itemIdentity <= previousIdentity))
            return reject(CatalogKeysetError::Parse,
                          QStringLiteral("revocations are duplicate/noncanonical order"));
        previousIdentity = itemIdentity;
        manifestRevoked.insert(itemIdentity);
        manifest.revocations.append(item);
    }
    for (const QString &revokedIdentity : current.revokedIdentities)
        if (!manifestRevoked.contains(revokedIdentity))
            return reject(CatalogKeysetError::EpochDowngrade,
                          QStringLiteral("previous signing-key revocation was removed"));
    next.revokedIdentities.unite(manifestRevoked);
    if (next.revokedIdentities.size() > trackedLimit)
        return reject(CatalogKeysetError::PersistedState,
                      QStringLiteral("revocation history exceeds local bound"));

    const QByteArray digest = QCryptographicHash::hash(
        verified.exactPayload, QCryptographicHash::Sha256);
    if (manifest.epoch < current.highestEpoch)
        return reject(CatalogKeysetError::EpochDowngrade, QStringLiteral("keyset epoch downgrade"));
    if (manifest.epoch == current.highestEpoch && !current.payloadSha256AtHighestEpoch.isEmpty()
        && digest != current.payloadSha256AtHighestEpoch)
        return reject(CatalogKeysetError::EpochCollision,
                      QStringLiteral("keyset epoch collision"));

    CatalogAcceptedKeyrings keyrings;
    CatalogAcceptedKeyrings historicalKeyrings;
    keyrings.manifestEpoch = manifest.epoch;
    historicalKeyrings.manifestEpoch = manifest.epoch;
    for (const CatalogKeysetEntry &entry : manifest.keys) {
        const QString itemIdentity = keyIdentity(entry.purpose, entry.kid, entry.authorityId);
        if (next.revokedIdentities.contains(itemIdentity)) continue;
        if (entry.purpose == CatalogSigningPurpose::Catalog) {
            historicalKeyrings.catalog.publicKeysHex.insert(entry.kid, entry.publicKeyHex);
            historicalKeyrings.catalog.keyEpochs.insert(entry.kid, entry.keyEpoch);
        } else {
            historicalKeyrings.receiptPublicKeysHex.insert(entry.kid, entry.publicKeyHex);
            historicalKeyrings.receiptKeyEpochs.insert(entry.kid, entry.keyEpoch);
            historicalKeyrings.receiptAuthorityIds.insert(entry.kid, entry.authorityId);
        }
        if (now < entry.notBefore || now >= entry.notAfter) continue;
        if (entry.purpose == CatalogSigningPurpose::Catalog) {
            keyrings.catalog.publicKeysHex.insert(entry.kid, entry.publicKeyHex);
            keyrings.catalog.keyEpochs.insert(entry.kid, entry.keyEpoch);
        } else {
            keyrings.receiptPublicKeysHex.insert(entry.kid, entry.publicKeyHex);
            keyrings.receiptKeyEpochs.insert(entry.kid, entry.keyEpoch);
            keyrings.receiptAuthorityIds.insert(entry.kid, entry.authorityId);
        }
    }
    const auto overlapValid = [](const CatalogAcceptedKeyrings &candidate) {
        QHash<QString, int> receiptByAuthority;
        for (const QString &authority : candidate.receiptAuthorityIds)
            ++receiptByAuthority[authority];
        bool receiptValid = receiptByAuthority.size() == 2;
        for (auto count = receiptByAuthority.constBegin();
             count != receiptByAuthority.constEnd(); ++count)
            receiptValid = receiptValid && count.value() >= 1 && count.value() <= 2;
        return !candidate.catalog.publicKeysHex.isEmpty()
            && candidate.catalog.publicKeysHex.size() <= 2
            && candidate.receiptPublicKeysHex.size() >= 2
            && candidate.receiptPublicKeysHex.size() <= 4 && receiptValid;
    };
    manifest.exactEnvelope = envelope;
    manifest.payloadSha256 = digest;
    next.highestEpoch = manifest.epoch;
    next.payloadSha256AtHighestEpoch = digest;
    next.acceptedEnvelope = envelope;
    if (!overlapValid(keyrings)) {
        if (mode == CatalogKeysetAcceptanceMode::PersistedRecovery
            && overlapValid(historicalKeyrings)) {
            CatalogKeysetAcceptance result;
            result.recoverableExpired = true;
            result.error = CatalogKeysetError::Expired;
            result.detail = manifestExpired
                ? QStringLiteral("persisted keyset has expired")
                : QStringLiteral("persisted keyset has no currently usable signing overlap");
            result.manifest = manifest;
            result.nextState = next;
            result.persistedCatalogVerificationKeyring = historicalKeyrings.catalog;
            return result;
        }
        return reject(CatalogKeysetError::EmptyUsableKeyset,
                      QStringLiteral("active catalog/receipt signing overlap invalid"));
    }
    CatalogKeysetAcceptance result;
    result.accepted = true;
    result.manifest = manifest;
    result.keyrings = keyrings;
    result.nextState = next;
    result.persistedCatalogVerificationKeyring = historicalKeyrings.catalog;
    return result;
}

bool serializeCatalogKeysetTrustState(const CatalogKeysetTrustState &state,
                                      QByteArray &serialized, QString &error)
{
    serialized.clear(); error.clear();
    if (!safeCurrentState(state, 256)) {
        error = QStringLiteral("keyset trust state incomplete"); return false;
    }
    QJsonArray keys;
    QStringList identities = state.keyFingerprints.keys();
    std::sort(identities.begin(), identities.end());
    for (const QString &item : identities) {
        keys.append(QJsonObject{
            {QStringLiteral("identity"), item},
            {QStringLiteral("fingerprint"), QString::fromLatin1(
                 state.keyFingerprints.value(item).toBase64(
                     QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals))},
            {QStringLiteral("key_epoch"), double(state.keyEpochs.value(item))},
            {QStringLiteral("authority_id"), state.keyAuthorities.value(item)},
        });
    }
    QJsonArray revoked;
    QStringList revokedList = state.revokedIdentities.values();
    std::sort(revokedList.begin(), revokedList.end());
    for (const QString &item : revokedList) revoked.append(item);
    const QJsonObject root{
        {QStringLiteral("schema"), 2},
        {QStringLiteral("highest_epoch"), double(state.highestEpoch)},
        {QStringLiteral("payload_sha256"), QString::fromLatin1(
             state.payloadSha256AtHighestEpoch.toBase64(
                 QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals))},
        {QStringLiteral("accepted_envelope"), QString::fromLatin1(
             state.acceptedEnvelope.toBase64(
                 QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals))},
        {QStringLiteral("keys"), keys},
        {QStringLiteral("revoked"), revoked},
    };
    serialized = QJsonDocument(root).toJson(QJsonDocument::Compact); return true;
}

bool parseCatalogKeysetTrustState(const QByteArray &serialized,
                                  CatalogKeysetTrustState &state, QString &error)
{
    state = {}; error.clear();
    QJsonDocument document;
    const QSet<QString> rootKeys{QStringLiteral("schema"), QStringLiteral("highest_epoch"),
                                 QStringLiteral("payload_sha256"),
                                 QStringLiteral("accepted_envelope"),
                                 QStringLiteral("keys"), QStringLiteral("revoked")};
    quint64 schemaVersion = 0;
    if (!parseStrictJsonDocument(serialized, document, error, 256 * 1024)
        || !document.isObject() || !exactKeys(document.object(), rootKeys)
        || !uintField(document.object(), QStringLiteral("schema"), schemaVersion)
        || schemaVersion != 2
        || !uintField(document.object(), QStringLiteral("highest_epoch"), state.highestEpoch)
        || !document.object().value(QStringLiteral("keys")).isArray()
        || !document.object().value(QStringLiteral("revoked")).isArray()
        || !decodeCanonical(document.object().value(QStringLiteral("payload_sha256")),
                            state.payloadSha256AtHighestEpoch, 32)
        || !decodeCanonical(document.object().value(QStringLiteral("accepted_envelope")),
                            state.acceptedEnvelope, -1, 128 * 1024)
        || state.acceptedEnvelope.isEmpty()) {
        state = {}; error = QStringLiteral("serialized keyset trust state invalid"); return false;
    }
    QString previous;
    const QSet<QString> keyFields{QStringLiteral("identity"), QStringLiteral("fingerprint"),
                                  QStringLiteral("key_epoch"), QStringLiteral("authority_id")};
    for (const QJsonValue &value : document.object().value(QStringLiteral("keys")).toArray()) {
        if (!value.isObject() || !exactKeys(value.toObject(), keyFields)) {
            state = {}; error = QStringLiteral("serialized key history shape invalid"); return false;
        }
        const QJsonObject object = value.toObject();
        const QString item = object.value(QStringLiteral("identity")).toString();
        const QString authority = object.value(QStringLiteral("authority_id")).toString();
        QByteArray fingerprint;
        quint64 epoch = 0;
        if (!safeKeyIdentity(item) || (!previous.isEmpty() && item <= previous)
            || !decodeCanonical(object.value(QStringLiteral("fingerprint")), fingerprint, 32)
            || !uintField(object, QStringLiteral("key_epoch"), epoch)
            || (!authority.isEmpty() && !safeAuthorityId(authority))) {
            state = {}; error = QStringLiteral("serialized key history invalid"); return false;
        }
        previous = item;
        state.keyFingerprints.insert(item, fingerprint);
        state.keyEpochs.insert(item, epoch);
        state.keyAuthorities.insert(item, authority);
    }
    previous.clear();
    for (const QJsonValue &value : document.object().value(QStringLiteral("revoked")).toArray()) {
        const QString item = value.toString();
        if (!value.isString() || !safeKeyIdentity(item)
            || (!previous.isEmpty() && item <= previous)) {
            state = {}; error = QStringLiteral("serialized revocation history invalid"); return false;
        }
        previous = item;
        state.revokedIdentities.insert(item);
    }
    if (!safeCurrentState(state, 256)) {
        state = {}; error = QStringLiteral("serialized keyset state violates bounds"); return false;
    }
    return true;
}

} // namespace avpn
