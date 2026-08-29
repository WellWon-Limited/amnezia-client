// Focused host integration checks for the product coordinator/facade event boundary.
#include "../CatalogCoordinator.h"
#include "../CatalogSecureStore.h"
#include "../CatalogUserIntent.h"
#include "../LegacyNativeOwnershipPolicy.h"
#include "../NativeSessionGuardEvent.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDateTime>
#include <QDebug>
#include <QEventLoop>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QSettings>
#include <QTemporaryDir>
#include <QTimer>

#include <openssl/evp.h>

#include <cstring>
#include <tuple>
#include <utility>

using namespace avpn;

namespace {

int checks = 0;

void expect(bool condition, const char *message)
{
    ++checks;
    if (!condition) {
        qCritical().noquote() << "FAILED:" << message;
        std::abort();
    }
}

QByteArray fixtureBytes(const char *name)
{
    QFile file(QFileInfo(QString::fromUtf8(__FILE__)).absolutePath()
               + QStringLiteral("/fixtures/") + QString::fromLatin1(name));
    if (!file.open(QIODevice::ReadOnly)) return {};
    return file.readAll().trimmed();
}

QByteArray deterministicSigningPublicKeyHex(const QByteArray &seedLabel)
{
    const QByteArray seed = QCryptographicHash::hash(seedLabel, QCryptographicHash::Sha256);
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr,
        reinterpret_cast<const unsigned char *>(seed.constData()), size_t(seed.size()));
    QByteArray publicKey(32, Qt::Uninitialized);
    size_t publicKeySize = size_t(publicKey.size());
    const bool ok = key
        && EVP_PKEY_get_raw_public_key(
               key, reinterpret_cast<unsigned char *>(publicKey.data()), &publicKeySize) == 1
        && publicKeySize == 32;
    EVP_PKEY_free(key);
    return ok ? publicKey.toHex() : QByteArray{};
}

QByteArray signPurposePayloadForCoordinatorTest(const QJsonObject &payload,
                                                const QByteArray &seedLabel,
                                                const QByteArray &domain,
                                                const QString &kid)
{
    const QByteArray seed = QCryptographicHash::hash(seedLabel, QCryptographicHash::Sha256);
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr,
        reinterpret_cast<const unsigned char *>(seed.constData()), size_t(seed.size()));
    const QByteArray exactPayload = QJsonDocument(payload).toJson(QJsonDocument::Compact);
    const QByteArray encoded = exactPayload.toBase64(
        QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
    const QByteArray input = domain + kid.toUtf8() + '\n' + encoded;
    QByteArray signature(64, Qt::Uninitialized);
    size_t signatureSize = size_t(signature.size());
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    const bool signedOk = key && context
        && EVP_DigestSignInit(context, nullptr, nullptr, nullptr, key) == 1
        && EVP_DigestSign(
               context, reinterpret_cast<unsigned char *>(signature.data()), &signatureSize,
               reinterpret_cast<const unsigned char *>(input.constData()),
               size_t(input.size())) == 1;
    EVP_MD_CTX_free(context);
    EVP_PKEY_free(key);
    if (!signedOk || signatureSize != 64) return {};
    signature.resize(int(signatureSize));
    return QJsonDocument(QJsonObject{
        {QStringLiteral("alg"), QStringLiteral("Ed25519")},
        {QStringLiteral("kid"), kid},
        {QStringLiteral("payload"), QString::fromLatin1(encoded)},
        {QStringLiteral("signature"), QString::fromLatin1(signature.toBase64(
             QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals))},
    }).toJson(QJsonDocument::Compact);
}

QByteArray signCatalogPayloadForCoordinatorTest(const QJsonObject &payload)
{
    return signPurposePayloadForCoordinatorTest(
        payload, QByteArrayLiteral("tribe-dev-catalog-signing-seed"),
        QByteArrayLiteral("tribe-catalog-v2\n"), QStringLiteral("catalog-k1"));
}

enum class CatalogKeyTransitionForTest {
    Keep = 0,
    OmitOld,
    RevokeOld,
    OmitReceiptA,
    RevokeReceiptA,
    ExpireReceiptA,
};

QByteArray keysetEnvelopeForCoordinatorTest(quint64 epoch,
                                            const QDateTime &issuedAt,
                                            const QDateTime &expiresAt,
                                            CatalogKeyTransitionForTest transition
                                                = CatalogKeyTransitionForTest::Keep)
{
    const QJsonObject fixture = QJsonDocument::fromJson(
        fixtureBytes("keyset_v1_golden_envelope.json")).object();
    const auto decoded = QByteArray::fromBase64Encoding(
        fixture.value(QStringLiteral("payload")).toString().toLatin1(),
        QByteArray::Base64UrlEncoding | QByteArray::AbortOnBase64DecodingErrors);
    if (decoded.decodingStatus != QByteArray::Base64DecodingStatus::Ok) return {};
    QJsonObject payload = QJsonDocument::fromJson(decoded.decoded).object();
    const QString issued = issuedAt.toUTC().toString(Qt::ISODateWithMs);
    const QString expires = expiresAt.toUTC().toString(Qt::ISODateWithMs);
    payload.insert(QStringLiteral("keyset_epoch"), double(epoch));
    payload.insert(QStringLiteral("issued_at"), issued);
    payload.insert(QStringLiteral("not_before"), issued);
    payload.insert(QStringLiteral("expires_at"), expires);
    const QJsonArray fixtureKeys = payload.value(QStringLiteral("keys")).toArray();
    QJsonArray keys;
    for (const QJsonValue &value : fixtureKeys) {
        QJsonObject entry = value.toObject();
        if (entry.value(QStringLiteral("purpose")) == QLatin1String("catalog")
            && (transition == CatalogKeyTransitionForTest::OmitOld
                || transition == CatalogKeyTransitionForTest::RevokeOld)) {
            const QByteArray publicHex = deterministicSigningPublicKeyHex(
                QByteArrayLiteral("tribe-dev-catalog-signing-seed-v2"));
            entry.insert(QStringLiteral("kid"), QStringLiteral("catalog-k2"));
            entry.insert(QStringLiteral("key_epoch"), 2);
            entry.insert(QStringLiteral("public_key"), QString::fromLatin1(
                QByteArray::fromHex(publicHex).toBase64(
                    QByteArray::Base64UrlEncoding
                    | QByteArray::OmitTrailingEquals)));
        }
        const bool receiptA = entry.value(QStringLiteral("purpose"))
                                  == QLatin1String("receipt")
            && entry.value(QStringLiteral("authority_id")) == QLatin1String("edge-a")
            && entry.value(QStringLiteral("kid")) == QLatin1String("receipt-a-k1");
        if (receiptA
            && (transition == CatalogKeyTransitionForTest::OmitReceiptA
                || transition == CatalogKeyTransitionForTest::RevokeReceiptA)) {
            const QByteArray publicHex = deterministicSigningPublicKeyHex(
                QByteArrayLiteral("tribe-dev-receipt-a-signing-seed-v2"));
            entry.insert(QStringLiteral("kid"), QStringLiteral("receipt-a-k2"));
            entry.insert(QStringLiteral("key_epoch"), 2);
            entry.insert(QStringLiteral("public_key"), QString::fromLatin1(
                QByteArray::fromHex(publicHex).toBase64(
                    QByteArray::Base64UrlEncoding
                    | QByteArray::OmitTrailingEquals)));
        }
        entry.insert(QStringLiteral("not_before"), issued);
        entry.insert(QStringLiteral("not_after"), expires);
        if (receiptA && transition == CatalogKeyTransitionForTest::ExpireReceiptA) {
            entry.insert(QStringLiteral("not_after"),
                         issuedAt.addSecs(90).toUTC().toString(Qt::ISODateWithMs));
            keys.append(entry);
            QJsonObject replacement = entry;
            const QByteArray publicHex = deterministicSigningPublicKeyHex(
                QByteArrayLiteral("tribe-dev-receipt-a-signing-seed-v2"));
            replacement.insert(QStringLiteral("kid"), QStringLiteral("receipt-a-k2"));
            replacement.insert(QStringLiteral("key_epoch"), 2);
            replacement.insert(QStringLiteral("public_key"), QString::fromLatin1(
                QByteArray::fromHex(publicHex).toBase64(
                    QByteArray::Base64UrlEncoding
                    | QByteArray::OmitTrailingEquals)));
            replacement.insert(QStringLiteral("not_after"), expires);
            keys.append(replacement);
            continue;
        }
        keys.append(entry);
    }
    payload.insert(QStringLiteral("keys"), keys);
    QJsonArray revoked;
    if (transition == CatalogKeyTransitionForTest::RevokeOld) {
        revoked.append(QJsonObject{
            {QStringLiteral("purpose"), QStringLiteral("catalog")},
            {QStringLiteral("kid"), QStringLiteral("catalog-k1")},
            {QStringLiteral("revoked_at"), issued},
            {QStringLiteral("reason_code"), QStringLiteral("rotated")},
        });
    }
    revoked.append(QJsonObject{
        {QStringLiteral("purpose"), QStringLiteral("catalog")},
        {QStringLiteral("kid"), QStringLiteral("catalog-retired")},
        {QStringLiteral("revoked_at"), QStringLiteral("2026-08-01T00:00:00.000Z")},
        {QStringLiteral("reason_code"), QStringLiteral("rotated")},
    });
    if (transition == CatalogKeyTransitionForTest::RevokeReceiptA) {
        revoked.append(QJsonObject{
            {QStringLiteral("purpose"), QStringLiteral("receipt")},
            {QStringLiteral("kid"), QStringLiteral("receipt-a-k1")},
            {QStringLiteral("authority_id"), QStringLiteral("edge-a")},
            {QStringLiteral("revoked_at"), issued},
            {QStringLiteral("reason_code"), QStringLiteral("rotated")},
        });
    }
    payload.insert(QStringLiteral("revoked"), revoked);
    return signPurposePayloadForCoordinatorTest(
        payload, QByteArrayLiteral("tribe-dev-keyset-root-seed"),
        QByteArrayLiteral("tribe-keyset-v1\n"), QStringLiteral("root-test"));
}

QByteArray timedCatalogEnvelopeForCoordinatorTest(const QString &requestNonce,
                                                   quint64 revision,
                                                   const QDateTime &issuedAt,
                                                   const QByteArray &seedLabel =
                                                       QByteArrayLiteral(
                                                           "tribe-dev-catalog-signing-seed"),
                                                   const QString &signingKid =
                                                       QStringLiteral("catalog-k1"),
                                                   quint64 keyEpoch = 1)
{
    const QJsonObject fixture = QJsonDocument::fromJson(
        fixtureBytes("catalog_v2_golden_envelope.json")).object();
    const QByteArray encodedPayload = fixture.value(QStringLiteral("payload")).toString().toLatin1();
    const auto decoded = QByteArray::fromBase64Encoding(
        encodedPayload, QByteArray::Base64UrlEncoding
                            | QByteArray::AbortOnBase64DecodingErrors);
    if (decoded.decodingStatus != QByteArray::Base64DecodingStatus::Ok) return {};
    QJsonObject payload = QJsonDocument::fromJson(decoded.decoded).object();
    const QDateTime expiresAt = issuedAt.addSecs(60 * 60);
    payload.insert(QStringLiteral("catalog_revision"), double(revision));
    payload.insert(QStringLiteral("key_epoch"), double(keyEpoch));
    payload.insert(QStringLiteral("request_nonce"), requestNonce);
    payload.insert(QStringLiteral("issued_at"), issuedAt.toUTC().toString(Qt::ISODateWithMs));
    payload.insert(QStringLiteral("expires_at"),
                   expiresAt.toUTC().toString(Qt::ISODateWithMs));
    payload.insert(QStringLiteral("refresh_after"),
                   issuedAt.addSecs(16 * 60).toUTC().toString(Qt::ISODateWithMs));
    payload.insert(QStringLiteral("entitlement_expires_at"),
                   issuedAt.addDays(30).toUTC().toString(Qt::ISODateWithMs));
    QJsonArray locations = payload.value(QStringLiteral("locations")).toArray();
    for (int locationIndex = 0; locationIndex < locations.size(); ++locationIndex) {
        QJsonObject location = locations.at(locationIndex).toObject();
        QJsonArray candidates = location.value(QStringLiteral("candidates")).toArray();
        for (int candidateIndex = 0; candidateIndex < candidates.size(); ++candidateIndex) {
            QJsonObject candidate = candidates.at(candidateIndex).toObject();
            candidate.insert(QStringLiteral("health_observed_at"),
                             issuedAt.addSecs(-30).toUTC().toString(Qt::ISODateWithMs));
            QJsonObject native = candidate.value(QStringLiteral("native_profile")).toObject();
            native.insert(QStringLiteral("expires_at"),
                          expiresAt.toUTC().toString(Qt::ISODateWithMs));
            candidate.insert(QStringLiteral("native_profile"), native);
            candidates[candidateIndex] = candidate;
        }
        location.insert(QStringLiteral("candidates"), candidates);
        locations[locationIndex] = location;
    }
    payload.insert(QStringLiteral("locations"), locations);
    const auto tokenPart = [](const QByteArray &value) {
        return QString::fromLatin1(value.toBase64(
            QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
    };
    const QString verificationToken = QStringLiteral("v1.")
        + tokenPart(signingKid.toUtf8()) + QLatin1Char('.')
        + tokenPart(QByteArrayLiteral("{}")) + QLatin1Char('.')
        + tokenPart(QByteArray(64, 's'));
    payload.insert(QStringLiteral("extensions"), QJsonArray{QJsonObject{
        {QStringLiteral("id"), QStringLiteral("verification.providers_v1")},
        {QStringLiteral("critical"), true},
        {QStringLiteral("required_cap"), QStringLiteral("probe.egress_receipt_v1")},
        {QStringLiteral("value"), QJsonObject{
             {QStringLiteral("schema_version"), 1},
             {QStringLiteral("quorum"), 2},
             {QStringLiteral("verification_token"), verificationToken},
             {QStringLiteral("verification_token_expires_at"),
              issuedAt.addSecs(11 * 60).toUTC().toString(Qt::ISODateWithMs)},
             {QStringLiteral("providers"), QJsonArray{
                  QJsonObject{{QStringLiteral("id"), QStringLiteral("verifier-a")},
                              {QStringLiteral("trust_domain"), QStringLiteral("edge-a")},
                              {QStringLiteral("base_url"),
                               QStringLiteral("https://verify-a.example")},
                              {QStringLiteral("bootstrap_ips"),
                               QJsonArray{QStringLiteral("1.1.1.1")}},
                              {QStringLiteral("receipt_kid"),
                               QStringLiteral("receipt-a-k1")},
                              {QStringLiteral("receipt_key_epoch"), 1}},
                  QJsonObject{{QStringLiteral("id"), QStringLiteral("verifier-b")},
                              {QStringLiteral("trust_domain"), QStringLiteral("edge-b")},
                              {QStringLiteral("base_url"),
                               QStringLiteral("https://verify-b.example")},
                              {QStringLiteral("bootstrap_ips"),
                               QJsonArray{QStringLiteral("8.8.8.8")}},
                              {QStringLiteral("receipt_kid"),
                               QStringLiteral("receipt-b-k1")},
                              {QStringLiteral("receipt_key_epoch"), 1}},
              }},
         }},
    }});
    return signPurposePayloadForCoordinatorTest(
        payload, seedLabel, QByteArrayLiteral("tribe-catalog-v2\n"), signingKid);
}

QByteArray freshCatalogEnvelopeForCoordinatorTest(const QString &requestNonce,
                                                   quint64 revision)
{
    return timedCatalogEnvelopeForCoordinatorTest(
        requestNonce, revision,
        QDateTime::fromString(QStringLiteral("2026-08-28T11:59:00.000Z"),
                              Qt::ISODateWithMs));
}

QByteArray directoryCatalogEnvelopeForCoordinatorTest(
    const QString &requestNonce, quint64 revision,
    CatalogResolveSelection selection,
    bool retainOutOfScopeCredential = false)
{
    const QDateTime issuedAt = QDateTime::fromString(
        QStringLiteral("2026-08-28T11:59:00.000Z"), Qt::ISODateWithMs);
    const QByteArray base = timedCatalogEnvelopeForCoordinatorTest(
        requestNonce, revision, issuedAt);
    const QJsonObject outer = QJsonDocument::fromJson(base).object();
    const auto decoded = QByteArray::fromBase64Encoding(
        outer.value(QStringLiteral("payload")).toString().toLatin1(),
        QByteArray::Base64UrlEncoding
            | QByteArray::AbortOnBase64DecodingErrors);
    if (decoded.decodingStatus != QByteArray::Base64DecodingStatus::Ok) return {};
    QJsonObject payload = QJsonDocument::fromJson(decoded.decoded).object();

    QJsonArray credentialLocations;
    for (const QJsonValue &locationValue
         : payload.value(QStringLiteral("locations")).toArray()) {
        QJsonObject location = locationValue.toObject();
        if (!selection.locationId.isEmpty()
            && location.value(QStringLiteral("id")).toString()
                   != selection.locationId)
            continue;
        if (!retainOutOfScopeCredential
            && selection.transport != ConnectionMode::Auto) {
            QJsonArray candidates;
            const QString requiredTransport =
                catalogResolveTransportName(selection.transport);
            for (const QJsonValue &candidate
                 : location.value(QStringLiteral("candidates")).toArray()) {
                if (candidate.toObject().value(QStringLiteral("transport")).toString()
                    == requiredTransport)
                    candidates.append(candidate);
            }
            location.insert(QStringLiteral("candidates"), candidates);
        }
        credentialLocations.append(location);
    }
    payload.insert(QStringLiteral("locations"), credentialLocations);

    QJsonObject selectionObject{
        {QStringLiteral("transport"),
         catalogResolveTransportName(selection.transport)}};
    if (!selection.locationId.isEmpty())
        selectionObject.insert(QStringLiteral("location_id"), selection.locationId);
    const QString observedAt = issuedAt.addSecs(-30).toUTC().toString(
        Qt::ISODateWithMs);
    const QJsonArray transportSummaries{
        QJsonObject{{QStringLiteral("transport"), QStringLiteral("awg")},
                    {QStringLiteral("state"), QStringLiteral("selectable")},
                    {QStringLiteral("predicted_quality"), 0.91},
                    {QStringLiteral("observed_at"), observedAt}},
        QJsonObject{{QStringLiteral("transport"), QStringLiteral("xray")},
                    {QStringLiteral("state"), QStringLiteral("selectable")},
                    {QStringLiteral("predicted_quality"), 0.89},
                    {QStringLiteral("observed_at"), observedAt}},
    };
    const QJsonArray directoryLocations{
        QJsonObject{{QStringLiteral("id"), QStringLiteral("fi-hel")},
                    {QStringLiteral("country"), QStringLiteral("FI")},
                    {QStringLiteral("city"), QStringLiteral("HEL")},
                    {QStringLiteral("display_key"),
                     QStringLiteral("location.fi.hel")},
                    {QStringLiteral("transports"), transportSummaries}},
    };
    QJsonArray extensions = payload.value(QStringLiteral("extensions")).toArray();
    extensions.append(QJsonObject{
        {QStringLiteral("id"),
         QStringLiteral("catalog.location_directory_v1")},
        {QStringLiteral("critical"), true},
        {QStringLiteral("required_cap"),
         QStringLiteral("catalog.location_directory_v1")},
        {QStringLiteral("value"),
         QJsonObject{{QStringLiteral("schema_version"), 1},
                     {QStringLiteral("selection"), selectionObject},
                     {QStringLiteral("locations"), directoryLocations}}},
    });
    payload.insert(QStringLiteral("extensions"), extensions);
    return signCatalogPayloadForCoordinatorTest(payload);
}

class FakeClockSource final : public ICatalogClockSource {
public:
    QDateTime now = QDateTime::fromString(QStringLiteral("2026-08-28T12:00:00.000Z"),
                                         Qt::ISODateWithMs);
    qint64 monotonic = 1000;
    QDateTime wallUtc() const override { return now; }
    qint64 monotonicMs() const override { return monotonic; }
};

class FakeInventory final : public ICatalogRuntimeInventory {
public:
    mutable int calls = 0;
    bool available = true;
    bool snapshot(CatalogResolveRequest &request, PlatformCapabilities &capabilities,
                  QVariantList &versions, QString &error) const override
    {
        ++calls;
        error.clear();
        if (!available) {
            error = QStringLiteral("manifest_unavailable");
            return false;
        }
        request = {};
        request.app = {CatalogAppPlatform::Android, QStringLiteral("5.1.97"), 97,
                       QStringLiteral("arm64-v8a")};
        request.adapters.androidVpnService = QStringLiteral("1");
        request.engines.awg = CatalogEngineFact{QStringLiteral("awg-android"),
                                                QStringLiteral("3.1.20260814")};
        request.engines.xray = CatalogEngineFact{QStringLiteral("amnezia-libxray"),
                                                 QStringLiteral("1.0.3")};
        request.capabilities = {QStringLiteral("awg.random_trailers"),
                                QStringLiteral("awg.disable_cookies"),
                                QStringLiteral("xray.vless.reality.vision.tcp"),
                                QStringLiteral("tribe.guarded_settings_owner")};
        capabilities = {};
        capabilities.catalogSchemaMax = 2;
        capabilities.nativeProfileFormats = {QStringLiteral("tribe_native_profile_v1")};
        capabilities.containerConfigFormats = {
            QStringLiteral("amnezia_container_config_v1")};
        capabilities.profileKinds = {QStringLiteral("awg31"),
                                      QStringLiteral("xray_vless_reality_vision_tcp")};
        capabilities.transports = {TransportKind::Awg, TransportKind::Xray};
        capabilities.capabilities = QSet<QString>(request.capabilities.cbegin(),
                                                   request.capabilities.cend());
        versions = {QVariantMap{{QStringLiteral("transport"), QStringLiteral("awg")},
                                {QStringLiteral("version"), QStringLiteral("3.1.20260814")},
                                {QStringLiteral("adapter"), QStringLiteral("awg-android")}},
                    QVariantMap{{QStringLiteral("transport"), QStringLiteral("xray")},
                                {QStringLiteral("version"), QStringLiteral("1.0.3")},
                                {QStringLiteral("adapter"), QStringLiteral("amnezia-libxray")}}};
        return true;
    }
};

class FakeKeysetClient final : public ICatalogKeysetClient {
public:
    ICatalogKeysetFetchObserver *observer = nullptr;
    quint64 nextOperation = 1;
    int starts = 0;
    int cancels = 0;
    quint64 activeOperation = 0;
    void setObserver(ICatalogKeysetFetchObserver *value) override { observer = value; }
    void clearObserver(ICatalogKeysetFetchObserver *expected) override
    { if (observer == expected) observer = nullptr; }
    bool start(const QUrl &, quint64 &operation, QString &error) override
    {
        error.clear();
        ++starts;
        activeOperation = operation = nextOperation++;
        return true;
    }
    void cancel(quint64 operation) override
    { if (operation == activeOperation) { ++cancels; activeOperation = 0; } }
    void finish(CatalogKeysetFetchKind kind, quint64 operation,
                QByteArray envelope = {}, int retryAfterS = 0)
    {
        if (operation == activeOperation) activeOperation = 0;
        if (observer) observer->onCatalogKeysetFetchResult(
            CatalogKeysetFetchResult{operation, kind, std::move(envelope), retryAfterS});
    }
};

class FakeResolveClient final : public ICatalogResolveClient {
public:
    ICatalogResolveObserver *observer = nullptr;
    quint64 nextOperation = 1;
    CatalogResolveAttempt activeAttempt;
    CatalogResolveRequest lastRequest;
    QList<CatalogResolveRequest> requests;
    int starts = 0;
    int cancels = 0;
    void setObserver(ICatalogResolveObserver *value) override { observer = value; }
    void clearObserver(ICatalogResolveObserver *expected) override
    { if (observer == expected) observer = nullptr; }
    bool start(QUrl, QByteArray, CatalogResolveRequest request,
               CatalogResolveAttempt &attempt, QString &error) override
    {
        ++starts;
        error.clear();
        lastRequest = request;
        requests.append(request);
        const char nonceByte = char(0x40 + (nextOperation % 48));
        activeAttempt = {
            nextOperation++,
            QString::fromLatin1(
                QByteArray(32, nonceByte).toBase64(
                    QByteArray::Base64UrlEncoding
                    | QByteArray::OmitTrailingEquals)),
            request.selection.value_or(CatalogResolveSelection{}),
            request.selection.has_value()};
        attempt = activeAttempt;
        return true;
    }
    void cancel(quint64 operation) override
    { if (operation == activeAttempt.operation) { ++cancels; activeAttempt = {}; } }
    void finish(CatalogResolveResultKind kind, QByteArray envelope = {},
                bool authoritative = true, int retryAfterS = 0)
    {
        if (!observer || !activeAttempt.operation) return;
        const CatalogResolveAttempt completed = activeAttempt;
        activeAttempt = {};
        observer->onCatalogResolveResult({completed.operation, kind,
                                          kind == CatalogResolveResultKind::SignedCatalog ? 200 : 503,
                                          std::move(envelope), completed.requestNonce,
                                          kind == CatalogResolveResultKind::SignedCatalog
                                              ? QStringLiteral("ok")
                                              : QStringLiteral("temporarily_unavailable"),
                                          retryAfterS, 0, authoritative});
    }
};

class FakeOutcomeClient final : public ICatalogOutcomeClient {
public:
    ICatalogOutcomeUploadObserver *observer = nullptr;
    quint64 nextOperation = 1;
    quint64 activeOperation = 0;
    QString activeEventId;
    int starts = 0;
    int cancels = 0;
    CatalogOutcomeEvent lastEvent;
    void setObserver(ICatalogOutcomeUploadObserver *value) override { observer = value; }
    void clearObserver(ICatalogOutcomeUploadObserver *expected) override
    { if (observer == expected) observer = nullptr; }
    bool start(const QUrl &, QByteArray bearerToken, const CatalogOutcomeEvent &event,
               quint64 &operation, QString &error) override
    {
        error.clear();
        expect(bearerToken == QByteArrayLiteral("test-token-not-logged"),
               "outcome uploader receives current auth without persisting it");
        bearerToken.fill('\0');
        ++starts;
        activeOperation = operation = nextOperation++;
        activeEventId = event.eventId;
        lastEvent = event;
        return true;
    }
    void cancel(quint64 operation) override
    { if (operation == activeOperation) ++cancels; }
    void finish(CatalogOutcomeUploadKind kind, int retryAfter = 0,
                bool duplicate = false)
    {
        if (!observer || !activeOperation) return;
        const CatalogOutcomeUploadResult result{activeOperation, activeEventId, kind,
                                                 duplicate, retryAfter, {}};
        activeOperation = 0;
        activeEventId.clear();
        observer->onCatalogOutcomeUploadResult(result);
    }
};

class FakeStore final : public ICatalogLkgStore {
public:
    CatalogLkgLoadStatus status = CatalogLkgLoadStatus::Empty;
    CatalogLkgRecord loaded;
    mutable int loads = 0;
    int writes = 0;
    int clears = 0;
    bool failClear = false;
    bool failNextWrite = false;
    QList<CatalogLkgRecord> writeHistory;
    CatalogLkgLoadStatus load(CatalogLkgRecord &record, QString &error) const override
    {
        ++loads;
        record = loaded;
        if (status == CatalogLkgLoadStatus::Error)
            error = QStringLiteral("secure item locked");
        else
            error.clear();
        return status;
    }
    bool replaceAtomically(const CatalogLkgRecord &record, QString &error) override
    {
        ++writes;
        if (failNextWrite) {
            failNextWrite = false;
            error = QStringLiteral("injected atomic authority write failure");
            return false;
        }
        loaded = record;
        writeHistory.append(record);
        error.clear();
        return true;
    }
    bool clear(QString &error) override
    {
        ++clears;
        if (failClear) {
            error = QStringLiteral("secure tombstone rotation failed");
            return false;
        }
        loaded = {};
        error.clear();
        return true;
    }
};

class FakeVerifier final : public IReceiptAuthorityVerifier {
public:
    IPostTunnelVerificationObserver *observer = nullptr;
    void setObserver(IPostTunnelVerificationObserver *value) override { observer = value; }
    void clearObserver(IPostTunnelVerificationObserver *expected) override
    { if (observer == expected) observer = nullptr; }
    bool start(const CatalogCandidate &, VerificationToken, QString &error) override
    { error = QStringLiteral("not used"); return false; }
    void cancel(VerificationToken) override {}
    bool setAuthority(ReceiptVerifierAuthority, QString &error) override
    { error.clear(); return true; }
    void clearAuthority() override {}
};

class FakeAdapters final : public IProtectedTransportAdapters {
public:
    bool setProtectedTunnelIpLiterals(const QStringList &, QString &error) override
    { error.clear(); return true; }
};

class FakeReducer final : public IConnectionRuntimeReducer {
public:
    IConnectionReducerObserver *observer = nullptr;
    int connectCalls = 0;
    int reconcileCalls = 0;
    int disconnectCalls = 0;
    int verificationRetries = 0;
    int transportTimeouts = 0;
    int armTimeouts = 0;
    int releaseTimeouts = 0;
    int stopTimeouts = 0;
    int verificationTimeouts = 0;
    int recoveryReleased = 0;
    QHash<QString, CandidateHistory> history;
    void setObserver(IConnectionReducerObserver *value) override { observer = value; }
    void clearObserver(IConnectionReducerObserver *expected) override
    { if (observer == expected) observer = nullptr; }
    bool connectAcceptedCatalog(const Catalog &, QList<CatalogCandidate>,
                                const QHash<QString, CandidateHistory> &,
                                CandidateSelectionRequest,
                                const CatalogRuntimeAuthority &, QString &error) override
    { ++connectCalls; error.clear(); return true; }
    bool reconcileAcceptedCatalog(const Catalog &, QList<CatalogCandidate>,
                                  const QHash<QString, CandidateHistory> &,
                                  CandidateSelectionRequest,
                                  const CatalogRuntimeAuthority &, QString &error) override
    { ++reconcileCalls; error.clear(); return true; }
    void disconnect() override { ++disconnectCalls; }
    bool retryVerification(QString &error) override
    { ++verificationRetries; error.clear(); return true; }
    void onAuthorityDeadline(TransportOperationToken) override {}
    void onVerificationFreshnessDeadline(VerificationToken) override {}
    void onTransportTimeout(TransportOperationToken value) override
    { ++transportTimeouts; lastSession = value; }
    void onGuardArmTimeout(TransportOperationToken value, QByteArray policy) override
    { ++armTimeouts; lastSession = value; lastPolicy = std::move(policy); }
    void onGuardReleaseTimeout(TransportOperationToken value) override
    { ++releaseTimeouts; lastSession = value; }
    void onStopTimeout(TransportOperationToken value) override
    { ++stopTimeouts; lastSession = value; }
    void onVerificationTimeout(VerificationToken value) override
    { ++verificationTimeouts; lastVerification = value; }
    void onGuardRecoveryReleased(const ConnectionGuardEvent &) override
    { ++recoveryReleased; }
    const QHash<QString, CandidateHistory> &updatedHistory() const override { return history; }
    TransportOperationToken lastSession;
    VerificationToken lastVerification;
    QByteArray lastPolicy;
};

struct Harness {
    FakeClockSource source;
    CatalogTrustedClock clock{&source};
    FakeInventory inventory;
    FakeKeysetClient keyset;
    FakeResolveClient resolve;
    FakeStore store;
    FakeVerifier verifier;
    FakeAdapters adapters;
    FakeReducer reducer;
    CatalogConnectionFacade facade;
    CatalogCoordinatorConfig config;

    Harness()
    {
        config.apiBaseUrl = QUrl(QStringLiteral("https://api.tribevpn.example"));
        config.bundledRootPublicKeysHex.insert(
            QStringLiteral("root-k1"), QString(64, QLatin1Char('1')));
        config.bearerTokenProvider = [] { return QByteArrayLiteral("test-token-not-logged"); };
        config.initialNetworkClass = CatalogNetworkClass::Wifi;
        config.platformGuardAndRuntimeReady = true;
    }

    CatalogCoordinator make(QObject *parent = nullptr)
    {
        return CatalogCoordinator(config, &inventory, &keyset, &resolve, &store, &clock,
                                  &verifier, &adapters, &reducer, &facade, parent);
    }
};

void configureGoldenCatalogRoot(Harness &h)
{
    const auto decodedRoot = QByteArray::fromBase64Encoding(
        fixtureBytes("keyset_v1_golden_root_public_key.txt"),
        QByteArray::Base64UrlEncoding | QByteArray::AbortOnBase64DecodingErrors);
    expect(decodedRoot.decodingStatus == QByteArray::Base64DecodingStatus::Ok
               && decodedRoot.decoded.size() == 32,
           "test catalog root fixture is canonical");
    h.config.bundledRootPublicKeysHex = {
        {QStringLiteral("tribe-root-1"), QString::fromLatin1(decodedRoot.decoded.toHex())}};
}

void configureCoordinatorTestRoot(Harness &h)
{
    const QByteArray publicKey = deterministicSigningPublicKeyHex(
        QByteArrayLiteral("tribe-dev-keyset-root-seed"));
    expect(publicKey.size() == 64, "deterministic coordinator root key derives");
    h.config.bundledRootPublicKeysHex = {
        {QStringLiteral("root-test"), QString::fromLatin1(publicKey)}};
}

void acceptFreshTestCatalog(Harness &h, CatalogCoordinator &coordinator,
                            quint64 revision)
{
    QString error;
    expect(coordinator.requestConnect(error) && h.keyset.activeOperation != 0,
           "test coordinator starts signed discovery");
    const quint64 keysetOperation = h.keyset.activeOperation;
    h.keyset.finish(CatalogKeysetFetchKind::Artifact, keysetOperation,
                    fixtureBytes("keyset_v1_golden_envelope.json"));
    expect(h.resolve.activeAttempt.operation != 0,
           "accepted test keyset starts nonce-bound catalog resolve");
    const QByteArray envelope = freshCatalogEnvelopeForCoordinatorTest(
        h.resolve.activeAttempt.requestNonce, revision);
    expect(!envelope.isEmpty(), "fresh test catalog fixture signs");
    h.resolve.finish(CatalogResolveResultKind::SignedCatalog, envelope);
    expect(h.reducer.connectCalls == 1,
           "fresh test catalog reaches reducer exactly once");
}

void runEventLoopFor(int milliseconds)
{
    QEventLoop loop;
    QTimer::singleShot(milliseconds, &loop, &QEventLoop::quit);
    loop.exec();
}

class FakeFacadeActions final : public ICatalogConnectionActions {
public:
    int reselect = 0;
    int doctor = 0;
    int refresh = 0;
    bool requestConnectionMode(ConnectionMode, QString &error) override
    { error.clear(); return true; }
    bool requestLocationMode(const QString &, QString &error) override
    { error.clear(); return true; }
    bool requestCatalogRefresh(QString &error) override
    { ++refresh; error.clear(); return true; }
    bool requestConnect(QString &error) override { error.clear(); return true; }
    void requestDisconnect() override {}
    bool requestVerificationRetry(QString &error) override { error.clear(); return true; }
    bool requestReselect(QString &error) override { ++reselect; error.clear(); return true; }
    bool requestDoctor(QString &error) override { ++doctor; error.clear(); return true; }
};

struct ReceiptAttemptScript {
    QStringList pinnedHosts;
    QStringList nonces;
    QList<QJsonObject> requestBodies;
    QList<QByteArray> authorizationHeaders;
    int managers = 0;
};

struct ReceiptHttpFailureScript {
    int status = 0;
    QNetworkReply::NetworkError error = QNetworkReply::UnknownContentError;
    QByteArray body;
    int retryAfter = 0;
};

class ScriptedReceiptHttpFailureReply final : public QNetworkReply {
public:
    ScriptedReceiptHttpFailureReply(const QNetworkRequest &request,
                                    const ReceiptHttpFailureScript &script,
                                    QObject *parent)
        : QNetworkReply(parent), m_body(script.body)
    {
        setRequest(request);
        setUrl(request.url());
        setOperation(QNetworkAccessManager::PostOperation);
        setAttribute(QNetworkRequest::HttpStatusCodeAttribute, script.status);
        setRawHeader(QByteArrayLiteral("Cache-Control"),
                     QByteArrayLiteral("private, no-store, no-cache, max-age=0"));
        setRawHeader(QByteArrayLiteral("Pragma"), QByteArrayLiteral("no-cache"));
        setRawHeader(QByteArrayLiteral("Content-Encoding"), QByteArrayLiteral("identity"));
        setRawHeader(QByteArrayLiteral("Content-Type"),
                     QByteArrayLiteral("application/json"));
        setHeader(QNetworkRequest::ContentLengthHeader, m_body.size());
        if (script.retryAfter > 0)
            setRawHeader(QByteArrayLiteral("Retry-After"),
                         QByteArray::number(script.retryAfter));
        setError(script.error, QStringLiteral("injected Qt HTTP content error"));
        open(QIODevice::ReadOnly | QIODevice::Unbuffered);
        QTimer::singleShot(0, this, [this]() {
            if (m_aborted) return;
            if (!m_body.isEmpty()) emit readyRead();
            setFinished(true);
            emit errorOccurred(error());
            emit finished();
        });
    }

    void abort() override
    {
        m_aborted = true;
        setFinished(true);
    }

    qint64 bytesAvailable() const override
    {
        return (m_body.size() - m_offset) + QNetworkReply::bytesAvailable();
    }

protected:
    qint64 readData(char *data, qint64 maximum) override
    {
        if (m_offset >= m_body.size()) return -1;
        const qint64 count = qMin(maximum, qint64(m_body.size() - m_offset));
        memcpy(data, m_body.constData() + m_offset, size_t(count));
        m_offset += count;
        return count;
    }

private:
    QByteArray m_body;
    qint64 m_offset = 0;
    bool m_aborted = false;
};

class ScriptedReceiptHttpFailureNetwork final : public QNetworkAccessManager {
public:
    ScriptedReceiptHttpFailureNetwork(ReceiptHttpFailureScript script,
                                      QObject *parent)
        : QNetworkAccessManager(parent), m_script(std::move(script))
    {}

protected:
    QNetworkReply *createRequest(Operation operation, const QNetworkRequest &request,
                                 QIODevice *) override
    {
        if (operation != PostOperation) return nullptr;
        return new ScriptedReceiptHttpFailureReply(request, m_script, this);
    }

private:
    ReceiptHttpFailureScript m_script;
};

class ScriptedReceiptReply final : public QNetworkReply {
public:
    ScriptedReceiptReply(const QNetworkRequest &request, bool failTransport,
                         QObject *parent)
        : QNetworkReply(parent), m_failTransport(failTransport)
    {
        setRequest(request);
        setUrl(request.url());
        setOperation(QNetworkAccessManager::PostOperation);
        open(QIODevice::ReadOnly | QIODevice::Unbuffered);
        if (m_failTransport)
            setError(QNetworkReply::ConnectionRefusedError,
                     QStringLiteral("injected transport failure"));
        if (m_failTransport) {
            QTimer::singleShot(0, this, [this]() {
                if (m_aborted) return;
                setFinished(true);
                emit errorOccurred(error());
                emit finished();
            });
        }
    }
    void abort() override
    {
        m_aborted = true;
        setFinished(true);
    }
protected:
    qint64 readData(char *, qint64) override { return -1; }
private:
    bool m_failTransport = false;
    bool m_aborted = false;
};

class ScriptedReceiptNetwork final : public QNetworkAccessManager {
public:
    ScriptedReceiptNetwork(ReceiptAttemptScript *script, bool failTransport,
                           QObject *parent)
        : QNetworkAccessManager(parent), m_script(script), m_failTransport(failTransport)
    {}
protected:
    QNetworkReply *createRequest(Operation operation, const QNetworkRequest &request,
                                 QIODevice *outgoingData) override
    {
        if (operation != PostOperation || !m_script) return nullptr;
        m_script->pinnedHosts.append(request.url().host());
        const QByteArray body = outgoingData ? outgoingData->peek(16 * 1024) : QByteArray{};
        const QJsonObject object = QJsonDocument::fromJson(body).object();
        m_script->nonces.append(object.value(QStringLiteral("nonce")).toString());
        m_script->requestBodies.append(object);
        m_script->authorizationHeaders.append(
            request.rawHeader(QByteArrayLiteral("Authorization")));
        return new ScriptedReceiptReply(request, m_failTransport, this);
    }
private:
    ReceiptAttemptScript *m_script = nullptr;
    bool m_failTransport = false;
};

class ReceiptResultObserver final : public IPostTunnelVerificationObserver {
public:
    QList<PostTunnelVerificationResult> results;
    void onPostTunnelVerificationStage(VerificationToken,
                                       PostTunnelVerificationStage) override {}
    void onPostTunnelVerification(const PostTunnelVerificationResult &result) override
    { results.append(result); }
};

void cleanTrustedClockBootstrapPreservesRollbackFence()
{
    FakeClockSource source;
    CatalogTrustedClock clock(&source, 300, 300);
    QString error;
    expect(clock.restore({}, error) && clock.nowUtc() == source.now,
           "clean trusted clock bootstraps from wall+monotonic input");
    const CatalogTrustedClockState unsignedState = clock.stateForPersistence();
    expect(!unsignedState.highestSignedIssuedAtUtc.isValid()
               && !unsignedState.highestObservedWallUtc.isValid(),
           "unsigned bootstrap wall time is not persisted as signed authority");
    expect(clock.observeAcceptedSignedTime(source.now.addSecs(-60), error),
           "first accepted signed time establishes durable clock authority");
    const CatalogTrustedClockState signedState = clock.stateForPersistence();
    expect(signedState.highestSignedIssuedAtUtc.isValid()
               && signedState.highestObservedWallUtc == source.now,
           "signed and observed clock high-water persist as an inseparable pair");

    FakeClockSource rolled;
    rolled.now = source.now.addSecs(-301);
    CatalogTrustedClock restored(&rolled, 300, 300);
    expect(!restored.restore(signedState, error) && restored.rollbackDetected(),
           "clean bootstrap does not weaken persisted wall-clock rollback rejection");
}

void expiredPersistedAuthorityRecoversOnlyThroughFreshRoot()
{
    const QDateTime initialNow = QDateTime::fromString(
        QStringLiteral("2026-08-28T12:00:00.000Z"), Qt::ISODateWithMs);
    const QDateTime recoveryNow = QDateTime::fromString(
        QStringLiteral("2026-10-01T12:00:00.000Z"), Qt::ISODateWithMs);
    const QByteArray initialKeyset = keysetEnvelopeForCoordinatorTest(
        1,
        QDateTime::fromString(QStringLiteral("2026-08-01T00:00:00.000Z"),
                              Qt::ISODateWithMs),
        QDateTime::fromString(QStringLiteral("2026-09-30T00:00:00.000Z"),
                              Qt::ISODateWithMs));
    CatalogLkgRecord persisted;
    CatalogKeysetTrustState originalKeysetTrust;
    CatalogRuntimeState originalRuntime;
    {
        Harness seed;
        configureCoordinatorTestRoot(seed);
        seed.source.now = initialNow;
        CatalogCoordinator coordinator = seed.make();
        QString error;
        expect(coordinator.initialize(error), "expiry seed coordinator initializes");
        expect(coordinator.requestConnect(error), "expiry seed starts signed discovery");
        seed.keyset.finish(CatalogKeysetFetchKind::Artifact,
                           seed.keyset.activeOperation, initialKeyset);
        expect(seed.resolve.activeAttempt.operation != 0,
               "root-authenticated seed keyset starts resolve");
        seed.resolve.finish(
            CatalogResolveResultKind::SignedCatalog,
            timedCatalogEnvelopeForCoordinatorTest(
                seed.resolve.activeAttempt.requestNonce, 10,
                initialNow.addSecs(-60)));
        expect(seed.reducer.connectCalls == 1,
               "fresh seed authority is connectable before expiry");
        persisted = seed.store.loaded;
        expect(!persisted.verifiedEnvelope.isEmpty()
                   && !persisted.acceptedKeysetState.isEmpty()
                   && !persisted.runtimeState.isEmpty(),
               "seed persists catalog, keyset and trusted runtime atomically");
        expect(parseCatalogKeysetTrustState(
                   persisted.acceptedKeysetState, originalKeysetTrust, error)
                   && parseCatalogRuntimeState(
                       persisted.runtimeState, originalRuntime, error),
               "seed persisted trust records parse");
        expect(originalKeysetTrust.highestEpoch == 1
                   && originalKeysetTrust.revokedIdentities.contains(
                       QStringLiteral("catalog/catalog-retired"))
                   && originalRuntime.trustedClock.highestSignedIssuedAtUtc.isValid(),
               "seed contains key epoch, revocation tombstone and trusted-clock high-water");
    }

    {
        Harness current;
        configureCoordinatorTestRoot(current);
        current.source.now = initialNow.addSecs(5 * 60);
        current.store.status = CatalogLkgLoadStatus::Loaded;
        current.store.loaded = persisted;
        CatalogCoordinator coordinator = current.make();
        QString error;
        expect(coordinator.initialize(error) && current.facade.catalogAvailable(),
               "currently valid LKG restore remains unchanged and available");
        expect(coordinator.requestConnect(error)
                   && current.reducer.connectCalls == 1
                   && current.keyset.starts == 0,
               "currently valid LKG still connects offline without forced discovery");
    }

    for (const QDateTime &lifecycleNow : {
             initialNow.addDays(1),  // outside catalog offline grace, entitlement/keyset active
             initialNow.addDays(31)  // entitlement expired, root keyset still active
         }) {
        Harness lifecycle;
        configureCoordinatorTestRoot(lifecycle);
        lifecycle.source.now = lifecycleNow;
        lifecycle.store.status = CatalogLkgLoadStatus::Loaded;
        lifecycle.store.loaded = persisted;
        CatalogCoordinator coordinator = lifecycle.make();
        QString error;
        expect(coordinator.initialize(error) && coordinator.productionReady()
                   && !lifecycle.facade.catalogAvailable(),
               "active-keyset catalog/entitlement expiry enters recoverable quarantine");
        expect(coordinator.requestConnect(error) && lifecycle.keyset.starts == 1,
               "active-keyset expired LKG still requires fresh root discovery");
        lifecycle.keyset.finish(CatalogKeysetFetchKind::NetworkUnavailable,
                                lifecycle.keyset.activeOperation);
        expect(lifecycle.reducer.connectCalls == 0,
               "active-keyset expired catalog/entitlement is offline fail-closed");
    }

    CatalogLkgRecord expiredTombstone;
    {
        Harness offline;
        configureCoordinatorTestRoot(offline);
        offline.source.now = recoveryNow;
        offline.store.status = CatalogLkgLoadStatus::Loaded;
        offline.store.loaded = persisted;
        CatalogCoordinator coordinator = offline.make();
        QString error;
        expect(coordinator.initialize(error) && coordinator.productionReady(),
               "normal keyset/LKG expiry completes production-ready cold start");
        expect(coordinator.authoritativeV2() && !offline.facade.legacyV1Allowed()
                   && !offline.facade.catalogAvailable(),
               "expired authority remains a v2 tombstone but is never catalog-connectable");
        expiredTombstone = offline.store.loaded;
        CatalogRuntimeState advancedRuntime;
        expect(offline.store.writes == 1
                   && offline.store.loaded.verifiedEnvelope.isEmpty()
                   && offline.store.loaded.acceptedKeysetState
                          == persisted.acceptedKeysetState
                   && offline.store.loaded.trustState.highestCatalogRevision
                          == persisted.trustState.highestCatalogRevision
                   && parseCatalogRuntimeState(
                       offline.store.loaded.runtimeState, advancedRuntime, error)
                   && advancedRuntime.trustedClock.highestObservedWallUtc
                          == recoveryNow,
               "cold recovery atomically tombstones credentials and advances wall high-water");
        expect(coordinator.requestConnect(error) && offline.keyset.starts == 1,
               "expired LKG connect intent starts at the bundled root keyset");
        offline.keyset.finish(CatalogKeysetFetchKind::NetworkUnavailable,
                              offline.keyset.activeOperation);
        expect(offline.reducer.connectCalls == 0,
               "offline expired material cannot dispatch a native connection");
    }

    {
        Harness rolled;
        configureCoordinatorTestRoot(rolled);
        rolled.source.now = initialNow.addSecs(5 * 60);
        rolled.store.status = CatalogLkgLoadStatus::Loaded;
        rolled.store.loaded = expiredTombstone;
        CatalogCoordinator coordinator = rolled.make();
        QString error;
        expect(!coordinator.initialize(error)
                   && rolled.facade.connectionStage() == QLatin1String("failed")
                   && rolled.keyset.starts == 0
                   && rolled.reducer.connectCalls == 0,
               "advanced quarantine wall high-water blocks rolled-wall offline resurrection");
    }

    {
        Harness online;
        configureCoordinatorTestRoot(online);
        online.source.now = recoveryNow;
        online.store.status = CatalogLkgLoadStatus::Loaded;
        online.store.loaded = persisted;
        CatalogCoordinator coordinator = online.make();
        QString error;
        expect(coordinator.initialize(error) && coordinator.requestConnect(error),
               "expired authority can enter root-anchored online recovery");
        const int writesBeforeFreshKeyset = online.store.writes;
        const QByteArray freshKeyset = keysetEnvelopeForCoordinatorTest(
            2, recoveryNow.addSecs(-2 * 60), recoveryNow.addDays(60));
        online.keyset.finish(CatalogKeysetFetchKind::Artifact,
                             online.keyset.activeOperation, freshKeyset);
        CatalogKeysetTrustState transitionedTrust;
        expect(online.resolve.activeAttempt.operation != 0
                   && online.reducer.connectCalls == 0,
               "fresh root keyset dispatches resolve but never revives expired LKG");
        expect(online.store.writes == writesBeforeFreshKeyset + 1
                   && online.store.loaded.verifiedEnvelope.isEmpty()
                   && parseCatalogKeysetTrustState(
                       online.store.loaded.acceptedKeysetState,
                       transitionedTrust, error)
                   && transitionedTrust.highestEpoch == 2,
               "expired quarantine stores new root state plus tombstone before resolve");
        online.resolve.finish(
            CatalogResolveResultKind::SignedCatalog,
            timedCatalogEnvelopeForCoordinatorTest(
                online.resolve.activeAttempt.requestNonce, 11,
                recoveryNow.addSecs(-60)));
        expect(online.reducer.connectCalls == 1 && online.facade.catalogAvailable(),
               "fresh nonce-bound catalog becomes connectable after recovery");
        CatalogKeysetTrustState recoveredKeysetTrust;
        CatalogRuntimeState recoveredRuntime;
        expect(parseCatalogKeysetTrustState(
                   online.store.loaded.acceptedKeysetState,
                   recoveredKeysetTrust, error)
                   && parseCatalogRuntimeState(
                       online.store.loaded.runtimeState, recoveredRuntime, error),
               "recovered atomic authority record parses");
        expect(recoveredKeysetTrust.highestEpoch == 2
                   && recoveredKeysetTrust.revokedIdentities
                          == originalKeysetTrust.revokedIdentities
                   && online.store.loaded.trustState.highestCatalogRevision == 11
                   && recoveredRuntime.trustedClock.highestSignedIssuedAtUtc
                          >= originalRuntime.trustedClock.highestSignedIssuedAtUtc,
               "online recovery advances authority without dropping clock/high-water/tombstones");
    }

    for (const QString &defect : {
             QStringLiteral("corrupt"), QStringLiteral("signature"),
             QStringLiteral("root"), QStringLiteral("catalog_rollback"),
             QStringLiteral("clock_rollback")}) {
        Harness broken;
        if (defect != QLatin1String("root")) configureCoordinatorTestRoot(broken);
        broken.source.now = recoveryNow;
        broken.store.status = CatalogLkgLoadStatus::Loaded;
        broken.store.loaded = persisted;
        QString error;
        if (defect == QLatin1String("corrupt")) {
            broken.store.loaded.acceptedKeysetState = QByteArrayLiteral("{");
        } else if (defect == QLatin1String("signature")) {
            CatalogKeysetTrustState state;
            expect(parseCatalogKeysetTrustState(
                       broken.store.loaded.acceptedKeysetState, state, error),
                   "signature-defect keyset state parses before mutation");
            state.acceptedEnvelope[state.acceptedEnvelope.size() / 2] = 'x';
            expect(serializeCatalogKeysetTrustState(
                       state, broken.store.loaded.acceptedKeysetState, error),
                   "signature-defect keyset state reserializes");
        } else if (defect == QLatin1String("catalog_rollback")) {
            ++broken.store.loaded.trustState.highestCatalogRevision;
        } else if (defect == QLatin1String("clock_rollback")) {
            broken.source.now = originalRuntime.trustedClock.highestObservedWallUtc
                                    .addSecs(-301);
        }
        CatalogCoordinator coordinator = broken.make();
        expect(!coordinator.initialize(error)
                   && broken.facade.connectionStage() == QLatin1String("failed")
                   && broken.facade.v2Authoritative()
                   && broken.keyset.starts == 0
                   && broken.reducer.connectCalls == 0,
               "corruption/signature/root/rollback remains terminal, never recovery");
    }
}

CatalogLkgRecord seededAuthorityRecordForRotation(const QDateTime &now)
{
    Harness seed;
    configureCoordinatorTestRoot(seed);
    seed.source.now = now;
    CatalogCoordinator coordinator = seed.make();
    QString error;
    expect(coordinator.initialize(error) && coordinator.requestConnect(error),
           "rotation seed starts root-anchored discovery");
    const QByteArray keyset = keysetEnvelopeForCoordinatorTest(
        1, now.addDays(-20), now.addDays(40));
    seed.keyset.finish(CatalogKeysetFetchKind::Artifact,
                       seed.keyset.activeOperation, keyset);
    expect(seed.resolve.activeAttempt.operation != 0,
           "rotation seed keyset starts resolve");
    seed.resolve.finish(
        CatalogResolveResultKind::SignedCatalog,
        timedCatalogEnvelopeForCoordinatorTest(
            seed.resolve.activeAttempt.requestNonce, 10, now.addSecs(-60)));
    expect(seed.reducer.connectCalls == 1
               && !seed.store.loaded.verifiedEnvelope.isEmpty()
               && !seed.store.loaded.acceptedKeysetState.isEmpty(),
           "rotation seed persists one complete catalog/keyset authority pair");
    return seed.store.loaded;
}

void keysetRotationIsAtomicCrashSafeAndFailClosed()
{
    const QDateTime now = QDateTime::fromString(
        QStringLiteral("2026-08-28T12:00:00.000Z"), Qt::ISODateWithMs);
    const CatalogLkgRecord original = seededAuthorityRecordForRotation(now);
    const QByteArray overlapping = keysetEnvelopeForCoordinatorTest(
        2, now.addSecs(-120), now.addDays(60));
    const QByteArray omitted = keysetEnvelopeForCoordinatorTest(
        2, now.addSecs(-120), now.addDays(60),
        CatalogKeyTransitionForTest::OmitOld);
    const QByteArray revoked = keysetEnvelopeForCoordinatorTest(
        2, now.addSecs(-120), now.addDays(60),
        CatalogKeyTransitionForTest::RevokeOld);

    CatalogLkgRecord overlapRecord;
    {
        Harness h;
        configureCoordinatorTestRoot(h);
        h.source.now = now;
        h.store.status = CatalogLkgLoadStatus::Loaded;
        h.store.loaded = original;
        CatalogCoordinator coordinator = h.make();
        QString error;
        expect(coordinator.initialize(error) && h.facade.catalogAvailable(),
               "overlap transition restores current valid LKG");
        const int writesBefore = h.store.writes;
        expect(coordinator.requestCatalogRefresh(error),
               "overlap transition starts explicit refresh");
        h.keyset.finish(CatalogKeysetFetchKind::Artifact,
                        h.keyset.activeOperation, overlapping);
        expect(h.store.writes == writesBefore + 1
                   && !h.store.loaded.verifiedEnvelope.isEmpty()
                   && h.resolve.activeAttempt.operation != 0
                   && h.reducer.disconnectCalls == 0,
               "valid signer overlap performs one atomic write and preserves live LKG");
        overlapRecord = h.store.loaded; // crash before the pending resolve response
    }
    {
        Harness relaunched;
        configureCoordinatorTestRoot(relaunched);
        relaunched.source.now = now.addSecs(5);
        relaunched.store.status = CatalogLkgLoadStatus::Loaded;
        relaunched.store.loaded = overlapRecord;
        CatalogCoordinator coordinator = relaunched.make();
        QString error;
        expect(coordinator.initialize(error) && relaunched.facade.catalogAvailable()
                   && coordinator.requestConnect(error)
                   && relaunched.reducer.connectCalls == 1
                   && relaunched.keyset.starts == 0,
               "crash after overlap write restores the still-valid atomic pair offline");
    }

    CatalogLkgRecord omissionTombstone;
    {
        Harness h;
        configureCoordinatorTestRoot(h);
        h.source.now = now;
        h.store.status = CatalogLkgLoadStatus::Loaded;
        h.store.loaded = original;
        CatalogCoordinator coordinator = h.make();
        QString error;
        expect(coordinator.initialize(error)
                   && coordinator.requestCatalogRefresh(error),
               "omission transition starts from a valid authority pair");
        const int writesBefore = h.store.writes;
        h.keyset.finish(CatalogKeysetFetchKind::Artifact,
                        h.keyset.activeOperation, omitted);
        CatalogKeysetTrustState trust;
        expect(h.store.writes == writesBefore + 1
                   && h.store.loaded.verifiedEnvelope.isEmpty()
                   && h.store.loaded.trustState.hasAcceptedV2
                   && parseCatalogKeysetTrustState(
                       h.store.loaded.acceptedKeysetState, trust, error)
                   && trust.highestEpoch == 2
                   && !h.facade.catalogAvailable()
                   && h.reducer.connectCalls == 0
                   && h.resolve.activeAttempt.operation != 0,
               "root omission atomically stores new keyset plus credential-free high-water");
        omissionTombstone = h.store.loaded; // crash before fresh catalog response
    }
    {
        Harness offline;
        configureCoordinatorTestRoot(offline);
        offline.source.now = now.addSecs(5);
        offline.store.status = CatalogLkgLoadStatus::Loaded;
        offline.store.loaded = omissionTombstone;
        CatalogCoordinator coordinator = offline.make();
        QString error;
        expect(coordinator.initialize(error) && !offline.facade.catalogAvailable()
                   && coordinator.requestConnect(error),
               "omission tombstone relaunch is production-ready only for online recovery");
        offline.keyset.finish(CatalogKeysetFetchKind::NetworkUnavailable,
                              offline.keyset.activeOperation);
        expect(offline.reducer.connectCalls == 0,
               "omitted signer can never be resurrected by offline relaunch");
    }
    {
        Harness online;
        configureCoordinatorTestRoot(online);
        online.source.now = now.addSecs(5);
        online.store.status = CatalogLkgLoadStatus::Loaded;
        online.store.loaded = omissionTombstone;
        CatalogCoordinator coordinator = online.make();
        QString error;
        expect(coordinator.initialize(error) && coordinator.requestConnect(error),
               "omission tombstone can request fresh root authority online");
        online.keyset.finish(CatalogKeysetFetchKind::Artifact,
                             online.keyset.activeOperation, omitted);
        expect(online.resolve.activeAttempt.operation != 0
                   && online.reducer.connectCalls == 0,
               "same accepted root epoch resolves without reviving omitted credentials");
        online.resolve.finish(
            CatalogResolveResultKind::SignedCatalog,
            timedCatalogEnvelopeForCoordinatorTest(
                online.resolve.activeAttempt.requestNonce, 11, now.addSecs(-30),
                QByteArrayLiteral("tribe-dev-catalog-signing-seed-v2"),
                QStringLiteral("catalog-k2"), 2));
        expect(online.reducer.connectCalls == 1 && online.facade.catalogAvailable()
                   && !online.store.loaded.verifiedEnvelope.isEmpty(),
               "fresh catalog under replacement signer restores connectability atomically");
    }

    {
        Harness live;
        configureCoordinatorTestRoot(live);
        live.source.now = now;
        live.store.status = CatalogLkgLoadStatus::Loaded;
        live.store.loaded = original;
        CatalogCoordinator coordinator = live.make();
        QString error;
        expect(coordinator.initialize(error), "revocation transition restores authority");
        ConnectionRuntimeSnapshot running;
        running.phase = ConnectionPhase::ConnectedHealthy;
        running.operation = 71;
        running.session = {71, 1};
        running.guardArmed = true;
        coordinator.onConnectionReducerSnapshot(running);
        expect(coordinator.requestCatalogRefresh(error),
               "live revocation transition starts root refresh");
        live.keyset.finish(CatalogKeysetFetchKind::Artifact,
                           live.keyset.activeOperation, revoked);
        expect(live.store.loaded.verifiedEnvelope.isEmpty()
                   && live.reducer.disconnectCalls == 1
                   && live.resolve.activeAttempt.operation == 0,
               "explicit revocation persists tombstone then stops live runtime before resolve");
        coordinator.requestDisconnect();
        expect(live.reducer.disconnectCalls == 1,
               "OFF during rotation barrier cancels reconnect without duplicate stop");
        ConnectionRuntimeSnapshot unknownStop;
        unknownStop.phase = ConnectionPhase::Failed;
        coordinator.onConnectionReducerSnapshot(unknownStop);
        expect(live.resolve.activeAttempt.operation == 0,
               "non-exact failed snapshot cannot cross revocation teardown barrier");
        ConnectionRuntimeSnapshot exactReleased;
        exactReleased.phase = ConnectionPhase::Idle;
        coordinator.onConnectionReducerSnapshot(exactReleased);
        expect(live.resolve.activeAttempt.operation != 0,
               "exact idle plus inner/outer release resumes one fresh resolve");
        live.resolve.finish(
            CatalogResolveResultKind::SignedCatalog,
            timedCatalogEnvelopeForCoordinatorTest(
                live.resolve.activeAttempt.requestNonce, 11, now.addSecs(-30),
                QByteArrayLiteral("tribe-dev-catalog-signing-seed-v2"),
                QStringLiteral("catalog-k2"), 2));
        expect(live.reducer.connectCalls == 0
                   && coordinator.requestConnect(error)
                   && live.reducer.connectCalls == 1,
               "list refresh after revocation remains OFF until explicit connect intent");
    }

    {
        Harness failure;
        configureCoordinatorTestRoot(failure);
        failure.source.now = now;
        failure.store.status = CatalogLkgLoadStatus::Loaded;
        failure.store.loaded = original;
        CatalogCoordinator coordinator = failure.make();
        FakeOutcomeClient outcome;
        coordinator.setOutcomeClient(&outcome);
        QString error;
        expect(coordinator.initialize(error), "keyset persist-failure setup restores");
        ConnectionRuntimeSnapshot running;
        running.phase = ConnectionPhase::ConnectedHealthy;
        running.operation = 72;
        running.session = {72, 1};
        running.guardArmed = true;
        running.profileId = QStringLiteral("fi-awg-02");
        running.locationId = QStringLiteral("fi-hel");
        running.transport = TransportKind::Awg;
        running.configGeneration = 12;
        running.bindingGeneration = 3;
        coordinator.onConnectionReducerSnapshot(running);
        expect(outcome.activeOperation != 0,
               "persist-failure setup owns an in-flight advisory outcome");
        expect(coordinator.requestCatalogRefresh(error),
               "keyset persist-failure starts transition");
        failure.store.failNextWrite = true;
        failure.keyset.finish(CatalogKeysetFetchKind::Artifact,
                              failure.keyset.activeOperation, revoked);
        CatalogKeysetTrustState diskTrust;
        expect(failure.reducer.disconnectCalls == 1
                   && !failure.facade.catalogAvailable()
                   && failure.resolve.activeAttempt.operation == 0
                   && !failure.store.loaded.verifiedEnvelope.isEmpty()
                   && parseCatalogKeysetTrustState(
                       failure.store.loaded.acceptedKeysetState, diskTrust, error)
                   && diskTrust.highestEpoch == 1
                   && outcome.cancels == 1,
               "failed revocation write keeps old disk pair but fail-stops this live process");
        const int writesAfterFailure = failure.store.writes;
        const int outcomeStartsAfterFailure = outcome.starts;
        QCoreApplication::processEvents();
        expect(outcome.starts == outcomeStartsAfterFailure,
               "queued outcome flush cannot cross the authority persistence fail-stop latch");
        outcome.finish(CatalogOutcomeUploadKind::Acknowledged);
        coordinator.onCatalogKeysetFetchResult(
            {999, CatalogKeysetFetchKind::Artifact, overlapping, 0});
        coordinator.onCatalogResolveResult(
            {999, CatalogResolveResultKind::SignedCatalog, 200, {},
             QStringLiteral("stale"), QStringLiteral("ok"), 0, 0, true});
        ConnectionRuntimeSnapshot lateGreen;
        lateGreen.phase = ConnectionPhase::ConnectedHealthy;
        lateGreen.operation = 999;
        lateGreen.session = {999, 1};
        lateGreen.guardArmed = true;
        coordinator.onConnectionReducerSnapshot(lateGreen);
        expect(failure.reducer.disconnectCalls == 1
                   && failure.resolve.starts == 0
                   && failure.reducer.verificationRetries == 0
                   && failure.store.writes == writesAfterFailure
                   && !failure.facade.catalogAvailable()
                   && !failure.facade.verified(),
               "late authority results/green callback are no-ops after one fail-stop disconnect");
        error.clear();
        expect(!coordinator.requestConnect(error)
                   && error == QLatin1String("catalog_authority_persist_failed")
                   && failure.reducer.connectCalls == 0,
               "authority persistence latch blocks every later native dispatch");
    }

    for (const CatalogKeyTransitionForTest receiptTransition : {
             CatalogKeyTransitionForTest::OmitReceiptA,
             CatalogKeyTransitionForTest::RevokeReceiptA,
             CatalogKeyTransitionForTest::ExpireReceiptA,
         }) {
        Harness receipt;
        configureCoordinatorTestRoot(receipt);
        receipt.source.now = now;
        receipt.store.status = CatalogLkgLoadStatus::Loaded;
        receipt.store.loaded = original;
        CatalogCoordinator coordinator = receipt.make();
        QString error;
        expect(coordinator.initialize(error),
               "receipt-authority rotation restores current catalog");
        ConnectionRuntimeSnapshot running;
        running.phase = ConnectionPhase::ConnectedHealthy;
        running.operation = 80 + int(receiptTransition);
        running.session = {quint64(running.operation), 1};
        running.guardArmed = true;
        coordinator.onConnectionReducerSnapshot(running);
        expect(coordinator.requestCatalogRefresh(error),
               "receipt-authority rotation starts root refresh");
        const QByteArray receiptKeyset = keysetEnvelopeForCoordinatorTest(
            2, now.addSecs(-120), now.addDays(60), receiptTransition);
        receipt.keyset.finish(CatalogKeysetFetchKind::Artifact,
                              receipt.keyset.activeOperation, receiptKeyset);
        expect(receipt.store.loaded.verifiedEnvelope.isEmpty()
                   && !receipt.facade.catalogAvailable()
                   && receipt.reducer.disconnectCalls == 1
                   && receipt.resolve.activeAttempt.operation == 0,
               "receipt omission/revocation/expiry tombstones and stops before resolve");
        ConnectionRuntimeSnapshot exactReleased;
        exactReleased.phase = ConnectionPhase::Idle;
        coordinator.onConnectionReducerSnapshot(exactReleased);
        const quint64 exactResolve = receipt.resolve.activeAttempt.operation;
        coordinator.onConnectionReducerSnapshot(exactReleased);
        expect(exactResolve != 0
                   && receipt.resolve.activeAttempt.operation == exactResolve
                   && receipt.resolve.starts == 1,
               "duplicate exact release cannot dispatch a second rotation resolve");
    }

    {
        Harness logout;
        configureCoordinatorTestRoot(logout);
        logout.source.now = now;
        logout.store.status = CatalogLkgLoadStatus::Loaded;
        logout.store.loaded = original;
        CatalogCoordinator coordinator = logout.make();
        QString error;
        expect(coordinator.initialize(error), "rotation logout setup restores");
        ConnectionRuntimeSnapshot running;
        running.phase = ConnectionPhase::ConnectedHealthy;
        running.operation = 91;
        running.session = {91, 1};
        running.guardArmed = true;
        coordinator.onConnectionReducerSnapshot(running);
        expect(coordinator.requestCatalogRefresh(error),
               "rotation logout setup starts refresh");
        logout.keyset.finish(CatalogKeysetFetchKind::Artifact,
                             logout.keyset.activeOperation, revoked);
        coordinator.clearAfterLogout();
        ConnectionRuntimeSnapshot released;
        released.phase = ConnectionPhase::Idle;
        coordinator.onConnectionReducerSnapshot(released);
        expect(logout.resolve.starts == 0 && logout.store.clears == 1,
               "logout cancels rotation resolve barrier and wipes only after exact release");
    }
    {
        Harness recovery;
        configureCoordinatorTestRoot(recovery);
        recovery.source.now = now;
        recovery.store.status = CatalogLkgLoadStatus::Loaded;
        recovery.store.loaded = original;
        CatalogCoordinator coordinator = recovery.make();
        QString error;
        expect(coordinator.initialize(error), "rotation platform-recovery setup restores");
        ConnectionRuntimeSnapshot running;
        running.phase = ConnectionPhase::ConnectedHealthy;
        running.operation = 92;
        running.session = {92, 1};
        running.guardArmed = true;
        coordinator.onConnectionReducerSnapshot(running);
        expect(coordinator.requestCatalogRefresh(error),
               "rotation platform-recovery setup starts refresh");
        recovery.keyset.finish(CatalogKeysetFetchKind::Artifact,
                               recovery.keyset.activeOperation, revoked);
        const QJsonObject guardEvent{
            {QStringLiteral("type"), QStringLiteral("native_session_guard_v1")},
            {QStringLiteral("schema"), 1},
            {QStringLiteral("operation"), QStringLiteral("92")},
            {QStringLiteral("session"), QStringLiteral("1")},
            {QStringLiteral("kind"), QStringLiteral("armed")},
            {QStringLiteral("policy_sha256"), QString(64, QLatin1Char('a'))},
            {QStringLiteral("outer_session_id"), QStringLiteral("outer-rotation")},
            {QStringLiteral("expected_runtime_session_id"),
             QStringLiteral("123e4567-e89b-42d3-a456-426614174000")},
            {QStringLiteral("reason"), QString()},
        };
        expect(coordinator.nativeSessionGuardRecoveryRequired(guardEvent),
               "platform recovery takes exclusive ownership of rotation teardown");
        ConnectionRuntimeSnapshot released;
        released.phase = ConnectionPhase::Idle;
        coordinator.onConnectionReducerSnapshot(released);
        expect(recovery.resolve.starts == 0
                   && coordinator.nativeSessionGuardRecoveryPending(),
               "platform recovery cancels rotation barrier and Idle cannot resolve");
    }
}

void authoritativePersistenceFailuresAreSticky()
{
    const QDateTime now = QDateTime::fromString(
        QStringLiteral("2026-08-28T12:00:00.000Z"), Qt::ISODateWithMs);
    const QByteArray keyset = keysetEnvelopeForCoordinatorTest(
        1, now.addDays(-20), now.addDays(40));
    const CatalogLkgRecord existingAuthority =
        seededAuthorityRecordForRotation(now);
    {
        Harness restoreFailure;
        configureCoordinatorTestRoot(restoreFailure);
        restoreFailure.source.now = now;
        restoreFailure.store.status = CatalogLkgLoadStatus::Loaded;
        restoreFailure.store.loaded = existingAuthority;
        restoreFailure.store.failNextWrite = true;
        CatalogCoordinator coordinator = restoreFailure.make();
        QString error;
        expect(!coordinator.initialize(error)
                   && restoreFailure.facade.v2Authoritative()
                   && !restoreFailure.facade.catalogAvailable()
                   && restoreFailure.reducer.connectCalls == 0,
               "loaded LKG high-water write failure clears the already-restored facade view");
        error.clear();
        expect(!coordinator.requestConnect(error)
                   && error == QLatin1String("catalog_authority_persist_failed"),
               "restore high-water failure stays sticky before any native dispatch");
    }
    {
        Harness networkCatalog;
        configureCoordinatorTestRoot(networkCatalog);
        networkCatalog.source.now = now;
        CatalogCoordinator coordinator = networkCatalog.make();
        QString error;
        expect(coordinator.initialize(error) && coordinator.requestConnect(error),
               "network-catalog persist-failure setup starts discovery");
        networkCatalog.keyset.finish(CatalogKeysetFetchKind::Artifact,
                                     networkCatalog.keyset.activeOperation, keyset);
        networkCatalog.store.failNextWrite = true;
        networkCatalog.resolve.finish(
            CatalogResolveResultKind::SignedCatalog,
            timedCatalogEnvelopeForCoordinatorTest(
                networkCatalog.resolve.activeAttempt.requestNonce, 1,
                now.addSecs(-60)));
        expect(networkCatalog.reducer.connectCalls == 0
                   && !networkCatalog.facade.catalogAvailable()
                   && networkCatalog.facade.v2Authoritative(),
               "failed network-catalog replace publishes no ephemeral connect authority");
        error.clear();
        expect(!coordinator.requestConnect(error)
                   && error == QLatin1String("catalog_authority_persist_failed"),
               "network-catalog replace failure is sticky until durable recovery");
    }
    {
        Harness noncatalog;
        configureCoordinatorTestRoot(noncatalog);
        noncatalog.source.now = now;
        CatalogCoordinator coordinator = noncatalog.make();
        QString error;
        expect(coordinator.initialize(error) && coordinator.requestConnect(error),
               "authoritative noncatalog persist-failure setup starts discovery");
        noncatalog.keyset.finish(CatalogKeysetFetchKind::Artifact,
                                 noncatalog.keyset.activeOperation, keyset);
        noncatalog.store.failNextWrite = true;
        noncatalog.resolve.finish(CatalogResolveResultKind::TemporarilyUnavailable,
                                  {}, true, 10);
        expect(noncatalog.facade.v2Authoritative()
                   && !noncatalog.facade.catalogAvailable()
                   && noncatalog.reducer.connectCalls == 0,
               "authoritative noncatalog replace failure remains v2 fail-closed");
        error.clear();
        expect(!coordinator.requestConnect(error)
                   && error == QLatin1String("catalog_authority_persist_failed"),
               "noncatalog authority persistence failure also latches dispatch closed");
    }
    {
        Harness liveNoncatalog;
        configureCoordinatorTestRoot(liveNoncatalog);
        liveNoncatalog.source.now = now;
        liveNoncatalog.store.status = CatalogLkgLoadStatus::Loaded;
        liveNoncatalog.store.loaded = existingAuthority;
        CatalogCoordinator coordinator = liveNoncatalog.make();
        QString error;
        expect(coordinator.initialize(error),
               "live noncatalog persist-failure setup restores authority");
        ConnectionRuntimeSnapshot running;
        running.phase = ConnectionPhase::ConnectedHealthy;
        running.operation = 101;
        running.session = {101, 1};
        running.guardArmed = true;
        coordinator.onConnectionReducerSnapshot(running);
        expect(coordinator.requestCatalogRefresh(error),
               "live noncatalog setup starts signed refresh");
        liveNoncatalog.keyset.finish(
            CatalogKeysetFetchKind::Artifact,
            liveNoncatalog.keyset.activeOperation,
            keysetEnvelopeForCoordinatorTest(
                2, now.addSecs(-120), now.addDays(60)));
        liveNoncatalog.store.failNextWrite = true;
        liveNoncatalog.resolve.finish(
            CatalogResolveResultKind::TemporarilyUnavailable, {}, true, 10);
        expect(liveNoncatalog.reducer.disconnectCalls == 1
                   && !liveNoncatalog.facade.catalogAvailable(),
               "failed authoritative noncatalog write stops an existing native owner once");
        error.clear();
        expect(!coordinator.requestConnect(error)
                   && error == QLatin1String("catalog_authority_persist_failed"),
               "live noncatalog persistence failure cannot fall back to old in-memory LKG");
    }
}

void locationDirectoryIntentIsScopedWithoutOffAllocation()
{
    QTemporaryDir directory;
    expect(directory.isValid(), "scoped-intent preference directory is available");
    QSettings settings(directory.filePath(QStringLiteral("intent.ini")),
                       QSettings::IniFormat);
    QString error;
    expect(persistCatalogUserIntent(
               &settings,
               {ConnectionMode::ForceXray, QStringLiteral("fi-hel")}, error),
           "non-default scoped intent persists before first catalog");

    Harness h;
    configureCoordinatorTestRoot(h);
    h.config.userIntentSettings = &settings;
    CatalogCoordinator coordinator = h.make();
    expect(coordinator.initialize(error) && coordinator.requestConnect(error),
           "persisted non-default intent opts into initial discovery");
    h.keyset.finish(
        CatalogKeysetFetchKind::Artifact, h.keyset.activeOperation,
        keysetEnvelopeForCoordinatorTest(
            1, h.source.now.addDays(-1), h.source.now.addDays(30)));
    expect(h.resolve.activeAttempt.operation != 0
               && !h.resolve.activeAttempt.scopedSelectionSent
               && !h.resolve.lastRequest.selection.has_value()
               && h.resolve.lastRequest.capabilities.contains(
                   QStringLiteral("catalog.location_directory_v1")),
           "initial N/N-1 handshake advertises directory support but sends no selection");
    h.resolve.finish(
        CatalogResolveResultKind::SignedCatalog,
        directoryCatalogEnvelopeForCoordinatorTest(
            h.resolve.activeAttempt.requestNonce, 1, {}));
    expect(h.reducer.connectCalls == 0
               && h.resolve.activeAttempt.operation != 0
               && h.resolve.activeAttempt.scopedSelectionSent
               && h.resolve.activeAttempt.expectedSelection
                      == CatalogResolveSelection{ConnectionMode::ForceXray,
                                                 QStringLiteral("fi-hel")},
           "signed auto/fastest directory triggers exact second resolve before native start");
    expect(h.resolve.lastRequest.selection.has_value()
               && *h.resolve.lastRequest.selection
                      == CatalogResolveSelection{ConnectionMode::ForceXray,
                                                 QStringLiteral("fi-hel")},
           "second request scopes backend credentials to final persisted intent");
    h.resolve.finish(
        CatalogResolveResultKind::SignedCatalog,
        directoryCatalogEnvelopeForCoordinatorTest(
            h.resolve.activeAttempt.requestNonce, 2,
            {ConnectionMode::ForceXray, QStringLiteral("fi-hel")}));
    expect(h.reducer.connectCalls == 1 && h.reducer.reconcileCalls == 0,
           "exact signed selection echo is the first credential shortlist dispatched");

    coordinator.requestDisconnect();
    const int keysetStartsBeforeBrowsing = h.keyset.starts;
    const int resolveStartsBeforeBrowsing = h.resolve.starts;
    for (int index = 0; index < 128; ++index) {
        const ConnectionMode mode = index % 2 == 0
            ? ConnectionMode::ForceAwg : ConnectionMode::ForceXray;
        const QString location = index % 3 == 0
            ? QStringLiteral("auto") : QStringLiteral("fi-hel");
        expect(coordinator.requestConnectionMode(mode, error)
                   && coordinator.requestLocationMode(location, error),
               "OFF browsing accepts only signed-directory intent values");
    }
    expect(h.keyset.starts == keysetStartsBeforeBrowsing
               && h.resolve.starts == resolveStartsBeforeBrowsing
               && h.reducer.connectCalls == 1,
           "OFF browsing across 128 choices performs zero resolves and zero native starts");
    expect(coordinator.requestConnectionMode(ConnectionMode::ForceAwg, error)
               && coordinator.requestLocationMode(QStringLiteral("fi-hel"), error)
               && coordinator.requestConnect(error)
               && h.keyset.starts == keysetStartsBeforeBrowsing + 1
               && h.reducer.connectCalls == 1,
           "next ON issues only the final OFF intent instead of replaying intermediate choices");
}

void liveIntentRefreshKeepsVerifiedOwnerAndFencesStaleEchoes()
{
    Harness h;
    configureCoordinatorTestRoot(h);
    CatalogCoordinator coordinator = h.make();
    QString error;
    expect(coordinator.initialize(error) && coordinator.requestConnect(error),
           "live-switch setup starts discovery");
    const QByteArray keyset = keysetEnvelopeForCoordinatorTest(
        1, h.source.now.addDays(-1), h.source.now.addDays(30));
    h.keyset.finish(CatalogKeysetFetchKind::Artifact,
                    h.keyset.activeOperation, keyset);
    h.resolve.finish(
        CatalogResolveResultKind::SignedCatalog,
        directoryCatalogEnvelopeForCoordinatorTest(
            h.resolve.activeAttempt.requestNonce, 1, {}));
    expect(h.reducer.connectCalls == 1,
           "auto/fastest directory starts the initial inner once");

    ConnectionRuntimeSnapshot live;
    live.phase = ConnectionPhase::ConnectedHealthy;
    live.operation = 77;
    live.session = {77, 1};
    live.profileId = QStringLiteral("fi-awg-02");
    live.transport = TransportKind::Awg;
    live.locationId = QStringLiteral("fi-hel");
    live.configGeneration = 12;
    live.bindingGeneration = 3;
    live.guardArmed = true;
    live.hasAcceptedV2 = true;
    live.verifiedAtUtc = h.source.now.addSecs(-10);
    live.verifiedUntilUtc = h.source.now.addSecs(60);
    live.nativeProfileExpiresAt = h.source.now.addSecs(600);
    live.catalogFreshnessDeadline = h.source.now.addSecs(600);
    live.entitlementDeadline = h.source.now.addSecs(600);
    coordinator.onConnectionReducerSnapshot(live);

    expect(coordinator.requestConnectionMode(ConnectionMode::ForceXray, error)
               && h.reducer.disconnectCalls == 0
               && h.keyset.activeOperation != 0
               && h.facade.currentLocationId() == QLatin1String("fi-hel")
               && h.facade.verified(),
           "live mode change keeps old verified inner/outer owner while fetching scope");
    h.keyset.finish(CatalogKeysetFetchKind::Artifact,
                    h.keyset.activeOperation, keyset);
    const CatalogResolveAttempt staleAttempt = h.resolve.activeAttempt;
    const QByteArray staleEnvelope = directoryCatalogEnvelopeForCoordinatorTest(
        staleAttempt.requestNonce, 2,
        {ConnectionMode::ForceXray, {}});
    expect(staleAttempt.scopedSelectionSent
               && staleAttempt.expectedSelection
                      == CatalogResolveSelection{ConnectionMode::ForceXray, {}},
           "first live request is immutably scoped to Xray/fastest");

    expect(coordinator.requestConnectionMode(ConnectionMode::ForceAwg, error)
               && h.resolve.cancels == 1
               && h.reducer.disconnectCalls == 0,
           "rapid intent change fences the old resolve without ordinary disconnect");
    coordinator.onCatalogResolveResult(
        {staleAttempt.operation, CatalogResolveResultKind::SignedCatalog, 200,
         staleEnvelope, staleAttempt.requestNonce, QStringLiteral("ok"), 0, 0, true});
    expect(h.reducer.reconcileCalls == 0
               && h.facade.connectionMode() == QLatin1String("awg")
               && h.facade.currentLocationId() == QLatin1String("fi-hel"),
           "stale A response cannot replace rapid B intent or current country");

    h.keyset.finish(CatalogKeysetFetchKind::Artifact,
                    h.keyset.activeOperation, keyset);
    expect(h.resolve.activeAttempt.expectedSelection
               == CatalogResolveSelection{ConnectionMode::ForceAwg, {}},
           "replacement resolve carries only the latest immutable selection");
    h.resolve.finish(CatalogResolveResultKind::TemporarilyUnavailable,
                     {}, true, 5);
    expect(h.reducer.reconcileCalls == 0 && h.reducer.disconnectCalls == 0
               && h.facade.verified()
               && h.facade.currentLocationId() == QLatin1String("fi-hel")
               && h.facade.connectionMode() == QLatin1String("awg"),
           "503/backpressure retains old verified owner, country, and requested intent");

    expect(coordinator.requestConnectionMode(ConnectionMode::ForceXray, error)
               && h.keyset.activeOperation != 0,
           "new intent fences the backoff and starts a fresh exact operation");
    h.keyset.finish(CatalogKeysetFetchKind::Artifact,
                    h.keyset.activeOperation, keyset);
    h.resolve.finish(
        CatalogResolveResultKind::SignedCatalog,
        directoryCatalogEnvelopeForCoordinatorTest(
            h.resolve.activeAttempt.requestNonce, 2, {}));
    expect(h.reducer.reconcileCalls == 0 && h.reducer.disconnectCalls == 0
               && h.facade.verified(),
           "signed selection mismatch leaves the live verified session untouched");

    expect(coordinator.requestConnectionMode(ConnectionMode::ForceAwg, error),
           "mismatch recovery starts another exact AWG scope");
    h.keyset.finish(CatalogKeysetFetchKind::Artifact,
                    h.keyset.activeOperation, keyset);
    h.resolve.finish(
        CatalogResolveResultKind::SignedCatalog,
        directoryCatalogEnvelopeForCoordinatorTest(
            h.resolve.activeAttempt.requestNonce, 2,
            {ConnectionMode::ForceAwg, {}}));
    expect(h.reducer.reconcileCalls == 1 && h.reducer.disconnectCalls == 0,
           "matching live catalog reaches reconcile without releasing the outer guard");

    expect(coordinator.requestConnectionMode(ConnectionMode::ForceXray, error),
           "OFF-race setup starts one more scoped live resolve");
    h.keyset.finish(CatalogKeysetFetchKind::Artifact,
                    h.keyset.activeOperation, keyset);
    coordinator.requestDisconnect();
    h.resolve.finish(
        CatalogResolveResultKind::SignedCatalog,
        directoryCatalogEnvelopeForCoordinatorTest(
            h.resolve.activeAttempt.requestNonce, 3,
            {ConnectionMode::ForceXray, {}}));
    expect(h.reducer.reconcileCalls == 1 && h.reducer.connectCalls == 1,
           "OFF during scoped resolve makes the late signed result presentation-only");
}

void authoritativeEndpointTombstonePrecedesCatalogRejection()
{
    enum class Rejection { Signature, UnknownSigner, Revision, Clock };
    const QList<Rejection> variants{
        Rejection::Signature, Rejection::UnknownSigner,
        Rejection::Revision, Rejection::Clock};
    for (const Rejection variant : variants) {
        Harness h;
        configureCoordinatorTestRoot(h);
        CatalogCoordinator coordinator = h.make();
        QString error;
        expect(coordinator.initialize(error) && coordinator.requestConnect(error),
               "endpoint tombstone rejection setup starts discovery");
        const QByteArray keyset = keysetEnvelopeForCoordinatorTest(
            1, h.source.now.addDays(-1), h.source.now.addDays(30));
        h.keyset.finish(CatalogKeysetFetchKind::Artifact,
                        h.keyset.activeOperation, keyset);
        const QString nonce = h.resolve.activeAttempt.requestNonce;
        QByteArray envelope;
        if (variant == Rejection::UnknownSigner) {
            envelope = timedCatalogEnvelopeForCoordinatorTest(
                nonce, 1, h.source.now.addSecs(-60),
                QByteArrayLiteral("unknown-catalog-seed"),
                QStringLiteral("catalog-unknown"), 1);
        } else if (variant == Rejection::Revision) {
            envelope = timedCatalogEnvelopeForCoordinatorTest(
                nonce, 0, h.source.now.addSecs(-60));
        } else if (variant == Rejection::Clock) {
            envelope = timedCatalogEnvelopeForCoordinatorTest(
                nonce, 1, h.source.now.addDays(2));
        } else {
            envelope = timedCatalogEnvelopeForCoordinatorTest(
                nonce, 1, h.source.now.addSecs(-60));
            envelope[envelope.size() - 2] =
                envelope.at(envelope.size() - 2) == 'A' ? 'B' : 'A';
        }
        h.resolve.finish(CatalogResolveResultKind::SignedCatalog, envelope);
        expect(h.store.writes == 1
                   && h.store.loaded.authoritativeV2EndpointSeen
                   && h.store.loaded.verifiedEnvelope.isEmpty()
                   && !h.store.loaded.trustState.hasAcceptedV2
                   && !h.store.loaded.acceptedKeysetState.isEmpty()
                   && h.facade.v2Authoritative()
                   && !h.facade.legacyV1Allowed()
                   && h.reducer.connectCalls == 0,
               "endpoint-only authority is durable before every catalog rejection");

        QByteArray plaintext;
        CatalogLkgRecord parsed;
        expect(CatalogSecureStore::serializePlaintext(
                   h.store.loaded, plaintext, error)
                   && CatalogSecureStore::parsePlaintext(
                       plaintext, parsed, error),
               "endpoint rejection tombstone round-trips through schema-v4 codec");
        Harness relaunched;
        configureCoordinatorTestRoot(relaunched);
        relaunched.source.now = h.source.now;
        relaunched.store.status = CatalogLkgLoadStatus::Loaded;
        relaunched.store.loaded = parsed;
        CatalogCoordinator afterCrash = relaunched.make();
        expect(afterCrash.initialize(error)
                   && relaunched.facade.v2Authoritative()
                   && !relaunched.facade.legacyV1Allowed()
                   && !relaunched.facade.catalogAvailable()
                   && relaunched.keyset.starts == 0
                   && relaunched.reducer.connectCalls == 0,
               "relaunch after rejected catalog cannot reopen legacy or native start");
    }
}

void cleanInstallConnectStartsDiscoveryAndOffFencesIt()
{
    Harness h;
    CatalogCoordinator coordinator = h.make();
    QString error;
    expect(coordinator.initialize(error), "clean production foundation initializes");
    expect(h.inventory.calls == 1, "runtime inventory is sampled before LKG/network");
    expect(h.keyset.starts == 0,
           "local initialization never performs background v2 authority discovery");
    expect(!h.facade.v2Authoritative(), "clean NotFound/Empty store keeps legacy allowed");
    expect(h.facade.legacyV1Allowed(), "legacy is allowed before authoritative v2");
    expect(coordinator.requestConnect(error), "first connect accepts discovery intent");
    expect(h.keyset.starts == 1, "first connect dispatches keyset fetch without candidate precheck");
    expect(h.reducer.connectCalls == 0, "no reducer start occurs before signed catalog");
    expect(coordinator.requestConnect(error), "repeat connect while discovery is idempotent");
    expect(h.keyset.starts == 1, "repeat connect does not duplicate keyset fetch");
    coordinator.requestDisconnect();
    expect(h.reducer.disconnectCalls == 1, "explicit OFF reaches the v2 reducer");
    h.keyset.finish(CatalogKeysetFetchKind::NetworkUnavailable, 1);
    expect(h.reducer.connectCalls == 0, "late discovery result cannot reconnect after OFF");
}

void firstConnectWaitsForEnrollmentWithoutNetworkOrLegacyAuthority()
{
    Harness h;
    h.config.bearerTokenProvider = [] { return QByteArray{}; };
    CatalogCoordinator coordinator = h.make();
    QString error;
    expect(coordinator.initialize(error),
           "tokenless clean install can restore local trust/inventory state");
    expect(!coordinator.requestConnect(error)
               && error == QLatin1String("catalog_auth_not_ready"),
           "first connect without enrollment is a typed deferred-auth result");
    expect(h.keyset.starts == 0 && h.resolve.starts == 0
               && h.reducer.connectCalls == 0,
           "missing auth dispatches neither v2 network nor native nor legacy work");
    expect(!h.facade.v2Authoritative() && h.facade.legacyV1Allowed(),
           "absence of an authenticated response alone does not assert v2 authority");
}

void catalogListRefreshNeverBecomesConnectionIntent()
{
    Harness h;
    CatalogCoordinator coordinator = h.make();
    QString error;
    expect(coordinator.initialize(error), "list-refresh coordinator initializes locally");
    expect(coordinator.requestCatalogRefresh(error),
           "explicit server-list refresh dispatches signed discovery");
    expect(h.keyset.starts == 1 && h.reducer.connectCalls == 0
               && h.reducer.disconnectCalls == 0,
           "list refresh neither starts nor mutates a native tunnel");
    h.keyset.finish(CatalogKeysetFetchKind::NetworkUnavailable, 1);
    expect(h.reducer.connectCalls == 0,
           "late list-refresh failure cannot turn into connection intent");
}

void legacyNativeOwnerBlocksDiscoveryUntilExactTerminal()
{
    Harness h;
    CatalogCoordinator coordinator = h.make();
    QString error;
    expect(coordinator.initialize(error), "migration coordinator initializes locally");
    coordinator.setExternalNativeOwnershipBlocked(true);
    coordinator.applicationResumed();
    coordinator.networkPathChanged(CatalogNetworkClass::Cellular,
                                   QStringLiteral("legacy-owner-path"));
    expect(coordinator.requestConnect(error),
           "v2 intent queues while a legacy native owner is tearing down");
    expect(h.keyset.starts == 0 && h.resolve.starts == 0
               && h.reducer.connectCalls == 0,
           "legacy Connecting/Connected barrier permits no discovery or native start");
    expect(h.facade.connectionStage() == QLatin1String("disconnecting")
               && h.facade.errorCode()
                      == QLatin1String("legacy_native_teardown_pending"),
           "migration wait is externally typed without claiming Disconnected");
    coordinator.setExternalNativeOwnershipBlocked(false);
    QCoreApplication::processEvents();
    expect(h.keyset.starts == 1,
           "exact legacy terminal receipt resumes the retained v2 discovery intent once");
    coordinator.setExternalNativeOwnershipBlocked(false);
    QCoreApplication::processEvents();
    expect(h.keyset.starts == 1,
           "duplicate terminal callbacks cannot duplicate v2 ownership/discovery");
}

void corruptDurableStoreFailsClosedInPresentation()
{
    Harness h;
    h.store.status = CatalogLkgLoadStatus::Error;
    CatalogCoordinator coordinator = h.make();
    QString error;
    expect(!coordinator.initialize(error), "secure-store error blocks production readiness");
    expect(h.inventory.calls == 0, "secure-store ambiguity fails before unrelated inventory work");
    expect(h.facade.v2Authoritative(), "ambiguous durable store closes legacy fail-closed");
    expect(!h.facade.legacyV1Allowed(), "store corruption never reopens v1");
    expect(h.facade.connectionStage() == QLatin1String("failed"),
           "store corruption is a typed terminal facade state");
}

void restoredAuthorityPrecedesFallibleRuntimeInventory()
{
    Harness h;
    h.store.status = CatalogLkgLoadStatus::Loaded;
    h.store.loaded.authoritativeV2EndpointSeen = true;
    h.inventory.available = false;
    CatalogCoordinator coordinator = h.make();
    QString error;
    expect(!coordinator.initialize(error), "unavailable runtime inventory blocks v2 startup");
    expect(h.inventory.calls == 1, "local inventory is still sampled once");
    expect(h.facade.v2Authoritative(),
           "authenticated v2 tombstone is published before inventory failure");
    expect(!h.facade.legacyV1Allowed(),
           "runtime manifest outage cannot resurrect legacy after accepted v2");
}

void tombstoneOnlyRecordRestoresAuthorityBeforeCatalog()
{
    Harness h;
    h.store.status = CatalogLkgLoadStatus::Loaded;
    h.store.loaded.authoritativeV2EndpointSeen = true;
    CatalogCoordinator coordinator = h.make();
    QString error;
    expect(coordinator.initialize(error), "tombstone-only secure record restores");
    expect(coordinator.authoritativeV2(), "authoritative endpoint tombstone is durable");
    expect(h.facade.v2Authoritative(), "facade publishes restored tombstone before connect");
    expect(!h.facade.catalogAvailable(), "tombstone alone does not invent a catalog");
}

void logoutWaitsForExactTeardownAndSecureWipe()
{
    Harness h;
    int completedLogouts = 0;
    QObject::connect(&h.facade, &CatalogConnectionFacade::secureLogoutCompleted,
                     [&completedLogouts]() { ++completedLogouts; });
    h.store.status = CatalogLkgLoadStatus::Loaded;
    h.store.loaded.authoritativeV2EndpointSeen = true;
    CatalogCoordinator coordinator = h.make();
    QString error;
    expect(coordinator.initialize(error), "logout coordinator restores v2 tombstone");
    ConnectionRuntimeSnapshot live;
    live.phase = ConnectionPhase::ConnectedHealthy;
    live.session = {7, 9};
    live.profileId = QStringLiteral("profile-live");
    live.transport = TransportKind::Awg;
    live.configGeneration = 3;
    live.bindingGeneration = 4;
    live.guardArmed = true;
    live.hasAcceptedV2 = true;
    coordinator.onConnectionReducerSnapshot(live);

    coordinator.clearAfterLogout();
    expect(h.reducer.disconnectCalls == 1 && h.store.clears == 0,
           "logout first requests exact reducer teardown and preserves secure authority");
    expect(!coordinator.requestConnect(error)
               && error == QLatin1String("logout_in_progress"),
           "connect is blocked throughout logout teardown");
    expect(h.facade.v2Authoritative() && !h.facade.legacyV1Allowed(),
           "legacy remains fenced before exact inner stop and guard release");

    ConnectionRuntimeSnapshot released;
    released.phase = ConnectionPhase::Idle;
    released.hasAcceptedV2 = true;
    coordinator.onConnectionReducerSnapshot(released);
    expect(h.store.clears == 1 && !h.facade.v2Authoritative()
               && h.facade.legacyV1Allowed() && completedLogouts == 1,
           "only exact Idle plus released guard completes secure logout and reopens legacy");

    Harness failed;
    failed.store.status = CatalogLkgLoadStatus::Loaded;
    failed.store.loaded.authoritativeV2EndpointSeen = true;
    failed.store.failClear = true;
    CatalogCoordinator failedCoordinator = failed.make();
    expect(failedCoordinator.initialize(error), "failed-wipe coordinator restores v2 tombstone");
    failedCoordinator.onConnectionReducerSnapshot(live);
    failedCoordinator.clearAfterLogout();
    failedCoordinator.onConnectionReducerSnapshot(released);
    expect(failed.store.clears == 1 && failed.facade.v2Authoritative()
               && !failed.facade.legacyV1Allowed(),
           "partial secure wipe stays fail-closed and never exposes legacy");

    CatalogConnectionFacade cleanInstall;
    int cleanInstallCompletions = 0;
    QObject::connect(&cleanInstall, &CatalogConnectionFacade::secureLogoutCompleted,
                     [&cleanInstallCompletions]() { ++cleanInstallCompletions; });
    cleanInstall.setCoordinatorStage(QStringLiteral("resolving"));
    expect(cleanInstallCompletions == 0,
           "broad false-authority NOTIFY cannot impersonate secure logout completion");
    cleanInstall.clearV2AuthorityAfterSecureLogout();
    expect(cleanInstallCompletions == 1,
           "clean-install queued intent receives the dedicated secure logout completion");
}

void facadeV2ActionsNeverNeedLegacyEngine()
{
    CatalogConnectionFacade facade;
    FakeFacadeActions actions;
    facade.setActions(&actions);
    expect(facade.refreshCatalog(), "facade dispatches control-plane-only catalog refresh");
    expect(facade.reselectV2(), "facade dispatches v2-owned reselect");
    expect(facade.startDoctorV2(), "facade dispatches v2-owned doctor");
    expect(actions.refresh == 1 && actions.reselect == 1 && actions.doctor == 1,
           "v2 actions use only the coordinator action interface");
}

void outcomeAbiMatchesBackendGoldenAndStrictHttpContract()
{
    const QString fixture = QFileInfo(QString::fromUtf8(__FILE__)).absolutePath()
        + QStringLiteral("/fixtures/outcome_v1_golden_request.json");
    QFile file(fixture);
    expect(file.open(QIODevice::ReadOnly), "backend outcome golden fixture opens");
    const QJsonObject golden = QJsonDocument::fromJson(file.readAll()).object();
    CatalogOutcomeEvent event;
    event.eventId = golden.value(QStringLiteral("event_id")).toString();
    event.deviceAudience = golden.value(QStringLiteral("device_audience")).toString();
    event.profileId = golden.value(QStringLiteral("profile_id")).toString();
    event.bindingGeneration = quint64(golden.value(QStringLiteral("binding_generation")).toDouble());
    event.configGeneration = quint64(golden.value(QStringLiteral("config_generation")).toDouble());
    event.catalogRevision = quint64(golden.value(QStringLiteral("catalog_revision")).toDouble());
    event.context = golden.value(QStringLiteral("context")).toString();
    event.transport = TransportKind::Awg;
    event.networkClass = CatalogNetworkClass::Wired;
    event.stage = CatalogOutcomeStage::Connected;
    event.connectMs = 120;
    event.dnsMs = 10;
    event.receiptMs = 30;
    event.sessionMs = 310000;
    event.verifiedSuccess = true;
    event.survived5m = true;
    event.queuedAtUtc = QDateTime::fromString(
        QStringLiteral("2026-08-28T12:00:00.000Z"), Qt::ISODateWithMs);
    QJsonObject body;
    QString error;
    expect(buildCatalogOutcomeUpload(event, body, error), "outcome golden event compiles");
    expect(body == golden, "client outcome JSON matches backend golden byte semantics");
    event.sessionMs = 299999;
    expect(!buildCatalogOutcomeUpload(event, body, error),
           "five-minute survival below exact boundary is rejected");

    CatalogOutcomeHttpResponse response;
    response.status = 200;
    response.headers.insert(QByteArrayLiteral("cache-control"),
                            QByteArrayLiteral("private, no-store"));
    response.headers.insert(QByteArrayLiteral("content-type"),
                            QByteArrayLiteral("application/json"));
    response.body = QByteArrayLiteral(
        "{\"schema_version\":1,\"accepted\":true,\"duplicate\":false}");
    CatalogOutcomeUploadResult result;
    expect(parseCatalogOutcomeHttpResponse(response, result, error),
           "strict outcome ACK parses");
    expect(result.kind == CatalogOutcomeUploadKind::Acknowledged && !result.duplicate,
           "outcome ACK is classified exactly");
    response.body = QByteArrayLiteral(
        "{\"schema_version\":1.5,\"accepted\":true,\"duplicate\":false}");
    expect(!parseCatalogOutcomeHttpResponse(response, result, error),
           "fractional outcome schema is never truncated to v1");
    response.body = QByteArrayLiteral(
        "{\"schema_version\":1,\"accepted\":true,\"duplicate\":false}");
    response.headers.insert(QByteArrayLiteral("cache-control"),
                            QByteArrayLiteral("public, no-store"));
    expect(!parseCatalogOutcomeHttpResponse(response, result, error),
           "public cache policy is rejected");

    response.status = 429;
    response.headers.insert(QByteArrayLiteral("cache-control"),
                            QByteArrayLiteral("private, no-store"));
    response.headers.insert(QByteArrayLiteral("retry-after"), QByteArrayLiteral("60"));
    response.body = QByteArrayLiteral(
        "{\"schema_version\":1,\"code\":\"rate_limited\","
        "\"message\":\"later\",\"retry_after\":60}");
    expect(parseCatalogOutcomeHttpResponse(response, result, error)
               && result.kind == CatalogOutcomeUploadKind::Retryable
               && result.retryAfterS == 60,
           "outcome rate-limit is bounded retry, never connect failure");
}

void durableOutcomeUploaderDeletesOnlyAfterExactAck()
{
    Harness h;
    h.store.status = CatalogLkgLoadStatus::Loaded;
    h.store.loaded.authoritativeV2EndpointSeen = true;
    CatalogRuntimeState runtime;
    CatalogOutcomeEvent event;
    event.eventId = QStringLiteral("123e4567-e89b-42d3-a456-426614174000");
    event.deviceAudience = QString::fromLatin1(
        QByteArray(32, 'a').toBase64(QByteArray::Base64UrlEncoding
                                      | QByteArray::OmitTrailingEquals));
    event.profileId = QStringLiteral("profile-outcome-1");
    event.configGeneration = 3;
    event.bindingGeneration = 4;
    event.catalogRevision = 8;
    event.context = QStringLiteral("context-outcome-v1");
    event.transport = TransportKind::Xray;
    event.networkClass = CatalogNetworkClass::Wifi;
    event.stage = CatalogOutcomeStage::Disconnected;
    event.verifiedSuccess = false;
    event.sessionMs = 42000;
    event.queuedAtUtc = h.source.now;
    QString error;
    expect(appendCatalogOutcome(runtime, event, error),
           "valid redacted outcome enters bounded durable queue");
    expect(serializeCatalogRuntimeState(runtime, h.store.loaded.runtimeState, error),
           "pending outcome serializes into encrypted record payload");

    FakeOutcomeClient uploader;
    CatalogCoordinator coordinator = h.make();
    coordinator.setOutcomeClient(&uploader);
    expect(coordinator.initialize(error), "outcome-bearing tombstone record restores");
    expect(uploader.starts == 1 && uploader.lastEvent.eventId == event.eventId,
           "cold restart immediately replays exact pending idempotency event");
    uploader.finish(CatalogOutcomeUploadKind::Retryable, 60);
    CatalogRuntimeState afterRetry;
    expect(parseCatalogRuntimeState(h.store.loaded.runtimeState, afterRetry, error)
               && afterRetry.pendingOutcomes.size() == 1,
           "offline/rate-limited upload never deletes without backend ACK");

    coordinator.setOutcomeClient(nullptr);
    coordinator.setOutcomeClient(&uploader);
    QCoreApplication::processEvents();
    expect(uploader.starts == 2 && uploader.lastEvent.eventId == event.eventId,
           "same durable UUID is replayed after uploader restart");
    uploader.finish(CatalogOutcomeUploadKind::Acknowledged, 0, true);
    CatalogRuntimeState afterAck;
    expect(parseCatalogRuntimeState(h.store.loaded.runtimeState, afterAck, error)
               && afterAck.pendingOutcomes.isEmpty(),
           "duplicate/accepted ACK is the only durable deletion boundary");
}

void receiptVerifierRetriesEveryResolvedSignedBootstrapIp()
{
    Harness h;
    QString error;
    expect(h.clock.restore({}, error), "receipt test trusted clock initializes");
    ReceiptAttemptScript script;
    int lookupCounter = 20;
    ReceiptDnsLookup dns = [&lookupCounter](const QString &, QObject *owner,
                                            ReceiptDnsCallback callback) {
        const int id = ++lookupCounter;
        QHostInfo info;
        info.setLookupId(id);
        info.setAddresses({QHostAddress(QStringLiteral("8.8.8.8")),
                           QHostAddress(QStringLiteral("1.1.1.1"))});
        QTimer::singleShot(0, owner, [callback = std::move(callback), info]() {
            callback(info);
        });
        return id;
    };
    ReceiptNetworkFactory factory = [&script](QObject *owner) {
        const bool fail = script.managers++ == 0;
        return new ScriptedReceiptNetwork(&script, fail, owner);
    };
    PostTunnelReceiptVerifier verifier(&h.clock, nullptr, 15000, 32768,
                                       factory, dns, [](int) {});
    ReceiptVerifierAuthority authority;
    authority.verificationToken = QByteArrayLiteral("v1.receipt-only.test.signature");
    authority.deviceAudience = QString::fromLatin1(
        QByteArray(32, 'a').toBase64(QByteArray::Base64UrlEncoding
                                      | QByteArray::OmitTrailingEquals));
    authority.catalogRevision = 7;
    authority.keysetEpoch = 2;
    authority.expiresAt = h.source.now.addSecs(900);
    ReceiptVerificationProvider first;
    first.id = QStringLiteral("verifier-a");
    first.trustDomain = QStringLiteral("edge-a");
    first.endpoint = QUrl(QStringLiteral("https://verify-a.example/v2/verify/receipt"));
    first.receiptPublicKeysHex.insert(QStringLiteral("receipt-a-k1"),
                                      QString(64, QLatin1Char('1')));
    first.protectedAuthorityIps = {QStringLiteral("1.1.1.1"),
                                   QStringLiteral("8.8.8.8")};
    ReceiptVerificationProvider second;
    second.id = QStringLiteral("verifier-b");
    second.trustDomain = QStringLiteral("edge-b");
    second.endpoint = QUrl(QStringLiteral("https://verify-b.example/v2/verify/receipt"));
    second.receiptPublicKeysHex.insert(QStringLiteral("receipt-b-k1"),
                                       QString(64, QLatin1Char('2')));
    second.protectedAuthorityIps = {QStringLiteral("9.9.9.9")};
    authority.providers = {first, second};
    expect(verifier.setAuthority(authority, error),
           "strict dual-provider receipt authority accepts test policy");
    ReceiptResultObserver observer;
    verifier.setObserver(&observer);
    CatalogCandidate candidate;
    candidate.profileId = QStringLiteral("profile-bootstrap-retry");
    candidate.nativeProfile.configGeneration = 3;
    candidate.nativeProfile.bindingGeneration = 4;
    candidate.verification.context = QStringLiteral("context-bootstrap-retry");
    // Egress identities follow the backend/OpenAPI hierarchy grammar and may contain '/'; they
    // are intentionally distinct from the slash-free verification-context grammar.
    candidate.verification.expectedEgressIds = {QStringLiteral("provider-a/fi")};
    const VerificationToken token{{101, 202}, 1};
    const bool started = verifier.start(candidate, token, error);
    if (!started) qWarning().noquote() << "receipt retry start:" << error;
    expect(started,
           "receipt verifier starts after TunnelReady prerequisites");
    for (int pass = 0; pass < 8 && script.pinnedHosts.size() < 2; ++pass)
        QCoreApplication::processEvents();
    expect(script.pinnedHosts == QStringList{QStringLiteral("1.1.1.1"),
                                             QStringLiteral("8.8.8.8")},
           "first dead signed IP advances to the second under one provider deadline");
    expect(script.nonces.size() == 2 && !script.nonces.at(0).isEmpty()
               && script.nonces.at(0) != script.nonces.at(1),
           "each bootstrap transport retry uses a fresh anti-replay nonce");
    const QSet<QString> receiptRequestKeys{
        QStringLiteral("schema_version"), QStringLiteral("nonce"),
        QStringLiteral("provider_id"), QStringLiteral("device_audience"),
        QStringLiteral("profile_id"), QStringLiteral("binding_generation"),
        QStringLiteral("config_generation"), QStringLiteral("context"),
        QStringLiteral("min_probe_bytes")};
    const QStringList firstRequestKeyList = script.requestBodies.at(0).keys();
    const QSet<QString> firstRequestKeys(firstRequestKeyList.cbegin(),
                                         firstRequestKeyList.cend());
    expect(script.requestBodies.size() == 2
               && firstRequestKeys == receiptRequestKeys
               && script.requestBodies.at(0).value(QStringLiteral("provider_id"))
                      == QLatin1String("verifier-a")
               && script.requestBodies.at(0).value(QStringLiteral("config_generation"))
                      .toDouble() == 3.0
               && script.requestBodies.at(0).value(QStringLiteral("binding_generation"))
                      .toDouble() == 4.0
               && script.requestBodies.at(0).value(QStringLiteral("min_probe_bytes"))
                      .toDouble() == 32768.0,
           "receipt request uses the frozen provider/profile/config/binding v1 schema");
    expect(script.authorizationHeaders.size() == 2
               && script.authorizationHeaders.at(0)
                      == QByteArrayLiteral("Bearer v1.receipt-only.test.signature")
               && script.authorizationHeaders.at(1)
                      == script.authorizationHeaders.at(0),
           "receipt providers receive only the catalog-scoped verification grant");
    expect(observer.results.isEmpty(),
           "one dead IP does not prematurely classify the candidate while alternatives remain");
    verifier.cancel(token);

    ReceiptAttemptScript allDead;
    ReceiptNetworkFactory allDeadFactory = [&allDead](QObject *owner) {
        ++allDead.managers;
        return new ScriptedReceiptNetwork(&allDead, true, owner);
    };
    int allDeadLookupCounter = 80;
    ReceiptDnsLookup allDeadDns = [&allDeadLookupCounter](
        const QString &host, QObject *owner, ReceiptDnsCallback callback) {
        const int id = ++allDeadLookupCounter;
        QHostInfo info;
        info.setLookupId(id);
        info.setAddresses(host == QLatin1String("verify-b.example")
                              ? QList<QHostAddress>{QHostAddress(QStringLiteral("9.9.9.9"))}
                              : QList<QHostAddress>{QHostAddress(QStringLiteral("8.8.8.8")),
                                                    QHostAddress(QStringLiteral("1.1.1.1"))});
        QTimer::singleShot(0, owner, [callback = std::move(callback), info]() {
            callback(info);
        });
        return id;
    };
    PostTunnelReceiptVerifier exhausted(&h.clock, nullptr, 15000, 32768,
                                        allDeadFactory, allDeadDns, [](int) {});
    expect(exhausted.setAuthority(authority, error),
           "second strict receipt authority installs independently");
    ReceiptResultObserver exhaustedObserver;
    exhausted.setObserver(&exhaustedObserver);
    const VerificationToken exhaustedToken{{102, 203}, 1};
    expect(exhausted.start(candidate, exhaustedToken, error),
           "all-dead bootstrap scenario starts");
    for (int pass = 0; pass < 12 && exhaustedObserver.results.isEmpty(); ++pass)
        QCoreApplication::processEvents();
    expect(allDead.pinnedHosts.size() == 3
               && exhaustedObserver.results.size() == 1
               && exhaustedObserver.results.first().disposition
                      == VerificationDisposition::CandidateFailed
               && exhaustedObserver.results.first().failureStage
                      == ConnectionFailureStage::VerificationTraffic,
           "zero proof across both independent providers remains candidate-path evidence after "
           "every signed bootstrap IP is attempted");
}

void receiptVerifierParsesTypedHttpErrorsDespiteQtContentErrors()
{
    Harness h;
    QString error;
    expect(h.clock.restore({}, error), "typed receipt HTTP test clock initializes");

    ReceiptVerifierAuthority authority;
    authority.verificationToken = QByteArrayLiteral("v1.receipt-only.test.signature");
    authority.deviceAudience = QString::fromLatin1(
        QByteArray(32, 'a').toBase64(QByteArray::Base64UrlEncoding
                                      | QByteArray::OmitTrailingEquals));
    authority.catalogRevision = 7;
    authority.keysetEpoch = 2;
    authority.expiresAt = h.source.now.addSecs(900);
    for (const auto &[id, domain, endpoint, ip, keyDigit] : {
             std::tuple{QStringLiteral("verifier-a"), QStringLiteral("edge-a"),
                        QStringLiteral("https://verify-a.example/v2/verify/receipt"),
                        QStringLiteral("1.1.1.1"), QLatin1Char('1')},
             std::tuple{QStringLiteral("verifier-b"), QStringLiteral("edge-b"),
                        QStringLiteral("https://verify-b.example/v2/verify/receipt"),
                        QStringLiteral("9.9.9.9"), QLatin1Char('2')}}) {
        ReceiptVerificationProvider provider;
        provider.id = id;
        provider.trustDomain = domain;
        provider.endpoint = QUrl(endpoint);
        provider.receiptPublicKeysHex.insert(id + QStringLiteral("-k1"),
                                             QString(64, keyDigit));
        provider.protectedAuthorityIps = {ip};
        authority.providers.append(provider);
    }

    CatalogCandidate candidate;
    candidate.profileId = QStringLiteral("profile-typed-http");
    candidate.nativeProfile.configGeneration = 3;
    candidate.nativeProfile.bindingGeneration = 4;
    candidate.verification.context = QStringLiteral("context-typed-http-v1");
    candidate.verification.expectedEgressIds = {QStringLiteral("provider-a/fi")};

    const QList<std::tuple<ReceiptHttpFailureScript, VerificationDisposition,
                           QString, int>> scenarios{
        {{409, QNetworkReply::ContentConflictError,
          QByteArrayLiteral("{\"code\":\"binding_stale\"}"), 0},
         VerificationDisposition::CatalogStale,
         QStringLiteral("receipt_binding_stale"), 0},
        {{429, QNetworkReply::UnknownContentError,
          QByteArrayLiteral("{\"code\":\"rate_limited\",\"retry_after\":37}"), 37},
         VerificationDisposition::InfrastructureUnavailable,
         QStringLiteral("receipt_rate_limited"), 37},
        {{503, QNetworkReply::ServiceUnavailableError,
          QByteArrayLiteral("{\"code\":\"temporarily_unavailable\",\"retry_after\":41}"), 41},
         VerificationDisposition::InfrastructureUnavailable,
         QStringLiteral("receipt_temporarily_unavailable"), 41},
        {{401, QNetworkReply::AuthenticationRequiredError,
          QByteArrayLiteral("{\"code\":\"auth_invalid\"}"), 0},
         VerificationDisposition::AuthorityRejected,
         QStringLiteral("receipt_auth_invalid"), 0},
    };

    quint64 operation = 300;
    for (const auto &scenario : scenarios) {
        const ReceiptHttpFailureScript script = std::get<0>(scenario);
        const VerificationDisposition expectedDisposition = std::get<1>(scenario);
        const QString expectedReason = std::get<2>(scenario);
        const int expectedRetry = std::get<3>(scenario);
        ReceiptNetworkFactory factory = [script](QObject *owner) {
            return new ScriptedReceiptHttpFailureNetwork(script, owner);
        };
        ReceiptDnsLookup dns = [](const QString &, QObject *owner,
                                  ReceiptDnsCallback callback) {
            QHostInfo info;
            info.setLookupId(77);
            info.setAddresses({QHostAddress(QStringLiteral("1.1.1.1"))});
            QTimer::singleShot(0, owner, [callback = std::move(callback), info]() {
                callback(info);
            });
            return 77;
        };
        PostTunnelReceiptVerifier verifier(&h.clock, nullptr, 15000, 32768,
                                           factory, dns, [](int) {});
        expect(verifier.setAuthority(authority, error),
               "typed receipt HTTP authority installs");
        ReceiptResultObserver observer;
        verifier.setObserver(&observer);
        const VerificationToken token{{++operation, operation + 100}, 1};
        expect(verifier.start(candidate, token, error),
               "typed receipt HTTP scenario starts");
        for (int pass = 0; pass < 12 && observer.results.isEmpty(); ++pass)
            QCoreApplication::processEvents();
        expect(observer.results.size() == 1
                   && observer.results.first().disposition == expectedDisposition
                   && observer.results.first().typedReason == expectedReason
                   && observer.results.first().retryAfterSeconds == expectedRetry,
               "Qt HTTP content/server error preserves the typed receipt policy result");
    }
}

void catalogStaleWaitsForExactReleaseThenRefreshesAndReconnectsOnce()
{
    Harness h;
    const auto decodedRoot = QByteArray::fromBase64Encoding(
        fixtureBytes("keyset_v1_golden_root_public_key.txt"),
        QByteArray::Base64UrlEncoding | QByteArray::AbortOnBase64DecodingErrors);
    expect(decodedRoot.decodingStatus == QByteArray::Base64DecodingStatus::Ok
               && decodedRoot.decoded.size() == 32,
           "coordinator stale test root fixture is canonical");
    h.config.bundledRootPublicKeysHex = {
        {QStringLiteral("tribe-root-1"), QString::fromLatin1(decodedRoot.decoded.toHex())}};
    CatalogCoordinator coordinator = h.make();
    QString error;
    expect(coordinator.initialize(error), "catalog-stale coordinator initializes");

    const QByteArray keyset = fixtureBytes("keyset_v1_golden_envelope.json");
    const CatalogKeysetAcceptance keysetCheck = acceptCatalogKeysetEnvelope(
        keyset, h.config.bundledRootPublicKeysHex, {}, h.source.now);
    if (!keysetCheck.accepted)
        qWarning().noquote() << "catalog-stale keyset fixture rejected:"
                             << keysetCheck.detail;
    expect(keysetCheck.accepted, "catalog-stale keyset fixture is accepted");
    const auto finishFreshCatalog = [&](quint64 revision) {
        const quint64 keysetOperation = h.keyset.activeOperation;
        expect(keysetOperation != 0, "fresh catalog recovery owns one keyset operation");
        h.keyset.finish(CatalogKeysetFetchKind::Artifact, keysetOperation, keyset);
        if (!h.resolve.activeAttempt.operation)
            qWarning().noquote() << "catalog-stale resolve was not dispatched:"
                                 << h.facade.connectionStage() << h.facade.errorCode()
                                 << "resolve starts" << h.resolve.starts;
        expect(h.resolve.activeAttempt.operation != 0,
               "accepted root keyset dispatches one bound resolve");
        const QByteArray envelope = freshCatalogEnvelopeForCoordinatorTest(
            h.resolve.activeAttempt.requestNonce, revision);
        expect(!envelope.isEmpty(), "fresh catalog recovery fixture signs");
        if (revision == 1842) {
            CatalogResolveRequest diagnosticRequest;
            PlatformCapabilities diagnosticCaps;
            QVariantList diagnosticVersions;
            QString diagnosticError;
            h.inventory.snapshot(diagnosticRequest, diagnosticCaps,
                                 diagnosticVersions, diagnosticError);
            diagnosticCaps.capabilities.insert(
                QStringLiteral("probe.egress_receipt_v1"));
            const CatalogAcceptanceResult diagnostic = acceptCatalogEnvelope(
                envelope, keysetCheck.keyrings.catalog, diagnosticCaps, {},
                CatalogSource::Network, h.source.now,
                {h.resolve.activeAttempt.requestNonce});
            if (!diagnostic.authoritative || !diagnostic.connectable)
                qWarning().noquote() << "catalog-stale signed fixture rejected:"
                                     << int(diagnostic.error)
                                     << int(diagnostic.parseError.code)
                                     << int(diagnostic.trustError)
                                     << diagnostic.detail;
        }
        h.resolve.finish(CatalogResolveResultKind::SignedCatalog, envelope);
    };

    expect(coordinator.requestConnect(error) && h.keyset.starts == 1,
           "initial ON starts signed discovery");
    finishFreshCatalog(1842);
    if (h.reducer.connectCalls != 1)
        qWarning().noquote() << "catalog-stale initial catalog did not connect:"
                             << h.facade.connectionStage() << h.facade.errorCode()
                             << "store writes" << h.store.writes;
    expect(h.reducer.connectCalls == 1,
           "initial signed AWG/Xray catalog reaches the reducer once");

    const auto liveSnapshot = [](quint64 operation, quint64 session) {
        ConnectionRuntimeSnapshot snapshot;
        snapshot.phase = ConnectionPhase::ConnectedHealthy;
        snapshot.operation = operation;
        snapshot.session = {operation, session};
        snapshot.profileId = QStringLiteral("fi-awg-02");
        snapshot.locationId = QStringLiteral("fi-hel");
        snapshot.transport = TransportKind::Awg;
        snapshot.configGeneration = 12;
        snapshot.bindingGeneration = 3;
        snapshot.guardArmed = true;
        snapshot.hasAcceptedV2 = true;
        return snapshot;
    };
    const auto staleSnapshot = [](ConnectionRuntimeSnapshot snapshot,
                                  ConnectionPhase phase) {
        snapshot.phase = phase;
        snapshot.terminalDisposition = ConnectionTerminalDisposition::CatalogStale;
        snapshot.lastFailureStage = ConnectionFailureStage::VerificationAuthority;
        snapshot.lastTypedReason = QStringLiteral("receipt_binding_stale");
        return snapshot;
    };

    ConnectionRuntimeSnapshot live = liveSnapshot(41, 7);
    coordinator.onConnectionReducerSnapshot(live);
    coordinator.onConnectionReducerSnapshot(staleSnapshot(live, ConnectionPhase::Failed));
    coordinator.onConnectionReducerSnapshot(staleSnapshot(live, ConnectionPhase::ReleasingGuard));
    expect(h.keyset.starts == 1 && h.reducer.connectCalls == 1,
           "typed stale receipt cannot refresh or reconnect while native/guard ownership remains");

    ConnectionRuntimeSnapshot exactReleased = staleSnapshot(live, ConnectionPhase::Failed);
    exactReleased.session = {};
    exactReleased.guardArmed = false;
    coordinator.onConnectionReducerSnapshot(exactReleased);
    coordinator.onConnectionReducerSnapshot(exactReleased); // duplicate terminal receipt
    QCoreApplication::processEvents();
    expect(h.keyset.starts == 2 && h.reducer.connectCalls == 1,
           "exact stop+release queues exactly one fresh discovery and no stale-LKG restart");
    finishFreshCatalog(1843);
    expect(h.reducer.connectCalls == 2,
           "fresh accepted catalog reconnects exactly once after typed stale teardown");

    // OFF cancels automatic reconnect but retains the stale-catalog barrier for the next ON.
    live = liveSnapshot(42, 8);
    coordinator.onConnectionReducerSnapshot(live);
    coordinator.onConnectionReducerSnapshot(staleSnapshot(live, ConnectionPhase::Failed));
    coordinator.requestDisconnect();
    exactReleased = staleSnapshot(live, ConnectionPhase::Failed);
    exactReleased.session = {};
    exactReleased.guardArmed = false;
    coordinator.onConnectionReducerSnapshot(exactReleased);
    QCoreApplication::processEvents();
    expect(h.keyset.starts == 2 && h.reducer.connectCalls == 2,
           "OFF during stale teardown fences both refresh and reconnect");

    // A level-triggered platform recovery latch also cancels a queued stale reconnect, even if ON
    // was pressed again before that queued event reached the loop.
    expect(coordinator.requestConnect(error), "next ON retains stale-refresh intent");
    const QJsonObject recovery{
        {QStringLiteral("type"), QStringLiteral("native_session_guard_v1")},
        {QStringLiteral("schema"), 1},
        {QStringLiteral("operation"), QStringLiteral("51")},
        {QStringLiteral("session"), QStringLiteral("9")},
        {QStringLiteral("kind"), QStringLiteral("armed")},
        {QStringLiteral("policy_sha256"), QString(64, QLatin1Char('a'))},
        {QStringLiteral("outer_session_id"), QStringLiteral("outer-stale-recovery")},
        {QStringLiteral("expected_runtime_session_id"),
         QStringLiteral("123e4567-e89b-42d3-a456-426614174000")},
        {QStringLiteral("reason"), QString()},
    };
    expect(coordinator.nativeSessionGuardRecoveryRequired(recovery),
           "exact platform recovery latch is accepted");
    QCoreApplication::processEvents();
    expect(h.keyset.starts == 2 && h.reducer.connectCalls == 2,
           "platform recovery fences a queued stale refresh/reconnect");
    const QJsonObject recoveryReceipt{
        {QStringLiteral("type"), QStringLiteral("native_session_guard_recovery_v1")},
        {QStringLiteral("schema"), 1},
        {QStringLiteral("action"), QStringLiteral("stop")},
        {QStringLiteral("kind"), QStringLiteral("stopped_released")},
        {QStringLiteral("operation"), QStringLiteral("51")},
        {QStringLiteral("session"), QStringLiteral("9")},
        {QStringLiteral("policy_sha256"), QString(64, QLatin1Char('a'))},
        {QStringLiteral("outer_session_id"), QStringLiteral("outer-stale-recovery")},
        {QStringLiteral("expected_runtime_session_id"),
         QStringLiteral("123e4567-e89b-42d3-a456-426614174000")},
        {QStringLiteral("reason"), QString()},
    };
    expect(coordinator.nativeSessionGuardRecoveryResolved(recoveryReceipt),
           "exact platform STOP+RELEASE resolves the recovery fence");
    expect(coordinator.requestConnect(error),
           "explicit ON after recovery resumes only fresh catalog discovery");
    QCoreApplication::processEvents();
    expect(h.keyset.starts == 3 && h.reducer.connectCalls == 2,
           "post-recovery ON still cannot reuse the stale LKG");
    finishFreshCatalog(1844);
    expect(h.reducer.connectCalls == 3,
           "post-recovery fresh catalog reconnects once");

    // Logout owns teardown and secure wipe; a stale receipt cannot resurrect discovery underneath
    // it. The real reducer clears terminalDisposition on explicit disconnect and ends at Idle.
    live = liveSnapshot(43, 10);
    coordinator.onConnectionReducerSnapshot(live);
    coordinator.onConnectionReducerSnapshot(staleSnapshot(live, ConnectionPhase::Failed));
    coordinator.clearAfterLogout();
    ConnectionRuntimeSnapshot loggedOut;
    loggedOut.phase = ConnectionPhase::Idle;
    loggedOut.operation = 44;
    loggedOut.hasAcceptedV2 = true;
    coordinator.onConnectionReducerSnapshot(loggedOut);
    QCoreApplication::processEvents();
    expect(h.keyset.starts == 3 && h.reducer.connectCalls == 3
               && h.store.clears == 1 && !h.facade.v2Authoritative(),
           "logout fences stale recovery and completes only after exact Idle+released guard");
}

void productionShapedManifestStartsFromDeviceOwnedKeys()
{
    const QString commitA(40, QLatin1Char('a'));
    const QString commitB(40, QLatin1Char('b'));
    const auto engine = [](const QString &protocol, const QString &adapter,
                           const QString &adapterVersion, const QString &core,
                           const QString &commit, const QString &abi,
                           const QJsonArray &capabilities) {
        return QJsonObject{
            {QStringLiteral("protocol"), protocol},
            {QStringLiteral("adapter"), adapter},
            {QStringLiteral("adapterVersion"), adapterVersion},
            {QStringLiteral("declaredCoreVersion"), core},
            {QStringLiteral("sourceCommit"), commit},
            {QStringLiteral("abi"), abi},
            {QStringLiteral("capabilities"), capabilities},
            {QStringLiteral("runtimeCoreVersion"), core},
            {QStringLiteral("runtimeVersionProbed"), true},
            {QStringLiteral("versionEvidence"), QStringLiteral("runtime_api")},
        };
    };
    const QJsonObject manifest{
        {QStringLiteral("type"), QStringLiteral("engine_manifest_v1")},
        {QStringLiteral("schema"), 1},
        {QStringLiteral("app"), QJsonObject{
             {QStringLiteral("version"), QStringLiteral("5.1.97")},
             {QStringLiteral("build"), 97}}},
        {QStringLiteral("engines"),
         QJsonArray{
             engine(QStringLiteral("awg"), QStringLiteral("awg-android"),
                    QStringLiteral("3.1.20260814"), QStringLiteral("3.1.20260814"),
                    commitA, QStringLiteral("awg-jni-v1"),
                    {QStringLiteral("awg.random_trailers"),
                     QStringLiteral("awg.disable_cookies"),
                     QStringLiteral("tribe.guarded_settings_owner")}),
             engine(QStringLiteral("xray"), QStringLiteral("amnezia-libxray"),
                    QStringLiteral("1.0.3"), QStringLiteral("1.260728.0"),
                    commitB, QStringLiteral("libxray-jni-v1"),
                    {QStringLiteral("xray.vless.reality.vision.tcp"),
                     QStringLiteral("tribe.guarded_settings_owner")})}},
    };
    RuntimeEngineLock lock;
    lock.manifestSchema = 1;
    lock.platform = CatalogAppPlatform::Android;
    lock.engines = {
        {QStringLiteral("awg"), QStringLiteral("awg-android"), QStringLiteral("3.1.20260814"),
         QStringLiteral("3.1.20260814"), commitA, QStringLiteral("awg-jni-v1"),
         {QStringLiteral("awg.random_trailers"),
          QStringLiteral("awg.disable_cookies"),
          QStringLiteral("tribe.guarded_settings_owner")}, true},
        {QStringLiteral("xray"), QStringLiteral("amnezia-libxray"),
         QStringLiteral("1.0.3"), QStringLiteral("1.260728.0"), commitB,
         QStringLiteral("libxray-jni-v1"),
         {QStringLiteral("xray.vless.reality.vision.tcp"),
          QStringLiteral("tribe.guarded_settings_owner")}, true},
    };
    CatalogResolveRequest request;
    // This ordering is the production invariant: applyRuntimeEngineManifest performs final
    // resolve validation, so the AWG identity must already be installed even though every other
    // request fact starts empty/default.
    request.deviceKeys.awgPublicKey = QString::fromLatin1(QByteArray(32, '\x42').toBase64());
    QString error;
    expect(applyRuntimeEngineManifest(
               manifest,
               {CatalogAppPlatform::Android, QStringLiteral("5.1.97"), 97,
                QStringLiteral("arm64-v8a")},
               lock, request, error),
           "production-shaped empty inventory accepts after device keys are preinstalled");
    expect(request.engines.awg.has_value() && request.engines.xray.has_value(),
           "manifest produces both audited client-engine tuples");
    CatalogResolveRequest missingKeys;
    expect(!applyRuntimeEngineManifest(
               manifest,
               {CatalogAppPlatform::Android, QStringLiteral("5.1.97"), 97,
                QStringLiteral("arm64-v8a")},
               lock, missingKeys, error),
           "manifest final validation rejects AWG inventory without device identity");
    QJsonObject fractionalSchema = manifest;
    fractionalSchema.insert(QStringLiteral("schema"), 1.5);
    expect(!applyRuntimeEngineManifest(
               fractionalSchema,
               {CatalogAppPlatform::Android, QStringLiteral("5.1.97"), 97,
                QStringLiteral("arm64-v8a")},
               lock, request, error),
           "fractional engine-manifest schema is rejected exactly");
    QJsonObject fractionalBuild = manifest;
    QJsonObject app = fractionalBuild.value(QStringLiteral("app")).toObject();
    app.insert(QStringLiteral("build"), 97.5);
    fractionalBuild.insert(QStringLiteral("app"), app);
    expect(!applyRuntimeEngineManifest(
               fractionalBuild,
               {CatalogAppPlatform::Android, QStringLiteral("5.1.97"), 97,
                QStringLiteral("arm64-v8a")},
               lock, request, error),
           "fractional engine-manifest build is rejected exactly");
}

void macosDaemonManifestUsesTheAuthenticatedBuildFlavor()
{
#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
    const QString commitA(40, QLatin1Char('c'));
    const QString commitB(40, QLatin1Char('d'));
    const auto engine = [](const QString &protocol, const QString &adapter,
                           const QString &adapterVersion, const QString &core,
                           const QString &commit, const QString &abi,
                           const QJsonArray &capabilities) {
        return QJsonObject{
            {QStringLiteral("protocol"), protocol},
            {QStringLiteral("adapter"), adapter},
            {QStringLiteral("adapterVersion"), adapterVersion},
            {QStringLiteral("declaredCoreVersion"), core},
            {QStringLiteral("sourceCommit"), commit},
            {QStringLiteral("abi"), abi},
            {QStringLiteral("capabilities"), capabilities},
            {QStringLiteral("runtimeCoreVersion"), QJsonValue::Null},
            {QStringLiteral("runtimeVersionProbed"), false},
            {QStringLiteral("versionEvidence"), QStringLiteral("compile_time_lock_only")},
        };
    };
    const QJsonObject manifest{
        {QStringLiteral("type"), QStringLiteral("engine_manifest_v1")},
        {QStringLiteral("schema"), 1},
        {QStringLiteral("app"), QJsonObject{
             {QStringLiteral("version"), QStringLiteral("5.1.97")},
             {QStringLiteral("build"), 97}}},
        {QStringLiteral("engines"), QJsonArray{
             engine(QStringLiteral("awg"), QStringLiteral("awg-go"),
                    QStringLiteral("3.1.20260814"), QStringLiteral("3.1.20260814"),
                    commitA, QStringLiteral("awg-uapi-v31"),
                    {QStringLiteral("awg.random_trailers"),
                     QStringLiteral("awg.disable_cookies"), QStringLiteral("uapi.readback"),
                     QStringLiteral("tribe.guarded_settings_owner")}),
             engine(QStringLiteral("xray"), QStringLiteral("amnezia-xray-bindings"),
                    QStringLiteral("1.4.0"), QStringLiteral("1.260728.0"), commitB,
                    QStringLiteral("xray-bindings-c-v1"),
                    {QStringLiteral("xray.vless.reality.vision.tcp"),
                     QStringLiteral("xray.embedded"),
                     QStringLiteral("tribe.guarded_settings_owner")})}},
    };
    RuntimeEngineLock lock;
    lock.manifestSchema = 1;
    lock.platform = CatalogAppPlatform::Macos;
    lock.engines = {
        {QStringLiteral("awg"), QStringLiteral("awg-go"),
         QStringLiteral("3.1.20260814"), QStringLiteral("3.1.20260814"),
         commitA, QStringLiteral("awg-uapi-v31"),
         {QStringLiteral("awg.random_trailers"),
          QStringLiteral("awg.disable_cookies"),
          QStringLiteral("tribe.guarded_settings_owner")}, false},
        {QStringLiteral("xray"), QStringLiteral("amnezia-xray-bindings"),
         QStringLiteral("1.4.0"), QStringLiteral("1.260728.0"), commitB,
         QStringLiteral("xray-bindings-c-v1"),
         {QStringLiteral("xray.vless.reality.vision.tcp"),
          QStringLiteral("tribe.guarded_settings_owner")}, false},
    };
    CatalogResolveRequest request;
    request.deviceKeys.awgPublicKey = QString::fromLatin1(QByteArray(32, '\x42').toBase64());
    QString error;
    expect(applyRuntimeEngineManifest(
               manifest,
               {CatalogAppPlatform::Macos, QStringLiteral("5.1.97"), 97,
                QStringLiteral("arm64")},
               lock, request, error),
           "standalone macOS accepts exact authenticated daemon build lock");
    expect(request.adapters.macosDaemonIpc == std::optional<QString>(QStringLiteral("1"))
               && !request.adapters.macosNetworkExtension.has_value(),
           "standalone macOS emits daemon flavor and never masquerades as Network Extension");
    QJsonObject tampered = manifest;
    QJsonArray entries = tampered.value(QStringLiteral("engines")).toArray();
    QJsonObject awg = entries.at(0).toObject();
    awg.insert(QStringLiteral("sourceCommit"), QString(40, QLatin1Char('e')));
    entries.replace(0, awg);
    tampered.insert(QStringLiteral("engines"), entries);
    expect(!applyRuntimeEngineManifest(
               tampered,
               {CatalogAppPlatform::Macos, QStringLiteral("5.1.97"), 97,
                QStringLiteral("arm64")},
               lock, request, error),
           "standalone macOS rejects daemon evidence that differs from compiled receipt");
#endif
}

void preexistingNativeGuardRecoveryIsLevelTriggeredFailClosed()
{
    Harness h;
    CatalogCoordinator coordinator = h.make();
    const QJsonObject recovery{
        {QStringLiteral("type"), QStringLiteral("native_session_guard_v1")},
        {QStringLiteral("schema"), 1},
        {QStringLiteral("operation"), QStringLiteral("41")},
        {QStringLiteral("session"), QStringLiteral("7")},
        {QStringLiteral("kind"), QStringLiteral("armed")},
        {QStringLiteral("policy_sha256"), QString(64, QLatin1Char('a'))},
        {QStringLiteral("outer_session_id"), QStringLiteral("outer-relaunch-1")},
        {QStringLiteral("expected_runtime_session_id"),
         QStringLiteral("123e4567-e89b-42d3-a456-426614174000")},
        {QStringLiteral("reason"), QString()},
    };
    coordinator.nativeSessionGuardRecoveryRequired(recovery);
    expect(coordinator.nativeSessionGuardRecoveryPending(),
           "pre-existing platform guard latches recovery before startup");
    expect(h.facade.v2Authoritative() && !h.facade.legacyV1Allowed(),
           "relaunch ownership proof closes legacy immediately");
    QString error;
    expect(!coordinator.initialize(error),
           "startup cannot claim production readiness while ownership is unresolved");
    expect(error == QLatin1String("native_guard_recovery_required"),
           "startup reports typed recovery requirement");
    error.clear();
    expect(!coordinator.initialize(error)
               && error == QLatin1String("native_guard_recovery_required"),
           "repeated initialize remains unavailable while recovery latch is set");
    expect(h.store.writes == 1 && h.store.loaded.authoritativeV2EndpointSeen,
           "relaunch anti-downgrade tombstone becomes durable after secure init");
    expect(h.store.loaded.acceptedKeysetState.isEmpty(),
           "pre-keyset recovery tombstone canonically omits empty keyset state");
    QByteArray tombstonePlaintext;
    CatalogLkgRecord parsedTombstone;
    expect(CatalogSecureStore::serializePlaintext(
               h.store.loaded, tombstonePlaintext, error)
               && CatalogSecureStore::parsePlaintext(
                   tombstonePlaintext, parsedTombstone, error)
               && parsedTombstone.acceptedKeysetState.isEmpty(),
           "schema-v4 pre-keyset tombstone survives the real secure-store codec");
    {
        Harness relaunched;
        relaunched.store.status = CatalogLkgLoadStatus::Loaded;
        relaunched.store.loaded = parsedTombstone;
        CatalogCoordinator afterWrite = relaunched.make();
        QString relaunchError;
        expect(afterWrite.initialize(relaunchError)
                   && afterWrite.productionReady()
                   && relaunched.facade.v2Authoritative()
                   && !relaunched.facade.catalogAvailable()
                   && relaunched.keyset.starts == 0,
               "actual no-keyset tombstone write can initialize a new coordinator");
    }
    expect(!coordinator.requestConnect(error)
               && error == QLatin1String("native_guard_recovery_required"),
           "recovery latch blocks every new native start");
    expect(h.keyset.starts == 0 && h.reducer.connectCalls == 0,
           "blocked recovery performs no network/start side effects");
    coordinator.requestDisconnect();
    expect(h.reducer.disconnectCalls == 0
               && h.facade.connectionStage() == QLatin1String("failed"),
           "generic disconnect cannot falsely report Idle for an unowned live guard");

    const auto receipt = [&](const QString &operation, const QString &kind) {
        return QJsonObject{
            {QStringLiteral("type"),
             QStringLiteral("native_session_guard_recovery_v1")},
            {QStringLiteral("schema"), 1},
            {QStringLiteral("action"), QStringLiteral("stop")},
            {QStringLiteral("kind"), kind},
            {QStringLiteral("operation"), operation},
            {QStringLiteral("session"), QStringLiteral("7")},
            {QStringLiteral("policy_sha256"), QString(64, QLatin1Char('a'))},
            {QStringLiteral("outer_session_id"),
             QStringLiteral("outer-relaunch-1")},
            {QStringLiteral("expected_runtime_session_id"),
             QStringLiteral("123e4567-e89b-42d3-a456-426614174000")},
            {QStringLiteral("reason"), QString()},
        };
    };
    expect(!coordinator.nativeSessionGuardRecoveryResolved(
               receipt(QStringLiteral("42"), QStringLiteral("stopped_released")))
               && coordinator.nativeSessionGuardRecoveryPending(),
           "stale exact-stop receipt cannot clear a different native owner");
    expect(coordinator.nativeSessionGuardRecoveryResolved(
               receipt(QStringLiteral("41"), QStringLiteral("stopped_released"))),
           "byte-exact STOP plus outer RELEASE receipt resolves ownership");
    expect(!coordinator.nativeSessionGuardRecoveryPending()
               && coordinator.productionReady(),
           "resolved recovery unblocks v2 without reopening legacy");
    expect(h.facade.v2Authoritative() && !h.facade.legacyV1Allowed(),
           "successful recovery preserves the monotonic v2 tombstone");
    expect(coordinator.requestConnect(error) && h.keyset.starts == 1,
           "a fresh v2 discovery may start only after exact recovery completion");

    {
        Harness requiredFailure;
        CatalogCoordinator failed = requiredFailure.make();
        QString failureError;
        expect(failed.initialize(failureError),
               "post-init guard persist-failure setup initializes");
        requiredFailure.store.failNextWrite = true;
        expect(!failed.nativeSessionGuardRecoveryRequired(recovery)
                   && failed.nativeSessionGuardRecoveryPending()
                   && requiredFailure.facade.v2Authoritative(),
               "required-event tombstone write failure keeps ownership latch fail-closed");
        expect(!failed.nativeSessionGuardRecoveryResolved(
                   receipt(QStringLiteral("41"),
                           QStringLiteral("stopped_released")))
                   && failed.nativeSessionGuardRecoveryPending()
                   && requiredFailure.reducer.recoveryReleased == 0,
               "exact release cannot clear a latch after failed authority persistence");
        failureError.clear();
        expect(!failed.requestConnect(failureError)
                   && !failed.requestCatalogRefresh(failureError)
                   && requiredFailure.keyset.starts == 0
                   && requiredFailure.reducer.connectCalls == 0,
               "failed required-event persistence blocks ON and refresh side effects");

        Harness relaunchedFailure;
        CatalogCoordinator relaunched = relaunchedFailure.make();
        expect(relaunched.nativeSessionGuardRecoveryRequired(recovery)
                   && !relaunched.initialize(failureError)
                   && relaunched.nativeSessionGuardRecoveryPending()
                   && relaunchedFailure.facade.v2Authoritative()
                   && !relaunchedFailure.facade.legacyV1Allowed()
                   && relaunchedFailure.keyset.starts == 0
                   && relaunchedFailure.reducer.connectCalls == 0,
               "level-triggered platform event restores relaunch recovery after failed write");
    }

    {
        Harness resolvedFailure;
        CatalogCoordinator failed = resolvedFailure.make();
        QString failureError;
        expect(failed.initialize(failureError)
                   && failed.nativeSessionGuardRecoveryRequired(recovery),
               "resolved-event persist-failure setup durably latches required state");
        resolvedFailure.store.failNextWrite = true;
        expect(!failed.nativeSessionGuardRecoveryResolved(
                   receipt(QStringLiteral("41"),
                           QStringLiteral("stopped_released")))
                   && failed.nativeSessionGuardRecoveryPending()
                   && resolvedFailure.reducer.recoveryReleased == 0,
               "release acknowledgement waits for durable anti-downgrade authority");
        failureError.clear();
        expect(!failed.requestConnect(failureError)
                   && resolvedFailure.keyset.starts == 0
                   && resolvedFailure.reducer.connectCalls == 0,
               "failed release persistence remains sticky fail-closed");
    }

    Harness malformedHarness;
    CatalogCoordinator malformed = malformedHarness.make();
    QJsonObject invalid = recovery;
    invalid.insert(QStringLiteral("unexpected"), true);
    malformed.nativeSessionGuardRecoveryRequired(invalid);
    expect(malformed.nativeSessionGuardRecoveryPending()
               && malformedHarness.facade.v2Authoritative(),
           "malformed recovery detail still fails closed rather than reopening legacy");
    expect(malformedHarness.facade.errorCode()
               == QLatin1String("native_guard_recovery_event_invalid"),
           "malformed recovery has a typed redacted terminal reason");

    ConnectionGuardEvent ignoredEvent;
    QString parseError;
    QJsonObject fractionalSchema = recovery;
    fractionalSchema.insert(QStringLiteral("schema"), 1.5);
    expect(!parseNativeSessionGuardEvent(fractionalSchema, ignoredEvent, parseError),
           "fractional guard schema is never truncated to v1");
    QJsonObject unicodeOuter = recovery;
    unicodeOuter.insert(QStringLiteral("outer_session_id"),
                        QString::fromUtf8("outer-Ð°"));
    expect(!parseNativeSessionGuardEvent(unicodeOuter, ignoredEvent, parseError),
           "opaque native owner identity is canonical ASCII only");
}

void queuedV2IntentNeverMasksLegacyNativeOwnership()
{
    expect(delayedLegacyOwnerMustBlockV2(false, false, true, false),
           "late live legacy callback blocks queued v2 before authority");
    expect(!delayedLegacyOwnerMustBlockV2(true, false, true, false),
           "authoritative v2 native ownership is never broadly classified as legacy");
    expect(!delayedLegacyOwnerMustBlockV2(false, true, true, false),
           "an existing serialized legacy teardown is not dispatched twice");
    expect(queuedV2OffMustTearDownLegacy(false, false, false),
           "OFF cancels queued v2 and still tears down a live legacy owner");
    expect(queuedV2OffMustTearDownLegacy(false, true, true),
           "OFF retains teardown intent for an in-flight legacy operation");
    expect(!queuedV2OffMustTearDownLegacy(false, false, true),
           "OFF with exact legacy Disconnected needs no broad native mutation");
    expect(!queuedV2OffMustTearDownLegacy(true, true, false),
           "authoritative v2 teardown remains exclusively reducer/guard-owned");
    expect(authoritativeUnexpectedLegacyOwnerMustStop(
               true, false, false, false, false),
           "late surviving legacy owner after authority is serialized to Disconnected");
    expect(!authoritativeUnexpectedLegacyOwnerMustStop(
               true, false, false, true, false),
           "generic callback cannot broadly stop an exact reducer-owned v2 runtime");
    expect(!authoritativeUnexpectedLegacyOwnerMustStop(
               true, false, true, false, false),
           "platform recovery transaction exclusively owns surviving v2 teardown");
    expect(!authoritativeUnexpectedLegacyOwnerMustStop(
               true, false, false, false, true),
           "exact Disconnected requires no duplicate legacy teardown");
}

void duplicateNetworkPathSignalDoesNotAllocateAnotherEpoch()
{
    Harness h;
    CatalogCoordinator coordinator = h.make();
    QString error;
    expect(coordinator.initialize(error), "path-dedupe coordinator initializes");
    coordinator.networkPathChanged(CatalogNetworkClass::Wifi,
                                   QStringLiteral("volatile-path-a"));
    const int firstWrites = h.store.writes;
    expect(firstWrites > 0, "first material path observation is persisted");
    coordinator.networkPathChanged(CatalogNetworkClass::Wifi,
                                   QStringLiteral("volatile-path-a"));
    expect(h.store.writes == firstWrites,
           "duplicate class and volatile path token do not churn durable epoch");
    coordinator.networkPathChanged(CatalogNetworkClass::Wifi,
                                   QStringLiteral("volatile-path-b"));
    expect(h.store.writes == firstWrites + 1,
           "same medium with a genuinely new volatile path token advances once");
}

void facadeWakeReanchorsAllTrustedAgesAndDeadlines()
{
    CatalogConnectionFacade facade;
    const QDateTime base = QDateTime::fromString(
        QStringLiteral("2026-08-28T12:00:00Z"), Qt::ISODate);
    Catalog catalog;
    catalog.schemaVersion = 2;
    catalog.issuedAt = base.addSecs(-100);
    facade.setCatalogView(catalog, {}, {}, false, false, false, base);
    ConnectionRuntimeSnapshot live;
    live.phase = ConnectionPhase::ConnectedHealthy;
    live.session = {1, 1};
    live.profileId = QStringLiteral("profile-redacted");
    live.transport = TransportKind::Awg;
    live.verifiedAtUtc = base.addSecs(-10);
    live.verifiedUntilUtc = base.addSecs(30);
    live.nativeProfileExpiresAt = base.addSecs(100);
    live.catalogFreshnessDeadline = base.addSecs(120);
    live.entitlementDeadline = base.addSecs(140);
    facade.onConnectionReducerSnapshot(live);
    expect(facade.verified() && facade.authorityRemainingSeconds() == 100,
           "facade starts from the coordinator trusted clock anchor");
    facade.updateTrustedPresentationNow(base.addSecs(40));
    expect(!facade.verified() && facade.catalogAgeSeconds() == 140
               && facade.authorityRemainingSeconds() == 60,
           "wake re-anchor cannot leave receipt green or stale authority age");
    facade.invalidateVerificationPresentation();
    expect(!facade.verified() && facade.verificationAgeSeconds() == -1,
           "wake invalidation remains fail-closed after clock re-anchor");
}

void userIntentPreferencesSurviveRestartWithoutRestoringRuntimeFacts()
{
    QTemporaryDir directory;
    expect(directory.isValid(), "temporary preferences directory is available");
    const QString fileName = directory.filePath(QStringLiteral("intent.ini"));
    {
        QSettings settings(fileName, QSettings::IniFormat);
        QString error;
        expect(persistCatalogUserIntent(
                   &settings,
                   {ConnectionMode::ForceXray, QStringLiteral("nl:ams")}, error),
               "valid requested transport and signed-location-shaped pin persist");
        settings.beginGroup(QStringLiteral("TribeCatalog/UserIntentV1"));
        const QStringList childKeys = settings.childKeys();
        const QSet<QString> keys(childKeys.cbegin(), childKeys.cend());
        settings.endGroup();
        expect(keys == QSet<QString>{QStringLiteral("schema"),
                                     QStringLiteral("requested_transport"),
                                     QStringLiteral("pinned_location_id")},
               "preference record has an exact versioned allowlist and no runtime fields");
    }
    {
        QSettings restarted(fileName, QSettings::IniFormat);
        bool sanitized = false;
        const CatalogUserIntent loaded = loadCatalogUserIntent(&restarted, &sanitized);
        expect(!sanitized && loaded.mode == ConnectionMode::ForceXray
                   && loaded.pinnedLocationId == QLatin1String("nl:ams"),
               "requested mode and pin survive a real QSettings restart");

        Harness h;
        h.config.userIntentSettings = &restarted;
        CatalogCoordinator coordinator = h.make();
        QString error;
        expect(coordinator.initialize(error),
               "coordinator initializes with restored non-secret user intent");
        expect(h.facade.connectionMode() == QLatin1String("xray")
                   && h.facade.selectedLocationMode() == QLatin1String("nl:ams"),
               "facade restores requested transport and location independently");
        expect(h.facade.actualTransport() == QLatin1String("none")
                   && h.facade.currentLocationId().isEmpty()
                   && !h.facade.verified(),
               "restart never invents actual transport, active location, or verification");
    }
}

void corruptAndStaleUserIntentFailsBackToSafeDefaults()
{
    QTemporaryDir directory;
    expect(directory.isValid(), "temporary corrupt-preference directory is available");
    const QString fileName = directory.filePath(QStringLiteral("intent.ini"));
    QSettings settings(fileName, QSettings::IniFormat);
    settings.beginGroup(QStringLiteral("TribeCatalog/UserIntentV1"));
    settings.setValue(QStringLiteral("schema"), 2);
    settings.setValue(QStringLiteral("requested_transport"), QStringLiteral("wireguard"));
    settings.setValue(QStringLiteral("pinned_location_id"), QStringLiteral("../escape"));
    settings.setValue(QStringLiteral("unexpected_actual_transport"),
                      QStringLiteral("xray"));
    settings.endGroup();
    settings.sync();

    bool sanitized = false;
    const CatalogUserIntent reset = loadCatalogUserIntent(&settings, &sanitized);
    expect(sanitized && reset.mode == ConnectionMode::Auto
               && reset.pinnedLocationId.isEmpty(),
           "future/corrupt/unknown preference fields reset to Auto and an empty pin");
    settings.beginGroup(QStringLiteral("TribeCatalog/UserIntentV1"));
    expect(settings.childKeys().size() == 3
               && settings.value(QStringLiteral("schema")).toInt() == 1
               && settings.value(QStringLiteral("requested_transport")).toString()
                      == QLatin1String("auto")
               && settings.value(QStringLiteral("pinned_location_id")).toString().isEmpty(),
           "corrupt record is rewritten to the canonical v1 schema");
    settings.endGroup();

    Catalog catalog;
    CatalogLocation present;
    present.id = QStringLiteral("de:fra");
    catalog.locations.append(present);
    CatalogUserIntent validPin{ConnectionMode::ForceAwg, QStringLiteral("de:fra")};
    expect(catalogContainsPinnedLocation(catalog, validPin.pinnedLocationId)
               && validPin.pinnedLocationId == QLatin1String("de:fra"),
           "pin present in the current signed catalog remains selected");
    CatalogUserIntent stalePin{ConnectionMode::ForceXray, QStringLiteral("nl:ams")};
    expect(!catalogContainsPinnedLocation(catalog, stalePin.pinnedLocationId)
               && stalePin.mode == ConnectionMode::ForceXray
               && stalePin.pinnedLocationId == QLatin1String("nl:ams"),
           "removed signed-catalog location is unavailable without clearing user intent");
}

void lifecycleAndVerificationRetryFencesAreExact()
{
    const TransportOperationToken session{41, 7};
    const QByteArray policy(32, '\x5a');
    const VerificationToken verification{session, 9};
    const QList<ConnectionLifecycleWait> waits{
        {ConnectionLifecycleWaitKind::GuardArm, session, {}, policy},
        {ConnectionLifecycleWaitKind::TransportStart, session, {}, {}},
        {ConnectionLifecycleWaitKind::TransportStop, session, {}, {}},
        {ConnectionLifecycleWaitKind::GuardRelease, session, {}, policy},
        {ConnectionLifecycleWaitKind::Verification, session, verification, {}},
    };
    ConnectionLifecycleDeadlineFence fence;
    const auto first = fence.replace(waits.first());
    expect(first.has_value() && first->isValid(),
           "first lifecycle wait arms one exact generation");
    expect(!fence.replace(waits.first()).has_value(),
           "duplicate reducer snapshot cannot renew lifecycle deadline");
    const auto replacement = fence.replace(waits.at(1));
    expect(replacement.has_value()
               && !fence.consume(*first, waits.at(1))
               && fence.consume(*replacement, waits.at(1)),
           "stale lifecycle generation/key is a no-op and exact replacement consumes once");
    expect(!fence.replace(waits.at(1)).has_value(),
           "consumed stop/release wait cannot re-arm from its fail-closed timeout snapshot");
    fence.clear();
    expect(fence.replace(waits.at(1)).has_value(),
           "leaving the wait clears its tombstone for a future exact lifecycle generation");

    FakeReducer reducer;
    for (const ConnectionLifecycleWait &wait : waits)
        expect(dispatchConnectionLifecycleTimeout(&reducer, wait),
               "valid lifecycle wait dispatches its typed reducer hook");
    expect(reducer.armTimeouts == 1 && reducer.transportTimeouts == 1
               && reducer.stopTimeouts == 1 && reducer.releaseTimeouts == 1
               && reducer.verificationTimeouts == 1
               && reducer.lastVerification == verification,
           "all five lifecycle hooks preserve exact immutable identities");

    const QDateTime base = QDateTime::fromString(
        QStringLiteral("2026-08-28T12:00:00Z"), Qt::ISODate);
    VerificationRetryDeadlineKey retry{
        session, VerificationRetryDirective::RetrySameAuthority, 5, 3, 4, 8, 11,
        base.addSecs(300), base.addSecs(300), base.addSecs(300)};
    VerificationRetryDeadlineFence retryFence;
    const auto retryArm = retryFence.replace(retry);
    expect(retryArm.has_value() && !retryFence.replace(retry).has_value(),
           "duplicate unknown snapshot cannot postpone automatic verification retry");
    VerificationRetryDeadlineKey movedPath = retry;
    movedPath.pathEpoch++;
    expect(!retryFence.consume(*retryArm, movedPath),
           "path/authority generation change fences stale verification retry");
    const auto movedArm = retryFence.replace(movedPath);
    expect(movedArm.has_value() && retryFence.consume(*movedArm, movedPath),
           "replacement path receives its own exact retry generation");

    expect(proactiveReceiptRefreshDelayMs(base, base.addSecs(300), 30) == 270000,
           "five-minute receipt renews thirty seconds before expiry");
    expect(proactiveReceiptRefreshDelayMs(base, base.addSecs(6), 30) == 4000,
           "short receipt uses a bounded fractional safety margin instead of expiring first");
    ReceiptRefreshDeadlineFence receiptFence;
    ReceiptRefreshDeadlineKey receipt{verification, 3, 4, base.addSecs(300)};
    const auto receiptArm = receiptFence.replace(receipt);
    expect(receiptArm.has_value() && !receiptFence.replace(receipt).has_value(),
           "duplicate healthy snapshots cannot renew the proactive receipt deadline");
    ReceiptRefreshDeadlineKey renewedReceipt{{session, 10}, 3, 4,
                                               base.addSecs(570)};
    const auto renewedReceiptArm = receiptFence.replace(renewedReceipt);
    expect(renewedReceiptArm.has_value()
               && !receiptFence.consume(*receiptArm, renewedReceipt)
               && receiptFence.consume(*renewedReceiptArm, renewedReceipt),
           "only the exact renewed receipt generation can consume its refresh deadline");
}

void receiptRenewalPreservesOriginalFiveMinuteObservation()
{
    Harness h;
    configureGoldenCatalogRoot(h);
    CatalogCoordinator coordinator = h.make();
    QString error;
    expect(coordinator.initialize(error), "receipt-renewal coordinator initializes");
    acceptFreshTestCatalog(h, coordinator, 2842);

    const QDateTime base = h.source.now;
    const QString profileId = QStringLiteral("fi-awg-02");
    CandidateHistory history;
    history.configGeneration = 12;
    history.bindingGeneration = 3;
    h.reducer.history.insert(profileId, history);

    const auto healthy = [&](TransportOperationToken session,
                             VerificationToken verification,
                             QDateTime verifiedAt, QDateTime verifiedUntil) {
        ConnectionRuntimeSnapshot snapshot;
        snapshot.phase = ConnectionPhase::ConnectedHealthy;
        snapshot.operation = session.operation;
        snapshot.session = session;
        snapshot.verification = verification;
        snapshot.profileId = profileId;
        snapshot.locationId = QStringLiteral("fi-hel");
        snapshot.transport = TransportKind::Awg;
        snapshot.configGeneration = 12;
        snapshot.bindingGeneration = 3;
        snapshot.nativeProfileExpiresAt = base.addSecs(3500);
        snapshot.catalogFreshnessDeadline = base.addSecs(3500);
        snapshot.entitlementDeadline = base.addSecs(3500);
        snapshot.verifiedAtUtc = verifiedAt;
        snapshot.verifiedUntilUtc = verifiedUntil;
        snapshot.guardArmed = true;
        snapshot.hasAcceptedV2 = true;
        return snapshot;
    };

    const TransportOperationToken firstSession{51, 1};
    ConnectionRuntimeSnapshot first = healthy(
        firstSession, {firstSession, 1}, base, base.addSecs(300));
    coordinator.onConnectionReducerSnapshot(first);
    h.source.now = base.addSecs(270);
    ConnectionRuntimeSnapshot refreshing = first;
    refreshing.phase = ConnectionPhase::VerifyingTraffic;
    refreshing.verification = {firstSession, 2};
    coordinator.onConnectionReducerSnapshot(refreshing);
    ConnectionRuntimeSnapshot renewed = healthy(
        firstSession, {firstSession, 2}, h.source.now, h.source.now.addSecs(300));
    coordinator.onConnectionReducerSnapshot(renewed);

    h.source.now = base.addSecs(300);
    coordinator.onSurvivalCheckpoint(firstSession, profileId, 12, 3, 1, 1);
    CatalogRuntimeState state;
    expect(parseCatalogRuntimeState(h.store.loaded.runtimeState, state, error),
           "renewed receipt state remains parseable");
    const QString historyKey = scopedCatalogHistoryKey(
        {CatalogNetworkClass::Wifi, 1}, profileId);
    const auto survivedCount = [&]() {
        return std::count_if(state.pendingOutcomes.cbegin(), state.pendingOutcomes.cend(),
            [&](const CatalogOutcomeEvent &event) {
                return event.profileId == profileId && event.survived5m.has_value()
                       && *event.survived5m;
            });
    };
    expect(state.candidateHistory.value(historyKey).survival5mEwma == 1.0
               && survivedCount() == 1,
           "same-session pre-expiry renewal reaches the original five-minute checkpoint once");

    const TransportOperationToken gapSession{52, 1};
    h.source.now = base.addSecs(310);
    ConnectionRuntimeSnapshot beforeGap = healthy(
        gapSession, {gapSession, 1}, h.source.now, h.source.now.addSecs(300));
    coordinator.onConnectionReducerSnapshot(beforeGap);
    // Simulate a delayed main loop: the refresh result arrives after old coverage elapsed, before
    // the already-queued old observation callback is delivered.
    h.source.now = base.addSecs(620);
    ConnectionRuntimeSnapshot afterGap = healthy(
        gapSession, {gapSession, 2}, h.source.now, h.source.now.addSecs(300));
    coordinator.onConnectionReducerSnapshot(afterGap);
    coordinator.onSurvivalCheckpoint(gapSession, profileId, 12, 3, 1, 3);
    expect(parseCatalogRuntimeState(h.store.loaded.runtimeState, state, error)
               && survivedCount() == 1,
           "late renewal starts a new generation and its old queued checkpoint is a no-op");
    h.source.now = base.addSecs(890);
    ConnectionRuntimeSnapshot gapRefreshing = afterGap;
    gapRefreshing.phase = ConnectionPhase::VerifyingTraffic;
    gapRefreshing.verification = {gapSession, 3};
    coordinator.onConnectionReducerSnapshot(gapRefreshing);
    ConnectionRuntimeSnapshot gapRenewed = healthy(
        gapSession, {gapSession, 3}, h.source.now, h.source.now.addSecs(300));
    coordinator.onConnectionReducerSnapshot(gapRenewed);
    h.source.now = base.addSecs(920);
    coordinator.onSurvivalCheckpoint(gapSession, profileId, 12, 3, 1, 5);
    expect(parseCatalogRuntimeState(h.store.loaded.runtimeState, state, error)
               && survivedCount() == 2,
           "replacement observation earns survival only after its own full five minutes");

    const TransportOperationToken failedSession{53, 1};
    h.source.now = base.addSecs(930);
    ConnectionRuntimeSnapshot second = healthy(
        failedSession, {failedSession, 1}, h.source.now, h.source.now.addSecs(300));
    coordinator.onConnectionReducerSnapshot(second);
    h.source.now = base.addSecs(1200);
    ConnectionRuntimeSnapshot failedRefresh = second;
    failedRefresh.phase = ConnectionPhase::VerificationUnknown;
    failedRefresh.verification = {failedSession, 2};
    failedRefresh.verificationRetryDirective =
        VerificationRetryDirective::RetrySameAuthority;
    failedRefresh.verificationRetryAfterSeconds = 300;
    failedRefresh.lastTypedReason = QStringLiteral("receipt_provider_503");
    coordinator.onConnectionReducerSnapshot(failedRefresh);
    h.source.now = base.addSecs(1230);
    coordinator.onSurvivalCheckpoint(failedSession, profileId, 12, 3, 1, 7);
    expect(parseCatalogRuntimeState(h.store.loaded.runtimeState, state, error),
           "failed-refresh runtime state remains parseable");
    expect(survivedCount() == 2,
           "failed renewal cancels its observation and a stale checkpoint cannot report survival");
}

void verificationUnknownRetriesAndOfflineRevokesGreen()
{
    {
        Harness h;
        configureGoldenCatalogRoot(h);
        CatalogCoordinator coordinator = h.make();
        QString error;
        expect(coordinator.initialize(error), "verification-retry coordinator initializes");
        acceptFreshTestCatalog(h, coordinator, 3842);

        const QDateTime base = h.source.now;
        const TransportOperationToken session{61, 1};
        ConnectionRuntimeSnapshot unknown;
        unknown.phase = ConnectionPhase::VerificationUnknown;
        unknown.operation = session.operation;
        unknown.session = session;
        unknown.verification = {session, 1};
        unknown.profileId = QStringLiteral("fi-awg-02");
        unknown.locationId = QStringLiteral("fi-hel");
        unknown.transport = TransportKind::Awg;
        unknown.configGeneration = 12;
        unknown.bindingGeneration = 3;
        unknown.nativeProfileExpiresAt = base.addSecs(3500);
        unknown.catalogFreshnessDeadline = base.addSecs(3500);
        unknown.entitlementDeadline = base.addSecs(3500);
        unknown.guardArmed = true;
        unknown.hasAcceptedV2 = true;
        unknown.lastTypedReason = QStringLiteral("receipt_provider_503");
        unknown.verificationRetryDirective =
            VerificationRetryDirective::RetrySameAuthority;
        unknown.verificationRetryAfterSeconds = 1;
        coordinator.onConnectionReducerSnapshot(unknown);
        runEventLoopFor(1100);
        expect(h.reducer.verificationRetries == 1,
               "transient verifier 503 dispatches one bounded same-authority retry");

        ConnectionRuntimeSnapshot green = unknown;
        green.phase = ConnectionPhase::ConnectedHealthy;
        green.verification = {session, 2};
        green.verificationRetryDirective = VerificationRetryDirective::None;
        green.verificationRetryAfterSeconds = 0;
        green.lastTypedReason.clear();
        green.verifiedAtUtc = base;
        green.verifiedUntilUtc = base.addSecs(300);
        coordinator.onConnectionReducerSnapshot(green);
        expect(h.facade.verified(), "successful timed retry republishes fresh green");

        ConnectionRuntimeSnapshot dnsChanged = unknown;
        dnsChanged.verification = {session, 3};
        dnsChanged.lastTypedReason = QStringLiteral("receipt_dns_snapshot_changed");
        dnsChanged.verificationRetryDirective = VerificationRetryDirective::RefreshCatalog;
        dnsChanged.verificationRetryAfterSeconds = 1;
        coordinator.onConnectionReducerSnapshot(dnsChanged);
        runEventLoopFor(1100);
        expect(h.reducer.verificationRetries == 1 && h.keyset.starts == 2
                   && h.keyset.activeOperation != 0,
               "signed DNS snapshot change refreshes catalog instead of retrying stale authority");
        runEventLoopFor(50);
        expect(h.keyset.starts == 2,
               "catalog-refresh retry is generation-consumed and cannot tight-loop");
    }

    {
        Harness h;
        CatalogCoordinator coordinator = h.make();
        QString error;
        expect(coordinator.initialize(error), "offline-liveness coordinator initializes");
        const QDateTime base = h.source.now;
        h.facade.updateTrustedPresentationNow(base);
        const TransportOperationToken session{71, 1};
        ConnectionRuntimeSnapshot green;
        green.phase = ConnectionPhase::ConnectedHealthy;
        green.operation = session.operation;
        green.session = session;
        green.verification = {session, 1};
        green.profileId = QStringLiteral("offline-profile");
        green.transport = TransportKind::Awg;
        green.configGeneration = 1;
        green.bindingGeneration = 1;
        green.verifiedAtUtc = base;
        green.verifiedUntilUtc = base.addSecs(300);
        green.nativeProfileExpiresAt = base.addSecs(600);
        green.catalogFreshnessDeadline = base.addSecs(600);
        green.entitlementDeadline = base.addSecs(600);
        coordinator.onConnectionReducerSnapshot(green);
        expect(h.facade.verified(), "fresh online receipt starts green presentation");

        const int writesBeforeOffline = h.store.writes;
        coordinator.networkReachabilityChanged(false);
        expect(!h.facade.verified()
                   && h.facade.errorCode()
                          == QLatin1String("verification_unknown_network_offline"),
               "online-to-offline revokes green immediately without a verifier timeout");
        coordinator.onConnectionReducerSnapshot(green);
        expect(!h.facade.verified(),
               "late duplicate native snapshot cannot repaint an offline tunnel green");
        coordinator.networkPathChanged(CatalogNetworkClass::Wifi,
                                       QStringLiteral("offline-medium-churn"));
        coordinator.onSurvivalCheckpoint(session, green.profileId, 1, 1, 1, 1);
        expect(h.store.writes == writesBeforeOffline,
               "offline medium churn and stale survival callback neither allocate nor penalize");

        coordinator.networkReachabilityChanged(true);
        coordinator.networkPathChanged(CatalogNetworkClass::Wifi,
                                       QStringLiteral("newly-online-path"));
        expect(h.store.writes == writesBeforeOffline + 1 && h.keyset.starts == 1,
               "offline-to-online allocates one fresh path epoch and starts one signed refresh");
    }
}

} // namespace

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    cleanTrustedClockBootstrapPreservesRollbackFence();
    expiredPersistedAuthorityRecoversOnlyThroughFreshRoot();
    keysetRotationIsAtomicCrashSafeAndFailClosed();
    authoritativePersistenceFailuresAreSticky();
    locationDirectoryIntentIsScopedWithoutOffAllocation();
    liveIntentRefreshKeepsVerifiedOwnerAndFencesStaleEchoes();
    authoritativeEndpointTombstonePrecedesCatalogRejection();
    cleanInstallConnectStartsDiscoveryAndOffFencesIt();
    firstConnectWaitsForEnrollmentWithoutNetworkOrLegacyAuthority();
    catalogListRefreshNeverBecomesConnectionIntent();
    legacyNativeOwnerBlocksDiscoveryUntilExactTerminal();
    corruptDurableStoreFailsClosedInPresentation();
    tombstoneOnlyRecordRestoresAuthorityBeforeCatalog();
    logoutWaitsForExactTeardownAndSecureWipe();
    restoredAuthorityPrecedesFallibleRuntimeInventory();
    facadeV2ActionsNeverNeedLegacyEngine();
    outcomeAbiMatchesBackendGoldenAndStrictHttpContract();
    durableOutcomeUploaderDeletesOnlyAfterExactAck();
    receiptVerifierRetriesEveryResolvedSignedBootstrapIp();
    receiptVerifierParsesTypedHttpErrorsDespiteQtContentErrors();
    catalogStaleWaitsForExactReleaseThenRefreshesAndReconnectsOnce();
    productionShapedManifestStartsFromDeviceOwnedKeys();
    macosDaemonManifestUsesTheAuthenticatedBuildFlavor();
    preexistingNativeGuardRecoveryIsLevelTriggeredFailClosed();
    queuedV2IntentNeverMasksLegacyNativeOwnership();
    duplicateNetworkPathSignalDoesNotAllocateAnotherEpoch();
    facadeWakeReanchorsAllTrustedAgesAndDeadlines();
    userIntentPreferencesSurviveRestartWithoutRestoringRuntimeFacts();
    corruptAndStaleUserIntentFailsBackToSafeDefaults();
    lifecycleAndVerificationRetryFencesAreExact();
    receiptRenewalPreservesOriginalFiveMinuteObservation();
    verificationUnknownRetriesAndOfflineRevokesGreen();
    qInfo().noquote() << "catalog_coordinator_check: OK (" << checks
                      << "coordinator/facade integration checks)";
    return 0;
}
