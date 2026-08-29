#include "../CatalogKeyset.h"
#include "../CatalogResolveClient.h"
#include "../CatalogRuntimeState.h"
#include "../CatalogSecureStore.h"
#include "../CatalogTrustedClock.h"
#include "../SignedEnvelope.h"

#include <QCoreApplication>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSaveFile>
#include <QTemporaryDir>

#include <cstdio>

using namespace avpn;

static int g_failed = 0;
static int g_total = 0;
#define CHECK(expr) do { ++g_total; if (!(expr)) { ++g_failed; \
    fprintf(stderr, "FAIL [%s:%d]: %s\n", __FILE__, __LINE__, #expr); } } while (0)

static QByteArray fixture(const char *name)
{
    const QString path = QFileInfo(QString::fromUtf8(__FILE__)).absolutePath()
                         + QStringLiteral("/fixtures/") + QString::fromLatin1(name);
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) return {};
    return file.readAll().trimmed();
}

static QByteArray decodeUrl(const QByteArray &encoded)
{
    return QByteArray::fromBase64(encoded, QByteArray::Base64UrlEncoding
                                             | QByteArray::AbortOnBase64DecodingErrors);
}

class FakeKeyProvider final : public ICatalogSecureKeyProvider {
public:
    CatalogSecureKeyStatus loadMetadata(CatalogSecureMetadata &out,
                                        QString &) override
    {
        if (!exists) return CatalogSecureKeyStatus::Missing;
        out = metadata;
        return CatalogSecureKeyStatus::Available;
    }
    CatalogSecureKeyStatus loadOrCreateMetadata(CatalogSecureMetadata &out,
                                                QString &) override
    {
        if (!exists) {
            exists = true;
            metadata.key32 = QByteArray(32, '\x5a');
            metadata.cleared = true;
        }
        out = metadata;
        return CatalogSecureKeyStatus::Available;
    }
    bool replaceMetadataWhileLocked(const CatalogSecureMetadata &expected,
                                    const CatalogSecureMetadata &replacement,
                                    QString &error) override
    {
        ++replaceCalls;
        if (!exists || !(metadata == expected) || replaceCalls == failReplaceCall) {
            error = QStringLiteral("injected metadata CAS failure");
            return false;
        }
        metadata = replacement;
        return true;
    }
    bool exists = false;
    CatalogSecureMetadata metadata;
    int replaceCalls = 0;
    int failReplaceCall = -1;
};

class FakeProtection final : public ICatalogFileProtection {
public:
    bool protect(const QString &, QString &error) override
    {
        ++calls;
        if (fail) { error = QStringLiteral("injected protection failure"); return false; }
        return true;
    }
    int calls = 0;
    bool fail = false;
};

class FakeClockSource final : public ICatalogClockSource {
public:
    QDateTime wallUtc() const override { return wall; }
    qint64 monotonicMs() const override { return monotonic; }
    QDateTime wall;
    qint64 monotonic = 0;
};

static CatalogLkgRecord lkgRecord()
{
    CatalogLkgRecord record;
    record.verifiedEnvelope = QByteArrayLiteral("signed-envelope");
    CatalogKeysetTrustState keyset;
    keyset.highestEpoch = 3;
    keyset.payloadSha256AtHighestEpoch = QByteArray(32, '\x31');
    keyset.acceptedEnvelope = QByteArrayLiteral("signed-keyset-envelope");
    keyset.keyFingerprints.insert(QStringLiteral("catalog/catalog-k1"),
                                  QByteArray(32, '\x32'));
    keyset.keyEpochs.insert(QStringLiteral("catalog/catalog-k1"), 3);
    keyset.keyAuthorities.insert(QStringLiteral("catalog/catalog-k1"), QString{});
    QString serializationError;
    if (!serializeCatalogKeysetTrustState(
            keyset, record.acceptedKeysetState, serializationError))
        return {};
    CatalogRuntimeState runtime;
    runtime.trustedClock.highestSignedIssuedAtUtc = QDateTime::fromString(
        QStringLiteral("2026-08-28T09:59:00.000Z"), Qt::ISODateWithMs);
    runtime.trustedClock.highestObservedWallUtc = QDateTime::fromString(
        QStringLiteral("2026-08-28T10:00:00.000Z"), Qt::ISODateWithMs);
    if (!serializeCatalogRuntimeState(
            runtime, record.runtimeState, serializationError))
        return {};
    record.trustState.hasAcceptedV2 = true;
    record.trustState.deviceAudience = QString::fromLatin1(
        QByteArray(32, '\x61').toBase64(QByteArray::Base64UrlEncoding
                                        | QByteArray::OmitTrailingEquals));
    record.trustState.highestCatalogRevision = 7;
    record.trustState.highestDeviceRevocationEpoch = 2;
    record.trustState.highestKeyEpoch = 3;
    record.trustState.highestPolicyRevision = 4;
    record.trustState.highestConfigGenerationByProfile.insert(QStringLiteral("p1"), 5);
    record.trustState.highestBindingGenerationByProfile.insert(QStringLiteral("p1"), 6);
    record.trustState.payloadSha256AtHighestRevision = QByteArray(32, '\x6b');
    return record;
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);

    // Byte-for-byte backend root/keyset fixture: catalog + two provider-specific receipt keys.
    {
        const QByteArray envelope = fixture("keyset_v1_golden_envelope.json");
        const QByteArray rootRaw = decodeUrl(fixture("keyset_v1_golden_root_public_key.txt"));
        CHECK(!envelope.isEmpty() && rootRaw.size() == 32);
        const QHash<QString, QString> root{
            {QStringLiteral("tribe-root-1"), QString::fromLatin1(rootRaw.toHex())}};
        const QDateTime now = QDateTime::fromString(
            QStringLiteral("2026-08-28T12:00:00Z"), Qt::ISODate);
        const CatalogKeysetAcceptance accepted = acceptCatalogKeysetEnvelope(
            envelope, root, {}, now);
        CHECK(accepted.accepted && accepted.manifest.epoch == 1);
        CHECK(accepted.keyrings.catalog.publicKeysHex.contains(QStringLiteral("catalog-k1")));
        CHECK(accepted.keyrings.receiptPublicKeysHex.size() == 2);
        CHECK(accepted.keyrings.receiptAuthorityIds.value(QStringLiteral("receipt-a-k1"))
              == QLatin1String("edge-a"));
        CHECK(accepted.keyrings.receiptAuthorityIds.value(QStringLiteral("receipt-b-k1"))
              == QLatin1String("edge-b"));
        QByteArray serialized;
        QString error;
        CHECK(serializeCatalogKeysetTrustState(accepted.nextState, serialized, error));
        CatalogKeysetTrustState restored;
        CHECK(parseCatalogKeysetTrustState(serialized, restored, error));
        CHECK(restored.highestEpoch == accepted.nextState.highestEpoch);
        CHECK(restored.keyAuthorities == accepted.nextState.keyAuthorities);
        QJsonObject fractionalTrust = QJsonDocument::fromJson(serialized).object();
        fractionalTrust.insert(QStringLiteral("schema"), 2.5);
        CHECK(!parseCatalogKeysetTrustState(
            QJsonDocument(fractionalTrust).toJson(QJsonDocument::Compact), restored, error));

        QByteArray tampered = envelope;
        tampered[tampered.size() / 2] = tampered.at(tampered.size() / 2) == 'A' ? 'B' : 'A';
        CHECK(!acceptCatalogKeysetEnvelope(tampered, root, {}, now).accepted);
        const CatalogKeysetAcceptance replay = acceptCatalogKeysetEnvelope(
            envelope, root, accepted.nextState, now);
        CHECK(replay.accepted);
        const QDateTime expiredNow = QDateTime::fromString(
            QStringLiteral("2026-10-01T00:00:00Z"), Qt::ISODate);
        const CatalogKeysetAcceptance onlineExpired = acceptCatalogKeysetEnvelope(
            envelope, root, accepted.nextState, expiredNow);
        CHECK(!onlineExpired.accepted && !onlineExpired.recoverableExpired
              && onlineExpired.error == CatalogKeysetError::Expired);
        const CatalogKeysetAcceptance persistedExpired = acceptCatalogKeysetEnvelope(
            envelope, root, accepted.nextState, expiredNow, {},
            CatalogKeysetAcceptanceMode::PersistedRecovery);
        CHECK(!persistedExpired.accepted && persistedExpired.recoverableExpired
              && persistedExpired.error == CatalogKeysetError::Expired
              && persistedExpired.nextState == accepted.nextState
              && persistedExpired.keyrings.catalog.publicKeysHex.isEmpty()
              && persistedExpired.persistedCatalogVerificationKeyring.publicKeysHex
                     .contains(QStringLiteral("catalog-k1")));
        CatalogKeysetTrustState rolledBack = accepted.nextState;
        rolledBack.highestEpoch = 2;
        const CatalogKeysetAcceptance expiredRollback = acceptCatalogKeysetEnvelope(
            envelope, root, rolledBack, expiredNow, {},
            CatalogKeysetAcceptanceMode::PersistedRecovery);
        CHECK(!expiredRollback.accepted && !expiredRollback.recoverableExpired
              && expiredRollback.error == CatalogKeysetError::EpochDowngrade);
    }

    // Backend receipt golden: reconstruct the declared 32 KiB byte-cycle and verify the exact
    // provider-specific signature/domain. A one-byte probe mutation cannot reuse the signature.
    {
        const QJsonObject vector = QJsonDocument::fromJson(
            fixture("receipt_v1_golden_vector.json")).object();
        QByteArray probe(32768, Qt::Uninitialized);
        for (int index = 0; index < probe.size(); ++index) probe[index] = char(index & 0xff);
        QJsonObject payload = vector.value(QStringLiteral("payload_fields")).toObject();
        payload.insert(QStringLiteral("probe_bytes"), QString::fromLatin1(
            probe.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals)));
        const QByteArray exactPayload = QJsonDocument(payload).toJson(QJsonDocument::Compact);
        const QByteArray token = exactPayload.toBase64(
            QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
        const QJsonObject envelopeObject{
            {QStringLiteral("alg"), QStringLiteral("Ed25519")},
            {QStringLiteral("kid"), vector.value(QStringLiteral("kid"))},
            {QStringLiteral("payload"), QString::fromLatin1(token)},
            {QStringLiteral("signature"), vector.value(QStringLiteral("signature"))},
        };
        const QByteArray envelope = QJsonDocument(envelopeObject).toJson(QJsonDocument::Compact);
        const QByteArray publicRaw = decodeUrl(
            vector.value(QStringLiteral("public_key")).toString().toLatin1());
        VerifiedSignedEnvelope verified;
        QString error;
        CHECK(verifyPurposeSignedEnvelope(
            envelope, QByteArrayLiteral("tribe-receipt-v1\n"),
            {{vector.value(QStringLiteral("kid")).toString(),
              QString::fromLatin1(publicRaw.toHex())}}, verified, error));
        CHECK(verified.exactPayload == exactPayload);
        probe[0] ^= 1;
        payload.insert(QStringLiteral("probe_bytes"), QString::fromLatin1(
            probe.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals)));
        QJsonObject badEnvelope = envelopeObject;
        badEnvelope.insert(QStringLiteral("payload"), QString::fromLatin1(
            QJsonDocument(payload).toJson(QJsonDocument::Compact).toBase64(
                QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals)));
        CHECK(!verifyPurposeSignedEnvelope(
            QJsonDocument(badEnvelope).toJson(QJsonDocument::Compact),
            QByteArrayLiteral("tribe-receipt-v1\n"),
            {{vector.value(QStringLiteral("kid")).toString(),
              QString::fromLatin1(publicRaw.toHex())}}, verified, error));
        probe.fill('\0');
    }

    // Every typed v2 status is authoritative and exact no-store; safe audited cache directives
    // are tolerated, public caching and auth reason drift are rejected.
    {
        const QString nonce = QString::fromLatin1(
            QByteArray(32, 'n').toBase64(QByteArray::Base64UrlEncoding
                                         | QByteArray::OmitTrailingEquals));
        CatalogResolveHttpResponse response;
        response.status = 429;
        response.headers = {
            {QByteArrayLiteral("cache-control"), QByteArrayLiteral("private, no-store")},
            {QByteArrayLiteral("content-type"), QByteArrayLiteral("application/json")},
            {QByteArrayLiteral("retry-after"), QByteArrayLiteral("60")},
        };
        response.body = QByteArrayLiteral(
            "{\"schema_version\":1,\"code\":\"rate_limited\",\"message\":\"wait\",\"retry_after\":60}");
        CatalogResolveResult result;
        QString error;
        CHECK(parseCatalogResolveHttpResponse(response, nonce, result, error));
        CHECK(result.kind == CatalogResolveResultKind::RateLimited
              && result.authoritativeV2Endpoint && result.retryAfterS == 60);
        response.headers[QByteArrayLiteral("cache-control")] =
            QByteArrayLiteral("private,no-store,no-cache,max-age=0");
        CHECK(parseCatalogResolveHttpResponse(response, nonce, result, error));
        response.headers[QByteArrayLiteral("cache-control")] =
            QByteArrayLiteral("private,no-store,public");
        CHECK(!parseCatalogResolveHttpResponse(response, nonce, result, error));
        response.status = 410;
        response.headers.remove(QByteArrayLiteral("retry-after"));
        response.headers[QByteArrayLiteral("cache-control")] =
            QByteArrayLiteral("private,no-store");
        response.body = QByteArrayLiteral(
            "{\"schema_version\":1,\"code\":\"device_revoked\",\"message\":\"gone\",\"reason\":\"revoked\"}");
        CHECK(parseCatalogResolveHttpResponse(response, nonce, result, error));
        CHECK(result.kind == CatalogResolveResultKind::RevokedOrTransferred
              && result.authoritativeV2Endpoint);
        response.body = QByteArrayLiteral(
            "{\"schema_version\":1.5,\"code\":\"device_revoked\","
            "\"message\":\"gone\",\"reason\":\"revoked\"}");
        CHECK(!parseCatalogResolveHttpResponse(response, nonce, result, error));
        response.body = QByteArrayLiteral(
            "{\"schema_version\":1,\"code\":\"device_revoked\","
            "\"message\":\"gone\",\"reason\":\"revoked\"}");
        response.body.replace("revoked", "unknown");
        CHECK(!parseCatalogResolveHttpResponse(response, nonce, result, error));

        response.status = 426;
        response.body = QByteArrayLiteral(
            "{\"schema_version\":1,\"code\":\"upgrade_required\",\"message\":\"upgrade\"}");
        CHECK(parseCatalogResolveHttpResponse(response, nonce, result, error));
        CHECK(result.kind == CatalogResolveResultKind::UpgradeRequired
              && result.authoritativeV2Endpoint && result.minimumAppBuild == 0);
        response.body = QByteArrayLiteral(
            "{\"schema_version\":1,\"code\":\"upgrade_required\",\"message\":\"upgrade\","
            "\"minimum_app_build\":101}");
        CHECK(parseCatalogResolveHttpResponse(response, nonce, result, error));
        CHECK(result.kind == CatalogResolveResultKind::UpgradeRequired
              && result.minimumAppBuild == 101);

        response.status = 403;
        response.body = QByteArrayLiteral(
            "{\"schema_version\":1,\"code\":\"account_blocked\",\"message\":\"blocked\","
            "\"minimum_app_build\":101}");
        CHECK(!parseCatalogResolveHttpResponse(response, nonce, result, error));
    }

    // Candidate learning/cooldowns are scoped to a privacy-safe network path generation. A Wi-Fi
    // -> cellular switch or a new path epoch cannot inherit the previous path's cooldown.
    {
        CatalogRuntimeState state;
        CandidateHistory history;
        history.configGeneration = 3;
        history.bindingGeneration = 4;
        history.cooldownUntil = QDateTime::fromString(
            QStringLiteral("2026-08-28T10:10:00Z"), Qt::ISODate);
        CatalogNetworkPathScope wifi{CatalogNetworkClass::Wifi, 7};
        state.nextNetworkPathEpoch = 8;
        QString error;
        CHECK(mergeCandidateHistoryForPath(
            state, wifi, {{QStringLiteral("profile-a"), history}}, error));
        CatalogCandidate candidate;
        candidate.profileId = QStringLiteral("profile-a");
        CHECK(candidateHistoryForPath(state, wifi, {candidate})
                  .value(candidate.profileId).cooldownUntil == history.cooldownUntil);
        CHECK(candidateHistoryForPath(
                  state, {CatalogNetworkClass::Cellular, 7}, {candidate}).isEmpty());
        CHECK(candidateHistoryForPath(
                  state, {CatalogNetworkClass::Wifi, 8}, {candidate}).isEmpty());
        CHECK(!scopedCatalogHistoryKey(wifi, candidate.profileId).contains(candidate.profileId));
        QByteArray serialized;
        CHECK(serializeCatalogRuntimeState(state, serialized, error));
        CatalogRuntimeState restored;
        CHECK(parseCatalogRuntimeState(serialized, restored, error));
        QJsonObject fractionalRuntime = QJsonDocument::fromJson(serialized).object();
        fractionalRuntime.insert(QStringLiteral("schema"), 3.5);
        CHECK(!parseCatalogRuntimeState(
            QJsonDocument(fractionalRuntime).toJson(QJsonDocument::Compact), restored, error));
        CHECK(parseCatalogRuntimeState(serialized, restored, error));
        CHECK(candidateHistoryForPath(restored, wifi, {candidate}).size() == 1);
        CatalogNetworkPathScope afterRestart;
        CHECK(allocateCatalogNetworkPathScope(restored, CatalogNetworkClass::Wifi,
                                              afterRestart, error));
        CHECK(afterRestart.epoch == 8); // never restarts at 1 / reuses old Wi-Fi scope

        QJsonObject nMinusOne = QJsonDocument::fromJson(serialized).object();
        nMinusOne.insert(QStringLiteral("schema"), 2);
        nMinusOne.remove(QStringLiteral("next_path_epoch"));
        CatalogRuntimeState migrated;
        CHECK(parseCatalogRuntimeState(
            QJsonDocument(nMinusOne).toJson(QJsonDocument::Compact), migrated, error));
        CHECK(migrated.nextNetworkPathEpoch == 8);
    }

    // History retention is deterministic and bounded: old path epochs are pruned while the exact
    // current scope survives. The resulting state remains serializable instead of becoming a
    // permanent >512-entry persistence failure.
    {
        CatalogRuntimeState state;
        CatalogNetworkPathScope current;
        QString error;
        CandidateHistory history;
        history.configGeneration = 1;
        history.bindingGeneration = 1;
        for (int index = 0; index < 520; ++index) {
            CHECK(allocateCatalogNetworkPathScope(
                state, index % 2 ? CatalogNetworkClass::Wifi
                                 : CatalogNetworkClass::Cellular,
                current, error));
            CHECK(mergeCandidateHistoryForPath(
                state, current,
                {{QStringLiteral("profile-%1").arg(index), history}}, error));
        }
        CHECK(state.candidateHistory.size() == 320);
        CatalogCandidate currentCandidate;
        currentCandidate.profileId = QStringLiteral("profile-519");
        CHECK(candidateHistoryForPath(state, current, {currentCandidate}).size() == 1);
        QByteArray bounded;
        CHECK(serializeCatalogRuntimeState(state, bounded, error));
        CatalogRuntimeState restored;
        CHECK(parseCatalogRuntimeState(bounded, restored, error));
        CHECK(restored.candidateHistory.size() == 320
              && restored.nextNetworkPathEpoch == 521);
    }

    // AEAD store round-trip, post-commit pending recovery re-applies protection, and failure to
    // protect recovery cryptographically tombstones the committed bytes.
    {
        QByteArray plain;
        CatalogLkgRecord direct;
        QString directError;
        CHECK(CatalogSecureStore::serializePlaintext(lkgRecord(), plain, directError));
        CHECK(canonicalCatalogTrustAudience(lkgRecord().trustState.deviceAudience));
        if (!CatalogSecureStore::parsePlaintext(plain, direct, directError))
            fprintf(stderr, "direct plaintext: %s\n%s\n", directError.toUtf8().constData(),
                    plain.constData());
        CHECK(CatalogSecureStore::parsePlaintext(plain, direct, directError));
        CHECK(direct.authoritativeV2EndpointSeen);
        QJsonObject schema3Full = QJsonDocument::fromJson(plain).object();
        schema3Full.insert(QStringLiteral("schema"), 3);
        CHECK(CatalogSecureStore::parsePlaintext(
            QJsonDocument(schema3Full).toJson(QJsonDocument::Compact),
            direct, directError));
        QJsonObject schema2Full = schema3Full;
        schema2Full.insert(QStringLiteral("schema"), 2);
        schema2Full.remove(QStringLiteral("authoritative_v2_endpoint_seen"));
        CHECK(CatalogSecureStore::parsePlaintext(
            QJsonDocument(schema2Full).toJson(QJsonDocument::Compact),
            direct, directError));
        QJsonObject fractionalPlain = QJsonDocument::fromJson(plain).object();
        fractionalPlain.insert(QStringLiteral("schema"), 3.5);
        CHECK(!CatalogSecureStore::parsePlaintext(
            QJsonDocument(fractionalPlain).toJson(QJsonDocument::Compact),
            direct, directError));
        CatalogLkgRecord tombstone;
        tombstone.authoritativeV2EndpointSeen = true;
        tombstone.acceptedKeysetState = QByteArrayLiteral("accepted-keyset");
        tombstone.runtimeState = QByteArrayLiteral("runtime-state");
        QByteArray tombstonePlain;
        CHECK(CatalogSecureStore::serializePlaintext(
            tombstone, tombstonePlain, directError));
        CatalogLkgRecord parsedTombstone;
        CHECK(CatalogSecureStore::parsePlaintext(
            tombstonePlain, parsedTombstone, directError));
        CHECK(parsedTombstone.authoritativeV2EndpointSeen
              && parsedTombstone.verifiedEnvelope.isEmpty()
              && !parsedTombstone.trustState.hasAcceptedV2);
        QJsonObject schema3Endpoint = QJsonDocument::fromJson(tombstonePlain).object();
        schema3Endpoint.insert(QStringLiteral("schema"), 3);
        CHECK(CatalogSecureStore::parsePlaintext(
            QJsonDocument(schema3Endpoint).toJson(QJsonDocument::Compact),
            parsedTombstone, directError));

        CatalogLkgRecord authorityTombstone = lkgRecord();
        authorityTombstone.verifiedEnvelope.clear();
        QByteArray authorityPlain;
        CHECK(CatalogSecureStore::serializePlaintext(
            authorityTombstone, authorityPlain, directError));
        CatalogLkgRecord parsedAuthority;
        CHECK(CatalogSecureStore::parsePlaintext(
            authorityPlain, parsedAuthority, directError));
        CHECK(parsedAuthority.verifiedEnvelope.isEmpty()
              && parsedAuthority.trustState.hasAcceptedV2
              && parsedAuthority.trustState.highestCatalogRevision == 7
              && !parsedAuthority.acceptedKeysetState.isEmpty());

        CatalogLkgRecord incomplete = authorityTombstone;
        incomplete.acceptedKeysetState.clear();
        CHECK(!CatalogSecureStore::serializePlaintext(
            incomplete, authorityPlain, directError));
        incomplete = authorityTombstone;
        incomplete.runtimeState.clear();
        CHECK(!CatalogSecureStore::serializePlaintext(
            incomplete, authorityPlain, directError));
        CatalogRuntimeState clockless;
        CHECK(serializeCatalogRuntimeState(
            clockless, incomplete.runtimeState, directError));
        CHECK(!CatalogSecureStore::serializePlaintext(
            incomplete, authorityPlain, directError));
        CHECK(CatalogSecureStore::serializePlaintext(
            authorityTombstone, authorityPlain, directError));
        QJsonObject missingKeyset = QJsonDocument::fromJson(authorityPlain).object();
        CHECK(!missingKeyset.isEmpty());
        missingKeyset.insert(QStringLiteral("keyset_state"), QString{});
        CHECK(!CatalogSecureStore::parsePlaintext(
            QJsonDocument(missingKeyset).toJson(QJsonDocument::Compact),
            parsedAuthority, directError));
        QJsonObject schema3Authority = QJsonDocument::fromJson(authorityPlain).object();
        schema3Authority.insert(QStringLiteral("schema"), 3);
        CHECK(!CatalogSecureStore::parsePlaintext(
            QJsonDocument(schema3Authority).toJson(QJsonDocument::Compact),
            parsedAuthority, directError));
        QTemporaryDir temp(QStringLiteral("/private/tmp/tribe-catalog-store-XXXXXX"));
        CHECK(temp.isValid());
        const QString path = temp.path() + QStringLiteral("/catalog/lkg.bin");
        FakeKeyProvider keys;
        FakeProtection protection;
        CatalogSecureStore store(path, &keys, &protection);
        QString error;
        CHECK(store.replaceAtomically(lkgRecord(), error));
        CHECK(protection.calls == 1);
        CatalogLkgRecord loaded;
        const CatalogLkgLoadStatus initialLoad = store.load(loaded, error);
        if (initialLoad != CatalogLkgLoadStatus::Loaded)
            fprintf(stderr, "initial store load: %s\n", error.toUtf8().constData());
        CHECK(initialLoad == CatalogLkgLoadStatus::Loaded);
        CHECK(loaded.verifiedEnvelope == lkgRecord().verifiedEnvelope);

        QFile current(path);
        CHECK(current.open(QIODevice::ReadOnly));
        const QByteArray oldCiphertext = current.readAll();
        current.close();
        CHECK(store.clear(error));
        QSaveFile restored(path);
        CHECK(restored.open(QIODevice::WriteOnly));
        CHECK(restored.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner));
        CHECK(restored.write(oldCiphertext) == oldCiphertext.size() && restored.commit());
        CHECK(store.load(loaded, error) == CatalogLkgLoadStatus::Error);
    }
    {
        QTemporaryDir temp(QStringLiteral("/private/tmp/tribe-catalog-recover-XXXXXX"));
        const QString path = temp.path() + QStringLiteral("/catalog/lkg.bin");
        FakeKeyProvider keys;
        FakeProtection protection;
        CatalogSecureStore store(path, &keys, &protection);
        keys.failReplaceCall = 2; // commit/protect succeeded; crash before final metadata
        QString error;
        CHECK(!store.replaceAtomically(lkgRecord(), error));
        CHECK(keys.metadata.pendingRevision == 1 && protection.calls == 1);
        keys.failReplaceCall = -1;
        CatalogLkgRecord loaded;
        const CatalogLkgLoadStatus recovered = store.load(loaded, error);
        if (recovered != CatalogLkgLoadStatus::Loaded)
            fprintf(stderr, "pending store load: %s\n", error.toUtf8().constData());
        CHECK(recovered == CatalogLkgLoadStatus::Loaded);
        CHECK(protection.calls == 2 && keys.metadata.pendingRevision == 0);
    }
    {
        QTemporaryDir temp(QStringLiteral("/private/tmp/tribe-catalog-protect-XXXXXX"));
        const QString path = temp.path() + QStringLiteral("/catalog/lkg.bin");
        FakeKeyProvider keys;
        FakeProtection protection;
        CatalogSecureStore store(path, &keys, &protection);
        keys.failReplaceCall = 2;
        QString error;
        CHECK(!store.replaceAtomically(lkgRecord(), error));
        keys.failReplaceCall = -1;
        protection.fail = true;
        CatalogLkgRecord loaded;
        const CatalogLkgLoadStatus protectedFailure = store.load(loaded, error);
        if (protectedFailure != CatalogLkgLoadStatus::Error)
            fprintf(stderr, "pending protection status=%d error=%s\n",
                    int(protectedFailure), error.toUtf8().constData());
        CHECK(protectedFailure == CatalogLkgLoadStatus::Error);
        CHECK(keys.metadata.cleared && keys.metadata.pendingRevision == 0);
        CHECK(!QFile::exists(path));
    }

    // Trusted clock advances monotonically and refuses restored-wall rollback.
    {
        FakeClockSource source;
        source.wall = QDateTime::fromString(QStringLiteral("2026-08-28T10:00:00Z"),
                                            Qt::ISODate);
        CatalogTrustedClock clock(&source, 300, 300);
        QString error;
        CHECK(clock.restore({}, error));
        CHECK(clock.observeAcceptedSignedTime(
            QDateTime::fromString(QStringLiteral("2026-08-28T09:59:00Z"), Qt::ISODate), error));
        source.monotonic = 60000;
        source.wall = source.wall.addSecs(-120);
        CHECK(clock.nowUtc() == QDateTime::fromString(
            QStringLiteral("2026-08-28T10:01:00Z"), Qt::ISODate));
        const CatalogTrustedClockState state = clock.stateForPersistence();
        FakeClockSource rolled;
        rolled.wall = state.highestObservedWallUtc.addSecs(-301);
        CatalogTrustedClock restored(&rolled, 300, 300);
        CHECK(!restored.restore(state, error));
        CHECK(restored.rollbackDetected());
    }

    if (g_failed) {
        fprintf(stderr, "catalog_security_check: FAILED %d/%d\n", g_failed, g_total);
        return 1;
    }
    printf("catalog_security_check: OK (%d keyset/receipt/http/store/clock checks)\n", g_total);
    return 0;
}
