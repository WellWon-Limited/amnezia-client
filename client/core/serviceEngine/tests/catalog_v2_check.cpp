// Tribe serviceEngine v2 — deterministic signed catalog/security/selection/registry checks.
#include "../CandidateSelector.h"
#include "../CatalogAcceptance.h"
#include "../CatalogResolve.h"
#include "../LegacyCatalogFallback.h"
#include "../SubscriptionRequest.h"
#include "../TransportAdapter.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

#include <openssl/evp.h>

#include <cstdio>

using namespace avpn;

static int g_failed = 0;
static int g_total = 0;

#define CHECK(expr)                                                                                 \
    do {                                                                                            \
        ++g_total;                                                                                  \
        if (!(expr)) {                                                                              \
            ++g_failed;                                                                             \
            fprintf(stderr, "FAIL [%s:%d]: %s\n", __FILE__, __LINE__, #expr);                     \
        }                                                                                           \
    } while (0)

class DeterministicSigner {
public:
    DeterministicSigner()
    {
        QByteArray seed(32, 0);
        for (int i = 0; i < seed.size(); ++i)
            seed[i] = char(i + 1);
        m_key = EVP_PKEY_new_raw_private_key(
            EVP_PKEY_ED25519, nullptr,
            reinterpret_cast<const unsigned char *>(seed.constData()), seed.size());
    }
    ~DeterministicSigner() { EVP_PKEY_free(m_key); }

    QString publicHex() const
    {
        QByteArray raw(32, 0);
        size_t size = size_t(raw.size());
        if (!m_key || EVP_PKEY_get_raw_public_key(
                          m_key, reinterpret_cast<unsigned char *>(raw.data()), &size) != 1)
            return {};
        raw.resize(int(size));
        return QString::fromLatin1(raw.toHex());
    }

    QByteArray sign(const QByteArray &message) const
    {
        QByteArray signature(64, 0);
        size_t size = size_t(signature.size());
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (!ctx)
            return {};
        const bool ok = EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, m_key) == 1
                        && EVP_DigestSign(
                               ctx, reinterpret_cast<unsigned char *>(signature.data()), &size,
                               reinterpret_cast<const unsigned char *>(message.constData()),
                               size_t(message.size())) == 1;
        EVP_MD_CTX_free(ctx);
        if (!ok)
            return {};
        signature.resize(int(size));
        return signature;
    }

private:
    EVP_PKEY *m_key = nullptr;
};

static QString key32(char fill)
{
    return QString::fromLatin1(QByteArray(32, fill).toBase64());
}

static QString key32Url(char fill)
{
    return QString::fromLatin1(
        QByteArray(32, fill).toBase64(QByteArray::Base64UrlEncoding
                                     | QByteArray::OmitTrailingEquals));
}

static QJsonObject awgConfig()
{
    return {
        {"endpoint_host", "awg-fi.example.net"},
        {"endpoint_port", 51820},
        {"server_public_key", key32('\x11')},
        {"client_public_key", key32('\x22')},
        {"address", QJsonArray{"10.77.0.2/32", "fd00:77::2/128"}},
        {"allowed_ips", QJsonArray{"0.0.0.0/0", "::/0"}},
        {"dns", QJsonArray{"1.1.1.1", "2606:4700:4700::1111"}},
        {"mtu", 1280},
        {"persistent_keepalive", 25},
        {"awg_params", QJsonObject{
            {"Jc", 4}, {"Jmin", 40}, {"Jmax", 70},
            {"S1", 20}, {"S2", 24}, {"S3", 28}, {"S4", 32},
            {"H1", 1001}, {"H2", 1002}, {"H3", 1003}, {"H4", 1004},
            {"I1", "<r 2><b 0x8580><rd 4><rc 3><t>"},
            {"HeaderProtectionKey", key32('\x33')},
            {"ContentPaddingAddition", "0-64"},
            {"RekeyAfterTime", "120"}, {"RekeyTimeout", "5"},
            {"RejectAfterTime", "180"}, {"KeepaliveTimeout", "10"},
            {"MaxHandshakeAttempts", "20"},
            {"RandomTrailers", true}, {"DisableCookies", true},
        }},
    };
}

static QJsonObject xrayConfig()
{
    return {
        {"endpoint_host", "xray-fi.example.net"},
        {"endpoint_port", 443},
        {"uuid", "123e4567-e89b-42d3-a456-426614174000"},
        {"network", "tcp"}, {"security", "reality"},
        {"flow", "xtls-rprx-vision"},
        {"reality_public_key", key32Url('\x44')},
        {"short_id", "a1b2c3d4"}, {"server_name", "cdn-fi.example.net"},
        {"fingerprint", "chrome"},
    };
}

static QJsonObject nativeProfile(const QString &container, const QString &kind,
                                 const QJsonObject &config)
{
    return {
        {"format", "tribe_native_profile_v1"},
        {"container_config_format", "amnezia_container_config_v1"},
        {"container_type", container}, {"profile_kind", kind},
        {"config_generation", 9}, {"binding_generation", 3},
        {"expires_at", "2026-09-20T00:00:00Z"}, {"config", config},
    };
}

static QJsonObject candidate(const QString &id, const QString &transport,
                             const QString &kind, const QString &domain,
                             const QJsonObject &profile, const QJsonArray &caps)
{
    return {
        {"profile_id", id}, {"transport", transport}, {"profile_kind", kind},
        {"failure_domain", domain}, {"server_health", 0.98},
        {"health_observed_at", "2026-08-27T11:59:30Z"},
        {"capacity_headroom", 0.72}, {"required_caps", caps},
        {"verification", QJsonObject{
            {"expected_egress_ids", QJsonArray{QStringLiteral("fi-exit")}},
            {"context", "opaque-context-01"},
        }},
        {"native_profile", profile},
    };
}

static QJsonObject validPayloadObject()
{
    const QJsonObject awg = candidate(
        QStringLiteral("fi-awg-01"), QStringLiteral("awg"), QStringLiteral("awg31"),
        QStringLiteral("provider-a/asn-a/host-a"),
        nativeProfile(QStringLiteral("amnezia-awg"), QStringLiteral("awg31"), awgConfig()),
        QJsonArray{QStringLiteral("awg.random_trailers"),
                   QStringLiteral("awg.disable_cookies")});
    const QJsonObject xray = candidate(
        QStringLiteral("fi-xray-01"), QStringLiteral("xray"),
        QStringLiteral("xray_vless_reality_vision_tcp"),
        QStringLiteral("provider-b/asn-b/host-b"),
        nativeProfile(QStringLiteral("amnezia-xray"),
                      QStringLiteral("xray_vless_reality_vision_tcp"), xrayConfig()),
        QJsonArray{QStringLiteral("xray.vless.reality.vision.tcp")});
    return {
        {"schema_version", 2}, {"catalog_revision", 1842}, {"key_epoch", 4},
        {"device_audience", key32Url('a')}, {"request_nonce", key32Url('n')},
        {"device_revocation_epoch", 7}, {"policy_revision", 11},
        {"entitlement_expires_at", "2026-09-27T00:00:00Z"},
        {"issued_at", "2026-08-27T12:00:00Z"},
        {"expires_at", "2026-08-28T12:00:00Z"},
        {"refresh_after", "2026-08-27T12:15:00Z"},
        {"policy", QJsonObject{
            {"mode_default", "auto"}, {"max_attempts", 3},
            {"connect_timeout_ms", 12000}, {"verify_timeout_ms", 6000},
            {"profile_cooldown_s", 300}, {"minimum_dwell_s", 300},
            {"offline_grace_s", 21600},
        }},
        {"locations", QJsonArray{QJsonObject{
            {"id", "fi-hel"}, {"country", "FI"}, {"city", "HEL"},
            {"display_key", "location.fi.hel"}, {"candidates", QJsonArray{awg, xray}},
        }}},
    };
}

static QJsonObject jsonFixture(const char *name)
{
    QFile file(QFileInfo(QString::fromUtf8(__FILE__)).absolutePath()
               + QStringLiteral("/fixtures/") + QString::fromLatin1(name));
    if (!file.open(QIODevice::ReadOnly)) return {};
    return QJsonDocument::fromJson(file.readAll()).object();
}

static QJsonObject receiptProviderExtension()
{
    const QString verificationToken = jsonFixture(
        "verification_grant_v1_golden.json").value(QStringLiteral("token")).toString();
    return {
        {"id", "verification.providers_v1"},
        {"critical", true},
        {"required_cap", "probe.egress_receipt_v1"},
        {"value", QJsonObject{
            {"schema_version", 1}, {"quorum", 2},
            {"verification_token", verificationToken},
            {"verification_token_expires_at", "2026-08-27T12:10:00Z"},
            {"providers", QJsonArray{
                QJsonObject{{"id", "provider-a"}, {"trust_domain", "authority-a"},
                            {"base_url", "https://verify-a.example.net"},
                            {"bootstrap_ips", QJsonArray{"1.1.1.1"}},
                            {"receipt_kid", "receipt-a"}, {"receipt_key_epoch", 7}},
                QJsonObject{{"id", "provider-b"}, {"trust_domain", "authority-b"},
                            {"base_url", "https://verify-b.example.org"},
                            {"bootstrap_ips", QJsonArray{"8.8.8.8"}},
                            {"receipt_kid", "receipt-b"}, {"receipt_key_epoch", 8}},
            }},
        }},
    };
}

static QJsonObject locationDirectoryExtension(const QString &transport = QStringLiteral("auto"),
                                              const QString &locationId = {})
{
    QJsonObject selection{{"transport", transport}};
    if (!locationId.isEmpty()) selection.insert(QStringLiteral("location_id"), locationId);
    return {
        {"id", "catalog.location_directory_v1"},
        {"critical", true},
        {"required_cap", "catalog.location_directory_v1"},
        {"value", QJsonObject{
            {"schema_version", 1}, {"selection", selection},
            {"locations", QJsonArray{QJsonObject{
                {"id", "fi-hel"}, {"country", "FI"}, {"city", "HEL"},
                {"display_key", "location.fi.hel"},
                {"transports", QJsonArray{
                    QJsonObject{{"transport", "awg"}, {"state", "selectable"},
                                {"predicted_quality", 0.91},
                                {"observed_at", "2026-08-27T11:59:30Z"}},
                    QJsonObject{{"transport", "xray"}, {"state", "selectable"},
                                {"predicted_quality", 0.88},
                                {"observed_at", "2026-08-27T11:59:30Z"}},
                }},
            }}},
        }},
    };
}

static QByteArray compact(const QJsonObject &object)
{
    return QJsonDocument(object).toJson(QJsonDocument::Compact);
}

static QByteArray envelopeForPayload(const QByteArray &payload, const QString &kid,
                                     const DeterministicSigner &signer)
{
    const QByteArray encoded = payload.toBase64(QByteArray::Base64UrlEncoding
                                                | QByteArray::OmitTrailingEquals);
    const QByteArray signature = signer.sign(CatalogParser::signatureInput(kid, encoded));
    return compact({{"alg", "Ed25519"}, {"kid", kid},
                    {"payload", QString::fromLatin1(encoded)},
                    {"signature", QString::fromLatin1(signature.toBase64(
                                      QByteArray::Base64UrlEncoding
                                      | QByteArray::OmitTrailingEquals))}});
}

static QJsonObject candidateAt(const QJsonObject &root, int index)
{
    return root.value("locations").toArray().at(0).toObject()
        .value("candidates").toArray().at(index).toObject();
}

static void replaceCandidate(QJsonObject &root, int index, const QJsonObject &replacement)
{
    QJsonArray locations = root.value("locations").toArray();
    QJsonObject location = locations.at(0).toObject();
    QJsonArray candidates = location.value("candidates").toArray();
    candidates[index] = replacement;
    location["candidates"] = candidates;
    locations[0] = location;
    root["locations"] = locations;
}

static PlatformCapabilities allCapabilities()
{
    PlatformCapabilities caps;
    caps.catalogSchemaMax = 2;
    caps.nativeProfileFormats.insert(QStringLiteral("tribe_native_profile_v1"));
    caps.containerConfigFormats.insert(QStringLiteral("amnezia_container_config_v1"));
    caps.profileKinds = {QStringLiteral("awg31"),
                         QStringLiteral("xray_vless_reality_vision_tcp")};
    caps.capabilities = {QStringLiteral("awg.random_trailers"),
                         QStringLiteral("awg.disable_cookies"),
                         QStringLiteral("xray.vless.reality.vision.tcp")};
    caps.transports = {TransportKind::Awg, TransportKind::Xray};
    return caps;
}

class FakeAdapter final : public ITransportAdapter {
public:
    FakeAdapter(TransportKind transport, amnezia::DockerContainer declared,
                amnezia::DockerContainer compiled)
        : m_transport(transport), m_declared(declared), m_compiled(compiled) {}

    TransportKind transport() const override { return m_transport; }
    amnezia::DockerContainer nativeContainer() const override { return m_declared; }
    QSet<QString> supportedProfileKinds() const override
    {
        return m_transport == TransportKind::Awg
                   ? QSet<QString>{QStringLiteral("awg31")}
                   : QSet<QString>{QStringLiteral("xray_vless_reality_vision_tcp")};
    }
    bool validateAndCompile(const CatalogCandidate &candidate, CompiledNativeProfile &compiled,
                            QString &) const override
    {
        compiled.container = m_compiled;
        compiled.transport = candidate.transport;
        compiled.profileId = candidate.profileId;
        compiled.locationId = candidate.locationId;
        compiled.locationCountry = candidate.locationCountry;
        compiled.failureDomain = candidate.failureDomain;
        compiled.configGeneration = candidate.nativeProfile.configGeneration;
        compiled.bindingGeneration = candidate.nativeProfile.bindingGeneration;
        compiled.expiresAt = candidate.nativeProfile.expiresAt;
        const QString dataKey = nativeConfigDataKeyForTransport(m_transport);
        compiled.vpnConfiguration = {
            {"protocol", transportKindName(m_transport)},
            {dataKey, QJsonObject{{"config", "sanitized-native-test-config"}}},
            {"hostName", "vpn.example.net"}, {"dns1", "1.1.1.1"},
            {"dns2", "1.0.0.1"}, {"splitTunnelType", 0}, {"config_version", 1},
        };
        return true;
    }
    bool prepareStart(const CompiledNativeProfile &compiled,
                      TransportOperationToken,
                      PreparedTransportStart &prepared,
                      QString &) override
    {
        prepared.compiled = compiled;
        prepared.finalConfiguration = compiled.vpnConfiguration;
        prepared.finalConfiguration.insert(
            QStringLiteral("native_envelope_schema"),
            QStringLiteral("tribe_catalog_v2_native_v1"));
        prepared.nativeDispatchPolicySha256 = QByteArray(32, 'p');
        return true;
    }
    void setObserver(ITransportAdapterObserver *) override {}
    void clearObserver(ITransportAdapterObserver *) override {}
    bool start(const PreparedTransportStart &, TransportOperationToken, QString &) override
    {
        return true;
    }
    void stop(TransportOperationToken) override {}
    TransportTelemetry telemetry() const override { return {}; }

private:
    TransportKind m_transport;
    amnezia::DockerContainer m_declared;
    amnezia::DockerContainer m_compiled;
};

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    app.setApplicationVersion(QStringLiteral("5.1.97"));
    {
        const QUrl url = versionedSubscriptionUrl(
            QStringLiteral("https://api.example.test"), app.applicationVersion());
        const QUrlQuery query(url);
        CHECK(url.scheme() == QLatin1String("https"));
        CHECK(url.host() == QLatin1String("api.example.test"));
        CHECK(url.path() == QLatin1String("/v1/subscription"));
        CHECK(query.allQueryItemValues(QStringLiteral("app_version"))
                  == QStringList{QStringLiteral("5.1.97")});
        CHECK(versionedSubscriptionUrl(QStringLiteral("https://api.example.test"),
                                       QString()).isEmpty());
        CHECK(versionedSubscriptionUrl(QStringLiteral("https://api.example.test"),
                                       QStringLiteral("97")).isEmpty());
        CHECK(versionedSubscriptionUrl(QStringLiteral("https://api.example.test"),
                                       QStringLiteral("5.1.97-beta")).isEmpty());
    }
    const DeterministicSigner signer;
    const QString kid = QStringLiteral("catalog-test-1");
    CatalogKeyring keyring;
    keyring.publicKeysHex.insert(kid, signer.publicHex());
    keyring.keyEpochs.insert(kid, 4);
    const QDateTime now = QDateTime::fromString(QStringLiteral("2026-08-27T12:05:00Z"), Qt::ISODate);
    const QByteArray payload = compact(validPayloadObject());
    const QByteArray envelope = envelopeForPayload(payload, kid, signer);

    Catalog catalog;
    CatalogParseError error;
    CHECK(CatalogParser::verifyAndParse(envelope, keyring, catalog, error));
    CHECK(catalog.schemaVersion == 2);
    CHECK(catalog.locations.size() == 1);
    CHECK(catalog.locations.first().candidates.size() == 2);
    CHECK(catalog.locations.first().candidates.at(0).transport == TransportKind::Awg);
    CHECK(catalog.locations.first().candidates.at(1).transport == TransportKind::Xray);
    CHECK(nativeContainerForTransport(TransportKind::Awg) == amnezia::DockerContainer::Awg);
    CHECK(nativeContainerForTransport(TransportKind::Xray) == amnezia::DockerContainer::Xray);
    CHECK(catalog.locations.first().candidates.at(1).nativeProfile.containerType
          == QLatin1String("amnezia-xray"));

    // The public signed directory is a separate typed/bounded authority from the credential
    // shortlist. Its exact selection echo binds scoped refreshes; no profile/host/binding ids or
    // credentials are represented in the directory DTO.
    {
        QJsonObject root = validPayloadObject();
        QJsonArray scopedLocations = root.value(QStringLiteral("locations")).toArray();
        QJsonObject scopedLocation = scopedLocations.first().toObject();
        const QJsonArray allCandidates =
            scopedLocation.value(QStringLiteral("candidates")).toArray();
        scopedLocation[QStringLiteral("candidates")] =
            QJsonArray{allCandidates.at(1)}; // exact Xray-only credential scope
        scopedLocations[0] = scopedLocation;
        root[QStringLiteral("locations")] = scopedLocations;
        root[QStringLiteral("extensions")] = QJsonArray{locationDirectoryExtension(
            QStringLiteral("xray"), QStringLiteral("fi-hel"))};
        const QByteArray signedDirectory = envelopeForPayload(compact(root), kid, signer);
        Catalog parsed;
        CatalogParseError parseError;
        CHECK(CatalogParser::verifyAndParse(signedDirectory, keyring, parsed, parseError));
        CHECK(parsed.locationDirectory.has_value());
        CHECK(parsed.locationDirectory->locations.size() == 1);
        CHECK(parsed.locationDirectory->locations.first().transports.size() == 2);
        CHECK(parsed.locationDirectory->locations.first().transports.first().predictedQuality
              == std::optional<double>(0.91));
        const CatalogResolveSelection xrayFinland{
            ConnectionMode::ForceXray, QStringLiteral("fi-hel")};
        CHECK(parsed.locationDirectory->selection == xrayFinland);
        CatalogTrustState trust;
        const CatalogAcceptanceResult bound = acceptCatalogEnvelope(
            signedDirectory, keyring, allCapabilities(), trust, CatalogSource::Network, now,
            {key32Url('n'), CatalogResolveSelection{ConnectionMode::ForceXray,
                                                   QStringLiteral("fi-hel")}});
        CHECK(bound.authoritative && bound.connectable);
        const CatalogAcceptanceResult mismatch = acceptCatalogEnvelope(
            signedDirectory, keyring, allCapabilities(), trust, CatalogSource::Network, now,
            {key32Url('n'), CatalogResolveSelection{ConnectionMode::ForceAwg,
                                                   QStringLiteral("fi-hel")}});
        CHECK(!mismatch.authoritative
              && mismatch.error == CatalogAcceptanceError::ResponseBinding);
        const CatalogAcceptanceResult unscopedNonDefault = acceptCatalogEnvelope(
            signedDirectory, keyring, allCapabilities(), trust,
            CatalogSource::Network, now, {key32Url('n')});
        CHECK(!unscopedNonDefault.authoritative
              && unscopedNonDefault.error
                     == CatalogAcceptanceError::ResponseBinding);

        QJsonObject overbroad = validPayloadObject();
        overbroad[QStringLiteral("extensions")] = QJsonArray{
            locationDirectoryExtension(QStringLiteral("xray"),
                                       QStringLiteral("fi-hel"))};
        const CatalogAcceptanceResult overbroadCredentials = acceptCatalogEnvelope(
            envelopeForPayload(compact(overbroad), kid, signer), keyring,
            allCapabilities(), trust, CatalogSource::Network, now,
            {key32Url('n'),
             CatalogResolveSelection{ConnectionMode::ForceXray,
                                     QStringLiteral("fi-hel")}, true});
        CHECK(!overbroadCredentials.authoritative
              && overbroadCredentials.error
                     == CatalogAcceptanceError::ResponseBinding);

        QJsonObject malformed = root;
        QJsonArray extensions = malformed.value(QStringLiteral("extensions")).toArray();
        QJsonObject extension = extensions.first().toObject();
        QJsonObject value = extension.value(QStringLiteral("value")).toObject();
        QJsonArray locations = value.value(QStringLiteral("locations")).toArray();
        QJsonObject location = locations.first().toObject();
        QJsonArray transports = location.value(QStringLiteral("transports")).toArray();
        const QJsonValue firstTransport = transports.at(0);
        transports[0] = transports.at(1);
        transports[1] = firstTransport;
        location[QStringLiteral("transports")] = transports;
        locations[0] = location;
        value[QStringLiteral("locations")] = locations;
        extension[QStringLiteral("value")] = value;
        extensions[0] = extension;
        malformed[QStringLiteral("extensions")] = extensions;
        CHECK(!CatalogParser::verifyAndParse(
            envelopeForPayload(compact(malformed), kid, signer), keyring, parsed, parseError));

        malformed = root;
        extensions = malformed.value(QStringLiteral("extensions")).toArray();
        extension = extensions.first().toObject();
        value = extension.value(QStringLiteral("value")).toObject();
        locations = value.value(QStringLiteral("locations")).toArray();
        location = locations.first().toObject();
        transports = location.value(QStringLiteral("transports")).toArray();
        QJsonObject xrayUnavailable = transports.at(1).toObject();
        xrayUnavailable[QStringLiteral("state")] = QStringLiteral("temporarily_unavailable");
        xrayUnavailable.remove(QStringLiteral("predicted_quality"));
        xrayUnavailable.remove(QStringLiteral("observed_at"));
        transports[1] = xrayUnavailable;
        location[QStringLiteral("transports")] = transports;
        locations[0] = location;
        value[QStringLiteral("locations")] = locations;
        extension[QStringLiteral("value")] = value;
        extensions[0] = extension;
        malformed[QStringLiteral("extensions")] = extensions;
        CHECK(!CatalogParser::verifyAndParse(
            envelopeForPayload(compact(malformed), kid, signer), keyring, parsed, parseError));
    }

    // Signing-key IDs are byte-identical to the backend VERSION_PATTERN. `+` is valid; path-like
    // separators and a 65th byte are rejected even if a caller tries to place them in the keyring.
    {
        Catalog parsed;
        CatalogParseError parseError;
        CatalogKeyring plusKeyring;
        plusKeyring.publicKeysHex.insert(QStringLiteral("catalog+k1"), signer.publicHex());
        plusKeyring.keyEpochs.insert(QStringLiteral("catalog+k1"), 4);
        CHECK(CatalogParser::verifyAndParse(
            envelopeForPayload(payload, QStringLiteral("catalog+k1"), signer),
            plusKeyring, parsed, parseError));
        for (const QString &badKid : {QStringLiteral("catalog/k1"),
                                     QStringLiteral("catalog:k1"),
                                     QString(65, QLatin1Char('a'))}) {
            CatalogKeyring badKeyring;
            badKeyring.publicKeysHex.insert(badKid, signer.publicHex());
            badKeyring.keyEpochs.insert(badKid, 4);
            CHECK(!CatalogParser::verifyAndParse(
                envelopeForPayload(payload, badKid, signer),
                badKeyring, parsed, parseError));
        }
    }

    // Resolve request reports exact shipped app/adapter/engine facts; no version defaults and no
    // private key can enter the body.
    {
        CatalogResolveRequest request;
        request.requestNonce = key32Url('n');
        request.app = {CatalogAppPlatform::Ios, QStringLiteral("5.1.68.97"), 97,
                       QStringLiteral("arm64")};
        request.adapters.appleNetworkExtension = QStringLiteral("apple-ne-v2");
        request.engines.awg = CatalogEngineFact{QStringLiteral("awg-apple"),
                                                QStringLiteral("3.1.4-tribe.3")};
        request.engines.xray = CatalogEngineFact{QStringLiteral("amnezia-libxray"),
                                                 QStringLiteral("1.0.3")};
        request.deviceKeys.awgPublicKey = key32('\x61');
        request.capabilities = {QStringLiteral("awg.random_trailers"),
                                QStringLiteral("awg.disable_cookies"),
                                QStringLiteral("xray.vless.reality.vision.tcp"),
                                QStringLiteral("tribe.guarded_settings_owner"),
                                QStringLiteral("catalog.location_directory_v1")};
        QJsonObject body;
        QString requestError;
        CHECK(buildCatalogResolveRequest(request, body, requestError));
        CHECK(body.value("app").toObject().value("build").toInt() == 97);
        CHECK(body.value("request_nonce").toString() == request.requestNonce);
        CHECK(body.value("engines").toObject().contains("awg"));
        CHECK(body.value("engines").toObject().contains("xray"));
        CHECK(body.value("device_keys").toObject().contains("awg_public_key"));
        CHECK(body.value("device_keys").toObject().size() == 1);
        CHECK(!body.value("device_keys").toObject().contains("awg_key_generation"));
        CHECK(!QString::fromUtf8(QJsonDocument(body).toJson()).contains("private"));
        CHECK(!body.contains(QStringLiteral("selection")));
        request.selection = CatalogResolveSelection{ConnectionMode::ForceXray,
                                                    QStringLiteral("fi-hel")};
        CHECK(buildCatalogResolveRequest(request, body, requestError));
        const QJsonObject expectedSelection{
            {QStringLiteral("transport"), QStringLiteral("xray")},
            {QStringLiteral("location_id"), QStringLiteral("fi-hel")}};
        CHECK(body.value(QStringLiteral("selection")).toObject() == expectedSelection);
        request.capabilities.removeAll(QStringLiteral("catalog.location_directory_v1"));
        CHECK(!buildCatalogResolveRequest(request, body, requestError));
        request.selection.reset();
        request.capabilities.append(QStringLiteral("catalog.location_directory_v1"));

        CatalogResolveRequest invalid = request;
        invalid.adapters.appleNetworkExtension.reset();
        CHECK(!buildCatalogResolveRequest(invalid, body, requestError));
        invalid = request;
        invalid.capabilities.append(QStringLiteral("awg.random_trailers"));
        CHECK(!buildCatalogResolveRequest(invalid, body, requestError));
        invalid = request;
        invalid.capabilities.removeAll(QStringLiteral("xray.vless.reality.vision.tcp"));
        CHECK(!buildCatalogResolveRequest(invalid, body, requestError));
        invalid = request;
        invalid.capabilities.removeAll(QStringLiteral("tribe.guarded_settings_owner"));
        CHECK(!buildCatalogResolveRequest(invalid, body, requestError));
        invalid = request;
        invalid.deviceKeys.awgPublicKey = QStringLiteral("not-a-wireguard-key");
        CHECK(!buildCatalogResolveRequest(invalid, body, requestError));
        invalid = request;
        invalid.engines.awg.reset();
        invalid.capabilities.removeAll(QStringLiteral("awg.random_trailers"));
        invalid.capabilities.removeAll(QStringLiteral("awg.disable_cookies"));
        CHECK(!buildCatalogResolveRequest(invalid, body, requestError));
        invalid.deviceKeys = {};
        CHECK(buildCatalogResolveRequest(invalid, body, requestError));
        CHECK(body.value("device_keys").toObject().isEmpty());
        invalid = request;
        invalid.requestNonce.append(QLatin1Char('='));
        CHECK(!buildCatalogResolveRequest(invalid, body, requestError));

        CatalogResolveRequest macNe = request;
        macNe.app.platform = CatalogAppPlatform::Macos;
        macNe.adapters.appleNetworkExtension.reset();
        macNe.adapters.macosNetworkExtension = QStringLiteral("macos-ne-v1");
        CHECK(buildCatalogResolveRequest(macNe, body, requestError));
        CHECK(body.value("adapters").toObject().size() == 1
              && body.value("adapters").toObject().value("macos_network_extension")
                     == QLatin1String("macos-ne-v1"));
        CatalogResolveRequest macDaemon = macNe;
        macDaemon.adapters.macosNetworkExtension.reset();
        macDaemon.adapters.macosDaemonIpc = QStringLiteral("macos-daemon-v1");
        CHECK(buildCatalogResolveRequest(macDaemon, body, requestError));
        CHECK(body.value("adapters").toObject().size() == 1
              && body.value("adapters").toObject().contains("macos_daemon_ipc"));
        macDaemon.adapters.macosNetworkExtension = QStringLiteral("macos-ne-v1");
        CHECK(!buildCatalogResolveRequest(macDaemon, body, requestError));
        CatalogResolveRequest iosWithMac = request;
        iosWithMac.adapters.macosNetworkExtension = QStringLiteral("macos-ne-v1");
        CHECK(!buildCatalogResolveRequest(iosWithMac, body, requestError));
    }

    // Golden vector generated by backend crypto_sign.py from its deterministic dev seed. The
    // intentionally incomplete payload reaches schema parsing (not InvalidSignature), proving
    // both languages sign the exact encoded token text with the same domain separator.
    {
        const QString goldenKid = QStringLiteral("k1");
        const QByteArray goldenToken = QByteArrayLiteral("eyJzY2hlbWFfdmVyc2lvbiI6Mn0");
        const QByteArray goldenSignature = QByteArrayLiteral(
            "uJAx8fDHYPNeJGKbNEz3ny-sbxzRlRMA6X-LPpdbl6rNNlet2Nj0_vKYPZu5DhEAd_-SXnONwcsg9rnvqkFZCA");
        CHECK(CatalogParser::signatureInput(goldenKid, goldenToken)
              == QByteArrayLiteral("tribe-catalog-v2\nk1\n") + goldenToken);
        CatalogKeyring goldenKeyring;
        goldenKeyring.publicKeysHex.insert(
            goldenKid,
            QStringLiteral("95da1bd9062653d9c185c3ca5cae995516a8e353abccd3cf98cd12cd2f3a075a"));
        goldenKeyring.keyEpochs.insert(goldenKid, 1);
        const QByteArray goldenEnvelope = compact({
            {"alg", "Ed25519"}, {"kid", goldenKid},
            {"payload", QString::fromLatin1(goldenToken)},
            {"signature", QString::fromLatin1(goldenSignature)},
        });
        Catalog incomplete;
        CatalogParseError goldenError;
        CHECK(!CatalogParser::verifyAndParse(goldenEnvelope, goldenKeyring,
                                             incomplete, goldenError));
        CHECK(goldenError.code == CatalogParseErrorCode::MissingField);
    }

    // Full backend-owned golden envelope: both typed profiles, all optional AWG3 fields/CPS
    // grammar, max Reality short_id and `randomized` fingerprint cross the real verifier/parser.
    {
        const QDir fixtures(QFileInfo(QString::fromUtf8(__FILE__)).absoluteDir()
                                .filePath(QStringLiteral("fixtures")));
        QFile envelopeFile(fixtures.filePath(QStringLiteral("catalog_v2_golden_envelope.json")));
        QFile publicKeyFile(fixtures.filePath(
            QStringLiteral("catalog_v2_golden_public_key.hex")));
        CHECK(envelopeFile.open(QIODevice::ReadOnly));
        CHECK(publicKeyFile.open(QIODevice::ReadOnly));
        CatalogKeyring goldenKeyring;
        goldenKeyring.publicKeysHex.insert(
            QStringLiteral("k1"), QString::fromLatin1(publicKeyFile.readAll().trimmed()));
        goldenKeyring.keyEpochs.insert(QStringLiteral("k1"), 4);
        Catalog goldenCatalog;
        CatalogParseError goldenError;
        CHECK(CatalogParser::verifyAndParse(envelopeFile.readAll(), goldenKeyring,
                                            goldenCatalog, goldenError));
        CHECK(goldenCatalog.catalogRevision == 1842);
        CHECK(goldenCatalog.deviceAudience == key32Url('a'));
        CHECK(goldenCatalog.requestNonce == key32Url('n'));
        CHECK(goldenCatalog.locations.first().candidates.size() == 2);
        CHECK(goldenCatalog.locations.first().candidates.at(0).nativeProfile.config
                  .value("awg_params").toObject().value("RandomTrailers").toBool());
        CHECK(goldenCatalog.locations.first().candidates.at(1).nativeProfile.config
                  .value("fingerprint").toString() == QLatin1String("randomized"));
        CHECK(goldenCatalog.locations.first().candidates.at(1).nativeProfile.config
                  .value("short_id").toString().size() == 16);
    }

    // Signature is domain-separated over canonical encoded payload text and verified before decode.
    {
        QJsonObject tampered = QJsonDocument::fromJson(envelope).object();
        QByteArray encoded = tampered.value("payload").toString().toLatin1();
        encoded[encoded.size() / 2] = encoded.at(encoded.size() / 2) == 'A' ? 'B' : 'A';
        tampered["payload"] = QString::fromLatin1(encoded);
        Catalog rejected;
        CHECK(!CatalogParser::verifyAndParse(compact(tampered), keyring, rejected, error));
        CHECK(error.code == CatalogParseErrorCode::InvalidSignature);

        QJsonObject kidConfusion = QJsonDocument::fromJson(envelope).object();
        kidConfusion["kid"] = "catalog-test-2";
        CatalogKeyring twoKeys = keyring;
        twoKeys.publicKeysHex.insert(QStringLiteral("catalog-test-2"), signer.publicHex());
        twoKeys.keyEpochs.insert(QStringLiteral("catalog-test-2"), 4);
        CHECK(!CatalogParser::verifyAndParse(compact(kidConfusion), twoKeys, rejected, error));
        CHECK(error.code == CatalogParseErrorCode::InvalidSignature);

        QJsonObject padded = QJsonDocument::fromJson(envelope).object();
        padded["payload"] = padded.value("payload").toString() + QLatin1Char('=');
        CHECK(!CatalogParser::verifyAndParse(compact(padded), keyring, rejected, error));
        CHECK(error.code == CatalogParseErrorCode::InvalidBase64Url);
        padded["payload"] = QStringLiteral("abc+");
        CHECK(!CatalogParser::verifyAndParse(compact(padded), keyring, rejected, error));
        CHECK(error.code == CatalogParseErrorCode::InvalidBase64Url);

        CatalogKeyring missingEpoch = keyring;
        missingEpoch.keyEpochs.clear();
        CHECK(!CatalogParser::verifyAndParse(envelope, missingEpoch, rejected, error));
        CHECK(error.code == CatalogParseErrorCode::SigningKeyEpochMismatch);
        CatalogKeyring wrongEpoch = keyring;
        wrongEpoch.keyEpochs[kid] = 3;
        CHECK(!CatalogParser::verifyAndParse(envelope, wrongEpoch, rejected, error));
        CHECK(error.code == CatalogParseErrorCode::SigningKeyEpochMismatch);

        QJsonObject unknownEnvelope = QJsonDocument::fromJson(envelope).object();
        unknownEnvelope["crit"] = QJsonArray{"future"};
        CHECK(!CatalogParser::verifyAndParse(compact(unknownEnvelope), keyring, rejected, error));
        CHECK(error.code != CatalogParseErrorCode::None);
    }

    // Duplicate/escaped keys, malformed UTF-8 and JSON resource limits are rejected.
    {
        const QJsonObject envObject = QJsonDocument::fromJson(envelope).object();
        const QByteArray duplicateEnvelope = QByteArrayLiteral("{\"alg\":\"Ed25519\",\"kid\":\"")
            + kid.toUtf8() + QByteArrayLiteral("\",\"\\u006bid\":\"") + kid.toUtf8()
            + QByteArrayLiteral("\",\"payload\":\"")
            + envObject.value("payload").toString().toLatin1()
            + QByteArrayLiteral("\",\"signature\":\"")
            + envObject.value("signature").toString().toLatin1() + QByteArrayLiteral("\"}");
        CHECK(!CatalogParser::verifyAndParse(duplicateEnvelope, keyring, catalog, error));
        CHECK(error.code == CatalogParseErrorCode::DuplicateJsonKey);

        const QByteArray duplicatePayload =
            QByteArrayLiteral("{\"schema_version\":2,\"\\u0073chema_version\":2}");
        CHECK(!CatalogParser::verifyAndParse(envelopeForPayload(duplicatePayload, kid, signer),
                                             keyring, catalog, error));
        CHECK(error.code == CatalogParseErrorCode::DuplicateJsonKey);

        QByteArray badUtf8 = QByteArrayLiteral("{\"x\":\"");
        badUtf8.append(char(0xff));
        badUtf8.append(QByteArrayLiteral("\"}"));
        CHECK(!CatalogParser::verifyAndParse(envelopeForPayload(badUtf8, kid, signer),
                                             keyring, catalog, error));
        CHECK(error.code == CatalogParseErrorCode::InvalidUtf8);

        CatalogParserLimits tiny;
        tiny.maximumJsonDepth = 2;
        CHECK(!CatalogParser::verifyAndParse(envelope, keyring, catalog, error, tiny));
        CHECK(error.code == CatalogParseErrorCode::JsonLimitsExceeded);
        tiny = {};
        tiny.maximumCandidatesPerLocation = 1;
        CHECK(!CatalogParser::verifyAndParse(envelope, keyring, catalog, error, tiny));
        CHECK(error.code == CatalogParseErrorCode::InvalidCandidate);
    }

    // Strict typed profile schema: no raw Xray sections, no zero generation, no kind drift,
    // no duplicate required capability, and no unsafe timestamp ordering.
    {
        auto expectPayloadFailure = [&](QJsonObject root, CatalogParseErrorCode code) {
            Catalog parsed;
            CatalogParseError local;
            const bool parsedOk = CatalogParser::parseVerifiedPayload(compact(root), kid,
                                                                       parsed, local);
            if (parsedOk || local.code != code) {
                fprintf(stderr, "unexpected parser result: ok=%d expected=%d actual=%d path=%s detail=%s\n",
                        parsedOk, int(code), int(local.code), local.path.toUtf8().constData(),
                        local.detail.toUtf8().constData());
            }
            CHECK(!parsedOk);
            CHECK(local.code == code);
        };

        QJsonObject root = validPayloadObject();
        root.remove(QStringLiteral("device_audience"));
        expectPayloadFailure(root, CatalogParseErrorCode::MissingField);
        root = validPayloadObject();
        root.remove(QStringLiteral("request_nonce"));
        expectPayloadFailure(root, CatalogParseErrorCode::MissingField);
        for (const QString &invalidOpaque : {
                 QStringLiteral("short"),
                 key32Url('n') + QLatin1Char('='),
                 key32Url('n').left(42),
                 key32Url('n').left(42) + QLatin1Char('B'),
             }) {
            root = validPayloadObject();
            root[QStringLiteral("request_nonce")] = invalidOpaque;
            expectPayloadFailure(root, CatalogParseErrorCode::InvalidField);
        }
        root = validPayloadObject();
        root[QStringLiteral("device_audience")] = key32Url('a').left(42);
        expectPayloadFailure(root, CatalogParseErrorCode::InvalidField);

        root = validPayloadObject();
        QJsonObject xray = candidateAt(root, 1);
        QJsonObject native = xray.value("native_profile").toObject();
        QJsonObject config = native.value("config").toObject();
        config["inbounds"] = QJsonArray{};
        native["config"] = config; xray["native_profile"] = native;
        replaceCandidate(root, 1, xray);
        expectPayloadFailure(root, CatalogParseErrorCode::InvalidNativeProfile);

        root = validPayloadObject();
        xray = candidateAt(root, 1); native = xray.value("native_profile").toObject();
        native["binding_generation"] = 0; xray["native_profile"] = native;
        replaceCandidate(root, 1, xray);
        expectPayloadFailure(root, CatalogParseErrorCode::InvalidField);

        root = validPayloadObject();
        xray = candidateAt(root, 1); native = xray.value("native_profile").toObject();
        native["profile_kind"] = "xray_future"; xray["native_profile"] = native;
        replaceCandidate(root, 1, xray);
        expectPayloadFailure(root, CatalogParseErrorCode::InvalidNativeProfile);

        root = validPayloadObject();
        xray = candidateAt(root, 1);
        xray["required_caps"] = QJsonArray{"xray.vless.reality.vision.tcp",
                                           "xray.vless.reality.vision.tcp"};
        replaceCandidate(root, 1, xray);
        expectPayloadFailure(root, CatalogParseErrorCode::InvalidField);

        root = validPayloadObject();
        root["refresh_after"] = QStringLiteral("2026-08-29T00:00:00Z");
        expectPayloadFailure(root, CatalogParseErrorCode::InvalidField);

        root = validPayloadObject();
        QJsonObject awg = candidateAt(root, 0); native = awg.value("native_profile").toObject();
        config = native.value("config").toObject();
        QJsonObject params = config.value("awg_params").toObject();
        params["FuturePassthrough"] = "1";
        config["awg_params"] = params; native["config"] = config; awg["native_profile"] = native;
        replaceCandidate(root, 0, awg);
        expectPayloadFailure(root, CatalogParseErrorCode::InvalidNativeProfile);

        root = validPayloadObject();
        root["future_root_field"] = true;
        expectPayloadFailure(root, CatalogParseErrorCode::InvalidField);

        root = validPayloadObject();
        xray = candidateAt(root, 1); xray["future_candidate_field"] = true;
        replaceCandidate(root, 1, xray);
        expectPayloadFailure(root, CatalogParseErrorCode::InvalidCandidate);

        root = validPayloadObject();
        xray = candidateAt(root, 1); native = xray.value("native_profile").toObject();
        native["config_generation"] = 0; xray["native_profile"] = native;
        replaceCandidate(root, 1, xray);
        expectPayloadFailure(root, CatalogParseErrorCode::InvalidField);

        root = validPayloadObject();
        xray = candidateAt(root, 1); xray["profile_kind"] = "future_profile";
        native = xray.value("native_profile").toObject();
        native["profile_kind"] = "future_profile"; xray["native_profile"] = native;
        replaceCandidate(root, 1, xray);
        expectPayloadFailure(root, CatalogParseErrorCode::InvalidNativeProfile);

        root = validPayloadObject();
        xray = candidateAt(root, 1); native = xray.value("native_profile").toObject();
        native["container_config_format"] = "amnezia_container_config_v2";
        xray["native_profile"] = native; replaceCandidate(root, 1, xray);
        expectPayloadFailure(root, CatalogParseErrorCode::InvalidNativeProfile);

        root = validPayloadObject();
        xray = candidateAt(root, 1); native = xray.value("native_profile").toObject();
        native["expires_at"] = "2026-08-28T11:59:59Z";
        xray["native_profile"] = native; replaceCandidate(root, 1, xray);
        expectPayloadFailure(root, CatalogParseErrorCode::InvalidNativeProfile);

        root = validPayloadObject();
        QJsonArray locations = root.value("locations").toArray();
        QJsonObject location = locations.first().toObject();
        location["country"] = "fi"; locations[0] = location; root["locations"] = locations;
        expectPayloadFailure(root, CatalogParseErrorCode::InvalidLocation);

        root = validPayloadObject();
        xray = candidateAt(root, 1);
        xray["health_observed_at"] = "2026-08-27T12:00:01Z";
        replaceCandidate(root, 1, xray);
        expectPayloadFailure(root, CatalogParseErrorCode::InvalidCandidate);

        root = validPayloadObject();
        xray = candidateAt(root, 1); native = xray.value("native_profile").toObject();
        config = native.value("config").toObject(); config["endpoint_host"] = "10.0.0.1";
        native["config"] = config; xray["native_profile"] = native;
        replaceCandidate(root, 1, xray);
        expectPayloadFailure(root, CatalogParseErrorCode::InvalidNativeProfile);

        root = validPayloadObject();
        xray = candidateAt(root, 1); native = xray.value("native_profile").toObject();
        config = native.value("config").toObject(); config["endpoint_host"] = "singlelabel";
        native["config"] = config; xray["native_profile"] = native;
        replaceCandidate(root, 1, xray);
        expectPayloadFailure(root, CatalogParseErrorCode::InvalidNativeProfile);

        for (const QString &nonCanonicalHost : {
                 QStringLiteral("Xray-Fi.Example.Net"),
                 QStringLiteral("2606:4700:4700:0:0:0:0:1111"),
                 QStringLiteral("2606:4700:4700::1111%3"),
             }) {
            root = validPayloadObject();
            xray = candidateAt(root, 1); native = xray.value("native_profile").toObject();
            config = native.value("config").toObject();
            config["endpoint_host"] = nonCanonicalHost;
            native["config"] = config; xray["native_profile"] = native;
            replaceCandidate(root, 1, xray);
            Catalog rejectedHostCatalog;
            CatalogParseError rejectedHostError;
            const bool acceptedHost = CatalogParser::parseVerifiedPayload(
                QJsonDocument(root).toJson(QJsonDocument::Compact), kid,
                rejectedHostCatalog, rejectedHostError);
            if (acceptedHost)
                fprintf(stderr, "noncanonical endpoint unexpectedly accepted: %s\n",
                        nonCanonicalHost.toUtf8().constData());
            CHECK(!acceptedHost);
            CHECK(rejectedHostError.code == CatalogParseErrorCode::InvalidNativeProfile);
        }

        for (const QString &canonicalPublicLiteral : {
                 QStringLiteral("8.8.8.8"),
                 QStringLiteral("2606:4700:4700::1111"),
             }) {
            root = validPayloadObject();
            xray = candidateAt(root, 1); native = xray.value("native_profile").toObject();
            config = native.value("config").toObject();
            config["endpoint_host"] = canonicalPublicLiteral;
            native["config"] = config; xray["native_profile"] = native;
            replaceCandidate(root, 1, xray);
            Catalog parsedLiteral;
            CatalogParseError literalError;
            CHECK(CatalogParser::parseVerifiedPayload(
                QJsonDocument(root).toJson(QJsonDocument::Compact), kid,
                parsedLiteral, literalError));
        }

        for (const QString &badShortId : {QStringLiteral("abc"),
                                          QStringLiteral("A1B2"),
                                          QStringLiteral("001122334455667788")}) {
            root = validPayloadObject();
            xray = candidateAt(root, 1); native = xray.value("native_profile").toObject();
            config = native.value("config").toObject(); config["short_id"] = badShortId;
            native["config"] = config; xray["native_profile"] = native;
            replaceCandidate(root, 1, xray);
            expectPayloadFailure(root, CatalogParseErrorCode::InvalidNativeProfile);
        }

        for (const QString &badUuid : {
                 QStringLiteral("123E4567-E89B-42D3-A456-426614174000"), // non-canonical case
                 QStringLiteral("00000000-0000-0000-0000-000000000000"), // nil/version 0
                 QStringLiteral("123e4567-e89b-02d3-a456-426614174000"), // version 0
                 QStringLiteral("123e4567-e89b-62d3-a456-426614174000"), // unsupported version 6
                 QStringLiteral("123e4567-e89b-42d3-7456-426614174000"), // non-RFC variant
             }) {
            root = validPayloadObject();
            xray = candidateAt(root, 1); native = xray.value("native_profile").toObject();
            config = native.value("config").toObject(); config["uuid"] = badUuid;
            native["config"] = config; xray["native_profile"] = native;
            replaceCandidate(root, 1, xray);
            expectPayloadFailure(root, CatalogParseErrorCode::InvalidNativeProfile);
        }

        root = validPayloadObject();
        xray = candidateAt(root, 1); native = xray.value("native_profile").toObject();
        config = native.value("config").toObject();
        config["server_name"] = QStringLiteral("Cdn-Fi.Example.Net");
        native["config"] = config; xray["native_profile"] = native;
        replaceCandidate(root, 1, xray);
        expectPayloadFailure(root, CatalogParseErrorCode::InvalidNativeProfile);

        const QStringList fingerprints = {
            QStringLiteral("chrome"), QStringLiteral("firefox"), QStringLiteral("safari"),
            QStringLiteral("ios"), QStringLiteral("android"), QStringLiteral("edge"),
            QStringLiteral("360"), QStringLiteral("qq"), QStringLiteral("random"),
            QStringLiteral("randomized"),
        };
        for (const QString &fingerprint : fingerprints) {
            root = validPayloadObject();
            xray = candidateAt(root, 1); native = xray.value("native_profile").toObject();
            config = native.value("config").toObject(); config["fingerprint"] = fingerprint;
            native["config"] = config; xray["native_profile"] = native;
            replaceCandidate(root, 1, xray);
            Catalog parsed;
            CatalogParseError local;
            CHECK(CatalogParser::parseVerifiedPayload(compact(root), kid, parsed, local));
        }
        root = validPayloadObject();
        xray = candidateAt(root, 1); native = xray.value("native_profile").toObject();
        config = native.value("config").toObject(); config["fingerprint"] = "randomizednoalpn";
        native["config"] = config; xray["native_profile"] = native;
        replaceCandidate(root, 1, xray);
        expectPayloadFailure(root, CatalogParseErrorCode::InvalidNativeProfile);

        root = validPayloadObject();
        QJsonObject awgBad = candidateAt(root, 0);
        native = awgBad.value("native_profile").toObject();
        config = native.value("config").toObject(); config["address"] = QJsonArray{"10.77.0.2/24"};
        native["config"] = config; awgBad["native_profile"] = native;
        replaceCandidate(root, 0, awgBad);
        expectPayloadFailure(root, CatalogParseErrorCode::InvalidNativeProfile);

        for (const QJsonArray &maliciousAddresses : {
                 QJsonArray{"0.0.0.0/32"}, QJsonArray{"127.0.0.1/32"},
                 QJsonArray{"224.0.0.1/32"}, QJsonArray{"169.254.1.1/32"},
                 QJsonArray{"::/128"}, QJsonArray{"::1/128"},
                 QJsonArray{"ff02::1/128"}, QJsonArray{"fe80::1/128"},
                 QJsonArray{"10.77.0.2/32", "10.77.0.3/32"},
                 QJsonArray{"fd00:77::2/128", "fd00:77::3/128"},
             }) {
            root = validPayloadObject(); awgBad = candidateAt(root, 0);
            native = awgBad.value("native_profile").toObject();
            config = native.value("config").toObject();
            config["address"] = maliciousAddresses;
            native["config"] = config; awgBad["native_profile"] = native;
            replaceCandidate(root, 0, awgBad);
            expectPayloadFailure(root, CatalogParseErrorCode::InvalidNativeProfile);
        }
        root = validPayloadObject(); awgBad = candidateAt(root, 0);
        native = awgBad.value("native_profile").toObject();
        config = native.value("config").toObject(); config["mtu"] = 1501;
        native["config"] = config; awgBad["native_profile"] = native;
        replaceCandidate(root, 0, awgBad);
        expectPayloadFailure(root, CatalogParseErrorCode::InvalidNativeProfile);

        for (const QJsonArray &maliciousRoutes : {
                 QJsonArray{"0.0.0.0/0"},
                 QJsonArray{"::/0", "0.0.0.0/0"},
                 QJsonArray{"10.0.0.0/8", "::/0"},
             }) {
            root = validPayloadObject(); awgBad = candidateAt(root, 0);
            native = awgBad.value("native_profile").toObject();
            config = native.value("config").toObject();
            config["allowed_ips"] = maliciousRoutes;
            native["config"] = config; awgBad["native_profile"] = native;
            replaceCandidate(root, 0, awgBad);
            expectPayloadFailure(root, CatalogParseErrorCode::InvalidNativeProfile);
        }
        for (const QString &maliciousDns : {
                 QStringLiteral("0.0.0.0"), QStringLiteral("127.0.0.1"),
                 QStringLiteral("10.0.0.1"), QStringLiteral("169.254.1.1"),
                 QStringLiteral("224.0.0.1"), QStringLiteral("192.0.2.1"),
                 QStringLiteral("::1"), QStringLiteral("fc00::1"),
                 QStringLiteral("fe80::1"), QStringLiteral("ff02::1"),
                 QStringLiteral("2001:db8::1"),
                 QStringLiteral("2606:4700:4700:0:0:0:0:1111"),
             }) {
            root = validPayloadObject(); awgBad = candidateAt(root, 0);
            native = awgBad.value("native_profile").toObject();
            config = native.value("config").toObject();
            config["dns"] = QJsonArray{maliciousDns};
            native["config"] = config; awgBad["native_profile"] = native;
            replaceCandidate(root, 0, awgBad);
            expectPayloadFailure(root, CatalogParseErrorCode::InvalidNativeProfile);
        }
        root = validPayloadObject(); awgBad = candidateAt(root, 0);
        native = awgBad.value("native_profile").toObject();
        config = native.value("config").toObject();
        config["address"] = QJsonArray{"10.77.0.2/32", "fd00:0077::2/128"};
        native["config"] = config; awgBad["native_profile"] = native;
        replaceCandidate(root, 0, awgBad);
        expectPayloadFailure(root, CatalogParseErrorCode::InvalidNativeProfile);

        root = validPayloadObject(); awgBad = candidateAt(root, 0);
        native = awgBad.value("native_profile").toObject(); config = native.value("config").toObject();
        params = config.value("awg_params").toObject(); params["RekeyTimeout"] = "9-3";
        config["awg_params"] = params; native["config"] = config; awgBad["native_profile"] = native;
        replaceCandidate(root, 0, awgBad);
        expectPayloadFailure(root, CatalogParseErrorCode::InvalidNativeProfile);

        root = validPayloadObject(); awgBad = candidateAt(root, 0);
        native = awgBad.value("native_profile").toObject(); config = native.value("config").toObject();
        params = config.value("awg_params").toObject(); params["I1"] = "<r 9999>";
        config["awg_params"] = params; native["config"] = config; awgBad["native_profile"] = native;
        replaceCandidate(root, 0, awgBad);
        expectPayloadFailure(root, CatalogParseErrorCode::InvalidNativeProfile);

        root = validPayloadObject(); awgBad = candidateAt(root, 0);
        native = awgBad.value("native_profile").toObject(); config = native.value("config").toObject();
        params = config.value("awg_params").toObject(); params.remove("S4");
        config["awg_params"] = params; native["config"] = config; awgBad["native_profile"] = native;
        replaceCandidate(root, 0, awgBad);
        expectPayloadFailure(root, CatalogParseErrorCode::InvalidNativeProfile);

        root = validPayloadObject();
        QJsonObject policy = root.value("policy").toObject(); policy["max_attempts"] = 6;
        root["policy"] = policy;
        expectPayloadFailure(root, CatalogParseErrorCode::InvalidPolicy);

        root = validPayloadObject();
        xray = candidateAt(root, 1); xray["required_caps"] = QJsonArray{"Xray.Bad"};
        replaceCandidate(root, 1, xray);
        expectPayloadFailure(root, CatalogParseErrorCode::InvalidCandidate);

        // Catalog, receipt and outcome all carry this value byte-for-byte.  Reject a catalog
        // that would only fail after the tunnel is started; 16 and 128 are inclusive.
        for (const int length : {16, 128}) {
            root = validPayloadObject();
            QJsonObject bounded = candidateAt(root, 0);
            QJsonObject verification = bounded.value("verification").toObject();
            verification["context"] = QString(length, QLatin1Char('a'));
            bounded["verification"] = verification;
            replaceCandidate(root, 0, bounded);
            Catalog parsed;
            CatalogParseError local;
            CHECK(CatalogParser::parseVerifiedPayload(compact(root), kid, parsed, local));
        }
        for (const QString &badContext : {
                 QString(15, QLatin1Char('a')),
                 QString(15, QLatin1Char('a')) + QLatin1Char('/'),
             }) {
            root = validPayloadObject();
            QJsonObject invalid = candidateAt(root, 0);
            QJsonObject verification = invalid.value("verification").toObject();
            verification["context"] = badContext;
            invalid["verification"] = verification;
            replaceCandidate(root, 0, invalid);
            expectPayloadFailure(root, CatalogParseErrorCode::InvalidCandidate);
        }
        root = validPayloadObject();
        {
            QJsonObject invalid = candidateAt(root, 0);
            QJsonObject verification = invalid.value("verification").toObject();
            verification["context"] = QString(129, QLatin1Char('a'));
            invalid["verification"] = verification;
            replaceCandidate(root, 0, invalid);
        }
        expectPayloadFailure(root, CatalogParseErrorCode::InvalidField);

        // city is explicitly optional in the canonical exclude-none payload.
        root = validPayloadObject();
        locations = root.value("locations").toArray();
        location = locations.first().toObject(); location.remove("city");
        locations[0] = location; root["locations"] = locations;
        Catalog withoutCity;
        CatalogParseError withoutCityError;
        CHECK(CatalogParser::parseVerifiedPayload(compact(root), kid,
                                                   withoutCity, withoutCityError));

        // Explicit evolution zone: old clients ignore bounded unknown non-critical metadata, while
        // an unknown critical extension fails closed and never enters a native profile.
        root = validPayloadObject();
        root[QStringLiteral("extensions")] = QJsonArray{QJsonObject{
            {QStringLiteral("id"), QStringLiteral("server.advisory")},
            {QStringLiteral("critical"), false},
            {QStringLiteral("required_cap"), QStringLiteral("catalog.advisory.v1")},
            {QStringLiteral("value"), QJsonObject{{QStringLiteral("message_key"),
                                                    QStringLiteral("notice.future")}}},
        }};
        Catalog forwardCompatible;
        CatalogParseError forwardCompatibleError;
        CHECK(CatalogParser::parseVerifiedPayload(
            compact(root), kid, forwardCompatible, forwardCompatibleError));
        root = validPayloadObject();
        root[QStringLiteral("extensions")] = QJsonArray{QJsonObject{
            {QStringLiteral("id"), QStringLiteral("routing.future")},
            {QStringLiteral("critical"), true},
            {QStringLiteral("value"), QJsonObject{}},
        }};
        expectPayloadFailure(root, CatalogParseErrorCode::UnsupportedCriticalExtension);
        root = validPayloadObject();
        root[QStringLiteral("extensions")] = QJsonArray{QJsonObject{
            {QStringLiteral("id"), QStringLiteral("server.advisory")},
            {QStringLiteral("critical"), false},
            {QStringLiteral("required_cap"), QJsonValue::Null},
            {QStringLiteral("value"), true},
        }};
        expectPayloadFailure(root, CatalogParseErrorCode::InvalidField);

        // The only known critical evolution extension is parsed into a typed, bounded receipt
        // authority. It is never forwarded to an AWG/Xray native profile.
        root = validPayloadObject();
        root[QStringLiteral("extensions")] = QJsonArray{receiptProviderExtension()};
        Catalog withReceiptProviders;
        CatalogParseError receiptProviderError;
        CHECK(CatalogParser::parseVerifiedPayload(compact(root), kid,
                                                   withReceiptProviders,
                                                   receiptProviderError));
        CHECK(withReceiptProviders.receiptProviderPolicy.has_value());
        CHECK(withReceiptProviders.receiptProviderPolicy->providers.size() == 2);
        CHECK(withReceiptProviders.receiptProviderPolicy->quorum == 2);
        CHECK(withReceiptProviders.receiptProviderPolicy->providers.first().receiptKid
              == QLatin1String("receipt-a"));

        root = validPayloadObject();
        QJsonObject grantBoundary = receiptProviderExtension();
        QJsonObject grantValue = grantBoundary.value("value").toObject();
        grantValue["verification_token_expires_at"] = "2026-08-27T12:15:00Z";
        grantBoundary["value"] = grantValue;
        root["extensions"] = QJsonArray{grantBoundary};
        Catalog exactGrantBoundary;
        CatalogParseError exactGrantBoundaryError;
        CHECK(CatalogParser::parseVerifiedPayload(
            compact(root), kid, exactGrantBoundary, exactGrantBoundaryError));

        root = validPayloadObject();
        grantBoundary = receiptProviderExtension();
        grantValue = grantBoundary.value("value").toObject();
        grantValue["verification_token_expires_at"] = "2026-08-27T12:15:01Z";
        grantBoundary["value"] = grantValue;
        root["extensions"] = QJsonArray{grantBoundary};
        expectPayloadFailure(root, CatalogParseErrorCode::InvalidField);

        for (const QString &mutation : {QStringLiteral("noncritical"),
                                        QStringLiteral("wrong_cap"),
                                        QStringLiteral("overlap_ip"),
                                        QStringLiteral("unsorted"),
                                        QStringLiteral("explicit_port"),
                                        QStringLiteral("token_expired"),
                                        QStringLiteral("token_shape")}) {
            root = validPayloadObject();
            QJsonObject extension = receiptProviderExtension();
            if (mutation == QLatin1String("noncritical")) extension["critical"] = false;
            if (mutation == QLatin1String("wrong_cap")) extension["required_cap"] = "other.cap";
            QJsonObject value = extension.value("value").toObject();
            QJsonArray providers = value.value("providers").toArray();
            if (mutation == QLatin1String("overlap_ip")) {
                QJsonObject second = providers.at(1).toObject();
                second["bootstrap_ips"] = QJsonArray{"1.1.1.1"};
                providers[1] = second;
            }
            if (mutation == QLatin1String("unsorted")) {
                const QJsonValue first = providers.at(0);
                providers[0] = providers.at(1); providers[1] = first;
            }
            if (mutation == QLatin1String("explicit_port")) {
                QJsonObject first = providers.at(0).toObject();
                first["base_url"] = QStringLiteral("https://verify-a.example:443");
                providers[0] = first;
            }
            value["providers"] = providers;
            if (mutation == QLatin1String("token_expired"))
                value["verification_token_expires_at"] = "2026-08-27T12:20:01Z";
            if (mutation == QLatin1String("token_shape"))
                value["verification_token"] = QStringLiteral("v1.a.b");
            extension["value"] = value;
            root["extensions"] = QJsonArray{extension};
            expectPayloadFailure(root, CatalogParseErrorCode::InvalidField);
        }

        root = validPayloadObject();
        locations = root.value("locations").toArray();
        QJsonObject duplicateLocation = locations.first().toObject();
        duplicateLocation["id"] = "de-fra";
        locations.append(duplicateLocation); root["locations"] = locations;
        expectPayloadFailure(root, CatalogParseErrorCode::InvalidCandidate);
    }

    CHECK(CatalogParser::verifyAndParse(envelope, keyring, catalog, error));

    // Anti-downgrade/freshness/LKG: exact replay is okay; revision collision and lower epochs fail.
    {
        CatalogTrustState empty;
        CatalogTrustVerdict accepted =
            evaluateCatalogTrust(catalog, empty, CatalogSource::Network, now);
        CHECK(accepted.accepted);
        CHECK(accepted.nextState.hasAcceptedV2);

        CatalogTrustVerdict replay = evaluateCatalogTrust(
            catalog, accepted.nextState, CatalogSource::Network, now);
        CHECK(replay.accepted);
        CatalogTrustState missingAudience = accepted.nextState;
        missingAudience.deviceAudience.clear();
        CHECK(evaluateCatalogTrust(catalog, missingAudience,
                                   CatalogSource::Network, now).error
              == CatalogTrustError::InvalidPersistedState);

        Catalog collision = catalog;
        collision.payloadSha256 = QByteArray(32, '\x7f');
        CHECK(evaluateCatalogTrust(collision, accepted.nextState,
                                   CatalogSource::Network, now).error
              == CatalogTrustError::RevisionCollision);
        Catalog downgrade = catalog;
        downgrade.catalogRevision--;
        CHECK(evaluateCatalogTrust(downgrade, accepted.nextState,
                                   CatalogSource::Network, now).error
              == CatalogTrustError::RevisionDowngrade);
        Catalog epoch = catalog;
        epoch.catalogRevision++;
        epoch.deviceRevocationEpoch--;
        CHECK(evaluateCatalogTrust(epoch, accepted.nextState,
                                   CatalogSource::Network, now).error
              == CatalogTrustError::RevocationEpochDowngrade);
        epoch = catalog; epoch.catalogRevision++; epoch.keyEpoch--;
        CHECK(evaluateCatalogTrust(epoch, accepted.nextState,
                                   CatalogSource::Network, now).error
              == CatalogTrustError::KeyEpochDowngrade);
        epoch = catalog; epoch.catalogRevision++; epoch.policyRevision--;
        CHECK(evaluateCatalogTrust(epoch, accepted.nextState,
                                   CatalogSource::Network, now).error
              == CatalogTrustError::PolicyRevisionDowngrade);
        Catalog generation = catalog;
        generation.catalogRevision++;
        generation.locations.first().candidates.first().nativeProfile.configGeneration--;
        CHECK(evaluateCatalogTrust(generation, accepted.nextState,
                                   CatalogSource::Network, now).error
              == CatalogTrustError::ConfigGenerationDowngrade);
        generation = catalog;
        generation.catalogRevision++;
        generation.locations.first().candidates.first().nativeProfile.bindingGeneration--;
        CHECK(evaluateCatalogTrust(generation, accepted.nextState,
                                   CatalogSource::Network, now).error
              == CatalogTrustError::BindingGenerationDowngrade);

        Catalog future = catalog;
        future.issuedAt = now.addSecs(3600);
        CHECK(evaluateCatalogTrust(future, empty, CatalogSource::Network, now).error
              == CatalogTrustError::FutureIssuedAt);
        const QDateTime offlineNow = catalog.expiresAt.addSecs(3600);
        CHECK(evaluateCatalogTrust(catalog, accepted.nextState,
                                   CatalogSource::Network, offlineNow).error
              == CatalogTrustError::Expired);
        CHECK(evaluateCatalogTrust(catalog, accepted.nextState,
                                   CatalogSource::LastKnownGood, offlineNow).accepted);
        CatalogTrustLimits exactLifetime;
        exactLifetime.allowedClockSkewS = 0;
        const QDateTime graceDeadline =
            catalog.expiresAt.addSecs(catalog.policy.offlineGraceS);
        const CatalogTrustVerdict insideGrace = evaluateCatalogTrust(
            catalog, accepted.nextState, CatalogSource::LastKnownGood,
            graceDeadline.addSecs(-1), exactLifetime);
        CHECK(insideGrace.accepted);
        CHECK(insideGrace.freshnessDeadline == graceDeadline);
        CHECK(evaluateCatalogTrust(catalog, accepted.nextState,
                                   CatalogSource::LastKnownGood, graceDeadline,
                                   exactLifetime).error == CatalogTrustError::Expired);
        CHECK(evaluateCatalogTrust(catalog, accepted.nextState,
                                   CatalogSource::Network, catalog.expiresAt,
                                   exactLifetime).error == CatalogTrustError::Expired);
        CHECK(evaluateCatalogTrust(catalog, empty,
                                   CatalogSource::LastKnownGood, offlineNow).error
              == CatalogTrustError::MissingLkgTrustState);
        Catalog staleEntitlement = catalog;
        staleEntitlement.entitlementExpiresAt = offlineNow.addSecs(-1);
        CHECK(evaluateCatalogTrust(staleEntitlement, accepted.nextState,
                                   CatalogSource::LastKnownGood, offlineNow).error
              == CatalogTrustError::EntitlementExpired);
        staleEntitlement.entitlementExpiresAt = graceDeadline;
        CHECK(evaluateCatalogTrust(staleEntitlement, accepted.nextState,
                                   CatalogSource::LastKnownGood, graceDeadline,
                                   exactLifetime).error
              == CatalogTrustError::EntitlementExpired);
        CHECK(evaluateCatalogTrust(catalog, empty, CatalogSource::Network, {}).error
              == CatalogTrustError::InvalidClock);
        Catalog noDigest = catalog;
        noDigest.payloadSha256.clear();
        CHECK(evaluateCatalogTrust(noDigest, empty, CatalogSource::Network, now).error
              == CatalogTrustError::InvalidPayloadDigest);
    }

    // Compatibility/acceptance filters unknown/missing client mechanisms; never silently uses them.
    {
        PlatformCapabilities caps = allCapabilities();
        const CompatibleCatalogView all = compatibleCandidates(catalog, caps, now);
        CHECK(all.candidates.size() == 2);
        caps.capabilities.remove(QStringLiteral("xray.vless.reality.vision.tcp"));
        const CompatibleCatalogView awgOnly = compatibleCandidates(catalog, caps, now);
        CHECK(awgOnly.candidates.size() == 1);
        CHECK(awgOnly.candidates.first().transport == TransportKind::Awg);
        caps = allCapabilities();
        caps.profileKinds.remove(QStringLiteral("awg31"));
        CHECK(compatibleCandidates(catalog, caps, now).candidates.size() == 1);

        CatalogCandidate inconsistent = catalog.locations.first().candidates.first();
        inconsistent.nativeProfile.profileKind = QStringLiteral("future_profile");
        CHECK(checkCandidateCompatibility(inconsistent, 2, allCapabilities(), now).error
              == CandidateCompatibilityError::ProfileKindMismatch);
        inconsistent = catalog.locations.first().candidates.first();
        inconsistent.nativeProfile.bindingGeneration = 0;
        CHECK(checkCandidateCompatibility(inconsistent, 2, allCapabilities(), now).error
              == CandidateCompatibilityError::GenerationInvalid);
        inconsistent = catalog.locations.first().candidates.first();
        inconsistent.nativeProfile.config = {};
        CHECK(checkCandidateCompatibility(inconsistent, 2, allCapabilities(), now).error
              == CandidateCompatibilityError::NativeConfigInvalid);
        inconsistent = catalog.locations.first().candidates.first();
        inconsistent.healthObservedAt = now.addSecs(301);
        CHECK(checkCandidateCompatibility(inconsistent, 2, allCapabilities(), now).error
              == CandidateCompatibilityError::HealthTimestampInvalid);

        const CatalogCandidate hintBase = catalog.locations.first().candidates.first();
        CatalogCandidate staleHint = hintBase;
        staleHint.serverHealth = 1.0;
        staleHint.capacityHeadroom = 1.0;
        staleHint.healthObservedAt = now.addSecs(-301);
        CatalogCandidate neutralHint = hintBase;
        neutralHint.serverHealth = 0.5;
        neutralHint.capacityHeadroom = 0.5;
        neutralHint.healthObservedAt = now;
        CHECK(candidateScore(staleHint, {}, 7, now)
              == candidateScore(neutralHint, {}, 7, now));
        CatalogCandidate futureHint = staleHint;
        futureHint.healthObservedAt = now.addSecs(1);
        CHECK(candidateScore(futureHint, {}, 7, now)
              == candidateScore(neutralHint, {}, 7, now));
        CatalogCandidate staleZero = hintBase;
        staleZero.serverHealth = 0.0;
        staleZero.capacityHeadroom = 0.0;
        staleZero.healthObservedAt = now.addSecs(-301);
        CandidateSelectionRequest hintRequest;
        hintRequest.nowUtc = now;
        CHECK(rankCandidates({staleZero}, {}, hintRequest).size() == 1);
        staleZero.healthObservedAt = now;
        CHECK(rankCandidates({staleZero}, {}, hintRequest).size() == 1);
        CHECK(rankCandidates({staleZero}, {}, hintRequest).first().score
              > rankCandidates({neutralHint}, {}, hintRequest).first().score);
        CatalogCandidate provisionedAtCapacity = hintBase;
        provisionedAtCapacity.serverHealth = 1.0;
        provisionedAtCapacity.capacityHeadroom = 0.0;
        provisionedAtCapacity.healthObservedAt = now;
        CHECK(rankCandidates({provisionedAtCapacity}, {}, hintRequest).size() == 1);

        CandidateHistory oldGeneration;
        oldGeneration.configGeneration = hintBase.nativeProfile.configGeneration - 1;
        oldGeneration.bindingGeneration = hintBase.nativeProfile.bindingGeneration;
        oldGeneration.verifiedSuccessEwma = 1.0;
        oldGeneration.survival5mEwma = 1.0;
        oldGeneration.cooldownUntil = now.addSecs(3600);
        QHash<QString, CandidateHistory> rotatedHistory;
        rotatedHistory.insert(hintBase.profileId, oldGeneration);
        const QList<RankedCandidate> rotated = rankCandidates(
            {hintBase}, rotatedHistory, hintRequest);
        CHECK(rotated.size() == 1); // old cooldown cannot poison rotated credentials
        CHECK(rotated.first().score == candidateScore(hintBase, {}, 0, now));
        oldGeneration.configGeneration = hintBase.nativeProfile.configGeneration;
        rotatedHistory[hintBase.profileId] = oldGeneration;
        CHECK(rankCandidates({hintBase}, rotatedHistory, hintRequest).isEmpty());

        const CatalogAcceptanceResult accepted = acceptCatalogEnvelope(
            envelope, keyring, allCapabilities(), {}, CatalogSource::Network, now,
            {key32Url('n')});
        CHECK(accepted.authoritative && accepted.connectable
              && accepted.candidates.size() == 2);
        const CatalogAcceptanceResult replayedResponse = acceptCatalogEnvelope(
            envelope, keyring, allCapabilities(), {}, CatalogSource::Network, now,
            {key32Url('o')});
        CHECK(!replayedResponse.authoritative && !replayedResponse.connectable);
        CHECK(replayedResponse.error == CatalogAcceptanceError::ResponseBinding);
        QJsonObject otherAudiencePayload = validPayloadObject();
        otherAudiencePayload[QStringLiteral("device_audience")] = key32Url('b');
        const CatalogAcceptanceResult otherAudience = acceptCatalogEnvelope(
            envelopeForPayload(compact(otherAudiencePayload), kid, signer), keyring,
            allCapabilities(), accepted.nextTrustState, CatalogSource::Network, now,
            {key32Url('n')});
        CHECK(!otherAudience.authoritative && !otherAudience.connectable);
        CHECK(otherAudience.trustError == CatalogTrustError::AudienceMismatch);
        CatalogTrustLimits exactLifetime;
        exactLifetime.allowedClockSkewS = 0;
        const QDateTime graceDeadline =
            catalog.expiresAt.addSecs(catalog.policy.offlineGraceS);
        const CatalogAcceptanceResult acceptedLkg = acceptCatalogEnvelope(
            envelope, keyring, allCapabilities(), accepted.nextTrustState,
            CatalogSource::LastKnownGood, graceDeadline.addSecs(-1), {}, {}, exactLifetime);
        CHECK(acceptedLkg.authoritative && acceptedLkg.connectable
              && acceptedLkg.candidates.size() == 2);
        CHECK(acceptedLkg.runtimeAuthority.source == CatalogSource::LastKnownGood);
        CHECK(acceptedLkg.runtimeAuthority.freshnessDeadline == graceDeadline);
        const CatalogAcceptanceResult lkgWithOnlineNonce = acceptCatalogEnvelope(
            envelope, keyring, allCapabilities(), accepted.nextTrustState,
            CatalogSource::LastKnownGood, graceDeadline.addSecs(-1), {key32Url('n')}, {},
            exactLifetime);
        CHECK(lkgWithOnlineNonce.error == CatalogAcceptanceError::ResponseBinding);
        const CatalogAcceptanceResult expiredLkg = acceptCatalogEnvelope(
            envelope, keyring, allCapabilities(), accepted.nextTrustState,
            CatalogSource::LastKnownGood, graceDeadline, {}, {}, exactLifetime);
        CHECK(!expiredLkg.authoritative && !expiredLkg.connectable
              && expiredLkg.trustError == CatalogTrustError::Expired);
        PlatformCapabilities none = allCapabilities();
        none.transports.clear();
        const CatalogAcceptanceResult rejected = acceptCatalogEnvelope(
            envelope, keyring, none, {}, CatalogSource::Network, now,
            {key32Url('n')});
        CHECK(rejected.authoritative && !rejected.connectable);
        CHECK(rejected.error == CatalogAcceptanceError::NoCompatibleCandidate);
        CHECK(rejected.nextTrustState.hasAcceptedV2);
        CatalogPathInputs noCompatiblePath;
        noCompatiblePath.legacyV1SubscriptionValid = true;
        noCompatiblePath.trust = rejected.nextTrustState;
        CHECK(chooseCatalogPath(noCompatiblePath) == CatalogPath::None);
        CatalogPathInputs signedUpgrade;
        signedUpgrade.legacyV1SubscriptionValid = true;
        signedUpgrade.signedUpgradeRequired = true;
        CHECK(chooseCatalogPath(signedUpgrade) == CatalogPath::None);
        CatalogPathInputs signedBlocked;
        signedBlocked.legacyV1SubscriptionValid = true;
        signedBlocked.signedAccountBlocked = true;
        CHECK(chooseCatalogPath(signedBlocked) == CatalogPath::None);
    }

    // Immutable selection/fallback: same location + other transport/domain first, forced modes
    // are respected, cooldown/failure domains are hard filters, deterministic seed is stable.
    {
        QList<CatalogCandidate> candidates = compatibleCandidates(
            catalog, allCapabilities(), now).candidates;
        CatalogCandidate awg2 = candidates.at(0);
        awg2.profileId = QStringLiteral("fi-awg-02");
        awg2.failureDomain = QStringLiteral("provider-c/asn-c/host-c");
        candidates.append(awg2);
        CatalogCandidate de = candidates.at(1);
        de.profileId = QStringLiteral("de-xray-01");
        de.locationId = QStringLiteral("de-fra");
        de.failureDomain = QStringLiteral("provider-d/asn-d/host-d");
        candidates.append(de);

        CandidateSelectionRequest request;
        request.mode = ConnectionMode::Auto;
        request.previousProfileId = QStringLiteral("fi-awg-01");
        request.previousLocationId = QStringLiteral("fi-hel");
        request.previousTransport = TransportKind::Awg;
        request.previousFailureDomain = QStringLiteral("provider-a/asn-a/host-a");
        request.failedProfileIds.insert(request.previousProfileId);
        request.nowUtc = now;
        request.deterministicSeed = 42;
        const QList<RankedCandidate> ranked = rankCandidates(candidates, {}, request);
        CHECK(!ranked.isEmpty());
        CHECK(ranked.first().candidate.profileId == QLatin1String("fi-xray-01"));
        CHECK(ranked.first().fallbackTier == 0);
        CHECK(ranked.at(1).candidate.profileId == QLatin1String("fi-awg-02"));
        CHECK(ranked.last().candidate.locationId == QLatin1String("de-fra"));
        CHECK(rankCandidates(candidates, {}, request).first().score == ranked.first().score);

        request.mode = ConnectionMode::ForceAwg;
        CHECK(rankCandidates(candidates, {}, request).first().candidate.transport
              == TransportKind::Awg);
        request.mode = ConnectionMode::Auto;
        request.fixedLocationId = QStringLiteral("fi-hel");
        for (const RankedCandidate &item : rankCandidates(candidates, {}, request))
            CHECK(item.candidate.locationId == QLatin1String("fi-hel"));
        request.failedFailureDomains.insert(QStringLiteral("provider-b/asn-b/host-b"));
        for (const RankedCandidate &item : rankCandidates(candidates, {}, request))
            CHECK(item.candidate.failureDomain != QLatin1String("provider-b/asn-b/host-b"));
        CHECK(keepHealthyCurrent(300.0, 250.0, 30, 300));
        CHECK(!keepHealthyCurrent(400.0, 250.0, 600, 300));
    }

    // v1 fallback is bootstrap-only; an accepted v2 epoch can never be downgraded to legacy AWG.
    {
        CatalogPathInputs input;
        input.legacyV1SubscriptionValid = true;
        CHECK(chooseCatalogPath(input) == CatalogPath::LegacyV1Awg);
        input.trust.hasAcceptedV2 = true;
        CHECK(chooseCatalogPath(input) == CatalogPath::None);
        input.lkgV2Accepted = true;
        CHECK(chooseCatalogPath(input) == CatalogPath::LastKnownGoodV2);
        input.freshV2Accepted = true;
        CHECK(chooseCatalogPath(input) == CatalogPath::FreshV2);
    }

    // Registry is fail-closed: no Xray sanitizer, duplicate/mismatched adapters, or wrong compiled
    // native container can never reach VpnConnection dispatch.
    {
        const CatalogCandidate awg = catalog.locations.first().candidates.at(0);
        const CatalogCandidate xray = catalog.locations.first().candidates.at(1);
        TransportAdapterRegistry registry;
        CompiledNativeProfile compiled;
        QString adapterError;
        CHECK(!registry.compile(xray, compiled, adapterError));

        FakeAdapter badDeclaration(TransportKind::Awg, amnezia::DockerContainer::Xray,
                                   amnezia::DockerContainer::Awg);
        CHECK(!registry.add(&badDeclaration, adapterError));
        FakeAdapter awgAdapter(TransportKind::Awg, amnezia::DockerContainer::Awg,
                               amnezia::DockerContainer::Awg);
        CHECK(registry.add(&awgAdapter, adapterError));
        CHECK(registry.compile(awg, compiled, adapterError));
        CHECK(compiled.container == amnezia::DockerContainer::Awg);
        CHECK(!registry.add(&awgAdapter, adapterError));

        FakeAdapter badXrayCompile(TransportKind::Xray, amnezia::DockerContainer::Xray,
                                   amnezia::DockerContainer::Awg);
        CHECK(registry.add(&badXrayCompile, adapterError));
        CHECK(!registry.compile(xray, compiled, adapterError));

        TransportAdapterRegistry xrayRegistry;
        FakeAdapter xrayAdapter(TransportKind::Xray, amnezia::DockerContainer::Xray,
                                amnezia::DockerContainer::Xray);
        CHECK(xrayRegistry.add(&xrayAdapter, adapterError));
        CHECK(xrayRegistry.compile(xray, compiled, adapterError));
        CHECK(compiled.container == amnezia::DockerContainer::Xray);
        CHECK(xray.nativeProfile.containerType == QLatin1String("amnezia-xray"));
    }

    if (g_failed) {
        fprintf(stderr, "FAIL: %d/%d catalog v2 checks failed\n", g_failed, g_total);
        return 1;
    }
    printf("OK: %d catalog v2 parser/resolve/trust/compat/selector/fallback/adapter checks\n",
           g_total);
    return 0;
}
