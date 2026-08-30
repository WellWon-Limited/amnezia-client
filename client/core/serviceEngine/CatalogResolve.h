// Tribe serviceEngine v2 — strict client inventory for POST /v2/catalog/resolve.
#pragma once

#include "dto/Catalog.h"

#include <QByteArray>
#include <QJsonArray>
#include <QJsonObject>
#include <QRegularExpression>
#include <QSet>
#include <QString>
#include <QStringList>

#include <optional>

namespace avpn {

enum class CatalogAppPlatform {
    Unknown = 0,
    Ios,
    Android,
    Macos,
};

inline QString catalogPlatformName(CatalogAppPlatform platform)
{
    switch (platform) {
    case CatalogAppPlatform::Ios: return QStringLiteral("ios");
    case CatalogAppPlatform::Android: return QStringLiteral("android");
    case CatalogAppPlatform::Macos: return QStringLiteral("macos");
    case CatalogAppPlatform::Unknown: break;
    }
    return {};
}

struct CatalogAppFact {
    CatalogAppPlatform platform = CatalogAppPlatform::Unknown;
    QString version;
    int build = 0;
    QString arch;
};

struct CatalogAdapterFacts {
    std::optional<QString> appleNetworkExtension;
    // macOS App Store / Network Extension is a distinct build/runtime from iOS NE and the
    // privileged desktop daemon. A macOS build must advertise exactly one of these two facts.
    std::optional<QString> macosNetworkExtension;
    std::optional<QString> macosDaemonIpc;
    std::optional<QString> androidVpnService;
};

struct CatalogEngineFact {
    QString implementation;
    QString version;
};

struct CatalogEngineFacts {
    std::optional<CatalogEngineFact> awg;
    std::optional<CatalogEngineFact> xray;
};

struct CatalogDeviceKeyFacts {
    // Public key only. The private AWG identity never enters HTTP JSON.
    std::optional<QString> awgPublicKey;
};

struct CatalogResolveRequest {
    int catalogSchemaMax = 2;
    // CSPRNG-owned by the network coordinator: canonical unpadded base64url of exactly 32 bytes.
    QString requestNonce;
    QStringList nativeProfileFormats{QStringLiteral("tribe_native_profile_v1")};
    CatalogAppFact app;
    CatalogAdapterFacts adapters;
    CatalogEngineFacts engines;
    CatalogDeviceKeyFacts deviceKeys;
    QStringList capabilities;
    // Omitted for the initial discovery request so this binary can still talk to an N-1 strict
    // backend. Once a signed directory proves support, subsequent requests may scope credentials.
    std::optional<CatalogResolveSelection> selection;
};

inline QString catalogResolveTransportName(ConnectionMode mode)
{
    switch (mode) {
    case ConnectionMode::Auto: return QStringLiteral("auto");
    case ConnectionMode::ForceAwg: return QStringLiteral("awg");
    case ConnectionMode::ForceXray: return QStringLiteral("xray");
    }
    return {};
}

inline bool canonicalCatalogOpaque32(const QString &value)
{
    const QByteArray encoded = value.toLatin1();
    if (encoded.size() != 43 || QString::fromLatin1(encoded) != value)
        return false;
    for (const char ch : encoded) {
        if (!((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')
              || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_'))
            return false;
    }
    const auto decoded = QByteArray::fromBase64Encoding(
        encoded, QByteArray::Base64UrlEncoding | QByteArray::AbortOnBase64DecodingErrors);
    return decoded.decodingStatus == QByteArray::Base64DecodingStatus::Ok
           && decoded.decoded.size() == 32
           && decoded.decoded.toBase64(QByteArray::Base64UrlEncoding
                                       | QByteArray::OmitTrailingEquals) == encoded;
}

inline bool validCatalogVersionFact(const QString &value)
{
    static const QRegularExpression version(
        QStringLiteral("^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$"));
    return version.match(value).hasMatch();
}

inline bool canonicalCatalogWgPublicKey(const QString &value)
{
    const QByteArray encoded = value.toLatin1();
    if (QString::fromLatin1(encoded) != value)
        return false;
    const auto decoded = QByteArray::fromBase64Encoding(
        encoded, QByteArray::Base64Encoding | QByteArray::AbortOnBase64DecodingErrors);
    return decoded.decodingStatus == QByteArray::Base64DecodingStatus::Ok
           && decoded.decoded.size() == 32 && decoded.decoded.toBase64() == encoded;
}

inline bool buildCatalogResolveRequest(const CatalogResolveRequest &request,
                                       QJsonObject &body, QString &error)
{
    body = {};
    error.clear();
    const auto reject = [&](const QString &detail) {
        error = detail;
        return false;
    };
    if (request.catalogSchemaMax != 2)
        return reject(QStringLiteral("this client must advertise exact catalog_schema_max=2"));
    if (!canonicalCatalogOpaque32(request.requestNonce))
        return reject(QStringLiteral("request nonce must be canonical 32-byte base64url"));
    if (request.nativeProfileFormats.isEmpty() || request.nativeProfileFormats.size() > 8)
        return reject(QStringLiteral("invalid native profile format list"));
    QSet<QString> uniqueFormats;
    for (const QString &format : request.nativeProfileFormats) {
        if (format != QLatin1String("tribe_native_profile_v1")
            || uniqueFormats.contains(format))
            return reject(QStringLiteral("unsupported or duplicate native profile format"));
        uniqueFormats.insert(format);
    }
    if (request.app.platform == CatalogAppPlatform::Unknown
        || !validCatalogVersionFact(request.app.version)
        || request.app.build < 1 || request.app.arch.isEmpty() || request.app.arch.size() > 32) {
        return reject(QStringLiteral("invalid app runtime facts"));
    }
    static const QRegularExpression arch(QStringLiteral("^[A-Za-z0-9_-]+$"));
    if (!arch.match(request.app.arch).hasMatch())
        return reject(QStringLiteral("invalid app architecture"));

    const auto validOptionalVersion = [](const std::optional<QString> &value) {
        return !value.has_value() || validCatalogVersionFact(*value);
    };
    if (!validOptionalVersion(request.adapters.appleNetworkExtension)
        || !validOptionalVersion(request.adapters.macosNetworkExtension)
        || !validOptionalVersion(request.adapters.macosDaemonIpc)
        || !validOptionalVersion(request.adapters.androidVpnService))
        return reject(QStringLiteral("invalid platform adapter version"));
    const int adapterCount = int(request.adapters.appleNetworkExtension.has_value())
                             + int(request.adapters.macosNetworkExtension.has_value())
                             + int(request.adapters.macosDaemonIpc.has_value())
                             + int(request.adapters.androidVpnService.has_value());
    const bool relevantAdapterPresent = adapterCount == 1
        && ((request.app.platform == CatalogAppPlatform::Ios
             && request.adapters.appleNetworkExtension.has_value())
            || (request.app.platform == CatalogAppPlatform::Android
                && request.adapters.androidVpnService.has_value())
            || (request.app.platform == CatalogAppPlatform::Macos
                && (request.adapters.macosNetworkExtension.has_value()
                    != request.adapters.macosDaemonIpc.has_value())));
    if (!relevantAdapterPresent)
        return reject(QStringLiteral("runtime adapter for app platform is missing"));

    const auto validEngine = [](const std::optional<CatalogEngineFact> &engine) {
        return !engine.has_value()
               || (validCatalogVersionFact(engine->implementation)
                   && validCatalogVersionFact(engine->version));
    };
    if ((!request.engines.awg.has_value() && !request.engines.xray.has_value())
        || !validEngine(request.engines.awg) || !validEngine(request.engines.xray))
        return reject(QStringLiteral("invalid or empty embedded engine inventory"));

    if (request.engines.awg.has_value()) {
        if (!request.deviceKeys.awgPublicKey.has_value()
            || !canonicalCatalogWgPublicKey(*request.deviceKeys.awgPublicKey))
            return reject(QStringLiteral("AWG engine requires a valid public key"));
    } else if (request.deviceKeys.awgPublicKey.has_value()) {
        return reject(QStringLiteral("AWG key facts supplied without an AWG engine"));
    }

    if (request.capabilities.isEmpty() || request.capabilities.size() > 64)
        return reject(QStringLiteral("invalid capability list size"));
    static const QRegularExpression capability(
        QStringLiteral("^[a-z][a-z0-9_.-]{2,95}$"));
    QSet<QString> uniqueCapabilities;
    for (const QString &item : request.capabilities) {
        if (!capability.match(item).hasMatch() || uniqueCapabilities.contains(item))
            return reject(QStringLiteral("invalid or duplicate capability"));
        uniqueCapabilities.insert(item);
    }
    if (request.engines.awg.has_value()
        && (!uniqueCapabilities.contains(QStringLiteral("awg.random_trailers"))
            || !uniqueCapabilities.contains(QStringLiteral("awg.disable_cookies"))))
        return reject(QStringLiteral("AWG 3.1 engine is missing exact capabilities"));
    if (request.engines.xray.has_value()
        && !uniqueCapabilities.contains(QStringLiteral("xray.vless.reality.vision.tcp")))
        return reject(QStringLiteral("Xray engine is missing exact capability"));
    // Every v2 transport runs inside the platform-owned route/TUN guard.  Advertising an engine
    // without proving that the outer guard is the sole network-settings owner would let a valid
    // signed profile reach an adapter whose inner core can overwrite protected routes.
    if (!uniqueCapabilities.contains(QStringLiteral("tribe.guarded_settings_owner")))
        return reject(QStringLiteral("runtime adapter is missing guarded settings ownership"));

    if (request.selection.has_value()) {
        static const QRegularExpression locationId(
            QStringLiteral("^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$"));
        if (!uniqueCapabilities.contains(QStringLiteral("catalog.location_directory_v1")))
            return reject(QStringLiteral("scoped selection requires location directory support"));
        if ((!request.selection->locationId.isEmpty()
             && !locationId.match(request.selection->locationId).hasMatch())
            || (request.selection->transport == ConnectionMode::ForceAwg
                && !request.engines.awg.has_value())
            || (request.selection->transport == ConnectionMode::ForceXray
                && !request.engines.xray.has_value()))
            return reject(QStringLiteral("invalid scoped catalog selection"));
    }

    QJsonArray nativeFormats;
    for (const QString &format : request.nativeProfileFormats)
        nativeFormats.append(format);
    QJsonArray capabilities;
    for (const QString &item : request.capabilities)
        capabilities.append(item);

    QJsonObject adapters;
    if (request.adapters.appleNetworkExtension)
        adapters.insert(QStringLiteral("apple_network_extension"),
                        *request.adapters.appleNetworkExtension);
    if (request.adapters.macosNetworkExtension)
        adapters.insert(QStringLiteral("macos_network_extension"),
                        *request.adapters.macosNetworkExtension);
    if (request.adapters.macosDaemonIpc)
        adapters.insert(QStringLiteral("macos_daemon_ipc"), *request.adapters.macosDaemonIpc);
    if (request.adapters.androidVpnService)
        adapters.insert(QStringLiteral("android_vpn_service"),
                        *request.adapters.androidVpnService);

    const auto engineJson = [](const CatalogEngineFact &engine) {
        return QJsonObject{{QStringLiteral("implementation"), engine.implementation},
                           {QStringLiteral("version"), engine.version}};
    };
    QJsonObject engines;
    if (request.engines.awg)
        engines.insert(QStringLiteral("awg"), engineJson(*request.engines.awg));
    if (request.engines.xray)
        engines.insert(QStringLiteral("xray"), engineJson(*request.engines.xray));

    QJsonObject deviceKeys;
    if (request.deviceKeys.awgPublicKey)
        deviceKeys.insert(QStringLiteral("awg_public_key"), *request.deviceKeys.awgPublicKey);

    body = {
        {QStringLiteral("catalog_schema_max"), request.catalogSchemaMax},
        {QStringLiteral("request_nonce"), request.requestNonce},
        {QStringLiteral("native_profile_formats"), nativeFormats},
        {QStringLiteral("app"), QJsonObject{
             {QStringLiteral("platform"), catalogPlatformName(request.app.platform)},
             {QStringLiteral("version"), request.app.version},
             {QStringLiteral("build"), request.app.build},
             {QStringLiteral("arch"), request.app.arch},
         }},
        {QStringLiteral("adapters"), adapters},
        {QStringLiteral("engines"), engines},
        {QStringLiteral("device_keys"), deviceKeys},
        {QStringLiteral("capabilities"), capabilities},
    };
    if (request.selection.has_value()) {
        QJsonObject selection{
            {QStringLiteral("transport"),
             catalogResolveTransportName(request.selection->transport)},
        };
        if (!request.selection->locationId.isEmpty())
            selection.insert(QStringLiteral("location_id"), request.selection->locationId);
        body.insert(QStringLiteral("selection"), selection);
    }
    return true;
}

} // namespace avpn
