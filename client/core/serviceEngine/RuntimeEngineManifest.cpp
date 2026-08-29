#include "RuntimeEngineManifest.h"

#include <QJsonArray>
#include <QRegularExpression>
#include <QSet>

#include <algorithm>
#include <cmath>
#include <limits>
#include <utility>

namespace avpn {
namespace {

bool exactKeys(const QJsonObject &object, const QSet<QString> &keys)
{
    if (object.size() != keys.size()) return false;
    for (auto it = object.constBegin(); it != object.constEnd(); ++it)
        if (!keys.contains(it.key())) return false;
    return true;
}

bool safeVersion(const QJsonValue &value)
{
    return value.isString() && validCatalogVersionFact(value.toString());
}

bool safeCommit(const QJsonValue &value)
{
    static const QRegularExpression commit(QStringLiteral("^(?:[0-9a-f]{40}|[0-9a-f]{64})$"));
    return value.isString() && commit.match(value.toString()).hasMatch();
}

bool exactJsonInteger(const QJsonValue &value, qint64 minimum, qint64 maximum,
                      qint64 &out)
{
    if (!value.isDouble()) return false;
    const double number = value.toDouble();
    if (!std::isfinite(number) || number < double(minimum) || number > double(maximum)
        || std::floor(number) != number) return false;
    out = qint64(number);
    return true;
}

struct EngineEvidence {
    QString protocol;
    QString adapter;
    QString adapterVersion;
    QString declaredCoreVersion;
    QString sourceCommit;
    QString abi;
    QStringList capabilities;
    bool runtimeVersionProbed = false;
    QString runtimeCoreVersion;
};

bool parseEngine(const QJsonObject &object, EngineEvidence &out, QString &error,
                 RuntimeEngineManifestLimits limits)
{
    const QSet<QString> keys{
        QStringLiteral("protocol"), QStringLiteral("adapter"),
        QStringLiteral("adapterVersion"), QStringLiteral("declaredCoreVersion"),
        QStringLiteral("sourceCommit"), QStringLiteral("abi"),
        QStringLiteral("capabilities"), QStringLiteral("runtimeCoreVersion"),
        QStringLiteral("runtimeVersionProbed"), QStringLiteral("versionEvidence")};
    if (!exactKeys(object, keys) || !safeVersion(object.value(QStringLiteral("protocol")))
        || !safeVersion(object.value(QStringLiteral("adapter")))
        || !safeVersion(object.value(QStringLiteral("adapterVersion")))
        || !safeVersion(object.value(QStringLiteral("declaredCoreVersion")))
        || !safeCommit(object.value(QStringLiteral("sourceCommit")))
        || !safeVersion(object.value(QStringLiteral("abi")))
        || !object.value(QStringLiteral("capabilities")).isArray()
        || !object.value(QStringLiteral("runtimeVersionProbed")).isBool()
        || !object.value(QStringLiteral("versionEvidence")).isString()) {
        error = QStringLiteral("engine manifest entry shape is invalid");
        return false;
    }
    const bool probed = object.value(QStringLiteral("runtimeVersionProbed")).toBool();
    const QJsonValue runtime = object.value(QStringLiteral("runtimeCoreVersion"));
    const QString evidence = object.value(QStringLiteral("versionEvidence")).toString();
    if ((probed && (!safeVersion(runtime) || evidence != QLatin1String("runtime_api")))
        || (!probed && (!runtime.isNull()
                        || evidence != QLatin1String("compile_time_lock_only")))) {
        error = QStringLiteral("engine runtime evidence is internally inconsistent");
        return false;
    }
    const QJsonArray caps = object.value(QStringLiteral("capabilities")).toArray();
    if (caps.isEmpty() || caps.size() > qBound(1, limits.maximumCapabilitiesPerEngine, 64)) {
        error = QStringLiteral("engine capability list is outside bounds");
        return false;
    }
    static const QRegularExpression cap(QStringLiteral("^[a-z][a-z0-9_.-]{2,95}$"));
    QSet<QString> unique;
    for (const QJsonValue &value : caps) {
        if (!value.isString() || !cap.match(value.toString()).hasMatch()
            || unique.contains(value.toString())) {
            error = QStringLiteral("engine capability is invalid or duplicate");
            return false;
        }
        unique.insert(value.toString());
        out.capabilities.append(value.toString());
    }
    out.protocol = object.value(QStringLiteral("protocol")).toString();
    out.adapter = object.value(QStringLiteral("adapter")).toString();
    out.adapterVersion = object.value(QStringLiteral("adapterVersion")).toString();
    out.declaredCoreVersion = object.value(QStringLiteral("declaredCoreVersion")).toString();
    out.sourceCommit = object.value(QStringLiteral("sourceCommit")).toString();
    out.abi = object.value(QStringLiteral("abi")).toString();
    out.runtimeVersionProbed = probed;
    out.runtimeCoreVersion = probed ? runtime.toString() : QString{};
    return true;
}

bool approvedEvidence(const EngineEvidence &engine, const RuntimeEngineLockEntry &locked)
{
    if (engine.protocol != locked.protocol || engine.adapter != locked.adapter
        || engine.adapterVersion != locked.adapterVersion
        || engine.declaredCoreVersion != locked.declaredCoreVersion
        || engine.sourceCommit != locked.sourceCommit || engine.abi != locked.abi
        || (locked.runtimeProbeRequired && !engine.runtimeVersionProbed)
        || (!locked.runtimeProbeRequired && engine.runtimeVersionProbed)
        || (engine.runtimeVersionProbed
            && engine.runtimeCoreVersion != engine.declaredCoreVersion)) return false;
    for (const QString &capability : locked.requiredCapabilities)
        if (!engine.capabilities.contains(capability)) return false;
    if (engine.protocol == QLatin1String("awg")) {
        return engine.capabilities.contains(QStringLiteral("awg.random_trailers"))
               && engine.capabilities.contains(QStringLiteral("awg.disable_cookies"));
    }
    if (engine.protocol == QLatin1String("xray")) {
        return engine.capabilities.contains(QStringLiteral("xray.vless.reality.vision.tcp"));
    }
    return false;
}

} // namespace

bool applyRuntimeEngineManifest(const QJsonObject &manifest, const CatalogAppFact &expectedApp,
                                const RuntimeEngineLock &compiledLock,
                                CatalogResolveRequest &request, QString &error,
                                RuntimeEngineManifestLimits limits)
{
    error.clear();
    const QSet<QString> rootKeys{QStringLiteral("type"), QStringLiteral("schema"),
                                 QStringLiteral("app"), QStringLiteral("engines")};
    const QSet<QString> appKeys{QStringLiteral("version"), QStringLiteral("build")};
    qint64 manifestSchema = 0;
    if (!exactKeys(manifest, rootKeys)
        || manifest.value(QStringLiteral("type")).toString()
               != QLatin1String("engine_manifest_v1")
        || !exactJsonInteger(manifest.value(QStringLiteral("schema")), 1, 1,
                             manifestSchema)
        || !manifest.value(QStringLiteral("app")).isObject()
        || !manifest.value(QStringLiteral("engines")).isArray()) {
        error = QStringLiteral("runtime engine manifest root is unavailable/invalid");
        return false;
    }
    if (compiledLock.manifestSchema != 1 || compiledLock.platform != expectedApp.platform
        || compiledLock.engines.isEmpty()
        || compiledLock.engines.size() != manifest.value(QStringLiteral("engines")).toArray().size()) {
        error = QStringLiteral("generated engine lock unavailable/mismatched");
        return false;
    }
    const QJsonObject app = manifest.value(QStringLiteral("app")).toObject();
    qint64 appBuild = 0;
    if (!exactKeys(app, appKeys) || !app.value(QStringLiteral("version")).isString()
        || !exactJsonInteger(app.value(QStringLiteral("build")), 1,
                             std::numeric_limits<int>::max(), appBuild)
        || app.value(QStringLiteral("version")).toString() != expectedApp.version
        || appBuild != expectedApp.build
        || expectedApp.platform == CatalogAppPlatform::Unknown || expectedApp.arch.isEmpty()) {
        error = QStringLiteral("installed app facts do not match runtime engine manifest");
        return false;
    }
    const QJsonArray engines = manifest.value(QStringLiteral("engines")).toArray();
    if (engines.isEmpty() || engines.size() > qBound(1, limits.maximumEngines, 16)) {
        error = QStringLiteral("runtime engine manifest inventory is outside bounds");
        return false;
    }
    CatalogResolveRequest resolved = request;
    resolved.app = expectedApp;
    resolved.adapters = {};
    resolved.engines = {};
    resolved.capabilities.clear();
    QSet<QString> protocols;
    QSet<QString> capabilities;
    for (const QJsonValue &value : engines) {
        if (!value.isObject()) {
            error = QStringLiteral("runtime engine manifest entry is not an object");
            return false;
        }
        EngineEvidence engine;
        if (!parseEngine(value.toObject(), engine, error, limits)
            || protocols.contains(engine.protocol)) {
            if (error.isEmpty()) error = QStringLiteral("runtime engine evidence is unsupported");
            return false;
        }
        const auto locked = std::find_if(
            compiledLock.engines.constBegin(), compiledLock.engines.constEnd(),
            [&](const RuntimeEngineLockEntry &entry) { return entry.protocol == engine.protocol; });
        if (locked == compiledLock.engines.constEnd() || !approvedEvidence(engine, *locked)) {
            error = QStringLiteral("runtime engine evidence differs from generated lock");
            return false;
        }
        protocols.insert(engine.protocol);
        for (const QString &cap : engine.capabilities) {
            if (!capabilities.contains(cap)) {
                capabilities.insert(cap);
                resolved.capabilities.append(cap);
            }
        }
        const CatalogEngineFact fact{engine.adapter, engine.adapterVersion};
        if (engine.protocol == QLatin1String("awg")) resolved.engines.awg = fact;
        else if (engine.protocol == QLatin1String("xray")) resolved.engines.xray = fact;
    }
    // Adapter value is the proven manifest/service ABI schema revision. Apple callers remain
    // fail-closed until their controller exposes this same pre-connect manifest.
    const QString adapterSchema = QString::number(manifestSchema);
    if (expectedApp.platform == CatalogAppPlatform::Android)
        resolved.adapters.androidVpnService = adapterSchema;
    else if (expectedApp.platform == CatalogAppPlatform::Ios)
        resolved.adapters.appleNetworkExtension = adapterSchema;
    else {
#if defined(MACOS_NE)
        resolved.adapters.macosNetworkExtension = adapterSchema;
#else
        resolved.adapters.macosDaemonIpc = adapterSchema;
#endif
    }
    // The network client, not the package inventory, owns the per-attempt CSPRNG nonce. Validate
    // every other resolve field here with a local canonical sentinel while preserving the caller's
    // empty nonce; CatalogResolveClient replaces it immediately before serialization.
    CatalogResolveRequest validation = resolved;
    if (validation.requestNonce.isEmpty()) {
        validation.requestNonce = QString::fromLatin1(
            QByteArray(32, '\0').toBase64(QByteArray::Base64UrlEncoding
                                           | QByteArray::OmitTrailingEquals));
    }
    QJsonObject ignored;
    if (!buildCatalogResolveRequest(validation, ignored, error)) return false;
    request = std::move(resolved);
    return true;
}

} // namespace avpn
