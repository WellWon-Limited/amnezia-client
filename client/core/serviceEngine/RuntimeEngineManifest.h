// Tribe catalog v2 — strict conversion of platform-owned engine evidence into resolve facts.
#pragma once

#include "CatalogResolve.h"

#include <QJsonObject>

namespace avpn {

class IRuntimeEngineManifestSource {
public:
    virtual ~IRuntimeEngineManifestSource() = default;
    // Empty means the platform has not proved its pre-connect inventory. Callers must fail closed;
    // they must never reconstruct versions from QML/settings or duplicate package pins here.
    virtual QJsonObject currentEngineManifest() const = 0;
};

struct RuntimeEngineManifestLimits {
    int maximumEngines = 8;
    int maximumCapabilitiesPerEngine = 32;
};

struct RuntimeEngineLockEntry {
    QString protocol;
    QString adapter;
    QString adapterVersion;
    QString declaredCoreVersion;
    QString sourceCommit;
    QString abi;
    QStringList requiredCapabilities;
    bool runtimeProbeRequired = true;
};

struct RuntimeEngineLock {
    int manifestSchema = 1;
    CatalogAppPlatform platform = CatalogAppPlatform::Unknown;
    QList<RuntimeEngineLockEntry> engines;
};

// expectedApp is obtained from the installed package/application runtime, not user input. Its
// platform/version/build must byte-match the platform manifest. arch is injected from QSysInfo.
bool applyRuntimeEngineManifest(const QJsonObject &manifest,
                                const CatalogAppFact &expectedApp,
                                const RuntimeEngineLock &compiledLock,
                                CatalogResolveRequest &request,
                                QString &error,
                                RuntimeEngineManifestLimits limits = {});

} // namespace avpn
