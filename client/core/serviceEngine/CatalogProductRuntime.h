// Tribe catalog v2 — production composition root. Owns every v2 authority/runtime component.
#pragma once

#include "CatalogCoordinator.h"

#include <QObject>

#include <functional>
#include <memory>

class QNetworkAccessManager;
class SecureAppSettingsRepository;
class VpnConnection;

namespace avpn {

// The only production inventory implementation. It consumes VpnConnection's platform-generated
// closed manifest and byte-matches it against Conan-derived compile definitions before producing
// resolve facts. It never reconstructs versions from settings, QML, or server input.
class ProductRuntimeEngineInventory final : public ICatalogRuntimeInventory {
public:
    ProductRuntimeEngineInventory(VpnConnection *connection,
                                  std::function<ClientKeys()> awgKeysProvider);
    bool snapshot(CatalogResolveRequest &request,
                  PlatformCapabilities &capabilities,
                  QVariantList &redactedEngineVersions,
                  QString &error) const override;

private:
    VpnConnection *m_connection = nullptr;
    std::function<ClientKeys()> m_awgKeysProvider;
};

// Created once by AvpnEngineQml/CoreController and parented to the application controller. A bare
// facade is never treated as readiness: this root installs the coordinator actions, restores the
// encrypted anti-downgrade record, and independently gates native availability on exact per-
// transport runtime identity + session-guard evidence.
class CatalogProductRuntime final : public QObject {
public:
    CatalogProductRuntime(VpnConnection *connection,
                          SecureAppSettingsRepository *settings,
                          QNetworkAccessManager *network,
                          CatalogConnectionFacade *facade,
                          QUrl apiBaseUrl,
                          std::function<QByteArray()> bearerTokenProvider,
                          std::function<ClientKeys()> awgKeysProvider,
                          QObject *parent = nullptr);
    ~CatalogProductRuntime() override;

    bool initialize(QString &error);
    bool productionReady() const;
    // True only when the compiled platform bridge/root/secure store can eventually own a v2
    // connection. A late engine manifest or first-run enrollment may delay readiness, but this
    // positive gate lets the legacy button queue the intent without ever starting a v1 tunnel.
    bool canInterceptLegacyConnect() const;
    // True from the first accepted catalog-v2 Connect intent until an explicit pre-authority
    // cancel/logout.  AvpnEngineQml uses this to fence every legacy tunnel mutation while
    // enrollment, a late platform manifest, or signed discovery is still in flight.
    bool ownsConnectionIntent() const;
    bool requestConnectWhenReady(QString &error);
    void cancelPendingConnect();
    bool pendingConnect() const;
    CatalogCoordinator *coordinator() const;
    bool setApiBaseUrl(const QUrl &apiBaseUrl, QString &error);
    void refreshLocalKeys();
    void applicationResumed();
    void setLegacyNativeOwnershipBlocked(bool blocked);
    void networkPathChanged(CatalogNetworkClass networkClass,
                            const QString &volatilePathToken = {});
    void networkReachabilityChanged(bool online);
    void clearAfterLogout();

    // Compile-time offline roots only. Empty means this build was not provisioned for catalog v2;
    // there is intentionally no fixture/server/settings fallback.
    static QHash<QString, QString> compiledOfflineRootKeys();

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace avpn
