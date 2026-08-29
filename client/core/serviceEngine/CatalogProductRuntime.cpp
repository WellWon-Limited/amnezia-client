#include "CatalogProductRuntime.h"

#include "CatalogKeysetClient.h"
#include "CatalogOutcomeClient.h"
#include "CatalogResolveClient.h"
#include "CatalogSecureStore.h"
#include "ConnectionReducer.h"
#include "PostTunnelReceiptVerifier.h"
#include "RuntimeEngineManifest.h"
#include "VpnConnectionTransportAdapter.h"

#if defined(Q_OS_ANDROID)
#include "AndroidCatalogSecureStorage.h"
#include <QCoreApplication>
#include <QJniEnvironment>
#include <QJniObject>
#elif defined(Q_OS_IOS) || defined(Q_OS_MACOS)
#include "AppleCatalogSecureStorage.h"
#endif

#include "core/repositories/secureAppSettingsRepository.h"
#include "version.h"
#include "vpnConnection.h"

#include <QDir>
#include <QFileInfo>
#include <QNetworkAccessManager>
#include <QSettings>
#include <QStandardPaths>
#include <QSysInfo>
#include <QVariantMap>

#include <utility>
#include <optional>

namespace avpn {
namespace {

CatalogAppPlatform productPlatform()
{
#if defined(Q_OS_ANDROID)
    return CatalogAppPlatform::Android;
#elif defined(Q_OS_IOS)
    return CatalogAppPlatform::Ios;
#elif defined(Q_OS_MACOS)
    return CatalogAppPlatform::Macos;
#else
    return CatalogAppPlatform::Unknown;
#endif
}

QString productArchitecture(QString &error)
{
    error.clear();
    const QString architecture = QSysInfo::currentCpuArchitecture().toLower();
#if defined(Q_OS_ANDROID)
    // QSysInfo reports Qt CPU names, not Android package ABI directory names.
    const bool supported = architecture == QLatin1String("arm64")
        || architecture == QLatin1String("arm")
        || architecture == QLatin1String("x86")
        || architecture == QLatin1String("x86_64");
#elif defined(Q_OS_IOS)
    // The receipted App Store/device artifact is arm64-only. Simulator builds
    // are useful compile proofs but may not resolve a production catalog.
    const bool supported = architecture == QLatin1String("arm64");
#elif defined(Q_OS_MACOS) && defined(MACOS_NE)
    const bool supported = architecture == QLatin1String("arm64")
        || architecture == QLatin1String("x86_64");
#elif defined(Q_OS_MACOS)
    // The shipping daemon flavor is deliberately thin arm64.
    const bool supported = architecture == QLatin1String("arm64");
#else
    const bool supported = false;
#endif
    if (!supported) {
        error = QStringLiteral("installed application architecture is outside the release contract");
        return {};
    }
    return architecture;
}

bool compiledEngineLock(RuntimeEngineLock &lock, QString &error)
{
    lock = {};
    lock.manifestSchema = 1;
    lock.platform = productPlatform();
    error.clear();
#if defined(Q_OS_ANDROID) \
    && defined(TRIBE_ANDROID_AWG_ADAPTER_VERSION) \
    && defined(TRIBE_ANDROID_AWG_SOURCE_COMMIT) \
    && defined(TRIBE_ANDROID_AWG_CORE_VERSION) \
    && defined(TRIBE_ANDROID_AWG_ABI) \
    && defined(TRIBE_ANDROID_XRAY_ADAPTER_VERSION) \
    && defined(TRIBE_ANDROID_XRAY_SOURCE_COMMIT) \
    && defined(TRIBE_ANDROID_XRAY_CORE_VERSION) \
    && defined(TRIBE_ANDROID_XRAY_ABI)
    lock.engines = {
        {QStringLiteral("awg"), QStringLiteral("awg-android"),
         QStringLiteral(TRIBE_ANDROID_AWG_ADAPTER_VERSION),
         QStringLiteral(TRIBE_ANDROID_AWG_CORE_VERSION),
         QStringLiteral(TRIBE_ANDROID_AWG_SOURCE_COMMIT),
         QStringLiteral(TRIBE_ANDROID_AWG_ABI),
         {QStringLiteral("awg.random_trailers"),
          QStringLiteral("awg.disable_cookies"),
          QStringLiteral("tribe.guarded_settings_owner")}, true},
        {QStringLiteral("xray"), QStringLiteral("amnezia-libxray"),
         QStringLiteral(TRIBE_ANDROID_XRAY_ADAPTER_VERSION),
         QStringLiteral(TRIBE_ANDROID_XRAY_CORE_VERSION),
         QStringLiteral(TRIBE_ANDROID_XRAY_SOURCE_COMMIT),
         QStringLiteral(TRIBE_ANDROID_XRAY_ABI),
         {QStringLiteral("xray.vless.reality.vision.tcp"),
          QStringLiteral("xray.socket_protection_slot"),
          QStringLiteral("tribe.guarded_settings_owner")}, true},
    };
    return true;
#elif (defined(Q_OS_IOS) || defined(MACOS_NE)) \
    && defined(TRIBE_APPLE_AWG_ADAPTER_VERSION) \
    && defined(TRIBE_APPLE_AWG_SOURCE_COMMIT) \
    && defined(TRIBE_APPLE_AWG_CORE_VERSION) \
    && defined(TRIBE_APPLE_XRAY_ADAPTER_VERSION) \
    && defined(TRIBE_APPLE_XRAY_SOURCE_COMMIT) \
    && defined(TRIBE_APPLE_XRAY_CORE_VERSION) \
    && defined(TRIBE_APPLE_XRAY_SOCKET_ABI)
    lock.engines = {
        {QStringLiteral("awg"), QStringLiteral("awg-apple"),
         QStringLiteral(TRIBE_APPLE_AWG_ADAPTER_VERSION),
         QStringLiteral(TRIBE_APPLE_AWG_CORE_VERSION),
         QStringLiteral(TRIBE_APPLE_AWG_SOURCE_COMMIT),
         QStringLiteral("awg-apple-c-uapi-v3.1"),
         {QStringLiteral("awg.random_trailers"),
          QStringLiteral("awg.disable_cookies"),
          QStringLiteral("tribe.guarded_settings_owner")}, false},
        {QStringLiteral("xray"), QStringLiteral("amnezia-libxray"),
         QStringLiteral(TRIBE_APPLE_XRAY_ADAPTER_VERSION),
         QStringLiteral(TRIBE_APPLE_XRAY_CORE_VERSION),
         QStringLiteral(TRIBE_APPLE_XRAY_SOURCE_COMMIT),
         QStringLiteral(TRIBE_APPLE_XRAY_SOCKET_ABI),
         {QStringLiteral("xray.vless.reality.vision.tcp"),
          QStringLiteral("xray.socket_protection_result"),
          QStringLiteral("tribe.guarded_settings_owner")}, false},
    };
    return true;
#elif defined(Q_OS_MACOS) && !defined(MACOS_NE) \
    && defined(TRIBE_MACOS_AWG_ADAPTER_VERSION) \
    && defined(TRIBE_MACOS_AWG_CORE_VERSION) \
    && defined(TRIBE_MACOS_AWG_SOURCE_COMMIT) \
    && defined(TRIBE_MACOS_AWG_ABI) \
    && defined(TRIBE_MACOS_XRAY_ADAPTER_VERSION) \
    && defined(TRIBE_MACOS_XRAY_CORE_VERSION) \
    && defined(TRIBE_MACOS_XRAY_SOURCE_COMMIT) \
    && defined(TRIBE_MACOS_XRAY_ABI)
    lock.engines = {
        {QStringLiteral("awg"), QStringLiteral("awg-go"),
         QStringLiteral(TRIBE_MACOS_AWG_ADAPTER_VERSION),
         QStringLiteral(TRIBE_MACOS_AWG_CORE_VERSION),
         QStringLiteral(TRIBE_MACOS_AWG_SOURCE_COMMIT),
         QStringLiteral(TRIBE_MACOS_AWG_ABI),
         {QStringLiteral("awg.random_trailers"),
          QStringLiteral("awg.disable_cookies"),
          QStringLiteral("tribe.guarded_settings_owner")}, false},
        {QStringLiteral("xray"), QStringLiteral("amnezia-xray-bindings"),
         QStringLiteral(TRIBE_MACOS_XRAY_ADAPTER_VERSION),
         QStringLiteral(TRIBE_MACOS_XRAY_CORE_VERSION),
         QStringLiteral(TRIBE_MACOS_XRAY_SOURCE_COMMIT),
         QStringLiteral(TRIBE_MACOS_XRAY_ABI),
         {QStringLiteral("xray.vless.reality.vision.tcp"),
          QStringLiteral("tribe.guarded_settings_owner")}, false},
    };
    return true;
#else
    error = QStringLiteral("generated product engine lock is unavailable for this build flavor");
    return false;
#endif
}

QString catalogStorePath()
{
#if defined(Q_OS_ANDROID)
    QJniEnvironment environment;
    const QJniObject context = QNativeInterface::QAndroidApplication::context();
    if (!context.isValid()) return {};
    const QJniObject directory = context.callObjectMethod(
        "getNoBackupFilesDir", "()Ljava/io/File;");
    const QJniObject path = directory.callObjectMethod(
        "getAbsolutePath", "()Ljava/lang/String;");
    if (environment.checkAndClearExceptions() || !path.isValid()) return {};
    return QDir(path.toString()).filePath(QStringLiteral("tribe/catalog-v2/catalog.lkg"));
#else
    const QString requested = QDir::cleanPath(
        QStandardPaths::writableLocation(QStandardPaths::AppDataLocation));
    if (requested.isEmpty() || !QFileInfo(requested).isAbsolute()) return {};
    // Apple exposes the sandbox below `/var`, which is itself a root-owned OS symlink to
    // `/private/var`. CatalogSecureStore intentionally rejects every symlink component, so resolve
    // only this trusted platform-supplied existing prefix before appending our fixed descendant.
    // User/settings/server input never participates in this path.
    QString existing = requested;
    while (!QFileInfo(existing).exists()) {
        const QString parent = QFileInfo(existing).absolutePath();
        if (parent == existing || parent.isEmpty()) return {};
        existing = parent;
    }
    const QString canonicalExisting = QFileInfo(existing).canonicalFilePath();
    if (canonicalExisting.isEmpty() || !QFileInfo(canonicalExisting).isDir()) return {};
    const QString suffix = QDir(existing).relativeFilePath(requested);
    if (suffix.startsWith(QLatin1String(".."))) return {};
    const QString canonicalRoot = suffix == QLatin1String(".")
        ? canonicalExisting : QDir(canonicalExisting).filePath(suffix);
    return QDir(canonicalRoot).filePath(QStringLiteral("catalog-v2/catalog.lkg"));
#endif
}

NativeProfileCompileOptions compileOptions(SecureAppSettingsRepository *settings,
                                           const ClientKeys &keys)
{
    NativeProfileCompileOptions options;
    options.awgKeys = keys;
    options.configVersion = APP_BUILD;
    if (settings) {
        const QString primary = settings->primaryDns();
        const QString secondary = settings->secondaryDns();
        if (!primary.isEmpty() && !secondary.isEmpty())
            options.dnsServers = {primary, secondary};
    }
    return options;
}

} // namespace

ProductRuntimeEngineInventory::ProductRuntimeEngineInventory(
    VpnConnection *connection, std::function<ClientKeys()> awgKeysProvider)
    : m_connection(connection), m_awgKeysProvider(std::move(awgKeysProvider))
{}

bool ProductRuntimeEngineInventory::snapshot(
    CatalogResolveRequest &request, PlatformCapabilities &capabilities,
    QVariantList &redactedEngineVersions, QString &error) const
{
    request = {};
    capabilities = {};
    redactedEngineVersions.clear();
    error.clear();
    if (!m_connection) {
        error = QStringLiteral("native connection manifest source unavailable");
        return false;
    }
    RuntimeEngineLock lock;
    if (!compiledEngineLock(lock, error)) return false;
    CatalogAppFact app;
    app.platform = productPlatform();
    app.version = QStringLiteral(APP_VERSION);
    app.build = APP_BUILD;
    app.arch = productArchitecture(error);
    if (app.arch.isEmpty()) return false;
    const ClientKeys keys = m_awgKeysProvider ? m_awgKeysProvider() : ClientKeys{};
    if (!canonicalCatalogWgPublicKey(keys.publicKey) || keys.privateKey.isEmpty()) {
        error = QStringLiteral("device AWG installation keypair is unavailable/noncanonical");
        return false;
    }
    // applyRuntimeEngineManifest performs the final strict request validation after installing
    // engine facts. Therefore the device-owned AWG facts must already be present in its input;
    // adding them afterwards would make every honest dual-engine manifest fail deterministically.
    request.deviceKeys.awgPublicKey = keys.publicKey;
    const QJsonObject manifest = m_connection->nativeEngineManifest();
    if (manifest.isEmpty()
        || !applyRuntimeEngineManifest(manifest, app, lock, request, error))
        return false;

    const bool awgReady = m_connection->nativeRuntimeIdentitySupported(Proto::Awg)
                          && m_connection->nativeSessionGuardSupported(Proto::Awg);
    const bool xrayReady = m_connection->nativeRuntimeIdentitySupported(Proto::Xray)
                           && m_connection->nativeSessionGuardSupported(Proto::Xray);
    if (!awgReady) {
        request.engines.awg.reset();
        request.deviceKeys = {};
        request.capabilities.removeAll(QStringLiteral("awg.random_trailers"));
        request.capabilities.removeAll(QStringLiteral("awg.disable_cookies"));
    }
    if (!xrayReady) {
        request.engines.xray.reset();
        request.capabilities.removeAll(QStringLiteral("xray.vless.reality.vision.tcp"));
    }
    CatalogResolveRequest validation = request;
    validation.requestNonce = QString::fromLatin1(
        QByteArray(32, '\0').toBase64(QByteArray::Base64UrlEncoding
                                       | QByteArray::OmitTrailingEquals));
    QJsonObject validatedRequest;
    if (!buildCatalogResolveRequest(validation, validatedRequest, error)) return false;

    capabilities.catalogSchemaMax = 2;
    capabilities.nativeProfileFormats = {QStringLiteral("tribe_native_profile_v1")};
    capabilities.containerConfigFormats = {QStringLiteral("amnezia_container_config_v1")};
    capabilities.capabilities = QSet<QString>(request.capabilities.cbegin(),
                                               request.capabilities.cend());
    if (request.engines.awg) {
        capabilities.transports.insert(TransportKind::Awg);
        capabilities.profileKinds.insert(QStringLiteral("awg31"));
        redactedEngineVersions.append(QVariantMap{
            {QStringLiteral("transport"), QStringLiteral("awg")},
            {QStringLiteral("version"), request.engines.awg->version},
            {QStringLiteral("adapter"), request.engines.awg->implementation}});
    }
    if (request.engines.xray) {
        capabilities.transports.insert(TransportKind::Xray);
        capabilities.profileKinds.insert(QStringLiteral("xray_vless_reality_vision_tcp"));
        redactedEngineVersions.append(QVariantMap{
            {QStringLiteral("transport"), QStringLiteral("xray")},
            {QStringLiteral("version"), request.engines.xray->version},
            {QStringLiteral("adapter"), request.engines.xray->implementation}});
    }
    // The resolver can honestly operate in Auto with one proved bundled transport.  Per-location
    // dual availability remains visible to the selector/facade, but an unavailable platform bridge
    // for one engine must not erase the other audited engine from the resolve request.
    return !capabilities.transports.isEmpty();
}

class CatalogProductRuntime::Impl {
public:
    Impl(CatalogProductRuntime *owner, VpnConnection *connection,
         SecureAppSettingsRepository *settings, QNetworkAccessManager *network,
         CatalogConnectionFacade *facade, QUrl apiBaseUrl,
         std::function<QByteArray()> bearerTokenProvider,
         std::function<ClientKeys()> awgKeysProvider)
        : connection(connection), settings(settings), network(network), facade(facade),
          bearerTokenProvider(std::move(bearerTokenProvider)),
          awgKeysProvider(std::move(awgKeysProvider))
    {
        inventory = std::make_unique<ProductRuntimeEngineInventory>(
            connection, this->awgKeysProvider);
        clockSource = std::make_unique<SystemCatalogClockSource>();
        clock = std::make_unique<CatalogTrustedClock>(clockSource.get());
        keysetClient = std::make_unique<CatalogKeysetClient>(network, owner);
        resolveClient = std::make_unique<CatalogResolveClient>(network, owner);
        outcomeClient = std::make_unique<CatalogOutcomeClient>(network, owner);

#if defined(Q_OS_ANDROID)
        keyProvider = std::make_unique<AndroidCatalogSecureKeyProvider>();
#elif defined(Q_OS_IOS) || defined(Q_OS_MACOS)
        keyProvider = std::make_unique<AppleCatalogSecureKeyProvider>(
            QStringLiteral("org.avpn.tribe.catalog-v2.metadata"));
        fileProtection = std::make_unique<AppleCatalogFileProtection>();
#endif
        if (keyProvider) {
            secureStore = std::make_unique<CatalogSecureStore>(
                catalogStorePath(), keyProvider.get(), fileProtection.get());
        }
        verifier = std::make_unique<PostTunnelReceiptVerifier>(clock.get(), owner);
        adapters = std::make_unique<BundledNativeTransportAdapters>(
            connection, compileOptions(settings, currentKeys()), settings, owner, clock.get());
        guard = std::make_unique<VpnConnectionSessionGuard>(connection, owner);
        reducer = std::make_unique<ConnectionReducer>(&registry, verifier.get(), guard.get(),
                                                      clock.get());
        // QCoreApplication organization/application names are established before this product
        // root is created. Reuse the same non-secret preferences backend as the rest of the app.
        userIntentSettings = std::make_unique<QSettings>();

        const bool awgReady = connection
            && connection->nativeRuntimeIdentitySupported(Proto::Awg)
            && connection->nativeSessionGuardSupported(Proto::Awg);
        const bool xrayReady = connection
            && connection->nativeRuntimeIdentitySupported(Proto::Xray)
            && connection->nativeSessionGuardSupported(Proto::Xray);
        bool registryReady = false;
        QString registryError;
        if (awgReady)
            registryReady = adapters->registerForMode(registry, ConnectionMode::ForceAwg,
                                                       registryError);
        if (xrayReady) {
            QString xrayError;
            const bool xrayRegistered = adapters->registerForMode(
                registry, ConnectionMode::ForceXray, xrayError);
            registryReady = registryReady || xrayRegistered;
            if (!xrayRegistered && registryError.isEmpty()) registryError = xrayError;
        }

        CatalogCoordinatorConfig config;
        config.apiBaseUrl = std::move(apiBaseUrl);
        config.bundledRootPublicKeysHex = CatalogProductRuntime::compiledOfflineRootKeys();
        config.bearerTokenProvider = this->bearerTokenProvider;
        // Auto remains useful with one proved transport. Dual availability is preferred and is
        // exposed per location, but absence of one platform bridge must not disable the other.
        config.platformGuardAndRuntimeReady = registryReady;
        config.durableAntiDowngradeRequired = true;
        config.userIntentSettings = userIntentSettings.get();
        coordinator = std::make_unique<CatalogCoordinator>(
            std::move(config), inventory.get(), keysetClient.get(), resolveClient.get(),
            secureStore.get(), clock.get(), verifier.get(), adapters.get(), reducer.get(),
            facade, owner);
        coordinator->setOutcomeClient(outcomeClient.get());
        if (facade) {
            QObject::connect(
                facade, &CatalogConnectionFacade::v2AuthorityChanged,
                owner, [this]() {
                    if (!this->facade) return;
                    if (this->facade->v2Authoritative()) onlineDiscoveryEnabled = true;
                });
            QObject::connect(
                facade, &CatalogConnectionFacade::secureLogoutCompleted,
                owner, [this]() {
                    // This dedicated signal is emitted only after exact inner/outer teardown and
                    // successful cryptographic store clear. It also handles clean-install logout,
                    // where v2Authority was never true but a queued discovery intent may exist.
                    pendingUserConnect = false;
                    ownsUserConnectionIntent = false;
                    onlineDiscoveryEnabled = false;
                    pendingPathClass.reset();
                    pendingPathToken.clear();
                });
        }
        canQueueFirstConnect = registryReady && secureStore
            && !CatalogProductRuntime::compiledOfflineRootKeys().isEmpty();
        if (connection) {
            QObject::connect(
                connection, &VpnConnection::nativeSessionGuardRecoveryRequired,
                owner, [this](const QJsonObject &event) {
                    if (!coordinator) return;
                    const bool resolvable =
                        coordinator->nativeSessionGuardRecoveryRequired(event);
                    if (resolvable && !recoveryResolutionDispatched && this->connection
                        && this->connection->requestNativeSessionGuardRecoveryResolution(
                            event, QStringLiteral("stop"))) {
                        recoveryResolutionDispatched = true;
                    }
                }, Qt::QueuedConnection);
            QObject::connect(
                connection, &VpnConnection::nativeSessionGuardRecoveryResolved,
                owner, [this](const QJsonObject &receipt) {
                    if (coordinator
                        && coordinator->nativeSessionGuardRecoveryResolved(receipt))
                        recoveryResolutionDispatched = false;
                }, Qt::QueuedConnection);

            // iOS can discover the surviving NE before this composition root connects signals.
            // Consume the controller's level-triggered latch immediately; an empty detail still
            // blocks all starts and waits for the later strict status signal.
            if (connection->nativeSessionGuardRecoveryPending()) {
                const QJsonObject event = connection->nativeSessionGuardRecoveryEvent();
                const bool resolvable =
                    coordinator->nativeSessionGuardRecoveryRequired(event);
                if (resolvable && !recoveryResolutionDispatched && !event.isEmpty()
                    && connection->requestNativeSessionGuardRecoveryResolution(
                        event, QStringLiteral("stop"))) {
                    recoveryResolutionDispatched = true;
                }
            }
        }
    }

    ClientKeys currentKeys() const
    { return awgKeysProvider ? awgKeysProvider() : ClientKeys{}; }

    bool initializeAndDrive(QString &error)
    {
        error.clear();
        if (!coordinator) {
            error = QStringLiteral("catalog product composition unavailable");
            return false;
        }
        const bool ready = coordinator->initialize(error);
        if (!ready) return false;
        if (facade && facade->v2Authoritative()) onlineDiscoveryEnabled = true;
        if (!pendingUserConnect) return true;
        QByteArray token = bearerTokenProvider ? bearerTokenProvider() : QByteArray{};
        const bool hasAuth = !token.trimmed().isEmpty();
        token.fill('\0');
        if (!hasAuth) {
            error = QStringLiteral("catalog_auth_not_ready");
            return false;
        }
        if (adapters) adapters->setAwgKeys(currentKeys());
        if (!coordinator->requestConnect(error)) return false;
        pendingUserConnect = false;
        if (pendingPathClass.has_value()) {
            coordinator->networkPathChanged(*pendingPathClass, pendingPathToken);
            pendingPathClass.reset();
            pendingPathToken.clear();
        }
        return true;
    }

    VpnConnection *connection = nullptr;
    SecureAppSettingsRepository *settings = nullptr;
    QNetworkAccessManager *network = nullptr;
    CatalogConnectionFacade *facade = nullptr;
    std::function<QByteArray()> bearerTokenProvider;
    std::function<ClientKeys()> awgKeysProvider;
    std::unique_ptr<ProductRuntimeEngineInventory> inventory;
    std::unique_ptr<SystemCatalogClockSource> clockSource;
    std::unique_ptr<CatalogTrustedClock> clock;
    std::unique_ptr<CatalogKeysetClient> keysetClient;
    std::unique_ptr<CatalogResolveClient> resolveClient;
    std::unique_ptr<CatalogOutcomeClient> outcomeClient;
    std::unique_ptr<ICatalogSecureKeyProvider> keyProvider;
    std::unique_ptr<ICatalogFileProtection> fileProtection;
    std::unique_ptr<CatalogSecureStore> secureStore;
    std::unique_ptr<PostTunnelReceiptVerifier> verifier;
    TransportAdapterRegistry registry;
    std::unique_ptr<BundledNativeTransportAdapters> adapters;
    std::unique_ptr<VpnConnectionSessionGuard> guard;
    std::unique_ptr<ConnectionReducer> reducer;
    std::unique_ptr<QSettings> userIntentSettings;
    std::unique_ptr<CatalogCoordinator> coordinator;
    bool recoveryResolutionDispatched = false;
    bool canQueueFirstConnect = false;
    bool pendingUserConnect = false;
    bool ownsUserConnectionIntent = false;
    bool onlineDiscoveryEnabled = false;
    std::optional<CatalogNetworkClass> pendingPathClass;
    QString pendingPathToken;
};

CatalogProductRuntime::CatalogProductRuntime(
    VpnConnection *connection, SecureAppSettingsRepository *settings,
    QNetworkAccessManager *network, CatalogConnectionFacade *facade, QUrl apiBaseUrl,
    std::function<QByteArray()> bearerTokenProvider,
    std::function<ClientKeys()> awgKeysProvider, QObject *parent)
    : QObject(parent),
      m_impl(std::make_unique<Impl>(this, connection, settings, network, facade,
                                   std::move(apiBaseUrl), std::move(bearerTokenProvider),
                                   std::move(awgKeysProvider)))
{}

CatalogProductRuntime::~CatalogProductRuntime() = default;

bool CatalogProductRuntime::initialize(QString &error)
{
    if (!m_impl || !m_impl->coordinator) {
        error = QStringLiteral("catalog product composition unavailable");
        return false;
    }
    return m_impl->initializeAndDrive(error);
}

bool CatalogProductRuntime::productionReady() const
{
    return m_impl && m_impl->coordinator && m_impl->coordinator->productionReady();
}

bool CatalogProductRuntime::canInterceptLegacyConnect() const
{
    return m_impl && m_impl->canQueueFirstConnect;
}

bool CatalogProductRuntime::ownsConnectionIntent() const
{
    return m_impl && m_impl->ownsUserConnectionIntent;
}

bool CatalogProductRuntime::requestConnectWhenReady(QString &error)
{
    error.clear();
    if (!canInterceptLegacyConnect()) {
        error = QStringLiteral("catalog_v2_platform_guard_unavailable");
        return false;
    }
    m_impl->ownsUserConnectionIntent = true;
    m_impl->onlineDiscoveryEnabled = true;
    m_impl->pendingUserConnect = true;
    QByteArray token = m_impl->bearerTokenProvider
                           ? m_impl->bearerTokenProvider() : QByteArray{};
    const bool hasAuth = !token.trimmed().isEmpty();
    token.fill('\0');
    if (!hasAuth) {
        error = QStringLiteral("catalog_auth_not_ready");
        return true; // accepted/queued behind first-run enrollment; no legacy tunnel starts
    }
    if (m_impl->connection && m_impl->connection->nativeEngineManifest().isEmpty()) {
        error = QStringLiteral("runtime_engine_manifest_pending");
        return true;
    }
    const bool ready = m_impl->initializeAndDrive(error);
    return ready;
}

void CatalogProductRuntime::cancelPendingConnect()
{
    if (!m_impl) return;
    m_impl->pendingUserConnect = false;
    m_impl->ownsUserConnectionIntent = false;
    if (m_impl->coordinator) m_impl->coordinator->requestDisconnect();
}

bool CatalogProductRuntime::pendingConnect() const
{
    return m_impl && m_impl->pendingUserConnect;
}

CatalogCoordinator *CatalogProductRuntime::coordinator() const
{
    return m_impl ? m_impl->coordinator.get() : nullptr;
}

bool CatalogProductRuntime::setApiBaseUrl(const QUrl &apiBaseUrl, QString &error)
{
    if (!m_impl || !m_impl->coordinator) {
        error = QStringLiteral("catalog product composition unavailable");
        return false;
    }
    return m_impl->coordinator->updateApiBaseUrl(apiBaseUrl, error);
}

void CatalogProductRuntime::refreshLocalKeys()
{
    if (m_impl && m_impl->adapters) {
        m_impl->adapters->setAwgKeys(m_impl->currentKeys());
        if (m_impl->pendingUserConnect) {
            if (m_impl->connection
                && m_impl->connection->nativeEngineManifest().isEmpty())
                return; // queued manifest callback is the only honest readiness continuation
            QString ignored;
            m_impl->initializeAndDrive(ignored);
        }
    }
}

void CatalogProductRuntime::applicationResumed()
{
    if (m_impl && m_impl->coordinator
        && (m_impl->onlineDiscoveryEnabled
            || (m_impl->facade && m_impl->facade->v2Authoritative())))
        m_impl->coordinator->applicationResumed();
}

void CatalogProductRuntime::setLegacyNativeOwnershipBlocked(bool blocked)
{
    if (m_impl && m_impl->coordinator)
        m_impl->coordinator->setExternalNativeOwnershipBlocked(blocked);
}

void CatalogProductRuntime::networkPathChanged(CatalogNetworkClass networkClass,
                                                const QString &volatilePathToken)
{
    if (!m_impl || !m_impl->coordinator) return;
    if (!m_impl->onlineDiscoveryEnabled
        && !(m_impl->facade && m_impl->facade->v2Authoritative())) {
        // Preserve only privacy-safe local path facts.  A clean install must not accept catalog
        // authority in the background while a legacy Connecting/Connected owner may exist.
        m_impl->pendingPathClass = networkClass;
        m_impl->pendingPathToken = volatilePathToken;
        return;
    }
    m_impl->coordinator->networkPathChanged(networkClass, volatilePathToken);
}

void CatalogProductRuntime::networkReachabilityChanged(bool online)
{
    if (m_impl && m_impl->coordinator)
        m_impl->coordinator->networkReachabilityChanged(online);
}

void CatalogProductRuntime::clearAfterLogout()
{
    if (m_impl && m_impl->coordinator) {
        // Keep legacy fenced while the coordinator waits for exact inner stop + outer release.
        m_impl->ownsUserConnectionIntent = true;
        m_impl->coordinator->clearAfterLogout();
    }
}

QHash<QString, QString> CatalogProductRuntime::compiledOfflineRootKeys()
{
    QHash<QString, QString> roots;
#if defined(TRIBE_CATALOG_ROOT_KID) && defined(TRIBE_CATALOG_ROOT_PUBLIC_KEY_HEX)
    roots.insert(QStringLiteral(TRIBE_CATALOG_ROOT_KID),
                 QStringLiteral(TRIBE_CATALOG_ROOT_PUBLIC_KEY_HEX).toLower());
#endif
    return roots;
}

} // namespace avpn
