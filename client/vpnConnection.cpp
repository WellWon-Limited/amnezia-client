#include "vpnConnection.h"
#include "version.h"

#include <QDebug>
#include <QEventLoop>
#include <QFile>
#include <QHostInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QObject>
#include <QRegularExpression>
#include <QSharedPointer>
#include <QString>
#include <QStringList>
#include <QTimer>
#include <QUuid>

#include <core/configurators/openVpnConfigurator.h>
#include <core/configurators/wireguardConfigurator.h>

#ifdef AMNEZIA_DESKTOP
    #include "core/utils/ipcClient.h"
    #include <core/protocols/wireGuardProtocol.h>
    #include <core/protocols/xrayProtocol.h>
    #include <QRemoteObjectPendingCallWatcher>
#endif

#if defined(AMNEZIA_DESKTOP) && defined(Q_OS_MACOS) && !defined(MACOS_NE)
    #include <QLocalSocket>
    #include <QSet>
    #include "ipc.h"
    #include "ipcsecurity.h"
#endif

#ifdef Q_OS_ANDROID
    #include "platforms/android/android_controller.h"
    #include <QThread>

#endif

#if defined(Q_OS_IOS) || defined(MACOS_NE)
    #include "platforms/ios/ios_controller.h"
#endif

#include "core/serviceEngine/CidrValidate.h" // AVPN: IPv6-CIDR для split-фильтра (header-only)
#include "core/serviceEngine/TuningStore.h" // AVPN backend-first-3 (Task 8): status_poll_ms (header-only)
#include "core/utils/networkUtilities.h"
#include "core/utils/serverConfigUtils.h"
#include "vpnConnection.h"

using namespace ProtocolUtils;

#if defined(AMNEZIA_DESKTOP) && defined(Q_OS_MACOS) && !defined(MACOS_NE)
namespace {

bool canonicalPositiveDecimal(const QJsonValue &value)
{
    if (!value.isString()) return false;
    const QString text = value.toString();
    if (text.isEmpty() || text.size() > 20 || text == QLatin1String("0")
            || (text.size() > 1 && text.startsWith(QLatin1Char('0')))) return false;
    for (const QChar ch : text) {
        if (ch < QLatin1Char('0') || ch > QLatin1Char('9')) return false;
    }
    bool ok = false;
    const quint64 parsed = text.toULongLong(&ok, 10);
    return ok && parsed > 0 && QString::number(parsed) == text;
}

bool canonicalLowerSha256(const QJsonValue &value)
{
    if (!value.isString() || value.toString().size() != 64) return false;
    for (const QChar ch : value.toString()) {
        if (!((ch >= QLatin1Char('0') && ch <= QLatin1Char('9'))
              || (ch >= QLatin1Char('a') && ch <= QLatin1Char('f')))) return false;
    }
    return true;
}

bool canonicalUuid(const QJsonValue &value)
{
    if (!value.isString()) return false;
    const QUuid uuid(value.toString());
    return !uuid.isNull()
            && uuid.toString(QUuid::WithoutBraces).toLower() == value.toString();
}

bool safeAsciiOpaque(const QJsonValue &value, bool allowEmpty)
{
    if (!value.isString()) return false;
    const QString text = value.toString();
    if (text.isEmpty()) return allowEmpty;
    if (text.size() > 200) return false;
    for (const QChar ch : text) {
        const ushort c = ch.unicode();
        const bool alpha = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
        const bool digit = c >= '0' && c <= '9';
        if (!alpha && !digit && c != '-' && c != '_' && c != '.' && c != ':') return false;
    }
    return true;
}

bool safeAsciiReason(const QJsonValue &value)
{
    if (!value.isString() || value.toString().size() > 96) return false;
    for (const QChar ch : value.toString()) {
        if (ch.unicode() < 0x20 || ch.unicode() > 0x7e) return false;
    }
    return true;
}

bool exactGuardEvent(const QJsonObject &event)
{
    static const QSet<QString> keys{
        QStringLiteral("type"), QStringLiteral("schema"), QStringLiteral("operation"),
        QStringLiteral("session"), QStringLiteral("kind"),
        QStringLiteral("policy_sha256"), QStringLiteral("outer_session_id"),
        QStringLiteral("expected_runtime_session_id"), QStringLiteral("reason")};
    const QStringList actual = event.keys();
    const QString kind = event.value(QStringLiteral("kind")).toString();
    const bool knownKind = kind == QLatin1String("armed")
            || kind == QLatin1String("arm_rejected")
            || kind == QLatin1String("released")
            || kind == QLatin1String("release_rejected")
            || kind == QLatin1String("lost");
    return QSet<QString>(actual.cbegin(), actual.cend()) == keys
            && event.value(QStringLiteral("type"))
                   == QLatin1String("native_session_guard_v1")
            && event.value(QStringLiteral("schema")).isDouble()
            && event.value(QStringLiteral("schema")).toDouble() == 1.0
            && canonicalPositiveDecimal(event.value(QStringLiteral("operation")))
            && canonicalPositiveDecimal(event.value(QStringLiteral("session")))
            && canonicalLowerSha256(event.value(QStringLiteral("policy_sha256")))
            && canonicalUuid(event.value(QStringLiteral("expected_runtime_session_id")))
            && safeAsciiOpaque(event.value(QStringLiteral("outer_session_id")),
                               kind == QLatin1String("arm_rejected"))
            && safeAsciiReason(event.value(QStringLiteral("reason")))
            && knownKind;
}

bool sameGuardIdentity(const QJsonObject &lhs, const QJsonObject &rhs,
                       bool includeOuter = true)
{
    return exactGuardEvent(lhs) && exactGuardEvent(rhs)
            && lhs.value(QStringLiteral("operation")) == rhs.value(QStringLiteral("operation"))
            && lhs.value(QStringLiteral("session")) == rhs.value(QStringLiteral("session"))
            && lhs.value(QStringLiteral("policy_sha256"))
                   == rhs.value(QStringLiteral("policy_sha256"))
            && lhs.value(QStringLiteral("expected_runtime_session_id"))
                   == rhs.value(QStringLiteral("expected_runtime_session_id"))
            && (!includeOuter || lhs.value(QStringLiteral("outer_session_id"))
                   == rhs.value(QStringLiteral("outer_session_id")));
}

QJsonObject guardIdentityRequest(const QString &type, const QJsonObject &event,
                                 const QString &protocol = {})
{
    QJsonObject request{
        {QStringLiteral("type"), type}, {QStringLiteral("schema"), 1},
        {QStringLiteral("operation"), event.value(QStringLiteral("operation"))},
        {QStringLiteral("session"), event.value(QStringLiteral("session"))},
        {QStringLiteral("policy_sha256"), event.value(QStringLiteral("policy_sha256"))},
        {QStringLiteral("outer_session_id"),
         event.value(QStringLiteral("outer_session_id"))},
        {QStringLiteral("expected_runtime_session_id"),
         event.value(QStringLiteral("expected_runtime_session_id"))},
    };
    if (!protocol.isEmpty()) request.insert(QStringLiteral("protocol"), protocol);
    return request;
}

bool exactCommandReceipt(const QJsonObject &receipt, const QString &action,
                         const QJsonObject &event)
{
    static const QSet<QString> keys{
        QStringLiteral("type"), QStringLiteral("schema"), QStringLiteral("action"),
        QStringLiteral("accepted"), QStringLiteral("operation"), QStringLiteral("session"),
        QStringLiteral("policy_sha256"), QStringLiteral("outer_session_id"),
        QStringLiteral("expected_runtime_session_id"), QStringLiteral("reason")};
    const QStringList actual = receipt.keys();
    QJsonObject projected{
        {QStringLiteral("type"), QStringLiteral("native_session_guard_v1")},
        {QStringLiteral("schema"), 1},
        {QStringLiteral("operation"), receipt.value(QStringLiteral("operation"))},
        {QStringLiteral("session"), receipt.value(QStringLiteral("session"))},
        {QStringLiteral("kind"), QStringLiteral("armed")},
        {QStringLiteral("policy_sha256"), receipt.value(QStringLiteral("policy_sha256"))},
        {QStringLiteral("outer_session_id"), receipt.value(QStringLiteral("outer_session_id"))},
        {QStringLiteral("expected_runtime_session_id"),
         receipt.value(QStringLiteral("expected_runtime_session_id"))},
        {QStringLiteral("reason"), receipt.value(QStringLiteral("reason"))},
    };
    return QSet<QString>(actual.cbegin(), actual.cend()) == keys
            && receipt.value(QStringLiteral("type"))
                   == QLatin1String("native_session_guard_command_v1")
            && receipt.value(QStringLiteral("schema")).isDouble()
            && receipt.value(QStringLiteral("schema")).toDouble() == 1.0
            && receipt.value(QStringLiteral("action")) == action
            && receipt.value(QStringLiteral("accepted")).isBool()
            && sameGuardIdentity(projected, event);
}

bool exactRecoveryReceipt(const QJsonObject &receipt, const QString &action,
                          const QJsonObject &event)
{
    static const QSet<QString> keys{
        QStringLiteral("type"), QStringLiteral("schema"), QStringLiteral("action"),
        QStringLiteral("kind"), QStringLiteral("operation"), QStringLiteral("session"),
        QStringLiteral("policy_sha256"), QStringLiteral("outer_session_id"),
        QStringLiteral("expected_runtime_session_id"), QStringLiteral("reason")};
    const QStringList actual = receipt.keys();
    const QString kind = receipt.value(QStringLiteral("kind")).toString();
    QJsonObject projected{
        {QStringLiteral("type"), QStringLiteral("native_session_guard_v1")},
        {QStringLiteral("schema"), 1},
        {QStringLiteral("operation"), receipt.value(QStringLiteral("operation"))},
        {QStringLiteral("session"), receipt.value(QStringLiteral("session"))},
        {QStringLiteral("kind"), QStringLiteral("armed")},
        {QStringLiteral("policy_sha256"), receipt.value(QStringLiteral("policy_sha256"))},
        {QStringLiteral("outer_session_id"), receipt.value(QStringLiteral("outer_session_id"))},
        {QStringLiteral("expected_runtime_session_id"),
         receipt.value(QStringLiteral("expected_runtime_session_id"))},
        {QStringLiteral("reason"), receipt.value(QStringLiteral("reason"))},
    };
    return QSet<QString>(actual.cbegin(), actual.cend()) == keys
            && receipt.value(QStringLiteral("type"))
                   == QLatin1String("native_session_guard_recovery_v1")
            && receipt.value(QStringLiteral("schema")).isDouble()
            && receipt.value(QStringLiteral("schema")).toDouble() == 1.0
            && receipt.value(QStringLiteral("action")) == action
            && (kind == QLatin1String("adopted")
                || kind == QLatin1String("stopped_released")
                || kind == QLatin1String("rejected"))
            && sameGuardIdentity(projected, event);
}

template <typename StartCall>
QJsonObject waitGuardReply(StartCall &&start)
{
    return IpcClient::withInterface([&](QSharedPointer<IpcInterfaceReplica> iface) {
        auto reply = start(iface);
        return reply.waitForFinished(5000) ? reply.returnValue() : QJsonObject{};
    });
}

} // namespace
#endif

VpnConnection::VpnConnection(SecureServersRepository* serversRepository, SecureAppSettingsRepository* appSettingsRepository, QObject *parent)
    : QObject(parent), m_serversRepository(serversRepository), m_appSettingsRepository(appSettingsRepository), m_checkTimer(this)
{
#if defined(Q_OS_IOS) || defined(MACOS_NE)
    m_checkTimer.setInterval(qBound(250, (int)avpn::TuningStore::numberOr(QStringLiteral("status_poll_ms"), 1000), 5000)); // AVPN: server-tunable
    connect(IosController::Instance(), &IosController::connectionStateChanged, this, &VpnConnection::setConnectionState);
    connect(IosController::Instance(), &IosController::bytesChanged, this, &VpnConnection::onBytesChanged);
    // AVPN: preserve the validated opaque native session identity for the v2 reducer.
    connect(IosController::Instance(), &IosController::runtimeStatusChanged,
            this, &VpnConnection::nativeRuntimeStatusChanged);
    connect(IosController::Instance(), &IosController::runtimeAuthorityRenewalReceipt,
            this, &VpnConnection::nativeRuntimeAuthorityRenewalReceipt);
    connect(IosController::Instance(), &IosController::sessionGuardEvent,
            this, &VpnConnection::nativeSessionGuardEvent);
    connect(IosController::Instance(), &IosController::engineManifestChanged,
            this, &VpnConnection::nativeEngineManifestChanged);
    connect(IosController::Instance(), &IosController::sessionGuardRecoveryRequired,
            this, &VpnConnection::nativeSessionGuardRecoveryRequired);
    connect(IosController::Instance(), &IosController::sessionGuardRecoveryResolved,
            this, &VpnConnection::nativeSessionGuardRecoveryResolved);
#elif defined(Q_OS_ANDROID)
    connect(AndroidController::instance(), &AndroidController::runtimeStatusChanged,
            this, &VpnConnection::nativeRuntimeStatusChanged);
    connect(AndroidController::instance(), &AndroidController::runtimeAuthorityRenewalReceipt,
            this, &VpnConnection::nativeRuntimeAuthorityRenewalReceipt);
    connect(AndroidController::instance(), &AndroidController::sessionGuardEvent,
            this, &VpnConnection::nativeSessionGuardEvent);
    connect(AndroidController::instance(), &AndroidController::engineManifestChanged,
            this, &VpnConnection::nativeEngineManifestChanged);
    connect(AndroidController::instance(), &AndroidController::sessionGuardRecoveryRequired,
            this, &VpnConnection::nativeSessionGuardRecoveryRequired);
    connect(AndroidController::instance(), &AndroidController::sessionGuardRecoveryResolved,
            this, &VpnConnection::nativeSessionGuardRecoveryResolved);
    QTimer::singleShot(0, AndroidController::instance(),
                       &AndroidController::requestSessionGuardRecoveryStatus);
#endif

#if defined(AMNEZIA_DESKTOP) && defined(Q_OS_MACOS) && !defined(MACOS_NE)
    // Inventory is queried independently of a VPN protocol instance so catalog resolve can run
    // before the first connection. The authenticated daemon owns the compile-time lock facts.
    QTimer::singleShot(0, this, &VpnConnection::requestDesktopEngineManifest);
    QTimer::singleShot(0, this, &VpnConnection::requestDesktopNativeGuardRecoveryStatus);
#endif
}

VpnConnection::~VpnConnection()
{
}

void VpnConnection::onBytesChanged(quint64 receivedBytes, quint64 sentBytes)
{
    emit bytesChanged(receivedBytes, sentBytes);
}

void VpnConnection::onKillSwitchModeChanged(bool enabled)
{
#ifdef AMNEZIA_DESKTOP
    IpcClient::withInterface([enabled](QSharedPointer<IpcInterfaceReplica> iface){
        QRemoteObjectPendingReply<bool> reply = iface->refreshKillSwitch(enabled);
        if (reply.waitForFinished() && reply.returnValue())
            qDebug() << "VpnConnection::onKillSwitchModeChanged: Killswitch refreshed";
        else
            qWarning() << "VpnConnection::onKillSwitchModeChanged: Failed to execute remote refreshKillSwitch call";
    });
#endif
}

void VpnConnection::onConnectionStateChanged(Vpn::ConnectionState state)
{
#ifdef AMNEZIA_DESKTOP
    if (!m_serversRepository || !m_appSettingsRepository) {
        qCritical() << "VpnConnection::onConnectionStateChanged: repositories not initialized";
        return;
    }

    const QString defaultServerId = m_serversRepository->defaultServerId();
    // AVPN v2: direct serviceEngine profiles are not repository records. Prefer the exact
    // container passed to connectToVpn; retain repository lookup only for pre-v2 call sites.
    DockerContainer container = m_activeContainer;
    if (container == DockerContainer::None) switch (m_serversRepository->serverKind(defaultServerId)) {
    case serverConfigUtils::ConfigType::SelfHostedAdmin: {
        const auto cfg = m_serversRepository->selfHostedAdminConfig(defaultServerId);
        if (cfg.has_value()) {
            container = cfg->defaultContainer;
        }
        break;
    }
    case serverConfigUtils::ConfigType::SelfHostedUser: {
        const auto cfg = m_serversRepository->selfHostedUserConfig(defaultServerId);
        if (cfg.has_value()) {
            container = cfg->defaultContainer;
        }
        break;
    }
    case serverConfigUtils::ConfigType::Native: {
        const auto cfg = m_serversRepository->nativeConfig(defaultServerId);
        if (cfg.has_value()) {
            container = cfg->defaultContainer;
        }
        break;
    }
    case serverConfigUtils::ConfigType::AmneziaPremiumV2:
    case serverConfigUtils::ConfigType::AmneziaFreeV3:
    case serverConfigUtils::ConfigType::ExternalPremium: {
        const auto cfg = m_serversRepository->apiV2Config(defaultServerId);
        if (cfg.has_value()) {
            container = cfg->defaultContainer;
        }
        break;
    }
    case serverConfigUtils::ConfigType::AmneziaPremiumV1:
    case serverConfigUtils::ConfigType::AmneziaFreeV2:
        break;
    case serverConfigUtils::ConfigType::Invalid:
    default:
        break;
    }

    IpcClient::withInterface([&](QSharedPointer<IpcInterfaceReplica> iface) {
        switch (state) {
            case Vpn::ConnectionState::Connected: {
                iface->resetIpStack();

                auto flushDns = iface->flushDns();
                if (flushDns.waitForFinished() && flushDns.returnValue())
                    qDebug() << "VpnConnection::onConnectionStateChanged: Successfully flushed DNS";
                else
                    qWarning() << "VpnConnection::onConnectionStateChanged: Failed to flush DNS";

                // AVPN v2: prepared policy is authoritative for this session. Never consult a
                // subsequently changed repository while installing native routes.
                const auto preparedRouteMode = static_cast<amnezia::RouteMode>(
                    m_vpnConfiguration.value(configKey::splitTunnelType).toInt(
                        amnezia::RouteMode::VpnAllSites));
                const amnezia::RouteMode effectiveRouteMode = m_hasPreparedConnectionPolicy
                    ? preparedRouteMode : m_appSettingsRepository->routeMode();
                const bool effectiveSitesSplit = m_hasPreparedConnectionPolicy
                    ? effectiveRouteMode != amnezia::RouteMode::VpnAllSites
                      && !m_vpnConfiguration.value(configKey::splitTunnelSites).toArray().isEmpty()
                    : m_appSettingsRepository->isSitesSplitTunnelingEnabled();

                if (!ContainerUtils::isAwgContainer(container) && container != DockerContainer::WireGuard) {
                    QString dns1 = m_vpnConfiguration.value(configKey::dns1).toString();
                    QString dns2 = m_vpnConfiguration.value(configKey::dns2).toString();

#ifdef Q_OS_MACOS
                    if (!effectiveSitesSplit
                        || effectiveRouteMode != amnezia::RouteMode::VpnAllExceptSites) {
                        iface->routeAddList(m_vpnProtocol->vpnGateway(), QStringList() << dns1 << dns2);
                    }
#else
                    iface->routeAddList(m_vpnProtocol->vpnGateway(), QStringList() << dns1 << dns2);
#endif

                    if (effectiveSitesSplit) {
                        iface->routeDeleteList(m_vpnProtocol->vpnGateway(), QStringList() << "0.0.0.0");
                        const RouteMode routeMode = effectiveRouteMode;
                        if (routeMode == amnezia::RouteMode::VpnOnlyForwardSites) {
                            QTimer::singleShot(1000, m_vpnProtocol.data(),
                                               [this, routeMode]() {
                                if (m_hasPreparedConnectionPolicy)
                                    addPreparedSitesRoutes(m_vpnProtocol->vpnGateway());
                                else
                                    addSitesRoutes(m_vpnProtocol->vpnGateway(), routeMode);
                            });
                        } else if (routeMode == amnezia::RouteMode::VpnAllExceptSites) {
                            iface->routeAddList(m_vpnProtocol->vpnGateway(), QStringList() << "0.0.0.0/1");
                            iface->routeAddList(m_vpnProtocol->vpnGateway(), QStringList() << "128.0.0.0/1");

                            iface->routeAddList(m_vpnProtocol->routeGateway(), QStringList() << remoteAddress());
#ifdef Q_OS_MACOS
                            iface->routeAddList(m_vpnProtocol->routeGateway(), QStringList() << dns1 << dns2);
#endif
                            if (m_hasPreparedConnectionPolicy)
                                addPreparedSitesRoutes(m_vpnProtocol->routeGateway());
                            else
                                addSitesRoutes(m_vpnProtocol->routeGateway(), routeMode);
                        }
                    }
                }
            } break;
            case Vpn::ConnectionState::Disconnected:
            case Vpn::ConnectionState::Error: {
                auto flushDns = iface->flushDns();
                if (flushDns.waitForFinished() && flushDns.returnValue())
                    qDebug() << "VpnConnection::onConnectionStateChanged: Successfully flushed DNS";
                else
                    qWarning() << "VpnConnection::onConnectionStateChanged: Failed to flush DNS";

                auto clearSavedRoutes = iface->clearSavedRoutes();
                if (clearSavedRoutes.waitForFinished() && clearSavedRoutes.returnValue())
                    qDebug() << "VpnConnection::onConnectionStateChanged: Successfully cleared saved routes";
                else
                    qWarning() << "VpnConnection::onConnectionStateChanged: Failed to clear saved routes";
            } break;
            default:
                break;
        }
    });
#endif

#if defined(Q_OS_IOS) || defined(MACOS_NE)
    if (state == Vpn::ConnectionState::Connected ||
        state == Vpn::ConnectionState::Connecting ||
        state == Vpn::ConnectionState::Reconnecting) {
        // AVPN (Task 8): перечитать интервал перед стартом — в конструкторе конфиг ещё мог не
        // примениться (numberOr => вкомпиленный 1000), здесь уже свежий TuningStore-снапшот.
        m_checkTimer.setInterval(qBound(250, (int)avpn::TuningStore::numberOr(QStringLiteral("status_poll_ms"), 1000), 5000)); // AVPN: server-tunable
        m_checkTimer.start();
    } else {
        m_checkTimer.stop();
    }
#endif
}

const QString &VpnConnection::remoteAddress() const
{
    return m_remoteAddress;
}

QJsonObject VpnConnection::nativeRuntimeStatus() const
{
#if defined(Q_OS_IOS) || defined(MACOS_NE)
    return IosController::Instance()->runtimeStatus();
#elif defined(Q_OS_ANDROID)
    return AndroidController::instance()->runtimeStatus();
#elif defined(AMNEZIA_DESKTOP)
    if (const auto *xray = qobject_cast<XrayProtocol *>(m_vpnProtocol.data()))
        return xray->runtimeStatus();
    if (const auto *awg = qobject_cast<WireguardProtocol *>(m_vpnProtocol.data()))
        return awg->runtimeStatus();
    return {};
#else
    return {};
#endif
}

QJsonObject VpnConnection::nativeEngineManifest() const
{
#if defined(Q_OS_IOS) || defined(MACOS_NE)
    return IosController::Instance()->engineManifest();
#elif defined(Q_OS_ANDROID)
    return AndroidController::instance()->engineManifest();
#elif defined(AMNEZIA_DESKTOP) && defined(Q_OS_MACOS) && !defined(MACOS_NE)
    return m_nativeEngineManifest;
#else
    // Production desktop must obtain this from authenticated daemon IPC; no duplicated
    // client-side pins are accepted as evidence.
    return {};
#endif
}

void VpnConnection::requestDesktopEngineManifest()
{
#if defined(AMNEZIA_DESKTOP) && defined(Q_OS_MACOS) && !defined(MACOS_NE)
    auto *socket = new QLocalSocket(this);
    auto buffer = QSharedPointer<QByteArray>::create();
    auto *deadline = new QTimer(socket);
    deadline->setSingleShot(true);
    socket->setReadBufferSize(amnezia::ipcsecurity::kMaxDaemonCommandBytes);
    connect(deadline, &QTimer::timeout, socket, [socket]() {
        socket->abort();
        socket->deleteLater();
    });
    connect(socket, &QLocalSocket::connected, socket, [socket]() {
        QByteArray capability;
        QString error;
        if (!amnezia::ipcsecurity::performClientHandshake(
                socket, {}, &capability, &error)) {
            socket->abort();
            socket->deleteLater();
            return;
        }
        socket->write(QJsonDocument(QJsonObject{
            {QStringLiteral("type"), QStringLiteral("engine_manifest_v1")}})
                          .toJson(QJsonDocument::Compact));
        socket->write("\n");
        socket->flush();
    });
    connect(socket, &QLocalSocket::readyRead, socket, [this, socket, buffer]() {
        const QByteArray chunk = socket->readAll();
        if (chunk.size() > amnezia::ipcsecurity::kMaxDaemonCommandBytes
            || buffer->size() > amnezia::ipcsecurity::kMaxDaemonCommandBytes - chunk.size()) {
            socket->abort();
            socket->deleteLater();
            return;
        }
        buffer->append(chunk);
        const qsizetype newline = buffer->indexOf('\n');
        if (newline < 0) return;
        const QByteArray frame = buffer->left(newline).trimmed();
        QJsonParseError parseError;
        const QJsonDocument document = QJsonDocument::fromJson(frame, &parseError);
        const QJsonObject manifest = document.object();
        static const QSet<QString> rootKeys{
            QStringLiteral("type"), QStringLiteral("schema"),
            QStringLiteral("app"), QStringLiteral("engines")};
        const QStringList keys = manifest.keys();
        if (parseError.error == QJsonParseError::NoError && document.isObject()
            && QSet<QString>(keys.cbegin(), keys.cend()) == rootKeys
            && manifest.value(QStringLiteral("type")) == QLatin1String("engine_manifest_v1")
            && manifest.value(QStringLiteral("schema")).isDouble()
            && manifest.value(QStringLiteral("schema")).toDouble() == 1.0
            && manifest.value(QStringLiteral("app")).isObject()
            && manifest.value(QStringLiteral("engines")).isArray()) {
            m_nativeEngineManifest = manifest;
            emit nativeEngineManifestChanged(manifest);
        }
        socket->disconnectFromServer();
        socket->deleteLater();
    });
    connect(socket, &QLocalSocket::errorOccurred, socket,
            [socket](QLocalSocket::LocalSocketError) { socket->deleteLater(); });
    deadline->start(3000);
    socket->connectToServer(amnezia::getWireguardDaemonUrl());
#endif
}

void VpnConnection::requestDesktopNativeGuardRecoveryStatus()
{
#if defined(AMNEZIA_DESKTOP) && defined(Q_OS_MACOS) && !defined(MACOS_NE)
    const QJsonObject status = waitGuardReply(
        [](const QSharedPointer<IpcInterfaceReplica> &iface) {
            return iface->nativeSessionGuardStatusV1();
        });
    static const QSet<QString> keys{
        QStringLiteral("type"), QStringLiteral("schema"),
        QStringLiteral("state"), QStringLiteral("event")};
    const QStringList actual = status.keys();
    const bool envelopeValid = QSet<QString>(actual.cbegin(), actual.cend()) == keys
            && status.value(QStringLiteral("type"))
                   == QLatin1String("native_session_guard_status_v1")
            && status.value(QStringLiteral("schema")).isDouble()
            && status.value(QStringLiteral("schema")).toDouble() == 1.0;
    if (!envelopeValid) {
        // Empty/timeout cannot prove that PF and a native reader are absent.
        m_desktopNativeGuardRecoveryPending = true;
        return;
    }
    const QString state = status.value(QStringLiteral("state")).toString();
    if (state == QLatin1String("idle") && status.value(QStringLiteral("event")).isNull()) {
        m_desktopNativeGuardRecoveryPending = false;
        m_desktopNativeGuardRecoveryEvent = {};
        return;
    }
    if (state != QLatin1String("owned")
            || !status.value(QStringLiteral("event")).isObject()) {
        m_desktopNativeGuardRecoveryPending = true;
        return;
    }
    const QJsonObject event = status.value(QStringLiteral("event")).toObject();
    if (!exactGuardEvent(event)) {
        m_desktopNativeGuardRecoveryPending = true;
        return;
    }
    m_desktopNativeGuardRecoveryPending = true;
    m_desktopNativeGuardRecoveryEvent = event;
    emit nativeSessionGuardRecoveryRequired(event);
#endif
}

void VpnConnection::consumeDesktopNativeRuntimeStatus(const QJsonObject &status)
{
#if defined(AMNEZIA_DESKTOP) && defined(Q_OS_MACOS) && !defined(MACOS_NE)
    if (!exactGuardEvent(m_desktopNativeGuardEvent)) return;
    const QString expected = m_desktopNativeGuardEvent.value(
        QStringLiteral("expected_runtime_session_id")).toString();
    if (status.value(QStringLiteral("type"))
            != QLatin1String("tunnel_runtime_status_v1")
        || !status.value(QStringLiteral("schema")).isDouble()
        || status.value(QStringLiteral("schema")).toDouble() != 1.0
        || status.value(QStringLiteral("session_id")).toString() != expected) return;

    const QString state = status.value(QStringLiteral("runtime_state")).toString();
    if (state == QLatin1String("running")) {
        const QJsonObject receipt = waitGuardReply(
            [&](const QSharedPointer<IpcInterfaceReplica> &iface) {
                return iface->nativeSessionGuardMarkRunningV1(guardIdentityRequest(
                    QStringLiteral("native_session_guard_running_v1"),
                    m_desktopNativeGuardEvent));
            });
        if (!exactCommandReceipt(receipt, QStringLiteral("running"),
                                 m_desktopNativeGuardEvent)
            || !receipt.value(QStringLiteral("accepted")).toBool()) {
            QJsonObject failed = status;
            failed.insert(QStringLiteral("runtime_state"), QStringLiteral("failed"));
            failed.insert(QStringLiteral("failure_reason"),
                          QStringLiteral("outer_guard_running_receipt_rejected"));
            emit nativeRuntimeStatusChanged(failed);
            return;
        }
    } else if (state == QLatin1String("stopped")) {
        const QJsonObject receipt = waitGuardReply(
            [&](const QSharedPointer<IpcInterfaceReplica> &iface) {
                return iface->nativeSessionGuardMarkStoppedV1(guardIdentityRequest(
                    QStringLiteral("native_session_guard_stopped_v1"),
                    m_desktopNativeGuardEvent));
            });
        if (!exactCommandReceipt(receipt, QStringLiteral("stopped"),
                                 m_desktopNativeGuardEvent)
            || !receipt.value(QStringLiteral("accepted")).toBool()) {
            QJsonObject failed = status;
            failed.insert(QStringLiteral("runtime_state"), QStringLiteral("failed"));
            failed.insert(QStringLiteral("failure_reason"),
                          QStringLiteral("outer_guard_stopped_receipt_rejected"));
            emit nativeRuntimeStatusChanged(failed);
            return;
        }
    }
    emit nativeRuntimeStatusChanged(status);
#else
    Q_UNUSED(status)
#endif
}

bool VpnConnection::requestNativeSessionGuardArm(const QJsonObject &configuration,
                                                 const QString &operation,
                                                 const QString &session,
                                                 const QString &policyHashHex,
                                                 const QString &expectedRuntimeSessionId)
{
#ifdef Q_OS_ANDROID
    return AndroidController::instance()->requestSessionGuardArm(
        configuration, operation, session, policyHashHex, expectedRuntimeSessionId);
#elif defined(Q_OS_IOS)
    return IosController::Instance()->requestSessionGuardArm(
        configuration, operation, session, policyHashHex, expectedRuntimeSessionId);
#elif defined(AMNEZIA_DESKTOP) && defined(Q_OS_MACOS) && !defined(MACOS_NE)
    if (m_desktopNativeGuardRecoveryPending) return false;
    const QJsonObject request{
        {QStringLiteral("type"), QStringLiteral("native_session_guard_prepare_v1")},
        {QStringLiteral("schema"), 1},
        {QStringLiteral("operation"), operation},
        {QStringLiteral("session"), session},
        {QStringLiteral("policy_sha256"), policyHashHex},
        {QStringLiteral("expected_runtime_session_id"), expectedRuntimeSessionId},
        {QStringLiteral("configuration"), configuration},
    };
    const QJsonObject event = waitGuardReply(
        [&](const QSharedPointer<IpcInterfaceReplica> &iface) {
            return iface->nativeSessionGuardPrepareV1(request);
        });
    const bool identityMatches = exactGuardEvent(event)
            && event.value(QStringLiteral("operation")) == operation
            && event.value(QStringLiteral("session")) == session
            && event.value(QStringLiteral("policy_sha256")) == policyHashHex
            && event.value(QStringLiteral("expected_runtime_session_id"))
                   == expectedRuntimeSessionId;
    if (!identityMatches) {
        // The call may have armed PF before a reply/channel loss. Resolve from
        // the durable helper lease; never infer that dispatch failure means idle.
        requestDesktopNativeGuardRecoveryStatus();
        return false;
    }
    if (event.value(QStringLiteral("kind")) == QLatin1String("armed")) {
        m_desktopNativeGuardEvent = event;
        m_desktopNativeGuardConfiguration = configuration;
    } else if (event.value(QStringLiteral("kind")) == QLatin1String("lost")) {
        m_desktopNativeGuardRecoveryPending = true;
        m_desktopNativeGuardRecoveryEvent = event;
        emit nativeSessionGuardRecoveryRequired(event);
    }
    QTimer::singleShot(0, this, [this, event]() { emit nativeSessionGuardEvent(event); });
    return true;
#else
    Q_UNUSED(configuration); Q_UNUSED(operation); Q_UNUSED(session); Q_UNUSED(policyHashHex);
    Q_UNUSED(expectedRuntimeSessionId);
    return false;
#endif
}

bool VpnConnection::activateNativeSession(const QJsonObject &configuration,
                                          const QString &operation,
                                          const QString &session,
                                          const QString &outerSessionId,
                                          const QString &expectedRuntimeSessionId)
{
#ifdef Q_OS_ANDROID
    return AndroidController::instance()->activateNativeSession(
        configuration, operation, session, outerSessionId, expectedRuntimeSessionId);
#elif defined(Q_OS_IOS)
    return IosController::Instance()->activateNativeSession(
        configuration, operation, session, outerSessionId, expectedRuntimeSessionId);
#elif defined(AMNEZIA_DESKTOP) && defined(Q_OS_MACOS) && !defined(MACOS_NE)
    if (!exactGuardEvent(m_desktopNativeGuardEvent)
        || m_desktopNativeGuardEvent.value(QStringLiteral("kind"))
               != QLatin1String("armed")
        || m_desktopNativeGuardEvent.value(QStringLiteral("operation")) != operation
        || m_desktopNativeGuardEvent.value(QStringLiteral("session")) != session
        || m_desktopNativeGuardEvent.value(QStringLiteral("outer_session_id")) != outerSessionId
        || m_desktopNativeGuardEvent.value(QStringLiteral("expected_runtime_session_id"))
               != expectedRuntimeSessionId
        || configuration != m_desktopNativeGuardConfiguration) return false;
    const QString protocol = configuration.value(QStringLiteral("protocol")).toString();
    if (protocol != QLatin1String("awg") && protocol != QLatin1String("xray")) return false;
    const QJsonObject claim = waitGuardReply(
        [&](const QSharedPointer<IpcInterfaceReplica> &iface) {
            return iface->nativeSessionGuardClaimInnerV1(guardIdentityRequest(
                QStringLiteral("native_session_guard_claim_v1"),
                m_desktopNativeGuardEvent, protocol));
        });
    if (!exactCommandReceipt(claim, QStringLiteral("claim"), m_desktopNativeGuardEvent)
        || !claim.value(QStringLiteral("accepted")).toBool()) return false;

    if (m_vpnProtocol) {
        const QJsonObject previous = nativeRuntimeStatus();
        if (previous.value(QStringLiteral("runtime_state")) != QLatin1String("stopped")) {
            return false;
        }
        m_vpnProtocol.reset();
    }
    m_vpnConfiguration = configuration;
    m_hasPreparedConnectionPolicy = true;
    m_remoteAddress = configuration.value(configKey::hostName).toString();
    m_activeContainer = protocol == QLatin1String("awg")
            ? DockerContainer::Awg : DockerContainer::Xray;
    if (protocol == QLatin1String("awg")) {
        m_vpnProtocol.reset(new WireguardProtocol(configuration,
                                                  expectedRuntimeSessionId));
        connect(qobject_cast<WireguardProtocol *>(m_vpnProtocol.data()),
                &WireguardProtocol::runtimeStatusChanged, this,
                &VpnConnection::consumeDesktopNativeRuntimeStatus);
    } else {
        m_vpnProtocol.reset(new XrayProtocol(configuration,
                                             expectedRuntimeSessionId, true));
        connect(qobject_cast<XrayProtocol *>(m_vpnProtocol.data()),
                &XrayProtocol::runtimeStatusChanged, this,
                &VpnConnection::consumeDesktopNativeRuntimeStatus);
    }
    createProtocolConnections();
    setConnectionState(Vpn::ConnectionState::Connecting);
    const ErrorCode result = m_vpnProtocol->start();
    if (result != ErrorCode::NoError) {
        QJsonObject failed{
            {QStringLiteral("type"), QStringLiteral("tunnel_runtime_status_v1")},
            {QStringLiteral("schema"), 1}, {QStringLiteral("protocol"), protocol},
            {QStringLiteral("session_id"), expectedRuntimeSessionId},
            {QStringLiteral("runtime_state"), QStringLiteral("failed")},
            {QStringLiteral("failure_reason"), QStringLiteral("native_start_failed")},
        };
        QTimer::singleShot(0, this, [this, failed]() {
            emit nativeRuntimeStatusChanged(failed);
        });
    }
    // Once claim was accepted, failure is an exact native terminal/stop
    // transaction, not a dispatch rejection which could release PF early.
    return true;
#else
    Q_UNUSED(configuration); Q_UNUSED(operation); Q_UNUSED(session); Q_UNUSED(outerSessionId);
    Q_UNUSED(expectedRuntimeSessionId);
    return false;
#endif
}

bool VpnConnection::renewNativeRuntimeAuthority(
    const QJsonObject &configuration, const QString &operation,
    const QString &session, const QString &outerSessionId,
    const QString &expectedRuntimeSessionId, const QString &renewalId,
    const QString &authorityCommitmentHex)
{
#ifdef Q_OS_ANDROID
    return AndroidController::instance()->renewRuntimeAuthority(
        configuration, operation, session, outerSessionId,
        expectedRuntimeSessionId, renewalId, authorityCommitmentHex);
#elif defined(Q_OS_IOS)
    return IosController::Instance()->renewRuntimeAuthority(
        configuration, operation, session, outerSessionId,
        expectedRuntimeSessionId, renewalId, authorityCommitmentHex);
#elif defined(AMNEZIA_DESKTOP) && defined(Q_OS_MACOS) && !defined(MACOS_NE)
    if (!exactGuardEvent(m_desktopNativeGuardEvent)
        || m_desktopNativeGuardEvent.value(QStringLiteral("kind"))
               != QLatin1String("armed")
        || m_desktopNativeGuardEvent.value(QStringLiteral("operation")) != operation
        || m_desktopNativeGuardEvent.value(QStringLiteral("session")) != session
        || m_desktopNativeGuardEvent.value(QStringLiteral("outer_session_id"))
               != outerSessionId
        || m_desktopNativeGuardEvent.value(
               QStringLiteral("expected_runtime_session_id"))
               != expectedRuntimeSessionId
        || !canonicalUuid(QJsonValue(renewalId))
        || !canonicalLowerSha256(QJsonValue(authorityCommitmentHex))) return false;
    const QJsonObject request{
        {QStringLiteral("type"), QStringLiteral("runtime_authority_renew_request_v1")},
        {QStringLiteral("schema"), 1},
        {QStringLiteral("operation"), operation},
        {QStringLiteral("session"), session},
        {QStringLiteral("policy_sha256"),
         m_desktopNativeGuardEvent.value(QStringLiteral("policy_sha256"))},
        {QStringLiteral("outer_session_id"), outerSessionId},
        {QStringLiteral("expected_runtime_session_id"), expectedRuntimeSessionId},
        {QStringLiteral("renewal_id"), renewalId},
        {QStringLiteral("authority_commitment_sha256"), authorityCommitmentHex},
        {QStringLiteral("configuration"), configuration},
    };
    return IpcClient::withInterface(
        [this, request](QSharedPointer<IpcInterfaceReplica> iface) -> bool {
            QRemoteObjectPendingReply<QJsonObject> reply =
                iface->nativeSessionGuardRenewAuthorityV1(request);
            auto *watcher = new QRemoteObjectPendingCallWatcher(reply, this);
            QObject::connect(
                watcher, &QRemoteObjectPendingCallWatcher::finished, this,
                [this](QRemoteObjectPendingCallWatcher *call) {
                    if (call->error() == QRemoteObjectPendingCall::NoError) {
                        const QJsonObject receipt = call->returnValue().toJsonObject();
                        if (!receipt.isEmpty())
                            emit nativeRuntimeAuthorityRenewalReceipt(receipt);
                    }
                    call->deleteLater();
                });
            return true;
        }, []() { return false; });
#else
    Q_UNUSED(configuration); Q_UNUSED(operation); Q_UNUSED(session);
    Q_UNUSED(outerSessionId); Q_UNUSED(expectedRuntimeSessionId);
    Q_UNUSED(renewalId); Q_UNUSED(authorityCommitmentHex);
    return false;
#endif
}

bool VpnConnection::stopNativeSession(const QString &outerSessionId,
                                      const QString &expectedRuntimeSessionId)
{
#ifdef Q_OS_ANDROID
    return AndroidController::instance()->stopNativeSession(
        outerSessionId, expectedRuntimeSessionId);
#elif defined(Q_OS_IOS)
    return IosController::Instance()->stopNativeSession(
        outerSessionId, expectedRuntimeSessionId);
#elif defined(AMNEZIA_DESKTOP) && defined(Q_OS_MACOS) && !defined(MACOS_NE)
    if (!exactGuardEvent(m_desktopNativeGuardEvent)
        || m_desktopNativeGuardEvent.value(QStringLiteral("outer_session_id")) != outerSessionId
        || m_desktopNativeGuardEvent.value(QStringLiteral("expected_runtime_session_id"))
               != expectedRuntimeSessionId || !m_vpnProtocol) return false;
    const QJsonObject begin = waitGuardReply(
        [&](const QSharedPointer<IpcInterfaceReplica> &iface) {
            return iface->nativeSessionGuardBeginStopV1(guardIdentityRequest(
                QStringLiteral("native_session_guard_stop_begin_v1"),
                m_desktopNativeGuardEvent));
        });
    if (!exactCommandReceipt(begin, QStringLiteral("stop_begin"),
                             m_desktopNativeGuardEvent)
        || !begin.value(QStringLiteral("accepted")).toBool()) return false;
    m_vpnProtocol->stop();
    return true;
#else
    Q_UNUSED(outerSessionId); Q_UNUSED(expectedRuntimeSessionId);
    return false;
#endif
}

bool VpnConnection::requestNativeSessionGuardRelease(const QString &operation,
                                                     const QString &session,
                                                     const QString &outerSessionId)
{
#ifdef Q_OS_ANDROID
    return AndroidController::instance()->requestSessionGuardRelease(
        operation, session, outerSessionId);
#elif defined(Q_OS_IOS)
    return IosController::Instance()->requestSessionGuardRelease(
        operation, session, outerSessionId);
#elif defined(AMNEZIA_DESKTOP) && defined(Q_OS_MACOS) && !defined(MACOS_NE)
    if (!exactGuardEvent(m_desktopNativeGuardEvent)
        || m_desktopNativeGuardEvent.value(QStringLiteral("operation")) != operation
        || m_desktopNativeGuardEvent.value(QStringLiteral("session")) != session
        || m_desktopNativeGuardEvent.value(QStringLiteral("outer_session_id"))
               != outerSessionId) return false;
    const QJsonObject event = waitGuardReply(
        [&](const QSharedPointer<IpcInterfaceReplica> &iface) {
            return iface->nativeSessionGuardReleaseV1(guardIdentityRequest(
                QStringLiteral("native_session_guard_release_v1"),
                m_desktopNativeGuardEvent));
        });
    if (!exactGuardEvent(event)
        || !sameGuardIdentity(event, m_desktopNativeGuardEvent)) return false;
    if (event.value(QStringLiteral("kind")) == QLatin1String("released")) {
        m_desktopNativeGuardEvent = {};
        m_desktopNativeGuardConfiguration = {};
        if (m_vpnProtocol
            && nativeRuntimeStatus().value(QStringLiteral("runtime_state"))
                   == QLatin1String("stopped")) m_vpnProtocol.reset();
    }
    QTimer::singleShot(0, this, [this, event]() { emit nativeSessionGuardEvent(event); });
    return true;
#else
    Q_UNUSED(operation); Q_UNUSED(session); Q_UNUSED(outerSessionId);
    return false;
#endif
}

bool VpnConnection::requestNativeSessionGuardReconcileArm(
    const QString &operation, const QString &session, const QString &policyHashHex,
    const QString &expectedRuntimeSessionId)
{
#ifdef Q_OS_ANDROID
    return AndroidController::instance()->requestSessionGuardReconcileArm(
        operation, session, policyHashHex, expectedRuntimeSessionId);
#elif defined(Q_OS_IOS)
    return IosController::Instance()->requestSessionGuardReconcileArm(
        operation, session, policyHashHex, expectedRuntimeSessionId);
#else
    Q_UNUSED(operation); Q_UNUSED(session); Q_UNUSED(policyHashHex);
    Q_UNUSED(expectedRuntimeSessionId);
    return false;
#endif
}

bool VpnConnection::requestNativeSessionGuardReconcileRelease(
    const QString &operation, const QString &session, const QString &policyHashHex,
    const QString &outerSessionId, const QString &expectedRuntimeSessionId)
{
#ifdef Q_OS_ANDROID
    return AndroidController::instance()->requestSessionGuardReconcileRelease(
        operation, session, policyHashHex, outerSessionId, expectedRuntimeSessionId);
#elif defined(Q_OS_IOS)
    return IosController::Instance()->requestSessionGuardReconcileRelease(
        operation, session, policyHashHex, outerSessionId, expectedRuntimeSessionId);
#else
    Q_UNUSED(operation); Q_UNUSED(session); Q_UNUSED(policyHashHex);
    Q_UNUSED(outerSessionId); Q_UNUSED(expectedRuntimeSessionId);
    return false;
#endif
}

bool VpnConnection::nativeSessionGuardRecoveryPending() const
{
#if defined(Q_OS_ANDROID)
    return AndroidController::instance()->nativeGuardRecoveryPending();
#elif defined(Q_OS_IOS)
    return IosController::Instance()->nativeGuardRecoveryPending();
#elif defined(AMNEZIA_DESKTOP) && defined(Q_OS_MACOS) && !defined(MACOS_NE)
    return m_desktopNativeGuardRecoveryPending;
#else
    return false;
#endif
}

QJsonObject VpnConnection::nativeSessionGuardRecoveryEvent() const
{
#if defined(Q_OS_ANDROID)
    return AndroidController::instance()->nativeGuardRecoveryEvent();
#elif defined(Q_OS_IOS)
    return IosController::Instance()->nativeGuardRecoveryEvent();
#elif defined(AMNEZIA_DESKTOP) && defined(Q_OS_MACOS) && !defined(MACOS_NE)
    return m_desktopNativeGuardRecoveryEvent;
#else
    return {};
#endif
}

bool VpnConnection::requestNativeSessionGuardRecoveryResolution(
    const QJsonObject &exactRecoveryEvent, const QString &action,
    const QJsonObject &validatedPreparedConfiguration)
{
#if defined(Q_OS_ANDROID)
    return AndroidController::instance()->requestSessionGuardRecoveryResolution(
        exactRecoveryEvent, action, validatedPreparedConfiguration);
#elif defined(Q_OS_IOS)
    return IosController::Instance()->requestSessionGuardRecoveryResolution(
        exactRecoveryEvent, action, validatedPreparedConfiguration);
#elif defined(AMNEZIA_DESKTOP) && defined(Q_OS_MACOS) && !defined(MACOS_NE)
    if (!m_desktopNativeGuardRecoveryPending
        || !sameGuardIdentity(exactRecoveryEvent,
                              m_desktopNativeGuardRecoveryEvent)
        || (action != QLatin1String("adopt") && action != QLatin1String("stop"))
        || (action == QLatin1String("adopt")
            && validatedPreparedConfiguration.isEmpty())
        || (action == QLatin1String("stop")
            && !validatedPreparedConfiguration.isEmpty())) return false;
    const QJsonObject request{
        {QStringLiteral("type"),
         QStringLiteral("native_session_guard_recovery_resolve_v1")},
        {QStringLiteral("schema"), 1}, {QStringLiteral("action"), action},
        {QStringLiteral("event"), exactRecoveryEvent},
        {QStringLiteral("configuration"), validatedPreparedConfiguration},
    };
    const QJsonObject receipt = waitGuardReply(
        [&](const QSharedPointer<IpcInterfaceReplica> &iface) {
            return iface->nativeSessionGuardRecoveryResolveV1(request);
        });
    if (!exactRecoveryReceipt(receipt, action, exactRecoveryEvent)) return false;
    const QString kind = receipt.value(QStringLiteral("kind")).toString();
    if (kind == QLatin1String("adopted")) {
        if (validatedPreparedConfiguration.value(QStringLiteral("protocol"))
                != QLatin1String("awg")) return false;
        m_desktopNativeGuardEvent = exactRecoveryEvent;
        m_desktopNativeGuardEvent.insert(QStringLiteral("kind"), QStringLiteral("armed"));
        m_desktopNativeGuardEvent.insert(QStringLiteral("reason"), QString());
        m_desktopNativeGuardConfiguration = validatedPreparedConfiguration;
        const QString runtimeId = receipt.value(
            QStringLiteral("expected_runtime_session_id")).toString();
        m_vpnProtocol.reset(new WireguardProtocol(validatedPreparedConfiguration,
                                                  runtimeId));
        auto *awg = qobject_cast<WireguardProtocol *>(m_vpnProtocol.data());
        connect(awg, &WireguardProtocol::runtimeStatusChanged, this,
                &VpnConnection::consumeDesktopNativeRuntimeStatus);
        createProtocolConnections();
        if (!awg->adoptExactSession()) return false;
        m_desktopNativeGuardRecoveryPending = false;
        m_desktopNativeGuardRecoveryEvent = {};
    } else if (kind == QLatin1String("stopped_released")) {
        m_desktopNativeGuardEvent = {};
        m_desktopNativeGuardConfiguration = {};
        m_desktopNativeGuardRecoveryPending = false;
        m_desktopNativeGuardRecoveryEvent = {};
        m_vpnProtocol.reset();
    }
    QTimer::singleShot(0, this, [this, receipt]() {
        emit nativeSessionGuardRecoveryResolved(receipt);
    });
    return true;
#else
    Q_UNUSED(exactRecoveryEvent); Q_UNUSED(action); Q_UNUSED(validatedPreparedConfiguration);
    return false;
#endif
}

QString VpnConnection::nativeRuntimeSessionId() const
{
#if defined(Q_OS_IOS) || defined(MACOS_NE)
    return IosController::Instance()->runtimeSessionId();
#elif defined(Q_OS_ANDROID)
    return AndroidController::instance()->runtimeSessionId();
#elif defined(AMNEZIA_DESKTOP)
    if (const auto *xray = qobject_cast<XrayProtocol *>(m_vpnProtocol.data()))
        return xray->runtimeSessionId();
    if (const auto *awg = qobject_cast<WireguardProtocol *>(m_vpnProtocol.data()))
        return awg->runtimeSessionId();
    return {};
#else
    return {};
#endif
}

bool VpnConnection::nativeRuntimeIdentitySupported(Proto proto) const
{
#if defined(Q_OS_IOS) || defined(MACOS_NE) || defined(Q_OS_ANDROID)
    return proto == Proto::Awg || proto == Proto::WireGuard
            || proto == Proto::Xray || proto == Proto::SSXray;
#elif defined(AMNEZIA_DESKTOP)
    return proto == Proto::Awg || proto == Proto::WireGuard
            || proto == Proto::Xray || proto == Proto::SSXray;
#else
    Q_UNUSED(proto);
    return false;
#endif
}

bool VpnConnection::nativeRuntimeIdentitySupported() const
{
    // The bundled registry promises both AWG and Xray. Do not register that
    // bundle on a platform that can identify only one of its native sessions.
    return nativeRuntimeIdentitySupported(Proto::Awg)
            && nativeRuntimeIdentitySupported(Proto::Xray);
}

bool VpnConnection::nativeSessionGuardSupported(Proto proto) const
{
#if defined(Q_OS_ANDROID)
    if (proto == Proto::Awg || proto == Proto::WireGuard)
        return TRIBE_ANDROID_AWG_GUARD_RECEIPT == 1;
    if (proto == Proto::Xray || proto == Proto::SSXray)
        return TRIBE_ANDROID_XRAY_GUARD_RECEIPT == 1;
#elif defined(Q_OS_IOS)
    if (proto == Proto::Awg || proto == Proto::WireGuard)
        return TRIBE_IOS_AWG_GUARD_RECEIPT == 1;
    if (proto == Proto::Xray || proto == Proto::SSXray)
        return TRIBE_IOS_XRAY_GUARD_RECEIPT == 1;
#elif defined(MACOS_NE)
    if (proto == Proto::Awg || proto == Proto::WireGuard)
        return TRIBE_MACOS_NE_AWG_GUARD_RECEIPT == 1;
    if (proto == Proto::Xray || proto == Proto::SSXray)
        return TRIBE_MACOS_NE_XRAY_GUARD_RECEIPT == 1;
#elif defined(AMNEZIA_DESKTOP) && defined(Q_OS_MACOS)
    if (proto == Proto::Awg || proto == Proto::WireGuard)
        return TRIBE_MACOS_DAEMON_AWG_GUARD_RECEIPT == 1;
    if (proto == Proto::Xray || proto == Proto::SSXray)
        return TRIBE_MACOS_DAEMON_XRAY_GUARD_RECEIPT == 1;
#else
    Q_UNUSED(proto);
#endif
    return false;
}

void VpnConnection::setRepositories(SecureServersRepository* serversRepository, SecureAppSettingsRepository* appSettingsRepository)
{
    m_serversRepository = serversRepository;
    m_appSettingsRepository = appSettingsRepository;
}

void VpnConnection::addSitesRoutes(const QString &gw, amnezia::RouteMode mode)
{
#ifdef AMNEZIA_DESKTOP
    if (!m_appSettingsRepository) {
        qCritical() << "VpnConnection::addSitesRoutes: repositories not initialized";
        return;
    }

    QStringList ips;
    QStringList sites;
    const QVariantMap &m = m_appSettingsRepository->vpnSites(mode);
    for (auto i = m.constBegin(); i != m.constEnd(); ++i) {
        if (NetworkUtilities::checkIpSubnetFormat(i.key())) {
            ips.append(i.key());
        } else {
            const QStringList siteIps = SecureAppSettingsRepository::siteIpList(i.value());
            for (const QString &ip : siteIps) {
                if (NetworkUtilities::checkIpSubnetFormat(ip)) {
                    ips.append(ip);
                }
            }
            sites.append(i.key());
        }
    }
    ips.removeDuplicates();

    IpcClient::withInterface([&](QSharedPointer<IpcInterfaceReplica> iface) {
        iface->routeAddList(gw, ips);
    });

    auto remainingLookups = QSharedPointer<int>::create(sites.size());
    auto needFlush = QSharedPointer<bool>::create(false);

    // re-resolve domains
    for (const QString &site : sites) {
        const auto &cbResolv = [this, site, gw, mode, ips, remainingLookups, needFlush](const QHostInfo &hostInfo) {
            QStringList resolvedIps;
            for (const QHostAddress &addr : hostInfo.addresses()) {
                if (addr.protocol() == QAbstractSocket::NetworkLayerProtocol::IPv4Protocol) {
                    resolvedIps.append(addr.toString());
                }
            }
            resolvedIps.removeDuplicates();
            qDebug() << "[SplitTunneling] addSitesRoutes resolved" << site << "->" << resolvedIps;

            QStringList newIps;
            for (const QString &ip : resolvedIps) {
                if (!ips.contains(ip)) {
                    IpcClient::withInterface([gw, ip](QSharedPointer<IpcInterfaceReplica> iface) {
                        iface->routeAddList(gw, QStringList() << ip);
                    });
                    newIps.append(ip);
                }
            }

            if (!newIps.isEmpty()) {
                m_appSettingsRepository->addVpnSite(mode, site, newIps);
                *needFlush = true;
            }

            if (--(*remainingLookups) > 0)
                return;

            if (!*needFlush)
                return;

            // Async flush: never waitForFinished() here — that re-enters the event loop and
            // can re-enter this QHostInfo callback until the stack overflows (0xc00000fd).
            IpcClient::withInterface([this](QSharedPointer<IpcInterfaceReplica> iface) {
                QRemoteObjectPendingReply<bool> reply = iface->flushDns();
                auto *watcher = new QRemoteObjectPendingCallWatcher(reply, this);
                QObject::connect(watcher, &QRemoteObjectPendingCallWatcher::finished, this,
                        [](QRemoteObjectPendingCallWatcher *call) {
                            if (call->error() != QRemoteObjectPendingCall::NoError
                                || !call->returnValue().toBool()) {
                                qWarning() << "VpnConnection::addSitesRoutes: Failed to flush DNS";
                            }
                            call->deleteLater();
                        });
            });
        };
        QHostInfo::lookupHost(site, this, cbResolv);
    }
#endif
}

void VpnConnection::addPreparedSitesRoutes(const QString &gw)
{
#ifdef AMNEZIA_DESKTOP
    // AVPN: v2 snapshots contain only already-resolved, bounded CIDR/IP entries. No repository
    // lookup or asynchronous DNS mutation is permitted after the final envelope sanitizer.
    QStringList routes;
    const QJsonArray values = m_vpnConfiguration.value(configKey::splitTunnelSites).toArray();
    routes.reserve(values.size());
    for (const QJsonValue &value : values)
        if (value.isString())
            routes.append(value.toString());
    IpcClient::withInterface([gw, routes](QSharedPointer<IpcInterfaceReplica> iface) {
        iface->routeAddList(gw, routes);
    });
#else
    Q_UNUSED(gw);
#endif
}

QSharedPointer<VpnProtocol> VpnConnection::vpnProtocol() const
{
    return m_vpnProtocol;
}

void VpnConnection::disconnectSlots()
{
    if (m_vpnProtocol) {
        m_vpnProtocol->disconnect();
    }
}

ErrorCode VpnConnection::lastError() const
{
#ifdef Q_OS_ANDROID
    return ErrorCode::AndroidError;
#endif

    if (m_vpnProtocol.isNull()) {
        return ErrorCode::InternalError;
    }

    return m_vpnProtocol.data()->lastError();
}

Vpn::ConnectionState VpnConnection::connectionState() const
{
    return m_connectionState;
}

void VpnConnection::connectToVpn(const QString &serverId, DockerContainer container, const QJsonObject &vpnConfiguration)
{
    connectToVpnImpl(serverId, container, vpnConfiguration, false);
}

void VpnConnection::connectToVpnWithPreparedPolicy(
    const QString &serverId, DockerContainer container, const QJsonObject &vpnConfiguration)
{
    // AVPN: the serviceEngine policy compiler performs the final exact-envelope sanitizer before
    // entering here. Legacy callers stay on connectToVpn() and retain repository compilation.
    connectToVpnImpl(serverId, container, vpnConfiguration, true);
}

void VpnConnection::connectToVpnImpl(const QString &serverId, DockerContainer container,
                                     const QJsonObject &vpnConfiguration,
                                     bool hasPreparedPolicy)
{
    if (!m_appSettingsRepository || !m_serversRepository) {
        qCritical() << "VpnConnection::connectToVpn: repositories not initialized";
        setConnectionState(Vpn::ConnectionState::Error);
        return;
    }

    const amnezia::RouteMode dispatchRouteMode = hasPreparedPolicy
        ? static_cast<amnezia::RouteMode>(vpnConfiguration.value(configKey::splitTunnelType)
                                             .toInt(amnezia::RouteMode::VpnAllSites))
        : m_appSettingsRepository->routeMode();
    qDebug() << QString("Trying to connect to VPN, server id is %1, container is %2, route mode is")
                        .arg(serverId)
                        .arg(ContainerUtils::containerToString(container))
             << dispatchRouteMode;

    m_activeContainer = container; // AVPN v2: preserve exact dispatch identity for routes/DNS.
    m_hasPreparedConnectionPolicy = hasPreparedPolicy; // AVPN: immutable local-policy ownership.
    m_remoteAddress = NetworkUtilities::getIPAddress(vpnConfiguration.value(configKey::hostName).toString());
    setConnectionState(Vpn::ConnectionState::Connecting);

    m_vpnConfiguration = vpnConfiguration;

#ifdef AMNEZIA_DESKTOP
    if (m_vpnProtocol) {
        disconnect(m_vpnProtocol.data(), &VpnProtocol::protocolError, this, &VpnConnection::vpnProtocolError);
        // AVPN (2×deactivate fix, 2026-07-10): stop()/reset() старого протокола синхронно эмитят
        // транзитный Disconnected — он приходил ПОСЛЕ уже выставленного Connecting, движок принимал
        // его за терминал и передёргивал старт заново (второй deactivate/activate на один клик,
        // лишний цикл протокола). Глотаем ТОЛЬКО это синхронное эхо (флаг строго вокруг вызовов);
        // любой асинхронный Disconnected по-прежнему доходит.
        m_swallowTransitionalDisconnected = true;
        m_vpnProtocol->stop();
        m_vpnProtocol.reset();
        m_swallowTransitionalDisconnected = false;
    }
    if (!m_hasPreparedConnectionPolicy)
        appendKillSwitchConfig();
#endif

    if (!m_hasPreparedConnectionPolicy)
        appendSplitTunnelingConfig();

#if !defined(Q_OS_ANDROID) && !defined(Q_OS_IOS) && !defined(MACOS_NE)
    m_vpnProtocol.reset(VpnProtocol::factory(container, m_vpnConfiguration));
    if (!m_vpnProtocol) {
        setConnectionState(Vpn::ConnectionState::Error);
        return;
    }
    m_vpnProtocol->prepare();
#elif defined Q_OS_ANDROID
    androidVpnProtocol = createDefaultAndroidVpnProtocol();
    createAndroidConnections();

    m_vpnProtocol.reset(androidVpnProtocol);
#elif defined Q_OS_IOS || defined(MACOS_NE)
    Proto proto = ContainerUtils::defaultProtocol(container);
    IosController::Instance()->connectVpn(proto, m_vpnConfiguration);
    // AVPN (аудит N5): UniqueConnection — путь Error→повторный connectToVpn не проходит через
    // disconnectFromVpn (там единственный disconnect этого коннекта) → дубликаты копились.
    connect(&m_checkTimer, &QTimer::timeout, IosController::Instance(), &IosController::checkStatus,
            Qt::UniqueConnection);
    return;
#endif

    createProtocolConnections();

    if (ErrorCode err = m_vpnProtocol->start(); err != ErrorCode::NoError) {
        setConnectionState(Vpn::ConnectionState::Error);
        emit vpnProtocolError(err);
    }
}

void VpnConnection::createProtocolConnections()
{
    connect(m_vpnProtocol.data(), &VpnProtocol::protocolError, this, &VpnConnection::vpnProtocolError);
    connect(m_vpnProtocol.data(), &VpnProtocol::connectionStateChanged, this, &VpnConnection::setConnectionState);
    connect(m_vpnProtocol.data(), SIGNAL(bytesChanged(quint64, quint64)), this, SLOT(onBytesChanged(quint64, quint64)));

#ifdef AMNEZIA_DESKTOP
    if (auto *xray = qobject_cast<XrayProtocol *>(m_vpnProtocol.data())) {
        // Catalog-v2 status first passes through the exact outer-guard
        // running/stopped receipt bridge. Legacy Xray has no such lease.
        if (m_desktopNativeGuardEvent.isEmpty()) {
            connect(xray, &XrayProtocol::runtimeStatusChanged,
                    this, &VpnConnection::nativeRuntimeStatusChanged);
        }
    }
    IpcClient::withInterface([this](QSharedPointer<IpcInterfaceReplica> rep) {
        connect(rep.data(), &IpcInterfaceReplica::networkChanged, this, &VpnConnection::reconnectToVpn, Qt::QueuedConnection);
        connect(rep.data(), &IpcInterfaceReplica::wakeup, this, &VpnConnection::reconnectToVpn, Qt::QueuedConnection);
    });
#endif
}

void VpnConnection::appendKillSwitchConfig()
{
    if (!m_appSettingsRepository) {
        qCritical() << "VpnConnection::appendKillSwitchConfig: repositories not initialized";
        return;
    }

    m_vpnConfiguration.insert(configKey::killSwitchOption, QVariant(m_appSettingsRepository->isKillSwitchEnabled()).toString());
    m_vpnConfiguration.insert(configKey::allowedDnsServers, QVariant(m_appSettingsRepository->getAllowedDnsServers()).toJsonValue());
}

void VpnConnection::appendSplitTunnelingConfig()
{
    if (!m_appSettingsRepository) {
        qCritical() << "VpnConnection::appendSplitTunnelingConfig: repositories not initialized";
        return;
    }

    bool allowSiteBasedSplitTunneling = true;

    // this block is for old native configs and for old self-hosted configs
    auto protocolName = m_vpnConfiguration.value(configKey::vpnProto).toString();
    if (protocolName == ProtocolUtils::protoToString(Proto::Awg) || protocolName == ProtocolUtils::protoToString(Proto::WireGuard)) {
        allowSiteBasedSplitTunneling = false;
        auto configData = m_vpnConfiguration.value(protocolName + "_config_data").toObject();
        if (configData.value(configKey::allowedIps).isString()) {
            QJsonArray allowedIpsJsonArray = QJsonArray::fromStringList(configData.value(configKey::allowedIps).toString().split(", "));
            configData.insert(configKey::allowedIps, allowedIpsJsonArray);
            m_vpnConfiguration.insert(protocolName + "_config_data", configData);
        } else if (configData.value(configKey::allowedIps).isUndefined()) {
            auto nativeConfig = configData.value(configKey::config).toString();
            auto nativeConfigLines = nativeConfig.split("\n");
            for (auto &line : nativeConfigLines) {
                if (line.contains("AllowedIPs")) {
                    auto allowedIpsString = line.split(" = ");
                    if (allowedIpsString.size() < 1) {
                        break;
                    }
                    QJsonArray allowedIpsJsonArray = QJsonArray::fromStringList(allowedIpsString.at(1).split(", "));
                    configData.insert(configKey::allowedIps, allowedIpsJsonArray);
                    m_vpnConfiguration.insert(protocolName + "_config_data", configData);
                    break;
                }
            }
        }

        if (configData.value(configKey::persistentKeepAlive).isUndefined()) {
            auto nativeConfig = configData.value(configKey::config).toString();
            auto nativeConfigLines = nativeConfig.split("\n");
            for (auto &line : nativeConfigLines) {
                if (line.contains("PersistentKeepalive")) {
                    auto persistentKeepaliveString = line.split(" = ");
                    if (persistentKeepaliveString.size() > 1) {
                        configData.insert(configKey::persistentKeepAlive, persistentKeepaliveString.at(1));
                        m_vpnConfiguration.insert(protocolName + "_config_data", configData);
                    }
                    break;
                }
            }
        }

        QJsonArray allowedIpsJsonArray = configData.value(configKey::allowedIps).toArray();
        if (allowedIpsJsonArray.contains("0.0.0.0/0") && allowedIpsJsonArray.contains("::/0")) {
            allowSiteBasedSplitTunneling = true;
        }
    }

    amnezia::RouteMode routeMode = amnezia::RouteMode::VpnAllSites;
    QJsonArray sitesJsonArray;
    if (m_appSettingsRepository->isSitesSplitTunnelingEnabled()) {
        routeMode = m_appSettingsRepository->routeMode();

        if (allowSiteBasedSplitTunneling) {
            QStringList sites;
            const QVariantMap &m = m_appSettingsRepository->vpnSites(routeMode);
            for (auto i = m.constBegin(); i != m.constEnd(); ++i) {
                if (NetworkUtilities::checkIpSubnetFormat(i.key())) {
                    sites.append(i.key());
                }
#if defined(Q_OS_IOS) || defined(Q_OS_ANDROID) || defined(MACOS_NE)
                // AVPN (IPv6 split): checkIpSubnetFormat — IPv4-only и молча выбрасывал 2174 v6-префикса
                // ru_prefixes.h, при том что туннель забирает ::/0 → на dual-stack операторах AAAA-трафик
                // рунета шёл В туннель (загран-IP) при включённом «АвтоVPN». iOS (IPAddressRange →
                // ipv6ExcludedRoutes) и Android (InetNetwork/excludeRoute) v6 переваривают. Desktop-путь
                // НЕ гейтим: localsocketcontroller хардкодит isIpv6:false — v6 туда слать нельзя,
                // пока демон-тракт не научен (там остаётся прежнее v4-only поведение).
                // Встроено в новую апстрим-структуру f73697d3 (siteIpList/QStringList): v6-ключ — сразу,
                // v6-значения — из списка IP резолва ниже.
                else if (avpn::isIpv6Cidr(i.key())) {
                    sites.append(i.key());
                }
#endif
                else {
                    const QStringList siteIps = SecureAppSettingsRepository::siteIpList(i.value());
                    for (const QString &ip : siteIps) {
                        if (NetworkUtilities::checkIpSubnetFormat(ip)) {
                            sites.append(ip);
                        }
#if defined(Q_OS_IOS) || defined(Q_OS_ANDROID) || defined(MACOS_NE)
                        else if (avpn::isIpv6Cidr(ip)) {
                            sites.append(ip);
                        }
#endif
                    }
                }
            }
            sites.removeDuplicates();
            for (const auto &site : sites) {
                sitesJsonArray.append(site);
            }

            if (sitesJsonArray.isEmpty()) {
                routeMode = amnezia::RouteMode::VpnAllSites;
            } else if (routeMode == amnezia::RouteMode::VpnOnlyForwardSites) {
                // Allow traffic to Amnezia DNS
                sitesJsonArray.append(m_vpnConfiguration.value(configKey::dns1).toString());
                sitesJsonArray.append(m_vpnConfiguration.value(configKey::dns2).toString());
            }
        }
    }

    m_vpnConfiguration.insert(configKey::splitTunnelType, routeMode);
    m_vpnConfiguration.insert(configKey::splitTunnelSites, sitesJsonArray);

    amnezia::AppsRouteMode appsRouteMode = amnezia::AppsRouteMode::VpnAllApps;
    QJsonArray appsJsonArray;
    if (m_appSettingsRepository->isAppsSplitTunnelingEnabled()) {
        appsRouteMode = m_appSettingsRepository->appsRouteMode();

        auto apps = m_appSettingsRepository->vpnApps(appsRouteMode);
        for (const auto &app : apps) {
            appsJsonArray.append(app.appPath.isEmpty() ? app.packageName : app.appPath);
        }

        if (appsJsonArray.isEmpty()) {
            appsRouteMode = amnezia::AppsRouteMode::VpnAllApps;
        }
    }

    m_vpnConfiguration.insert(configKey::appSplitTunnelType, appsRouteMode);
    m_vpnConfiguration.insert(configKey::splitTunnelApps, appsJsonArray);

    qDebug() << QString("Site split tunneling is %1, route mode is %2")
                        .arg(m_appSettingsRepository->isSitesSplitTunnelingEnabled() ? "enabled" : "disabled")
                        .arg(routeMode);
    qDebug() << QString("App split tunneling is %1, route mode is %2")
                        .arg(m_appSettingsRepository->isAppsSplitTunnelingEnabled() ? "enabled" : "disabled")
                        .arg(appsRouteMode);
}

#ifdef Q_OS_ANDROID
void VpnConnection::restoreConnection()
{
    createAndroidConnections();

    m_vpnProtocol.reset(androidVpnProtocol);

    createProtocolConnections();
}

void VpnConnection::createAndroidConnections()
{
    androidVpnProtocol = createDefaultAndroidVpnProtocol();

    connect(AndroidController::instance(), &AndroidController::connectionStateChanged, androidVpnProtocol,
            &AndroidVpnProtocol::setConnectionState);
    connect(AndroidController::instance(), &AndroidController::statisticsUpdated, androidVpnProtocol, &AndroidVpnProtocol::setBytesChanged);
}

AndroidVpnProtocol *VpnConnection::createDefaultAndroidVpnProtocol()
{
    return new AndroidVpnProtocol(m_vpnConfiguration);
}
#endif

QString VpnConnection::bytesPerSecToText(quint64 bytes)
{
    double mbps = bytes * 8 / 1e6;
    return QString("%1 %2").arg(QString::number(mbps, 'f', 2)).arg(tr("Mbps")); // Mbit/s
}

void VpnConnection::reconnectToVpn() {
    if (m_vpnProtocol.isNull())
        return;

    if (m_connectionState != Vpn::ConnectionState::Connected) {
        qWarning() << QString("Reconnect triggered on %1 during inappropriate state: %2; ignoring slot")
                              .arg(QMetaEnum::fromType<Vpn::ConnectionState>().valueToKey(m_connectionState));
        return;
    }

    qDebug() << "Reconnect triggered. Reconnecting to the server";

    setConnectionState(Vpn::ConnectionState::Reconnecting);

    // AVPN (IPC-stall fix, 2026-07-10, КОРЕНЬ «клик Connect мёртв до перезапуска приложения» на
    // Windows): маска Reconnecting глотает Disconnected (swallow в setConnectionState — нужен для
    // транзитного эха stop() и «disconnected»-ответа демона на deactivate). Но если демон умирает
    // В ОКНЕ реконнекта (рестарт/переустановка сервиса под живым GUI — networkChanged от гаснущего
    // демона и триггерит этот слот), терминальный сигнал не приходит НИКОГДА: m_connectionState
    // застревал в Reconnecting навсегда, reconcile-машина вечно ждала терминала (промежуточное
    // состояние, её сторож не взведён — операция не её). Сторож: не вышли из Reconnecting за 20с
    // (штатный реконнект — секунды; iOS-хендшейк-окно 12с сюда не ходит, слот десктоп-only) →
    // честный Disconnected, машина разблокирована, подключение — вручную (§13, авто-коннекта нет).
    const quint64 generation = ++m_reconnectGeneration;
    QTimer::singleShot(20000, this, [this, generation]() {
        if (generation != m_reconnectGeneration)
            return;  // за 20с начался следующий реконнект — это не наше окно
        if (m_connectionState != Vpn::ConnectionState::Reconnecting)
            return;
        qWarning() << "reconnect watchdog: still Reconnecting after 20s — forcing Disconnected";
        m_connectionState = Vpn::ConnectionState::Disconnected;  // выйти из свалло-состояния ДО set
        setConnectionState(Vpn::ConnectionState::Disconnected);
    });

    m_vpnProtocol->stop();
    if (ErrorCode err = m_vpnProtocol->start(); err != ErrorCode::NoError) {
        setConnectionState(Vpn::ConnectionState::Error);
        emit vpnProtocolError(err);
    }
}

void VpnConnection::disconnectFromVpn()
{
#if defined(Q_OS_IOS) || defined(MACOS_NE)
    // iOS/macOS NE use IosController directly; m_vpnProtocol is not set there.
    // AVPN: НЕ эмитим синхронный Disconnected — реальный придёт из IosController (disconnectVpn эмитит
    // Disconnected сразу, если гасить нечего; иначе stopTunnel → vpnStatusDidChange → Disconnected). Так
    // реконнект на новый сервер НЕ стартует, пока старый туннель не дошёл до Disconnected (как в Amnezia;
    // иначе старт поверх Disconnecting → «Operation not permitted» → Network Error при смене сервера).
    setConnectionState(Vpn::ConnectionState::Disconnecting);
    disconnect(&m_checkTimer, &QTimer::timeout, IosController::Instance(), &IosController::checkStatus);
    IosController::Instance()->disconnectVpn();
    return;
#endif

    if (m_vpnProtocol.isNull()) {
        setConnectionState(Vpn::ConnectionState::Disconnected);
        return;
    }

    setConnectionState(Vpn::ConnectionState::Disconnecting);

#ifdef Q_OS_ANDROID
    auto *const connection = new QMetaObject::Connection;
    *connection = connect(AndroidController::instance(), &AndroidController::vpnStateChanged, this,
                          [this, connection](AndroidController::ConnectionState state) {
                              if (state == AndroidController::ConnectionState::DISCONNECTED) {
                                  setConnectionState(Vpn::ConnectionState::Disconnected);
                                  disconnect(*connection);
                                  delete connection;
                              }
                          });
#endif

    m_vpnProtocol->stop();

#if !defined(Q_OS_ANDROID) && !defined(AMNEZIA_DESKTOP)
    m_vpnProtocol->deleteLater();
#endif

    m_vpnProtocol = nullptr;
}

void VpnConnection::setConnectionState(Vpn::ConnectionState state) {
    onConnectionStateChanged(state);

#if !defined(Q_OS_IOS) && !defined(MACOS_NE)
    // AVPN: этот swallow — ТОЛЬКО для десктопного onReconnect() (protocol stop→start под маской
    // Reconnecting: транзитный Disconnected от stop() не должен ронять UI). На iOS/NE Reconnecting
    // эмитит IosController в окне handshake-ретраев (12–24с), и настоящий Disconnected от ОС
    // (NE убит/jetsam, другой VPN перехватил туннель, выключили в Настройках iOS) ОБЯЗАН дойти до
    // reconcile-машины: проглоченный сигнал оставлял m_connectionState в Reconnecting навсегда —
    // reconcile вечно ждал терминала, кнопка Connect была мертва до перезапуска приложения.
    // Состояние туннеля от ОС всегда авторитетно (CONNECT-INVARIANTS §7/§13).
    if (state == Vpn::Disconnected && m_connectionState == Vpn::Reconnecting)
        return;
    // AVPN (2×deactivate fix): синхронное эхо stop() старого протокола в connectToVpn — глотаем
    // строго на время вызова (см. флаг). Ловушку «застряли в Reconnecting навсегда» закрывает
    // 20с-сторож в reconnectToVpn().
    if (state == Vpn::Disconnected && m_swallowTransitionalDisconnected)
        return;
#endif

    m_connectionState = state;
    emit connectionStateChanged(state);
}
