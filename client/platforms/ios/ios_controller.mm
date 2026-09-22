#include "ios_controller.h"

#include <QDebug>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QThread>
#include <QEventLoop>
#include <QTimer>
#include <QUuid>
#include <memory>
#include "AvpnIntentController.h"

#import "ios_controller_wrapper.h"
#import <os/lock.h> // AVPN: os_unfair_lock — владение m_currentTunnel (ревью 2026-07-11)
#import "core/utils/swiftBridge.h"
#include "core/serviceEngine/TuningStore.h" // AVPN backend-first (Task 6): xray_* NE timeouts + network_change_debounce_ms

const char* Action::start = "start";
const char* Action::restart = "restart";
const char* Action::stop = "stop";
const char* Action::getTunnelId = "getTunnelId";
const char* Action::getStatus = "status";
const char* Action::rebind = "rebind"; // AVPN BUG-4 auto-heal

const char* MessageKey::action = "action";
const char* MessageKey::tunnelId = "tunnelId";
const char* MessageKey::config = "config";
const char* MessageKey::errorCode = "errorCode";
const char* MessageKey::host = "host";
const char* MessageKey::port = "port";
const char* MessageKey::isOnDemand = "is-on-demand";
const char* MessageKey::SplitTunnelType = "SplitTunnelType";
const char* MessageKey::SplitTunnelSites = "SplitTunnelSites";

using namespace ProtocolUtils;

#if !MACOS_NE
static UIViewController* getViewController() {
    UIApplication *application = [UIApplication sharedApplication];

    if (@available(iOS 13.0, *)) {
        for (UIScene *scene in application.connectedScenes) {
            if (scene.activationState != UISceneActivationStateForegroundActive) {
                continue;
            }

            if (![scene isKindOfClass:[UIWindowScene class]]) {
                continue;
            }

            UIWindowScene *windowScene = (UIWindowScene *)scene;

            for (UIWindow *window in windowScene.windows) {
                if (window.isKeyWindow && window.rootViewController) {
                    return window.rootViewController;
                }
            }

            for (UIWindow *window in windowScene.windows) {
                if (!window.isHidden && window.rootViewController) {
                    return window.rootViewController;
                }
            }
        }
    }

    for (UIWindow *window in application.windows) {
        if (window.isKeyWindow && window.rootViewController) {
            return window.rootViewController;
        }
    }

    for (UIWindow *window in application.windows) {
        if (window.rootViewController) {
            return window.rootViewController;
        }
    }

    return nil;
}
#endif

Vpn::ConnectionState iosStatusToState(NEVPNStatus status) {
  switch (status) {
    case NEVPNStatusInvalid:
        return Vpn::ConnectionState::Unknown;
    case NEVPNStatusDisconnected:
        return Vpn::ConnectionState::Disconnected;
    case NEVPNStatusConnecting:
        return Vpn::ConnectionState::Connecting;
    case NEVPNStatusConnected:
        return Vpn::ConnectionState::Connected;
    case NEVPNStatusReasserting:
        return Vpn::ConnectionState::Connecting;
    case NEVPNStatusDisconnecting:
        return Vpn::ConnectionState::Disconnecting;
    default:
        return Vpn::ConnectionState::Unknown;
}
}

namespace {
constexpr int kHandshakeTimeoutMs = 12000;
constexpr uint64_t kHandshakeRxThreshold = 4096;
constexpr int kHandshakeMaxTimeouts = 3;   // AVPN: столько таймаутов без рукопожатия → Error + stop (нода недоступна).
                                           // NB (аудит N9): полный цикл 3×12с достижим только для OS-инициированных
                                           // стартов (App Intent/Настройки iOS); app-старт ограничен сторожем
                                           // reconcile-машины 15с (AvpnEngineQml m_watchdog) — это осознанно.
bool isWireGuardBasedProto(amnezia::Proto proto) {
    return proto == amnezia::Proto::WireGuard || proto == amnezia::Proto::Awg;
}

// AVPN (волна AWG 3.1 + Xray, этап D3): xray-пути NE (VLESS/Reality через libxray + tun2socks).
// У них нет рукопожатия в смысле WG — handshakeChanged не эмитим (0 = «неизвестно», §17.1),
// rx/tx приходят из tunnel_runtime_status_v1 (PacketTunnelProvider+Xray.swift, счётчики
// tun-интерфейса hev-socks5-tunnel; строки, кумулятив).
bool isXrayBasedProto(amnezia::Proto proto) {
    return proto == amnezia::Proto::Xray || proto == amnezia::Proto::SSXray;
}

QString stringFromResponse(NSDictionary *response, NSString *key) {
    id value = response[key];
    if ([value isKindOfClass:[NSString class]]) {
        return QString::fromNSString((NSString *)value);
    }
    return QString();
}

// AVPN backend-first (T20): handshake-пороги из rawConfig (numbers.handshake_timeout_ms /
// numbers.handshake_max_timeouts, засеяны VpnConnectionTunnelControl::up), фолбэк — константы
// выше. Пусто/не число → фолбэк (byte-for-byte старое поведение).
int intFromRawConfig(const QJsonObject &cfg, const char *key, int fallback) {
    const QJsonValue v = cfg.value(QLatin1String(key));
    return v.isDouble() ? v.toInt(fallback) : fallback;
}

uint64_t uint64FromResponse(NSDictionary *response, NSString *key, uint64_t fallback = 0) {
    id value = response[key];
    if (!value || value == [NSNull null]) {
        return fallback;
    }
    if ([value isKindOfClass:[NSNumber class]]) {
        return [(NSNumber *)value unsignedLongLongValue];
    }
    if ([value isKindOfClass:[NSString class]]) {
        const char *str = [(NSString *)value UTF8String];
        if (str && *str) {
            return strtoull(str, nullptr, 10);
        }
    }
    return fallback;
}

long long int64FromResponse(NSDictionary *response, NSString *key, long long fallback = 0) {
    id value = response[key];
    if (!value || value == [NSNull null]) {
        return fallback;
    }
    if ([value isKindOfClass:[NSNumber class]]) {
        return [(NSNumber *)value longLongValue];
    }
    if ([value isKindOfClass:[NSString class]]) {
        const char *str = [(NSString *)value UTF8String];
        if (str && *str) {
            return strtoll(str, nullptr, 10);
        }
    }
    return fallback;
}
}

namespace {
IosController* s_instance = nullptr;
}

IosController::IosController() : QObject()
{
    s_instance = this;
    m_iosControllerWrapper = [[IosControllerWrapper alloc] initWithCppController:this];

    [[NSNotificationCenter defaultCenter]
        removeObserver: (__bridge NSObject *)m_iosControllerWrapper];
    [[NSNotificationCenter defaultCenter]
        addObserver: (__bridge NSObject *)m_iosControllerWrapper selector:@selector(vpnStatusDidChange:) name:NEVPNStatusDidChangeNotification object:nil];
    [[NSNotificationCenter defaultCenter]
        addObserver: (__bridge NSObject *)m_iosControllerWrapper selector:@selector(vpnConfigurationDidChange:) name:NEVPNConfigurationChangeNotification object:nil];

}

void IosController::emitConnectionStateIfChanged(Vpn::ConnectionState state)
{
    if (m_lastEmittedState == state) {
        return;
    }
    m_lastEmittedState = state;
#if defined(Q_OS_IOS)
    Avpn_recordLifecycle(QStringLiteral("os_state"), {{QStringLiteral("state"), int(state)},
        {QStringLiteral("session_generation"), m_sessionMetadata.value(QStringLiteral("generation"))},
        {QStringLiteral("operation_generation"), qulonglong(m_operationGeneration)},
        {QStringLiteral("request_id"), qulonglong(m_statusRequests.requestId())}});
#endif
    emit connectionStateChanged(state);
}

IosController* IosController::Instance() {
    if (!s_instance) {
        s_instance = new IosController();
    }

    return s_instance;
}

// AVPN (краш-фикс UAF, 2026-07-06): единственная точка владения m_currentTunnel. Без retain
// менеджер из autoreleased-массива loadAllFromPreferences жил только в кеше NE-фреймворка;
// после ночного фона кеш освобождался → m_checkTimer (QThread) → checkStatus →
// objc_msgSend(m_currentTunnel, 'connection') по трупу = SIGSEGV (AmneziaVPN-2026-07-06-091741.ips).
// AVPN (ревью 2026-07-11): владение m_currentTunnel — строго под локом. Гонка: checkStatus
// уходит на глобальную dispatch-очередь и читает менеджер с фонового треда, а быстрый реконнект
// (connectVpn → setCurrentTunnel(nil)) параллельно делает release на главном → UAF (тот же класс,
// что AmneziaVPN-2026-07-06-091741.ips). IosController — синглтон, статик-лок достаточен.
static os_unfair_lock s_tunnelOwnershipLock = OS_UNFAIR_LOCK_INIT;

void IosController::setCurrentTunnel(NETunnelProviderManager *tunnel)
{
    os_unfair_lock_lock(&s_tunnelOwnershipLock);
    if (tunnel == m_currentTunnel) {
        os_unfair_lock_unlock(&s_tunnelOwnershipLock);
        return;
    }
    NETunnelProviderManager *old = m_currentTunnel;
    [tunnel retain];
    m_currentTunnel = tunnel;
    ++m_statusGeneration;
    m_statusRequests.invalidate();
    os_unfair_lock_unlock(&s_tunnelOwnershipLock);
    [old release]; // release ВНЕ лока (dealloc может дёргать KVO/колбэки)
}

NETunnelProviderManager *IosController::retainedCurrentTunnel()
{
    os_unfair_lock_lock(&s_tunnelOwnershipLock);
    NETunnelProviderManager *t = [m_currentTunnel retain];
    os_unfair_lock_unlock(&s_tunnelOwnershipLock);
    return t; // caller обязан release
}

QVariantMap IosController::sessionMetadata() const
{
    return m_sessionMetadata; // controller/engine share Qt affinity; all updates are marshalled here
}

NETunnelProviderManager *IosController::selectOurManager(NSArray<NETunnelProviderManager *> *managers)
{
    NETunnelProviderManager *selected = nil;
    int best = -1;
    NSString *currentId = ((NETunnelProviderProtocol *)m_currentTunnel.protocolConfiguration).providerConfiguration[@"tribeManagerId"];
    for (NETunnelProviderManager *manager in managers) {
        if (!isOurManager(manager)) continue;
        const NEVPNStatus status = manager.connection.status;
        int rank = (status == NEVPNStatusConnected || status == NEVPNStatusReasserting) ? 30 :
                   status == NEVPNStatusConnecting ? 20 : status == NEVPNStatusDisconnecting ? 10 : 0;
        NSString *identity = ((NETunnelProviderProtocol *)manager.protocolConfiguration).providerConfiguration[@"tribeManagerId"];
        if (currentId && [currentId isEqual:identity]) ++rank;
        if (rank > best) { selected = manager; best = rank; }
    }
    return selected;
}

void IosController::restoreSessionMetadata(NETunnelProviderManager *manager)
{
    NETunnelProviderProtocol *proto = (NETunnelProviderProtocol *)manager.protocolConfiguration;
    NSDictionary *metadata = proto.providerConfiguration[@"tribeSessionMetadata"];
    QVariantMap restored;
    if ([metadata isKindOfClass:[NSDictionary class]] && [metadata[@"schema_version"] intValue] == 1) {
        NSData *data = [NSJSONSerialization dataWithJSONObject:metadata options:0 error:nil];
        restored = QJsonDocument::fromJson(QByteArray((const char *)data.bytes, data.length)).object().toVariantMap();
    }
    if (proto.providerConfiguration[@"xray"]) m_proto = amnezia::Proto::Xray;
    else if (proto.providerConfiguration[@"ovpn"]) m_proto = amnezia::Proto::OpenVpn;
    else m_proto = amnezia::Proto::Awg;
    if (!restored.isEmpty() && m_sessionMetadata.value(QStringLiteral("configuration_generation")) == restored.value(QStringLiteral("generation")))
        restored = m_sessionMetadata; // prefs identify configuration, runtime status identifies each NE run
    if (m_sessionMetadata != restored) {
        m_sessionMetadata = restored;
        emit sessionMetadataChanged(restored);
    }
}

NSDictionary *IosController::providerMetadata()
{
    QJsonObject metadata = m_rawConfig.value(QStringLiteral("tribeSessionMetadata")).toObject();
    metadata.insert(QStringLiteral("generation"), QUuid::createUuid().toString(QUuid::WithoutBraces));
    const QByteArray encoded = QJsonDocument(metadata).toJson(QJsonDocument::Compact);
    NSDictionary *value = [NSJSONSerialization JSONObjectWithData:[NSData dataWithBytes:encoded.constData() length:encoded.size()] options:0 error:nil];
    return value ?: @{};
}

bool IosController::operationCurrent(uint64_t generation) const
{
    if (generation != m_operationGeneration || !m_connectPending) return false;
#if defined(Q_OS_IOS)
    return m_operationIntentGeneration == Avpn_currentIntentGeneration();
#else
    return true;
#endif
}

bool IosController::initialize()
{
    // Async errors are signals; returning a stack bool before loadAll completed was meaningless.
    requestReconcileStatus();
    return true;
}

void IosController::requestReconcileStatus()
{
    if (QThread::currentThread() != thread()) {
        QMetaObject::invokeMethod(this, [this] { requestReconcileStatus(); }, Qt::QueuedConnection);
        return;
    }
    if (m_connectPending || m_reconcileScheduled) return;
    m_reconcileScheduled = true;
    const uint64_t request = ++m_reconcileGeneration;
    const uint64_t operation = m_operationGeneration;
    QTimer::singleShot(3000, this, [this, request] {
        if (m_reconcileGeneration != request || !m_reconcileScheduled) return;
        ++m_reconcileGeneration;
        m_reconcileScheduled = false;
        qWarning() << "[ios lifecycle] preference reconciliation timed out";
        if (!m_currentTunnel) emitConnectionStateIfChanged(Vpn::ConnectionState::Error);
        // Absence of a callback is NOT proof the tunnel is down.
    });
    [NETunnelProviderManager loadAllFromPreferencesWithCompletionHandler:^(NSArray<NETunnelProviderManager *> *managers, NSError *error) {
        [managers retain]; [error retain];
        QMetaObject::invokeMethod(this, [this, managers, error, request, operation] {
            if (request == m_reconcileGeneration && operation == m_operationGeneration) {
                m_reconcileScheduled = false;
                if (error) {
                    qWarning() << "[ios lifecycle] preference reconciliation failed" << error.code;
                    if (!m_currentTunnel) emitConnectionStateIfChanged(Vpn::ConnectionState::Error);
                } else {
                    NETunnelProviderManager *manager = selectOurManager(managers);
                    if (manager) {
                        setCurrentTunnel(manager);
                        restoreSessionMetadata(manager);
                        vpnStatusDidChange(manager.connection);
                    } else if (!m_currentTunnel || m_currentTunnel.connection.status == NEVPNStatusDisconnected ||
                               m_currentTunnel.connection.status == NEVPNStatusInvalid) {
                        setCurrentTunnel(nil);
                        restoreSessionMetadata(nil);
                        emit disconnectReason(QStringLiteral("profile_missing"), true);
                        emitConnectionStateIfChanged(Vpn::ConnectionState::Disconnected);
                    } // Loaded no profile but an old session still active: never invent its terminal.
                }
            }
            [managers release]; [error release];
        }, Qt::QueuedConnection);
    }];
}

bool IosController::connectVpn(amnezia::Proto proto, const QJsonObject& configuration)
{
    if (QThread::currentThread() != thread()) {
        const uint64_t queuedOperation = ++m_operationGeneration;
        QMetaObject::invokeMethod(this, [this, proto, configuration, queuedOperation] {
            if (queuedOperation == m_operationGeneration) connectVpn(proto, configuration);
        }, Qt::QueuedConnection);
        return true;
    }
    const uint64_t operation = ++m_operationGeneration;
    ++m_reconcileGeneration;
    m_reconcileScheduled = false;
    m_connectPending = true;
#if defined(Q_OS_IOS)
    m_operationIntentGeneration = Avpn_currentIntentGeneration();
#endif
    m_proto = proto;
    m_rawConfig = configuration;
    [m_serverAddress release];
    m_serverAddress = [configuration.value(configKey::hostName).toString().toNSString() copy];
    m_handshakeConfirmed = false;
    m_handshakeAwaiting = false;
    m_handshakeTimer.invalidate();
    m_handshakeTimeouts = 0;
    m_statusRequests.invalidate();
    ++m_statusGeneration;
    m_rxBytes = m_txBytes = 0;
    m_lastXrayStartFailure.clear();
    m_lastXrayCoreLogTail.clear();
    m_lastEmittedState = Vpn::ConnectionState::Unknown;
    QTimer::singleShot(10000, this, [this, operation] {
        if (m_operationGeneration != operation || !m_connectPending) return;
        ++m_operationGeneration; // save/load callbacks cannot start after the deadline
        m_connectPending = false;
        emitConnectionStateIfChanged(Vpn::ConnectionState::Error);
        requestReconcileStatus();
    });
    [NETunnelProviderManager loadAllFromPreferencesWithCompletionHandler:^(NSArray<NETunnelProviderManager *> *managers, NSError *error) {
        [managers retain]; [error retain];
        QMetaObject::invokeMethod(this, [this, managers, error, operation] {
            if (operationCurrent(operation)) {
                if (error) {
                    m_connectPending = false;
                    emitConnectionStateIfChanged(Vpn::ConnectionState::Error);
                } else {
                    NETunnelProviderManager *manager = selectOurManager(managers);
                    if (manager && manager.connection.status != NEVPNStatusDisconnected && manager.connection.status != NEVPNStatusInvalid) {
                        // The engine must first obtain a real terminal before replacing a live profile.
                        setCurrentTunnel(manager);
                        m_connectPending = false;
                        restoreSessionMetadata(manager);
                        emitConnectionStateIfChanged(Vpn::ConnectionState::Error);
                        vpnStatusDidChange(manager.connection);
                    } else {
                        setCurrentTunnel(manager ?: [[[NETunnelProviderManager alloc] init] autorelease]);
                        m_currentTunnel.localizedDescription = @"Tribe VPN";
                        if (!configureSelectedTunnel()) {
                            m_connectPending = false;
                            emitConnectionStateIfChanged(Vpn::ConnectionState::Error);
                        }
                    }
                }
            }
            [managers release]; [error release];
        }, Qt::QueuedConnection);
    }];
    return true;
}

bool IosController::configureSelectedTunnel()
{
    switch (m_proto) {
    case amnezia::Proto::OpenVpn: return setupOpenVPN();
    case amnezia::Proto::WireGuard: return setupWireGuard();
    case amnezia::Proto::Awg: return setupAwg();
    case amnezia::Proto::Xray: return setupXray();
    case amnezia::Proto::SSXray: return setupSSXray();
    default: return false;
    }
}

void IosController::disconnectVpn()
{
    if (QThread::currentThread() != thread()) {
        const uint64_t queuedOperation = ++m_operationGeneration;
        QMetaObject::invokeMethod(this, [this, queuedOperation] {
            if (queuedOperation == m_operationGeneration) disconnectVpn();
        }, Qt::QueuedConnection);
        return;
    }
    ++m_operationGeneration;
    ++m_reconcileGeneration;
    m_reconcileScheduled = false;
    m_connectPending = false;
    m_localStopRequested = true;
    ++m_statusGeneration;
    m_statusRequests.invalidate();

    // AVPN: если гасить нечего (нет менеджера / нет сессии / уже опущен) — эмитим Disconnected СРАЗУ,
    // чтобы движок не повис в ожидании. Если сессия ЖИВАЯ — только stopTunnel; РЕАЛЬНЫЙ Disconnected
    // прилетит из vpnStatusDidChange (его и ждёт reconcile перед реконнектом на новый сервер — это и есть
    // «как в Amnezia»: не стартуем новый туннель, пока старый не дошёл до Disconnected).
    if (!m_currentTunnel) {
        // A stopped GUI may not have discovered an active Settings/Intent session yet.
        const uint64_t operation = m_operationGeneration;
        QTimer::singleShot(3000, this, [this, operation] {
            if (m_operationGeneration != operation || !m_localStopRequested) return;
            ++m_operationGeneration;
            m_localStopRequested = false;
            emitConnectionStateIfChanged(Vpn::ConnectionState::Error);
            requestReconcileStatus();
        });
        [NETunnelProviderManager loadAllFromPreferencesWithCompletionHandler:^(NSArray<NETunnelProviderManager *> *managers, NSError *error) {
            [managers retain]; [error retain];
            QMetaObject::invokeMethod(this, [this, managers, error, operation] {
                if (operation == m_operationGeneration) {
                    if (error) emitConnectionStateIfChanged(Vpn::ConnectionState::Error);
                    else {
                        NETunnelProviderManager *manager = selectOurManager(managers);
                        if (manager) {
                            setCurrentTunnel(manager);
                            restoreSessionMetadata(manager);
                            disconnectVpn();
                        } else {
                            m_localStopRequested = false;
                            emitConnectionStateIfChanged(Vpn::ConnectionState::Disconnected);
                        }
                    }
                }
                [managers release]; [error release];
            }, Qt::QueuedConnection);
        }];
        return;
    }
    if (![m_currentTunnel.connection isKindOfClass:[NETunnelProviderSession class]]) {
        emitConnectionStateIfChanged(Vpn::ConnectionState::Error);
        return;
    }
    NEVPNStatus st = m_currentTunnel.connection.status;
    if (st == NEVPNStatusDisconnected || st == NEVPNStatusInvalid) {
        m_localStopRequested = false;
        emit disconnectReason(QStringLiteral("expected_app_stop"), false);
        m_lastEmittedState = Vpn::ConnectionState::Disconnected;
        emit connectionStateChanged(Vpn::ConnectionState::Disconnected);
        return;
    }
    [(NETunnelProviderSession *)m_currentTunnel.connection stopTunnel];
}


void IosController::checkStatus()
{
    if (QThread::currentThread() != thread()) {
        QMetaObject::invokeMethod(this, [this] { checkStatus(); }, Qt::QueuedConnection);
        return;
    }

    // AVPN (ревью 2026-07-11): менеджер — только retained-копией (гонка с release на реконнекте),
    // ответ — только для СВОЕЙ сессии (gen): стейл-ответ старой сессии, долетевший после
    // реконнекта, перезаписывал m_rxBytes старым большим кумулятивом → следующая дельта
    // rxBytes - m_rxBytes уходила в quint64-underflow (~2^64) в bytesChanged.
    NETunnelProviderManager *tunnel = retainedCurrentTunnel();
    if (!tunnel) {
        return;
    }

    if (tunnel.connection.status != NEVPNStatusConnected) {
        [tunnel release];
        return;
    }

    const uint64_t gen = m_statusGeneration.load();
    const auto ticket = m_statusRequests.begin(gen);
    if (!ticket) { [tunnel release]; return; }
    const uint64_t request = *ticket;
    QTimer::singleShot(3000, this, [this, gen, request] {
        if (!m_statusRequests.complete(gen, request)) return;
        qWarning() << "[ios lifecycle] status deadline" << gen << request;
#if defined(Q_OS_IOS)
        Avpn_recordLifecycle(QStringLiteral("status_timeout"), {{QStringLiteral("generation"), qulonglong(gen)}, {QStringLiteral("request_id"), qulonglong(request)}});
#endif
    });

    NSString *actionKey = [NSString stringWithUTF8String:MessageKey::action];
    NSString *actionValue = [NSString stringWithUTF8String:Action::getStatus];
    NSString *tunnelIdKey = [NSString stringWithUTF8String:MessageKey::tunnelId];
    NSString *tunnelIdValue = !m_tunnelId.isEmpty() ? m_tunnelId.toNSString() : @"";

    NSDictionary* message = @{actionKey: actionValue, tunnelIdKey: tunnelIdValue};
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    // tunnel: наш retain (retainedCurrentTunnel) отпускается в КОНЦЕ блока — синхронно после
    // sendProviderMessage (ответ-хендлер менеджер не трогает; release в колбэке был бы двойным
    // при callback(nil)-ветках). Сам блок дополнительно держит tunnel как object-capture.
    sendVpnExtensionMessage(tunnel, message, [this, gen, request](NSDictionary* response){
        if (!response) {
            QMetaObject::invokeMethod(this, [this, gen, request]() {
                m_statusRequests.complete(gen, request);
            }, Qt::QueuedConnection);
            return;
        }

        QVariantMap metadata;
        if ([response[@"session_metadata"] isKindOfClass:[NSDictionary class]]) {
            NSData *data = [NSJSONSerialization dataWithJSONObject:response[@"session_metadata"] options:0 error:nil];
            metadata = QJsonDocument::fromJson(QByteArray((const char *)data.bytes, data.length)).object().toVariantMap();
        }
        const uint64_t txBytes = uint64FromResponse(response, @"tx_bytes");
        const uint64_t rxBytes = uint64FromResponse(response, @"rx_bytes");
        const long long last_handshake_time_sec = int64FromResponse(response, @"last_handshake_time_sec");
        // AVPN (этап D3): runtime_state xray-пути (starting/running/stopping/stopped/failed) —
        // только для лога; у WG-ответа ключа нет (пусто).
        const QString runtimeState = stringFromResponse(response, @"runtime_state");
        // AVPN: причину отказа старта ядра снимаем ЗДЕСЬ — NSDictionary* response живёт только
        // в этом хендлере; во внутреннюю (GUI-поток) лямбду уезжает уже готовая строка.
        const QString startFailure = stringFromResponse(response, @"last_start_failure");
        // AVPN (девайс-разбор 2026-09-02): имя интерфейса и хвост лога ядра — единственное, по чему
        // «Подключено без трафика» отличается от здорового коннекта (индекс интерфейса не отличает
        // Wi-Fi от нашего же utun).
        const QString ifaceName = stringFromResponse(response, @"active_interface_name");
        const QString coreLogTail = stringFromResponse(response, @"core_log_tail");
        // AVPN (diag 2026-09-03): счётчики привязки сокетов ядра — извлекаем ЗДЕСЬ (response
        // живёт только в этом хендлере), в GUI-лямбду уходят готовые числа.
        const long long xrayProtectBound = (long long)[response[@"protect_bound"] longLongValue];
        const long long xrayProtectUnbound = (long long)[response[@"protect_unbound"] longLongValue];
        const long long xrayProtectRejected = (long long)[response[@"protect_rejected"] longLongValue];
        // AVPN seamless roaming (§23.6): счётчики адаптера (path_lost/restored, bumps, rebinds,
        // pauses) — в Qt-лог приложения при изменении, чтобы диагностика видела роуминг даже
        // при выключенном файловом логе NE (ne.log пишется только при isLoggingEnabled).
        QString roamSummary;
        if (NSDictionary *roam = [response[@"roam"] isKindOfClass:[NSDictionary class]] ? response[@"roam"] : nil) {
            QStringList parts;
            for (NSString *k in [[roam allKeys] sortedArrayUsingSelector:@selector(compare:)]) {
                id v = roam[k];
                if (![k isKindOfClass:[NSString class]] || ![v respondsToSelector:@selector(longLongValue)])
                    continue; // чужой/битый ответ — не наш JSON; молча пропускаем
                parts << QString::fromNSString(k) + QLatin1Char('=') + QString::number([v longLongValue]);
            }
            roamSummary = parts.join(QLatin1Char(' '));
        }

        QMetaObject::invokeMethod(this, [this, gen, request, metadata, txBytes, rxBytes, last_handshake_time_sec, runtimeState,
                                         startFailure, ifaceName, coreLogTail, roamSummary,
                                         xrayProtectBound, xrayProtectUnbound, xrayProtectRejected]() {
            // AVPN: ответ чужого (старого) поколения сессии — выбросить целиком.
            if (m_statusGeneration.load() != gen || !m_statusRequests.complete(gen, request))
                return;
            if (metadata.value(QStringLiteral("schema_version")).toInt() == 1 &&
                !metadata.value(QStringLiteral("generation")).toString().isEmpty() && m_sessionMetadata != metadata) {
                m_sessionMetadata = metadata;
                emit sessionMetadataChanged(metadata);
            }
            if (!roamSummary.isEmpty() && roamSummary != m_lastRoamSummary) {
                m_lastRoamSummary = roamSummary;
                qInfo() << "[roam] NE counters:" << roamSummary;
            }
            // AVPN backend-first (T20): пороги — из m_rawConfig (засеяны VpnConnectionTunnelControl::up
            // ключами awg_handshake_timeout_ms/awg_handshake_max_timeouts), пусто/офлайн → constexpr-фолбэк.
            const int handshakeTimeoutMs =
                    intFromRawConfig(m_rawConfig, "awg_handshake_timeout_ms", kHandshakeTimeoutMs);
            const int handshakeMaxTimeouts =
                    intFromRawConfig(m_rawConfig, "awg_handshake_max_timeouts", kHandshakeMaxTimeouts);
            // AVPN backend-first (Task 5): rx-порог подтверждения рукопожатия — тоже из m_rawConfig
            // (awg_handshake_rx_threshold_bytes, засеян VpnConnectionTunnelControl::up).
            // intFromRawConfig не гарантирует положительность — порог <= 0 бессмыслен, откатываемся на фолбэк.
            const int handshakeRxThresholdRaw =
                    intFromRawConfig(m_rawConfig, "awg_handshake_rx_threshold_bytes", (int)kHandshakeRxThreshold);
            const uint64_t handshakeRxThreshold =
                    handshakeRxThresholdRaw > 0 ? (uint64_t)handshakeRxThresholdRaw : kHandshakeRxThreshold;
            if (isWireGuardBasedProto(m_proto) && m_handshakeAwaiting) {
                const bool hasHandshakeData = (last_handshake_time_sec >= 0);
                // AVPN: tx НЕ доказывает рукопожатие — init-ретраи можно бесконечно слать в чёрную дыру
                // без ответа (на сотовой rx=0, а tx рос → срабатывал старый txBytes-клауз → ЛОЖНЫЙ Connected,
                // «зелёный орб, трафика нет»). Реальный handshake подтверждают ТОЛЬКО: last_handshake_time_sec>0
                // (авторитетно, wireguard-go ставит время завершённого рукопожатия) или приход данных назад (rx).
                const bool hasFreshHandshake = hasHandshakeData &&
                        ((last_handshake_time_sec > 0) ||
                         (rxBytes >= handshakeRxThreshold));

                if (hasFreshHandshake) {
                    m_handshakeConfirmed = true;
                    m_handshakeAwaiting = false;
                    m_handshakeTimer.invalidate();
                    m_handshakeTimeouts = 0;
                    qDebug() << "IosController::checkStatus : handshake confirmed";
                    emitConnectionStateIfChanged(Vpn::ConnectionState::Connected);
                } else if (m_handshakeTimer.isValid() &&
                           m_handshakeTimer.elapsed() > handshakeTimeoutMs) {
                    m_handshakeTimer.restart();
                    // AVPN: нода не отвечает (rx=0). Не висим в Reconnecting вечно — после N таймаутов
                    // честно отдаём Error и гасим туннель (типично: IP:порт ноды режется оператором).
                    if (++m_handshakeTimeouts >= handshakeMaxTimeouts) {
                        qWarning() << "IosController::checkStatus : handshake failed after"
                                   << m_handshakeTimeouts << "timeouts — stopping tunnel";
                        m_handshakeAwaiting = false;
                        m_handshakeTimer.invalidate();
                        emitConnectionStateIfChanged(Vpn::ConnectionState::Error);
                        if (m_currentTunnel &&
                            [m_currentTunnel.connection isKindOfClass:[NETunnelProviderSession class]]) {
                            [(NETunnelProviderSession *)m_currentTunnel.connection stopTunnel];
                        }
                    } else {
                        qDebug() << "IosController::checkStatus : handshake timed out, keeping tunnel alive"
                                 << m_handshakeTimeouts << "/" << handshakeMaxTimeouts;
                        emitConnectionStateIfChanged(Vpn::ConnectionState::Reconnecting);
                    }
                }
            }

            // AVPN: счётчик «поехал назад» (рестарт NE-сессии/гонка) — пересев без эмиссии дельты,
            // иначе беззнаковое вычитание даёт «дельту» ~2^64 (второй рубеж — guard в accumulateByteDelta).
            if (rxBytes >= m_rxBytes && txBytes >= m_txBytes)
                emit bytesChanged(rxBytes - m_rxBytes, txBytes - m_txBytes);
            // AVPN: отдаём возраст хендшейка наружу (unix sec; <=0 → 0 «неизвестно») — serviceEngine
            // HealthLoop использует его для DEAD-детекта на iOS (раньше latestHandshakeEpoch был 0).
            // AVPN (этап D3): для xray-путей рукопожатия нет по определению — сигнал не эмитим
            // (0 = «неизвестно» по контракту stats, шум не нужен); живость xray HealthLoop меряет
            // по rx/tx + пробам. runtime_state != running — в лог (failed = NE сам гасит туннель).
            if (isXrayBasedProto(m_proto)) {
                // AVPN (девайс-разбор 2026-09-02): причина отказа ядра доезжает НЕЗАВИСИМО от
                // runtime_state. Прежний гейт «только когда state != running» хоронил её ровно в
                // том случае, ради которого и заводился: ядро отрапортовало running, а дозвоны
                // отменялись — «вечное подключение» без единой строки в диагностике.
                if (!startFailure.isEmpty() && startFailure != m_lastXrayStartFailure) {
                    m_lastXrayStartFailure = startFailure;
                    qWarning() << "IosController::checkStatus : xray start failure" << startFailure
                               << "runtime_state" << runtimeState;
                    emit xrayStartFailed(startFailure);
                }
                if (!runtimeState.isEmpty() && runtimeState != QLatin1String("running")) {
                    qWarning() << "IosController::checkStatus : xray runtime_state" << runtimeState;
                }
                // Хвост лога ядра — в лог приложения (он же уезжает в диагностику).
                if (!coreLogTail.isEmpty() && coreLogTail != m_lastXrayCoreLogTail) {
                    m_lastXrayCoreLogTail = coreLogTail;
                    qWarning() << "IosController::checkStatus : xray core log (iface" << ifaceName
                               << "):" << coreLogTail;
                }
                // AVPN (diag 2026-09-03): здоровье data-plane xray в лог приложения — привязка
                // сокетов ядра (bound/unbound/rejected) и кумулятивный rx/tx туннеля. По этим
                // числам «Подключено без трафика» перестаёт быть безымянным: rejected>0 =
                // дозвоны отменяются fail-closed; rx==0 при tx>0 = уходит, но не возвращается.
                {
                    const QString diag = QStringLiteral("bound=%1 unbound=%2 rejected=%3 rx=%4 tx=%5 iface=%6")
                        .arg(xrayProtectBound).arg(xrayProtectUnbound).arg(xrayProtectRejected)
                        .arg((long long)rxBytes).arg((long long)txBytes).arg(ifaceName);
                    if (diag != m_lastXrayDataPlaneDiag) {
                        m_lastXrayDataPlaneDiag = diag;
                        qWarning() << "IosController::checkStatus : xray data-plane" << diag;
                    }
                }
            } else {
                emit handshakeChanged(last_handshake_time_sec > 0 ? (qint64) last_handshake_time_sec : 0);
            }
            m_rxBytes = rxBytes;
            m_txBytes = txBytes;
        }, Qt::QueuedConnection);
    });
    [tunnel release]; // парный к retainedCurrentTunnel() в checkStatus
    });
}

// AVPN (BUG-4 auto-heal): ребайнд сокета живого NE-туннеля. Тот же канал, что checkStatus
// (retained-менеджер + provider message), но fire-and-forget: подтверждение heal'а — сам
// data-plane (HealthLoop увидит оживший rx/handshake либо повторный DEAD → failover).
bool IosController::rebindTunnel()
{
    NETunnelProviderManager *tunnel = retainedCurrentTunnel();
    if (!tunnel)
        return false;
    if (tunnel.connection.status != NEVPNStatusConnected) {
        [tunnel release];
        return false;
    }
    NSString *actionKey = [NSString stringWithUTF8String:MessageKey::action];
    NSString *actionValue = [NSString stringWithUTF8String:Action::rebind];
    NSString *tunnelIdKey = [NSString stringWithUTF8String:MessageKey::tunnelId];
    NSString *tunnelIdValue = !m_tunnelId.isEmpty() ? m_tunnelId.toNSString() : @"";
    NSDictionary *message = @{actionKey : actionValue, tunnelIdKey : tunnelIdValue};
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        // tunnel: наш retain отпускается в конце блока (паттерн checkStatus) — ответ-хендлер
        // менеджер не трогает, только лог.
        sendVpnExtensionMessage(tunnel, message, [](NSDictionary *response) {
            const bool ok = response && [response[@"ok"] boolValue];
            qInfo() << "IosController::rebindTunnel : extension replied" << (ok ? "ok" : "no/ignored");
        });
        [tunnel release];
    });
    return true;
}

void IosController::vpnStatusDidChange(void *pNotification)
{
    NETunnelProviderSession *session = (NETunnelProviderSession *)pNotification;
    if (QThread::currentThread() != thread()) {
        [session retain];
        QMetaObject::invokeMethod(this, [this, session] { vpnStatusDidChange(session); [session release]; }, Qt::QueuedConnection);
        return;
    }

    if (!session) {
        return;
    }
    if (!m_currentTunnel || (NETunnelProviderSession *)m_currentTunnel.connection != session) {
        requestReconcileStatus();
        return;
    }

    qDebug() << "IosController::vpnStatusDidChange" << iosStatusToState(session.status) << session;

        if (session.status == NEVPNStatusDisconnected) {
#if defined(Q_OS_IOS)
            const QVariantMap intent = Avpn_currentIntent();
            bool intentional = intent.value(QStringLiteral("action")).toString() == QLatin1String("pause") ||
                               intent.value(QStringLiteral("action")).toString() == QLatin1String("off");
            QString reason = intentional ? QStringLiteral("user_intent") :
                             m_localStopRequested ? QStringLiteral("expected_app_stop") : QStringLiteral("unknown_external");
            const QVariantMap stop = Avpn_lastStop();
            const QString sessionGeneration = m_sessionMetadata.value(QStringLiteral("generation")).toString();
            if (!intentional && !m_localStopRequested && !sessionGeneration.isEmpty() &&
                stop.value(QStringLiteral("generation")).toString() == sessionGeneration) {
                intentional = stop.value(QStringLiteral("intentional")).toBool();
                reason = QStringLiteral("ne_stop_%1").arg(stop.value(QStringLiteral("reason")).toInt());
            }
            emit disconnectReason(reason, intentional);
            Avpn_recordLifecycle(QStringLiteral("disconnect_reason"), {{QStringLiteral("reason"), reason},
                {QStringLiteral("intentional"), intentional}, {QStringLiteral("session_generation"), sessionGeneration}});
            m_localStopRequested = false;
#else
            emit disconnectReason(QStringLiteral("unknown_external"), false);
#endif
            if (@available(iOS 16.0, *)) {
                [session fetchLastDisconnectErrorWithCompletionHandler:^(NSError * _Nullable error) {
                    if (error != nil) {
                        qDebug() << "Disconnect error" << error.domain << error.code << error.localizedDescription;

                        if ([error.domain isEqualToString:NEVPNConnectionErrorDomain]) {
                            switch (error.code) {
                                case NEVPNConnectionErrorOverslept:
                                    qDebug() << "Disconnect error info" << "The VPN connection was terminated because the system slept for an extended period of time.";
                                    break;
                                case NEVPNConnectionErrorNoNetworkAvailable:
                                    qDebug() << "Disconnect error info" << "The VPN connection could not be established because the system is not connected to a network.";
                                    break;
                                case NEVPNConnectionErrorUnrecoverableNetworkChange:
                                    qDebug() << "Disconnect error info" << "The VPN connection was terminated because the network conditions changed in such a way that the VPN connection could not be maintained.";
                                    break;
                                case NEVPNConnectionErrorConfigurationFailed:
                                    qDebug() << "Disconnect error info" << "The VPN connection could not be established because the configuration is invalid. ";
                                    break;
                                case NEVPNConnectionErrorServerAddressResolutionFailed:
                                    qDebug() << "Disconnect error info" << "The address of the VPN server could not be determined.";
                                    break;
                                case NEVPNConnectionErrorServerNotResponding:
                                    qDebug() << "Disconnect error info" << "Network communication with the VPN server has failed.";
                                    break;
                                case NEVPNConnectionErrorServerDead:
                                    qDebug() << "Disconnect error info" << "The VPN server is no longer functioning.";
                                    break;
                                case NEVPNConnectionErrorAuthenticationFailed:
                                    qDebug() << "Disconnect error info" << "The user credentials were rejected by the VPN server.";
                                    break;
                                case NEVPNConnectionErrorClientCertificateInvalid:
                                    qDebug() << "Disconnect error info" << "The client certificate is invalid.";
                                    break;
                                case NEVPNConnectionErrorClientCertificateNotYetValid:
                                    qDebug() << "Disconnect error info" << "The client certificate will not be valid until some future point in time.";
                                    break;
                                case NEVPNConnectionErrorClientCertificateExpired:
                                    qDebug() << "Disconnect error info" << "The validity period of the client certificate has passed.";
                                    break;
                                case NEVPNConnectionErrorPluginFailed:
                                    qDebug() << "Disconnect error info" << "The VPN plugin died unexpectedly.";
                                    break;
                                case NEVPNConnectionErrorConfigurationNotFound:
                                    qDebug() << "Disconnect error info" << "The VPN configuration could not be found.";
                                    break;
                                case NEVPNConnectionErrorPluginDisabled:
                                    qDebug() << "Disconnect error info" << "The VPN plugin could not be found or needed to be updated.";
                                    break;
                                case NEVPNConnectionErrorNegotiationFailed:
                                    qDebug() << "Disconnect error info" << "The VPN protocol negotiation failed.";
                                    break;
                                case NEVPNConnectionErrorServerDisconnected:
                                    qDebug() << "Disconnect error info" << "The VPN server terminated the connection.";
                                    break;
                                case NEVPNConnectionErrorServerCertificateInvalid:
                                    qDebug() << "Disconnect error info" << "The server certificate is invalid.";
                                    break;
                                case NEVPNConnectionErrorServerCertificateNotYetValid:
                                    qDebug() << "Disconnect error info" << "The server certificate will not be valid until some future point in time.";
                                    break;
                                case NEVPNConnectionErrorServerCertificateExpired:
                                    qDebug() << "Disconnect error info" << "The validity period of the server certificate has passed.";
                                    break;
                                default:
                                    qDebug() << "Disconnect error info" << "Unknown code.";
                                    break;
                            }
                        }

                        NSError *underlyingError = error.userInfo[@"NSUnderlyingError"];
                        if (underlyingError != nil) {
                            qDebug() << "Disconnect underlying error" << underlyingError.domain << underlyingError.code << underlyingError.localizedDescription;

                            if ([underlyingError.domain isEqualToString:@"NEAgentErrorDomain"]) {
                                switch (underlyingError.code) {
                                    case 1:
                                        qDebug() << "Disconnect underlying error" << "General. Use sysdiagnose.";
                                        break;
                                    case 2:
                                        qDebug() << "Disconnect underlying error" << "Plug-in unavailable. Use sysdiagnose.";
                                        break;
                                    default:
                                        qDebug() << "Disconnect underlying error" << "Unknown code. Use sysdiagnose.";
                                        break;
                                }
                            }
                        }
                    }
                }];
            } else {
                qDebug() << "Disconnect error is unavailable on iOS < 16.0";
            }
        }

        Vpn::ConnectionState nextState = iosStatusToState(session.status);
        if (session.status == NEVPNStatusConnected && isWireGuardBasedProto(m_proto)) {
            if (!m_handshakeConfirmed) {
                nextState = Vpn::ConnectionState::Connecting;
                if (!m_handshakeAwaiting) {
                    m_handshakeAwaiting = true;
                    m_handshakeTimer.restart();
                    m_handshakeTimeouts = 0;
                }
            }
        } else if (session.status != NEVPNStatusConnected) {
            m_handshakeAwaiting = false;
            m_handshakeConfirmed = false;
            m_handshakeTimer.invalidate();
            m_handshakeTimeouts = 0;
            m_statusRequests.invalidate();
        }
        emitConnectionStateIfChanged(nextState);
}

void IosController::vpnConfigurationDidChange(void *)
{
    // Configuration notifications include our save/load. One coalesced, generation-checked load.
    QMetaObject::invokeMethod(this, [this] { requestReconcileStatus(); }, Qt::QueuedConnection);
}

bool IosController::setupOpenVPN()
{
    QJsonObject ovpn = m_rawConfig[ProtocolUtils::key_proto_config_data(amnezia::Proto::OpenVpn)].toObject();
    QString ovpnConfig = ovpn[configKey::config].toString();

    QJsonObject openVPNConfig {};
    openVPNConfig.insert(configKey::config, ovpnConfig);

    if (ovpn.contains(configKey::mtu)) {
        openVPNConfig.insert(configKey::mtu, ovpn[configKey::mtu]);
    } else {
        openVPNConfig.insert(configKey::mtu, protocols::openvpn::defaultMtu);
    }

    openVPNConfig.insert(configKey::splitTunnelType, m_rawConfig[configKey::splitTunnelType]);

    QJsonArray splitTunnelSites = m_rawConfig[configKey::splitTunnelSites].toArray();

    for(int index = 0; index < splitTunnelSites.count(); index++) {
        splitTunnelSites[index] = splitTunnelSites[index].toString().remove(" ");
    }

    openVPNConfig.insert(configKey::splitTunnelSites, splitTunnelSites);

    QJsonDocument openVPNConfigDoc(openVPNConfig);
    QString openVPNConfigStr(openVPNConfigDoc.toJson(QJsonDocument::Compact));

    return startOpenVPN(openVPNConfigStr);
}

static void insertNonEmptyAwgParams(QJsonObject &wgConfig, const QJsonObject &config)
{
    const QStringList awgProtocolKeys = configKey::awgProtocolKeys();

    for (const QString &key : awgProtocolKeys) {
        const QJsonValue value = config.value(key);
        if (value.isString() && !value.toString().isEmpty()) {
            wgConfig.insert(key, value);
        }
    }
}

bool IosController::setupWireGuard()
{
    QJsonObject config = m_rawConfig[ProtocolUtils::key_proto_config_data(amnezia::Proto::WireGuard)].toObject();

    QJsonObject wgConfig {};
    wgConfig.insert(configKey::dns1, m_rawConfig[configKey::dns1]);
    wgConfig.insert(configKey::dns2, m_rawConfig[configKey::dns2]);

    if (config.contains(configKey::mtu)) {
        wgConfig.insert(configKey::mtu, config[configKey::mtu]);
    } else {
        wgConfig.insert(configKey::mtu, protocols::wireguard::defaultMtu);
    }

    wgConfig.insert(configKey::hostName, config[configKey::hostName]);
    wgConfig.insert(configKey::port, config[configKey::port]);
    wgConfig.insert(configKey::clientIp, config[configKey::clientIp]);
    wgConfig.insert(configKey::clientPrivKey, config[configKey::clientPrivKey]);
    wgConfig.insert(configKey::serverPubKey, config[configKey::serverPubKey]);
    wgConfig.insert(configKey::pskKey, config[configKey::pskKey]);
    wgConfig.insert(configKey::splitTunnelType, m_rawConfig[configKey::splitTunnelType]);

    QJsonArray splitTunnelSites = m_rawConfig[configKey::splitTunnelSites].toArray();

    for(int index = 0; index < splitTunnelSites.count(); index++) {
        splitTunnelSites[index] = splitTunnelSites[index].toString().remove(" ");
    }

    wgConfig.insert(configKey::splitTunnelSites, splitTunnelSites);

    if (m_rawConfig.contains(QStringLiteral("dnsFwdWarmup")))
        wgConfig.insert(QStringLiteral("dnsFwdWarmup"), m_rawConfig.value(QStringLiteral("dnsFwdWarmup")));

    if (config.contains(configKey::allowedIps) && config[configKey::allowedIps].isArray()) {
        wgConfig.insert(configKey::allowedIps, config[configKey::allowedIps]);
    } else {
        QJsonArray allowed_ips { "0.0.0.0/0", "::/0" };
        wgConfig.insert(configKey::allowedIps, allowed_ips);
    }

    if (config.contains(configKey::persistentKeepAlive)) {
        wgConfig.insert(configKey::persistentKeepAlive, config[configKey::persistentKeepAlive]);
    }

    insertNonEmptyAwgParams(wgConfig, config);

    QJsonDocument wgConfigDoc(wgConfig);
    QString wgConfigDocStr(wgConfigDoc.toJson(QJsonDocument::Compact));

    return startWireGuard(wgConfigDocStr);
}

bool IosController::setupXray()
{
    QJsonObject config = m_rawConfig[ProtocolUtils::key_proto_config_data(amnezia::Proto::Xray)].toObject();
    QString xrayConfigStr = config.value(configKey::config).toString();

    QJsonObject finalConfig;
    finalConfig.insert(configKey::dns1, m_rawConfig[configKey::dns1].toString());
    finalConfig.insert(configKey::dns2, m_rawConfig[configKey::dns2].toString());
    finalConfig.insert(configKey::splitTunnelType, m_rawConfig[configKey::splitTunnelType]);

    QJsonArray splitTunnelSites = m_rawConfig[configKey::splitTunnelSites].toArray();

    for (int index = 0; index < splitTunnelSites.count(); index++) {
        splitTunnelSites[index] = splitTunnelSites[index].toString().remove(" ");
    }

    finalConfig.insert(configKey::splitTunnelSites, splitTunnelSites);
    finalConfig.insert(configKey::config, xrayConfigStr);
    // AVPN backend-first (Task 6): tun2socks connect/read-write timeouts + network-change reconnect
    // debounce, server-tunable via TuningStore (numbers.xray_connect_timeout_ms/xray_rw_timeout_ms/
    // network_change_debounce_ms). Fallbacks byte-for-byte match the pre-Task-6 NE literals
    // (setupAndRunTun2socks: 5000/60000; scheduleNetworkChangeHandling: 1000) — absent/offline ⇒
    // identical behavior. Decoded as optional Int? on the Swift side (XrayConfig).
    // Clamped: an operator typo (0/negative) in the backend config must not reach the NE — 0
    // connect-timeout would go into the tun2socks YAML as-is, 0/negative debounce would cause a
    // reconnect storm on a flapping network.
    finalConfig.insert(configKey::xrayConnectTimeoutMs,
                       qBound(100, int(avpn::TuningStore::numberOr(QStringLiteral("xray_connect_timeout_ms"), 5000)), 300000));
    finalConfig.insert(configKey::xrayRwTimeoutMs,
                       qBound(1000, int(avpn::TuningStore::numberOr(QStringLiteral("xray_rw_timeout_ms"), 60000)), 600000));
    finalConfig.insert(configKey::networkChangeDebounceMs,
                       qBound(200, int(avpn::TuningStore::numberOr(QStringLiteral("network_change_debounce_ms"), 1000)), 30000));
    // AVPN seamless roaming: рестарт ядра только при смене аплинка; 1 = старое поведение.
    finalConfig.insert(configKey::xrayRestartOnPathLoss,
                       avpn::TuningStore::flag(QStringLiteral("xray_restart_on_path_loss"), false) ? 1 : 0);
    // AVPN IPv6-волна: xray-туннель забирает `::/0` (без v6-источника) — иначе на dual-stack сети
    // AAAA-трафик уходит мимо VPN с настоящим адресом. Kill-switch с дефолтом TRUE.
    finalConfig.insert(configKey::xrayIpv6Capture,
                       avpn::TuningStore::flag(QStringLiteral("xray_ipv6_capture"), true) ? 1 : 0);

    QJsonDocument finalConfigDoc(finalConfig);
    QString finalConfigStr(finalConfigDoc.toJson(QJsonDocument::Compact));

    return startXray(finalConfigStr);
}

bool IosController::setupSSXray()
{
    QJsonObject config = m_rawConfig[ProtocolUtils::key_proto_config_data(amnezia::Proto::SSXray)].toObject();
    QString ssXrayConfigStr = config.value(configKey::config).toString();

    QJsonObject finalConfig;
    finalConfig.insert(configKey::dns1, m_rawConfig[configKey::dns1]);
    finalConfig.insert(configKey::dns2, m_rawConfig[configKey::dns2]);
    finalConfig.insert(configKey::config, ssXrayConfigStr);
    // AVPN backend-first (Task 6): same tun2socks/network-change knobs as setupXray() above — SSXray
    // shares the same NE "xray" provider-configuration blob and XrayConfig Decodable on the Swift side.
    // Clamped for the same reason as setupXray(): operator typo (0/negative) must not reach the NE.
    finalConfig.insert(configKey::xrayConnectTimeoutMs,
                       qBound(100, int(avpn::TuningStore::numberOr(QStringLiteral("xray_connect_timeout_ms"), 5000)), 300000));
    finalConfig.insert(configKey::xrayRwTimeoutMs,
                       qBound(1000, int(avpn::TuningStore::numberOr(QStringLiteral("xray_rw_timeout_ms"), 60000)), 600000));
    finalConfig.insert(configKey::networkChangeDebounceMs,
                       qBound(200, int(avpn::TuningStore::numberOr(QStringLiteral("network_change_debounce_ms"), 1000)), 30000));
    // AVPN seamless roaming: рестарт ядра только при смене аплинка; 1 = старое поведение.
    finalConfig.insert(configKey::xrayRestartOnPathLoss,
                       avpn::TuningStore::flag(QStringLiteral("xray_restart_on_path_loss"), false) ? 1 : 0);
    // AVPN IPv6-волна: xray-туннель забирает `::/0` (без v6-источника) — иначе на dual-stack сети
    // AAAA-трафик уходит мимо VPN с настоящим адресом. Kill-switch с дефолтом TRUE.
    finalConfig.insert(configKey::xrayIpv6Capture,
                       avpn::TuningStore::flag(QStringLiteral("xray_ipv6_capture"), true) ? 1 : 0);

    QJsonDocument finalConfigDoc(finalConfig);
    QString finalConfigStr(finalConfigDoc.toJson(QJsonDocument::Compact));

    return startXray(finalConfigStr);
}

bool IosController::setupAwg()
{
    QJsonObject config = m_rawConfig[ProtocolUtils::key_proto_config_data(amnezia::Proto::Awg)].toObject();

    QJsonObject wgConfig {};
    wgConfig.insert(configKey::dns1, m_rawConfig[configKey::dns1]);
    wgConfig.insert(configKey::dns2, m_rawConfig[configKey::dns2]);

    if (config.contains(configKey::mtu)) {
        wgConfig.insert(configKey::mtu, config[configKey::mtu]);
    } else {
        wgConfig.insert(configKey::mtu, protocols::awg::defaultMtu);
    }

    wgConfig.insert(configKey::hostName, config[configKey::hostName]);
    wgConfig.insert(configKey::port, config[configKey::port]);
    wgConfig.insert(configKey::clientIp, config[configKey::clientIp]);
    wgConfig.insert(configKey::clientPrivKey, config[configKey::clientPrivKey]);
    wgConfig.insert(configKey::serverPubKey, config[configKey::serverPubKey]);
    wgConfig.insert(configKey::pskKey, config[configKey::pskKey]);
    wgConfig.insert(configKey::splitTunnelType, m_rawConfig[configKey::splitTunnelType]);

    QJsonArray splitTunnelSites = m_rawConfig[configKey::splitTunnelSites].toArray();

    for(int index = 0; index < splitTunnelSites.count(); index++) {
        splitTunnelSites[index] = splitTunnelSites[index].toString().remove(" ");
    }

    wgConfig.insert(configKey::splitTunnelSites, splitTunnelSites);

    // AVPN split-DNS форвардер: корневые ключи cfg (VpnConnectionTunnelControl::up) → JSON для NE
    // (WGConfig.swift; значения — СТРОКИ). Отсутствуют = форвардер выключен.
    if (m_rawConfig.contains(QLatin1String("dnsFwdOn"))) {
        wgConfig.insert(QLatin1String("dnsFwdOn"), m_rawConfig[QLatin1String("dnsFwdOn")]);
        wgConfig.insert(QLatin1String("dnsFwdSuffixes"), m_rawConfig[QLatin1String("dnsFwdSuffixes")]);
        wgConfig.insert(QLatin1String("dnsFwdServer"), m_rawConfig[QLatin1String("dnsFwdServer")]);
    }

    // AVPN seamless roaming (awg-apple tribe.4): политика адаптера на потерю пути — корневые
    // ключи cfg (VpnConnectionTunnelControl::up) -> WGConfig.swift. Отсутствуют = дефолт seamless.
    for (const QLatin1String &key : { configKey::roamKeepBackend, configKey::roamPauseAfterS,
                                      configKey::roamStallProbeS, configKey::roamStallRebindS }) {
        if (m_rawConfig.contains(key)) {
            wgConfig.insert(key, m_rawConfig[key]);
        }
    }

    if (m_rawConfig.contains(QStringLiteral("dnsFwdWarmup")))
        wgConfig.insert(QStringLiteral("dnsFwdWarmup"), m_rawConfig.value(QStringLiteral("dnsFwdWarmup")));

    if (config.contains(configKey::allowedIps) && config[configKey::allowedIps].isArray()) {
        wgConfig.insert(configKey::allowedIps, config[configKey::allowedIps]);
    } else {
        QJsonArray allowed_ips { "0.0.0.0/0", "::/0" };
        wgConfig.insert(configKey::allowedIps, allowed_ips);
    }

    if (config.contains(configKey::persistentKeepAlive)) {
        wgConfig.insert(configKey::persistentKeepAlive, config[configKey::persistentKeepAlive]);
    }

    insertNonEmptyAwgParams(wgConfig, config);

    QJsonDocument wgConfigDoc(wgConfig);
    QString wgConfigDocStr(wgConfigDoc.toJson(QJsonDocument::Compact));

    return startWireGuard(wgConfigDocStr);
}

bool IosController::startOpenVPN(const QString &config)
{
    qDebug() << "IosController::startOpenVPN";

    NETunnelProviderProtocol *tunnelProtocol = [[NETunnelProviderProtocol alloc] init];
    tunnelProtocol.providerBundleIdentifier = [NSString stringWithUTF8String:VPN_NE_BUNDLEID];
    QByteArray configUtf8 = config.toUtf8();
    NSData *ovpnConfigData = [NSData dataWithBytes:configUtf8.constData() length:configUtf8.size()];
    tunnelProtocol.providerConfiguration = @{@"ovpn": ovpnConfigData};
    tunnelProtocol.serverAddress = m_serverAddress;
    if (@available(iOS 14.0, macOS 11.0, *)) {
        int splitTunnelType = 0;
        QJsonParseError parseError;
        QJsonDocument doc = QJsonDocument::fromJson(config.toUtf8(), &parseError);
        if (parseError.error == QJsonParseError::NoError && doc.isObject()) {
            QJsonObject obj = doc.object();
            splitTunnelType = obj.value(configKey::splitTunnelType).toInt(0);
        }
#if defined(MACOS_NE)
        // On macOS NE use route-based full tunnel. includeAllNetworks enables
        // policy-based drop-all mode and causes enforceRoutes to be ignored.
        tunnelProtocol.includeAllNetworks = NO;
        if (splitTunnelType == 0) {
            tunnelProtocol.enforceRoutes = YES;
            if (@available(iOS 14.2, macOS 11.0, *)) {
                tunnelProtocol.excludeLocalNetworks = YES;
            }
        }
#else
        tunnelProtocol.includeAllNetworks = (splitTunnelType == 0);
        if (@available(iOS 14.2, macOS 11.0, *)) {
            // Keep existing iOS behavior.
            if (splitTunnelType == 0) {
                tunnelProtocol.excludeLocalNetworks = NO;
            }
        }
#endif
    }

    NSMutableDictionary *provider = [NSMutableDictionary dictionaryWithDictionary:tunnelProtocol.providerConfiguration ?: @{}];
    provider[@"tribeSessionMetadata"] = providerMetadata();
    provider[@"tribeManagerId"] = ((NETunnelProviderProtocol *)m_currentTunnel.protocolConfiguration).providerConfiguration[@"tribeManagerId"] ?: [[NSUUID UUID] UUIDString];
    tunnelProtocol.providerConfiguration = provider;
    m_currentTunnel.protocolConfiguration = tunnelProtocol;
    [tunnelProtocol release]; // protocolConfiguration retains/copies; this file is MRC
    restoreSessionMetadata(m_currentTunnel);

    NETunnelProviderProtocol *appliedProtocol = (NETunnelProviderProtocol *)m_currentTunnel.protocolConfiguration;
    NSData *ovpnPayload = appliedProtocol.providerConfiguration[@"ovpn"];
    NSString *payloadPreview = @"";
    if (ovpnPayload != nil) {
        NSString *decodedPayload = [[NSString alloc] initWithData:ovpnPayload encoding:NSUTF8StringEncoding];
        if (decodedPayload != nil) {
            payloadPreview = [decodedPayload substringToIndex:MIN((NSUInteger)512, decodedPayload.length)];
        }
    }

    qDebug().noquote() << "IosController::startOpenVPN protocolConfiguration"
                       << "bundleId=" << QString::fromNSString(appliedProtocol.providerBundleIdentifier ?: @"")
                       << "serverAddress=" << QString::fromNSString(appliedProtocol.serverAddress ?: @"")
                       << "providerKeys=" << QString::fromNSString([[appliedProtocol.providerConfiguration.allKeys description] copy])
                       << "ovpnBytes=" << (ovpnPayload != nil ? ovpnPayload.length : 0);
    qDebug().noquote() << "IosController::startOpenVPN protocolConfiguration payloadPreview="
                       << QString::fromNSString(payloadPreview);

    startTunnel();
    return true; // AVPN(N3): не было return — UB; результат сейчас игнорируется, но поток обязан вернуть значение
}

bool IosController::startWireGuard(const QString &config)
{
    qDebug() << "IosController::startWireGuard";

    NETunnelProviderProtocol *tunnelProtocol = [[NETunnelProviderProtocol alloc] init];
    tunnelProtocol.providerBundleIdentifier = [NSString stringWithUTF8String:VPN_NE_BUNDLEID];
    QByteArray configUtf8 = config.toUtf8();
    NSData *wgConfigData = [NSData dataWithBytes:configUtf8.constData() length:configUtf8.size()];
    tunnelProtocol.providerConfiguration = @{@"wireguard": wgConfigData};
    tunnelProtocol.serverAddress = m_serverAddress;

    NSMutableDictionary *provider = [NSMutableDictionary dictionaryWithDictionary:tunnelProtocol.providerConfiguration ?: @{}];
    provider[@"tribeSessionMetadata"] = providerMetadata();
    provider[@"tribeManagerId"] = ((NETunnelProviderProtocol *)m_currentTunnel.protocolConfiguration).providerConfiguration[@"tribeManagerId"] ?: [[NSUUID UUID] UUIDString];
    tunnelProtocol.providerConfiguration = provider;
    m_currentTunnel.protocolConfiguration = tunnelProtocol;
    [tunnelProtocol release]; // protocolConfiguration retains/copies; this file is MRC
    restoreSessionMetadata(m_currentTunnel);

    startTunnel();
    return true; // AVPN(N3): не было return — UB; результат сейчас игнорируется, но поток обязан вернуть значение
}

bool IosController::startXray(const QString &config)
{
    qDebug() << "IosController::startXray";

    NETunnelProviderProtocol *tunnelProtocol = [[NETunnelProviderProtocol alloc] init];
    tunnelProtocol.providerBundleIdentifier = [NSString stringWithUTF8String:VPN_NE_BUNDLEID];
    QByteArray configUtf8 = config.toUtf8();
    NSData *xrayConfigData = [NSData dataWithBytes:configUtf8.constData() length:configUtf8.size()];
    tunnelProtocol.providerConfiguration = @{@"xray": xrayConfigData};
    tunnelProtocol.serverAddress = m_serverAddress;

    NSMutableDictionary *provider = [NSMutableDictionary dictionaryWithDictionary:tunnelProtocol.providerConfiguration ?: @{}];
    provider[@"tribeSessionMetadata"] = providerMetadata();
    provider[@"tribeManagerId"] = ((NETunnelProviderProtocol *)m_currentTunnel.protocolConfiguration).providerConfiguration[@"tribeManagerId"] ?: [[NSUUID UUID] UUIDString];
    tunnelProtocol.providerConfiguration = provider;
    m_currentTunnel.protocolConfiguration = tunnelProtocol;
    [tunnelProtocol release]; // protocolConfiguration retains/copies; this file is MRC
    restoreSessionMetadata(m_currentTunnel);

    startTunnel();
    return true; // AVPN(N3): не было return — UB; результат сейчас игнорируется, но поток обязан вернуть значение
}

void IosController::startTunnel()
{
    const uint64_t operation = m_operationGeneration;
    NETunnelProviderManager *tunnel = m_currentTunnel;
    if (!tunnel || !operationCurrent(operation)) return;
    [tunnel setEnabled:YES];
    [tunnel saveToPreferencesWithCompletionHandler:^(NSError *saveError) {
        [tunnel retain]; [saveError retain];
        QMetaObject::invokeMethod(this, [this, tunnel, saveError, operation] {
            if (operationCurrent(operation)) {
                if (saveError) {
                    m_connectPending = false;
                    emitConnectionStateIfChanged(Vpn::ConnectionState::Error);
                } else {
                    [tunnel loadFromPreferencesWithCompletionHandler:^(NSError *loadError) {
                        [tunnel retain]; [loadError retain];
                        QMetaObject::invokeMethod(this, [this, tunnel, loadError, operation] {
                            if (operationCurrent(operation)) {
                                m_connectPending = false;
                                if (loadError) {
                                    emitConnectionStateIfChanged(Vpn::ConnectionState::Error);
                                } else if (tunnel.connection.status == NEVPNStatusDisconnected || tunnel.connection.status == NEVPNStatusInvalid) {
                                    NSError *startError = nil;
                                    BOOL started = NO;
#if defined(Q_OS_IOS)
                                    Avpn_performIfCurrent(m_operationIntentGeneration, [&] {
                                        started = [tunnel.connection startVPNTunnelWithOptions:nil andReturnError:&startError];
                                    });
#else
                                    started = [tunnel.connection startVPNTunnelWithOptions:nil andReturnError:&startError];
#endif
                                    if (!started || startError) emitConnectionStateIfChanged(Vpn::ConnectionState::Error);
                                    else vpnStatusDidChange(tunnel.connection);
                                } else {
                                    // A Settings/Intent start won the race: observe it, do not start over it.
                                    vpnStatusDidChange(tunnel.connection);
                                }
                            }
                            [tunnel release]; [loadError release];
                        }, Qt::QueuedConnection);
                    }];
                }
            }
            [tunnel release]; [saveError release];
        }, Qt::QueuedConnection);
    }];
}

bool IosController::isOurManager(NETunnelProviderManager* manager) {
    NETunnelProviderProtocol* tunnelProto = (NETunnelProviderProtocol*)manager.protocolConfiguration;

    if (![tunnelProto isKindOfClass:[NETunnelProviderProtocol class]]) {
        qDebug() << "Ignoring manager because the proto is invalid";
        return false;
    }

    if (!tunnelProto.providerBundleIdentifier) {
        qDebug() << "Ignoring manager because the bundle identifier is null";
        return false;
    }

    if (![tunnelProto.providerBundleIdentifier isEqualToString:[NSString stringWithUTF8String:VPN_NE_BUNDLEID]]) {
        qDebug() << "Ignoring manager because the bundle identifier doesn't match";
        return false;
    }

    qDebug() << "Found the manager with the correct bundle identifier:" << QString::fromNSString(tunnelProto.providerBundleIdentifier);

    return true;
}

void IosController::sendVpnExtensionMessage(NETunnelProviderManager *tunnel, NSDictionary* message,
                                            std::function<void(NSDictionary*)> callback)
{
    // AVPN (ревью 2026-07-11): менеджер приходит retained-копией от вызывающего (checkStatus) —
    // ivar m_currentTunnel с фоновой очереди НЕ читаем (гонка с release на главном треде).
    if (!tunnel) {
        qDebug() << "Cannot set an extension callback without a tunnel manager";
        if (callback) {
            callback(nil);
        }
        return;
    }

    const auto delivered = std::make_shared<std::atomic_bool>(false);
    const auto originalCallback = callback;
    callback = [delivered, originalCallback](NSDictionary *response) {
        if (!delivered->exchange(true) && originalCallback) originalCallback(response);
    };
    NSError *error = nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:message options:0 error:&error];

    if (!data || error) {
        qDebug() << "Failed to serialize message to VpnExtension as JSON. Error:"
                 << [error.localizedDescription UTF8String];
        if (callback) {
            callback(nil);
        }
        return;
    }

    void (^completionHandler)(NSData *) = ^(NSData *responseData) {
        if (!responseData) {
            if (callback) callback(nil);
            return;
        }

        NSError *deserializeError = nil;
        NSDictionary *response = [NSJSONSerialization JSONObjectWithData:responseData options:0 error:&deserializeError];

        if (response && [response isKindOfClass:[NSDictionary class]]) {
            if (callback) callback(response);
            return;
        } else if (deserializeError) {
            qDebug() << "Failed to deserialize the VpnExtension response";
        }

        if (callback) callback(nil);
    };

    NETunnelProviderSession *session = (NETunnelProviderSession *)tunnel.connection;

    NSError *sendError = nil;

    if ([session respondsToSelector:@selector(sendProviderMessage:returnError:responseHandler:)]) {
        [session sendProviderMessage:data returnError:&sendError responseHandler:completionHandler];
    } else {
        qDebug() << "Method sendProviderMessage:responseHandler:error: does not exist";
        if (callback) {
            callback(nil);
        }
        return;
    }

    if (sendError) {
        qDebug() << "Failed to send message to VpnExtension. Error:"
                 << [sendError.localizedDescription UTF8String];
        if (callback) {
            callback(nil);
        }
    }

}

bool IosController::shareText(const QStringList& filesToSend) {
    NSMutableArray *sharingItems = [NSMutableArray new];

    for (int i = 0; i < filesToSend.size(); i++) {
        NSURL *logFileUrl = [[NSURL alloc] initFileURLWithPath:filesToSend[i].toNSString()];
        [sharingItems addObject:logFileUrl];
    }
#if !MACOS_NE
    UIViewController *qtController = getViewController();
    if (!qtController) {
        return false;
    }

    UIActivityViewController *activityController = [[UIActivityViewController alloc] initWithActivityItems:sharingItems applicationActivities:nil];
#endif
    __block bool isAccepted = false;
#if !MACOS_NE
    [activityController setCompletionWithItemsHandler:^(NSString *activityType, BOOL completed, NSArray *returnedItems, NSError *activityError) {
        isAccepted = completed;
        emit finished();
    }];

    [qtController presentViewController:activityController animated:YES completion:nil];
    UIPopoverPresentationController *popController = activityController.popoverPresentationController;
    if (popController) {
        popController.sourceView = qtController.view;
        popController.sourceRect = CGRectMake(100, 100, 100, 100);
    }

#endif
    QEventLoop wait;
    QObject::connect(this, &IosController::finished, &wait, &QEventLoop::quit);
    wait.exec();

    return isAccepted;
}

QString IosController::openFile() {
#if !MACOS_NE
    UIDocumentPickerViewController *documentPicker = [[UIDocumentPickerViewController alloc] initWithDocumentTypes:@[@"public.item"] inMode:UIDocumentPickerModeOpen];

    DocumentPickerDelegate *documentPickerDelegate = [[DocumentPickerDelegate alloc] init];
    documentPicker.delegate = documentPickerDelegate;

    UIViewController *qtController = getViewController();
    if (!qtController) return QString(); // AVPN(N3): был голый return в QString-функции

    [qtController presentViewController:documentPicker animated:YES completion:nil];

#endif
    __block QString filePath;
#if !MACOS_NE
    documentPickerDelegate.documentPickerClosedCallback = ^(NSString *path) {
        if (path) {
            filePath = QString::fromUtf8(path.UTF8String);
        } else {
            filePath = QString();
        }
        emit finished();
    };
#endif
    QEventLoop wait;
    QObject::connect(this, &IosController::finished, &wait, &QEventLoop::quit);
    wait.exec();

    return filePath;
}

namespace
{
// Keep in sync with StoreKit2Helper.errorCodeCancelled / errorCodePending
constexpr int storeKitErrorCodeCancelled = 1;
constexpr int storeKitErrorCodePending = 2;

IosController::StorePurchaseFailure storePurchaseFailureFromError(NSError *error)
{
    if (!error || ![error.domain isEqualToString:@"StoreKit2Helper"]) {
        return IosController::StorePurchaseFailure::Other;
    }
    switch (error.code) {
    case storeKitErrorCodeCancelled: return IosController::StorePurchaseFailure::Cancelled;
    case storeKitErrorCodePending: return IosController::StorePurchaseFailure::Pending;
    default: return IosController::StorePurchaseFailure::Other;
    }
}

QVariantMap toTransactionMap(NSDictionary *dict)
{
    QVariantMap transaction;
    for (NSString *key in @[@"transactionId", @"originalTransactionId", @"productId", @"environment"]) {
        NSString *value = dict[key];
        if (value) {
            transaction.insert(QString::fromUtf8(key.UTF8String), QString::fromUtf8(value.UTF8String));
        }
    }
    return transaction;
}

QList<QVariantMap> toTransactionList(NSArray<NSDictionary *> *transactions)
{
    QList<QVariantMap> list;
    for (NSDictionary *dict in transactions ?: @[]) {
        list.push_back(toTransactionMap(dict));
    }
    return list;
}
}

void IosController::purchaseProduct(const QString &productId,
                                   std::function<void(bool success,
                                                      const QString &transactionId,
                                                      const QString &purchasedProductId,
                                                      const QString &originalTransactionId,
                                                      const QString &storeEnvironment,
                                                      const QString &errorString,
                                                      StorePurchaseFailure failureReason)> &&callback)
{
    qInfo().noquote() << "[IAP][IosController] purchaseProduct called" << productId;
    if (@available(iOS 15.0, macOS 12.0, *)) {
        __block auto cb = std::move(callback);
        [[StoreKit2Helper shared] purchaseProductWithProductIdentifier:productId.toNSString()
                                                            completion:^(BOOL s,
                                                                         NSString * _Nullable transactionId,
                                                                         NSString * _Nullable prodId,
                                                                         NSString * _Nullable originalTxId,
                                                                         NSString * _Nullable environment,
                                                                         NSError * _Nullable error) {
            const QString txId = QString::fromUtf8((transactionId ?: @"").UTF8String);
            const QString pId  = QString::fromUtf8((prodId        ?: @"").UTF8String);
            const QString origTxId = QString::fromUtf8((originalTxId ?: @"").UTF8String);
            const QString env  = QString::fromUtf8((environment  ?: @"").UTF8String);
            const QString err  = QString::fromUtf8((error.localizedDescription ?: @"").UTF8String);
            const StorePurchaseFailure failureReason = s ? StorePurchaseFailure::Other
                                                         : storePurchaseFailureFromError(error);

            qInfo().noquote() << "[IAP][IosController] purchase completion" << "success=" << s
                              << "transactionId=" << txId << "originalTransactionId=" << origTxId
                              << "productId=" << pId << "environment=" << env << "error=" << err;

            if (cb) {
                cb(s, txId, pId, origTxId, env, err, failureReason);
            }
        }];
    } else {
        if (callback) {
            callback(false, QString(), QString(), QString(), QString(), "StoreKit 2 requires iOS 15.0 or later",
                     StorePurchaseFailure::Other);
        }
    }
}

void IosController::finishStoreTransaction(const QString &transactionId)
{
    if (transactionId.isEmpty()) {
        return;
    }
    if (@available(iOS 15.0, macOS 12.0, *)) {
        qInfo().noquote() << "[IAP][IosController] Finishing transaction" << transactionId;
        [[StoreKit2Helper shared] finishTransactionWithTransactionId:transactionId.toNSString()
                                                          completion:^(BOOL finished) {
            if (!finished) {
                qWarning().noquote() << "[IAP][IosController] Transaction was not found in the unfinished queue";
            }
        }];
    }
}

void IosController::startStoreTransactionObserver()
{
    if (@available(iOS 15.0, macOS 12.0, *)) {
        qInfo().noquote() << "[IAP][IosController] Starting transaction updates listener";
        [[StoreKit2Helper shared] startTransactionUpdatesListenerWithHandler:^(NSDictionary *transaction) {
            // Handler runs on the main GCD queue which shares the Qt main thread's run loop
            emit storeTransactionUpdated(toTransactionMap(transaction));
        }];
    }
}

void IosController::restorePurchases(std::function<void(bool success,
                                                       const QList<QVariantMap> &transactions,
                                                       const QString &errorString)> &&callback)
{
    if (@available(iOS 15.0, macOS 12.0, *)) {
        __block auto cb = std::move(callback);
        [[StoreKit2Helper shared] fetchCurrentEntitlementsWithCompletion:^(BOOL s,
                                                                           NSArray<NSDictionary *> * _Nullable restoredTransactions,
                                                                           NSError * _Nullable error) {
            QString err;
            if (error) {
                err = QString::fromUtf8(error.localizedDescription.UTF8String);
            }
            if (s) {
                qInfo().noquote() << "[IAP][IosController] currentEntitlements returned"
                                  << (int)(restoredTransactions ? restoredTransactions.count : 0) << "active entitlements";
            } else {
                qWarning().noquote() << "[IAP][IosController] fetchCurrentEntitlements failed:" << err;
            }
            if (cb) {
                cb(s, toTransactionList(restoredTransactions), err);
            }
        }];
    } else {
        if (callback) {
            callback(false, QList<QVariantMap>(), "StoreKit 2 requires iOS 15.0 or later");
        }
    }
}

void IosController::fetchLocalEntitlements(std::function<void(bool success,
                                                               const QList<QVariantMap> &transactions,
                                                               const QString &errorString)> &&callback)
{
    if (@available(iOS 15.0, macOS 12.0, *)) {
        __block auto cb = std::move(callback);
        [[StoreKit2Helper shared] fetchLocalEntitlementsWithCompletion:^(BOOL s,
                                                                         NSArray<NSDictionary *> * _Nullable entitlements,
                                                                         NSError * _Nullable error) {
            QString err;
            if (error) {
                err = QString::fromUtf8(error.localizedDescription.UTF8String);
            }
            if (cb) {
                cb(s, toTransactionList(entitlements), err);
            }
        }];
    } else {
        if (callback) {
            callback(false, QList<QVariantMap>(), "StoreKit 2 requires iOS 15.0 or later");
        }
    }
}

void IosController::fetchProducts(const QStringList &productIds,
                                  std::function<void(const QList<QVariantMap> &products,
                                                     const QStringList &invalidIds,
                                                     const QString &errorString)> &&callback)
{
    if (@available(iOS 15.0, macOS 12.0, *)) {
        NSMutableSet<NSString *> *ids = [NSMutableSet setWithCapacity:productIds.size()];
        for (const auto &pid : productIds) {
            [ids addObject:pid.toNSString()];
        }
        __block auto cb = std::move(callback);

        [[StoreKit2Helper shared] fetchProductsWithIdentifiers:ids
                                                    completion:^(NSArray<NSDictionary *> * _Nonnull products,
                                                                 NSArray<NSString *> * _Nonnull invalidIdentifiers,
                                                                 NSError * _Nullable error) {
            QList<QVariantMap> outProducts;
            for (NSDictionary *productInfo in products) {
                QVariantMap productData;
                productData["productId"] = QString::fromUtf8([productInfo[@"productId"] UTF8String]);
                productData["title"] = QString::fromUtf8([productInfo[@"title"] UTF8String]);
                productData["description"] = QString::fromUtf8([productInfo[@"description"] UTF8String]);
                productData["price"] = QString::fromUtf8([productInfo[@"price"] UTF8String]);
                if (productInfo[@"displayPrice"]) {
                    productData["displayPrice"] = QString::fromUtf8([productInfo[@"displayPrice"] UTF8String]);
                }
                productData["currencyCode"] = QString::fromUtf8([productInfo[@"currencyCode"] UTF8String]);
                if (productInfo[@"priceAmount"]) {
                    productData["priceAmount"] = [productInfo[@"priceAmount"] doubleValue];
                }
                if (productInfo[@"subscriptionBillingMonths"]) {
                    productData["subscriptionBillingMonths"] = [productInfo[@"subscriptionBillingMonths"] doubleValue];
                }
                if (productInfo[@"displayPricePerMonth"]) {
                    productData["displayPricePerMonth"] = QString::fromUtf8([productInfo[@"displayPricePerMonth"] UTF8String]);
                }
                if (productInfo[@"introOfferDisplayPrice"]) {
                    productData["introOfferDisplayPrice"] = QString::fromUtf8([productInfo[@"introOfferDisplayPrice"] UTF8String]);
                }
                if (productInfo[@"introOfferPaymentMode"]) {
                    productData["introOfferPaymentMode"] = QString::fromUtf8([productInfo[@"introOfferPaymentMode"] UTF8String]);
                }
                if (productInfo[@"hasFreeTrial"]) {
                    productData["hasFreeTrial"] = [productInfo[@"hasFreeTrial"] boolValue];
                }
                if (productInfo[@"trialDays"]) {
                    productData["trialDays"] = [productInfo[@"trialDays"] intValue];
                }
                outProducts.push_back(productData);
            }

            QStringList invalid;
            for (NSString *inv in invalidIdentifiers) {
                invalid.push_back(QString::fromUtf8(inv.UTF8String));
            }

            QString err;
            if (error) {
                err = QString::fromUtf8(error.localizedDescription.UTF8String);
            }

            if (cb) {
                cb(outProducts, invalid, err);
            }
        }];
    } else {
        if (callback) {
            callback(QList<QVariantMap>(), QStringList(), "StoreKit 2 requires iOS 15.0 or later");
        }
    }
}

void IosController::requestInetAccess() {
    NSURL *url = [NSURL URLWithString:@"http://captive.apple.com/generate_204"];
    if (!url) {
        qDebug() << "IosController::requestInetAccess URL error";
        return;
    }

    NSURLSession *session = [NSURLSession sharedSession];
    NSURLSessionDataTask *task = [session dataTaskWithURL:url completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        if (error) {
            qDebug() << "IosController::requestInetAccess error:" << error.localizedDescription;
        } else {
            NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *)response;
            QString responseBody = QString::fromUtf8((const char*)data.bytes, data.length);
        }
    }];
    [task resume];
}

bool IosController::isTestFlight() {
    NSURL *receiptURL = [[NSBundle mainBundle] appStoreReceiptURL];
    return receiptURL && [[receiptURL lastPathComponent] isEqualToString:@"sandboxReceipt"];
}

