#include "ios_controller.h"

#include <QDebug>
#include <QDateTime>
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
    emitConnectionStateForced(state);
}

void IosController::emitConnectionStateForced(Vpn::ConnectionState state)
{
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

// AVPN (ревью REV-2): фаза NE-сессии для решений натива (чистая логика — IosNativePolicy.h).
static avpn_ios::SessionPhase sessionPhase(NEVPNStatus status)
{
    switch (status) {
    case NEVPNStatusConnecting: return avpn_ios::SessionPhase::Starting;
    case NEVPNStatusConnected:
    case NEVPNStatusReasserting: return avpn_ios::SessionPhase::Live;
    case NEVPNStatusDisconnecting: return avpn_ios::SessionPhase::TearingDown;
    default: return avpn_ios::SessionPhase::Down;
    }
}

static NSString *managerIdentity(NETunnelProviderManager *manager)
{
    if (!manager) return nil;
    id proto = manager.protocolConfiguration;
    if (![proto isKindOfClass:[NETunnelProviderProtocol class]]) return nil;
    id identity = ((NETunnelProviderProtocol *)proto).providerConfiguration[@"tribeManagerId"];
    return [identity isKindOfClass:[NSString class]] ? (NSString *)identity : nil;
}

void IosController::setCurrentTunnel(NETunnelProviderManager *tunnel)
{
    // AVPN (C5/H7): каждый реконсил (configChange/foreground) отдаёт НОВЫЙ экземпляр менеджера того
    // же профиля. Раньше смена указателя инвалидировала ответ status, уже летящий от NE, — во время
    // роуминга это съедало подтверждение handshake. Тот же профиль (tribeManagerId) — та же сессия
    // наблюдения; поколение/заявки сбрасываем только при смене профиля. Новую NE-сессию того же
    // профиля отделяют connectVpn/disconnectVpn (явный ++m_statusGeneration) и не-Connected статус.
    // Вызывается только с Qt-потока (m_currentTunnel пишется только здесь же).
    NSString *oldIdentity = managerIdentity(m_currentTunnel);
    NSString *newIdentity = managerIdentity(tunnel);
    const bool sameProfile = oldIdentity && newIdentity && [oldIdentity isEqualToString:newIdentity];
    os_unfair_lock_lock(&s_tunnelOwnershipLock);
    if (tunnel == m_currentTunnel) {
        os_unfair_lock_unlock(&s_tunnelOwnershipLock);
        return;
    }
    NETunnelProviderManager *old = m_currentTunnel;
    [tunnel retain];
    m_currentTunnel = tunnel;
    if (!sameProfile) {
        ++m_statusGeneration;
        m_statusRequests.invalidate();
    }
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
    // prefs identify configuration, runtime status identifies each NE run. AVPN (REV-4): runtime
    // поколение закончившейся сессии на новый запуск того же профиля (Настройки/Control Center) не
    // переносим — иначе до первого status-ответа новая сессия носила чужой ключ (множество
    // «погашено приложением», сопоставление записи NE о стопе).
    if (!m_sessionRuntimeEnded && !restored.isEmpty()
        && m_sessionMetadata.value(QStringLiteral("configuration_generation")) == restored.value(QStringLiteral("generation")))
        restored = m_sessionMetadata;
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
    scheduleReconcileLoad(0);
}

// AVPN (фикс-волна 2026-09-22, C1 — источник блокера §2.1): дедлайн/ошибка loadAllFromPreferences —
// это ОТСУТСТВИЕ наблюдения, а не терминал туннеля. Раньше здесь эмитился Error (при живой
// NE-сессии и холодном старте GUI) → фасад защёлкивал «ждём подтверждённый down» → иконка VPN
// есть, кнопка серая. Теперь: ничего не эмитим, повторяем с backoff (ограниченно), поздний ответ
// того же запроса принимаем; после исчерпания — честное «статус неизвестен» (только лог).
void IosController::scheduleReconcileLoad(int attempt)
{
    if (m_connectPending || m_reconcileScheduled) return;
    m_reconcileScheduled = true;
    const uint64_t request = ++m_reconcileGeneration;
    const uint64_t operation = m_operationGeneration;
    QTimer::singleShot(avpn_ios::nativeTimings().reconcileDeadlineMs, this, [this, request, attempt] {
        if (m_reconcileGeneration != request || !m_reconcileScheduled) return;
        m_reconcileScheduled = false; // запрос остаётся текущим: поздний ответ ещё применим
        qWarning() << "[ios lifecycle] preference reconciliation timed out, attempt" << attempt;
#if defined(Q_OS_IOS)
        Avpn_recordLifecycle(QStringLiteral("reconcile_timeout"), {{QStringLiteral("attempt"), attempt}});
#endif
        retryReconcileLater(request, attempt);
    });
    [NETunnelProviderManager loadAllFromPreferencesWithCompletionHandler:^(NSArray<NETunnelProviderManager *> *managers, NSError *error) {
        [managers retain]; [error retain];
        QMetaObject::invokeMethod(this, [this, managers, error, request, operation, attempt] {
            if (request == m_reconcileGeneration && operation == m_operationGeneration) {
                const bool deadlinePassed = !m_reconcileScheduled;
                m_reconcileScheduled = false;
                if (error) {
                    qWarning() << "[ios lifecycle] preference reconciliation failed" << error.code;
                    if (!deadlinePassed) retryReconcileLater(request, attempt); // иначе повтор уже взведён дедлайном
                } else {
                    ++m_reconcileGeneration; // ответ получен: взведённый повтор этого запроса гаснет
                    NETunnelProviderManager *manager = selectOurManager(managers);
                    if (manager) {
                        setCurrentTunnel(manager);
                        restoreSessionMetadata(manager);
                        vpnStatusDidChange(manager.connection);
                    } else if (!m_currentTunnel || m_currentTunnel.connection.status == NEVPNStatusDisconnected ||
                               m_currentTunnel.connection.status == NEVPNStatusInvalid) {
                        setCurrentTunnel(nil);
                        restoreSessionMetadata(nil);
                        // AVPN (C2): отсутствие профиля (первый запуск / профиль удалён) — НЕ решение
                        // пользователя выключить VPN: intentional=false, один раз на переход.
                        emitDisconnectReason(QStringLiteral("profile_missing"), false);
                        emitConnectionStateIfChanged(Vpn::ConnectionState::Disconnected);
                    } // Loaded no profile but an old session still active: never invent its terminal.
                }
            }
            [managers release]; [error release];
        }, Qt::QueuedConnection);
    }];
}

void IosController::retryReconcileLater(uint64_t request, int attempt)
{
    const int delay = avpn_ios::retryDelayMs(attempt);
    if (delay < 0) {
        qWarning() << "[ios lifecycle] OS tunnel status unknown after" << attempt + 1 << "reconcile attempts";
#if defined(Q_OS_IOS)
        Avpn_recordLifecycle(QStringLiteral("reconcile_status_unknown"), {{QStringLiteral("attempts"), attempt + 1}});
#endif
        return; // честно «неизвестно»: терминал не выдумываем, следующий внешний запрос начнёт заново
    }
    QTimer::singleShot(delay, this, [this, request, attempt] {
        // Более новый запрос, полученный ответ или смена операции — повтор не нужен.
        if (m_reconcileGeneration != request || m_reconcileScheduled || m_connectPending) return;
        scheduleReconcileLoad(attempt + 1);
    });
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
    m_connectAwaitingTeardown = 0;
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
    m_creatingProfile = false;
    setPermissionPromptPending(false);
    armConnectDeadline(operation, avpn_ios::nativeTimings().connectDeadlineMs);
    [NETunnelProviderManager loadAllFromPreferencesWithCompletionHandler:^(NSArray<NETunnelProviderManager *> *managers, NSError *error) {
        [managers retain]; [error retain];
        QMetaObject::invokeMethod(this, [this, managers, error, operation] {
            if (operationCurrent(operation)) {
                if (error) {
                    m_connectPending = false;
                    ++m_connectDeadlineToken;
                    emitConnectionStateIfChanged(Vpn::ConnectionState::Error);
                } else {
                    NETunnelProviderManager *manager = selectOurManager(managers);
                    const avpn_ios::ConnectOverExisting existing = manager
                        ? avpn_ios::decideConnectOverExisting(sessionPhase(manager.connection.status))
                        : avpn_ios::ConnectOverExisting::StartNew;
                    if (existing == avpn_ios::ConnectOverExisting::AwaitTeardown) {
                        // AVPN (ревью REV-2): профиль гасится (стоп из Настроек/Shortcut, хвост нашего
                        // стопа). Он не живой: liveSessionFound здесь терял нажатие Connect (фасад ждал
                        // Connected, а приходил Disconnected = «внешний обрыв»). Ждём реальный
                        // Disconnected в пределах дедлайна коннекта и стартуем обычным путём.
                        setCurrentTunnel(manager);
                        m_currentTunnel.localizedDescription = @"Tribe VPN";
                        beginAwaitTeardown(operation);
                    } else if (existing == avpn_ios::ConnectOverExisting::AdoptLive) {
                        // AVPN (C3/K3): Connect застал СВОЙ живой профиль (Настройки/Shortcuts/Intent/прошлый
                        // запуск). Стартовать поверх нельзя, но и Error — ложь (туннель жив; Error защёлкивал
                        // фасад «ждём down» → серая кнопка при живой иконке). Снимаем заявку, восстанавливаем
                        // метаданные и говорим фасаду liveSessionFound() ДО реального статуса: он отменит
                        // свой старт и адоптирует следующий Connected.
                        setCurrentTunnel(manager);
                        m_connectPending = false;
                        ++m_connectDeadlineToken;
                        restoreSessionMetadata(manager);
#if defined(Q_OS_IOS)
                        Avpn_recordLifecycle(QStringLiteral("live_session_found"), {{QStringLiteral("status"), int(manager.connection.status)},
                            {QStringLiteral("session_generation"), m_sessionMetadata.value(QStringLiteral("generation"))}});
#endif
                        emit liveSessionFound();
                        vpnStatusDidChange(manager.connection);
                    } else {
                        const bool creating = (manager == nil);
                        setCurrentTunnel(manager ?: [[[NETunnelProviderManager alloc] init] autorelease]);
                        m_currentTunnel.localizedDescription = @"Tribe VPN";
                        if (creating) {
                            // AVPN (C4): save НОВОГО профиля на первом запуске показывает системный диалог
                            // «Разрешить VPN»; 10-секундный дедлайн накрывал его и рвал коннект, пока
                            // пользователь читал диалог. Пока ждём save — только длинный потолок;
                            // обычный дедлайн взводится от completion save (startTunnel).
                            m_creatingProfile = true;
                            setPermissionPromptPending(true);
                            armConnectDeadline(operation, avpn_ios::nativeTimings().permissionPromptCapMs);
                        }
                        if (!configureSelectedTunnel()) {
                            m_connectPending = false;
                            ++m_connectDeadlineToken;
                            m_creatingProfile = false;
                            setPermissionPromptPending(false);
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

void IosController::armConnectDeadline(uint64_t operation, int ms)
{
    const uint64_t token = ++m_connectDeadlineToken;
    QTimer::singleShot(ms, this, [this, operation, token] {
        if (token != m_connectDeadlineToken || m_operationGeneration != operation || !m_connectPending) return;
        ++m_operationGeneration; // save/load callbacks cannot start after the deadline
        m_connectPending = false;
        m_creatingProfile = false;
        setPermissionPromptPending(false);
        qWarning() << "[ios lifecycle] connect deadline";
#if defined(Q_OS_IOS)
        Avpn_recordLifecycle(QStringLiteral("connect_deadline"), {{QStringLiteral("operation_generation"), qulonglong(operation)}});
#endif
        emitConnectionStateIfChanged(Vpn::ConnectionState::Error);
        requestReconcileStatus();
    });
}

void IosController::setPermissionPromptPending(bool pending)
{
    if (m_permissionPromptPending == pending) return;
    m_permissionPromptPending = pending;
    emit permissionPromptPending(pending);
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
    ++m_connectDeadlineToken;
    m_creatingProfile = false;
    setPermissionPromptPending(false);
    m_connectAwaitingTeardown = 0;
    markLocalStopRequested();
    ++m_statusGeneration;
    m_statusRequests.invalidate();

    // AVPN: если гасить нечего (нет менеджера / нет сессии / уже опущен) — эмитим Disconnected СРАЗУ,
    // чтобы движок не повис в ожидании. Если сессия ЖИВАЯ — только stopTunnel; РЕАЛЬНЫЙ Disconnected
    // прилетит из vpnStatusDidChange (его и ждёт reconcile перед реконнектом на новый сервер — это и есть
    // «как в Amnezia»: не стартуем новый туннель, пока старый не дошёл до Disconnected).
    // AVPN (C1): терминалы этих веток — напрямую (emitConnectionStateForced): движок после
    // disconnectFromVpn стоит в Disconnecting и должен получить ответ, даже если прошлый эмит
    // натива уже был Disconnected (дедуп ...IfChanged его проглатывал).
    if (!m_currentTunnel) {
        // A stopped GUI may not have discovered an active Settings/Intent session yet.
        discoverTunnelToStop(m_operationGeneration, 0);
        return;
    }
    if (![m_currentTunnel.connection isKindOfClass:[NETunnelProviderSession class]]) {
        m_localStopRequested = false; // гасить нечем — флаг не должен залипать до следующего обрыва
        emitConnectionStateForced(Vpn::ConnectionState::Error);
        return;
    }
    NEVPNStatus st = m_currentTunnel.connection.status;
    if (st == NEVPNStatusDisconnected || st == NEVPNStatusInvalid) {
        m_localStopRequested = false;
        emitDisconnectReason(QStringLiteral("expected_app_stop"), false);
        emitConnectionStateForced(Vpn::ConnectionState::Disconnected);
        return;
    }
    noteAppStopForCurrentSession();
    [(NETunnelProviderSession *)m_currentTunnel.connection stopTunnel];
}

// AVPN (C1): менеджер ещё не найден (холодный старт GUI при живой Settings/Intent-сессии).
// Дедлайн/ошибка loadAll — не доказательство down и не повод для Error: повторяем с backoff;
// поздний ответ принимаем; после исчерпания — честное «статус неизвестен» (ничего не эмитим,
// m_localStopRequested снимается — иначе следующий внешний обрыв ошибочно считался бы нашим).
void IosController::discoverTunnelToStop(uint64_t operation, int attempt)
{
    const auto settled = std::make_shared<bool>(false);
    const auto noObservation = [this, operation, attempt, settled](const char *why) {
        if (*settled) return;
        *settled = true;
        if (m_operationGeneration != operation || !m_localStopRequested) return;
        const int delay = avpn_ios::retryDelayMs(attempt);
        qWarning() << "[ios lifecycle] stop discovery:" << why << "attempt" << attempt;
#if defined(Q_OS_IOS)
        Avpn_recordLifecycle(QStringLiteral("stop_discovery_retry"), {{QStringLiteral("why"), QString::fromLatin1(why)},
                                                                      {QStringLiteral("attempt"), attempt}});
#endif
        if (delay < 0) {
            m_localStopRequested = false;
#if defined(Q_OS_IOS)
            Avpn_recordLifecycle(QStringLiteral("stop_status_unknown"), {{QStringLiteral("attempts"), attempt + 1}});
#endif
            requestReconcileStatus(); // реальный статус придёт наблюдением, если оно вообще случится
            return;
        }
        QTimer::singleShot(delay, this, [this, operation, attempt] {
            if (m_operationGeneration != operation || !m_localStopRequested) return;
            if (m_currentTunnel) {
                disconnectVpn(); // профиль нашёлся иным путём (реконсил) — гасим его
                return;
            }
            discoverTunnelToStop(operation, attempt + 1);
        });
    };
    QTimer::singleShot(avpn_ios::nativeTimings().reconcileDeadlineMs, this, [noObservation] { noObservation("timeout"); });
    [NETunnelProviderManager loadAllFromPreferencesWithCompletionHandler:^(NSArray<NETunnelProviderManager *> *managers, NSError *error) {
        [managers retain]; [error retain];
        QMetaObject::invokeMethod(this, [this, managers, error, operation, noObservation, settled] {
            if (operation == m_operationGeneration && m_localStopRequested) {
                if (error) {
                    noObservation("error");
                } else {
                    *settled = true; // поздний ответ тоже годится: это реальное наблюдение
                    NETunnelProviderManager *manager = selectOurManager(managers);
                    if (manager) {
                        setCurrentTunnel(manager);
                        restoreSessionMetadata(manager);
                        disconnectVpn();
                    } else {
                        m_localStopRequested = false;
                        emitDisconnectReason(QStringLiteral("expected_app_stop"), false);
                        emitConnectionStateForced(Vpn::ConnectionState::Disconnected);
                    }
                }
            }
            [managers release]; [error release];
        }, Qt::QueuedConnection);
    }];
}

void IosController::noteAppStopForCurrentSession()
{
    // AVPN (ревью CL-C REV-4): в множество «погашено приложением» — только runtime-поколение ЖИВОЙ
    // сессии. Поколение конфигурации (статус-ответа ещё не было) у следующей сессии того же профиля
    // из Настроек то же — её пользовательский стоп стал бы expected_app_stop. Для этого случая
    // стоп опознаётся флагом m_localStopRequested (+ localStopSupersededByNewSession).
    if (m_sessionRuntimeEnded || !m_sessionMetadata.contains(QStringLiteral("configuration_generation"))) return;
    m_disconnectGate.noteAppStop(m_sessionMetadata.value(QStringLiteral("generation")).toString().toStdString());
}

// AVPN (REV-4): сессия закончилась (наблюдали Disconnected) — её runtime-метаданные больше не
// описывают текущий профиль. Откатываемся на метаданные конфигурации из prefs.
void IosController::noteSessionRuntimeEnded()
{
    m_sessionRuntimeEnded = true;
    if (m_currentTunnel && m_sessionMetadata.contains(QStringLiteral("configuration_generation")))
        restoreSessionMetadata(m_currentTunnel);
}

// AVPN (ревью REV-3): стоп приложения запоминает, ЧЬЮ сессию гасили. Флаг снимается не только
// наблюдением её Disconnected (GUI в фоне может его пропустить), но и доказательством новой
// сессии (avpn_ios::localStopSupersededByNewSession) — иначе пользовательский стоп следующей
// сессии из Настроек приходил как expected_app_stop (intentional=false).
void IosController::markLocalStopRequested()
{
    m_localStopRequested = true;
    m_localStopInfo.generation = m_sessionMetadata.value(QStringLiteral("generation")).toString().toStdString();
    m_localStopInfo.generationIsRuntime = m_sessionMetadata.contains(QStringLiteral("configuration_generation"));
    NEVPNStatus st = NEVPNStatusInvalid;
    if (m_currentTunnel) st = m_currentTunnel.connection.status;
    m_localStopInfo.stoppedLiveSession = (st == NEVPNStatusConnected || st == NEVPNStatusReasserting);
}

void IosController::clearLocalStopIfNewSession(bool observedConnecting)
{
    if (!m_localStopRequested) return;
    const std::string generation = m_sessionMetadata.value(QStringLiteral("generation")).toString().toStdString();
    const bool runtime = m_sessionMetadata.contains(QStringLiteral("configuration_generation"));
    if (!avpn_ios::localStopSupersededByNewSession(m_localStopInfo, observedConnecting, generation, runtime,
                                                   m_disconnectGate.isAppStopped(generation)))
        return;
    m_localStopRequested = false;
    m_localStopInfo = {};
#if defined(Q_OS_IOS)
    Avpn_recordLifecycle(QStringLiteral("local_stop_superseded"), {{QStringLiteral("session_generation"), QString::fromStdString(generation)},
                                                                   {QStringLiteral("connecting"), observedConnecting}});
#endif
}

void IosController::beginAwaitTeardown(uint64_t operation)
{
    m_connectAwaitingTeardown = operation;
#if defined(Q_OS_IOS)
    Avpn_recordLifecycle(QStringLiteral("connect_awaits_teardown"), {{QStringLiteral("operation_generation"), qulonglong(operation)}});
#endif
    recheckTeardown(operation);
}

// Терминал мог наступить до того, как мы начали ждать, а уведомление — прийти другому экземпляру
// сессии (реконсил во время заявки коннекта не бежит): перепроверяем статус сразу и затем с шагом.
// Ожидание ограничено дедлайном коннекта (armConnectDeadline снимает заявку → operationCurrent=false).
void IosController::recheckTeardown(uint64_t operation)
{
    if (m_connectAwaitingTeardown != operation) return;
    switch (continueConnectAfterTeardown()) {
    case TeardownStep::Waiting:
        QTimer::singleShot(250, this, [this, operation] { recheckTeardown(operation); });
        break;
    case TeardownStep::LiveFound:
        vpnStatusDidChange(m_currentTunnel.connection); // реальный статус — после liveSessionFound
        break;
    default:
        break;
    }
}

IosController::TeardownStep IosController::continueConnectAfterTeardown()
{
    const uint64_t operation = m_connectAwaitingTeardown;
    if (!operation) return TeardownStep::NotAwaiting;
    if (!operationCurrent(operation) || !m_currentTunnel) {
        m_connectAwaitingTeardown = 0; // дедлайн/стоп/смена намерения — обычная обработка наблюдений
        return TeardownStep::NotAwaiting;
    }
    const avpn_ios::SessionPhase phase = sessionPhase(m_currentTunnel.connection.status);
    if (phase == avpn_ios::SessionPhase::TearingDown) return TeardownStep::Waiting; // фасад в Op::Starting
    m_connectAwaitingTeardown = 0;
    if (phase == avpn_ios::SessionPhase::Down) {
        // Старая сессия погашена. Её Disconnected поглощаем без disconnectReason: нажатие Connect
        // пользователя новее этого стопа, а intentional=true (стоп из Настроек) снял бы только что
        // выраженное намерение «вкл» и отменил наш старт.
        m_disconnectGate.claimReport();
        m_disconnectGate.clearLive();
        m_localStopRequested = false;
        m_localStopInfo = {};
        noteSessionRuntimeEnded();
#if defined(Q_OS_IOS)
        Avpn_recordLifecycle(QStringLiteral("connect_after_teardown"), {{QStringLiteral("operation_generation"), qulonglong(operation)}});
#endif
        if (!configureSelectedTunnel()) {
            m_connectPending = false;
            ++m_connectDeadlineToken;
            emitConnectionStateIfChanged(Vpn::ConnectionState::Error);
        }
        return TeardownStep::StartContinued;
    }
    // За время ожидания профиль снова поднялся (Настройки/Shortcut) — это живая сессия (K3).
    m_connectPending = false;
    ++m_connectDeadlineToken;
    restoreSessionMetadata(m_currentTunnel);
#if defined(Q_OS_IOS)
    Avpn_recordLifecycle(QStringLiteral("live_session_found"), {{QStringLiteral("status"), int(m_currentTunnel.connection.status)},
        {QStringLiteral("session_generation"), m_sessionMetadata.value(QStringLiteral("generation"))}});
#endif
    emit liveSessionFound();
    return TeardownStep::LiveFound; // вызывающий пересылает реальный статус
}

void IosController::emitDisconnectReason(const QString &reason, bool intentional)
{
    if (!m_disconnectGate.claimReport()) return; // K2: не более одного раза на переход в Disconnected
    emit disconnectReason(reason, intentional);
#if defined(Q_OS_IOS)
    Avpn_recordLifecycle(QStringLiteral("disconnect_reason"), {{QStringLiteral("reason"), reason},
        {QStringLiteral("intentional"), intentional},
        {QStringLiteral("session_generation"), m_sessionMetadata.value(QStringLiteral("generation"))}});
#endif
}

// AVPN (фикс-волна 2026-09-22, C2/K2): причина перехода в Disconnected. Раньше intentional = последний
// intent "off"/"pause" независимо от того, кто гасил: стоп самого приложения (свитч/реконнект,
// 3 таймаута рукопожатия) и внешний обрыв туннеля, поднятого из Настроек после давнего OFF
// («липкий intent»), снимали намерение в фасаде → «VPN сам выключается». И каждый реконсил
// переэмитил причину. Решение — avpn_ios::decideDisconnect (юнит-тесты IosNativePolicyTests).
void IosController::reportDisconnected()
{
#if defined(Q_OS_IOS)
    const QString sessionGeneration = m_sessionMetadata.value(QStringLiteral("generation")).toString();
    if (!m_disconnectGate.reported()) {
        avpn_ios::DisconnectInputs in;
        in.localStopRequested = m_localStopRequested;
        in.sessionGeneration = sessionGeneration.toStdString();
        in.sessionConfigurationGeneration =
            m_sessionMetadata.value(QStringLiteral("configuration_generation")).toString().toStdString();
        in.appStoppedGeneration = m_disconnectGate.isAppStopped(in.sessionGeneration);
        const QVariantMap intent = Avpn_currentIntent();
        in.intentAction = intent.value(QStringLiteral("action")).toString().toStdString();
        in.intentGeneration = intent.value(QStringLiteral("generation")).toString().toStdString();
        in.haveLiveBaseline = m_disconnectGate.haveLive();
        in.intentGenerationAtLive = m_disconnectGate.intentAtLive();
        in.liveSinceMs = m_disconnectGate.liveSinceMs();
        const QVariantMap stop = Avpn_lastStop();
        in.neStop.present = !stop.isEmpty();
        in.neStop.generation = stop.value(QStringLiteral("generation")).toString().toStdString();
        in.neStop.configurationGeneration = stop.value(QStringLiteral("configuration_generation")).toString().toStdString();
        in.neStop.reason = stop.value(QStringLiteral("reason")).toInt();
        in.neStop.intentional = stop.value(QStringLiteral("intentional")).toBool();
        in.neStop.utcMs = stop.value(QStringLiteral("utc_ms")).toLongLong();
        in.nowMs = QDateTime::currentMSecsSinceEpoch();
        const avpn_ios::DisconnectDecision decision = avpn_ios::decideDisconnect(in);
        if (in.neStop.present) {
            // Разбор журнала 25.09: запись NE о последнем стопе — в лог, даже когда она не отнесена к
            // этой сессии (ночной стоп при холодном старте уходил в unknown_external без причины;
            // reason — NEProviderStopReason: 11 другой VPN, 16 обновление приложения).
            qInfo().noquote() << QStringLiteral("[ios lifecycle] NE last stop reason=%1 intentional=%2 age_s=%3 -> %4")
                                         .arg(in.neStop.reason)
                                         .arg(in.neStop.intentional ? 1 : 0)
                                         .arg((in.nowMs - in.neStop.utcMs) / 1000)
                                         .arg(QString::fromStdString(decision.reason));
        }
        emitDisconnectReason(QString::fromStdString(decision.reason), decision.intentional);
    }
#else
    emitDisconnectReason(m_localStopRequested ? QStringLiteral("expected_app_stop") : QStringLiteral("unknown_external"), false);
#endif
    m_localStopRequested = false;
    m_localStopInfo = {};
    m_disconnectGate.clearLive();
    noteSessionRuntimeEnded();
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
    // AVPN (C5): дедлайн освобождает только СЛОТ заявки (можно начать следующую); поздний ответ
    // этой заявки всё равно применится, если он новее последнего применённого (accept ниже).
    QTimer::singleShot(avpn_ios::nativeTimings().statusDeadlineMs, this, [this, gen, request] {
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
            // AVPN (C5/H7): владение заявкой (complete — exactly-once) и применение полезной нагрузки
            // (accept — request новее последнего применённого) разделены: ответ, опоздавший за
            // 3-секундный дедлайн (роуминг, workQueue адаптера), больше не теряет handshake/rx/tx.
            m_statusRequests.complete(gen, request);
            if (m_statusGeneration.load() != gen || !m_statusRequests.accept(gen, request))
                return;
            if (metadata.value(QStringLiteral("schema_version")).toInt() == 1 &&
                !metadata.value(QStringLiteral("generation")).toString().isEmpty()) {
                m_sessionRuntimeEnded = false; // AVPN (REV-4): runtime-поколение живой сессии
                if (m_sessionMetadata != metadata) {
                    m_sessionMetadata = metadata;
                    emit sessionMetadataChanged(metadata);
                }
            }
            clearLocalStopIfNewSession(false); // AVPN (REV-3): runtime-поколение новой NE-сессии
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
                            // AVPN (C2/K2): этот стоп — решение приложения, не пользователя: NE запишет
                            // .userInitiated, но Disconnected должен прийти как expected_app_stop.
                            markLocalStopRequested();
                            noteAppStopForCurrentSession();
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
// (retained-менеджер + provider message). Подтверждение heal'а — сам data-plane (HealthLoop),
// а факт выполнения (K4) — ответ NE: {"rebind":"performed"} | {"rebind":"denied","reason":...}.
// Раньше fire-and-forget: отказ NE по бюджету/«адаптер не запущен» GUI считал успешным
// ребайндом → failover откладывался на лишние DEAD-циклы.
bool IosController::rebindTunnel()
{
    if (QThread::currentThread() != thread()) {
        // Сигнал и дедлайн живут на Qt-потоке контроллера; вызывающий с чужого потока получает
        // «отправляется» (true), итог — rebindFinished.
        QMetaObject::invokeMethod(this, [this] { if (!rebindTunnel()) emit rebindFinished(false); }, Qt::QueuedConnection);
        return true;
    }
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
    // exactly-once: ответ NE / nil-колбэк / дедлайн 3 с соревнуются за один флаг.
    const auto finished = std::make_shared<std::atomic_bool>(false);
    // AVPN (ревью REV-5): сигнал без идентификатора заявки — итог перекрытого вызова (поздний false
    // дедлайна/медленного ответа) не должен закрыть ожидание более нового rebind в ServiceEngine.
    const uint64_t seq = ++m_rebindSeq;
    QTimer::singleShot(avpn_ios::nativeTimings().rebindReplyDeadlineMs, this, [this, finished, seq] {
        if (finished->exchange(true)) return;
        qWarning() << "IosController::rebindTunnel : no extension reply in time";
        if (seq != m_rebindSeq) return; // перекрыт более новым rebindTunnel()
        emit rebindFinished(false);
    });
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        // tunnel: наш retain отпускается в конце блока (паттерн checkStatus) — ответ-хендлер
        // менеджер не трогает. Разбор ответа — здесь (NSDictionary живёт только в хендлере).
        sendVpnExtensionMessage(tunnel, message, [this, finished, seq](NSDictionary *response) {
            id rebind = response[@"rebind"];
            id legacyOk = response[@"ok"];
            id reason = response[@"reason"];
            const bool hasRebind = [rebind isKindOfClass:[NSString class]];
            const bool hasLegacyOk = [legacyOk respondsToSelector:@selector(boolValue)];
            const bool performed = avpn_ios::rebindPerformed(
                response != nil, hasRebind, hasRebind ? std::string([(NSString *)rebind UTF8String] ?: "") : std::string(),
                hasLegacyOk, hasLegacyOk && [legacyOk boolValue]);
            const QString detail = hasRebind ? QString::fromNSString((NSString *)rebind)
                                   + ([reason isKindOfClass:[NSString class]] ? QLatin1Char('/') + QString::fromNSString((NSString *)reason) : QString())
                                 : response ? QStringLiteral("legacy") : QStringLiteral("no-reply");
            QMetaObject::invokeMethod(this, [this, finished, performed, detail, seq] {
                if (finished->exchange(true)) return;
                qInfo() << "IosController::rebindTunnel : extension replied" << detail << "performed" << performed;
                if (seq != m_rebindSeq) return; // перекрыт более новым rebindTunnel()
                emit rebindFinished(performed);
            }, Qt::QueuedConnection);
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
    // AVPN (ревью REV-2): Connect ждёт терминал гасящегося профиля — его Disconnecting/Disconnected
    // фасаду не пересылаем (он в своём Op::Starting), по Disconnected продолжаем старт.
    if (m_connectAwaitingTeardown) {
        const TeardownStep step = continueConnectAfterTeardown();
        if (step == TeardownStep::Waiting || step == TeardownStep::StartContinued) return;
    }
    if (!m_currentTunnel || (NETunnelProviderSession *)m_currentTunnel.connection != session) {
        requestReconcileStatus();
        return;
    }

    qDebug() << "IosController::vpnStatusDidChange" << iosStatusToState(session.status) << session;

        if (session.status != NEVPNStatusDisconnected && session.status != NEVPNStatusInvalid) {
            // AVPN (K2): сессия наблюдается не в Disconnected — следующий Disconnected будет новым
            // переходом (одна причина на переход). Живая фаза фиксирует базовую линию intent:
            // намерение "off", записанное ДО неё, для обрыва этой сессии «липкое» и не считается.
            m_disconnectGate.noteNotDisconnected();
#if defined(Q_OS_IOS)
            if (session.status != NEVPNStatusDisconnecting)
                m_disconnectGate.noteLive(Avpn_currentIntentGeneration().toStdString(), QDateTime::currentMSecsSinceEpoch());
#endif
            if (session.status != NEVPNStatusDisconnecting)
                clearLocalStopIfNewSession(session.status == NEVPNStatusConnecting);
        }
        if (session.status == NEVPNStatusDisconnected) {
            const bool firstReport = !m_disconnectGate.reported();
            reportDisconnected();
            if (!firstReport) {
                // повторное наблюдение того же Disconnected (реконсил) — причина уже сообщена
            } else if (@available(iOS 16.0, *)) {
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
                // AVPN (холодный старт, разбор журнала 25.09): давно живую сессию, пережившую выгрузку
                // приложения, показываем Connected сразу; рукопожатие проверяется ниже, как раньше.
                NSDate *connectedAt = session.connectedDate;
                const long long connectedForMs =
                        connectedAt ? (long long)(-[connectedAt timeIntervalSinceNow] * 1000.0) : -1;
                const bool previouslyLive = m_lastEmittedState == Vpn::ConnectionState::Connected ||
                        m_lastEmittedState == Vpn::ConnectionState::Connecting ||
                        m_lastEmittedState == Vpn::ConnectionState::Reconnecting;
                nextState = avpn_ios::showEstablishedAsConnected(m_connectPending, previouslyLive, connectedForMs)
                        ? Vpn::ConnectionState::Connected
                        : Vpn::ConnectionState::Connecting;
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
            if (operation == m_operationGeneration && m_connectPending && !operationCurrent(operation)) {
                // AVPN (ревью CL-C REV-3): пока был открыт диалог «Разрешить VPN», намерение сменилось
                // (Shortcut off/pause). Старт не выполняем, но и не ждём 120-секундный потолок с Error
                // в конце: заявку снимаем сразу, флаг диалога гасим, отдаём реальный статус (как в
                // ветке NotCurrent у старта).
                m_creatingProfile = false;
                setPermissionPromptPending(false);
                m_connectPending = false;
                ++m_connectDeadlineToken;
#if defined(Q_OS_IOS)
                Avpn_recordLifecycle(QStringLiteral("start_intent_superseded"), {{QStringLiteral("stage"), QStringLiteral("save")}});
#endif
                if (tunnel == m_currentTunnel) vpnStatusDidChange(tunnel.connection);
            } else if (operationCurrent(operation)) {
                // AVPN (C4): save нового профиля завершён (диалог «Разрешить VPN» закрыт) — обычный
                // дедлайн коннекта взводится ОТ этого момента, а не от нажатия Connect.
                const bool wasCreating = m_creatingProfile;
                m_creatingProfile = false;
                setPermissionPromptPending(false);
                if (saveError) {
                    m_connectPending = false;
                    ++m_connectDeadlineToken;
                    emitConnectionStateIfChanged(Vpn::ConnectionState::Error);
                } else {
                    if (wasCreating) armConnectDeadline(operation, avpn_ios::nativeTimings().connectDeadlineMs);
                    [tunnel loadFromPreferencesWithCompletionHandler:^(NSError *loadError) {
                        [tunnel retain]; [loadError retain];
                        QMetaObject::invokeMethod(this, [this, tunnel, loadError, operation] {
                            if (operationCurrent(operation)) {
                                m_connectPending = false;
                                ++m_connectDeadlineToken;
                                if (loadError) {
                                    emitConnectionStateIfChanged(Vpn::ConnectionState::Error);
                                } else if (tunnel.connection.status == NEVPNStatusDisconnected || tunnel.connection.status == NEVPNStatusInvalid) {
                                    NSError *startError = nil;
                                    BOOL started = NO;
#if defined(Q_OS_IOS)
                                    const AvpnIntentPerform performed = Avpn_performIfCurrent(m_operationIntentGeneration, [&] {
                                        started = [tunnel.connection startVPNTunnelWithOptions:nil andReturnError:&startError];
                                    });
                                    if (performed == AvpnIntentPerform::NotCurrent) {
                                        // Намерение сменилось до старта (Shortcut/NE): это не ошибка коннекта.
                                        // Отдаём реальный наблюдаемый статус (туннель опущен — проверено выше).
                                        Avpn_recordLifecycle(QStringLiteral("start_intent_superseded"));
                                        vpnStatusDidChange(tunnel.connection);
                                    } else
#else
                                    started = [tunnel.connection startVPNTunnelWithOptions:nil andReturnError:&startError];
#endif
                                    if (!started || startError) {
                                        emitConnectionStateIfChanged(Vpn::ConnectionState::Error);
                                    } else {
                                        // Впереди новый переход; следующий Disconnected — новая причина (K2).
                                        m_disconnectGate.noteStartIssued();
                                        // AVPN (ревью REV-3): новая сессия — флаг стопа прошлой ей не принадлежит.
                                        m_localStopRequested = false;
                                        m_localStopInfo = {};
#if defined(Q_OS_IOS)
                                        if (performed == AvpnIntentPerform::Superseded) {
                                            // За время start записали новое намерение. Выключение/пауза
                                            // побеждают наш старт; повторный resume — нет.
                                            const QString action = Avpn_currentIntent().value(QStringLiteral("action")).toString();
                                            Avpn_recordLifecycle(QStringLiteral("start_intent_raced"), {{QStringLiteral("action"), action}});
                                            if (action == QLatin1String("off") || action == QLatin1String("pause"))
                                                [(NETunnelProviderSession *)tunnel.connection stopTunnel];
                                        }
#endif
                                        // AVPN (C9): НЕ перечитываем connection.status синхронно — сразу после
                                        // startVPNTunnelWithOptions он ещё Disconnected (обновляется асинхронно),
                                        // и движок получал ложный терминал для Op::Starting. Реальный статус
                                        // придёт NEVPNStatusDidChangeNotification (Connecting → Connected).
                                    }
                                } else if (sessionPhase(tunnel.connection.status) == avpn_ios::SessionPhase::TearingDown) {
                                    // AVPN (ревью REV-2): профиль гасится — не живой; ждём его Disconnected
                                    // и стартуем (заявка и дедлайн коннекта возвращаются).
                                    m_connectPending = true;
                                    armConnectDeadline(operation, avpn_ios::nativeTimings().connectDeadlineMs);
                                    beginAwaitTeardown(operation);
                                } else {
                                    // A Settings/Intent start won the race: observe it, do not start over it.
                                    // AVPN (K3): это тот же случай «Connect застал живой профиль».
                                    restoreSessionMetadata(tunnel);
                                    emit liveSessionFound();
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

