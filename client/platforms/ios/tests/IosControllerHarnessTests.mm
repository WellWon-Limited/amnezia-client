// AVPN (фикс-волна 2026-09-22, зона CL-C): поведенческий харнесс IosController на macOS.
//
// Настоящий ios_controller.mm (MRC, -DQ_OS_IOS -DMACOS_NE=1) + подменённый NetworkExtension:
// +[NETunnelProviderManager loadAllFromPreferencesWithCompletionHandler:], save/load и
// -connection свизлятся на управляемые тестом фейки; NETunnelProviderSession — подкласс с
// программируемыми статусом, stopTunnel/start и ответами provider message. Intent-хранилище
// (AvpnIntentController.h) — в памяти. Каждый тест — отдельный процесс (синглтон контроллера).
//
// Сборка/запуск: build_ios_controller_harness.sh (BASE=<rev> собирает против старого кода —
// доказательство, что тесты ловят дефект). HARNESS_OLD=1 — API старого кода (bool performIfCurrent,
// без IosNativePolicy.h).
#include "ios_controller.h"
#include "AvpnIntentController.h"
#include "HarnessSwift.h" // шим StoreKit2Helper (генерируется build_ios_controller_harness.sh)
#import <NetworkExtension/NetworkExtension.h>
#import <objc/runtime.h>
#import <objc/message.h>
#include <QCoreApplication>
#include <QDateTime>
#include <QEventLoop>
#include <QJsonObject>
#include <QTimer>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <string>
#include <vector>
#ifndef HARNESS_OLD
#include "IosNativePolicy.h"
#endif

// ------------------------------------------------------------------------------------------------
// Время: новый код сжат через avpn_ios::nativeTimings(); для старого — его боевые константы.
#ifdef HARNESS_OLD
static int W(int, int oldMs) { return oldMs; }
#else
static int W(int newMs, int) { return newMs; }
#endif

static int g_failures = 0;
#define CHECK(cond, msg)                                                                  \
    do {                                                                                  \
        if (!(cond)) {                                                                    \
            ++g_failures;                                                                 \
            std::fprintf(stderr, "  CHECK FAILED %s:%d: %s  [%s]\n", __FILE__, __LINE__, \
                         msg, #cond);                                                     \
        }                                                                                 \
    } while (0)

static void spin(int ms)
{
    QEventLoop loop;
    QTimer::singleShot(ms, &loop, &QEventLoop::quit);
    loop.exec();
}

// ------------------------------------------------------------------------------------------------
// Intent-хранилище в памяти (вместо App Group).
static QVariantMap g_intent;
static QVariantMap g_lastStop;
static std::function<void()> g_duringPerform;
QVariantMap Avpn_currentIntent() { return g_intent; }
QString Avpn_currentIntentGeneration() { return g_intent.value(QStringLiteral("generation")).toString(); }
QVariantMap Avpn_lastStop() { return g_lastStop; }
void Avpn_recordLifecycle(const QString &, const QVariantMap &) {}
#ifdef HARNESS_OLD
bool Avpn_performIfCurrent(const QString &generation, const std::function<void()> &action)
{
    if (Avpn_currentIntentGeneration() != generation) return false;
    action();
    if (g_duringPerform) g_duringPerform();
    return true;
}
#else
AvpnIntentPerform Avpn_performIfCurrent(const QString &generation, const std::function<void()> &action)
{
    if (Avpn_currentIntentGeneration() != generation) return AvpnIntentPerform::NotCurrent;
    action();
    if (g_duringPerform) g_duringPerform();
    return Avpn_currentIntentGeneration() == generation ? AvpnIntentPerform::Performed
                                                        : AvpnIntentPerform::Superseded;
}
#endif
static void setIntent(const char *generation, const char *action)
{
    g_intent = {{QStringLiteral("generation"), QString::fromLatin1(generation)},
                {QStringLiteral("action"), QString::fromLatin1(action)},
                {QStringLiteral("source"), QStringLiteral("gui")},
                {QStringLiteral("applied"), true}};
}

// Линк-стабы зависимостей, которые харнессу не нужны.
namespace amnezia { namespace ProtocolUtils {
QString key_proto_config_data(Proto) { return QStringLiteral("awg_config_data"); }
} }
@implementation StoreKit2Helper
+ (instancetype)shared { return nil; }
- (void)purchaseProductWithProductIdentifier:(NSString *)p completion:(void (^)(BOOL, NSString *, NSString *, NSString *, NSString *, NSError *))c {}
- (void)finishTransactionWithTransactionId:(NSString *)t completion:(void (^)(BOOL))c {}
- (void)startTransactionUpdatesListenerWithHandler:(void (^)(NSDictionary *))h {}
- (void)fetchCurrentEntitlementsWithCompletion:(void (^)(BOOL, NSArray *, NSError *))c {}
- (void)fetchLocalEntitlementsWithCompletion:(void (^)(BOOL, NSArray *, NSError *))c {}
- (void)fetchProductsWithIdentifiers:(NSSet *)ids completion:(void (^)(NSArray *, NSArray *, NSError *))c {}
@end

// ------------------------------------------------------------------------------------------------
// Фейковая сессия NE.
static void notifyStatus(NETunnelProviderSession *session);

@interface HarnessSession : NETunnelProviderSession
@property (nonatomic, assign) NEVPNStatus hStatus;
@property (nonatomic, assign) int stopCalls;
@property (nonatomic, assign) int startCalls;
@property (nonatomic, assign) BOOL autoStop;
@property (nonatomic, assign) BOOL autoStart;
@property (nonatomic, retain) NSDictionary *statusReply;
@property (nonatomic, assign) int statusReplyDelayMs;
@property (nonatomic, retain) NSDictionary *rebindReply;
@property (nonatomic, assign) BOOL rebindNoReply;
@property (nonatomic, assign) BOOL stopWritesUserInitiated;
@property (nonatomic, copy) NSString *runtimeGeneration;
@property (nonatomic, copy) NSString *configurationGeneration;
@property (nonatomic, retain) NSDate *hConnectedDate; // nil — время подключения неизвестно
@end

@implementation HarnessSession
- (NEVPNStatus)status { return self.hStatus; }
- (NSDate *)connectedDate { return self.hConnectedDate; }
- (void)fetchLastDisconnectErrorWithCompletionHandler:(void (^)(NSError *))handler { if (handler) handler(nil); }
- (void)stopTunnel
{
    self.stopCalls = self.stopCalls + 1;
    if (self.stopWritesUserInitiated) {
        // NE записывает .userInitiated и на stopVPNTunnel самого приложения.
        g_lastStop = {{QStringLiteral("generation"), QString::fromNSString(self.runtimeGeneration ?: @"")},
                      {QStringLiteral("configuration_generation"), QString::fromNSString(self.configurationGeneration ?: @"")},
                      {QStringLiteral("reason"), 1}, {QStringLiteral("intentional"), true},
                      {QStringLiteral("utc_ms"), QDateTime::currentMSecsSinceEpoch()}};
    }
    if (!self.autoStop) return;
    HarnessSession *me = [self retain];
    QTimer::singleShot(10, qApp, [me] { me.hStatus = NEVPNStatusDisconnecting; notifyStatus(me); });
    QTimer::singleShot(40, qApp, [me] { me.hStatus = NEVPNStatusDisconnected; notifyStatus(me); [me release]; });
}
- (BOOL)startVPNTunnelWithOptions:(NSDictionary *)options andReturnError:(NSError **)error
{
    self.startCalls = self.startCalls + 1;
    if (self.autoStart) {
        HarnessSession *me = [self retain];
        QTimer::singleShot(50, qApp, [me] { me.hStatus = NEVPNStatusConnecting; notifyStatus(me); });
        QTimer::singleShot(90, qApp, [me] { me.hStatus = NEVPNStatusConnected; notifyStatus(me); [me release]; });
    }
    return YES; // статус остаётся Disconnected синхронно — как в реальном NE (C9)
}
- (BOOL)sendProviderMessage:(NSData *)messageData returnError:(NSError **)error responseHandler:(void (^)(NSData *))handler
{
    NSDictionary *message = [NSJSONSerialization JSONObjectWithData:messageData options:0 error:nil];
    NSString *action = message[@"action"];
    NSDictionary *reply = nil;
    int delayMs = 5;
    if ([action isEqual:@"status"]) {
        reply = self.statusReply;
        delayMs = self.statusReplyDelayMs;
    } else if ([action isEqual:@"rebind"]) {
        if (self.rebindNoReply) return YES; // NE не ответил вовсе
        reply = self.rebindReply;
    }
    if (!handler) return YES;
    void (^h)(NSData *) = [handler copy];
    NSData *data = reply ? [[NSJSONSerialization dataWithJSONObject:reply options:0 error:nil] retain] : nil;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)delayMs * NSEC_PER_MSEC),
                   dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        h(data);
        [data release];
        [h release];
    });
    return YES;
}
@end

static HarnessSession *newSession(NEVPNStatus status)
{
    // init у NEVPNConnection помечен недоступным в SDK — зовём через рантайм.
    HarnessSession *session = ((HarnessSession * (*)(id, SEL))objc_msgSend)([HarnessSession alloc], @selector(init));
    session.hStatus = status;
    session.autoStop = YES;
    session.autoStart = YES;
    session.statusReplyDelayMs = 5;
    return session; // +1, тест не освобождает (процесс короткий)
}

static void notifyStatus(NETunnelProviderSession *session)
{
    IosController::Instance()->vpnStatusDidChange(session); // так делает IosControllerWrapper
}

// ------------------------------------------------------------------------------------------------
// Подмена NETunnelProviderManager.
static const void *kSessionKey = &kSessionKey;
enum class LoadMode { Deliver, Never, Error };
static LoadMode g_loadMode = LoadMode::Deliver;
static NSArray *g_managers = nil;
static int g_loadDelayMs = 5;
static int g_loadAllCalls = 0;
static int g_saveDelayMs = 5;

static void attachSession(NETunnelProviderManager *manager, HarnessSession *session)
{
    objc_setAssociatedObject(manager, kSessionKey, session, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
}

static NETunnelProviderManager *newManager(NSString *identity, NSString *cfgGeneration, HarnessSession *session)
{
    NETunnelProviderManager *manager = [[NETunnelProviderManager alloc] init];
    NETunnelProviderProtocol *proto = [[NETunnelProviderProtocol alloc] init];
    proto.providerBundleIdentifier = @"x.ne";
    proto.providerConfiguration = @{@"wireguard": [NSData data], @"tribeManagerId": identity,
                                    @"tribeSessionMetadata": @{@"schema_version": @1, @"generation": cfgGeneration, @"node_id": @"9"}};
    manager.protocolConfiguration = proto;
    [proto release];
    session.configurationGeneration = cfgGeneration;
    attachSession(manager, session);
    return manager;
}

static void installSwizzles()
{
    Class cls = [NETunnelProviderManager class];
    Class meta = object_getClass(cls);
    IMP loadAll = imp_implementationWithBlock(^(id, void (^completion)(NSArray *, NSError *)) {
        ++g_loadAllCalls;
        if (g_loadMode == LoadMode::Never) return;
        void (^c)(NSArray *, NSError *) = [completion copy];
        const LoadMode mode = g_loadMode;
        NSArray *managers = [g_managers retain];
        QTimer::singleShot(g_loadDelayMs, qApp, [c, mode, managers] {
            if (mode == LoadMode::Error) c(nil, [NSError errorWithDomain:@"harness" code:5 userInfo:nil]);
            else c(managers ?: @[], nil);
            [managers release];
            [c release];
        });
    });
    SEL loadAllSel = @selector(loadAllFromPreferencesWithCompletionHandler:);
    class_replaceMethod(meta, loadAllSel, loadAll, method_getTypeEncoding(class_getClassMethod(cls, loadAllSel)));

    IMP save = imp_implementationWithBlock(^(id, void (^completion)(NSError *)) {
        void (^c)(NSError *) = [completion copy];
        QTimer::singleShot(g_saveDelayMs, qApp, [c] { c(nil); [c release]; });
    });
    SEL saveSel = @selector(saveToPreferencesWithCompletionHandler:);
    class_replaceMethod(cls, saveSel, save, method_getTypeEncoding(class_getInstanceMethod(cls, saveSel)));

    IMP load = imp_implementationWithBlock(^(id, void (^completion)(NSError *)) {
        void (^c)(NSError *) = [completion copy];
        QTimer::singleShot(5, qApp, [c] { c(nil); [c release]; });
    });
    SEL loadSel = @selector(loadFromPreferencesWithCompletionHandler:);
    class_replaceMethod(cls, loadSel, load, method_getTypeEncoding(class_getInstanceMethod(cls, loadSel)));

    IMP connection = imp_implementationWithBlock(^NEVPNConnection *(id manager) {
        HarnessSession *session = objc_getAssociatedObject(manager, kSessionKey);
        if (!session) { // менеджер, созданный самим контроллером (новый профиль)
            session = newSession(NEVPNStatusDisconnected);
            attachSession(manager, session);
            [session release];
        }
        return session;
    });
    SEL connSel = @selector(connection);
    class_replaceMethod(cls, connSel, connection, method_getTypeEncoding(class_getInstanceMethod(cls, connSel)));
}

// ------------------------------------------------------------------------------------------------
// Наблюдения.
struct Observed {
    std::vector<std::string> log; // упорядоченная лента: state:N / reason:R:I / live / rebind:B / hs:N
    std::vector<Vpn::ConnectionState> states;
    std::vector<std::pair<QString, bool>> reasons;
    std::vector<bool> rebinds;
    std::vector<bool> prompts; // permissionPromptPending(bool)
    int live = 0;
    qint64 lastHandshake = 0;
    bool has(Vpn::ConnectionState s) const { for (auto x : states) if (x == s) return true; return false; }
    int count(Vpn::ConnectionState s) const { int n = 0; for (auto x : states) if (x == s) ++n; return n; }
    void clear() { log.clear(); states.clear(); reasons.clear(); rebinds.clear(); prompts.clear(); live = 0; }
};
static Observed obs;

static void wireObservers()
{
    IosController *c = IosController::Instance();
    QObject::connect(c, &IosController::connectionStateChanged, [](Vpn::ConnectionState s) {
        obs.states.push_back(s);
        obs.log.push_back("state:" + std::to_string(int(s)));
    });
    QObject::connect(c, &IosController::disconnectReason, [](const QString &r, bool i) {
        obs.reasons.emplace_back(r, i);
        obs.log.push_back("reason:" + r.toStdString() + ":" + (i ? "1" : "0"));
    });
    QObject::connect(c, &IosController::handshakeChanged, [](qint64 h) { obs.lastHandshake = h; });
}

// Подписка на новые сигналы через QMetaObject по имени — компилируется и против старого хедера.
class SignalTap : public QObject {
public:
    int qt_metacall(QMetaObject::Call call, int id, void **args) override
    {
        id = QObject::qt_metacall(call, id, args);
        if (id < 0 || call != QMetaObject::InvokeMetaMethod) return id;
        if (id == 0) { ++obs.live; obs.log.push_back("live"); }
        if (id == 1) {
            const bool performed = *reinterpret_cast<bool *>(args[1]);
            obs.rebinds.push_back(performed);
            obs.log.push_back(performed ? "rebind:1" : "rebind:0");
        }
        if (id == 2) {
            const bool pending = *reinterpret_cast<bool *>(args[1]);
            obs.prompts.push_back(pending);
            obs.log.push_back(pending ? "prompt:1" : "prompt:0");
        }
        return -1;
    }
    bool attach()
    {
        IosController *c = IosController::Instance();
        const int live = c->metaObject()->indexOfSignal("liveSessionFound()");
        const int rebind = c->metaObject()->indexOfSignal("rebindFinished(bool)");
        const int prompt = c->metaObject()->indexOfSignal("permissionPromptPending(bool)");
        const int base = QObject::staticMetaObject.methodCount();
        if (live >= 0) QMetaObject::connect(c, live, this, base + 0, Qt::DirectConnection);
        if (rebind >= 0) QMetaObject::connect(c, rebind, this, base + 1, Qt::DirectConnection);
        if (prompt >= 0) QMetaObject::connect(c, prompt, this, base + 2, Qt::DirectConnection);
        return live >= 0 && rebind >= 0;
    }
};

static QJsonObject awgConfig(int handshakeTimeoutMs = 12000, int maxTimeouts = 3)
{
    QJsonObject inner{{QStringLiteral("hostName"), QStringLiteral("38.180.164.134")},
                      {QStringLiteral("port"), QStringLiteral("585")}};
    return QJsonObject{{QStringLiteral("hostName"), QStringLiteral("38.180.164.134")},
                       {QStringLiteral("awg_config_data"), inner},
                       {QStringLiteral("awg_handshake_timeout_ms"), handshakeTimeoutMs},
                       {QStringLiteral("awg_handshake_max_timeouts"), maxTimeouts},
                       {QStringLiteral("tribeSessionMetadata"), QJsonObject{{QStringLiteral("schema_version"), 1},
                                                                             {QStringLiteral("node_id"), QStringLiteral("9")}}}};
}

static NSDictionary *statusReply(NSString *runtimeGeneration, NSString *cfgGeneration, long long handshake, long long rx)
{
    return @{@"session_metadata": @{@"schema_version": @1, @"generation": runtimeGeneration,
                                    @"configuration_generation": cfgGeneration, @"node_id": @"9"},
             @"rx_bytes": [NSString stringWithFormat:@"%lld", rx], @"tx_bytes": @"1000",
             @"last_handshake_time_sec": @(handshake)};
}

// Живая сессия, найденная реконсилом (туннель поднят Настройками/прошлым запуском).
static HarnessSession *adoptLiveSession(NSString *identity = @"mgr-1", NSString *cfg = @"cfg-1")
{
    HarnessSession *s = newSession(NEVPNStatusConnected);
    s.runtimeGeneration = @"run-1";
    g_managers = [@[newManager(identity, cfg, s)] retain];
    g_loadMode = LoadMode::Deliver;
    IosController::Instance()->requestReconcileStatus();
    spin(60);
    return s;
}

// ------------------------------------------------------------------------------------------------
// Тесты.

// C1: дедлайн loadAll при неизвестном менеджере — не Error; повтор с backoff.
static void test_reconcile_deadline_no_error()
{
    g_loadMode = LoadMode::Never;
    IosController::Instance()->requestReconcileStatus();
    spin(W(1600, 3600));
    CHECK(!obs.has(Vpn::ConnectionState::Error), "дедлайн реконсила эмитил синтетический Error");
    CHECK(g_loadAllCalls >= 2, "после дедлайна нет повтора loadAll");
    const int calls = g_loadAllCalls;
    spin(W(2500, 100));
    CHECK(g_loadAllCalls <= 4, "повторы не ограничены");
    CHECK(g_loadAllCalls == calls || g_loadAllCalls <= 4, "повторы продолжаются бесконечно");
}

// C1: ошибка loadAll — не Error; повтор.
static void test_reconcile_error_no_error()
{
    g_loadMode = LoadMode::Error;
    IosController::Instance()->requestReconcileStatus();
    spin(W(500, 500));
    CHECK(!obs.has(Vpn::ConnectionState::Error), "ошибка loadAll эмитила синтетический Error");
    CHECK(g_loadAllCalls >= 2, "после ошибки loadAll нет повтора");
}

// C1: поздний ответ loadAll (после дедлайна) — реальное наблюдение, применяется.
static void test_reconcile_late_answer_applied()
{
    HarnessSession *s = newSession(NEVPNStatusConnected);
    g_managers = [@[newManager(@"mgr-1", @"cfg-1", s)] retain];
    g_loadDelayMs = W(300, 3300);
    IosController::Instance()->requestReconcileStatus();
    spin(W(700, 3800));
    CHECK(obs.has(Vpn::ConnectionState::Connecting) || obs.has(Vpn::ConnectionState::Connected),
          "поздний ответ loadAll выброшен — живой туннель не наблюдён");
    CHECK(!obs.has(Vpn::ConnectionState::Error), "Error при живом туннеле");
}

// C1: стоп без известного менеджера, loadAll молчит — без Error, флаг стопа не залипает.
static void test_stop_discovery_no_error_flag_cleared()
{
    g_loadMode = LoadMode::Never;
    IosController::Instance()->disconnectVpn();
    spin(W(2200, 3600));
    CHECK(!obs.has(Vpn::ConnectionState::Error), "поиск профиля для стопа эмитил синтетический Error");
    // Позже — туннель из Настроек, внешний обрыв: это НЕ наш стоп.
    HarnessSession *s = newSession(NEVPNStatusConnected);
    s.runtimeGeneration = @"run-7";
    g_managers = [@[newManager(@"mgr-1", @"cfg-7", s)] retain];
    g_loadMode = LoadMode::Deliver;
    setIntent("i-resume", "resume");
    IosController::Instance()->requestReconcileStatus();
    spin(W(1500, 3500));
    obs.clear();
    s.hStatus = NEVPNStatusDisconnected;
    notifyStatus(s);
    spin(20);
    CHECK(obs.reasons.size() == 1, "нет причины обрыва");
    if (!obs.reasons.empty())
        CHECK(obs.reasons[0].first != QStringLiteral("expected_app_stop"), "залипший m_localStopRequested: чужой обрыв помечен как наш стоп");
}

// C1: терминал веток disconnectVpn без менеджера — напрямую (не проглатывается дедупом).
static void test_stop_without_profile_emits_direct_terminal()
{
    g_managers = [@[] retain];
    IosController::Instance()->requestReconcileStatus();
    spin(50);
    CHECK(obs.has(Vpn::ConnectionState::Disconnected), "реконсил без профиля не дал Disconnected");
    obs.clear();
    IosController::Instance()->disconnectVpn();
    spin(80);
    CHECK(obs.has(Vpn::ConnectionState::Disconnected), "disconnectVpn без профиля: Disconnected проглочен дедупом");
}

// C2/K2: собственный стоп приложения — intentional=false, хотя intent "off" и NE userInitiated.
static void test_app_stop_not_intentional()
{
    setIntent("i-resume", "resume");
    HarnessSession *s = adoptLiveSession();
    s.stopWritesUserInitiated = YES;
    obs.clear();
    setIntent("i-off", "off"); // фасад пишет Avpn_recordGuiIntent(false) перед стопом
    IosController::Instance()->disconnectVpn();
    spin(100);
    CHECK(s.stopCalls == 1, "stopTunnel не вызван");
    CHECK(obs.reasons.size() == 1, "причина стопа не одна");
    if (!obs.reasons.empty()) {
        CHECK(obs.reasons[0].first == QStringLiteral("expected_app_stop"), "стоп приложения помечен не expected_app_stop");
        CHECK(!obs.reasons[0].second, "стоп приложения помечен intentional");
    }
}

// C2: «липкий intent» — давний "off", туннель из Настроек, внешний обрыв → intentional=false.
static void test_sticky_off_intent_not_intentional()
{
    setIntent("i-off-old", "off");
    HarnessSession *s = adoptLiveSession();
    obs.clear();
    g_lastStop = {{QStringLiteral("generation"), QStringLiteral("run-1")}, {QStringLiteral("configuration_generation"), QStringLiteral("cfg-1")},
                  {QStringLiteral("reason"), 2}, {QStringLiteral("intentional"), false},
                  {QStringLiteral("utc_ms"), QDateTime::currentMSecsSinceEpoch()}};
    s.hStatus = NEVPNStatusDisconnected;
    notifyStatus(s);
    spin(20);
    CHECK(obs.reasons.size() == 1, "нет причины обрыва");
    if (!obs.reasons.empty()) CHECK(!obs.reasons[0].second, "внешний обрыв при давнем off помечен intentional (липкий intent)");
}

// C2: настоящее намерение (pause после живой фазы) — intentional=true (регрессия).
static void test_new_pause_intent_intentional()
{
    setIntent("i-resume", "resume");
    HarnessSession *s = adoptLiveSession();
    obs.clear();
    setIntent("i-pause", "pause");
    s.hStatus = NEVPNStatusDisconnected;
    notifyStatus(s);
    spin(20);
    CHECK(obs.reasons.size() == 1 && obs.reasons[0].second, "пауза пользователя не intentional");
}

// K2: повторные наблюдения того же Disconnected — одна причина.
static void test_reason_once_per_transition()
{
    HarnessSession *s = newSession(NEVPNStatusDisconnected);
    g_managers = [@[newManager(@"mgr-1", @"cfg-1", s)] retain];
    for (int i = 0; i < 3; ++i) {
        IosController::Instance()->requestReconcileStatus();
        spin(40);
    }
    CHECK(obs.reasons.size() == 1, "disconnectReason переэмитится на каждом реконсиле");
    // Новый переход (Connected → Disconnected) — новая причина.
    s.hStatus = NEVPNStatusConnected;
    notifyStatus(s);
    s.hStatus = NEVPNStatusDisconnected;
    notifyStatus(s);
    CHECK(obs.reasons.size() == 2, "новый переход в Disconnected без причины");
}

// C2: profile_missing на первом запуске — intentional=false.
static void test_profile_missing_not_intentional()
{
    g_managers = [@[] retain];
    IosController::Instance()->requestReconcileStatus();
    spin(40);
    CHECK(obs.reasons.size() == 1, "нет profile_missing");
    if (!obs.reasons.empty()) {
        CHECK(obs.reasons[0].first == QStringLiteral("profile_missing"), "не profile_missing");
        CHECK(!obs.reasons[0].second, "profile_missing intentional=true снимает намерение на первом запуске");
    }
}

// C2: стоп после N таймаутов рукопожатия — решение приложения, не пользователя.
static void test_handshake_timeout_stop_not_intentional()
{
    setIntent("i-resume", "resume");
    HarnessSession *s = newSession(NEVPNStatusDisconnected);
    s.runtimeGeneration = @"run-5";
    s.stopWritesUserInitiated = YES;
    s.statusReply = statusReply(@"run-5", @"cfg-5", 0, 0);
    g_managers = [@[newManager(@"mgr-1", @"cfg-5", s)] retain];
    QTimer poll;
    QObject::connect(&poll, &QTimer::timeout, [] { IosController::Instance()->checkStatus(); });
    poll.start(30);
    IosController::Instance()->connectVpn(amnezia::Proto::Awg, awgConfig(150, 2));
    spin(1200);
    CHECK(s.startCalls == 1, "туннель не стартовал");
    CHECK(s.stopCalls == 1, "после таймаутов рукопожатия нет stopTunnel");
    CHECK(obs.reasons.size() == 1, "нет причины обрыва");
    if (!obs.reasons.empty()) {
        CHECK(obs.reasons[0].first == QStringLiteral("expected_app_stop"), "стоп по таймаутам не expected_app_stop");
        CHECK(!obs.reasons[0].second, "стоп по таймаутам рукопожатия помечен intentional");
    }
}

// C3/K3: Connect поверх живого своего профиля — без Error, liveSessionFound ДО статуса.
static void test_connect_over_live_session()
{
    setIntent("i-resume", "resume");
    HarnessSession *s = newSession(NEVPNStatusConnected);
    g_managers = [@[newManager(@"mgr-1", @"cfg-1", s)] retain];
    SignalTap tap;
    tap.attach();
    IosController::Instance()->connectVpn(amnezia::Proto::Awg, awgConfig());
    spin(80);
    CHECK(!obs.has(Vpn::ConnectionState::Error), "Connect поверх живого профиля эмитил Error");
    CHECK(obs.live == 1, "нет liveSessionFound");
    CHECK(!obs.log.empty() && obs.log.front() == "live", "liveSessionFound не раньше статуса");
    CHECK(obs.has(Vpn::ConnectionState::Connecting) || obs.has(Vpn::ConnectionState::Connected), "реальный статус не переслан");
    CHECK(s.startCalls == 0, "старт поверх живого туннеля");
}

// Ревью REV-2 (K3): Connect, пока свой профиль гасится (стоп из Настроек в пути) — это не живая
// сессия: без liveSessionFound/Error, терминал старой сессии и её причина фасаду не уходят,
// после реального Disconnected — обычный старт (нажатие Connect не теряется).
static void test_connect_over_disconnecting_session()
{
    setIntent("i-resume", "resume");
    HarnessSession *s = newSession(NEVPNStatusDisconnecting);
    s.runtimeGeneration = @"run-0";
    g_managers = [@[newManager(@"mgr-1", @"cfg-1", s)] retain];
    // NE записал стоп из Настроек (.userInitiated) — для старой сессии это intentional=true.
    g_lastStop = {{QStringLiteral("generation"), QStringLiteral("run-0")}, {QStringLiteral("configuration_generation"), QStringLiteral("cfg-1")},
                  {QStringLiteral("reason"), 1}, {QStringLiteral("intentional"), true},
                  {QStringLiteral("utc_ms"), QDateTime::currentMSecsSinceEpoch()}};
    SignalTap tap;
    tap.attach();
    IosController::Instance()->connectVpn(amnezia::Proto::Awg, awgConfig());
    spin(60);
    CHECK(obs.live == 0, "liveSessionFound для профиля в Disconnecting");
    CHECK(!obs.has(Vpn::ConnectionState::Error), "Connect поверх гасящегося профиля эмитил Error");
    CHECK(s.startCalls == 0, "старт поверх ещё не погашенного профиля");
    s.hStatus = NEVPNStatusDisconnected;
    notifyStatus(s);
    spin(200);
    CHECK(s.startCalls == 1, "после Disconnected старт не продолжен: нажатие Connect потеряно");
    CHECK(obs.reasons.empty(), "причина стопа старой сессии ушла фасаду посреди нашего старта");
    CHECK(!obs.has(Vpn::ConnectionState::Disconnected), "терминал старой сессии переслан посреди нашего старта");
    CHECK(!obs.has(Vpn::ConnectionState::Error), "Error после продолжения старта");
    CHECK(obs.has(Vpn::ConnectionState::Connecting) || obs.has(Vpn::ConnectionState::Connected), "реальный статус нового старта не пришёл");
}

// Ревью REV-2: ожидание терминала ограничено дедлайном коннекта (профиль завис в Disconnecting):
// честный Error старта, ожидание снято — поздний Disconnected старт уже не запускает.
static void test_connect_over_disconnecting_deadline()
{
    setIntent("i-resume", "resume");
    HarnessSession *s = newSession(NEVPNStatusDisconnecting);
    g_managers = [@[newManager(@"mgr-1", @"cfg-1", s)] retain];
    IosController::Instance()->connectVpn(amnezia::Proto::Awg, awgConfig());
    spin(W(500, 10500));
    CHECK(obs.count(Vpn::ConnectionState::Error) == 1, "дедлайн ожидания терминала не дал Error старта");
    s.hStatus = NEVPNStatusDisconnected;
    notifyStatus(s);
    spin(200);
    CHECK(s.startCalls == 0, "старт после истёкшего дедлайна");
}

// Ревью REV-2: пока ждали терминал, профиль снова подняли (Настройки) — это живая сессия (K3).
static void test_connect_over_disconnecting_then_relive()
{
    setIntent("i-resume", "resume");
    HarnessSession *s = newSession(NEVPNStatusDisconnecting);
    g_managers = [@[newManager(@"mgr-1", @"cfg-1", s)] retain];
    SignalTap tap;
    tap.attach();
    IosController::Instance()->connectVpn(amnezia::Proto::Awg, awgConfig());
    spin(60);
    s.hStatus = NEVPNStatusConnected;
    notifyStatus(s);
    spin(60);
    CHECK(obs.live == 1, "поднятый заново профиль не адоптирован (нет liveSessionFound)");
    CHECK(!obs.log.empty() && obs.log.front() == "live", "liveSessionFound не раньше статуса");
    CHECK(obs.has(Vpn::ConnectionState::Connecting) || obs.has(Vpn::ConnectionState::Connected), "реальный статус не переслан");
    CHECK(!obs.has(Vpn::ConnectionState::Error), "Error при адопте");
    CHECK(s.startCalls == 0, "старт поверх живого туннеля");
}

// Ревью REV-2, вторая точка (startTunnel): пока шёл save, профиль подняли и тут же гасят
// (Настройки/Shortcut) — после load он в Disconnecting. Ждём его терминал и стартуем.
static void test_start_race_disconnecting_waits()
{
    setIntent("i-resume", "resume");
    HarnessSession *s = newSession(NEVPNStatusDisconnected);
    g_managers = [@[newManager(@"mgr-1", @"cfg-1", s)] retain];
    g_saveDelayMs = 40;
    SignalTap tap;
    tap.attach();
    QTimer::singleShot(20, qApp, [s] { s.hStatus = NEVPNStatusDisconnecting; });
    IosController::Instance()->connectVpn(amnezia::Proto::Awg, awgConfig());
    spin(120);
    CHECK(obs.live == 0, "liveSessionFound для профиля в Disconnecting (startTunnel)");
    CHECK(s.startCalls == 0, "старт поверх гасящегося профиля");
    s.hStatus = NEVPNStatusDisconnected;
    notifyStatus(s);
    spin(250);
    CHECK(s.startCalls == 1, "после Disconnected старт не продолжен");
    CHECK(!obs.has(Vpn::ConnectionState::Error), "Error при ожидании терминала");
    CHECK(!obs.has(Vpn::ConnectionState::Disconnected), "терминал старой сессии переслан посреди старта");
}

// Ревью REV-3 (K2): стоп приложения, Disconnected которого GUI пропустил (фон), не приписывается
// следующей сессии, поднятой Настройками: её стоп из Настроек — intentional=true.
static void test_local_stop_flag_not_inherited_by_new_session()
{
    setIntent("i-resume", "resume");
    const long long now = QDateTime::currentSecsSinceEpoch();
    HarnessSession *s = adoptLiveSession();
    s.statusReply = statusReply(@"run-1", @"cfg-1", now, 50000);
    IosController::Instance()->checkStatus();
    spin(60);
    s.autoStop = NO; // GUI в фоне: переходы этой сессии не наблюдаем
    IosController::Instance()->disconnectVpn();
    spin(20);
    CHECK(s.stopCalls == 1, "stopTunnel не вызван");
    // Настройки подняли новый NE-запуск того же профиля.
    HarnessSession *s2 = newSession(NEVPNStatusConnected);
    s2.runtimeGeneration = @"run-2";
    s2.statusReply = statusReply(@"run-2", @"cfg-1", now, 60000);
    g_managers = [@[newManager(@"mgr-1", @"cfg-1", s2)] retain];
    IosController::Instance()->requestReconcileStatus();
    spin(60);
    IosController::Instance()->checkStatus();
    spin(60);
    obs.clear();
    // Пользователь выключил VPN в Настройках.
    g_lastStop = {{QStringLiteral("generation"), QStringLiteral("run-2")}, {QStringLiteral("configuration_generation"), QStringLiteral("cfg-1")},
                  {QStringLiteral("reason"), 1}, {QStringLiteral("intentional"), true},
                  {QStringLiteral("utc_ms"), QDateTime::currentMSecsSinceEpoch()}};
    s2.hStatus = NEVPNStatusDisconnected;
    notifyStatus(s2);
    spin(20);
    CHECK(obs.reasons.size() == 1, "нет причины обрыва новой сессии");
    if (!obs.reasons.empty()) {
        CHECK(obs.reasons[0].first != QStringLiteral("expected_app_stop"), "стоп новой сессии из Настроек приписан приложению (флаг залип)");
        CHECK(obs.reasons[0].second, "стоп из Настроек не intentional");
    }
}

// Ревью REV-3, регрессия: стоп приложения ещё не дошёл (сессия пока Connected, реконсил и status
// той же сессии) — флаг держится, итоговый Disconnected = expected_app_stop.
static void test_local_stop_flag_kept_for_same_session()
{
    setIntent("i-resume", "resume");
    const long long now = QDateTime::currentSecsSinceEpoch();
    HarnessSession *s = adoptLiveSession();
    s.statusReply = statusReply(@"run-1", @"cfg-1", now, 50000);
    s.stopWritesUserInitiated = YES;
    IosController::Instance()->checkStatus();
    spin(60);
    s.autoStop = NO;
    IosController::Instance()->disconnectVpn();
    spin(20);
    g_managers = [@[newManager(@"mgr-1", @"cfg-1", s)] retain];
    IosController::Instance()->requestReconcileStatus();
    spin(60);
    IosController::Instance()->checkStatus();
    spin(60);
    obs.clear();
    s.hStatus = NEVPNStatusDisconnecting;
    notifyStatus(s);
    s.hStatus = NEVPNStatusDisconnected;
    notifyStatus(s);
    spin(20);
    CHECK(obs.reasons.size() == 1, "нет причины стопа");
    if (!obs.reasons.empty()) {
        CHECK(obs.reasons[0].first == QStringLiteral("expected_app_stop"), "собственный стоп потерял expected_app_stop");
        CHECK(!obs.reasons[0].second, "собственный стоп помечен intentional");
    }
}

// C4: системный диалог «Разрешить VPN» дольше дедлайна — коннект не рвётся.
static void test_permission_prompt_not_cut_by_deadline()
{
    setIntent("i-resume", "resume");
    g_managers = [@[] retain];
    g_saveDelayMs = W(900, 10500); // пользователь читает диалог дольше дедлайна коннекта
    IosController::Instance()->connectVpn(amnezia::Proto::Awg, awgConfig());
    spin(W(1400, 11200));
    CHECK(!obs.has(Vpn::ConnectionState::Error), "дедлайн коннекта накрыл диалог разрешения");
    CHECK(obs.has(Vpn::ConnectionState::Connecting) || obs.has(Vpn::ConnectionState::Connected), "после разрешения старт не продолжился");
}

// C5/H7: ответ status позже дедлайна заявки — handshake применяется; подмена менеджера тем же
// профилем в полёте не инвалидирует ответ.
static void test_late_status_response_applied()
{
    setIntent("i-resume", "resume");
    HarnessSession *s = adoptLiveSession();
    CHECK(obs.has(Vpn::ConnectionState::Connecting), "живой туннель ждёт подтверждения рукопожатия");
    obs.clear();
    const long long now = QDateTime::currentSecsSinceEpoch();
    s.statusReply = statusReply(@"run-1", @"cfg-1", now, 50000);
    s.statusReplyDelayMs = W(400, 3400);
    IosController::Instance()->checkStatus();
    spin(50);
    // Реконсил (configChange/foreground) отдаёт новый экземпляр менеджера того же профиля.
    NETunnelProviderManager *again = newManager(@"mgr-1", @"cfg-1", s);
    g_managers = [@[again] retain];
    IosController::Instance()->requestReconcileStatus();
    spin(W(700, 3700));
    CHECK(obs.has(Vpn::ConnectionState::Connected), "поздний ответ status выброшен: рукопожатие не подтверждено");
    CHECK(obs.lastHandshake == now, "handshake из позднего ответа не дошёл до HealthLoop");
}

// C7/K4: результат rebind.
static void test_rebind_performed()
{
    HarnessSession *s = adoptLiveSession();
    SignalTap tap;
    tap.attach();
    s.rebindReply = @{@"rebind": @"performed"};
    CHECK(IosController::Instance()->rebindTunnel(), "rebind не отправлен живому туннелю");
    spin(W(600, 3500));
    CHECK(obs.rebinds.size() == 1 && obs.rebinds[0], "нет rebindFinished(true)");
}
static void test_rebind_denied()
{
    HarnessSession *s = adoptLiveSession();
    SignalTap tap;
    tap.attach();
    s.rebindReply = @{@"rebind": @"denied", @"reason": @"budget"};
    CHECK(IosController::Instance()->rebindTunnel(), "rebind не отправлен");
    spin(W(600, 3500));
    CHECK(obs.rebinds.size() == 1 && !obs.rebinds[0], "отказ NE по бюджету не дошёл как rebindFinished(false)");
}
static void test_rebind_no_reply()
{
    HarnessSession *s = adoptLiveSession();
    SignalTap tap;
    tap.attach();
    s.rebindNoReply = YES;
    CHECK(IosController::Instance()->rebindTunnel(), "rebind не отправлен");
    spin(W(700, 3500));
    CHECK(obs.rebinds.size() == 1 && !obs.rebinds[0], "нет ответа NE — нет rebindFinished(false) по дедлайну");
    spin(300);
    CHECK(obs.rebinds.size() == 1, "rebindFinished эмитится больше одного раза");
}

// C9: после startVPNTunnel статус не перечитывается синхронно (ложный Disconnected для Starting).
static void test_start_no_sync_disconnected()
{
    setIntent("i-resume", "resume");
    HarnessSession *s = newSession(NEVPNStatusDisconnected);
    g_managers = [@[newManager(@"mgr-1", @"cfg-1", s)] retain];
    IosController::Instance()->connectVpn(amnezia::Proto::Awg, awgConfig());
    spin(300);
    CHECK(s.startCalls == 1, "туннель не стартовал");
    CHECK(!obs.has(Vpn::ConnectionState::Disconnected), "ложный Disconnected сразу после startVPNTunnel");
    CHECK(obs.reasons.empty(), "ложная причина обрыва сразу после старта");
    CHECK(obs.has(Vpn::ConnectionState::Connecting), "реальный статус по уведомлению не пришёл");
}

// C6 (вызывающая сторона): за время start записали "off" — наш старт откатывается.
static void test_start_superseded_by_off_stops()
{
    setIntent("i-resume", "resume");
    HarnessSession *s = newSession(NEVPNStatusDisconnected);
    s.autoStart = NO;
    g_managers = [@[newManager(@"mgr-1", @"cfg-1", s)] retain];
    g_duringPerform = [] { setIntent("i-off-shortcut", "off"); };
    IosController::Instance()->connectVpn(amnezia::Proto::Awg, awgConfig());
    spin(150);
    CHECK(s.startCalls == 1, "туннель не стартовал");
    CHECK(s.stopCalls == 1, "старт, обогнанный выключением, не откатан");
}
static void test_start_superseded_by_resume_keeps()
{
    setIntent("i-resume", "resume");
    HarnessSession *s = newSession(NEVPNStatusDisconnected);
    g_managers = [@[newManager(@"mgr-1", @"cfg-1", s)] retain];
    g_duringPerform = [] { setIntent("i-resume-2", "resume"); };
    IosController::Instance()->connectVpn(amnezia::Proto::Awg, awgConfig());
    spin(200);
    CHECK(s.startCalls == 1 && s.stopCalls == 0, "повторный resume не должен гасить старт");
}

// Ревью CL-C REV-1 (K2): runtime-поколение сессии известно — свежая запись NE о стопе ПРОШЛОГО
// запуска того же профиля (пауза Shortcut → resume ≤2 мин) не приписывается ей. Сессию затем убил
// jetsam без своей записи: это внешний обрыв (intentional=false), фасад должен лечить.
static void test_previous_run_ne_stop_not_attributed()
{
    setIntent("i-resume", "resume");
    const long long now = QDateTime::currentSecsSinceEpoch();
    HarnessSession *s = adoptLiveSession();
    s.runtimeGeneration = @"run-2";
    s.statusReply = statusReply(@"run-2", @"cfg-1", now, 50000);
    IosController::Instance()->checkStatus();
    spin(60);
    g_lastStop = {{QStringLiteral("generation"), QStringLiteral("run-1")}, {QStringLiteral("configuration_generation"), QStringLiteral("cfg-1")},
                  {QStringLiteral("reason"), 1}, {QStringLiteral("intentional"), true},
                  {QStringLiteral("utc_ms"), QDateTime::currentMSecsSinceEpoch() - 60000}};
    obs.clear();
    s.hStatus = NEVPNStatusDisconnected;
    notifyStatus(s);
    spin(20);
    CHECK(obs.reasons.size() == 1, "нет причины обрыва");
    if (!obs.reasons.empty()) {
        CHECK(!obs.reasons[0].second, "запись стопа прошлого запуска приписана новой сессии (intentional=true)");
        CHECK(obs.reasons[0].first == QStringLiteral("unknown_external"), "обрыв без записи этой сессии не unknown_external");
    }
}

// Ревью CL-C REV-4 (K2): приложение погасило сессию run-1 (runtime-поколение известно). Затем
// Настройки поднимают новый NE-запуск того же профиля, и пользователь гасит его из Настроек ДО
// первого status-ответа. Старое runtime-поколение не переносится на новую сессию → её стоп
// не expected_app_stop, а стоп пользователя (NE: userInitiated).
static void test_app_stop_generation_not_inherited()
{
    setIntent("i-resume", "resume");
    const long long now = QDateTime::currentSecsSinceEpoch();
    HarnessSession *s = adoptLiveSession();
    s.statusReply = statusReply(@"run-1", @"cfg-1", now, 50000);
    IosController::Instance()->checkStatus();
    spin(60);
    IosController::Instance()->disconnectVpn(); // autoStop: Disconnecting → Disconnected наблюдаем
    spin(100);
    CHECK(obs.reasons.size() == 1 && obs.reasons[0].first == QStringLiteral("expected_app_stop"), "стоп приложения не expected_app_stop");
    obs.clear();
    // Новая сессия из Настроек/Control Center: реконсил (foreground) + уведомления, status ещё не было.
    s.runtimeGeneration = @"run-2";
    s.statusReply = nil;
    IosController::Instance()->requestReconcileStatus();
    spin(60);
    s.hStatus = NEVPNStatusConnecting;
    notifyStatus(s);
    s.hStatus = NEVPNStatusConnected;
    notifyStatus(s);
    spin(20);
    g_lastStop = {{QStringLiteral("generation"), QStringLiteral("run-2")}, {QStringLiteral("configuration_generation"), QStringLiteral("cfg-1")},
                  {QStringLiteral("reason"), 1}, {QStringLiteral("intentional"), true},
                  {QStringLiteral("utc_ms"), QDateTime::currentMSecsSinceEpoch()}};
    s.hStatus = NEVPNStatusDisconnected;
    notifyStatus(s);
    spin(20);
    CHECK(obs.reasons.size() == 1, "нет причины обрыва новой сессии");
    if (!obs.reasons.empty()) {
        CHECK(obs.reasons[0].first != QStringLiteral("expected_app_stop"), "стоп новой сессии из Настроек приписан приложению (старое runtime-поколение)");
        CHECK(obs.reasons[0].second, "стоп пользователя из Настроек не intentional");
    }
}

// Ревью CL-C REV-3 (C4): пока открыт диалог «Разрешить VPN», намерение сменилось (Shortcut off).
// Заявка снимается по completion save: флаг диалога гаснет сразу, без Error на потолке ожидания.
static void test_permission_prompt_intent_changed()
{
#ifndef HARNESS_OLD
    avpn_ios::nativeTimings().permissionPromptCapMs = 1200;
#endif
    setIntent("i-resume", "resume");
    g_managers = [@[] retain];
    g_saveDelayMs = 300;
    SignalTap tap;
    tap.attach();
    QTimer::singleShot(100, qApp, [] { setIntent("i-off-shortcut", "off"); });
    IosController::Instance()->connectVpn(amnezia::Proto::Awg, awgConfig());
    spin(450);
    CHECK(!obs.prompts.empty() && !obs.prompts.back(), "permissionPromptPending не снят по completion save");
    spin(W(1200, 10500));
    CHECK(!obs.has(Vpn::ConnectionState::Error), "Error на потолке ожидания для коннекта, который уже не нужен");
    CHECK(obs.has(Vpn::ConnectionState::Disconnected), "реальный статус не отдан после отмены старта");
}

// Ревью CL-C REV-5 (K4): итог перекрытого rebind (дедлайн без ответа) не закрывает новый шаг.
static void test_rebind_superseded_result_dropped()
{
    HarnessSession *s = adoptLiveSession();
    SignalTap tap;
    tap.attach();
    s.rebindNoReply = YES;
    CHECK(IosController::Instance()->rebindTunnel(), "rebind не отправлен");
    spin(W(100, 1000));
    s.rebindNoReply = NO;
    s.rebindReply = @{@"rebind": @"performed"};
    CHECK(IosController::Instance()->rebindTunnel(), "второй rebind не отправлен");
    spin(W(700, 3500));
    CHECK(obs.rebinds.size() == 1, "итог перекрытого rebind эмитится");
    if (!obs.rebinds.empty()) CHECK(obs.rebinds.back(), "итог нового rebind не performed");
}

struct Test { const char *name; void (*fn)(); };
// Разбор журнала 25.09: холодный старт при сессии, которую iOS держит Connected давно (приложение
// выгрузили, туннель жил), — Connected сразу, без Connecting до ответа NE на status.
static void test_cold_start_established_session_connected()
{
    HarnessSession *s = newSession(NEVPNStatusConnected);
    s.runtimeGeneration = @"run-1";
    s.hConnectedDate = [NSDate dateWithTimeIntervalSinceNow:-600];
    s.statusReply = nil; // NE ещё не ответил
    g_managers = [@[newManager(@"mgr-1", @"cfg-1", s)] retain];
    g_loadMode = LoadMode::Deliver;
    IosController::Instance()->requestReconcileStatus();
    spin(60);
    CHECK(obs.has(Vpn::ConnectionState::Connected), "давно живая сессия не показана Connected до ответа NE");
    CHECK(!obs.has(Vpn::ConnectionState::Connecting), "давно живая сессия прошла через Connecting");
}

// Только что поднятая сессия (Настройки/Shortcuts секунду назад) — по-прежнему ждёт рукопожатия.
static void test_fresh_session_waits_handshake()
{
    HarnessSession *s = newSession(NEVPNStatusConnected);
    s.runtimeGeneration = @"run-1";
    s.hConnectedDate = [NSDate date];
    s.statusReply = nil;
    g_managers = [@[newManager(@"mgr-1", @"cfg-1", s)] retain];
    g_loadMode = LoadMode::Deliver;
    IosController::Instance()->requestReconcileStatus();
    spin(60);
    CHECK(obs.has(Vpn::ConnectionState::Connecting), "свежая сессия не ждёт подтверждения рукопожатия");
    CHECK(!obs.has(Vpn::ConnectionState::Connected), "свежая сессия показана Connected без рукопожатия");
}

static const Test kTests[] = {
    {"reconcile_deadline_no_error", test_reconcile_deadline_no_error},
    {"reconcile_error_no_error", test_reconcile_error_no_error},
    {"reconcile_late_answer_applied", test_reconcile_late_answer_applied},
    {"stop_discovery_no_error_flag_cleared", test_stop_discovery_no_error_flag_cleared},
    {"stop_without_profile_emits_direct_terminal", test_stop_without_profile_emits_direct_terminal},
    {"app_stop_not_intentional", test_app_stop_not_intentional},
    {"sticky_off_intent_not_intentional", test_sticky_off_intent_not_intentional},
    {"new_pause_intent_intentional", test_new_pause_intent_intentional},
    {"reason_once_per_transition", test_reason_once_per_transition},
    {"profile_missing_not_intentional", test_profile_missing_not_intentional},
    {"handshake_timeout_stop_not_intentional", test_handshake_timeout_stop_not_intentional},
    {"connect_over_live_session", test_connect_over_live_session},
    {"connect_over_disconnecting_session", test_connect_over_disconnecting_session},
    {"connect_over_disconnecting_deadline", test_connect_over_disconnecting_deadline},
    {"connect_over_disconnecting_then_relive", test_connect_over_disconnecting_then_relive},
    {"start_race_disconnecting_waits", test_start_race_disconnecting_waits},
    {"local_stop_flag_not_inherited_by_new_session", test_local_stop_flag_not_inherited_by_new_session},
    {"local_stop_flag_kept_for_same_session", test_local_stop_flag_kept_for_same_session},
    {"permission_prompt_not_cut_by_deadline", test_permission_prompt_not_cut_by_deadline},
    {"late_status_response_applied", test_late_status_response_applied},
    {"rebind_performed", test_rebind_performed},
    {"rebind_denied", test_rebind_denied},
    {"rebind_no_reply", test_rebind_no_reply},
    {"start_no_sync_disconnected", test_start_no_sync_disconnected},
    {"start_superseded_by_off_stops", test_start_superseded_by_off_stops},
    {"start_superseded_by_resume_keeps", test_start_superseded_by_resume_keeps},
    {"previous_run_ne_stop_not_attributed", test_previous_run_ne_stop_not_attributed},
    {"app_stop_generation_not_inherited", test_app_stop_generation_not_inherited},
    {"permission_prompt_intent_changed", test_permission_prompt_intent_changed},
    {"rebind_superseded_result_dropped", test_rebind_superseded_result_dropped},
    {"cold_start_established_session_connected", test_cold_start_established_session_connected},
    {"fresh_session_waits_handshake", test_fresh_session_waits_handshake},
};

int main(int argc, char **argv)
{
    if (argc == 2 && std::string(argv[1]) == "--list") {
        for (const Test &t : kTests) std::printf("%s\n", t.name);
        return 0;
    }
    if (argc != 2) {
        std::fprintf(stderr, "usage: %s <test>|--list\n", argv[0]);
        return 2;
    }
    qputenv("QT_LOGGING_RULES", "*.debug=false;*.info=false;*.warning=false");
    QCoreApplication app(argc, argv);
#ifndef HARNESS_OLD
    avpn_ios::NativeTimings &t = avpn_ios::nativeTimings();
    t.reconcileDeadlineMs = 200;
    t.retryBaseMs = 100;
    t.connectDeadlineMs = 300;
    t.permissionPromptCapMs = 5000;
    t.rebindReplyDeadlineMs = 300;
    t.statusDeadlineMs = 200;
#endif
    installSwizzles();
    @autoreleasepool {
        IosController::Instance();
        wireObservers();
        for (const Test &test : kTests) {
            if (std::string(argv[1]) != test.name) continue;
            test.fn();
            std::printf("%s %s\n", g_failures ? "FAIL" : "PASS", test.name);
            return g_failures ? 1 : 0;
        }
    }
    std::fprintf(stderr, "unknown test %s\n", argv[1]);
    return 2;
}
