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
#include <QLoggingCategory>
#include <QStringList>
#include <QTimer>
#include <atomic>
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <string>
#include <vector>
#ifndef HARNESS_OLD
#include "IosNativePolicy.h"
#ifndef HARNESS_OLD
#include "BackgroundHoldBook.h" // AVPN (iOS data watch, 140): the real bookkeeping behind the fake guard
#include <cstring>
#endif
#include "core/serviceEngine/TuningStore.h"
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
#ifndef HARNESS_OLD
// AVPN (iOS data watch, 140): the one iOS background task behind AvpnBackgroundGuard, in memory. The
// REAL bookkeeping by reason (BackgroundHoldBook.h) runs over this fake system, as in the app.
static int g_bgBegins = 0;
static int g_bgEnds = 0;
static bool g_bgRefuse = false;
static std::function<void()> g_bgExpire; // what iOS would call when the background time runs out
struct HarnessBgSystem {
    bool begin(std::function<void()> onSystemExpired)
    {
        if (g_bgRefuse) return false;
        ++g_bgBegins;
        g_bgExpire = std::move(onSystemExpired);
        return true;
    }
    void end()
    {
        ++g_bgEnds;
        g_bgExpire = nullptr;
    }
};
static avpn_ios::BackgroundHold<HarnessBgSystem> &harnessBgHold()
{
    static avpn_ios::BackgroundHold<HarnessBgSystem> hold;
    return hold;
}
bool AvpnBackgroundGuard_acquire(avpn_ios::BgReason reason, std::function<void()> onExpired)
{
    return harnessBgHold().acquire(reason, std::move(onExpired));
}
void AvpnBackgroundGuard_release(avpn_ios::BgReason reason) { harnessBgHold().release(reason); }
bool AvpnBackgroundGuard_begin(std::function<void()> onExpired)
{
    return AvpnBackgroundGuard_acquire(avpn_ios::BgReason::TunnelRestart, std::move(onExpired));
}
void AvpnBackgroundGuard_end() { AvpnBackgroundGuard_release(avpn_ios::BgReason::TunnelRestart); }
#endif
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

// On-Demand: лента вызовов натива ("save:od=0|1", "stop") и программируемый исход сохранения.
enum class SaveMode { Deliver, Never, ErrorOnce };
static SaveMode g_saveMode = SaveMode::Deliver;
static std::vector<std::string> g_nativeLog;
static std::vector<bool> g_savedEnabled;  // isEnabled экземпляра в момент каждого сохранения
static int g_prefsEnabled = -1;           // -1 — load ничего не меняет; 0/1 — «в системе профиль (не)активен»
// Правило «в системе» (как его видят другие процессы и свежая загрузка): -1 — не моделируем;
// 0/1 — save записывает сюда значение в момент ЗАВЕРШЕНИЯ, load читает отсюда в экземпляр.
static int g_sysOnDemand = -1;

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
@property (nonatomic, retain) NSDictionary *upstreamLeaseSetReply; // AVPN (upstream nodes)
@property (nonatomic, retain) NSDictionary *lastUpstreamLeaseSet;  // the last upstream_lease_set message
@end

@implementation HarnessSession
- (NEVPNStatus)status { return self.hStatus; }
- (NSDate *)connectedDate { return self.hConnectedDate; }
- (void)fetchLastDisconnectErrorWithCompletionHandler:(void (^)(NSError *))handler { if (handler) handler(nil); }
- (void)stopTunnel
{
    self.stopCalls = self.stopCalls + 1;
    g_nativeLog.push_back("stop");
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
    } else if ([action isEqual:@"upstream_lease_set"]) {
        self.lastUpstreamLeaseSet = message;
        reply = self.upstreamLeaseSetReply;
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

    IMP save = imp_implementationWithBlock(^(id manager, void (^completion)(NSError *)) {
        g_nativeLog.push_back([(NETunnelProviderManager *)manager isOnDemandEnabled] ? "save:od=1" : "save:od=0");
        g_savedEnabled.push_back([(NETunnelProviderManager *)manager isEnabled]);
        if (g_saveMode == SaveMode::Never) return;
        const bool fail = g_saveMode == SaveMode::ErrorOnce;
        if (fail) g_saveMode = SaveMode::Deliver;
        const bool onDemand = [(NETunnelProviderManager *)manager isOnDemandEnabled];
        void (^c)(NSError *) = [completion copy];
        QTimer::singleShot(g_saveDelayMs, qApp, [c, fail, onDemand] {
            if (!fail && g_sysOnDemand >= 0) g_sysOnDemand = onDemand ? 1 : 0;
            c(fail ? [NSError errorWithDomain:@"harness" code:5 userInfo:nil] : nil);
            [c release];
        });
    });
    SEL saveSel = @selector(saveToPreferencesWithCompletionHandler:);
    class_replaceMethod(cls, saveSel, save, method_getTypeEncoding(class_getInstanceMethod(cls, saveSel)));

    IMP load = imp_implementationWithBlock(^(id manager, void (^completion)(NSError *)) {
        if (g_prefsEnabled >= 0) [(NETunnelProviderManager *)manager setEnabled:(g_prefsEnabled == 1)];
        if (g_sysOnDemand >= 0) [(NETunnelProviderManager *)manager setOnDemandEnabled:(g_sysOnDemand == 1)];
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
    // Волна-3 (5.1.96): натив после фазы старта туннель по таймаутам рукопожатия не гасит — только
    // Reconnecting; решение (переключить ноду, погасить) принимает фасад. Ожидание этого теста
    // оставалось от поведения до волны-3.
    CHECK(s.stopCalls == 0, "натив сам погасил туннель по таймаутам рукопожатия");
    CHECK(obs.has(Vpn::ConnectionState::Reconnecting), "после таймаутов рукопожатия нет Reconnecting");
    CHECK(!obs.has(Vpn::ConnectionState::Error), "таймауты рукопожатия дали Error");
    CHECK(obs.reasons.empty(), "причина обрыва при живом туннеле");
}

// ------------------------------------------------------------------------------------------------
// On-Demand (2026-09-30).
static NETunnelProviderManager *managerWithOnDemand(HarnessSession *s, BOOL enabled)
{
    NETunnelProviderManager *m = newManager(@"mgr-1", @"cfg-1", s);
    m.onDemandRules = @[[[[NEOnDemandRuleConnect alloc] init] autorelease]];
    m.onDemandEnabled = enabled;
    g_managers = [@[m] retain];
    g_loadMode = LoadMode::Deliver;
    return m;
}

// Сохранение старта идёт БЕЗ правила (даже если оно осталось от прошлой сессии); правило
// взводится только после подтверждённого рукопожатия.
static void test_on_demand_armed_after_handshake()
{
    setIntent("i-resume", "resume");
    HarnessSession *s = newSession(NEVPNStatusDisconnected);
    s.runtimeGeneration = @"run-1";
    s.statusReply = statusReply(@"run-1", @"cfg-1", 0, 0); // рукопожатия ещё нет
    NETunnelProviderManager *m = managerWithOnDemand(s, YES);
    QTimer poll;
    QObject::connect(&poll, &QTimer::timeout, [] { IosController::Instance()->checkStatus(); });
    poll.start(30);
    IosController::Instance()->connectVpn(amnezia::Proto::Awg, awgConfig(5000, 3));
    spin(260);
    CHECK(s.startCalls == 1, "туннель не стартовал");
    CHECK(!g_nativeLog.empty() && g_nativeLog.front() == "save:od=0", "старт сохранил профиль со взведённым правилом");
    CHECK(!m.isOnDemandEnabled, "правило взведено до подтверждения рукопожатия");
    s.statusReply = statusReply(@"run-1", @"cfg-1", (long long)[[NSDate date] timeIntervalSince1970], 5000);
    spin(200);
    CHECK(m.isOnDemandEnabled, "после рукопожатия правило не взведено");
    CHECK(m.onDemandRules.count == 1 && [m.onDemandRules.firstObject isKindOfClass:[NEOnDemandRuleConnect class]],
          "нет правила «подключать всегда»");
    CHECK(!g_nativeLog.empty() && g_nativeLog.back() == "save:od=1", "взвод правила не сохранён");
    CHECK(s.stopCalls == 0, "взвод правила погасил туннель");
    const size_t saves = g_nativeLog.size();
    spin(200);
    CHECK(g_nativeLog.size() == saves, "правило сохраняется повторно на каждом опросе");
}

static HarnessSession *liveSessionWithOnDemand(NETunnelProviderManager **manager, NEVPNStatus status = NEVPNStatusConnected)
{
    setIntent("i-resume", "resume");
    HarnessSession *s = newSession(status);
    s.runtimeGeneration = @"run-1";
    s.stopWritesUserInitiated = YES;
    *manager = managerWithOnDemand(s, YES);
    IosController::Instance()->requestReconcileStatus();
    spin(60);
    obs.clear();
    g_nativeLog.clear();
    return s;
}

// Стоп приложения при взведённом правиле: сначала сохранить «правило снято», потом stopTunnel.
static void test_stop_disarms_on_demand_before_stop()
{
    NETunnelProviderManager *m = nil;
    HarnessSession *s = liveSessionWithOnDemand(&m);
    g_saveDelayMs = 80;
    setIntent("i-off", "off");
    IosController::Instance()->disconnectVpn();
    spin(40);
    CHECK(s.stopCalls == 0, "stopTunnel раньше, чем снято правило: iOS поднимет туннель заново");
    spin(160);
    CHECK(s.stopCalls == 1, "stopTunnel не вызван после снятия правила");
    CHECK(g_nativeLog.size() == 2 && g_nativeLog[0] == "save:od=0" && g_nativeLog[1] == "stop", "порядок: снять правило → stop");
    CHECK(!m.isOnDemandEnabled, "правило осталось взведённым после стопа");
    CHECK(obs.has(Vpn::ConnectionState::Disconnected), "нет Disconnected");
    CHECK(obs.reasons.size() == 1, "причина стопа не одна");
    if (!obs.reasons.empty()) {
        CHECK(obs.reasons[0].first == QStringLiteral("expected_app_stop"), "стоп приложения помечен не expected_app_stop");
        CHECK(!obs.reasons[0].second, "стоп приложения помечен intentional");
    }
}

// Правило не взведено — стоп синхронный, без сохранений (поведение до On-Demand).
static void test_stop_without_on_demand_is_immediate()
{
    setIntent("i-resume", "resume");
    HarnessSession *s = adoptLiveSession();
    g_nativeLog.clear();
    IosController::Instance()->disconnectVpn();
    CHECK(s.stopCalls == 1, "без правила стоп перестал быть синхронным");
    spin(80);
    CHECK(g_nativeLog.size() == 1 && g_nativeLog[0] == "stop", "лишнее сохранение профиля при стопе без правила");
}

// «Выключить» при уже опущенном туннеле и взведённом правиле (iOS погасила сама): правило снять,
// гасить нечего.
static void test_stop_when_down_disarms_on_demand()
{
    NETunnelProviderManager *m = nil;
    HarnessSession *s = liveSessionWithOnDemand(&m, NEVPNStatusDisconnected);
    IosController::Instance()->disconnectVpn();
    CHECK(obs.has(Vpn::ConnectionState::Disconnected), "терминал стопа при опущенном туннеле не отдан сразу");
    spin(80);
    CHECK(g_nativeLog.size() == 1 && g_nativeLog[0] == "save:od=0", "правило не снято при опущенном туннеле");
    CHECK(!m.isOnDemandEnabled, "правило осталось взведённым");
    CHECK(s.stopCalls == 0, "stopTunnel по опущенному туннелю");
}

// То же, но iOS успела поднять туннель по правилу, пока сохранялось его снятие: гасим.
static void test_stop_when_down_stops_revived_session()
{
    NETunnelProviderManager *m = nil;
    HarnessSession *s = liveSessionWithOnDemand(&m, NEVPNStatusDisconnected);
    g_saveDelayMs = 80;
    IosController::Instance()->disconnectVpn();
    spin(20);
    s.hStatus = NEVPNStatusConnecting; // On-Demand
    notifyStatus(s);
    obs.clear();
    spin(200);
    CHECK(s.stopCalls == 1, "туннель, поднятый iOS во время снятия правила, не погашен");
    CHECK(obs.reasons.size() == 1, "нет причины стопа");
    if (!obs.reasons.empty()) {
        CHECK(obs.reasons[0].first == QStringLiteral("expected_app_stop"), "стоп поднятой iOS сессии не expected_app_stop");
        CHECK(!obs.reasons[0].second, "стоп приложения помечен intentional");
    }
}

// Системный демон не ответил на сохранение: стоп всё равно выполняется (по дедлайну).
static void test_stop_not_lost_when_disarm_save_silent()
{
    NETunnelProviderManager *m = nil;
    HarnessSession *s = liveSessionWithOnDemand(&m);
    g_saveMode = SaveMode::Never;
    IosController::Instance()->disconnectVpn();
    spin(100);
    CHECK(s.stopCalls == 0, "стоп не дождался дедлайна сохранения");
    spin(W(300, 3300));
    CHECK(s.stopCalls == 1, "молчание сохранения съело стоп");
}

// Сохранение отклонено (экземпляр устарел): перечитать, повторить, погасить — ровно один стоп.
static void test_stop_after_disarm_save_error_retries()
{
    NETunnelProviderManager *m = nil;
    HarnessSession *s = liveSessionWithOnDemand(&m);
    g_sysOnDemand = 1; // отклонённое сохранение правило в системе не снимает — перезагрузка вернёт YES
    g_saveMode = SaveMode::ErrorOnce;
    IosController::Instance()->disconnectVpn();
    spin(150);
    CHECK(s.stopCalls == 1, "после ошибки сохранения стоп не выполнен ровно один раз");
    CHECK(g_nativeLog.size() == 3 && g_nativeLog[0] == "save:od=0" && g_nativeLog[1] == "save:od=0" && g_nativeLog[2] == "stop",
          "нет повтора сохранения перед стопом");
    CHECK(!m.isOnDemandEnabled, "правило осталось взведённым");
}

// Туннель погас, потому что включили другой VPN: наш профиль в системе уже не активный, а у
// экземпляра в памяти isEnabled ещё YES. Снятие правила не должно сохранить его «активным» —
// иначе «выключить» в Tribe отключало бы чужой VPN.
static void test_stop_when_down_does_not_steal_active_vpn()
{
    NETunnelProviderManager *m = nil;
    HarnessSession *s = liveSessionWithOnDemand(&m, NEVPNStatusDisconnected);
    m.enabled = YES;       // устаревший экземпляр
    g_prefsEnabled = 0;    // система: активен другой VPN
    g_savedEnabled.clear();
    IosController::Instance()->disconnectVpn();
    spin(80);
    CHECK(g_savedEnabled.size() == 1, "правило не снято");
    if (!g_savedEnabled.empty())
        CHECK(!g_savedEnabled[0], "снятие правила сохранило наш профиль активным — чужой VPN будет отключён");
    CHECK(s.stopCalls == 0, "stopTunnel по опущенному туннелю");
}

// Правило взвёл другой процесс (команда «включить», переключатель в Настройках): экземпляр в
// памяти говорит «не взведено», система — «взведено». Стоп обязан идти через свежую загрузку.
static void test_stop_disarms_rule_armed_elsewhere()
{
    NETunnelProviderManager *m = nil;
    HarnessSession *s = liveSessionWithOnDemand(&m);
    m.onDemandEnabled = NO; // устаревший экземпляр
    g_sysOnDemand = 1;
    IosController::Instance()->disconnectVpn();
    CHECK(s.stopCalls == 0, "стоп без свежей загрузки профиля: правило другого процесса осталось взведённым");
    spin(100);
    CHECK(s.stopCalls == 1, "stopTunnel не вызван");
    CHECK(g_sysOnDemand == 0, "правило в системе осталось взведённым");
    CHECK(g_nativeLog.size() == 2 && g_nativeLog[0] == "save:od=0" && g_nativeLog[1] == "stop", "порядок: снять правило → stop");
}

// Правила в профиле есть, но в системе правило снято (после паузы/выключения): стоп — после
// свежей загрузки, без лишнего сохранения.
static void test_stop_with_disarmed_rules_skips_save()
{
    NETunnelProviderManager *m = nil;
    HarnessSession *s = liveSessionWithOnDemand(&m);
    m.onDemandEnabled = NO;
    g_sysOnDemand = 0;
    IosController::Instance()->disconnectVpn();
    spin(60);
    CHECK(s.stopCalls == 1, "stopTunnel не вызван");
    CHECK(g_nativeLog.size() == 1 && g_nativeLog[0] == "stop", "лишнее сохранение профиля при снятом правиле");
}

// «Выключить» и сразу «включить», пока снятие правила ещё сохраняется: Connect адоптирует живую
// сессию, стоп отменён — правило обязано вернуться (иначе сессия осталась бы без защиты).
static void test_quick_off_on_rearms_adopted_session()
{
    NETunnelProviderManager *m = nil;
    HarnessSession *s = liveSessionWithOnDemand(&m);
    g_sysOnDemand = 1;
    s.statusReply = statusReply(@"run-1", @"cfg-1", (long long)[[NSDate date] timeIntervalSince1970], 5000);
    QTimer poll;
    QObject::connect(&poll, &QTimer::timeout, [] { IosController::Instance()->checkStatus(); });
    poll.start(30);
    spin(80); // runtime-поколение сессии известно, рукопожатие подтверждено, правило взведено
    g_saveDelayMs = 80;
    g_nativeLog.clear();
    SignalTap tap;
    tap.attach();
    IosController::Instance()->disconnectVpn();
    spin(20);
    setIntent("i-resume-2", "resume");
    IosController::Instance()->connectVpn(amnezia::Proto::Awg, awgConfig());
    spin(500);
    CHECK(s.stopCalls == 0, "стоп выполнен поверх более нового Connect");
    CHECK(obs.live == 1, "живая сессия не адоптирована");
    CHECK(g_sysOnDemand == 1, "адоптированная сессия осталась без правила On-Demand");
    // Внешний обрыв адоптированной сессии — не «наш стоп» (флаг отменённого стопа снят).
    obs.clear();
    s.hStatus = NEVPNStatusDisconnected;
    notifyStatus(s);
    spin(20);
    CHECK(obs.reasons.size() == 1, "нет причины обрыва");
    if (!obs.reasons.empty())
        CHECK(obs.reasons[0].first != QStringLiteral("expected_app_stop"), "обрыв адоптированной сессии помечен отменённым стопом приложения");
}

// Сохранение снятия дошло ПОСЛЕ дедлайна: стоп уже был выполнен с ещё взведённым правилом, iOS
// подняла туннель заново — опоздавшее снятие гасит и эту сессию как стоп приложения.
static void test_late_disarm_stops_revived_session()
{
    NETunnelProviderManager *m = nil;
    HarnessSession *s = liveSessionWithOnDemand(&m);
    g_sysOnDemand = 1;
    g_saveDelayMs = W(450, 3600);
    IosController::Instance()->disconnectVpn();
    spin(W(300, 3300));
    CHECK(s.stopCalls == 1, "по дедлайну сохранения стоп не выполнен");
    CHECK(g_sysOnDemand == 1, "модель: правило ещё взведено");
    s.hStatus = NEVPNStatusConnecting; // On-Demand поднял туннель заново
    notifyStatus(s);
    s.hStatus = NEVPNStatusConnected;
    notifyStatus(s);
    obs.clear();
    spin(350);
    CHECK(g_sysOnDemand == 0, "опоздавшее снятие правила не дошло");
    CHECK(s.stopCalls == 2, "сессия, поднятая iOS до снятия правила, не погашена");
    CHECK(obs.reasons.size() == 1, "нет причины стопа");
    if (!obs.reasons.empty()) {
        CHECK(obs.reasons[0].first == QStringLiteral("expected_app_stop"), "стоп поднятой iOS сессии не expected_app_stop");
        CHECK(!obs.reasons[0].second, "стоп приложения помечен intentional");
    }
}

static HarnessSession *startedSessionAwaitingHandshake(NETunnelProviderManager **manager, QTimer *poll)
{
    setIntent("i-resume", "resume");
    HarnessSession *s = newSession(NEVPNStatusDisconnected);
    s.runtimeGeneration = @"run-1";
    s.statusReply = statusReply(@"run-1", @"cfg-1", 0, 0);
    *manager = managerWithOnDemand(s, NO);
    g_sysOnDemand = 0;
    QObject::connect(poll, &QTimer::timeout, [] { IosController::Instance()->checkStatus(); });
    poll->start(30);
    IosController::Instance()->connectVpn(amnezia::Proto::Awg, awgConfig(5000, 3));
    spin(260);
    return s;
}

// Пауза/выключение из другого процесса раньше подтверждения рукопожатия: правило не взводим.
static void test_arm_skipped_when_intent_paused()
{
    NETunnelProviderManager *m = nil;
    QTimer poll;
    HarnessSession *s = startedSessionAwaitingHandshake(&m, &poll);
    CHECK(s.startCalls == 1, "туннель не стартовал");
    setIntent("i-pause", "pause");
    s.statusReply = statusReply(@"run-1", @"cfg-1", (long long)[[NSDate date] timeIntervalSince1970], 5000);
    spin(200);
    CHECK(g_sysOnDemand == 0, "правило взведено при намерении «пауза»");
}

// Пауза пришла, пока сохранялся взвод (команда прочитала профиль до нашего сохранения и правило
// не сняла): после сохранения правило снимается, сессию своим стопом не помечаем.
static void test_arm_cleanup_when_pause_lands_during_save()
{
    NETunnelProviderManager *m = nil;
    QTimer poll;
    HarnessSession *s = startedSessionAwaitingHandshake(&m, &poll);
    g_saveDelayMs = 100;
    s.statusReply = statusReply(@"run-1", @"cfg-1", (long long)[[NSDate date] timeIntervalSince1970], 5000);
    spin(70);  // рукопожатие подтверждено, сохранение взвода в полёте
    poll.stop();
    setIntent("i-pause", "pause");
    s.hStatus = NEVPNStatusDisconnected; // команда «пауза» погасила туннель сама
    notifyStatus(s);
    obs.clear();
    s.hStatus = NEVPNStatusConnecting;   // взвод сохранился → iOS подняла туннель по правилу
    QTimer::singleShot(120, qApp, [s] { notifyStatus(s); });
    spin(400);
    CHECK(g_sysOnDemand == 0, "правило осталось взведённым после паузы");
    CHECK(s.stopCalls == 1, "сессия, поднятая iOS после паузы, не погашена");
    CHECK(obs.reasons.size() == 1, "нет причины стопа");
    if (!obs.reasons.empty())
        CHECK(obs.reasons[0].first != QStringLiteral("expected_app_stop"), "уборка после паузы помечена стопом приложения");
}

// Connect пришёл, пока снималось правило для стопа: стоп отменён, живая сессия адоптируется.
#ifndef HARNESS_OLD
// ---- AVPN (iOS data watch, build 140): On-Demand arming after leaving the screen, the `watch` block of
// the status reply, the plan file. Decisions: IosBackgroundArm.h, BackgroundHoldBook.h (pure tests in
// IosDataWatchTests.cpp); here the real controller over the model of the system's rule store.
// The app is on the screen again: the controller learns it from the system on its own status poll.
static void harnessReturnToScreen()
{
    IosController::Instance()->setAppActiveProbe([] { return true; });
    IosController::Instance()->checkStatus();
    spin(30);
    IosController::Instance()->setAppActiveProbe([] { return false; });
}

struct BgArmEvents {
    std::vector<std::string> lines;
    QMetaObject::Connection connection;
    BgArmEvents()
    {
        connection = QObject::connect(IosController::Instance(), &IosController::onDemandBackgroundEvent,
                                      [this](const QString &line) { lines.push_back(line.toStdString()); });
    }
    ~BgArmEvents() { QObject::disconnect(connection); }
    bool lastStartsWith(const char *prefix) const
    {
        return !lines.empty() && lines.back().compare(0, std::strlen(prefix), prefix) == 0;
    }
};

// The user leaves the app right after Connect: the handshake is not confirmed yet. The app holds
// background time, the existing status poll confirms the handshake, the existing arming arms the rule.
static void test_bg_arm_holds_until_handshake()
{
    NETunnelProviderManager *m = nil;
    QTimer poll;
    HarnessSession *s = startedSessionAwaitingHandshake(&m, &poll);
    BgArmEvents events;
    IosController::Instance()->noteAppBackground(true, 5000);
    CHECK(g_bgBegins == 1 && g_bgEnds == 0, "background time not taken for the arming");
    CHECK(events.lines.size() == 2
              && events.lines[0] == "on_demand_state armed=0 session=up proto=awg pending=0 handshake=awaiting"
              && events.lines[1] == "on_demand_bg_arm hold max_ms=5000",
          "the state of the rule and the hold are not journaled at the transition to background");
    spin(150);
    CHECK(g_bgEnds == 0 && !m.isOnDemandEnabled, "the hold ended or the rule was armed before the handshake");
    s.statusReply = statusReply(@"run-1", @"cfg-1", (long long)[[NSDate date] timeIntervalSince1970], 5000);
    spin(250);
    CHECK(m.isOnDemandEnabled, "the rule is not armed after the handshake came in the background");
    CHECK(g_bgBegins == 1 && g_bgEnds == 1, "background time not given back after the arming");
    CHECK(events.lastStartsWith("on_demand_bg_arm result=armed"), "result=armed not journaled");
    CHECK(s.stopCalls == 0, "the arming stopped the tunnel");
    // The next transition to background finds the rule armed: nothing to hold.
    IosController::Instance()->noteAppBackground(true, 5000);
    CHECK(g_bgBegins == 1 && events.lastStartsWith("on_demand_bg_arm result=not_needed why=armed"), "an armed session held background time again");
}

// No handshake within the bound: the hold is given back, the rule is NOT armed (only a proven session).
static void test_bg_arm_times_out()
{
    NETunnelProviderManager *m = nil;
    QTimer poll;
    startedSessionAwaitingHandshake(&m, &poll);
    BgArmEvents events;
    IosController::Instance()->noteAppBackground(true, 150);
    CHECK(g_bgBegins == 1, "no hold");
    spin(100);
    CHECK(g_bgEnds == 0, "released before its bound");
    spin(300);
    CHECK(g_bgEnds == 1 && events.lastStartsWith("on_demand_bg_arm result=timeout"), "the hold outlived its bound");
    CHECK(!m.isOnDemandEnabled, "a session without a confirmed handshake was armed");
    const size_t lines = events.lines.size();
    spin(150);
    CHECK(g_bgEnds == 1 && events.lines.size() == lines, "released or journaled twice");
}

// Flag off (the default): exactly build 139 - nothing held, nothing journaled.
static void test_bg_arm_flag_off_is_silent()
{
    NETunnelProviderManager *m = nil;
    QTimer poll;
    HarnessSession *s = startedSessionAwaitingHandshake(&m, &poll);
    BgArmEvents events;
    IosController::Instance()->noteAppBackground(false, 5000);
    spin(100);
    CHECK(g_bgBegins == 0 && g_bgEnds == 0 && events.lines.empty(), "with the flag off the background transition did something");
    // The arming itself is untouched by the flag: a handshake seen by the running app still arms.
    s.statusReply = statusReply(@"run-1", @"cfg-1", (long long)[[NSDate date] timeIntervalSince1970], 5000);
    spin(250);
    CHECK(m.isOnDemandEnabled && g_bgBegins == 0 && g_bgEnds == 0 && events.lines.empty(), "the existing arming changed or touched the guard");
    harnessReturnToScreen();
    CHECK(events.lines.empty() && g_bgEnds == 0, "the return to the screen did something without a hold");
}

static void test_bg_arm_not_needed_without_session()
{
    BgArmEvents events;
    IosController::Instance()->noteAppBackground(true, 5000);
    CHECK(g_bgBegins == 0, "background time taken with no tunnel");
    CHECK(events.lines.size() == 2 && events.lines[0] == "on_demand_state armed=0 session=down proto=- pending=0 handshake=done"
              && events.lines[1] == "on_demand_bg_arm result=not_needed why=no_session",
          "no session: state and not_needed are not journaled");
}

// Back on the screen before the handshake: the hold is given back, the running app arms as before.
static void test_bg_arm_foreground_releases()
{
    NETunnelProviderManager *m = nil;
    QTimer poll;
    startedSessionAwaitingHandshake(&m, &poll);
    BgArmEvents events;
    IosController::Instance()->noteAppBackground(true, 5000);
    // Review mutant W16: nobody tells the controller about the return - it asks the system itself
    // on its own status poll, so the hold cannot outlive the return because a caller forgot.
    IosController::Instance()->checkStatus();
    spin(30);
    CHECK(g_bgBegins == 1 && g_bgEnds == 0, "the hold was given back while the app is still in the background");
    harnessReturnToScreen();
    CHECK(g_bgBegins == 1 && g_bgEnds == 1, "the hold is not given back on the screen");
    CHECK(events.lastStartsWith("on_demand_bg_arm result=not_needed why=foreground"), "foreground release not journaled");
    harnessReturnToScreen();
    CHECK(g_bgEnds == 1 && events.lines.size() == 3, "a second poll on the screen released again");
}

// iOS ends the background time itself: the owner is told, nothing is released twice.
static void test_bg_arm_system_expiry()
{
    NETunnelProviderManager *m = nil;
    QTimer poll;
    startedSessionAwaitingHandshake(&m, &poll);
    BgArmEvents events;
    IosController::Instance()->noteAppBackground(true, 5000);
    CHECK(g_bgBegins == 1 && bool(g_bgExpire), "no hold");
    std::function<void()> expire = g_bgExpire;
    expire();
    CHECK(g_bgEnds == 1 && events.lastStartsWith("on_demand_bg_arm result=timeout why=expired"), "expiry by the system not handled");
    const size_t lines = events.lines.size();
    spin(120);
    harnessReturnToScreen();
    CHECK(g_bgEnds == 1 && events.lines.size() == lines, "after the expiry the hold was released or journaled again");
    CHECK(!m.isOnDemandEnabled, "the rule was armed without a handshake");
}

// iOS refuses background time: no hold, journaled, the app goes on as build 139.
static void test_bg_arm_refused_by_system()
{
    NETunnelProviderManager *m = nil;
    QTimer poll;
    startedSessionAwaitingHandshake(&m, &poll);
    BgArmEvents events;
    g_bgRefuse = true;
    IosController::Instance()->noteAppBackground(true, 5000);
    CHECK(g_bgBegins == 0 && g_bgEnds == 0 && events.lastStartsWith("on_demand_bg_arm result=timeout why=denied"), "a refusal is not journaled");
    spin(120);
    harnessReturnToScreen();
    CHECK(g_bgEnds == 0 && events.lines.size() == 2, "a refused hold was released");
}

// The tunnel-restart guard holds the same task: the arming finishing must not take its background time.
static void test_bg_arm_keeps_restart_guard_time()
{
    NETunnelProviderManager *m = nil;
    QTimer poll;
    HarnessSession *s = startedSessionAwaitingHandshake(&m, &poll);
    int restartExpired = 0;
    CHECK(AvpnBackgroundGuard_begin([&restartExpired] { ++restartExpired; }) && g_bgBegins == 1, "the restart guard got no background time");
    BgArmEvents events;
    IosController::Instance()->noteAppBackground(true, 5000);
    CHECK(g_bgBegins == 1, "a second system task was started for the arming");
    s.statusReply = statusReply(@"run-1", @"cfg-1", (long long)[[NSDate date] timeIntervalSince1970], 5000);
    spin(250);
    CHECK(m.isOnDemandEnabled && events.lastStartsWith("on_demand_bg_arm result=armed"), "not armed");
    CHECK(g_bgEnds == 0, "the arming finished and ended the task the restart guard still holds");
    AvpnBackgroundGuard_end();
    CHECK(g_bgEnds == 1 && restartExpired == 0, "the restart guard could not end its own hold");
}

// The `watch` block of the status reply reaches the facade with the session of the SAME reply; a build
// 139 extension (no block) gives a snapshot without it.
static void test_watch_block_forwarded()
{
    HarnessSession *s = adoptLiveSession();
    std::vector<QVariantMap> snapshots;
    QObject::connect(IosController::Instance(), &IosController::tunnelWatchSnapshot,
                     [&snapshots](const QVariantMap &snapshot) { snapshots.push_back(snapshot); });
    const long long now = (long long)[[NSDate date] timeIntervalSince1970];
    NSMutableDictionary *reply = [[statusReply(@"run-1", @"cfg-1", now, 5000) mutableCopy] autorelease];
    reply[@"watch"] = @{@"enabled": @YES, @"verdict": @"no_data", @"since_ms": @(1800000000000LL), @"cycles": @3,
                        @"probe": @"silent", @"would_switch": @YES, @"switch_seq": @0, @"switches": @[]};
    s.statusReply = reply;
    // An ordinary status poll (all there is with the flag off) never gives a snapshot.
    IosController::Instance()->checkStatus();
    spin(120);
    CHECK(snapshots.empty(), "a status poll nobody asked a snapshot from gave one");
    IosController::Instance()->requestStatusSnapshot();
    spin(120);
    CHECK(snapshots.size() == 1, "one request - one snapshot");
    IosController::Instance()->checkStatus();
    spin(120);
    CHECK(snapshots.size() == 1, "the poll after the answered request gave a second snapshot");
    if (!snapshots.empty()) {
        const QVariantMap watch = snapshots.back().value(QStringLiteral("watch")).toMap();
        const QVariantMap session = snapshots.back().value(QStringLiteral("session")).toMap();
        CHECK(watch.value(QStringLiteral("verdict")).toString() == QLatin1String("no_data")
                  && watch.value(QStringLiteral("enabled")).typeId() == QMetaType::Bool && watch.value(QStringLiteral("enabled")).toBool()
                  && watch.value(QStringLiteral("cycles")).toInt() == 3 && watch.value(QStringLiteral("since_ms")).toLongLong() == 1800000000000LL
                  && watch.value(QStringLiteral("would_switch")).toBool(),
              "the watch block did not arrive as sent");
        CHECK(session.value(QStringLiteral("node_id")).toString() == QLatin1String("9")
                  && session.value(QStringLiteral("generation")).toString() == QLatin1String("run-1"),
              "the snapshot does not carry the session of its own reply");
    }
    // A build 139 extension: no `watch` key at all.
    s.statusReply = statusReply(@"run-1", @"cfg-1", now, 6000);
    IosController::Instance()->requestStatusSnapshot();
    spin(120);
    CHECK(snapshots.size() == 2 && !snapshots.back().contains(QStringLiteral("watch"))
              && snapshots.back().value(QStringLiteral("session")).toMap().value(QStringLiteral("node_id")).toString() == QLatin1String("9"),
          "a reply without the block must give a snapshot without it");
    // A block that is not an object is dropped, the reply itself still applies.
    NSMutableDictionary *junk = [[statusReply(@"run-1", @"cfg-1", now, 7000) mutableCopy] autorelease];
    junk[@"watch"] = @"no_data";
    s.statusReply = junk;
    IosController::Instance()->requestStatusSnapshot();
    spin(120);
    CHECK(snapshots.size() == 3 && !snapshots.back().contains(QStringLiteral("watch")), "a garbled block was passed on");
}

// A snapshot request cancels the replies of requests sent before it: what the facade adopts was asked
// AFTER the return to the foreground.
static void test_status_snapshot_drops_older_reply()
{
    HarnessSession *s = adoptLiveSession();
    std::vector<QVariantMap> snapshots;
    QObject::connect(IosController::Instance(), &IosController::tunnelWatchSnapshot,
                     [&snapshots](const QVariantMap &snapshot) { snapshots.push_back(snapshot); });
    const long long now = (long long)[[NSDate date] timeIntervalSince1970];
    NSMutableDictionary *old = [[statusReply(@"run-1", @"cfg-1", now, 5000) mutableCopy] autorelease];
    old[@"watch"] = @{@"enabled": @YES, @"verdict": @"none"};
    s.statusReply = old;
    s.statusReplyDelayMs = 80; // the reply to the request below is still in flight when the snapshot is asked for
    IosController::Instance()->checkStatus();
    spin(20);
    NSMutableDictionary *fresh = [[statusReply(@"run-1", @"cfg-1", now, 9000) mutableCopy] autorelease];
    fresh[@"watch"] = @{@"enabled": @YES, @"verdict": @"no_data"};
    s.statusReply = fresh;
    IosController::Instance()->requestStatusSnapshot();
    spin(260);
    CHECK(snapshots.size() == 1, "the reply asked for before the snapshot request was adopted too");
    CHECK(!snapshots.empty() && snapshots.back().value(QStringLiteral("watch")).toMap().value(QStringLiteral("verdict")).toString()
                                     == QLatin1String("no_data"),
          "the snapshot is not the one asked for after the request");
}

// Stage 2, second review R5: the extension has no engine (an in-place switch failed and nothing could
// be started again). Its reply says so and carries no counters: the app is told, and nothing judges a
// handshake by a reply that has none.
static void test_engine_down_reply_is_told_and_judges_nothing()
{
    HarnessSession *s = adoptLiveSession();
    int told = 0;
    std::vector<QVariantMap> metadata;
    QObject::connect(IosController::Instance(), &IosController::tunnelEngineDown, [&told] { ++told; });
    QObject::connect(IosController::Instance(), &IosController::sessionMetadataChanged,
                     [&metadata](const QVariantMap &m) { metadata.push_back(m); });
    const long long now = (long long)[[NSDate date] timeIntervalSince1970];
    s.statusReply = statusReply(@"run-1", @"cfg-1", now, 5000);
    IosController::Instance()->checkStatus();
    spin(120);
    CHECK(told == 0, "a healthy reply said the engine is down");
    const size_t before = obs.states.size();
    s.statusReply = @{@"session_metadata": @{@"schema_version": @1, @"generation": @"run-1", @"configuration_generation": @"cfg-1",
                                             @"node_id": @"12", @"switch_seq": @2, @"switch_why": @"no_data"},
                      @"engine_down": @YES};
    QTimer poll;
    QObject::connect(&poll, &QTimer::timeout, [] { IosController::Instance()->checkStatus(); });
    poll.start(30);
    spin(600);
    poll.stop();
    CHECK(told >= 1, "the reply without an engine was not told to the app");
    CHECK(!metadata.empty() && metadata.back().value(QStringLiteral("node_id")).toString() == QLatin1String("12")
              && metadata.back().value(QStringLiteral("switch_seq")).toInt() == 2,
          "the session of that reply (where the tunnel stands) did not reach the app");
    CHECK(obs.states.size() == before, "a reply without counters changed the connection state");
    CHECK(!obs.has(Vpn::ConnectionState::Reconnecting) && !obs.has(Vpn::ConnectionState::Error),
          "a reply without counters was judged as a handshake timeout");
    CHECK(obs.reasons.empty(), "a disconnect reason for a live session");
    // Not a flag of the reply's type: a string or a missing key is not "down".
    const int toldBefore = told;
    NSMutableDictionary *junk = [[statusReply(@"run-1", @"cfg-1", now, 9000) mutableCopy] autorelease];
    junk[@"engine_down"] = @[@1];
    s.statusReply = junk;
    IosController::Instance()->checkStatus();
    spin(120);
    CHECK(told == toldBefore, "a garbled engine_down was taken for the truth");
}

// The same reply while a handshake is still awaited (the twin of handshake_timeout_stop_not_intentional,
// whose reply with counters gives Reconnecting after two timeouts): no counters - no timeout is counted.
static void test_engine_down_reply_is_not_a_handshake_timeout()
{
    setIntent("i-resume", "resume");
    HarnessSession *s = newSession(NEVPNStatusDisconnected);
    s.runtimeGeneration = @"run-5";
    s.statusReply = @{@"session_metadata": @{@"schema_version": @1, @"generation": @"run-5", @"configuration_generation": @"cfg-5",
                                             @"node_id": @"9"},
                      @"engine_down": @YES};
    g_managers = [@[newManager(@"mgr-1", @"cfg-5", s)] retain];
    int told = 0;
    QObject::connect(IosController::Instance(), &IosController::tunnelEngineDown, [&told] { ++told; });
    QTimer poll;
    QObject::connect(&poll, &QTimer::timeout, [] { IosController::Instance()->checkStatus(); });
    poll.start(30);
    IosController::Instance()->connectVpn(amnezia::Proto::Awg, awgConfig(150, 2));
    spin(1200);
    CHECK(s.startCalls == 1, "the tunnel did not start");
    CHECK(told >= 1, "the reply without an engine was not told to the app");
    CHECK(!obs.has(Vpn::ConnectionState::Reconnecting), "a reply without counters was counted as a handshake timeout");
    CHECK(!obs.has(Vpn::ConnectionState::Error) && s.stopCalls == 0, "a reply without counters stopped the tunnel");
}

static NSURL *g_planContainer = nil;
@interface NSFileManager (HarnessWatchPlan)
- (NSURL *)harness_containerURLForSecurityApplicationGroupIdentifier:(NSString *)identifier;
@end
@implementation NSFileManager (HarnessWatchPlan)
- (NSURL *)harness_containerURLForSecurityApplicationGroupIdentifier:(NSString *)identifier
{
    return [identifier isEqualToString:@"group.hk.wellwon.tribe"] ? g_planContainer : nil;
}
@end

// The plan file: the exact bytes, in the App Group container, replaced atomically; no container or an
// empty body - nothing is written.
static void test_watch_plan_file_written()
{
    method_exchangeImplementations(
        class_getInstanceMethod([NSFileManager class], @selector(containerURLForSecurityApplicationGroupIdentifier:)),
        class_getInstanceMethod([NSFileManager class], @selector(harness_containerURLForSecurityApplicationGroupIdentifier:)));
    NSString *dir = [NSTemporaryDirectory() stringByAppendingPathComponent:[[NSUUID UUID] UUIDString]];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *file = [dir stringByAppendingPathComponent:@"TribeWatchPlan.json"];
    g_planContainer = nil;
    CHECK(!IosController::Instance()->writeTunnelWatchPlanFile(QByteArrayLiteral("{\"schema\":1}")), "written without a container");
    g_planContainer = [NSURL fileURLWithPath:dir];
    CHECK(!IosController::Instance()->writeTunnelWatchPlanFile(QByteArray()), "an empty plan was written");
    CHECK(![[NSFileManager defaultManager] fileExistsAtPath:file], "a file appeared for an empty plan");
    const QByteArray first = QByteArrayLiteral("{\"schema\":1,\"features\":{\"ios_tunnel_watch\":true}}");
    CHECK(IosController::Instance()->writeTunnelWatchPlanFile(first), "the plan is not written");
    NSData *onDisk = [NSData dataWithContentsOfFile:file];
    CHECK(onDisk && QByteArray((const char *)onDisk.bytes, (qsizetype)onDisk.length) == first, "the bytes on disk are not the plan");
    // Stage 2: the plan may hold node keys - it never goes into a device backup.
    NSNumber *excluded = nil;
    [[NSURL fileURLWithPath:file] getResourceValue:&excluded forKey:NSURLIsExcludedFromBackupKey error:nil];
    CHECK(excluded.boolValue, "the plan file is not excluded from backups");
    const QByteArray second = QByteArrayLiteral("{\"schema\":1,\"features\":{\"ios_tunnel_watch\":false}}");
    CHECK(IosController::Instance()->writeTunnelWatchPlanFile(second), "the plan is not rewritten");
    onDisk = [NSData dataWithContentsOfFile:file];
    CHECK(onDisk && QByteArray((const char *)onDisk.bytes, (qsizetype)onDisk.length) == second, "the kill switch did not reach the file");
    excluded = nil; // an atomic write makes a new file: the mark has to be set after every write
    [[NSURL fileURLWithPath:file] getResourceValue:&excluded forKey:NSURLIsExcludedFromBackupKey error:nil];
    CHECK(excluded.boolValue, "the rewritten plan file is not excluded from backups");
    NSArray *left = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:dir error:nil];
    CHECK(left.count == 2 && [left containsObject:@"TribeWatchPlan.lock"], "the directory holds the plan and its lock, and no temporary file");

    // Third review, T4: the file has a second writer (the extension takes the spare nodes' keys out).
    // Both hold TribeWatchPlan.lock for their write: while the other side holds it, our write waits.
    NSString *lockPath = [dir stringByAppendingPathComponent:@"TribeWatchPlan.lock"];
    const auto elapsedMsWhileLockedFor = [&](int holdMs, const QByteArray &body) {
        const int fd = open(lockPath.fileSystemRepresentation, O_CREAT | O_RDWR, 0600);
        CHECK(fd >= 0 && flock(fd, LOCK_EX | LOCK_NB) == 0, "the test could not take the plan's lock");
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)holdMs * NSEC_PER_MSEC), dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
            flock(fd, LOCK_UN);
            close(fd);
        });
        const NSTimeInterval before = [NSDate timeIntervalSinceReferenceDate];
        CHECK(IosController::Instance()->writeTunnelWatchPlanFile(body), "the plan is not written");
        return (int)(([NSDate timeIntervalSinceReferenceDate] - before) * 1000);
    };
    const QByteArray third = QByteArrayLiteral("{\"schema\":2,\"seq\":3}");
    const int waited = elapsedMsWhileLockedFor(120, third);
    CHECK(waited >= 100, "the write did not wait for the other writer to release the lock");
    CHECK(waited < 240, "the write waited longer than the other writer held the lock");
    onDisk = [NSData dataWithContentsOfFile:file];
    CHECK(onDisk && QByteArray((const char *)onDisk.bytes, (qsizetype)onDisk.length) == third, "the plan written after the wait is not on disk");
    // A lock that is not released: the wait is bounded and the plan is written all the same - the kill
    // switch must reach the file.
    const QByteArray fourth = QByteArrayLiteral("{\"schema\":2,\"seq\":4,\"features\":{\"ios_tunnel_watch\":false}}");
    const int bounded = elapsedMsWhileLockedFor(900, fourth);
    CHECK(bounded >= 200 && bounded < 700, "the wait for the lock is not bounded at about a quarter of a second");
    onDisk = [NSData dataWithContentsOfFile:file];
    CHECK(onDisk && QByteArray((const char *)onDisk.bytes, (qsizetype)onDisk.length) == fourth, "a held lock kept the kill switch out of the file");
    spin(800); // the test's lock is released
    // The lock is free again after our own write.
    const int fd = open(lockPath.fileSystemRepresentation, O_CREAT | O_RDWR, 0600);
    CHECK(fd >= 0 && flock(fd, LOCK_EX | LOCK_NB) == 0, "our write left the lock taken");
    if (fd >= 0) {
        flock(fd, LOCK_UN);
        close(fd);
    }
    [[NSFileManager defaultManager] removeItemAtPath:dir error:nil];
    g_planContainer = nil;
}
#endif // HARNESS_OLD

static void test_connect_during_disarm_cancels_stop()
{
    NETunnelProviderManager *m = nil;
    HarnessSession *s = liveSessionWithOnDemand(&m);
    g_saveDelayMs = 80;
    SignalTap tap;
    tap.attach();
    IosController::Instance()->disconnectVpn();
    spin(20);
    IosController::Instance()->connectVpn(amnezia::Proto::Awg, awgConfig());
    spin(250);
    CHECK(s.stopCalls == 0, "стоп выполнен поверх более нового Connect");
    CHECK(obs.live == 1, "живая сессия не адоптирована");
    CHECK(!obs.has(Vpn::ConnectionState::Error), "Error при живой сессии");
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

#ifndef HARNESS_OLD
// Review of 136: a session iOS has kept Connected for 10 min (the cold-start rule shows it Connected,
// it is adopted) whose NE answers "never handshook". Handshake budget 150 ms x 2 for the test.
static int g_deadSignals = 0;
static NSDictionary *stalledReply(id softRestarts, id resumes) // nil counter = absent from the reply
{
    NSMutableDictionary *r = [[statusReply(@"run-1", @"cfg-1", 0, 0) mutableCopy] autorelease];
    NSMutableDictionary *roam = [NSMutableDictionary dictionary];
    if (softRestarts) roam[@"soft_restarts"] = softRestarts;
    if (resumes) roam[@"resumes"] = resumes;
    r[@"roam"] = roam;
    return r;
}
static HarnessSession *adoptStalledSession(NSDictionary *reply, bool uplinkUp)
{
    IosController *c = IosController::Instance();
    c->setRawConfigForTest(awgConfig(150, 2));
    c->setUplinkProbe([uplinkUp] { return uplinkUp; });
    QObject::connect(c, &IosController::adoptedDeadSessionStopped, [] { ++g_deadSignals; });
    HarnessSession *s = newSession(NEVPNStatusConnected);
    s.runtimeGeneration = @"run-1";
    s.hConnectedDate = [NSDate dateWithTimeIntervalSinceNow:-600];
    s.statusReply = reply;
    g_managers = [@[newManager(@"mgr-1", @"cfg-1", s)] retain];
    g_loadMode = LoadMode::Deliver;
    c->requestReconcileStatus();
    return s;
}
// 5.1.109 (IOS-UP35): the journal line with the decision inputs. main() mutes warnings through
// QT_LOGGING_RULES, which outranks setFilterRules - a category filter re-enables the default warnings.
// Scoped (review R6): starts with an empty capture, restores the previous handler and filter on exit -
// no state leaks into another test even if several run in one process.
static QStringList g_warnings;
struct WarningCapture {
    QtMessageHandler previousHandler = nullptr;
    QLoggingCategory::CategoryFilter previousFilter = nullptr;
    WarningCapture()
    {
        g_warnings.clear();
        previousFilter = QLoggingCategory::installFilter([](QLoggingCategory *category) {
            if (qstrcmp(category->categoryName(), "default") == 0) category->setEnabled(QtWarningMsg, true);
        });
        previousHandler = qInstallMessageHandler([](QtMsgType type, const QMessageLogContext &, const QString &msg) {
            if (type == QtWarningMsg) g_warnings << msg;
        });
    }
    ~WarningCapture()
    {
        qInstallMessageHandler(previousHandler);
        QLoggingCategory::installFilter(previousFilter);
        g_warnings.clear();
    }
    WarningCapture(const WarningCapture &) = delete;
    WarningCapture &operator=(const WarningCapture &) = delete;
};
static bool warned(const char *needle)
{
    for (const QString &w : g_warnings)
        if (w.contains(QLatin1String(needle))) return true;
    return false;
}
static int warnedCount(const char *needle)
{
    int n = 0;
    for (const QString &w : g_warnings)
        if (w.contains(QLatin1String(needle))) ++n;
    return n;
}
static void runStatusPolls(int ms)
{
    QTimer poll;
    QObject::connect(&poll, &QTimer::timeout, [] { IosController::Instance()->checkStatus(); });
    poll.start(30);
    spin(ms);
}
static void test_adopted_dead_session_stopped()
{
    WarningCapture capture;
    HarnessSession *s = adoptStalledSession(stalledReply(@0, @0), /*uplinkUp=*/true);
    runStatusPolls(1500);
    CHECK(warned("adopted_dead_check stop=1 why=- shown=1 pending=0 answered=1 hs=0 rx=0 rx_threshold=4096 "
                 "soft_restarts=0 resumes=0 physical_up=1"), "decision inputs of the stop are not journaled");
    CHECK(obs.has(Vpn::ConnectionState::Connected), "cold-start rule did not show the adopted session");
    CHECK(s.stopCalls == 1, "dead adopted session not stopped");
    CHECK(g_deadSignals == 1, "adoptedDeadSessionStopped not emitted");
    CHECK(!obs.has(Vpn::ConnectionState::Error), "dead adopted session stop emitted Error");
    bool appStop = false;
    for (const auto &r : obs.reasons)
        if (r.first == QStringLiteral("expected_app_stop") && !r.second) appStop = true;
    CHECK(appStop, "stop reason is not expected_app_stop intentional=false");
}
static void expectAdoptedKept(HarnessSession *s, const char *what)
{
    runStatusPolls(1500);
    CHECK(s.stopCalls == 0, what);
    CHECK(g_deadSignals == 0, "adoptedDeadSessionStopped emitted for a kept session");
    CHECK(!obs.has(Vpn::ConnectionState::Error), "kept adopted session got Error");
}
static void test_adopted_soft_restarted_session_kept()
{
    WarningCapture capture;
    expectAdoptedKept(adoptStalledSession(stalledReply(@1, @0), true), "soft-restarted session stopped");
    CHECK(obs.has(Vpn::ConnectionState::Reconnecting), "soft-restarted session is not Reconnecting");
    CHECK(warnedCount("adopted_dead_check stop=0 why=soft_restarted ") == 1,
          "kept decision not journaled exactly once (re-checked every timeout, logged on change)");
}
// Review R4: the "log on change" memory ends with the session - the next session of the same process
// with the same inputs is journaled again.
static void test_adopted_check_logged_per_session()
{
    WarningCapture capture;
    HarnessSession *s = adoptStalledSession(stalledReply(@1, @0), true);
    runStatusPolls(1500);
    CHECK(warnedCount("adopted_dead_check stop=0 why=soft_restarted ") == 1, "first session not journaled once");
    s.hStatus = NEVPNStatusDisconnected;
    notifyStatus(s);
    spin(50);
    s.hStatus = NEVPNStatusConnected; // the next session (On-Demand / Settings), same NE answers
    s.hConnectedDate = [NSDate dateWithTimeIntervalSinceNow:-600];
    notifyStatus(s);
    runStatusPolls(1500);
    CHECK(warnedCount("adopted_dead_check stop=0 why=soft_restarted ") == 2,
          "second session with the same inputs not journaled");
}
static void test_adopted_resumed_session_kept()
{
    expectAdoptedKept(adoptStalledSession(stalledReply(@0, @2), true), "resumed session stopped");
}
static void test_adopted_session_uplink_down_kept()
{
    WarningCapture capture;
    expectAdoptedKept(adoptStalledSession(stalledReply(@0, @0), /*uplinkUp=*/false), "session stopped while offline");
    CHECK(warned("adopted_dead_check stop=0 why=no_physical_uplink "), "offline decision not journaled");
}
static void test_adopted_session_empty_reply_kept()
{
    expectAdoptedKept(adoptStalledSession(nil, true), "session stopped without an NE answer");
}
static void test_adopted_session_no_counters_kept()
{
    expectAdoptedKept(adoptStalledSession(stalledReply(nil, nil), true), "session stopped without roam counters");
}
#endif

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


#ifndef HARNESS_OLD
// ------------------------------------------------------------------------------------------------
// AVPN upstream nodes (lane L3): the bridge half of client-envelope-contract.md.
static std::vector<QVariantMap> g_upstreamEvents;
static void tapUpstreamEvents()
{
    QObject::connect(IosController::Instance(), &IosController::upstreamLeaseEvent,
                     [](const QVariantMap &m) { g_upstreamEvents.push_back(m); });
}
static NSDictionary *upstreamObject(NSString *state, NSString *code, long long seq, long long revision,
                                    long long renewedMsAgo = 1000)
{
    return @{@"state": state, @"code": code, @"seq": @(seq), @"renewed_ms_ago": @(renewedMsAgo),
             @"expires_in_ms": @(800000), @"revision": @(revision), @"config_changed": @NO,
             @"applied_bytes": @(0), @"shadow_bytes": @(4096), @"meter_scope": @"tunnel"};
}
static NSDictionary *withUpstream(NSDictionary *reply, NSDictionary *upstream)
{
    NSMutableDictionary *r = [[reply mutableCopy] autorelease];
    r[@"upstream"] = upstream;
    return r;
}
static const char *kProfile = "3f9c2a7b1d4e8f60";
static avpn_ios::UpstreamLeaseEnvelope upstreamLease(const char *scope = "tunnel")
{
    avpn_ios::UpstreamLeaseEnvelope l;
    l.leaseId = "leaseAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    l.renewToken = "tlr1.AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-abcde";
    l.apiBase = "https://t.example.net";
    l.renewAfterS = 300;
    l.ttlS = 900;
    l.expiresInMs = 900000;
    l.seq = 1;
    l.epoch = 7;
    l.revision = 1763123456789LL;
    l.meterScope = scope;
    return l;
}
static avpn_ios::UpstreamStartEnvelope upstreamStart(bool withLease, const char *scope = "tunnel")
{
    avpn_ios::UpstreamStartEnvelope s;
    s.profileId = kProfile;
    s.nodeId = std::string("up:") + kProfile;
    s.configSha256 = std::string(64, 'a');
    s.hasLease = withLease;
    if (withLease) s.lease = upstreamLease(scope);
    return s;
}
static QJsonObject xrayConfigFor(const QString &nodeId)
{
    QJsonObject inner{{QStringLiteral("config"), QStringLiteral("{\"outbounds\":[]}")}};
    return QJsonObject{{QStringLiteral("hostName"), QStringLiteral("upstream.tribe")},
                       {QStringLiteral("awg_config_data"), inner},
                       {QStringLiteral("tribeSessionMetadata"), QJsonObject{{QStringLiteral("schema_version"), 1},
                                                                             {QStringLiteral("node_id"), nodeId}}}};
}
static NETunnelProviderManager *startXrayConnect(const QJsonObject &config, HarnessSession **sessionOut)
{
    setIntent("i-resume", "resume");
    HarnessSession *s = newSession(NEVPNStatusDisconnected);
    s.runtimeGeneration = @"run-1";
    s.statusReply = statusReply(@"run-1", @"cfg-1", 0, 0);
    NETunnelProviderManager *m = newManager(@"mgr-1", @"cfg-1", s);
    g_managers = [@[m] retain];
    g_loadMode = LoadMode::Deliver;
    IosController::Instance()->connectVpn(amnezia::Proto::Xray, config);
    spin(300);
    if (sessionOut) *sessionOut = s;
    return m;
}
static NSDictionary *providerConfig(NETunnelProviderManager *m)
{
    return ((NETunnelProviderProtocol *)m.protocolConfiguration).providerConfiguration;
}
static QJsonObject xrayBlob(NETunnelProviderManager *m)
{
    NSData *d = providerConfig(m)[@"xray"];
    return d ? QJsonDocument::fromJson(QByteArray((const char *)d.bytes, int(d.length))).object() : QJsonObject();
}

// Status reply -> upstreamLeaseEvent: only when something the engine acts on changed.
static void test_upstream_status_event_on_change()
{
    tapUpstreamEvents();
    const long long now = QDateTime::currentSecsSinceEpoch();
    HarnessSession *s = adoptLiveSession();
    NSDictionary *base = statusReply(@"run-1", @"cfg-1", now, 50000);
    s.statusReply = base; // AWG / own Xray reply: no `upstream`
    IosController::Instance()->checkStatus();
    spin(60);
    CHECK(g_upstreamEvents.empty(), "event without an upstream object");
    s.statusReply = withUpstream(base, upstreamObject(@"active", @"", 5, 100));
    IosController::Instance()->checkStatus();
    spin(60);
    CHECK(g_upstreamEvents.size() == 1, "first upstream status not emitted");
    if (!g_upstreamEvents.empty()) {
        const QVariantMap &e = g_upstreamEvents.back();
        CHECK(e.value("state").toString() == "active" && e.value("seq").toLongLong() == 5, "event fields");
        CHECK(e.value("shadow_bytes").toLongLong() == 4096 && e.value("meter_scope").toString() == "tunnel", "bytes/scope");
        CHECK(e.size() == 10, "contract section 5 has 10 keys");
    }
    s.statusReply = withUpstream(base, upstreamObject(@"active", @"", 5, 100, 9000)); // only ms moved
    IosController::Instance()->checkStatus();
    spin(60);
    CHECK(g_upstreamEvents.size() == 1, "status poll without a change emitted");
    s.statusReply = withUpstream(base, upstreamObject(@"active", @"", 6, 101));
    IosController::Instance()->checkStatus();
    spin(60);
    CHECK(g_upstreamEvents.size() == 2, "renewal / newer revision not emitted");
    s.statusReply = withUpstream(base, upstreamObject(@"terminal", @"lease_gone", 6, 101));
    IosController::Instance()->checkStatus();
    spin(60);
    CHECK(g_upstreamEvents.size() == 3, "terminal not emitted");
    if (g_upstreamEvents.size() == 3)
        CHECK(g_upstreamEvents.back().value("code").toString() == "lease_gone", "terminal code");
}

// setUpstreamStart -> the Xray envelope carries upstream_lease + upstream metadata.
static void test_upstream_start_envelope()
{
    IosController *c = IosController::Instance();
    CHECK(c->setUpstreamStart(upstreamStart(true, "proxy")), "valid start refused");
    HarnessSession *s = nullptr;
    NETunnelProviderManager *m = startXrayConnect(xrayConfigFor(QStringLiteral("up:3f9c2a7b1d4e8f60")), &s);
    CHECK(s.startCalls == 1, "tunnel not started");
    NSDictionary *pc = providerConfig(m);
    NSDictionary *lease = pc[@"upstream_lease"];
    CHECK([lease isKindOfClass:[NSDictionary class]], "no upstream_lease in the envelope");
    CHECK([lease[@"lease_id"] isEqual:@"leaseAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"], "lease_id");
    CHECK([lease[@"renew_token"] hasPrefix:@"tlr1."], "renew_token");
    CHECK([lease[@"api_base"] isEqual:@"https://t.example.net"], "api_base");
    const long long expiresIn = [lease[@"expires_in_ms"] longLongValue];
    CHECK(expiresIn <= 900000 && expiresIn > 800000, "expires_in_ms counts from the write");
    CHECK([lease[@"seq"] longLongValue] == 1 && [lease[@"epoch"] longLongValue] == 7, "seq/epoch");
    CHECK([lease[@"meter_scope"] isEqual:@"tunnel"], "proxy asked without meter_tags -> tunnel");
    CHECK([lease[@"meter_tags"] isKindOfClass:[NSArray class]] && [lease[@"meter_tags"] count] == 0, "empty meter_tags");
    NSDictionary *md = pc[@"tribeSessionMetadata"];
    CHECK([md[@"upstream"] intValue] == 1 && [md[@"profile_id"] isEqual:@"3f9c2a7b1d4e8f60"], "metadata upstream");
    CHECK([md[@"proto"] isEqual:@"xray"] && [md[@"node_id"] isEqual:@"up:3f9c2a7b1d4e8f60"], "metadata node");
    CHECK([md[@"config_sha256"] length] == 64 && md[@"generation"] != nil, "metadata sha/generation");
    CHECK(!xrayBlob(m).contains("xray_tunables"), "xray_tunables without server numbers");
}

// meter_tags pass through; with them the envelope keeps "proxy".
static void test_upstream_meter_tags_in_envelope()
{
    avpn_ios::UpstreamStartEnvelope start = upstreamStart(true, "proxy");
    start.lease.meterTags = {"proxy", "proxy-b"};
    CHECK(IosController::Instance()->setUpstreamStart(start), "start with meter_tags refused");
    NETunnelProviderManager *m = startXrayConnect(xrayConfigFor(QStringLiteral("up:3f9c2a7b1d4e8f60")), nullptr);
    NSDictionary *lease = providerConfig(m)[@"upstream_lease"];
    CHECK([lease[@"meter_scope"] isEqual:@"proxy"], "proxy with meter_tags");
    CHECK([lease[@"meter_tags"] isEqual:(@[@"proxy", @"proxy-b"])], "meter_tags in the envelope");
}

// A provisional start: metadata, no lease. An armed start for another node is dropped.
static void test_upstream_start_provisional_and_foreign()
{
    IosController *c = IosController::Instance();
    CHECK(c->setUpstreamStart(upstreamStart(false)), "provisional start refused");
    NETunnelProviderManager *m = startXrayConnect(xrayConfigFor(QStringLiteral("up:3f9c2a7b1d4e8f60")), nullptr);
    NSDictionary *pc = providerConfig(m);
    CHECK(pc[@"xray"] != nil, "provisional Xray start did not happen");
    CHECK(pc[@"upstream_lease"] == nil, "provisional start has a lease");
    CHECK([pc[@"tribeSessionMetadata"][@"upstream"] intValue] == 1, "provisional metadata");
    // Armed for another node: this connect (own Xray "9:xray") must not carry it.
    CHECK(c->setUpstreamStart(upstreamStart(true)), "start refused");
    HarnessSession *s2 = nullptr;
    NETunnelProviderManager *m2 = startXrayConnect(xrayConfigFor(QStringLiteral("9:xray")), &s2);
    NSDictionary *pc2 = providerConfig(m2);
    CHECK(s2.startCalls == 1 && pc2[@"xray"] != nil, "second (own Xray) start did not happen");
    CHECK(pc2[@"upstream_lease"] == nil, "lease leaked into another node's start");
    CHECK(pc2[@"tribeSessionMetadata"][@"upstream"] == nil, "upstream metadata leaked into own Xray");
    // Invalid struct refused.
    avpn_ios::UpstreamStartEnvelope bad = upstreamStart(true);
    bad.lease.renewToken.clear();
    CHECK(!c->setUpstreamStart(bad), "invalid start accepted");
}

// xray_tunables: only numbers the server publishes, clamped; own Xray too.
static void test_xray_tunables_in_envelope()
{
    avpn::TuningStore::set({{QStringLiteral("xray_memory_limit_mib"), 100.0},
                            {QStringLiteral("xray_hev_task_stack_size"), 24576.0}}, {});
    NETunnelProviderManager *m = startXrayConnect(xrayConfigFor(QStringLiteral("9:xray")), nullptr);
    CHECK(xrayBlob(m).contains("config"), "Xray start did not happen");
    const QJsonObject t = xrayBlob(m).value("xray_tunables").toObject();
    CHECK(t.value("memory_limit_mib").toInt() == 40, "memory limit clamped to 40");
    CHECK(t.value("hev_task_stack_size").toInt() == 24576, "task stack");
    CHECK(!t.contains("hev_tcp_buffer_size") && !t.contains("hev_max_session_count"), "absent numbers sent");
}

// upstream_lease_set: message to the live extension, reply -> upstreamLeaseEvent (always).
static void test_upstream_lease_set_message()
{
    tapUpstreamEvents();
    HarnessSession *s = adoptLiveSession();
    s.upstreamLeaseSetReply = @{@"upstream": upstreamObject(@"active", @"", 1, 100, -1)};
    CHECK(IosController::Instance()->sendUpstreamLeaseSet(upstreamLease()), "not sent");
    spin(80);
    NSDictionary *msg = s.lastUpstreamLeaseSet;
    CHECK([msg[@"action"] isEqual:@"upstream_lease_set"], "action");
    CHECK([msg[@"upstream_lease"][@"lease_id"] isEqual:@"leaseAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"], "lease in message");
    CHECK(g_upstreamEvents.size() == 1 && g_upstreamEvents.back().value("state").toString() == "active", "reply not emitted");
    avpn_ios::UpstreamLeaseEnvelope bad = upstreamLease();
    bad.apiBase = "http://x";
    CHECK(!IosController::Instance()->sendUpstreamLeaseSet(bad), "invalid lease sent");
}
#endif

static const Test kTests[] = {
#ifndef HARNESS_OLD
    {"upstream_status_event_on_change", test_upstream_status_event_on_change},
    {"upstream_start_envelope", test_upstream_start_envelope},
    {"upstream_meter_tags_in_envelope", test_upstream_meter_tags_in_envelope},
    {"upstream_start_provisional_and_foreign", test_upstream_start_provisional_and_foreign},
    {"xray_tunables_in_envelope", test_xray_tunables_in_envelope},
    {"upstream_lease_set_message", test_upstream_lease_set_message},
#endif
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
#ifndef HARNESS_OLD
    {"adopted_dead_session_stopped", test_adopted_dead_session_stopped},
    {"adopted_soft_restarted_session_kept", test_adopted_soft_restarted_session_kept},
    {"adopted_resumed_session_kept", test_adopted_resumed_session_kept},
    {"adopted_check_logged_per_session", test_adopted_check_logged_per_session},
    {"adopted_session_uplink_down_kept", test_adopted_session_uplink_down_kept},
    {"adopted_session_empty_reply_kept", test_adopted_session_empty_reply_kept},
    {"adopted_session_no_counters_kept", test_adopted_session_no_counters_kept},
#endif
    {"on_demand_armed_after_handshake", test_on_demand_armed_after_handshake},
#ifndef HARNESS_OLD
    // AVPN (iOS data watch, build 140)
    {"bg_arm_holds_until_handshake", test_bg_arm_holds_until_handshake},
    {"bg_arm_times_out", test_bg_arm_times_out},
    {"bg_arm_flag_off_is_silent", test_bg_arm_flag_off_is_silent},
    {"bg_arm_not_needed_without_session", test_bg_arm_not_needed_without_session},
    {"bg_arm_foreground_releases", test_bg_arm_foreground_releases},
    {"bg_arm_system_expiry", test_bg_arm_system_expiry},
    {"bg_arm_refused_by_system", test_bg_arm_refused_by_system},
    {"bg_arm_keeps_restart_guard_time", test_bg_arm_keeps_restart_guard_time},
    {"watch_block_forwarded", test_watch_block_forwarded},
    {"status_snapshot_drops_older_reply", test_status_snapshot_drops_older_reply},
    {"engine_down_reply_is_told_and_judges_nothing", test_engine_down_reply_is_told_and_judges_nothing},
    {"engine_down_reply_is_not_a_handshake_timeout", test_engine_down_reply_is_not_a_handshake_timeout},
    {"watch_plan_file_written", test_watch_plan_file_written},
#endif
    {"stop_disarms_on_demand_before_stop", test_stop_disarms_on_demand_before_stop},
    {"stop_without_on_demand_is_immediate", test_stop_without_on_demand_is_immediate},
    {"stop_when_down_disarms_on_demand", test_stop_when_down_disarms_on_demand},
    {"stop_when_down_stops_revived_session", test_stop_when_down_stops_revived_session},
    {"stop_not_lost_when_disarm_save_silent", test_stop_not_lost_when_disarm_save_silent},
    {"stop_after_disarm_save_error_retries", test_stop_after_disarm_save_error_retries},
    {"connect_during_disarm_cancels_stop", test_connect_during_disarm_cancels_stop},
    {"stop_when_down_does_not_steal_active_vpn", test_stop_when_down_does_not_steal_active_vpn},
    {"stop_disarms_rule_armed_elsewhere", test_stop_disarms_rule_armed_elsewhere},
    {"stop_with_disarmed_rules_skips_save", test_stop_with_disarmed_rules_skips_save},
    {"quick_off_on_rearms_adopted_session", test_quick_off_on_rearms_adopted_session},
    {"late_disarm_stops_revived_session", test_late_disarm_stops_revived_session},
    {"arm_skipped_when_intent_paused", test_arm_skipped_when_intent_paused},
    {"arm_cleanup_when_pause_lands_during_save", test_arm_cleanup_when_pause_lands_during_save},
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
