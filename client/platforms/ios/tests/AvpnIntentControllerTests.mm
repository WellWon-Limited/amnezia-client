// AVPN (фикс-волна 2026-09-22, зона CL-C): тесты AvpnIntentController.mm на настоящем файловом
// «App Group» (containerURLForSecurityApplicationGroupIdentifier: подменён на временный каталог).
//   C6/H10 — главный поток не блокируется на локе, который держит другой процесс (NE, suspend);
//            Avpn_performIfCurrent не держит лок на время системного вызова старта.
//   C8     — подряд идущие status_timeout схлопываются в журнале.
// Сборка/запуск — build_ios_controller_harness.sh (BASE=<rev> — против старого кода).
#include "AvpnIntentController.h"
#include "core/serviceEngine/AvpnIntentBridge.h"
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <string>
#include <sys/file.h>
#include <thread>
#include <unistd.h>

namespace avpn {
AvpnIntentBridge *AvpnIntentBridge::instance() { return nullptr; }
void AvpnIntentBridge::requestAction(const QVariantMap &) {}
}

static int g_failures = 0;
#define CHECK(cond, msg)                                                                         \
    do {                                                                                         \
        if (!(cond)) {                                                                           \
            ++g_failures;                                                                        \
            std::fprintf(stderr, "  CHECK FAILED %s:%d: %s  [%s]\n", __FILE__, __LINE__, msg, #cond); \
        }                                                                                        \
    } while (0)

static NSURL *g_dir = nil;

static void installContainer()
{
    char tmpl[] = "/tmp/avpn-appgroup.XXXXXX";
    const char *dir = mkdtemp(tmpl);
    g_dir = [[NSURL fileURLWithPath:[NSString stringWithUTF8String:dir] isDirectory:YES] retain];
    IMP imp = imp_implementationWithBlock(^NSURL *(id, NSString *) { return g_dir; });
    SEL sel = @selector(containerURLForSecurityApplicationGroupIdentifier:);
    Method m = class_getInstanceMethod([NSFileManager class], sel);
    method_setImplementation(m, imp);
}

static int openLock(const char *name)
{
    NSString *path = [[g_dir URLByAppendingPathComponent:[NSString stringWithUTF8String:name]] path];
    return open(path.fileSystemRepresentation, O_CREAT | O_RDWR, 0600);
}

static NSDictionary *readJson(const char *name)
{
    NSData *data = [NSData dataWithContentsOfURL:[g_dir URLByAppendingPathComponent:[NSString stringWithUTF8String:name]]];
    id value = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:nil] : nil;
    return [value isKindOfClass:[NSDictionary class]] ? value : @{};
}

// Вызов не должен зависнуть: другой процесс (NE) держит лок бесконечно долго.
static bool finishesWithin(int ms, const std::function<void()> &fn)
{
    auto done = std::make_shared<std::atomic_bool>(false);
    std::thread([done, fn] { @autoreleasepool { fn(); } done->store(true); }).detach();
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (done->load()) return true;
        usleep(5000);
    }
    return false;
}

static void test_gui_intent_not_blocked_by_held_lock()
{
    const int holder = openLock("TribeIntentState.lock");
    CHECK(holder >= 0 && flock(holder, LOCK_EX) == 0, "не удалось взять лок-держатель");
    const bool finished = finishesWithin(2000, [] { Avpn_recordGuiIntent(true); });
    CHECK(finished, "Avpn_recordGuiIntent завис на локе, который держит другой процесс (0x8BADF00D)");
    if (!finished) {
        std::printf("FAIL intent_gui_not_blocked_by_held_lock\n");
        std::fflush(stdout);
        _exit(1); // поток висит в flock — выходим, не дожидаясь
    }
    CHECK([readJson("TribeIntentState.json")[@"action"] isEqual:@"resume"], "намерение не записано (best-effort без лока)");
    flock(holder, LOCK_UN);
    close(holder);
}

static void test_perform_does_not_hold_lock_during_action()
{
    Avpn_recordGuiIntent(true);
    const QString generation = Avpn_currentIntentGeneration();
    CHECK(!generation.isEmpty(), "нет поколения намерения");
    bool ran = false, lockFreeInside = false;
    Avpn_performIfCurrent(generation, [&] {
        ran = true;
        const int probe = openLock("TribeIntentState.lock");
        lockFreeInside = probe >= 0 && flock(probe, LOCK_EX | LOCK_NB) == 0;
        if (probe >= 0) { flock(probe, LOCK_UN); close(probe); }
    });
    CHECK(ran, "действие не выполнено при текущем поколении");
    CHECK(lockFreeInside, "Avpn_performIfCurrent держит лок на время startVPNTunnel");
}

#ifndef HARNESS_OLD
static void test_perform_reports_superseded()
{
    Avpn_recordGuiIntent(true);
    const QString generation = Avpn_currentIntentGeneration();
    const AvpnIntentPerform r = Avpn_performIfCurrent(generation, [] { Avpn_recordGuiIntent(false); });
    CHECK(r == AvpnIntentPerform::Superseded, "новое намерение во время действия не распознано");
    bool ran = false;
    const AvpnIntentPerform stale = Avpn_performIfCurrent(generation, [&] { ran = true; });
    CHECK(stale == AvpnIntentPerform::NotCurrent && !ran, "устаревшее поколение выполнило действие");
    const AvpnIntentPerform ok = Avpn_performIfCurrent(Avpn_currentIntentGeneration(), [] {});
    CHECK(ok == AvpnIntentPerform::Performed, "текущее поколение не Performed");
}
#endif

static void test_lifecycle_status_timeout_collapsed()
{
    for (int i = 0; i < 5; ++i)
        Avpn_recordLifecycle(QStringLiteral("status_timeout"), {{QStringLiteral("request_id"), i}});
    Avpn_recordLifecycle(QStringLiteral("os_state"), {{QStringLiteral("state"), 4}});
    Avpn_recordLifecycle(QStringLiteral("status_timeout"), {{QStringLiteral("request_id"), 9}});
    NSArray *entries = readJson("TribeGUILifecycle.json")[@"entries"];
    CHECK(entries.count == 3, "повторяющиеся status_timeout не схлопнуты");
    if (entries.count == 3) {
        CHECK([entries[0][@"event"] isEqual:@"status_timeout"] && [entries[0][@"repeat"] intValue] == 5, "нет счётчика повторов");
        CHECK([entries[0][@"last_fields"][@"request_id"] intValue] == 4, "не сохранены поля последнего повтора");
        CHECK([entries[1][@"event"] isEqual:@"os_state"], "другое событие потеряно");
        CHECK([entries[2][@"event"] isEqual:@"status_timeout"] && !entries[2][@"repeat"], "новая серия после другого события");
    }
}

static void test_lifecycle_not_blocked_by_held_lock()
{
    const int holder = openLock("TribeLifecycle.lock");
    CHECK(holder >= 0 && flock(holder, LOCK_EX) == 0, "не удалось взять лок-держатель");
    const bool finished = finishesWithin(2000, [] { Avpn_recordLifecycle(QStringLiteral("os_state")); });
    CHECK(finished, "Avpn_recordLifecycle завис на чужом локе");
    if (!finished) {
        std::printf("FAIL intent_lifecycle_not_blocked_by_held_lock\n");
        std::fflush(stdout);
        _exit(1);
    }
    flock(holder, LOCK_UN);
    close(holder);
}

struct Test { const char *name; void (*fn)(); };
static const Test kTests[] = {
    {"intent_gui_not_blocked_by_held_lock", test_gui_intent_not_blocked_by_held_lock},
    {"intent_perform_does_not_hold_lock_during_action", test_perform_does_not_hold_lock_during_action},
#ifndef HARNESS_OLD
    {"intent_perform_reports_superseded", test_perform_reports_superseded},
#endif
    {"intent_lifecycle_status_timeout_collapsed", test_lifecycle_status_timeout_collapsed},
    {"intent_lifecycle_not_blocked_by_held_lock", test_lifecycle_not_blocked_by_held_lock},
};

int main(int argc, char **argv)
{
    if (argc == 2 && std::string(argv[1]) == "--list") {
        for (const Test &t : kTests) std::printf("%s\n", t.name);
        return 0;
    }
    if (argc != 2) return 2;
    qputenv("QT_LOGGING_RULES", "*.debug=false;*.warning=false");
    @autoreleasepool {
        installContainer();
        for (const Test &t : kTests) {
            if (std::string(argv[1]) != t.name) continue;
            t.fn();
            std::printf("%s %s\n", g_failures ? "FAIL" : "PASS", t.name);
            return g_failures ? 1 : 0;
        }
    }
    return 2;
}
