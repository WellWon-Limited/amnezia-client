#import "AvpnIntentController.h"
#import <Foundation/Foundation.h>
#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>
#include <QJsonDocument>
#include <QJsonObject>
#include <QDebug>
#include "IosNativePolicy.h"
#include "core/serviceEngine/AvpnIntentBridge.h"

namespace {
NSURL *containerURL()
{
    return [[NSFileManager defaultManager] containerURLForSecurityApplicationGroupIdentifier:@"group.hk.wellwon.tribe"];
}
// AVPN (фикс-волна 2026-09-22, C6/H10): раньше flock(LOCK_EX) без таймаута на главном Qt-потоке —
// NE/extension, suspend-нутый ОС внутри своего record() с тем же локом, замораживал GUI до
// watchdog 0x8BADF00D. Теперь LOCK_NB с ограниченными повторами (20×5 мс). Если лок так и не
// взят, а файл открыт (App Group есть) — вызывающий продолжает best-effort БЕЗ лока с логом:
// запись атомарна (NSDataWritingAtomic), теряется лишь сериализация CAS с соседним процессом,
// что лучше, чем зависший главный поток. fd < 0 = App Group недоступна (как раньше: no-op).
struct SharedLock {
    int fd = -1;
    bool locked = false;
    SharedLock(NSString *name = @"TribeIntentState.lock") {
        NSURL *url = [containerURL() URLByAppendingPathComponent:name];
        if (url) fd = open(url.path.fileSystemRepresentation, O_CREAT | O_RDWR, 0600);
        locked = avpn_ios::tryLockExclusive(fd);
        if (fd >= 0 && !locked)
            qWarning() << "[ios lifecycle] shared lock busy, continuing without it:" << QString::fromNSString(name);
    }
    ~SharedLock() {
        if (locked) flock(fd, LOCK_UN);
        if (fd >= 0) close(fd);
    }
    SharedLock(const SharedLock &) = delete;
    SharedLock &operator=(const SharedLock &) = delete;
};
NSDictionary *readRecord(NSString *name)
{
    NSURL *url = [containerURL() URLByAppendingPathComponent:name];
    NSData *data = url ? [NSData dataWithContentsOfURL:url] : nil;
    id result = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:nil] : nil;
    return [result isKindOfClass:[NSDictionary class]] ? result : @{};
}
bool writeRecord(NSDictionary *record, NSString *name)
{
    NSURL *url = [containerURL() URLByAppendingPathComponent:name];
    NSData *data = [NSJSONSerialization dataWithJSONObject:record options:0 error:nil];
    return url && data && [data writeToURL:url options:NSDataWritingAtomic | NSDataWritingFileProtectionCompleteUntilFirstUserAuthentication error:nil];
}
QVariantMap mapFromRecord(NSDictionary *record)
{
    NSData *data = [NSJSONSerialization dataWithJSONObject:record options:0 error:nil];
    return QJsonDocument::fromJson(QByteArray((const char *)data.bytes, data.length)).object().toVariantMap();
}
}

QVariantMap Avpn_currentIntent()
{
    @autoreleasepool { return mapFromRecord(readRecord(@"TribeIntentState.json")); }
}
QString Avpn_currentIntentGeneration()
{
    return Avpn_currentIntent().value(QStringLiteral("generation")).toString();
}
QVariantMap Avpn_lastStop()
{
    @autoreleasepool { return mapFromRecord(readRecord(@"TribeLastStop.json")); }
}
// AVPN (C6/H10): лок держим только на ПРОВЕРКУ поколения, не на время системного вызова
// (startVPNTunnelWithOptions может длиться сотни мс, а соседний процесс ждёт тот же лок).
// После действия поколение перепроверяется: если за это время записали новое намерение
// (Shortcut/NE), вызывающий получает Superseded и откатывает своё действие.
AvpnIntentPerform Avpn_performIfCurrent(const QString &generation, const std::function<void()> &action)
{
    @autoreleasepool {
        {
            SharedLock lock;
            if (lock.fd < 0 || Avpn_currentIntentGeneration() != generation) return AvpnIntentPerform::NotCurrent;
        }
        action();
        return Avpn_currentIntentGeneration() == generation ? AvpnIntentPerform::Performed
                                                            : AvpnIntentPerform::Superseded;
    }
}
bool Avpn_resumeIntentIfCurrent(const QString &generation)
{
    @autoreleasepool {
        SharedLock lock;
        if (lock.fd < 0) return false;
        NSDictionary *current = readRecord(@"TribeIntentState.json");
        const long long now = (long long)([[NSDate date] timeIntervalSince1970] * 1000);
        if (![current[@"generation"] isEqual:generation.toNSString()] ||
            ![current[@"action"] isEqual:@"pause"] || ![current[@"was_active"] boolValue] ||
            ![current[@"applied"] boolValue] || [current[@"deadline_ms"] longLongValue] <= 0 ||
            [current[@"deadline_ms"] longLongValue] > now) return false;
        NSString *next = [[NSUUID UUID] UUIDString];
        return writeRecord(@{@"schema_version": @1, @"generation": next, @"ack_generation": next,
                             @"source": @"gui", @"action": @"resume", @"applied": @YES,
                             @"created_ms": @(now)}, @"TribeIntentState.json");
    }
}
void Avpn_ackIntentAction(const QString &generation)
{
    @autoreleasepool {
        SharedLock lock;
        if (lock.fd < 0) return;
        NSMutableDictionary *record = [NSMutableDictionary dictionaryWithDictionary:readRecord(@"TribeIntentState.json")];
        if (![record[@"generation"] isEqual:generation.toNSString()]) return;
        record[@"ack_generation"] = generation.toNSString();
        writeRecord(record, @"TribeIntentState.json");
    }
}
extern "C" void Avpn_recordGuiIntent(bool enabled)
{
    @autoreleasepool {
        SharedLock lock;
        if (lock.fd < 0) return;
        NSString *generation = [[NSUUID UUID] UUIDString];
        writeRecord(@{@"schema_version": @1, @"generation": generation, @"ack_generation": generation,
                      @"source": @"gui", @"action": enabled ? @"resume" : @"off", @"applied": @YES,
                      @"created_ms": @((long long)([[NSDate date] timeIntervalSince1970] * 1000))}, @"TribeIntentState.json");
    }
}

extern "C" void Avpn_consumeIntentFlags(void)
{
    @autoreleasepool {
        QVariantMap record = Avpn_currentIntent();
        const QString generation = record.value(QStringLiteral("generation")).toString();
        if (!generation.isEmpty()) {
            if (record.value(QStringLiteral("source")).toString() != QLatin1String("intent") ||
                !record.value(QStringLiteral("applied")).toBool() ||
                record.value(QStringLiteral("ack_generation")).toString() == generation) return;
            // requestAction rechecks the generation on the Qt thread before emit/ack.
            avpn::AvpnIntentBridge::instance()->requestAction(record);
            return;
        }
        // Upgrade-only migration: consume old flags once, never erase a new versioned command.
        NSUserDefaults *defaults = [[NSUserDefaults alloc] initWithSuiteName:@"group.hk.wellwon.tribe"];
        const bool pause = [defaults boolForKey:@"AvpnIntent/pauseRequested"];
        const bool resume = [defaults boolForKey:@"AvpnIntent/resumeRequested"];
        [defaults removeObjectForKey:@"AvpnIntent/pauseRequested"];
        [defaults removeObjectForKey:@"AvpnIntent/resumeRequested"];
        [defaults removeObjectForKey:@"AvpnIntent/lastActionAt"];
        [defaults release];
        // A legacy flag has neither generation nor reliable age: it cannot authorize a new start.
        // Reconcile the real OS tunnel instead; never replay an old resume across an upgrade.
        if (pause || resume) Avpn_recordLifecycle(QStringLiteral("legacy_intent_discarded"));
    }
}

void Avpn_recordLifecycle(const QString &event, const QVariantMap &fields)
{
    @autoreleasepool {
        SharedLock lock(@"TribeLifecycle.lock");
        if (lock.fd < 0) return;
        NSDictionary *previous = readRecord(@"TribeGUILifecycle.json");
        NSMutableArray *entries = [NSMutableArray arrayWithArray:[previous[@"entries"] isKindOfClass:[NSArray class]] ? previous[@"entries"] : @[]];
        const QByteArray json = QJsonDocument::fromVariant(fields).toJson(QJsonDocument::Compact);
        id values = [NSJSONSerialization JSONObjectWithData:[NSData dataWithBytes:json.constData() length:json.size()] options:0 error:nil];
        NSNumber *utcMs = @((long long)([[NSDate date] timeIntervalSince1970] * 1000));
        NSNumber *monotonicMs = @((long long)([NSProcessInfo processInfo].systemUptime * 1000));
        // AVPN (C8): подряд идущие одинаковые status_timeout схлопываются в одну запись со
        // счётчиком repeat и временем последнего повтора — кольцо из 128 записей не вымывается.
        NSDictionary *last = [entries.lastObject isKindOfClass:[NSDictionary class]] ? entries.lastObject : nil;
        NSString *lastEvent = [last[@"event"] isKindOfClass:[NSString class]] ? last[@"event"] : @"";
        if (last && avpn_ios::lifecycleCollapsible(std::string(lastEvent.UTF8String ?: ""), event.toStdString())) {
            NSMutableDictionary *merged = [NSMutableDictionary dictionaryWithDictionary:last];
            merged[@"repeat"] = @(MAX(1LL, [last[@"repeat"] longLongValue]) + 1);
            merged[@"last_utc_ms"] = utcMs;
            merged[@"last_monotonic_ms"] = monotonicMs;
            merged[@"last_fields"] = values ?: @{};
            entries[entries.count - 1] = merged;
        } else {
            [entries addObject:@{@"event": event.toNSString(), @"fields": values ?: @{}, @"source": @"gui",
                                 @"utc_ms": utcMs, @"monotonic_ms": monotonicMs,
                                 @"build": [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleVersion"] ?: @"unknown"}];
        }
        while (entries.count > 128) [entries removeObjectAtIndex:0];
        writeRecord(@{@"schema_version": @1, @"entries": entries}, @"TribeGUILifecycle.json");
    }
}
QString Avpn_lifecycleLogTail()
{
    @autoreleasepool {
        QString result;
        for (NSString *name in @[@"TribeGUILifecycle.json", @"TribeNELifecycle.json", @"TribeIntentLifecycle.json"]) {
            NSDictionary *record = readRecord(name);
            if (record.count == 0) continue;
            NSData *data = [NSJSONSerialization dataWithJSONObject:record options:0 error:nil];
            result += QString::fromNSString(name) + QLatin1Char('\n') + QString::fromUtf8((const char *)data.bytes, data.length) + QLatin1Char('\n');
        }
        return result;
    }
}
