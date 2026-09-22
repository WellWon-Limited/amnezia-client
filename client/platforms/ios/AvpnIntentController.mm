#import "AvpnIntentController.h"
#import <Foundation/Foundation.h>
#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>
#include <QJsonDocument>
#include <QJsonObject>
#include "core/serviceEngine/AvpnIntentBridge.h"

namespace {
NSURL *containerURL()
{
    return [[NSFileManager defaultManager] containerURLForSecurityApplicationGroupIdentifier:@"group.hk.wellwon.tribe"];
}
struct SharedLock {
    int fd = -1;
    SharedLock(NSString *name = @"TribeIntentState.lock") {
        NSURL *url = [containerURL() URLByAppendingPathComponent:name];
        if (url) fd = open(url.path.fileSystemRepresentation, O_CREAT | O_RDWR, 0600);
        if (fd >= 0 && flock(fd, LOCK_EX) != 0) { close(fd); fd = -1; }
    }
    ~SharedLock() { if (fd >= 0) { flock(fd, LOCK_UN); close(fd); } }
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
bool Avpn_performIfCurrent(const QString &generation, const std::function<void()> &action)
{
    @autoreleasepool {
        SharedLock lock;
        if (lock.fd < 0 || Avpn_currentIntentGeneration() != generation) return false;
        action();
        return true;
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
        [entries addObject:@{@"event": event.toNSString(), @"fields": values ?: @{}, @"source": @"gui",
                             @"utc_ms": @((long long)([[NSDate date] timeIntervalSince1970] * 1000)),
                             @"monotonic_ms": @((long long)([NSProcessInfo processInfo].systemUptime * 1000)),
                             @"build": [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleVersion"] ?: @"unknown"}];
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
