// AVPN (Task 9) — реализация iOS APNs контроллера. См. AvpnPushController.h.
#import "AvpnPushController.h"

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <UserNotifications/UserNotifications.h>

#include <QString>

#include "core/serviceEngine/AvpnPushBridge.h"

// APNs-окружение токена для регистрации на бэке: Debug-сборка → sandbox; иначе по чеку App Store —
// TestFlight (sandboxReceipt) → sandbox, релиз App Store → production. Бэк маршрутит per-device
// (api.sandbox.push.apple.com vs api.push.apple.com), ключ один. Совпадает с aps-environment провижина.
static NSString *avpnPushEnvironment(void)
{
#if defined(DEBUG) || defined(QT_DEBUG)
    return @"sandbox";
#else
    NSURL *receiptURL = [[NSBundle mainBundle] appStoreReceiptURL];
    if ([[receiptURL lastPathComponent] isEqualToString:@"sandboxReceipt"])
        return @"sandbox"; // TestFlight
    return @"production";  // App Store
#endif
}

// Регистратор для AvpnPushBridge.requestAuthorization() (QML/движок может инициировать запрос).
static void avpnPushAuthRequesterTrampoline()
{
    AvpnPush_requestAuthorization();
}

// Сброс системного бейджа иконки — мост зовёт при markAllRead() (пользователь открыл центр уведомлений).
static void avpnPushBadgeClearerTrampoline()
{
    dispatch_async(dispatch_get_main_queue(), ^{
        if (@available(iOS 17.0, *)) {
            [[UNUserNotificationCenter currentNotificationCenter] setBadgeCount:0 withCompletionHandler:nil];
        } else {
            [UIApplication sharedApplication].applicationIconBadgeNumber = 0;
        }
    });
}

// Привязываем C-регистраторы к мосту один раз (вызывается из QtAppDelegate при старте).
__attribute__((constructor)) static void avpnPushInstallRequester()
{
    // ВНИМАНИЕ: конструктор может выполниться до создания моста — поэтому фактическую привязку
    // делает QtAppDelegate через AvpnPush_requestAuthorization путь. Здесь оставляем как страховку.
    if (auto *bridge = avpn::AvpnPushBridge::instance()) {
        bridge->setAuthorizationRequester(&avpnPushAuthRequesterTrampoline);
        bridge->setBadgeClearer(&avpnPushBadgeClearerTrampoline);
    }
}

// MARK: - Authorization + registration

void AvpnPush_requestAuthorization(void)
{
    UNUserNotificationCenter *center = [UNUserNotificationCenter currentNotificationCenter];
    UNAuthorizationOptions opts =
        UNAuthorizationOptionAlert | UNAuthorizationOptionSound | UNAuthorizationOptionBadge;

    [center requestAuthorizationWithOptions:opts
                         completionHandler:^(BOOL granted, NSError *_Nullable error) {
        if (auto *bridge = avpn::AvpnPushBridge::instance()) {
            bridge->setAuthStatus(granted ? QStringLiteral("granted") : QStringLiteral("denied"));
        }
        if (error) {
            NSLog(@"[AVPN push] requestAuthorization error: %@", error);
        }
        if (!granted) {
            NSLog(@"[AVPN push] notifications NOT granted");
            return;
        }
        // registerForRemoteNotifications ДОЛЖЕН вызываться на main thread.
        dispatch_async(dispatch_get_main_queue(), ^{
            [[UIApplication sharedApplication] registerForRemoteNotifications];
        });
    }];
}

void AvpnPush_registerIfAuthorized(void)
{
    // На холодном старте НЕ показываем промпт (это делает первый коннект). Но если право уже выдано —
    // тихо обновляем device token: APNs периодически его ротирует, а бэк деактивирует мёртвые.
    UNUserNotificationCenter *center = [UNUserNotificationCenter currentNotificationCenter];
    [center getNotificationSettingsWithCompletionHandler:^(UNNotificationSettings *settings) {
        if (settings.authorizationStatus == UNAuthorizationStatusAuthorized
            || settings.authorizationStatus == UNAuthorizationStatusProvisional) {
            if (auto *bridge = avpn::AvpnPushBridge::instance())
                bridge->setAuthStatus(QStringLiteral("granted"));
            dispatch_async(dispatch_get_main_queue(), ^{
                [[UIApplication sharedApplication] registerForRemoteNotifications];
            });
        }
    }];
}

// MARK: - Device token → backend + bridge

static NSString *avpnHexFromTokenBytes(const unsigned char *bytes, unsigned long length)
{
    NSMutableString *hex = [NSMutableString stringWithCapacity:length * 2];
    for (unsigned long i = 0; i < length; i++) {
        [hex appendFormat:@"%02x", bytes[i]];
    }
    return hex;
}

void AvpnPush_onDeviceToken(const unsigned char *bytes, unsigned long length)
{
    if (!bytes || length == 0) {
        return;
    }
    NSString *hex = avpnHexFromTokenBytes(bytes, length);
    NSString *env = avpnPushEnvironment();
    NSLog(@"[AVPN push] APNs device token (%@): %@", env, hex);

    // Отправку на бэк делает движок (AvpnEngineQml::registerPushToken) — у него subscription_token
    // для Bearer-авторизации (POST /v1/devices/push-token). Натив лишь кладёт окружение + токен в мост;
    // мост эмитит deviceTokenReady → движок шлёт авторизованно. ВАЖНО: окружение ПЕРЕД токеном
    // (обе вызова FIFO-маршалятся в Qt-поток → env применится до эмита deviceTokenReady).
    if (auto *bridge = avpn::AvpnPushBridge::instance()) {
        bridge->setPushEnvironment(QString::fromNSString(env));
        bridge->setDeviceToken(QString::fromNSString(hex), QStringLiteral("ios"));
    }
}

void AvpnPush_onRegisterFailed(const char *reason)
{
    NSLog(@"[AVPN push] registerForRemoteNotifications failed: %s", reason ? reason : "(nil)");
    // Не меняем authStatus — право могло быть выдано, просто APNs недоступен (симулятор/сеть).
}

// MARK: - Incoming push → bridge

void AvpnPush_onRemoteNotification(const char *userInfoJson)
{
    if (!userInfoJson) {
        return;
    }
    NSData *jsonData = [[NSString stringWithUTF8String:userInfoJson]
        dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *userInfo = nil;
    if (jsonData) {
        userInfo = [NSJSONSerialization JSONObjectWithData:jsonData options:0 error:nil];
    }

    // Стандартный APNs payload: { "aps": { "alert": { "title": ..., "body": ... } } }.
    NSString *title = @"Tribe";
    NSString *body = @"";
    NSDictionary *aps = [userInfo isKindOfClass:[NSDictionary class]] ? userInfo[@"aps"] : nil;
    id alert = [aps isKindOfClass:[NSDictionary class]] ? aps[@"alert"] : nil;
    if ([alert isKindOfClass:[NSDictionary class]]) {
        if (alert[@"title"]) title = alert[@"title"];
        if (alert[@"body"]) body = alert[@"body"];
    } else if ([alert isKindOfClass:[NSString class]]) {
        body = alert;
    }

    if (auto *bridge = avpn::AvpnPushBridge::instance()) {
        bridge->onRemoteNotification(QString::fromNSString(title), QString::fromNSString(body));
    }
}
