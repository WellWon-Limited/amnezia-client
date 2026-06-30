#import "QtAppDelegate.h"
#import "ios_controller.h"
#import "AvpnPushController.h" // AVPN (Task 9): APNs регистрация + входящие пуши
#import "AvpnDiagnostics.h"    // AVPN: авто-сбор диагностики вылетов (MetricKit) → POST /v1/diag/crash

#include <QFile>

#import <Foundation/Foundation.h>

// AVPN (Task 13): C-вход моста диплинка активации (реализован в AvpnDeepLinkBridge.cpp).
extern "C" void AvpnDeepLink_handleUrl(const char *url);

// AVPN (Task E): C-вход консьюмера «намерений» App Intent авто-паузы — читает App Group и эмитит
// pause/resume в движок (реализован в AvpnIntentController.mm).
extern "C" void Avpn_consumeIntentFlags(void);

@implementation QIOSApplicationDelegate (AmneziaVPNDelegate)
#if !MACOS_NE
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions
{
    [application setMinimumBackgroundFetchInterval: UIApplicationBackgroundFetchIntervalMinimum];
    // Override point for customization after application launch.
    NSLog(@"Application didFinishLaunchingWithOptions");

    // AVPN: подписка на MetricKit — если в ПРОШЛЫЙ запуск был вылет/зависание, iOS отдаст его
    // диагностику сейчас, и мы зашлём её на бэк (POST /v1/diag/crash). Идемпотентно, без UI.
    AvpnDiagnostics_install();

    // AVPN (Task 9): НЕ показываем промпт на холодном старте — разрешение спрашиваем контекстно,
    // после первого успешного коннекта (AvpnEngineQml::onConnectionStateChanged → AvpnPush.requestAuthorization).
    // Здесь только ТИХО обновляем device token, если право уже выдано (APNs его периодически ротирует).
    dispatch_async(dispatch_get_main_queue(), ^{
        AvpnPush_registerIfAuthorized();
    });

    // AVPN (Task 13): холодный старт по диплинку активации (tribevpn://activate?token=...).
    NSURL *launchUrl = launchOptions[UIApplicationLaunchOptionsURLKey];
    if (launchUrl && !launchUrl.fileURL)
        AvpnDeepLink_handleUrl(launchUrl.absoluteString.UTF8String);

    return YES;
}

// MARK: - AVPN (Task 9): APNs remote notification delegate callbacks

- (void)application:(UIApplication *)application
    didRegisterForRemoteNotificationsWithDeviceToken:(NSData *)deviceToken
{
    AvpnPush_onDeviceToken((const unsigned char *)deviceToken.bytes, deviceToken.length);
}

- (void)application:(UIApplication *)application
    didFailToRegisterForRemoteNotificationsWithError:(NSError *)error
{
    AvpnPush_onRegisterFailed(error.localizedDescription.UTF8String);
}

// Тихий/фоновый пуш (content-available) или обычный, доставленный в фоне.
- (void)application:(UIApplication *)application
    didReceiveRemoteNotification:(NSDictionary *)userInfo
          fetchCompletionHandler:(void (^)(UIBackgroundFetchResult))completionHandler
{
    NSData *json = [NSJSONSerialization dataWithJSONObject:userInfo options:0 error:nil];
    if (json) {
        NSString *str = [[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding];
        AvpnPush_onRemoteNotification(str.UTF8String);
    }
    completionHandler(UIBackgroundFetchResultNewData);
}

- (void)applicationDidEnterBackground:(UIApplication *)application
{
    // Use this method to release shared resources, save user data, invalidate timers, and store enough application state information to restore your application to its current state in case it is terminated later.
    // If your application supports background execution, this method is called instead of applicationWillTerminate: when the user quits.
    NSLog(@"In the background");
}

- (void)applicationWillEnterForeground:(UIApplication *)application
{
    // Called as part of the transition from the background to the inactive state; here you can undo many of the changes made on entering the background.
    NSLog(@"In the foreground");
}

// AVPN (Task E): согласовать движок с «намерением» фонового App Intent авто-паузы. Интент уже
// реально опустил/поднял туннель и записал флаг в App Group; здесь, когда Qt event loop снова
// крутится, читаем флаги и зовём pauseForShopping()/resumeFromPause() через AvpnIntentBridge.
// didBecomeActive ловит и foreground-возврат, и холодный старт (после didFinishLaunching).
- (void)applicationDidBecomeActive:(UIApplication *)application
{
    Avpn_consumeIntentFlags();
}

-(void)application:(UIApplication *)application performFetchWithCompletionHandler:(void (^)(UIBackgroundFetchResult))completionHandler {
    // We will add content here soon.
    NSLog(@"In the completionHandler");
}

- (BOOL)application:(UIApplication *)app
            openURL:(NSURL *)url
            options:(NSDictionary<UIApplicationOpenURLOptionsKey, id> *)options {
    // AVPN (Task 13): обратный диплинк активации (tribevpn://activate?token=...) через openURL.
    if (!url.fileURL && url.absoluteString.length > 0) {
        AvpnDeepLink_handleUrl(url.absoluteString.UTF8String);
        return YES;
    }
    if (url.fileURL) {
        QString filePath(url.path.UTF8String);
        if (filePath.isEmpty()) return NO;

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
            NSLog(@"Application openURL: %@", url);

            if (filePath.contains("backup")) {
                IosController::Instance()->importBackupFromOutside(filePath);
            } else {
                QFile file(filePath);
                bool isOpenFile = file.open(QIODevice::ReadOnly);
                QByteArray data = file.readAll();

                IosController::Instance()->importConfigFromOutside(QString(data));
            }
        });

        return YES;
    }
    return NO;
}

// AVPN (Task 13): Universal Links — https://tribevpn.com/activate?token=... после покупки.
- (BOOL)application:(UIApplication *)application
    continueUserActivity:(NSUserActivity *)userActivity
      restorationHandler:(void (^)(NSArray<id<UIUserActivityRestoring>> *))restorationHandler {
    if ([userActivity.activityType isEqualToString:NSUserActivityTypeBrowsingWeb]
        && userActivity.webpageURL) {
        AvpnDeepLink_handleUrl(userActivity.webpageURL.absoluteString.UTF8String);
        return YES;
    }
    return NO;
}
#endif
@end
