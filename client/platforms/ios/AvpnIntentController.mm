// AVPN (Task E) — реализация iOS-консьюмера «намерений» App Intent авто-паузы. См. AvpnIntentController.h.
#import "AvpnIntentController.h"

#import <Foundation/Foundation.h>

#include "core/serviceEngine/AvpnIntentBridge.h"

// App Group — совпадает с AvpnAppIntents.swift / Log.swift / main.entitlements.
static NSString *const kAvpnAppGroupID = @"group.hk.wellwon.zanaves";

// Ключи, которые ПИШЕТ App Intent (AvpnAppIntents.swift, enum AvpnIntentBridgeKey). Читаем их здесь.
static NSString *const kAvpnIntentPauseRequested = @"AvpnIntent/pauseRequested";
static NSString *const kAvpnIntentResumeRequested = @"AvpnIntent/resumeRequested";
static NSString *const kAvpnIntentLastActionAt = @"AvpnIntent/lastActionAt";

// Читает флаги App Group, эмитит сигналы моста и сбрасывает флаги (идемпотентно при повторном foreground).
// Зовётся из QtAppDelegate.mm applicationDidBecomeActive на main-потоке.
extern "C" void Avpn_consumeIntentFlags(void)
{
    NSUserDefaults *defaults = [[NSUserDefaults alloc] initWithSuiteName:kAvpnAppGroupID];
    if (!defaults) {
        return;
    }

    const BOOL pause = [defaults boolForKey:kAvpnIntentPauseRequested];
    const BOOL resume = [defaults boolForKey:kAvpnIntentResumeRequested];
    if (!pause && !resume) {
        return; // нет необработанного намерения
    }

    auto *bridge = avpn::AvpnIntentBridge::instance();
    if (!bridge) {
        return;
    }

    // pause и resume взаимоисключающи (avpnPostBridge пишет !pause в resume). Если вдруг оба true —
    // приоритет paused: интент-пауза опустила туннель, движок должен это отразить, а не «включить».
    if (pause) {
        NSLog(@"[AVPN intent] consume: pauseRequested → pauseForShopping");
        bridge->requestPause();
    } else if (resume) {
        NSLog(@"[AVPN intent] consume: resumeRequested → resumeFromPause");
        bridge->requestResume();
    }

    // Сбросить флаги, чтобы следующий foreground не повторил действие.
    [defaults setBool:NO forKey:kAvpnIntentPauseRequested];
    [defaults setBool:NO forKey:kAvpnIntentResumeRequested];
    [defaults removeObjectForKey:kAvpnIntentLastActionAt];
    [defaults synchronize];
}
