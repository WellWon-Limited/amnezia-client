// AVPN (разбор 2026-09-23): см. AvpnBackgroundGuard.h.
#include "AvpnBackgroundGuard.h"

#import <UIKit/UIKit.h>

static UIBackgroundTaskIdentifier s_task = UIBackgroundTaskInvalid;
static std::function<void()> s_onExpired;

void AvpnBackgroundGuard_end()
{
    if (s_task == UIBackgroundTaskInvalid)
        return;
    const UIBackgroundTaskIdentifier task = s_task;
    s_task = UIBackgroundTaskInvalid;
    s_onExpired = nullptr;
    [[UIApplication sharedApplication] endBackgroundTask:task];
}

bool AvpnBackgroundGuard_begin(std::function<void()> onExpired)
{
    if (s_task != UIBackgroundTaskInvalid)
        return true;
    s_onExpired = std::move(onExpired);
    s_task = [[UIApplication sharedApplication]
        beginBackgroundTaskWithName:@"tribe.tunnel-restart"
                  expirationHandler:^{
                      // Обязательно завершить задачу до выхода из обработчика, иначе iOS убьёт
                      // приложение за просроченное удержание. Колбэк — после завершения.
                      std::function<void()> cb = s_onExpired;
                      AvpnBackgroundGuard_end();
                      if (cb)
                          cb();
                  }];
    if (s_task == UIBackgroundTaskInvalid) {
        s_onExpired = nullptr;
        return false;
    }
    return true;
}
