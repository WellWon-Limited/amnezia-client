// AVPN (разбор 2026-09-23): см. AvpnBackgroundGuard.h.
// AVPN (iOS data watch, build 140): ownership by reason - the bookkeeping is BackgroundHoldBook.h (pure,
// tested); here only the UIKit task behind it.
#include "AvpnBackgroundGuard.h"

#import <UIKit/UIKit.h>

namespace {

struct UIKitBackgroundTask {
    UIBackgroundTaskIdentifier task = UIBackgroundTaskInvalid;

    bool begin(std::function<void()> onSystemExpired)
    {
        task = [[UIApplication sharedApplication]
            beginBackgroundTaskWithName:@"tribe.tunnel-restart"
                      expirationHandler:^{
                          // The task must be ended before this handler returns, or iOS kills the
                          // app for overstaying; the owners' callbacks run after that
                          // (BackgroundHold::onSystemExpired).
                          if (onSystemExpired)
                              onSystemExpired();
                      }];
        return task != UIBackgroundTaskInvalid;
    }

    void end()
    {
        if (task == UIBackgroundTaskInvalid)
            return;
        const UIBackgroundTaskIdentifier t = task;
        task = UIBackgroundTaskInvalid;
        [[UIApplication sharedApplication] endBackgroundTask:t];
    }
};

avpn_ios::BackgroundHold<UIKitBackgroundTask> &hold()
{
    static avpn_ios::BackgroundHold<UIKitBackgroundTask> h;
    return h;
}

} // namespace

bool AvpnBackgroundGuard_acquire(avpn_ios::BgReason reason, std::function<void()> onExpired)
{
    return hold().acquire(reason, std::move(onExpired));
}

void AvpnBackgroundGuard_release(avpn_ios::BgReason reason)
{
    hold().release(reason);
}

bool AvpnBackgroundGuard_begin(std::function<void()> onExpired)
{
    return AvpnBackgroundGuard_acquire(avpn_ios::BgReason::TunnelRestart, std::move(onExpired));
}

void AvpnBackgroundGuard_end()
{
    AvpnBackgroundGuard_release(avpn_ios::BgReason::TunnelRestart);
}
