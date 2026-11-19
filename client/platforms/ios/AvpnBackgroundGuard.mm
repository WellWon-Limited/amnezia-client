// AVPN (разбор 2026-09-23): см. AvpnBackgroundGuard.h.
// AVPN (iOS data watch, build 141): ownership by reason - the bookkeeping is BackgroundHoldBook.h (pure,
// tested); here only the UIKit task behind it.
#include "AvpnBackgroundGuard.h"
#include "BackgroundTaskBook.h"
#include "core/serviceEngine/BackgroundTaskHook.h"

#import <UIKit/UIKit.h>

namespace {

struct UIKitBackgroundTask {
    UIBackgroundTaskIdentifier task = UIBackgroundTaskInvalid;

    bool begin(std::function<void()> onSystemExpired)
    {
        task = [[UIApplication sharedApplication]
            beginBackgroundTaskWithName:@"tribe.background-hold"
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

using Hold = avpn_ios::BackgroundHold<UIKitBackgroundTask>;

// AVPN (build 142): the connect attempt's and the seat releases' keys over the same one task.
avpn_ios::BackgroundTaskBook<Hold> &taskBook()
{
    static avpn_ios::BackgroundTaskBook<Hold> *b = [] {
        auto *book = new avpn_ios::BackgroundTaskBook<Hold>(hold());
        book->setEnvironment(
            [] { return [UIApplication sharedApplication].applicationState == UIApplicationStateActive; },
            [] { return double([UIApplication sharedApplication].backgroundTimeRemaining); });
        return book;
    }();
    return *b;
}

std::function<void(const QString &)> &journalSink()
{
    static std::function<void(const QString &)> s;
    return s;
}

avpn_ios::BgTaskReason mapReason(avpn::bgtask::Reason r)
{
    return r == avpn::bgtask::Reason::Attempt ? avpn_ios::BgTaskReason::Attempt : avpn_ios::BgTaskReason::Release;
}

} // namespace

namespace avpn::bgtask {

void setJournal(std::function<void(const QString &)> sink)
{
    journalSink() = std::move(sink);
    taskBook().setLog([](const std::string &line) {
        if (journalSink())
            journalSink()(QString::fromStdString(line));
    });
}

void begin(Reason reason, quint64 key)
{
    taskBook().begin(mapReason(reason), key);
}

void end(Reason reason, quint64 key, EndWhy why)
{
    taskBook().end(mapReason(reason), key,
                   why == EndWhy::Stopped ? avpn_ios::BgTaskEnd::Stopped : avpn_ios::BgTaskEnd::Settled);
}

} // namespace avpn::bgtask

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
