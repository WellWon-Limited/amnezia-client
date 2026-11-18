#import "TribeJournalIos.h"

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

namespace {
NSString *const kAppGroup = @"group.hk.wellwon.tribe";
UIBackgroundTaskIdentifier g_task = UIBackgroundTaskInvalid;
}

QString TribeJournalIos_appGroupDir()
{
    NSURL *url = [[NSFileManager defaultManager] containerURLForSecurityApplicationGroupIdentifier:kAppGroup];
    return url ? QString::fromNSString(url.path) : QString();
}

void TribeJournalIos_setNativeLogging(bool on)
{
    NSUserDefaults *defaults = [[NSUserDefaults alloc] initWithSuiteName:kAppGroup];
    [defaults setBool:on forKey:@"IsLoggingEnabled"];
}

bool TribeJournalIos_isTestFlight()
{
    // A sandbox receipt alone also marks a development or ad-hoc install (device test of 142: journal_on said
    // testflight:true on a build run from Xcode). Those carry their provisioning profile in the bundle; a TestFlight
    // (and App Store) install never does.
    NSURL *receipt = [[NSBundle mainBundle] appStoreReceiptURL];
    const bool sandbox = receipt && [[receipt lastPathComponent] isEqualToString:@"sandboxReceipt"];
    const bool provisioned = [[NSBundle mainBundle] pathForResource:@"embedded" ofType:@"mobileprovision"] != nil;
    return sandbox && !provisioned;
}

bool TribeJournalIos_beginBackground(std::function<void()> onExpired)
{
    if (g_task != UIBackgroundTaskInvalid)
        return true;
    auto cb = std::make_shared<std::function<void()>>(std::move(onExpired));
    g_task = [[UIApplication sharedApplication] beginBackgroundTaskWithName:@"TribeJournalUpload"
                                                          expirationHandler:^{
        TribeJournalIos_endBackground();
        if (*cb)
            (*cb)();
    }];
    return g_task != UIBackgroundTaskInvalid;
}

void TribeJournalIos_endBackground()
{
    if (g_task == UIBackgroundTaskInvalid)
        return;
    const UIBackgroundTaskIdentifier task = g_task;
    g_task = UIBackgroundTaskInvalid;
    [[UIApplication sharedApplication] endBackgroundTask:task];
}
