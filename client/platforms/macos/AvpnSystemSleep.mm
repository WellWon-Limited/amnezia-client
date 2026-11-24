// AVPN (macOS desktop app, owner's Mac 24.11.2026, cause F): the app's own observations of the system's sleep for the
// engine's one fact "the system is fully awake" (core/serviceEngine/SystemAwake.h):
//  - NSWorkspaceWillSleepNotification -> WillSleep: the system is going to sleep;
//  - NSWorkspaceDidWakeNotification -> DidWake: fully awake (a Power Nap dark wake does not post it);
//  - NSWorkspaceScreensDidWakeNotification -> ScreensDidWake: a screen is on (a dark wake has none);
//  - a press or a key delivered to the app (QEvent::MouseButtonPress / KeyPress / TouchBegin / TabletPress) ->
//    PersonInput: a person is at the Mac.
// The notifications are filed on NSWorkspace's own notification center (Technical Q&A QA1340: "You will not receive
// sleep/wake notifications if you file with the default notification center") and delivered on the main queue - the
// Qt GUI thread of the app. Installed once, from the engine's constructor (AvpnEngineQml, Q_OS_MACOS && !MACOS_NE);
// the sink guards the engine's lifetime itself. Nothing here acts on the tunnel.

#import <AppKit/AppKit.h>

#include <QCoreApplication>
#include <QEvent>
#include <QObject>

#include <functional>

#include "core/serviceEngine/SystemAwake.h"

namespace {

std::function<void(avpn::SleepSignal)> &sleepSink()
{
    static std::function<void(avpn::SleepSignal)> sink;
    return sink;
}

void tell(avpn::SleepSignal s)
{
    if (sleepSink())
        sleepSink()(s);
}

// A person's input in any window of the app (an application-wide filter sees every event before its receiver; it
// never consumes one). The engine ignores it while the system is awake (SystemAwake: a proof of what is true).
class PersonInputFilter final : public QObject
{
public:
    using QObject::QObject;

protected:
    bool eventFilter(QObject *watched, QEvent *event) override
    {
        switch (event->type()) {
        case QEvent::MouseButtonPress:
        case QEvent::KeyPress:
        case QEvent::TouchBegin:
        case QEvent::TabletPress:
            tell(avpn::SleepSignal::PersonInput);
            break;
        default:
            break;
        }
        return QObject::eventFilter(watched, event);
    }
};

} // namespace

void AvpnSystemSleep_install(std::function<void(avpn::SleepSignal)> sink)
{
    static bool installed = false;
    sleepSink() = std::move(sink);
    if (installed)
        return;
    installed = true;

    NSNotificationCenter *center = [[NSWorkspace sharedWorkspace] notificationCenter];
    NSOperationQueue *main = [NSOperationQueue mainQueue];
    [center addObserverForName:NSWorkspaceWillSleepNotification object:nil queue:main
                    usingBlock:^(NSNotification *) { tell(avpn::SleepSignal::WillSleep); }];
    [center addObserverForName:NSWorkspaceDidWakeNotification object:nil queue:main
                    usingBlock:^(NSNotification *) { tell(avpn::SleepSignal::DidWake); }];
    [center addObserverForName:NSWorkspaceScreensDidWakeNotification object:nil queue:main
                    usingBlock:^(NSNotification *) { tell(avpn::SleepSignal::ScreensDidWake); }];

    if (QCoreApplication *app = QCoreApplication::instance())
        app->installEventFilter(new PersonInputFilter(app)); // owned by the application object
}
