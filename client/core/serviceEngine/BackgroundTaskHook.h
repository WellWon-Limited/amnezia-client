// client/core/serviceEngine/BackgroundTaskHook.h
//
// AVPN (build 142): the platform hook through which shared code asks for background execution time while a
// connect attempt runs and while a seat release is being resent (device log 13:22:02: the app froze mid-attempt).
// Only iOS implements it (platforms/ios/AvpnBackgroundGuard.mm over BackgroundTaskBook.h); on every other
// platform the calls are inline no-ops. No UIKit here. GUI thread only.
//   begin: idempotent per (reason, key); end: always paired (settled | stopped | expired is told by iOS itself).
// Attempt: key 0. Release: a fresh key per release from newKey().
#pragma once

#include <QtGlobal>
#include <functional>

#include <QString>

namespace avpn::bgtask {

enum class Reason { Attempt, Release };
enum class EndWhy { Settled, Stopped };

#ifdef Q_OS_IOS
void begin(Reason reason, quint64 key);
void end(Reason reason, quint64 key, EndWhy why);
// Where the "bg_task ..." lines go (the facade's journal); set once, from the GUI thread.
void setJournal(std::function<void(const QString &)> sink);
#else
inline void begin(Reason, quint64) {}
inline void end(Reason, quint64, EndWhy) {}
inline void setJournal(std::function<void(const QString &)>) {}
#endif

// A key for one pending release (never 0, which is the attempt's).
inline quint64 newKey()
{
    static quint64 next = 0;
    return ++next;
}

} // namespace avpn::bgtask
