// client/platforms/ios/BackgroundTaskBook.h
//
// AVPN (build 142, device log 13:22:02 - 13:23:18): a person taps Connect and at once leaves for another app.
// The connect attempt lives in the APP (it walks servers, runs the data check through the tunnel, decides), and
// iOS froze the app about 11 s later: the tunnel was up, the data check had just started, and the verdict came
// 64 s later, on return. So while an attempt runs, and while a seat release is being resent, the app holds
// background time (the one UIKit task of AvpnBackgroundGuard, BackgroundHoldBook.h) - about 30 s from iOS.
//
// This is the bookkeeping behind the platform hook of serviceEngine/BackgroundTaskHook.h, pure (no UIKit):
//   * a reason (attempt | release) holds the task while at least one key of it is open; the attempt uses one
//     key (begin twice = once), every pending release its own key (many releases at once is normal);
//   * begin is idempotent per (reason, key); end of a key that is not open does nothing; the last key of a
//     reason lets that reason go, the last reason lets the task go (BackgroundHold does the sharing);
//   * the system's expiration ends the task at once (BackgroundHold::onSystemExpired) and every reason that
//     was held is closed here with one journal line; nothing is retried in that background (latch) until the
//     app is on screen again - no begin/expire loop;
//   * journal: "bg_task begin reason=attempt|release remaining_s=<n|fg>", "bg_task end reason=... why=
//     settled|stopped|expired", "bg_task denied reason=..." (iOS refused).
// Not thread safe: the GUI thread (Qt's main thread on iOS) only, like AvpnBackgroundGuard.
// Hold = avpn_ios::BackgroundHold<System> (acquire(BgReason, std::function<void()>) -> bool, release(BgReason)).
#pragma once

#include <cstdint>
#include <functional>
#include <set>
#include <string>
#include <utility>

#include "BackgroundHoldBook.h"

namespace avpn_ios {

enum class BgTaskReason : unsigned { Attempt = 0, Release = 1 };
enum class BgTaskEnd { Settled, Stopped, Expired };

inline const char *bgTaskReasonName(BgTaskReason r) { return r == BgTaskReason::Attempt ? "attempt" : "release"; }
inline const char *bgTaskEndName(BgTaskEnd w)
{
    return w == BgTaskEnd::Settled ? "settled" : w == BgTaskEnd::Stopped ? "stopped" : "expired";
}
inline BgReason bgTaskHoldReason(BgTaskReason r)
{
    return r == BgTaskReason::Attempt ? BgReason::ConnectAttempt : BgReason::SeatRelease;
}

template <class Hold>
class BackgroundTaskBook {
public:
    explicit BackgroundTaskBook(Hold &hold) : m_hold(hold) {}

    // Journal sink, "is the app on screen", iOS's remaining background seconds (large = on screen).
    void setLog(std::function<void(const std::string &)> log) { m_log = std::move(log); }
    void setEnvironment(std::function<bool()> foreground, std::function<double()> remainingSeconds)
    {
        m_foreground = std::move(foreground);
        m_remaining = std::move(remainingSeconds);
    }

    void begin(BgTaskReason r, std::uint64_t key)
    {
        std::set<std::uint64_t> &keys = m_keys[unsigned(r)];
        if (keys.count(key))
            return; // idempotent per key
        if (m_latched) {
            if (m_foreground && m_foreground())
                m_latched = false; // on screen again: the next background may ask again
            else
                return; // iOS already took the time away (or refused) in this background
        }
        const bool first = keys.empty();
        keys.insert(key);
        if (!first)
            return;
        const bool ok = m_hold.acquire(bgTaskHoldReason(r), [this, r] { onExpired(r); });
        if (!ok) {
            keys.clear();
            m_latched = true;
            log(std::string("bg_task denied reason=") + bgTaskReasonName(r));
            return;
        }
        log(std::string("bg_task begin reason=") + bgTaskReasonName(r) + " remaining_s=" + remainingText());
    }

    void end(BgTaskReason r, std::uint64_t key, BgTaskEnd why)
    {
        std::set<std::uint64_t> &keys = m_keys[unsigned(r)];
        if (keys.erase(key) == 0 || !keys.empty())
            return;
        m_hold.release(bgTaskHoldReason(r));
        log(std::string("bg_task end reason=") + bgTaskReasonName(r) + " why=" + bgTaskEndName(why));
    }

    bool holds(BgTaskReason r) const { return !m_keys[unsigned(r)].empty(); }
    std::size_t openKeys(BgTaskReason r) const { return m_keys[unsigned(r)].size(); }
    bool latched() const { return m_latched; }

private:
    // BackgroundHold calls this after it has ended the system task (the handler must not outlive it).
    void onExpired(BgTaskReason r)
    {
        std::set<std::uint64_t> &keys = m_keys[unsigned(r)];
        if (keys.empty())
            return;
        keys.clear();
        m_latched = true;
        log(std::string("bg_task end reason=") + bgTaskReasonName(r) + " why=expired");
    }
    std::string remainingText() const
    {
        const double s = m_remaining ? m_remaining() : 1e9;
        return s >= 1e6 ? std::string("fg") : std::to_string(s < 0 ? 0 : int(s));
    }
    void log(const std::string &line) const
    {
        if (m_log)
            m_log(line);
    }

    Hold &m_hold;
    std::set<std::uint64_t> m_keys[2];
    bool m_latched = false;
    std::function<void(const std::string &)> m_log;
    std::function<bool()> m_foreground;
    std::function<double()> m_remaining;
};

} // namespace avpn_ios
