// client/platforms/ios/BackgroundHoldBook.h
//
// AVPN (iOS data watch, build 141; design §0a item 9 / §5.5 step 1): ownership of the ONE iOS background
// task (AvpnBackgroundGuard) by reason. Before 141 the task had a single owner - the tunnel restart guard
// (RestartGuard.h). Now the On-Demand arming after leaving the screen also needs background time; the two
// must not take it from each other:
//   * the system task runs while at least one reason holds it;
//   * releasing one reason does not end the task another reason still holds;
//   * the system ending the task (expiry) ends it for every reason, and each owner is told.
// With only the restart reason in use the behaviour is the one of build 139 call for call (test
// IosDataWatchTests.cpp: replay against a copy of the 139 guard).
//
// Pure: no UIKit. BackgroundHold<System> is the exact glue AvpnBackgroundGuard.mm runs, over a System with
//   bool begin(std::function<void()> onSystemExpired);  // false = iOS refused (no time left)
//   void end();
// so the test drives the same code with a fake system.
#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <utility>
#include <vector>

namespace avpn_ios {

// ConnectAttempt / SeatRelease (build 142): the connect attempt's own background time and a seat release
// that is being resent; they are driven by BackgroundTaskBook.h, never directly.
enum class BgReason : unsigned { TunnelRestart = 0, OnDemandArm = 1, ConnectAttempt = 2, SeatRelease = 3 };
constexpr unsigned kBgReasonCount = 4;

inline unsigned bgReasonBit(BgReason r) { return 1u << unsigned(r); }

class BackgroundHoldBook {
public:
    enum class Step { None, BeginTask, EndTask };

    // A reason asks for background time. BeginTask: nobody held it - the caller starts the task now and
    // calls taskRefused() if the system says no. None: the task already runs; the reason is recorded.
    Step acquire(BgReason r)
    {
        const bool first = m_reasons == 0;
        m_reasons |= bgReasonBit(r);
        return first ? Step::BeginTask : Step::None;
    }
    // The system refused the task just asked for: no reason holds anything.
    void taskRefused() { m_reasons = 0; }
    // EndTask only when the last reason leaves.
    Step release(BgReason r)
    {
        const unsigned bit = bgReasonBit(r);
        if (!(m_reasons & bit))
            return Step::None;
        m_reasons &= ~bit;
        return m_reasons == 0 ? Step::EndTask : Step::None;
    }
    // The system ended the task: it is over for every reason.
    void expire() { m_reasons = 0; }
    bool holds(BgReason r) const { return (m_reasons & bgReasonBit(r)) != 0; }
    // The task runs exactly while a reason holds it.
    bool taskRunning() const { return m_reasons != 0; }
    unsigned reasons() const { return m_reasons; }

private:
    unsigned m_reasons = 0;
};

template <class System>
class BackgroundHold {
public:
    explicit BackgroundHold(System sys = System()) : m_sys(std::move(sys)) {}

    // true = the reason holds background time (now or already). onExpired runs when the system ends the
    // task (after it is ended), once per reason; a second acquire of a reason that already holds keeps its
    // first callback (as the 139 guard did).
    bool acquire(BgReason r, std::function<void()> onExpired)
    {
        const bool already = m_book.holds(r);
        const BackgroundHoldBook::Step step = m_book.acquire(r);
        if (!already)
            m_callbacks[unsigned(r)] = std::move(onExpired);
        if (step != BackgroundHoldBook::Step::BeginTask)
            return true;
        if (!m_sys.begin([this] { onSystemExpired(); })) {
            m_book.taskRefused();
            for (auto &cb : m_callbacks)
                cb = nullptr;
            return false;
        }
        return true;
    }

    void release(BgReason r)
    {
        m_callbacks[unsigned(r)] = nullptr;
        if (m_book.release(r) == BackgroundHoldBook::Step::EndTask)
            m_sys.end();
    }

    // The system's expiration handler: end the task before leaving (iOS kills an app that overstays),
    // then tell every owner that still held it (a reason has a callback exactly while it holds).
    void onSystemExpired()
    {
        m_book.expire();
        std::array<std::function<void()>, kBgReasonCount> cbs;
        for (unsigned i = 0; i < kBgReasonCount; ++i)
            cbs[i] = std::exchange(m_callbacks[i], nullptr);
        m_sys.end();
        for (auto &cb : cbs)
            if (cb)
                cb();
    }

    bool holds(BgReason r) const { return m_book.holds(r); }
    bool taskRunning() const { return m_book.taskRunning(); }
    System &system() { return m_sys; }

private:
    System m_sys;
    BackgroundHoldBook m_book;
    std::array<std::function<void()>, kBgReasonCount> m_callbacks;
};

} // namespace avpn_ios
