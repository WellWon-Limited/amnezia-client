// AVPN (build 142): pure checks of BackgroundTaskBook.h - the bookkeeping behind the connect attempt's and the seat
// releases' iOS background time. No Qt, no UIKit: the same BackgroundHold glue AvpnBackgroundGuard.mm runs, over a
// fake system task. Run: tests/run_ios_reliability_checks.sh.
#include "../BackgroundTaskBook.h"

#include <cstdio>
#include <string>
#include <vector>

static int g_failed = 0;
static int g_total = 0;
#define CHECK(cond, what)                                                                          \
    do {                                                                                           \
        ++g_total;                                                                                 \
        if (!(cond)) {                                                                             \
            ++g_failed;                                                                            \
            std::printf("FAIL: %s (line %d)\n", what, __LINE__);                                   \
        }                                                                                          \
    } while (0)

using namespace avpn_ios;

struct FakeSystem {
    bool refuse = false;
    int begins = 0;
    int ends = 0;
    bool running = false;
    std::function<void()> expiration;
    bool begin(std::function<void()> onSystemExpired)
    {
        if (refuse)
            return false;
        ++begins;
        running = true;
        expiration = std::move(onSystemExpired);
        return true;
    }
    void end()
    {
        if (running)
            ++ends;
        running = false;
    }
};

using Hold = BackgroundHold<FakeSystem>;

struct Rig {
    Hold hold;
    BackgroundTaskBook<Hold> book{hold};
    std::vector<std::string> log;
    bool foreground = false;
    double remaining = 27.9;
    Rig()
    {
        book.setLog([this](const std::string &l) { log.push_back(l); });
        book.setEnvironment([this] { return foreground; }, [this] { return remaining; });
    }
    FakeSystem &sys() { return hold.system(); }
    void expire() { sys().expiration(); }
};

int main()
{
    {
        Rig r; // attempt: begin once, end once, journal lines
        r.book.begin(BgTaskReason::Attempt, 0);
        r.book.begin(BgTaskReason::Attempt, 0);
        CHECK(r.sys().begins == 1 && r.sys().running, "attempt: begin is idempotent, one system task");
        CHECK(r.log.size() == 1 && r.log[0] == "bg_task begin reason=attempt remaining_s=27", "attempt: begin journal line");
        r.book.end(BgTaskReason::Attempt, 0, BgTaskEnd::Settled);
        r.book.end(BgTaskReason::Attempt, 0, BgTaskEnd::Settled);
        CHECK(r.sys().ends == 1 && !r.sys().running, "attempt: end ends the task once");
        CHECK(r.log.size() == 2 && r.log[1] == "bg_task end reason=attempt why=settled", "attempt: end journal line");
    }
    {
        Rig r; // the user stop names its reason; on screen the remaining time is "fg"
        r.remaining = 1e300;
        r.book.begin(BgTaskReason::Attempt, 0);
        r.book.end(BgTaskReason::Attempt, 0, BgTaskEnd::Stopped);
        CHECK(r.log.size() == 2 && r.log[0] == "bg_task begin reason=attempt remaining_s=fg", "foreground remaining text");
        CHECK(r.log[1] == "bg_task end reason=attempt why=stopped", "stopped why");
    }
    {
        Rig r; // releases: many at once, the reason ends with the last key
        r.book.begin(BgTaskReason::Release, 1);
        r.book.begin(BgTaskReason::Release, 2);
        r.book.begin(BgTaskReason::Release, 2);
        CHECK(r.book.openKeys(BgTaskReason::Release) == 2 && r.sys().begins == 1, "release: two keys, one task");
        CHECK(r.log.size() == 1, "release: one begin line for the reason, not per key");
        r.book.end(BgTaskReason::Release, 1, BgTaskEnd::Settled);
        CHECK(r.sys().running && r.book.holds(BgTaskReason::Release), "release: the other key still holds");
        r.book.end(BgTaskReason::Release, 99, BgTaskEnd::Settled);
        CHECK(r.sys().running, "release: ending an unknown key does nothing");
        r.book.end(BgTaskReason::Release, 2, BgTaskEnd::Settled);
        CHECK(!r.sys().running && r.sys().ends == 1 && !r.book.holds(BgTaskReason::Release), "release: the last key ends it");
    }
    {
        Rig r; // attempt + release share one system task; one reason leaving does not end the other
        r.book.begin(BgTaskReason::Attempt, 0);
        r.book.begin(BgTaskReason::Release, 5);
        CHECK(r.sys().begins == 1, "attempt + release: one system task");
        r.book.end(BgTaskReason::Attempt, 0, BgTaskEnd::Settled);
        CHECK(r.sys().running, "attempt ended: the release still holds the task");
        r.book.end(BgTaskReason::Release, 5, BgTaskEnd::Settled);
        CHECK(!r.sys().running && r.sys().ends == 1, "both ended: the task ends once");
    }
    {
        Rig r; // the restart guard's reason (other owner) is not disturbed
        CHECK(r.hold.acquire(BgReason::TunnelRestart, nullptr), "restart guard holds");
        r.book.begin(BgTaskReason::Attempt, 0);
        r.book.end(BgTaskReason::Attempt, 0, BgTaskEnd::Settled);
        CHECK(r.sys().running, "the restart guard keeps the task when the attempt ends");
    }
    {
        Rig r; // expiration: ends the task at once, closes every held reason with one line, latches
        r.book.begin(BgTaskReason::Attempt, 0);
        r.book.begin(BgTaskReason::Release, 7);
        r.expire();
        CHECK(!r.sys().running && r.sys().ends == 1, "expired: the system task is ended in the handler");
        CHECK(!r.book.holds(BgTaskReason::Attempt) && !r.book.holds(BgTaskReason::Release), "expired: every reason closed");
        int expiredLines = 0;
        for (const std::string &l : r.log)
            if (l.find("why=expired") != std::string::npos)
                ++expiredLines;
        CHECK(expiredLines == 2, "expired: one journal line per reason");
        r.book.end(BgTaskReason::Attempt, 0, BgTaskEnd::Settled);
        r.book.end(BgTaskReason::Release, 7, BgTaskEnd::Settled);
        CHECK(r.sys().ends == 1 && r.log.size() == 4, "after expiry a late end adds nothing (no second end)");
        r.book.begin(BgTaskReason::Release, 8); // still in the background: no begin/expire loop
        CHECK(r.sys().begins == 1 && !r.book.holds(BgTaskReason::Release) && r.book.latched(), "latched in the background");
        r.foreground = true;
        r.book.begin(BgTaskReason::Release, 9);
        CHECK(r.sys().begins == 2 && r.book.holds(BgTaskReason::Release) && !r.book.latched(), "on screen again: may ask again");
    }
    {
        Rig r; // iOS refuses: no hold, journalled, latched
        r.sys().refuse = true;
        r.book.begin(BgTaskReason::Attempt, 0);
        CHECK(!r.book.holds(BgTaskReason::Attempt) && r.book.latched(), "denied: nothing held");
        CHECK(r.log.size() == 1 && r.log[0] == "bg_task denied reason=attempt", "denied journal line");
        r.book.end(BgTaskReason::Attempt, 0, BgTaskEnd::Settled);
        CHECK(r.log.size() == 1, "denied: a later end adds nothing");
    }
    {
        Rig r; // after a settle the next attempt begins a new task
        r.book.begin(BgTaskReason::Attempt, 0);
        r.book.end(BgTaskReason::Attempt, 0, BgTaskEnd::Settled);
        r.book.begin(BgTaskReason::Attempt, 0);
        CHECK(r.sys().begins == 2 && r.sys().running, "a new attempt, a new task");
    }
    std::printf("%d checks, %d failed\n", g_total, g_failed);
    return g_failed == 0 ? 0 : 1;
}
