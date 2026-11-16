// AVPN (iOS data watch, build 141): pure checks of the app's iOS half, no Qt and no UIKit.
//   BackgroundHoldBook.h - the ONE iOS background task owned by reason (tunnel restart, On-Demand
//                          arming). With only the restart reason in use it must behave as the guard of
//                          build 139 call for call: replayed here against a copy of that guard.
//   IosBackgroundArm.h   - when the On-Demand arming may hold background time and when it lets go.
// Run: tests/run_ios_reliability_checks.sh.
#include "../BackgroundHoldBook.h"
#include "../IosBackgroundArm.h"

#include <cstdio>
#include <cstring>
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

// What the system saw and what the owners were told, in order.
static std::vector<std::string> g_log;

// The fake of UIKit's background task: begin may be refused; the test fires the expiration itself.
struct FakeSystem {
    bool refuse = false;
    bool running = false;
    std::function<void()> expiration;
    bool begin(std::function<void()> onSystemExpired)
    {
        if (refuse) {
            g_log.push_back("begin:refused");
            return false;
        }
        g_log.push_back("begin");
        running = true;
        expiration = std::move(onSystemExpired);
        return true;
    }
    void end()
    {
        if (!running)
            return; // the 139 guard never ended a task that was not running
        running = false;
        g_log.push_back("end");
    }
};

// ---- the guard of build 139, copied line for line (AvpnBackgroundGuard.mm at fad4c2b24), UIKit replaced
// by the same fake ----------------------------------------------------------------------------------
struct Guard139 {
    FakeSystem sys;
    bool taskValid = false;
    std::function<void()> onExpired;

    void end()
    {
        if (!taskValid)
            return;
        taskValid = false;
        onExpired = nullptr;
        sys.end();
    }
    bool begin(std::function<void()> cb)
    {
        if (taskValid)
            return true;
        onExpired = std::move(cb);
        taskValid = sys.begin([this] {
            std::function<void()> cbNow = onExpired;
            end();
            if (cbNow)
                cbNow();
        });
        if (!taskValid) {
            onExpired = nullptr;
            return false;
        }
        return true;
    }
};

// One step of a scenario for the restart guard alone: b = begin, e = end, x = the system expires the
// task, r/a = the system refuses / accepts the next begin.
static std::vector<std::string> run139(const char *script)
{
    g_log.clear();
    Guard139 g;
    int n = 0;
    for (const char *p = script; *p; ++p) {
        switch (*p) {
        case 'b': {
            const int id = ++n;
            const bool ok = g.begin([id] { g_log.push_back("expired-callback#" + std::to_string(id)); });
            g_log.push_back(ok ? "begin->true" : "begin->false");
            break;
        }
        case 'e': g.end(); break;
        case 'x': if (g.sys.running && g.sys.expiration) { auto f = g.sys.expiration; f(); } break;
        case 'r': g.sys.refuse = true; break;
        case 'a': g.sys.refuse = false; break;
        }
    }
    return g_log;
}

static std::vector<std::string> runNew(const char *script)
{
    g_log.clear();
    BackgroundHold<FakeSystem> h;
    int n = 0;
    for (const char *p = script; *p; ++p) {
        switch (*p) {
        case 'b': {
            const int id = ++n;
            const bool ok = h.acquire(BgReason::TunnelRestart, [id] { g_log.push_back("expired-callback#" + std::to_string(id)); });
            g_log.push_back(ok ? "begin->true" : "begin->false");
            break;
        }
        case 'e': h.release(BgReason::TunnelRestart); break;
        case 'x': if (h.system().running && h.system().expiration) { auto f = h.system().expiration; f(); } break;
        case 'r': h.system().refuse = true; break;
        case 'a': h.system().refuse = false; break;
        }
    }
    return g_log;
}

static void restartGuardIsUnchanged()
{
    // Hand-written sequences of the restart guard's life...
    const char *scripts[] = {
        "b", "be", "bbe", "bee", "e", "x", "bx", "bxe", "bxb", "bxbe", "bebe", "bbxb", "rb", "rbab", "rbe", "brb",
        "bexb", "bxxe", "rbxab", "bebxbeb", "arbbeabxbe",
    };
    for (const char *s : scripts) {
        const std::vector<std::string> before = run139(s);
        const std::vector<std::string> after = runNew(s);
        CHECK(before == after, s);
    }
    // ...and every sequence of the five steps up to length 7 (5^1 + ... + 5^7 = 97 655).
    const char alphabet[] = "bexra";
    int compared = 0, different = 0;
    for (int len = 1; len <= 7; ++len) {
        std::vector<int> idx(len, 0);
        for (;;) {
            std::string s;
            for (int i : idx)
                s += alphabet[i];
            ++compared;
            if (run139(s.c_str()) != runNew(s.c_str())) {
                if (++different <= 3)
                    std::printf("FAIL: restart guard differs from 139 on \"%s\"\n", s.c_str());
            }
            int k = len - 1;
            while (k >= 0 && ++idx[k] == 5)
                idx[k--] = 0;
            if (k < 0)
                break;
        }
    }
    CHECK(compared == 97655, "every sequence up to length 7 was replayed");
    CHECK(different == 0, "with only the restart reason the new guard makes the same calls as build 139");
}

static void twoReasons()
{
    // The book alone.
    BackgroundHoldBook book;
    CHECK(book.acquire(BgReason::TunnelRestart) == BackgroundHoldBook::Step::BeginTask && book.taskRunning(), "the first reason starts the task");
    CHECK(book.acquire(BgReason::OnDemandArm) == BackgroundHoldBook::Step::None && book.holds(BgReason::OnDemandArm), "the second joins it");
    CHECK(book.acquire(BgReason::OnDemandArm) == BackgroundHoldBook::Step::None, "acquiring twice is idempotent");
    CHECK(book.release(BgReason::TunnelRestart) == BackgroundHoldBook::Step::None && book.taskRunning(), "one reason leaving does not end the task of the other");
    CHECK(book.release(BgReason::TunnelRestart) == BackgroundHoldBook::Step::None, "releasing what is not held does nothing");
    CHECK(book.release(BgReason::OnDemandArm) == BackgroundHoldBook::Step::EndTask && !book.taskRunning() && book.reasons() == 0, "the last reason ends it");
    CHECK(book.release(BgReason::OnDemandArm) == BackgroundHoldBook::Step::None, "and only once");
    CHECK(book.acquire(BgReason::OnDemandArm) == BackgroundHoldBook::Step::BeginTask, "a new task after the old one ended");
    CHECK(book.acquire(BgReason::TunnelRestart) == BackgroundHoldBook::Step::None, "joined again");
    book.expire();
    CHECK(!book.taskRunning() && book.reasons() == 0 && !book.holds(BgReason::TunnelRestart) && !book.holds(BgReason::OnDemandArm),
          "expiry ends it for every reason");
    CHECK(book.release(BgReason::TunnelRestart) == BackgroundHoldBook::Step::None, "nothing held after expiry: a late release ends nothing");
    CHECK(book.acquire(BgReason::TunnelRestart) == BackgroundHoldBook::Step::BeginTask, "after expiry a reason may ask again");
    book.taskRefused();
    CHECK(!book.taskRunning() && book.reasons() == 0 && !book.holds(BgReason::TunnelRestart), "a refused task holds nothing");

    // The glue with the fake system.
    g_log.clear();
    BackgroundHold<FakeSystem> h;
    CHECK(h.acquire(BgReason::OnDemandArm, [] { g_log.push_back("arm-expired"); }), "arming holds");
    CHECK(h.acquire(BgReason::TunnelRestart, [] { g_log.push_back("restart-expired"); }), "restart joins");
    CHECK(g_log == std::vector<std::string>{"begin"}, "one system task for two reasons");
    h.release(BgReason::OnDemandArm);
    CHECK(g_log == std::vector<std::string>{"begin"} && h.taskRunning() && h.holds(BgReason::TunnelRestart) && !h.holds(BgReason::OnDemandArm),
          "the arming finished: the restart keeps its background time");
    h.release(BgReason::TunnelRestart);
    CHECK((g_log == std::vector<std::string>{"begin", "end"}) && !h.taskRunning(), "the last one ends the task");

    // Expiry tells both, after the task is ended, and only those that still hold.
    g_log.clear();
    h.acquire(BgReason::TunnelRestart, [] { g_log.push_back("restart-expired"); });
    h.acquire(BgReason::OnDemandArm, [] { g_log.push_back("arm-expired"); });
    { auto f = h.system().expiration; f(); }
    CHECK((g_log == std::vector<std::string>{"begin", "end", "restart-expired", "arm-expired"}), "expiry: end first, then each owner");
    CHECK(!h.holds(BgReason::TunnelRestart) && !h.holds(BgReason::OnDemandArm) && !h.taskRunning(), "nothing is held after expiry");
    g_log.clear();
    h.acquire(BgReason::TunnelRestart, [] { g_log.push_back("restart-expired"); });
    h.acquire(BgReason::OnDemandArm, [] { g_log.push_back("arm-expired"); });
    h.release(BgReason::OnDemandArm);
    { auto f = h.system().expiration; f(); }
    CHECK((g_log == std::vector<std::string>{"begin", "end", "restart-expired"}), "an owner that already let go is not told");
    // An expiry is told once: the next task of ONE reason does not wake the other's old callback.
    g_log.clear();
    h.acquire(BgReason::TunnelRestart, [] { g_log.push_back("restart-expired"); });
    h.acquire(BgReason::OnDemandArm, [] { g_log.push_back("arm-expired"); });
    { auto f = h.system().expiration; f(); }
    h.acquire(BgReason::OnDemandArm, [] { g_log.push_back("arm-expired-2"); });
    { auto f = h.system().expiration; f(); }
    CHECK((g_log == std::vector<std::string>{"begin", "end", "restart-expired", "arm-expired", "begin", "end", "arm-expired-2"}),
          "a callback is used for one expiry only");
    // Letting go of a reason that holds nothing ends nothing and reaches the system with nothing.
    g_log.clear();
    h.release(BgReason::TunnelRestart);
    CHECK(g_log.empty() && !h.taskRunning(), "release without a hold: no call to the system");

    // A callback that asks again from inside the expiry is served by a NEW task.
    g_log.clear();
    BackgroundHold<FakeSystem> again;
    BackgroundHold<FakeSystem> *self = &again;
    again.acquire(BgReason::TunnelRestart, [self] {
        g_log.push_back("restart-expired");
        self->acquire(BgReason::TunnelRestart, [] { g_log.push_back("second-expired"); });
    });
    { auto f = again.system().expiration; f(); }
    CHECK((g_log == std::vector<std::string>{"begin", "end", "restart-expired", "begin"}) && again.holds(BgReason::TunnelRestart), "re-acquire from the callback");

    // A refusal: nobody holds, both may ask again.
    g_log.clear();
    BackgroundHold<FakeSystem> refused;
    refused.system().refuse = true;
    CHECK(!refused.acquire(BgReason::OnDemandArm, [] { g_log.push_back("arm-expired"); }) && !refused.holds(BgReason::OnDemandArm), "iOS refused: no hold");
    refused.system().refuse = false;
    CHECK(refused.acquire(BgReason::OnDemandArm, [] { g_log.push_back("arm-expired"); }) && refused.holds(BgReason::OnDemandArm), "and a later request works");
    CHECK((g_log == std::vector<std::string>{"begin:refused", "begin"}), "two attempts reached the system");
    // A refused request leaves no callback behind: a later task of the OTHER reason does not wake it.
    g_log.clear();
    BackgroundHold<FakeSystem> refusedThenOther;
    refusedThenOther.system().refuse = true;
    refusedThenOther.acquire(BgReason::OnDemandArm, [] { g_log.push_back("arm-expired"); });
    refusedThenOther.system().refuse = false;
    refusedThenOther.acquire(BgReason::TunnelRestart, [] { g_log.push_back("restart-expired"); });
    CHECK(!refusedThenOther.holds(BgReason::OnDemandArm) && refusedThenOther.holds(BgReason::TunnelRestart), "only the second request holds");
    { auto f = refusedThenOther.system().expiration; f(); }
    CHECK((g_log == std::vector<std::string>{"begin:refused", "begin", "end", "restart-expired"}), "the refused request is not told about a later expiry");
    // The first callback of a reason is kept when the reason asks twice (as the 139 guard did).
    g_log.clear();
    BackgroundHold<FakeSystem> twice;
    twice.acquire(BgReason::OnDemandArm, [] { g_log.push_back("first"); });
    twice.acquire(BgReason::OnDemandArm, [] { g_log.push_back("second"); });
    { auto f = twice.system().expiration; f(); }
    CHECK((g_log == std::vector<std::string>{"begin", "end", "first"}), "the first callback stays");
}

static BgArmInputs armInputs()
{
    BgArmInputs in;
    in.flagOn = true;
    in.haveTunnel = true;
    in.sessionUp = true;
    in.wireGuardBased = true;
    in.handshakeAwaiting = true;
    return in;
}

static void backgroundArmDecisions()
{
    // At the transition to background.
    CHECK(decideBackgroundArm(armInputs()).start == BgArmStart::Hold, "AmneziaWG session up, handshake not confirmed, rule not armed: hold");
    BgArmInputs in = armInputs();
    in.flagOn = false;
    CHECK(decideBackgroundArm(in).start == BgArmStart::NotNeeded && !std::strcmp(decideBackgroundArm(in).why, "flag_off"), "flag off: build 139");
    CHECK(decideBackgroundArm(BgArmInputs{}).start == BgArmStart::NotNeeded && !std::strcmp(decideBackgroundArm(BgArmInputs{}).why, "flag_off"),
          "the default inputs hold nothing");
    in = armInputs();
    in.haveTunnel = false;
    CHECK(!std::strcmp(decideBackgroundArm(in).why, "no_session") && decideBackgroundArm(in).start == BgArmStart::NotNeeded, "no manager");
    in = armInputs();
    in.sessionUp = false;
    CHECK(!std::strcmp(decideBackgroundArm(in).why, "no_session") && decideBackgroundArm(in).start == BgArmStart::NotNeeded, "tunnel down");
    in = armInputs();
    in.wireGuardBased = false;
    CHECK(!std::strcmp(decideBackgroundArm(in).why, "xray") && decideBackgroundArm(in).start == BgArmStart::NotNeeded, "Xray is never armed (§27)");
    in = armInputs();
    in.armed = true;
    CHECK(!std::strcmp(decideBackgroundArm(in).why, "armed") && decideBackgroundArm(in).start == BgArmStart::NotNeeded, "already armed");
    in = armInputs();
    in.localStopRequested = true;
    CHECK(!std::strcmp(decideBackgroundArm(in).why, "stopping") && decideBackgroundArm(in).start == BgArmStart::NotNeeded, "our own stop is under way");
    in = armInputs();
    in.handshakeAwaiting = false;
    CHECK(!std::strcmp(decideBackgroundArm(in).why, "arm_decided") && decideBackgroundArm(in).start == BgArmStart::NotNeeded,
          "handshake confirmed and the arming already decided (skipped): not re-armed here");
    in.changePending = true;
    CHECK(decideBackgroundArm(in).start == BgArmStart::Hold, "the arming's save is in flight: hold until it lands");

    // On each status-poll tick while held.
    BgArmTickInputs t;
    t.nowMs = 10000;
    t.heldSinceMs = 9000;
    t.maxHoldMs = 25000;
    t.sessionUp = true;
    t.handshakeAwaiting = true;
    CHECK(decideBackgroundArmTick(t) == BgArmTick::Keep, "still waiting for the handshake");
    BgArmTickInputs armed = t;
    armed.armed = true;
    CHECK(decideBackgroundArmTick(armed) == BgArmTick::ReleaseArmed, "armed: let go");
    BgArmTickInputs down = t;
    down.sessionUp = false;
    CHECK(decideBackgroundArmTick(down) == BgArmTick::ReleaseNotNeeded, "the tunnel went down");
    BgArmTickInputs stopping = t;
    stopping.localStopRequested = true;
    CHECK(decideBackgroundArmTick(stopping) == BgArmTick::ReleaseNotNeeded, "our stop began");
    BgArmTickInputs decided = t;
    decided.handshakeAwaiting = false;
    CHECK(decideBackgroundArmTick(decided) == BgArmTick::ReleaseNotNeeded, "confirmed, arming decided without arming");
    decided.changePending = true;
    CHECK(decideBackgroundArmTick(decided) == BgArmTick::Keep, "the save is in flight: keep");
    BgArmTickInputs late = t;
    late.nowMs = t.heldSinceMs + 24999;
    CHECK(decideBackgroundArmTick(late) == BgArmTick::Keep, "24.999 s: keep");
    late.nowMs = t.heldSinceMs + 25000;
    CHECK(decideBackgroundArmTick(late) == BgArmTick::ReleaseTimeout, "25 s: the bound");
    BgArmTickInputs clockBack = t;
    clockBack.nowMs = 100;
    CHECK(decideBackgroundArmTick(clockBack) == BgArmTick::ReleaseTimeout, "the clock went back: the hold is given back, not stretched");
    BgArmTickInputs armedLate = late;
    armedLate.armed = true;
    CHECK(decideBackgroundArmTick(armedLate) == BgArmTick::ReleaseArmed, "armed wins over the bound");
    // Back on the screen: background time is not needed (the controller asks the system on its poll).
    BgArmTickInputs active = t;
    active.appActive = true;
    CHECK(decideBackgroundArmTick(active) == BgArmTick::ReleaseNotNeeded, "on the screen again: let go");
    active.armed = true;
    CHECK(decideBackgroundArmTick(active) == BgArmTick::ReleaseArmed, "armed is still told as armed");
    CHECK(!std::strcmp(bgArmTickResult(BgArmTick::ReleaseArmed), "armed") && !std::strcmp(bgArmTickResult(BgArmTick::ReleaseTimeout), "timeout")
              && !std::strcmp(bgArmTickResult(BgArmTick::ReleaseNotNeeded), "not_needed") && !std::strcmp(bgArmTickResult(BgArmTick::Keep), ""),
          "journal words");

    CHECK(describeOnDemandState(false, true, true, false, true) == "on_demand_state armed=0 session=up proto=awg pending=0 handshake=awaiting", "state line 1");
    CHECK(describeOnDemandState(true, true, true, true, false) == "on_demand_state armed=1 session=up proto=awg pending=1 handshake=done", "state line 2");
    CHECK(describeOnDemandState(false, true, false, false, false) == "on_demand_state armed=0 session=up proto=xray pending=0 handshake=done", "state line 3");
    CHECK(describeOnDemandState(false, false, true, false, false) == "on_demand_state armed=0 session=down proto=- pending=0 handshake=done", "state line 4");
}

int main()
{
    restartGuardIsUnchanged();
    twoReasons();
    backgroundArmDecisions();
    std::printf("%d/%d ok\n", g_total - g_failed, g_total);
    if (g_failed) {
        std::printf("IosDataWatchTests: %d FAILED\n", g_failed);
        return 1;
    }
    std::printf("IosDataWatchTests: OK\n");
    return 0;
}
