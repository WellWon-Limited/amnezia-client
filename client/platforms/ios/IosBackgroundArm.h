// client/platforms/ios/IosBackgroundArm.h
//
// AVPN (iOS data watch, build 140; design §5.5 step 1 and §0a item 7; features.ios_on_demand_bg_arm, off by
// default): the On-Demand rule (CONNECT-INVARIANTS §27) is armed only by the running app, from a status
// reply with a confirmed handshake (IosController::armOnDemandForConfirmedSession). A user who leaves the
// app in the first seconds after Connect (or after a switch to another node) froze the app before that
// reply - the session stayed without the rule until the next open. Now, when the app leaves the screen with
// an AmneziaWG session up and the rule not armed yet, it holds background time (AvpnBackgroundGuard,
// reason OnDemandArm) so the EXISTING status poll keeps running and the EXISTING arming happens on the
// confirmed handshake - same policy "only a proven session", same decideOnDemandArm; then it lets go.
// No arming at start, Xray never armed (§27), no new timer: the hold's own bound is judged on the status
// poll's tick. Pure; tests: tests/IosDataWatchTests.cpp, harness IosControllerHarnessTests.mm.
#pragma once

#include <string>

namespace avpn_ios {

struct BgArmInputs {
    bool flagOn = false;            // features.ios_on_demand_bg_arm
    bool haveTunnel = false;        // our manager is known
    bool sessionUp = false;         // NE status Connecting / Connected / Reasserting
    bool wireGuardBased = false;    // AmneziaWG / WireGuard session (Xray: never, §27)
    bool armed = false;             // this process armed the rule (or found it armed)
    bool changePending = false;     // an arming load/save is in flight
    bool handshakeAwaiting = false; // the session still waits for its confirmed handshake
    bool localStopRequested = false;// our own stop of this session is under way
};

enum class BgArmStart { Hold, NotNeeded };

struct BgArmDecision {
    BgArmStart start = BgArmStart::NotNeeded;
    const char *why = "flag_off"; // journal reason when not needed
};

// At the transition to background. Hold only while the existing arming can still happen: the handshake is
// not confirmed yet (the poll will confirm it and arm) or the arming is in flight. A confirmed session
// whose arming was already decided (armed, or skipped by decideOnDemandArm) is not re-armed here.
inline BgArmDecision decideBackgroundArm(const BgArmInputs &in)
{
    if (!in.flagOn) return {BgArmStart::NotNeeded, "flag_off"};
    if (!in.haveTunnel || !in.sessionUp) return {BgArmStart::NotNeeded, "no_session"};
    if (!in.wireGuardBased) return {BgArmStart::NotNeeded, "xray"};
    if (in.armed) return {BgArmStart::NotNeeded, "armed"};
    if (in.localStopRequested) return {BgArmStart::NotNeeded, "stopping"};
    if (!in.handshakeAwaiting && !in.changePending) return {BgArmStart::NotNeeded, "arm_decided"};
    return {BgArmStart::Hold, ""};
}

// On each status-poll tick while held (and on the arming's own result).
enum class BgArmTick { Keep, ReleaseArmed, ReleaseTimeout, ReleaseNotNeeded };

struct BgArmTickInputs {
    long long nowMs = 0;
    long long heldSinceMs = 0;
    long long maxHoldMs = 25000;
    bool armed = false;
    bool sessionUp = false;
    bool localStopRequested = false;
    bool handshakeAwaiting = false;
    bool changePending = false;
};

inline BgArmTick decideBackgroundArmTick(const BgArmTickInputs &in)
{
    if (in.armed) return BgArmTick::ReleaseArmed;
    if (!in.sessionUp || in.localStopRequested) return BgArmTick::ReleaseNotNeeded;
    // Confirmed and the arming already decided without arming (skip: intent off, disarm in flight...).
    if (!in.handshakeAwaiting && !in.changePending) return BgArmTick::ReleaseNotNeeded;
    // Wall clock back: never stretch the hold beyond the bound counted from now.
    const long long held = in.nowMs >= in.heldSinceMs ? in.nowMs - in.heldSinceMs : 0;
    if (held >= in.maxHoldMs) return BgArmTick::ReleaseTimeout;
    return BgArmTick::Keep;
}

inline const char *bgArmTickResult(BgArmTick t)
{
    switch (t) {
    case BgArmTick::ReleaseArmed: return "armed";
    case BgArmTick::ReleaseTimeout: return "timeout";
    case BgArmTick::ReleaseNotNeeded: return "not_needed";
    case BgArmTick::Keep: break;
    }
    return "";
}

// One line at every transition to background with the flag on: what the rule looks like right now.
inline std::string describeOnDemandState(bool armed, bool sessionUp, bool wireGuardBased, bool changePending,
                                         bool handshakeAwaiting)
{
    std::string s = "on_demand_state armed=";
    s += armed ? "1" : "0";
    s += " session=";
    s += sessionUp ? "up" : "down";
    s += " proto=";
    s += !sessionUp ? "-" : (wireGuardBased ? "awg" : "xray");
    s += " pending=";
    s += changePending ? "1" : "0";
    s += " handshake=";
    s += handshakeAwaiting ? "awaiting" : "done";
    return s;
}

} // namespace avpn_ios
