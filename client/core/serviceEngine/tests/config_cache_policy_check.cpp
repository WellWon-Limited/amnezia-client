// 5.1.109 (plan step S4.1): pure decisions about the cached copy of the signed /v1/config
// (ConfigCachePolicy.h). Defect of 12.11.2026 on 5.1.108 (138): a config loaded from the cache forced
// xray_client=false until a fresh signed answer, so after every cold start Xray was gone until the
// API answered. No network, no storage, no clock: every input is passed in.
#include "../ConfigCachePolicy.h"

#include <cmath>
#include <cstdio>
#include <cstring>
#include <limits>

using namespace avpn;

static int g_fail = 0, g_total = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        ++g_total;                                                                                 \
        if (!(cond)) {                                                                             \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                           \
            ++g_fail;                                                                              \
        }                                                                                          \
    } while (0)

static const qint64 kHour = 3600LL * 1000;
static const qint64 kNow = 1794500000000LL; // 12.11.2026, any fixed moment
static const qint64 kBound = 72 * kHour;

static bool is(const XrayClientDecision &d, bool allowed, XrayPolicy why)
{
    return d.allowed == allowed && d.why == why;
}

// A fresh signed answer of this run is in force as it is, whatever the cache or the clock say.
static void freshAnswerWins()
{
    CHECK(is(decideXrayClient(true, true, 0, kNow, kBound), true, XrayPolicy::FreshOn));
    CHECK(is(decideXrayClient(true, false, 0, kNow, kBound), false, XrayPolicy::FreshOff));
    // "off" from the server wins at once even if the cached copy would still be trusted
    CHECK(is(decideXrayClient(true, false, kNow - kHour, kNow, kBound), false, XrayPolicy::FreshOff));
    // a fresh "on" does not depend on the bound: trust in the cache switched off, clock behind
    CHECK(is(decideXrayClient(true, true, kNow + kHour, kNow, 0), true, XrayPolicy::FreshOn));
}

// The cached copy: the signed "true" is honoured only inside the bound since it was received.
static void cachedTrueInsideAndPastTheBound()
{
    CHECK(is(decideXrayClient(false, true, kNow, kNow, kBound), true, XrayPolicy::CacheTrusted));        // just received
    CHECK(is(decideXrayClient(false, true, kNow - 60000, kNow, kBound), true, XrayPolicy::CacheTrusted)); // a minute ago
    CHECK(is(decideXrayClient(false, true, kNow - 71 * kHour, kNow, kBound), true, XrayPolicy::CacheTrusted));
    CHECK(is(decideXrayClient(false, true, kNow - kBound + 1, kNow, kBound), true, XrayPolicy::CacheTrusted));
    CHECK(is(decideXrayClient(false, true, kNow - kBound, kNow, kBound), false, XrayPolicy::CacheExpired)); // the edge
    CHECK(is(decideXrayClient(false, true, kNow - 73 * kHour, kNow, kBound), false, XrayPolicy::CacheExpired));
    CHECK(is(decideXrayClient(false, true, kNow - 30 * 24 * kHour, kNow, kBound), false, XrayPolicy::CacheExpired));
}

// The last signed value was "false" (or the key was absent): frozen, however fresh the copy is.
static void cachedFalseStaysOff()
{
    CHECK(is(decideXrayClient(false, false, kNow, kNow, kBound), false, XrayPolicy::CacheOff));
    CHECK(is(decideXrayClient(false, false, kNow - kHour, kNow, kBound), false, XrayPolicy::CacheOff));
    CHECK(is(decideXrayClient(false, false, 0, kNow, kBound), false, XrayPolicy::CacheOff));
}

// No receive time: a cache written by 138 or earlier, or a wiped key - frozen as before 139.
static void missingTimestamp()
{
    CHECK(is(decideXrayClient(false, true, 0, kNow, kBound), false, XrayPolicy::CacheNoStamp));
    CHECK(is(decideXrayClient(false, true, -1, kNow, kBound), false, XrayPolicy::CacheNoStamp));
}

// The clock is behind the receive time: the age is unknown - frozen. Set forward it only shortens.
static void clockMoved()
{
    CHECK(is(decideXrayClient(false, true, kNow + 1, kNow, kBound), false, XrayPolicy::CacheClockBack));
    CHECK(is(decideXrayClient(false, true, kNow + 5 * 24 * kHour, kNow, kBound), false, XrayPolicy::CacheClockBack));
    // ... and trusted again once the clock is back after the receive time
    CHECK(is(decideXrayClient(false, true, kNow, kNow + kHour, kBound), true, XrayPolicy::CacheTrusted));
    // clock set a year forward: expired, never "trusted for longer"
    CHECK(is(decideXrayClient(false, true, kNow, kNow + 365 * 24 * kHour, kBound), false, XrayPolicy::CacheExpired));
}

// The bound comes from the server with the same signed copy (numbers.xray_client_cache_max_age_h).
static void boundFromTheServer()
{
    CHECK(std::strcmp(kXrayCacheMaxAgeKey, "xray_client_cache_max_age_h") == 0);
    CHECK(xrayCacheMaxAgeMs(kXrayCacheMaxAgeDefaultH) == 72 * kHour);
    CHECK(xrayCacheMaxAgeMs(1) == kHour);
    CHECK(xrayCacheMaxAgeMs(0.5) == kHour / 2);
    CHECK(xrayCacheMaxAgeMs(24) == 24 * kHour);
    // 0 = the server switches the trust off: the behaviour before 139
    CHECK(xrayCacheMaxAgeMs(0) == 0);
    CHECK(xrayCacheMaxAgeMs(-5) == 0);
    CHECK(xrayCacheMaxAgeMs(std::numeric_limits<double>::quiet_NaN()) == 0);
    // ceiling 7 days: an operator typo cannot make the trust endless
    CHECK(xrayCacheMaxAgeMs(168) == 168 * kHour);
    CHECK(xrayCacheMaxAgeMs(169) == 168 * kHour);
    CHECK(xrayCacheMaxAgeMs(1e12) == 168 * kHour);
    CHECK(xrayCacheMaxAgeMs(std::numeric_limits<double>::infinity()) == 168 * kHour);

    const qint64 at = kNow - 10 * kHour; // the same cached copy, 10 hours old
    CHECK(is(decideXrayClient(false, true, at, kNow, xrayCacheMaxAgeMs(72)), true, XrayPolicy::CacheTrusted));
    CHECK(is(decideXrayClient(false, true, at, kNow, xrayCacheMaxAgeMs(12)), true, XrayPolicy::CacheTrusted));
    CHECK(is(decideXrayClient(false, true, at, kNow, xrayCacheMaxAgeMs(10)), false, XrayPolicy::CacheExpired));
    CHECK(is(decideXrayClient(false, true, at, kNow, xrayCacheMaxAgeMs(6)), false, XrayPolicy::CacheExpired));
    CHECK(is(decideXrayClient(false, true, at, kNow, xrayCacheMaxAgeMs(0)), false, XrayPolicy::CacheTrustOff));
    CHECK(is(decideXrayClient(false, true, kNow, kNow, xrayCacheMaxAgeMs(0)), false, XrayPolicy::CacheTrustOff));
    // raised over the ceiling: 8 days old is still out
    CHECK(is(decideXrayClient(false, true, kNow - 8 * 24 * kHour, kNow, xrayCacheMaxAgeMs(1000)), false,
             XrayPolicy::CacheExpired));
    CHECK(is(decideXrayClient(false, true, kNow - 6 * 24 * kHour, kNow, xrayCacheMaxAgeMs(1000)), true,
             XrayPolicy::CacheTrusted));
}

// Journal names are a contract with the device checks (xray_policy why=...).
static void journalNames()
{
    CHECK(std::strcmp(xrayPolicyName(XrayPolicy::NoConfig), "no_config") == 0);
    CHECK(std::strcmp(xrayPolicyName(XrayPolicy::FreshOn), "fresh_on") == 0);
    CHECK(std::strcmp(xrayPolicyName(XrayPolicy::FreshOff), "fresh_off") == 0);
    CHECK(std::strcmp(xrayPolicyName(XrayPolicy::CacheTrusted), "cache_trusted") == 0);
    CHECK(std::strcmp(xrayPolicyName(XrayPolicy::CacheOff), "cache_off") == 0);
    CHECK(std::strcmp(xrayPolicyName(XrayPolicy::CacheTrustOff), "cache_trust_off") == 0);
    CHECK(std::strcmp(xrayPolicyName(XrayPolicy::CacheNoStamp), "cache_no_stamp") == 0);
    CHECK(std::strcmp(xrayPolicyName(XrayPolicy::CacheClockBack), "cache_clock_back") == 0);
    CHECK(std::strcmp(xrayPolicyName(XrayPolicy::CacheExpired), "cache_expired") == 0);
}

// Within a run an EXPIRED trust is never regained (review of d5d739403: setting the clock back revived
// it). Only the expiry is one-way (review of 3dbe0361f: a clock behind the receive time was sticky
// too - after the time was corrected a one-hour-old cached "true" stayed off until a restart).
static void expiredTrustIsOneWayWithinARun()
{
    const qint64 at = kNow - 71 * kHour;
    CachedTrust trust;
    CHECK(is(judgeCachedTrust(trust, true, at, kNow, kBound), true, XrayPolicy::CacheTrusted));
    CHECK(!trust.expired);
    CHECK(is(judgeCachedTrust(trust, true, at, kNow + 30 * 60000, kBound), true, XrayPolicy::CacheTrusted));
    CHECK(is(judgeCachedTrust(trust, true, at, kNow + 2 * kHour, kBound), false, XrayPolicy::CacheExpired));
    CHECK(trust.expired);
    // the clock is set back into the bound (not before the receive time): still expired
    CHECK(is(judgeCachedTrust(trust, true, at, kNow, kBound), false, XrayPolicy::CacheExpired));
    CHECK(is(decideXrayClient(false, true, at, kNow, kBound), true, XrayPolicy::CacheTrusted)); // the bare rule would revive it
    // ... and the server raising the bound does not revive it either: only a fresh signed answer does
    CHECK(is(judgeCachedTrust(trust, true, at, kNow, 168 * kHour), false, XrayPolicy::CacheExpired));
    // ... nor does a detour through a clock behind the receive time
    CHECK(is(judgeCachedTrust(trust, true, at, at - kHour, kBound), false, XrayPolicy::CacheClockBack));
    CHECK(is(judgeCachedTrust(trust, true, at, kNow, kBound), false, XrayPolicy::CacheExpired));

    // the clock was behind the receive time at start: a passing state, NOT sticky
    CachedTrust clockBack;
    const qint64 stamp = kNow + kHour;
    CHECK(is(judgeCachedTrust(clockBack, true, stamp, kNow, kBound), false, XrayPolicy::CacheClockBack));
    CHECK(!clockBack.expired);
    CHECK(is(judgeCachedTrust(clockBack, true, stamp, stamp + kHour, kBound), true, XrayPolicy::CacheTrusted)); // the time was corrected
    CHECK(is(judgeCachedTrust(clockBack, true, stamp, kNow, kBound), false, XrayPolicy::CacheClockBack));      // ... and went back again
    CHECK(is(judgeCachedTrust(clockBack, true, stamp, stamp + 2 * kHour, kBound), true, XrayPolicy::CacheTrusted));
    // corrected to a time past the bound: expired, and from then on one-way
    CHECK(is(judgeCachedTrust(clockBack, true, stamp, stamp + 73 * kHour, kBound), false, XrayPolicy::CacheExpired));
    CHECK(is(judgeCachedTrust(clockBack, true, stamp, stamp + kHour, kBound), false, XrayPolicy::CacheExpired));

    // the other reasons come from inputs that do not change within a run; they do not mark the trust
    CachedTrust off;
    CHECK(is(judgeCachedTrust(off, false, kNow, kNow, kBound), false, XrayPolicy::CacheOff));
    CHECK(is(judgeCachedTrust(off, true, 0, kNow, kBound), false, XrayPolicy::CacheNoStamp));
    CHECK(is(judgeCachedTrust(off, true, kNow, kNow, 0), false, XrayPolicy::CacheTrustOff));
    CHECK(!off.expired);
}

// "An API path works again": ask for the config while it is owed - at once, then not closer than the
// refresh throttle to the previous such refetch.
static void refetchOnApiSuccess()
{
    const qint64 spacing = kConfigRefreshThrottleMs;
    CHECK(spacing == 15 * 60 * 1000);                         // the foreground throttle, one constant
    // on the cached copy, owed, none in flight, no refetch yet
    CHECK(refetchConfigOnApiSuccess(/*fresh=*/false, /*inFlight=*/false, /*owed=*/true, /*lastRefetch=*/-1, kNow, spacing));
    // nothing owed: no config request has failed (the edge answered 4xx, or none was made yet)
    CHECK(!refetchConfigOnApiSuccess(false, false, false, -1, kNow, spacing));
    CHECK(!refetchConfigOnApiSuccess(false, false, false, kNow - 60 * 60000, kNow, spacing));
    // a request is already in flight: no second one
    CHECK(!refetchConfigOnApiSuccess(false, true, true, -1, kNow, spacing));
    // a fresh config is in force
    CHECK(!refetchConfigOnApiSuccess(true, false, true, -1, kNow, spacing));
    // owed again (the refetch itself failed, or the next foreground request did), but the previous
    // refetch was 5 minutes ago (d5d739403 asked on EVERY API success - about every 20 s)
    CHECK(!refetchConfigOnApiSuccess(false, false, true, kNow - 5 * 60000, kNow, spacing));
    CHECK(!refetchConfigOnApiSuccess(false, false, true, kNow - spacing + 1, kNow, spacing));
    CHECK(refetchConfigOnApiSuccess(false, false, true, kNow - spacing, kNow, spacing));
    CHECK(refetchConfigOnApiSuccess(false, false, true, kNow - 60 * 60000, kNow, spacing));
    // the clock went back behind the previous refetch: there is no spacing to keep
    CHECK(refetchConfigOnApiSuccess(false, false, true, kNow + kHour, kNow, spacing));
}

// A config request that got no answer: who votes in the edge walk and who owes the next refetch.
static void configFailureVotesAndOwes()
{
    // a usual request (start, a return to the screen, an edge switch, the macOS timer) on the cache
    ConfigFailure f = classifyConfigFailure(/*fresh=*/false, /*startedByApiSuccess=*/false, /*outlivedFreeze=*/false);
    CHECK(f.voteInEdgeWalk && f.refetchOwed);
    // ... with a fresh config already in force: votes as before, nothing is owed
    f = classifyConfigFailure(true, false, false);
    CHECK(f.voteInEdgeWalk && !f.refetchOwed);
    // the refetch of an API success: no vote ([success, fail, fail] switched the edge on d5d739403,
    // not on the base); the config is still owed - the next refetch comes after the spacing
    // (3dbe0361f: it was not, and 180 API successes in an hour brought no config)
    f = classifyConfigFailure(false, true, false);
    CHECK(!f.voteInEdgeWalk && f.refetchOwed);
    // a request that outlived a freeze of the process: no vote; the config is still owed
    f = classifyConfigFailure(false, false, true);
    CHECK(!f.voteInEdgeWalk && f.refetchOwed);
    f = classifyConfigFailure(true, false, true);
    CHECK(!f.voteInEdgeWalk && !f.refetchOwed);
    f = classifyConfigFailure(false, true, true);
    CHECK(!f.voteInEdgeWalk && f.refetchOwed);
}

// A config request that lived longer than its timeout allows was frozen with the process.
static void requestThatOutlivedAFreeze()
{
    const qint64 timeout = 15000;
    CHECK(!configRequestOutlivedFreeze(kNow - 200, kNow, timeout));       // failed at once
    CHECK(!configRequestOutlivedFreeze(kNow - 15000, kNow, timeout));     // an honest timeout
    CHECK(!configRequestOutlivedFreeze(kNow - 17000, kNow, timeout));     // ... with the timer's slack
    CHECK(configRequestOutlivedFreeze(kNow - 17001, kNow, timeout));      // the timer fired late: frozen
    CHECK(configRequestOutlivedFreeze(kNow - 8 * kHour, kNow, timeout));  // a night in the background
    CHECK(!configRequestOutlivedFreeze(0, kNow, timeout));                // no start stamp: not judged frozen
    CHECK(!configRequestOutlivedFreeze(kNow + kHour, kNow, timeout));     // the clock went back: not judged frozen
}

int main()
{
    freshAnswerWins();
    cachedTrueInsideAndPastTheBound();
    cachedFalseStaysOff();
    missingTimestamp();
    clockMoved();
    boundFromTheServer();
    journalNames();
    expiredTrustIsOneWayWithinARun();
    refetchOnApiSuccess();
    configFailureVotesAndOwes();
    requestThatOutlivedAFreeze();
    if (g_fail) {
        std::printf("config_cache_policy_check: %d FAILED of %d\n", g_fail, g_total);
        return 1;
    }
    std::printf("config_cache_policy_check: OK (%d checks)\n", g_total);
    return 0;
}
