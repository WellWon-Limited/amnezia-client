// client/core/serviceEngine/ConfigCachePolicy.h
// AVPN serviceEngine - pure decisions about the cached copy of the signed /v1/config. [header-only, QtCore]
//
// 5.1.109 (plan step S4.1; defect found 12.11.2026 on 5.1.108 (138)). Since 22.09.2026 a config loaded
// from the cache forced features.xray_client=false until a fresh signed /v1/config arrived, so that a
// server-side "off" is never overridden by an old cache. The price: after every cold start Xray was
// gone until the API answered - the Auto / Amnezia / Xray switch disappeared, Xray servers were "not
// supported", and on a network where AmneziaWG is throttled and the API is unreachable the user had
// nothing to connect with, although Xray worked a minute before.
//
// The rule now: the last SIGNED xray_client=true is honoured from the cache for a bounded time since
// that signed config was received (numbers.xray_client_cache_max_age_h of the same signed copy,
// default 72 h, 0 = never - the behaviour before 139). A fresh signed answer always wins at once, in
// both directions. Within a run the trust is one-way: once ended it stays ended until a fresh answer
// (judgeCachedTrust). features.node_scan is NOT covered: it stays frozen from the cache (incident
// 06.11.2026). Also here: when the config is asked for again on an API success, and what a failed
// config request means for the edge walk (refetchConfigOnApiSuccess, classifyConfigFailure).
//
// Accepted (review of d5d739403): the cached body is stored without its signature and the receive
// time is a plain setting. A local user who edits them changes the behaviour of their own device
// only; the server kill-switch is not a defence against the owner of the device.
//
// Upstream Amnezia has no counterpart: the remote config, its cache and the server kill-switch exist
// only in this layer (there Xray comes from the user's own config and is always available).
// Tests: tests/config_cache_policy_check.cpp (the decisions), tests/config_refresh_check.cpp
// (ConfigService with loopback servers). Canon: CONNECT-INVARIANTS §22 п. 7а, §30 п. 2а, REMOTE-TUNING §1.
#pragma once

#include <QString>
#include <QtGlobal>

namespace avpn {

// numbers.xray_client_cache_max_age_h - how long the cached signed xray_client=true is honoured.
inline constexpr char kXrayCacheMaxAgeKey[] = "xray_client_cache_max_age_h";
inline constexpr double kXrayCacheMaxAgeDefaultH = 72.0;
// Ceiling 168 h (7 days): an operator typo must not turn the bound into "forever" - the bound is the
// longest time a device that cannot reach the API keeps Xray after the server switched it off.
inline constexpr double kXrayCacheMaxAgeCeilH = 168.0;

// Hours from the signed config -> milliseconds. 0, a negative number and NaN switch the trust off.
inline qint64 xrayCacheMaxAgeMs(double hours)
{
    if (!(hours > 0.0))
        return 0;
    const double h = hours < kXrayCacheMaxAgeCeilH ? hours : kXrayCacheMaxAgeCeilH;
    return qint64(h * 3600.0 * 1000.0);
}

enum class XrayPolicy {
    NoConfig,      // no config applied in this run yet (first launch, empty cache): the client default, off
    FreshOn,       // a fresh signed answer of this run says true
    FreshOff,      // a fresh signed answer says false or carries no key (the client default is "off")
    CacheTrusted,  // cached signed true, received less than the bound ago
    CacheOff,      // the cached signed copy says false or carries no key
    CacheTrustOff, // the bound is 0: the server switched the trust in the cache off
    CacheNoStamp,  // no receive time stored (the cache was written by a build before 139)
    CacheClockBack,// the clock is behind the receive time: the age is unknown
    CacheExpired,  // received the bound ago or earlier
};

inline const char *xrayPolicyName(XrayPolicy p)
{
    switch (p) {
    case XrayPolicy::NoConfig:       return "no_config";
    case XrayPolicy::FreshOn:        return "fresh_on";
    case XrayPolicy::FreshOff:       return "fresh_off";
    case XrayPolicy::CacheTrusted:   return "cache_trusted";
    case XrayPolicy::CacheOff:       return "cache_off";
    case XrayPolicy::CacheTrustOff:  return "cache_trust_off";
    case XrayPolicy::CacheNoStamp:   return "cache_no_stamp";
    case XrayPolicy::CacheClockBack: return "cache_clock_back";
    case XrayPolicy::CacheExpired:   return "cache_expired";
    }
    return "unknown";
}

struct XrayClientDecision {
    bool allowed = false;
    XrayPolicy why = XrayPolicy::CacheOff;
};

// May the client use Xray right now, as far as the config says (the platform gate and the macOS
// runtime gate are separate - NodeRotation.h::xrayClientSupported).
//  fresh        - the config in force was received and verified in this run;
//  signedValue  - features.xray_client of that signed config (no key = false);
//  receivedAtMs - when the cached signed config was received (<= 0 = unknown); nowMs - the clock;
//  maxAgeMs     - xrayCacheMaxAgeMs() of the bound carried by the same signed config.
// Everything doubtful about the cache reads as "frozen" (the behaviour before 139).
inline XrayClientDecision decideXrayClient(bool fresh, bool signedValue, qint64 receivedAtMs, qint64 nowMs,
                                           qint64 maxAgeMs)
{
    if (fresh)
        return {signedValue, signedValue ? XrayPolicy::FreshOn : XrayPolicy::FreshOff};
    if (!signedValue)
        return {false, XrayPolicy::CacheOff};
    if (maxAgeMs <= 0)
        return {false, XrayPolicy::CacheTrustOff};
    if (receivedAtMs <= 0)
        return {false, XrayPolicy::CacheNoStamp};
    if (nowMs < receivedAtMs)
        return {false, XrayPolicy::CacheClockBack};
    if (nowMs - receivedAtMs >= maxAgeMs)
        return {false, XrayPolicy::CacheExpired};
    return {true, XrayPolicy::CacheTrusted};
}

// Within one run the cached copy can LOSE the trust and never regain it: once the cached signed
// "true" was judged as not trusted (expired, the clock behind the receive time, no receive time, the
// bound switched off), it stays so until a fresh signed answer - setting the clock back does not
// revive an expired trust (review of d5d739403). ConfigService keeps one CachedTrust per run and
// judges it again at start, before every config request, on the throttled foreground refresh and on
// every API outcome it is told about - no timer of its own.
struct CachedTrust {
    bool ended = false;
    XrayPolicy why = XrayPolicy::NoConfig;
};
inline XrayClientDecision judgeCachedTrust(CachedTrust &trust, bool signedValue, qint64 receivedAtMs, qint64 nowMs,
                                           qint64 maxAgeMs)
{
    if (trust.ended)
        return {false, trust.why};
    const XrayClientDecision d = decideXrayClient(/*fresh=*/false, signedValue, receivedAtMs, nowMs, maxAgeMs);
    if (!d.allowed) {
        trust.ended = true;
        trust.why = d.why;
    }
    return d;
}

// The one throttle of the config refresh: the foreground return asks for /v1/config at most this
// often (DebugSnapshot.h::kFgConfigThrottleMs is this constant) and the refetch on an API success
// below keeps the same spacing.
inline constexpr qint64 kConfigRefreshThrottleMs = 15 * 60 * 1000;

// A request to the API has just succeeded on some path (AvpnEngineQml::noteApiOutcome ->
// ConfigService::reportNetworkSuccess). Ask for /v1/config now if this process still runs on the
// cached copy and the config is OWED: a config request of the usual kind (start, a return to the
// screen, an edge switch, the macOS timer) got no answer. One refetch per owed episode - a failed
// refetch does not arm the next one (classifyConfigFailure), only the next usual request that fails
// does - and never closer than the refresh throttle to the previous refetch. No timer: the retry
// rides on requests the app already makes. An attempt the edge answered (4xx, a bad signature) owes
// nothing here - the foreground throttle handles it as before.
// Was (138): on iOS the config was asked for again only on a return to the screen or an edge switch.
// Was (d5d739403): every API success asked again while /v1/config kept failing (about every 20 s
// under a live session).
inline bool refetchConfigOnApiSuccess(bool fresh, bool inFlight, bool owed, qint64 lastRefetchMs, qint64 nowMs,
                                      qint64 minSpacingMs)
{
    if (fresh || inFlight || !owed)
        return false;
    if (lastRefetchMs <= 0 || nowMs < lastRefetchMs) // none yet, or the clock went back: no spacing to keep
        return true;
    return nowMs - lastRefetchMs >= minSpacingMs;
}

// A config request ended without an answer from the edge (no HTTP status, or 5xx).
//  voteInEdgeWalk - the failure counts against the active edge (ConfigService::reportNetworkFailure)
//                   and feeds the white-list detector. Not for a refetch started by an API success:
//                   that request did not exist before 139 and must not add votes ([success, fail,
//                   fail] switched the edge on d5d739403). Not for an outcome the facade's existing
//                   classification ignores (the request outlived a freeze of the process or fell
//                   into the window of our own tunnel transition - DebugSnapshot.h::classifyApiOutcome).
//  refetchOwed    - the next API success may ask again: only while on the cached copy and only after
//                   a request of the usual kind (one refetch per owed episode).
struct ConfigFailure {
    bool voteInEdgeWalk = false;
    bool refetchOwed = false;
};
inline ConfigFailure classifyConfigFailure(bool fresh, bool startedByApiSuccess, bool outcomeIgnored)
{
    ConfigFailure f;
    f.voteInEdgeWalk = !startedByApiSuccess && !outcomeIgnored;
    f.refetchOwed = !fresh && !startedByApiSuccess;
    return f;
}

} // namespace avpn
