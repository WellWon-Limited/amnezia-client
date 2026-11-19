// client/core/serviceEngine/ApiReach.h
// AVPN (lane C, device round 10 of 19.11: operator white-list mode): can the DIRECT control plane (our API, reached
// without a tunnel) be reached on this network right now. One value, one owner - ConfigService (the API edge walk):
//  - Unreachable: one full round of the walk found every edge silent (EdgeWalk.h, the quick first try of each);
//  - Reachable:   an HTTP answer came from a direct request (any status below 500; the walk's own answer test);
//  - Unknown:     nothing observed on THIS network generation (a network change forgets both facts).
// Readers (the path engine: candidate filter, race wait, no-evidence prior) never keep their own copy.
#pragma once

namespace avpn {

enum class ApiReach { Unknown, Reachable, Unreachable };

inline const char *apiReachName(ApiReach r)
{
    switch (r) {
    case ApiReach::Unknown: return "unknown";
    case ApiReach::Reachable: return "reachable";
    case ApiReach::Unreachable: return "unreachable";
    }
    return "";
}

} // namespace avpn
