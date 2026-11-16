// client/core/serviceEngine/UpstreamTierRule.h
// AVPN serviceEngine - the policy-tier boundary of the candidate choice. [header-only, QtCore; pure]
//
// Plan provider-pool v2, D9. Every candidate has a tier given by the server (own nodes 0, upstream
// profiles their stub's `tier` >= 1). A lower tier is a hard boundary: tier N+1 OPENS only when tier N is
// exhausted in this attempt, and "exhausted" is a defined failure, never a bare timer:
//   - tier N has no eligible candidate left that has not failed, or
//   - at least min(K, eligible size of tier N) of its candidates have a defined failure - failed in this
//     attempt (unreachable, past its own data-probe limits) or a fresh own failure on this network -
//     AND none of its candidates is still inside its limits (in flight): a running try blocks the next
//     tier.
// Crowd evidence and ranking never count as a failure; last-known-good and ranking order candidates only
// INSIDE their tier (they never lift a candidate over a lower tier). Tiers are the distinct values that
// occur (gaps allowed); a tier with no eligible candidate does not exist for the rule.
//
// K is a server tunable (numbers.upstream_tier_k, default 6) and is bounded in code strictly below the
// data-plane fail cap of a session (ConnectTunables.h::dataPlaneFailMaxTriesTuned, passed in): otherwise
// the cap would end the session before a tier could ever open. With the default cap 4, K is 3.
//
// Upstream Amnezia has no counterpart. Tests (incl. property tests): tests/upstream_policy_check.cpp.
#pragma once

#include "TuningStore.h"

#include <QList>
#include <QSet>
#include <QString>
#include <QStringList>

#include <algorithm>

namespace avpn {

struct TierCandidate {
    QString id;
    int tier = 0;            // own nodes 0, upstream >= 1
    bool eligible = true;    // passes every other gate (supported, kill switches, pin, transport mode)
    int rank = 0;            // ranking inside the tier, lower first (server priority, measured quality)
    double crowdScore = 0;   // crowd evidence: ORDER only, never a failure
};

struct TierAttempt {
    QSet<QString> failed;          // defined failure in this attempt
    QSet<QString> freshOwnFailure; // own failure on this network key, still fresh (TTL)
    QSet<QString> inFlight;        // being tried, still inside its limits
};

struct TierDecision {
    int maxOpenTier = -1;     // highest open tier; -1 = no eligible candidate at all
    QList<int> openTiers;     // ascending
    QStringList order;        // not-yet-failed eligible candidates of open tiers, pick order
};

inline constexpr char kUpstreamTierKKey[] = "upstream_tier_k";
inline constexpr int kUpstreamTierKDefault = 6;

// K bounded to [1, cap - 1] (cap <= 1 -> 1).
inline int upstreamTierK(int k, int dataPlaneFailCap)
{
    const int hi = qMax(1, dataPlaneFailCap - 1);
    return qBound(1, k, hi);
}

inline int upstreamTierKTuned(int dataPlaneFailCap)
{
    const double v = TuningStore::numberOr(QLatin1String(kUpstreamTierKKey), kUpstreamTierKDefault);
    return upstreamTierK(v >= 1 && v < 1e6 ? int(v) : kUpstreamTierKDefault, dataPlaneFailCap);
}

inline TierDecision decideOpenTiers(const QList<TierCandidate> &candidates, const TierAttempt &attempt, int k,
                                    int dataPlaneFailCap, const QString &lastKnownGood = QString())
{
    TierDecision d;
    const int kk = upstreamTierK(k, dataPlaneFailCap);
    QList<int> tiers;
    for (const TierCandidate &c : candidates)
        if (c.eligible && !tiers.contains(c.tier))
            tiers << c.tier;
    std::sort(tiers.begin(), tiers.end());
    const auto failedC = [&attempt](const TierCandidate &c) {
        return attempt.failed.contains(c.id) || attempt.freshOwnFailure.contains(c.id);
    };
    for (int t : tiers) {
        d.openTiers << t;
        d.maxOpenTier = t;
        int size = 0, failures = 0, open = 0;
        bool running = false;
        for (const TierCandidate &c : candidates) {
            if (!c.eligible || c.tier != t)
                continue;
            ++size;
            if (failedC(c)) {
                ++failures;
            } else {
                ++open;
                if (attempt.inFlight.contains(c.id))
                    running = true;
            }
        }
        const bool exhausted = open == 0 || (failures >= qMin(kk, size) && !running);
        if (!exhausted)
            break;
    }
    QList<TierCandidate> pick;
    for (const TierCandidate &c : candidates)
        if (c.eligible && d.openTiers.contains(c.tier) && !failedC(c))
            pick << c;
    std::stable_sort(pick.begin(), pick.end(), [&lastKnownGood](const TierCandidate &a, const TierCandidate &b) {
        if (a.tier != b.tier)
            return a.tier < b.tier;
        const bool la = !lastKnownGood.isEmpty() && a.id == lastKnownGood;
        const bool lb = !lastKnownGood.isEmpty() && b.id == lastKnownGood;
        if (la != lb)
            return la;
        if (a.rank != b.rank)
            return a.rank < b.rank;
        if (a.crowdScore != b.crowdScore)
            return a.crowdScore > b.crowdScore;
        return a.id < b.id;
    });
    for (const TierCandidate &c : pick)
        d.order << c.id;
    return d;
}

} // namespace avpn
