// client/core/serviceEngine/UpstreamTier.h
// AVPN serviceEngine - the policy tier of the automatic pick over subscription nodes (plan provider-pool
// v2 D9, integration point 4, risk R1): own nodes tier 0, upstream stubs their server tier; the commit
// tier from UpstreamTierRule.h::decideOpenTiers. [header-only, QtCore; pure]
// Kept apart from UpstreamEngine.h so the picker (TransportPick.h) does not pull the lease/standby code.
// Upstream Amnezia has no counterpart. Tests: tests/upstream_engine_check.cpp.
#pragma once

#include "UpstreamNode.h"
#include "UpstreamTierRule.h"
#include "dto/Subscription.h"

#include <QList>
#include <QSet>
#include <QString>

namespace avpn {

// --- policy tier in the automatic pick (point 4, R1) ---------------------------------------------------

// Own nodes are tier 0; an upstream stub its server tier (>= 1).
inline int upstreamTierOf(const SubscriptionNode &n)
{
    return n.upstream.has_value() ? n.upstream->tier : 0;
}

// Order of a candidate inside its tier for the rule: stubs by the server's priority, own nodes 0
// (their own order - RTT, weight, history - is applied by the picker afterwards).
inline int upstreamTierRankOf(const SubscriptionNode &n)
{
    return n.upstream.has_value() ? n.upstream->priority : 0;
}

struct UpstreamTierGate {
    bool enabled = false;       // only while features.upstream_nodes is on (off = byte-identical pick)
    int k = kUpstreamTierKDefault;
    int dataPlaneFailCap = 4;   // ConnectTunables.h::dataPlaneFailMaxTriesTuned
    QSet<QString> failed;       // failed in this attempt: data-plane failures + start failures (always,
                                // also when the picker retries without its session exclusions)
    // Own nodes with a "fresh own failure on this network" by reachability evidence (decideFastTierOpen):
    // the rule's freshOwnFailure input. Non-empty = the attempt never falls back to own nodes.
    QSet<QString> ownPreFailed;
};

// Sentinel commit tier: no candidate may be committed (fast open, and the upstream tier is used up too).
inline constexpr int kUpstreamNoCommitTier = 1 << 30;

// The tier the automatic pick commits to now; -1 = no gate (disabled, or no upstream candidate in the
// pool: nothing to separate - the pick is exactly the pick without tiers).
//
// decideOpenTiers says which tiers are open: tier N+1 opens only when tier N is exhausted (no eligible
// candidate left that has not failed, or min(K, size) of it failed). Auto tries ONE candidate at a time,
// so "a tier is exhausted" must mean "go to the next tier": the commit tier is the HIGHEST open tier that
// still has a candidate that has not failed. (Reading decideOpenTiers' `order` front to back instead
// would retry the leftovers of an exhausted tier first, and with the default cap 4 and K 3 Auto would
// give up on a 5-node own tier before the first upstream try - exactly R1. K is bound below the cap in
// code, so at least one try is left for the next tier.) When every open tier is used up the gate falls
// back to the lowest open tier (the picker's retry without exclusions then starts again from own nodes).
inline int upstreamCommitTier(const QList<const SubscriptionNode *> &pool, const UpstreamTierGate &gate)
{
    if (!gate.enabled)
        return -1;
    bool anyUpstream = false;
    QList<TierCandidate> cands;
    for (const SubscriptionNode *n : pool) {
        if (!n)
            continue;
        anyUpstream = anyUpstream || n->upstream.has_value();
        TierCandidate c;
        c.id = n->nodeId;
        c.tier = upstreamTierOf(*n);
        c.rank = upstreamTierRankOf(*n);
        cands << c;
    }
    if (!anyUpstream)
        return -1;
    TierAttempt at;
    at.failed = gate.failed;
    at.freshOwnFailure = gate.ownPreFailed;
    const TierDecision d = decideOpenTiers(cands, at, gate.k, gate.dataPlaneFailCap);
    if (d.maxOpenTier < 0)
        return -1;
    int best = -1;
    for (const TierCandidate &c : cands)
        if (d.openTiers.contains(c.tier) && !gate.failed.contains(c.id) && !gate.ownPreFailed.contains(c.id))
            best = qMax(best, c.tier);
    if (best >= 0)
        return best;
    // Everything used up. Pre-exhausted own tier (fast open): do NOT fall back to own nodes - the attempt
    // ends as an exhausted one does today; the next user connect evaluates fresh evidence.
    return gate.ownPreFailed.isEmpty() ? d.openTiers.constFirst() : kUpstreamNoCommitTier;
}

// The pool restricted to the commit tier (unchanged when there is no gate). Inside an upstream tier the
// server's priority orders the candidates (lower first): only the best priority left is kept, so the
// picker's own order (RTT - none for a stub -, weight) never jumps over it; a failure moves to the next.
inline QList<const SubscriptionNode *> upstreamTierFilter(const QList<const SubscriptionNode *> &eligible,
                                                          int commitTier)
{
    if (commitTier < 0)
        return eligible;
    QList<const SubscriptionNode *> out;
    int bestPriority = -1;
    for (const SubscriptionNode *n : eligible) {
        if (!n || upstreamTierOf(*n) != commitTier)
            continue;
        if (commitTier > 0) {
            const int p = upstreamTierRankOf(*n);
            if (bestPriority >= 0 && p > bestPriority)
                continue;
            if (bestPriority < 0 || p < bestPriority) {
                bestPriority = p;
                out.clear();
            }
        }
        out << n;
    }
    return out;
}

// --- "own tier pre-exhausted by evidence" (D9: unreachable in stage 1) ---------------------------------
// In a whitelist window own nodes neither answer ICMP nor start (iOS: up to ~45 s per start watchdog), and
// the API is unreachable. When the evidence the app already has says so, the own tier counts as exhausted
// for THIS attempt before any own node is started, and Auto commits to the upstream tier at once.
// Kill switch features.upstream_fast_tier_open (default on; only while upstream_nodes is on); window
// numbers.upstream_fast_open_window_s (default 60, clamp 10..300).
inline constexpr char kUpstreamFastTierFlag[] = "upstream_fast_tier_open";
inline constexpr char kUpstreamFastWindowKey[] = "upstream_fast_open_window_s";

inline qint64 upstreamFastOpenWindowMsFrom(double v)
{
    return qint64(clampTunable(v, 60, 10, 300)) * 1000;
}
inline qint64 upstreamFastOpenWindowMsTuned()
{
    return upstreamFastOpenWindowMsFrom(TuningStore::numberOr(QLatin1String(kUpstreamFastWindowKey), 60));
}

struct FastTierEvidence {
    qint64 nowMs = 0;              // wall clock of the facade (all stamps below on the same clock)
    // The last completed off-tunnel ICMP round over own candidates (start preparation's round).
    qint64 rttRoundAtMs = -1;      // -1 = none in this run
    int ownProbed = 0;             // own candidates actually probed in it
    int ownAnswered = 0;           // of them, answered
    // The direct API path: the last request that got NO HTTP answer (transport) and the last that got
    // any HTTP answer (a refusal, a 5xx - our server or its edge spoke).
    qint64 apiTransportFailAtMs = -1;
    qint64 apiAnswerAtMs = -1;
    bool whitelistActive = false;  // WhitelistDetector::active() (iOS / Android only)
};

struct FastTierDecision {
    bool fire = false;
    QString why; // stable code: fired | off | manual | no_round | stale_round | too_few_probed | own_answered |
                 // api_alive | no_upstream
    QString evidence; // counts and ages only (switch log)
};

// enabled = the kill switch and features.upstream_nodes; manualPick = a pin / the user's tap decides;
// ownCandidates = own nodes the automatic pick could start; upstreamUsable = an upstream candidate (stub
// or pack-sourced) is pickable right now.
inline FastTierDecision decideFastTierOpen(const FastTierEvidence &e, bool enabled, bool manualPick, int ownCandidates,
                                           bool upstreamUsable, qint64 windowMs)
{
    FastTierDecision d;
    const auto no = [&d](const char *why) {
        d.why = QLatin1String(why);
        return d;
    };
    if (!enabled)
        return no("off");
    if (manualPick)
        return no("manual");
    if (e.rttRoundAtMs < 0)
        return no("no_round");
    const qint64 roundAge = e.nowMs - e.rttRoundAtMs;
    if (roundAge < 0 || roundAge > windowMs)
        return no("stale_round");
    if (e.ownProbed < 1 || e.ownProbed < qMin(2, ownCandidates))
        return no("too_few_probed");
    if (e.ownAnswered > 0)
        return no("own_answered");
    const qint64 apiAge = e.nowMs - e.apiTransportFailAtMs;
    const bool apiDead = e.apiTransportFailAtMs >= 0 && apiAge >= 0 && apiAge <= windowMs
                         && e.apiTransportFailAtMs > e.apiAnswerAtMs;
    if (!apiDead && !e.whitelistActive)
        return no("api_alive");
    if (!upstreamUsable)
        return no("no_upstream");
    d.fire = true;
    d.why = QStringLiteral("fired");
    d.evidence = QStringLiteral("own_probed=%1 answered=0 round_age=%2s api=%3 whitelist=%4")
                     .arg(e.ownProbed)
                     .arg(roundAge / 1000)
                     .arg(apiDead ? QStringLiteral("transport age=%1s").arg(apiAge / 1000) : QStringLiteral("-"))
                     .arg(e.whitelistActive ? 1 : 0);
    return d;
}

} // namespace avpn
