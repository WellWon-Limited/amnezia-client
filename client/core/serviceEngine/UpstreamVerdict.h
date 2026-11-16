// client/core/serviceEngine/UpstreamVerdict.h
// AVPN serviceEngine - the verdict of the data check of an upstream node. [header-only, QtCore; pure]
//
// Plan provider-pool v2, D7: an upstream node counts as connected only after a sized, incompressible
// body (upstream_verify_bytes, default 128 KiB) came back through the tunnel with a valid digest AND the
// request provably did not leave from the device's own access network. Whoami's "not one of our nodes =
// bypass" (WhoamiVerdict.h) does not apply: a provider exit is by definition not one of our nodes.
//
// Inputs are facts the caller measured; the function decides, in this order:
//  1. data (any failure -> NoData): requested > 0 (bad_request), a first byte (no_first_byte), TTFB within
//     its limit (ttfb_timeout), no stall above its limit (stalled), exactly the requested size
//     (incomplete / oversize), digest (digest_mismatch), total time within its hard limit (total_timeout);
//  2. path, in this order (decision of 14.11):
//     a. egress class "tribe-node" is impossible for an upstream node - the bytes came out of one of OUR
//        exits, so the leased profile did not carry them (a stale own tunnel, a wrong route):
//        NotThroughProvider (egress_tribe_node), never works;
//     b. both net tokens known and EQUAL (the same /20): NotThroughProvider (egress_is_access_net) -
//        decisive, nothing overrides it;
//     c. class "upstream-known": verified (verified_upstream_class) - ABOVE the ASN comparison: the server
//        learns an exit as upstream-known only from devices whose own network differed, so it outweighs an
//        ASN coincidence (large Russian operators run access and cloud hosting in one ASN);
//     d. both ASNs known and equal (tokens differ or unknown): NotThroughProvider (egress_is_access_asn);
//     e. tokens known and different: verified (verified_net_token); ASNs known and different: verified
//        (verified_asn);
//     f. nothing comparable: Unverifiable (reason unverifiable).
//  3. time: a verified, complete check past the soft time -> Slow (reason slow; pathReason keeps the
//     proof). `slow` is reported for an Unverifiable result too.
// passes = Works or Slow, or Unverifiable when the server has not made it strict
// (features.upstream_unverifiable_strict, default off = works-with-note). An unknown egress class string
// counts as absent (no evidence either way). Negative timings = not measured (that limit is not judged).
//
// Upstream Amnezia has no counterpart. Tests: tests/upstream_policy_check.cpp (build_upstream_policy.sh).
#pragma once

#include "TuningStore.h"

#include <QString>

namespace avpn {

enum class UpstreamEgressClass { Absent, TribeNode, UpstreamKnown, Other };

inline UpstreamEgressClass upstreamEgressClassFrom(const QString &s)
{
    if (s == QLatin1String("tribe-node")) return UpstreamEgressClass::TribeNode;
    if (s == QLatin1String("upstream-known")) return UpstreamEgressClass::UpstreamKnown;
    if (s == QLatin1String("other")) return UpstreamEgressClass::Other;
    return UpstreamEgressClass::Absent;
}

enum class UpstreamVerdict { Works, Slow, NoData, NotThroughProvider, Unverifiable };

inline const char *upstreamVerdictName(UpstreamVerdict v)
{
    switch (v) {
    case UpstreamVerdict::Works: return "works";
    case UpstreamVerdict::Slow: return "slow";
    case UpstreamVerdict::NoData: return "no_data";
    case UpstreamVerdict::NotThroughProvider: return "not_through_provider";
    case UpstreamVerdict::Unverifiable: return "unverifiable";
    }
    return "unknown";
}

// Limits of one check (ms). Defaults = the plan's data-probe limits (D9) and a soft time inside them.
struct UpstreamCheckLimits {
    qint64 ttfbMs = 3000;
    qint64 stallMs = 1500;
    qint64 totalMs = 5000;
    qint64 softTotalMs = 3000;
};

struct UpstreamCheckInput {
    qint64 bytesRequested = 0;
    qint64 bytesReceived = 0;
    bool digestOk = false;
    qint64 elapsedMs = -1;   // whole check; -1 = not measured
    qint64 ttfbMs = -1;      // first byte; -1 = not measured
    qint64 maxStallMs = -1;  // longest gap between bytes; -1 = not measured
    UpstreamCheckLimits limits;
    QString egressClass;     // the answer's class: "tribe-node" | "upstream-known" | "other" | "" (absent)
    qint64 egressAsn = 0;    // 0 = unknown
    QString egressNetToken;  // empty = unknown
    qint64 accessAsn = 0;    // the device's own access network, captured outside the tunnel before connect
    QString accessNetToken;
    bool strictUnverifiable = false; // the server's switch (upstreamUnverifiableStrictTuned)
};

struct UpstreamVerdictResult {
    UpstreamVerdict verdict = UpstreamVerdict::NoData;
    QString reason;      // stable code of the decisive rule
    QString pathReason;  // for Slow / Works / Unverifiable: the path proof (or "unverifiable")
    bool slow = false;   // complete but past the soft time
    bool passes = false; // counts as connected
};

inline constexpr char kUpstreamUnverifiableStrictFlag[] = "upstream_unverifiable_strict";

inline bool upstreamUnverifiableStrictTuned()
{
    return TuningStore::flag(QLatin1String(kUpstreamUnverifiableStrictFlag), false);
}

inline UpstreamVerdictResult judgeUpstreamCheck(const UpstreamCheckInput &in)
{
    UpstreamVerdictResult r;
    const auto noData = [&r](const char *why) {
        r.verdict = UpstreamVerdict::NoData;
        r.reason = QLatin1String(why);
        return r;
    };
    if (in.bytesRequested <= 0)
        return noData("bad_request");
    if (in.bytesReceived <= 0)
        return noData("no_first_byte");
    if (in.ttfbMs >= 0 && in.ttfbMs > in.limits.ttfbMs)
        return noData("ttfb_timeout");
    if (in.maxStallMs >= 0 && in.maxStallMs > in.limits.stallMs)
        return noData("stalled");
    if (in.bytesReceived < in.bytesRequested)
        return noData("incomplete");
    if (in.bytesReceived > in.bytesRequested)
        return noData("oversize");
    if (!in.digestOk)
        return noData("digest_mismatch");
    if (in.elapsedMs >= 0 && in.elapsedMs > in.limits.totalMs)
        return noData("total_timeout");

    r.slow = in.elapsedMs >= 0 && in.elapsedMs > in.limits.softTotalMs;
    const UpstreamEgressClass cls = upstreamEgressClassFrom(in.egressClass);
    const bool tokensKnown = !in.egressNetToken.isEmpty() && !in.accessNetToken.isEmpty();
    const bool asnKnown = in.egressAsn > 0 && in.accessAsn > 0;
    const auto leak = [&r](const char *why) {
        r.verdict = UpstreamVerdict::NotThroughProvider;
        r.reason = QLatin1String(why);
        r.pathReason = r.reason;
        return r;
    };
    if (cls == UpstreamEgressClass::TribeNode)
        return leak("egress_tribe_node");
    if (tokensKnown && in.egressNetToken == in.accessNetToken)
        return leak("egress_is_access_net");
    if (cls == UpstreamEgressClass::UpstreamKnown)
        r.pathReason = QStringLiteral("verified_upstream_class");
    else if (asnKnown && in.egressAsn == in.accessAsn)
        return leak("egress_is_access_asn");
    else if (tokensKnown)
        r.pathReason = QStringLiteral("verified_net_token");
    else if (asnKnown)
        r.pathReason = QStringLiteral("verified_asn");
    else {
        r.verdict = UpstreamVerdict::Unverifiable;
        r.reason = r.pathReason = QStringLiteral("unverifiable");
        r.passes = !in.strictUnverifiable;
        return r;
    }
    r.verdict = r.slow ? UpstreamVerdict::Slow : UpstreamVerdict::Works;
    r.reason = r.slow ? QStringLiteral("slow") : r.pathReason;
    r.passes = true;
    return r;
}

} // namespace avpn
