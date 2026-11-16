// client/core/serviceEngine/ScanClass.h
// AVPN serviceEngine - the verdict of one scan probe: class, speed class, bars, the ms a row shows.
// [header-only, QtCore; pure]
//
// Plan scanner-client-plan.md §2.5, §2.6 (facts per data probe: reach_ms, ttfb1_ms, rtt_ms, t64_ms, digest,
// egress); design D8 (legs); awg-probe-plan.md §3 (own AmneziaWG). Rules, in this order (each one a test in
// tests/scan_core_check.cpp):
//  1. No verdict: the host did not judge the path (memory guard, budget, cancel, deadline, config, internal
//     error) -> NotVerified.
//  2. Unreachable: the reach stage failed; an awg_mini session got no handshake; or, for a candidate without
//     a reach stage (provider profiles), the path could not be dialled at all (nothing came back).
//  3. NoData: reached but no complete answer: non-200, short / stalled / oversize body, digest mismatch
//     (computed on the device), a TTFB or total time past its limit (the host's limits, re-checked here).
//  3a. A provider leg (xray_leg of an upstream profile) that carried the data is a PROFILE verdict only when
//     the profile is single, not trimmed, its DNS plan routes every resolver through this leg AND the host
//     reports the plan exercised (dns_exercised); otherwise NotVerified (leg_dns, leg_trimmed, leg_composite)
//     - the machine then schedules a full-profile follow-up when it can. A leg that FAILED is a verdict for a
//     single profile (its only proxy outbound carries nothing). An own Xray path is one outbound by
//     construction: its leg is the path, no DNS rule.
//  4. Path (REQ S2: «works» only after a sized download whose digest the device verified and which provably
//     did not leave through the device's own access network; anything unproven is «Не проверено»):
//     own node (Xray and awg_mini alike): the egress net token equal to the access token -> Leak (the request
//       left from the device's own network); works ONLY with class "tribe-node" AND X-Tribe-Egress-Node equal
//       to this candidate's host node id (scanHostPartOf: "9" for "9:xray"; server 1.5.0 sends both for our
//       nodes). Another node -> NotVerified (egress_other_node); no node header -> NotVerified
//       (egress_node_missing); class "other"/"upstream-known" (the exit is not in the whoami map, e.g. a split
//       entry/exit node) -> NotVerified (egress_unmapped); no class -> NotVerified (egress_unknown). Never shown.
//     provider: the D7 path rules of UpstreamVerdict.h::judgeUpstreamCheck (egress tribe-node, equal net
//       token, equal ASN -> Leak; upstream-known / different tokens / different ASNs -> verified); nothing
//       comparable (Unverifiable) -> NotVerified "unverifiable" in the Scanner (plan C1), marked
//       exclusionCandidate (egress class not tribe-node) with the class and speed it would have; the machine
//       promotes it (evidence "exclusion") only when scanExclusionHolds below says so. Own nodes never use
//       exclusion (they have the egress-node proof). The connect gate keeps its own rule (UpstreamVerdict.h).
//  4a. Proof by exclusion (plan §2.8, lead decision 16.11; scanExclusionHolds): all of - the switch
//     features.upstream_unverifiable_strict off; the host's OPENING and CLOSING access attempts (§2.2c) both
//     made, both without any HTTP answer (a network-level failure), on one host path state (the same gen,
//     equal to that source's element of the current tuple when the tuple has it), received under the same
//     strict generation and scan token as now; the probe started at or after the opening attempt's start and
//     ended at or before the closing attempt's start (one clock: ms after scan_start). Any HTTP answer, a
//     missing attempt or time, another gen / generation / token -> no (the row stays «Не проверено»).
//     "Made" means packets left the physical interface: an attempt the host could not send (budget, dns -
//     the base's name did not resolve, bind - the socket protection failed, no_route) is reported NOT
//     attempted (null / attempted false) and so never counts as a network-level failure: a not-attempted
//     opening with a failed closing attempt is no bracket (ScanHostContract.h, "Access attempts").
//  5. Slow: works, but ttfb1 > scan_slow_ttfb_ms or t64 > scan_slow_t64_ms.
//  6. Speed: Slow class -> speed Slow; Works -> q = rtt + 0.5 * t64 (rtt missing -> ttfb1):
//     q <= scan_class_fast_ms fast, <= scan_class_slow_ms medium, else slow.
// Row ms = rtt_ms (one full-path round trip, the same kind as the home figure, A7); ttfb1 when rtt is
// missing. The current connection is never probed: its speed comes from its live ms alone (q = live ms).
//
// Upstream Amnezia has no counterpart.
#pragma once

#include "ScanTunables.h"
#include "ScanTypes.h"
#include "UpstreamVerdict.h"

#include <QString>

namespace avpn {

struct ScanVerdict {
    ScanClass cls = ScanClass::NotVerified;
    ScanSpeed speed = ScanSpeed::None;
    int ms = -1;           // what the row shows (-1 = none)
    QString reason;        // stable code of the decisive rule (journal, report)
    bool exclusionCandidate = false; // NotVerified only for lack of comparable access facts (see rule 4)
    ScanClass exclusionClass = ScanClass::NotVerified; // what it is if the exclusion proof holds
};

inline ScanSpeed scanSpeedOfScore(double q, const ScanTunables &t)
{
    if (q < 0)
        return ScanSpeed::None;
    if (q <= t.classFastMs)
        return ScanSpeed::Fast;
    if (q <= t.classSlowMs)
        return ScanSpeed::Medium;
    return ScanSpeed::Slow;
}

// Speed of the live connection from its live ms (never probed).
inline ScanSpeed scanSpeedOfLive(int liveRttMs, const ScanTunables &t)
{
    return liveRttMs < 0 ? ScanSpeed::Medium : scanSpeedOfScore(liveRttMs, t);
}

struct ScanClassifyInput {
    ScanOrigin origin = ScanOrigin::Own;
    ScanProbeKind kind = ScanProbeKind::XrayFull;
    QString candidateId;       // own: the engine node id (its host part names the expected egress node)
    bool hasReach = false;     // the candidate had a reach stage (own entry ip:port)
    bool composite = false;
    bool trimmed = false;
    bool dnsThroughLeg = false; // provider leg: the projection's DNS plan routes every resolver through it
    int dnsResolvers = 0;      // resolvers of that plan (0 = no DNS module: nothing to exercise)
    bool reachFailed = false;  // a reach item said not ok
    ScanProbeError reachError = ScanProbeError::None;
    ScanProbeFacts data;       // the data item (stage Data); ignored when reachFailed
    ScanAccess access;
};

// Why an exclusion proof failed (tests, journal); "" = it holds.
inline QString scanExclusionWhy(bool strict, const ScanAccessAttempt &opening, const QString &openingStamp,
                                const ScanAccessAttempt &closing, const QString &closingStamp, const QString &currentStamp,
                                const QList<ScanNetSource> &tuple, qint64 probeStartMs, qint64 probeEndMs)
{
    if (strict)
        return QStringLiteral("strict");
    if (!opening.attempted || !closing.attempted)
        return QStringLiteral("attempt_missing");
    if (opening.httpAnswered || closing.httpAnswered)
        return QStringLiteral("http_answered");
    if (openingStamp.isEmpty() || openingStamp != closingStamp || closingStamp != currentStamp)
        return QStringLiteral("generation");
    if (!opening.hasGen || !closing.hasGen || opening.gen != closing.gen)
        return QStringLiteral("host_gen");
    if (const ScanNetSource *t = scanNetSourceOf(tuple, opening.gen.source))
        if (*t != opening.gen)
            return QStringLiteral("host_gen");
    if (opening.atMs < 0 || closing.atMs < 0 || probeStartMs < 0 || probeEndMs < 0)
        return QStringLiteral("window");
    if (probeStartMs < opening.atMs || probeEndMs < probeStartMs || probeEndMs > closing.atMs)
        return QStringLiteral("window");
    return QString();
}

inline bool scanExclusionHolds(bool strict, const ScanAccessAttempt &opening, const QString &openingStamp,
                               const ScanAccessAttempt &closing, const QString &closingStamp, const QString &currentStamp,
                               const QList<ScanNetSource> &tuple, qint64 probeStartMs, qint64 probeEndMs)
{
    return scanExclusionWhy(strict, opening, openingStamp, closing, closingStamp, currentStamp, tuple, probeStartMs, probeEndMs).isEmpty();
}

inline ScanVerdict scanClassify(const ScanClassifyInput &in, const ScanTunables &t)
{
    ScanVerdict v;
    const auto out = [&v](ScanClass c, const char *why) {
        v.cls = c;
        v.reason = QLatin1String(why);
        return v;
    };
    if (in.reachFailed)
        return out(ScanClass::Unreachable, in.reachError == ScanProbeError::ReachRefused ? "reach_refused" : "reach_timeout");
    const ScanProbeFacts &f = in.data;
    if (scanProbeErrorNoVerdict(f.error))
        return out(ScanClass::NotVerified, scanProbeErrorName(f.error));
    if (in.kind == ScanProbeKind::None)
        return out(ScanClass::NotVerified, "not_probed");
    const bool awg = in.kind == ScanProbeKind::AwgMini;
    if (awg && !f.handshakeOk)
        return out(ScanClass::Unreachable, "handshake");
    const bool nothing = f.httpStatus == 0 && f.bytesReceived <= 0;
    if (nothing && !in.hasReach && !awg
        && (f.error == ScanProbeError::Dial || f.error == ScanProbeError::Tls || f.error == ScanProbeError::None))
        return out(ScanClass::Unreachable, "dial");
    if (f.httpStatus != 200)
        return out(ScanClass::NoData, nothing ? "no_answer" : "http");
    if (f.bytesRequested <= 0)
        return out(ScanClass::NoData, "bad_request");
    if (f.bytesReceived <= 0)
        return out(ScanClass::NoData, "no_first_byte");
    if (f.bytesReceived < f.bytesRequested)
        return out(ScanClass::NoData, f.error == ScanProbeError::Stalled ? "stalled" : "short");
    if (f.bytesReceived > f.bytesRequested)
        return out(ScanClass::NoData, "oversize");
    if (!f.shaOk)
        return out(ScanClass::NoData, "digest");
    if (f.ttfb1Ms >= 0 && f.ttfb1Ms > t.stage2TtfbMs)
        return out(ScanClass::NoData, "ttfb_timeout");
    if (f.durationMs >= 0 && f.durationMs > t.stage2TotalMs)
        return out(ScanClass::NoData, "total_timeout");
    if (f.error != ScanProbeError::None)
        return out(ScanClass::NoData, scanProbeErrorName(f.error));

    // Path.
    bool unverifiable = false;
    if (in.origin == ScanOrigin::Own) {
        const UpstreamEgressClass cls = upstreamEgressClassFrom(f.egressClass);
        if (!f.egressNetToken.isEmpty() && !in.access.netToken.isEmpty() && f.egressNetToken == in.access.netToken)
            return out(ScanClass::Leak, "egress_is_access_net");
        if (cls != UpstreamEgressClass::TribeNode)
            return out(ScanClass::NotVerified, cls == UpstreamEgressClass::Absent ? "egress_unknown" : "egress_unmapped");
        if (f.egressNode.isEmpty())
            return out(ScanClass::NotVerified, "egress_node_missing");
        if (f.egressNode != scanHostPartOf(in.candidateId))
            return out(ScanClass::NotVerified, "egress_other_node");
        v.reason = QStringLiteral("egress_tribe_node");
    } else {
        UpstreamCheckInput u;
        u.bytesRequested = u.bytesReceived = f.bytesRequested;
        u.digestOk = true;
        u.egressClass = f.egressClass;
        u.egressAsn = f.egressAsn;
        u.egressNetToken = f.egressNetToken;
        u.accessAsn = in.access.asn;
        u.accessNetToken = in.access.netToken;
        const UpstreamVerdictResult r = judgeUpstreamCheck(u);
        if (r.verdict == UpstreamVerdict::NotThroughProvider) {
            v.cls = ScanClass::Leak;
            v.reason = r.reason;
            return v;
        }
        // A leak the leg proved is decisive (above); a leg that carried data is a profile verdict only with
        // the DNS plan proven through it (rule 3a).
        const bool dnsProven = in.dnsThroughLeg && (in.dnsResolvers == 0 || f.dnsExercised);
        if (in.kind == ScanProbeKind::XrayLeg && (in.trimmed || in.composite || !dnsProven))
            return out(ScanClass::NotVerified, in.trimmed ? "leg_trimmed" : in.composite ? "leg_composite" : "leg_dns");
        unverifiable = r.verdict == UpstreamVerdict::Unverifiable;
        v.reason = r.pathReason;
    }

    // Time and speed.
    const int warm = f.rttMs >= 0 ? f.rttMs : f.ttfb1Ms;
    v.ms = warm;
    const bool slow = (f.ttfb1Ms >= 0 && f.ttfb1Ms > t.slowTtfbMs) || (f.t64Ms >= 0 && f.t64Ms > t.slowT64Ms);
    if (slow) {
        v.cls = ScanClass::Slow;
        v.speed = ScanSpeed::Slow;
    } else {
        v.cls = ScanClass::Works;
        const double q = (warm >= 0 ? warm : 0) + 0.5 * qMax(0, f.t64Ms);
        v.speed = warm < 0 && f.t64Ms < 0 ? ScanSpeed::Medium : scanSpeedOfScore(q, t);
    }
    if (unverifiable) {
        v.exclusionCandidate = upstreamEgressClassFrom(f.egressClass) != UpstreamEgressClass::TribeNode;
        v.exclusionClass = v.cls;
        v.cls = ScanClass::NotVerified;
        v.reason = QStringLiteral("unverifiable");
    }
    return v;
}

} // namespace avpn
