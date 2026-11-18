// client/core/serviceEngine/ScanPlan.h
// AVPN serviceEngine - the Scanner's candidates and probe schedule. [header-only, QtCore; pure]
//
// Plan scanner-client-plan.md §2.1 (ScanPlan.h), §2.5 (probe kind per candidate), §2.8 (seats), R8; design
// D8 (legs, full-profile probes), D9 (tiers). Input: the manifest view (own nodes with tier/rank, provider
// entries with probe class and projection), the own pool of the subscription, the live session, the host
// capabilities, the network kind, the numbers, network memory. Output: the candidates to probe in schedule
// order, the order-only candidates («Не проверено»), the concurrency of each probe pool, the projection of
// bytes. Rules (each one a test in tests/scan_core_check.cpp):
//  - Never the current node (it is judged by the live tunnel). Never a node the manifest does not list for
//    this network, an RU node, a node without an exact tunnel config, a node outside a restricting country.
//    manual_only nodes ARE probed (18.11): the connect engine decides on its own when it may use one.
//  - Probe kind per candidate, by host capability (ScanTypes.h ScanHostCaps):
//      own Xray path        -> xray_leg when the host has legs (one outbound by construction: the leg IS the
//                              path), else xray_full (XrayConfigBuilder::coreConfig), else order only;
//      own AmneziaWG        -> awg_mini (awg-probe-plan.md: the device's OWN key, a sized download through
//                              the node's NAT) only when ALL hold: the host has the kind, the client switch
//                              features.scanner_awg_mini is on (compiled default off), scan_awg_concurrency > 0
//                              (server default 0), the manifest says awg_probe: true for the node (the
//                              device's peer is there; else "awg_no_peer": absent, never a failure), the app
//                              knows the API's IP (no DNS inside the session), and the node is neither the
//                              live tunnel's node nor the target of a connect attempt in progress
//                              ("awg_live": a second session of the same key there would move the live
//                              endpoint). Otherwise the node is absent (A3). With all of that but the
//                              device's own tunnel address unknown (the session's source; the runner needs
//                              it) the node is order only, «Не проверено» awg_no_address;
//      provider single      -> xray_leg when the host has legs and the projection is present, untrimmed and
//                              has its one leg (a profile verdict needs the DNS plan through the leg AND a
//                              host that exercises it - dnsThroughLeg; otherwise the machine confirms a
//                              working leg with a full follow-up), else xray_full, else order only;
//      provider composite   -> xray_full when the host may verify composites, else order only
//                              (composite_unverifiable).
//    Provider probes need a probe lease (seat, D6) first (needsLease).
//  - Concurrency per pool = min(host max for the kind, scan_stage2_concurrency_{cellular,wifi}) for Xray full
//    and leg probes; awg_mini has its own number: min(host max, scan_awg_concurrency). One awg_mini session
//    per node per scan (one candidate per node id).
//  - Order (D9): tier ascending, then the last-known-good candidate of this network first INSIDE its tier,
//    then a fresh failure on this network last in its tier, then the server's rank, then the id - a total
//    order: the schedule is deterministic and network memory never lifts a candidate across a tier.
//  - Reach (R8): when the host has a reach stage, candidates with an IP entry (own Xray entry, a provider
//    leg's server) get reachAtMs = their slot x scan_stage1_stagger_ms, pushed so that two opens to one
//    entry IP are at least scan_entry_ip_spacing_ms apart. The host enforces the same spacing for every
//    data connection and the per-entry-IP limit (scan_stage1_per_entry_ip) at run time.
//  - Projection = sum of scanProbeCostBytes of the probed candidates (an upper bound: the scan stops at
//    scan_stop_works).
//
// Upstream Amnezia has no counterpart.
#pragma once

#include "ScanBudget.h"
#include "ScanTunables.h"
#include "ScanTypes.h"
#include "TuningStore.h"
#include "UpstreamNode.h" // upstreamNodeIdFor

#include <QHash>
#include <QList>
#include <QMap>
#include <QSet>
#include <QString>

#include <algorithm>

namespace avpn {

struct ScanPlanInput {
    ScanManifestView manifest;
    QList<ScanOwnNode> ownNodes;
    ScanCurrent current;
    ScanHostCaps caps;
    ScanNetKind net = ScanNetKind::Unknown;
    ScanTunables tunables;
    QSet<QString> freshFailures;            // engine node ids
    QString lastKnownGood;                  // engine node id proven on this network (the path engine's ledger)
    QString restrictCountry;                // empty = every country
    QMap<QString, QString> upstreamNames;   // profile_id -> display name (UpstreamNode.h::upstreamDisplayName)
    bool awgMiniEnabled = false;            // features.scanner_awg_mini (scanAwgMiniFlag), compiled default off
    bool awgProbeIpKnown = false;           // the app resolved the API's IP (the RU-split carve-out set)
    bool awgAddressKnown = true;            // the device's own tunnel address is known (awg_mini needs it as
                                            // its source; unknown -> «Не проверено» awg_no_address)
};

inline constexpr char kScannerAwgMiniFlag[] = "scanner_awg_mini";

// The client switch of awg_mini probes, compiled default OFF (absent = off). The config service does NOT
// force it off for a config loaded from the cache (ConfigService.cpp forces only node_scan off there), so with
// a cached config the switch may be on. Safety does not rest on the switch: a session also needs the node's
// awg_probe flag and scan_awg_concurrency > 0, both from the signature-checked scan manifest this scan fetched
// or revalidated (the server sets awg_probe only where the device's peer is on the node), plus the device's
// own tunnel address.
inline bool scanAwgMiniFlag() { return TuningStore::flag(QLatin1String(kScannerAwgMiniFlag), false); }

struct ScanPlanExclusion {
    QString id;
    QString reason;
};

struct ScanPlan {
    QList<ScanCandidate> probe;      // to probe, in schedule order
    QList<ScanCandidate> orderOnly;  // «Не проверено» (never probed by this host)
    QList<ScanPlanExclusion> excluded;
    int fullConcurrency = 0;
    int legConcurrency = 0;
    int awgConcurrency = 0;
    qint64 projectedBytes = 0;

    int concurrencyFor(ScanProbeKind k) const
    {
        switch (k) {
        case ScanProbeKind::XrayLeg: return legConcurrency;
        case ScanProbeKind::AwgMini: return awgConcurrency;
        case ScanProbeKind::XrayFull: return fullConcurrency;
        case ScanProbeKind::None: break;
        }
        return 0;
    }

    const ScanCandidate *find(const QString &id) const
    {
        for (const ScanCandidate &c : probe)
            if (c.id == id)
                return &c;
        for (const ScanCandidate &c : orderOnly)
            if (c.id == id)
                return &c;
        return nullptr;
    }
};

inline int scanPoolConcurrency(int hostMax, ScanNetKind net, const ScanTunables &t)
{
    const int netMax = net == ScanNetKind::Cellular ? t.stage2ConcurrencyCellular : t.stage2ConcurrencyWifi;
    return qMax(0, qMin(hostMax, netMax));
}

inline bool scanCandidateLess(const ScanCandidate &a, const ScanCandidate &b)
{
    if (a.tier != b.tier)
        return a.tier < b.tier;
    if (a.lastKnownGood != b.lastKnownGood)
        return a.lastKnownGood;
    if (a.freshFailure != b.freshFailure)
        return !a.freshFailure;
    if (a.rank != b.rank)
        return a.rank < b.rank;
    return a.id < b.id;
}

// The candidate a full-profile follow-up probes (D8): same identity, kind xray_full, no reach stage, its
// own probe id so its host item never mixes with the leg's.
inline ScanCandidate scanFollowUpOf(const ScanCandidate &leg, const ScanTunables &t)
{
    ScanCandidate f = leg;
    f.kind = ScanProbeKind::XrayFull;
    f.followUp = true;
    f.reachAtMs = -1;
    f.costBytes = scanProbeCostBytes(ScanProbeKind::XrayFull, false, t);
    return f;
}

inline QString scanProbeIdOf(const ScanCandidate &c)
{
    return c.followUp ? c.id + QStringLiteral("#full") : c.id;
}

inline ScanPlan buildScanPlan(const ScanPlanInput &in)
{
    ScanPlan p;
    const ScanTunables &t = in.tunables;
    const ScanHostCaps &caps = in.caps;
    p.fullConcurrency = scanPoolConcurrency(caps.maxFullConcurrent, in.net, t);
    p.legConcurrency = scanPoolConcurrency(caps.maxLegConcurrent, in.net, t);
    p.awgConcurrency = qMax(0, qMin(caps.maxAwgConcurrent, t.awgConcurrency));
    const QString currentId = in.current.nodeId;
    const auto exclude = [&p](const QString &id, const char *why) { p.excluded << ScanPlanExclusion{id, QLatin1String(why)}; };
    const auto countryOk = [&in](const QString &cc) {
        return in.restrictCountry.isEmpty() || cc.compare(in.restrictCountry, Qt::CaseInsensitive) == 0;
    };
    const auto orderOnly = [&p](ScanCandidate c, const char *why) {
        c.kind = ScanProbeKind::None;
        c.notVerifiedReason = QLatin1String(why);
        p.orderOnly << c;
    };

    QHash<QString, ScanOwnNode> pool;
    for (const ScanOwnNode &n : in.ownNodes)
        if (!n.nodeId.isEmpty())
            pool.insert(n.nodeId, n);

    QSet<QString> seen;
    for (const ScanManifestNode &mn : in.manifest.nodes) {
        if (seen.contains(mn.nodeId))
            continue;
        seen.insert(mn.nodeId);
        if (!currentId.isEmpty() && mn.nodeId == currentId) {
            exclude(mn.nodeId, "current");
            continue;
        }
        const auto it = pool.constFind(mn.nodeId);
        if (it == pool.constEnd()) {
            exclude(mn.nodeId, "not_in_pool");
            continue;
        }
        const ScanOwnNode &n = it.value();
        // A manual_only node IS probed (owner, 18.11: the server marks it for the AWG mini-probe and probing is cheap);
        // whether the connect may use it is the connect engine's own rule. RU nodes are never a VPN exit.
        if (n.ru) {
            exclude(n.nodeId, "ru");
            continue;
        }
        if (!n.configAvailable) {
            exclude(n.nodeId, "no_config");
            continue;
        }
        if (!countryOk(n.countryCode)) {
            exclude(n.nodeId, "country");
            continue;
        }
        ScanCandidate c;
        c.id = n.nodeId;
        c.origin = ScanOrigin::Own;
        c.label = n.label;
        c.countryCode = n.countryCode;
        c.transport = n.transport;
        c.transportVersion = n.transportVersion;
        c.tier = 0;
        c.rank = mn.rank;
        c.crowdWorks = mn.crowdWorks;
        c.entryIp = n.entryIp;
        c.entryPort = n.entryPort;
        c.freshFailure = in.freshFailures.contains(c.id);
        c.lastKnownGood = !in.lastKnownGood.isEmpty() && c.id == in.lastKnownGood;
        if (n.transport == ScanTransport::Awg) {
            const char *why = !caps.awgMini()                                         ? "awg_no_host"
                              : !in.awgMiniEnabled || p.awgConcurrency <= 0           ? "awg_off"
                              : !mn.awgProbe                                          ? "awg_no_peer"
                              : n.nodeId == in.current.attemptNodeId                  ? "awg_live"
                              : !in.awgProbeIpKnown                                   ? "awg_no_api_ip"
                                                                                      : nullptr;
            if (why) {
                exclude(n.nodeId, why); // A3: absent, never a failure
                continue;
            }
            if (!in.awgAddressKnown) {
                orderOnly(c, "awg_no_address"); // no source address for the session: «Не проверено»
                continue;
            }
            c.kind = ScanProbeKind::AwgMini;
            c.awgEchoTarget = mn.awgEchoTarget.isEmpty() ? in.manifest.awgEchoTarget : mn.awgEchoTarget;
            p.probe << c;
        } else if (caps.legProbe() && p.legConcurrency > 0) {
            c.kind = ScanProbeKind::XrayLeg;
            p.probe << c;
        } else if (caps.fullProbe() && p.fullConcurrency > 0) {
            c.kind = ScanProbeKind::XrayFull;
            p.probe << c;
        } else {
            orderOnly(c, "no_probe");
        }
    }

    if (in.manifest.upstreamEligible) {
        QSet<QString> seenUp;
        for (const ScanManifestUpstream &u : in.manifest.upstream) {
            if (seenUp.contains(u.profileId))
                continue;
            seenUp.insert(u.profileId);
            const QString id = upstreamNodeIdFor(u.profileId);
            if (!currentId.isEmpty() && id == currentId) {
                exclude(id, "current");
                continue;
            }
            // The provider's own balancer is an Auto candidate only, never a Scanner row (contract 1.10.0; the
            // server omits it from the manifest - a safeguard, also for an older server's countryless entry).
            if (!upstreamKindListed(upstreamRowKind(u.kind, u.countryCode))) {
                exclude(id, "auto_kind");
                continue;
            }
            if (!countryOk(u.countryCode)) {
                exclude(id, "country");
                continue;
            }
            ScanCandidate c;
            c.id = id;
            c.origin = ScanOrigin::Upstream;
            c.profileId = u.profileId;
            c.label = in.upstreamNames.value(u.profileId, u.label);
            c.countryCode = u.countryCode;
            c.transport = ScanTransport::Xray;
            c.tier = u.tier;
            c.rank = u.rank;
            c.priority = u.priority;
            c.composite = u.composite;
            c.trimmed = u.trimmed;
            c.crowdWorks = u.crowdWorks;
            c.freshFailure = in.freshFailures.contains(c.id);
            c.lastKnownGood = !in.lastKnownGood.isEmpty() && c.id == in.lastKnownGood;
            c.needsLease = true;
            const bool legOk = caps.legProbe() && p.legConcurrency > 0 && !u.composite && !u.trimmed
                               && u.hasProjection && !u.legTag.isEmpty();
            if (legOk) {
                c.kind = ScanProbeKind::XrayLeg;
                c.dnsThroughLeg = u.dnsThroughLeg && caps.dnsPlan;
                c.dnsResolvers = u.dnsResolvers;
                c.entryIp = u.legEntryIp;
                c.entryPort = u.legEntryPort;
                p.probe << c;
            } else if (caps.fullProbe() && p.fullConcurrency > 0 && (!u.composite || caps.canVerifyComposite)) {
                c.kind = ScanProbeKind::XrayFull;
                p.probe << c;
            } else {
                c.needsLease = false;
                orderOnly(c, u.composite && caps.fullProbe() ? "composite_unverifiable" : "no_probe");
            }
        }
    }

    std::stable_sort(p.probe.begin(), p.probe.end(), scanCandidateLess);
    std::stable_sort(p.orderOnly.begin(), p.orderOnly.end(), scanCandidateLess);

    // Reach offsets with the per-entry-IP spacing (R8). Provider full probes and AWG sessions have none
    // (a whole profile is dialled by its own routing; AmneziaWG is UDP: its handshake is its reach).
    QHash<QString, qint64> lastOpen;
    int slot = 0;
    for (ScanCandidate &c : p.probe) {
        const bool reach = caps.reachStage && c.kind != ScanProbeKind::AwgMini
                           && !(c.origin == ScanOrigin::Upstream && c.kind == ScanProbeKind::XrayFull)
                           && !c.entryIp.isEmpty() && c.entryPort > 0;
        if (!reach) {
            c.reachAtMs = -1;
        } else {
            qint64 at = qint64(slot++) * t.stage1StaggerMs;
            const auto it = lastOpen.constFind(c.entryIp);
            if (it != lastOpen.constEnd())
                at = qMax(at, it.value() + t.entryIpSpacingMs);
            lastOpen.insert(c.entryIp, at);
            c.reachAtMs = at;
        }
        c.costBytes = scanProbeCostBytes(c.kind, c.hasReach(), t);
        p.projectedBytes += c.costBytes;
    }
    return p;
}

} // namespace avpn
