// client/core/serviceEngine/ScanTypes.h
// AVPN serviceEngine - the Scanner's value types: candidates, probe kinds, probe facts, classes, speed
// classes, host capabilities, the manifest view the planner reads, the cached result of a network.
// [header-only, QtCore; pure]
//
// Plan: ~/avpn-build/plans/provider-pool/scanner-client-plan.md §2.1, §2.5, §2.6; contract
// upstream-scan/api/openapi.yaml (ScanManifest*, PathOutcomeItem). Every enum has a stable wire name
// (the JSON vectors and the host contract use them); an unknown wire name never maps to a "good" value.
//
// Upstream Amnezia has no counterpart. Tests: tests/scan_core_check.cpp (build_scan_core.sh).
#pragma once

#include "ScanNetworkGeneration.h"
#include "dto/Subscription.h" // UpstreamKind (contract 1.10.0)

#include <QHash>
#include <QJsonArray>
#include <QJsonObject>
#include <QList>
#include <QMap>
#include <QSet>
#include <QString>
#include <QStringList>

namespace avpn {

// --- enums and their wire names -------------------------------------------------------------------------

enum class ScanNetKind { Unknown, Wifi, Cellular, Ethernet };

inline const char *scanNetKindName(ScanNetKind k)
{
    switch (k) {
    case ScanNetKind::Wifi: return "wifi";
    case ScanNetKind::Cellular: return "cellular";
    case ScanNetKind::Ethernet: return "ethernet";
    case ScanNetKind::Unknown: break;
    }
    return "unknown";
}

inline ScanNetKind scanNetKindFrom(const QString &s)
{
    if (s == QLatin1String("wifi")) return ScanNetKind::Wifi;
    if (s == QLatin1String("cellular")) return ScanNetKind::Cellular;
    if (s == QLatin1String("ethernet")) return ScanNetKind::Ethernet;
    return ScanNetKind::Unknown;
}

// Own node of the subscription (tier 0) or a provider profile (tier >= 1).
enum class ScanOrigin { Own, Upstream };

enum class ScanTransport { Xray, Awg };

inline const char *scanTransportName(ScanTransport t) { return t == ScanTransport::Awg ? "awg" : "xray"; }
inline ScanTransport scanTransportFrom(const QString &s)
{
    return s == QLatin1String("awg") ? ScanTransport::Awg : ScanTransport::Xray;
}

// How a candidate is checked. None = not probed: the current connection (judged by the live tunnel) or an
// order-only candidate («Не проверено»). Which kind a candidate gets depends on the host's capabilities
// (ScanPlan.h).
enum class ScanProbeKind { None, XrayFull, XrayLeg, AwgMini };

inline const char *scanProbeKindName(ScanProbeKind k)
{
    switch (k) {
    case ScanProbeKind::XrayFull: return "xray_full";
    case ScanProbeKind::XrayLeg: return "xray_leg";
    case ScanProbeKind::AwgMini: return "awg_mini";
    case ScanProbeKind::None: break;
    }
    return "none";
}

inline ScanProbeKind scanProbeKindFrom(const QString &s)
{
    if (s == QLatin1String("xray_full")) return ScanProbeKind::XrayFull;
    if (s == QLatin1String("xray_leg")) return ScanProbeKind::XrayLeg;
    if (s == QLatin1String("awg_mini")) return ScanProbeKind::AwgMini;
    return ScanProbeKind::None;
}

// The verdict of one candidate (wire names = PathOutcomeItem.outcome).
enum class ScanClass { Works, Slow, NoData, Unreachable, Leak, NotVerified };

inline const char *scanClassName(ScanClass c)
{
    switch (c) {
    case ScanClass::Works: return "works";
    case ScanClass::Slow: return "slow";
    case ScanClass::NoData: return "no_data";
    case ScanClass::Unreachable: return "unreachable";
    case ScanClass::Leak: return "leak";
    case ScanClass::NotVerified: break;
    }
    return "not_verified";
}

inline ScanClass scanClassFrom(const QString &s)
{
    if (s == QLatin1String("works")) return ScanClass::Works;
    if (s == QLatin1String("slow")) return ScanClass::Slow;
    if (s == QLatin1String("no_data")) return ScanClass::NoData;
    if (s == QLatin1String("unreachable")) return ScanClass::Unreachable;
    if (s == QLatin1String("leak")) return ScanClass::Leak;
    return ScanClass::NotVerified;
}

inline bool scanClassWorking(ScanClass c) { return c == ScanClass::Works || c == ScanClass::Slow; }
inline bool scanClassFailure(ScanClass c)
{
    return c == ScanClass::NoData || c == ScanClass::Unreachable || c == ScanClass::Leak;
}

// Speed class of a working row (§2.6): words «быстро» / «средне» / none, bars 5 / 3 / 2 / 0.
enum class ScanSpeed { None, Fast, Medium, Slow };

inline const char *scanSpeedName(ScanSpeed s)
{
    switch (s) {
    case ScanSpeed::Fast: return "fast";
    case ScanSpeed::Medium: return "medium";
    case ScanSpeed::Slow: return "slow";
    case ScanSpeed::None: break;
    }
    return "none";
}

inline ScanSpeed scanSpeedFrom(const QString &s)
{
    if (s == QLatin1String("fast")) return ScanSpeed::Fast;
    if (s == QLatin1String("medium")) return ScanSpeed::Medium;
    if (s == QLatin1String("slow")) return ScanSpeed::Slow;
    return ScanSpeed::None;
}

// Bars of the speed class (artboard SPEED_LEVEL). Not the RTT bars of the servers list (SignalQuality.h).
inline int scanSpeedBars(ScanSpeed s)
{
    switch (s) {
    case ScanSpeed::Fast: return 5;
    case ScanSpeed::Medium: return 3;
    case ScanSpeed::Slow: return 2;
    case ScanSpeed::None: break;
    }
    return 0;
}

// Sort rank of the speed class: fast first, not verified last.
inline int scanSpeedRank(ScanSpeed s)
{
    switch (s) {
    case ScanSpeed::Fast: return 0;
    case ScanSpeed::Medium: return 1;
    case ScanSpeed::Slow: return 2;
    case ScanSpeed::None: break;
    }
    return 3;
}

// Probe errors the host reports (wire names in ScanHostContract.h). Unknown wire name -> Internal: never
// a verdict in favour of the path.
enum class ScanProbeError {
    None, ReachTimeout, ReachRefused, Dial, Tls, TtfbTimeout, Stalled, TotalTimeout, Http, Short, Digest,
    Memory, Budget, Cancelled, Deadline, Config, Internal,
    BindFailed, // the probe's own socket protection failed (a probe-local failure: no verdict, never a tunnel event)
};

inline const char *scanProbeErrorName(ScanProbeError e)
{
    switch (e) {
    case ScanProbeError::None: return "";
    case ScanProbeError::ReachTimeout: return "reach_timeout";
    case ScanProbeError::ReachRefused: return "reach_refused";
    case ScanProbeError::Dial: return "dial";
    case ScanProbeError::Tls: return "tls";
    case ScanProbeError::TtfbTimeout: return "ttfb_timeout";
    case ScanProbeError::Stalled: return "stalled";
    case ScanProbeError::TotalTimeout: return "total_timeout";
    case ScanProbeError::Http: return "http";
    case ScanProbeError::Short: return "short";
    case ScanProbeError::Digest: return "digest";
    case ScanProbeError::Memory: return "memory";
    case ScanProbeError::Budget: return "budget";
    case ScanProbeError::Cancelled: return "cancelled";
    case ScanProbeError::Deadline: return "deadline";
    case ScanProbeError::Config: return "config";
    case ScanProbeError::BindFailed: return "bind_failed";
    case ScanProbeError::Internal: break;
    }
    return "internal";
}

inline ScanProbeError scanProbeErrorFrom(const QString &s)
{
    static const QMap<QString, ScanProbeError> m = {
        {QString(), ScanProbeError::None},
        {QStringLiteral("reach_timeout"), ScanProbeError::ReachTimeout},
        {QStringLiteral("reach_refused"), ScanProbeError::ReachRefused},
        {QStringLiteral("dial"), ScanProbeError::Dial},
        {QStringLiteral("tls"), ScanProbeError::Tls},
        {QStringLiteral("ttfb_timeout"), ScanProbeError::TtfbTimeout},
        {QStringLiteral("stalled"), ScanProbeError::Stalled},
        {QStringLiteral("total_timeout"), ScanProbeError::TotalTimeout},
        {QStringLiteral("http"), ScanProbeError::Http},
        {QStringLiteral("short"), ScanProbeError::Short},
        {QStringLiteral("digest"), ScanProbeError::Digest},
        {QStringLiteral("memory"), ScanProbeError::Memory},
        {QStringLiteral("budget"), ScanProbeError::Budget},
        {QStringLiteral("cancelled"), ScanProbeError::Cancelled},
        {QStringLiteral("deadline"), ScanProbeError::Deadline},
        {QStringLiteral("config"), ScanProbeError::Config},
        {QStringLiteral("bind_failed"), ScanProbeError::BindFailed},
    };
    return m.value(s, ScanProbeError::Internal);
}

// The host did not judge the path at all (no verdict either way): the candidate stays «Не проверено».
inline bool scanProbeErrorNoVerdict(ScanProbeError e)
{
    return e == ScanProbeError::Memory || e == ScanProbeError::Budget || e == ScanProbeError::Cancelled
           || e == ScanProbeError::Deadline || e == ScanProbeError::Config || e == ScanProbeError::Internal
           || e == ScanProbeError::BindFailed;
}

// --- host capabilities ------------------------------------------------------------------------------------

// What the probe host of this device can do (answer of `scan_caps`, ScanHostContract.h). Everything the
// planner and the machine do differently per device comes from these values, never from a platform #ifdef:
// a minimal host that can only run full probes one at a time still gets a complete, valid scan; a host with
// legs, DNS plans and AWG mini-sessions gets the parallel scan.
//   maxFullConcurrent   xray_full probes at once (whole profile in a temporary instance); 0 = none.
//   canVerifyComposite  a composite provider profile may run as a full probe (macOS yes; iOS only when its
//                       memory guard says so - the host reports it per scan).
//   maxLegConcurrent    xray_leg probes at once in ONE shared probe instance (outbounds only); 0 = no legs.
//   dnsPlan             the host exercises a leg's DNS plan (one query per resolver through the forced leg)
//                       and reports dns_exercised; without it a provider leg is never a profile verdict.
//   maxAwgConcurrent    awg_mini sessions at once (userspace AmneziaWG with the device's own key on another
//                       own node, awg-probe-plan.md); 0 = none. The scan uses min(this, scan_awg_concurrency).
//   reachStage          a separate stage-1 TCP reachability before the data probe (else data only).
//   needsVpn            the host runs only while the VPN is on (iOS extension, A1).
//   memMb               host footprint when known (gate G2 input), -1 unknown.
//   platform            informational ("ios" | "macos" | "android" | ...): journals only, never decides.
struct ScanHostCaps {
    int maxFullConcurrent = 1;
    bool canVerifyComposite = false;
    int maxLegConcurrent = 0;
    bool dnsPlan = false;
    int maxAwgConcurrent = 0;
    bool reachStage = true;
    bool needsVpn = false;
    int memMb = -1;
    QString platform;

    bool legProbe() const { return maxLegConcurrent > 0; }
    bool awgMini() const { return maxAwgConcurrent > 0; }
    bool fullProbe() const { return maxFullConcurrent > 0; }
};

// --- network facts -----------------------------------------------------------------------------------------

// The network of the device. Three identities with three jobs (ScanNetworkGeneration.h, plan §2.11a):
//  - `key`: the anonymous operator-level REPORTING key (outcomes, the Doctor summary). The same for every Wi-Fi
//    of one ISP: it never identifies a network locally.
//  - `sources`: the STRICT local generation tuple, one {source, epoch, counter} per path monitor. It changes
//    when ANY component of ANY source changes (a new epoch = a monitor restart, a higher counter, a source that
//    appears or vanishes) - never a max() of counters. CURRENT evidence (fresh rows, access facts, the
//    live-tunnel proof, the exclusion bracket) is stamped with generation() and dies on any other value.
//  - `fingerprint`: the WEAK local fingerprint (scanNetFingerprint: interface kind + operator key + a gateway /
//    subnet hash where available; an opaque string here). It keys CACHED rows only - always drawn as cache
//    with their age, never counted as verified - which may survive a relaunch within scan_cache_works_ttl_s.
//    "" = none (no cached row ever matches).
// None of them leaves the device except `key`.
struct ScanNetwork {
    ScanNetKind kind = ScanNetKind::Unknown;
    QString key = QStringLiteral("unknown"); // openapi NetworkKey (UpstreamEngine.h::upstreamNetworkKey)
    QList<ScanNetSource> sources;
    QString fingerprint;
    QString radio;                // cellular radio generation "5g" | "lte" | "3g" | "2g" ("" = unknown / not cellular);
                                  // shown only (view.net_radio), never part of the network's identity

    QString generation() const { return scanNetGeneration(sources); }
    bool operator==(const ScanNetwork &o) const
    {
        return kind == o.kind && key == o.key && fingerprint == o.fingerprint && generation() == o.generation();
    }
    bool operator!=(const ScanNetwork &o) const { return !(*this == o); }
};

// An IP literal (IPv4 dotted quad or an IPv6 form); anything else is not dialled without DNS.
inline bool scanIsIpLiteralLoose(const QString &s)
{
    if (s.isEmpty() || s.size() > 45)
        return false;
    if (s.contains(QLatin1Char(':'))) {
        for (const QChar c : s)
            if (!(c.isDigit() || (c.toLower() >= QLatin1Char('a') && c.toLower() <= QLatin1Char('f')) || c == QLatin1Char(':') || c == QLatin1Char('.')))
                return false;
        return true;
    }
    const QStringList parts = s.split(QLatin1Char('.'));
    if (parts.size() != 4)
        return false;
    for (const QString &p : parts) {
        bool ok = false;
        const int v = p.toInt(&ok);
        if (!ok || v < 0 || v > 255 || p.isEmpty() || p.size() > 3)
            return false;
    }
    return true;
}

// The access network as /v1/netinfo (or a probe lease's `probe` grant, or the NE's netinfo_direct) saw it.
struct ScanAccess {
    qint64 asn = 0;   // 0 = unknown
    QString netToken; // empty = unknown (secret-ish: never logged)
};

// One direct access check of the probe host (plan §2.2c): GET <probe base>/v1/netinfo with THIS scan's token on a
// socket bound to the physical interface - the opening one before the first probe, the closing one after the
// last probe ended. httpAnswered false = no HTTP answer at all (DNS, TCP or TLS failure, timeout): a
// network-level failure; ANY HTTP status (an error too) = true. asn / netToken: the netinfo facts when it
// answered 200. atMs: when the attempt STARTED, ms after the host received scan_start (the same monotonic base
// as the items' start_ms / end_ms). gen: the host's own path monitor element at that moment.
struct ScanAccessAttempt {
    bool attempted = false;
    bool httpAnswered = false;
    ScanAccess facts;
    qint64 atMs = -1;
    bool hasGen = false;
    ScanNetSource gen;

    bool hasFacts() const { return attempted && httpAnswered && (facts.asn > 0 || !facts.netToken.isEmpty()); }
    bool networkFailed() const { return attempted && !httpAnswered; }
};

// --- the manifest view (signature, type, TTL and revision checks are the manifest client's job) ---------

struct ScanManifestNode {
    QString nodeId; // "9:xray"
    int tier = 0;
    int rank = 0;
    bool crowdWorks = false; // crowd_works (G4): «работает у других в вашей сети» - a mark only
    bool awgProbe = false;   // awg_probe (awg-probe-plan.md): the device's own peer is on this AWG node
    QString awgEchoTarget;   // awg_echo_target of this node ("" = the manifest-level value, if any)
    double score = -1;       // /v1/scan/candidates (1.14.0): the crowd score on this network 0..1, -1 = none
};

// The host node id a probe's X-Tribe-Egress-Node must name for an own candidate: the part before ':'
// ("9" for "9" and "9:xray"; openapi /v1/probe).
inline QString scanHostPartOf(const QString &nodeId)
{
    const int i = nodeId.indexOf(QLatin1Char(':'));
    return i < 0 ? nodeId : nodeId.left(i);
}

struct ScanManifestUpstream {
    QString profileId; // 16 hex
    QString label;
    int ordinal = 1;
    bool labelCustom = false;
    UpstreamKind kind = UpstreamKind::Unspecified; // wire `kind` (1.10.0; the server omits `auto` from the manifest)
    QString countryCode;
    int tier = 1;
    int rank = 0;
    int priority = 0;
    bool composite = false;   // probe_class == "composite"
    bool trimmed = false;     // projection cut: order only for leg probes (never "works" from its legs)
    int legsTotal = 0;
    bool hasProjection = false;
    bool crowdWorks = false;
    // From the projection (D8): the single leg, where it is dialled, and whether the profile's DNS plan
    // sends every resolver through that leg (then a leg probe that exercised the plan is a profile verdict).
    QString legTag;
    QString legEntryIp;       // IP literal of the leg's server ("" = a host name: no reach stage)
    int legEntryPort = 0;
    bool dnsThroughLeg = false;
    int dnsResolvers = 0;     // resolvers the host must exercise through the leg
    double score = -1;        // /v1/scan/candidates (1.14.0): the crowd score on this network 0..1, -1 = none
};

// The DNS plan of a single profile's projection (upstream_normalize.py `_projection`): legs [{tag, protocol,
// outbound, dialer, standalone}], catch_all {tcp, udp: {route, leg}}, dns [{address, tag, transport, route,
// leg}]. "Through the leg" = exactly one standalone leg, both catch-alls end in it, and every resolver either
// needs no network (route "none": fakedns) or routes through that leg; a resolver that goes direct (system,
// +local), to a block, a balancer or "other" cannot be proven by the leg. An empty dns list = no DNS module:
// domains travel to the proxy, nothing to exercise.
struct ScanDnsPlan {
    bool throughLeg = false;
    QString legTag;
    QString entryIp;
    int entryPort = 0;
    int resolvers = 0;
    QString reason;           // why not through the leg
};

inline bool scanIsIpLiteral(const QString &s) { return scanIsIpLiteralLoose(s); }

inline ScanDnsPlan scanDnsPlanOf(const QJsonObject &projection)
{
    ScanDnsPlan p;
    const QJsonArray legs = projection.value(QLatin1String("legs")).toArray();
    if (legs.size() != 1) {
        p.reason = QStringLiteral("legs");
        return p;
    }
    const QJsonObject leg = legs.at(0).toObject();
    p.legTag = leg.value(QLatin1String("tag")).toString();
    if (!leg.value(QLatin1String("standalone")).toBool(false)) {
        p.reason = QStringLiteral("dialer");
        return p;
    }
    // Where the leg is dialled: vnext[0] (vless/vmess) or servers[0] (trojan/shadowsocks).
    const QJsonObject settings = leg.value(QLatin1String("outbound")).toObject().value(QLatin1String("settings")).toObject();
    QJsonArray srv = settings.value(QLatin1String("vnext")).toArray();
    if (srv.isEmpty())
        srv = settings.value(QLatin1String("servers")).toArray();
    if (!srv.isEmpty()) {
        const QString addr = srv.at(0).toObject().value(QLatin1String("address")).toString();
        const int port = srv.at(0).toObject().value(QLatin1String("port")).toInt(0);
        if (scanIsIpLiteral(addr) && port > 0 && port < 65536) {
            p.entryIp = addr;
            p.entryPort = port;
        }
    }
    const QJsonObject catchAll = projection.value(QLatin1String("catch_all")).toObject();
    for (const char *net : {"tcp", "udp"}) {
        const QJsonObject c = catchAll.value(QLatin1String(net)).toObject();
        if (c.value(QLatin1String("route")).toString() != QLatin1String("leg")
            || c.value(QLatin1String("leg")).toString() != p.legTag) {
            p.reason = QStringLiteral("catch_all");
            return p;
        }
    }
    for (const QJsonValue &v : projection.value(QLatin1String("dns")).toArray()) {
        const QJsonObject d = v.toObject();
        const QString route = d.value(QLatin1String("route")).toString();
        if (route == QLatin1String("none"))
            continue;
        if (route != QLatin1String("leg") || d.value(QLatin1String("leg")).toString() != p.legTag) {
            p.reason = QStringLiteral("dns_") + (route.isEmpty() ? QStringLiteral("unknown") : route);
            return p;
        }
        ++p.resolvers;
    }
    p.throughLeg = true;
    return p;
}

struct ScanManifestView {
    QString networkKey;
    qint64 upstreamRevision = 0;
    bool upstreamEligible = false;
    qint64 probeMaxBytes = 1048576;
    qint64 tokenMaxBytes = 0;          // scan token budget (0 = unknown)
    qint64 tokenMaxRequests = 0;
    qint64 deviceBytesPerHour = 0;     // device_budget.bytes_per_hour (0 = unknown)
    qint64 deviceRequestsPerHour = 0;
    QMap<QString, double> numbers;
    QList<ScanManifestNode> nodes;
    QList<ScanManifestUpstream> upstream;
    QString awgEchoTarget;             // manifest-level awg_echo_target: fallback until contract 1.6.0 settles it per node
};

// Strict reading of the manifest body fields the planner needs (the body is already verified by its
// signature). Required fields missing or of the wrong type -> false with *error set; unknown fields are
// ignored; an upstream entry with a malformed profile id is dropped (the rest stays usable).
inline bool scanManifestViewFromJson(const QJsonObject &o, ScanManifestView &out, QString *error = nullptr)
{
    const auto fail = [error](const char *why) {
        if (error)
            *error = QLatin1String(why);
        return false;
    };
    ScanManifestView v;
    if (o.value(QLatin1String("type")).toString() != QLatin1String("scan_manifest"))
        return fail("type");
    if (o.value(QLatin1String("version")).toInt(-1) != 1)
        return fail("version");
    if (!o.value(QLatin1String("network_key")).isString())
        return fail("network_key");
    v.networkKey = o.value(QLatin1String("network_key")).toString();
    if (!o.value(QLatin1String("upstream_revision")).isDouble())
        return fail("upstream_revision");
    v.upstreamRevision = qint64(o.value(QLatin1String("upstream_revision")).toDouble());
    if (!o.value(QLatin1String("upstream_eligible")).isBool())
        return fail("upstream_eligible");
    v.upstreamEligible = o.value(QLatin1String("upstream_eligible")).toBool();
    const QJsonObject probe = o.value(QLatin1String("probe")).toObject();
    if (probe.value(QLatin1String("scheme")).toString() != QLatin1String("tribe-probe-v1"))
        return fail("probe");
    v.probeMaxBytes = qint64(probe.value(QLatin1String("max_bytes")).toDouble(1048576));
    const QJsonObject token = o.value(QLatin1String("scan_token")).toObject();
    if (!token.value(QLatin1String("token")).isString())
        return fail("scan_token");
    v.tokenMaxBytes = qint64(token.value(QLatin1String("max_bytes")).toDouble(0));
    v.tokenMaxRequests = qint64(token.value(QLatin1String("max_requests")).toDouble(0));
    const QJsonObject budget = o.value(QLatin1String("device_budget")).toObject();
    v.deviceBytesPerHour = qint64(budget.value(QLatin1String("bytes_per_hour")).toDouble(0));
    v.deviceRequestsPerHour = qint64(budget.value(QLatin1String("requests_per_hour")).toDouble(0));
    const QJsonObject numbers = o.value(QLatin1String("numbers")).toObject();
    for (auto it = numbers.constBegin(); it != numbers.constEnd(); ++it)
        if (it.value().isDouble())
            v.numbers.insert(it.key(), it.value().toDouble());
    v.awgEchoTarget = o.value(QLatin1String("awg_echo_target")).toString();
    if (!scanIsIpLiteralLoose(v.awgEchoTarget))
        v.awgEchoTarget.clear();
    if (!o.value(QLatin1String("nodes")).isArray() || !o.value(QLatin1String("upstream")).isArray())
        return fail("lists");
    for (const QJsonValue &nv : o.value(QLatin1String("nodes")).toArray()) {
        const QJsonObject n = nv.toObject();
        const QString id = n.value(QLatin1String("node_id")).toString();
        if (id.isEmpty() || id.size() > 64)
            continue;
        ScanManifestNode node;
        node.nodeId = id;
        node.tier = qMax(0, n.value(QLatin1String("tier")).toInt(0));
        node.rank = qMax(0, n.value(QLatin1String("rank")).toInt(0));
        node.crowdWorks = n.value(QLatin1String("crowd_works")).toBool(false);
        node.awgProbe = n.value(QLatin1String("awg_probe")).toBool(false);
        node.awgEchoTarget = n.value(QLatin1String("awg_echo_target")).toString();
        if (!scanIsIpLiteralLoose(node.awgEchoTarget))
            node.awgEchoTarget.clear();
        if (n.value(QLatin1String("score")).isDouble())
            node.score = qBound(0.0, n.value(QLatin1String("score")).toDouble(), 1.0);
        v.nodes << node;
    }
    for (const QJsonValue &uv : o.value(QLatin1String("upstream")).toArray()) {
        const QJsonObject u = uv.toObject();
        const QString pid = u.value(QLatin1String("profile_id")).toString();
        bool hexOk = pid.size() == 16;
        for (const QChar ch : pid)
            hexOk = hexOk && ((ch >= QLatin1Char('0') && ch <= QLatin1Char('9')) || (ch >= QLatin1Char('a') && ch <= QLatin1Char('f')));
        const QString cls = u.value(QLatin1String("probe_class")).toString();
        if (!hexOk || (cls != QLatin1String("single") && cls != QLatin1String("composite")))
            continue;
        ScanManifestUpstream e;
        e.profileId = pid;
        e.label = u.value(QLatin1String("label")).toString();
        e.ordinal = qMax(1, u.value(QLatin1String("ordinal")).toInt(1));
        e.labelCustom = u.value(QLatin1String("label_custom")).toBool(false);
        {
            const QJsonValue k = u.value(QLatin1String("kind"));
            e.kind = upstreamKindFromWire(!(k.isUndefined() || k.isNull()), k.toString());
        }
        e.countryCode = u.value(QLatin1String("country_code")).toString().toUpper();
        e.tier = qMax(1, u.value(QLatin1String("tier")).toInt(1));
        e.rank = qMax(0, u.value(QLatin1String("rank")).toInt(0));
        e.priority = u.value(QLatin1String("priority")).toInt(0);
        e.composite = cls == QLatin1String("composite");
        e.trimmed = u.value(QLatin1String("trimmed")).toBool(true); // absent = treat as trimmed (order only)
        e.legsTotal = qMax(0, u.value(QLatin1String("legs_total")).toInt(0));
        e.hasProjection = u.value(QLatin1String("projection")).isObject();
        e.crowdWorks = u.value(QLatin1String("crowd_works")).toBool(false);
        if (u.value(QLatin1String("score")).isDouble())
            e.score = qBound(0.0, u.value(QLatin1String("score")).toDouble(), 1.0);
        if (e.hasProjection) {
            const ScanDnsPlan plan = scanDnsPlanOf(u.value(QLatin1String("projection")).toObject());
            e.legTag = plan.legTag;
            e.legEntryIp = plan.entryIp;
            e.legEntryPort = plan.entryPort;
            e.dnsThroughLeg = plan.throughLeg && !e.composite && !e.trimmed;
            e.dnsResolvers = plan.resolvers;
        }
        v.upstream << e;
    }
    out = v;
    if (error)
        error->clear();
    return true;
}

// --- /v1/scan/candidates and /v1/scan/pool (contract 1.14.0) ------------------------------------------------

// One batch of a scope's rows the device has not seen in this scan (POST /v1/scan/candidates, signed with the
// context "tribe-scan-candidates-v1"). Its node / upstream rows use the manifest's row shapes (+ score); each
// provider row carries `node`, the exact stub SubscriptionNode the subscription would hold for it (the engine adds it
// to its pool before a pin: IScanEngine::offerScanNodes).
struct ScanCandidatesView {
    QString networkKey;
    QString scope;                 // default | country | whitelist
    QString country;
    qint64 upstreamRevision = 0;
    bool exhausted = false;        // nothing of the scope is left beyond this batch and `seen`
    QList<ScanManifestNode> nodes;
    QList<ScanManifestUpstream> upstream;
    QJsonArray providerNodes;      // the provider rows' `node` objects (SECRET-free stub nodes: no config)
    QHash<int, int> freeSeats;     // provider tier -> probe seats free now
};

inline bool scanCandidatesFromJson(const QJsonObject &o, ScanCandidatesView &out, QString *error = nullptr)
{
    const auto fail = [error](const char *why) {
        if (error)
            *error = QLatin1String(why);
        return false;
    };
    if (o.value(QLatin1String("type")).toString() != QLatin1String("scan_candidates"))
        return fail("type");
    if (o.value(QLatin1String("version")).toInt(-1) != 1)
        return fail("version");
    if (!o.value(QLatin1String("exhausted")).isBool() || !o.value(QLatin1String("nodes")).isArray()
        || !o.value(QLatin1String("upstream")).isArray() || !o.value(QLatin1String("probe_seats")).isArray())
        return fail("fields");
    // The rows are the manifest's shapes: the manifest's parser reads them (one rule for both lists).
    QJsonObject shim{{QStringLiteral("type"), QStringLiteral("scan_manifest")}, {QStringLiteral("version"), 1},
                     {QStringLiteral("network_key"), o.value(QLatin1String("network_key")).toString()},
                     {QStringLiteral("upstream_revision"), o.value(QLatin1String("upstream_revision")).toDouble(0)},
                     {QStringLiteral("upstream_eligible"), true},
                     {QStringLiteral("probe"), QJsonObject{{QStringLiteral("scheme"), QStringLiteral("tribe-probe-v1")}}},
                     {QStringLiteral("scan_token"), QJsonObject{{QStringLiteral("token"), QString()}}},
                     {QStringLiteral("nodes"), o.value(QLatin1String("nodes"))},
                     {QStringLiteral("upstream"), o.value(QLatin1String("upstream"))}};
    ScanManifestView v;
    QString why;
    if (!scanManifestViewFromJson(shim, v, &why))
        return fail("rows");
    ScanCandidatesView c;
    c.networkKey = o.value(QLatin1String("network_key")).toString();
    c.scope = o.value(QLatin1String("scope")).toString(QStringLiteral("default"));
    c.country = o.value(QLatin1String("country")).toString().toUpper();
    c.upstreamRevision = qint64(o.value(QLatin1String("upstream_revision")).toDouble(0));
    c.exhausted = o.value(QLatin1String("exhausted")).toBool();
    c.nodes = v.nodes;
    c.upstream = v.upstream;
    QSet<QString> kept;
    for (const ScanManifestUpstream &u : c.upstream)
        kept.insert(u.profileId);
    for (const QJsonValue &uv : o.value(QLatin1String("upstream")).toArray()) {
        const QJsonObject u = uv.toObject();
        const QJsonObject node = u.value(QLatin1String("node")).toObject();
        if (kept.contains(u.value(QLatin1String("profile_id")).toString()) && !node.isEmpty())
            c.providerNodes << node;
    }
    for (const QJsonValue &sv : o.value(QLatin1String("probe_seats")).toArray()) {
        const QJsonObject x = sv.toObject();
        if (x.value(QLatin1String("tier")).isDouble())
            c.freeSeats.insert(x.value(QLatin1String("tier")).toInt(), qMax(0, x.value(QLatin1String("free")).toInt(0)));
    }
    out = c;
    if (error)
        error->clear();
    return true;
}

// GET /v1/scan/pool: per country how many own listeners and provider profiles this device can use (the whole pool,
// not only the 24 stubs) and the white-list function's count. Counts only.
struct ScanPoolView {
    struct Country {
        QString countryCode;
        int own = 0;
        int provider = 0;
    };
    QList<Country> countries;
    int whitelist = 0;
    qint64 upstreamRevision = 0;
};

inline bool scanPoolFromJson(const QJsonObject &o, ScanPoolView &out)
{
    if (o.value(QLatin1String("type")).toString() != QLatin1String("scan_pool") || o.value(QLatin1String("version")).toInt(-1) != 1
        || !o.value(QLatin1String("countries")).isArray())
        return false;
    ScanPoolView p;
    p.upstreamRevision = qint64(o.value(QLatin1String("upstream_revision")).toDouble(0));
    for (const QJsonValue &cv : o.value(QLatin1String("countries")).toArray()) {
        const QJsonObject c = cv.toObject();
        const QString cc = c.value(QLatin1String("country_code")).toString().toUpper();
        if (cc.size() != 2)
            continue;
        p.countries << ScanPoolView::Country{cc, qMax(0, c.value(QLatin1String("own")).toInt(0)),
                                             qMax(0, c.value(QLatin1String("provider")).toInt(0))};
    }
    for (const QJsonValue &fv : o.value(QLatin1String("functions")).toArray()) {
        const QJsonObject f = fv.toObject();
        if (f.value(QLatin1String("kind")).toString() == QLatin1String("whitelist"))
            p.whitelist += qMax(0, f.value(QLatin1String("provider")).toInt(0));
    }
    out = p;
    return true;
}

// --- planner inputs ----------------------------------------------------------------------------------------

// An own node of the subscription as the coordinator sees it (pool row + the config builder's verdict).
struct ScanOwnNode {
    QString nodeId;            // "9:xray" (Xray listener) or "9" (AWG)
    QString label;             // display name of the location
    QString countryCode;
    ScanTransport transport = ScanTransport::Xray;
    QString transportVersion;  // AWG "3.1" etc., empty for Xray
    QString entryIp;           // where the path is dialled (Xray: the entry listener)
    int entryPort = 0;
    bool manualOnly = false;
    bool ru = false;
    bool configAvailable = true; // XrayConfigBuilder::coreConfig produced the exact tunnel config
};

// The live tunnel as the engine reports it (AvpnEngineQml: currentNodeId, dataFlowing, liveRttMs).
struct ScanCurrent {
    QString nodeId;            // empty = no tunnel target
    bool live = false;         // a tunnel exists (connected or reconnecting)
    bool connecting = false;   // an attempt is in progress
    bool dataFlowing = false;  // data passed (AEQ.h dataFlowing, not bare state == connected)
    bool failed = false;       // the last attempt ended in an error (engine Error)
    QString attemptNodeId;     // the target of a connect attempt in progress when it is not nodeId ("" = none)
    int liveRttMs = -1;
    ScanOrigin origin = ScanOrigin::Own;
    QString label;
    QString countryCode;
    ScanTransport transport = ScanTransport::Awg;
    QString transportVersion;
    int tier = 0;

    bool working() const { return live && dataFlowing && !nodeId.isEmpty(); }
};

// --- the planner's output per candidate --------------------------------------------------------------------

struct ScanCandidate {
    QString id;               // engine node id: what a tap pins ("9:xray", "up:<profile_id>")
    ScanOrigin origin = ScanOrigin::Own;
    QString profileId;        // upstream only
    QString label;
    QString countryCode;
    ScanTransport transport = ScanTransport::Xray;
    QString transportVersion;
    int tier = 0;
    int rank = 0;
    int priority = 0;
    bool composite = false;
    bool trimmed = false;
    ScanProbeKind kind = ScanProbeKind::None;
    QString notVerifiedReason; // order-only candidates: why (composite_unverifiable, no_full_probe, ...)
    QString entryIp;
    int entryPort = 0;
    bool needsLease = false;  // a provider probe: needs a probe lease (the seat; for full probes the config) first
    bool freshFailure = false;
    bool lastKnownGood = false; // network memory: first inside its tier (never across tiers)
    bool crowdWorks = false;  // a mark for the row only: never order, never verdict
    double score = -1;        // the server's crowd score of a /v1/scan/candidates row (0..1, -1 = none): its order only
    bool dnsThroughLeg = false; // provider single: the DNS plan routes every resolver through the leg
    int dnsResolvers = 0;
    bool followUp = false;    // a full probe scheduled to confirm a provider leg whose DNS plan was not proven
    QString awgEchoTarget;    // awg_mini: the prime echo target (the node's, else the manifest's; "" = none)
    qint64 reachAtMs = -1;    // earliest reach socket open, ms after the host start (-1 = no reach stage)
    qint64 costBytes = 0;     // projected bytes of its probe

    QString outcomeKind() const { return origin == ScanOrigin::Upstream ? QStringLiteral("upstream") : QStringLiteral("node"); }
    QString outcomeId() const { return origin == ScanOrigin::Upstream ? profileId : id; }
    bool hasReach() const { return reachAtMs >= 0 && !entryIp.isEmpty() && entryPort > 0; }
};

// --- facts of one probe (what the host measured) -----------------------------------------------------------

enum class ScanStage { Reach, Data };

struct ScanProbeFacts {
    QString id;
    ScanStage stage = ScanStage::Data;
    qint64 seq = 0;
    bool reachOk = false;     // reach item
    int reachMs = -1;
    int httpStatus = 0;       // data item: 0 = no HTTP answer
    int ttfb1Ms = -1;         // first request (all handshakes included)
    int rttMs = -1;           // first byte of the second request on the same connection
    int t64Ms = -1;           // first -> last byte of the data body
    int durationMs = -1;      // whole probe
    qint64 bytesRequested = 0;
    qint64 bytesReceived = 0;
    bool shaOk = false;       // digest computed locally by the tribe-probe-v1 scheme
    QString egressClass;      // X-Tribe-Egress-Class ("" absent)
    QString egressNode;       // X-Tribe-Egress-Node: our host node id the request left from ("" absent)
    qint64 egressAsn = 0;     // 0 unknown
    QString egressNetToken;   // X-Tribe-Net-Token
    bool dnsExercised = false; // leg probes: every resolver of the DNS plan answered through the leg
    // awg_mini (awg-probe-plan.md §3): the session's handshake and prime echoes (diagnostic only); its data
    // facts are the normal ones above (the sized /v1/probe through the node's NAT).
    bool handshakeOk = false;
    int handshakeMs = -1;
    int echoSent = 0;
    int echoReplies = 0;
    ScanProbeError error = ScanProbeError::None;
    qint64 spentBytes = 0;
    int retries = 0;
    qint64 startMs = -1;      // data item: the probe's start / end, ms after the host received scan_start
    qint64 endMs = -1;        // (monotonic; the base of the access attempts' at_ms); -1 = not reported
};

// --- cached result of one network (persisted by the coordinator) -------------------------------------------

struct ScanCachedRow {
    QString id;
    ScanOrigin origin = ScanOrigin::Own;
    QString profileId;
    QString label;
    QString countryCode;
    ScanTransport transport = ScanTransport::Xray;
    QString transportVersion;
    int tier = 0;
    int rank = 0;
    ScanClass cls = ScanClass::Works;
    ScanSpeed speed = ScanSpeed::None;
    int ms = -1;
    bool crowdWorks = false;
};

struct ScanCachedFailure {
    QString id;
    ScanClass cls = ScanClass::NoData;
    qint64 atMs = 0;
};

struct ScanCachedResult {
    QString networkKey;
    QString fingerprint;      // the weak local fingerprint of that scan's network (stored on the device only)
    qint64 savedAtMs = 0;     // wall clock of the end of that scan
    QString scope;            // the scope that scan covered ("" = all countries, a country code, "whitelist")
    QList<ScanCachedRow> rows;
    QList<ScanCachedFailure> failures;
    bool present() const { return savedAtMs > 0 && !networkKey.isEmpty(); }
};

inline QJsonObject scanCachedRowToJson(const ScanCachedRow &r)
{
    QJsonObject o;
    o.insert(QStringLiteral("id"), r.id);
    o.insert(QStringLiteral("origin"), r.origin == ScanOrigin::Upstream ? QStringLiteral("upstream") : QStringLiteral("own"));
    if (!r.profileId.isEmpty())
        o.insert(QStringLiteral("profile_id"), r.profileId);
    o.insert(QStringLiteral("label"), r.label);
    o.insert(QStringLiteral("cc"), r.countryCode);
    o.insert(QStringLiteral("transport"), QLatin1String(scanTransportName(r.transport)));
    if (!r.transportVersion.isEmpty())
        o.insert(QStringLiteral("transport_version"), r.transportVersion);
    o.insert(QStringLiteral("tier"), r.tier);
    o.insert(QStringLiteral("rank"), r.rank);
    o.insert(QStringLiteral("class"), QLatin1String(scanClassName(r.cls)));
    o.insert(QStringLiteral("speed"), QLatin1String(scanSpeedName(r.speed)));
    o.insert(QStringLiteral("ms"), r.ms);
    if (r.crowdWorks)
        o.insert(QStringLiteral("crowd_works"), true);
    return o;
}

inline bool scanCachedRowFromJson(const QJsonObject &o, ScanCachedRow &r)
{
    r = ScanCachedRow();
    r.id = o.value(QLatin1String("id")).toString();
    if (r.id.isEmpty() || r.id.size() > 64)
        return false;
    r.origin = o.value(QLatin1String("origin")).toString() == QLatin1String("upstream") ? ScanOrigin::Upstream : ScanOrigin::Own;
    r.profileId = o.value(QLatin1String("profile_id")).toString();
    r.label = o.value(QLatin1String("label")).toString();
    r.countryCode = o.value(QLatin1String("cc")).toString();
    r.transport = scanTransportFrom(o.value(QLatin1String("transport")).toString());
    r.transportVersion = o.value(QLatin1String("transport_version")).toString();
    r.tier = qMax(0, o.value(QLatin1String("tier")).toInt(0));
    r.rank = qMax(0, o.value(QLatin1String("rank")).toInt(0));
    r.cls = scanClassFrom(o.value(QLatin1String("class")).toString());
    r.speed = scanSpeedFrom(o.value(QLatin1String("speed")).toString());
    r.ms = o.value(QLatin1String("ms")).toInt(-1);
    r.crowdWorks = o.value(QLatin1String("crowd_works")).toBool(false);
    // Only working rows are cached as rows.
    return scanClassWorking(r.cls);
}

inline QJsonObject scanCachedResultToJson(const ScanCachedResult &c)
{
    QJsonObject o;
    o.insert(QStringLiteral("network_key"), c.networkKey);
    o.insert(QStringLiteral("fingerprint"), c.fingerprint);
    o.insert(QStringLiteral("saved_at_ms"), double(c.savedAtMs));
    if (!c.scope.isEmpty())
        o.insert(QStringLiteral("scope"), c.scope);
    QJsonArray rows, fails;
    for (const ScanCachedRow &r : c.rows)
        rows << scanCachedRowToJson(r);
    for (const ScanCachedFailure &f : c.failures) {
        QJsonObject fo;
        fo.insert(QStringLiteral("id"), f.id);
        fo.insert(QStringLiteral("class"), QLatin1String(scanClassName(f.cls)));
        fo.insert(QStringLiteral("at_ms"), double(f.atMs));
        fails << fo;
    }
    o.insert(QStringLiteral("rows"), rows);
    o.insert(QStringLiteral("failures"), fails);
    return o;
}

inline ScanCachedResult scanCachedResultFromJson(const QJsonObject &o)
{
    ScanCachedResult c;
    c.networkKey = o.value(QLatin1String("network_key")).toString();
    c.fingerprint = o.value(QLatin1String("fingerprint")).toString();
    c.savedAtMs = qint64(o.value(QLatin1String("saved_at_ms")).toDouble(0));
    c.scope = o.value(QLatin1String("scope")).toString();
    for (const QJsonValue &v : o.value(QLatin1String("rows")).toArray()) {
        ScanCachedRow r;
        if (scanCachedRowFromJson(v.toObject(), r))
            c.rows << r;
    }
    for (const QJsonValue &v : o.value(QLatin1String("failures")).toArray()) {
        const QJsonObject fo = v.toObject();
        ScanCachedFailure f;
        f.id = fo.value(QLatin1String("id")).toString();
        f.cls = scanClassFrom(fo.value(QLatin1String("class")).toString());
        f.atMs = qint64(fo.value(QLatin1String("at_ms")).toDouble(0));
        if (!f.id.isEmpty() && scanClassFailure(f.cls))
            c.failures << f;
    }
    return c;
}

// The persisted result's mark (TribeScanner::persistCache, since contract 1.10.0): its labels follow the «no
// Сервер N» rule. A provider row without a country stored by an earlier build carries the rejected «Сервер N»
// label (and may be the provider's balancer, which is no row now): dropped when the result is read back, so it is
// never shown as cache - the next scan finds it again under its new name. Pure.
inline constexpr char kScanCachedLabelRuleKey[] = "label_rule";
inline constexpr char kScanCachedLabelRule[] = "1.10";

inline void scanDropLegacyLabels(ScanCachedResult &c, const QJsonObject &stored)
{
    if (stored.value(QLatin1String(kScanCachedLabelRuleKey)).toString() == QLatin1String(kScanCachedLabelRule))
        return;
    for (int i = c.rows.size() - 1; i >= 0; --i)
        if (c.rows.at(i).origin == ScanOrigin::Upstream && c.rows.at(i).countryCode.isEmpty())
            c.rows.removeAt(i);
}

// The server list's figure of a node from the Scanner (owner 17.11: provider rows have no ICMP target). Source:
// the persisted result of the network the device is on now - the same network key AND weak fingerprint - and
// only while the Scanner itself would show that result when no scan can run (ScanMachine::cachedVisible outside
// a scan: at most worksTtlS (scan_cache_works_ttl_s) old; a clock up to 60 s behind tolerated, as rowShownAt).
// Only working rows (works / slow) are ever persisted, so a failed or «Не проверено» node gets nothing; a row
// without a figure (ms -1) is left out. The figure is the row's ms: rtt_ms of the data probe through that node
// (first byte of a second request on the same connection - one full-path round trip), ttfb1 when rtt is
// missing (ScanClass.h). Engine node id -> ms. Pure.
inline QHash<QString, int> scanListFigures(const ScanCachedResult &c, const QString &networkKey,
                                           const QString &fingerprint, qint64 nowMs, int worksTtlS)
{
    QHash<QString, int> out;
    if (!c.present() || networkKey.isEmpty() || fingerprint.isEmpty() || c.networkKey != networkKey
        || c.fingerprint != fingerprint)
        return out;
    const qint64 age = nowMs - c.savedAtMs;
    if (age < -60000 || age > qint64(worksTtlS) * 1000)
        return out;
    for (const ScanCachedRow &r : c.rows)
        if (scanClassWorking(r.cls) && r.ms >= 0)
            out.insert(r.id, r.ms);
    return out;
}

// Ids with a failure on this network younger than ttlS (fresh failures order a candidate last in its tier).
// A failure stamped in the future (clock moved back) counts as fresh.
inline QSet<QString> scanFreshFailures(const ScanCachedResult &c, qint64 nowMs, int ttlS)
{
    QSet<QString> out;
    for (const ScanCachedFailure &f : c.failures)
        if (nowMs - f.atMs < qint64(ttlS) * 1000)
            out.insert(f.id);
    return out;
}

} // namespace avpn
