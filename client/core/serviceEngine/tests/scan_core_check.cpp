// AVPN Scanner core (lane L1, scanner-client-plan.md): every rule of ScanTunables / ScanTypes / ScanClass /
// ScanPlan / ScanBudget / ScanOutcomes / ScanHostContract / ShadeQueue / ScanMachine, the
// artboard's demo scenarios on a fake clock (tests/scan_scenarios.h) and seeded property tests.
// Build/run: build_scan_core.sh
#include "scan_scenarios.h"

#include "../ScanMachine.h"
#include "../TuningStore.h"

#include <QCoreApplication>
#include <QRegularExpression>

#include <cmath>
#include <cstdio>
#include <limits>
#include <memory>
#include <random>

using namespace avpn;
using namespace scantest;

static int g_fail = 0, g_total = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        ++g_total;                                                                                 \
        if (!(cond)) {                                                                             \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                           \
            ++g_fail;                                                                              \
        }                                                                                          \
    } while (0)

static void checkMsg(bool ok, const QString &what)
{
    ++g_total;
    if (!ok) {
        ++g_fail;
        std::printf("FAIL %s\n", qPrintable(what));
    }
}

// --- tunables ---------------------------------------------------------------------------------------------

static void tunables()
{
    const ScanTunables d;
    const ScanTunables e = ScanTunables::fromNumbers({});
    for (const ScanTunableSpec &s : scanTunableTable()) {
        CHECK(d.*(s.field) == s.def);
        CHECK(e.*(s.field) == s.def);
        CHECK(s.lo <= s.def && s.def <= s.hi);
    }
    QMap<QString, double> n;
    n.insert(QStringLiteral("scan_stop_works"), 0);              // below the range
    n.insert(QStringLiteral("scan_stop_ms"), 1e9);               // above
    n.insert(QStringLiteral("scan_manual_cooldown_s"), std::numeric_limits<double>::quiet_NaN());
    n.insert(QStringLiteral("scan_class_fast_ms"), 900);
    n.insert(QStringLiteral("scan_class_slow_ms"), 300);         // below fast: raised to fast
    n.insert(QStringLiteral("scan_budget_scan_bytes"), 100000);
    const ScanTunables t = ScanTunables::fromNumbers(n);
    CHECK(t.stopWorks == 1);
    CHECK(t.stopMs == 60000);
    CHECK(t.manualCooldownS == 30);
    CHECK(t.classFastMs == 900 && t.classSlowMs == 900);
    CHECK(t.budgetScanBytes == 100000);
    QJsonObject j{{QStringLiteral("scan_stop_works"), 7}, {QStringLiteral("scan_poll_ms"), QStringLiteral("fast")}};
    const ScanTunables tj = ScanTunables::fromJson(j);
    CHECK(tj.stopWorks == 7 && tj.pollMs == 300);
    // every key of the table is distinct, named like the server's, documented
    QSet<QString> keys;
    const QRegularExpression keyRe(QStringLiteral("^scan_[a-z0-9_]+$"));
    int group3 = 0;
    for (const ScanTunableSpec &s : scanTunableTable()) {
        keys.insert(QLatin1String(s.key));
        CHECK(keyRe.match(QLatin1String(s.key)).hasMatch());
        CHECK(QByteArray(s.unit).size() > 0 && QByteArray(s.meaning).size() > 8 && s.group >= 1 && s.group <= 4);
        group3 += s.group == 3 ? 1 : 0;
    }
    CHECK(keys.size() == scanTunableTable().size());
    CHECK(group3 == 5 && !keys.contains(QStringLiteral("scan_auto_race_total_ms"))); // plan v2 C6 / C7; no light bound (19.11)
    // plan v2.2 §2.2b / §6 gap 7: exactly these names and defaults; cost clamps x0.5..x4
    const QMap<QString, int> gap7{{QStringLiteral("scan_cost_api_bytes"), 10240}, {QStringLiteral("scan_cost_manifest_bytes"), 270336},
                                  {QStringLiteral("scan_cost_batch_bytes"), 12288}, {QStringLiteral("scan_cost_config_bytes"), 32768},
                                  {QStringLiteral("scan_cost_tunnel_probe_bytes"), 82944},
                                  {QStringLiteral("scan_cost_outcomes_bytes"), 16384}, {QStringLiteral("scan_cost_netinfo_bytes"), 10240},
                                  {QStringLiteral("scan_drain_ms"), 2000}, {QStringLiteral("scan_freeze_ack_ms"), 1000}};
    int group4 = 0;
    for (const ScanTunableSpec &s : scanTunableTable()) {
        if (s.group != 4)
            continue;
        ++group4;
        CHECK(gap7.value(QLatin1String(s.key), -1) == s.def);
        if (QByteArray(s.key).startsWith("scan_cost_"))
            CHECK(s.lo == s.def / 2 && s.hi == (QByteArray(s.key) == "scan_cost_config_bytes" ? 1048576 : s.def * 4));
    }
    CHECK(group4 == gap7.size());
    CHECK(ScanTunables::fromNumbers({{QStringLiteral("scan_drain_ms"), 100}}).drainMs == 500
          && ScanTunables::fromNumbers({{QStringLiteral("scan_freeze_ack_ms"), 9000}}).freezeAckMs == 5000);
    // the live probe's reservation always covers warm + body + 2 x 8 KiB TLS
    CHECK(ScanTunables::fromNumbers({{QStringLiteral("scan_stage2_bytes"), 262144}, {QStringLiteral("scan_cost_tunnel_probe_bytes"), 41472}})
              .costTunnelProbeBytes == 1024 + 262144 + 16384);
}

// --- classification ------------------------------------------------------------------------------------------

static ScanProbeFacts goodData(int rtt = 60, int t64 = 160, int ttfb1 = 320)
{
    ScanProbeFacts f;
    f.stage = ScanStage::Data;
    f.httpStatus = 200;
    f.bytesRequested = f.bytesReceived = 65536;
    f.shaOk = true;
    f.ttfb1Ms = ttfb1;
    f.rttMs = rtt;
    f.t64Ms = t64;
    f.durationMs = 900;
    f.egressClass = QStringLiteral("tribe-node");
    return f;
}

// The host items of an own Xray probe answered alike on every connection (the Xray burst, ScanPlan.h): the data item,
// then its burst parts "<id>.<n>" (4 KB bodies when it carried its whole body) with the seqs that follow its own.
// Any other item as it is.
static QList<ScanProbeFacts> withBurst(const ScanProbeFacts &f)
{
    QList<ScanProbeFacts> l{f};
    if (f.stage != ScanStage::Data || !f.id.endsWith(QLatin1String(":xray")))
        return l;
    for (int n = 1; n < kScanXrayBurstParts; ++n) {
        ScanProbeFacts b = f;
        b.id = f.id + QStringLiteral(".%1").arg(n);
        b.seq = f.seq > 0 ? f.seq + n : 0;
        if (f.bytesReceived == f.bytesRequested && f.bytesReceived > 0)
            b.bytesRequested = b.bytesReceived = kScanXrayBurstBytes;
        l << b;
    }
    return l;
}

static ScanClassifyInput ownIn(const ScanProbeFacts &f, ScanProbeKind kind = ScanProbeKind::XrayFull)
{
    ScanClassifyInput in;
    in.origin = ScanOrigin::Own;
    in.kind = kind;
    in.candidateId = QStringLiteral("4:xray");
    in.hasReach = true;
    in.data = f;
    if (in.data.egressClass == QLatin1String("tribe-node") && in.data.egressNode.isEmpty())
        in.data.egressNode = QStringLiteral("4"); // the host of "4:xray"
    in.access.netToken = QStringLiteral("net-access");
    in.access.asn = 64500;
    return in;
}

static ScanClassifyInput upIn(ScanProbeFacts f, ScanProbeKind kind = ScanProbeKind::XrayFull)
{
    f.egressClass = QStringLiteral("other");
    f.egressAsn = 64600;
    f.egressNetToken = QStringLiteral("net-exit");
    ScanClassifyInput in = ownIn(f, kind);
    in.origin = ScanOrigin::Upstream;
    in.hasReach = false;
    return in;
}

static void classify()
{
    const ScanTunables t;
    ScanVerdict v = scanClassify(ownIn(goodData()), t);
    CHECK(v.cls == ScanClass::Works && v.speed == ScanSpeed::Fast && v.ms == 60 && v.reason == QLatin1String("egress_tribe_node"));
    CHECK(scanClassify(ownIn(goodData(300, 400)), t).speed == ScanSpeed::Medium);   // q = 500
    CHECK(scanClassify(ownIn(goodData(400, 0)), t).speed == ScanSpeed::Fast);       // q = 400: fast boundary inclusive
    CHECK(scanClassify(ownIn(goodData(401, 0)), t).speed == ScanSpeed::Medium);
    CHECK(scanClassify(ownIn(goodData(1200, 0)), t).speed == ScanSpeed::Medium);    // slow boundary inclusive
    CHECK(scanClassify(ownIn(goodData(1201, 0)), t).speed == ScanSpeed::Slow);
    v = scanClassify(ownIn(goodData(60, 160, 1600)), t);
    CHECK(v.cls == ScanClass::Slow && v.speed == ScanSpeed::Slow);
    CHECK(scanClassify(ownIn(goodData(60, 160, 1500)), t).cls == ScanClass::Works); // 1500 not past the limit
    CHECK(scanClassify(ownIn(goodData(60, 3100)), t).cls == ScanClass::Slow);
    ScanProbeFacts nortt = goodData(-1, 100, 300);
    CHECK(scanClassify(ownIn(nortt), t).ms == 300); // rtt missing: ttfb1
    // reach
    ScanClassifyInput r = ownIn(goodData());
    r.reachFailed = true;
    CHECK(scanClassify(r, t).cls == ScanClass::Unreachable && scanClassify(r, t).reason == QLatin1String("reach_timeout"));
    r.reachError = ScanProbeError::ReachRefused;
    CHECK(scanClassify(r, t).reason == QLatin1String("reach_refused"));
    // nothing came back
    ScanProbeFacts none;
    none.bytesRequested = 65536;
    none.error = ScanProbeError::Dial;
    CHECK(scanClassify(upIn(none), t).cls == ScanClass::Unreachable);
    CHECK(scanClassify(ownIn(none), t).cls == ScanClass::NoData); // reach was ok: the path carried nothing
    // data rules
    ScanProbeFacts f = goodData();
    f.httpStatus = 500;
    CHECK(scanClassify(ownIn(f), t).reason == QLatin1String("http"));
    f = goodData();
    f.bytesReceived = 20000;
    CHECK(scanClassify(ownIn(f), t).reason == QLatin1String("short"));
    f.error = ScanProbeError::Stalled;
    CHECK(scanClassify(ownIn(f), t).reason == QLatin1String("stalled"));
    f = goodData();
    f.bytesReceived = 70000;
    CHECK(scanClassify(ownIn(f), t).reason == QLatin1String("oversize"));
    f = goodData();
    f.shaOk = false;
    CHECK(scanClassify(ownIn(f), t).reason == QLatin1String("digest"));
    f = goodData(60, 160, 3500);
    CHECK(scanClassify(ownIn(f), t).reason == QLatin1String("ttfb_timeout"));
    f = goodData();
    f.durationMs = 6000;
    CHECK(scanClassify(ownIn(f), t).reason == QLatin1String("total_timeout"));
    f = goodData();
    f.bytesRequested = 0;
    f.bytesReceived = 0;
    CHECK(scanClassify(ownIn(f), t).cls == ScanClass::NoData);
    for (ScanProbeError e : {ScanProbeError::Memory, ScanProbeError::Budget, ScanProbeError::Cancelled, ScanProbeError::Deadline,
                             ScanProbeError::Config, ScanProbeError::Internal}) {
        f = goodData();
        f.error = e;
        CHECK(scanClassify(ownIn(f), t).cls == ScanClass::NotVerified);
    }
    // own path: the exit not in the whoami map is «not verified» (hidden), never a leak; the egress node, when
    // the server names it, must be the candidate's host
    f = goodData();
    f.egressClass = QStringLiteral("other");
    CHECK(scanClassify(ownIn(f), t).cls == ScanClass::NotVerified && scanClassify(ownIn(f), t).reason == QLatin1String("egress_unmapped"));
    f.egressClass = QStringLiteral("upstream-known");
    CHECK(scanClassify(ownIn(f), t).cls == ScanClass::NotVerified);
    f.egressClass.clear();
    CHECK(scanClassify(ownIn(f), t).cls == ScanClass::NotVerified && scanClassify(ownIn(f), t).reason == QLatin1String("egress_unknown")); // C2
    f = goodData();
    f.egressNetToken = QStringLiteral("net-access");
    CHECK(scanClassify(ownIn(f), t).cls == ScanClass::Leak);
    ScanClassifyInput nodeIn = ownIn(goodData());
    nodeIn.candidateId = QStringLiteral("4:xray");
    nodeIn.data.egressNode = QStringLiteral("4");
    CHECK(scanClassify(nodeIn, t).cls == ScanClass::Works);
    nodeIn.data.egressNode = QStringLiteral("9");
    CHECK(scanClassify(nodeIn, t).cls == ScanClass::NotVerified && scanClassify(nodeIn, t).reason == QLatin1String("egress_other_node"));
    nodeIn.data.egressNode.clear();
    CHECK(scanClassify(nodeIn, t).cls == ScanClass::NotVerified && scanClassify(nodeIn, t).reason == QLatin1String("egress_node_missing")); // C2
    CHECK(scanHostPartOf(QStringLiteral("9:xray")) == QLatin1String("9") && scanHostPartOf(QStringLiteral("9")) == QLatin1String("9"));
    // provider path (D7 rules of UpstreamVerdict.h)
    CHECK(scanClassify(upIn(goodData()), t).cls == ScanClass::Works);
    ScanClassifyInput u = upIn(goodData());
    u.data.egressClass = QStringLiteral("tribe-node");
    CHECK(scanClassify(u, t).cls == ScanClass::Leak);
    u = upIn(goodData());
    u.data.egressNetToken = QStringLiteral("net-access");
    CHECK(scanClassify(u, t).cls == ScanClass::Leak);
    u = upIn(goodData());
    u.data.egressAsn = 64500;
    u.data.egressNetToken.clear();
    CHECK(scanClassify(u, t).cls == ScanClass::Leak);
    u = upIn(goodData());
    u.data.egressClass = QStringLiteral("upstream-known");
    u.data.egressAsn = 64500; // upstream-known outweighs an equal ASN
    u.data.egressNetToken.clear();
    CHECK(scanClassify(u, t).cls == ScanClass::Works);
    u = upIn(goodData());
    u.data.egressAsn = 0;
    u.data.egressNetToken.clear();
    u.access = ScanAccess();
    CHECK(scanClassify(u, t).cls == ScanClass::NotVerified && scanClassify(u, t).reason == QLatin1String("unverifiable")); // C1: never works
    // legs
    ScanClassifyInput leg = upIn(goodData(), ScanProbeKind::XrayLeg);
    leg.dnsThroughLeg = true;
    leg.dnsResolvers = 1;
    leg.data.dnsExercised = true;
    CHECK(scanClassify(leg, t).cls == ScanClass::Works);
    leg.data.dnsExercised = false;
    CHECK(scanClassify(leg, t).reason == QLatin1String("leg_dns"));
    leg.dnsResolvers = 0; // no DNS module: nothing to exercise
    CHECK(scanClassify(leg, t).cls == ScanClass::Works);
    leg.dnsThroughLeg = false;
    CHECK(scanClassify(leg, t).reason == QLatin1String("leg_dns"));
    leg.dnsThroughLeg = true;
    leg.trimmed = true;
    CHECK(scanClassify(leg, t).reason == QLatin1String("leg_trimmed"));
    leg.trimmed = false;
    leg.composite = true;
    CHECK(scanClassify(leg, t).reason == QLatin1String("leg_composite"));
    leg.composite = false;
    leg.dnsThroughLeg = false;
    leg.data.egressClass = QStringLiteral("tribe-node");
    CHECK(scanClassify(leg, t).cls == ScanClass::Leak); // a leak the leg proved needs no DNS proof
    ScanClassifyInput legFail = upIn(goodData(), ScanProbeKind::XrayLeg);
    legFail.data.bytesReceived = 100;
    CHECK(scanClassify(legFail, t).cls == ScanClass::NoData); // a failed leg is a verdict
    CHECK(scanClassify(ownIn(goodData(), ScanProbeKind::XrayLeg), t).cls == ScanClass::Works); // own leg: no DNS rule
    // awg_mini (awg-probe-plan.md §3): handshake, then the sized download through the node's NAT with the
    // egress node equal to the probed node
    ScanClassifyInput a = ownIn(goodData(50, 200), ScanProbeKind::AwgMini);
    a.candidateId = QStringLiteral("3");
    a.hasReach = false;
    a.data.handshakeOk = true;
    a.data.egressNode = QStringLiteral("3");
    CHECK(scanClassify(a, t).cls == ScanClass::Works && scanClassify(a, t).ms == 50 && scanClassify(a, t).speed == ScanSpeed::Fast);
    a.data.echoReplies = 0; // the prime echoes are diagnostic only
    CHECK(scanClassify(a, t).cls == ScanClass::Works);
    a.data.egressNode = QStringLiteral("5");
    CHECK(scanClassify(a, t).cls == ScanClass::NotVerified && scanClassify(a, t).reason == QLatin1String("egress_other_node"));
    a.data.egressNode.clear();
    CHECK(scanClassify(a, t).reason == QLatin1String("egress_node_missing"));
    a.data.egressNode = QStringLiteral("3");
    a.data.egressClass = QStringLiteral("other");
    CHECK(scanClassify(a, t).cls == ScanClass::NotVerified && scanClassify(a, t).reason == QLatin1String("egress_unmapped"));
    a.data.egressClass.clear();
    CHECK(scanClassify(a, t).cls == ScanClass::NotVerified); // an AWG verdict needs the class
    a.data.egressClass = QStringLiteral("tribe-node");
    a.data.shaOk = false;
    CHECK(scanClassify(a, t).cls == ScanClass::NoData);
    a.data.shaOk = true;
    a.data.bytesReceived = 100;
    CHECK(scanClassify(a, t).cls == ScanClass::NoData);
    a.data.bytesReceived = 65536;
    a.data.ttfb1Ms = 1600;
    CHECK(scanClassify(a, t).cls == ScanClass::Slow);
    a.data.ttfb1Ms = 300;
    a.data.egressNetToken = QStringLiteral("net-access");
    CHECK(scanClassify(a, t).cls == ScanClass::Leak);
    a.data.egressNetToken.clear();
    a.data.handshakeOk = false;
    CHECK(scanClassify(a, t).cls == ScanClass::Unreachable && scanClassify(a, t).reason == QLatin1String("handshake"));
    ScanProbeFacts nothing;
    nothing.handshakeOk = true;
    nothing.bytesRequested = 65536;
    ScanClassifyInput an = ownIn(nothing, ScanProbeKind::AwgMini);
    an.hasReach = false;
    CHECK(scanClassify(an, t).cls == ScanClass::NoData); // handshake but no data: the node carries nothing
    // live speed
    CHECK(scanSpeedOfLive(-1, t) == ScanSpeed::Medium);
    CHECK(scanSpeedOfLive(100, t) == ScanSpeed::Fast);
    CHECK(scanSpeedBars(ScanSpeed::Fast) == 5 && scanSpeedBars(ScanSpeed::Medium) == 3 && scanSpeedBars(ScanSpeed::Slow) == 2
          && scanSpeedBars(ScanSpeed::None) == 0);
    // wire names never map an unknown value to a good one
    CHECK(scanClassFrom(QStringLiteral("perfect")) == ScanClass::NotVerified);
    CHECK(scanProbeErrorFrom(QStringLiteral("whatever")) == ScanProbeError::Internal);
    CHECK(scanProbeKindFrom(QStringLiteral("magic")) == ScanProbeKind::None);
}

// --- DNS plan and manifest view ----------------------------------------------------------------------------

static QJsonObject projection(const QString &dnsRoute, const QString &catchRoute = QStringLiteral("leg"), int legs = 1,
                              bool standalone = true, const QString &addr = QStringLiteral("203.0.113.5"))
{
    QJsonArray l;
    for (int i = 0; i < legs; ++i)
        l << QJsonObject{{QStringLiteral("tag"), i == 0 ? QStringLiteral("p") : QStringLiteral("q")},
                         {QStringLiteral("standalone"), standalone},
                         {QStringLiteral("outbound"), QJsonObject{{QStringLiteral("settings"), QJsonObject{{QStringLiteral("servers"),
                             QJsonArray{QJsonObject{{QStringLiteral("address"), addr}, {QStringLiteral("port"), 8443}}}}}}}}};
    const QJsonObject route{{QStringLiteral("route"), catchRoute}, {QStringLiteral("leg"), QStringLiteral("p")}};
    QJsonArray dns;
    if (!dnsRoute.isEmpty())
        dns << QJsonObject{{QStringLiteral("address"), QStringLiteral("8.8.8.8")}, {QStringLiteral("route"), dnsRoute},
                           {QStringLiteral("leg"), QStringLiteral("p")}};
    return QJsonObject{{QStringLiteral("legs"), l}, {QStringLiteral("catch_all"), QJsonObject{{QStringLiteral("tcp"), route}, {QStringLiteral("udp"), route}}},
                       {QStringLiteral("dns"), dns}};
}

static void dnsPlanAndManifest()
{
    ScanDnsPlan p = scanDnsPlanOf(projection(QStringLiteral("leg")));
    CHECK(p.throughLeg && p.resolvers == 1 && p.legTag == QLatin1String("p") && p.entryIp == QLatin1String("203.0.113.5") && p.entryPort == 8443);
    CHECK(scanDnsPlanOf(projection(QString())).throughLeg); // no DNS module
    CHECK(scanDnsPlanOf(projection(QStringLiteral("none"))).throughLeg); // fakedns
    CHECK(!scanDnsPlanOf(projection(QStringLiteral("direct"))).throughLeg);
    CHECK(scanDnsPlanOf(projection(QStringLiteral("direct"))).reason == QLatin1String("dns_direct"));
    CHECK(!scanDnsPlanOf(projection(QStringLiteral("balancer"))).throughLeg);
    CHECK(!scanDnsPlanOf(projection(QStringLiteral("leg"), QStringLiteral("balancer"))).throughLeg);
    CHECK(!scanDnsPlanOf(projection(QStringLiteral("leg"), QStringLiteral("leg"), 2)).throughLeg);
    CHECK(!scanDnsPlanOf(projection(QStringLiteral("leg"), QStringLiteral("leg"), 1, false)).throughLeg);
    CHECK(scanDnsPlanOf(projection(QStringLiteral("leg"), QStringLiteral("leg"), 1, true, QStringLiteral("edge.example"))).entryIp.isEmpty());
    CHECK(scanIsIpLiteral(QStringLiteral("10.1.2.3")) && scanIsIpLiteral(QStringLiteral("2001:db8::1")));
    CHECK(!scanIsIpLiteral(QStringLiteral("10.1.2")) && !scanIsIpLiteral(QStringLiteral("256.1.1.1")) && !scanIsIpLiteral(QStringLiteral("a.b.c.d")));

    World w = baseWorld("m", hostMac(), ScanNetKind::Wifi);
    QJsonObject body = manifestBody(w);
    ScanManifestView v;
    QString err;
    CHECK(scanManifestViewFromJson(body, v, &err) && err.isEmpty());
    CHECK(v.nodes.size() == 11 && v.upstream.size() == 4 && v.upstreamEligible);
    CHECK(v.upstream.at(0).crowdWorks && v.upstream.at(0).dnsThroughLeg && v.upstream.at(0).legEntryIp == QLatin1String("203.0.113.10"));
    CHECK(!v.upstream.at(1).dnsThroughLeg); // composite
    CHECK(!v.upstream.at(2).dnsThroughLeg); // DNS direct
    QJsonObject bad = body;
    bad.insert(QStringLiteral("type"), QStringLiteral("config"));
    CHECK(!scanManifestViewFromJson(bad, v, &err) && err == QLatin1String("type"));
    bad = body;
    bad.remove(QStringLiteral("scan_token"));
    CHECK(!scanManifestViewFromJson(bad, v, &err));
    bad = body;
    QJsonArray ups = bad.value(QStringLiteral("upstream")).toArray();
    QJsonObject u0 = ups.at(0).toObject();
    u0.insert(QStringLiteral("profile_id"), QStringLiteral("NOT-HEX"));
    ups[0] = u0;
    QJsonObject u1 = ups.at(1).toObject();
    u1.remove(QStringLiteral("trimmed"));
    ups[1] = u1;
    bad.insert(QStringLiteral("upstream"), ups);
    CHECK(scanManifestViewFromJson(bad, v, &err) && v.upstream.size() == 3 && v.upstream.at(0).trimmed); // dropped, absent trimmed = trimmed
}

// --- planner ---------------------------------------------------------------------------------------------

static ScanPlanInput planInput(const ScanHostCaps &caps, ScanNetKind net = ScanNetKind::Wifi, const QString &current = QStringLiteral("1"))
{
    World w = baseWorld("p", caps, net);
    ScanPlanInput in;
    scanManifestViewFromJson(manifestBody(w), in.manifest);
    for (const QJsonValue &v : manifestArgs(w).value(QStringLiteral("own_nodes")).toArray())
        in.ownNodes << ownFrom(v.toObject());
    in.current = liveOf(w, current, true);
    in.caps = caps;
    in.net = net;
    return in;
}

static const ScanCandidate *findC(const QList<ScanCandidate> &l, const QString &id)
{
    for (const ScanCandidate &c : l)
        if (c.id == id)
            return &c;
    return nullptr;
}

static bool excluded(const ScanPlan &p, const QString &id, const char *why)
{
    for (const ScanPlanExclusion &e : p.excluded)
        if (e.id == id && e.reason == QLatin1String(why))
            return true;
    return false;
}

static void plan()
{
    // minimal iPhone host (full probes only)
    ScanPlan p = buildScanPlan(planInput(hostIosMinimal()));
    CHECK(p.fullConcurrency == 1 && p.legConcurrency == 0 && p.awgConcurrency == 0);
    CHECK(excluded(p, QStringLiteral("1"), "current"));
    CHECK(excluded(p, QStringLiteral("2"), "awg_no_host") && excluded(p, QStringLiteral("6"), "awg_no_host"));
    CHECK(findC(p.probe, QStringLiteral("4:xray")) && findC(p.probe, QStringLiteral("4:xray"))->kind == ScanProbeKind::XrayFull);
    CHECK(findC(p.probe, up(1)) && findC(p.probe, up(1))->kind == ScanProbeKind::XrayFull && findC(p.probe, up(1))->needsLease);
    CHECK(findC(p.orderOnly, up(2)) && findC(p.orderOnly, up(2))->notVerifiedReason == QLatin1String("composite_unverifiable"));
    CHECK(!findC(p.probe, QStringLiteral("1")));
    // macOS host with legs, DNS plans and awg_mini
    p = buildScanPlan(planInput(hostMac()));
    CHECK(p.fullConcurrency == 2 && p.legConcurrency == 6 && p.awgConcurrency == 0); // scan_awg_concurrency default 0
    CHECK(findC(p.probe, QStringLiteral("4:xray"))->kind == ScanProbeKind::XrayLeg);
    CHECK(!findC(p.probe, QStringLiteral("2")) && excluded(p, QStringLiteral("2"), "awg_off")); // switch off by default
    {
        ScanPlanInput a = planInput(hostMac());
        a.awgMiniEnabled = true;
        a.awgProbeIpKnown = true;
        a.tunables.awgConcurrency = 2;
        a.manifest.nodes[3].awgProbe = false; // "3"
        a.current.attemptNodeId = QStringLiteral("6");
        const ScanPlan q = buildScanPlan(a);
        CHECK(q.awgConcurrency == 2); // its own number, not the net concurrency
        CHECK(findC(q.probe, QStringLiteral("2")) && findC(q.probe, QStringLiteral("2"))->kind == ScanProbeKind::AwgMini
              && findC(q.probe, QStringLiteral("2"))->reachAtMs == -1);
        CHECK(excluded(q, QStringLiteral("3"), "awg_no_peer"));
        CHECK(excluded(q, QStringLiteral("6"), "awg_live"));     // a connect attempt's target
        CHECK(excluded(q, QStringLiteral("1"), "current"));      // the live tunnel's node
        CHECK(findC(q.probe, QStringLiteral("2"))->awgEchoTarget == QLatin1String("10.8.1.1")); // manifest-level fallback
        a.manifest.nodes[1].awgEchoTarget = QStringLiteral("10.8.0.9");                          // "2": its own
        CHECK(findC(buildScanPlan(a).probe, QStringLiteral("2"))->awgEchoTarget == QLatin1String("10.8.0.9"));
        a.tunables.awgConcurrency = 0;
        CHECK(excluded(buildScanPlan(a), QStringLiteral("2"), "awg_off"));
        a.tunables.awgConcurrency = 2;
        a.awgProbeIpKnown = false;
        CHECK(excluded(buildScanPlan(a), QStringLiteral("2"), "awg_no_api_ip"));
        a.awgProbeIpKnown = true;
        a.awgAddressKnown = false; // the device's own tunnel address unknown: «Не проверено», not absent
        {
            const ScanPlan na = buildScanPlan(a);
            const ScanCandidate *o = findC(na.orderOnly, QStringLiteral("2"));
            CHECK(!findC(na.probe, QStringLiteral("2")) && o && o->notVerifiedReason == QLatin1String("awg_no_address")
                  && !excluded(na, QStringLiteral("2"), "awg_no_address"));
            CHECK(excluded(na, QStringLiteral("3"), "awg_no_peer")); // the other rules come first
        }
        a.awgAddressKnown = true;
        a.caps.maxAwgConcurrent = 1;
        CHECK(buildScanPlan(a).awgConcurrency == 1);
        a.caps.maxAwgConcurrent = 0;
        CHECK(excluded(buildScanPlan(a), QStringLiteral("2"), "awg_no_host"));
        a.caps.maxAwgConcurrent = 4;
        a.current = ScanCurrent();
        a.current.nodeId = QStringLiteral("2");
        a.current.connecting = true; // an attempt in progress on "2" (not yet live): never probed either
        CHECK(excluded(buildScanPlan(a), QStringLiteral("2"), "current"));
        TuningStore::reset();
        CHECK(!scanAwgMiniFlag());
        TuningStore::set({}, {{QStringLiteral("scanner_awg_mini"), true}});
        CHECK(scanAwgMiniFlag());
        TuningStore::reset();
    }
    CHECK(findC(p.probe, up(1))->kind == ScanProbeKind::XrayLeg && findC(p.probe, up(1))->dnsThroughLeg);
    CHECK(findC(p.probe, up(3))->kind == ScanProbeKind::XrayLeg && !findC(p.probe, up(3))->dnsThroughLeg);
    CHECK(findC(p.probe, up(2))->kind == ScanProbeKind::XrayFull && findC(p.probe, up(2))->reachAtMs == -1);
    // a host without DNS plans: provider legs are never verdicts by themselves
    ScanHostCaps noDns = hostMac();
    noDns.dnsPlan = false;
    CHECK(!findC(buildScanPlan(planInput(noDns)).probe, up(1))->dnsThroughLeg);
    // cellular concurrency
    p = buildScanPlan(planInput(hostMac(), ScanNetKind::Cellular));
    CHECK(p.legConcurrency == 4 && p.fullConcurrency == 2 && p.awgConcurrency == 0); // AWG off by default
    // nothing probeable
    ScanHostCaps none;
    none.maxFullConcurrent = 0;
    p = buildScanPlan(planInput(none));
    CHECK(p.probe.isEmpty() && findC(p.orderOnly, QStringLiteral("4:xray")) && findC(p.orderOnly, up(1)));
    CHECK(findC(p.orderOnly, up(1))->notVerifiedReason == QLatin1String("no_probe") && !findC(p.orderOnly, up(1))->needsLease);
    // trimmed single or no projection -> full; exclusions
    ScanPlanInput in = planInput(hostMac());
    in.manifest.upstream[0].trimmed = true;
    in.manifest.upstream[2].hasProjection = false;
    in.ownNodes[3].manualOnly = true;   // "3"
    in.ownNodes[4].ru = true;           // "4:xray"
    in.ownNodes[5].configAvailable = false; // "5:xray"
    ScanManifestNode stray;
    stray.nodeId = QStringLiteral("99:xray");
    in.manifest.nodes << stray;
    in.restrictCountry.clear();
    p = buildScanPlan(in);
    CHECK(findC(p.probe, up(1))->kind == ScanProbeKind::XrayFull && findC(p.probe, up(3))->kind == ScanProbeKind::XrayFull);
    CHECK(!excluded(p, QStringLiteral("3"), "manual_only")); // manual_only is probed (18.11); "3" is AmneziaWG: its own gates
    {
        // the in-app iOS host alternates own and provider candidates (18.11); every other host keeps the tier order
        ScanHostCaps app = hostMac();
        app.platform = QStringLiteral("ios-app");
        const ScanPlan pi = buildScanPlan(planInput(app));
        const ScanPlan pt = buildScanPlan(planInput(hostMac()));
        CHECK(pi.probe.size() == pt.probe.size() && pi.probe.size() >= 4);
        bool alternates = true;
        int own = 0, up = 0;
        for (const ScanCandidate &c : pt.probe)
            (c.origin == ScanOrigin::Upstream ? up : own) += 1;
        for (int i = 0; i + 1 < qMin(own, up) * 2; ++i)
            alternates = alternates && pi.probe.at(i).origin != pi.probe.at(i + 1).origin;
        CHECK(alternates && pt.probe.first().origin == ScanOrigin::Own && pt.probe.last().origin == ScanOrigin::Upstream);
        QList<ScanCandidate> lk = pt.probe;
        lk.last().lastKnownGood = true;
        CHECK(scanInterleaveOrigins(lk).first().id == pt.probe.last().id); // last-known-good leads whatever its side
    }
    {
        ScanPlanInput m = planInput(hostMac());
        m.ownNodes[4].manualOnly = true; // "4:xray", an own Xray node
        const ScanPlan pm = buildScanPlan(m);
        CHECK(findC(pm.probe, m.ownNodes[4].nodeId) && findC(pm.probe, m.ownNodes[4].nodeId)->kind != ScanProbeKind::None);
    }
    CHECK(excluded(p, QStringLiteral("4:xray"), "ru") && excluded(p, QStringLiteral("5:xray"), "no_config")
          && excluded(p, QStringLiteral("99:xray"), "not_in_pool"));
    in = planInput(hostMac());
    in.restrictCountry = QStringLiteral("de");
    p = buildScanPlan(in);
    for (const ScanCandidate &c : p.probe)
        CHECK(c.countryCode == QLatin1String("DE"));
    // order: tier, LKG inside its tier, fresh failure last in its tier, rank, id
    in = planInput(hostMac());
    in.lastKnownGood = up(3);
    in.freshFailures.insert(QStringLiteral("2:xray"));
    p = buildScanPlan(in);
    int lastTier = -1;
    for (const ScanCandidate &c : p.probe) {
        CHECK(c.tier >= lastTier);
        lastTier = c.tier;
    }
    int iUp3 = -1, iUp1 = -1, i2x = -1, i10 = -1;
    for (int i = 0; i < p.probe.size(); ++i) {
        if (p.probe.at(i).id == up(3)) iUp3 = i;
        if (p.probe.at(i).id == up(1)) iUp1 = i;
        if (p.probe.at(i).id == QLatin1String("2:xray")) i2x = i;
        if (p.probe.at(i).id == QLatin1String("10:xray")) i10 = i;
    }
    CHECK(iUp3 < iUp1);   // LKG first inside tier 1
    CHECK(i10 < iUp3);    // but never before tier 0
    CHECK(i2x > i10);     // fresh failure last in tier 0
    // reach offsets: stagger, per-entry-IP spacing; awg / provider full never; reachStage off -> none
    p = buildScanPlan(planInput(hostIosMinimal()));
    QMap<QString, QList<qint64>> perIp;
    for (const ScanCandidate &c : p.probe)
        if (c.reachAtMs >= 0)
            perIp[c.entryIp] << c.reachAtMs;
    for (auto it = perIp.begin(); it != perIp.end(); ++it)
        for (int i = 1; i < it.value().size(); ++i)
            CHECK(it.value().at(i) - it.value().at(i - 1) >= 300);
    CHECK(findC(p.probe, QStringLiteral("2:xray"))->reachAtMs == 0);
    CHECK(findC(p.probe, QStringLiteral("4:xray"))->reachAtMs == 300); // slot 1, but the same IP as 2:xray: spaced
    CHECK(findC(p.probe, QStringLiteral("5:xray"))->reachAtMs == 100); // slot 2, another IP
    CHECK(findC(p.probe, up(1))->reachAtMs == -1);                     // provider full: no reach stage
    ScanHostCaps noReach = hostMac();
    noReach.reachStage = false;
    for (const ScanCandidate &c : buildScanPlan(planInput(noReach)).probe)
        CHECK(c.reachAtMs == -1);
    // projection = sum of costs
    p = buildScanPlan(planInput(hostMac()));
    qint64 sum = 0, burst = 0;
    for (const ScanCandidate &c : p.probe) {
        sum += scanProbeTotalCostBytes(c, planInput(hostMac()).tunables);
        burst += scanXrayBurstPartsOf(c) > 1 ? 1 : 0;
    }
    CHECK(p.projectedBytes == sum && sum > 0);
    // an own Xray probe is projected with its 3 burst parts (warm + 4 KB + TLS each); providers and AWG stay single
    CHECK(burst > 0);
    for (const ScanCandidate &c : p.probe)
        CHECK(scanXrayBurstPartsOf(c) == (c.origin == ScanOrigin::Own && c.kind != ScanProbeKind::AwgMini ? 4 : 1)
              && scanProbeTotalCostBytes(c, ScanTunables()) - c.costBytes == (scanXrayBurstPartsOf(c) - 1) * (1024 + 4096 + 16384));
    // the parts must run at once: as many as the pool runs together (a pool of 1 = the single connection)
    for (const auto &[caps, want] : {std::pair<ScanHostCaps, int>{hostIosMinimal(), 1}, {hostMacMinimal(), 2}}) {
        bool seen = false;
        for (const ScanCandidate &c : buildScanPlan(planInput(caps)).probe)
            if (c.origin == ScanOrigin::Own && c.kind == ScanProbeKind::XrayFull) {
                seen = true;
                CHECK(scanXrayBurstPartsOf(c) == want);
            }
        CHECK(seen);
    }
    // the shape: data part as given, parts "<id>.<n>" with 4 KB bodies, no reach, no entry IP, their own cost
    {
        ScanHostCandidate d;
        d.id = QStringLiteral("4:xray");
        d.kind = ScanProbeKind::XrayFull;
        d.config = QStringLiteral("{}");
        d.entryIp = QStringLiteral("10.0.0.1");
        d.entryPort = 443;
        d.reachAtMs = 300;
        d.costBytes = 83456;
        const QList<ScanHostCandidate> parts = scanXrayBurstOf(d, 4, ScanTunables());
        CHECK(parts.size() == 4 && parts.at(0).id == d.id && parts.at(0).costBytes == 83456 && parts.at(0).reachAtMs == 300);
        for (int n = 1; n < parts.size(); ++n)
            CHECK(parts.at(n).id == QStringLiteral("4:xray.%1").arg(n) && parts.at(n).bytes == 4096 && parts.at(n).reachAtMs == -1
                  && parts.at(n).entryIp.isEmpty() && parts.at(n).entryPort == 0 && parts.at(n).config == d.config
                  && parts.at(n).costBytes == 1024 + 4096 + 16384);
        CHECK(scanXrayBurstOf(d, 1, ScanTunables()).size() == 1);
        int part = -1;
        CHECK(scanXrayBurstBaseOf(QStringLiteral("4:xray.3"), &part) == d.id && part == 3);
        CHECK(scanXrayBurstBaseOf(d.id, &part) == d.id && part == 0);
        CHECK(scanXrayBurstBaseOf(QStringLiteral("up:a.b"), &part) == QStringLiteral("up:a.b") && part == 0);
        CHECK(scanXrayBurstBaseOf(QStringLiteral("x.0"), &part) == QStringLiteral("x.0") && part == 0);
    }
    // upstream not eligible
    in = planInput(hostMac());
    in.manifest.upstreamEligible = false;
    for (const ScanCandidate &c : buildScanPlan(in).probe)
        CHECK(c.origin == ScanOrigin::Own);
    // the follow-up candidate
    const ScanCandidate fu = scanFollowUpOf(*findC(buildScanPlan(planInput(hostMac())).probe, up(3)), ScanTunables());
    CHECK(fu.kind == ScanProbeKind::XrayFull && fu.followUp && fu.reachAtMs == -1 && scanProbeIdOf(fu) == up(3) + QStringLiteral("#full"));
}

// --- budget ----------------------------------------------------------------------------------------------

static void budget()
{
    const ScanTunables t;
    CHECK(scanProbeCostBytes(ScanProbeKind::XrayFull, false, t) == 1024 + 65536 + 2 * 8192);
    CHECK(scanProbeCostBytes(ScanProbeKind::XrayLeg, true, t) == 512 + 1024 + 65536 + 2 * 8192);
    CHECK(scanProbeCostBytes(ScanProbeKind::AwgMini, false, t) == 2048 + 300 + 1024 + 65536 + 2 * 8192); // ~85 KB
    CHECK(scanProbeCostBytes(ScanProbeKind::None, false, t) == 0);
    ScanBudgetLedger l;
    const qint64 n = kT0;
    l.add(n - 50 * 60000, 2000000, true);
    l.add(n - 10 * 60000, 2000000, true);
    l.add(n - 5 * 60000, 3000000, false);
    l.add(n, 0, true);  // ignored
    l.add(n, -5, true); // ignored
    CHECK(l.entries().size() == 3);
    CHECK(l.spentInHour(n, true) == 4000000 && l.spentInHour(n, false) == 7000000);
    CHECK(l.leftInHour(n, 5242880, true) == 1242880);
    CHECK(l.leftInHour(n, 1000, true) == 0); // never negative
    CHECK(l.msUntilLeft(n, 5242880, 1000000, true) == 0);
    CHECK(l.msUntilLeft(n, 5242880, 1500000, true) == 10 * 60000); // the oldest entry ages out in 10 min
    CHECK(l.msUntilLeft(n, 5242880, 6000000, true) == -1);
    l.prune(n + 51 * 60000);
    CHECK(l.entries().size() == 1 && l.entries().at(0).bytes == 3000000);
    // decisions
    ScanBudgetLedger e;
    ScanBudgetDecision d = decideScanBudget(e, n, ScanNetKind::Wifi, 2000000, 0, t);
    CHECK(d.allowed && d.capBytes == -1);
    d = decideScanBudget(e, n, ScanNetKind::Cellular, 2000000, 0, t);
    CHECK(d.allowed && d.capBytes == t.budgetScanBytes);
    ScanBudgetLedger full;
    full.add(n - 20 * 60000, 4500000, true);
    d = decideScanBudget(full, n, ScanNetKind::Cellular, 1000000, 0, t);
    CHECK(!d.allowed && d.hourly && d.retryInMs == 40 * 60000);
    CHECK(scanRetryMinutes(d.retryInMs) == 40);
    d = decideScanBudget(full, n, ScanNetKind::Cellular, 500000, 0, t);
    CHECK(d.allowed && d.capBytes == 5242880 - 4500000);
    d = decideScanBudget(full, n, ScanNetKind::Wifi, 1000000, 0, t);
    CHECK(d.allowed && d.capBytes == -1); // the cellular hour does not limit Wi-Fi
    d = decideScanBudget(full, n, ScanNetKind::Wifi, 1000000, 5000000, t);
    CHECK(!d.allowed); // the server's device budget counts every network
    d = decideScanBudget(e, n, ScanNetKind::Cellular, 100 * 1024 * 1024, 0, t);
    CHECK(d.allowed); // a projection above every cap is judged against the cap itself
    ScanBudgetLedger fut;
    fut.add(n + 30 * 60000, 5000000, true); // clock moved back: still counts
    CHECK(fut.spentInHour(n, true) == 5000000);
    CHECK(scanRetryMinutes(1) == 1 && scanRetryMinutes(60001) == 2 && scanRetryMinutes(0) == 0);
    // persistence
    const ScanBudgetLedger back = ScanBudgetLedger::fromJson(full.toJson());
    CHECK(back.entries().size() == 1 && back.entries().at(0).bytes == 4500000 && back.entries().at(0).cellular);
    QJsonArray junk{QJsonObject{{QStringLiteral("at_ms"), -1}, {QStringLiteral("bytes"), 10}}, QStringLiteral("x"),
                    QJsonObject{{QStringLiteral("at_ms"), 5}, {QStringLiteral("bytes"), -10}}};
    CHECK(ScanBudgetLedger::fromJson(junk).entries().isEmpty());
}

// --- outcomes -------------------------------------------------------------------------------------------

static void outcomes()
{
    ScanOutcomeCollector c;
    c.begin(QStringLiteral("cell:250-02:4g"));
    ScanOutcomeItem it;
    it.kind = QStringLiteral("node");
    it.id = QStringLiteral("9:xray");
    it.outcome = ScanClass::Works;
    it.ttfbMs = 420;
    it.bytes = 65536;
    it.durationMs = 900;
    CHECK(c.add(it));
    it.outcome = ScanClass::NoData;
    CHECK(!c.add(it)); // once per collection
    ScanOutcomeItem nv = it;
    nv.id = QStringLiteral("10:xray");
    nv.outcome = ScanClass::NotVerified;
    CHECK(!c.add(nv));
    ScanOutcomeItem cache = it;
    cache.id = QStringLiteral("11:xray");
    cache.stage = ScanOutcomeStage::Cache;
    CHECK(!c.add(cache));
    ScanOutcomeItem badKind = it;
    badKind.id = QStringLiteral("12");
    badKind.kind = QStringLiteral("other");
    CHECK(!c.add(badKind));
    ScanOutcomeItem longId = it;
    longId.id = QString(65, QLatin1Char('a'));
    CHECK(!c.add(longId));
    ScanOutcomeItem up1 = it;
    up1.kind = QStringLiteral("upstream");
    up1.id = QStringLiteral("00000000000000a1"); // same id string, other kind: separate
    up1.ttfbMs = 900000;
    up1.bytes = -1;
    up1.durationMs = 5000000;
    CHECK(c.add(up1));
    ScanOutcomeItem withProbe = it;
    withProbe.id = QStringLiteral("13:xray");
    withProbe.outcome = ScanClass::Works;
    withProbe.probe = QStringLiteral("leg");
    withProbe.rttMs = 61;
    CHECK(c.add(withProbe));
    ScanOutcomeItem failProbe = it;
    failProbe.id = QStringLiteral("14:xray");
    failProbe.outcome = ScanClass::NoData;
    failProbe.probe = QStringLiteral("teleport"); // unknown kind: not sent
    failProbe.rttMs = 61;                        // no rtt for a failure
    CHECK(c.add(failProbe));
    const QJsonArray pi = c.batches().at(0).value(QStringLiteral("items")).toArray();
    CHECK(pi.at(2).toObject().value(QStringLiteral("probe")).toString() == QLatin1String("leg")
          && pi.at(2).toObject().value(QStringLiteral("rtt_ms")).toInt() == 61);
    CHECK(!pi.at(3).toObject().contains(QStringLiteral("probe")) && !pi.at(3).toObject().contains(QStringLiteral("rtt_ms")));
    const QList<QJsonObject> b = c.batches();
    CHECK(b.size() == 1 && b.at(0).value(QStringLiteral("items")).toArray().size() == 4);
    const QJsonObject j = b.at(0).value(QStringLiteral("items")).toArray().at(1).toObject();
    CHECK(j.value(QStringLiteral("ttfb_ms")).toInt() == 600000 && !j.contains(QStringLiteral("bytes"))
          && j.value(QStringLiteral("duration_ms")).toInt() == 3600000);
    CHECK(j.value(QStringLiteral("network_key")).toString() == QLatin1String("cell:250-02:4g"));
    ScanOutcomeCollector many;
    many.begin(QStringLiteral("wifi"));
    for (int i = 0; i < 70; ++i) {
        ScanOutcomeItem x = it;
        x.id = QString::number(i);
        many.add(x);
    }
    const QList<QJsonObject> mb = many.batches();
    CHECK(mb.size() == 3 && mb.at(0).value(QStringLiteral("items")).toArray().size() == 32
          && mb.at(2).value(QStringLiteral("items")).toArray().size() == 6);
    ScanOutcomeCollector badKey;
    badKey.begin(QStringLiteral("cell:250-02"));
    badKey.add(it);
    CHECK(badKey.batches().isEmpty());
    CHECK(scanNetworkKeyValid(QStringLiteral("cell:asn:12389:4g")) && scanNetworkKeyValid(QStringLiteral("wifi:asn:1"))
          && scanNetworkKeyValid(QStringLiteral("unknown")) && !scanNetworkKeyValid(QStringLiteral("cell:unknown"))
          && !scanNetworkKeyValid(QStringLiteral("wifi:bssid")));
}

// --- host contract -----------------------------------------------------------------------------------------

static ScanStartRequest sampleStart()
{
    ScanStartRequest r;
    r.scanId = QStringLiteral("scan-1-1");
    r.deadlineMs = 9000;
    r.maxBytes = 1572864;
    r.limits = scanHostLimitsFrom(ScanTunables(), 1, 4, 2);
    r.probeBase = QStringLiteral("https://api.example.test");
    r.token = QStringLiteral("tsc1.TEST");
    r.access.asn = 64500;
    r.access.netToken = QStringLiteral("net-access");
    ScanHostCandidate a;
    a.id = QStringLiteral("4:xray");
    a.kind = ScanProbeKind::XrayLeg;
    a.config = QStringLiteral("{\"outbound\":{}}");
    a.entryIp = QStringLiteral("10.0.0.1");
    a.entryPort = 443;
    a.reachAtMs = 0;
    a.costBytes = 83456;
    ScanHostCandidate b;
    b.id = up(3) + QStringLiteral("#full");
    b.kind = ScanProbeKind::XrayFull;
    b.config = QStringLiteral("{}");
    b.profileId = QStringLiteral("00000000000000a3");
    b.earlyRetry = true;
    b.costBytes = 82944;
    ScanHostCandidate c;
    c.id = QStringLiteral("2");
    c.kind = ScanProbeKind::AwgMini;
    c.config = QStringLiteral("{\"interface\":{}}");
    r.candidates << a << b << c;
    return r;
}

static QByteArray withField(QJsonObject o, const QString &path, const QJsonValue &v)
{
    const QStringList p = path.split(QLatin1Char('.'));
    if (p.size() == 1) {
        if (v.isUndefined())
            o.remove(p.at(0));
        else
            o.insert(p.at(0), v);
    } else {
        QJsonObject inner = o.value(p.at(0)).toObject();
        if (v.isUndefined())
            inner.remove(p.at(1));
        else
            inner.insert(p.at(1), v);
        o.insert(p.at(0), inner);
    }
    return scanCompact(o);
}

static void hostContract()
{
    const ScanStartRequest s = sampleStart();
    const QJsonObject j = scanEncodeStart(s);
    ScanHostRequest d;
    QString detail;
    CHECK(scanDecodeRequest(scanCompact(j), d, &detail) == ScanHostError::None);
    CHECK(d.action == ScanHostAction::Start && d.start.scanId == s.scanId && d.start.deadlineMs == 9000 && d.start.maxBytes == 1572864);
    CHECK(d.start.limits == s.limits && d.start.token == s.token && d.start.access.asn == 64500 && d.start.access.netToken == s.access.netToken);
    CHECK(d.start.candidates.size() == 3 && d.start.candidates.at(0).entryIp == QLatin1String("10.0.0.1")
          && d.start.candidates.at(1).profileId == QLatin1String("00000000000000a3") && d.start.candidates.at(1).earlyRetry
          && d.start.candidates.at(2).kind == ScanProbeKind::AwgMini && d.start.candidates.at(2).reachAtMs == -1);
    ScanStartRequest noCap = s;
    noCap.maxBytes = -1;
    CHECK(scanEncodeStart(noCap).value(QStringLiteral("max_bytes")).isNull());
    CHECK(scanDecodeRequest(scanCompact(scanEncodeStart(noCap)), d) == ScanHostError::None && d.start.maxBytes == -1);
    // other requests
    CHECK(scanDecodeRequest(scanCompact(scanEncodeCaps()), d) == ScanHostError::None && d.action == ScanHostAction::Caps);
    CHECK(scanDecodeRequest(scanCompact(scanEncodePoll(QStringLiteral("x"), 7)), d) == ScanHostError::None && d.since == 7);
    CHECK(scanDecodeRequest(scanCompact(scanEncodeCancel(QStringLiteral("x"))), d) == ScanHostError::None && d.action == ScanHostAction::Cancel);
    CHECK(scanDecodeRequest(scanCompact(scanEncodeAdd(QStringLiteral("x"), s.candidates)), d) == ScanHostError::None && d.candidates.size() == 3);
    // refusals
    CHECK(scanDecodeRequest(QByteArrayLiteral("{\"action\":\"scan_teleport\"}"), d) == ScanHostError::UnknownAction);
    CHECK(scanDecodeRequest(QByteArrayLiteral("{\"action\":\"upstream_lease_set\"}"), d) == ScanHostError::UnknownAction);
    CHECK(scanDecodeRequest(withField(j, QStringLiteral("version"), QStringLiteral("tribe-scan-v2")), d) == ScanHostError::Version);
    CHECK(scanDecodeRequest(withField(j, QStringLiteral("probe.token"), QJsonValue::Undefined), d, &detail) == ScanHostError::BadRequest
          && detail == QLatin1String("probe.token"));
    CHECK(scanDecodeRequest(withField(j, QStringLiteral("probe.base"), QStringLiteral("http://plain")), d) == ScanHostError::BadRequest);
    CHECK(scanDecodeRequest(withField(j, QStringLiteral("deadline_ms"), 10), d) == ScanHostError::BadRequest);
    CHECK(scanDecodeRequest(withField(j, QStringLiteral("deadline_ms"), 9000.5), d) == ScanHostError::BadRequest);
    CHECK(scanDecodeRequest(withField(j, QStringLiteral("limits.concurrency"), 99), d) == ScanHostError::BadRequest);
    CHECK(scanDecodeRequest(withField(j, QStringLiteral("limits.leg_concurrency"), QJsonValue::Undefined), d) == ScanHostError::None
          && d.start.limits.legConcurrency == 0); // optional for an app that sends no pool fields
    CHECK(scanDecodeRequest(withField(j, QStringLiteral("scan_id"), QString()), d) == ScanHostError::BadRequest);
    CHECK(scanDecodeRequest(QByteArrayLiteral("[1,2]"), d) == ScanHostError::BadRequest);
    CHECK(scanDecodeRequest(QByteArrayLiteral("{nope"), d) == ScanHostError::BadRequest);
    QJsonObject badCand = j;
    QJsonArray cs = badCand.value(QStringLiteral("candidates")).toArray();
    QJsonObject c0 = cs.at(0).toObject();
    c0.remove(QStringLiteral("config"));
    cs[0] = c0;
    badCand.insert(QStringLiteral("candidates"), cs);
    CHECK(scanDecodeRequest(scanCompact(badCand), d) == ScanHostError::BadRequest);
    c0 = cs.at(1).toObject();
    c0.insert(QStringLiteral("kind"), QStringLiteral("magic"));
    cs[0] = c0;
    badCand.insert(QStringLiteral("candidates"), cs);
    CHECK(scanDecodeRequest(scanCompact(badCand), d) == ScanHostError::BadRequest);
    QJsonObject unknownFields = j;
    unknownFields.insert(QStringLiteral("future_field"), QJsonObject{{QStringLiteral("x"), 1}});
    CHECK(scanDecodeRequest(scanCompact(unknownFields), d) == ScanHostError::None);
    // replies: caps of a minimal host (no new fields) and of a full host
    ScanHostReply r = scanDecodeReply(QByteArrayLiteral(
        "{\"type\":\"scan_caps\",\"version\":\"tribe-scan-v1\",\"max_full_concurrent\":1,\"can_verify_composite\":false,"
        "\"needs_vpn\":true,\"kinds\":[\"xray_full\"],\"mem_mb\":31}"));
    CHECK(r.kind == ScanHostReplyKind::Caps && r.caps.maxFullConcurrent == 1 && r.caps.maxLegConcurrent == 0 && r.caps.maxAwgConcurrent == 0
          && r.caps.reachStage && !r.caps.dnsPlan && r.caps.needsVpn && r.caps.memMb == 31);
    r = scanDecodeReply(scanCompact(scanEncodeCapsReply(hostMac(), {QStringLiteral("xray_full"), QStringLiteral("xray_leg"), QStringLiteral("awg_mini")})));
    CHECK(r.kind == ScanHostReplyKind::Caps && r.caps.maxLegConcurrent == 6 && r.caps.maxAwgConcurrent == 4 && r.caps.dnsPlan
          && r.caps.canVerifyComposite && r.caps.platform == QLatin1String("macos"));
    r = scanDecodeReply(scanCompact(scanEncodeCapsReply(hostMac(), {QStringLiteral("xray_full")})));
    CHECK(r.caps.maxLegConcurrent == 0 && r.caps.maxAwgConcurrent == 0 && !r.caps.dnsPlan); // kinds gate the pools
    r = scanDecodeReply(QByteArrayLiteral("{\"type\":\"scan_caps\",\"version\":\"tribe-scan-v9\"}"));
    CHECK(r.kind == ScanHostReplyKind::Error && r.error == ScanHostError::Version);
    r = scanDecodeReply(QByteArrayLiteral("{\"type\":\"scan_caps\",\"version\":\"tribe-scan-v1\",\"max_full_concurrent\":-1,"
                                          "\"can_verify_composite\":false,\"needs_vpn\":true,\"kinds\":[]}"));
    CHECK(r.kind == ScanHostReplyKind::Error && r.error == ScanHostError::Malformed);
    r = scanDecodeReply(scanCompact(scanEncodeAck(QStringLiteral("scan-1-1"), 3, 40)));
    CHECK(r.kind == ScanHostReplyKind::Ack && r.accepted == 3 && r.memMb == 40);
    // progress
    ScanHostProgress p;
    p.scanId = QStringLiteral("scan-1-1");
    p.seq = 3;
    p.phase = QStringLiteral("data");
    ScanProbeFacts reach;
    reach.id = QStringLiteral("4:xray");
    reach.stage = ScanStage::Reach;
    reach.seq = 1;
    reach.reachOk = true;
    reach.reachMs = 80;
    ScanProbeFacts data = goodData();
    data.id = QStringLiteral("4:xray");
    data.seq = 2;
    data.spentBytes = 83000;
    data.dnsExercised = true;
    ScanProbeFacts awg;
    awg.id = QStringLiteral("2");
    awg.seq = 3;
    awg.handshakeOk = true;
    awg.handshakeMs = 70;
    awg.echoSent = 1;
    awg.echoReplies = 1;
    awg.httpStatus = 200;
    awg.rttMs = 50;
    awg.bytesRequested = awg.bytesReceived = 65536;
    awg.shaOk = true;
    awg.egressClass = QStringLiteral("tribe-node");
    awg.egressNode = QStringLiteral("2");
    p.items << reach << data << awg;
    data.startMs = 120;
    data.endMs = 830;
    p.items.clear();
    p.items << reach << data << awg;
    p.bytesSpent = 200000;
    p.memMb = 33;
    p.access.attempted = true;
    p.access.httpAnswered = true;
    p.access.facts.asn = 64500;
    p.access.facts.netToken = QStringLiteral("net-access");
    p.access.atMs = 0;
    p.access.hasGen = true;
    p.access.gen = ScanNetSource{QStringLiteral("ne"), 0x0123456789abcdefULL, 4};
    p.hasGen = true;
    p.gen = p.access.gen;
    r = scanDecodeReply(scanCompact(scanEncodeProgress(p)));
    CHECK(r.kind == ScanHostReplyKind::Progress && r.progress.items.size() == 3 && r.progress.bytesSpent == 200000
          && r.progress.access.hasFacts() && r.progress.access.facts.asn == 64500 && r.progress.access.atMs == 0
          && r.progress.access.hasGen && r.progress.access.gen == p.access.gen && r.progress.hasGen && !r.progress.accessClose.attempted
          && !r.progress.finalTotals);
    CHECK(r.progress.items.at(1).startMs == 120 && r.progress.items.at(1).endMs == 830 && r.progress.items.at(0).startMs == -1);
    {
        // the 64-bit epoch survives the wire as 16 hex characters
        const QJsonObject g = scanEncodeProgress(p).value(QStringLiteral("gen")).toObject();
        CHECK(g.value(QStringLiteral("epoch")).toString() == QLatin1String("0123456789abcdef") && g.value(QStringLiteral("counter")).toInt() == 4);
        // the closing attempt and the final totals
        ScanHostProgress fin = p;
        fin.items.clear();
        fin.done = true;
        fin.finalTotals = true;
        fin.reason = QStringLiteral("cancelled");
        fin.accessClose.attempted = true;
        fin.accessClose.httpAnswered = false;
        fin.accessClose.atMs = 7400;
        fin.accessClose.facts.asn = 5; // no HTTP answer: facts are dropped on decode
        ScanHostReply rf = scanDecodeReply(scanCompact(scanEncodeProgress(fin)));
        CHECK(rf.kind == ScanHostReplyKind::Progress && rf.progress.finalTotals && rf.progress.accessClose.networkFailed()
              && rf.progress.accessClose.atMs == 7400 && rf.progress.accessClose.facts.asn == 0 && rf.progress.access.hasFacts());
        QJsonObject fj = scanEncodeProgress(fin);
        CHECK(fj.value(QStringLiteral("final")).toBool() && fj.value(QStringLiteral("access_close")).toObject().value(QStringLiteral("http_answered")) == QJsonValue(false));
        fj.insert(QStringLiteral("done"), false); // final without done
        CHECK(scanDecodeReply(scanCompact(fj)).error == ScanHostError::Malformed);
        fj = scanEncodeProgress(fin);
        fj.insert(QStringLiteral("access_close"), QJsonObject{{QStringLiteral("http_answered"), false}}); // attempted missing
        CHECK(scanDecodeReply(scanCompact(fj)).error == ScanHostError::Malformed);
        fj = scanEncodeProgress(fin);
        fj.insert(QStringLiteral("access_close"), QJsonObject{{QStringLiteral("attempted"), true}}); // http_answered missing
        CHECK(scanDecodeReply(scanCompact(fj)).error == ScanHostError::Malformed);
        fj = scanEncodeProgress(fin);
        fj.insert(QStringLiteral("gen"), QJsonObject{{QStringLiteral("source"), QStringLiteral("ne")}, {QStringLiteral("epoch"), 5}, {QStringLiteral("counter"), 1}});
        CHECK(scanDecodeReply(scanCompact(fj)).error == ScanHostError::Malformed); // epoch must be 16 hex chars
        fj = scanEncodeProgress(fin);
        fj.insert(QStringLiteral("access"), QJsonValue::Null);
        fj.insert(QStringLiteral("access_close"), QJsonObject{{QStringLiteral("attempted"), false}});
        rf = scanDecodeReply(scanCompact(fj));
        CHECK(rf.kind == ScanHostReplyKind::Progress && !rf.progress.access.attempted && !rf.progress.accessClose.attempted);
        // an item that ends before it starts
        QJsonObject pj2 = scanEncodeProgress(p);
        QJsonArray it2 = pj2.value(QStringLiteral("items")).toArray();
        QJsonObject d2 = it2.at(1).toObject();
        d2.insert(QStringLiteral("end_ms"), 100);
        it2[1] = d2;
        pj2.insert(QStringLiteral("items"), it2);
        CHECK(scanDecodeReply(scanCompact(pj2)).error == ScanHostError::Malformed);
        // freeze: the request, its ack {spent, reserved} (both required), the cancel ack with optional totals
        CHECK(scanDecodeRequest(scanCompact(scanEncodeFreeze(QStringLiteral("x"))), d) == ScanHostError::None && d.action == ScanHostAction::Freeze);
        ScanHostReply fa = scanDecodeReply(scanCompact(scanEncodeFreezeAck(QStringLiteral("scan-1-1"), 90000, 165888)));
        CHECK(fa.kind == ScanHostReplyKind::FreezeAck && fa.scanId == QLatin1String("scan-1-1") && fa.bytesSpent == 90000 && fa.bytesReserved == 165888);
        CHECK(scanDecodeReply(QByteArrayLiteral("{\"type\":\"scan_freeze_ack\",\"scan_id\":\"s\",\"spent\":1}")).error == ScanHostError::Malformed);
        CHECK(scanDecodeReply(QByteArrayLiteral("{\"type\":\"scan_freeze_ack\",\"scan_id\":\"s\",\"bytes_spent\":1,\"bytes_reserved\":2}")).error
              == ScanHostError::Malformed); // the plan's names: spent / reserved
        ScanHostReply ca = scanDecodeReply(scanCompact(scanEncodeCancelAck(QStringLiteral("scan-1-1"), 123456, 30)));
        CHECK(ca.kind == ScanHostReplyKind::Ack && ca.finalTotals && ca.bytesSpent == 123456);
        ca = scanDecodeReply(scanCompact(scanEncodeAck(QStringLiteral("scan-1-1"), 0, 30)));
        CHECK(ca.kind == ScanHostReplyKind::Ack && !ca.finalTotals);
        // the start request carries the attempt's cost and path
        CHECK(scanEncodeStart(s).value(QStringLiteral("limits")).toObject().value(QStringLiteral("netinfo_cost_bytes")).toInt() == 10240
              && scanEncodeStart(s).value(QStringLiteral("probe")).toObject().value(QStringLiteral("netinfo_path")).toString() == QLatin1String("/v1/netinfo"));
        CHECK(scanDecodeRequest(withField(j, QStringLiteral("probe.netinfo_path"), QStringLiteral("v1/netinfo")), d) == ScanHostError::BadRequest);
        CHECK(scanDecodeRequest(withField(j, QStringLiteral("probe.netinfo_path"), QJsonValue::Undefined), d) == ScanHostError::None
              && d.start.netinfoPath == QLatin1String("/v1/netinfo") && d.start.limits.netinfoCostBytes == 10240);
    }
    CHECK(r.progress.items.at(0).stage == ScanStage::Reach && r.progress.items.at(0).reachOk && r.progress.items.at(0).reachMs == 80);
    CHECK(r.progress.items.at(1).shaOk && r.progress.items.at(1).rttMs == 60 && r.progress.items.at(1).egressClass == QLatin1String("tribe-node")
          && r.progress.items.at(1).dnsExercised);
    CHECK(r.progress.items.at(2).handshakeOk && r.progress.items.at(2).echoReplies == 1 && r.progress.items.at(2).handshakeMs == 70
          && r.progress.items.at(2).egressNode == QLatin1String("2") && r.progress.items.at(2).shaOk);
    QJsonObject pj = scanEncodeProgress(p);
    QJsonArray items = pj.value(QStringLiteral("items")).toArray();
    QJsonObject badItem = items.at(2).toObject();
    badItem.insert(QStringLiteral("echo_replies"), 2); // more replies than sent
    items[2] = badItem;
    QJsonObject bad = pj;
    bad.insert(QStringLiteral("items"), items);
    CHECK(scanDecodeReply(scanCompact(bad)).error == ScanHostError::Malformed);
    items = pj.value(QStringLiteral("items")).toArray();
    badItem = items.at(1).toObject();
    badItem.insert(QStringLiteral("sha_ok"), QStringLiteral("yes"));
    items[1] = badItem;
    bad.insert(QStringLiteral("items"), items);
    CHECK(scanDecodeReply(scanCompact(bad)).error == ScanHostError::Malformed);
    items = pj.value(QStringLiteral("items")).toArray();
    badItem = items.at(1).toObject();
    badItem.remove(QStringLiteral("bytes"));
    items[1] = badItem;
    bad.insert(QStringLiteral("items"), items);
    CHECK(scanDecodeReply(scanCompact(bad)).error == ScanHostError::Malformed); // required field
    bad = pj;
    bad.insert(QStringLiteral("phase"), QStringLiteral("dreaming"));
    CHECK(scanDecodeReply(scanCompact(bad)).error == ScanHostError::Malformed);
    bad = pj;
    bad.remove(QStringLiteral("bytes_spent"));
    CHECK(scanDecodeReply(scanCompact(bad)).error == ScanHostError::Malformed);
    QJsonObject extra = pj;
    extra.insert(QStringLiteral("android_only_detail"), 5);
    CHECK(scanDecodeReply(scanCompact(extra)).kind == ScanHostReplyKind::Progress); // unknown fields ignored
    // errors
    r = scanDecodeReply(QByteArrayLiteral("{\"error\":\"unknown_action\"}"));
    CHECK(r.kind == ScanHostReplyKind::Error && r.error == ScanHostError::UnknownAction);
    r = scanDecodeReply(QByteArrayLiteral("{\"error\":\"memory\",\"mem_mb\":42,\"need_mb\":12}"));
    CHECK(r.error == ScanHostError::Memory && r.memMb == 42 && r.needMb == 12);
    CHECK(scanDecodeReply(QByteArrayLiteral("{\"error\":\"no_vpn\"}")).error == ScanHostError::NoVpn);
    CHECK(scanDecodeReply(QByteArrayLiteral("{\"error\":\"eaten_by_grue\"}")).error == ScanHostError::Other);
    CHECK(scanDecodeReply(QByteArrayLiteral("{\"error\":5}")).error == ScanHostError::Malformed);
    CHECK(scanDecodeReply(QByteArrayLiteral("not json")).error == ScanHostError::Malformed);
    CHECK(scanDecodeReply(QByteArrayLiteral("{\"type\":\"scan_mystery\"}")).error == ScanHostError::Malformed);
    CHECK(scanDecodeReply(QByteArray()).error == ScanHostError::Malformed);
    // redaction
    const QJsonObject red = scanRedactForLog(j).toObject();
    const QByteArray redBytes = scanCompact(red);
    CHECK(!redBytes.contains("tsc1.TEST") && !redBytes.contains("outbound") && !redBytes.contains("net-access") && redBytes.contains("<redacted>"));
    CHECK(red.value(QStringLiteral("probe")).toObject().value(QStringLiteral("base")).toString() == s.probeBase);
}

// --- shade queue -------------------------------------------------------------------------------------------

static ShadeRequest sh(ShadeTone t, const char *key, const QStringList &args = {})
{
    ShadeRequest r;
    r.tone = t;
    r.textKey = QLatin1String(key);
    r.args = args;
    return r;
}

static void shades()
{
    ShadeTiming timing;
    timing.holdMs = 1500; // this choreography is written for a 1.5 s hold (the default is 2.5 s)
    ShadeQueue q(timing);
    const qint64 n = 1000;
    ShadeStep s = q.enqueue(sh(ShadeTone::Info, "scan_found", {QStringLiteral("10")}), n);
    CHECK(s.actions.size() == 1 && s.actions.at(0).kind == ShadeActionKind::Show && s.wakeAtMs == n + 1500);
    s = q.enqueue(sh(ShadeTone::Info, "scan_found", {QStringLiteral("10")}), n + 100); // visible duplicate
    CHECK(s.actions.isEmpty() && q.pendingCount() == 0);
    s = q.enqueue(sh(ShadeTone::Info, "report_queued"), n + 200);
    CHECK(s.actions.isEmpty() && q.pendingCount() == 1); // no pre-emption
    s = q.enqueue(sh(ShadeTone::Warning, "connect_failed_next"), n + 300);
    s = q.enqueue(sh(ShadeTone::Info, "report_queued"), n + 400); // queued duplicate
    CHECK(q.pendingCount() == 2);
    s = q.tick(n + 1499);
    CHECK(s.actions.isEmpty());
    s = q.tick(n + 1500);
    CHECK(s.actions.size() == 1 && s.actions.at(0).kind == ShadeActionKind::Hide && s.wakeAtMs == n + 1860);
    s = q.tick(n + 1860);
    CHECK(s.actions.size() == 1 && s.actions.at(0).request.tone == ShadeTone::Warning); // warning first
    // the info waited from n+200: at n+1860+1860 it is stale (> 3 s) and dropped
    s = q.tick(n + 1860 + 1500);
    s = q.tick(n + 1860 + 1860);
    CHECK(s.actions.isEmpty() && !q.visible() && q.pendingCount() == 0);
    // warnings never go stale
    ShadeQueue w;
    w.enqueue(sh(ShadeTone::Info, "a"), 0);
    w.enqueue(sh(ShadeTone::Warning, "b"), 10);
    s = w.tick(10000);
    bool shownB = false;
    for (const ShadeAction &a : s.actions)
        shownB = shownB || (a.kind == ShadeActionKind::Show && a.request.textKey == QLatin1String("b"));
    CHECK(shownB);
    // tap
    ShadeQueue t;
    t.enqueue(sh(ShadeTone::Success, "report_sent"), 0);
    s = t.tapped(200);
    CHECK(s.actions.size() == 1 && s.actions.at(0).kind == ShadeActionKind::Hide && s.wakeAtMs == 560);
    s = t.tapped(300); // already leaving
    CHECK(s.actions.isEmpty());
    // overflow: oldest info/success first, then oldest warning
    ShadeQueue o;
    o.enqueue(sh(ShadeTone::Info, "v"), 0);
    o.enqueue(sh(ShadeTone::Info, "i1"), 1);
    o.enqueue(sh(ShadeTone::Warning, "w1"), 2);
    o.enqueue(sh(ShadeTone::Success, "s1"), 3);
    o.enqueue(sh(ShadeTone::Warning, "w2"), 4);
    QStringList keys;
    for (const ShadeRequest &r : o.pending())
        keys << r.textKey;
    CHECK(keys == QStringList({QStringLiteral("w1"), QStringLiteral("s1"), QStringLiteral("w2")}));
    o.enqueue(sh(ShadeTone::Warning, "w3"), 5);
    o.enqueue(sh(ShadeTone::Warning, "w4"), 6);
    keys.clear();
    for (const ShadeRequest &r : o.pending())
        keys << r.textKey;
    CHECK(keys == QStringList({QStringLiteral("w2"), QStringLiteral("w3"), QStringLiteral("w4")}));
    // an explicit key coalesces different texts
    ShadeQueue k;
    ShadeRequest a1 = sh(ShadeTone::Warning, "x");
    a1.key = QStringLiteral("seat");
    ShadeRequest a2 = sh(ShadeTone::Warning, "y");
    a2.key = QStringLiteral("seat");
    k.enqueue(a1, 0);
    k.enqueue(a2, 1);
    CHECK(k.pendingCount() == 0);
    // clock backwards is read as the last time
    ShadeQueue c;
    c.enqueue(sh(ShadeTone::Info, "z"), 5000);
    s = c.tick(100);
    CHECK(s.actions.isEmpty() && c.visible());
}


// --- scenarios -----------------------------------------------------------------------------------------------

static void scenariosAll()
{
    for (const Scenario &s : scenarios()) {
        Driver d(s.world());
        d.run();
        Fail f;
        checkAllSteps(d, f, s.name);
        s.expect(d, f);
        ++g_total;
        if (!f.list.isEmpty()) {
            ++g_fail;
            std::printf("FAIL scenario %s\n", qPrintable(s.name));
            for (const QString &x : f.list)
                std::printf("     %s\n", qPrintable(x));
        }
    }
}

// --- machine rules outside the scenarios -------------------------------------------------------------------

static ScanOpen openOf(const World &w, const QString &current, bool working)
{
    ScanOpen o;
    o.network = w.net;
    o.current = liveOf(w, current, working);
    return o;
}

static void machineRules()
{
    World w = baseWorld("rules", hostMac(), ScanNetKind::Wifi);
    // manifest unavailable: NoScan; the live row stays, no check of the connection runs (owner 18.11, variant B)
    {
        ScanMachine m(w.caps);
        m.opened(openOf(w, QStringLiteral("1"), true), kT0);
        ScanStep s = m.manifestUnavailable(QStringLiteral("service_off"), kT0 + 100);
        CHECK(m.phase() == ScanPhase::NoScan && s.actions.size() >= 0 && !scanViewToJson(m.view(kT0 + 100)).contains(QStringLiteral("card")));
        const ScanView v = m.view(kT0 + 100);
        CHECK(v.empty.variant == ScanEmptyVariant::None); // the live row is shown
        ScanMachine off(w.caps);
        off.opened(openOf(w, QString(), false), kT0);
        off.manifestUnavailable(QString(), kT0 + 100);
        const ScanView v2 = off.view(kT0 + 100);
        CHECK(v2.empty.variant == ScanEmptyVariant::NoScan && v2.empty.reason == QLatin1String("service_off"));
    }
    // the host refuses the start before any result: NoScan host_memory; a late progress of another scan is ignored
    {
        ScanMachine m(w.caps);
        m.opened(openOf(w, QString(), false), kT0);
        m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50);
        const QString id = m.scanId();
        ScanStep s = m.hostFailed(QStringLiteral("other"), ScanHostError::Memory, kT0 + 60);
        CHECK(m.phase() == ScanPhase::Reach);
        s = m.hostFailed(id, ScanHostError::Memory, kT0 + 70);
        CHECK(m.phase() == ScanPhase::NoScan && m.view(kT0 + 70).empty.reason == QLatin1String("host_memory"));
        ScanHostProgress p;
        p.scanId = id;
        p.phase = QStringLiteral("data");
        ScanProbeFacts f = goodData();
        f.id = QStringLiteral("4:xray");
        f.seq = 1;
        p.items << f;
        CHECK(m.hostProgress(p, kT0 + 80).actions.isEmpty());
    }
    // a grant that arrives after the stop is released at once
    {
        ScanMachine m(w.caps);
        m.opened(openOf(w, QStringLiteral("1"), true), kT0);
        ScanStep s = m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50);
        const ScanAction *batch = s.find(ScanActionKind::RequestProbeBatch);
        CHECK(batch && !batch->ids.isEmpty() && s.count(ScanActionKind::RequestProbeBatch) == 1);
        const QString leased = batch ? batch->ids.value(0) : QString();
        m.closed(kT0 + 60);
        s = m.probeLeaseGranted(leased, ScanAccess(), kT0 + 70);
        CHECK(s.has(ScanActionKind::ReleaseProbeLeases) && !s.has(ScanActionKind::AddHostCandidates));
        CHECK(m.probeLeaseGranted(QStringLiteral("up:ffffffffffffffff"), ScanAccess(), kT0 + 80).has(ScanActionKind::ReleaseProbeLeases));
    }
    // iPhone: the tunnel goes away during the scan -> the scan ends (the host lived in it), no reconnect
    {
        World wi = baseWorld("rules", hostIosFull(), ScanNetKind::Wifi);
        ScanMachine m(wi.caps);
        m.opened(openOf(wi, QStringLiteral("1"), true), kT0);
        m.manifestReady(manifestInputFrom(manifestArgs(wi)), kT0 + 50);
        CHECK(m.phase() == ScanPhase::Reach);
        const ScanStep s = m.vpnState(ScanCurrent(), kT0 + 500);
        CHECK(m.phase() == ScanPhase::Done || m.phase() == ScanPhase::Empty);
        for (const ScanAction &a : s.actions)
            CHECK(!scanActionTouchesTunnel(a.kind));
    }
    // taps: ignored for the current row, a failed row, while connecting, an unknown id; a tap during the scan
    {
        ScanMachine m(w.caps);
        m.opened(openOf(w, QStringLiteral("1"), true), kT0);
        m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50);
        ScanHostProgress p;
        p.scanId = m.scanId();
        p.phase = QStringLiteral("data");
        ScanProbeFacts f = goodData();
        f.id = QStringLiteral("2:xray");
        f.egressNode = QStringLiteral("2");
        f.seq = 1;
        p.items << withBurst(f);
        m.hostProgress(p, kT0 + 600);
        CHECK(m.rowTapped(QStringLiteral("1"), kT0 + 700).actions.isEmpty());       // the live connection
        CHECK(m.rowTapped(QStringLiteral("nope"), kT0 + 700).actions.isEmpty());
        ScanStep s = m.rowTapped(QStringLiteral("2:xray"), kT0 + 700);              // during the scan
        CHECK(s.has(ScanActionKind::FreezeHostScan) && !s.has(ScanActionKind::StopHostScan) && s.has(ScanActionKind::ConnectRow)
              && m.phase() == ScanPhase::Done); // the freeze first, the cancel after its ack (F7)
        CHECK(m.rowTapped(QStringLiteral("2:xray"), kT0 + 800).actions.isEmpty());   // already connecting
        {
            // lab seam S4: the probes the tap's stop cut in flight are «Не проверено» («cancelled»), at most
            // scan_unverified_rows_max of them, never gone and never a failure
            const ScanView tv = m.view(kT0 + 800);
            int cancelled = 0;
            for (const ScanRowView &r : tv.rows)
                cancelled += (!r.verified && !r.current && r.notVerifiedReason == QLatin1String("cancelled")) ? 1 : 0;
            CHECK(cancelled >= 1 && tv.unverifiedCount <= m.tunables().unverifiedRowsMax);
            const QJsonObject sum = m.lastSummary();
            CHECK(sum.value(QStringLiteral("not_verified_reasons")).toObject().value(QStringLiteral("cancelled")).toInt() >= cancelled);
        }
        // the ladder goes on through the visible rows after the tapped one (the «Не проверено» rows included),
        // then «… проверьте снова через минуту»
        s = m.connectFailed(QStringLiteral("2:xray"), kT0 + 2000);
        CHECK(s.has(ScanActionKind::ShowShade));
        bool later = false;
        for (int k = 0; k < 12 && !later; ++k) {
            for (const ScanAction &a : s.actions)
                later = later || a.shade.textKey == QLatin1String("connect_failed_later");
            if (!later)
                s = m.connectFailed(m.connectingId(), kT0 + 2001 + k);
        }
        CHECK(later); // nothing left in the order
        CHECK(m.rowTapped(QStringLiteral("2:xray"), kT0 + 2100).actions.isEmpty()); // failed row
        CHECK(m.attemptEnded(kT0 + 2200).actions.isEmpty());                      // chain already over
    }
    // Device round 13, C1: the person's Stop (or any action that takes the tunnel) ends the row's request without a
    // failure: the row leaves «Подключение…» at once, is not marked failed, and takes a tap again.
    {
        ScanMachine m(w.caps);
        m.opened(openOf(w, QStringLiteral("1"), true), kT0);
        m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50);
        ScanHostProgress p;
        p.scanId = m.scanId();
        p.phase = QStringLiteral("data");
        ScanProbeFacts f = goodData();
        f.id = QStringLiteral("2:xray");
        f.egressNode = QStringLiteral("2");
        f.seq = 1;
        p.items << withBurst(f);
        m.hostProgress(p, kT0 + 600);
        CHECK(m.rowTapped(QStringLiteral("2:xray"), kT0 + 700).has(ScanActionKind::ConnectRow));
        CHECK(m.connectingId() == QLatin1String("2:xray"));
        m.connectRefused(QString(), kT0 + 900); // superseded: no node named
        CHECK(m.connectingId().isEmpty());
        bool stuck = false;
        for (const ScanRowView &r : m.view(kT0 + 950).rows)
            stuck = stuck || (r.id == QLatin1String("2:xray") && (r.state == ScanRowState::Connecting || r.state == ScanRowState::Failed));
        CHECK(!stuck);
        CHECK(m.rowTapped(QStringLiteral("2:xray"), kT0 + 1000).has(ScanActionKind::ConnectRow));
        // the engine refuses the row by name (its node is not in the pool): it cannot be connected, so it is not offered
        m.connectRefused(QStringLiteral("2:xray"), kT0 + 1100);
        bool offered = false;
        for (const ScanRowView &r : m.view(kT0 + 1200).rows)
            offered = offered || (r.id == QLatin1String("2:xray") && r.tappable);
        CHECK(!offered && m.connectingId().isEmpty());
    }
    // S1 rule 2 (owner road 26.11, journal J2): the engine refused the tap before it dialled anything (the attempt ended
    // inside connect(): exact_unavailable, no_transport, no_network, ...). The facade ends the row's request with
    // connectRefused("") (AvpnEngineQml::endScanRowRequestNotStarted): no outcome before or after, the row keeps its scan
    // state and takes a tap again. Before, exactRowFailed sent outcome no_data for the never-dialled row and painted it
    // «Не удалось».
    {
        const auto scanned = [&w]() {
            auto m = std::make_unique<ScanMachine>(w.caps);
            m->opened(openOf(w, QStringLiteral("1"), true), kT0);
            m->manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50);
            ScanHostProgress p;
            p.scanId = m->scanId();
            p.phase = QStringLiteral("data");
            ScanProbeFacts f = goodData();
            f.id = QStringLiteral("2:xray");
            f.egressNode = QStringLiteral("2");
            f.seq = 1;
            p.items << withBurst(f);
            m->hostProgress(p, kT0 + 600);
            return m;
        };
        const auto rowOf = [](const ScanView &v, const QString &id) {
            for (const ScanRowView &r : v.rows)
                if (r.id == id)
                    return r;
            return ScanRowView();
        };
        // failure outcomes of the row (the tap stops the scan, whose own proof of the row - works - goes out as before)
        const auto outcomesFor = [](const ScanStep &st, const QString &id) {
            int n = 0;
            for (const ScanAction &a : st.actions)
                if (a.kind == ScanActionKind::SendOutcomes)
                    for (const ScanOutcomeItem &it : a.outcomes)
                        n += it.id == id && !scanClassWorking(it.outcome) ? 1 : 0;
            return n;
        };
        const QString row = QStringLiteral("2:xray");
        auto m = scanned();
        const ScanRowView before = rowOf(m->view(kT0 + 650), row);
        CHECK(before.id == row && before.tappable && before.state != ScanRowState::Failed);
        const ScanStep tap = m->rowTapped(row, kT0 + 700);
        CHECK(tap.has(ScanActionKind::ConnectRow) && outcomesFor(tap, row) == 0); // nothing before a dial
        const ScanStep refused = m->connectRefused(QString(), kT0 + 720);
        CHECK(outcomesFor(refused, row) == 0 && m->connectingId().isEmpty());
        int later = 0;
        for (qint64 t = kT0 + 1000; t < kT0 + 120000; t += 5000)
            later += outcomesFor(m->tick(t), row);
        CHECK(later == 0);
        const ScanRowView after = rowOf(m->view(kT0 + 120000), row);
        CHECK(after.state == before.state && after.verified == before.verified && after.tappable && !after.dimmed);
        CHECK(m->rowTapped(row, kT0 + 120100).has(ScanActionKind::ConnectRow)); // tappable again
        // review C3: a row refused before anything was dialled (a provider row whose seat request failed, the facade's
        // seat-first Stay): connectRefused(row) - «Не удалось» until the list is rebuilt, and no outcome at all
        auto rf = scanned();
        rf->rowTapped(row, kT0 + 700);
        int refusedOutcomes = outcomesFor(rf->connectRefused(row, kT0 + 720), row);
        for (qint64 t = kT0 + 1000; t < kT0 + 60000; t += 5000)
            refusedOutcomes += outcomesFor(rf->tick(t), row);
        const ScanRowView refusedRow = rowOf(rf->view(kT0 + 60000), row);
        CHECK(refusedOutcomes == 0 && !refusedRow.tappable && rf->connectingId().isEmpty());
        // the contrast: a failure of a dialled exact row (exactRowFailed) is a verdict - outcome and «Не удалось»
        auto f = scanned();
        f->rowTapped(row, kT0 + 700);
        const ScanStep failed = f->exactRowFailed(row, kT0 + 720);
        CHECK(outcomesFor(failed, row) == 1 && rowOf(f->view(kT0 + 730), row).state == ScanRowState::Failed);
    }
    // R6 (review of 141): the tapped row is an exact request. Its failure ends the chain at once: the old pair
    // connectFailed + attemptEnded moved the chain to the next row and marked THAT row failed, untried.
    for (const bool exact : {false, true}) {
        ScanMachine m(w.caps);
        m.opened(openOf(w, QStringLiteral("1"), true), kT0);
        m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50);
        ScanHostProgress p;
        p.scanId = m.scanId();
        p.phase = QStringLiteral("data");
        ScanProbeFacts f = goodData();
        f.id = QStringLiteral("2:xray");
        f.egressNode = QStringLiteral("2");
        f.seq = 1;
        p.items << withBurst(f);
        m.hostProgress(p, kT0 + 600);
        m.rowTapped(QStringLiteral("2:xray"), kT0 + 700);
        CHECK(!m.connectingId().isEmpty());
        QString other;
        if (exact) {
            for (const ScanRowView &r : m.view(kT0 + 800).rows)
                if (r.id != QLatin1String("2:xray") && !r.current && r.tappable && !r.unavailable)
                    other = r.id;
            m.exactRowFailed(QStringLiteral("2:xray"), kT0 + 2000);
        } else {
            m.connectFailed(QStringLiteral("2:xray"), kT0 + 2000);
            other = m.connectingId();
            CHECK(!other.isEmpty() && other != QLatin1String("2:xray")); // the old ladder moved on
            m.attemptEnded(kT0 + 2001);                                  // ... and failed that row, never tried
        }
        CHECK(m.connectingId().isEmpty());
        CHECK(!other.isEmpty());
        // the other row is tappable only when nothing failed it
        CHECK(m.rowTapped(other, kT0 + 2200).has(ScanActionKind::ConnectRow) == exact);
        CHECK(m.rowTapped(QStringLiteral("2:xray"), kT0 + 2300).actions.isEmpty()); // the tapped row failed
    }
    // no step checks the live connection (owner 18.11, variant B): the stop ends the scan at once, also for a
    // connection that came up late
    {
        ScanMachine m(w.caps);
        m.opened(openOf(w, QStringLiteral("1"), true), kT0);
        m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50);
        CHECK(m.tick(kT0 + 50 + 7999).actions.isEmpty() && m.view(kT0 + 50 + 7999).phase == ScanPhase::Reach);
        const ScanStep s = m.tick(kT0 + 50 + 8000);
        CHECK(s.has(ScanActionKind::FreezeHostScan) && m.phase() == ScanPhase::Done);
        ScanMachine late(w.caps);
        late.opened(openOf(w, QString(), false), kT0);
        late.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50);
        late.vpnState(liveOf(w, QStringLiteral("2:xray"), true), kT0 + 6000);
        const ScanStep ls = late.tick(kT0 + 50 + 8000);
        CHECK(late.phase() == ScanPhase::Done && ls.has(ScanActionKind::PersistResults));
    }
    // stop when nothing runs does nothing; the report link only in the empty / no-scan states
    {
        ScanMachine m(w.caps);
        CHECK(m.stopTapped(kT0).actions.isEmpty());
        CHECK(m.reportLinkTapped(kT0).actions.isEmpty());
        CHECK(m.retryTapped(kT0).has(ScanActionKind::RequestManifest)); // never scanned: retry scans
    }
    // the hint of a tap carries its TTL from the numbers
    {
        World wt = w;
        wt.numbers.insert(QStringLiteral("scan_attempt_hint_ttl_s"), 45);
        Driver d(wt);
        d.w.script << qMakePair(qint64(0), at("opened", openArgs(wt, QStringLiteral("1"), true)));
        d.w.script << qMakePair(qint64(9000), at("row_tapped", {{QStringLiteral("node_id"), QStringLiteral("2:xray")}}));
        d.w.runMs = 11000;
        d.run();
        const QList<ScanAction> taps = actionsOf(d, ScanActionKind::ConnectRow);
        CHECK(taps.size() == 1 && taps.at(0).hintTtlMs == 45000);
    }
    // a tunnel the user is bringing up: no second connect, and Stop never turns it off (mutations 26, 42)
    {
        World wi = baseWorld("rules", hostIosMinimal(), ScanNetKind::Wifi);
        ScanMachine m(wi.caps);
        ScanOpen o = openOf(wi, QStringLiteral("2:xray"), false); // live, connecting, no data yet
        ScanStep s = m.opened(o, kT0);
        CHECK(m.phase() == ScanPhase::Connecting && !s.has(ScanActionKind::UserConnectForScan) && !m.startedVpn());
        s = m.stopTapped(kT0 + 300);
        // owner 24.11: Stop keeps the screen open (back to the country choice)
        CHECK(!s.has(ScanActionKind::CancelPendingConnect) && !s.has(ScanActionKind::CloseScreen) && m.screenOpen());
        ScanMachine m2(wi.caps);
        ScanOpen off = openOf(wi, QString(), false);
        off.current.connecting = true; // an attempt without a live tunnel yet
        CHECK(!m2.opened(off, kT0).has(ScanActionKind::UserConnectForScan));
        CHECK(!m2.closed(kT0 + 100).has(ScanActionKind::CancelPendingConnect));
    }
    // a failed row stays out of every later attempt order (mutation 34)
    {
        Driver d(w);
        d.w.current = QStringLiteral("1");
        d.w.connectFails.insert(QStringLiteral("4:xray"));
        d.w.script << qMakePair(qint64(0), at("opened", openArgs(w, QStringLiteral("1"), true)));
        d.w.script << qMakePair(qint64(9000), at("row_tapped", {{QStringLiteral("node_id"), QStringLiteral("4:xray")}}));
        d.w.script << qMakePair(qint64(16000), at("row_tapped", {{QStringLiteral("node_id"), QStringLiteral("8:xray")}}));
        d.w.runMs = 20000;
        d.run();
        const QList<ScanAction> taps = actionsOf(d, ScanActionKind::ConnectRow);
        CHECK(taps.size() == 2 && !taps.value(1).ids.contains(QStringLiteral("4:xray")) && !taps.value(1).ids.isEmpty());
    }
    // the byte cap bounds the seats asked at once (mutation 32)
    {
        World wb = baseWorld("budget", hostMac(), ScanNetKind::Cellular);
        QList<NodeSpec> only;
        for (const NodeSpec &n : wb.nodes)
            if (n.provider && !n.composite)
                only << n;
        for (int k = 5; k <= 9; ++k) {
            NodeSpec n = only.value(0);
            n.id = up(k);
            n.rank = k;
            only << n;
        }
        wb.nodes = only;
        wb.out = allWork(wb.nodes);
        // A = 300000: the manifest's worst case (280576) fits; after its real 20480 the app slice holds the
        // batch 12288 + one release 10240 + outcomes 16384 -> the host's grant 240608: 2 leg probes (83968 B
        // each), not 3
        wb.numbers.insert(QStringLiteral("scan_budget_scan_bytes"), 300000);
        ScanMachine m(wb.caps);
        m.opened(openOf(wb, QString(), false), kT0);
        const ScanStep s = m.manifestReady(manifestInputFrom(manifestArgs(wb)), kT0 + 50);
        const ScanAction *b = s.find(ScanActionKind::RequestProbeBatch);
        CHECK(b && b->ids.size() == 2);
        CHECK(m.capBytes() == 240608 && m.hostGrant() == 240608); // the rest «Не проверено» (the result: the list shows them at the end)
        {
            int nv = 0;
            for (const ScanRowView &r : m.result(kT0 + 50))
                nv += r.verified ? 0 : 1;
            CHECK(nv == 2 && m.view(kT0 + 50).unverifiedCount == 0); // never on the list while the scan runs (owner 19.11)
        }
        CHECK(m.allowanceBytes() == 300000 && m.allowanceUsed() == 300000 - 0); // grant + app slice = A, nothing left over
        int adds = 0;
        for (const QString &id : b->ids)
            adds += m.probeLeaseGranted(id, ScanAccess(), kT0 + 100).count(ScanActionKind::AddHostCandidates);
        CHECK(adds == 2 && m.spentBytes() + m.leaseReservedBytes() <= m.capBytes());
    }
    // a clock that goes back is read as the last one
    {
        ScanMachine m(w.caps);
        m.opened(openOf(w, QStringLiteral("1"), true), kT0 + 10000);
        m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0);
        CHECK(m.deadline() == kT0 + 10000 + 8000);
    }
}

// --- summary, shade timing, lease batches -------------------------------------------------------------------

static void extras()
{
    // DoctorScanSummary of the last finished scan (openapi 1.5.0)
    World w = baseWorld("summary", hostMac(), ScanNetKind::Cellular);
    w.current = QStringLiteral("1");
    w.out[QStringLiteral("7:xray")].reachOk = false;
    w.leaseRefuse.insert(up(3), QStringLiteral("no_seat")); // a single profile: a leg, in the batch on cellular too
    w.script << qMakePair(qint64(0), at("opened", openArgs(w, w.current, true)));
    w.runMs = 12000;
    Driver d(w);
    d.run();
    const QJsonObject sum = d.m.lastSummary();
    CHECK(sum.value(QStringLiteral("schema")).toInt() == 1);
    CHECK(sum.value(QStringLiteral("network_key")).toString() == QLatin1String("cell:250-02:4g")); // the full key
    CHECK(sum.value(QStringLiteral("manifest_revision")).toInt() == 7 && sum.value(QStringLiteral("candidates")).toInt() > 0);
    const QJsonObject counts = sum.value(QStringLiteral("counts")).toObject();
    CHECK(counts.value(QStringLiteral("works")).toInt() >= 1 && counts.value(QStringLiteral("unreachable")).toInt() == 1);
    QSet<QString> allowed{QStringLiteral("schema"), QStringLiteral("network_key"), QStringLiteral("manifest_revision"), QStringLiteral("candidates"),
                          QStringLiteral("counts"), QStringLiteral("top"), QStringLiteral("not_verified_reasons"), QStringLiteral("stop_reason"),
                          QStringLiteral("duration_ms"), QStringLiteral("bytes_spent"), QStringLiteral("caps"), QStringLiteral("seats_requested")};
    CHECK(summaryRejects(sum).isEmpty()); // the strict 1.7.0 schema accepts it
    for (const QString &k : sum.keys())
        CHECK(allowed.contains(k)); // additionalProperties: false
    const QRegularExpression nodeId(QStringLiteral("^[0-9]{1,10}(:[a-z0-9_]{1,16}){0,2}$")), pid(QStringLiteral("^[0-9a-f]{16}$")),
        key(QStringLiteral("^[a-z][a-z0-9_]{0,31}$"));
    const QJsonArray top = sum.value(QStringLiteral("top")).toArray();
    CHECK(!top.isEmpty() && top.size() <= 20);
    for (const QJsonValue &v : top) {
        const QJsonObject r = v.toObject();
        const bool up = r.value(QStringLiteral("kind")).toString() == QLatin1String("upstream");
        CHECK((up ? pid : nodeId).match(r.value(QStringLiteral("id")).toString()).hasMatch());
    }
    for (const QString &k : sum.value(QStringLiteral("not_verified_reasons")).toObject().keys())
        CHECK(key.match(k).hasMatch());
    CHECK(key.match(sum.value(QStringLiteral("stop_reason")).toString()).hasMatch());
    CHECK(sum.value(QStringLiteral("not_verified_reasons")).toObject().value(QStringLiteral("no_seat")).toInt() == 1);
    CHECK(sum.value(QStringLiteral("caps")).toObject().value(QStringLiteral("leg_probe")).toBool());
    CHECK(scanReasonKey(QStringLiteral("Leg-DNS 1")) == QLatin1String("leg_dns_1") && scanReasonKey(QStringLiteral("1x")) == QLatin1String("x")
          && scanReasonKey(QString()) == QLatin1String("other"));
    // shade hold from the manifest, with the compiled fallback
    CHECK(shadeTimingFrom({}).holdMs == 2500);
    CHECK(shadeTimingFrom({{QStringLiteral("scan_shade_ms"), 2500}}).holdMs == 2500);
    CHECK(shadeTimingFrom({{QStringLiteral("scan_shade_ms"), 50}}).holdMs == 500);
    CHECK(shadeTimingFrom({{QStringLiteral("scan_shade_ms"), 1e9}}).holdMs == 10000);
    CHECK(shadeTimingFrom({{QStringLiteral("scan_shade_ms"), std::numeric_limits<double>::infinity()}}).holdMs == 2500);
    // seats (plan v2 §2.10): one probe-batch per scan, at most 12, the rest «Не проверено» (batch_cap);
    // include_config only when a full probe may follow; the server's 30 seats per device per minute hold for
    // two scans a minute (the 30 s cooldown), follow-ups included
    World wb = baseWorld("batch", hostMac(), ScanNetKind::Wifi);
    QList<NodeSpec> nodes;
    for (const NodeSpec &n : wb.nodes)
        if (!n.provider)
            nodes << n;
    for (int k = 1; k <= 15; ++k) {
        NodeSpec n = baseWorld("x", hostMac(), ScanNetKind::Wifi).nodes.at(11 + (k % 4));
        n.id = QStringLiteral("up:%1").arg(k, 16, 16, QLatin1Char('0'));
        n.rank = k;
        n.dnsThroughLeg = k % 3 != 0; // every third needs a full follow-up
        nodes << n;
    }
    wb.nodes = nodes;
    wb.out = allWork(wb.nodes);
    for (const NodeSpec &n : wb.nodes)
        if (!n.provider)
            wb.out[n.id].reachOk = false; // own nodes fail: the providers fill the list
    wb.current = QStringLiteral("1");
    wb.script << qMakePair(qint64(0), at("opened", openArgs(wb, wb.current, true)));
    wb.script << qMakePair(qint64(30000), at("retry"));
    wb.runMs = 59000;
    Driver db(wb);
    db.run();
    const QList<ScanAction> bs = actionsOf(db, ScanActionKind::RequestProbeBatch);
    CHECK(bs.size() == 2); // one per scan, two scans inside one minute
    int seats = 0;
    for (const ScanAction &a : bs) {
        CHECK(a.ids.size() == 8 && a.includeConfig); // the first wave: 6 leg + 2 full slots of this host
        seats += a.ids.size();
    }
    CHECK(seats <= 30); // UPSTREAM_PROBE_DEVICE_PER_MIN
    CHECK(db.leasesAsked.size() == seats); // follow-ups never ask again
    bool followed = false;
    for (const ScanAction &a : actionsOf(db, ScanActionKind::AddHostCandidates))
        for (const ScanCandidate &c : a.candidates)
            followed = followed || c.followUp;
    CHECK(followed);
    CHECK(db.releases == seats && db.maxReleaseIds <= 12); // every seat goes back, in batch releases
    CHECK(db.m.lastSummary().value(QStringLiteral("not_verified_reasons")).toObject().value(QStringLiteral("batch_cap")).toInt() == 15 - 8);
    CHECK(db.m.lastStats().value(QStringLiteral("seats_requested")).toInt() == 8
          && db.m.lastSummary().value(QStringLiteral("seats_requested")).toInt() == 8); // contract 1.7.0
    CHECK(summaryRejects(db.m.lastSummary()).isEmpty());
    // a leg host where every leg's DNS plan is proven and no composite: no configs asked
    World wn = baseWorld("noconfig", hostMac(), ScanNetKind::Wifi);
    QList<NodeSpec> legsOnly;
    for (const NodeSpec &n : wn.nodes)
        if (!n.provider || (!n.composite && n.dnsThroughLeg))
            legsOnly << n;
    wn.nodes = legsOnly;
    ScanMachine mn(wn.caps);
    mn.opened(openOf(wn, QStringLiteral("1"), true), kT0);
    const ScanStep sn = mn.manifestReady(manifestInputFrom(manifestArgs(wn)), kT0 + 50);
    CHECK(sn.find(ScanActionKind::RequestProbeBatch) && !sn.find(ScanActionKind::RequestProbeBatch)->includeConfig);
    // one single provider whose DNS plan is not through its leg is enough to ask the configs
    World wd = baseWorld("dnsconfig", hostMac(), ScanNetKind::Wifi);
    QList<NodeSpec> oneDirect;
    for (const NodeSpec &n : wd.nodes)
        if (!n.provider || n.id == up(3)) // up(3): single, DNS direct
            oneDirect << n;
    wd.nodes = oneDirect;
    ScanMachine md(wd.caps);
    md.opened(openOf(wd, QStringLiteral("1"), true), kT0);
    const ScanStep sd = md.manifestReady(manifestInputFrom(manifestArgs(wd)), kT0 + 50);
    CHECK(sd.find(ScanActionKind::RequestProbeBatch) && sd.find(ScanActionKind::RequestProbeBatch)->includeConfig);
    // ... unless this host cannot run a full probe at all (the follow-up could never run)
    ScanHostCaps legsOnlyHost = hostMac();
    legsOnlyHost.maxFullConcurrent = 0;
    ScanMachine ml(legsOnlyHost);
    ml.opened(openOf(wd, QStringLiteral("1"), true), kT0);
    const ScanStep sl = ml.manifestReady(manifestInputFrom(manifestArgs(wd)), kT0 + 50);
    CHECK(sl.find(ScanActionKind::RequestProbeBatch) && !sl.find(ScanActionKind::RequestProbeBatch)->includeConfig);
}

// --- review v2 fixes (F1, F2, F5-F10, F12) and the second-round mutation survivors ---------------------------

static ScanHostProgress progressOf(const ScanMachine &m, QList<ScanProbeFacts> items, qint64 spent = 0, qint64 reserved = 0, bool done = false)
{
    ScanHostProgress p;
    p.scanId = m.scanId();
    p.phase = done ? QStringLiteral("done") : QStringLiteral("data");
    QList<ScanProbeFacts> all;
    qint64 seq = 0;
    for (const ScanProbeFacts &f : items)
        for (const ScanProbeFacts &x : withBurst(f)) {
            all << x;
            seq = qMax(seq, x.seq);
        }
    for (ScanProbeFacts &f : all)
        if (f.seq == 0)
            f.seq = ++seq;
    p.items = all;
    p.seq = seq;
    p.bytesSpent = spent;
    p.bytesReserved = reserved;
    p.done = done;
    p.reason = done ? QStringLiteral("deadline") : QString();
    return p;
}

static void reviewFixes()
{
    // F1 (a): switch off -> the last results + «Подключиться и проверить», nothing emitted until pressed
    {
        World w = baseWorld("f1", hostIosFull(), ScanNetKind::Wifi);
        ScanMachine m(w.caps);
        ScanOpen o = openOf(w, QString(), false);
        o.connectOnOpen = false;
        ScanStep s = m.opened(o, kT0);
        CHECK(s.actions.isEmpty() && m.phase() == ScanPhase::NoScan);
        ScanView v = m.view(kT0);
        CHECK(v.empty.reason == QLatin1String("vpn_off") && v.bar.button == ScanBarButton::ConnectAndScan && v.bar.buttonEnabled);
        CHECK(m.retryTapped(kT0 + 100).actions.isEmpty()); // «Повторить» does not connect with the switch off
        s = m.connectAndScanTapped(kT0 + 200);
        CHECK(s.has(ScanActionKind::UserConnectForScan) && s.has(ScanActionKind::RequestManifest) && m.phase() == ScanPhase::Connecting);
        CHECK(TuningStore::flag(QStringLiteral("scanner_connect_on_open"), true) && scanConnectOnOpenFlag()); // compiled default on
    }
    // F1 (b): after «Подключено» nothing turns the VPN off: stop, finish, close
    {
        World w = baseWorld("f1b", hostIosFull(), ScanNetKind::Wifi);
        w.lkg = QStringLiteral("2:xray");
        w.script << qMakePair(qint64(0), at("opened", openArgs(w, QString(), false)));
        w.script << qMakePair(qint64(12000), at("closed"));
        w.script << qMakePair(qint64(50000), at("opened", openArgs(w, QStringLiteral("2:xray"), true)));
        w.script << qMakePair(qint64(51000), at("stop"));
        w.runMs = 53000;
        Driver d(w);
        d.run();
        CHECK(countActions(d, ScanActionKind::UserConnectForScan) == 1 && countActions(d, ScanActionKind::CancelPendingConnect) == 0);
    }
    // F1: a relaunched app (a fresh machine) never cancels a connect it did not start
    {
        World w = baseWorld("f1r", hostIosFull(), ScanNetKind::Wifi);
        ScanMachine before(w.caps);
        CHECK(before.opened(openOf(w, QString(), false), kT0).has(ScanActionKind::UserConnectForScan));
        ScanMachine after(w.caps); // the process restarted while that connect is still coming up
        ScanOpen o = openOf(w, QString(), false);
        o.current.connecting = true;
        CHECK(!after.opened(o, kT0 + 500).has(ScanActionKind::UserConnectForScan) && !after.startedVpn());
        CHECK(!after.stopTapped(kT0 + 600).has(ScanActionKind::CancelPendingConnect));
    }
    // F1 (c): a host that probes with the VPN off never connects except from a tap
    {
        World w = baseWorld("f1c", hostMac(), ScanNetKind::Wifi);
        ScanMachine m(w.caps);
        ScanStep s = m.opened(openOf(w, QString(), false), kT0);
        CHECK(!s.has(ScanActionKind::UserConnectForScan) && m.phase() == ScanPhase::Preparing);
        CHECK(!m.connectAndScanTapped(kT0 + 40000).has(ScanActionKind::UserConnectForScan));
        m.closed(kT0 + 40100);
        CHECK(!m.retryTapped(kT0 + 80000).has(ScanActionKind::UserConnectForScan));
    }
    // F2: the live connection is a «Подключено» row, but verified only after the sized check through the tunnel
    {
        World w = baseWorld("f2", hostMac(), ScanNetKind::Wifi);
        ScanMachine m(w.caps);
        m.opened(openOf(w, QStringLiteral("1"), true), kT0);
        ScanStep s = m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50);
        const ScanAction *lp = s.find(ScanActionKind::ProbeLiveTunnel);
        CHECK(lp && lp->nodeId == QLatin1String("1") && lp->bytes == 65536);
        ScanView v = m.view(kT0 + 60);
        CHECK(v.verifiedCount == 0 && v.rows.size() == 1 && v.rows.at(0).state == ScanRowState::Connected && !v.rows.at(0).verified);
        Driver dd(w);
        ScanProbeFacts bad = dd.liveFacts(QStringLiteral("1"));
        bad.bytesReceived = 18000; // frozen after 18 KB: not verified
        bad.error = ScanProbeError::Stalled;
        m.liveProbeResult(QStringLiteral("1"), bad, kT0 + 700);
        CHECK(m.view(kT0 + 700).verifiedCount == 0);
        CHECK(m.liveProbeResult(QStringLiteral("1"), dd.liveFacts(QStringLiteral("1")), kT0 + 800).actions.isEmpty()); // one per scan
        s = m.tick(kT0 + 50 + 8000);
        const ScanAction *pr = s.find(ScanActionKind::PersistResults);
        bool cached = false;
        if (pr)
            for (const ScanCachedRow &r : pr->cached.rows)
                cached = cached || r.id == QLatin1String("1");
        CHECK(pr && !cached); // never cached as works
        CHECK(m.lastSummary().value(QStringLiteral("counts")).toObject().value(QStringLiteral("not_verified")).toInt() >= 1);
        // a good answer verifies it
        ScanMachine g(w.caps);
        g.opened(openOf(w, QStringLiteral("1"), true), kT0);
        g.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50);
        g.liveProbeResult(QStringLiteral("1"), dd.liveFacts(QStringLiteral("1")), kT0 + 650);
        v = g.view(kT0 + 650);
        CHECK(v.verifiedCount == 1 && v.rows.at(0).verified && v.rows.at(0).state == ScanRowState::Connected);
    }
    // F5: Wi-Fi evidence never certifies a provider path on cellular when the new netinfo failed
    {
        World w = baseWorld("f5", hostMac(), ScanNetKind::Wifi);
        QList<NodeSpec> keep;
        for (const NodeSpec &n : w.nodes)
            if (n.id == QLatin1String("1") || n.id == up(1)) // the live node and one provider leg (free leg pool)
                keep << n;
        w.nodes = keep;
        const auto runOn = [&w](const ScanAccess &cellAccess) {
            ScanMachine m(w.caps);
            m.opened(openOf(w, QStringLiteral("1"), true), kT0);
            ScanManifestInput in = manifestInputFrom(manifestArgs(w)); // access {64500, net-access}
            m.manifestReady(in, kT0 + 50);
            m.networkChanged(scanNet(ScanNetKind::Cellular, QStringLiteral("cell:250-02:4g"), 7), ScanCachedResult(), kT0 + 300);
            ScanManifestInput cell = in;
            cell.access = cellAccess;
            const ScanStep s = m.manifestReady(cell, kT0 + 400);
            const ScanAction *b = s.find(ScanActionKind::RequestProbeBatch);
            checkMsg(b && b->ids.contains(up(1)), QStringLiteral("F5 batch"));
            const ScanStep g = m.probeLeaseGranted(up(1), ScanAccess(), kT0 + 500);
            checkMsg(g.has(ScanActionKind::AddHostCandidates), QStringLiteral("F5 provider leg enters the host"));
            ScanProbeFacts f = goodData();
            f.id = up(1);
            f.egressClass = QStringLiteral("other");
            f.egressAsn = 64600;               // differs from both access networks
            f.egressNetToken = QStringLiteral("net-exit");
            f.dnsExercised = true;
            m.hostProgress(progressOf(m, {f}), kT0 + 900);
            bool shownWorks = false;
            for (const ScanRowView &r : m.view(kT0 + 900).rows)
                shownWorks = shownWorks || (r.id == up(1) && r.verified);
            return shownWorks;
        };
        CHECK(!runOn(ScanAccess()));                                       // no fresh evidence: «Не проверено»
        ScanAccess fresh;
        fresh.asn = 64501;
        fresh.netToken = QStringLiteral("net-cell");
        CHECK(runOn(fresh));                                               // control: fresh evidence verifies it
    }
    // F6: the shared byte gate - atomic admission across pools and retries
    {
        ScanHostByteGate g(200000);
        CHECK(g.admit(QStringLiteral("a"), 83456) && g.admit(QStringLiteral("b"), 83456));
        CHECK(!g.admit(QStringLiteral("c"), 83456) && g.reserved() == 166912); // the third would pass the cap
        CHECK(!g.admit(QStringLiteral("a"), 10)); // one reservation per probe (a retry stays inside it)
        g.finish(QStringLiteral("a"), 90000);     // never more than its cost
        CHECK(g.spent() == 83456 && g.reserved() == 83456);
        CHECK(!g.admit(QStringLiteral("c"), 83456)); // 83456 + 83456 + 83456 > 200000
        g.finish(QStringLiteral("b"), 20000);
        CHECK(g.admit(QStringLiteral("c"), 83456) && g.spent() == 103456);
        CHECK(!g.charge(20000) && g.charge(13088) && g.spent() + g.reserved() == 200000);
        g.finish(QStringLiteral("nope"), 5000);
        CHECK(g.spent() == 116544);
        std::mt19937 rng(61);
        for (int k = 0; k < 300; ++k) {
            ScanHostByteGate x(qint64(rng() % 600000));
            QStringList open;
            for (int i = 0; i < 60; ++i) {
                const int op = int(rng() % 3);
                if (op == 0) {
                    const QString id = QStringLiteral("p%1").arg(i);
                    if (x.admit(id, qint64(rng() % 120000)))
                        open << id;
                } else if (op == 1 && !open.isEmpty()) {
                    x.finish(open.takeAt(int(rng() % open.size())), qint64(rng() % 150000));
                } else {
                    x.charge(qint64(rng() % 2000));
                }
                checkMsg(x.spent() + x.reserved() <= x.maxBytes() && x.spent() >= 0 && x.reserved() >= 0, QStringLiteral("byte gate cap"));
            }
        }
    }
    // F7 (plan §2.2b step 5): freeze -> ack {spent, reserved} -> cancel -> final totals; the ledger gets app
    // actual + the host charge once: the final total; without a final within scan_drain_ms the ack's spent +
    // reserved; without a freeze ack within scan_freeze_ack_ms the whole host grant. Own nodes only, VPN off:
    // the app side is the manifest + token (20480 B real) alone.
    {
        World w = baseWorld("f7", hostMac(), ScanNetKind::Cellular);
        QList<NodeSpec> own;
        for (const NodeSpec &n : w.nodes)
            if (!n.provider)
                own << n;
        w.nodes = own;
        const auto start = [&w](ScanMachine &m) {
            m.opened(openOf(w, QString(), false), kT0);
            const ScanStep s = m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50);
            const ScanAction *a = s.find(ScanActionKind::StartHostScan);
            // A = 1572864; app slice: manifest + token real 20480, outcomes 16384 reserved
            checkMsg(a && a->maxBytes == 1572864 - 20480 - 16384 && m.hostGrant() == a->maxBytes, QStringLiteral("F7 grant"));
            m.hostProgress(progressOf(m, {}, 100000, 60000), kT0 + 400);
        };
        ScanMachine m(w.caps);
        start(m);
        const QString id = m.scanId();
        ScanStep s = m.stopTapped(kT0 + 500);
        CHECK(s.has(ScanActionKind::FreezeHostScan) && !s.has(ScanActionKind::StopHostScan) && !s.has(ScanActionKind::PersistBudget) && m.draining());
        s = m.hostFreezeAck(id, 100000, 60000, kT0 + 530);
        CHECK(s.has(ScanActionKind::StopHostScan) && !s.has(ScanActionKind::PersistBudget) && m.draining());
        ScanHostProgress fin = progressOf(m, {}, 140000, 0, true);
        fin.finalTotals = true;
        fin.reason = QStringLiteral("cancelled");
        s = m.hostProgress(fin, kT0 + 650);
        CHECK(s.has(ScanActionKind::PersistBudget) && !m.draining() && m.ledger().spentInHour(kT0 + 650, true) == 20480 + 140000);
        CHECK(m.hostProgress(fin, kT0 + 700).actions.isEmpty() && m.ledger().spentInHour(kT0 + 700, true) == 20480 + 140000); // once
        // the totals in the cancel ack instead
        ScanMachine c(w.caps);
        start(c);
        c.stopTapped(kT0 + 500);
        c.hostFreezeAck(c.scanId(), 100000, 60000, kT0 + 530);
        s = c.hostCancelAck(c.scanId(), 131000, kT0 + 700);
        CHECK(s.has(ScanActionKind::PersistBudget) && c.ledger().spentInHour(kT0 + 700, true) == 20480 + 131000);
        // ack, no final: spent + reserved of the ACK after scan_drain_ms (not the last progress)
        ScanMachine p(w.caps);
        start(p);
        p.stopTapped(kT0 + 500);
        p.hostFreezeAck(p.scanId(), 110000, 70000, kT0 + 530);
        CHECK(p.tick(kT0 + 530 + 2000 - 1).actions.isEmpty() && p.draining());
        s = p.tick(kT0 + 530 + 2000);
        CHECK(s.has(ScanActionKind::PersistBudget) && !p.draining() && p.ledger().spentInHour(kT0 + 3000, true) == 20480 + 180000);
        // no freeze ack: the cancel goes anyway and the WHOLE grant is charged after scan_freeze_ack_ms
        ScanMachine q(w.caps);
        start(q);
        q.stopTapped(kT0 + 500);
        CHECK(q.tick(kT0 + 500 + 1000 - 1).actions.isEmpty());
        s = q.tick(kT0 + 500 + 1000);
        CHECK(s.has(ScanActionKind::StopHostScan) && s.has(ScanActionKind::PersistBudget)
              && q.ledger().spentInHour(kT0 + 1600, true) == 20480 + q.hostGrant() && q.hostGrant() == 1572864 - 20480 - 16384);
        CHECK(q.hostFreezeAck(q.scanId(), 1, 1, kT0 + 1700).actions.isEmpty()); // a late ack changes nothing
        // the waits are server numbers with clamps
        ScanTunables t = ScanTunables::fromNumbers({{QStringLiteral("scan_freeze_ack_ms"), 50}, {QStringLiteral("scan_drain_ms"), 1e9}});
        CHECK(t.freezeAckMs == 200 && t.drainMs == 10000);
        // a host that ends by itself (final, deadline) needs no freeze
        ScanMachine r(w.caps);
        start(r);
        ScanHostProgress byItself = progressOf(r, {}, 90000, 0, true);
        byItself.finalTotals = true;
        s = r.hostProgress(byItself, kT0 + 4000);
        CHECK(!s.has(ScanActionKind::FreezeHostScan) && !s.has(ScanActionKind::StopHostScan));
        r.tick(kT0 + 50 + 7000);
        CHECK(!r.draining() && r.ledger().spentInHour(kT0 + 7100, true) == 20480 + 90000);
        // done without final (queue drained) does not settle: the host stays open for scan_add
        ScanMachine u(w.caps);
        start(u);
        ScanHostProgress drained = progressOf(u, {}, 90000, 0, true);
        drained.reason = QStringLiteral("complete");
        u.hostProgress(drained, kT0 + 3000);
        CHECK(u.draining());
    }
    // F8: leaving an unfinished scan does not reset the manual cooldown
    {
        World w = baseWorld("f8", hostMac(), ScanNetKind::Wifi);
        ScanMachine m(w.caps);
        m.opened(openOf(w, QStringLiteral("1"), true), kT0);
        m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50);
        m.closed(kT0 + 1000);
        ScanStep s = m.opened(openOf(w, QStringLiteral("1"), true), kT0 + 2000);
        CHECK(!s.has(ScanActionKind::RequestManifest) && m.phase() == ScanPhase::NoScan);
        CHECK(m.view(kT0 + 2000).bar.button == ScanBarButton::RetryInSeconds && m.view(kT0 + 2000).bar.buttonValue == 28);
        m.closed(kT0 + 2100);
        CHECK(m.opened(openOf(w, QStringLiteral("1"), true), kT0 + 30000).has(ScanActionKind::RequestManifest));
    }
    // F9: the live check runs again on a second scan of the same connection
    {
        World w = baseWorld("f9", hostMac(), ScanNetKind::Wifi);
        w.current = QStringLiteral("1");
        w.script << qMakePair(qint64(0), at("opened", openArgs(w, w.current, true)));
        w.script << qMakePair(qint64(31000), at("retry"));
        w.runMs = 45000;
        Driver d(w);
        d.run();
        CHECK(countActions(d, ScanActionKind::RequestManifest) == 2 && countActions(d, ScanActionKind::ProbeLiveTunnel) == 2);
    }
    // F10 (plan §2.11a): another local network with the same operator key - the app's monitor counted a
    // change and the gateway differs: the old results are not current evidence there
    {
        World w = baseWorld("f10", hostMac(), ScanNetKind::Wifi);
        w.net = scanNet(ScanNetKind::Wifi, QStringLiteral("wifi:asn:64500"), 1, QStringLiteral("gw-a"));
        w.current = QStringLiteral("1");
        w.script << qMakePair(qint64(0), at("opened", openArgs(w, w.current, true)));
        World w2 = w;
        w2.net = scanNet(ScanNetKind::Wifi, QStringLiteral("wifi:asn:64500"), 2, QStringLiteral("gw-b")); // same ISP key
        w.script << qMakePair(qint64(9000), at("closed"));
        w.script << qMakePair(qint64(10000), at("network_changed", {{QStringLiteral("network"), netJson(w2.net)}, {QStringLiteral("app_in_front"), false}}));
        w.script << qMakePair(qint64(11000), at("opened", openArgs(w2, w2.current, true)));
        w.runMs = 20000;
        Driver d(w);
        d.run();
        const QJsonObject v = viewAt(d, 11000);
        CHECK(phaseOf(v) == QLatin1String("preparing")); // scans although the cooldown of the old network runs
        for (const QJsonValue &r : v.value(QStringLiteral("rows")).toArray())
            CHECK(r.toObject().value(QStringLiteral("flags")).toArray().contains(QStringLiteral("current"))); // only the live row
        CHECK(countActions(d, ScanActionKind::RequestManifest) == 2);
        // cached rows of another fingerprint never show
        ScanCachedResult c;
        c.networkKey = w.net.key;
        c.fingerprint = w.net.fingerprint;
        c.savedAtMs = kT0 - 60000;
        ScanCachedRow row;
        row.id = QStringLiteral("4:xray");
        row.speed = ScanSpeed::Fast;
        c.rows << row;
        ScanMachine m(w.caps);
        ScanOpen o = openOf(w2, QString(), false);
        o.cached = c;
        m.opened(o, kT0);
        CHECK(m.view(kT0).rows.isEmpty());
        // ... but a relaunch on the SAME network (new app epoch: another strict tuple, the same fingerprint)
        // shows them at once, as cache with their age, never verified (fig. 18), while the new scan runs
        ScanMachine relaunched(w.caps);
        ScanOpen o2 = openOf(w, QString(), false);
        o2.network.sources = {ScanNetSource{QStringLiteral("app"), 0x77ULL, 0}};
        o2.cached = c;
        relaunched.opened(o2, kT0);
        const ScanView rv = relaunched.view(kT0);
        CHECK(rv.scanning && rv.rows.size() == 1 && rv.rows.at(0).fromCache && rv.verifiedCount == 0 && rv.checkedAgoMin == 1);
        // ... never older than kScanCacheShowMaxMs, and as the result of a scan that cannot run (no scan)
        // only within scan_cache_works_ttl_s
        ScanMachine stale(w.caps);
        c.savedAtMs = kT0 - kScanCacheShowMaxMs - 1;
        o2.cached = c;
        stale.opened(o2, kT0);
        CHECK(stale.view(kT0).rows.isEmpty());
        for (const qint64 age : {qint64(300000), qint64(601000)}) {
            ScanMachine ns(w.caps);
            c.savedAtMs = kT0 - age;
            o2.cached = c;
            ns.opened(o2, kT0);
            ns.manifestUnavailable(QStringLiteral("service_off"), kT0 + 50);
            const ScanView nv = ns.view(kT0 + 50);
            // shown under the scan's window, it stays while the list is on the screen (owner 19.11: never expires in
            // front of the person) ...
            CHECK(ns.phase() == ScanPhase::NoScan && nv.rows.size() == 1 && nv.verifiedCount == 0);
            // ... and the next list built (the page opened again) judges scan_cache_works_ttl_s
            ns.shown(o2, kT0 + 60);
            CHECK(ns.view(kT0 + 60).rows.size() == (age <= 600000 - 60 ? 1 : 0));
        }
        // the local identities never leave the device: not in outcomes, the summary or the report
        bool leaked = false;
        for (const ScanAction &a : actionsOf(d, ScanActionKind::SendOutcomes))
            for (const ScanOutcomeItem &it : a.outcomes) {
                const QJsonObject j = it.toJson(a.networkKey);
                leaked = leaked || j.contains(QStringLiteral("generation")) || j.contains(QStringLiteral("fingerprint"));
            }
        const QByteArray sum = QJsonDocument(d.m.lastSummary()).toJson();
        CHECK(!leaked && !sum.contains("generation") && !sum.contains("fingerprint") && !sum.contains(w.net.fingerprint.toUtf8()));
    }
    // F10: the strict tuple - no max() of counters; any component of any source
    {
        const ScanNetSource app10{QStringLiteral("app"), 0xe1ULL, 10}, ne1{QStringLiteral("ne"), 0xe2ULL, 1}, ne2{QStringLiteral("ne"), 0xe2ULL, 2};
        const QString g = scanNetGeneration({app10, ne1});
        CHECK(scanNetGeneration({app10, ne2}) != g);                                           // (10,1) -> (10,2)
        CHECK(scanNetGeneration({app10, ScanNetSource{QStringLiteral("ne"), 0xe3ULL, 0}}) != g); // a monitor restart
        CHECK(scanNetGeneration({app10, ScanNetSource{QStringLiteral("ne"), 0xe3ULL, 1}}) != g); // a new epoch, same counter
        CHECK(scanNetGeneration({app10}) != g);                                                // a source vanishes
        CHECK(scanNetGeneration({ScanNetSource{QStringLiteral("app"), 0xe1ULL, 11}, ScanNetSource{QStringLiteral("ne"), 0xe2ULL, 0}}) != g); // sum kept
        CHECK(scanNetGeneration({ne1, app10}) == g && scanNetGeneration({app10, ne1}) == g); // unchanged (any order)
        CHECK(g.size() == 16);
        // fingerprint: kind + key + optional gateway hash
        CHECK(scanNetFingerprint(QStringLiteral("wifi"), QStringLiteral("wifi:asn:1")) != scanNetFingerprint(QStringLiteral("wifi"), QStringLiteral("wifi:asn:1"), QStringLiteral("gw")));
        CHECK(scanNetFingerprint(QStringLiteral("wifi"), QStringLiteral("wifi:asn:1")) == scanNetFingerprint(QStringLiteral("wifi"), QStringLiteral("wifi:asn:1")));
        ScanNetSource back;
        CHECK(scanNetSourceFromJson(scanNetSourceToJson(ScanNetSource{QStringLiteral("ne"), 0xffffffffffffffffULL, 9}), back)
              && back.epoch == 0xffffffffffffffffULL && back.counter == 9);
        // in the machine: verified provider rows and access evidence die with the tuple (no scan running)
        World w = baseWorld("f10t", hostMac(), ScanNetKind::Wifi);
        QList<NodeSpec> keep;
        for (const NodeSpec &n : w.nodes)
            if (n.id == QLatin1String("1") || n.id == up(1))
                keep << n;
        w.nodes = keep;
        w.net.sources = {app10, ne1};
        ScanMachine m(w.caps);
        m.opened(openOf(w, QString(), false), kT0);
        m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50);
        m.probeLeaseGranted(up(1), ScanAccess(), kT0 + 100);
        ScanProbeFacts f = goodData();
        f.id = up(1);
        f.egressClass = QStringLiteral("other");
        f.egressAsn = 64600;
        f.egressNetToken = QStringLiteral("net-exit");
        f.dnsExercised = true;
        m.hostProgress(progressOf(m, {f}), kT0 + 900);
        ScanView v = m.view(kT0 + 900);
        CHECK(v.verifiedCount == 1);
        m.tick(kT0 + 50 + 8000);
        CHECK(m.phase() == ScanPhase::Done && m.view(kT0 + 8100).verifiedCount == 1);
        ScanNetwork same = w.net;
        same.sources = {ne1, app10}; // the same tuple in another order: nothing changes
        m.networkChanged(same, ScanCachedResult(), kT0 + 8200);
        CHECK(m.phase() == ScanPhase::Done && m.view(kT0 + 8200).verifiedCount == 1);
        ScanNetwork bumped = w.net;
        bumped.sources = {app10, ne2}; // the extension saw a path change
        m.networkChanged(bumped, ScanCachedResult(), kT0 + 8300);
        v = m.view(kT0 + 8300);
        CHECK(v.verifiedCount == 0 && v.rows.size() == 1 && v.rows.at(0).fromCache); // only cache now
    }
    // F12: the support queue is full - no new full check, a backpressure notice; space comes back -> it runs
    {
        World w = baseWorld("f12q", hostMac(), ScanNetKind::Wifi);
        w.current = QStringLiteral("1");
        w.script << qMakePair(qint64(0), at("opened", openArgs(w, w.current, true)));
        w.script << qMakePair(qint64(8500), at("report_queue_state", {{QStringLiteral("full"), true}}));
        w.script << qMakePair(qint64(9000), at("support_check_tapped"));
        w.script << qMakePair(qint64(9500), at("report_queue_state", {{QStringLiteral("full"), false}}));
        w.script << qMakePair(qint64(10000), at("support_check_tapped"));
        w.runMs = 14000;
        Driver d(w);
        d.run();
        CHECK(shadeCount(d, "report_queue_full") == 1 && countActions(d, ScanActionKind::StartReportCheck) == 1);
        const ScanAction a = actionsOf(d, ScanActionKind::StartReportCheck).value(0);
        CHECK(a.report.value(QStringLiteral("scan_stats")).isObject()); // seats asked etc. ride with the report, not the summary
    }
    // F12: the report is an immutable object with its own id; a done for another id changes nothing
    {
        World w = baseWorld("f12", hostMac(), ScanNetKind::Wifi);
        w.current = QStringLiteral("1");
        w.script << qMakePair(qint64(0), at("opened", openArgs(w, w.current, true)));
        w.script << qMakePair(qint64(9000), at("support_check_tapped"));
        w.script << qMakePair(qint64(9100), at("report_check_done", {{QStringLiteral("delivery"), QStringLiteral("sent")}, {QStringLiteral("report_id"), QStringLiteral("report-other")}}));
        w.runMs = 13000;
        Driver d(w);
        d.run();
        const ScanAction a = actionsOf(d, ScanActionKind::StartReportCheck).value(0);
        CHECK(a.reportId.startsWith(QLatin1String("report-")) && a.report.value(QStringLiteral("id")).toString() == a.reportId);
        CHECK(a.report.value(QStringLiteral("network_key")).toString() == QLatin1String("wifi:asn:64500") && a.report.value(QStringLiteral("scan")).isObject());
        CHECK(phaseOf(viewAt(d, 9150)) == QLatin1String("done") && d.m.lastSummary().size() > 0);
        CHECK(shadeCount(d, "report_sent") == 1);
    }
    // mutation 32 (second round): provider probes never pass the cap when the host spent more than projected
    {
        World wb = baseWorld("m32", hostMac(), ScanNetKind::Cellular);
        QList<NodeSpec> only;
        for (const NodeSpec &n : wb.nodes)
            if (n.provider && !n.composite)
                only << n;
        wb.nodes = only;
        wb.numbers.insert(QStringLiteral("scan_budget_scan_bytes"), 300000);
        ScanMachine m(wb.caps);
        m.opened(openOf(wb, QString(), false), kT0);
        const ScanStep s = m.manifestReady(manifestInputFrom(manifestArgs(wb)), kT0 + 50);
        const ScanAction *b = s.find(ScanActionKind::RequestProbeBatch);
        CHECK(b && b->ids.size() == 2);
        m.hostProgress(progressOf(m, {}, 160000, 0), kT0 + 80); // the host already spent more than planned
        int adds = 0;
        for (const QString &id : b->ids)
            adds += m.probeLeaseGranted(id, ScanAccess(), kT0 + 100).count(ScanActionKind::AddHostCandidates);
        CHECK(adds == 0);
    }
    // mutation 37 (second round): a grant after a deadline stop goes back at once
    {
        World w = baseWorld("m37", hostMac(), ScanNetKind::Wifi);
        ScanMachine m(w.caps);
        m.opened(openOf(w, QStringLiteral("1"), true), kT0);
        const ScanStep s = m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50);
        const ScanAction *b = s.find(ScanActionKind::RequestProbeBatch);
        CHECK(b && !b->ids.isEmpty());
        m.tick(kT0 + 50 + 8000); // the deadline: the scan stops with the batch still unanswered
        const ScanStep late = m.probeLeaseGranted(b->ids.value(0), ScanAccess(), kT0 + 8100);
        CHECK(late.has(ScanActionKind::ReleaseProbeLeases) && !late.has(ScanActionKind::AddHostCandidates));
    }
}

// --- plan v2.2: one allowance, freeze, attempts, exclusion, seats ------------------------------------------

static ScanAccessAttempt attemptOf(bool answered, qint64 atMs, const ScanNetSource &gen)
{
    ScanAccessAttempt a;
    a.attempted = true;
    a.httpAnswered = answered;
    a.atMs = atMs;
    a.hasGen = true;
    a.gen = gen;
    return a;
}

static void planV22()
{
    // the plan's own example (§2.2b): fresh cellular hour, 304 manifest + token (20480 real), a live
    // connection, providers present -> app slice 183296, host grant 1389568
    {
        World w = baseWorld("example", hostMac(), ScanNetKind::Cellular);
        ScanMachine m(w.caps);
        const ScanStep o = m.opened(openOf(w, QStringLiteral("1"), true), kT0);
        const ScanAction *mr = o.find(ScanActionKind::RequestManifest);
        CHECK(mr && mr->costBytes == 270336 + 10240 && !mr->requestId.isEmpty()); // reserved before it is sent
        const ScanStep s = m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50);
        const ScanAction *a = s.find(ScanActionKind::StartHostScan);
        CHECK(a && a->maxBytes == 1430528 && m.hostGrant() == 1430528 && m.allowanceBytes() == 1572864); // no light-check share
        CHECK(a && a->limits.netinfoCostBytes == 10240);
        const ScanAction *b = s.find(ScanActionKind::RequestProbeBatch);
        CHECK(b && !b->includeConfig && b->costBytes == 12288); // cellular: never include_config
        const ScanAction *lp = s.find(ScanActionKind::ProbeLiveTunnel);
        CHECK(lp && lp->costBytes == 82944);
        // composite providers need their config: on cellular they stay «Не проверено» (config_cellular)
        bool configCellular = false;
        for (const ScanRowView &r : m.result(kT0 + 50))
            configCellular = configCellular || r.notVerifiedReason == QLatin1String("config_cellular");
        CHECK(configCellular);
        // an app request reports its real bytes: they replace the reservation, also when they are more
        const qint64 used = m.allowanceUsed();
        m.appRequestDone(lp->requestId, 70000, kT0 + 700);
        CHECK(m.allowanceUsed() == used - 82944 + 70000);
        m.appRequestDone(b->requestId, 12288 + 17000, kT0 + 800); // one chunk past its reservation: recorded
        CHECK(m.allowanceUsed() == used - 82944 + 70000 + 17000);
        m.appRequestDone(QStringLiteral("scan-nope/batch"), 5, kT0 + 900); // unknown: nothing
        CHECK(m.allowanceUsed() == used - 82944 + 70000 + 17000);
    }
    // Wi-Fi: include_config makes the batch reservation one config per seat
    {
        World w = baseWorld("wifi_batch", hostMac(), ScanNetKind::Wifi);
        w.deviceBytesPerHour = 64 * 1024 * 1024; // a device budget: an allowance on Wi-Fi too
        ScanMachine m(w.caps);
        m.opened(openOf(w, QStringLiteral("1"), true), kT0);
        const ScanStep s = m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50);
        const ScanAction *b = s.find(ScanActionKind::RequestProbeBatch);
        CHECK(b && b->includeConfig && b->ids.size() == 4 && b->costBytes == 12288 + 4 * ScanTunables().costConfigBytes);
    }
    // seats: one batch sized to the first wave - the pools the providers use; a leg-only host asks 4 on iOS
    {
        World w = baseWorld("ios_seats", hostIosFull(), ScanNetKind::Wifi);
        QList<NodeSpec> nodes = ownOnly(w.nodes);
        for (int k = 1; k <= 9; ++k) {
            NodeSpec n = artboardNodes().at(11); // a single profile with its DNS plan through the leg
            n.id = QStringLiteral("up:%1").arg(k, 16, 16, QLatin1Char('0'));
            n.rank = k;
            nodes << n;
        }
        w.nodes = nodes;
        w.out = allWork(w.nodes);
        ScanMachine m(w.caps);
        m.opened(openOf(w, QStringLiteral("1"), true), kT0);
        const ScanStep s = m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50);
        const ScanAction *b = s.find(ScanActionKind::RequestProbeBatch);
        CHECK(b && b->ids.size() == 4 && !b->includeConfig); // the leg pool's 4 slots (legs only: no full pool)
        bool capped = false;
        for (const ScanRowView &r : m.result(kT0 + 50))
            capped = capped || r.notVerifiedReason == QLatin1String("batch_cap");
        CHECK(capped && m.probeBatchesThisScan() == 1); // the rest «Не проверено», never a second batch
    }
    // a lease grant's own access facts are not evidence (a lease-bound token, plan §2.11)
    {
        World w = baseWorld("grant_access", hostMac(), ScanNetKind::Wifi);
        QList<NodeSpec> keep;
        for (const NodeSpec &n : w.nodes)
            if (n.id == QLatin1String("1") || n.id == up(1))
                keep << n;
        w.nodes = keep;
        ScanMachine m(w.caps);
        m.opened(openOf(w, QStringLiteral("1"), true), kT0);
        QJsonObject args = manifestArgs(w);
        args.insert(QStringLiteral("access"), QJsonObject()); // no manifest evidence
        m.manifestReady(manifestInputFrom(args), kT0 + 50);
        ScanAccess grant;
        grant.asn = 64500;
        grant.netToken = QStringLiteral("net-access");
        m.probeLeaseGranted(up(1), grant, kT0 + 100);
        ScanProbeFacts f = goodData();
        f.id = up(1);
        f.egressClass = QStringLiteral("other");
        f.egressAsn = 64600;
        f.egressNetToken = QStringLiteral("net-exit");
        f.dnsExercised = true;
        m.hostProgress(progressOf(m, {f}), kT0 + 900);
        CHECK(rowOf(scanViewToJson(m.view(kT0 + 900)), up(1)).value(QStringLiteral("flags")).toArray().contains(QStringLiteral("unverified")));
    }
    // the host's opening attempt is the evidence; its path state moving afterwards voids it
    {
        World w = baseWorld("opening", hostMac(), ScanNetKind::Wifi);
        QList<NodeSpec> keep;
        for (const NodeSpec &n : w.nodes)
            if (n.id == QLatin1String("1") || n.id == up(1) || n.id == up(3))
                keep << n;
        w.nodes = keep;
        const ScanNetSource ne1{QStringLiteral("ne"), 0xe2ULL, 1}, ne2{QStringLiteral("ne"), 0xe2ULL, 2};
        const auto run = [&](bool bump) {
            ScanMachine m(w.caps);
            m.opened(openOf(w, QStringLiteral("1"), true), kT0);
            QJsonObject args = manifestArgs(w);
            args.insert(QStringLiteral("access"), QJsonObject());
            m.manifestReady(manifestInputFrom(args), kT0 + 50);
            m.probeLeaseGranted(up(1), ScanAccess(), kT0 + 100);
            ScanHostProgress p = progressOf(m, {});
            p.access = attemptOf(true, 0, ne1);
            p.access.facts.asn = 64500;
            p.access.facts.netToken = QStringLiteral("net-access");
            p.hasGen = true;
            p.gen = ne1;
            m.hostProgress(p, kT0 + 300);
            ScanProbeFacts f = goodData();
            f.id = up(1);
            f.seq = 1;
            f.egressClass = QStringLiteral("other");
            f.egressAsn = 64600;
            f.egressNetToken = QStringLiteral("net-exit");
            f.dnsExercised = true;
            ScanHostProgress q = progressOf(m, {f});
            q.access = p.access;
            q.hasGen = true;
            q.gen = bump ? ne2 : ne1;
            m.hostProgress(q, kT0 + 900);
            for (const ScanRowView &r : m.result(kT0 + 900))
                if (r.id == up(1))
                    return r.verified;
            return true;
        };
        CHECK(run(false)); // verified directly by the opening attempt's facts
        CHECK(!run(true)); // the host's path moved: «Не проверено»
    }
    // the exclusion rule itself (ScanClass.h::scanExclusionWhy)
    {
        const ScanNetSource ne{QStringLiteral("ne"), 0xe2ULL, 1};
        const ScanAccessAttempt open = attemptOf(false, 0, ne), close = attemptOf(false, 7000, ne);
        const QString st = QStringLiteral("gen|scan");
        const QList<ScanNetSource> tuple{ScanNetSource{QStringLiteral("app"), 1, 1}, ne};
        CHECK(scanExclusionHolds(false, open, st, close, st, st, tuple, 200, 900));
        CHECK(scanExclusionWhy(true, open, st, close, st, st, tuple, 200, 900) == QLatin1String("strict"));
        CHECK(scanExclusionWhy(false, attemptOf(true, 0, ne), st, close, st, st, tuple, 200, 900) == QLatin1String("http_answered"));
        CHECK(scanExclusionWhy(false, open, st, attemptOf(true, 7000, ne), st, st, tuple, 200, 900) == QLatin1String("http_answered"));
        CHECK(scanExclusionWhy(false, open, st, ScanAccessAttempt(), st, st, tuple, 200, 900) == QLatin1String("attempt_missing"));
        CHECK(scanExclusionWhy(false, ScanAccessAttempt(), st, close, st, st, tuple, 200, 900) == QLatin1String("attempt_missing"));
        CHECK(scanExclusionWhy(false, open, QStringLiteral("other|scan"), close, st, st, tuple, 200, 900) == QLatin1String("generation"));
        CHECK(scanExclusionWhy(false, open, QString(), close, QString(), QString(), tuple, 200, 900) == QLatin1String("generation"));
        CHECK(scanExclusionWhy(false, open, st, close, st, QStringLiteral("gen|scan2"), tuple, 200, 900) == QLatin1String("generation")); // token
        CHECK(scanExclusionWhy(false, open, st, attemptOf(false, 7000, ScanNetSource{QStringLiteral("ne"), 0xe2ULL, 2}), st, st, tuple, 200, 900)
              == QLatin1String("host_gen"));
        ScanAccessAttempt noGen = open;
        noGen.hasGen = false;
        CHECK(scanExclusionWhy(false, noGen, st, close, st, st, tuple, 200, 900) == QLatin1String("host_gen"));
        const QList<ScanNetSource> moved{ScanNetSource{QStringLiteral("app"), 1, 1}, ScanNetSource{QStringLiteral("ne"), 0xe2ULL, 5}};
        CHECK(scanExclusionWhy(false, open, st, close, st, st, moved, 200, 900) == QLatin1String("host_gen")); // the tuple has ne elsewhere
        CHECK(scanExclusionHolds(false, open, st, close, st, st, {ScanNetSource{QStringLiteral("app"), 1, 1}}, 200, 900)); // no ne in the tuple
        CHECK(scanExclusionWhy(false, open, st, close, st, st, tuple, -1, 900) == QLatin1String("window"));
        CHECK(scanExclusionWhy(false, attemptOf(false, 300, ne), st, close, st, st, tuple, 200, 900) == QLatin1String("window")); // started before
        CHECK(scanExclusionWhy(false, open, st, attemptOf(false, 800, ne), st, st, tuple, 200, 900) == QLatin1String("window"));  // ended after
        CHECK(scanExclusionHolds(false, open, st, close, st, st, tuple, 0, 7000)); // the edges count as inside
        // the class of the candidate: only an Unverifiable provider result whose egress is not tribe-node
        ScanProbeFacts f = goodData();
        f.egressClass = QStringLiteral("other");
        ScanClassifyInput in = upIn(f);
        in.access = ScanAccess();
        ScanVerdict v = scanClassify(in, ScanTunables());
        CHECK(v.cls == ScanClass::NotVerified && v.reason == QLatin1String("unverifiable") && v.exclusionCandidate
              && scanClassWorking(v.exclusionClass));
        ScanClassifyInput own = ownIn(goodData());
        own.access = ScanAccess();
        CHECK(!scanClassify(own, ScanTunables()).exclusionCandidate); // own nodes never use exclusion
    }
    // a release the allowance cannot admit waits for the scan's final release (which has its reservation)
    {
        World w = baseWorld("release", hostMac(), ScanNetKind::Cellular);
        QList<NodeSpec> only;
        for (const NodeSpec &n : w.nodes)
            if (n.provider && !n.composite)
                only << n;
        w.nodes = only;
        w.numbers.insert(QStringLiteral("scan_budget_scan_bytes"), 300000);
        ScanMachine m(w.caps);
        m.opened(openOf(w, QString(), false), kT0);
        const ScanStep s = m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50);
        const ScanAction *b = s.find(ScanActionKind::RequestProbeBatch);
        CHECK(b && b->ids.size() == 2 && m.allowanceUsed() == m.allowanceBytes()); // nothing left over
        m.probeLeaseGranted(b->ids.at(0), ScanAccess(), kT0 + 100);
        m.probeLeaseGranted(b->ids.at(1), ScanAccess(), kT0 + 100);
        ScanProbeFacts f;
        f.id = b->ids.at(0);
        f.stage = ScanStage::Reach;
        f.reachOk = false;
        f.seq = 1;
        f.error = ScanProbeError::ReachTimeout;
        const ScanStep r1 = m.hostProgress(progressOf(m, {f}), kT0 + 600);
        CHECK(!r1.has(ScanActionKind::ReleaseProbeLeases)); // no room: deferred
        const ScanStep stop = m.stopTapped(kT0 + 700);
        const ScanAction *fin = stop.find(ScanActionKind::ReleaseProbeLeases);
        CHECK(fin && fin->ids.size() == 2 && fin->ids.contains(b->ids.at(0)) && fin->costBytes == 10240); // both, on the reserved slot
        CHECK(m.allowanceUsed() <= m.allowanceBytes());
    }
    // the server's cost of one access attempt reaches the host's limits
    {
        const ScanTunables t = ScanTunables::fromNumbers({{QStringLiteral("scan_cost_netinfo_bytes"), 20000}});
        CHECK(t.costNetinfoBytes == 20000 && scanHostLimitsFrom(t, 1, 4, 2).netinfoCostBytes == 20000);
    }
    // the server's batch cap holds whatever the pools are
    {
        ScanHostCaps big = hostMac();
        big.maxLegConcurrent = 32;
        World w = baseWorld("big_pools", big, ScanNetKind::Wifi);
        w.numbers.insert(QStringLiteral("scan_stage2_concurrency_wifi"), 32);
        QList<NodeSpec> nodes = ownOnly(w.nodes);
        for (int k = 1; k <= 20; ++k) {
            NodeSpec n = artboardNodes().at(11);
            n.id = QStringLiteral("up:%1").arg(k, 16, 16, QLatin1Char('0'));
            n.rank = k;
            nodes << n;
        }
        w.nodes = nodes;
        ScanMachine m(w.caps);
        m.opened(openOf(w, QStringLiteral("1"), true), kT0);
        const ScanStep s = m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50);
        const ScanAction *b = s.find(ScanActionKind::RequestProbeBatch);
        CHECK(b && b->ids.size() == kScanProbeBatchMax);
    }
    // the ledger entry: app actual (a report that comes after the scan ended still counts until the entry is
    // written), a request never reported at its worst case, reservations never sent at 0
    {
        World w = baseWorld("ledger", hostMac(), ScanNetKind::Cellular);
        w.nodes = ownOnly(w.nodes);
        const auto run = [&w](bool reportOutcomes) {
            ScanMachine m(w.caps);
            m.opened(openOf(w, QString(), false), kT0);
            m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50);
            ScanProbeFacts f;
            f.id = QStringLiteral("4:xray");
            f.stage = ScanStage::Reach;
            f.reachOk = false;
            f.error = ScanProbeError::ReachTimeout;
            f.seq = 1;
            m.hostProgress(progressOf(m, {f}), kT0 + 2000);
            const ScanStep stop = m.tick(kT0 + 50 + 8000); // the deadline: outcomes go, the freeze follows
            const ScanAction *o = stop.find(ScanActionKind::SendOutcomes);
            checkMsg(o && o->costBytes == 16384 && stop.has(ScanActionKind::FreezeHostScan), QStringLiteral("ledger: outcomes and freeze"));
            if (o && reportOutcomes)
                m.appRequestDone(o->requestId, 5000, kT0 + 8100);
            m.hostFreezeAck(m.scanId(), 100000, 0, kT0 + 8100);
            ScanHostProgress fin = progressOf(m, {}, 100000, 0, true);
            fin.finalTotals = true;
            m.hostProgress(fin, kT0 + 8200);
            return m.ledger().spentInHour(kT0 + 8300, true);
        };
        CHECK(run(true) == 20480 + 100000 + 5000);
        CHECK(run(false) == 20480 + 100000 + 16384);
    }
    // the screen reopened on another network while the scan prepares: the scan targets the new network
    // (its manifest, its allowance rules)
    {
        World w = baseWorld("reopen_net", hostMac(), ScanNetKind::Wifi);
        ScanMachine m(w.caps);
        m.opened(openOf(w, QStringLiteral("1"), true), kT0);
        World c = baseWorld("reopen_net", hostMac(), ScanNetKind::Cellular);
        const ScanStep s = m.opened(openOf(c, QStringLiteral("1"), true), kT0 + 20); // no close in between
        const ScanAction *mr = s.find(ScanActionKind::RequestManifest);
        CHECK(m.phase() == ScanPhase::Preparing && mr && mr->networkKey == c.net.key && mr->costBytes == 280576
              && mr->requestId != m.scanId() + QStringLiteral("/manifest"));
        const ScanStep h = m.manifestReady(manifestInputFrom(manifestArgs(c)), kT0 + 100);
        const ScanAction *b = h.find(ScanActionKind::RequestProbeBatch);
        CHECK(b && !b->includeConfig && m.allowanceBytes() == 1572864);
    }
    // the reference gate's freeze: nothing admitted or charged after it, open reservations still finish
    {
        ScanHostByteGate g(300000);
        CHECK(g.admit(QStringLiteral("netinfo_close"), 10240) && g.admit(QStringLiteral("4:xray"), 83968));
        g.freeze();
        CHECK(g.frozen() && !g.admit(QStringLiteral("5:xray"), 1) && !g.charge(512));
        const qint64 bound = g.spent() + g.reserved();
        g.finish(QStringLiteral("4:xray"), 50000);
        g.finish(QStringLiteral("netinfo_close"), 1200);
        CHECK(g.spent() <= bound && g.reserved() == 0);
    }
    // outcomes: evidence on every item (contract 1.7.0): exclusion for a row proven by exclusion, else direct;
    // a batch the strict server schema accepts, and one it would reject (the check is not vacuous)
    {
        ScanOutcomeItem it;
        it.kind = QStringLiteral("upstream");
        it.id = QStringLiteral("00000000000000a1");
        it.outcome = ScanClass::Works;
        it.stage = ScanOutcomeStage::Data;
        it.probe = QStringLiteral("leg");
        it.rttMs = 62;
        it.evidence = QStringLiteral("exclusion");
        ScanOutcomeItem d = it;
        d.id = QStringLiteral("9:xray");
        d.kind = QStringLiteral("node");
        d.outcome = ScanClass::Unreachable;
        d.stage = ScanOutcomeStage::Reach;
        d.evidence.clear();
        ScanOutcomeItem odd = it;
        odd.id = QStringLiteral("00000000000000a2");
        odd.evidence = QStringLiteral("something");
        CHECK(kScanOutcomeEvidenceAccepted && it.toJson(QStringLiteral("wifi")).value(QStringLiteral("evidence")).toString() == QLatin1String("exclusion")
              && d.toJson(QStringLiteral("wifi")).value(QStringLiteral("evidence")).toString() == QLatin1String("direct")
              && odd.toJson(QStringLiteral("wifi")).value(QStringLiteral("evidence")).toString() == QLatin1String("direct"));
        ScanOutcomeCollector c;
        c.begin(QStringLiteral("cell:250-02:4g"));
        c.add(it);
        c.add(d);
        c.add(odd);
        CHECK(c.batches().size() == 1 && outcomeBatchRejects(c.batches().first()).isEmpty());
        QJsonObject bad = c.batches().first();
        QJsonArray items = bad.value(QStringLiteral("items")).toArray();
        QJsonObject i0 = items.at(0).toObject();
        i0.insert(QStringLiteral("verdict_source"), QStringLiteral("x"));
        items[0] = i0;
        bad.insert(QStringLiteral("items"), items);
        CHECK(outcomeBatchRejects(bad).startsWith(QStringLiteral("unknown key")));
        i0.remove(QStringLiteral("verdict_source"));
        i0.insert(QStringLiteral("evidence"), QStringLiteral("probably"));
        items[0] = i0;
        bad.insert(QStringLiteral("items"), items);
        CHECK(outcomeBatchRejects(bad) == QLatin1String("enum"));
        QJsonObject sum{{QStringLiteral("schema"), 1}, {QStringLiteral("network_key"), QStringLiteral("wifi")}, {QStringLiteral("candidates"), 3},
                        {QStringLiteral("counts"), QJsonObject{}}, {QStringLiteral("seats_requested"), 49}};
        CHECK(summaryRejects(sum) == QLatin1String("seats_requested"));
    }
}

// --- host failures: refused start, host gone mid-scan (coordinator finding 16.11) ----------------------------

static void hostFailures()
{
    World w = baseWorld("hostfail", hostMac(), ScanNetKind::Cellular);
    w.nodes = ownOnly(w.nodes);
    ScanCachedResult cached; // a result of this network 2 minutes old: the no-scan view keeps it
    cached.networkKey = w.net.key;
    cached.fingerprint = w.net.fingerprint;
    cached.savedAtMs = kT0 - 120000;
    ScanCachedRow row;
    row.id = QStringLiteral("4:xray");
    row.speed = ScanSpeed::Fast;
    row.ms = 40;
    cached.rows << row;
    const auto start = [&](ScanMachine &m, const World &x) {
        ScanOpen o = openOf(x, QString(), false);
        o.cached = cached;
        m.opened(o, kT0);
        return m.manifestReady(manifestInputFrom(manifestArgs(x)), kT0 + 50);
    };
    // (1) refused before the host took the start: settled at once, app actual + host 0, NoScan host_<error>
    {
        ScanMachine m(w.caps);
        start(m, w);
        CHECK(m.draining());
        const ScanStep s = m.hostFailed(m.scanId(), ScanHostError::Internal, kT0 + 70, false);
        CHECK(!m.draining() && !s.has(ScanActionKind::FreezeHostScan) && !s.has(ScanActionKind::StopHostScan));
        CHECK(s.count(ScanActionKind::PersistBudget) == 1 && m.ledger().entries().size() == 1
              && m.ledger().spentInHour(kT0 + 70, true) == 20480); // the manifest + token only
        const ScanView v = m.view(kT0 + 70);
        CHECK(v.phase == ScanPhase::NoScan && v.empty.reason == QLatin1String("host_internal") && v.rows.size() == 1
              && v.rows.at(0).fromCache && v.checkedAgoMin == 2);
        // nothing was probed: no cooldown - «Повторить» at once (macOS run of 16.11: no «через 25 с»)
        CHECK(v.bar.button == ScanBarButton::Retry && v.bar.buttonEnabled && m.cooldownUntil() <= kT0);
        // ... then reopened at once: a new scan (its own manifest request), the first scan's one ledger entry
        m.closed(kT0 + 100);
        ScanOpen o = openOf(w, QString(), false);
        o.cached = cached;
        const ScanStep re = m.opened(o, kT0 + 200);
        CHECK(re.has(ScanActionKind::RequestManifest) && m.phase() == ScanPhase::Preparing && m.ledger().entries().size() == 1 && !m.draining());
        CHECK(m.view(kT0 + 200).rows.size() == 1);
        ScanMachine q(w.caps); // nothing was deferred: a minute later nothing more is written
        start(q, w);
        q.hostFailed(q.scanId(), ScanHostError::Internal, kT0 + 70, false);
        CHECK(q.tick(kT0 + 60000).actions.isEmpty() && q.ledger().entries().size() == 1);
        // with providers: the batch that went out counts at its worst case (never reported)
        World wp = baseWorld("hostfail_p", hostMac(), ScanNetKind::Cellular);
        ScanMachine p(wp.caps);
        p.opened(openOf(wp, QString(), false), kT0);
        p.manifestReady(manifestInputFrom(manifestArgs(wp)), kT0 + 50);
        p.hostFailed(p.scanId(), ScanHostError::Memory, kT0 + 70, false);
        CHECK(!p.draining() && p.ledger().spentInHour(kT0 + 70, true) == 20480 + 12288 && p.view(kT0 + 70).empty.reason == QLatin1String("host_memory"));
    }
    // (2) the host took the start and then failed: the draining rule, bounded, with a wake
    {
        // no answer at all: the whole grant after scan_freeze_ack_ms
        ScanMachine m(w.caps);
        start(m, w);
        const qint64 grant = m.hostGrant();
        m.hostProgress(progressOf(m, {}, 40000, 83968), kT0 + 400); // the host was running
        ScanStep s = m.hostFailed(m.scanId(), ScanHostError::UnknownScan, kT0 + 500, false); // "refused" but it had answered
        CHECK(s.has(ScanActionKind::FreezeHostScan) && m.draining() && s.wakeAtMs == kT0 + 500 + 1000);
        CHECK(m.view(kT0 + 500).phase == ScanPhase::NoScan && m.view(kT0 + 500).empty.reason == QLatin1String("host_unknown_scan"));
        CHECK(!m.tick(kT0 + 1499).has(ScanActionKind::PersistBudget));
        s = m.tick(kT0 + 1500);
        CHECK(s.has(ScanActionKind::StopHostScan) && s.has(ScanActionKind::PersistBudget) && !m.draining()
              && m.ledger().spentInHour(kT0 + 1500, true) == 20480 + grant);
        // default (accepted) without any answer before: the same bounded rule
        ScanMachine d(w.caps);
        start(d, w);
        s = d.hostFailed(d.scanId(), ScanHostError::Internal, kT0 + 70);
        CHECK(s.has(ScanActionKind::FreezeHostScan) && s.wakeAtMs == kT0 + 70 + 1000);
        d.tick(kT0 + 1070);
        CHECK(!d.draining() && d.ledger().entries().size() == 1);
        // the host still answers the freeze: its ack, then (no final) after scan_drain_ms
        ScanMachine a(w.caps);
        start(a, w);
        a.hostProgress(progressOf(a, {}, 40000, 83968), kT0 + 400);
        a.hostFailed(a.scanId(), ScanHostError::Internal, kT0 + 500);
        s = a.hostFreezeAck(a.scanId(), 50000, 30000, kT0 + 530);
        CHECK(s.has(ScanActionKind::StopHostScan) && s.wakeAtMs == kT0 + 530 + 2000);
        a.tick(kT0 + 2530);
        CHECK(!a.draining() && a.ledger().spentInHour(kT0 + 2530, true) == 20480 + 80000);
        // with fresh results the scan keeps them (Done), and still settles
        ScanMachine r(w.caps);
        start(r, w);
        ScanProbeFacts f = goodData();
        f.id = QStringLiteral("2:xray");
        f.egressNode = QStringLiteral("2");
        f.seq = 1;
        r.hostProgress(progressOf(r, {f}, 83000, 0), kT0 + 900);
        s = r.hostFailed(r.scanId(), ScanHostError::Internal, kT0 + 1000);
        CHECK(s.has(ScanActionKind::FreezeHostScan) && r.phase() == ScanPhase::Done && r.view(kT0 + 1000).verifiedCount == 1);
        r.tick(kT0 + 2000);
        CHECK(!r.draining() && r.ledger().entries().size() == 1);
    }
    // iPhone: the tunnel (the host's process) goes away mid-scan - bounded the same way
    {
        World wi = baseWorld("hostfail_ios", hostIosFull(), ScanNetKind::Cellular);
        wi.nodes = ownOnly(wi.nodes);
        ScanMachine m(wi.caps);
        m.opened(openOf(wi, QStringLiteral("2:xray"), true), kT0);
        m.manifestReady(manifestInputFrom(manifestArgs(wi)), kT0 + 50);
        const ScanStep s = m.vpnState(ScanCurrent(), kT0 + 600);
        CHECK(s.has(ScanActionKind::FreezeHostScan) && s.wakeAtMs >= 0);
        m.tick(kT0 + 1600);
        CHECK(!m.draining() && m.ledger().entries().size() == 1);
    }
    // a host that ends by itself (done, a reason) but never sends its final: frozen, bounded
    {
        ScanMachine m(w.caps);
        start(m, w);
        ScanHostProgress p = progressOf(m, {}, 60000, 0, true); // done, reason deadline, no final
        const ScanStep s = m.hostProgress(p, kT0 + 3000);
        CHECK(s.has(ScanActionKind::FreezeHostScan) && s.wakeAtMs >= 0);
        m.tick(kT0 + 4000);
        CHECK(!m.draining());
    }
    // contract tolerance of the host lanes' extra fields (no contract change): caps gen / mem_available_mb,
    // candidate bytes / total_ms, item dns detail and error bind_failed (an unknown item error = internal ->
    // «Не проверено»), host error codes outside the set -> other
    {
        QJsonObject caps = scanEncodeCapsReply(hostIosFull(), {QStringLiteral("xray_full"), QStringLiteral("xray_leg"), QStringLiteral("awg_mini")});
        caps.insert(QStringLiteral("gen"), QJsonObject{{QStringLiteral("source"), QStringLiteral("ne")}, {QStringLiteral("epoch"), QStringLiteral("00000000000000aa")},
                                                      {QStringLiteral("counter"), 3}});
        caps.insert(QStringLiteral("mem_available_mb"), 21);
        const ScanHostReply rc = scanDecodeReply(scanCompact(caps));
        CHECK(rc.kind == ScanHostReplyKind::Caps && rc.caps.maxLegConcurrent == 4 && rc.caps.needsVpn);
        QJsonObject start2 = scanEncodeStart(sampleStart());
        QJsonArray cs = start2.value(QStringLiteral("candidates")).toArray();
        QJsonObject c0 = cs.at(0).toObject();
        c0.insert(QStringLiteral("bytes"), 16384);
        c0.insert(QStringLiteral("total_ms"), 3000);
        cs[0] = c0;
        start2.insert(QStringLiteral("candidates"), cs);
        ScanHostRequest d;
        CHECK(scanDecodeRequest(scanCompact(start2), d) == ScanHostError::None && d.start.candidates.size() == 3);
        ScanProbeFacts f = goodData();
        f.id = QStringLiteral("4:xray");
        f.seq = 1;
        QJsonObject item = scanProbeFactsToJson(f);
        item.insert(QStringLiteral("dns"), QJsonArray{QJsonObject{{QStringLiteral("resolver"), QStringLiteral("1.1.1.1")}, {QStringLiteral("ok"), true}}});
        item.insert(QStringLiteral("error"), QStringLiteral("bind_failed"));
        ScanHostProgress p;
        p.scanId = QStringLiteral("s");
        p.phase = QStringLiteral("data");
        QJsonObject pj = scanEncodeProgress(p);
        pj.insert(QStringLiteral("items"), QJsonArray{item});
        const ScanHostReply rp = scanDecodeReply(scanCompact(pj));
        CHECK(rp.kind == ScanHostReplyKind::Progress && rp.progress.items.size() == 1 && rp.progress.items.at(0).error == ScanProbeError::BindFailed);
        ScanClassifyInput in = ownIn(rp.progress.items.at(0));
        CHECK(scanClassify(in, ScanTunables()).cls == ScanClass::NotVerified);
        CHECK(scanDecodeReply(QByteArrayLiteral("{\"error\":\"bind_failed\"}")).error == ScanHostError::BindFailed);
        CHECK(scanDecodeReply(QByteArrayLiteral("{\"error\":\"thermal\"}")).error == ScanHostError::Other);
        CHECK(scanDecodeRequest(QByteArrayLiteral("{\"action\":\"scan_stop_all\"}"), d) == ScanHostError::UnknownAction); // host-local only
    }
}

// --- contract v2.3 pass: awg_mini config, base_ips, per-job fields, bind_failed, machine events ----------------

static void contractV23()
{
    // 1. the awg_mini config: exactly the contract's shape from the typed input
    {
        QString why;
        const QString cfg = scanAwgMiniConfig(testAwgInput(), &why);
        const QString uapi = QStringLiteral(
            "private_key=1111111111111111111111111111111111111111111111111111111111111111\n"
            "listen_port=0\n"
            "jc=4\njmin=40\njmax=70\ns1=50\ns2=100\nh1=1234\nh2=5678\nh3=91011\nh4=121314\ni1=<b 0xf6ab3267fa>\n"
            "replace_peers=true\n"
            "public_key=2222222222222222222222222222222222222222222222222222222222222222\n"
            "endpoint=203.0.113.5:51820\n"
            "replace_allowed_ips=true\n"
            "allowed_ip=198.51.100.7/32\n"
            "allowed_ip=10.8.1.1/32\n");
        const QJsonObject o = QJsonDocument::fromJson(cfg.toUtf8()).object();
        CHECK(why.isEmpty() && o.value(QStringLiteral("uapi")).toString() == uapi);
        CHECK(o.value(QStringLiteral("address")).toString() == QLatin1String("100.64.0.250/32") && o.value(QStringLiteral("mtu")).toInt() == 1280
              && o.value(QStringLiteral("prime_echo_target")).toString() == QLatin1String("10.8.1.1") && o.value(QStringLiteral("bound_if")).toInt() == 4);
        CHECK(o.value(QStringLiteral("probe")).toObject() == QJsonObject({{QStringLiteral("host"), QStringLiteral("api.tribe.example")},
                                                                          {QStringLiteral("ip"), QStringLiteral("198.51.100.7")},
                                                                          {QStringLiteral("port"), 443}}));
        CHECK(o.keys() == QStringList({QStringLiteral("address"), QStringLiteral("bound_if"), QStringLiteral("mtu"), QStringLiteral("prime_echo_target"),
                                       QStringLiteral("probe"), QStringLiteral("uapi")}));
        CHECK(!uapi.contains(QStringLiteral("keepalive")) && !uapi.startsWith(QStringLiteral("set=")));
        // the same keys in the other encodings, IPv6, a pre-shared key, no echo, no mtu, unknown interface
        ScanAwgMiniInput v6 = testAwgInput();
        v6.privateKey = QStringLiteral("ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB"); // upper-case hex
        v6.address = QStringLiteral("fd00::fa/128");
        v6.endpoint = QStringLiteral("[2001:db8::5]:51820");
        v6.probeIp = QStringLiteral("2001:db8::7");
        v6.presharedKey = QString::fromLatin1(QByteArray(32, 'k').toBase64());
        v6.echoTarget.clear();
        v6.mtu = 0;
        v6.boundIf = -1;
        const QJsonObject o6 = QJsonDocument::fromJson(scanAwgMiniConfig(v6).toUtf8()).object();
        const QString u6 = o6.value(QStringLiteral("uapi")).toString();
        CHECK(u6.contains(QStringLiteral("private_key=abababababababababababababababababababababababababababababababab\n"))
              && u6.contains(QStringLiteral("preshared_key=") + QString::fromLatin1(QByteArray(32, 'k').toHex()) + QStringLiteral("\n"))
              && u6.contains(QStringLiteral("endpoint=[2001:db8::5]:51820\n")) && u6.endsWith(QStringLiteral("allowed_ip=2001:db8::7/128\n")));
        CHECK(o6.value(QStringLiteral("address")).toString() == QLatin1String("fd00::fa/128") && !o6.contains(QStringLiteral("mtu"))
              && o6.value(QStringLiteral("prime_echo_target")).isNull() && o6.value(QStringLiteral("bound_if")).isNull());
        // refusals: never a session without what it needs
        const auto refused = [](void (*edit)(ScanAwgMiniInput &)) {
            ScanAwgMiniInput in = testAwgInput();
            edit(in);
            QString why;
            const QString c = scanAwgMiniConfig(in, &why);
            return c.isEmpty() ? why : QString();
        };
        CHECK(refused([](ScanAwgMiniInput &i) { i.address.clear(); }) == QLatin1String("awg_no_address"));
        CHECK(refused([](ScanAwgMiniInput &i) { i.address = QStringLiteral("100.64.0.250/33"); }) == QLatin1String("awg_no_address"));
        CHECK(refused([](ScanAwgMiniInput &i) { i.address = QStringLiteral("tunnel.local/32"); }) == QLatin1String("awg_no_address"));
        CHECK(refused([](ScanAwgMiniInput &i) { i.privateKey = QStringLiteral("short"); }) == QLatin1String("awg_no_key"));
        CHECK(refused([](ScanAwgMiniInput &i) { i.peerPublicKey.clear(); }) == QLatin1String("awg_no_peer_key"));
        CHECK(refused([](ScanAwgMiniInput &i) { i.presharedKey = QStringLiteral("nope"); }) == QLatin1String("awg_no_peer_key"));
        CHECK(refused([](ScanAwgMiniInput &i) { i.endpoint = QStringLiteral("node.example:51820"); }) == QLatin1String("awg_no_endpoint"));
        CHECK(refused([](ScanAwgMiniInput &i) { i.endpoint = QStringLiteral("203.0.113.5"); }) == QLatin1String("awg_no_endpoint"));
        CHECK(refused([](ScanAwgMiniInput &i) { i.probeIp = QStringLiteral("api.tribe.example"); }) == QLatin1String("awg_no_api_ip"));
        CHECK(refused([](ScanAwgMiniInput &i) { i.probeHost.clear(); }) == QLatin1String("awg_no_api_ip"));
        CHECK(refused([](ScanAwgMiniInput &i) { i.obfuscation << qMakePair(QStringLiteral("endpoint"), QStringLiteral("1.2.3.4:1")); })
              == QLatin1String("awg_bad_param")); // a param may not smuggle a structural line
        CHECK(refused([](ScanAwgMiniInput &i) { i.obfuscation << qMakePair(QStringLiteral("jc"), QStringLiteral("4\npublic_key=00")); })
              == QLatin1String("awg_bad_param"));
        CHECK(refused([](ScanAwgMiniInput &i) { i.obfuscation << qMakePair(QStringLiteral("j c"), QStringLiteral("4")); }) == QLatin1String("awg_bad_param"));
        CHECK(refused([](ScanAwgMiniInput &i) { i.echoTarget = QStringLiteral("echo.example"); }) == QLatin1String("awg_bad_param"));
        CHECK(refused([](ScanAwgMiniInput &i) { i.mtu = 9000; }) == QLatin1String("awg_bad_mtu"));
        // the typed builder: an awg_mini without the address is never emitted, its id + reason come back
        ScanCandidate awg;
        awg.id = QStringLiteral("2");
        awg.kind = ScanProbeKind::AwgMini;
        awg.origin = ScanOrigin::Own;
        awg.awgEchoTarget = QStringLiteral("10.8.0.9");
        awg.costBytes = 85292;
        ScanCandidate awg3 = awg;
        awg3.id = QStringLiteral("3");
        ScanCandidate leg;
        leg.id = QStringLiteral("4:xray");
        leg.kind = ScanProbeKind::XrayLeg;
        leg.entryIp = QStringLiteral("10.0.0.1");
        leg.entryPort = 443;
        leg.reachAtMs = 0;
        ScanCandidate emptyCfg = leg;
        emptyCfg.id = QStringLiteral("5:xray");
        QList<QPair<QString, QString>> ref;
        const QList<ScanHostCandidate> built = scanBuildHostCandidates(
            QList<ScanCandidate>{awg, awg3, leg, emptyCfg},
            [](const ScanCandidate &c) { return c.id == QLatin1String("5:xray") ? QString() : QStringLiteral("{\"outbound\":{}}"); },
            [](const ScanCandidate &c) {
                ScanAwgMiniInput in = testAwgInput();
                in.echoTarget.clear(); // the candidate's echo target fills it
                if (c.id == QLatin1String("3"))
                    in.address.clear();
                return in;
            },
            &ref);
        CHECK(built.size() == 2 && built.at(0).id == QLatin1String("2") && built.at(1).id == QLatin1String("4:xray"));
        CHECK(QJsonDocument::fromJson(built.at(0).config.toUtf8()).object().value(QStringLiteral("prime_echo_target")).toString() == QLatin1String("10.8.0.9"));
        CHECK(ref.size() == 2 && ref.at(0) == qMakePair(QStringLiteral("3"), QStringLiteral("awg_no_address"))
              && ref.at(1) == qMakePair(QStringLiteral("5:xray"), QStringLiteral("config")));
        // the redaction covers the config's secret fields wherever a parsed config shows up
        const QByteArray red = scanCompact(scanRedactForLog(QJsonDocument::fromJson(built.at(0).config.toUtf8()).object()).toObject());
        CHECK(!red.contains("private_key=") && !red.contains("100.64.0.250") && red.contains("api.tribe.example") && red.contains("<redacted>"));
        // and the start request through the typed builder keeps every other field
        ScanAction a;
        a.kind = ScanActionKind::StartHostScan;
        a.scanId = QStringLiteral("scan-1");
        a.candidates = {awg, awg3, leg};
        a.baseIps = {QStringLiteral("198.51.100.7"), QStringLiteral("2001:db8::7")};
        a.deadlineMs = 9000;
        QList<QPair<QString, QString>> ref2;
        const ScanStartRequest r = scanBuildStartRequest(a, QStringLiteral("tsc1.TEST"), QStringLiteral("https://api.tribe.example"), ScanAccess(),
                                                         [](const ScanCandidate &) { return QStringLiteral("{}"); },
                                                         [](const ScanCandidate &c) {
                                                             ScanAwgMiniInput in = testAwgInput();
                                                             if (c.id == QLatin1String("3"))
                                                                 in.address.clear();
                                                             return in;
                                                         },
                                                         &ref2);
        CHECK(r.candidates.size() == 2 && ref2.size() == 1 && r.probeBaseIps == a.baseIps && r.deadlineMs == 9000);
        // the 3c1f55a5e builder keeps its behaviour (every config as given)
        CHECK(scanBuildHostCandidates(QList<ScanCandidate>{awg, emptyCfg}, [](const ScanCandidate &) { return QString(); }).size() == 2);
    }
    // 2. probe.base_ips: optional, 1..8 IP literals; the machine passes the coordinator's (filtered)
    {
        ScanStartRequest r = sampleStart();
        CHECK(!scanEncodeStart(r).value(QStringLiteral("probe")).toObject().contains(QStringLiteral("base_ips"))); // absent when none
        r.probeBaseIps = {QStringLiteral("198.51.100.7"), QStringLiteral("2001:db8::7")};
        const QJsonObject j = scanEncodeStart(r);
        ScanHostRequest d;
        CHECK(scanDecodeRequest(scanCompact(j), d) == ScanHostError::None && d.start.probeBaseIps == r.probeBaseIps);
        QString detail;
        CHECK(scanDecodeRequest(withField(j, QStringLiteral("probe.base_ips"), QJsonArray{QStringLiteral("api.example")}), d, &detail)
                  == ScanHostError::BadRequest && detail == QLatin1String("probe.base_ips"));
        QJsonArray nine;
        for (int i = 1; i <= 9; ++i)
            nine << QStringLiteral("198.51.100.%1").arg(i);
        CHECK(scanDecodeRequest(withField(j, QStringLiteral("probe.base_ips"), nine), d) == ScanHostError::BadRequest);
        CHECK(scanDecodeRequest(withField(j, QStringLiteral("probe.base_ips"), QJsonArray()), d) == ScanHostError::BadRequest);
        CHECK(scanDecodeRequest(withField(j, QStringLiteral("probe.base_ips"), QJsonValue::Null), d) == ScanHostError::None && d.start.probeBaseIps.isEmpty());
        World w = baseWorld("baseips", hostMac(), ScanNetKind::Wifi);
        w.probeBaseIps = {QStringLiteral("198.51.100.7"), QStringLiteral("api.tribe.example"), QStringLiteral("198.51.100.7")};
        for (int i = 1; i <= 9; ++i)
            w.probeBaseIps << QStringLiteral("203.0.113.%1").arg(i);
        ScanMachine m(w.caps);
        m.opened(openOf(w, QStringLiteral("1"), true), kT0);
        const ScanStep s = m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50);
        const ScanAction *start = s.find(ScanActionKind::StartHostScan);
        CHECK(start && start->baseIps.size() == kScanProbeBaseIpsMax && start->baseIps.first() == QLatin1String("198.51.100.7")
              && !start->baseIps.contains(QStringLiteral("api.tribe.example")));
        CHECK(scanActionToJson(*start).value(QStringLiteral("base_ips")).toArray().size() == kScanProbeBaseIpsMax);
        ScanMachine none(w.caps);
        none.opened(openOf(baseWorld("baseips0", hostMac(), ScanNetKind::Wifi), QStringLiteral("1"), true), kT0);
        const ScanStep s0 = none.manifestReady(manifestInputFrom(manifestArgs(baseWorld("baseips0", hostMac(), ScanNetKind::Wifi))), kT0 + 50);
        CHECK(s0.find(ScanActionKind::StartHostScan) && !scanActionToJson(*s0.find(ScanActionKind::StartHostScan)).contains(QStringLiteral("base_ips")));
    }
    // 4. named extras: candidate bytes / total_ms (per job), item dns detail, bind_failed
    {
        ScanStartRequest r = sampleStart();
        r.candidates[0].bytes = 24576;
        r.candidates[0].totalMs = 3000;
        const QJsonObject j = scanEncodeStart(r);
        ScanHostRequest d;
        CHECK(scanDecodeRequest(scanCompact(j), d) == ScanHostError::None && d.start.candidates.at(0).bytes == 24576
              && d.start.candidates.at(0).totalMs == 3000 && d.start.candidates.at(1).bytes == 0);
        CHECK(!scanEncodeStart(sampleStart()).value(QStringLiteral("candidates")).toArray().at(0).toObject().contains(QStringLiteral("bytes")));
        QJsonArray cs = j.value(QStringLiteral("candidates")).toArray();
        QJsonObject c0 = cs.at(0).toObject();
        c0.insert(QStringLiteral("bytes"), 100); // below 1024
        cs[0] = c0;
        QJsonObject bad = j;
        bad.insert(QStringLiteral("candidates"), cs);
        CHECK(scanDecodeRequest(scanCompact(bad), d) == ScanHostError::BadRequest);
        c0.insert(QStringLiteral("bytes"), 24576);
        c0.insert(QStringLiteral("total_ms"), 99999);
        cs[0] = c0;
        bad.insert(QStringLiteral("candidates"), cs);
        CHECK(scanDecodeRequest(scanCompact(bad), d) == ScanHostError::BadRequest);
        // bind_failed: the item is «Не проверено» (reason bind_failed), no tunnel action; the host error too
        ScanProbeFacts f = goodData();
        f.error = ScanProbeError::BindFailed;
        f.httpStatus = 0;
        f.bytesReceived = 0;
        CHECK(scanClassify(ownIn(f), ScanTunables()).cls == ScanClass::NotVerified
              && scanClassify(ownIn(f), ScanTunables()).reason == QLatin1String("bind_failed"));
        CHECK(QLatin1String(scanProbeErrorName(ScanProbeError::BindFailed)) == QLatin1String("bind_failed")
              && scanProbeErrorFrom(QStringLiteral("bind_failed")) == ScanProbeError::BindFailed);
        World w = baseWorld("bind", hostMac(), ScanNetKind::Wifi);
        ScanMachine m(w.caps);
        m.opened(openOf(w, QStringLiteral("1"), true), kT0);
        m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50);
        ScanProbeFacts b;
        b.id = QStringLiteral("4:xray");
        b.seq = 1;
        b.bytesRequested = 65536;
        b.error = ScanProbeError::BindFailed;
        const ScanStep sb = m.hostProgress(progressOf(m, {b}), kT0 + 400);
        for (const ScanAction &a : sb.actions)
            CHECK(!scanActionTouchesTunnel(a.kind));
        bool nv = false;
        for (const ScanRowView &r2 : m.result(kT0 + 400))
            nv = nv || (r2.id == QLatin1String("4:xray") && !r2.verified && r2.notVerifiedReason == QLatin1String("bind_failed"));
        CHECK(nv); // «Не проверено», reason bind_failed
        CHECK(scanHostFailureReason(ScanHostError::BindFailed) == QLatin1String("host_bind_failed"));
    }
    // 5a. reportCheckRefused: a notice, no «sent» / «will be sent», the check over, the queue state kept
    {
        World w = baseWorld("refused", hostMac(), ScanNetKind::Wifi);
        w.current = QStringLiteral("1");
        w.reportRefuse = QStringLiteral("queue_full");
        w.script << qMakePair(qint64(0), at("opened", openArgs(w, w.current, true)));
        w.script << qMakePair(qint64(9000), at("support_check_tapped"));
        w.runMs = 12000;
        Driver d(w);
        d.run();
        CHECK(countActions(d, ScanActionKind::StartReportCheck) == 1 && shadeCount(d, "report_queue_full") == 1
              && !hasShade(d, "report_sent") && !hasShade(d, "report_queued") && !d.m.reportCheckRunning());
        // another diagnostic runs: its own notice; a refusal for another report changes nothing
        ScanMachine m(w.caps);
        m.opened(openOf(w, QStringLiteral("1"), true), kT0);
        m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50);
        m.reportQueueState(false, kT0 + 60);
        const ScanStep st = m.reportLinkTapped(kT0 + 70); // not in the empty state: nothing
        CHECK(st.actions.isEmpty());
        m.tick(kT0 + 50 + 8000);
        const ScanStep ck = m.supportCheckTapped(kT0 + 8200);
        const ScanAction *rc = ck.find(ScanActionKind::StartReportCheck);
        CHECK(rc && m.reportCheckRefused(QStringLiteral("report-other"), QStringLiteral("busy"), kT0 + 8300).actions.isEmpty());
        const ScanStep busy = m.reportCheckRefused(rc->reportId, QStringLiteral("busy"), kT0 + 8400);
        CHECK(busy.find(ScanActionKind::ShowShade) && busy.find(ScanActionKind::ShowShade)->shade.textKey == QLatin1String("report_check_busy"));
        CHECK(!m.reportCheckRunning());
        CHECK(m.supportCheckTapped(kT0 + 8500).has(ScanActionKind::StartReportCheck)); // a new try is possible
    }
    // 5b. «Понял» in the no-scan budget state: close + the Wi-Fi intent, as for the empty result
    {
        World w = baseWorld("gotit_budget", hostMac(), ScanNetKind::Cellular);
        QJsonArray ledger;
        ledger << QJsonObject{{QStringLiteral("at_ms"), double(kT0 - 20 * 60000)}, {QStringLiteral("bytes"), 4.95 * 1024 * 1024}, {QStringLiteral("cellular"), true}};
        ScanMachine m(w.caps);
        m.restoreBudget(ledger);
        m.opened(openOf(w, QString(), false), kT0);
        CHECK(m.phase() == ScanPhase::NoScan && m.view(kT0).empty.reason == QLatin1String("budget"));
        const ScanStep g = m.gotItTapped(kT0 + 100);
        CHECK(g.has(ScanActionKind::CloseScreen) && !m.screenOpen());
        bool intent = false;
        for (const ScanAction &a : g.actions)
            intent = intent || a.shade.textKey == QLatin1String("wifi_intent");
        CHECK(!intent); // owner 19.11: nothing scans later by itself
        // another no-scan reason: «Понял» does nothing there
        ScanMachine o(w.caps);
        o.opened(openOf(w, QString(), false), kT0);
        o.manifestUnavailable(QStringLiteral("service_off"), kT0 + 50);
        CHECK(o.gotItTapped(kT0 + 100).actions.isEmpty());
    }
    // 5c. hostFailed with the host's detail: host_kill_switch on the screen and in the Doctor summary
    {
        CHECK(scanHostFailureReason(ScanHostError::Internal, QStringLiteral("kill_switch_exemption")) == QLatin1String("host_kill_switch"));
        CHECK(scanHostFailureReason(ScanHostError::Internal) == QLatin1String("host_internal"));
        CHECK(scanHostFailureReason(ScanHostError::Internal, QStringLiteral("Pool Exhausted")) == QLatin1String("host_pool_exhausted"));
        CHECK(scanHostFailureReason(ScanHostError::Internal, QString(64, QLatin1Char('x'))).size() == 32);
        World w = baseWorld("killswitch", hostMac(), ScanNetKind::Wifi);
        w.nodes = ownOnly(w.nodes);
        ScanMachine m(w.caps);
        m.opened(openOf(w, QString(), false), kT0);
        m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50);
        m.hostFailed(m.scanId(), ScanHostError::Internal, kT0 + 70, false, QStringLiteral("kill_switch_exemption"));
        CHECK(m.view(kT0 + 70).empty.reason == QLatin1String("host_kill_switch") && !m.draining());
        const QJsonObject sum = m.lastSummary();
        CHECK(sum.value(QStringLiteral("stop_reason")).toString() == QLatin1String("host_kill_switch") && sum.value(QStringLiteral("schema")).toInt() == 1);
        CHECK(summaryRejects(sum).isEmpty() && sum.value(QStringLiteral("seats_requested")).toInt() == 0);
        // with fresh results the stop reason is the host's too
        ScanMachine r(w.caps);
        r.opened(openOf(w, QString(), false), kT0);
        r.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50);
        ScanProbeFacts f = goodData();
        f.id = QStringLiteral("2:xray");
        f.egressNode = QStringLiteral("2");
        f.seq = 1;
        r.hostProgress(progressOf(r, {f}, 83000, 0), kT0 + 900);
        r.hostFailed(r.scanId(), ScanHostError::Internal, kT0 + 1000, true, QStringLiteral("kill_switch_exemption"));
        CHECK(r.phase() == ScanPhase::Done && r.lastSummary().value(QStringLiteral("stop_reason")).toString() == QLatin1String("host_kill_switch"));
    }
    // candidateRefused: the builder could not make the probe - «Не проверено» with its reason, the scan goes on
    {
        World w = baseWorld("cand_refused", hostMac(), ScanNetKind::Wifi);
        w.awgMini = true;
        w.numbers.insert(QStringLiteral("scan_awg_concurrency"), 2);
        ScanMachine m(w.caps);
        m.opened(openOf(w, QStringLiteral("4:xray"), true), kT0);
        const ScanStep s = m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50);
        bool awgInHost = false;
        for (const ScanCandidate &c : s.find(ScanActionKind::StartHostScan)->candidates)
            awgInHost = awgInHost || (c.id == QLatin1String("2") && c.kind == ScanProbeKind::AwgMini);
        CHECK(awgInHost);
        m.candidateRefused(QStringLiteral("2"), QStringLiteral("awg_no_address"), kT0 + 60);
        bool judged = false, listed = false;
        for (const ScanRowView &r : m.result(kT0 + 60))
            judged = judged || (r.id == QLatin1String("2") && r.state == ScanRowState::NotVerified && r.notVerifiedReason == QLatin1String("awg_no_address"));
        for (const ScanRowView &r : m.view(kT0 + 60).rows)
            listed = listed || r.id == QLatin1String("2");
        CHECK(judged && !listed && m.phase() == ScanPhase::Reach); // «Не проверено» joins the list only at the scan's end
        ScanProbeFacts late = goodData(); // a late item for it is ignored
        late.id = QStringLiteral("2");
        late.seq = 1;
        late.handshakeOk = true;
        late.egressNode = QStringLiteral("2");
        m.hostProgress(progressOf(m, {late}), kT0 + 500);
        for (const ScanRowView &r : m.view(kT0 + 500).rows)
            CHECK(r.id != QLatin1String("2") || !r.verified);
        CHECK(m.candidateRefused(QStringLiteral("nope"), QStringLiteral("x"), kT0 + 600).actions.isEmpty());
    }
    // 3. an opening attempt that never left the interface (null) + a failed closing one: no exclusion
    {
        const ScanNetSource ne{QStringLiteral("ne"), 0xe2ULL, 1};
        const QString st = QStringLiteral("g|s");
        CHECK(scanExclusionWhy(false, ScanAccessAttempt(), st, attemptOf(false, 7000, ne), st, st, {}, 200, 900) == QLatin1String("attempt_missing"));
        ScanHostProgress p;
        p.scanId = QStringLiteral("s");
        p.phase = QStringLiteral("data");
        QJsonObject pj = scanEncodeProgress(p);
        pj.insert(QStringLiteral("access"), QJsonObject{{QStringLiteral("attempted"), false}});
        CHECK(!scanDecodeReply(scanCompact(pj)).progress.access.attempted);
    }
}

// --- the manual cooldown only after a scan that reached a host (macOS run of 16.11) --------------------------

// --- the seams of the first real end-to-end scan (lab run 3, 16.11) ------------------------------------------

static void labSeams()
{
    // A desktop scan with the VPN off (the lab's macOS service host): own Xray nodes; 5:xray is frozen by the
    // operator - its probe is still in flight when the scan's deadline stops it.
    World w = baseWorld("lab_seams", hostMac(), ScanNetKind::Wifi);
    QList<NodeSpec> xray;
    for (const NodeSpec &n : ownOnly(w.nodes))
        if (n.transport == ScanTransport::Xray)
            xray << n;
    w.nodes = xray;
    w.out = allWork(w.nodes);
    w.out[QStringLiteral("5:xray")].durMs = 60000;
    w.script << qMakePair(qint64(0), at("opened", openArgs(w, QString(), false)));
    w.runMs = 14000;
    {
        Driver d(w);
        d.run();
        Fail f;
        checkAllSteps(d, f, w.name);
        for (const QString &x : f.list)
            checkMsg(false, x);
        // S4: the cut probe is one candidate of the summary - not verified, "cancelled" - and the counts sum
        const QJsonObject sum = d.m.lastSummary();
        const QJsonObject counts = sum.value(QStringLiteral("counts")).toObject();
        CHECK(d.m.phase() == ScanPhase::Done && sum.value(QStringLiteral("candidates")).toInt() == xray.size()
              && counts.value(QStringLiteral("works")).toInt() == xray.size() - 1 && counts.value(QStringLiteral("not_verified")).toInt() == 1
              && sum.value(QStringLiteral("not_verified_reasons")).toObject() == (QJsonObject{{QStringLiteral("cancelled"), 1}})
              && sum.value(QStringLiteral("stop_reason")).toString() == QLatin1String("deadline"));
        CHECK(summaryBucketsWhy(sum).isEmpty());
        // ... a «Не проверено» row (fewer than scan_list_target_works verified), never «Не работает»
        const ScanView v = d.m.view(d.now);
        bool row = false;
        for (const ScanRowView &r : v.rows)
            row = row || (r.id == QLatin1String("5:xray") && !r.verified && r.state == ScanRowState::NotVerified
                          && r.notVerifiedReason == QLatin1String("cancelled"));
        CHECK(row && v.unverifiedCount == 1);
        // ... and no outcome: unknown is not a failure
        int items = 0;
        for (const ScanAction &a : actionsOf(d, ScanActionKind::SendOutcomes))
            for (const ScanOutcomeItem &o : a.outcomes) {
                ++items;
                CHECK(o.id != QLatin1String("5:xray"));
            }
        CHECK(items == xray.size() - 1);

        // S7: Done with rows and no live connection: the report link is offered and sends the summary through the
        // report flow
        CHECK(v.empty.reportLink && scanViewToJson(v).value(QStringLiteral("empty")).toObject().value(QStringLiteral("report_link")).toBool());
        ScanMachine &m = d.m;
        const qint64 t = d.now + 100;
        const ScanStep s = m.reportLinkTapped(t);
        const ScanAction *a = s.find(ScanActionKind::StartReportCheck);
        CHECK(a && !a->withConnection && !a->reportId.isEmpty() && a->report.value(QStringLiteral("scan")).toObject() == sum
              && a->report.value(QStringLiteral("with_connection")).toBool() == false);
        CHECK(m.view(t).empty.reportSending && m.view(t).empty.reportLink);
        CHECK(m.reportLinkTapped(t + 10).actions.isEmpty()); // one report at a time
        const ScanStep done = m.reportCheckDone(ScanReportDelivery::Sent, t + 1600, a ? a->reportId : QString());
        bool sent = false;
        for (const ScanAction &x : done.actions)
            sent = sent || x.shade.textKey == QLatin1String("report_sent");
        CHECK(sent && !m.view(t + 1600).empty.reportSending);
        // backpressure (plan §3.1): a full queue answers with its notice, no new check
        m.reportQueueState(true, t + 1700);
        const ScanStep full = m.reportLinkTapped(t + 1800);
        CHECK(!full.has(ScanActionKind::StartReportCheck) && full.has(ScanActionKind::ShowShade)
              && full.find(ScanActionKind::ShowShade)->shade.textKey == QLatin1String("report_queue_full"));
        m.reportQueueState(false, t + 1900);
        // a live connection appears (a row's connect): Support's check is the way and the link goes
        ScanCurrent live = liveOf(w, QStringLiteral("2:xray"), true);
        m.vpnState(live, t + 2000);
        CHECK(!m.view(t + 2000).empty.reportLink && m.reportLinkTapped(t + 2000).actions.isEmpty());
        // while a scan runs: no link
        m.vpnState(ScanCurrent(), t + 2100);
        m.retryTapped(t + 60000);
        CHECK(scanPhaseScanning(m.phase()) && !m.view(t + 60000).empty.reportLink && m.reportLinkTapped(t + 60000).actions.isEmpty());
    }
    // S7: Done WITH a live connection (desktop, VPN on): never the link (Support's check is the way)
    {
        World x = w;
        x.out[QStringLiteral("5:xray")].durMs = 500;
        x.current = QStringLiteral("2:xray");
        x.script.clear();
        x.script << qMakePair(qint64(0), at("opened", openArgs(x, x.current, true)));
        Driver d(x);
        d.run();
        const ScanView v = d.m.view(d.now);
        CHECK(d.m.phase() == ScanPhase::Done && !v.empty.reportLink
              && d.m.reportLinkTapped(d.now).actions.isEmpty());
        // S4 with the live row: it is one of the summary's rows (+1 candidate), judged by the live tunnel
        const QJsonObject sum = d.m.lastSummary();
        CHECK(summaryBucketsWhy(sum).isEmpty() && sum.value(QStringLiteral("candidates")).toInt() == x.nodes.size());
    }
    // S4: a host that failed before proving anything ends in NoScan: its candidates are counted (not verified,
    // "cancelled"), but drawn as nothing - the last result is what the screen shows
    {
        ScanMachine m(w.caps);
        m.opened(openOf(w, QString(), false), kT0);
        m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50);
        m.hostFailed(m.scanId(), ScanHostError::Memory, kT0 + 400);
        const ScanView v = m.view(kT0 + 400);
        const QJsonObject sum = m.lastSummary();
        CHECK(m.phase() == ScanPhase::NoScan && v.rows.isEmpty() && v.empty.reportLink && summaryBucketsWhy(sum).isEmpty()
              && sum.value(QStringLiteral("not_verified_reasons")).toObject().value(QStringLiteral("cancelled")).toInt()
                     == sum.value(QStringLiteral("candidates")).toInt());
    }
}

// S3 (owner road 26.11, J8; review C2): after a relaunch the button already knows the hour is spent. The gate is the
// start's own rule over the last plan's projection, persisted with the ledger and restored at construction
// (ScanBudget.h decideScanStart, ScanMachine startNeed): a fresh process over a spent hour and a persisted projection
// shows the limit and sends nothing - no manifest, no live probe; with 1.2 MiB left and a persisted 0.65 MiB projection
// it is free (no false block of a scan that fits); a start that blocks because the plan grew stores the bigger
// projection first, so the next tap sends nothing.
static void s3BudgetGateIsTheStartRule()
{
    World w = baseWorld("s3_gate", hostMac(), ScanNetKind::Cellular);
    const auto ledgerOf = [](qint64 spent) {
        QJsonArray l;
        l << QJsonObject{{QStringLiteral("at_ms"), double(kT0 - 20 * 60000)}, {QStringLiteral("bytes"), double(spent)},
                         {QStringLiteral("cellular"), true}};
        return l;
    };
    const auto projection = [](qint64 cell) {
        return QJsonObject{{QStringLiteral("cellular"), double(cell)}, {QStringLiteral("other"), 0.0}};
    };
    const auto chargeable = [](const ScanStep &st) {
        return st.has(ScanActionKind::RequestManifest) || st.has(ScanActionKind::ProbeLiveTunnel)
               || st.has(ScanActionKind::StartHostScan) || st.has(ScanActionKind::RequestProbeBatch)
               || st.has(ScanActionKind::RequestCandidates) || st.has(ScanActionKind::SendOutcomes);
    };
    // the hour spent (as on 26.11: about 3.7 MB of 5 MiB) and the last plan's projection persisted - a fresh process,
    // the VPN up on a row: blocked, nothing chargeable on open, tap or «Найти ещё»
    {
        ScanMachine m(w.caps);
        m.restoreBudget(ledgerOf(3800000));
        m.restoreProjection(projection(1435006));
        const ScanStep open = m.opened(openOf(w, QStringLiteral("1"), true), kT0);
        CHECK(!chargeable(open) && m.phase() == ScanPhase::NoScan);
        const ScanView v = m.view(kT0);
        CHECK(v.bar.button == ScanBarButton::RetryInMinutes && !v.bar.buttonEnabled && v.bar.buttonValue >= 1
              && v.bar.hint == ScanHint::CellularBudgetHour);
        CHECK(!chargeable(m.retryTapped(kT0 + 2000)));
        CHECK(!chargeable(m.moreTapped(QString(), kT0 + 2100)));
        CHECK(m.ledger().spentInHour(kT0 + 2200, true) == 3800000); // nothing charged
    }
    // 1.2 MiB left, a persisted projection of 0.65 MiB: the scan fits - free, the open fetches the manifest
    {
        ScanMachine m(w.caps);
        m.restoreBudget(ledgerOf(5242880 - 1258291));
        m.restoreProjection(projection(681574));
        const ScanStep open = m.opened(openOf(w, QString(), false), kT0);
        CHECK(open.has(ScanActionKind::RequestManifest) && m.phase() == ScanPhase::Preparing);
        CHECK(m.view(kT0).bar.hint != ScanHint::CellularBudgetHour);
    }
    // the projection travels with the ledger: what one machine stored, the next one (a relaunch) restores
    {
        ScanMachine a(w.caps);
        a.restoreProjection(projection(777777));
        ScanMachine b(w.caps);
        b.restoreProjection(a.projectionJson());
        CHECK(b.projectionJson() == a.projectionJson());
    }
    // a start that blocks because the plan grew: the projection is stored first - the gate is blocked from then on
    {
        ScanMachine m(w.caps);
        m.restoreBudget(ledgerOf(5242880 - 900000)); // room for a small plan only
        m.restoreProjection(projection(0));
        CHECK(m.opened(openOf(w, QString(), false), kT0).has(ScanActionKind::RequestManifest));
        m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50); // the whole pool: its projection does not fit
        CHECK(m.phase() == ScanPhase::NoScan && m.view(kT0 + 60).empty.reason == QLatin1String("budget"));
        CHECK(m.projectionJson().value(QStringLiteral("cellular")).toDouble() > 0);
        CHECK(!chargeable(m.retryTapped(kT0 + 2000)) && m.view(kT0 + 2000).bar.button == ScanBarButton::RetryInMinutes);
    }
}

static void cooldownRule()
{
    World w = baseWorld("cool", hostMac(), ScanNetKind::Cellular);
    w.nodes = ownOnly(w.nodes);
    // the desktop service is not running: NoScan service_off, retry enabled at once, no countdown
    {
        ScanMachine m(w.caps);
        m.opened(openOf(w, QString(), false), kT0);
        m.manifestUnavailable(QStringLiteral("service_off"), kT0 + 80, 20480);
        ScanView v = m.view(kT0 + 80);
        CHECK(v.phase == ScanPhase::NoScan && v.empty.reason == QLatin1String("service_off") && v.bar.button == ScanBarButton::Retry
              && v.bar.buttonEnabled && v.bar.buttonValue == 0 && v.nextChangeAtMs < 0);
        CHECK(m.ledger().spentInHour(kT0 + 80, true) == 20480); // the manifest's real bytes, not its worst case
        // the fixed back-off: a press within kScanManifestBackoffMs of the last request does nothing (and the
        // button does not count it down); after it, the press scans
        CHECK(m.retryTapped(kT0 + 500).actions.isEmpty() && m.view(kT0 + 500).bar.button == ScanBarButton::Retry);
        CHECK(m.retryTapped(kT0 + 1000).has(ScanActionKind::RequestManifest) && m.phase() == ScanPhase::Preparing);
        // the same for the S1b button
        World wi = baseWorld("cool_ios", hostIosFull(), ScanNetKind::Cellular);
        ScanMachine b(wi.caps);
        ScanOpen o = openOf(wi, QString(), false);
        o.connectOnOpen = false;
        b.opened(o, kT0);
        b.connectAndScanTapped(kT0 + 10);
        b.manifestUnavailable(QStringLiteral("service_off"), kT0 + 80);
        CHECK(b.connectAndScanTapped(kT0 + 600).actions.isEmpty());
    }
    // a refused start (and no host at all): at once; a host that accepted the start and then failed: the cooldown
    {
        ScanMachine r(w.caps);
        r.opened(openOf(w, QString(), false), kT0);
        r.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50);
        CHECK(r.cooldownUntil() == kT0 + 30000); // armed by the host start ...
        r.hostFailed(r.scanId(), ScanHostError::NoVpn, kT0 + 70, false);
        CHECK(r.cooldownUntil() <= kT0 && r.view(kT0 + 70).bar.button == ScanBarButton::Retry); // ... disarmed by the refusal
        CHECK(r.view(kT0 + 70).empty.reason == QLatin1String("host_no_vpn") && r.retryTapped(kT0 + 1100).has(ScanActionKind::RequestManifest));
        ScanMachine a(w.caps);
        a.opened(openOf(w, QString(), false), kT0);
        a.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50);
        a.hostProgress(progressOf(a, {}, 1000, 0), kT0 + 400); // it answered: it took the start
        a.hostFailed(a.scanId(), ScanHostError::Internal, kT0 + 500, false);
        a.tick(kT0 + 1500);
        CHECK(a.cooldownUntil() == kT0 + 30000 && a.view(kT0 + 1500).bar.button == ScanBarButton::RetryInSeconds
              && a.retryTapped(kT0 + 2000).actions.isEmpty());
        // a refused start while the live probe went through the tunnel: bytes moved, the cooldown holds
        ScanMachine l(w.caps);
        l.opened(openOf(w, QStringLiteral("2:xray"), true), kT0);
        const ScanStep ls = l.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50);
        CHECK(ls.has(ScanActionKind::ProbeLiveTunnel));
        l.hostFailed(l.scanId(), ScanHostError::Internal, kT0 + 70, false);
        CHECK(l.cooldownUntil() == kT0 + 30000);
        // owner road 26.11 (S2, J3; review C1): the same refused start for MEMORY gives the pause back - its text tells
        // the person to turn the VPN off and run the check again; a cooldown armed before this tap stays as it was
        ScanMachine lm(w.caps);
        lm.opened(openOf(w, QStringLiteral("2:xray"), true), kT0);
        CHECK(lm.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50).has(ScanActionKind::ProbeLiveTunnel));
        lm.hostFailed(lm.scanId(), ScanHostError::Memory, kT0 + 70, false);
        CHECK(lm.cooldownUntil() <= kT0);
        const ScanView lv = lm.view(kT0 + 70);
        CHECK(lv.empty.reason == QLatin1String("host_memory") && lv.bar.button == ScanBarButton::Retry && lv.bar.buttonEnabled
              && lv.bar.buttonValue == 0);
        CHECK(lm.retryTapped(kT0 + 1100).has(ScanActionKind::RequestManifest));
        ScanMachine k(w.caps);
        k.opened(openOf(w, QString(), false), kT0);
        k.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50); // armed until kT0 + 30000 by the host start
        k.hostProgress(progressOf(k, {}, 1000, 0), kT0 + 400);
        k.hostFailed(k.scanId(), ScanHostError::Internal, kT0 + 500, false); // took the start: the pause holds
        k.tick(kT0 + 31000);
        CHECK(k.retryTapped(kT0 + 31000).has(ScanActionKind::RequestManifest));
        k.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 31050);
        k.hostFailed(k.scanId(), ScanHostError::Memory, kT0 + 31070, false);
        CHECK(k.cooldownUntil() == kT0 + 30000); // what it was before the tap
        // the host never started but the app-side scan sent the live probe (grant below one probe): the cooldown
        World ws = baseWorld("cool_app_side", hostMac(), ScanNetKind::Cellular);
        ws.manifestBytes = 270336;
        ws.numbers.insert(QStringLiteral("scan_budget_scan_bytes"), 420000);
        ScanMachine as(ws.caps);
        as.opened(openOf(ws, QStringLiteral("1"), true), kT0);
        const ScanStep ss = as.manifestReady(manifestInputFrom(manifestArgs(ws)), kT0 + 50);
        CHECK(!ss.has(ScanActionKind::StartHostScan) && ss.has(ScanActionKind::ProbeLiveTunnel) && as.cooldownUntil() == kT0 + 30000);
        // budget / switch-off no-scans arm nothing
        ScanMachine n(w.caps);
        QJsonArray ledger;
        ledger << QJsonObject{{QStringLiteral("at_ms"), double(kT0 - 20 * 60000)}, {QStringLiteral("bytes"), 4.95 * 1024 * 1024}, {QStringLiteral("cellular"), true}};
        n.restoreBudget(ledger);
        n.opened(openOf(w, QString(), false), kT0);
        CHECK(n.phase() == ScanPhase::NoScan && n.cooldownUntil() == 0);
        World wo = baseWorld("cool_off", hostIosFull(), ScanNetKind::Wifi);
        ScanMachine off(wo.caps);
        ScanOpen oo = openOf(wo, QString(), false);
        oo.connectOnOpen = false;
        off.opened(oo, kT0);
        CHECK(off.view(kT0).empty.reason == QLatin1String("vpn_off") && off.cooldownUntil() == 0
              && off.view(kT0).bar.button == ScanBarButton::ConnectAndScan);
    }
    // ten instant retries on cellular with the service down: each scans, all inside the hourly budget
    {
        ScanMachine m(w.caps);
        m.opened(openOf(w, QString(), false), kT0);
        qint64 t = kT0;
        int scans = 0;
        for (int k = 0; k < 10; ++k) {
            m.manifestUnavailable(QStringLiteral("service_off"), t + 80, 20480);
            CHECK(m.view(t + 80).bar.button == ScanBarButton::Retry && m.view(t + 80).bar.buttonEnabled);
            t += 1100; // the user presses again a second later
            if (k < 9)
                scans += m.retryTapped(t).has(ScanActionKind::RequestManifest) ? 1 : 0;
        }
        CHECK(scans == 9 && m.ledger().entries().size() == 10 && m.ledger().spentInHour(t, true) == 10 * 20480
              && m.ledger().spentInHour(t, true) <= m.tunables().budgetCellularBytesPerHour);
        // the hour is the bound: requests that never report their bytes are charged at the worst case, and
        // the button turns into «через N мин» before the cellular hour is passed
        ScanMachine h(w.caps);
        h.opened(openOf(w, QString(), false), kT0);
        qint64 u = kT0;
        int ok = 0;
        for (int k = 0; k < 40; ++k) {
            h.manifestUnavailable(QStringLiteral("service_off"), u + 80); // bytes unknown: 280576 each
            u += 1100;
            const ScanStep r = h.retryTapped(u);
            if (!r.has(ScanActionKind::RequestManifest))
                break;
            ++ok;
        }
        CHECK(ok < 40 && h.view(u).bar.button == ScanBarButton::RetryInMinutes
              && h.ledger().spentInHour(u, true) <= h.tunables().budgetCellularBytesPerHour);
    }
}

// --- real bytes above a reservation are recorded (review 16.11: the live probe cut on the wire) --------------

static void overruns()
{
    // the allowance itself: admission atomic, a finish charges the real size, the remainder never negative
    {
        ScanAllowance g(100000);
        CHECK(g.admit(QStringLiteral("a"), 60000) && g.admit(QStringLiteral("b"), 30000) && !g.admit(QStringLiteral("c"), 20000));
        g.finish(QStringLiteral("a"), 60000 + 16384 + 900); // one chunk late
        CHECK(g.spent() == 77284 && g.reserved() == 30000 && g.left() == 0 && g.overshoot() == 7284);
        CHECK(!g.admit(QStringLiteral("c"), 1)); // the remainder is gone: nothing more is admitted
        g.finish(QStringLiteral("b"), 1000);
        CHECK(g.left() == 100000 - 78284 && g.overshoot() == 0 && g.admit(QStringLiteral("c"), 20000));
        g.finish(QStringLiteral("c"), -5); // never negative
        CHECK(g.spent() == 78284 && g.reserved() == 0);
        ScanAllowance free;
        CHECK(free.admit(QStringLiteral("x"), 1 << 30) && free.left() == -1 && free.overshoot() == 0);
    }
    World w = baseWorld("overrun", hostMac(), ScanNetKind::Cellular);
    w.nodes = ownOnly(w.nodes);
    const qint64 late = kScanAppChunkBytes + 1200; // one chunk + headers past the reservation
    // the live probe: its real bytes count, the host's later admissions see the smaller remainder
    {
        ScanMachine m(w.caps);
        m.opened(openOf(w, QStringLiteral("1"), true), kT0);
        const ScanStep s = m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50);
        const ScanAction *lp = s.find(ScanActionKind::ProbeLiveTunnel);
        CHECK(lp && lp->costBytes == 82944);
        const qint64 grant = m.hostGrant();
        Driver dd(w);
        ScanProbeFacts f = dd.liveFacts(QStringLiteral("1"));
        f.spentBytes = 82944 + late;
        m.liveProbeResult(QStringLiteral("1"), f, kT0 + 700);
        CHECK(m.allowanceOvershoot() == late && m.hostGrant() == grant); // recorded; the host keeps its grant
        // a further app request (a release in the middle of the scan) is admitted only against what is left
        m.stopTapped(kT0 + 1000);
        m.hostFreezeAck(m.scanId(), 50000, 0, kT0 + 1030);
        ScanHostProgress fin = progressOf(m, {}, 50000, 0, true);
        fin.finalTotals = true;
        m.hostProgress(fin, kT0 + 1100);
        // ledger = manifest 20480 + live 82944 + late + the live row's outcome batch sent at the end and never
        // reported (its worst case 16384) + host 50000
        CHECK(!m.draining() && m.ledger().spentInHour(kT0 + 1100, true) == 20480 + 82944 + late + 16384 + 50000);
    }
    // the manifest: a full answer one chunk past its reservation - the grant is cut from what is left
    {
        World wm = w;
        wm.manifestBytes = 270336 + 10240 + late;
        ScanMachine m(wm.caps);
        m.opened(openOf(wm, QString(), false), kT0);
        const ScanStep s = m.manifestReady(manifestInputFrom(manifestArgs(wm)), kT0 + 50);
        const ScanAction *a = s.find(ScanActionKind::StartHostScan);
        CHECK(a && a->maxBytes == 1572864 - (270336 + 10240 + late) - 16384);
        m.hostFailed(m.scanId(), ScanHostError::Internal, kT0 + 70, false);
        CHECK(m.ledger().spentInHour(kT0 + 70, true) == 270336 + 10240 + late); // all of it, host 0
    }
    // the seat batch: its answer one chunk past its reservation
    {
        World wb = baseWorld("overrun_batch", hostMac(), ScanNetKind::Cellular);
        ScanMachine m(wb.caps);
        m.opened(openOf(wb, QString(), false), kT0);
        const ScanStep s = m.manifestReady(manifestInputFrom(manifestArgs(wb)), kT0 + 50);
        const ScanAction *b = s.find(ScanActionKind::RequestProbeBatch);
        CHECK(b && b->costBytes == 12288);
        const qint64 before = m.allowanceUsed();
        m.appRequestDone(b->requestId, 12288 + late, kT0 + 200);
        CHECK(m.allowanceUsed() == before + late && m.allowanceOvershoot() == late);
        m.hostFailed(m.scanId(), ScanHostError::Internal, kT0 + 300, false);
        CHECK(m.ledger().spentInHour(kT0 + 300, true) == 20480 + 12288 + late);
    }
    // real bytes reported after the ledger entry was written, and for a request charged at once outside a
    // scan: the excess over what was charged joins the hour; less is not refunded
    {
        ScanMachine m(w.caps);
        m.opened(openOf(w, QStringLiteral("1"), true), kT0);
        const ScanStep s = m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50);
        const ScanAction *lp = s.find(ScanActionKind::ProbeLiveTunnel);
        m.hostFailed(m.scanId(), ScanHostError::Internal, kT0 + 60, false); // settled at once: live at its worst case
        const qint64 l0 = m.ledger().spentInHour(kT0 + 60, true);
        const ScanStep r = m.appRequestDone(lp->requestId, 82944 + late, kT0 + 700);
        CHECK(r.has(ScanActionKind::PersistBudget) && m.ledger().spentInHour(kT0 + 700, true) == l0 + late);
        CHECK(m.appRequestDone(lp->requestId, 999999, kT0 + 800).actions.isEmpty()); // once
        // a request outside a scan (the live probe of a connection that came up after the scan) is charged
        // at once at its reservation; reported larger, the excess joins the hour too
        const ScanStep c = m.vpnState(liveOf(w, QStringLiteral("2:xray"), true), kT0 + 2500);
        const ScanAction *o = c.find(ScanActionKind::ProbeLiveTunnel);
        CHECK(o && o->requestId.startsWith(QStringLiteral("post/")) && o->costBytes == 82944);
        if (o) {
            const qint64 l1 = m.ledger().spentInHour(kT0 + 2500, true);
            m.appRequestDone(o->requestId, o->costBytes + 3000, kT0 + 2600);
            CHECK(m.ledger().spentInHour(kT0 + 2600, true) == l1 + 3000);
            m.appRequestDone(o->requestId, 1, kT0 + 2700);
            CHECK(m.ledger().spentInHour(kT0 + 2700, true) == l1 + 3000);
        }
    }
    // the hour is crossed because of an overrun: the scan's reservations fill what the hour had left, the live
    // probe comes back one chunk late - recorded in full, the hour is past its cap, nothing negative, the next
    // scan is blocked
    {
        World wh = baseWorld("overrun_hour", hostMac(), ScanNetKind::Cellular);
        QList<NodeSpec> two;
        for (const NodeSpec &n : wh.nodes)
            if (n.id == QLatin1String("1") || n.id == QLatin1String("4:xray"))
                two << n;
        wh.nodes = two;
        const qint64 cap = 5242880, left = 640000; // the projection (one own Xray burst) and the app side fit
        QJsonArray ledger;
        ledger << QJsonObject{{QStringLiteral("at_ms"), double(kT0 - 20 * 60000)}, {QStringLiteral("bytes"), double(cap - left)}, {QStringLiteral("cellular"), true}};
        ScanMachine m(wh.caps);
        m.restoreBudget(ledger);
        m.opened(openOf(wh, QStringLiteral("1"), true), kT0);
        const ScanStep s = m.manifestReady(manifestInputFrom(manifestArgs(wh)), kT0 + 50);
        CHECK(s.has(ScanActionKind::StartHostScan) && m.allowanceBytes() == left && m.allowanceUsed() == left); // all of it reserved
        Driver dd(wh);
        ScanProbeFacts f = dd.liveFacts(QStringLiteral("1"));
        f.spentBytes = 82944 + late;
        m.liveProbeResult(QStringLiteral("1"), f, kT0 + 700);
        CHECK(m.allowanceOvershoot() == late && m.hostGrant() >= 0);
        m.stopTapped(kT0 + 1000);
        m.tick(kT0 + 2000); // no freeze ack: the whole grant
        CHECK(!m.draining() && m.ledger().spentInHour(kT0 + 2000, true) > cap
              && m.ledger().spentInHour(kT0 + 2000, true) == cap - left + left + late); // every real byte, past the cap
        CHECK(m.ledger().leftInHour(kT0 + 2000, cap, true) == 0);
        const ScanStep again = m.retryTapped(kT0 + 31000); // after the cooldown: the hour blocks it
        CHECK(!again.has(ScanActionKind::RequestManifest) && m.view(kT0 + 31000).bar.button == ScanBarButton::RetryInMinutes);
    }
    // a whole run with overruns on every cut reply: the ledger is never below the real bytes
    {
        World wr = baseWorld("overrun_run", hostMac(), ScanNetKind::Cellular);
        wr.current = QStringLiteral("1");
        wr.cutApp = QStringLiteral("batch");
        wr.appOverrunBytes = int(late);
        wr.liveOverrunBytes = int(late);
        wr.script << qMakePair(qint64(0), at("opened", openArgs(wr, wr.current, true)));
        wr.runMs = 12000;
        Driver d(wr);
        d.run();
        Fail f;
        checkAllSteps(d, f, wr.name);
        for (const QString &x : f.list)
            checkMsg(false, x);
        d.m.tick(d.now + 60000);
        d.m.tick(d.now + 70000);
        CHECK(d.overruns == 2 && d.m.ledger().spentInHour(d.now + 70000, true) >= d.appBytesReported);
    }
}

// --- properties --------------------------------------------------------------------------------------------

// Random worlds and random user/env events on top of the Driver: every invariant of every step holds.
static World randomWorld(std::mt19937 &rng, int k)
{
    const ScanHostCaps hosts[] = {hostIosMinimal(), hostIosFull(), hostMac(), hostMacMinimal()};
    World w = baseWorld("random", hosts[rng() % 4], rng() % 2 ? ScanNetKind::Cellular : ScanNetKind::Wifi);
    w.name = QStringLiteral("random_%1").arg(k);
    for (auto it = w.out.begin(); it != w.out.end(); ++it) {
        Outcome &o = it.value();
        o.reachOk = rng() % 5 != 0;
        o.works = rng() % 4 != 0;
        o.ttfb1 = 100 + int(rng() % 2500);
        o.rtt = 20 + int(rng() % 1400);
        o.t64 = 50 + int(rng() % 3500);
        o.durMs = 200 + int(rng() % 2500);
        o.handshake = rng() % 5 != 0;
        o.egressOther = rng() % 9 == 0;
        if (rng() % 9 == 0)
            o.egressNode = rng() % 2 ? QStringLiteral("-") : QStringLiteral("9");
        o.dnsOk = rng() % 3 != 0;
        o.sameNet = rng() % 10 == 0;
        o.fullWorks = int(rng() % 3) - 1;
        if (rng() % 12 == 0)
            o.error = ScanProbeError::Memory;
    }
    for (NodeSpec &n : w.nodes) {
        n.crowd = rng() % 3 == 0;
        n.awgProbe = rng() % 4 != 0;
    }
    w.awgMini = rng() % 2;
    w.awgIpKnown = rng() % 5 != 0;
    if (rng() % 2)
        w.numbers.insert(QStringLiteral("scan_awg_concurrency"), double(rng() % 4));
    const QStringList ids = {QStringLiteral("1"), QStringLiteral("2:xray"), QStringLiteral("4:xray"), up(1), QString()};
    w.current = ids.at(int(rng() % ids.size()));
    w.lkg = QStringLiteral("2:xray");
    if (rng() % 3 == 0)
        w.leaseRefuse.insert(up(int(1 + rng() % 4)), rng() % 2 ? QStringLiteral("no_seat") : QStringLiteral("disabled"));
    if (rng() % 3 == 0) {
        QJsonArray ledger;
        ledger << QJsonObject{{QStringLiteral("at_ms"), double(kT0 - qint64(rng() % 3600000))}, {QStringLiteral("bytes"), double(rng() % 6000000 + 1)},
                              {QStringLiteral("cellular"), true}};
        w.ledger = ledger;
    }
    if (rng() % 4 == 0)
        w.numbers.insert(QStringLiteral("scan_budget_scan_bytes"), 65536 + double(rng() % 500000));
    if (rng() % 4 == 0)
        w.numbers.insert(QStringLiteral("scan_stop_works"), 1 + double(rng() % 12));
    w.connectFails.insert(QStringLiteral("2:xray"));
    w.script << qMakePair(qint64(0), at("opened", openArgs(w, w.current, !w.current.isEmpty())));
    const char *user[] = {"row_tapped", "stop", "closed", "retry", "filter", "check_tapped", "report_link_tapped", "got_it", "app_foreground",
                          "network_changed", "opened", "connect_failed", "attempt_ended", "report_check_started", "host_failed", "lease_refused"};
    const int nUser = int(rng() % 7);
    for (int i = 0; i < nUser; ++i) {
        const qint64 t = qint64(rng() % 15000);
        const QString e = QLatin1String(user[rng() % 16]);
        const QString target = (QStringList{QStringLiteral("2:xray"), QStringLiteral("4:xray"), QStringLiteral("2"), up(1), up(2)}).at(int(rng() % 5));
        const ScanNetwork other = rng() % 2 ? scanNet(ScanNetKind::Wifi, QStringLiteral("wifi:asn:64999"))
                                            : scanNet(ScanNetKind::Cellular, QStringLiteral("cell:250-01:5g"));
        const World snapshot = w;
        const bool accepted = rng() % 2;
        w.script << qMakePair(t, std::function<QJsonObject(qint64)>([e, target, other, snapshot, accepted](qint64 at) {
            if (e == QLatin1String("row_tapped") || e == QLatin1String("connect_failed"))
                return ev(e.toUtf8().constData(), at, {{QStringLiteral("node_id"), target}});
            if (e == QLatin1String("filter"))
                return ev("filter", at, {{QStringLiteral("cc"), QStringLiteral("DE")}});
            if (e == QLatin1String("network_changed"))
                return ev("network_changed", at, {{QStringLiteral("network"), netJson(other)}, {QStringLiteral("cached"), QJsonObject()},
                                                  {QStringLiteral("app_in_front"), true}});
            if (e == QLatin1String("opened"))
                return ev("opened", at, openArgs(snapshot, snapshot.current, !snapshot.current.isEmpty()));
            if (e == QLatin1String("host_failed")) // the first scan's id (opened at kT0); later scans ignore it
                return ev("host_failed", at, {{QStringLiteral("scan_id"), QStringLiteral("scan-%1-1").arg(kT0)}, {QStringLiteral("error"), QStringLiteral("memory")},
                                              {QStringLiteral("start_accepted"), accepted}});
            if (e == QLatin1String("lease_refused"))
                return ev("lease_refused", at, {{QStringLiteral("node_id"), target}, {QStringLiteral("code"), QStringLiteral("no_seat")}});
            return ev(e.toUtf8().constData(), at);
        }));
    }
    w.runMs = 20000;
    return w;
}

static void properties()
{
    std::mt19937 rng(20261115);
    int summaries = 0, withCancelled = 0, withLive = 0;
    for (int k = 0; k < 160; ++k) {
        const World w = randomWorld(rng, k);
        Driver d(w);
        d.run();
        Fail f;
        checkAllSteps(d, f, w.name); // every step: the summary's counts sum to its candidates (lab seam S4)
        {
            // lab seam S4: the property must meet the case it is about - probes the stop cut in flight
            QSet<QString> seen;
            for (const Recorded &r : d.steps) {
                const QByteArray key = QJsonDocument(r.summary).toJson(QJsonDocument::Compact);
                if (r.summary.isEmpty() || seen.contains(QString::fromUtf8(key)))
                    continue;
                seen.insert(QString::fromUtf8(key));
                ++summaries;
                withCancelled += r.summary.value(QStringLiteral("not_verified_reasons")).toObject().contains(QStringLiteral("cancelled")) ? 1 : 0;
                for (const QJsonValue &t : r.summary.value(QStringLiteral("top")).toArray())
                    withLive += t.toObject().value(QStringLiteral("probe")).toString() == QLatin1String("tunnel") ? 1 : 0;
            }
        }
        {
            // nothing drains forever: after the bounded waits every scan's host bytes are settled
            ScanMachine &m = d.m;
            m.tick(d.now + 60000);
            m.tick(d.now + 70000);
            checkMsg(!m.draining(), w.name + QStringLiteral(": draining forever"));
            // the ledger never understates: at least every real byte the coordinator reported
            checkMsg(m.ledger().spentInHour(d.now + 70000, false) >= d.appBytesReported, w.name + QStringLiteral(": ledger below the real bytes"));
        }
        // tier admission: a shown non-forced row of tier T means every working row of a tier below T is shown
        // (checked on the machine's final state)
        const qint64 end = d.now;
        const ScanView v = d.m.view(end);
        QSet<QString> shown;
        for (const ScanRowView &r : v.rows)
            if (r.verified)
                shown.insert(r.id);
        int maxShownTier = -1;
        const QList<ScanMachine::DebugRow> all = d.m.debugWorkingRows(end);
        for (const ScanMachine::DebugRow &r : all)
            if (shown.contains(r.id) && !r.forced)
                maxShownTier = qMax(maxShownTier, r.tier);
        if (v.bar.selected.isEmpty())
            for (const ScanMachine::DebugRow &r : all)
                if (r.tier < maxShownTier)
                    f.check(shown.contains(r.id), w.name + QStringLiteral(": a lower-tier working row left out: ") + r.id);
        // the list's order and lifetime between consecutive views: checkAllSteps (scan_world.h checkListStep)
        for (const QString &x : f.list)
            checkMsg(false, x);
        if (f.list.isEmpty())
            checkMsg(true, QString());
    }
    std::printf("properties: %d summaries, %d with probes cancelled in flight, %d live rows\n", summaries, withCancelled, withLive);
    CHECK(summaries > 100 && withCancelled > 0 && withLive > 0);
    // the schedule never contains the current node (random currents, every host)
    for (int k = 0; k < 300; ++k) {
        const ScanHostCaps hosts[] = {hostIosMinimal(), hostIosFull(), hostMac(), hostMacMinimal()};
        World w = baseWorld("s", hosts[rng() % 4], rng() % 2 ? ScanNetKind::Cellular : ScanNetKind::Wifi);
        const QString cur = w.nodes.at(int(rng() % w.nodes.size())).id;
        ScanPlanInput in = planInput(w.caps, w.net.kind, cur);
        in.lastKnownGood = w.nodes.at(int(rng() % w.nodes.size())).id;
        const ScanPlan p = buildScanPlan(in);
        for (const ScanCandidate &c : p.probe)
            checkMsg(c.id != cur, QStringLiteral("current scheduled"));
        for (const ScanCandidate &c : p.orderOnly)
            checkMsg(c.id != cur, QStringLiteral("current as order-only"));
        // deterministic and in tier order
        const ScanPlan p2 = buildScanPlan(in);
        checkMsg(p.probe.size() == p2.probe.size(), QStringLiteral("deterministic"));
        for (int i = 0; i < p.probe.size() && i < p2.probe.size(); ++i)
            checkMsg(p.probe.at(i).id == p2.probe.at(i).id, QStringLiteral("deterministic order"));
        for (int i = 1; i < p.probe.size(); ++i)
            checkMsg(p.probe.at(i - 1).tier <= p.probe.at(i).tier, QStringLiteral("tier order"));
    }
    // crowd marks never change order or verdict
    for (int k = 0; k < 30; ++k) {
        World a = randomWorld(rng, 1000 + k);
        a.script.erase(a.script.begin() + 1, a.script.end());
        World b = a;
        for (NodeSpec &n : b.nodes)
            n.crowd = !n.crowd;
        Driver da(a), db(b);
        da.run();
        db.run();
        QStringList ra, rb;
        for (const QJsonValue &r : lastView(da).value(QStringLiteral("rows")).toArray())
            ra << r.toObject().value(QStringLiteral("id")).toString() + r.toObject().value(QStringLiteral("state")).toString();
        for (const QJsonValue &r : lastView(db).value(QStringLiteral("rows")).toArray())
            rb << r.toObject().value(QStringLiteral("id")).toString() + r.toObject().value(QStringLiteral("state")).toString();
        checkMsg(ra == rb, QStringLiteral("crowd changed the list"));
    }
    // any prefix of any event stream is safe: random JSON events straight into the machine
    const char *names[] = {"opened", "closed", "stop", "retry", "got_it", "filter", "network_changed", "app_foreground", "vpn_state",
                           "manifest_ready", "manifest_unavailable", "host_failed", "host_progress", "lease_granted", "lease_refused",
                           "light_fact", "row_tapped", "connect_failed", "attempt_ended", "check_tapped", "report_link_tapped",
                           "report_check_started", "report_check_progress", "report_check_done", "tick", "garbage"};
    for (int k = 0; k < 300; ++k) {
        const ScanHostCaps hosts[] = {hostIosMinimal(), hostIosFull(), hostMac()};
        World w = baseWorld("fuzz", hosts[rng() % 3], rng() % 2 ? ScanNetKind::Cellular : ScanNetKind::Wifi);
        ScanMachine m(w.caps);
        qint64 now = kT0;
        QString prevPhase = QStringLiteral("idle");
        ListSteps list(m.tunables());
        for (int i = 0; i < 80; ++i) {
            now += qint64(rng() % 1500) - 200;
            const QString e = QLatin1String(names[rng() % 26]);
            QJsonObject args;
            if (e == QLatin1String("opened"))
                args = openArgs(w, rng() % 2 ? QStringLiteral("1") : QString(), rng() % 2);
            else if (e == QLatin1String("vpn_state"))
                args = {{QStringLiteral("current"), currentJson(liveOf(w, rng() % 2 ? QStringLiteral("2:xray") : QString(), rng() % 2))}};
            else if (e == QLatin1String("manifest_ready"))
                args = manifestArgs(w);
            else if (e == QLatin1String("host_progress")) {
                ScanHostProgress p;
                p.scanId = rng() % 4 ? m.scanId() : QStringLiteral("other");
                p.phase = QStringLiteral("data");
                p.seq = qint64(rng() % 50);
                ScanProbeFacts f = goodData(int(rng() % 900), int(rng() % 4000));
                f.id = w.nodes.at(int(rng() % w.nodes.size())).id + (rng() % 5 == 0 ? QStringLiteral("#full") : QString());
                if (rng() % 4)
                    f.egressNode = scanHostPartOf(f.id.section(QLatin1Char('#'), 0, 0));
                f.seq = qint64(rng() % 60);
                f.stage = rng() % 3 ? ScanStage::Data : ScanStage::Reach;
                f.reachOk = rng() % 2;
                f.shaOk = rng() % 4;
                f.handshakeOk = rng() % 2;
                f.echoSent = 40;
                f.echoReplies = int(rng() % 41);
                p.items << f;
                p.bytesSpent = qint64(rng() % 3000000);
                p.done = rng() % 6 == 0;
                p.reason = (QStringList{QString(), QStringLiteral("complete"), QStringLiteral("deadline"), QStringLiteral("memory")}).at(int(rng() % 4));
                args = {{QStringLiteral("reply"), scanEncodeProgress(p)}};
            } else if (e == QLatin1String("lease_granted") || e == QLatin1String("lease_refused") || e == QLatin1String("row_tapped")
                       || e == QLatin1String("connect_failed"))
                args = {{QStringLiteral("node_id"), w.nodes.at(int(rng() % w.nodes.size())).id}, {QStringLiteral("code"), QStringLiteral("no_seat")}};
            else if (e == QLatin1String("light_fact"))
                args = {{QStringLiteral("kind"), (QStringList{QStringLiteral("server"), QStringLiteral("services"), QStringLiteral("sites"), QStringLiteral("speed")}).at(int(rng() % 4))},
                        {QStringLiteral("state"), rng() % 2 ? QStringLiteral("done") : QStringLiteral("running")}};
            else if (e == QLatin1String("network_changed"))
                args = {{QStringLiteral("network"), netJson(rng() % 2 ? w.net : scanNet(ScanNetKind::Wifi, QStringLiteral("wifi")))},
                        {QStringLiteral("app_in_front"), bool(rng() % 2)}};
            else if (e == QLatin1String("host_failed"))
                args = {{QStringLiteral("scan_id"), m.scanId()}, {QStringLiteral("error"), QStringLiteral("internal")},
                        {QStringLiteral("start_accepted"), bool(rng() % 2)}};
            else if (e == QLatin1String("filter"))
                args = {{QStringLiteral("cc"), rng() % 2 ? QStringLiteral("DE") : QStringLiteral("ZZ")}};
            const QJsonObject event = ev(e.toUtf8().constData(), now, args);
            const ScanStep s = applyScanEvent(m, event);
            Recorded r{event, s, scanViewToJson(m.view(now)), m.spentBytes(), m.leaseReservedBytes(), m.capBytes(), m.allowanceBytes(),
                       m.allowanceUsed(), m.draining(), 0, QJsonObject(), m.listBuilds()};
            Fail f;
            checkStepInvariants(r, prevPhase, m, QString(), f, QStringLiteral("fuzz"));
            list.step(r, f.list, QStringLiteral("fuzz ") + e);
            const QString buckets = summaryBucketsWhy(m.lastSummary()); // lab seam S4, any event stream
            f.check(buckets.isEmpty(), QStringLiteral("fuzz: summary ") + buckets);
            // the current-node check needs the real current: done by checkAllSteps on driven runs
            for (const QString &x : f.list)
                if (!x.contains(QStringLiteral("current node")))
                    checkMsg(false, x);
            prevPhase = phaseOf(r.view);
        }
        // whatever happened, a scan's host bytes settle within the bounded waits: nothing drains forever
        m.tick(now + 60000);
        m.tick(now + 70000);
        checkMsg(!m.draining(), QStringLiteral("fuzz: draining forever"));
    }
}

// --- provider rows (contract 1.10.0, owner 17.11) and the network change after a result ------------------------

// «Найти ещё» (ScanMachine::moreTapped, 18.11): the next batch skips what this network judged, keeps the rows found,
// counts its own new rows for the stop, says when nothing is left; a country restricts the batch.
static void findMore()
{
    World w = baseWorld("more", hostMac(), ScanNetKind::Wifi);
    w.nodes = ownOnly(w.nodes);
    w.numbers.insert(QStringLiteral("scan_stop_works"), 1); // one working row ends a batch
    const auto candidatesOf = [](const ScanStep &s) {
        QList<ScanCandidate> out;
        for (const ScanAction &a : s.actions)
            if (a.kind == ScanActionKind::StartHostScan)
                out << a.candidates;
        return out;
    };
    // manifestReady, and for a scope / «Найти ещё» an older server's answer to the batch request (local fallback)
    const auto afterManifest = [&](ScanMachine &mm, qint64 at) {
        ScanStep st = mm.manifestReady(manifestInputFrom(manifestArgs(w)), at);
        for (const ScanAction &a : st.actions)
            if (a.kind == ScanActionKind::RequestCandidates) {
                const ScanStep f = mm.candidatesUnavailable(a.requestId, QStringLiteral("scanner_off"), 300, at + 1);
                st.actions << f.actions;
            }
        return st;
    };
    const auto works = [](const QString &id) {
        ScanProbeFacts f = goodData();
        f.id = id;
        f.egressNode = id.section(QLatin1Char(':'), 0, 0);
        return f;
    };
    ScanMachine m(w.caps);
    m.opened(openOf(w, QString(), false), kT0);
    const QList<ScanCandidate> first = candidatesOf(afterManifest(m, kT0 + 50));
    CHECK(first.size() >= 3);
    if (first.size() < 3)
        return;
    m.hostProgress(progressOf(m, {works(first.at(0).id)}), kT0 + 900);
    m.tick(kT0 + 50 + 8000);
    ScanView v = m.view(kT0 + 8100);
    CHECK(!v.scanning && v.verifiedCount == 1 && v.moreAvailable && v.batch == 1);
    CHECK(scanViewToJson(v).value(QStringLiteral("more_available")).toBool() && scanViewToJson(v).value(QStringLiteral("batch")).toInt() == 1);

    // batch 2: the proven row stays fresh, its candidate is not probed again; the stop counts the new rows only
    {
        ScanMachine early = m; // the re-scan cooldown runs (owner 19.11): «Найти ещё» is not held by it
        CHECK(early.view(kT0 + 9000).bar.button == ScanBarButton::RetryInSeconds && early.view(kT0 + 9000).moreBlocked.isEmpty());
        CHECK(early.moreTapped(QString(), kT0 + 9000).has(ScanActionKind::RequestManifest));
    }
    CHECK(m.moreTapped(QString(), kT0 + 31000).has(ScanActionKind::RequestManifest));
    const QList<ScanCandidate> second = candidatesOf(afterManifest(m, kT0 + 31050));
    bool skipped = !second.isEmpty();
    for (const ScanCandidate &c : second)
        skipped = skipped && c.id != first.at(0).id;
    CHECK(skipped && second.size() == first.size() - 1);
    v = m.view(kT0 + 31060);
    CHECK(v.scanning && v.verifiedCount == 1 && v.batch == 2 && v.moreState == QLatin1String("running"));
    QList<ScanProbeFacts> all;
    for (const ScanCandidate &c : second)
        all << works(c.id);
    m.hostProgress(progressOf(m, all), kT0 + 31900);
    m.tick(kT0 + 31050 + 8000);
    v = m.view(kT0 + 39200);
    CHECK(!v.scanning && v.verifiedCount == 1 + second.size() && !v.moreAvailable && v.moreState == QLatin1String("exhausted"));
    CHECK(scanViewToJson(v).value(QStringLiteral("more")).toObject().value(QStringLiteral("state")).toString() == QLatin1String("exhausted")); // everything judged: nothing more

    // batch 3: nothing left - ends at once, still nothing more
    m.moreTapped(QString(), kT0 + 70000);
    const QList<ScanCandidate> third = candidatesOf(afterManifest(m, kT0 + 70050));
    v = m.view(kT0 + 70100);
    CHECK(third.isEmpty() && !v.scanning && !v.moreAvailable && v.batch == 3 && v.verifiedCount == 1 + second.size());

    // a country batch over the whole pool: only that country's candidates, the filter set to it
    ScanMachine c(w.caps);
    c.opened(openOf(w, QString(), false), kT0);
    const QList<ScanCandidate> any = candidatesOf(afterManifest(c, kT0 + 50));
    c.tick(kT0 + 50 + 8000);
    QString cc;
    for (const ScanCandidate &x : any)
        if (!x.countryCode.isEmpty())
            cc = x.countryCode;
    CHECK(!cc.isEmpty());
    c.moreTapped(cc.toLower(), kT0 + 31000);
    const QList<ScanCandidate> only = candidatesOf(afterManifest(c, kT0 + 31050));
    bool sameCountry = !only.isEmpty();
    for (const ScanCandidate &x : only)
        sameCountry = sameCountry && x.countryCode == cc;
    CHECK(sameCountry && c.view(kT0 + 31060).moreCountry == cc);

    // an ordinary open after a series starts a new one
    ScanMachine o(w.caps);
    o.opened(openOf(w, QString(), false), kT0);
    o.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50);
    o.tick(kT0 + 50 + 8000);
    o.moreTapped(QString(), kT0 + 31000);
    afterManifest(o, kT0 + 31050);
    o.tick(kT0 + 31050 + 8100);
    CHECK(o.view(kT0 + 39100).batch == 2);
    o.retryTapped(kT0 + 90000);
    CHECK(o.view(kT0 + 90010).batch == 1);
    // the country menu is the scope of the next scan over the whole pool (UI spec 18.11)
    ScanMachine sc(w.caps);
    sc.opened(openOf(w, QString(), false), kT0);
    sc.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50);
    sc.tick(kT0 + 50 + 8000);
    ScanView sv = sc.view(kT0 + 8100);
    CHECK(!sv.bar.scopeCountries.isEmpty() && sv.bar.scannedScope.isEmpty());
    const QJsonObject bar = scanViewToJson(sv).value(QStringLiteral("bar")).toObject();
    CHECK(bar.value(QStringLiteral("scope_countries")).toArray().size() == sv.bar.scopeCountries.size()
          && bar.contains(QStringLiteral("scanned_scope")));
    const QString scopeCc = sv.bar.scopeCountries.first().countryCode;
    sc.filterChosen(scopeCc, kT0 + 8200);
    CHECK(sc.view(kT0 + 8200).bar.scope == scopeCc);
    sc.retryTapped(kT0 + 40000);
    const QList<ScanCandidate> scoped = candidatesOf(afterManifest(sc, kT0 + 40050));
    bool inScope = !scoped.isEmpty();
    for (const ScanCandidate &x : scoped)
        inScope = inScope && x.countryCode == scopeCc;
    CHECK(inScope && sc.view(kT0 + 40060).bar.scannedScope == scopeCc);
    sc.filterChosen(QStringLiteral("ZZ"), kT0 + 50000); // not in the pool: nothing changes
    CHECK(sc.view(kT0 + 50000).bar.scope == scopeCc || sc.view(kT0 + 50000).scanning);

    // a batch probes at most 10 candidates; the rest makes «more available»
    ScanPlanInput big = planInput(hostMac());
    big.maxProbe = 2;
    const ScanPlan bp = buildScanPlan(big);
    const ScanPlan fp = buildScanPlan(planInput(hostMac()));
    CHECK(bp.probe.size() == 2 && bp.remaining == fp.probe.size() - 2 && kScanMoreBatch == 10);

    // the radio generation is shown, never part of the network's identity
    ScanMachine rd(w.caps);
    ScanOpen ro = openOf(w, QString(), false);
    ro.network.kind = ScanNetKind::Cellular;
    ro.network.radio = QStringLiteral("lte");
    rd.opened(ro, kT0);
    CHECK(rd.view(kT0).netRadio == QLatin1String("lte") && scanViewToJson(rd.view(kT0)).value(QStringLiteral("net_radio")).toString() == QLatin1String("lte"));
    ScanNetwork nr = ro.network;
    nr.radio = QStringLiteral("5g");
    CHECK(nr == ro.network);
    rd.networkChanged(nr, ScanCachedResult(), kT0 + 10);
    CHECK(rd.view(kT0 + 10).netRadio == QLatin1String("5g"));
}

// «Найти ещё» on the owner's iPhone (19.11): (a) a dead button while the re-scan countdown ran - the cooldown held it
// silently; now only a real limit holds it and the view names it; (b) a second batch replaced the list - the list
// cap (scan_list_target_works) applied to the whole series and re-sorted it by speed; now each batch has its own
// cap, the rows of the batches before keep their places and the new rows join after them; `seen` carries what the
// host cannot probe; a server batch of rows already seen ends the series instead of offering it again.
static void findMoreAppends()
{
    World w = baseWorld("more_append", hostMac(), ScanNetKind::Wifi);
    w.nodes = ownOnly(w.nodes);
    w.caps.maxAwgConcurrent = 0; // this host cannot probe AmneziaWG: those nodes are absent ("awg_no_host")
    w.numbers.insert(QStringLiteral("scan_stop_works"), 1);
    w.numbers.insert(QStringLiteral("scan_list_target_works"), 1);
    const auto actionOf = [](const ScanStep &s, ScanActionKind k) {
        for (const ScanAction &a : s.actions)
            if (a.kind == k)
                return a;
        return ScanAction();
    };
    const auto works = [](const QString &id, int rtt) {
        ScanProbeFacts f = goodData(rtt);
        f.id = id;
        f.egressNode = id.section(QLatin1Char(':'), 0, 0);
        return f;
    };
    const auto ids = [](const ScanView &v) {
        QStringList out;
        for (const ScanRowView &r : v.rows)
            if (r.verified)
                out << r.id;
        return out;
    };
    ScanMachine m(w.caps);
    m.opened(openOf(w, QString(), false), kT0);
    const ScanAction s1 = actionOf(m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50), ScanActionKind::StartHostScan);
    CHECK(s1.candidates.size() >= 3);
    if (s1.candidates.size() < 3)
        return;
    bool awgProbed = false;
    for (const ScanCandidate &c : s1.candidates)
        awgProbed = awgProbed || c.transport == ScanTransport::Awg;
    CHECK(!awgProbed);
    const QString a = s1.candidates.at(0).id;
    m.hostProgress(progressOf(m, {works(a, 900)}), kT0 + 900); // a medium row
    m.tick(kT0 + 50 + 8000);
    ScanView v = m.view(kT0 + 8100);
    CHECK(!v.scanning && ids(v) == QStringList{a} && v.moreState == QLatin1String("available"));
    const quint64 listBuilds = m.listBuilds();

    // (a) inside the re-scan cooldown: «Повторить через N с», and «Найти ещё» starts at once
    CHECK(v.bar.button == ScanBarButton::RetryInSeconds && v.moreBlocked.isEmpty());
    const ScanStep more = m.moreTapped(QString(), kT0 + 9000);
    CHECK(more.has(ScanActionKind::RequestManifest));
    const ScanStep ms = m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 9050);
    const ScanAction rc = actionOf(ms, ScanActionKind::RequestCandidates);
    // `seen`: the judged row and the nodes this host cannot probe (own AmneziaWG "1", "2")
    CHECK(!rc.requestId.isEmpty() && rc.ids.contains(a) && rc.ids.contains(QStringLiteral("1")) && rc.ids.contains(QStringLiteral("2")));
    // an older server: the device's own next batch, without what was seen
    const ScanAction s2 = actionOf(m.candidatesUnavailable(rc.requestId, QStringLiteral("unsupported"), 300, kT0 + 9100),
                                   ScanActionKind::StartHostScan);
    CHECK(!s2.candidates.isEmpty());
    if (s2.candidates.isEmpty())
        return;
    for (const ScanCandidate &c : s2.candidates)
        CHECK(c.id != a);
    const QString b = s2.candidates.at(0).id;
    m.hostProgress(progressOf(m, {works(b, 60)}), kT0 + 9600); // a FAST row: it must not jump over the first batch
    v = m.view(kT0 + 9700);
    CHECK(ids(v) == (QStringList{a, b})); // (b) appended while the batch runs
    m.tick(kT0 + 9100 + 8000);
    v = m.view(kT0 + 17200);
    CHECK(!v.scanning && v.batch == 2 && ids(v) == (QStringList{a, b}) && v.verifiedCount == 2); // (b) 1 + 1, in place
    CHECK(m.listBuilds() == listBuilds); // «Найти ещё» appends to the list it continues: never builds a new one

    // (a) the cellular hour used up: the button says why, a tap does nothing
    {
        QJsonArray ledger; // far past the cellular hour's cap, spent after the first batch
        ledger << QJsonObject{{QStringLiteral("at_ms"), double(kT0 + 10000)}, {QStringLiteral("bytes"), double(512LL * 1024 * 1024)},
                              {QStringLiteral("cellular"), true}};
        World wc = w;
        wc.net = scanNet(ScanNetKind::Cellular, QStringLiteral("cell:250-02:4g"));
        ScanMachine mc(wc.caps);
        mc.opened(openOf(wc, QString(), false), kT0);
        const ScanAction c1 = actionOf(mc.manifestReady(manifestInputFrom(manifestArgs(wc)), kT0 + 50), ScanActionKind::StartHostScan);
        if (!c1.candidates.isEmpty())
            mc.hostProgress(progressOf(mc, {works(c1.candidates.at(0).id, 900)}), kT0 + 900);
        mc.tick(kT0 + 50 + 8000);
        CHECK(mc.view(kT0 + 8100).moreState == QLatin1String("available") && mc.view(kT0 + 8100).moreBlocked.isEmpty());
        mc.restoreBudget(ledger);
        const ScanView bv = mc.view(kT0 + 40000);
        CHECK(bv.moreBlocked == QLatin1String("budget") && bv.moreRetryMin > 0);
        const QJsonObject mj = scanViewToJson(bv).value(QStringLiteral("more")).toObject();
        CHECK(mj.value(QStringLiteral("blocked")).toString() == QLatin1String("budget") && mj.value(QStringLiteral("retry_min")).toInt() > 0);
        CHECK(!mc.moreTapped(QString(), kT0 + 40000).has(ScanActionKind::RequestManifest));
        CHECK(!scanViewToJson(m.view(kT0 + 40000)).value(QStringLiteral("more")).toObject().contains(QStringLiteral("blocked")));
    }

    // a server that answers «Найти ещё» with rows the request already listed in `seen`: nothing new - exhausted
    ScanMachine sv(w.caps);
    sv.opened(openOf(w, QString(), false), kT0);
    const ScanAction t1 = actionOf(sv.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50), ScanActionKind::StartHostScan);
    if (t1.candidates.isEmpty())
        return;
    sv.hostProgress(progressOf(sv, {works(t1.candidates.at(0).id, 900)}), kT0 + 900);
    sv.tick(kT0 + 50 + 8000);
    sv.moreTapped(QString(), kT0 + 9000);
    const ScanAction rs = actionOf(sv.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 9050), ScanActionKind::RequestCandidates);
    ScanManifestView mv;
    scanManifestViewFromJson(manifestBody(w), mv);
    ScanCandidatesView cv;
    cv.exhausted = false;
    for (const ScanManifestNode &n : mv.nodes)
        if (rs.ids.contains(n.nodeId))
            cv.nodes << n;
    CHECK(!cv.nodes.isEmpty());
    sv.candidatesReady(rs.requestId, cv, 2000, kT0 + 9100);
    const ScanView ev = sv.view(kT0 + 9200);
    CHECK(!ev.scanning && ev.moreState == QLatin1String("exhausted") && ids(ev).size() == 1);
}

// R8: «Найти ещё» with a pool beyond the 512 ids one request may carry. The batch the server returns after 522 judged
// rows can be ten rows the truncated `seen` did not list but the device already judged: nothing new to probe, so the
// series ends as exhausted (before: counted against the truncated list as new -> no probe, the button stayed).
static void findMoreTruncatedSeen()
{
    World w = baseWorld("more_truncated", hostMac(), ScanNetKind::Wifi);
    w.nodes.clear();
    for (int i = 0; i < 560; ++i) {
        NodeSpec n;
        n.id = QStringLiteral("n%1:xray").arg(i + 100);
        n.label = QStringLiteral("Node %1").arg(i);
        n.cc = QStringLiteral("DE");
        n.entryIp = QStringLiteral("198.51.100.%1").arg(1 + i % 250);
        n.entryPort = 443;
        n.rank = i;
        w.nodes << n;
    }
    w.out = allWork(w.nodes);
    w.numbers.insert(QStringLiteral("scan_stop_works"), 100000);
    const auto actionOf = [](const ScanStep &s, ScanActionKind k) {
        for (const ScanAction &a : s.actions)
            if (a.kind == k)
                return a;
        return ScanAction();
    };
    ScanManifestView mv;
    scanManifestViewFromJson(manifestBody(w), mv);
    ScanMachine m(w.caps);
    m.opened(openOf(w, QString(), false), kT0);
    qint64 t = kT0;
    t += 50;
    ScanAction first = actionOf(m.manifestReady(manifestInputFrom(manifestArgs(w)), t), ScanActionKind::StartHostScan);
    QSet<QString> judged;
    const auto judge = [&](const QList<ScanCandidate> &cands) {
        QList<ScanProbeFacts> items;
        for (const ScanCandidate &c : cands) {
            ScanProbeFacts f = goodData(60);
            f.id = c.id;
            f.egressNode = c.id.section(QLatin1Char(':'), 0, 0);
            items << f;
            judged.insert(c.id);
        }
        t += 900;
        m.hostProgress(progressOf(m, items), t);
        t += 9000;
        m.tick(t);
    };
    judge(first.candidates);
    ScanAction rs;
    for (int round = 0; round < 80 && judged.size() < 530; ++round) {
        t += 40000;
        m.moreTapped(QString(), t);
        t += 50;
        rs = actionOf(m.manifestReady(manifestInputFrom(manifestArgs(w)), t), ScanActionKind::RequestCandidates);
        if (rs.requestId.isEmpty())
            break;
        ScanCandidatesView cv;
        for (const ScanManifestNode &n : mv.nodes)
            if (!rs.ids.contains(n.nodeId) && !judged.contains(n.nodeId) && cv.nodes.size() < 24)
                cv.nodes << n;
        t += 50;
        const ScanAction st = actionOf(m.candidatesReady(rs.requestId, cv, 2000, t), ScanActionKind::StartHostScan);
        if (st.candidates.isEmpty())
            break;
        judge(st.candidates);
    }
    CHECK(judged.size() >= 530);
    // the next request is truncated to 512; ten judged rows lie beyond it
    t += 40000;
    m.moreTapped(QString(), t);
    t += 50;
    rs = actionOf(m.manifestReady(manifestInputFrom(manifestArgs(w)), t), ScanActionKind::RequestCandidates);
    CHECK(!rs.requestId.isEmpty() && rs.ids.size() == 512);
    ScanCandidatesView cv;
    cv.exhausted = false;
    for (const ScanManifestNode &n : mv.nodes)
        if (!rs.ids.contains(n.nodeId) && judged.contains(n.nodeId) && cv.nodes.size() < 10)
            cv.nodes << n;
    CHECK(cv.nodes.size() == 10);
    t += 50;
    m.candidatesReady(rs.requestId, cv, 2000, t);
    const ScanView v = m.view(t + 100);
    CHECK(!v.scanning && v.moreState == QLatin1String("exhausted"));
}

// A scan always starts a new list (owner 19.11, device test: «Czechia stayed at the top, dark, the new countries below»).
// «Сканировать» clears the previous result's rows (the live connection's row stays), the scan builds the list from empty,
// append-only; «Найти ещё» appends; a cached result is shown only for the scope it covered (one slot per scope).
static int stepAfter(const Driver &d, const char *event, qint64 offsetMs)
{
    for (int i = 0; i < d.steps.size(); ++i)
        if (d.steps.at(i).event.value(QLatin1String("event")).toString() == QLatin1String(event)
            && qint64(d.steps.at(i).event.value(QLatin1String("now_ms")).toDouble()) - kT0 >= offsetMs)
            return i;
    return -1;
}

// Device round 13 (A7, A8): in EVERY state where the VPN is connected the connected server is the first row. A list
// built from a cached result, or again after the person tapped a row of a later batch, puts the live connection's
// row first; a row that becomes connected by a tap stays in place for the list on the screen.
static void connectedFirstInEveryList()
{
    World w = baseWorld("cf", hostMac(), ScanNetKind::Wifi);
    w.nodes = ownOnly(w.nodes);
    w.numbers.insert(QStringLiteral("scan_stop_works"), 1);
    const auto candidatesOf = [](const ScanStep &s) {
        QList<ScanCandidate> out;
        for (const ScanAction &a : s.actions)
            if (a.kind == ScanActionKind::StartHostScan)
                out << a.candidates;
        return out;
    };
    const auto afterManifest = [&](ScanMachine &mm, qint64 at) {
        ScanStep st = mm.manifestReady(manifestInputFrom(manifestArgs(w)), at);
        for (const ScanAction &a : st.actions)
            if (a.kind == ScanActionKind::RequestCandidates) {
                const ScanStep f = mm.candidatesUnavailable(a.requestId, QStringLiteral("scanner_off"), 300, at + 1);
                st.actions << f.actions;
            }
        return st;
    };
    const auto works = [](const QString &id) {
        ScanProbeFacts f = goodData();
        f.id = id;
        f.egressNode = id.section(QLatin1Char(':'), 0, 0);
        return f;
    };
    const auto firstRow = [](ScanMachine &mm, qint64 at) {
        const ScanView v = mm.view(at);
        return v.rows.isEmpty() ? QString() : v.rows.first().id;
    };
    ScanMachine m(w.caps);
    m.opened(openOf(w, QString(), false), kT0);
    const QList<ScanCandidate> first = candidatesOf(afterManifest(m, kT0 + 50));
    CHECK(first.size() >= 3);
    if (first.size() < 3)
        return;
    m.hostProgress(progressOf(m, {works(first.at(0).id)}), kT0 + 900);
    m.tick(kT0 + 50 + 8000);
    m.moreTapped(QString(), kT0 + 31000);
    const QList<ScanCandidate> second = candidatesOf(afterManifest(m, kT0 + 31050));
    CHECK(!second.isEmpty());
    if (second.isEmpty())
        return;
    ScanStep ended = m.hostProgress(progressOf(m, {works(second.at(0).id)}), kT0 + 32000);
    ended.actions << m.tick(kT0 + 31050 + 8100).actions;
    {
        // what is put away keeps each row's batch (the reopened list has every row the person saw: device round 13, A10)
        bool saw = false;
        QSet<int> batches;
        for (const ScanAction &a : ended.actions)
            if (a.kind == ScanActionKind::PersistResults) {
                saw = true;
                for (const ScanCachedRow &r : a.cached.rows)
                    batches.insert(r.batch);
            }
        CHECK(saw && batches.contains(1) && batches.contains(2) && !batches.contains(0));
    }
    const QString tapped = second.at(0).id;
    CHECK(m.view(kT0 + 40000).rows.size() >= 2);
    // the tap: the row connects and stays where it is on the list on the screen
    const QStringList before = [&]() { QStringList o; for (const ScanRowView &r : m.view(kT0 + 40000).rows) o << r.id; return o; }();
    CHECK(m.rowTapped(tapped, kT0 + 40100).has(ScanActionKind::ConnectRow));
    m.vpnState(openOf(w, tapped, true).current, kT0 + 42000);
    {
        QStringList after;
        for (const ScanRowView &r : m.view(kT0 + 42100).rows)
            after << r.id;
        CHECK(after == before); // no jump
    }
    // the next time a list is built (the page is closed and opened again) the connected row is the first one
    m.closed(kT0 + 43000);
    m.opened(openOf(w, tapped, true), kT0 + 44000);
    CHECK(firstRow(m, kT0 + 44100) == tapped);
    // a scope change builds a list from the cache: the live connection's row is first there too
    m.filterChosen(QString(), kT0 + 45000);
    CHECK(firstRow(m, kT0 + 45100) == tapped);
}

// Device round 13, A10: a result of a «Найти ещё» series (14 rows in two batches) is kept whole across the store and
// shown whole when the page is opened again; the cache is bounded (kScanCacheRowsMax); a result stored by an earlier
// build (no batch numbers) still reads as one batch.
static void cachedResultKeepsEveryShownRow()
{
    World w = baseWorld("cache14", hostMac(), ScanNetKind::Wifi);
    w.nodes = ownOnly(w.nodes);
    ScanCachedResult c;
    c.networkKey = w.net.key;
    c.fingerprint = w.net.fingerprint;
    c.savedAtMs = kT0 - 60000;
    c.scope = QStringLiteral("DE");
    QStringList ids;
    for (int i = 0; i < 14; ++i) {
        ScanCachedRow r;
        r.id = QStringLiteral("%1:xray").arg(100 + i);
        r.label = QStringLiteral("Германия %1").arg(i + 1);
        r.countryCode = QStringLiteral("DE");
        r.speed = ScanSpeed::Fast;
        r.ms = 40 + 5 * i;
        r.batch = i < 10 ? 1 : 2;
        c.rows << r;
        ids << r.id;
    }
    const ScanCachedResult back = scanCachedResultFromJson(scanCachedResultToJson(c));
    CHECK(back.rows.size() == 14 && back.rows.at(12).batch == 2 && back.rows.at(0).batch == 1);
    const auto shownIds = [&](const ScanCachedResult &cr) {
        ScanMachine m(w.caps);
        ScanOpen o = openOf(w, QString(), false);
        o.cached = cr;
        m.shown(o, kT0);
        QStringList out;
        for (const ScanRowView &r : m.view(kT0 + 20).rows)
            out << r.id;
        return out;
    };
    CHECK(shownIds(back) == ids); // every row the person saw is back, in the order of the cached speeds
    ScanCachedResult legacy = back;
    for (ScanCachedRow &r : legacy.rows)
        r.batch = 0;
    CHECK(shownIds(legacy).size() == 10); // an earlier build's result: one batch, the old cap
    // the bound
    ScanCachedResult big = c;
    big.rows.clear();
    for (int i = 0; i < 2 * kScanCacheRowsMax; ++i) {
        ScanCachedRow r = c.rows.first();
        r.id = QStringLiteral("%1:xray").arg(1000 + i);
        r.batch = 1 + i / 10;
        big.rows << r;
    }
    CHECK(scanCachedResultFromJson(scanCachedResultToJson(big)).rows.size() == big.rows.size()); // the reader never drops
}

// Review of 142 (finding 1): connecting a restored row keeps its batch; 14 cached rows stay 14 after the page is reopened.
static void connectedRestoredRowKeepsItsBatch()
{
    World w = baseWorld("restored", hostMac(), ScanNetKind::Wifi);
    w.nodes = ownOnly(w.nodes);
    ScanCachedResult c;
    c.networkKey = w.net.key;
    c.fingerprint = w.net.fingerprint;
    c.savedAtMs = kT0 - 60000;
    c.scope = QStringLiteral("DE");
    for (int i = 0; i < 14; ++i) {
        ScanCachedRow r;
        r.id = QStringLiteral("%1:xray").arg(100 + i);
        r.label = QStringLiteral("Германия %1").arg(i + 1);
        r.countryCode = QStringLiteral("DE");
        r.speed = ScanSpeed::Fast;
        r.ms = 40 + 5 * i;
        r.batch = i < 10 ? 1 : 2;
        c.rows << r;
    }
    ScanMachine m(w.caps);
    ScanOpen o = openOf(w, QString(), false);
    o.cached = c;
    m.shown(o, kT0);
    CHECK(m.view(kT0 + 10).rows.size() == 14);
    ScanOpen conn = openOf(w, QStringLiteral("112:xray"), true);
    m.vpnState(conn.current, kT0 + 1000);
    m.closed(kT0 + 2000);
    ScanOpen again = conn;
    again.cached = c;
    m.shown(again, kT0 + 3000);
    CHECK(m.view(kT0 + 3010).rows.size() == 14);
    CHECK(m.view(kT0 + 3010).rows.first().id == QLatin1String("112:xray"));
}

static void scanStartsNewList()
{
    const QString de = QStringLiteral("DE");
    // (a) a Germany result is cached; «Все страны» is chosen: no Germany rows from that result as an all-countries one
    {
        World w = baseWorld("fresh_a", hostMac(), ScanNetKind::Wifi);
        w.nodes = ownOnly(w.nodes);
        ScanCachedResult cde = cachedOf(w, 3 * 60000, {QStringLiteral("4:xray"), QStringLiteral("9:xray")});
        cde.scope = de;
        w.script << qMakePair(qint64(0), [w, cde](qint64 t) { return ev("shown", t, openArgs(w, QString(), false, cde)); });
        w.script << qMakePair(qint64(1000), at("filter", {{QStringLiteral("cc"), QString()}}));
        w.runMs = 2000;
        Driver d(w);
        d.run();
        const int i0 = stepAfter(d, "shown", 0), i1 = stepAfter(d, "filter", 0);
        CHECK(i0 >= 0 && i1 >= 0);
        if (i0 >= 0 && i1 >= 0) {
            CHECK(rowIds(d.steps.at(i0).view) == (QStringList{QStringLiteral("4:xray"), QStringLiteral("9:xray")})); // shown under Germany
            CHECK(rowIds(d.steps.at(i1).view).isEmpty());
            CHECK(d.steps.at(i1).view.value(QLatin1String("bar")).toObject().value(QLatin1String("scope")).toString().isEmpty());
        }
        // ... unless an all-countries result is cached for this network: that one comes, and Germany's back when chosen
        ScanCachedResult call = cachedOf(w, 5 * 60000, {QStringLiteral("2:xray"), QStringLiteral("5:xray"), QStringLiteral("4:xray")});
        call.scope = QString();
        cde.otherScopes.push_back(call);
        World w2 = w;
        w2.script.clear();
        w2.script << qMakePair(qint64(0), [w2, cde](qint64 t) { return ev("shown", t, openArgs(w2, QString(), false, cde)); });
        w2.script << qMakePair(qint64(1000), at("filter", {{QStringLiteral("cc"), QString()}}));
        w2.script << qMakePair(qint64(2000), at("filter", {{QStringLiteral("cc"), de}}));
        w2.runMs = 4000;
        Driver d2(w2);
        d2.run();
        const QList<int> at3 = {stepAfter(d2, "shown", 0), stepAfter(d2, "filter", 1000), stepAfter(d2, "filter", 2000)};
        CHECK(!at3.contains(-1));
        if (!at3.contains(-1)) {
            QStringList all = rowIds(d2.steps.at(at3.at(1)).view), want{QStringLiteral("2:xray"), QStringLiteral("4:xray"), QStringLiteral("5:xray")};
            all.sort();
            CHECK(all == want); // (d) the all-countries slot
            CHECK(rowIds(d2.steps.at(at3.at(2)).view) == (QStringList{QStringLiteral("4:xray"), QStringLiteral("9:xray")})); // (d) Germany's slot back
        }
    }
    // (b) rows on screen -> «Сканировать»: the first view after the tap has none of them but the live connection's row
    {
        World w = baseWorld("fresh_b", hostMac(), ScanNetKind::Wifi);
        w.nodes = ownOnly(w.nodes);
        const ScanCachedResult c = cachedOf(w, 3 * 60000, {QStringLiteral("4:xray"), QStringLiteral("2:xray"), QStringLiteral("9:xray")});
        w.script << qMakePair(qint64(0), [w, c](qint64 t) { return ev("shown", t, openArgs(w, QStringLiteral("2:xray"), true, c)); });
        w.script << qMakePair(qint64(1000), at("retry"));
        w.script << qMakePair(qint64(90000), at("retry")); // again over the finished scan's own rows
        w.runMs = 110000;
        Driver d(w);
        d.run();
        const int i0 = stepAfter(d, "shown", 0), i1 = stepAfter(d, "retry", 0), i2 = stepAfter(d, "retry", 90000);
        CHECK(i0 >= 0 && i1 >= 0 && i2 >= 0);
        if (i0 >= 0 && i1 >= 0 && i2 >= 0) {
            CHECK(rowIds(d.steps.at(i0).view).size() == 3);
            CHECK(rowIds(d.steps.at(i1).view) == QStringList{QStringLiteral("2:xray")}); // only the live row
            const QJsonObject done = d.steps.at(i2 - 1).view;
            CHECK(phaseOf(done) == QLatin1String("done") && rowIds(done).size() > 1);
            CHECK(rowIds(d.steps.at(i2).view) == QStringList{QStringLiteral("2:xray")});
            const QJsonObject end = lastView(d);
            CHECK(rowIds(end).value(0) == QLatin1String("2:xray") && rowIds(end).size() > 1);
            for (const QJsonValue &v : end.value(QLatin1String("rows")).toArray())
                CHECK(!v.toObject().value(QLatin1String("flags")).toArray().contains(QStringLiteral("cache")));
            CHECK(d.steps.at(i1).listBuilds == d.steps.at(i0).listBuilds + 1); // built by the scan, from empty
        }
    }
    // the slots survive the store: the persisted JSON carries the other scopes (at most kScanCacheScopeSlots - 1), never nested
    {
        World w = baseWorld("fresh_json", hostMac(), ScanNetKind::Wifi);
        ScanCachedResult c = cachedOf(w, 60000, {QStringLiteral("4:xray")});
        c.scope = de;
        for (int i = 0; i < 6; ++i) {
            ScanCachedResult o = cachedOf(w, 120000 + i, {QStringLiteral("2:xray")});
            o.scope = QStringLiteral("S%1").arg(i);
            o.otherScopes.push_back(c); // a nested one is never read back
            c.otherScopes.push_back(o);
        }
        const ScanCachedResult back = scanCachedResultFromJson(scanCachedResultToJson(c));
        CHECK(back.scope == de && int(back.otherScopes.size()) == kScanCacheScopeSlots - 1);
        CHECK(back.otherScopes.at(0).scope == QLatin1String("S0") && back.otherScopes.at(0).rows.size() == 1);
        for (const ScanCachedResult &o : back.otherScopes)
            CHECK(o.otherScopes.empty());
    }
    // (c) «Найти ещё» keeps appending to the current list: findMoreAppends (rows appended, the list built once)
}

// The server's side of the scope and «Найти ещё» (contract 1.14.0): /v1/scan/pool feeds the scope menu,
// /v1/scan/candidates gives the batch (score order across tiers, `seen`, `exhausted`); an older server falls back.
static void serverBatches()
{
    // the parsers
    {
        const QJsonObject pool{{"type", "scan_pool"}, {"version", 1}, {"upstream_revision", 7}, {"upstream_eligible", true},
                               {"countries", QJsonArray{QJsonObject{{"country_code", "de"}, {"own", 1}, {"provider", 3}},
                                                        QJsonObject{{"country_code", "XYZ"}, {"own", 1}, {"provider", 0}}}},
                               {"functions", QJsonArray{QJsonObject{{"kind", "whitelist"}, {"provider", 4}}}}};
        ScanPoolView pv;
        CHECK(scanPoolFromJson(pool, pv) && pv.countries.size() == 1 && pv.countries.first().countryCode == "DE"
              && pv.countries.first().own == 1 && pv.countries.first().provider == 3 && pv.whitelist == 4);
        CHECK(!scanPoolFromJson(QJsonObject{{"type", "scan_manifest"}}, pv));
        World w = baseWorld("srv_parse", hostMac(), ScanNetKind::Wifi);
        const QJsonObject body = manifestBody(w);
        QJsonArray ups = body.value("upstream").toArray();
        QJsonObject u0 = ups.at(0).toObject();
        u0.insert("score", 0.8);
        u0.insert("node", QJsonObject{{"node_id", "up:" + u0.value("profile_id").toString()}, {"proto", "xray"}});
        QJsonArray nodes = body.value("nodes").toArray();
        QJsonObject n0 = nodes.at(0).toObject();
        n0.insert("score", QJsonValue::Null);
        const QJsonObject cand{{"type", "scan_candidates"}, {"version", 1}, {"issued_at", "2026-11-18T10:00:00Z"},
                               {"network_key", body.value("network_key")}, {"scope", "country"}, {"country", "de"},
                               {"upstream_revision", 7}, {"exhausted", true}, {"nodes", QJsonArray{n0}}, {"upstream", QJsonArray{u0}},
                               {"probe_seats", QJsonArray{QJsonObject{{"tier", 1}, {"free", 5}}}}};
        ScanCandidatesView cv;
        CHECK(scanCandidatesFromJson(cand, cv) && cv.exhausted && cv.country == "DE" && cv.nodes.size() == 1 && cv.upstream.size() == 1
              && cv.upstream.first().score == 0.8 && cv.nodes.first().score < 0 && cv.providerNodes.size() == 1
              && cv.freeSeats.value(1) == 5);
        QJsonObject bad = cand;
        bad.remove("exhausted");
        CHECK(!scanCandidatesFromJson(bad, cv));
    }

    World w = baseWorld("srv", hostMac(), ScanNetKind::Wifi);
    w.nodes = ownOnly(w.nodes);
    w.numbers.insert(QStringLiteral("scan_stop_works"), 1);
    const auto actionOf = [](const ScanStep &s, ScanActionKind k) {
        for (const ScanAction &a : s.actions)
            if (a.kind == k)
                return a;
        return ScanAction();
    };
    const auto works = [](const QString &id) {
        ScanProbeFacts f = goodData();
        f.id = id;
        f.egressNode = id.section(QLatin1Char(':'), 0, 0);
        return f;
    };
    ScanMachine m(w.caps);
    m.opened(openOf(w, QString(), false), kT0);
    // the first screen of the whole pool: the manifest, no batch request
    const ScanStep first = m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50);
    const ScanAction start1 = actionOf(first, ScanActionKind::StartHostScan);
    CHECK(actionOf(first, ScanActionKind::RequestCandidates).requestId.isEmpty() && start1.candidates.size() >= 3);
    if (start1.candidates.size() < 3)
        return;
    m.hostProgress(progressOf(m, {works(start1.candidates.at(0).id)}), kT0 + 900);
    m.tick(kT0 + 50 + 8100);
    // the pool: the menu covers the whole pool and the white lists
    m.poolReady(ScanPoolView{{{QStringLiteral("NL"), 2, 9}, {QStringLiteral("DE"), 1, 3}}, 4, 7}, kT0 + 8200);
    ScanView v = m.view(kT0 + 8200);
    CHECK(v.bar.scopeCountries.size() == 2 && v.bar.scopeCountries.first().countryCode == "NL" && v.bar.scopeCountries.first().count == 11
          && v.bar.scopeWhitelist == 4 && scanViewToJson(v).value("bar").toObject().value("scope_whitelist").toInt() == 4);

    // «Найти ещё»: the server's batch with `seen`; only its rows, in its order (score first across tiers)
    m.moreTapped(QString(), kT0 + 31000);
    const ScanStep ms = m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 31050);
    const ScanAction rc = actionOf(ms, ScanActionKind::RequestCandidates);
    CHECK(!rc.requestId.isEmpty() && rc.ids.contains(start1.candidates.at(0).id) && rc.batch == kScanMoreBatch
          && rc.scopeCountry.isEmpty() && actionOf(ms, ScanActionKind::StartHostScan).candidates.isEmpty());
    ScanManifestView mv;
    scanManifestViewFromJson(manifestBody(w), mv);
    ScanCandidatesView cv;
    cv.exhausted = true;
    for (const ScanManifestNode &n : mv.nodes)
        if (n.nodeId != start1.candidates.at(0).id && cv.nodes.size() < 2 && std::any_of(start1.candidates.begin(), start1.candidates.end(),
                                                                                      [&n](const ScanCandidate &c) { return c.id == n.nodeId; }))
            cv.nodes << n;
    CHECK(cv.nodes.size() == 2);
    cv.nodes[1].score = 0.9; // the crowd's favourite goes first whatever its rank
    const ScanStep cs = m.candidatesReady(rc.requestId, cv, 4000, kT0 + 31300);
    const ScanAction start2 = actionOf(cs, ScanActionKind::StartHostScan);
    CHECK(start2.candidates.size() == 2 && start2.candidates.first().id == cv.nodes.at(1).nodeId);
    QList<ScanProbeFacts> all;
    for (const ScanCandidate &c : start2.candidates)
        all << works(c.id);
    m.hostProgress(progressOf(m, all), kT0 + 32000);
    m.tick(kT0 + 31300 + 8100);
    v = m.view(kT0 + 39500);
    CHECK(!v.scanning && v.moreState == QLatin1String("exhausted") && v.verifiedCount == 3);
    CHECK(m.candidatesReady(rc.requestId, cv, 10, kT0 + 39600).actions.isEmpty() || !m.view(kT0 + 39600).scanning); // stale: nothing starts

    // a country scope: the server's first page of that country
    m.filterChosen(QStringLiteral("nl"), kT0 + 70000);
    CHECK(m.view(kT0 + 70000).bar.scope == "NL");
    m.retryTapped(kT0 + 70000);
    const ScanAction rn = actionOf(m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 70050), ScanActionKind::RequestCandidates);
    CHECK(rn.scopeCountry == "NL" && rn.batch == kScanScopeFirstBatch && rn.ids.isEmpty());

    // the white lists: a scope of their own; an older server -> the device's own rows of that kind (none here)
    ScanMachine wl(w.caps);
    wl.opened(openOf(w, QString(), false), kT0);
    wl.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50);
    wl.tick(kT0 + 50 + 8100);
    wl.filterChosen(QStringLiteral("whitelist"), kT0 + 8200);
    CHECK(wl.view(kT0 + 8200).bar.scope.isEmpty()); // the pool says nothing of white lists yet
    wl.poolReady(ScanPoolView{{}, 3, 1}, kT0 + 8300);
    wl.filterChosen(QStringLiteral("WhiteList"), kT0 + 8300);
    CHECK(wl.view(kT0 + 8300).bar.scope == QLatin1String(kScanScopeWhitelist));
    wl.retryTapped(kT0 + 40000);
    const ScanAction rw = actionOf(wl.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 40050), ScanActionKind::RequestCandidates);
    CHECK(rw.scopeCountry == QLatin1String(kScanScopeWhitelist));
    const ScanStep fb = wl.candidatesUnavailable(rw.requestId, QStringLiteral("scanner_off"), 300, kT0 + 40100);
    CHECK(actionOf(fb, ScanActionKind::StartHostScan).candidates.isEmpty() && !wl.view(kT0 + 40100).scanning); // nothing to probe
    // the session fell back for good: the next scope scan does not ask again
    wl.filterChosen(QString(), kT0 + 80000);
    wl.moreTapped(QStringLiteral("NL"), kT0 + 80000);
    CHECK(actionOf(wl.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 80050), ScanActionKind::RequestCandidates).requestId.isEmpty());
}

// Device round 13, A6/A12: the menu counts the pool's servers of a scope, the list shows the ones that answered. When the
// series is exhausted the view says how many of the menu's count the list does not show (view.more.unshown), so the end
// message is honest; with nothing missing it says nothing.
static void exhaustedScopeSaysWhatIsMissing()
{
    World w = baseWorld("unshown", hostMac(), ScanNetKind::Wifi);
    for (int pool : {2, 7}) {
        ScanMachine m(w.caps);
        m.opened(openOf(w, QString(), false), kT0);
        m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50);
        m.tick(kT0 + 50 + 8100);
        m.poolReady(ScanPoolView{{{QStringLiteral("DE"), pool, 0}}, 0, 0}, kT0 + 8200);
        m.filterChosen(QStringLiteral("DE"), kT0 + 8300);
        m.retryTapped(kT0 + 40000);
        const ScanStep st = m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 40050);
        ScanCandidatesView cv; // the server has nothing more of the scope than what it said
        cv.exhausted = true;
        for (const ScanAction &a : st.actions)
            if (a.kind == ScanActionKind::RequestCandidates)
                m.candidatesReady(a.requestId, cv, 500, kT0 + 40100);
        m.tick(kT0 + 40100 + 12000);
        const ScanView v = m.view(kT0 + 60000);
        int shown = 0;
        for (const ScanRowView &r : v.rows)
            shown += r.countryCode == QLatin1String("DE") ? 1 : 0;
        CHECK(v.moreState == QLatin1String("exhausted"));
        // review of 142 (finding 3): nothing failed, so nothing "did not answer" - whatever the menu counts beyond the list
        CHECK(shown < pool && v.moreUnshown == 0);
        CHECK(!scanViewToJson(v).value(QStringLiteral("more")).toObject().contains(QStringLiteral("unshown")));
    }
}

static void countrylessRows()
{
    // Device round air7 (19.11): a white-list row (no country) became a second «Все страны» entry of the menu.
    World w = baseWorld("wl_menu", hostMac(), ScanNetKind::Wifi);
    ScanMachine m(w.caps);
    ScanOpen o = openOf(w, QString(), false);
    ScanCachedResult c;
    c.networkKey = o.network.key;
    c.fingerprint = o.network.fingerprint;
    c.savedAtMs = kT0;
    ScanCachedRow nl;
    nl.id = QStringLiteral("up:aaaaaaaaaaaaaa01");
    nl.origin = ScanOrigin::Upstream;
    nl.profileId = QStringLiteral("aaaaaaaaaaaaaa01");
    nl.countryCode = QStringLiteral("NL");
    nl.label = QStringLiteral("Нидерланды 1");
    nl.ms = 40;
    ScanCachedRow wl = nl;
    wl.id = QStringLiteral("up:aaaaaaaaaaaaaa02");
    wl.profileId = QStringLiteral("aaaaaaaaaaaaaa02");
    wl.countryCode.clear();
    wl.label = QStringLiteral("Белые списки 1");
    c.rows << nl << wl;
    o.cached = c;
    m.shown(o, kT0 + 1000);
    const ScanView v = m.view(kT0 + 1000);
    CHECK(v.rows.size() == 2);
    bool blank = false;
    for (const ScanCountryView &x : v.bar.countries)
        blank = blank || x.countryCode.isEmpty();
    CHECK(!blank && v.bar.countries.size() == 1 && v.bar.total == 2);
}

// Owner 24.11: the Scanner opens on its country choice. view.slots lists this network's fresh results, one per scope
// ({scope, works, ago_min}: a choice row with one shows it without a scan); «Остановить» cancels the scan and the
// screen stays open (back to the choice), with the scope's last result as on open.
static ScanCachedRow choiceRow(const QString &id, const QString &cc, ScanClass cls)
{
    ScanCachedRow r;
    r.id = id;
    r.origin = ScanOrigin::Upstream;
    r.profileId = id.mid(3);
    r.countryCode = cc;
    r.label = cc + QStringLiteral(" 1");
    r.cls = cls;
    r.speed = ScanSpeed::Fast;
    r.ms = 50;
    return r;
}

// Review round 36, F2: a scope's result counts only its own rows. The live tunnel is probed in every scope and saved in
// that scope's slot; connected to the Netherlands while Germany is scanned, Germany must not read «1 доступно».
static void slotCountsOnlyItsScope()
{
    World w = baseWorld("slot_scope", hostMac(), ScanNetKind::Wifi);
    ScanOpen o = openOf(w, QString(), false);
    const auto result = [&o](const QString &scope, qint64 savedAt, const QList<ScanCachedRow> &rows) {
        ScanCachedResult c;
        c.networkKey = o.network.key;
        c.fingerprint = o.network.fingerprint;
        c.savedAtMs = savedAt;
        c.scope = scope;
        c.rows = rows;
        return c;
    };
    const ScanCachedRow nlLive = choiceRow(QStringLiteral("up:bbbbbbbbbbbbbb01"), QStringLiteral("NL"), ScanClass::Works);
    const ScanCachedRow de = choiceRow(QStringLiteral("up:bbbbbbbbbbbbbb02"), QStringLiteral("DE"), ScanClass::Works);
    ScanCachedRow wl = choiceRow(QStringLiteral("up:bbbbbbbbbbbbbb03"), QString(), ScanClass::Works);
    ScanCachedResult deMixed = result(QStringLiteral("DE"), kT0 - 60000, {nlLive, de});
    ScanCachedResult frOnlyLive = result(QStringLiteral("FR"), kT0 - 120000, {nlLive});
    ScanCachedResult wlRes = result(QStringLiteral("whitelist"), kT0 - 180000, {nlLive, wl});
    ScanCachedResult all = result(QString(), kT0 - 240000, {nlLive, de, wl});
    deMixed.otherScopes = {frOnlyLive, wlRes, all};
    o.cached = deMixed;
    ScanMachine m(w.caps);
    m.shown(o, kT0);
    const ScanView v = m.view(kT0);
    QHash<QString, int> works;
    for (const ScanSlotView &sv : v.scopeSlots)
        works.insert(sv.scope, sv.works);
    CHECK(works.value(QStringLiteral("DE"), -1) == 1);            // the German row, not the Dutch live one
    CHECK(works.value(QStringLiteral("whitelist"), -1) == 1);     // a row without a country
    CHECK(works.value(QString(), -1) == 3);                       // «Все страны»: every row
    CHECK(!works.contains(QStringLiteral("FR")));                 // only another country's row: no result of France
    // ... and choosing France shows nothing of it: its choice row scans
    ScanPoolView pool;
    pool.countries = {ScanPoolView::Country{QStringLiteral("DE"), 3, 0}, ScanPoolView::Country{QStringLiteral("FR"), 2, 0},
                      ScanPoolView::Country{QStringLiteral("NL"), 2, 0}};
    m.poolReady(pool, kT0 + 50);
    m.filterChosen(QStringLiteral("FR"), kT0 + 100);
    CHECK(m.view(kT0 + 100).bar.scope == QLatin1String("FR"));
    bool frRow = false;
    for (const ScanRowView &r : m.view(kT0 + 100).rows)
        frRow = frRow || r.fromCache;
    CHECK(!frRow);
}

// Review round 36, F3: choosing a scope's advertised fresh result shows it - also after a failed re-scan of the same
// scope (NoScan manifest_unavailable): an explicit action (slotChosen), not a side effect of a scope change.
static void slotChosenLeavesTheError()
{
    World w = baseWorld("slot_chosen", hostMac(), ScanNetKind::Wifi);
    ScanOpen o = openOf(w, QString(), false);
    ScanCachedResult de;
    de.networkKey = o.network.key;
    de.fingerprint = o.network.fingerprint;
    de.savedAtMs = kT0 - 2 * 60000;
    de.scope = QStringLiteral("DE");
    de.rows << choiceRow(QStringLiteral("up:cccccccccccccc01"), QStringLiteral("DE"), ScanClass::Works)
            << choiceRow(QStringLiteral("up:cccccccccccccc02"), QStringLiteral("DE"), ScanClass::Works);
    o.cached = de;
    ScanMachine m(w.caps);
    m.shown(o, kT0);
    CHECK(m.view(kT0).bar.scope == QLatin1String("DE") && m.view(kT0).rows.size() == 2);
    CHECK(m.retryTapped(kT0 + 100).has(ScanActionKind::RequestManifest)); // «Сканировать снова»
    m.manifestUnavailable(QStringLiteral("manifest_unavailable"), kT0 + 300); // HTTP 503
    const ScanView err = m.view(kT0 + 300);
    CHECK(err.phase == ScanPhase::NoScan && err.rows.isEmpty() && err.scopeSlots.size() == 1);
    // the old path: the same scope chosen again is no change - the error stays (why the explicit action exists)
    m.filterChosen(QStringLiteral("DE"), kT0 + 400);
    CHECK(m.view(kT0 + 400).phase == ScanPhase::NoScan);
    // a scope without a fresh result, and a running scan: slotChosen changes nothing
    m.slotChosen(QStringLiteral("NL"), kT0 + 450);
    CHECK(m.view(kT0 + 450).phase == ScanPhase::NoScan && m.view(kT0 + 450).bar.scope == QLatin1String("DE"));
    const quint64 build = m.view(kT0 + 450).listBuild;
    const ScanStep s = m.slotChosen(QStringLiteral("DE"), kT0 + 500);
    const ScanView v = m.view(kT0 + 500);
    CHECK(s.actions.isEmpty() || !s.has(ScanActionKind::RequestManifest)); // never a scan
    CHECK(v.phase == ScanPhase::Idle && v.empty.reason.isEmpty() && v.empty.variant == ScanEmptyVariant::None);
    CHECK(v.rows.size() == 2 && v.rows.at(0).fromCache && v.bar.scope == QLatin1String("DE") && v.listBuild != build);
    CHECK(v.checkedAgoMin == 2);
    // while a scan runs the choice never reaches it (the page stops the scan first); the machine ignores it
    ScanMachine r(w.caps);
    r.shown(o, kT0);
    r.retryTapped(kT0 + 100);
    r.slotChosen(QStringLiteral("DE"), kT0 + 200);
    CHECK(r.view(kT0 + 200).scanning);
}

static void choiceSlotsAndStopStays()
{
    World w = baseWorld("choice", hostMac(), ScanNetKind::Wifi);
    ScanOpen o = openOf(w, QString(), false);
    ScanCachedResult de;
    de.networkKey = o.network.key;
    de.fingerprint = o.network.fingerprint;
    de.savedAtMs = kT0 - 3 * 60000 - 5000; // 3 min old
    de.scope = QStringLiteral("DE");
    de.rows << choiceRow(QStringLiteral("up:aaaaaaaaaaaaaa01"), QStringLiteral("DE"), ScanClass::Works)
            << choiceRow(QStringLiteral("up:aaaaaaaaaaaaaa02"), QStringLiteral("DE"), ScanClass::Slow);
    ScanCachedResult all = de;
    all.scope.clear();
    all.savedAtMs = kT0 - 7 * 60000; // 7 min old
    all.rows = {choiceRow(QStringLiteral("up:aaaaaaaaaaaaaa03"), QStringLiteral("NL"), ScanClass::Works)};
    ScanCachedResult stale = de;
    stale.scope = QStringLiteral("FI");
    stale.savedAtMs = kT0 - 11 * 60000; // past scan_cache_works_ttl_s (600 s): never offered
    stale.rows = {choiceRow(QStringLiteral("up:aaaaaaaaaaaaaa04"), QStringLiteral("FI"), ScanClass::Works)};
    ScanCachedResult bare = de;
    bare.scope = QStringLiteral("PL");
    bare.savedAtMs = kT0 - 60000;
    bare.rows.clear(); // a result without a row: nothing to show
    de.otherScopes = {all, stale, bare};
    o.cached = de;

    // the slots of the open page: fresh ones only, newest first, with the working rows and the age in minutes
    {
        ScanMachine m(w.caps);
        m.shown(o, kT0);
        const ScanView v = m.view(kT0);
        CHECK(v.scopeSlots.size() == 2);
        if (v.scopeSlots.size() == 2) {
            CHECK(v.scopeSlots.at(0).scope == QLatin1String("DE") && v.scopeSlots.at(0).works == 2 && v.scopeSlots.at(0).agoMin == 3);
            CHECK(v.scopeSlots.at(1).scope.isEmpty() && v.scopeSlots.at(1).works == 1 && v.scopeSlots.at(1).agoMin == 7);
        }
        const QJsonArray js = scanViewToJson(v).value(QStringLiteral("slots")).toArray();
        CHECK(js.size() == 2 && js.at(0).toObject().value(QStringLiteral("scope")).toString() == QLatin1String("DE")
              && js.at(0).toObject().value(QStringLiteral("works")).toInt() == 2
              && js.at(0).toObject().value(QStringLiteral("ago_min")).toInt() == 3
              && js.at(1).toObject().value(QStringLiteral("scope")).toString().isEmpty());
        // the view is read again when an age turns a minute, and when a slot stops being fresh
        CHECK(v.nextChangeAtMs > kT0 && v.nextChangeAtMs <= de.savedAtMs + 4 * 60000);
        const ScanView later = m.view(all.savedAtMs + 600000 + 1);
        CHECK(later.scopeSlots.size() == 1 && later.scopeSlots.at(0).scope == QLatin1String("DE"));
        CHECK(m.view(de.savedAtMs + 600000 + 1).scopeSlots.isEmpty());
        // a slot the view offers is the one a choice shows: no scan, its rows as the cached result
        m.filterChosen(QStringLiteral("DE"), kT0 + 100);
        const ScanView dv = m.view(kT0 + 100);
        CHECK(!dv.scanning && dv.rows.size() == 2 && dv.rows.at(0).fromCache && dv.bar.scope == QLatin1String("DE"));
        m.filterChosen(QString(), kT0 + 200);
        const ScanView av = m.view(kT0 + 200);
        CHECK(av.rows.size() == 1 && av.rows.at(0).id == QLatin1String("up:aaaaaaaaaaaaaa03"));
    }
    // a network without results: no slots (the JSON has no key)
    {
        ScanMachine m(w.caps);
        m.shown(openOf(w, QString(), false), kT0);
        CHECK(m.view(kT0).scopeSlots.isEmpty() && !scanViewToJson(m.view(kT0)).contains(QStringLiteral("slots")));
    }
    // «Остановить»: the scan is cancelled, the screen stays open, the scope's fresh result is shown again
    {
        ScanMachine m(w.caps);
        m.shown(o, kT0);
        m.filterChosen(QStringLiteral("DE"), kT0 + 100);
        CHECK(m.retryTapped(kT0 + 200).has(ScanActionKind::RequestManifest));
        CHECK(m.view(kT0 + 200).scanning && m.view(kT0 + 200).rows.isEmpty()); // a scan the person starts: a new list
        const quint64 build = m.view(kT0 + 200).listBuild;
        const ScanStep s = m.stopTapped(kT0 + 300);
        CHECK(!s.has(ScanActionKind::CloseScreen) && m.screenOpen());
        const ScanView v = m.view(kT0 + 300);
        CHECK(v.phase == ScanPhase::Idle && !v.scanning && v.bar.scope == QLatin1String("DE"));
        CHECK(v.rows.size() == 2 && v.rows.at(0).fromCache && v.listBuild != build);
        CHECK(v.scopeSlots.size() == 2);
        // stopped before anything was probed: no pause (the cooldown is armed by a host start, armCooldown)
        CHECK(v.bar.button == ScanBarButton::Retry && v.bar.buttonEnabled);
        // a scope without a result after a stop: an empty list of that scope, the screen still open
        ScanMachine n(w.caps);
        n.shown(o, kT0);
        ScanPoolView pool;
        pool.countries = {ScanPoolView::Country{QStringLiteral("DE"), 3, 0}, ScanPoolView::Country{QStringLiteral("SE"), 1, 0}};
        n.poolReady(pool, kT0 + 50);
        n.filterChosen(QStringLiteral("SE"), kT0 + 100);
        CHECK(n.view(kT0 + 100).bar.scope == QLatin1String("SE") && n.view(kT0 + 100).rows.isEmpty());
        n.retryTapped(kT0 + 200);
        CHECK(!n.stopTapped(kT0 + 300).has(ScanActionKind::CloseScreen) && n.screenOpen() && n.view(kT0 + 300).rows.isEmpty());
        // leaving the screen still closes it (back from the choice)
        n.closed(kT0 + 400);
        CHECK(!n.screenOpen());
    }
}

// «Остановить» (owner 24.11, one screen: the rings stop with the number found so far). A scan that already found a
// working server keeps it: Done, its rows and count, the scope's fresh result (cache + slot), the summary's
// stop_reason "cancel", one freeze and one cancel of the host, no «Найдено N» shade. A scan stopped before it found
// anything is cancelled as before: idle, nothing kept (the page goes back to its choice).
static void stopKeepsWhatItFound()
{
    const auto world = [](qint64 stopAt) {
        World w = baseWorld("stop_keeps", hostMac(), ScanNetKind::Wifi);
        w.script << qMakePair(qint64(0), at("opened", openArgs(w, QString(), false)));
        if (stopAt >= 0)
            w.script << qMakePair(stopAt, at("stop"));
        w.runMs = 12000;
        return w;
    };
    // the same scan without a stop: the first moment it shows a verified row while it still runs
    Driver plain(world(-1));
    plain.run();
    qint64 foundAt = -1;
    int verifiedThen = 0;
    for (const Recorded &r : plain.steps)
        if (scanPhaseNameScanning(phaseOf(r.view)) && r.view.value(QLatin1String("verified")).toInt() > 0) {
            foundAt = qint64(r.event.value(QLatin1String("now_ms")).toDouble()) - kT0;
            verifiedThen = r.view.value(QLatin1String("verified")).toInt();
            break;
        }
    const int allFound = lastView(plain).value(QLatin1String("verified")).toInt();
    CHECK(foundAt > 0 && phaseOf(lastView(plain)) == QLatin1String("done") && verifiedThen < allFound);

    // stopped right then: what was found stays on the screen
    Driver d(world(foundAt + 1));
    d.run();
    const QJsonObject v = lastView(d);
    const int kept = v.value(QLatin1String("verified")).toInt();
    CHECK(phaseOf(v) == QLatin1String("done"));
    CHECK(kept >= verifiedThen && kept < allFound);
    CHECK(countActions(d, ScanActionKind::PersistResults) >= 1); // + one per later proof by exclusion
    const QJsonArray fresh = v.value(QLatin1String("slots")).toArray();
    CHECK(fresh.size() == 1 && fresh.at(0).toObject().value(QLatin1String("works")).toInt() == kept);
    CHECK(v.value(QLatin1String("available")).toInt() == kept && v.value(QLatin1String("partial")).toBool());
    CHECK(countActions(d, ScanActionKind::FreezeHostScan) == 1 && countActions(d, ScanActionKind::StopHostScan) == 1);
    CHECK(countActions(d, ScanActionKind::CloseScreen) == 0 && d.m.screenOpen());
    CHECK(d.m.lastSummary().value(QLatin1String("stop_reason")).toString() == QLatin1String("cancel"));
    CHECK(shadeCount(d, "scan_found") == 0 && shadeCount(plain, "scan_found") == 0); // the rings say the count
    CHECK(!d.m.draining());

    // stopped before anything was found: cancelled, nothing kept
    Driver e(world(foundAt / 2));
    e.run();
    const QJsonObject ev = lastView(e);
    CHECK(phaseOf(ev) == QLatin1String("idle") && ev.value(QLatin1String("rows")).toArray().isEmpty());
    CHECK(countActions(e, ScanActionKind::PersistResults) == 0 && e.m.screenOpen());
}

// --- review of the one-screen Scanner (24.11) ------------------------------------------------------------------

static QJsonObject viewJson(const ScanMachine &m, qint64 now) { return scanViewToJson(m.view(now)); }

static int rowsInState(const QJsonObject &v, const char *state)
{
    int n = 0;
    for (const QJsonValue &x : v.value(QLatin1String("rows")).toArray())
        n += x.toObject().value(QLatin1String("state")).toString() == QLatin1String(state) ? 1 : 0;
    return n;
}

static const ScanAction *lastAction(const Driver &d, ScanActionKind k)
{
    for (int i = d.steps.size() - 1; i >= 0; --i)
        if (const ScanAction *a = d.steps.at(i).step.find(k))
            return a;
    return nullptr;
}

// The first moment a scan of `w` shows a verified row while it still runs, after `from` (ms from kT0); -1 = none.
static qint64 firstFoundAt(const World &w, qint64 from)
{
    Driver plain(w);
    plain.run();
    for (const Recorded &r : plain.steps) {
        const qint64 at = qint64(r.event.value(QLatin1String("now_ms")).toDouble()) - kT0;
        if (at > from && scanPhaseNameScanning(phaseOf(r.view)) && r.view.value(QLatin1String("verified")).toInt() > 0)
            return at;
    }
    return -1;
}

// F1: the number in the rings is the machine's view.available - the rows the list shows as available in the shown
// scope, counted in one place: cached rows too, a row that failed after a tap no more.
static void availableIsWhatTheListShows()
{
    // a cached result of 3 working rows shown while the VPN is connected: the 3 rows and the «Подключено» one (E1, air-D:
    // the live connection is counted as the list shows it), never 0 / 1
    {
        World w = baseWorld("available", hostMac(), ScanNetKind::Wifi);
        ScanOpen o = openOf(w, QStringLiteral("1"), true);
        ScanCachedResult all;
        all.networkKey = o.network.key;
        all.fingerprint = o.network.fingerprint;
        all.savedAtMs = kT0 - 5 * 60000;
        all.rows << choiceRow(QStringLiteral("up:aaaaaaaaaaaaaa01"), QStringLiteral("DE"), ScanClass::Works)
                 << choiceRow(QStringLiteral("up:aaaaaaaaaaaaaa02"), QStringLiteral("NL"), ScanClass::Slow)
                 << choiceRow(QStringLiteral("up:aaaaaaaaaaaaaa03"), QStringLiteral("FI"), ScanClass::Works);
        o.cached = all;
        ScanMachine m(w.caps);
        m.shown(o, kT0);
        const QJsonObject v = viewJson(m, kT0);
        CHECK(rowsInState(v, "works") + rowsInState(v, "slow") == 3 && rowsInState(v, "connected") == 1);
        CHECK(v.value(QLatin1String("available")).toInt() == 4);
    }
    // a finished scan: every working row of the list; a row tapped and failed is «Не удалось» and no more counted
    {
        World w = baseWorld("available_done", hostMac(), ScanNetKind::Wifi);
        w.script << qMakePair(qint64(0), at("opened", openArgs(w, QString(), false)));
        w.runMs = 9000;
        Driver d(w);
        d.run();
        const QJsonObject v = lastView(d);
        const int shown = rowsInState(v, "works") + rowsInState(v, "slow");
        CHECK(phaseOf(v) == QLatin1String("done") && shown > 1 && v.value(QLatin1String("available")).toInt() == shown);
        QString a;
        for (const QJsonValue &x : v.value(QLatin1String("rows")).toArray())
            if (a.isEmpty() && x.toObject().value(QLatin1String("state")).toString() == QLatin1String("works"))
                a = x.toObject().value(QLatin1String("id")).toString();
        const qint64 t = d.now + 1000;
        d.m.rowTapped(a, t);
        CHECK(viewJson(d.m, t).value(QLatin1String("available")).toInt() == shown); // «Подключение…» is still available
        d.m.exactRowFailed(a, t + 100);
        const QJsonObject f = viewJson(d.m, t + 100);
        CHECK(rowOf(f, a).value(QLatin1String("state")).toString() == QLatin1String("failed"));
        CHECK(f.value(QLatin1String("available")).toInt() == shown - 1);
    }
    // nothing works: 0
    {
        World w = baseWorld("available_zero", hostMacMinimal(), ScanNetKind::Wifi);
        w.nodes = ownOnly(w.nodes);
        for (auto it = w.out.begin(); it != w.out.end(); ++it)
            it.value().reachOk = false, it.value().works = false;
        w.script << qMakePair(qint64(0), at("opened", openArgs(w, QString(), false)));
        w.runMs = 12000;
        Driver d(w);
        d.run();
        const QJsonObject v = lastView(d);
        CHECK(!scanPhaseNameScanning(phaseOf(v)) && v.contains(QLatin1String("available"))
              && v.value(QLatin1String("available")).toInt() == 0);
    }
}

// F6 (device round, iPhone): a second row tapped while the first still connects. The server list's rule - the newest
// pick wins (PageStart.onPickNode -> AvpnEngineQml::pinAndReconnect, no guard while a connect runs) - holds here too:
// the new row connects, the older one's request ends without a verdict (no «Не удалось», no outcome), and its late
// failure fails nothing.
static void secondRowTapTakesOver()
{
    World w = baseWorld("tap_takes_over", hostMac(), ScanNetKind::Wifi);
    w.current = QStringLiteral("1");
    w.script << qMakePair(qint64(0), at("opened", openArgs(w, w.current, true)));
    w.runMs = 9000;
    Driver d(w);
    d.run();
    QStringList ids;
    for (const QJsonValue &x : lastView(d).value(QLatin1String("rows")).toArray()) {
        const QJsonObject r = x.toObject();
        if (r.value(QLatin1String("state")).toString() == QLatin1String("works")
            && !r.value(QLatin1String("flags")).toArray().contains(QStringLiteral("not_tappable")))
            ids << r.value(QLatin1String("id")).toString();
    }
    CHECK(ids.size() >= 3);
    if (ids.size() < 3)
        return;
    const QString a = ids.at(0), b = ids.at(1);
    const qint64 t = d.now + 1000;
    const ScanStep sa = d.m.rowTapped(a, t);
    CHECK(sa.has(ScanActionKind::ConnectRow) && sa.find(ScanActionKind::ConnectRow)->nodeId == a);
    const ScanStep sb = d.m.rowTapped(b, t + 400);
    const ScanAction *cb = sb.find(ScanActionKind::ConnectRow);
    CHECK(cb && cb->nodeId == b && !cb->ids.contains(a) && cb->userOrigin && cb->forceConnect);
    for (const ScanAction &x : sb.actions)
        CHECK(x.kind != ScanActionKind::ShowShade);
    QJsonObject v = viewJson(d.m, t + 400);
    CHECK(rowOf(v, a).value(QLatin1String("state")).toString() == QLatin1String("works"));
    CHECK(rowOf(v, b).value(QLatin1String("state")).toString() == QLatin1String("connecting") && d.m.connectingId() == b);
    // the superseded row's late failure is not the running chain's
    d.m.connectFailed(a, t + 800);
    d.m.exactRowFailed(a, t + 850);
    v = viewJson(d.m, t + 850);
    CHECK(rowOf(v, a).value(QLatin1String("state")).toString() == QLatin1String("works") && d.m.connectingId() == b);
    // the new row comes up: its chain reports it working, nothing is reported for the superseded row
    const ScanStep up = d.m.vpnState(liveOf(w, b, true), t + 2500);
    const ScanAction *o = up.find(ScanActionKind::SendOutcomes);
    bool bWorks = false, aAny = false;
    for (const ScanOutcomeItem &it : o ? o->outcomes : QList<ScanOutcomeItem>()) {
        bWorks = bWorks || ((it.id == b || QStringLiteral("up:") + it.id == b) && it.outcome == ScanClass::Works);
        aAny = aAny || it.id == a || QStringLiteral("up:") + it.id == a;
    }
    CHECK(bWorks && !aAny && d.m.connectingId().isEmpty());
    // the same row tapped again while it connects: nothing new
    ScanMachine &m = d.m;
    m.rowTapped(ids.at(2), t + 3000);
    CHECK(!m.rowTapped(ids.at(2), t + 3100).has(ScanActionKind::ConnectRow));
}

// F5: «Остановить» stays honest. (b) a stopped scan never replaces the scope's COMPLETE fresh result: that one stays
// the stored result, the stopped scan's proven rows go out as evidence only (store false), and showing the scope's
// result again shows the complete one. (c) without one, the partial result is stored marked partial; the mark survives
// the store and a restore, a scope switch, and every view of it says so (view.partial, slots[].partial).
static void stoppedResultStaysHonest()
{
    // (b): a full scan, then the same scope scanned again and stopped once it found something
    {
        World w = baseWorld("stop_after_complete", hostMac(), ScanNetKind::Wifi);
        w.script << qMakePair(qint64(0), at("opened", openArgs(w, QString(), false)));
        w.script << qMakePair(qint64(40000), at("retry"));
        w.runMs = 52000;
        const qint64 found = firstFoundAt(w, 40000);
        CHECK(found > 40000);
        World ws = w;
        ws.script << qMakePair(found + 1, at("stop"));
        Driver plain(w);
        plain.run();
        const int complete = lastView(plain).value(QLatin1String("verified")).toInt();
        Driver d(ws);
        d.run();
        const ScanAction *p = lastAction(d, ScanActionKind::PersistResults);
        CHECK(p && scanActionToJson(*p).value(QLatin1String("store")).toBool(true) == false && p->cached.partial);
        const QJsonObject v = lastView(d);
        CHECK(phaseOf(v) == QLatin1String("done") && v.value(QLatin1String("partial")).toBool());
        const QJsonArray sl = v.value(QLatin1String("slots")).toArray();
        CHECK(sl.size() == 1 && sl.at(0).toObject().value(QLatin1String("works")).toInt() == complete
              && !sl.at(0).toObject().value(QLatin1String("partial")).toBool());
        // «Показать результат» of that scope: the stored complete result, not the stopped one
        const qint64 t = d.now + 1000;
        d.m.slotChosen(QString(), t);
        const QJsonObject c = viewJson(d.m, t);
        CHECK(!c.value(QLatin1String("partial")).toBool() && c.value(QLatin1String("available")).toInt() == complete);
    }
    // (c): no complete result of the scope: the stopped one is stored, marked
    {
        World w = baseWorld("stop_first", hostMac(), ScanNetKind::Wifi);
        w.script << qMakePair(qint64(0), at("opened", openArgs(w, QString(), false)));
        w.runMs = 12000;
        const qint64 found = firstFoundAt(w, 0);
        World ws = w;
        ws.script << qMakePair(found + 1, at("stop"));
        Driver d(ws);
        d.run();
        const ScanAction *p = lastAction(d, ScanActionKind::PersistResults);
        CHECK(p && scanActionToJson(*p).value(QLatin1String("store")).toBool(true) && p->cached.partial);
        const QJsonObject v = lastView(d);
        CHECK(v.value(QLatin1String("partial")).toBool());
        const QJsonArray sl = v.value(QLatin1String("slots")).toArray();
        CHECK(sl.size() == 1 && sl.at(0).toObject().value(QLatin1String("partial")).toBool());
        if (!p)
            return;
        // the store and a restore keep the mark (and in another scope's slot too)
        ScanCachedResult stored = scanCachedResultFromJson(scanCachedResultToJson(p->cached));
        CHECK(stored.partial);
        ScanCachedResult other = stored;
        other.scope = QStringLiteral("DE");
        other.savedAtMs = stored.savedAtMs + 1000;
        other.partial = false;
        other.otherScopes = {stored};
        const ScanCachedResult back = scanCachedResultFromJson(scanCachedResultToJson(other));
        CHECK(!back.partial && back.otherScopes.size() == 1 && back.otherScopes.at(0).partial);
        // a page opened later on that stored result: the slot and the shown result say «stopped»
        ScanOpen o = openOf(w, QString(), false);
        o.cached = stored;
        ScanMachine m(w.caps);
        const qint64 t = stored.savedAtMs + 60000;
        m.shown(o, t);
        QJsonObject r = viewJson(m, t);
        const QJsonArray rs = r.value(QLatin1String("slots")).toArray();
        CHECK(!rs.isEmpty() && rs.at(0).toObject().value(QLatin1String("partial")).toBool());
        m.slotChosen(QString(), t + 10);
        r = viewJson(m, t + 10);
        CHECK(r.value(QLatin1String("partial")).toBool() && r.value(QLatin1String("available")).toInt() > 0);
    }
    // the server list's figures: a newer narrower (stopped) result never wipes the figures of rows it did not reach
    {
        ScanCachedResult full;
        full.networkKey = QStringLiteral("wifi:asn:64500");
        full.fingerprint = QStringLiteral("fp");
        full.savedAtMs = kT0 - 4 * 60000;
        full.rows << choiceRow(QStringLiteral("up:aaaaaaaaaaaaaa01"), QStringLiteral("DE"), ScanClass::Works)
                  << choiceRow(QStringLiteral("up:aaaaaaaaaaaaaa02"), QStringLiteral("NL"), ScanClass::Works);
        full.rows[0].ms = 90;
        full.rows[1].ms = 70;
        ScanCachedResult stopped = full;
        stopped.scope = QStringLiteral("DE");
        stopped.partial = true;
        stopped.savedAtMs = kT0 - 60000;
        stopped.rows = {full.rows.at(0)};
        stopped.rows[0].ms = 50;
        stopped.otherScopes = {full};
        const QHash<QString, int> fig = scanListFigures(stopped, QStringLiteral("fp"), kT0, 600);
        CHECK(fig.value(QStringLiteral("up:aaaaaaaaaaaaaa01"), -1) == 50 && fig.value(QStringLiteral("up:aaaaaaaaaaaaaa02"), -1) == 70);
    }
}

// F2: a scope the machine refuses (here the white lists of a pool without them) leaves the old scope - and the
// «Сканировать» after it scans nothing, never that old scope; a scope it takes scans again.
static void refusedScopeNeverScansAnother()
{
    World w = baseWorld("refused_scope", hostMac(), ScanNetKind::Wifi);
    ScanMachine m(w.caps);
    m.shown(openOf(w, QString(), false), kT0);
    ScanPoolView pool;
    pool.countries = {ScanPoolView::Country{QStringLiteral("DE"), 3, 0}, ScanPoolView::Country{QStringLiteral("SE"), 1, 0}};
    pool.whitelist = 0;
    m.poolReady(pool, kT0 + 10);
    m.filterChosen(QStringLiteral("DE"), kT0 + 20);
    CHECK(m.view(kT0 + 20).bar.scope == QLatin1String("DE"));
    m.filterChosen(QStringLiteral("whitelist"), kT0 + 30);
    CHECK(m.view(kT0 + 30).bar.scope == QLatin1String("DE")); // refused: the old scope stays
    CHECK(!m.retryTapped(kT0 + 40).has(ScanActionKind::RequestManifest) && !m.view(kT0 + 40).scanning);
    m.filterChosen(QStringLiteral("SE"), kT0 + 50);
    CHECK(m.retryTapped(kT0 + 60).has(ScanActionKind::RequestManifest));
}

// D1 (device round air-C, iPhone Air, 24.11): one verdict per row - the number in the rings is the rows the list shows
// as available. The journal: «21:43:06.255 app_probe id=12 kind=awg_mini hs_ok=true http=200 bytes_rx=65536 sha_ok=true
// rtt_ms=89», then «21:43:08.376 path_outcome node=12 outcome=probe_ok source=scanner state=suspect» (an older failed
// connect on this network); rings «10 доступно», rows 9 «Доступно» + node 12 «Не удалось». Here: own AWG "1" proven by
// awg_mini (handshake + 64 KiB, sha ok, 89 ms) and own Xray "4:xray" proven by a light leg probe, both with the ledger's
// «real tunnel carried no data here» mark. The full-path proof wins on the row; the light one never outranks the mark
// (PathLedger stage 2): «Не удалось», not counted - the rings, the rows and the choice row («M доступно») agree.
static void oneVerdictPerRow()
{
    World w = baseWorld("one_verdict", hostMac(), ScanNetKind::Wifi);
    w.awgMini = true;
    w.numbers.insert(QStringLiteral("scan_awg_concurrency"), 2);
    w.out[QStringLiteral("1")].rtt = 89;
    w.script << qMakePair(qint64(0), at("tunnel_no_data", {{QStringLiteral("ids"), QJsonArray{QStringLiteral("1"), QStringLiteral("4:xray")}}}));
    w.script << qMakePair(qint64(0), at("opened", openArgs(w, QString(), false)));
    w.runMs = 12000;
    Driver d(w);
    d.run();
    const QJsonObject v = lastView(d);
    const QString st1 = rowOf(v, QStringLiteral("1")).value(QLatin1String("state")).toString();
    const QString st4 = rowOf(v, QStringLiteral("4:xray")).value(QLatin1String("state")).toString();
    CHECK(phaseOf(v) == QLatin1String("done"));
    CHECK(st1 == QLatin1String("works") || st1 == QLatin1String("slow")); // the scan's handshake + data proof wins
    CHECK(st4 == QLatin1String("failed"));                                // a light probe never outranks the mark
    const int shown = rowsInState(v, "works") + rowsInState(v, "slow");
    CHECK(v.value(QLatin1String("available")).toInt() == shown);
    const QJsonArray sl = v.value(QLatin1String("slots")).toArray();
    CHECK(sl.size() == 1 && sl.at(0).toObject().value(QLatin1String("works")).toInt() == shown);
    // the stored result keeps the proof's strength: restored later, the same verdicts and the same count
    const ScanAction *p = lastAction(d, ScanActionKind::PersistResults);
    CHECK(p != nullptr);
    if (!p)
        return;
    const ScanCachedResult stored = scanCachedResultFromJson(scanCachedResultToJson(p->cached));
    bool full1 = false, full4 = true;
    for (const ScanCachedRow &r : stored.rows) {
        if (r.id == QLatin1String("1"))
            full1 = r.fullProof;
        if (r.id == QLatin1String("4:xray"))
            full4 = r.fullProof;
    }
    CHECK(full1 && !full4);
    ScanOpen o = openOf(w, QString(), false);
    o.cached = stored;
    ScanMachine m(w.caps);
    const qint64 t = stored.savedAtMs + 60000;
    m.tunnelNoDataHere({QStringLiteral("1"), QStringLiteral("4:xray")}, t);
    m.shown(o, t);
    const QJsonObject r = viewJson(m, t);
    CHECK(rowOf(r, QStringLiteral("4:xray")).value(QLatin1String("state")).toString() == QLatin1String("failed"));
    CHECK(r.value(QLatin1String("available")).toInt() == rowsInState(r, "works") + rowsInState(r, "slow")
          && r.value(QLatin1String("available")).toInt() == shown);
    const QJsonArray rs = r.value(QLatin1String("slots")).toArray();
    CHECK(!rs.isEmpty() && rs.at(0).toObject().value(QLatin1String("works")).toInt() == shown);
    // a data ok through the real tunnel since (the mark gone): the row is available again
    m.tunnelNoDataHere({}, t + 10);
    CHECK(rowOf(viewJson(m, t + 10), QStringLiteral("4:xray")).value(QLatin1String("state")).toString() == QLatin1String("works"));
}

// D2 (device round air-C, Latvia on Wi-Fi): POST /v1/scan/candidates timed out after 15.2 s ("api candidates status=0
// nodes=0"), the scope has no row of the device's own - the old machine ended the scan Empty and stored it
// ("persist_results rows=0", «Латвия: доступных серверов сейчас нет»). One rule with a failed manifest (the LTE case):
// a scan that checked nothing could not start - NoScan, nothing stored, no cooldown, the scope's old result untouched.
static void failedCandidatesAreNoResult()
{
    World w = baseWorld("cand_failed", hostMac(), ScanNetKind::Wifi);
    const auto actionOf = [](const ScanStep &s, ScanActionKind k) {
        for (const ScanAction &a : s.actions)
            if (a.kind == k)
                return a;
        return ScanAction();
    };
    for (const char *reason : {"timeout", "unsupported"}) {
        ScanMachine m(w.caps);
        m.opened(openOf(w, QString(), false), kT0);
        m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50);
        m.tick(kT0 + 50 + 8100);
        m.poolReady(ScanPoolView{{}, 3, 1}, kT0 + 8300);
        m.filterChosen(QStringLiteral("whitelist"), kT0 + 8300); // a scope with none of the device's own rows
        m.retryTapped(kT0 + 40000);
        const ScanAction rc = actionOf(m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 40050), ScanActionKind::RequestCandidates);
        CHECK(!rc.requestId.isEmpty());
        const ScanStep f = m.candidatesUnavailable(rc.requestId, QLatin1String(reason), 300, kT0 + 55250);
        const ScanView v = m.view(kT0 + 55250);
        CHECK(!f.has(ScanActionKind::PersistResults) && !f.has(ScanActionKind::StartHostScan));
        CHECK(v.phase == ScanPhase::NoScan && v.empty.reason == QLatin1String("candidates_unavailable"));
        bool slot = false;
        for (const ScanSlotView &sv : v.scopeSlots)
            slot = slot || sv.scope == QLatin1String(kScanScopeWhitelist);
        CHECK(!slot); // never stored as that scope's result
        // no host started: no cooldown armed by it - «Сканировать» is offered again
        CHECK(v.bar.button == ScanBarButton::Retry && v.bar.buttonEnabled);
        CHECK(m.retryTapped(kT0 + 56500).has(ScanActionKind::RequestManifest));
    }
}

// D6 (device round air-C): «Проверяем доступность · 2 из 21» while the log said "start_host_scan candidates=18" - the
// denominator counted the candidates the plan gave up before any probe (and counted them as reached). One set for
// both numbers: what this scan checks (handed to the host, or still waiting for a seat).
static void progressCountsWhatIsChecked()
{
    World w = baseWorld("progress", hostMac(), ScanNetKind::Cellular); // full-kind providers: no config on cellular
    w.script << qMakePair(qint64(0), at("opened", openArgs(w, QString(), false)));
    w.runMs = 12000;
    Driver d(w);
    d.run();
    int startAt = -1;
    for (int i = 0; i < d.steps.size() && startAt < 0; ++i)
        if (d.steps.at(i).step.has(ScanActionKind::StartHostScan))
            startAt = i;
    CHECK(startAt >= 0);
    if (startAt < 0)
        return;
    const ScanStep &st = d.steps.at(startAt).step;
    int checks = st.find(ScanActionKind::StartHostScan)->candidates.size();
    if (const ScanAction *b = st.find(ScanActionKind::RequestProbeBatch))
        checks += b->ids.size();
    const QJsonObject v = d.steps.at(startAt).view;
    CHECK(phaseOf(v) == QLatin1String("reach"));
    CHECK(v.value(QLatin1String("stage_total")).toInt() == checks && v.value(QLatin1String("stage_count")).toInt() == 0);
    // the count never passes the total, and it ends with every checked candidate reached
    for (const Recorded &r : d.steps)
        if (phaseOf(r.view) == QLatin1String("reach"))
            CHECK(r.view.value(QLatin1String("stage_count")).toInt() <= r.view.value(QLatin1String("stage_total")).toInt());
}

// E1 (device round air-D, iPhone Air, 25.11): a scan WHILE CONNECTED (Германия 1 Xray). The round's lines: "action
// probe_live_tunnel bytes=65536", "api live_probe warm status=0" (our API did not answer through the tunnel), "api
// probe_batch status=0 asked=10 granted=0 fail=transport", "persist_results rows=1"; the list: Германия 1 «Подключено»,
// Финляндия 1 Xray «Доступно», Белые списки 1, 2 «Не проверено" - the rings said 1. The live connection carries data (the
// engine's check), it reads «Подключено» and is counted like the list shows it, proven by the scan's own check or not.
static void connectedRowIsCounted()
{
    World w = baseWorld("connected_count", hostMac(), ScanNetKind::Wifi);
    w.current = QStringLiteral("2:xray");
    w.liveProbeWorks = false;   // "api live_probe warm status=0"
    w.cutApp = QStringLiteral("batch"); // "api probe_batch status=0 ... fail=transport": the providers stay unchecked
    w.script << qMakePair(qint64(0), at("opened", openArgs(w, w.current, true)));
    w.runMs = 12000;
    Driver d(w);
    d.run();
    const QJsonObject v = lastView(d);
    const QJsonObject live = rowOf(v, QStringLiteral("2:xray"));
    CHECK(phaseOf(v) == QLatin1String("done") && live.value(QLatin1String("state")).toString() == QLatin1String("connected"));
    const int shown = rowsInState(v, "works") + rowsInState(v, "slow") + rowsInState(v, "connected");
    CHECK(rowsInState(v, "connected") == 1 && v.value(QLatin1String("available")).toInt() == shown);
}

// E2 (device round air-D): the engine dropped the tapped row's request before its own attempt began ("intent_off
// why=external_loss" after the older row's seat request hung): the row is not «Не удалось», no outcome is sent, the chain
// is over and the person is told the connect did not start ("connect_not_started") - the row can be tapped again.
static void droppedRequestIsNoVerdict()
{
    World w = baseWorld("dropped", hostMac(), ScanNetKind::Wifi);
    w.script << qMakePair(qint64(0), at("opened", openArgs(w, QString(), false)));
    w.runMs = 9000;
    Driver d(w);
    d.run();
    QStringList ids;
    for (const QJsonValue &x : lastView(d).value(QLatin1String("rows")).toArray())
        if (x.toObject().value(QLatin1String("state")).toString() == QLatin1String("works"))
            ids << x.toObject().value(QLatin1String("id")).toString();
    CHECK(ids.size() >= 2);
    if (ids.size() < 2)
        return;
    const QString a = ids.at(0), b = ids.at(1);
    const qint64 t = d.now + 1000;
    d.m.rowTapped(a, t);
    d.m.rowTapped(b, t + 700);
    const ScanStep s = d.m.rowRequestDropped(b, t + 6500);
    const QJsonObject v = viewJson(d.m, t + 6500);
    CHECK(rowOf(v, b).value(QLatin1String("state")).toString() == QLatin1String("works"));
    CHECK(rowOf(v, a).value(QLatin1String("state")).toString() == QLatin1String("works"));
    CHECK(d.m.connectingId().isEmpty() && !s.has(ScanActionKind::SendOutcomes));
    bool told = false;
    for (const ScanAction &x : s.actions)
        told = told || (x.kind == ScanActionKind::ShowShade && x.shade.textKey == QLatin1String("connect_not_started"));
    CHECK(told);
    CHECK(d.m.rowTapped(b, t + 7000).has(ScanActionKind::ConnectRow)); // tappable again
}

// E3 (device round air-D, pair 1): a row tapped (Германия 2), its tunnel coming up, and the path monitor's notice of our
// own utun 0.5 s later - "network kind=wifi key=wifi:asn:12389 gen=f48c..." with the path engine's
// "scan_network_key_refined net_gen=19" (the same physical network) - rebuilt the list from the cached result in another
// order; the second tap, aimed at the row under the finger, hit another row. While a row's connect runs the list keeps
// its rows and order on such a notice (and on a moment of "kind=unknown"); another network still rebuilds it.
static void ownTunnelNoticeKeepsTheList()
{
    World w = baseWorld("own_tunnel", hostMac(), ScanNetKind::Wifi);
    w.script << qMakePair(qint64(0), at("opened", openArgs(w, QString(), false)));
    w.runMs = 9000;
    Driver d(w);
    d.run();
    const QJsonObject v0 = lastView(d);
    const QStringList ids0 = rowIds(v0);
    QString a;
    for (const QJsonValue &x : v0.value(QLatin1String("rows")).toArray())
        if (a.isEmpty() && x.toObject().value(QLatin1String("state")).toString() == QLatin1String("works"))
            a = x.toObject().value(QLatin1String("id")).toString();
    CHECK(ids0.size() >= 3 && !a.isEmpty());
    const qint64 t = d.now + 1000;
    d.m.rowTapped(a, t);
    const double build = viewJson(d.m, t).value(QLatin1String("list_build")).toDouble();
    // a moment without a network while the tunnel switches, then the same Wi-Fi with a new generation and a refined key
    ScanNetwork none = scanNet(ScanNetKind::Unknown, QStringLiteral("unknown"), 7);
    d.m.networkChanged(none, ScanCachedResult(), t + 450);
    ScanNetwork same = w.net;
    same.key = w.net.key + QStringLiteral(":asn:12389");
    same.sources = {ScanNetSource{QStringLiteral("app"), kAppEpoch, 9}};
    d.m.networkChanged(same, ScanCachedResult(), t + 500);
    const QJsonObject v1 = viewJson(d.m, t + 500);
    CHECK(v1.value(QLatin1String("list_build")).toDouble() == build);
    CHECK(rowIds(v1) == ids0); // every row in its place
    bool cached = false;
    for (const QJsonValue &x : v1.value(QLatin1String("rows")).toArray())
        cached = cached || x.toObject().value(QLatin1String("flags")).toArray().contains(QStringLiteral("cache"));
    CHECK(!cached && rowOf(v1, a).value(QLatin1String("state")).toString() == QLatin1String("connecting"));
    // another network (another fingerprint) still rebuilds the list
    d.m.networkChanged(scanNet(ScanNetKind::Wifi, QStringLiteral("wifi:asn:64999"), 1, QStringLiteral("gw2")), ScanCachedResult(), t + 900);
    CHECK(viewJson(d.m, t + 900).value(QLatin1String("list_build")).toDouble() != build);
}

// Review R50 (finding 3): a REAL change Wi-Fi A -> no network -> Wi-Fi B during a row connect, B with A's weak fingerprint
// (iOS: the Wi-Fi identity is the subnet - two home routers on 192.168.1.0/24) showed A's results as checked in B. Our
// own tunnel's moment without a network is short (device logs: 0.15 s, 1.4 s into a row connect; every other gap 30 s
// and more): an Unknown notice during a row connect is ignored for ScanMachine::kOwnTunnelGapMs only. The known network
// back within it is our own transition (the list and its results stay); a longer gap is a network change like any
// other - nothing measured in A is carried into B's generation as current.
static void ownTunnelGapIsBounded()
{
    for (const qint64 gap : {qint64(0), ScanMachine::kOwnTunnelGapMs, ScanMachine::kOwnTunnelGapMs + 1, qint64(20000)}) {
        World w = baseWorld("own_tunnel_gap", hostMac(), ScanNetKind::Wifi);
        w.script << qMakePair(qint64(0), at("opened", openArgs(w, QString(), false)));
        w.runMs = 9000;
        Driver d(w);
        d.run();
        const QJsonObject v0 = lastView(d);
        const QStringList ids0 = rowIds(v0);
        QString a;
        for (const QJsonValue &x : v0.value(QLatin1String("rows")).toArray())
            if (a.isEmpty() && x.toObject().value(QLatin1String("state")).toString() == QLatin1String("works"))
                a = x.toObject().value(QLatin1String("id")).toString();
        CHECK(ids0.size() >= 3 && !a.isEmpty());
        const qint64 t = d.now + 1000;
        d.m.rowTapped(a, t);
        const double build = viewJson(d.m, t).value(QLatin1String("list_build")).toDouble();
        d.m.networkChanged(scanNet(ScanNetKind::Unknown, QStringLiteral("unknown"), 7), ScanCachedResult(), t + 400);
        CHECK(viewJson(d.m, t + 400).value(QLatin1String("list_build")).toDouble() == build); // the moment itself: kept
        // the same kind and fingerprint, a new generation: our own tunnel (same Wi-Fi) or Wi-Fi B on the same subnet
        ScanNetwork back = w.net;
        back.sources = {ScanNetSource{QStringLiteral("app"), kAppEpoch, 9}};
        const qint64 t1 = t + 400 + gap;
        d.m.networkChanged(back, ScanCachedResult(), t1);
        const QJsonObject v1 = viewJson(d.m, t1);
        int fresh = 0; // rows measured in A shown as current (no cache flag)
        for (const QJsonValue &x : v1.value(QLatin1String("rows")).toArray()) {
            const QJsonObject r = x.toObject();
            if (r.value(QLatin1String("state")).toString() == QLatin1String("works")
                && !r.value(QLatin1String("flags")).toArray().contains(QStringLiteral("cache")))
                ++fresh;
        }
        if (gap <= ScanMachine::kOwnTunnelGapMs) {
            CHECK(v1.value(QLatin1String("list_build")).toDouble() == build && rowIds(v1) == ids0 && fresh > 0);
        } else {
            CHECK(v1.value(QLatin1String("list_build")).toDouble() != build); // a network change like any other
            CHECK(fresh == 0);                                                 // was: A's results checked in B
        }
    }
}

static void refusedEndsScope()
{
    // Device round air9 (19.11): under «Германия» one profile's probe config could not be built; it stayed «Не
    // проверено» outside `seen`, the server offered it again, it was refused again - «Найти ещё» never ended.
    World w = baseWorld("srv_refused", hostMac(), ScanNetKind::Wifi);
    w.nodes = ownOnly(w.nodes);
    w.numbers.insert(QStringLiteral("scan_stop_works"), 1);
    const auto actionOf = [](const ScanStep &s, ScanActionKind k) {
        for (const ScanAction &a : s.actions)
            if (a.kind == k)
                return a;
        return ScanAction();
    };
    const auto works = [](const QString &id) {
        ScanProbeFacts f = goodData();
        f.id = id;
        f.egressNode = id.section(QLatin1Char(':'), 0, 0);
        return f;
    };
    ScanMachine m(w.caps);
    m.opened(openOf(w, QString(), false), kT0);
    const ScanAction start1 = actionOf(m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50), ScanActionKind::StartHostScan);
    CHECK(start1.candidates.size() >= 3);
    if (start1.candidates.size() < 3)
        return;
    m.hostProgress(progressOf(m, {works(start1.candidates.at(0).id)}), kT0 + 900);
    m.tick(kT0 + 50 + 8100);
    m.moreTapped(QString(), kT0 + 31000);
    const ScanAction rc = actionOf(m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 31050), ScanActionKind::RequestCandidates);
    ScanManifestView mv;
    scanManifestViewFromJson(manifestBody(w), mv);
    ScanCandidatesView cv;
    cv.exhausted = true; // nothing of the scope beyond this batch
    for (const ScanManifestNode &n : mv.nodes)
        if (n.nodeId != start1.candidates.at(0).id && cv.nodes.size() < 2
            && std::any_of(start1.candidates.begin(), start1.candidates.end(), [&n](const ScanCandidate &c) { return c.id == n.nodeId; }))
            cv.nodes << n;
    CHECK(cv.nodes.size() == 2);
    if (cv.nodes.size() < 2)
        return;
    const ScanAction start2 = actionOf(m.candidatesReady(rc.requestId, cv, 4000, kT0 + 31300), ScanActionKind::StartHostScan);
    CHECK(start2.candidates.size() == 2);
    if (start2.candidates.size() < 2)
        return;
    const QString refused = start2.candidates.at(0).id;
    m.candidateRefused(refused, QStringLiteral("config"), kT0 + 31310); // the coordinator could not build its config
    m.hostProgress(progressOf(m, {works(start2.candidates.at(1).id)}), kT0 + 32000);
    m.tick(kT0 + 31300 + 8100);
    const ScanView v = m.view(kT0 + 39500);
    CHECK(!v.scanning && v.moreState == QLatin1String("exhausted"));
    // and a scope that is not exhausted never offers the refused row again: it is in the next `seen`
    ScanMachine m2(w.caps);
    m2.opened(openOf(w, QString(), false), kT0);
    const ScanAction s21 = actionOf(m2.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50), ScanActionKind::StartHostScan);
    if (s21.candidates.size() < 3)
        return;
    m2.candidateRefused(s21.candidates.at(1).id, QStringLiteral("config"), kT0 + 60);
    m2.hostProgress(progressOf(m2, {works(s21.candidates.at(0).id)}), kT0 + 900);
    m2.tick(kT0 + 50 + 8100);
    m2.moreTapped(QString(), kT0 + 31000);
    const ScanAction rc2 = actionOf(m2.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 31050), ScanActionKind::RequestCandidates);
    CHECK(!rc2.requestId.isEmpty() && rc2.ids.contains(s21.candidates.at(1).id));
    // the same when the HOST refuses the config (probe error `config`, device round air9: an xray_full profile)
    ScanMachine m3(w.caps);
    m3.opened(openOf(w, QString(), false), kT0);
    const ScanAction s31 = actionOf(m3.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50), ScanActionKind::StartHostScan);
    if (s31.candidates.size() < 3)
        return;
    ScanProbeFacts bad;
    bad.id = s31.candidates.at(1).id;
    bad.error = ScanProbeError::Config;
    m3.hostProgress(progressOf(m3, {works(s31.candidates.at(0).id), bad}), kT0 + 900);
    m3.tick(kT0 + 50 + 8100);
    m3.moreTapped(QString(), kT0 + 31000);
    const ScanAction rc3 = actionOf(m3.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 31050), ScanActionKind::RequestCandidates);
    CHECK(!rc3.requestId.isEmpty() && rc3.ids.contains(s31.candidates.at(1).id));
}

static void liveProofHasAnEnd()
{
    // Device round air7 (19.11): a cached «Германия» result on the screen (Idle, after a network flip), a row tapped
    // and connected in 2.2 s - then «проверяем загрузку…» for 15+ minutes: Idle never sent the proof, and the row
    // said «checking» whatever was (not) running.
    World w = baseWorld("live_end", hostMac(), ScanNetKind::Wifi);
    Driver dd(w);
    const auto flagsOf = [](const ScanView &v, const QString &id) {
        for (const QJsonValue &r : scanViewToJson(v).value(QStringLiteral("rows")).toArray())
            if (r.toObject().value(QStringLiteral("id")).toString() == id)
                return r.toObject().value(QStringLiteral("flags")).toArray();
        return QJsonArray();
    };
    const auto shownWithCache = [&](ScanMachine &m) {
        ScanOpen o = openOf(w, QString(), false);
        ScanCachedResult c;
        c.networkKey = o.network.key;
        c.fingerprint = o.network.fingerprint;
        c.savedAtMs = kT0;
        ScanCachedRow a;
        a.id = QStringLiteral("1");
        a.countryCode = QStringLiteral("DE");
        a.label = QStringLiteral("Германия 1");
        a.ms = 40;
        ScanCachedRow b = a;
        b.id = QStringLiteral("2");
        b.label = QStringLiteral("Германия 2");
        c.rows << a << b;
        o.cached = c;
        m.shown(o, kT0 + 1000);
    };
    {
        ScanMachine m(w.caps);
        shownWithCache(m);
        CHECK(m.phase() == ScanPhase::Idle && m.view(kT0 + 1000).rows.size() == 2);
        CHECK(m.rowTapped(QStringLiteral("2"), kT0 + 2000).has(ScanActionKind::ConnectRow));
        const ScanStep up = m.vpnState(liveOf(w, QStringLiteral("2"), true), kT0 + 4000);
        const ScanAction *lp = up.find(ScanActionKind::ProbeLiveTunnel);
        CHECK(lp && lp->nodeId == QLatin1String("2")); // the row the person connected gets its proof
        CHECK(flagsOf(m.view(kT0 + 4000), QStringLiteral("2")).contains(QStringLiteral("live_unverified")));
        if (lp)
            m.appRequestDone(lp->requestId, 70000, kT0 + 6000); // the answer was dropped as stale: no result comes
        const QJsonArray f = flagsOf(m.view(kT0 + 6000), QStringLiteral("2"));
        CHECK(f.contains(QStringLiteral("current")) && !f.contains(QStringLiteral("live_unverified")) && !f.contains(QStringLiteral("unverified")));
        CHECK(m.view(kT0 + 6000).rows.size() == 2); // the result stays on the screen
    }
    {
        ScanMachine m(w.caps);
        shownWithCache(m);
        m.rowTapped(QStringLiteral("1"), kT0 + 2000);
        const ScanAction *lp = m.vpnState(liveOf(w, QStringLiteral("1"), true), kT0 + 4000).find(ScanActionKind::ProbeLiveTunnel);
        CHECK(lp != nullptr);
        m.liveProbeResult(QStringLiteral("1"), dd.liveFacts(QStringLiteral("1")), kT0 + 4700);
        const ScanView v = m.view(kT0 + 4700);
        bool proved = false;
        for (const ScanRowView &r : v.rows)
            proved = proved || (r.id == QLatin1String("1") && r.verified && r.state == ScanRowState::Connected);
        CHECK(proved && v.rows.size() == 2);
    }
    {
        // opening the screen with a live VPN: no proof is spent, and the row is no «проверяем загрузку…»
        ScanMachine q(w.caps);
        CHECK(!q.shown(openOf(w, QStringLiteral("1"), true), kT0).has(ScanActionKind::ProbeLiveTunnel));
        const QJsonArray f = flagsOf(q.view(kT0), QStringLiteral("1"));
        CHECK(f.contains(QStringLiteral("current")) && !f.contains(QStringLiteral("live_unverified")));
    }
}

static void listFullPerBatch()
{
    // Device round air9 (19.11), «Германия», «Найти ещё»: a provider of a higher tier was granted its seat and given
    // back at once (list_full) in every later batch - the list's fill was counted over the whole series while the
    // list admits scan_list_target_works rows PER BATCH; the row never got a verdict, was offered again, forever.
    World w = baseWorld("list_batch", hostMac(), ScanNetKind::Wifi);
    w.numbers.insert(QStringLiteral("scan_list_target_works"), 1);
    w.numbers.insert(QStringLiteral("scan_stop_works"), 1);
    ScanMachine m(w.caps);
    m.opened(openOf(w, QString(), false), kT0);
    const ScanStep first = m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50);
    const ScanAction *st = first.find(ScanActionKind::StartHostScan);
    CHECK(st && !st->candidates.isEmpty());
    if (!st || st->candidates.isEmpty())
        return;
    ScanProbeFacts f = goodData();
    f.id = st->candidates.at(0).id; // an own row (tier 0) works: batch 1's list is full
    f.egressNode = f.id.section(QLatin1Char(':'), 0, 0);
    m.hostProgress(progressOf(m, {f}), kT0 + 900);
    m.tick(kT0 + 50 + 8100);
    CHECK(!m.view(kT0 + 8200).scanning);
    m.moreTapped(QString(), kT0 + 40000);
    const ScanStep ms = m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 40050);
    const ScanAction *rc = ms.find(ScanActionKind::RequestCandidates);
    CHECK(rc != nullptr);
    if (!rc)
        return;
    ScanManifestView mv;
    scanManifestViewFromJson(manifestBody(w), mv);
    ScanCandidatesView cv;
    cv.exhausted = true;
    for (const ScanManifestUpstream &u : mv.upstream)
        if (upstreamNodeIdFor(u.profileId) == up(1))
            cv.upstream << u;
    CHECK(cv.upstream.size() == 1);
    const ScanStep cs = m.candidatesReady(rc->requestId, cv, 4000, kT0 + 40100);
    const ScanAction *b = cs.find(ScanActionKind::RequestProbeBatch);
    CHECK(b && b->ids.contains(up(1)));
    const ScanStep g = m.probeLeaseGranted(up(1), ScanAccess(), kT0 + 40200);
    CHECK(g.has(ScanActionKind::AddHostCandidates)); // the new batch's list is empty: the provider is probed
}

static void rowsAfter17Nov()
{
    // the manifest's `kind`: absent = Unspecified, unknown = auto
    {
        World w = baseWorld("kind", hostMac(), ScanNetKind::Wifi);
        QJsonObject body = manifestBody(w);
        QJsonArray ups = body.value(QStringLiteral("upstream")).toArray();
        CHECK(ups.size() >= 1);
        QJsonObject base = ups.at(0).toObject();
        QJsonArray mine;
        const auto entry = [&](const char *pid, const char *kind, const char *cc) {
            QJsonObject e = base;
            e.insert(QStringLiteral("profile_id"), QLatin1String(pid));
            if (kind)
                e.insert(QStringLiteral("kind"), QLatin1String(kind));
            else
                e.remove(QStringLiteral("kind"));
            e.insert(QStringLiteral("country_code"), cc ? QJsonValue(QLatin1String(cc)) : QJsonValue());
            mine << e;
        };
        entry("aaaaaaaaaaaaaa01", "country", "NL");
        entry("aaaaaaaaaaaaaa02", "whitelist", nullptr);
        entry("aaaaaaaaaaaaaa03", "auto", nullptr);
        entry("aaaaaaaaaaaaaa04", nullptr, nullptr);      // an older server: no kind, no country
        entry("aaaaaaaaaaaaaa05", nullptr, "PL");         // an older server: no kind, a country
        entry("aaaaaaaaaaaaaa06", "balancer-v2", "DE");   // a kind this build does not know
        entry("aaaaaaaaaaaaaa07", "country", nullptr);    // a country row without a country
        body.insert(QStringLiteral("upstream"), mine);
        ScanManifestView v;
        CHECK(scanManifestViewFromJson(body, v));
        CHECK(v.upstream.size() == 7);
        if (v.upstream.size() == 7) {
            CHECK(v.upstream.at(0).kind == UpstreamKind::Country && v.upstream.at(1).kind == UpstreamKind::Whitelist);
            CHECK(v.upstream.at(2).kind == UpstreamKind::Auto && v.upstream.at(3).kind == UpstreamKind::Unspecified);
            CHECK(v.upstream.at(5).kind == UpstreamKind::Auto);
        }
        // the planner never makes a row of the balancer (the server omits it; a safeguard for old servers)
        ScanPlanInput in = planInput(hostMac());
        in.manifest.upstream = v.upstream;
        const ScanPlan p = buildScanPlan(in);
        const auto planned = [&](const char *pid) {
            const QString id = upstreamNodeIdFor(QLatin1String(pid));
            return findC(p.probe, id) != nullptr || findC(p.orderOnly, id) != nullptr;
        };
        CHECK(planned("aaaaaaaaaaaaaa01") && planned("aaaaaaaaaaaaaa02") && planned("aaaaaaaaaaaaaa05"));
        CHECK(!planned("aaaaaaaaaaaaaa03") && excluded(p, QStringLiteral("up:aaaaaaaaaaaaaa03"), "auto_kind"));
        CHECK(!planned("aaaaaaaaaaaaaa04") && excluded(p, QStringLiteral("up:aaaaaaaaaaaaaa04"), "auto_kind"));
        CHECK(!planned("aaaaaaaaaaaaaa06") && excluded(p, QStringLiteral("up:aaaaaaaaaaaaaa06"), "auto_kind"));
        CHECK(!planned("aaaaaaaaaaaaaa07") && excluded(p, QStringLiteral("up:aaaaaaaaaaaaaa07"), "auto_kind"));
    }

    // the server list's figures: the persisted result of THIS network while the Scanner would show it
    {
        ScanCachedResult c;
        c.networkKey = QStringLiteral("wifi:asn:64500");
        c.fingerprint = QStringLiteral("fp-a");
        c.savedAtMs = kT0;
        ScanCachedRow a;
        a.id = QStringLiteral("up:aaaaaaaaaaaaaa01");
        a.origin = ScanOrigin::Upstream;
        a.cls = ScanClass::Works;
        a.ms = 44;
        ScanCachedRow b = a;
        b.id = QStringLiteral("up:aaaaaaaaaaaaaa02");
        b.cls = ScanClass::Slow;
        b.ms = 310;
        ScanCachedRow nf = a;
        nf.id = QStringLiteral("up:aaaaaaaaaaaaaa05");
        nf.ms = -1; // no figure: nothing is invented
        c.rows << a << b << nf;
        const int ttl = ScanTunables().cacheWorksTtlS;
        QHash<QString, int> f = scanListFigures(c, c.fingerprint, kT0 + 5000, ttl);
        CHECK(f.size() == 2 && f.value(a.id) == 44 && f.value(b.id) == 310 && !f.contains(nf.id));
        CHECK(scanListFigures(c, c.fingerprint, kT0 + qint64(ttl) * 1000, ttl).size() == 2);
        CHECK(scanListFigures(c, c.fingerprint, kT0 + qint64(ttl) * 1000 + 1, ttl).isEmpty()); // too old
        CHECK(scanListFigures(c, c.fingerprint, kT0 - 60000, ttl).size() == 2);               // clock behind
        CHECK(scanListFigures(c, c.fingerprint, kT0 - 60001, ttl).isEmpty());
        CHECK(scanListFigures(c, QStringLiteral("fp-b"), kT0, ttl).isEmpty());              // other network
        // saved before the reporting key was refined (the access ASN learned later on the same network): still its own
        ScanCachedResult refined = c;
        refined.networkKey = QStringLiteral("wifi");
        CHECK(scanListFigures(refined, c.fingerprint, kT0, ttl).size() == 2);
        CHECK(scanListFigures(c, QString(), kT0, ttl).isEmpty());
        CHECK(scanListFigures(ScanCachedResult(), c.fingerprint, kT0, ttl).isEmpty());
        // a failure never gives a figure: it is not a row of the persisted result
        ScanCachedRow bad = a;
        bad.cls = ScanClass::NoData;
        ScanCachedRow back;
        CHECK(!scanCachedRowFromJson(scanCachedRowToJson(bad), back));
    }

    // an earlier build's countryless provider rows («Сервер N») are not read back; marked results keep theirs
    {
        ScanCachedResult c;
        c.networkKey = QStringLiteral("wifi");
        c.fingerprint = QStringLiteral("fp");
        c.savedAtMs = kT0;
        ScanCachedRow own;
        own.id = QStringLiteral("4:xray");
        own.cls = ScanClass::Works;
        ScanCachedRow up = own;
        up.id = QStringLiteral("up:aaaaaaaaaaaaaa02");
        up.origin = ScanOrigin::Upstream;
        up.label = QStringLiteral("Сервер 5");
        ScanCachedRow upCc = up;
        upCc.id = QStringLiteral("up:aaaaaaaaaaaaaa01");
        upCc.countryCode = QStringLiteral("NL");
        upCc.label = QStringLiteral("Нидерланды 1");
        c.rows << own << up << upCc;
        const QJsonObject legacy = scanCachedResultToJson(c);
        ScanCachedResult r = scanCachedResultFromJson(legacy);
        scanDropLegacyLabels(r, legacy);
        CHECK(r.rows.size() == 2 && r.rows.at(0).id == own.id && r.rows.at(1).id == upCc.id);
        QJsonObject marked = legacy;
        marked.insert(QLatin1String(kScanCachedLabelRuleKey), QLatin1String(kScanCachedLabelRule));
        ScanCachedResult m = scanCachedResultFromJson(marked);
        scanDropLegacyLabels(m, marked);
        CHECK(m.rows.size() == 3);
    }

    // Owner 19.11: no scan starts unless the person presses «Сканировать». A finished result + another network:
    // no scan by itself - the new network's cached result with its age and its scope, else the open page.
    {
        World w = baseWorld("netchange", hostMac(), ScanNetKind::Wifi);
        const ScanNetwork other = scanNet(ScanNetKind::Wifi, QStringLiteral("wifi:asn:64501"), 2);
        ScanCachedResult cached;
        cached.networkKey = other.key;
        cached.fingerprint = other.fingerprint;
        cached.savedAtMs = kT0 + 20000; // a Germany scan of that network, 1 min before the change
        cached.scope = QStringLiteral("DE");
        ScanCachedRow cr;
        cr.id = QStringLiteral("9:xray");
        cr.label = QStringLiteral("Германия 9");
        cr.countryCode = QStringLiteral("DE");
        cr.speed = ScanSpeed::Fast;
        cr.ms = 80;
        cached.rows << cr;
        const QJsonObject cj = scanCachedResultToJson(cached);
        CHECK(cj.value(QStringLiteral("scope")).toString() == QLatin1String("DE") && scanCachedResultFromJson(cj).scope == QLatin1String("DE"));
        for (bool open : {true, false})
            for (bool withCache : {true, false}) {
                ScanMachine m(w.caps);
                m.opened(openOf(w, QStringLiteral("1"), true), kT0);
                m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50);
                m.tick(kT0 + 60000);
                m.tick(kT0 + 70000);
                CHECK(m.phase() == ScanPhase::Done || m.phase() == ScanPhase::Empty);
                if (!open)
                    m.closed(kT0 + 71000);
                const ScanStep s = m.networkChanged(other, withCache ? cached : ScanCachedResult(), kT0 + 80000);
                const ScanView v = m.view(kT0 + 80000);
                CHECK(!scanPhaseScanning(m.phase()) && !s.has(ScanActionKind::RequestManifest) && !s.has(ScanActionKind::UserConnectForScan));
                CHECK(m.phase() == ScanPhase::Idle && v.empty.reason.isEmpty());
                bool oldShown = false, cacheShown = false;
                for (const ScanRowView &r : v.rows) {
                    oldShown = oldShown || (!r.fromCache && !r.current);
                    cacheShown = cacheShown || (r.fromCache && r.id == cr.id);
                }
                CHECK(!oldShown); // never another network's result as current
                if (withCache)
                    CHECK(cacheShown && v.checkedAgoMin == 1 && v.bar.scope == QLatin1String("DE") && v.bar.scannedScope == QLatin1String("DE"));
                else
                    CHECK(!cacheShown && v.checkedAgoMin < 0 && v.bar.scannedScope.isEmpty());
            }
    }
    // a running scan the person started: the change restarts it on the new network (the same press)
    {
        World w = baseWorld("netchange_run", hostMac(), ScanNetKind::Wifi);
        ScanMachine m(w.caps);
        m.opened(openOf(w, QString(), false), kT0);
        m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50);
        CHECK(m.phase() == ScanPhase::Reach || m.phase() == ScanPhase::Data);
        const ScanStep s = m.networkChanged(scanNet(ScanNetKind::Wifi, QStringLiteral("wifi:asn:64501"), 2), ScanCachedResult(), kT0 + 2000);
        CHECK(scanPhaseScanning(m.phase()) && s.has(ScanActionKind::RequestManifest));
    }
    // a persisted result keeps its scope; shown() brings it back under that scope (a Germany scan stays Germany)
    {
        World w = baseWorld("cache_scope", hostMac(), ScanNetKind::Wifi);
        w.nodes = ownOnly(w.nodes);
        ScanMachine m(w.caps);
        m.shown(openOf(w, QString(), false), kT0);
        const ScanStep sh = m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 10); // a manifest outside a scan
        CHECK(!sh.has(ScanActionKind::StartHostScan) && m.phase() == ScanPhase::Idle);
        m.poolReady(ScanPoolView{{{QStringLiteral("DE"), 2, 0}, {QStringLiteral("EE"), 1, 0}}, 0, 1}, kT0 + 15);
        m.filterChosen(QStringLiteral("DE"), kT0 + 20);
        const QString scope = m.view(kT0 + 20).bar.scope;
        m.retryTapped(kT0 + 30);
        ScanStep st = m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 60);
        for (const ScanAction &a : st.actions)
            if (a.kind == ScanActionKind::RequestCandidates)
                st.actions << m.candidatesUnavailable(a.requestId, QStringLiteral("unsupported"), 300, kT0 + 70).actions;
        ScanCachedResult saved;
        for (qint64 t : {qint64(60000), qint64(70000)})
            for (const ScanAction &a : m.tick(kT0 + t).actions)
                if (a.kind == ScanActionKind::PersistResults)
                    saved = a.cached;
        CHECK(!scope.isEmpty() && saved.present() && saved.scope == scope);
        ScanMachine again(w.caps);
        ScanOpen o = openOf(w, QString(), false);
        o.cached = saved;
        again.shown(o, kT0 + 80000);
        const ScanView v = again.view(kT0 + 80000);
        CHECK(again.phase() == ScanPhase::Idle && !v.rows.isEmpty() == !saved.rows.isEmpty());
        if (!saved.rows.isEmpty())
            CHECK(v.bar.scope == scope && v.bar.scannedScope == scope && v.checkedAgoMin >= 0);
    }
}

// The Xray burst (device 18.11): own Xray goes to the host as its data part plus 3 burst parts "<id>.<n>"; the row is
// proven only when every part carried data, else it takes the first failed part's class. Driven directly (literal
// part ids): a machine that judged the data part alone shows the row as working although a part got nothing.
static void xrayBurst()
{
    const QString id = QStringLiteral("4:xray");
    const auto facts = [&](const QString &probeId, qint64 seq, int body, bool answered) {
        ScanProbeFacts f;
        f.id = probeId;
        f.stage = ScanStage::Data;
        f.seq = seq;
        f.bytesRequested = body;
        f.durationMs = 600;
        if (!answered) {
            f.error = ScanProbeError::TtfbTimeout; // its ClientHello never completed
            return f;
        }
        f.httpStatus = 200;
        f.bytesReceived = body;
        f.shaOk = true;
        f.ttfb1Ms = 320;
        f.rttMs = 60;
        f.t64Ms = 160;
        f.egressClass = QStringLiteral("tribe-node");
        f.egressNode = scanHostPartOf(id);
        return f;
    };
    for (const int failPart : {0, 2, -1}) { // 0 = every part through, 2 = burst part 2 without data, -1 = the same, it arrives first
        World w = baseWorld("burst", hostMacMinimal(), ScanNetKind::Wifi);
        w.caps.maxFullConcurrent = 4; // the in-app iPhone host's full pool: the 4 parts run at once
        w.nodes = {*specOf(w, id)};
        ScanMachine m(w.caps);
        ScanOpen o;
        o.network = w.net;
        m.opened(o, kT0);
        ScanStep st = m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 80);
        const ScanAction *a = st.find(ScanActionKind::StartHostScan);
        CHECK(a && a->candidates.size() == 1);
        if (!a || a->candidates.size() != 1)
            continue;
        const QString scanId = a->scanId;
        // the projection holds the whole burst: the data part plus 3 parts of warm + 4 KB + TLS
        CHECK(scanProbeTotalCostBytes(a->candidates.at(0), m.tunables())
              == a->candidates.at(0).costBytes + 3 * (qint64(m.tunables().warmBytes) + 4096 + 2 * kScanTlsOverheadBytes));
        ScanHostProgress p;
        p.scanId = scanId;
        p.phase = QStringLiteral("data");
        const int bad = failPart < 0 ? 2 : failPart;
        qint64 seq = 0;
        if (failPart < 0)
            p.items << facts(id + QStringLiteral(".2"), ++seq, 4096, false);
        p.items << facts(id, ++seq, 65536, true);
        for (int n = 1; n <= 3; ++n)
            if (!(failPart < 0 && n == 2))
                p.items << facts(id + QStringLiteral(".%1").arg(n), ++seq, 4096, n != bad || failPart == 0);
        // the data part alone is no verdict yet
        ScanHostProgress first = p;
        first.items = failPart < 0 ? p.items.mid(0, 0) : p.items.mid(0, 1);
        if (failPart >= 0) {
            m.hostProgress(first, kT0 + 900);
            CHECK(rowOf(scanViewToJson(m.view(kT0 + 900)), id).isEmpty());
        }
        p.seq = seq;
        p.bytesSpent = 120000;
        st = m.hostProgress(p, kT0 + 1000);
        QList<ScanStep> steps{st};
        if (!st.has(ScanActionKind::PersistResults))
            steps << m.hostFreezeAck(scanId, 120000, 0, kT0 + 1100);
        const ScanAction *persist = nullptr;
        for (const ScanStep &x : steps)
            if (x.find(ScanActionKind::PersistResults))
                persist = x.find(ScanActionKind::PersistResults);
        CHECK(persist != nullptr);
        const QJsonObject row = rowOf(scanViewToJson(m.view(kT0 + 1200)), id);
        const QString state = row.value(QLatin1String("state")).toString();
        if (failPart == 0) {
            checkMsg(state == QLatin1String("works") || state == QLatin1String("slow"), QStringLiteral("every part through: available (%1)").arg(state));
            CHECK(persist && persist->cached.failures.isEmpty());
        } else {
            checkMsg(state != QLatin1String("works") && state != QLatin1String("slow"),
                     QStringLiteral("a burst part without data: not available (failPart %1, state %2)").arg(failPart).arg(state));
            CHECK(persist && persist->cached.failures.size() == 1 && persist->cached.failures.at(0).id == id
                  && persist->cached.failures.at(0).cls == ScanClass::NoData);
            CHECK(m.lastSummary().value(QLatin1String("counts")).toObject().value(QLatin1String("no_data")).toInt() == 1);
        }
    }
    // the fake host answers per part (a whole scan on the fake clock, every per-step invariant): one part the network
    // drops keeps that row off the list; every other row as before
    for (const bool drop : {false, true}) {
        World w = baseWorld("burst_world", hostMac(), ScanNetKind::Wifi);
        w.current = QStringLiteral("1");
        if (drop)
            w.out[id].burstNoData = 3;
        w.script << qMakePair(qint64(0), at("opened", openArgs(w, w.current, true)));
        w.runMs = 12000;
        Driver d(w);
        d.run();
        Fail f;
        checkAllSteps(d, f, w.name);
        checkMsg(f.list.isEmpty(), QStringLiteral("burst world invariants: %1").arg(f.list.join(QLatin1String("; "))));
        const QJsonObject v = lastView(d);
        const QString state = rowOf(v, id).value(QLatin1String("state")).toString();
        checkMsg(drop ? state != QLatin1String("works") && state != QLatin1String("slow") : state == QLatin1String("works"),
                 QStringLiteral("burst world drop=%1: %2 is %3").arg(drop).arg(id, state));
        CHECK(rowOf(v, QStringLiteral("5:xray")).value(QLatin1String("state")).toString() == QLatin1String("works"));
        int parts = 0;
        for (const Driver::HC &h : d.hq)
            parts += h.probeId.startsWith(id + QLatin1Char('.')) ? 1 : 0;
        CHECK(parts == 3);
    }
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    tunables();
    classify();
    dnsPlanAndManifest();
    plan();
    budget();
    outcomes();
    hostContract();
    shades();
    scenariosAll();
    machineRules();
    extras();
    reviewFixes();
    planV22();
    hostFailures();
    contractV23();
    labSeams();
    s3BudgetGateIsTheStartRule();
    cooldownRule();
    rowsAfter17Nov();
    countrylessRows();
    choiceSlotsAndStopStays();
    stopKeepsWhatItFound();
    availableIsWhatTheListShows();
    secondRowTapTakesOver();
    stoppedResultStaysHonest();
    refusedScopeNeverScansAnother();
    oneVerdictPerRow();
    failedCandidatesAreNoResult();
    progressCountsWhatIsChecked();
    connectedRowIsCounted();
    droppedRequestIsNoVerdict();
    ownTunnelNoticeKeepsTheList();
    ownTunnelGapIsBounded();
    slotCountsOnlyItsScope();
    slotChosenLeavesTheError();
    refusedEndsScope();
    liveProofHasAnEnd();
    listFullPerBatch();
    xrayBurst();
    findMore();
    findMoreAppends();
    findMoreTruncatedSeen();
    scanStartsNewList();
    connectedFirstInEveryList();
    cachedResultKeepsEveryShownRow();
    connectedRestoredRowKeepsItsBatch();
    exhaustedScopeSaysWhatIsMissing();
    serverBatches();
    overruns();
    properties();
    if (g_fail) {
        std::printf("scan_core_check: %d of %d FAILED\n", g_fail, g_total);
        return 1;
    }
    std::printf("scan_core_check: OK (%d checks)\n", g_total);
    return 0;
}
