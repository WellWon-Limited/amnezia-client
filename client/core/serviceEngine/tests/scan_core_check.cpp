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
    CHECK(group3 == 6 && !keys.contains(QStringLiteral("scan_auto_race_total_ms"))); // plan v2 C6 / C7
    // plan v2.2 §2.2b / §6 gap 7: exactly these names and defaults; cost clamps x0.5..x4
    const QMap<QString, int> gap7{{QStringLiteral("scan_cost_api_bytes"), 10240}, {QStringLiteral("scan_cost_manifest_bytes"), 270336},
                                  {QStringLiteral("scan_cost_batch_bytes"), 12288}, {QStringLiteral("scan_cost_config_bytes"), 262144},
                                  {QStringLiteral("scan_cost_tunnel_probe_bytes"), 82944}, {QStringLiteral("scan_cost_light_bytes"), 40960},
                                  {QStringLiteral("scan_cost_outcomes_bytes"), 16384}, {QStringLiteral("scan_cost_netinfo_bytes"), 10240},
                                  {QStringLiteral("scan_drain_ms"), 2000}, {QStringLiteral("scan_freeze_ack_ms"), 1000}};
    int group4 = 0;
    for (const ScanTunableSpec &s : scanTunableTable()) {
        if (s.group != 4)
            continue;
        ++group4;
        CHECK(gap7.value(QLatin1String(s.key), -1) == s.def);
        if (QByteArray(s.key).startsWith("scan_cost_"))
            CHECK(s.lo == s.def / 2 && s.hi == s.def * 4);
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
    qint64 sum = 0;
    for (const ScanCandidate &c : p.probe)
        sum += c.costBytes;
    CHECK(p.projectedBytes == sum && sum > 0);
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
    ShadeQueue q;
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
    // manifest unavailable: NoScan with the card
    {
        ScanMachine m(w.caps);
        m.opened(openOf(w, QStringLiteral("1"), true), kT0);
        ScanStep s = m.manifestUnavailable(QStringLiteral("service_off"), kT0 + 100);
        CHECK(m.phase() == ScanPhase::NoScan && s.has(ScanActionKind::StartLightChecks));
        const ScanView v = m.view(kT0 + 100);
        CHECK(v.card.mode == ScanCardMode::Filling && v.empty.variant == ScanEmptyVariant::None); // the live row is shown
        ScanMachine off(w.caps);
        off.opened(openOf(w, QString(), false), kT0);
        off.manifestUnavailable(QString(), kT0 + 100);
        const ScanView v2 = off.view(kT0 + 100);
        CHECK(v2.empty.variant == ScanEmptyVariant::NoScan && v2.empty.reason == QLatin1String("service_off") && v2.card.mode == ScanCardMode::Off);
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
        p.items << f;
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
    // the light checks are bounded: S4 ends at scan_light_timeout_ms
    {
        ScanMachine m(w.caps);
        m.opened(openOf(w, QStringLiteral("1"), true), kT0);
        m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50);
        // the light checks start with the scan: their bound (7 s) passes before the stop (8 s)
        CHECK(m.tick(kT0 + 50 + 6999).actions.isEmpty() && m.view(kT0 + 50 + 6999).phase == ScanPhase::Reach);
        m.tick(kT0 + 50 + 7000);
        CHECK(m.phase() == ScanPhase::Reach);
        const ScanStep s = m.tick(kT0 + 50 + 8000);
        CHECK(s.has(ScanActionKind::FreezeHostScan) && m.phase() == ScanPhase::Done); // facts final: no S4 wait
        const ScanView v = m.view(kT0 + 50 + 8000);
        CHECK(v.card.services.state == ScanFactState::Unknown && v.card.sites.state == ScanFactState::Unknown && v.card.mode == ScanCardMode::Filled);
        // a connection that came up late: S4 waits for its facts, bounded
        ScanMachine late(w.caps);
        late.opened(openOf(w, QString(), false), kT0);
        late.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50);
        late.vpnState(liveOf(w, QStringLiteral("2:xray"), true), kT0 + 6000);
        late.tick(kT0 + 50 + 8000);
        CHECK(late.phase() == ScanPhase::Self && late.view(kT0 + 8050).stage == ScanStageKey::Self);
        CHECK(!late.tick(kT0 + 6000 + 6999).has(ScanActionKind::PersistResults) && late.phase() == ScanPhase::Self);
        late.tick(kT0 + 6000 + 7000);
        CHECK(late.phase() == ScanPhase::Done);
    }
    // stop when nothing runs does nothing; the report link only in the empty / no-scan states
    {
        ScanMachine m(w.caps);
        CHECK(m.stopTapped(kT0).actions.isEmpty());
        CHECK(m.reportLinkTapped(kT0).actions.isEmpty());
        CHECK(m.checkTapped(kT0).actions.isEmpty());
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
        CHECK(!s.has(ScanActionKind::CancelPendingConnect) && s.has(ScanActionKind::CloseScreen));
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
    // the Wi-Fi intent lives scan_wifi_rescan_window_s, then it is gone (mutation 41)
    {
        World wc = baseWorld("rules", hostMacMinimal(), ScanNetKind::Cellular);
        wc.nodes = ownOnly(wc.nodes);
        for (auto it = wc.out.begin(); it != wc.out.end(); ++it)
            it.value().reachOk = false, it.value().works = false;
        Driver d(wc);
        d.w.script << qMakePair(qint64(0), at("opened", openArgs(wc, QString(), false)));
        d.w.script << qMakePair(qint64(11000), at("got_it"));
        d.w.script << qMakePair(qint64(11000 + 1800000), at("network_changed", {{QStringLiteral("network"),
                                                                                netJson(scanNet(ScanNetKind::Wifi, QStringLiteral("wifi")))},
                                                                               {QStringLiteral("app_in_front"), true}}));
        d.w.runMs = 11000 + 1800000 + 2000;
        d.run();
        CHECK(hasShade(d, "wifi_intent") && d.opens.isEmpty() && countActions(d, ScanActionKind::RequestManifest) == 1);
        // inside the window but on cellular, then Wi-Fi while in the background, then the foreground
        Driver e(wc);
        e.w.script << qMakePair(qint64(0), at("opened", openArgs(wc, QString(), false)));
        e.w.script << qMakePair(qint64(11000), at("got_it"));
        e.w.script << qMakePair(qint64(20000), at("network_changed", {{QStringLiteral("network"), netJson(scanNet(ScanNetKind::Wifi, QStringLiteral("wifi")))},
                                                                     {QStringLiteral("app_in_front"), false}}));
        e.w.script << qMakePair(qint64(25000), at("app_foreground"));
        e.w.runMs = 27000;
        e.run();
        CHECK(e.opens.size() == 1 && e.opens.value(0) == QLatin1String("25000"));
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
        CHECK(m.capBytes() == 240608 && m.hostGrant() == 240608 && m.view(kT0 + 50).unverifiedCount == 2); // the rest «Не проверено»
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
    CHECK(shadeTimingFrom({}).holdMs == 1500);
    CHECK(shadeTimingFrom({{QStringLiteral("scan_shade_ms"), 2500}}).holdMs == 2500);
    CHECK(shadeTimingFrom({{QStringLiteral("scan_shade_ms"), 50}}).holdMs == 500);
    CHECK(shadeTimingFrom({{QStringLiteral("scan_shade_ms"), 1e9}}).holdMs == 10000);
    CHECK(shadeTimingFrom({{QStringLiteral("scan_shade_ms"), std::numeric_limits<double>::infinity()}}).holdMs == 1500);
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
    qint64 seq = 0;
    for (ScanProbeFacts &f : items)
        if (f.seq == 0)
            f.seq = ++seq;
    p.items = items;
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
            m.networkChanged(scanNet(ScanNetKind::Cellular, QStringLiteral("cell:250-02:4g"), 7), ScanCachedResult(), true, kT0 + 300);
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
    // F9: the light checks run again on a second scan of the same connection
    {
        World w = baseWorld("f9", hostMac(), ScanNetKind::Wifi);
        w.current = QStringLiteral("1");
        w.script << qMakePair(qint64(0), at("opened", openArgs(w, w.current, true)));
        w.script << qMakePair(qint64(31000), at("retry"));
        w.runMs = 45000;
        Driver d(w);
        d.run();
        CHECK(countActions(d, ScanActionKind::StartLightChecks) == 2 && countActions(d, ScanActionKind::RequestManifest) == 2);
        CHECK(countActions(d, ScanActionKind::ProbeLiveTunnel) == 2); // and the live check too
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
            CHECK(ns.phase() == ScanPhase::NoScan && nv.rows.size() == (age <= 600000 ? 1 : 0) && nv.verifiedCount == 0);
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
        m.networkChanged(same, ScanCachedResult(), true, kT0 + 8200);
        CHECK(m.phase() == ScanPhase::Done && m.view(kT0 + 8200).verifiedCount == 1);
        ScanNetwork bumped = w.net;
        bumped.sources = {app10, ne2}; // the extension saw a path change
        m.networkChanged(bumped, ScanCachedResult(), true, kT0 + 8300);
        v = m.view(kT0 + 8300);
        CHECK(v.verifiedCount == 0 && v.rows.size() == 1 && v.rows.at(0).fromCache); // only cache now
    }
    // F12: the support queue is full - no new full check, a backpressure notice; space comes back -> it runs
    {
        World w = baseWorld("f12q", hostMac(), ScanNetKind::Wifi);
        w.current = QStringLiteral("1");
        w.script << qMakePair(qint64(0), at("opened", openArgs(w, w.current, true)));
        w.script << qMakePair(qint64(8500), at("report_queue_state", {{QStringLiteral("full"), true}}));
        w.script << qMakePair(qint64(9000), at("check_tapped"));
        w.script << qMakePair(qint64(9500), at("report_queue_state", {{QStringLiteral("full"), false}}));
        w.script << qMakePair(qint64(10000), at("check_tapped"));
        w.runMs = 14000;
        Driver d(w);
        d.run();
        CHECK(shadeCount(d, "report_queue_full") == 1 && countActions(d, ScanActionKind::StartReportCheck) == 1);
        CHECK(viewAt(d, 9200).value(QStringLiteral("card")).toObject().value(QStringLiteral("report_queue_full")).toBool());
        CHECK(!viewAt(d, 9600).value(QStringLiteral("card")).toObject().contains(QStringLiteral("report_queue_full")));
        const ScanAction a = actionsOf(d, ScanActionKind::StartReportCheck).value(0);
        CHECK(a.report.value(QStringLiteral("scan_stats")).isObject()); // seats asked etc. ride with the report, not the summary
    }
    // F12: the report is an immutable object with its own id; a done for another id changes nothing
    {
        World w = baseWorld("f12", hostMac(), ScanNetKind::Wifi);
        w.current = QStringLiteral("1");
        w.script << qMakePair(qint64(0), at("opened", openArgs(w, w.current, true)));
        w.script << qMakePair(qint64(9000), at("check_tapped"));
        w.script << qMakePair(qint64(9100), at("report_check_done", {{QStringLiteral("delivery"), QStringLiteral("sent")}, {QStringLiteral("report_id"), QStringLiteral("report-other")}}));
        w.runMs = 13000;
        Driver d(w);
        d.run();
        const ScanAction a = actionsOf(d, ScanActionKind::StartReportCheck).value(0);
        CHECK(a.reportId.startsWith(QLatin1String("report-")) && a.report.value(QStringLiteral("id")).toString() == a.reportId);
        CHECK(a.report.value(QStringLiteral("network_key")).toString() == QLatin1String("wifi:asn:64500") && a.report.value(QStringLiteral("scan")).isObject());
        CHECK(phaseOf(viewAt(d, 9150)) == QLatin1String("done") && viewAt(d, 9150).value(QStringLiteral("card")).toObject().value(QStringLiteral("mode")).toString() == QLatin1String("checking"));
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
        CHECK(a && a->maxBytes == 1389568 && m.hostGrant() == 1389568 && m.allowanceBytes() == 1572864);
        CHECK(a && a->limits.netinfoCostBytes == 10240);
        const ScanAction *b = s.find(ScanActionKind::RequestProbeBatch);
        CHECK(b && !b->includeConfig && b->costBytes == 12288); // cellular: never include_config
        const ScanAction *lp = s.find(ScanActionKind::ProbeLiveTunnel);
        const ScanAction *lc = s.find(ScanActionKind::StartLightChecks);
        CHECK(lp && lp->costBytes == 82944 && lc && lc->costBytes == 40960);
        // composite providers need their config: on cellular they stay «Не проверено» (config_cellular)
        bool configCellular = false;
        for (const ScanRowView &r : m.view(kT0 + 50).rows)
            configCellular = configCellular || r.notVerifiedReason == QLatin1String("config_cellular");
        CHECK(configCellular);
        // the RU split off: the light checks cost nothing
        ScanMachine nosplit(w.caps);
        nosplit.opened(openOf(w, QStringLiteral("1"), true), kT0);
        QJsonObject args = manifestArgs(w);
        args.insert(QStringLiteral("ru_split_on"), false);
        const ScanStep s2 = nosplit.manifestReady(manifestInputFrom(args), kT0 + 50);
        CHECK(s2.find(ScanActionKind::StartHostScan) && s2.find(ScanActionKind::StartHostScan)->maxBytes == 1389568 + 40960);
        // an app request reports its real bytes: they replace the reservation, also when they are more
        const qint64 used = m.allowanceUsed();
        m.appRequestDone(lp->requestId, 70000, kT0 + 700);
        CHECK(m.allowanceUsed() == used - 82944 + 70000);
        m.appRequestDone(lc->requestId, 40960 + 17000, kT0 + 800); // one chunk past its reservation: recorded
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
        CHECK(b && b->includeConfig && b->ids.size() == 4 && b->costBytes == 12288 + 4 * 262144);
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
        for (const ScanRowView &r : m.view(kT0 + 50).rows)
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
            return !rowOf(scanViewToJson(m.view(kT0 + 900)), up(1)).value(QStringLiteral("flags")).toArray().contains(QStringLiteral("unverified"));
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
        for (const ScanRowView &r2 : m.view(kT0 + 400).rows)
            nv = nv || (r2.id == QLatin1String("4:xray") && !r2.verified && r2.notVerifiedReason == QLatin1String("bind_failed"));
        CHECK(nv); // «Не проверено», reason bind_failed
        CHECK(scanHostFailureReason(ScanHostError::BindFailed) == QLatin1String("host_bind_failed"));
    }
    // 5a. reportCheckRefused: a notice, no «sent» / «will be sent», the card as before, the queue state kept
    {
        World w = baseWorld("refused", hostMac(), ScanNetKind::Wifi);
        w.current = QStringLiteral("1");
        w.reportRefuse = QStringLiteral("queue_full");
        w.script << qMakePair(qint64(0), at("opened", openArgs(w, w.current, true)));
        w.script << qMakePair(qint64(9000), at("check_tapped"));
        w.runMs = 12000;
        Driver d(w);
        d.run();
        CHECK(countActions(d, ScanActionKind::StartReportCheck) == 1 && shadeCount(d, "report_queue_full") == 1
              && !hasShade(d, "report_sent") && !hasShade(d, "report_queued"));
        const QJsonObject card = lastView(d).value(QStringLiteral("card")).toObject();
        CHECK(card.value(QStringLiteral("mode")).toString() == QLatin1String("filled") && card.value(QStringLiteral("button")).toString() == QLatin1String("ready")
              && !card.contains(QStringLiteral("report_queue_full")));
        CHECK(viewAt(d, 9100).value(QStringLiteral("card")).toObject().value(QStringLiteral("mode")).toString() == QLatin1String("checking"));
        // another diagnostic runs: its own notice; a refusal for another report changes nothing
        ScanMachine m(w.caps);
        m.opened(openOf(w, QStringLiteral("1"), true), kT0);
        m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50);
        m.reportQueueState(false, kT0 + 60);
        const ScanStep st = m.reportLinkTapped(kT0 + 70); // not in the empty state: nothing
        CHECK(st.actions.isEmpty());
        m.tick(kT0 + 50 + 8000);
        m.lightFact(ScanLightFact{ScanFactKind::Services, ScanFactState::Done, {2, 2, 2, 2}}, kT0 + 8100);
        m.lightFact(ScanLightFact{ScanFactKind::Sites, ScanFactState::Done, {}, true}, kT0 + 8100);
        const ScanStep ck = m.checkTapped(kT0 + 8200);
        const ScanAction *rc = ck.find(ScanActionKind::StartReportCheck);
        CHECK(rc && m.reportCheckRefused(QStringLiteral("report-other"), QStringLiteral("busy"), kT0 + 8300).actions.isEmpty());
        const ScanStep busy = m.reportCheckRefused(rc->reportId, QStringLiteral("busy"), kT0 + 8400);
        CHECK(busy.find(ScanActionKind::ShowShade) && busy.find(ScanActionKind::ShowShade)->shade.textKey == QLatin1String("report_check_busy"));
        CHECK(m.view(kT0 + 8400).card.mode == ScanCardMode::Filled && !m.view(kT0 + 8400).card.reportQueueFull);
        CHECK(m.view(kT0 + 8400).card.sites.state == ScanFactState::Done && m.view(kT0 + 8400).card.sites.ok); // restored
        CHECK(m.checkTapped(kT0 + 8500).has(ScanActionKind::StartReportCheck)); // a new try is possible
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
        CHECK(g.has(ScanActionKind::CloseScreen) && m.wifiIntentUntil() == kT0 + 100 + 1800000 && !m.screenOpen());
        bool intent = false;
        for (const ScanAction &a : g.actions)
            intent = intent || a.shade.textKey == QLatin1String("wifi_intent");
        CHECK(intent);
        // another no-scan reason: «Понял» does nothing there
        ScanMachine o(w.caps);
        o.opened(openOf(w, QString(), false), kT0);
        o.manifestUnavailable(QStringLiteral("service_off"), kT0 + 50);
        CHECK(o.gotItTapped(kT0 + 100).actions.isEmpty() && o.wifiIntentUntil() == 0);
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
        bool shown = false;
        for (const ScanRowView &r : m.view(kT0 + 60).rows)
            shown = shown || (r.id == QLatin1String("2") && r.state == ScanRowState::NotVerified && r.notVerifiedReason == QLatin1String("awg_no_address"));
        CHECK(shown && m.phase() == ScanPhase::Reach);
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

        // S7: Done with rows and no live connection (the card says «VPN не подключён», no button): the report
        // link is offered and sends the summary through the same report flow as the card's button
        CHECK(v.card.mode == ScanCardMode::Off && v.card.button == ScanCardButton::Hidden && v.empty.reportLink
              && scanViewToJson(v).value(QStringLiteral("empty")).toObject().value(QStringLiteral("report_link")).toBool());
        ScanMachine &m = d.m;
        const qint64 t = d.now + 100;
        CHECK(m.checkTapped(t).actions.isEmpty()); // no card button without a connection
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
        // a live connection appears (a row's connect): the card's button is the way and the link goes
        ScanCurrent live = liveOf(w, QStringLiteral("2:xray"), true);
        m.vpnState(live, t + 2000);
        CHECK(!m.view(t + 2000).empty.reportLink && m.reportLinkTapped(t + 2000).actions.isEmpty());
        // while a scan runs: no link
        m.vpnState(ScanCurrent(), t + 2100);
        m.retryTapped(t + 60000);
        CHECK(scanPhaseScanning(m.phase()) && !m.view(t + 60000).empty.reportLink && m.reportLinkTapped(t + 60000).actions.isEmpty());
    }
    // S7: Done WITH a live connection (desktop, VPN on): the card's button, never the link
    {
        World x = w;
        x.out[QStringLiteral("5:xray")].durMs = 500;
        x.current = QStringLiteral("2:xray");
        x.script.clear();
        x.script << qMakePair(qint64(0), at("opened", openArgs(x, x.current, true)));
        Driver d(x);
        d.run();
        const ScanView v = d.m.view(d.now);
        CHECK(d.m.phase() == ScanPhase::Done && v.card.button == ScanCardButton::Ready && !v.empty.reportLink
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
        const ScanAction *lc = s.find(ScanActionKind::StartLightChecks);
        CHECK(lp && lp->costBytes == 82944 && lc);
        const qint64 grant = m.hostGrant();
        Driver dd(w);
        ScanProbeFacts f = dd.liveFacts(QStringLiteral("1"));
        f.spentBytes = 82944 + late;
        m.liveProbeResult(QStringLiteral("1"), f, kT0 + 700);
        CHECK(m.allowanceOvershoot() == late && m.hostGrant() == grant); // recorded; the host keeps its grant
        m.appRequestDone(lc->requestId, 20000, kT0 + 900);
        CHECK(m.allowanceOvershoot() == late - (40960 - 20000) || m.allowanceOvershoot() == 0);
        // a further app request (a release in the middle of the scan) is admitted only against what is left
        m.stopTapped(kT0 + 1000);
        m.hostFreezeAck(m.scanId(), 50000, 0, kT0 + 1030);
        ScanHostProgress fin = progressOf(m, {}, 50000, 0, true);
        fin.finalTotals = true;
        m.hostProgress(fin, kT0 + 1100);
        // ledger = manifest 20480 + live 82944 + late + light 20000 + the live row's outcome batch sent at the
        // end and never reported (its worst case 16384) + host 50000
        CHECK(!m.draining() && m.ledger().spentInHour(kT0 + 1100, true) == 20480 + 82944 + late + 20000 + 16384 + 50000);
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
        const qint64 cap = 5242880, left = 560000;
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
        wr.cutApp = QStringLiteral("light");
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

// Order key of a shown verified row: (speed rank, ms or +inf, then a stable rest) - checked as a non-decreasing
// sequence; a pair of rows whose keys did not change keeps its relative order between two views.
static QString rowKey(const QJsonObject &r)
{
    const int rank = scanSpeedRank(scanSpeedFrom(r.value(QStringLiteral("speed")).toString()));
    return QStringLiteral("%1").arg(rank) + QLatin1Char('|') + r.value(QStringLiteral("speed")).toString();
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
        // relative order stability between consecutive views
        for (int i = 1; i < d.steps.size(); ++i) {
            const QJsonArray a = d.steps.at(i - 1).view.value(QStringLiteral("rows")).toArray();
            const QJsonArray b = d.steps.at(i).view.value(QStringLiteral("rows")).toArray();
            QMap<QString, QPair<int, QString>> pa, pb;
            for (int x = 0; x < a.size(); ++x)
                pa.insert(a.at(x).toObject().value(QStringLiteral("id")).toString(),
                          qMakePair(x, rowKey(a.at(x).toObject()) + QString::number(a.at(x).toObject().value(QStringLiteral("ms")).toInt())
                                           + a.at(x).toObject().value(QStringLiteral("state")).toString()));
            for (int x = 0; x < b.size(); ++x)
                pb.insert(b.at(x).toObject().value(QStringLiteral("id")).toString(),
                          qMakePair(x, rowKey(b.at(x).toObject()) + QString::number(b.at(x).toObject().value(QStringLiteral("ms")).toInt())
                                           + b.at(x).toObject().value(QStringLiteral("state")).toString()));
            const QStringList common = [&] {
                QStringList c;
                for (auto it = pa.constBegin(); it != pa.constEnd(); ++it)
                    if (pb.contains(it.key()) && pb.value(it.key()).second == it.value().second)
                        c << it.key();
                return c;
            }();
            for (int x = 0; x < common.size(); ++x)
                for (int y = x + 1; y < common.size(); ++y) {
                    const bool before = pa.value(common.at(x)).first < pa.value(common.at(y)).first;
                    const bool after = pb.value(common.at(x)).first < pb.value(common.at(y)).first;
                    f.check(before == after, w.name + QStringLiteral(": two unchanged rows swapped"));
                }
        }
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
                       m.allowanceUsed(), m.draining()};
            Fail f;
            checkStepInvariants(r, prevPhase, m, QString(), f, QStringLiteral("fuzz"));
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
        QHash<QString, int> f = scanListFigures(c, c.networkKey, c.fingerprint, kT0 + 5000, ttl);
        CHECK(f.size() == 2 && f.value(a.id) == 44 && f.value(b.id) == 310 && !f.contains(nf.id));
        CHECK(scanListFigures(c, c.networkKey, c.fingerprint, kT0 + qint64(ttl) * 1000, ttl).size() == 2);
        CHECK(scanListFigures(c, c.networkKey, c.fingerprint, kT0 + qint64(ttl) * 1000 + 1, ttl).isEmpty()); // too old
        CHECK(scanListFigures(c, c.networkKey, c.fingerprint, kT0 - 60000, ttl).size() == 2);               // clock behind
        CHECK(scanListFigures(c, c.networkKey, c.fingerprint, kT0 - 60001, ttl).isEmpty());
        CHECK(scanListFigures(c, QStringLiteral("cell:250-02:4g"), c.fingerprint, kT0, ttl).isEmpty());   // other network
        CHECK(scanListFigures(c, c.networkKey, QStringLiteral("fp-b"), kT0, ttl).isEmpty());              // other fingerprint
        CHECK(scanListFigures(c, c.networkKey, QString(), kT0, ttl).isEmpty());
        CHECK(scanListFigures(ScanCachedResult(), c.networkKey, c.fingerprint, kT0, ttl).isEmpty());
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

    // the rescan rule after a network change
    {
        const QString none;
        CHECK(scanRescanOnNetworkChange(true, ScanPhase::Done, none, false, false));
        CHECK(scanRescanOnNetworkChange(true, ScanPhase::Empty, none, false, false));
        CHECK(scanRescanOnNetworkChange(true, ScanPhase::NoScan, QStringLiteral("cooldown"), false, false));
        CHECK(scanRescanOnNetworkChange(true, ScanPhase::NoScan, QStringLiteral("budget"), false, false));
        CHECK(scanRescanOnNetworkChange(true, ScanPhase::NoScan, QStringLiteral("network_changed"), false, false));
        CHECK(!scanRescanOnNetworkChange(false, ScanPhase::Done, none, false, false));                       // screen closed
        CHECK(!scanRescanOnNetworkChange(true, ScanPhase::Done, none, true, false));                         // would start the VPN
        CHECK(scanRescanOnNetworkChange(true, ScanPhase::Done, none, true, true));
        for (const char *r : {"service_off", "scanner_off", "vpn_off", "host_memory", "manifest_unavailable"})
            CHECK(!scanRescanOnNetworkChange(true, ScanPhase::NoScan, QLatin1String(r), false, false));
        for (ScanPhase ph : {ScanPhase::Idle, ScanPhase::Preparing, ScanPhase::Connecting, ScanPhase::Reach, ScanPhase::Data,
                             ScanPhase::Self})
            CHECK(!scanRescanOnNetworkChange(true, ph, none, false, true));
    }

    // the machine: a finished result + another network = a new scan by itself (artboard), never a VPN start
    {
        World w = baseWorld("netchange", hostMac(), ScanNetKind::Wifi);
        ScanMachine m(w.caps);
        m.opened(openOf(w, QStringLiteral("1"), true), kT0);
        m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50);
        m.tick(kT0 + 60000);
        m.tick(kT0 + 70000);
        CHECK(m.phase() == ScanPhase::Done || m.phase() == ScanPhase::Empty);
        const ScanStep s = m.networkChanged(scanNet(ScanNetKind::Wifi, QStringLiteral("wifi:asn:64501"), 2), ScanCachedResult(),
                                            true, kT0 + 80000);
        CHECK(scanPhaseScanning(m.phase()) && s.has(ScanActionKind::RequestManifest));
        CHECK(!s.has(ScanActionKind::UserConnectForScan));
        CHECK(m.cooldownUntil() <= kT0 + 80000 || m.view(kT0 + 80000).empty.reason.isEmpty());
        // the same with the screen closed: nothing starts
        ScanMachine c(w.caps);
        c.opened(openOf(w, QStringLiteral("1"), true), kT0);
        c.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 50);
        c.tick(kT0 + 60000);
        c.tick(kT0 + 70000);
        c.closed(kT0 + 71000);
        const ScanStep cs = c.networkChanged(scanNet(ScanNetKind::Wifi, QStringLiteral("wifi:asn:64501"), 2), ScanCachedResult(),
                                             true, kT0 + 80000);
        CHECK(!scanPhaseScanning(c.phase()) && !cs.has(ScanActionKind::RequestManifest));
    }
    // the cellular hour used up: the new network shows frame 22 (NoScan budget), no manifest
    {
        World w = baseWorld("netchange_budget", hostMac(), ScanNetKind::Cellular);
        ScanMachine m(w.caps);
        QJsonArray ledger;
        ledger << QJsonObject{{QStringLiteral("at_ms"), double(kT0 - 20 * 60000)}, {QStringLiteral("bytes"), 4.95 * 1024 * 1024},
                              {QStringLiteral("cellular"), true}};
        m.restoreBudget(ledger);
        m.opened(openOf(w, QString(), false), kT0);
        CHECK(m.phase() == ScanPhase::NoScan && m.view(kT0).empty.reason == QLatin1String("budget"));
        const ScanStep s = m.networkChanged(scanNet(ScanNetKind::Cellular, QStringLiteral("cell:250-01:4g"), 2), ScanCachedResult(),
                                            true, kT0 + 1000);
        CHECK(m.phase() == ScanPhase::NoScan && m.view(kT0 + 1000).empty.reason == QLatin1String("budget"));
        CHECK(!s.has(ScanActionKind::RequestManifest) && !s.has(ScanActionKind::UserConnectForScan));
        // ... and on Wi-Fi the hour does not apply: it scans
        const ScanStep sw = m.networkChanged(scanNet(ScanNetKind::Wifi, QStringLiteral("wifi:asn:64500"), 3), ScanCachedResult(),
                                             true, kT0 + 2000);
        CHECK(scanPhaseScanning(m.phase()) && sw.has(ScanActionKind::RequestManifest));
    }
    // iPhone: the tunnel is gone after the scan - the change keeps the old result and «Повторить», no VPN start;
    // with the tunnel up the change rescans through it
    {
        World wi = baseWorld("netchange_ios", hostIosFull(), ScanNetKind::Wifi);
        ScanMachine m(wi.caps);
        m.opened(openOf(wi, QStringLiteral("1"), true), kT0);
        m.manifestReady(manifestInputFrom(manifestArgs(wi)), kT0 + 50);
        m.vpnState(ScanCurrent(), kT0 + 500); // the tunnel went away: the scan ends
        CHECK(m.phase() == ScanPhase::Done || m.phase() == ScanPhase::Empty);
        const ScanStep s = m.networkChanged(scanNet(ScanNetKind::Wifi, QStringLiteral("wifi:asn:64501"), 2), ScanCachedResult(),
                                            true, kT0 + 2000);
        CHECK(m.phase() == ScanPhase::NoScan && m.view(kT0 + 2000).empty.reason == QLatin1String("network_changed"));
        for (const ScanAction &a : s.actions)
            CHECK(!scanActionTouchesTunnel(a.kind));
        ScanMachine u(wi.caps);
        u.opened(openOf(wi, QStringLiteral("1"), true), kT0);
        u.manifestReady(manifestInputFrom(manifestArgs(wi)), kT0 + 50);
        u.tick(kT0 + 60000);
        u.tick(kT0 + 70000);
        CHECK(u.phase() == ScanPhase::Done || u.phase() == ScanPhase::Empty);
        const ScanStep us = u.networkChanged(scanNet(ScanNetKind::Wifi, QStringLiteral("wifi:asn:64501"), 2), ScanCachedResult(),
                                             true, kT0 + 80000);
        CHECK(scanPhaseScanning(u.phase()) && us.has(ScanActionKind::RequestManifest));
        for (const ScanAction &a : us.actions)
            CHECK(!scanActionTouchesTunnel(a.kind));
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
    cooldownRule();
    rowsAfter17Nov();
    overruns();
    properties();
    if (g_fail) {
        std::printf("scan_core_check: %d of %d FAILED\n", g_fail, g_total);
        return 1;
    }
    std::printf("scan_core_check: OK (%d checks)\n", g_total);
    return 0;
}
