// AVPN path engine, stage 1 core (design 2026-11-17): PathId, NetworkKey, PathLedger, PathSelect, AttemptOwner,
// and the network scenarios of design §9 played by the simulator (path_world.h) in virtual time.
// Build/run: build_path_engine.sh. QtCore only, no event loop.
#include "../path/AttemptOwner.h"
#include "../path/NetworkKey.h"
#include "../path/PathId.h"
#include "../path/PathLedger.h"
#include "../path/PathSelect.h"
#include "path_world.h"

#include <cstdio>

using namespace avpn;
using namespace avpn::path;
using namespace avpn::path::sim;

static int g_fail = 0, g_total = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        ++g_total;                                                                                 \
        if (!(cond)) {                                                                             \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                           \
            ++g_fail;                                                                              \
        }                                                                                          \
    } while (0)

// --- helpers ---------------------------------------------------------------------------------------------

static PathCandidate own(const char *id, PathKind kind, const char *cc, bool manual = false, double weight = 1.0)
{
    PathCandidate c;
    c.id = PathId{ QString::fromLatin1(id), QStringLiteral("r1") };
    c.kind = kind;
    c.country = QString::fromLatin1(cc);
    c.manualOnly = manual;
    c.rank = kind == PathKind::OwnAwg ? kTransportRankAwg : kTransportRankXray;
    c.weight = weight;
    return c;
}
static PathCandidate awg(const char *id, const char *cc, bool manual = false, double w = 1.0)
{
    return own(id, PathKind::OwnAwg, cc, manual, w);
}
static PathCandidate xray(const char *id, const char *cc, bool manual = false, double w = 1.0)
{
    return own(id, PathKind::OwnXray, cc, manual, w);
}
static PathCandidate prov(const char *id, UpstreamKind kind, const char *cc, int priority, int tier = 1)
{
    PathCandidate c = own(id, PathKind::Provider, kind == UpstreamKind::Country ? cc : "");
    c.providerKind = kind;
    c.rank = 30;
    c.tier = tier;
    c.priority = priority;
    return c;
}

static NetworkObservation wifi(const char *gw)
{
    NetworkObservation o;
    o.medium = NetMedium::Wifi;
    o.gateway = QString::fromLatin1(gw);
    o.subnet = QStringLiteral("192.168.1.0/24");
    return o;
}
static NetworkObservation cell(const char *carrier, const char *radio)
{
    NetworkObservation o;
    o.medium = NetMedium::Cellular;
    o.carrier = QString::fromLatin1(carrier);
    o.radio = QString::fromLatin1(radio);
    return o;
}
static QString key(const NetworkObservation &o) { return localNetworkKey(o); }

static QStringList legPaths(const Sim &s, int from = 0)
{
    QStringList out;
    for (int i = from; i < s.legs.size(); ++i)
        out << s.legs[i].path;
    return out;
}

static PathState stateOf(const Sim &s, const PathCandidate &c)
{
    return s.ledger.view(s.tracker.current().local, c.id, s.wall()).state;
}

static void stopLive(Sim &s)
{
    s.deliver(AttemptEvent::userStop(s.now));
    s.run([&] { return s.owner.phase() == AttemptPhase::Idle; }, 5000);
}

// Scenario results for the summary table.
struct Row {
    QString scenario;
    QString outcome;
    qint64 ms;
    int paths;
    QString order;
};
static QList<Row> g_rows;
static void row(const char *name, const Sim &s, const AttemptResult &r, int legFrom)
{
    QString outcome = r.connected ? QStringLiteral("connected ") + r.path.id.id
                                  : QStringLiteral("failed ") + QLatin1String(failReasonName(r.reason));
    if (r.fallbackNotice)
        outcome += QStringLiteral(" (fallback notice)");
    // the time from the tap (the race in front of the owner included), not only the owner's own awake time
    const qint64 ms = std::max<qint64>(r.elapsedMs, s.lastTapWallMs() < 600000 ? s.lastTapWallMs() : r.elapsedMs);
    g_rows.append({ QString::fromLatin1(name), outcome, ms, r.paths, legPaths(s, legFrom).join(QLatin1Char(' ')) });
}

// --- PathId ----------------------------------------------------------------------------------------------

static void testPathId()
{
    SubscriptionNode a;
    a.nodeId = QStringLiteral("11");
    a.endpoint = QStringLiteral("1.2.3.4:585");
    a.serverPubkey = QStringLiteral("pk");
    a.awg.Jc = 4;
    a.manualOnly = true;
    a.countryCode = QStringLiteral("fi");
    const PathCandidate ca = pathCandidateFromNode(a);
    CHECK(ca.kind == PathKind::OwnAwg && ca.id.id == QLatin1String("11") && ca.id.revision.size() == 16);
    CHECK(ca.manualOnly && ca.country == QLatin1String("FI") && ca.tier == 0);

    SubscriptionNode b = a;
    b.dns = QStringList{ QStringLiteral("8.8.8.8") };
    b.mtu = 1280;
    CHECK(derivePathId(b) == derivePathId(a)); // DNS / MTU do not decide reachability
    b.endpoint = QStringLiteral("1.2.3.4:586");
    CHECK(derivePathId(b).id == ca.id.id && derivePathId(b).revision != ca.id.revision);
    SubscriptionNode h = a;
    h.awg.H1 = 77;
    CHECK(derivePathId(h).revision != ca.id.revision); // the obfuscation bundle is what DPI sees

    SubscriptionNode x;
    x.nodeId = QStringLiteral("11:xray");
    x.proto = QStringLiteral("xray");
    x.endpoint = QStringLiteral("5.6.7.8:443");
    x.xray = XrayParams{};
    x.xray->uuid = QStringLiteral("u1");
    const PathId px = derivePathId(x);
    CHECK(pathKindOf(x) == PathKind::OwnXray);
    x.xray->uuid = QStringLiteral("u2");
    CHECK(derivePathId(x) == px); // the per-device credential is not part of the path
    x.xray->fingerprint = QStringLiteral("firefox");
    CHECK(derivePathId(x).revision != px.revision);

    SubscriptionNode u;
    u.nodeId = QStringLiteral("up:2eec");
    u.proto = QStringLiteral("xray");
    u.countryCode = QStringLiteral("NL");
    u.upstream = UpstreamStub{};
    u.upstream->configSha256 = QStringLiteral("AAA");
    u.upstream->kind = UpstreamKind::Whitelist;
    u.upstream->tier = 2;
    u.upstream->priority = 5;
    const PathCandidate cu = pathCandidateFromNode(u);
    CHECK(cu.kind == PathKind::Provider && cu.providerKind == UpstreamKind::Whitelist && cu.country.isEmpty());
    CHECK(cu.tier == 2 && cu.priority == 5);
    u.upstream->configSha256 = QStringLiteral("aaa");
    CHECK(derivePathId(u) == cu.id); // the hash is compared case-insensitively
    u.upstream->configSha256 = QStringLiteral("bbb");
    CHECK(derivePathId(u).revision != cu.id.revision);
}

// --- NetworkKey ------------------------------------------------------------------------------------------

static void testNetworkKey()
{
    const NetworkObservation home = wifi("192.168.1.1"), office = wifi("10.0.0.1");
    CHECK(key(home).startsWith(QLatin1String("wifi:")) && key(home) != key(office));
    CHECK(!key(home).contains(QLatin1String("192.168"))); // the raw gateway never reaches the key
    NetworkObservation bare;
    bare.medium = NetMedium::Wifi;
    CHECK(key(bare) == QLatin1String("wifi:-"));
    CHECK(key(cell("250-01", "LTE")) == QLatin1String("cell:250-01:lte"));
    {
        // iOS cannot read the carrier and the ASN is unknown at the tap: the coarse key is empty, the network is still
        // cellular (device round 19.11: the race's cellular cap never applied, races spent 0.28 MB on LTE)
        NetworkTracker t;
        t.observe(cell("", "lte"));
        CHECK(t.current().local == QLatin1String("cell:-:lte") && t.current().coarse.isEmpty() && t.current().cellular());
        NetworkTracker w;
        w.observe(wifi("192.168.1.1"));
        CHECK(!w.current().cellular());
    }
    NetworkObservation off;
    off.medium = NetMedium::Offline;
    CHECK(key(off).isEmpty());

    NetworkObservation withAsn = home;
    withAsn.asn = 12389;
    CHECK(coarseNetworkKey(withAsn) == QLatin1String("wifi:asn:12389"));
    CHECK(coarseNetworkKey(home).isEmpty());
    CHECK(coarseNetworkKey(cell("250-01", "lte")) == QLatin1String("cellular:250-01"));

    NetworkTracker first;
    CHECK(first.observe(NetworkObservation{}) && first.current().local == QLatin1String("unknown")
          && first.current().usable() && first.current().generation == 1); // nothing known: still connectable
    CHECK(first.observe(wifi("192.168.1.1")) && first.current().generation == 2);
    NetworkTracker t;
    CHECK(t.observe(home) && t.current().generation == 1);
    CHECK(!t.observe(home) && t.current().generation == 1);
    CHECK(!t.observe(withAsn) && t.current().coarse == QLatin1String("wifi:asn:12389")); // learning the ASN
    NetworkObservation unknown;
    CHECK(!t.observe(unknown) && t.current().local == key(home)); // iOS "Unknown" while a VPN is up
    CHECK(t.observe(off) && t.current().generation == 2 && !t.current().usable());
    CHECK(t.observe(home) && t.current().generation == 3 && t.isCurrent(3) && !t.isCurrent(1));
}

// --- PathLedger ------------------------------------------------------------------------------------------

static void testLedger()
{
    LedgerTunables lt;
    PathLedger l(lt);
    const QString net = QStringLiteral("wifi:abc");
    const PathId p{ QStringLiteral("17"), QStringLiteral("r1") };
    const qint64 t0 = 1'800'000'000'000LL;
    CHECK(l.view(net, p, t0).state == PathState::Unknown);
    CHECK(!l.record(net, p, PathOutcome::Inconclusive, t0) && l.size() == 0); // "the check did not happen"
    CHECK(!l.record(QString(), p, PathOutcome::NoData, t0));

    CHECK(l.record(net, p, PathOutcome::NoHandshake, t0));
    CHECK(l.view(net, p, t0).state == PathState::Suspect);
    l.record(net, p, PathOutcome::NoHandshake, t0 + 1000);
    PathView v = l.view(net, p, t0 + 1000);
    CHECK(v.state == PathState::Dead && v.inQuarantine && v.quarantineUntilMs == t0 + 1000 + lt.quarantineMs[0]);
    v = l.view(net, p, t0 + 1000 + lt.quarantineMs[0]);
    CHECK(v.state == PathState::Dead && !v.inQuarantine); // quarantine over: offered again after the others
    l.record(net, p, PathOutcome::NoData, t0 + 200000);
    CHECK(l.view(net, p, t0 + 200000).quarantineUntilMs == t0 + 200000 + lt.quarantineMs[1]);
    l.record(net, p, PathOutcome::NoData, t0 + 300000);
    l.record(net, p, PathOutcome::NoData, t0 + 400000);
    l.record(net, p, PathOutcome::NoData, t0 + 500000);
    CHECK(l.view(net, p, t0 + 500000).quarantineUntilMs == t0 + 500000 + lt.quarantineMs[3]); // ladder tops at 6 h

    // stage 2: a probe ok does not clear a tunnel "no data" (the Xray-15 case) - only a data ok does
    CHECK(l.record(net, p, PathOutcome::ProbeOk, t0 + 600000));
    v = l.view(net, p, t0 + 600000);
    CHECK(v.state == PathState::Dead && v.failStreak > 0);
    // after a handshake failure a probe ok does lift the path (the mini-probe completed a handshake and data)
    const PathId hs{ QStringLiteral("hs"), QStringLiteral("r") };
    l.record(net, hs, PathOutcome::NoHandshake, t0 + 600000);
    CHECK(l.record(net, hs, PathOutcome::ProbeOk, t0 + 600001));
    v = l.view(net, hs, t0 + 600001);
    CHECK(v.state == PathState::Working && v.strength == EvidenceStrength::Probe && v.failStreak == 0);
    CHECK(l.view(net, hs, t0 + 600001 + lt.probeOkTtlMs + 1).state == PathState::Unknown); // a probe proof is short
    l.record(net, p, PathOutcome::DataOk, t0 + 700000, 2000, 300);
    v = l.view(net, p, t0 + 700000);
    CHECK(v.strength == EvidenceStrength::Data && v.connectMs == 2000 && v.ttfbMs == 300);

    // no seat: out of the first places for the cooldown, the ladder untouched
    const PathId up{ QStringLiteral("up:x"), QStringLiteral("r1") };
    l.record(net, up, PathOutcome::NoSeat, t0);
    v = l.view(net, up, t0 + 1);
    CHECK(v.state == PathState::Dead && v.inQuarantine && v.refused && v.failStreak == 0);
    CHECK(l.view(net, up, t0 + lt.refusalCooldownMs).state == PathState::Unknown);

    // revision change: old evidence no longer applies, and a new outcome resets the entry
    const PathId p2{ QStringLiteral("17"), QStringLiteral("r2") };
    CHECK(l.view(net, p2, t0 + 700000).state == PathState::Unknown);
    l.record(net, p2, PathOutcome::NoData, t0 + 800000);
    CHECK(l.entry(net, QStringLiteral("17"))->revision == QLatin1String("r2"));
    CHECK(l.entry(net, QStringLiteral("17"))->dataOkMs == 0 && l.view(net, p2, t0 + 800000).failStreak == 1);
    CHECK(l.view(net, p, t0 + 800000).state == PathState::Unknown);

    // another network knows nothing of this one
    CHECK(l.view(QStringLiteral("cell:250-01:lte"), p2, t0 + 800000).state == PathState::Unknown);

    // persistence round trip
    const QByteArray json = l.toJson();
    const PathLedger back = PathLedger::fromJson(json, lt);
    CHECK(back.size() == l.size() && back.toJson() == json);
    CHECK(back.view(net, p2, t0 + 800000).failStreak == 1);
    CHECK(PathLedger::fromJson("{\"v\":2,\"e\":[]}", lt).size() == 0); // another version reads as empty
    CHECK(PathLedger::fromJson("garbage", lt).size() == 0);

    // pruning: expired entries, then the oldest beyond the bound
    LedgerTunables small = lt;
    small.maxEntries = 3;
    PathLedger b(small);
    for (int i = 0; i < 5; ++i)
        b.record(net, PathId{ QStringLiteral("n%1").arg(i), QStringLiteral("r") }, PathOutcome::DataOk, t0 + i, 1, 1);
    CHECK(b.size() == 3 && !b.entry(net, QStringLiteral("n0")) && !b.entry(net, QStringLiteral("n1"))
          && b.entry(net, QStringLiteral("n4")));
    b.prune(t0 + 2 + small.evidenceTtlMs + 1);
    CHECK(b.size() == 2 && !b.entry(net, QStringLiteral("n2")));
    CHECK(b.view(net, PathId{ QStringLiteral("n3"), QStringLiteral("r") }, t0 + 3 + small.evidenceTtlMs + 1).state
          == PathState::Unknown); // untouched too long: ignored even before pruning
    LedgerTunables tiny = lt;
    tiny.maxEntries = 1;
    CHECK(PathLedger::fromJson(json, tiny).size() == 1); // the bound holds on load too
}

// Failure evidence expires by its own age (device round R, 26.11: own «Финляндия 1 Xray» «не удалось» on LTE and
// Wi-Fi for days - its only no-data was the err=2 false verdict of 25.11, and every scan's probe pass kept the entry
// touched; review of 1ff3cf163: the expiry must hold for every reader and for the next failure, with no probe needed).
static QStringList ids(const QList<RankedPath> &r);

static void testFailureSettle()
{
    const LedgerTunables lt;
    CHECK(lt.failureTtlMs == lt.quarantineMs.back() && lt.failureTtlMs == 6LL * 3600 * 1000); // the ladder's top
    const QString net = QStringLiteral("cell:-:lte");
    const qint64 t0 = 1'800'000'000'000LL;
    const qint64 minute = 60LL * 1000, hour = 60 * minute, ttl = lt.failureTtlMs;

    {   // a single no-data, a probe pass every minute: held until t0 + TTL, then gone for every reader
        PathLedger l(lt);
        const PathId p{ QStringLiteral("11:xray"), QStringLiteral("r") };
        CHECK(l.record(net, p, PathOutcome::NoData, t0));
        bool heldAll = true;
        for (qint64 t = t0 + minute; t < t0 + ttl; t += minute) {
            l.record(net, p, PathOutcome::ProbeOk, t, 900);
            const PathView v = l.view(net, p, t);
            heldAll = heldAll && v.state == PathState::Suspect && v.failStreak == 1 && l.tunnelNoDataHere(net, p, t);
        }
        CHECK(heldAll);                                                     // the probes neither clear nor extend it
        CHECK(l.tunnelNoDataHere(net, p, t0 + ttl - 1) && l.view(net, p, t0 + ttl - 1).state == PathState::Suspect);
        PathView v = l.view(net, p, t0 + ttl);                              // no new probe needed
        CHECK(!l.tunnelNoDataHere(net, p, t0 + ttl));
        CHECK(v.state == PathState::Working && v.strength == EvidenceStrength::Probe && v.failStreak == 0); // recent probe
        // a real no-data after that marks it again, as the first of a new streak; a probe right after does not lift it
        const qint64 t1 = t0 + ttl + minute;
        CHECK(l.record(net, p, PathOutcome::NoData, t1));
        CHECK(l.tunnelNoDataHere(net, p, t1) && l.view(net, p, t1).failStreak == 1);
        CHECK(l.record(net, p, PathOutcome::ProbeOk, t1 + minute, 900));
        CHECK(l.tunnelNoDataHere(net, p, t1 + minute) && l.view(net, p, t1 + minute).state == PathState::Suspect);
        CHECK(!l.tunnelNoDataHere(QStringLiteral("wifi:abc"), p, t1));     // another network knows nothing of it
        CHECK(!l.tunnelNoDataHere(net, PathId{ p.id, QStringLiteral("r2") }, t1)); // another revision neither
    }
    {   // no probe at all: unknown at t0 + TTL, and the data proof that predates the failure does not come back
        PathLedger l(lt);
        const PathId p{ QStringLiteral("12:xray"), QStringLiteral("r") };
        l.record(net, p, PathOutcome::DataOk, t0 - hour, 1800, 900);
        l.record(net, p, PathOutcome::NoData, t0);
        CHECK(l.view(net, p, t0 + ttl - 1).state == PathState::Suspect && l.tunnelNoDataHere(net, p, t0 + ttl - 1));
        const PathView v = l.view(net, p, t0 + ttl);
        CHECK(v.state == PathState::Unknown && v.strength == EvidenceStrength::None && v.failStreak == 0
              && v.speedMs == -1 && v.lastSuccessMs == 0);
        CHECK(!l.tunnelNoDataHere(net, p, t0 + ttl) && l.entry(net, p.id) != nullptr); // never pruned, not reported
        // two ways out of a lost handshake, kept apart in the code (do not unify): a fresh probe pass contradicts it
        // and restores the earlier state, data proof included; forgetting it by age keeps the proof the same way
        // (review of 863c9d8e8: forgetting by age is never harsher than the probe lift) - while age forgets a
        // no-data together with the proof it superseded (above)
        const PathId h{ QStringLiteral("h"), QStringLiteral("r") };
        l.record(net, h, PathOutcome::DataOk, t0 - hour, 1800, 900);
        l.record(net, h, PathOutcome::NoHandshake, t0);
        l.record(net, h, PathOutcome::ProbeOk, t0 + minute, 900);
        const PathView vh = l.view(net, h, t0 + minute);
        CHECK(vh.state == PathState::Working && vh.strength == EvidenceStrength::Data && vh.failStreak == 0);
        const PathId a{ QStringLiteral("a"), QStringLiteral("r") };
        l.record(net, a, PathOutcome::DataOk, t0 - hour, 1800, 900);
        l.record(net, a, PathOutcome::NoHandshake, t0);
        CHECK(l.view(net, a, t0 + ttl - 1).state == PathState::Suspect);
        const PathView va = l.view(net, a, t0 + ttl);
        CHECK(va.state == PathState::Working && va.strength == EvidenceStrength::Data && va.speedMs == 2700
              && va.failStreak == 0);
    }
    {   // review of 863c9d8e8: only a tunnel that carried no data supersedes a data proof
        const PathCandidate fast = xray("21:xray", "FI"), slow = awg("22", "DE");
        const auto rig = [&](PathOutcome failure) {
            PathLedger l(lt);
            l.record(net, fast.id, PathOutcome::DataOk, t0 - hour, 600, 300);   // the fastest, proven first
            l.record(net, fast.id, failure, t0);                                // then one failure, no probe after
            l.record(net, slow.id, PathOutcome::DataOk, t0 + hour, 2500, 500);  // a slower one carries the VPN
            return l;
        };
        SelectInput in;
        in.pool = { slow, fast };
        // one lost start deadline, 6 h without a probe: proven by data again with its speed, first in Auto
        PathLedger hs = rig(PathOutcome::NoHandshake);
        const PathView vf = hs.view(net, fast.id, t0 + ttl);
        CHECK(vf.state == PathState::Working && vf.strength == EvidenceStrength::Data && vf.speedMs == 900);
        in.evidence = hs.viewOf(net, in.pool, t0 + ttl);
        CHECK(ids(selectPaths(in)) == QStringList({ "21:xray", "22" }));
        // the same with a tunnel that carried no data: unknown, behind the proven one
        PathLedger nd = rig(PathOutcome::NoData);
        CHECK(nd.view(net, fast.id, t0 + ttl).state == PathState::Unknown);
        in.evidence = nd.viewOf(net, in.pool, t0 + ttl);
        CHECK(ids(selectPaths(in)) == QStringList({ "22", "21:xray" }));
        // two lost handshakes, quarantine over, 6 h since the last: clean with the proof kept
        PathLedger two(lt);
        two.record(net, fast.id, PathOutcome::DataOk, t0 - hour, 600, 300);
        two.record(net, fast.id, PathOutcome::NoHandshake, t0);
        two.record(net, fast.id, PathOutcome::NoHandshake, t0 + minute);
        CHECK(two.view(net, fast.id, t0 + minute + ttl - 1).state == PathState::Dead
              && !two.view(net, fast.id, t0 + minute + ttl - 1).inQuarantine);
        const PathView v2 = two.view(net, fast.id, t0 + minute + ttl);
        CHECK(v2.state == PathState::Working && v2.strength == EvidenceStrength::Data && v2.speedMs == 900);
        // mixed: a no-data, later a lost handshake - the no-data superseded the proof: voided
        PathLedger mixed(lt);
        mixed.record(net, fast.id, PathOutcome::DataOk, t0 - hour, 600, 300);
        mixed.record(net, fast.id, PathOutcome::NoData, t0);
        mixed.record(net, fast.id, PathOutcome::NoHandshake, t0 + hour);
        CHECK(mixed.view(net, fast.id, t0 + hour + ttl).state == PathState::Unknown
              && mixed.view(net, fast.id, t0 + hour + ttl).strength == EvidenceStrength::None);
        // a no-data older than the proof (an earlier streak, ended by that data ok) supersedes nothing
        PathLedger older(lt);
        older.record(net, fast.id, PathOutcome::NoData, t0 - 2 * hour);
        older.record(net, fast.id, PathOutcome::DataOk, t0 - hour, 600, 300);
        older.record(net, fast.id, PathOutcome::NoHandshake, t0);
        CHECK(older.view(net, fast.id, t0 + ttl).state == PathState::Working
              && older.view(net, fast.id, t0 + ttl).strength == EvidenceStrength::Data);
    }
    {   // P1: an expired no-data must not come back with fresh failures; the streak counts the fresh failures only
        for (const bool liftInBetween : { false, true }) {
            PathLedger l(lt);
            const PathId p{ QStringLiteral("13:xray"), QStringLiteral("r") };
            l.record(net, p, PathOutcome::NoData, t0);
            if (liftInBetween) {
                CHECK(l.record(net, p, PathOutcome::ProbeOk, t0 + ttl + minute, 900));
                CHECK(l.view(net, p, t0 + ttl + minute).state == PathState::Working);
            }
            const qint64 f1 = t0 + ttl + hour, f2 = f1 + minute;
            l.record(net, p, PathOutcome::NoHandshake, f1);
            CHECK(l.view(net, p, f1).failStreak == 1 && l.view(net, p, f1).state == PathState::Suspect);
            CHECK(!l.tunnelNoDataHere(net, p, f1) && l.entry(net, p.id)->noDataMs == 0);
            l.record(net, p, PathOutcome::NoHandshake, f2);
            const PathView v = l.view(net, p, f2);
            CHECK(v.failStreak == 2 && v.state == PathState::Dead && v.quarantineUntilMs == f2 + lt.quarantineMs[0]);
            CHECK(!l.tunnelNoDataHere(net, p, f2));
            CHECK(l.record(net, p, PathOutcome::ProbeOk, f2 + minute, 900)); // a probe lifts no-handshake failures
            CHECK(l.view(net, p, f2 + minute).state == PathState::Working && l.view(net, p, f2 + minute).failStreak == 0);
        }
    }
    {   // a two-failure row: quarantined until its time, the tail after it, clean at TTL since the last failure, with
        // probes passing every minute in between; the ladder and its times are unchanged while the evidence is live
        PathLedger l(lt);
        const PathId p{ QStringLiteral("14:xray"), QStringLiteral("r") };
        l.record(net, p, PathOutcome::NoData, t0);
        l.record(net, p, PathOutcome::NoData, t0 + 1000);
        const qint64 last = t0 + 1000, until = last + lt.quarantineMs[0];
        bool live = true;
        for (qint64 t = t0 + minute; t < last + ttl; t += minute) {
            l.record(net, p, PathOutcome::ProbeOk, t, 900);
            const PathView v = l.view(net, p, t);
            live = live && v.state == PathState::Dead && v.failStreak == 2 && v.quarantineUntilMs == until
                && v.inQuarantine == (t < until) && l.tunnelNoDataHere(net, p, t);
        }
        CHECK(live);
        const PathView v = l.view(net, p, last + ttl);
        CHECK(v.state == PathState::Working && v.strength == EvidenceStrength::Probe && v.failStreak == 0
              && !v.inQuarantine && !l.tunnelNoDataHere(net, p, last + ttl));
        // at the ladder's top step the path is clean exactly when its quarantine ends
        const PathId q{ QStringLiteral("15:xray"), QStringLiteral("r") };
        for (int i = 0; i < 5; ++i)
            l.record(net, q, PathOutcome::NoData, t0 + i * minute);
        const qint64 qlast = t0 + 4 * minute;
        CHECK(l.view(net, q, qlast).quarantineUntilMs == qlast + lt.quarantineMs.back());
        CHECK(l.view(net, q, qlast + ttl - 1).state == PathState::Dead && l.view(net, q, qlast + ttl - 1).inQuarantine);
        CHECK(l.view(net, q, qlast + ttl).state == PathState::Unknown && !l.tunnelNoDataHere(net, q, qlast + ttl));
        // a running quarantine is never cut by the age (a TTL below the ladder's top, to separate the two conditions)
        LedgerTunables shortTtl = lt;
        shortTtl.failureTtlMs = hour;
        PathLedger s(shortTtl);
        for (int i = 0; i < 5; ++i)
            s.record(net, q, PathOutcome::NoData, t0 + i * minute);
        CHECK(s.view(net, q, qlast + 2 * hour).state == PathState::Dead && s.view(net, q, qlast + 2 * hour).inQuarantine
              && s.tunnelNoDataHere(net, q, qlast + 2 * hour));
        CHECK(s.view(net, q, qlast + lt.quarantineMs.back()).state == PathState::Unknown);
        // a data ok through the tunnel still clears everything at once
        const PathId d{ QStringLiteral("16:xray"), QStringLiteral("r") };
        l.record(net, d, PathOutcome::NoData, t0);
        l.record(net, d, PathOutcome::NoData, t0 + 1000);
        l.record(net, d, PathOutcome::DataOk, t0 + 2000, 2000, 300);
        CHECK(l.view(net, d, t0 + 2000).state == PathState::Working && !l.tunnelNoDataHere(net, d, t0 + 2000));
        // an entry untouched for evidenceTtlMs is not reported at all
        const PathId u{ QStringLiteral("17:xray"), QStringLiteral("r") };
        for (int i = 0; i < 5; ++i)
            l.record(net, u, PathOutcome::NoData, t0 + i * minute);
        CHECK(!l.tunnelNoDataHere(net, u, t0 + 4 * minute + lt.evidenceTtlMs + 1) && l.entry(net, u.id) != nullptr);
    }
    {   // save / reload: with "lf" the last failure governs; without it the no-data time does - never the touch
        PathLedger l(lt);
        const PathId p{ QStringLiteral("18:xray"), QStringLiteral("r") };
        l.record(net, p, PathOutcome::NoData, t0);
        l.record(net, p, PathOutcome::ProbeOk, t0 + ttl - minute, 900); // touched a minute before the TTL
        const QByteArray json = l.toJson();
        CHECK(json.contains("\"lf\":"));
        const PathLedger back = PathLedger::fromJson(json, lt);
        CHECK(back.tunnelNoDataHere(net, p, t0 + ttl - 1) && !back.tunnelNoDataHere(net, p, t0 + ttl));
        QJsonDocument doc = QJsonDocument::fromJson(json);
        QJsonObject root = doc.object();
        QJsonArray arr = root.value(QStringLiteral("e")).toArray();
        QJsonObject e0 = arr.at(0).toObject();
        e0.remove(QStringLiteral("lf"));
        arr.replace(0, e0);
        root.insert(QStringLiteral("e"), arr);
        const PathLedger old = PathLedger::fromJson(QJsonDocument(root).toJson(QJsonDocument::Compact), lt);
        CHECK(old.entry(net, p.id) && old.entry(net, p.id)->lastFailureMs == 0);
        CHECK(old.tunnelNoDataHere(net, p, t0 + ttl - 1) && !old.tunnelNoDataHere(net, p, t0 + ttl));
        CHECK(old.view(net, p, t0 + ttl).failStreak == 0);
        // no failure time at all (a no-handshake entry without "lf"): left to the entry's evidenceTtlMs
        const PathId h{ QStringLiteral("19"), QStringLiteral("r") };
        PathLedger n(lt);
        n.record(net, h, PathOutcome::NoHandshake, t0);
        QJsonObject r2 = QJsonDocument::fromJson(n.toJson()).object();
        QJsonArray a2 = r2.value(QStringLiteral("e")).toArray();
        QJsonObject h0 = a2.at(0).toObject();
        h0.remove(QStringLiteral("lf"));
        a2.replace(0, h0);
        r2.insert(QStringLiteral("e"), a2);
        const PathLedger noTime = PathLedger::fromJson(QJsonDocument(r2).toJson(QJsonDocument::Compact), lt);
        CHECK(noTime.view(net, h, t0 + ttl).state == PathState::Suspect);
    }
    {   // several marks expire together on a network where other rows carried data after those failures: the proven
        // rows lead, the expired rows come after as unknown; an expired row with a recent probe pass is working by
        // probe, still behind every data-proven row
        PathLedger l(lt);
        const PathCandidate fi = xray("11:xray", "FI"), de = awg("12", "DE"), ee = awg("17", "EE"),
                            wl = prov("up:wl", UpstreamKind::Whitelist, "", 1), pl = xray("20:xray", "PL");
        l.record(net, fi.id, PathOutcome::DataOk, t0 - hour, 600, 300);   // fast, before its failure
        l.record(net, fi.id, PathOutcome::NoData, t0);
        l.record(net, de.id, PathOutcome::DataOk, t0 - hour, 500, 200);
        l.record(net, de.id, PathOutcome::NoData, t0);
        l.record(net, pl.id, PathOutcome::NoData, t0);
        l.record(net, ee.id, PathOutcome::DataOk, t0 + hour, 2500, 500);  // slower, proven after those failures
        l.record(net, wl.id, PathOutcome::DataOk, t0 + 2 * hour, 3000, 900);
        SelectInput in;
        in.pool = { fi, de, ee, wl, pl };
        in.evidence = l.viewOf(net, in.pool, t0 + ttl - 1);
        QList<RankedPath> order = selectPaths(in);
        CHECK(ids(order).mid(0, 2) == QStringList({ "17", "up:wl" }) && order.at(2).group == SelectGroup::Suspect);
        in.evidence = l.viewOf(net, in.pool, t0 + ttl);
        order = selectPaths(in);
        CHECK(ids(order).mid(0, 2) == QStringList({ "17", "up:wl" }));
        bool unknownTail = order.size() == 5;
        for (int i = 2; i < order.size(); ++i)
            unknownTail = unknownTail && order.at(i).group == SelectGroup::Unknown;
        CHECK(unknownTail);
        CHECK(detail::laneEvidence(in.pool, in.evidence).value(QStringLiteral("xray"), 1) == 1); // not "only failed"
        // a recent probe pass on one expired row: working by probe, behind both data-proven rows
        l.record(net, fi.id, PathOutcome::ProbeOk, t0 + ttl, 400);
        in.evidence = l.viewOf(net, in.pool, t0 + ttl + 1);
        order = selectPaths(in);
        CHECK(ids(order).mid(0, 3) == QStringList({ "17", "up:wl", "11:xray" })
              && order.at(2).group == SelectGroup::Working && order.at(2).view.strength == EvidenceStrength::Probe);
        // restricted-network prior: expired rows hold no proof (their old data does not cancel it)
        PathLedger r(lt);
        PathCandidate standby = prov("up:sb", UpstreamKind::Whitelist, "", 1);
        standby.standbyEntry = true;
        r.record(net, fi.id, PathOutcome::DataOk, t0 - hour, 600, 300);
        r.record(net, fi.id, PathOutcome::NoData, t0);
        const QList<PathCandidate> pool{ fi, standby };
        CHECK(restrictedNetworkPrior(pool, r.viewOf(net, pool, t0 + ttl), ApiReach::Unreachable, true)
                  .value(QStringLiteral("up:sb")) == kPriorFirstCrowd);
    }
}

// --- PathSelect ------------------------------------------------------------------------------------------

static QStringList ids(const QList<RankedPath> &r)
{
    QStringList out;
    for (const RankedPath &p : r)
        out << p.path.id.id;
    return out;
}

static PathView viewState(PathState s, bool quarantine = false, qint64 success = 0)
{
    PathView v;
    v.state = s;
    v.inQuarantine = quarantine;
    v.failStreak = s == PathState::Suspect ? 1 : s == PathState::Dead ? 2 : 0;
    if (s == PathState::Working) {
        v.strength = EvidenceStrength::Data;
        v.lastSuccessMs = success;
    }
    return v;
}

// F2 of device round 19.11 (iPhone Air, LTE, Auto): repeats kept landing on Estonia 3 AmneziaWG (connect + first
// byte 2.7-4.6 s, median 5.0 s to data) because it connected last, while Finland 1 Xray had carried data on the same
// network in 2.7-3.0 s (3.5-3.7 s to data). The measured, decayed time to data orders working paths; the preference
// and the mode still come first.
static void testSpeedOrder()
{
    const QString net = QStringLiteral("cell:-:lte");
    const qint64 T = 1'800'000'000'000LL;
    const PathCandidate ee = awg("17", "EE"), fi = xray("11:xray", "FI");
    PathLedger l;
    l.record(net, fi.id, PathOutcome::DataOk, T, 1858, 946);       // 06:34
    l.record(net, fi.id, PathOutcome::DataOk, T + 60000, 2032, 813);
    l.record(net, ee.id, PathOutcome::DataOk, T + 120000, 3029, 588);
    l.record(net, ee.id, PathOutcome::DataOk, T + 180000, 4083, 549); // the newest proof
    const PathView vfi = l.view(net, fi.id, T + 200000), vee = l.view(net, ee.id, T + 200000);
    CHECK(vfi.speedMs > 2700 && vfi.speedMs < 2900 && vee.speedMs > 4000 && vee.speedMs < 4400);
    SelectInput in;
    in.pool = { ee, fi };
    in.evidence = l.viewOf(net, in.pool, T + 200000);
    CHECK(ids(selectPaths(in)) == QStringList({ "11:xray", "17" })); // before: 17 (newest proof first)
    // a preferred country still wins over a faster path elsewhere
    in.choice = UserChoice::preferCountry(QStringLiteral("EE"));
    CHECK(selectPaths(in).first().path.id.id == QLatin1String("17"));
    in.choice = UserChoice::automatic();
    // the mode is stronger than speed
    in.mode = TransportMode::Awg;
    CHECK(ids(selectPaths(in)) == QStringList({ "17" }));
    in.mode = TransportMode::Auto;
    // within one speed step the newest proof leads (no flapping between equally fast paths)
    PathLedger near;
    near.record(net, fi.id, PathOutcome::DataOk, T, 2000, 800);
    near.record(net, ee.id, PathOutcome::DataOk, T + 1000, 2100, 750);
    in.evidence = near.viewOf(net, in.pool, T + 2000);
    CHECK(selectPaths(in).first().path.id.id == QLatin1String("17"));
    // decayed: a new slow sample moves the average halfway at once, an old value weighs less with age
    PathLedger d;
    d.record(net, ee.id, PathOutcome::DataOk, T, 2000, 0);
    d.record(net, ee.id, PathOutcome::DataOk, T + 1000, 4000, 0);
    CHECK(d.view(net, ee.id, T + 2000).speedMs == 3000);
    PathLedger old;
    old.record(net, ee.id, PathOutcome::DataOk, T, 2000, 0);
    old.record(net, ee.id, PathOutcome::DataOk, T + 12LL * 3600 * 1000, 4000, 0); // two half-lives later
    CHECK(old.view(net, ee.id, T + 12LL * 3600 * 1000).speedMs == 3600);
    // an adopted tunnel (no start measured, connect 0) adds no sample
    d.record(net, ee.id, PathOutcome::DataOk, T + 3000, 0, 300);
    CHECK(d.view(net, ee.id, T + 4000).speedMs == 3000);
    // probe proofs: the faster time to proof first (the race's winner before a later, slower proof)
    PathLedger p;
    p.record(net, fi.id, PathOutcome::ProbeOk, T, 990);
    p.record(net, ee.id, PathOutcome::ProbeOk, T + 1400, 1390);
    in.evidence = p.viewOf(net, in.pool, T + 2000);
    CHECK(ids(selectPaths(in)) == QStringList({ "11:xray", "17" }));
    // persisted
    const PathLedger back = PathLedger::fromJson(l.toJson());
    CHECK(back.view(net, fi.id, T + 200000).speedMs == vfi.speedMs && back.view(net, ee.id, T + 200000).speedMs == vee.speedMs);
}

static void testSelect()
{
    SelectInput in;
    in.pool = { awg("17", "EE"), awg("16", "NL"), awg("12", "DE"), awg("11", "FI", true), xray("11:xray", "FI"),
                xray("12:xray", "DE"), prov("up:a", UpstreamKind::Country, "NL", 0), prov("up:w", UpstreamKind::Whitelist, "", 1) };
    // nothing known: interleaved by kind, manual_only last
    CHECK(ids(selectPaths(in)) == QStringList({ "12", "11:xray", "up:a", "up:w", "16", "12:xray", "17", "11" }));

    // a working manual_only path comes first (device evidence on this network outranks the server's prior)
    in.evidence.insert(QStringLiteral("11"), viewState(PathState::Working, false, 5));
    CHECK(selectPaths(in).first().path.id.id == QLatin1String("11"));
    CHECK(selectPaths(in).first().group == SelectGroup::Working);
    in.evidence.clear();

    // a failed regular path counts as exhausted: an unproven manual_only path goes before it
    in.evidence.insert(QStringLiteral("12"), viewState(PathState::Suspect));
    in.evidence.insert(QStringLiteral("16"), viewState(PathState::Dead, true));
    in.evidence.insert(QStringLiteral("17"), viewState(PathState::Dead, false));
    in.mode = TransportMode::Awg;
    CHECK(ids(selectPaths(in)) == QStringList({ "11", "12", "17", "16" }));

    // a dead path in quarantine is never offered before an untried non-dead one; tried ones never again
    in.tried = { QStringLiteral("11") };
    CHECK(ids(selectPaths(in)) == QStringList({ "12", "17", "16" }));
    in.tried.clear();

    // the mode is stronger than any choice
    in.mode = TransportMode::Xray;
    for (const RankedPath &r : selectPaths(in))
        CHECK(r.path.kind != PathKind::OwnAwg);
    in.choice = UserChoice::exactPath(QStringLiteral("17"));
    CHECK(selectPaths(in).isEmpty()); // an exact AmneziaWG node in Xray mode: nothing (honest failure)
    in.mode = TransportMode::Auto;
    CHECK(ids(selectPaths(in)) == QStringList({ "17" })); // exact: only it, even dead
    in.tried = { QStringLiteral("17") };
    CHECK(selectPaths(in).isEmpty()); // and only once
    in.tried.clear();

    // preferred country: its paths first inside each evidence group (manual_only not demoted); a preferred path
    // that failed here goes behind every working or untried path of any country (review E9 of 18.11)
    in.evidence.clear();
    in.evidence.insert(QStringLiteral("12"), viewState(PathState::Suspect));
    in.evidence.insert(QStringLiteral("16"), viewState(PathState::Working, false, 9));
    in.choice = UserChoice::preferCountry(QStringLiteral("de"));
    QList<RankedPath> r = selectPaths(in);
    CHECK(ids(r).first() == QLatin1String("12:xray") && r[0].preferred); // preferred, untried
    CHECK(r[1].path.id.id == QLatin1String("16") && !r[1].preferred);   // working elsewhere before untried elsewhere
    {
        const int failed = int(ids(r).indexOf(QStringLiteral("12")));
        CHECK(failed > 1 && r[failed].preferred && r[failed].group == SelectGroup::Suspect);
        for (int i = 0; i < failed; ++i)
            CHECK(r[i].group != SelectGroup::Suspect && r[i].group != SelectGroup::QuarantineOver);
    }
    in.choice = UserChoice::preferCountry(QStringLiteral("FI"));
    CHECK(ids(selectPaths(in)).mid(0, 2) == QStringList({ "11", "11:xray" })); // manual_only 11 inside FI

    // crowd prior orders the unknown paths before the server prior
    in.choice = UserChoice::automatic();
    in.evidence.clear();
    in.crowd.insert(QStringLiteral("up:w"), 0.95);
    CHECK(selectPaths(in).first().path.id.id == QLatin1String("up:w"));
    in.crowd.clear();

    // a kind that only failed on this network yields its place inside a round
    in.evidence.insert(QStringLiteral("12"), viewState(PathState::Suspect));
    CHECK(ids(selectPaths(in)).mid(0, 4) == QStringList({ "11:xray", "up:a", "up:w", "16" }));
    // the rounds hold across the legs of one attempt: a kind that had its turn waits for the others
    in.evidence.clear();
    in.tried = { QStringLiteral("12") };
    CHECK(ids(selectPaths(in)).mid(0, 5) == QStringList({ "11:xray", "up:a", "up:w", "16", "12:xray" }));
}

// --- AttemptOwner unit: stale events, user stop, budget --------------------------------------------------

// Device round 19.11: a chosen server implies its country; kinds take turns inside an attempt; the race spreads over
// kinds.
static void testChoiceCountryAndLanes()
{
    const auto prov = [](const char *id, const char *cc) {
        PathCandidate c;
        c.id.id = QString::fromLatin1(id);
        c.kind = PathKind::Provider;
        c.providerKind = UpstreamKind::Country;
        c.country = QString::fromLatin1(cc);
        c.tier = 1;
        return c;
    };
    const auto own = [](const char *id, const char *cc, PathKind k) {
        PathCandidate c;
        c.id.id = QString::fromLatin1(id);
        c.kind = k;
        c.country = QString::fromLatin1(cc);
        return c;
    };
    const auto ids = [](const QList<RankedPath> &l) {
        QStringList o;
        for (const RankedPath &r : l)
            o << r.path.id.id;
        return o;
    };
    const auto workingView = [](qint64 at, int speedMs = 3000) {
        PathView v;
        v.state = PathState::Working;
        v.strength = EvidenceStrength::Data;
        v.lastSuccessMs = at;
        v.speedMs = speedMs;
        return v;
    };
    // 1. the person chose Czechia 2; it was tried; Poland 1 and Czechia 5 both carried data here: Czechia first
    {
        SelectInput in;
        in.pool = { prov("up:cz2", "CZ"), prov("up:cz5", "CZ"), prov("up:cz7", "CZ"), prov("up:pl1", "PL"),
                    own("17", "EE", PathKind::OwnAwg) };
        in.choice = UserChoice::preferServer(QStringLiteral("CZ"), { QStringLiteral("up:cz2") });
        in.evidence.insert(QStringLiteral("up:pl1"), workingView(2000, 1000));
        in.evidence.insert(QStringLiteral("up:cz5"), workingView(1000, 4000));
        in.evidence.insert(QStringLiteral("17"), workingView(3000, 1000));
        CHECK(ids(selectPaths(in)).first() == QLatin1String("up:cz2")); // the choice itself
        in.tried.insert(QStringLiteral("up:cz2"));
        const QStringList o = ids(selectPaths(in));
        CHECK(o.first() == QLatin1String("up:cz5")); // the country's working path before faster ones elsewhere
        CHECK(o.indexOf(QStringLiteral("up:cz7")) > o.indexOf(QStringLiteral("17"))); // untried Czechia: after what works
        CHECK(o.indexOf(QStringLiteral("up:cz7")) < o.size()); // and still offered
        // a country preference (no server) is unchanged: every path of the country is "preferred"
        in.choice = UserChoice::preferCountry(QStringLiteral("CZ"));
        in.tried.clear();
        const QList<RankedPath> r = selectPaths(in);
        CHECK(r.first().preferred && !r.first().sameCountry);
    }
    // 2. kinds take turns: three AmneziaWG servers and a provider all "work" here by older proof
    {
        SelectInput in;
        in.pool = { own("15", "EE", PathKind::OwnAwg), own("17", "EE", PathKind::OwnAwg), own("10", "US", PathKind::OwnAwg),
                    prov("up:pl1", "PL"), prov("up:de3", "DE") };
        in.evidence.insert(QStringLiteral("15"), workingView(5000, 1000));
        in.evidence.insert(QStringLiteral("17"), workingView(4000, 1000));
        in.evidence.insert(QStringLiteral("10"), workingView(3000, 1000));
        in.evidence.insert(QStringLiteral("up:pl1"), workingView(1000, 4000));
        CHECK(ids(selectPaths(in)).first() == QLatin1String("15")); // nothing tried: speed and freshness decide
        in.tried.insert(QStringLiteral("15")); // AmneziaWG had its turn and failed now
        CHECK(ids(selectPaths(in)).first() == QLatin1String("up:pl1")); // the other kind, although slower and older
        in.tried.insert(QStringLiteral("up:pl1"));
        CHECK(ids(selectPaths(in)).first() == QLatin1String("17")); // one each: AmneziaWG again
        in.tried.insert(QStringLiteral("17")); // the second AmneziaWG server failed in this attempt
        const QStringList o = ids(selectPaths(in));
        CHECK(o.first() == QLatin1String("up:de3")); // the kind is failing NOW: an untried provider path first
        CHECK(o.last() == QLatin1String("10"));      // its last "working" server waits behind
    }
    // 3. the race takes one of each kind before the second of any
    {
        const QList<PathCandidate> order = { own("11:xray", "FI", PathKind::OwnXray), own("12:xray", "DE", PathKind::OwnXray),
                                             own("15:xray", "EE", PathKind::OwnXray), prov("up:pl1", "PL"),
                                             own("17", "EE", PathKind::OwnAwg), prov("up:de3", "DE") };
        QStringList o;
        for (const PathCandidate &c : raceSpread(order))
            o << c.id.id;
        CHECK(o == QStringList({ "11:xray", "up:pl1", "17", "12:xray", "up:de3", "15:xray" }));
        // with the cellular cap: our Xray (116,736) + a provider (107,520) + AmneziaWG (54,572) fit one race
        CHECK(116736 + 117760 + 54572 <= RaceTimings().cellularMaxBytes);
    }
}

static void testOwnerStale()
{
    const NetworkObservation home = wifi("192.168.1.1");
    World w;
    w.set(key(home), QStringLiteral("16"), Behaviour::works(300, 400, 100));
    Sim s({ awg("17", "EE", false, 2.0), awg("16", "NL") }, w, home);
    const AttemptResult r = s.tap(UserChoice::automatic());
    CHECK(r.connected && r.path.id.id == QLatin1String("16") && r.paths == 2);
    const PathStamp dead = s.legs[0].stamp, live = s.legs[1].stamp;
    const QByteArray before = s.ledger.toJson();
    const AttemptPhase phase = s.owner.phase();
    const quint64 attempt = s.owner.attempt();
    for (const AttemptEvent &e : { AttemptEvent::tunnelUp(s.now, dead), AttemptEvent::dataChecked(s.now, dead, PathOutcome::DataOk, 5),
                                   AttemptEvent::pathFailed(s.now, dead, PathOutcome::NoData),
                                   AttemptEvent::stopConfirmed(s.now, dead),
                                   AttemptEvent::dataChecked(s.now, live, PathOutcome::NoData), // after Finish
                                   AttemptEvent::pathFailed(s.now, live, PathOutcome::NoHandshake),
                                   AttemptEvent::networkChanged(s.now, NetworkKey{ QStringLiteral("x"), {}, 0 }) }) {
        CHECK(s.owner.handle(e, s.ctx()).isEmpty());
    }
    CHECK(s.ledger.toJson() == before && s.owner.phase() == phase && s.owner.attempt() == attempt);

    // the user's stop in the middle of a start: stop confirmed, then one terminal result
    World w2;
    Sim s2({ awg("17", "EE") }, w2, home);
    s2.deliver(AttemptEvent::userStart(0, UserChoice::automatic(), TransportMode::Auto, s2.tracker.current()));
    s2.idle(1000);
    s2.deliver(AttemptEvent::userStop(s2.now));
    s2.run([&] { return !s2.results.isEmpty(); }, 5000);
    CHECK(s2.results.size() == 1 && s2.results[0].reason == FailReason::StoppedByUser);
    CHECK(s2.ledger.size() == 0 && s2.reports.isEmpty()); // a cancel is not an outcome of the path
    s2.idle(10000);
    CHECK(s2.results.size() == 1);

    // a new tap during an attempt ends the old attempt once and stops its leg before the new one starts
    Sim s3({ awg("17", "EE"), awg("16", "NL") }, w2, home);
    s3.deliver(AttemptEvent::userStart(0, UserChoice::automatic(), TransportMode::Auto, s3.tracker.current()));
    s3.idle(1000);
    const AttemptResult r3 = s3.tap(UserChoice::exactPath(QStringLiteral("16")), TransportMode::Auto, 30000);
    CHECK(s3.results.size() == 2 && s3.results[0].reason == FailReason::StoppedByUser && s3.results[0].attempt == 1);
    CHECK(r3.reason == FailReason::ExactNodeFailed && r3.attempt == 2 && s3.legs.size() == 2);
    CHECK(s3.legs[1].startedMs >= 1000 + s3.stopMs); // the new leg only after the old one is confirmed stopped

    // the platform cannot start anything (inconclusive start errors): nothing recorded, bounded by maxPaths
    World w4;
    QList<PathCandidate> many;
    for (int i = 0; i < 12; ++i) {
        const QByteArray id = QByteArray::number(100 + i);
        many << awg(id.constData(), "EE");
        w4.set(key(home), QString::fromLatin1(id), Behaviour::startError(false));
    }
    Sim s4(many, w4, home);
    const AttemptResult r4 = s4.tap(UserChoice::automatic());
    CHECK(!r4.connected && r4.reason == FailReason::NothingProven && r4.paths == s4.owner.timings().maxPaths);
    CHECK(s4.ledger.size() == 0);
}


// --- AttemptOwner: live session lost, adopted session, stop never confirmed, exact server ----------------

static void testOwnerLive()
{
    const NetworkObservation home = wifi("192.168.3.1");
    const QString k = key(home);
    World w;
    const Behaviour ok = Behaviour::works(300, 400, 100);
    w.set(k, QStringLiteral("17"), ok);
    w.set(k, QStringLiteral("16"), ok);
    const QList<PathCandidate> pool = { awg("17", "EE", false, 2.0), awg("16", "NL") };
    Sim s(pool, w, home);
    AttemptResult r = s.tap(UserChoice::automatic());
    CHECK(r.connected && r.path.id.id == QLatin1String("17"));

    // not blamed (a first health DEAD): the failover attempt raises the same proven path again (re-up)
    int from = int(s.legs.size());
    s.deliver(AttemptEvent::liveLost(s.now, PathOutcome::Inconclusive, false, true, UserChoice::automatic(),
                                     TransportMode::Auto, s.tracker.current()));
    s.run([&] { return s.results.size() > 1; }, 30000);
    CHECK(s.results.size() == 2 && s.results.last().connected && legPaths(s, from) == QStringList({ "17" }));

    // blamed (data proven dead): recorded, and the failover attempt does not take it again
    from = int(s.legs.size());
    s.deliver(AttemptEvent::liveLost(s.now, PathOutcome::NoData, false, true, UserChoice::automatic(),
                                     TransportMode::Auto, s.tracker.current()));
    s.run([&] { return s.results.size() > 2; }, 30000);
    CHECK(s.results.last().connected && s.results.last().path.id.id == QLatin1String("16"));
    CHECK(legPaths(s, from) == QStringList({ "16" }) && stateOf(s, pool[0]) == PathState::Suspect);

    // the tunnel went away by itself without a failover: the owner holds nothing live any more
    s.deliver(AttemptEvent::liveLost(s.now, PathOutcome::Inconclusive, true, false, UserChoice::automatic(),
                                     TransportMode::Auto, s.tracker.current()));
    CHECK(s.owner.phase() == AttemptPhase::Idle && !s.owner.running());

    // Device round 12: the live session moved to another network and was lost there. What a report says is about ONE
    // network - its key and its generation are the same network's (the one the loss was observed on), so the ledger
    // write is not dropped as "not current" and the path stops being "working" there; the old network keeps its own.
    {
        const NetworkObservation lte = cell("250-02", "lte");
        World w2 = w;
        w2.set(key(lte), QStringLiteral("17"), Behaviour::noData(300));
        w2.set(key(lte), QStringLiteral("16"), ok);
        Sim m(pool, w2, home);
        m.ledger.record(key(lte), pool[0].id, PathOutcome::DataOk, m.wall(), 300, 100); // 17 "works" on LTE by history
        CHECK(m.tap(UserChoice::automatic()).connected && m.owner.currentPath().id.id == QLatin1String("17"));
        m.changeNetworkAt(m.now, lte);
        m.idle(200);
        CHECK(m.owner.phase() == AttemptPhase::Connected && m.owner.network().local == key(lte));
        const int before = int(m.reports.size());
        m.deliver(AttemptEvent::liveLost(m.now, PathOutcome::NoData, false, true, UserChoice::automatic(),
                                         TransportMode::Auto, m.tracker.current()));
        CHECK(m.reports.size() == before + 1);
        const OutcomeReport rep = m.reports.value(before);
        CHECK(rep.outcome == PathOutcome::NoData && rep.path.id == QLatin1String("17"));
        CHECK(rep.network == key(lte) && rep.networkGeneration == m.tracker.current().generation);
        CHECK(stateOf(m, pool[0]) == PathState::Suspect);                                       // on LTE
        CHECK(m.ledger.view(k, pool[0].id, m.wall()).state == PathState::Working);              // on Wi-Fi, untouched
        m.run([&] { return m.results.size() > 1; }, 30000);
        CHECK(m.results.size() == 2 && m.results.last().connected && m.results.last().path.id.id == QLatin1String("16"));
        // every report of a leg names one network too (key and generation of the network the leg ran on)
        for (const OutcomeReport &o : m.reports)
            CHECK(o.network == (o.networkGeneration == m.tracker.current().generation ? key(lte) : k));
    }

    // an adopted live tunnel: one data check decides; data passes -> Connected without a start
    from = int(s.legs.size());
    s.deliver(AttemptEvent::adopted(s.now, pool[1], UserChoice::automatic(), TransportMode::Auto, s.tracker.current()));
    s.run([&] { return s.results.size() > 3; }, 10000);
    CHECK(s.results.size() == 4 && s.results.last().connected && s.legs.size() == from); // nothing (re)started
    CHECK(s.results.last().elapsedMs <= s.owner.timings().dataCheckMs);
    stopLive(s);
    // adopted, but no data: the attempt walks on to the other path
    Sim s2(pool, World{}, home);
    s2.deliver(AttemptEvent::adopted(0, pool[0], UserChoice::automatic(), TransportMode::Auto, s2.tracker.current()));
    s2.run([&] { return !s2.results.isEmpty(); }, 60000);
    CHECK(s2.reports.size() >= 1 && s2.reports[0].outcome == PathOutcome::NoData && s2.legs.size() == 1
          && s2.legs[0].path == QLatin1String("16"));

    // a stop that is never confirmed does not block the attempt (nothing recorded for it)
    World w3;
    w3.set(k, QStringLiteral("16"), ok);
    Sim s3(pool, w3, home);
    s3.stopMs = 600000;
    r = s3.tap(UserChoice::automatic());
    CHECK(r.connected && r.path.id.id == QLatin1String("16")
          && r.elapsedMs == s3.owner.timings().awgStartMs + s3.owner.timings().stopConfirmMs + 700);
    CHECK(s3.reports.size() == 2); // the no-handshake of 17 and the data of 16, nothing about the stop

    // an exact server with two transports: both are its own, nothing else is ever taken
    World w4;
    w4.set(k, QStringLiteral("12:xray"), ok);
    w4.set(k, QStringLiteral("16"), ok);
    Sim s4({ awg("12", "DE"), xray("12:xray", "DE"), awg("16", "NL") }, w4, home);
    r = s4.tap(UserChoice::exactPaths({ QStringLiteral("12"), QStringLiteral("12:xray") }));
    CHECK(r.connected && r.path.id.id == QLatin1String("12:xray") && legPaths(s4) == QStringList({ "12", "12:xray" }));
    r = s4.tap(UserChoice::exactPaths({ QStringLiteral("12"), QStringLiteral("12:xray") }), TransportMode::Awg);
    CHECK(r.reason == FailReason::ExactNodeFailed && legPaths(s4).last() == QLatin1String("12"));
}

// --- scenarios (design §9) -------------------------------------------------------------------------------

// The pool of 17.11 (SELECTION-MAP §2, COMPLAINTS K01): AmneziaWG 17/16/12 automatic, 10/11/15 manual_only;
// relayed Xray listeners 11/12/15 automatic; four provider profiles. Countries of 16/17 and of the providers are
// a reconstruction (not in the journal); 10 and 15 never ran on that Wi-Fi in the journal - they are modelled as
// blocked (RU blocks of their exits since 06.11 / 10.11, COMPLAINTS K01). Provider priority: the journal's fresh
// Xray-mode attempt at 19:59 took 2eec first among the providers (it had the best priority then) -
// `providerFirst` = that order; false = the pessimistic order of the 20:03 rounds (b1fd, 53a6 before 2eec).
// --- AttemptOwner: a starving check yields only to a proof of its own attempt (device round 12 of 21.11) ---

static void testOwnerStarved()
{
    const NetworkObservation home = wifi("192.168.12.1"), lte = cell("250-02", "lte");
    const QList<PathCandidate> pool = { awg("17", "EE", false, 2.0), awg("16", "NL") };
    World w;
    for (const NetworkObservation &n : { home, lte }) {
        w.set(key(n), QStringLiteral("17"), Behaviour::works(300, 3000, 1500)); // first byte at 1.5 s: past the 1 s share
        w.set(key(n), QStringLiteral("16"), Behaviour::works(300, 400, 100));
    }
    Sim s(pool, w, home);
    // Both "work" on both networks by the ledger - 17 carried data, 16 has a probe proof: history, not a proof that waits.
    for (const NetworkObservation &n : { home, lte }) {
        s.ledger.record(key(n), pool[0].id, PathOutcome::DataOk, s.wall(), 300, 100);
        s.ledger.record(key(n), pool[1].id, PathOutcome::ProbeOk, s.wall(), 200);
    }
    const auto checking17 = [&s] {
        return s.owner.phase() == AttemptPhase::Checking && s.owner.currentPath().id.id == QLatin1String("17");
    };
    const auto start = [&s, &checking17] {
        s.deliver(AttemptEvent::userStart(s.now, UserChoice::automatic(), TransportMode::Auto, s.tracker.current()));
        s.run(checking17, 5000);
        return checking17();
    };
    const auto finish = [&s] {
        const int before = int(s.results.size());
        s.run([&s, before] { return s.results.size() > before; }, 20000);
        return s.results.size() > before ? s.results.last() : AttemptResult{};
    };

    // 1. No proof in this attempt: the starving leg is not ended - it connects on its own late first byte.
    CHECK(start());
    s.deliver(AttemptEvent::proofReady(s.now, true));
    CHECK(s.yields == 0 && checking17());
    AttemptResult r = finish();
    CHECK(r.connected && r.path.id.id == QLatin1String("17") && r.paths == 1);
    stopLive(s);

    // 2. A proof named in this attempt while the leg was not starving: nothing then; the leg connects.
    CHECK(start());
    s.deliver(AttemptEvent::proofReady(s.now, false, QStringLiteral("16")));
    CHECK(s.yields == 0 && checking17());
    r = finish();
    CHECK(r.connected && r.path.id.id == QLatin1String("17"));
    stopLive(s);
    //    The NEXT attempt: that proof was the earlier attempt's. 16 still "works" by the ledger and is in the order,
    //    yet the starving leg is not ended.
    CHECK(start());
    s.deliver(AttemptEvent::proofReady(s.now, true));
    CHECK(s.yields == 0 && checking17());
    r = finish();
    CHECK(r.connected && r.path.id.id == QLatin1String("17") && r.paths == 1);
    stopLive(s);

    // 3. A proof of the old network says nothing about the new one: named on Wi-Fi, the leg restarted on cellular starves.
    CHECK(start());
    s.deliver(AttemptEvent::proofReady(s.now, false, QStringLiteral("16")));
    s.changeNetworkAt(s.now, lte);
    s.run([&s, &checking17] { return s.legs.size() >= 5 && checking17(); }, 5000);
    CHECK(s.legs.size() == 5 && s.legs.last().network == key(lte) && checking17());
    s.deliver(AttemptEvent::proofReady(s.now, true));
    CHECK(s.yields == 0 && checking17());
    r = finish();
    CHECK(r.connected && r.path.id.id == QLatin1String("17"));
    stopLive(s);

    // 4. A proof of THIS attempt on this network, then the check starves: the leg yields to it (nothing recorded) and
    //    the next leg is that path - whichever came first, the proof or the starving.
    CHECK(start());
    s.deliver(AttemptEvent::proofReady(s.now, false, QStringLiteral("16")));
    const int reports = int(s.reports.size());
    s.deliver(AttemptEvent::proofReady(s.now, true));
    CHECK(s.yields == 1 && s.reports.size() == reports && s.owner.phase() == AttemptPhase::Stopping);
    r = finish();
    CHECK(r.connected && r.path.id.id == QLatin1String("16") && r.paths == 2);
}

static QList<PathCandidate> pool1711(bool providerFirst = true)
{
    const int p2eec = providerFirst ? 0 : 2, pb1fd = providerFirst ? 1 : 0, p53a6 = providerFirst ? 2 : 1;
    return { awg("17", "EE"), awg("16", "NL"), awg("12", "DE"), awg("10", "US", true), awg("11", "FI", true),
             awg("15", "EE", true), xray("11:xray", "FI"), xray("12:xray", "DE"), xray("15:xray", "EE"),
             prov("up:b1fd", UpstreamKind::Country, "NL", pb1fd), prov("up:53a6", UpstreamKind::Country, "DE", p53a6),
             prov("up:2eec", UpstreamKind::Country, "FI", p2eec), prov("up:786a", UpstreamKind::Country, "NL", 3) };
}
// Behaviour on the owner's Wi-Fi from journal_app.jsonl 17.11: 11 handshake 2.0 s + whoami 1.17 s; own Xray up in
// ~2 s, no data; provider 2eec up 0.45 s, data 0.34 s (ttfb 219 ms); b1fd/53a6/786a up 0.4 s, no first byte.
static World world1711(const QString &net)
{
    World w;
    w.set(net, QStringLiteral("11"), Behaviour::works(2000, 1170, 300));
    for (const char *x : { "11:xray", "12:xray", "15:xray" })
        w.set(net, QString::fromLatin1(x), Behaviour::noData(2000));
    w.set(net, QStringLiteral("up:2eec"), Behaviour::works(450, 342, 219));
    for (const char *u : { "up:b1fd", "up:53a6", "up:786a" })
        w.set(net, QString::fromLatin1(u), Behaviour::noData(400));
    return w; // 17, 16, 12, 10, 15: no handshake (no script)
}

static void scenarioHomeWifi()
{
    const NetworkObservation home = wifi("192.168.1.1");
    const QList<PathCandidate> pool = pool1711();

    // AmneziaWG mode, as at 19:38: the first tap walks the regular nodes, then the last wave reaches 11
    {
        Sim s(pool, world1711(key(home)), home);
        int from = 0;
        AttemptResult r = s.tap(UserChoice::automatic(), TransportMode::Awg);
        row("home Wi-Fi 17.11, AWG mode, tap 1", s, r, from);
        CHECK(r.connected && r.path.id.id == QLatin1String("11"));
        CHECK(r.elapsedMs <= s.owner.timings().budgetMs);
        CHECK(legPaths(s) == QStringList({ "12", "16", "17", "10", "11" }));
        CHECK(stateOf(s, pool[2]) == PathState::Suspect && stateOf(s, pool[0]) == PathState::Suspect);
        for (const LegTrace &l : s.legs)
            CHECK(l.path != QLatin1String("11:xray") && !l.path.startsWith(QLatin1String("up:"))); // mode
        stopLive(s);
        s.idle(5000);
        from = int(s.legs.size());
        r = s.tap(UserChoice::automatic(), TransportMode::Awg);
        row("home Wi-Fi 17.11, AWG mode, next connect", s, r, from);
        CHECK(r.connected && r.path.id.id == QLatin1String("11") && r.paths == 1 && r.elapsedMs <= 3300);

        // the pinned provider that has no data here (20:09): must end, not loop - from a live session on 11
        from = int(s.legs.size());
        r = s.tap(UserChoice::exactPath(QStringLiteral("up:786a")), TransportMode::Auto);
        row("home Wi-Fi 17.11, exact up:786a (from live 11)", s, r, from);
        CHECK(!r.connected && r.reason == FailReason::ExactNodeFailed && r.paths == 1);
        CHECK(legPaths(s, from) == QStringList({ "up:786a" }));
        const int finished = int(s.results.size());
        s.idle(60000);
        CHECK(s.results.size() == finished && s.owner.phase() == AttemptPhase::Idle); // no retry by itself
        from = int(s.legs.size());
        r = s.tap(UserChoice::exactPath(QStringLiteral("up:786a")), TransportMode::Auto);
        row("home Wi-Fi 17.11, exact up:786a again", s, r, from);
        CHECK(r.reason == FailReason::ExactNodeFailed && r.paths == 1);
        CHECK(s.ledger.view(key(home), pool[12].id, s.wall()).state == PathState::Dead);
        // Auto afterwards still goes straight to the proven path
        r = s.tap(UserChoice::automatic(), TransportMode::Auto);
        CHECK(r.connected && r.path.id.id == QLatin1String("11") && r.paths == 1);
    }

    // Auto mode on the same Wi-Fi, nothing known yet (fresh ledger): connects on the FIRST tap
    {
        Sim s(pool, world1711(key(home)), home);
        AttemptResult r = s.tap(UserChoice::automatic(), TransportMode::Auto);
        row("home Wi-Fi 17.11, Auto, tap 1", s, r, 0);
        CHECK(r.connected && r.path.id.id == QLatin1String("up:2eec"));
        stopLive(s);
        const int from = int(s.legs.size());
        r = s.tap(UserChoice::automatic(), TransportMode::Auto);
        row("home Wi-Fi 17.11, Auto, next connect", s, r, from);
        CHECK(r.connected && r.path.id.id == QLatin1String("up:2eec") && r.paths == 1 && r.elapsedMs < 1000);
    }

    // the same with the pessimistic provider order: every candidate stays inside one walk, never twice
    {
        Sim s(pool1711(false), world1711(key(home)), home);
        AttemptResult r;
        int tap = 0;
        do {
            ++tap;
            const int from = int(s.legs.size());
            r = s.tap(UserChoice::automatic(), TransportMode::Auto);
            const QByteArray name = "home Wi-Fi 17.11, Auto, 2eec 3rd provider, tap " + QByteArray::number(tap);
            row(name.constData(), s, r, from);
            CHECK(r.elapsedMs <= s.owner.timings().budgetMs + s.stopMs);
            QSet<QString> seen;
            for (const QString &p : legPaths(s, from)) {
                CHECK(!seen.contains(p)); // never twice in one attempt
                seen.insert(p);
            }
            s.idle(5000);
        } while (!r.connected && tap < 4);
        CHECK(r.connected && r.path.id.id == QLatin1String("up:2eec") && tap <= 2);
    }
}

static void scenarioClean()
{
    const NetworkObservation net = wifi("10.1.1.1");
    QList<PathCandidate> pool = pool1711();
    World w;
    for (const PathCandidate &c : pool)
        w.set(key(net), c.id.id, Behaviour::works(300, 400, 100));
    Sim s(pool, w, net);
    AttemptResult r = s.tap(UserChoice::automatic());
    row("clean network, tap 1", s, r, 0);
    CHECK(r.connected && r.paths == 1 && r.elapsedMs == 700 && !r.path.manualOnly);
    const QString first = r.path.id.id;
    stopLive(s);
    const int from = int(s.legs.size());
    r = s.tap(UserChoice::automatic());
    row("clean network, next connect", s, r, from);
    CHECK(r.connected && r.path.id.id == first && r.paths == 1);
}

static void scenarioWhitelist()
{
    const NetworkObservation net = cell("250-01", "lte");
    const QList<PathCandidate> pool = { awg("17", "EE"), awg("16", "NL"), awg("12", "DE"), xray("11:xray", "FI"),
                                        xray("12:xray", "DE"), prov("up:c1", UpstreamKind::Country, "NL", 0),
                                        prov("up:c2", UpstreamKind::Country, "DE", 1),
                                        prov("up:wl1", UpstreamKind::Whitelist, "", 2),
                                        prov("up:a1", UpstreamKind::Auto, "", 3) };
    World w; // only the whitelist profile passes; everything else is dropped (no handshake)
    w.set(key(net), QStringLiteral("up:wl1"), Behaviour::works(500, 600, 250));
    Sim s(pool, w, net);
    AttemptResult r;
    int tap = 0;
    do {
        ++tap;
        const int from = int(s.legs.size());
        r = s.tap(UserChoice::automatic());
        const QByteArray name = "cellular whitelist, tap " + QByteArray::number(tap);
        row(name.constData(), s, r, from);
        s.idle(5000);
    } while (!r.connected && tap < 5);
    CHECK(r.connected && r.path.id.id == QLatin1String("up:wl1") && tap == 1);
    stopLive(s);
    const int from = int(s.legs.size());
    r = s.tap(UserChoice::automatic());
    row("cellular whitelist, next connect", s, r, from);
    CHECK(r.connected && r.path.id.id == QLatin1String("up:wl1") && r.paths == 1);
}

static void scenarioFlapping()
{
    const NetworkObservation net = wifi("172.16.0.1");
    const QString k = key(net);
    const PathCandidate a = awg("17", "EE", false, 2.0), b = awg("16", "NL");
    World w;
    const Behaviour ok = Behaviour::works(300, 400, 100);
    w.set(k, a.id.id, PathScript::always(ok).then(60000, Behaviour::noHandshake()).then(180000, ok));
    w.set(k, b.id.id, PathScript::always(ok).then(185000, Behaviour::noHandshake()));
    Sim s({ a, b }, w, net);
    AttemptResult r = s.tap(UserChoice::automatic());
    CHECK(r.connected && r.path.id.id == a.id.id);
    stopLive(s);
    s.idle(61000 - s.now);
    int from = int(s.legs.size());
    r = s.tap(UserChoice::automatic());
    row("flapping, A goes away", s, r, from);
    CHECK(r.connected && r.path.id.id == b.id.id && legPaths(s, from) == QStringList({ "17", "16" }));
    CHECK(stateOf(s, a) == PathState::Suspect); // one failure does not kill a path
    stopLive(s);
    from = int(s.legs.size());
    r = s.tap(UserChoice::automatic());
    CHECK(r.connected && r.path.id.id == b.id.id && r.paths == 1); // the proven one, not the suspect
    stopLive(s);
    s.idle(190000 - s.now);
    from = int(s.legs.size());
    r = s.tap(UserChoice::automatic());
    row("flapping, B goes away, A is back", s, r, from);
    CHECK(r.connected && r.path.id.id == a.id.id && legPaths(s, from) == QStringList({ "16", "17" }));
    CHECK(stateOf(s, a) == PathState::Working && s.ledger.view(k, a.id, s.wall()).failStreak == 0);
    CHECK(stateOf(s, b) == PathState::Suspect);
}

static void scenarioNetworkChange()
{
    const NetworkObservation home = wifi("192.168.1.1"), lte = cell("250-02", "5g");
    World w;
    w.set(key(home), QStringLiteral("17"), Behaviour::works(4000, 400, 100)); // slow here
    w.set(key(lte), QStringLiteral("17"), Behaviour::works(300, 400, 100));
    Sim s({ awg("17", "EE", false, 2.0), awg("16", "NL") }, w, home);
    s.changeNetworkAt(2000, lte);
    const AttemptResult r = s.tap(UserChoice::automatic());
    row("network change mid-attempt (Wi-Fi -> cellular at 2 s)", s, r, 0);
    CHECK(r.connected && r.path.id.id == QLatin1String("17") && r.elapsedMs == 3200);
    CHECK(s.legs.size() == 2 && s.legs[0].network == key(home) && s.legs[1].network == key(lte));
    CHECK(s.legs[0].stamp.network != s.legs[1].stamp.network);
    const QByteArray before = s.ledger.toJson();
    s.idle(10000); // the Wi-Fi leg's tunnel-up arrives at 4 s, after the result
    CHECK(s.results.size() == 1 && s.ledger.toJson() == before && s.owner.phase() == AttemptPhase::Connected);
    CHECK(!s.ledger.entry(key(home), QStringLiteral("17"))); // the cut leg described the old network: not recorded
    CHECK(s.ledger.view(key(lte), PathId{ QStringLiteral("17"), QStringLiteral("r1") }, s.wall()).state
          == PathState::Working);
    CHECK(s.reports.size() == 1);

    // losing the network mid-attempt ends it honestly, nothing recorded
    Sim s2({ awg("17", "EE") }, World{}, home);
    NetworkObservation off;
    off.medium = NetMedium::Offline;
    s2.changeNetworkAt(1000, off);
    const AttemptResult r2 = s2.tap(UserChoice::automatic());
    CHECK(r2.reason == FailReason::NoNetwork && s2.ledger.size() == 0 && r2.elapsedMs == 1500);
}

static void scenarioSuspended()
{
    const NetworkObservation home = wifi("192.168.1.1");
    World w;
    w.set(key(home), QStringLiteral("17"), Behaviour::works(2000, 400, 100));
    Sim s({ awg("17", "EE") }, w, home);
    s.suspend(1000, 30000); // the app sleeps 30 s right after the tap; the tunnel comes up meanwhile
    const AttemptResult r = s.tap(UserChoice::automatic());
    row("app suspended 30 s during the start", s, r, 0);
    CHECK(r.connected && r.paths == 1 && r.elapsedMs < s.owner.timings().awgStartMs);
    CHECK(s.reports.size() == 1 && s.reports[0].outcome == PathOutcome::DataOk);
    CHECK(s.lastTapWallMs() > 30000); // wall time includes the sleep, the deadlines did not
}

// "System asleep" (AttemptOwner.h; owner's Mac 24.11.2026, cause F): the lid is closed, the Mac sleeps and makes a
// Power Nap dark wake every ~15 min - the app runs in each for seconds (ticks and callbacks here) while the context
// says the system is not fully awake. Times follow the service log of that night: "will sleep" 08:29:21, dark wakes
// 08:39:16 (19 s) and 08:41:45 (11 s), 08:58:42 (2 s), the lid-open wake 15:38:14 (~7 h after "will sleep").
static void scenarioSystemSleep()
{
    const NetworkObservation home = wifi("192.168.1.1"), otherAp = wifi("192.168.7.1");
    const QString k = key(home);
    constexpr qint64 kSleep = 1000;                       // "will sleep", 1 s after the tap
    constexpr qint64 kDark1 = kSleep + 595'000;           // 08:39:16, 19 s
    constexpr qint64 kDark2 = kDark1 + 149'000;           // 08:41:45, 11 s
    constexpr qint64 kDark3 = kDark2 + 1'017'000;         // 08:58:42, 2 s
    constexpr qint64 kWake = kSleep + 25'733'000;         // 15:38:14
    const auto night = [&](Sim &s) {
        s.at(kSleep, [&s] { s.setSystemAsleep(true); });
        s.suspend(kSleep + 1, kDark1 - kSleep - 1);
        s.suspend(kDark1 + 19'000, kDark2 - kDark1 - 19'000);
        s.suspend(kDark2 + 11'000, kDark3 - kDark2 - 11'000);
        s.suspend(kDark3 + 2'000, kWake - kDark3 - 2'000);
        s.at(kWake, [&s] { s.setSystemAsleep(false); });
    };

    // A) Sleep mid-check (the 08:41:56 start): the leg is up, its data check gets nothing (the Mac sleeps); in the dark
    // wakes nothing is checked, judged, recorded, stopped or started; on the awake edge the check runs again on the
    // same tunnel and the path works - the same leg connects, the sleep spent none of the attempt's budget.
    {
        World w;
        w.set(k, QStringLiteral("17"), PathScript::always(Behaviour::silent(300)).then(kWake, Behaviour::works(300, 400, 100)));
        w.set(k, QStringLiteral("16"), Behaviour::works(300, 400, 100));
        Sim s({ awg("17", "EE", false, 2.0), awg("16", "NL") }, w, home);
        night(s);
        s.deliver(AttemptEvent::userStart(0, UserChoice::automatic(), TransportMode::Auto, s.tracker.current()));
        s.run([&] { return s.now >= kWake - 1; }, kWake);
        CHECK(s.systemAsleep && s.owner.systemAsleep());
        CHECK(s.legs.size() == 1 && s.results.isEmpty() && s.owner.phase() == AttemptPhase::Checking);
        CHECK(s.startsAsleep == 0 && s.checksAsleep == 0 && s.reportsAsleep == 0 && s.stopsAsleep == 0);
        CHECK(s.reports.isEmpty() && s.ledger.size() == 0);
        CHECK(s.owner.awakeMs() <= kSleep + 100); // the clock stood through every dark wake
        const int checksBefore = s.checksRun;
        s.run([&] { return !s.results.isEmpty(); }, 30'000);
        CHECK(s.results.size() == 1 && s.results[0].connected && s.results[0].path.id.id == QLatin1String("17"));
        CHECK(s.legs.size() == 1 && s.checksRun == checksBefore + 1 && s.rechecks == 1); // one evaluation
        CHECK(s.results[0].elapsedMs < 5000);                                            // awake time only
        CHECK(s.reports.size() == 1 && s.reports[0].outcome == PathOutcome::DataOk);
        row("sleep mid-check, dark wakes, lid open (24.11)", s, s.results[0], 0);
    }

    // B) The network changes in the dark wakes (BSSID 08:39:16 to another access point, 08:41:45 back offline) and is
    // another one at the full wake: noted, never acted on while asleep; on the awake edge the attempt moves to the
    // network known then - the old leg goes down unrecorded, the next leg starts on that network.
    {
        World w;
        w.set(k, QStringLiteral("17"), Behaviour::silent(300));
        w.set(key(otherAp), QStringLiteral("17"), Behaviour::works(300, 400, 100));
        Sim s({ awg("17", "EE", false, 2.0), awg("16", "NL") }, w, home);
        night(s);
        NetworkObservation off;
        off.medium = NetMedium::Offline;
        s.changeNetworkAt(kDark1 + 200, otherAp);
        s.changeNetworkAt(kDark2 + 300, off);
        s.changeNetworkAt(kWake - 1, otherAp); // the platform observed the network right before the edge (facade order)
        s.deliver(AttemptEvent::userStart(0, UserChoice::automatic(), TransportMode::Auto, s.tracker.current()));
        s.run([&] { return s.now >= kWake - 1; }, kWake);
        CHECK(s.legs.size() == 1 && s.results.isEmpty());
        CHECK(s.startsAsleep == 0 && s.stopsAsleep == 0 && s.reportsAsleep == 0 && s.checksAsleep == 0);
        s.run([&] { return !s.results.isEmpty(); }, 30'000);
        CHECK(s.results.size() == 1 && s.results[0].connected);
        CHECK(s.legs.size() == 2 && s.legs[1].network == key(otherAp) && s.legs[1].startedMs >= kWake);
        CHECK(!s.ledger.entry(k, QStringLiteral("17"))); // the cut leg described the old network: not recorded
    }

    // C) The live session is lost while asleep (a seat answer that arrived in a dark wake): nothing is recorded, nothing
    // stopped or started in the dark wake; the loss is taken once on the awake edge (failover).
    {
        World w;
        w.set(k, QStringLiteral("17"), Behaviour::works(300, 400, 100));
        w.set(k, QStringLiteral("16"), Behaviour::works(300, 400, 100));
        Sim s({ awg("17", "EE", false, 2.0), awg("16", "NL") }, w, home);
        const AttemptResult r = s.tap(UserChoice::automatic());
        CHECK(r.connected && s.owner.phase() == AttemptPhase::Connected);
        const qint64 base = s.now;
        s.at(base + 100, [&s] { s.setSystemAsleep(true); });
        s.at(base + 5000, [&s] {
            s.deliver(AttemptEvent::liveLost(s.now, PathOutcome::NoData, false, true, UserChoice::automatic(),
                                             TransportMode::Auto, s.tracker.current()));
        });
        s.idle(60'000);
        CHECK(s.owner.phase() == AttemptPhase::Connected && s.results.size() == 1);
        CHECK(s.reportsAsleep == 0 && s.stopsAsleep == 0 && s.startsAsleep == 0);
        s.setSystemAsleep(false);
        s.run([&] { return s.results.size() > 1; }, 30'000);
        CHECK(s.results.size() == 2 && s.results.last().connected && s.results.last().path.id.id == QLatin1String("16"));
        CHECK(s.reports.size() >= 2 && s.reports[1].outcome == PathOutcome::NoData); // the loss, once, after the edge
    }

    // D) The person's own events are taken as always while asleep: a stop stops at once and ends the attempt once; a
    // start begins its attempt, and its leg waits for the awake edge (a person's press in the window is itself a
    // proof of a full wake on the macOS app, SystemAwake.h - this is the owner's rule when none came).
    {
        World w;
        w.set(k, QStringLiteral("17"), Behaviour::silent(300));
        Sim s({ awg("17", "EE") }, w, home);
        s.deliver(AttemptEvent::userStart(0, UserChoice::automatic(), TransportMode::Auto, s.tracker.current()));
        s.idle(1000);
        s.setSystemAsleep(true);
        s.deliver(AttemptEvent::userStop(s.now));
        CHECK(s.stopsAsleep == 1);
        s.run([&] { return !s.results.isEmpty(); }, 5000);
        CHECK(s.results.size() == 1 && s.results[0].reason == FailReason::StoppedByUser && s.startsAsleep == 0);
        World w2;
        w2.set(k, QStringLiteral("17"), Behaviour::works(300, 400, 100));
        Sim s2({ awg("17", "EE") }, w2, home);
        s2.setSystemAsleep(true);
        s2.deliver(AttemptEvent::userStart(s2.now, UserChoice::automatic(), TransportMode::Auto, s2.tracker.current()));
        s2.idle(60'000);
        CHECK(s2.owner.running() && s2.legs.isEmpty() && s2.results.isEmpty());
        s2.setSystemAsleep(false);
        s2.run([&] { return !s2.results.isEmpty(); }, 10'000);
        CHECK(s2.legs.size() == 1 && s2.results.size() == 1 && s2.results[0].connected && s2.startsAsleep == 0);
    }
}

// Android permission prompt (the system's "allow VPN configuration" dialog, VpnService.prepare): the host delivers
// no tick while it is on screen (the same rule as the iOS prompt) - the simulator's suspend() is exactly that - and
// reports "denied" with the leg's stamp. Granted: the leg goes on; denied: the attempt ends once.
static void scenarioPermissionPrompt()
{
    const NetworkObservation home = wifi("192.168.1.1");
    const QString k = key(home);

    // The defect: with no pause the dialog read for 20 s runs the 4.5 s start deadline out and the owner walks on.
    {
        World w;
        w.set(k, QStringLiteral("a1"), Behaviour::works(20700, 400, 100));
        w.set(k, QStringLiteral("a2"), Behaviour::noHandshake());
        Sim s({ awg("a1", "EE"), awg("a2", "FI") }, w, home);
        const AttemptResult r = s.tap(UserChoice::automatic());
        row("prompt 20 s, NO pause (the defect, for contrast)", s, r, 0);
        CHECK(s.legs.size() > 1);
    }
    // Pending 20 s (and longer than the whole 45 s budget), then granted: the same leg connects, nothing recorded
    // against the server, the wait is not counted.
    for (const int promptMs : { 20000, 60000 }) {
        World w;
        w.set(k, QStringLiteral("a1"), Behaviour::works(promptMs + 700, 400, 100));
        w.set(k, QStringLiteral("a2"), Behaviour::works(300, 400, 100));
        Sim s({ awg("a1", "EE"), awg("a2", "FI") }, w, home);
        s.suspend(300, promptMs);
        const AttemptResult r = s.tap(UserChoice::automatic());
        row(promptMs == 20000 ? "prompt pending 20 s, granted" : "prompt pending 60 s, granted", s, r, 0);
        CHECK(r.connected && r.paths == 1 && s.legs.size() == 1 && s.legs[0].path == QLatin1String("a1"));
        CHECK(s.reports.size() == 1 && s.reports[0].outcome == PathOutcome::DataOk);
        CHECK(r.elapsedMs < s.owner.timings().budgetMs / 4); // the wait did not use the attempt budget
        CHECK(s.lastTapWallMs() > promptMs);
    }
    // Denied after 20 s: the attempt ends once with PermissionDenied - no second leg, nothing recorded, no ledger
    // entry, and no event of a later tick changes it.
    for (const bool exact : { false, true }) {
        World w;
        w.set(k, QStringLiteral("a1"), Behaviour::noHandshake());
        w.set(k, QStringLiteral("a2"), Behaviour::works(300, 400, 100));
        Sim s({ awg("a1", "EE"), awg("a2", "FI") }, w, home);
        s.suspend(300, 20000);
        s.at(20000, [&s] {
            s.deliver(AttemptEvent::permissionDenied(s.now, s.owner.currentLeg()));
            s.deliver(AttemptEvent::stopConfirmed(s.now, s.owner.stoppingLeg())); // a stale echo: nothing
        });
        const AttemptResult r = s.tap(exact ? UserChoice::exactPath(QStringLiteral("a1"))
                                            : UserChoice::automatic());
        row(exact ? "prompt denied (exact server)" : "prompt denied (Auto)", s, r, 0);
        CHECK(!r.connected && r.reason == FailReason::PermissionDenied && r.paths == 1);
        CHECK(s.legs.size() == 1 && s.reports.isEmpty() && s.ledger.size() == 0);
        s.idle(90000); // a tap is needed for the next try: nothing starts by itself
        CHECK(s.legs.size() == 1 && s.results.size() == 1 && s.owner.phase() == AttemptPhase::Idle && !s.owner.running());
        // the next tap is a new attempt (the dialog is raised again only by it)
        const AttemptResult again = s.tap(UserChoice::automatic());
        CHECK(again.attempt == r.attempt + 1);
    }
    // A denial that does not belong to the running leg (an older leg, no attempt, the leg already up) changes nothing.
    {
        World w;
        w.set(k, QStringLiteral("b1"), Behaviour::works(1000, 400, 100));
        Sim s({ awg("b1", "EE") }, w, home);
        s.deliver(AttemptEvent::permissionDenied(s.now, PathStamp{ 9, 1, 1 })); // no attempt yet
        CHECK(s.results.isEmpty());
        const AttemptResult r = s.tap(UserChoice::automatic());
        s.deliver(AttemptEvent::permissionDenied(s.now, s.owner.currentLeg())); // connected: not a leg in Starting
        CHECK(r.connected && s.results.size() == 1 && s.owner.phase() == AttemptPhase::Connected);
    }
}

// Local build (AttemptOwner.h "Local build"; Android emulator round 20.11): with «Доступ к сайтам РФ» on, Android
// installs ~10 800 routes in VpnService.establish() - 7-10 s before the tunnel interface exists - while an AmneziaWG
// leg had 4.5 s from its start to a handshake: every leg was judged dead before its tunnel existed, the timeouts went
// into the ledger as failures of the servers. The platform reports "building" / "built"; the server's start deadline
// runs only after "built"; a build that never finishes ends at the local bound with nothing recorded.
static void scenarioLocalBuild()
{
    const NetworkObservation home = wifi("192.168.4.1");
    const QString k = key(home);
    const AttemptTimings t;

    // The defect, for contrast: the platform does not report its build (no pause) - an 8 s build eats the 4.5 s
    // start deadline, a working server is recorded "no handshake" and the walk goes on.
    {
        World w;
        w.set(k, QStringLiteral("a1"), Behaviour::works(8000 + 700, 400, 100));
        w.set(k, QStringLiteral("a2"), Behaviour::works(8000 + 700, 400, 100));
        Sim s({ awg("a1", "EE"), awg("a2", "FI") }, w, home);
        const AttemptResult r = s.tap(UserChoice::automatic());
        row("local build 8 s, NOT reported (the defect)", s, r, 0);
        CHECK(!r.connected && s.ledger.size() > 0);
    }
    // Reported 8 s build, then the server answers in 700 ms: the same leg connects, the only report is "data ok"
    // and its connect time is the server's part (700 ms), not the device's 8.7 s.
    {
        World w;
        w.set(k, QStringLiteral("a1"), Behaviour::works(700, 400, 100));
        w.set(k, QStringLiteral("a2"), Behaviour::works(300, 400, 100));
        Sim s({ awg("a1", "EE"), awg("a2", "FI") }, w, home);
        s.buildMs = 8000;
        const AttemptResult r = s.tap(UserChoice::automatic());
        row("local build 8 s reported, server 0.7 s", s, r, 0);
        CHECK(r.connected && r.path.id.id == QLatin1String("a1") && r.paths == 1 && s.legs.size() == 1);
        CHECK(s.reports.size() == 1 && s.reports[0].outcome == PathOutcome::DataOk && s.reports[0].connectMs == 700);
        CHECK(s.localOverruns == 0);
    }
    // After "built" the leg has its FULL start deadline for the server: an answer at 4.4 s after an 8 s build connects;
    // one at 4.6 s is the server's own failure and is recorded as such (the rule still judges the server).
    for (const int serverMs : { t.awgStartMs - 100, t.awgStartMs + 100 }) {
        World w;
        w.set(k, QStringLiteral("a1"), Behaviour::works(serverMs, 400, 100));
        w.set(k, QStringLiteral("a2"), Behaviour::works(300, 400, 100));
        Sim s({ awg("a1", "EE"), awg("a2", "FI") }, w, home);
        s.buildMs = 8000;
        const AttemptResult r = s.tap(UserChoice::automatic());
        row(serverMs < t.awgStartMs ? "local build 8 s, server 4.4 s" : "local build 8 s, server 4.6 s (late)", s, r, 0);
        CHECK(r.connected);
        if (serverMs < t.awgStartMs) {
            CHECK(r.path.id.id == QLatin1String("a1") && s.legs.size() == 1 && s.reports.size() == 1);
        } else {
            CHECK(r.path.id.id == QLatin1String("a2") && legPaths(s) == (QStringList{ "a1", "a2" }));
            CHECK(stateOf(s, awg("a1", "EE")) == PathState::Suspect); // the server's own late answer: its evidence
        }
    }
    // A build that never finishes: the leg ends at the local bound with a LOCAL outcome - no report, no ledger entry
    // for that server - and the next candidate is tried and connects (its own build reported normally).
    {
        World w;
        w.set(k, QStringLiteral("a1"), Behaviour::works(700, 400, 100));
        w.set(k, QStringLiteral("a2"), Behaviour::works(700, 400, 100));
        Sim s({ awg("a1", "EE"), awg("a2", "FI") }, w, home);
        s.buildMs = 3000;
        s.buildMsFor.insert(QStringLiteral("a1"), Sim::kBuildNever);
        const AttemptResult r = s.tap(UserChoice::automatic());
        row("local build never ends on a1", s, r, 0);
        CHECK(r.connected && r.path.id.id == QLatin1String("a2") && legPaths(s) == (QStringList{ "a1", "a2" }));
        CHECK(s.localOverruns == 1);
        CHECK(s.reports.size() == 1 && s.reports[0].path.id == QLatin1String("a2"));
        CHECK(stateOf(s, awg("a1", "EE")) == PathState::Unknown && s.ledger.size() == 1);
        CHECK(s.legs[1].startedMs >= t.localBuildMs); // a1 had the whole local bound, not the 4.5 s start deadline
    }
    // An exact server whose build never finishes: the attempt ends honestly (exact node failed), still nothing
    // recorded against it.
    {
        World w;
        w.set(k, QStringLiteral("a1"), Behaviour::works(700, 400, 100));
        Sim s({ awg("a1", "EE"), awg("a2", "FI") }, w, home);
        s.buildMs = Sim::kBuildNever;
        const AttemptResult r = s.tap(UserChoice::exactPath(QStringLiteral("a1")));
        row("local build never ends (exact server)", s, r, 0);
        CHECK(!r.connected && r.reason == FailReason::ExactNodeFailed && s.reports.isEmpty() && s.ledger.size() == 0);
    }
    // A server that really does not answer is still judged after its build: the full deadline after "built", then
    // "no handshake" recorded against it, the walk goes on.
    {
        World w;
        w.set(k, QStringLiteral("a2"), Behaviour::works(700, 400, 100));
        Sim s({ awg("a1", "EE"), awg("a2", "FI") }, w, home);
        s.buildMs = 8000;
        const AttemptResult r = s.tap(UserChoice::automatic());
        row("local build 8 s, a1 really dead", s, r, 0);
        CHECK(r.connected && r.path.id.id == QLatin1String("a2"));
        CHECK(stateOf(s, awg("a1", "EE")) == PathState::Suspect);
        CHECK(s.legs[1].startedMs >= 8000 + t.awgStartMs); // a1 was judged only after its build + the full deadline
    }
    // Reports that are not the running leg's change nothing: no attempt, an older leg, a leg already up.
    {
        World w;
        w.set(k, QStringLiteral("b1"), Behaviour::works(1000, 400, 100));
        Sim s({ awg("b1", "EE") }, w, home);
        s.deliver(AttemptEvent::localBuild(s.now, PathStamp{ 9, 1, 1 }, true)); // no attempt yet
        CHECK(s.results.isEmpty());
        s.at(200, [&s] { s.deliver(AttemptEvent::localBuild(s.now, PathStamp{ 9, 1, 1 }, true)); }); // not this leg
        const AttemptResult r = s.tap(UserChoice::automatic());
        CHECK(r.connected && s.legs.size() == 1 && s.localOverruns == 0);
        s.deliver(AttemptEvent::localBuild(s.now, s.owner.currentLeg(), true)); // connected: not a leg in Starting
        s.idle(t.localBuildMs + 1000);
        CHECK(s.owner.phase() == AttemptPhase::Connected && s.results.size() == 1 && s.localOverruns == 0);
    }
}

// android2 V2 (21.11, Redmi, «Доступ к сайтам РФ» on): the service builds one start at a time, 31-39 s each. A leg
// that overran its local bound was stopped and the next leg's start sent - but the service took that start only after
// the previous build ended (7.9 s later at 08:13:38-08:13:46), and the next leg's 4.5 s clock ran from the command:
// "no handshake" recorded against a server whose tunnel build never began. With the platform's reports on, the time
// from the start command to the leg's own "built" is the device's: bounded by the local bound, never a server verdict.
static void scenarioLocalBuildQueued()
{
    const NetworkObservation home = wifi("192.168.4.1");
    const QString k = key(home);
    const AttemptTimings t;
    for (const bool reported : { false, true }) {
        World w;
        for (const char *id : { "n16", "n17", "n15" })
            w.set(k, QString::fromLatin1(id), Behaviour::works(700, 400, 100));
        Sim s({ awg("n16", "RS"), awg("n17", "EE", false, 0.9), awg("n15", "FI", false, 0.8) }, w, home);
        s.buildMs = 33000;
        s.buildReachMs = 400;
        s.serialBuilds = true;
        s.owner.setLocalBuildReported(reported);
        const AttemptResult r = s.tap(UserChoice::automatic());
        if (!reported) {
            // the defect, for contrast: the clock from the command judges the second leg while its build has not begun
            row("V2 queued builds, clock from the command (the defect)", s, r, 0);
            bool judged = false;
            for (const OutcomeReport &rep : s.reports)
                judged = judged || rep.outcome == PathOutcome::NoHandshake;
            CHECK(judged);
            continue;
        }
        // reported: every leg's time until its own "built" is local - no server is judged, nothing is recorded
        row("V2 queued builds, local until built", s, r, 0);
        CHECK(!r.connected && s.reports.isEmpty() && s.ledger.size() == 0);
        CHECK(s.localOverruns >= 2 && s.legs.size() == 3); // the third leg is cut by the budget, also unrecorded
        for (int i = 1; i < s.legs.size(); ++i) // each leg had the whole local bound from its start command
            CHECK(s.legs[i].startedMs - s.legs[i - 1].startedMs >= t.localBuildMs);
    }
    {   // a fast build (0.3 s, reached after 0.4 s): the server is judged after its "built" with the full deadline
        World w;
        w.set(k, QStringLiteral("n17"), Behaviour::works(700, 400, 100));
        Sim s({ awg("n16", "RS"), awg("n17", "EE", false, 0.9) }, w, home);
        s.buildMs = 300;
        s.buildReachMs = 400;
        s.serialBuilds = true;
        s.owner.setLocalBuildReported(true);
        const AttemptResult r = s.tap(UserChoice::automatic());
        row("reported fast build, n16 really dead", s, r, 0);
        CHECK(r.connected && r.path.id.id == QLatin1String("n17"));
        CHECK(stateOf(s, awg("n16", "RS")) == PathState::Suspect); // judged - after its own build
        CHECK(s.legs[1].startedMs >= 400 + 300 + t.awgStartMs);
        CHECK(s.reports.last().connectMs == 700); // the server's part only
    }
    {   // a server that answers 4.4 s after its own "built", the start having waited 7.9 s in the service: connects
        World w;
        w.set(k, QStringLiteral("n17"), Behaviour::works(t.awgStartMs - 100, 400, 100));
        Sim s({ awg("n17", "EE") }, w, home);
        s.buildMs = 300;
        s.buildReachMs = 7900;
        s.owner.setLocalBuildReported(true);
        const AttemptResult r = s.tap(UserChoice::automatic());
        CHECK(r.connected && s.legs.size() == 1 && s.localOverruns == 0);
    }
}

// Device round air-B 24.11 (iPhone Air, Wi-Fi, first Auto tap after a cold launch, no memory of the network, race on).
// Times from the tap (19:51:51.942 UTC): the race waits 2.75 s and the owner starts its first choice BLIND at 2.804 s
// (12:xray); at 3.038 s the race proves 11:xray and the blind leg yields while its start is still running; the
// extension takes 25.03 s to tear that session down (Disconnected 19:52:20.009). At 13.038 s the owner gives the stop
// up (attempt_stop_unconfirmed) and sends leg 2 (11:xray, the proof's lead); the native PARKS it behind the teardown
// (one tunnel session at a time); at 18.038 s its 5 s clock writes no_handshake/suspect against the path the race
// had just proven; leg 3 (11 AmneziaWG, probe-proven at 8.222 s) starts with the real Disconnected and carries data.
// The device: tap -> verified 30.0 s, attempt_result ms=27193 paths=3. The race itself is not simulated: its two
// proofs enter the ledger and the owner at the device's times.
struct AirBRun {
    AttemptResult result;
    qint64 tapMs = -1;      // tap -> the attempt's result
    QStringList legs;
    QList<OutcomeReport> reports;
    int parked = 0;
    PathState proven = PathState::Unknown; // 11:xray in the ledger at the end
    bool falseMark = false;                // a no_handshake against a leg that never left the device
};

static AirBRun runAirB2411(bool parkReported, int stopStartingMs)
{
    const NetworkObservation home = wifi("192.168.24.1");
    const QString k = key(home);
    const PathCandidate x12 = xray("12:xray", "DE", false, 2.0), x11 = xray("11:xray", "FI"), a11 = awg("11", "FI", true);
    World w;
    w.set(k, x12.id.id, Behaviour::works(1340, 900, 400));
    w.set(k, x11.id.id, Behaviour::works(1350, 1000, 400)); // 11:xray verified 1.32-1.35 s after its start later that round
    w.set(k, a11.id.id, Behaviour::works(1400, 400, 383));
    Sim s({ x12, x11, a11 }, w, home);
    s.ios.on = true;
    s.ios.parkReported = parkReported;
    s.ios.stopStartingMs = stopStartingMs;
    s.ios.stopUpMs = 500;
    s.at(2804, [&s] { // race_owner_start why=hedge lead=-
        s.deliver(AttemptEvent::userStart(s.now, UserChoice::automatic(), TransportMode::Auto, s.tracker.current()));
    });
    s.at(3038, [&s, k, x11] { // path_outcome 11:xray probe_ok source=race, then the proof reaches the owner
        s.ledger.record(k, x11.id, PathOutcome::ProbeOk, s.wall(), 2738);
        s.deliver(AttemptEvent::proofReady(s.now, false, x11.id.id));
    });
    s.at(8222, [&s, k, a11] { s.ledger.record(k, a11.id, PathOutcome::ProbeOk, s.wall(), 597); }); // 11 probe_ok
    s.run([&s] { return !s.results.isEmpty(); }, 90000);
    AirBRun out;
    if (!s.results.isEmpty()) {
        out.result = s.results.last();
        out.tapMs = s.now;
    }
    out.legs = legPaths(s);
    out.reports = s.reports;
    out.parked = s.parkedStarts;
    out.proven = stateOf(s, x11);
    for (const OutcomeReport &rep : s.reports)
        out.falseMark = out.falseMark || (rep.path.id == x11.id.id && rep.outcome == PathOutcome::NoHandshake);
    return out;
}

static void scenarioTraceAirB2411()
{
    const auto put = [](const char *name, const AirBRun &t) {
        g_rows.append({ QString::fromLatin1(name),
                        t.result.connected ? QStringLiteral("connected ") + t.result.path.id.id : QStringLiteral("failed"),
                        t.tapMs, t.result.paths, t.legs.join(QLatin1Char(' ')) });
    };
    const AirBRun before = runAirB2411(/*parkReported=*/false, 25030);
    const AirBRun after = runAirB2411(/*parkReported=*/true, 25030);
    const AirBRun prompt = runAirB2411(/*parkReported=*/true, 1000);
    put("air-B 24.11 first tap, before (park unreported)", before);
    put("air-B 24.11 first tap, park reported", after);
    put("air-B 24.11 first tap, park reported, 1 s stop", prompt);
    // Before: the emulation reproduces the device - leg 2 parked and judged, three legs, ~30 s to data on 11 AWG.
    CHECK(before.result.connected && before.result.path.id.id == QLatin1String("11"));
    CHECK(before.legs == QStringList({ "12:xray", "11:xray", "11" }) && before.parked == 1);
    CHECK(before.falseMark && before.proven == PathState::Suspect);
    CHECK(before.tapMs >= 29000 && before.tapMs <= 31000);                       // device: 30.0 s
    CHECK(before.result.elapsedMs >= 26500 && before.result.elapsedMs <= 28000); // device: ms=27193
    // Park reported: the proven path's start waits for the real teardown, nothing is judged for the wait, the proof
    // is honoured (11:xray carries data) - the time is bounded by the teardown plus one start and its check.
    CHECK(after.result.connected && after.result.path.id.id == QLatin1String("11:xray"));
    CHECK(after.legs == QStringList({ "12:xray", "11:xray" }) && after.parked == 1 && !after.falseMark);
    CHECK(after.proven == PathState::Working && after.reports.size() == 1
          && after.reports[0].outcome == PathOutcome::DataOk);
    CHECK(after.reports[0].connectMs == 1350); // the server's part only: the park is not the path's connect time
    CHECK(after.tapMs >= 3038 + 25030 && after.tapMs <= 3038 + 25030 + 1350 + 1000 + 200);
    // The stop of a starting leg answered in ~1 s (the extension side of the fix): no park at all, data in ~6.4 s.
    CHECK(prompt.result.connected && prompt.result.path.id.id == QLatin1String("11:xray") && prompt.parked == 0);
    CHECK(!prompt.falseMark && prompt.tapMs <= 3038 + 1000 + 1350 + 1000 + 200);
}

// The same platform outside the race (path_race off, the sequential walk): a person's Stop 0.3 s into a start and a
// leg whose own start never finishes (its setTunnelNetworkSettings never calls back). The stop of a starting session
// takes 25 s (the build of 24.11) or 1 s (the extension answers a running start itself); a start sent meanwhile is
// parked. Reported park: the next leg is never judged for the wait.
static void scenarioIosStopDuringStart()
{
    const NetworkObservation home = wifi("192.168.25.1");
    const QString k = key(home);
    const PathCandidate a1 = awg("a1", "FI"), a2 = awg("a2", "EE", false, 0.5);
    // 1. Stop 0.3 s into a start, Connect again 1.7 s later.
    for (const int stopStartingMs : { 25030, 1000 }) {
        for (const bool parkReported : { false, true }) {
            World w;
            w.set(k, a1.id.id, Behaviour::works(1400, 400, 120));
            w.set(k, a2.id.id, Behaviour::works(1400, 400, 120));
            Sim s({ a1, a2 }, w, home);
            s.ios.on = true;
            s.ios.parkReported = parkReported;
            s.ios.stopStartingMs = stopStartingMs;
            s.deliver(AttemptEvent::userStart(s.now, UserChoice::automatic(), TransportMode::Auto, s.tracker.current()));
            const quint64 first = s.owner.attempt();
            s.at(300, [&s] { s.deliver(AttemptEvent::userStop(s.now)); });
            // the person taps Connect again 1.7 s after the Stop, whether or not the stop is over by then
            s.at(2000, [&s] {
                s.deliver(AttemptEvent::userStart(s.now, UserChoice::automatic(), TransportMode::Auto, s.tracker.current()));
            });
            // Disconnected = the stop confirmed: the first attempt's result before the second tap
            qint64 stoppedAt = -1;
            s.run([&] { return !s.results.isEmpty(); }, 1990);
            if (!s.results.isEmpty())
                stoppedAt = s.now;
            const int from = int(s.legs.size());
            s.run([&] { return !s.results.isEmpty() && s.results.last().attempt > first; }, 90000);
            CHECK(!s.results.isEmpty() && s.results.first().reason == FailReason::StoppedByUser);
            const AttemptResult r = s.results.last();
            bool judged = false;
            for (const OutcomeReport &rep : s.reports)
                judged = judged || rep.outcome == PathOutcome::NoHandshake;
            const char *name = stopStartingMs > 2000
                ? (parkReported ? "iOS Stop 0.3 s into a start (25 s stop), park reported"
                                : "iOS Stop 0.3 s into a start (25 s stop), before")
                : (parkReported ? "iOS Stop 0.3 s into a start (1 s stop), park reported"
                                : "iOS Stop 0.3 s into a start (1 s stop), before");
            // ms = the second tap -> its result
            g_rows.append({ QString::fromLatin1(name), r.connected ? QStringLiteral("connected ") + r.path.id.id
                                                                   : QStringLiteral("failed"),
                            s.now - 2000, r.paths, legPaths(s, from).join(QLatin1Char(' ')) });
            CHECK(r.connected);
            if (stopStartingMs <= 2000) {
                // the extension answers the stop of a starting session: Disconnected ~1.3 s after the first tap, the
                // next Connect starts at once and nothing is judged, whatever the park report
                CHECK(stoppedAt > 0 && stoppedAt <= 300 + stopStartingMs + 200 && !judged && s.parkedStarts == 0);
                CHECK(r.path.id.id == QLatin1String("a1") && r.paths == 1 && s.now - 2000 <= 1400 + 400 + 200);
            } else if (parkReported) {
                // the 25 s stop: the next Connect waits for it (parked, the owner gave the stop up) - never blamed
                CHECK(stoppedAt < 0 && !judged && s.parkedStarts == 1 && r.path.id.id == QLatin1String("a1"));
                CHECK(stateOf(s, a1) == PathState::Working);
            } else {
                // before: the parked start of the next Connect is judged no_handshake against a working server
                CHECK(judged && stateOf(s, a1) == PathState::Suspect && r.path.id.id == QLatin1String("a2"));
            }
        }
    }
    // 2. A leg whose own start never finishes: its deadline judges it as before (its start left the device); its stop
    //    is the stop of a starting session; the next leg, sent after the stop was given up, is parked.
    for (const int stopStartingMs : { 25030, 1000 }) {
        for (const bool parkReported : { false, true }) {
            World w;
            w.set(k, a1.id.id, Behaviour::noHandshake());
            w.set(k, a2.id.id, Behaviour::works(1400, 400, 120));
            Sim s({ a1, a2 }, w, home);
            s.ios.on = true;
            s.ios.parkReported = parkReported;
            s.ios.stopStartingMs = stopStartingMs;
            s.ios.extStartMsFor.insert(a1.id.id, Sim::kBuildNever);
            const AttemptResult r = s.tap(UserChoice::automatic());
            const char *name = stopStartingMs > 2000
                ? (parkReported ? "iOS leg timeout during its start (25 s stop), park reported"
                                : "iOS leg timeout during its start (25 s stop), before")
                : (parkReported ? "iOS leg timeout during its start (1 s stop), park reported"
                                : "iOS leg timeout during its start (1 s stop), before");
            row(name, s, r, 0);
            CHECK(legPaths(s) == QStringList({ "a1", "a2" }) && stateOf(s, a1) == PathState::Suspect);
            if (stopStartingMs <= 2000) {
                CHECK(r.connected && r.path.id.id == QLatin1String("a2") && s.parkedStarts == 0);
                CHECK(s.lastTapWallMs() <= 4500 + 1000 + 1400 + 400 + 200);
            } else if (parkReported) {
                // a2 waits for the real teardown, then carries data; only a1's own verdict is in the ledger
                CHECK(r.connected && r.path.id.id == QLatin1String("a2") && s.parkedStarts == 1);
                CHECK(stateOf(s, a2) == PathState::Working && s.lastTapWallMs() >= 4500 + 25030);
            } else {
                // before: a2 is judged for the park and the attempt ends with nothing proven
                CHECK(!r.connected && stateOf(s, a2) == PathState::Suspect);
            }
        }
    }
    // 3. A "no handshake" that reaches a leg in its local phase is never recorded (the invariant in report()).
    {
        World w;
        w.set(k, a1.id.id, Behaviour::works(1400, 400, 120));
        Sim s({ a1 }, w, home);
        s.deliver(AttemptEvent::userStart(s.now, UserChoice::exactPath(a1.id.id), TransportMode::Auto, s.tracker.current()));
        s.deliver(AttemptEvent::localBuild(s.now, s.owner.currentLeg(), true));
        s.at(200, [&s] { s.deliver(AttemptEvent::pathFailed(s.now, s.owner.currentLeg(), PathOutcome::NoHandshake)); });
        s.run([&s] { return !s.results.isEmpty(); }, 30000);
        CHECK(!s.results.isEmpty() && s.reports.isEmpty() && s.ledger.size() == 0);
    }
    // 4. (review R43 F5) A start parked a second time (the profile torn down again during its save): the clock stands
    //    again, and the 20 s local bound counts both parks together - a second park never buys a fresh 20 s.
    {
        const AttemptTimings t;
        World w;
        w.set(k, a1.id.id, Behaviour::noHandshake());
        Sim s({ a1 }, w, home);
        s.deliver(AttemptEvent::userStart(s.now, UserChoice::exactPath(a1.id.id), TransportMode::Auto, s.tracker.current()));
        const PathStamp leg = s.owner.currentLeg();
        s.deliver(AttemptEvent::localBuild(s.now, leg, true));
        s.at(15000, [&s, leg] { s.deliver(AttemptEvent::localBuild(s.now, leg, false)); }); // goes out after 15 s
        s.at(15500, [&s, leg] { s.deliver(AttemptEvent::localBuild(s.now, leg, true)); }); // parked again 0.5 s later
        s.run([&s] { return !s.results.isEmpty(); }, 60000);
        CHECK(s.localOverruns == 1 && s.reports.isEmpty() && s.ledger.size() == 0);
        // overrun when both parks reach the bound: 15 s + 5 s = 20.5 s from the tap, not 15.5 s + 20 s
        CHECK(s.now <= 15500 + (t.localBuildMs - 15000) + t.stopConfirmMs + 600 && s.now >= 15500 + (t.localBuildMs - 15000));
        CHECK(!s.results.isEmpty() && s.results.last().elapsedMs < 15500 + 20000);
    }
}

// Android (review R43): the local phase and the invariant of AttemptOwner::report() as Android uses them - the service
// reports its builds, the leg is local from its start command until its own "built" (setLocalBuildReported). Every
// outcome below is the one of the build before the invariant (the 71 scenario rows of this file, the Android ones
// included, are byte-identical to the base): no Android path delivers a no_handshake while a leg is local - its local
// outcomes are LocalBuildOverrun and NotStarted (Inconclusive) - so the invariant changes no Android outcome. What
// changes for Android (R43 F5, ServiceEngine::onLocalBuild): a "building" of the same leg after its "built" (the
// service rebuilding that start) opens a second local phase instead of being ignored, and the local bound counts all
// phases of a leg together.
static void scenarioAndroidLocalPhaseUnchanged()
{
    const NetworkObservation home = wifi("192.168.26.1");
    const QString k = key(home);
    const AttemptTimings t;
    const PathCandidate n16 = awg("n16", "RS"), n17 = awg("n17", "EE", false, 0.9);
    const auto noHandshakes = [](const Sim &s) {
        int n = 0;
        for (const OutcomeReport &rep : s.reports)
            n += rep.outcome == PathOutcome::NoHandshake ? 1 : 0;
        return n;
    };
    {   // a server that does not answer after its own "built": still judged no_handshake (nothing is hidden)
        World w;
        w.set(k, n17.id.id, Behaviour::works(700, 400, 100));
        Sim s({ n16, n17 }, w, home);
        s.owner.setLocalBuildReported(true);
        s.buildMs = 2000;
        const AttemptResult r = s.tap(UserChoice::automatic());
        row("Android: built 2 s, n16 dead (judged)", s, r, 0);
        CHECK(r.connected && r.path.id.id == QLatin1String("n17") && noHandshakes(s) == 1);
        CHECK(stateOf(s, n16) == PathState::Suspect && s.legs[1].startedMs >= 2000 + t.awgStartMs);
    }
    {   // a build that never ends, then a fast one: a local outcome, nothing recorded for the first server
        World w;
        w.set(k, n16.id.id, Behaviour::works(700, 400, 100));
        w.set(k, n17.id.id, Behaviour::works(700, 400, 100));
        Sim s({ n16, n17 }, w, home);
        s.owner.setLocalBuildReported(true);
        s.buildMs = 300;
        s.buildMsFor.insert(n16.id.id, Sim::kBuildNever);
        const AttemptResult r = s.tap(UserChoice::automatic());
        row("Android: n16 never built, n17 built", s, r, 0);
        CHECK(r.connected && r.path.id.id == QLatin1String("n17") && s.localOverruns == 1 && noHandshakes(s) == 0);
        CHECK(stateOf(s, n16) == PathState::Unknown);
    }
    {   // the service takes the start late (queued behind an earlier build): local until its own "built", then judged
        World w;
        Sim s({ n16 }, w, home);
        s.owner.setLocalBuildReported(true);
        s.buildMs = 300;
        s.buildReachMs = 7900;
        const AttemptResult r = s.tap(UserChoice::exactPath(n16.id.id));
        row("Android: start taken after 7.9 s, dead", s, r, 0);
        CHECK(!r.connected && noHandshakes(s) == 1 && s.localOverruns == 0);
        CHECK(s.reports.size() == 1 && s.reports[0].outcome == PathOutcome::NoHandshake);
    }
    {   // what changes (F5): a second build of the same leg after its "built" is local again, bounded with the first
        World w;
        Sim s({ n16 }, w, home);
        s.owner.setLocalBuildReported(true);
        s.deliver(AttemptEvent::userStart(s.now, UserChoice::exactPath(n16.id.id), TransportMode::Auto, s.tracker.current()));
        const PathStamp leg = s.owner.currentLeg();
        s.at(100, [&s, leg] { s.deliver(AttemptEvent::localBuild(s.now, leg, true)); });
        s.at(8000, [&s, leg] { s.deliver(AttemptEvent::localBuild(s.now, leg, false)); });
        s.at(9000, [&s, leg] { s.deliver(AttemptEvent::localBuild(s.now, leg, true)); }); // the service builds it again
        s.run([&s] { return !s.results.isEmpty(); }, 60000);
        CHECK(noHandshakes(s) == 0 && s.localOverruns == 1);                       // never judged during either build
        CHECK(!s.results.isEmpty() && s.results.last().elapsedMs <= t.localBuildMs + 1000 + t.stopConfirmMs + 600);
    }
}

static void scenarioPreference()
{
    const NetworkObservation home = wifi("192.168.7.1");
    const QString k = key(home);
    const QList<PathCandidate> pool = { awg("de1", "DE"), xray("de1:xray", "DE"), awg("nl1", "NL", false, 2.0),
                                        awg("fi1", "FI") };
    World w;
    w.set(k, QStringLiteral("de1:xray"), Behaviour::noData(1500));
    w.set(k, QStringLiteral("nl1"), Behaviour::works(300, 400, 100));
    w.set(k, QStringLiteral("fi1"), Behaviour::works(300, 400, 100));
    Sim s(pool, w, home);
    int from = 0;
    AttemptResult r = s.tap(UserChoice::preferCountry(QStringLiteral("DE")));
    row("preferred DE unavailable, tap 1", s, r, from);
    CHECK(r.connected && r.path.id.id == QLatin1String("nl1") && r.fallbackNotice && r.paths == 3);
    stopLive(s);
    from = int(s.legs.size());
    r = s.tap(UserChoice::preferCountry(QStringLiteral("DE")));
    row("preferred DE failed here, tap 2", s, r, from);
    // review E9 of 18.11: DE failed on this network - the proven path goes first, DE is not retried ahead of it
    CHECK(r.connected && r.fallbackNotice && legPaths(s, from) == QStringList({ "nl1" }));
    stopLive(s);
    from = int(s.legs.size());
    r = s.tap(UserChoice::preferCountry(QStringLiteral("DE")));
    row("preferred DE failed here, tap 3", s, r, from);
    CHECK(r.connected && r.fallbackNotice && r.path.id.id == QLatin1String("nl1") && r.paths == 1);
    CHECK(!r.preferredTried); // R2: the notice says "recently did not work", not "does not work"
    stopLive(s);
    // a server of the list (preferServer: the transports of one host) falls back like a country, with the notice
    from = int(s.legs.size());
    r = s.tap(UserChoice::preferServer(QStringLiteral("DE"), { QStringLiteral("de1"), QStringLiteral("de1:xray") }));
    CHECK(r.connected && r.fallbackNotice && r.path.id.id == QLatin1String("nl1"));
    stopLive(s);

    // the preference is kept: with nothing working or untried left here, DE is tried before the other failures
    s.world().set(k, QStringLiteral("nl1"), Behaviour::noHandshake());
    s.world().set(k, QStringLiteral("fi1"), Behaviour::noHandshake());
    s.idle(s.ledger.tunables().quarantineMs[0] + 1000);
    from = int(s.legs.size());
    r = s.tap(UserChoice::preferCountry(QStringLiteral("DE")));
    // R2 (device round 4): DE failed here longer ago than the first quarantine step - it gets one real try first
    CHECK(legPaths(s, from).mid(0, 2) == QStringList({ "de1", "de1:xray" }));
    CHECK(legPaths(s, from).count(QStringLiteral("de1")) == 1); // once per attempt
    stopLive(s);

    // the exact node never falls back
    from = int(s.legs.size());
    r = s.tap(UserChoice::exactPath(QStringLiteral("de1")));
    row("exact node de1 unavailable", s, r, from);
    CHECK(!r.connected && r.reason == FailReason::ExactNodeFailed && legPaths(s, from) == QStringList({ "de1" }));
}

static void scenarioModeBeatsPreference()
{
    const NetworkObservation home = wifi("192.168.8.1");
    const QString k = key(home);
    World w;
    w.set(k, QStringLiteral("de1:xray"), Behaviour::works(300, 400, 100));
    w.set(k, QStringLiteral("nl1"), Behaviour::works(300, 400, 100));
    Sim s({ awg("de1", "DE"), xray("de1:xray", "DE"), awg("nl1", "NL") }, w, home);
    const AttemptResult r = s.tap(UserChoice::preferCountry(QStringLiteral("DE")), TransportMode::Awg);
    row("Amnezia mode, preferred DE works only over Xray", s, r, 0);
    CHECK(r.connected && r.path.id.id == QLatin1String("nl1") && r.fallbackNotice);
    CHECK(!legPaths(s).contains(QStringLiteral("de1:xray")));
    // and an exact Xray node in Amnezia mode is not started at all
    stopLive(s);
    const int from = int(s.legs.size());
    const AttemptResult r2 = s.tap(UserChoice::exactPath(QStringLiteral("de1:xray")), TransportMode::Awg);
    CHECK(r2.reason == FailReason::ExactNodeFailed && r2.paths == 0 && s.legs.size() == from);
}

static void scenarioRevision()
{
    const NetworkObservation home = wifi("192.168.1.1");
    QList<PathCandidate> pool = { awg("12", "DE"), awg("11", "FI", true) };
    World w;
    w.set(key(home), QStringLiteral("11"), Behaviour::works(2000, 1170, 300));
    Sim s(pool, w, home);
    AttemptResult r = s.tap(UserChoice::automatic(), TransportMode::Awg);
    CHECK(r.connected && r.path.id.id == QLatin1String("11") && legPaths(s) == QStringList({ "12", "11" }));
    stopLive(s);
    r = s.tap(UserChoice::automatic(), TransportMode::Awg);
    CHECK(r.paths == 1); // proven: straight to 11
    stopLive(s);
    // the server moves 11 to another endpoint: a new revision, the proof does not carry over
    pool[1].id.revision = QStringLiteral("r2");
    s.setPool(pool);
    CHECK(stateOf(s, pool[1]) == PathState::Unknown);
    const int from = int(s.legs.size());
    r = s.tap(UserChoice::automatic(), TransportMode::Awg);
    row("revision change of the proven path", s, r, from);
    CHECK(r.connected && legPaths(s, from) == QStringList({ "11" })); // 12 failed here: 11 is next anyway
    CHECK(s.ledger.entry(key(home), QStringLiteral("11"))->revision == QLatin1String("r2"));
}

// --- Review of 18.11 (E1-E4, E9) as scenarios ------------------------------------------------------------------

static bool hasEffect(const QList<AttemptEffect> &fx, EffectType t)
{
    for (const AttemptEffect &e : fx)
        if (e.type == t)
            return true;
    return false;
}

static void scenarioReview1811()
{
    const NetworkObservation home = wifi("192.168.5.1");
    const QString k = key(home);

    // E1: the native start never answers (no Connecting, nothing): every leg ends by the owner's own deadline, the
    // attempt has one terminal result, and the next tap is a new attempt at once (nothing stays latched).
    {
        World w;
        Sim s({ awg("a1", "EE"), awg("a2", "NL") }, w, home);
        const AttemptResult r = s.tap(UserChoice::automatic());
        row("E1 native start stalls on every path", s, r, 0);
        CHECK(!r.connected && r.reason == FailReason::NothingProven && !s.owner.running());
        CHECK(r.elapsedMs <= s.owner.timings().budgetMs && s.results.size() == 1);
        s.world().set(k, QStringLiteral("a2"), Behaviour::works(300, 400, 100));
        const int from = int(s.legs.size());
        const qint64 tapAt = s.now;
        const AttemptResult r2 = s.tap(UserChoice::automatic());
        CHECK(r2.connected && r2.attempt == r.attempt + 1 && s.legs[from].startedMs == tapAt);
    }

    // E2: a duplicate or late native error of a failed leg never fails the next leg (the stamp of the leg that
    // failed travels with the error; the owner drops it by construction).
    {
        World w;
        w.set(k, QStringLiteral("b2"), Behaviour::works(300, 400, 100));
        w.set(k, QStringLiteral("b1"), Behaviour::startError(false));
        Sim s({ awg("b1", "EE", false, 2.0), awg("b2", "NL") }, w, home);
        s.deliver(AttemptEvent::userStart(0, UserChoice::automatic(), TransportMode::Auto, s.tracker.current()));
        s.run([&] { return s.legs.size() == 2; }, 5000);
        const PathStamp first = s.legs[0].stamp;
        s.deliver(AttemptEvent::pathFailed(s.now, first, PathOutcome::Inconclusive, /*tunnelGone=*/true)); // duplicate
        s.at(s.now + 100, [&s, first] { s.deliver(AttemptEvent::pathFailed(s.now, first, PathOutcome::Inconclusive, true)); });
        s.run([&] { return !s.results.isEmpty(); }, 30000);
        const AttemptResult r = s.results.isEmpty() ? AttemptResult{} : s.results.last();
        row("E2 duplicate error of the failed leg", s, r, 0);
        CHECK(r.connected && r.path.id.id == QLatin1String("b2") && s.legs.size() == 2);
    }

    // E3: suspended 3 s into a 4.5 s AmneziaWG start; the tunnel comes up during the sleep or just after the
    // resume (within the resume grace): connected, nothing charged for the sleep.
    for (const int upMs : { 3500, 34800 }) {
        World w;
        w.set(k, QStringLiteral("c1"), Behaviour::works(upMs, 400, 100));
        Sim s({ awg("c1", "EE") }, w, home);
        s.suspend(3000, 30000);
        const AttemptResult r = s.tap(UserChoice::automatic());
        row(upMs < 30000 ? "E3 suspended mid-start, up during the sleep" : "E3 suspended mid-start, up after resume",
            s, r, 0);
        CHECK(r.connected && r.paths == 1 && s.reports.size() == 1 && s.reports[0].outcome == PathOutcome::DataOk);
    }
    // E3: suspended in the middle of the data check: the check is run again on the same tunnel, nothing recorded
    // for the interrupted one, the leg is not abandoned.
    {
        World w;
        w.set(k, QStringLiteral("d1"), PathScript::always(Behaviour::silent(500)).then(20000, Behaviour::works(500, 400, 100)));
        Sim s({ awg("d1", "EE") }, w, home);
        s.suspend(1500, 30000);
        const AttemptResult r = s.tap(UserChoice::automatic());
        row("E3 suspended mid-check", s, r, 0);
        CHECK(r.connected && r.paths == 1 && s.rechecks == 1 && s.checksRun == 2);
        CHECK(s.reports.size() == 1 && s.reports[0].outcome == PathOutcome::DataOk);
    }
    // E3: an inconclusive check (no suspension) is run again once on the same tunnel, then the leg is given up
    // with nothing recorded.
    {
        AttemptOwner o;
        PathLedger l;
        const SelectionContext ctx{ { awg("e1", "EE") }, &l, 0, {} };
        NetworkTracker tr;
        tr.observe(home);
        QList<AttemptEffect> fx = o.handle(AttemptEvent::userStart(0, UserChoice::automatic(), TransportMode::Auto, tr.current()), ctx);
        const PathStamp leg = o.currentLeg();
        fx = o.handle(AttemptEvent::tunnelUp(300, leg), ctx);
        fx = o.handle(AttemptEvent::dataChecked(900, leg, PathOutcome::Inconclusive), ctx);
        CHECK(hasEffect(fx, EffectType::RunDataCheck) && !hasEffect(fx, EffectType::StopPath) && !hasEffect(fx, EffectType::Report));
        CHECK(o.phase() == AttemptPhase::Checking && fx.first().recheck);
        fx = o.handle(AttemptEvent::dataChecked(1500, leg, PathOutcome::Inconclusive), ctx);
        CHECK(hasEffect(fx, EffectType::StopPath) && !hasEffect(fx, EffectType::Report));
    }

    // E4: a validated payload delivered exactly at the check deadline wins over the deadline (no grace at all here),
    // and one delivered past the check's own limit but before the backstop is "works, slow".
    {
        AttemptTimings t;
        t.checkGraceMs = 0;
        World w;
        w.set(k, QStringLiteral("f1"), Behaviour::works(500, t.dataCheckMs, 3000));
        Sim s({ awg("f1", "EE") }, w, home, t);
        const AttemptResult r = s.tap(UserChoice::automatic());
        row("E4 payload complete at the check deadline", s, r, 0);
        CHECK(r.connected && s.reports.size() == 1 && s.reports[0].outcome == PathOutcome::DataOk);
    }
    {
        World w;
        const AttemptTimings t;
        w.set(k, QStringLiteral("g1"), Behaviour::works(500, t.dataCheckMs + 800, 3500));
        w.set(k, QStringLiteral("g2"), Behaviour::silent(500));
        Sim s({ awg("g1", "EE", false, 2.0), awg("g2", "NL") }, w, home);
        const AttemptResult r = s.tap(UserChoice::automatic());
        row("E4 payload complete past the check's limit (slow)", s, r, 0);
        CHECK(r.connected && r.path.id.id == QLatin1String("g1") && r.paths == 1);
        // a check that never answers is judged by the backstop: no data, recorded
        stopLive(s);
        const AttemptResult r2 = s.tap(UserChoice::exactPath(QStringLiteral("g2")));
        CHECK(!r2.connected && r2.reason == FailReason::ExactNodeFailed);
        CHECK(s.reports.last().outcome == PathOutcome::NoData && s.reports.last().path.id == QLatin1String("g2"));
    }

    // E9: a preferred country whose paths all failed here before does not burn the budget ahead of the path that
    // works elsewhere: one leg, the fallback notice, the preference kept.
    {
        World w;
        w.set(k, QStringLiteral("nl"), Behaviour::works(300, 400, 100));
        Sim s({ awg("de1", "DE"), xray("de2", "DE"), xray("de3", "DE"), awg("nl", "NL") }, w, home);
        for (const char *id : { "de1", "de2", "de3" })
            s.ledger.record(k, PathId{ QString::fromLatin1(id), QStringLiteral("r1") }, PathOutcome::NoHandshake, s.wall());
        s.ledger.record(k, PathId{ QStringLiteral("nl"), QStringLiteral("r1") }, PathOutcome::DataOk, s.wall(), 300, 100);
        const AttemptResult r = s.tap(UserChoice::preferCountry(QStringLiteral("DE")));
        row("E9 preferred country failed here before", s, r, 0);
        CHECK(r.connected && r.paths == 1 && r.path.id.id == QLatin1String("nl") && r.fallbackNotice);
        CHECK(s.owner.choice().kind == UserChoice::Kind::PreferCountry && s.owner.choice().country == QLatin1String("DE"));
    }
}

// --- Stage 2: the probe race in front of the owner (path/PathRace.h) --------------------------------------------

static ProberCaps hostCaps()
{
    ProberCaps c;
    c.available = true; // the iPhone Air spike: 6 legs, 1 provider profile at a time, 2 AmneziaWG
    return c;
}

// Device round 19.11: the Wi-Fi and the LTE trace (see scenarioRace, 8). Returns the time from the tap to data.
struct TraceRun {
    AttemptResult result;
    qint64 ms = 0;
    QStringList legs;
    int yields = 0;
    QStringList picks; // the paths the owner raised, "*" = the lead of a proof
};

static TraceRun runTrace1911(bool lteNet, Sim::Rule rule)
{
    const NetworkObservation net = lteNet ? cell("25099", "lte") : wifi("192.168.19.1");
    const QString k = key(net);
    World w;
    if (lteNet) {
        w.set(k, QStringLiteral("16"), Behaviour::noData(2000));        // shakes hands at 1.95-2.15 s, carries nothing
        w.setProbe(k, QStringLiteral("16"), ProbeBehaviour::silent()); // its probe never proved (d1_1-3: no probe_ok)
        w.set(k, QStringLiteral("11:xray"), Behaviour::works(1900, 1500, 700));
        w.setProbe(k, QStringLiteral("11:xray"), ProbeBehaviour::ok(1240)); // probe_ms 1098-1360
        w.set(k, QStringLiteral("17"), Behaviour::works(2110, 1400, 600));
        w.setProbe(k, QStringLiteral("17"), ProbeBehaviour::ok(950));       // 928-979
        w.set(k, QStringLiteral("15"), Behaviour::works(2160, 1200, 400));
        w.setProbe(k, QStringLiteral("15"), ProbeBehaviour::ok(920));       // 634-938
    } else {
        w.set(k, QStringLiteral("16"), Behaviour::works(2150, 1600, 600));  // the blind leg WORKS on this Wi-Fi
        w.setProbe(k, QStringLiteral("16"), ProbeBehaviour::ok(750));       // AmneziaWG probes 624-832 ms here
        w.set(k, QStringLiteral("11:xray"), Behaviour::works(2060, 1500, 700));
        w.setProbe(k, QStringLiteral("11:xray"), ProbeBehaviour::ok(1040)); // 1033-1049
        w.set(k, QStringLiteral("17"), Behaviour::works(2070, 1310, 500));
        w.setProbe(k, QStringLiteral("17"), ProbeBehaviour::ok(830));       // 624-832
        w.set(k, QStringLiteral("15"), Behaviour::works(2100, 1300, 400));
        w.setProbe(k, QStringLiteral("15"), ProbeBehaviour::ok(900));
    }
    const QList<PathCandidate> pool = { awg("16", "RS", false, 3.0), xray("11:xray", "FI"), awg("17", "EE"),
                                        awg("15", "EE") };
    Sim s(pool, w, net);
    s.caps = hostCaps();
    s.stopMs = 850;
    s.starveShareMs = 1000;
    s.rule = rule;
    TraceRun t;
    t.result = s.raceTap(UserChoice::automatic());
    t.ms = s.lastTapWallMs();
    t.legs = legPaths(s);
    t.yields = s.yields;
    return t;
}

// Device round 19.11 evening (LTE, build 6bdda3644): the first server of every kind was dead at that hour - Serbia 1
// AmneziaWG and our Xray entry carried no data, the first provider profile neither; Estonia 3 AmneziaWG and the second
// provider profile worked. The race probed the three first candidates, its cap was used up by their reservations
// (11 KB really spent), it ended with nothing proven, and the walk then spent about 6 s on each of the same three:
// first connect 17-24 s, or none within the tester's 17 s.
static void scenarioHostileCellular1911()
{
    const NetworkObservation lte = cell("", "lte");
    const QString k = key(lte);
    World w;
    w.set(k, QStringLiteral("16"), Behaviour::noData(2000));
    w.setProbe(k, QStringLiteral("16"), ProbeBehaviour::fail(1500));
    w.set(k, QStringLiteral("11:xray"), Behaviour::noData(1900));
    w.setProbe(k, QStringLiteral("11:xray"), ProbeBehaviour::fail(3000));
    w.set(k, QStringLiteral("up:dead"), Behaviour::noData(800));
    w.setProbe(k, QStringLiteral("up:dead"), ProbeBehaviour::fail(3000));
    w.set(k, QStringLiteral("17"), Behaviour::works(2100, 1300, 400));
    w.setProbe(k, QStringLiteral("17"), ProbeBehaviour::ok(950, 30 * 1024));
    w.set(k, QStringLiteral("up:good"), Behaviour::works(800, 1200, 500));
    w.setProbe(k, QStringLiteral("up:good"), ProbeBehaviour::ok(1400, 45 * 1024));
    const QList<PathCandidate> pool = { awg("16", "RS", false, 3.0), xray("11:xray", "FI"),
                                        prov("up:dead", UpstreamKind::Country, "NL", 0), awg("17", "EE"),
                                        prov("up:good", UpstreamKind::Country, "PL", 1) };
    Sim s(pool, w, lte);
    s.caps = hostCaps();
    s.stopMs = 850;
    s.starveShareMs = 1000;
    s.rule = Sim::Rule::Proposed;
    s.bytesLeft = RaceTimings().cellularMaxBytes;
    const AttemptResult r = s.raceTap(UserChoice::automatic());
    const QStringList legs = legPaths(s);
    g_rows.append({ QStringLiteral("hostile LTE 19.11: first of every kind dead"),
                    r.connected ? QStringLiteral("connected ") + r.path.id.id : QStringLiteral("failed"),
                    s.lastTapWallMs(), r.paths, legs.join(QLatin1Char(' ')) });
    CHECK(r.connected);
    CHECK(r.path.id.id == QLatin1String("17") || r.path.id.id == QLatin1String("up:good"));
    // the walk does not go through the three servers the race has just seen fail
    CHECK(!legs.contains(QStringLiteral("11:xray")) && !legs.contains(QStringLiteral("up:dead")));
    CHECK(legs.size() <= 2);
    CHECK(s.lastTapWallMs() <= 9000); // the device took 17-24 s
}

// Device round 19.11 night (LTE, build b3381533f, empty ledger): the probes were out but none had answered when the
// race's wait ended (dead first candidates answer only by their timeouts, the working provider waits its turn). The
// blind leg went to node 16 - whose probe was in flight - so that probe was cancelled, the host scan was reset and
// every other probe started again; 3 s later the next leg did the same, and the race ended with nothing proven:
// 2 connects of 6 within 17 s. The walk now prefers a candidate nobody is probing.
static void scenarioBlindLegBesideSlowProbes()
{
    const NetworkObservation lte = cell("", "lte");
    const QString k = key(lte);
    World w;
    w.set(k, QStringLiteral("16"), Behaviour::noData(2000));
    w.setProbe(k, QStringLiteral("16"), ProbeBehaviour::fail(3900));
    w.set(k, QStringLiteral("11:xray"), Behaviour::noData(1900));
    w.setProbe(k, QStringLiteral("11:xray"), ProbeBehaviour::fail(3900));
    w.set(k, QStringLiteral("up:dead"), Behaviour::noData(800));
    w.setProbe(k, QStringLiteral("up:dead"), ProbeBehaviour::fail(3900));
    w.set(k, QStringLiteral("17"), Behaviour::works(2100, 1300, 400));
    w.setProbe(k, QStringLiteral("17"), ProbeBehaviour::ok(3500, 30 * 1024)); // slower than the race's wait
    w.set(k, QStringLiteral("15"), Behaviour::works(2100, 1300, 400));
    w.setProbe(k, QStringLiteral("15"), ProbeBehaviour::ok(900, 30 * 1024));
    const QList<PathCandidate> pool = { awg("16", "RS", false, 3.0), xray("11:xray", "FI"),
                                        prov("up:dead", UpstreamKind::Country, "NL", 0), awg("17", "EE"), awg("15", "EE") };
    Sim s(pool, w, lte);
    s.caps = hostCaps();
    s.stopMs = 850;
    s.starveShareMs = 1000;
    s.rule = Sim::Rule::Proposed;
    s.bytesLeft = RaceTimings().cellularMaxBytes;
    const AttemptResult r = s.raceTap(UserChoice::automatic());
    const QStringList legs = legPaths(s);
    g_rows.append({ QStringLiteral("LTE 19.11 night: no probe answers before the wait ends"),
                    r.connected ? QStringLiteral("connected ") + r.path.id.id : QStringLiteral("failed"),
                    s.lastTapWallMs(), r.paths, legs.join(QLatin1Char(' ')) });
    CHECK(r.connected);
    // the blind leg is not a path whose probe is in flight (16, 11:xray, up:dead and 17 are being probed)
    CHECK(!legs.isEmpty() && legs.first() == QLatin1String("15"));
    CHECK(legs.size() == 1);
    CHECK(s.lastTapWallMs() <= 7500);
}

// Lane C (device round 10, 19.11: LTE in the operator's white-list mode): our API is unreachable on every edge, our own
// AmneziaWG and Xray servers are blocked, the two white-list provider profiles (with a standby-pack entry) work, the three
// other provider profiles need the direct API to start and cannot. The device took 25-40 s for the first connect (3.0 s
// session wait, then 6 s per leg through the dead ones), and from the second tap walked servers that cannot start.
static void scenarioWhitelistNetworkNoControlPlane()
{
    const NetworkObservation lte = cell("", "lte");
    const QString k = key(lte);
    const auto build = [&](ApiReach reach, bool restrictedNet, const NetworkObservation &net) {
        const QString nk = key(net);
        World w;
        w.set(nk, QStringLiteral("16"), restrictedNet ? Behaviour::noHandshake() : Behaviour::works(2100, 1300, 400));
        w.set(nk, QStringLiteral("11:xray"), restrictedNet ? Behaviour::noData(1900) : Behaviour::works(2100, 1300, 400));
        for (const char *id : { "up:n1", "up:n2", "up:n3" })
            w.set(nk, QString::fromLatin1(id), Behaviour::noHandshake()); // needs the lease over the dead API
        w.set(nk, QStringLiteral("up:w1"), Behaviour::works(800, 1200, 500));
        w.set(nk, QStringLiteral("up:w2"), Behaviour::works(800, 1200, 500));
        PathCandidate w1 = prov("up:w1", UpstreamKind::Whitelist, "", 5), w2 = prov("up:w2", UpstreamKind::Whitelist, "", 6);
        w1.standbyEntry = w2.standbyEntry = true;
        const QList<PathCandidate> pool = { awg("16", "RS"), xray("11:xray", "FI"),
                                            prov("up:n1", UpstreamKind::Country, "NL", 0),
                                            prov("up:n2", UpstreamKind::Country, "PL", 1),
                                            prov("up:n3", UpstreamKind::Country, "DE", 2), w1, w2 };
        auto s = std::make_unique<Sim>(pool, w, net);
        s->caps = hostCaps();
        s->caps.ready = false; // the race's session cannot come over the dead API
        s->caps.preparing = true;
        s->stopMs = 850;
        s->starveShareMs = 1000;
        s->rule = Sim::Rule::Proposed;
        s->bytesLeft = RaceTimings().cellularMaxBytes;
        s->controlPlane = reach;
        return s;
    };
    {
        // first tap, empty ledger: a white-list provider with a pack entry, no non-pack leg, no session wait
        auto s = build(ApiReach::Unreachable, true, lte);
        const AttemptResult r = s->raceTap(UserChoice::automatic());
        const QStringList legs = legPaths(*s);
        g_rows.append({ QStringLiteral("white-list LTE, API dead: first tap"),
                        r.connected ? QStringLiteral("connected ") + r.path.id.id : QStringLiteral("failed"),
                        s->lastTapWallMs(), r.paths, legs.join(QLatin1Char(' ')) });
        CHECK(r.connected && r.path.id.id == QLatin1String("up:w1"));
        CHECK(legs == QStringList({ "up:w1" }));
        CHECK(s->lastTapWallMs() <= 4000);
        CHECK(s->probesStarted == 0); // no race bytes on a session that cannot come
        // Stop, the next tap: the proven server leads and starts at once
        s->deliver(AttemptEvent::userStop(s->now));
        s->idle(2000);
        const int from = s->legs.size();
        const AttemptResult r2 = s->raceTap(UserChoice::automatic());
        g_rows.append({ QStringLiteral("white-list LTE, API dead: second tap"),
                        r2.connected ? QStringLiteral("connected ") + r2.path.id.id : QStringLiteral("failed"),
                        s->lastTapWallMs(), r2.paths, legPaths(*s, from).join(QLatin1Char(' ')) });
        CHECK(r2.connected && r2.path.id.id == QLatin1String("up:w1"));
        CHECK(legPaths(*s, from) == QStringList({ "up:w1" }));
        CHECK(s->lastTapWallMs() <= 2500);
    }
    {
        // a wrong first white-list server: the walk goes to the other one before anything else
        auto s = build(ApiReach::Unreachable, true, lte);
        s->world().set(k, QStringLiteral("up:w1"), Behaviour::noHandshake());
        const AttemptResult r = s->raceTap(UserChoice::automatic());
        CHECK(r.connected && r.path.id.id == QLatin1String("up:w2"));
        CHECK(legPaths(*s) == QStringList({ "up:w1", "up:w2" }));
    }
    {
        // the mirror: Wi-Fi with the control plane dead - the usual order (own servers first), nothing moved to the
        // white-list seats; the providers that need the API are still not offered
        const NetworkObservation home = wifi("192.168.1.1");
        auto s = build(ApiReach::Unreachable, false, home);
        const AttemptResult r = s->raceTap(UserChoice::automatic());
        const QStringList legs = legPaths(*s);
        g_rows.append({ QStringLiteral("Wi-Fi, API dead (mirror)"),
                        r.connected ? QStringLiteral("connected ") + r.path.id.id : QStringLiteral("failed"),
                        s->lastTapWallMs(), r.paths, legs.join(QLatin1Char(' ')) });
        CHECK(r.connected && !legs.isEmpty() && legs.first() != QLatin1String("up:w1") && legs.first() != QLatin1String("up:w2"));
        CHECK(!legs.contains(QStringLiteral("up:n1")) && !legs.contains(QStringLiteral("up:n2")) && !legs.contains(QStringLiteral("up:n3")));
    }
    {
        // control plane back (Reachable): the non-pack providers are candidates again, the prior is off
        auto s = build(ApiReach::Reachable, true, lte);
        SelectInput in;
        in.pool = s->pool();
        in.controlPlane = ApiReach::Reachable;
        QStringList ids;
        for (const RankedPath &r : selectPaths(in))
            ids << r.path.id.id;
        CHECK(ids.contains(QStringLiteral("up:n1")) && ids.contains(QStringLiteral("up:n2")) && ids.contains(QStringLiteral("up:n3")));
        SelectInput dead = in;
        dead.controlPlane = ApiReach::Unreachable;
        ids.clear();
        for (const RankedPath &r : selectPaths(dead))
            ids << r.path.id.id;
        CHECK(!ids.contains(QStringLiteral("up:n1")) && ids.contains(QStringLiteral("up:w1")));
        SelectInput unk = in;
        unk.controlPlane = ApiReach::Unknown;
        CHECK(selectPaths(unk).size() == in.pool.size()); // UNKNOWN: nothing skipped
        // an exact choice of a non-pack provider is the person's: not skipped even with the API dead
        dead.choice = UserChoice::exactPath(QStringLiteral("up:n1"));
        CHECK(selectPaths(dead).size() == 1);
    }
    {
        // Round 9, R5b: the C1 filter is an optimisation, never a reason to have nothing to try: with only providers
        // that need the control plane left for this mode, they are offered (Unreachable, Xray mode)
        const QList<PathCandidate> pool = { prov("up:n1", UpstreamKind::Country, "NL", 0), prov("up:n2", UpstreamKind::Country, "PL", 1) };
        SelectInput in;
        in.pool = pool;
        in.mode = TransportMode::Xray;
        in.controlPlane = ApiReach::Unreachable;
        CHECK(selectPaths(in).size() == 2);
        CHECK(!controlPlaneFilterActive(pool, in.mode, in.tried, in.controlPlane, false));
        // with something else to try the filter still applies
        PathCandidate w = prov("up:w1", UpstreamKind::Whitelist, "", 5);
        w.standbyEntry = true;
        in.pool = pool + QList<PathCandidate>{ w };
        CHECK(selectPaths(in).size() == 1);
        // and once the only path that does not need it was tried, the rest is offered again
        in.tried.insert(QStringLiteral("up:w1"));
        CHECK(selectPaths(in).size() == 2);
    }
    {
        // C3: the prior needs cellular, an unreachable control plane and no proof; a proof cancels it
        const QList<PathCandidate> pool = [] {
            PathCandidate w = prov("up:w1", UpstreamKind::Whitelist, "", 5);
            w.standbyEntry = true;
            return QList<PathCandidate>{ awg("16", "RS"), prov("up:n1", UpstreamKind::Country, "NL", 0), w };
        }();
        const QHash<QString, PathView> none;
        CHECK(restrictedNetworkPrior(pool, none, ApiReach::Unreachable, true).contains(QStringLiteral("up:w1")));
        CHECK(restrictedNetworkPrior(pool, none, ApiReach::Unreachable, false).isEmpty());
        CHECK(restrictedNetworkPrior(pool, none, ApiReach::Unknown, true).isEmpty());
        CHECK(restrictedNetworkPrior(pool, none, ApiReach::Reachable, true).isEmpty());
        QHash<QString, PathView> proof;
        PathView v;
        v.state = PathState::Working;
        proof.insert(QStringLiteral("16"), v);
        CHECK(restrictedNetworkPrior(pool, proof, ApiReach::Unreachable, true).isEmpty());
    }
}

static void scenarioTrace1911()
{
    struct Case {
        const char *name;
        bool lte;
        Sim::Rule rule;
    };
    const Case cases[] = {
        { "trace 19.11 Wi-Fi, old (blind at once, starve only)", false, Sim::Rule::Old },
        { "trace 19.11 Wi-Fi, current (blind yields to a proof)", false, Sim::Rule::Current },
        { "trace 19.11 Wi-Fi, proposed (race first, proof leads)", false, Sim::Rule::Proposed },
        { "trace 19.11 LTE, old (blind at once, starve only)", true, Sim::Rule::Old },
        { "trace 19.11 LTE, current (blind yields to a proof)", true, Sim::Rule::Current },
        { "trace 19.11 LTE, proposed (race first, proof leads)", true, Sim::Rule::Proposed },
    };
    QHash<QString, TraceRun> runs;
    for (const Case &c : cases) {
        const TraceRun t = runTrace1911(c.lte, c.rule);
        runs.insert(QString::fromLatin1(c.name), t);
        g_rows.append({ QString::fromLatin1(c.name),
                        t.result.connected ? QStringLiteral("connected ") + t.result.path.id.id : QStringLiteral("failed"),
                        t.ms, t.result.paths, t.legs.join(QLatin1Char(' ')) });
    }
    const auto ms = [&](int i) { return runs.value(QString::fromLatin1(cases[i].name)).ms; };
    const auto run = [&](int i) { return runs.value(QString::fromLatin1(cases[i].name)); };
    // The emulation of the earlier builds reproduces the device (calibration of the stage numbers): Wi-Fi old 3.7-3.9 s,
    // current 5.56 s; LTE old 7.5-8.2 s, current 5.59 s - each within half a second.
    CHECK(run(0).result.connected && run(0).legs == QStringList({ "16" }) && ms(0) >= 3300 && ms(0) <= 4300);
    CHECK(run(1).result.connected && run(1).yields == 1 && ms(1) >= 5100 && ms(1) <= 6100);
    CHECK(run(3).result.connected && run(3).legs.first() == QLatin1String("16") && ms(3) >= 7000 && ms(3) <= 8700);
    CHECK(run(4).result.connected && run(4).yields == 1 && ms(4) >= 5100 && ms(4) <= 6100);
    // Current on LTE: on the device (d1b_1-3) the leg after the proof of Finland 1 Xray went to an Estonia AmneziaWG
    // path (the choice after the stop, when later probe proofs ranked first). Since kinds take turns inside one
    // attempt (PathSelect.h 5a) the emulation picks the other kind after the AmneziaWG leg failed: Finland 1 Xray.
    CHECK(run(4).legs.size() == 2 && run(4).legs.at(1) == QLatin1String("11:xray"));
    // Proposed: no leg is raised blind on either trace (the first proof comes before the race's wait is over), so no leg
    // yields - the yield of a blind leg stays for networks where nothing proves within the wait (race 1, "race wait
    // over"). The first leg is the path the race proved first, and it beats the
    // current rule on both networks and the old rule on LTE; on Wi-Fi it pays at most the first proof over the old
    // rule's lucky blind leg (the price of not betting).
    for (int i : { 2, 5 }) {
        CHECK(run(i).result.connected && run(i).yields == 0 && run(i).legs.size() == 1);
        CHECK(ms(i) < ms(i - 1));
    }
    CHECK(ms(5) < ms(3));
    CHECK(ms(2) <= ms(0) + 1000);
    CHECK(run(2).legs.first() == QLatin1String("16")); // Wi-Fi: Serbia 1 proved first (it works here) and leads
    CHECK(run(5).legs.first() != QLatin1String("16")); // LTE: never the path that carries nothing
}

static void scenarioRace()
{
    const NetworkObservation home = wifi("192.168.9.1");
    const QString k = key(home);

    // 1. Hostile home Wi-Fi, first connect (the 17.11 world, the working provider ordered late): stage 1 against the
    //    race. Target: data in under 7 s with the race.
    {
        Sim plain(pool1711(false), world1711(k), home);
        const AttemptResult r1 = plain.tap(UserChoice::automatic());
        row("race 1: hostile Wi-Fi, stage 1 (no host)", plain, r1, 0);
        Sim s(pool1711(false), world1711(k), home);
        s.caps = hostCaps();
        const AttemptResult r = s.raceTap(UserChoice::automatic());
        row("race 1: hostile Wi-Fi, first connect with the race", s, r, 0);
        CHECK(r.connected && s.lastTapWallMs() < 7000);
        CHECK(!r1.connected || plain.lastTapWallMs() > s.lastTapWallMs()); // stage 1 walks the blocked paths first
        CHECK(r.paths <= 2); // the owner starts with a probe-proven path
        // the second tap: the proven path is known - it starts at once, the race runs over the rest beside it
        stopLive(s);
        const int from = int(s.legs.size());
        const AttemptResult r2 = s.raceTap(UserChoice::automatic());
        row("race 1: second tap (known path at once)", s, r2, from);
        CHECK(r2.connected && r2.path.id.id == r.path.id.id && r2.paths == 1 && s.ownerStartedMs == s.legs[from].startedMs);
    }

    // 2. The Xray-15 blind spot: the probe passes, the real tunnel carries nothing. The tunnel's no-data outranks the
    //    probe: the path is not picked again by the race (a later probe ok does not lift it).
    {
        World w;
        w.set(k, QStringLiteral("15:xray"), Behaviour::noData(500));
        w.setProbe(k, QStringLiteral("15:xray"), ProbeBehaviour::ok(400));
        w.set(k, QStringLiteral("16"), Behaviour::works(800, 400, 120));
        w.setProbe(k, QStringLiteral("16"), ProbeBehaviour::ok(1200));
        Sim s({ xray("15:xray", "EE", false, 3.0), awg("16", "NL", /*manual=*/true) }, w, home); // 15 is the first choice
        s.caps = hostCaps();
        const AttemptResult r = s.raceTap(UserChoice::automatic());
        row("race 2: Xray-15 blind spot, tap 1", s, r, 0);
        CHECK(r.connected && r.path.id.id == QLatin1String("16") && legPaths(s) == QStringList({ "15:xray", "16" }));
        CHECK(stateOf(s, xray("15:xray", "EE")) == PathState::Suspect);
        stopLive(s);
        for (int tap = 2; tap <= 4; ++tap) {
            const int from = int(s.legs.size());
            const AttemptResult rn = s.raceTap(UserChoice::automatic());
            CHECK(rn.connected && legPaths(s, from) == QStringList({ "16" })); // 15 is probed (ok) but never raised
            CHECK(stateOf(s, xray("15:xray", "EE")) == PathState::Suspect);
            stopLive(s);
        }
        row("race 2: Xray-15 blind spot, taps 2-4 (15 probed, never raised)", s, s.results.last(), int(s.legs.size()) - 1);
    }

    // 3. The probe says alive but the leg does not come up (no handshake in the tunnel): the owner walks on to the next
    //    proven path; the handshake failure is recorded, a later probe ok may lift it (it is not a no-data).
    {
        World w;
        w.setProbe(k, QStringLiteral("17"), ProbeBehaviour::ok(500));
        w.set(k, QStringLiteral("12"), Behaviour::works(900, 400, 150));
        Sim s({ awg("17", "EE", false, 2.0), awg("12", "DE") }, w, home);
        s.caps = hostCaps();
        const AttemptResult r = s.raceTap(UserChoice::automatic());
        row("race 3: probe alive, leg fails", s, r, 0);
        CHECK(r.connected && r.path.id.id == QLatin1String("12") && legPaths(s) == QStringList({ "17", "12" }));
    }

    // 4. Race results arriving after the network changed are dropped; the owner starts on the new network.
    {
        World w;
        const NetworkObservation lte = cell("25001", "lte");
        // (the hedged first choice 17 is never probed beside its own leg: the spare 12 carries the late answer)
        w.setProbe(k, QStringLiteral("12"), ProbeBehaviour::ok(2500));
        w.set(key(lte), QStringLiteral("17"), Behaviour::works(700, 400, 120));
        Sim s({ awg("17", "EE", false, 2.0), awg("12", "DE") }, w, home);
        s.caps = hostCaps();
        s.changeNetworkAt(1000, lte);
        const AttemptResult r = s.raceTap(UserChoice::automatic());
        row("race 4: results after a network change", s, r, 0);
        CHECK(r.connected && s.raceLog.contains(QStringLiteral("done:network_changed")));
        CHECK(s.ledger.view(k, awg("12", "DE").id, s.wall()).state == PathState::Unknown); // the late probe ok: dropped
    }

    // 5. Cellular budget exhausted: no probe can be paid - one path at a time, exactly as stage 1.
    {
        const NetworkObservation lte = cell("25002", "lte");
        Sim s(pool1711(false), world1711(key(lte)), lte);
        s.caps = hostCaps();
        s.bytesLeft = 20 * 1024;
        const AttemptResult r = s.raceTap(UserChoice::automatic());
        Sim plain(pool1711(false), world1711(key(lte)), lte);
        const AttemptResult r1 = plain.tap(UserChoice::automatic());
        row("race 5: cellular budget exhausted", s, r, 0);
        CHECK(s.probesStarted == 0 && s.raceLog.contains(QStringLiteral("done:bytes")));
        CHECK(r.connected == r1.connected && legPaths(s) == legPaths(plain));
    }

    // 6. Provider probe seats whose batch answer is lost: at most providerPerRace such seats per race (each lives until
    //    the server's 60 s probe TTL); the race and the attempt go on.
    {
        World w;
        QList<PathCandidate> pool;
        for (int i = 0; i < 6; ++i) {
            const QByteArray id = "up:p" + QByteArray::number(i);
            pool << prov(id.constData(), UpstreamKind::Country, "NL", i);
            w.setProbe(k, QString::fromLatin1(id), ProbeBehaviour::lostAnswer());
        }
        pool << awg("11", "FI", true);
        w.set(k, QStringLiteral("11"), Behaviour::works(1500, 600, 200));
        Sim s(pool, w, home);
        s.caps = hostCaps();
        const AttemptResult r = s.raceTap(UserChoice::automatic());
        row("race 6: provider probe seat answers lost", s, r, 0);
        CHECK(r.connected && r.path.id.id == QLatin1String("11"));
        CHECK(s.providerProbes <= s.race.timings().providerPerRace && s.lostSeatAnswers <= s.race.timings().providerPerRace);
    }

    // 8. Device round 19.11 (iPhone Air, Auto, empty ledger, race on) - the two traces under the three rules (Sim::Rule).
    //    Stage numbers from the journals of build 74da6399f (air8: d2_1-3 Wi-Fi, d1b_1-3 LTE; leg start -> tunnel up,
    //    tunnel up -> data proven, probe start -> proof), a stop ~0.85 s (0.41-1.12 s yield -> next leg), the starving
    //    share of the data check 1 s (WhoamiVerdict.h). Device: Wi-Fi 3.7-3.9 s (Old), 5.56 s (Current); LTE 7.5-8.2 s
    //    (Old), 5.59 s (Current). Pool in the device's order: Serbia 1 AmneziaWG (16) first, Finland 1 own Xray, Estonia.
    scenarioTrace1911();
    scenarioHostileCellular1911();
    scenarioBlindLegBesideSlowProbes();
    scenarioWhitelistNetworkNoControlPlane();
    // F5 of device round 19.11: the byte cap is a real cap. A probe starts only when real bytes spent + what the probes
    // in flight hold + its own bound fit; a candidate the cap cannot pay does not block the cheaper ones behind it.
    // (Rewritten for the real-byte cap: a result no longer carries a byte number, spent() does.)
    {
        NetworkTracker tr;
        tr.observe(cell("", "lte"));
        PathRace::Costs costs;
        costs.awg = 45000;
        costs.xray = 110000;
        costs.provider = 320000;
        const QList<PathCandidate> list = { xray("x1", "FI"), prov("up:p", UpstreamKind::Country, "NL", 0), xray("x2", "DE"),
                                            awg("a1", "EE"), awg("a2", "NL"), xray("x3", "NL") };
        RaceTimings rt;
        rt.hedgeMs = 5000;
        PathRace race(rt);
        const qint64 cap = 262144;
        qint64 projected = 0;
        QStringList started;
        QList<RaceEffect> fx = race.begin(0, list, tr.current(), hostCaps(), cap, costs);
        bool bytesDone = false;
        for (qint64 t = 0; t <= 6000; t += 250) {
            if (t > 0)
                fx << race.tick(t);
            while (!fx.isEmpty()) {
                const RaceEffect e = fx.takeFirst();
                bytesDone = bytesDone || (e.type == RaceEffectType::Done && e.reason == RaceDoneReason::Bytes);
                if (e.type != RaceEffectType::StartProbe)
                    continue;
                started << e.path.id.id;
                projected += e.path.kind == PathKind::OwnXray ? costs.xray : e.path.kind == PathKind::OwnAwg ? costs.awg
                                                                                                          : costs.provider;
                CHECK(race.spentBytes() + race.reservedBytes() <= cap); // admission: spent + held (this probe too) fits
                race.spent(20000);                                       // the probe spends 20 KB, then ends without a proof
                fx << race.probeDone(t + 100, e.stamp, PathOutcome::Inconclusive);
            }
        }
        CHECK(projected > cap);            // the bounds of every probe together pass the cap: real bytes and holds gate them
        CHECK(race.spentBytes() <= cap);
        CHECK(!started.contains(QStringLiteral("up:p")) && started.contains(QStringLiteral("x1")) && started.contains(QStringLiteral("x2")));
        CHECK(!race.running());
        CHECK(started.contains(QStringLiteral("x2")));    // the provider that cannot be paid (320 000 B never fits) does not block the next
        (void)bytesDone;
    }

    // Device round 19.11 (LTE at an hour when the first server of every kind was dead): the three first probes spent
    // about 11 KB together, but their projections stayed charged, the race ended "bytes" with nothing proven and the
    // working servers behind them were never probed (first connect 17-24 s). A probe reserves its projection while
    // it runs and is charged what it spent when it ends: dead paths free the cap for the next candidates.
    {
        NetworkTracker tr;
        tr.observe(cell("", "lte"));
        PathRace::Costs costs;
        costs.awg = 54572;
        costs.xray = 116736;
        costs.provider = 107520;
        const QList<PathCandidate> list = { awg("a16", "RS"), xray("x11", "FI"), prov("up:dead", UpstreamKind::Country, "NL", 0),
                                            awg("a17", "EE"), xray("x12", "DE"), prov("up:good", UpstreamKind::Country, "PL", 0) };
        RaceTimings rt;
        rt.hedgeMs = 5000;
        PathRace race(rt);
        const qint64 cap = 327680; // the cap of that round: the fourth probe did not fit the reservations
        QStringList started, proven;
        qint64 reservedNow = 0, reservedPeak = 0, spent = 0;
        QHash<quint64, qint64> reservedOf;
        bool bytesDone = false;
        QList<RaceEffect> fx = race.begin(0, list, tr.current(), hostCaps(), cap, costs);
        QList<std::pair<qint64, RaceEffect>> answers; // (when, the StartProbe it answers)
        for (qint64 t = 0; t <= 7000; t += 250) {
            if (t > 0)
                fx << race.tick(t);
            for (int i = 0; i < answers.size();) {
                if (answers.at(i).first > t) {
                    ++i;
                    continue;
                }
                const RaceEffect st = answers.takeAt(i).second;
                const bool works = st.path.id.id == QLatin1String("a17") || st.path.id.id == QLatin1String("up:good");
                const qint64 used = works ? 45000 : 4000; // a dead path costs a few KB
                spent += used;
                reservedNow -= reservedOf.take(st.stamp.probe);
                race.spent(used);
                fx << race.probeDone(t, st.stamp, works ? PathOutcome::ProbeOk : PathOutcome::Inconclusive);
            }
            while (!fx.isEmpty()) {
                const RaceEffect e = fx.takeFirst();
                bytesDone = bytesDone || (e.type == RaceEffectType::Done && e.reason == RaceDoneReason::Bytes);
                if (e.type == RaceEffectType::Report)
                    proven << e.path.id.id;
                if (e.type == RaceEffectType::Winner)
                    race.acceptWinner(e.path.id.id);
                if (e.type != RaceEffectType::StartProbe)
                    continue;
                started << e.path.id.id;
                const qint64 r = e.path.kind == PathKind::OwnXray ? costs.xray : e.path.kind == PathKind::OwnAwg ? costs.awg
                                                                                                           : costs.provider;
                reservedOf.insert(e.stamp.probe, r);
                reservedNow += r;
                reservedPeak = std::max(reservedPeak, reservedNow + spent);
                answers.append({ t + 1500, e }); // every probe answers 1.5 s after its start
            }
        }
        CHECK(started.contains(QStringLiteral("a17")) && started.contains(QStringLiteral("up:good"))); // before: never started
        CHECK(proven.contains(QStringLiteral("a17")));
        CHECK(!bytesDone);                 // the race does not end "bytes" with 11 KB spent
        CHECK(reservedPeak <= cap);        // what is held plus what was spent never passes the cap
        CHECK(spent <= cap);
    }

    // Second review of 141, F8 (rewritten for the real-byte cap): a provider probe also spends bytes OUTSIDE the host (its
    // seat batch with the config, the release). Both streams reach the cap through spent(): with 112 640 B left a provider
    // probe that spent 40 000 B at the host and 40 000 B at the API leaves 32 640 B, and an AmneziaWG probe of 54 572 B must
    // NOT start; with the host's 40 000 B alone, 72 640 B remain and it starts.
    {
        NetworkTracker tr;
        tr.observe(cell("", "lte"));
        PathRace::Costs costs;
        costs.awg = 54572;
        costs.provider = 107520;
        const QList<PathCandidate> list = { prov("up:p", UpstreamKind::Country, "NL", 0), awg("a1", "EE") };
        RaceTimings rt;
        rt.hedgeMs = 5000;
        const auto run = [&](bool apiShare) {
            PathRace race(rt);
            QStringList started;
            ProbeStamp provider;
            for (const RaceEffect &e : race.begin(0, list, tr.current(), hostCaps(), 112640, costs))
                if (e.type == RaceEffectType::StartProbe) {
                    started << e.path.id.id;
                    provider = e.stamp;
                }
            CHECK(started == QStringList({ "up:p" })); // the AmneziaWG probe does not fit beside the hold
            race.spent(40000);                         // the host's delta
            if (apiShare)
                race.spent(40000);                     // the seat batch, config and release, as the API client spent them
            for (const RaceEffect &e : race.probeDone(1500, provider, PathOutcome::Inconclusive))
                if (e.type == RaceEffectType::StartProbe)
                    started << e.path.id.id;
            return started;
        };
        CHECK(run(true) == QStringList({ "up:p" }));             // 32 640 B left: no room for 54 572 B
        CHECK(run(false) == QStringList({ "up:p", "a1" }));      // 72 640 B left: it starts
    }

    // J5 of the sixth review (replaces G7/H6 and the *Fixed/*Outside arithmetic): a probe that never left the app (a
    // candidate refused locally: no peer, no config) spent nothing and holds nothing once it ended. With a cap of exactly
    // one Xray probe, the failed AmneziaWG probe must not take the Xray probe's place.
    {
        NetworkTracker tr;
        tr.observe(cell("", "lte"));
        PathRace::Costs costs;
        costs.awg = 54572;
        costs.xray = 116736;
        const qint64 cap = costs.awg + costs.xray; // the AmneziaWG hold, then the Xray probe fit together
        RaceTimings rt;
        rt.hedgeMs = 5000;
        rt.parallelism = 1;
        PathRace race(rt);
        QStringList started;
        ProbeStamp first;
        for (const RaceEffect &e : race.begin(0, { awg("a1", "EE"), xray("x1", "NL") }, tr.current(), hostCaps(), cap - 1000, costs))
            if (e.type == RaceEffectType::StartProbe) {
                started << e.path.id.id;
                first = e.stamp;
            }
        CHECK(started == QStringList({ "a1" }));
        CHECK(race.reservedBytes() == costs.awg && race.spentBytes() == 0);
        for (const RaceEffect &e : race.probeDone(300, first, PathOutcome::Inconclusive)) // refused locally: no bytes at all
            if (e.type == RaceEffectType::StartProbe)
                started << e.path.id.id;
        CHECK(race.spentBytes() == 0 && race.reservedBytes() == costs.xray); // nothing charged, nothing left held
        CHECK(started == QStringList({ "a1", "x1" }));                       // the Xray probe (116 736 B of 170 308) starts
    }

    // Device 19.11 evening (iPhone Air, LTE): four slow probes out, the owner's blind legs raise two of the probed paths, each
    // cancel makes the host restart the others (a new scan: its opening /netinfo again) - the old accounting reserved every
    // restart again and the race ended "bytes" with nothing proven at +6.3 s. Reservations belong to probes, a reopen moves a
    // probe without a new hold, and only real bytes count: ~45 KB of real spend against a 393 KB cap never ends the race.
    {
        NetworkTracker tr;
        tr.observe(cell("", "lte"));
        PathRace::Costs costs;
        costs.awg = 54572;
        costs.xray = 116736;
        costs.provider = 107520;
        RaceTimings rt;
        rt.hedgeMs = 20000;
        PathRace race(rt);
        const QList<PathCandidate> list = { awg("a1", "RS"), xray("x1", "FI"), prov("up:p", UpstreamKind::Country, "NL", 0),
                                            awg("a2", "EE"), xray("x2", "DE"), xray("x3", "NL"), awg("a3", "PL") };
        QStringList started;
        bool bytesDone = false;
        QList<ProbeStamp> cancelledNow;
        const auto take = [&](const QList<RaceEffect> &fx) {
            for (const RaceEffect &e : fx) {
                bytesDone = bytesDone || (e.type == RaceEffectType::Done && e.reason == RaceDoneReason::Bytes);
                if (e.type == RaceEffectType::StartProbe)
                    started << e.path.id.id;
                if (e.type == RaceEffectType::CancelProbe)
                    cancelledNow << e.stamp;
            }
        };
        take(race.begin(0, list, tr.current(), hostCaps(), 393216, costs));
        race.spent(9000);   // the scan's opening /netinfo
        for (qint64 t = 250; t <= 6300; t += 250) {
            if (t == 3000) { // the owner's blind leg takes a probed path: the host restarts the other probes in a new scan
                take(race.legStarted(t, QStringLiteral("a1")));
                race.spent(9000 + 4000); // the new scan's opening and what the restarted parts had spent
            }
            if (t == 6000) {
                take(race.legStarted(t, QStringLiteral("x1")));
                race.spent(9000 + 4000);
            }
            take(race.tick(t));
            for (const ProbeStamp &c : cancelledNow) // the host's final total of the stopped scan arrives a tick later
                race.settled(c);
            cancelledNow.clear();
        }
        CHECK(!bytesDone);                       // before: ended "bytes" at +6.3 s with nothing proven
        CHECK(race.spentBytes() >= 22000 && race.spentBytes() <= 393216 / 4); // real bytes only, far below the cap
        CHECK(started.size() >= 6);              // the candidates behind the cancelled probes were still started
    }

    // Seventh review, finding 2: a probe the race cancels (timeout) keeps its hold on the cap until its spend is final. Cap 120 KB;
    // an Xray probe really spent 90 KB but the last counter shown says 9 KB: at its timeout the AmneziaWG probe (54.6 KB) must
    // not be admitted (before: the reservation went with the probe and the race passed its cap: 90 + 36 KB of real bytes).
    {
        NetworkTracker tr;
        tr.observe(cell("", "lte"));
        PathRace::Costs costs;
        costs.awg = 54572;
        costs.xray = 100000;
        RaceTimings rt;
        rt.hedgeMs = 20000;
        rt.probeTimeoutMs = 1000;
        PathRace race(rt);
        QStringList started;
        ProbeStamp x1;
        const auto take = [&](const QList<RaceEffect> &fx) {
            for (const RaceEffect &e : fx)
                if (e.type == RaceEffectType::StartProbe) {
                    started << e.path.id.id;
                    if (e.path.id.id == QLatin1String("x1"))
                        x1 = e.stamp;
                }
        };
        take(race.begin(0, { xray("x1", "FI"), awg("a1", "EE") }, tr.current(), hostCaps(), 120000, costs));
        race.spent(9000);
        take(race.tick(2500)); // x1 times out
        CHECK(started == QStringList({ "x1" }));
        CHECK(race.spentBytes() + race.reservedBytes() >= 109000);       // still held: no room for a 54.6 KB probe
        race.spent(81000);                                               // the late counter: 90 KB in all
        take(race.tick(2750));
        race.settled(x1);
        take(race.tick(3000));
        CHECK(started == QStringList({ "x1" }));                         // 90 KB spent + 54.6 KB > 120 KB: still not admitted
        CHECK(race.spentBytes() <= 120000);
    }

    // The hold of a probe in flight is released in full however the probe ends (a result, its timeout, the owner raising its
    // path, the race's end): with a cap for exactly one probe at a time, each end lets the next one start, and nothing
    // stays held afterwards.
    {
        NetworkTracker tr;
        tr.observe(cell("", "lte"));
        PathRace::Costs costs;
        costs.awg = 50000;
        costs.xray = 50000;
        RaceTimings rt;
        rt.hedgeMs = 20000;
        rt.parallelism = 4;
        rt.probeTimeoutMs = 1000;
        PathRace race(rt);
        const QList<PathCandidate> list = { xray("x1", "FI"), xray("x2", "DE"), xray("x3", "NL"), xray("x4", "PL"), xray("x5", "SE") };
        QStringList started;
        const auto starts = [&](const QList<RaceEffect> &fx) {
            ProbeStamp last;
            for (const RaceEffect &e : fx)
                if (e.type == RaceEffectType::StartProbe) {
                    started << e.path.id.id;
                    last = e.stamp;
                }
            return last;
        };
        ProbeStamp s1 = starts(race.begin(0, list, tr.current(), hostCaps(), 60000, costs));
        CHECK(started == QStringList({ "x1" }) && race.reservedBytes() == 50000);
        const ProbeStamp s2 = starts(race.probeDone(300, s1, PathOutcome::Inconclusive)); // a result releases it
        CHECK(started == QStringList({ "x1", "x2" }) && race.reservedBytes() == 50000);
        starts(race.tick(2500));                                                           // its timeout: no candidate, still held
        CHECK(started == QStringList({ "x1", "x2" }) && race.reservedBytes() == 50000); // x2: no candidate, still held
        race.settled(s2);                                                                  // its spend is final: the hold ends
        const ProbeStamp s3 = starts(race.tick(2750));
        CHECK(started == QStringList({ "x1", "x2", "x3" }) && race.reservedBytes() == 50000);
        starts(race.legStarted(2800, QStringLiteral("x3")));                              // the owner raises its path
        CHECK(started.size() == 3 && race.reservedBytes() == 50000);                       // x3 held until settled
        race.settled(s3);
        starts(race.tick(3050));
        CHECK(started == QStringList({ "x1", "x2", "x3", "x4" }) && race.reservedBytes() == 50000);
        race.stop(3100);                                                                   // the race ends
        CHECK(race.reservedBytes() == 0 && !race.running());
    }

    // Round 16, F3: a probe that ended with a RESULT keeps holding what can still be spent for it - the seat release of a provider probe
    // (providerTail) - until the prober settles it. Cap 120 000; the provider probe's host part is counted (60 000); an AmneziaWG probe
    // (bound 54 572) fits next to that only if the release is forgotten. Before: the result released the whole hold, the AmneziaWG probe
    // was admitted and the late release took the race past its cap.
    {
        NetworkTracker tr;
        tr.observe(cell("", "lte"));
        PathRace::Costs costs;
        costs.awg = 54572;
        costs.provider = 90000;
        costs.providerTail = 20480; // kScanSeatReleaseSends x costApiBytes
        RaceTimings rt;
        rt.hedgeMs = 20000;
        rt.probeTimeoutMs = 5000;
        const auto run = [&](qint64 lateRelease, bool &admittedAfterResult, bool &admittedAfterSettle, qint64 &worstSum) {
            PathRace race(rt);
            QStringList started;
            ProbeStamp p1;
            const auto take = [&](const QList<RaceEffect> &fx) {
                for (const RaceEffect &e : fx)
                    if (e.type == RaceEffectType::StartProbe) {
                        started << e.path.id.id;
                        if (e.path.id.id == QLatin1String("up:p1"))
                            p1 = e.stamp;
                    }
            };
            const auto watch = [&]() { worstSum = std::max(worstSum, race.spentBytes() + race.reservedBytes()); };
            take(race.begin(0, { prov("up:p1", UpstreamKind::Country, "PL", 1), awg("a1", "EE") }, tr.current(), hostCaps(), 120000, costs));
            CHECK(started == QStringList({ "up:p1" })); // 90 000 + 54 572 > 120 000: the AmneziaWG probe waits
            race.spent(60000);                           // the provider probe's host part, counted
            take(race.probeDone(300, p1, PathOutcome::ProbeOk));
            watch();
            take(race.tick(550));
            admittedAfterResult = started.contains(QStringLiteral("a1"));
            CHECK(race.reservedBytes() == (admittedAfterResult ? 54572 : 20480)); // the release is what the finished probe still holds
            race.spent(lateRelease);                                              // the release chain ended: its bytes, then the settle
            race.settled(p1);
            watch();
            take(race.tick(800));
            admittedAfterSettle = started.contains(QStringLiteral("a1"));
            watch();
            race.spent(50000); // what the AmneziaWG probe really spends
            CHECK(!admittedAfterSettle || race.spentBytes() <= 120000);
            return race.spentBytes();
        };
        bool afterResult = true, afterSettle = false;
        qint64 worst = 0;
        run(5000, afterResult, afterSettle, worst); // a one-send release (5 000): 65 000 + 54 572 fit once it is settled
        CHECK(!afterResult);                         // not admitted while the release is outstanding
        CHECK(afterSettle);                          // admitted after the settle
        CHECK(worst <= 120000);                      // counted + held never passed the cap
        afterResult = afterSettle = true;
        worst = 0;
        run(19000, afterResult, afterSettle, worst); // the reviewer's numbers: 79 000 + 54 572 do not fit: never admitted
        CHECK(!afterResult && !afterSettle && worst <= 120000);
    }
    // F3, mirror: the hold of a finished probe is its release budget, kept whole until the release's bytes arrive in one lump with the
    // settle (the chain's bytes are counted once, when it ends): counted + held never exceeds spent-before + the probe's bound and
    // never goes below the bytes really counted; the race still ends (nothing stays held) when the settle comes.
    {
        NetworkTracker tr;
        tr.observe(cell("", "lte"));
        PathRace::Costs costs;
        costs.provider = 90000;
        costs.providerTail = 20480;
        costs.awg = 100000; // a candidate that waits for cap room keeps the race alive while the release is outstanding
        RaceTimings rt;
        rt.hedgeMs = 20000;
        PathRace race(rt);
        ProbeStamp p1;
        for (const RaceEffect &e : race.begin(0, { prov("up:p1", UpstreamKind::Country, "PL", 1), awg("a1", "EE") }, tr.current(), hostCaps(), 150000, costs))
            if (e.type == RaceEffectType::StartProbe)
                p1 = e.stamp;
        race.spent(40000);
        CHECK(race.spentBytes() + race.reservedBytes() == 40000 + 90000);
        race.probeDone(300, p1, PathOutcome::ProbeOk);
        CHECK(race.reservedBytes() == 20480 && race.running()); // a result at once: the winner is not delayed; only the cap room is held
        CHECK(race.spentBytes() + race.reservedBytes() <= 40000 + 90000 && race.spentBytes() + race.reservedBytes() >= race.spentBytes());
        race.spent(12000);
        race.settled(p1);
        CHECK(race.reservedBytes() == 0 && race.spentBytes() == 52000 && race.spentBytes() <= 40000 + 90000); // held once, counted once
        race.settled(p1); // a repeat changes nothing
        CHECK(race.reservedBytes() == 0 && race.spentBytes() == 52000);
        // the race ends once the settle came (an exhausted race with a hold outstanding but nothing waiting does not wait for it)
        bool done = false;
        for (qint64 t = 550; t <= 1500; t += 250)
            for (const RaceEffect &e : race.tick(t))
                done = done || e.type == RaceEffectType::Done;
        CHECK(done && !race.running());
    }
    // F3: nothing waits for the cap -> the race ends at the last result even with the release outstanding (the owner starts at once);
    // a candidate waiting for cap room keeps the race alive until the settle. The cellular first tick still admits Xray + provider +
    // AmneziaWG (116 736 + 117 760 + 54 572 <= 393 216).
    {
        NetworkTracker tr;
        tr.observe(cell("", "lte"));
        PathRace::Costs costs;
        costs.xray = 116736;
        costs.provider = 117760;
        costs.providerTail = 20480;
        costs.awg = 54572;
        RaceTimings rt;
        PathRace race(rt);
        QStringList started;
        QList<ProbeStamp> stamps;
        for (const RaceEffect &e : race.begin(0, { xray("x1", "FI"), prov("up:p1", UpstreamKind::Country, "PL", 1), awg("a1", "EE") },
                                              tr.current(), hostCaps(), RaceTimings().cellularMaxBytes, costs))
            if (e.type == RaceEffectType::StartProbe) {
                started << e.path.id.id;
                stamps << e.stamp;
            }
        for (qint64 t = 250; t <= 1000 && started.size() < 3; t += 250) // one probe starts per stagger
            for (const RaceEffect &e : race.tick(t))
                if (e.type == RaceEffectType::StartProbe) {
                    started << e.path.id.id;
                    stamps << e.stamp;
                }
        CHECK(started.size() == 3);
        bool done = false;
        for (const ProbeStamp &s : stamps)
            for (const RaceEffect &e : race.probeDone(400, s, PathOutcome::Inconclusive))
                done = done || e.type == RaceEffectType::Done;
        CHECK(done && !race.running() && race.reservedBytes() == 0); // exhausted at the last result: no wait for the release
    }

    // B3a: the first candidate works. With no evidence the race goes first: the first leg waits for the first proof
    // (here that candidate's own probe) and costs at most that probe over no race - never a dropped leg. A known path
    // (the second tap) starts at once: never slower than no race.
    {
        World w;
        w.set(k, QStringLiteral("a1"), Behaviour::works(900, 400, 120));
        w.setProbe(k, QStringLiteral("a1"), ProbeBehaviour::ok(700));
        Sim plain({ awg("a1", "EE"), awg("a2", "NL") }, w, home);
        plain.tap(UserChoice::automatic());
        Sim s({ awg("a1", "EE"), awg("a2", "NL") }, w, home);
        s.caps = hostCaps();
        const AttemptResult r = s.raceTap(UserChoice::automatic());
        row("race B3a: first candidate works", s, r, 0);
        CHECK(r.connected && r.paths == 1 && s.lastTapWallMs() <= plain.lastTapWallMs() + 700 + s.tickMs);
        CHECK(s.raceLog.contains(QStringLiteral("owner:winner")) && s.yields == 0);
        stopLive(s);
        stopLive(plain);
        const int from = int(s.legs.size());
        plain.tap(UserChoice::automatic());
        const AttemptResult r2 = s.raceTap(UserChoice::automatic());
        CHECK(r2.connected && legPaths(s, from) == QStringList({ "a1" }) && s.lastTapWallMs() <= plain.lastTapWallMs());
    }
    // Nothing proven by the race's wait (PathRace.h hedgeAfterMs, 2750 ms by default): the owner starts its first
    // choice blind and the race runs on beside it. That leg's own probe proved nothing in the wait; a proof that comes
    // while it starts is better evidence than the bet - the leg yields and the proven path is next (the lead).
    {
        World w;
        w.set(k, QStringLiteral("x2"), Behaviour::works(900, 400, 120));
        w.setProbe(k, QStringLiteral("x2"), ProbeBehaviour::ok(3000)); // proof at 3.25 s, the blind leg is starting
        const QList<PathCandidate> pool = { awg("a1", "EE", false, 2.0), xray("x2", "NL") }; // a1: no handshake here
        Sim s(pool, w, home);
        s.caps = hostCaps();
        const AttemptResult r = s.raceTap(UserChoice::automatic());
        row("race wait over: blind first choice, proof later", s, r, 0);
        CHECK(s.race.timings().hedgeAfterMs() == 2750 && s.raceLog.contains(QStringLiteral("owner:hedge")));
        CHECK(s.ownerStartedMs >= 2750 && s.ownerStartedMs <= 2750 + s.tickMs);
        CHECK(r.connected && r.path.id.id == QLatin1String("x2") && s.yields == 1 && legPaths(s) == QStringList({ "a1", "x2" }));
        CHECK(s.lastTapWallMs() < 2750 + 4500); // before the blind leg's own start deadline
    }
    // Lead: the leg after a proof goes to THAT path even when, by its start, a later proof ranks first (device round
    // 19.11 LTE: the choice after the stop took an Estonia AmneziaWG probe proof over the Finland 1 Xray proof).
    {
        World w;
        w.set(k, QStringLiteral("x1"), Behaviour::works(900, 400, 120));
        w.set(k, QStringLiteral("a2"), Behaviour::works(900, 400, 120));
        Sim s({ xray("x1", "FI"), awg("a2", "EE") }, w, home);
        s.ledger.record(k, awg("a2", "EE").id, PathOutcome::ProbeOk, s.wall(), 300);  // faster probe, outranks x1
        s.ledger.record(k, xray("x1", "FI").id, PathOutcome::ProbeOk, s.wall(), 1200);
        const auto fx = s.owner.handle(AttemptEvent::userStart(0, UserChoice::automatic(), TransportMode::Auto,
                                                               s.tracker.current(), QStringLiteral("x1")), s.ctx());
        bool leadStart = false;
        for (const AttemptEffect &e : fx)
            leadStart = leadStart || (e.type == EffectType::StartPath && e.path.id.id == QLatin1String("x1") && e.lead);
        CHECK(leadStart);
        // a lead that is not a working path here, or is behind a preferred path, does not override the order
        AttemptOwner o2;
        const auto fx2 = o2.handle(AttemptEvent::userStart(0, UserChoice::preferCountry(QStringLiteral("EE")),
                                                           TransportMode::Auto, s.tracker.current(), QStringLiteral("x1")),
                                   s.ctx());
        bool preferredFirst = false;
        for (const AttemptEffect &e : fx2)
            preferredFirst = preferredFirst || (e.type == EffectType::StartPath && e.path.id.id == QLatin1String("a2") && !e.lead);
        CHECK(preferredFirst);
        AttemptOwner o3;
        const auto fx3 = o3.handle(AttemptEvent::userStart(0, UserChoice::automatic(), TransportMode::Awg,
                                                           s.tracker.current(), QStringLiteral("x1")), s.ctx());
        bool modeWins = false;
        for (const AttemptEffect &e : fx3)
            modeWins = modeWins || (e.type == EffectType::StartPath && e.path.id.id == QLatin1String("a2") && !e.lead);
        CHECK(modeWins); // the transport mode is stronger than any proof
    }
    // B3b: the race stops at its winner plus one spare proof
    {
        World w;
        QList<PathCandidate> pool;
        for (int i = 0; i < 8; ++i) {
            const QByteArray id = "x" + QByteArray::number(i);
            pool << xray(id.constData(), "DE");
            w.set(k, QString::fromLatin1(id), Behaviour::works(600, 300, 100));
        }
        Sim s(pool, w, home);
        s.caps = hostCaps();
        s.raceTap(UserChoice::automatic());
        CHECK(s.race.proven() <= 2 + 1 && s.probesStarted < 8);
    }
    // 7. No host on the platform: exactly stage 1 (same legs, same time).
    {
        Sim a(pool1711(false), world1711(k), home);
        Sim b(pool1711(false), world1711(k), home);
        const AttemptResult ra = a.tap(UserChoice::automatic());
        const AttemptResult rb = b.raceTap(UserChoice::automatic()); // caps.available == false
        row("race 7: no host on the platform", b, rb, 0);
        CHECK(ra.connected == rb.connected && legPaths(a) == legPaths(b) && a.lastTapWallMs() == b.lastTapWallMs()
              && b.probesStarted == 0);
    }

    // The race machine itself: stale results, the stagger, the host's caps.
    {
        PathRace race;
        NetworkTracker tr;
        tr.observe(home);
        const QList<PathCandidate> list = { awg("a", "EE"), awg("b", "NL"), awg("c", "DE"), xray("d", "FI"),
                                            prov("up:e", UpstreamKind::Country, "NL", 0), prov("up:f", UpstreamKind::Country, "DE", 1) };
        QList<RaceEffect> fx = race.begin(0, list, tr.current(), hostCaps(), -1, PathRace::Costs{});
        int starts = 0;
        for (const RaceEffect &e : fx)
            starts += e.type == RaceEffectType::StartProbe;
        CHECK(starts == 1); // one per stagger
        fx = race.tick(250);
        fx << race.tick(500);
        fx << race.tick(750);
        int awg = 0, prv = 0;
        for (const RaceEffect &e : fx)
            if (e.type == RaceEffectType::StartProbe) {
                awg += e.path.kind == PathKind::OwnAwg;
                prv += e.path.kind == PathKind::Provider;
            }
        CHECK(race.inFlight() <= 4 && awg <= 1); // two AmneziaWG at once (a + b), the third waits
        const ProbeStamp old{ race.raceNumber() + 7, tr.current().generation, 1 };
        CHECK(race.probeDone(800, old, PathOutcome::ProbeOk).isEmpty()); // another race: dropped
    }
    // CONNECT-INVARIANTS §32 p. 3 (device round 19.11: the hedged leg's own AmneziaWG node was probe 1 of every race,
    // with the device's key beside the leg coming up): the path the owner raises leaves the race - its probe in
    // flight is cancelled, it is never started again in that race; the others go on.
    {
        NetworkTracker tr;
        tr.observe(home);
        const QList<PathCandidate> list = { awg("a", "EE"), awg("b", "NL"), xray("c", "FI") };
        // hedge at once (race_hedge_ms = 0): the first candidate is the leg raised now - never probed
        {
            RaceTimings atOnce;
            atOnce.hedgeMs = 0;
            PathRace race(atOnce);
            QStringList started;
            for (const RaceEffect &e : race.begin(0, list, tr.current(), hostCaps(), -1, PathRace::Costs{}))
                if (e.type == RaceEffectType::StartProbe)
                    started << e.path.id.id;
            for (qint64 t = 250; t <= 2000; t += 250)
                for (const RaceEffect &e : race.tick(t))
                    if (e.type == RaceEffectType::StartProbe)
                        started << e.path.id.id;
            CHECK(started == QStringList({ "b", "c" }));
        }
        RaceTimings later;
        later.hedgeMs = 5000; // the owner's leg comes later: its probe in flight is cancelled then
        PathRace race(later);
        QList<RaceEffect> fx = race.begin(0, list, tr.current(), hostCaps(), -1, PathRace::Costs{});
        CHECK(fx.size() >= 1 && fx.first().type == RaceEffectType::StartProbe && fx.first().path.id.id == QLatin1String("a"));
        const ProbeStamp a = fx.first().stamp;
        fx = race.legStarted(10, QStringLiteral("a"));
        bool cancelled = false;
        for (const RaceEffect &e : fx)
            cancelled = cancelled || (e.type == RaceEffectType::CancelProbe && e.stamp == a);
        CHECK(cancelled && race.inFlight() == 0);
        QStringList started;
        for (qint64 t = 250; t <= 2000; t += 250)
            for (const RaceEffect &e : race.tick(t))
                if (e.type == RaceEffectType::StartProbe)
                    started << e.path.id.id;
        CHECK(started == QStringList({ "b", "c" }));
        CHECK(race.probeDone(2100, a, PathOutcome::ProbeOk).isEmpty()); // its late answer: dropped
        // a path still waiting in the window leaves it too
        PathRace r2(later);
        r2.begin(0, list, tr.current(), hostCaps(), -1, PathRace::Costs{});
        r2.legStarted(10, QStringLiteral("c"));
        QStringList s2;
        for (qint64 t = 250; t <= 2000; t += 250)
            for (const RaceEffect &e : r2.tick(t))
                if (e.type == RaceEffectType::StartProbe)
                    s2 << e.path.id.id;
        CHECK(s2 == QStringList({ "b" }));
    }
}

// --- Device round 4, R1: what is not the path's fault never enters the ledger ------------------------------------

static void scenarioAttribution()
{
    const NetworkObservation home = wifi("192.168.4.1");
    const QString k = key(home);
    // Control plane down right after a launch: the remembered path's checks cannot reach our endpoints (the tunnel
    // carries data) - the path stays "working", nothing is recorded, the attempt ends without blaming it.
    {
        World w;
        w.set(k, QStringLiteral("17"), Behaviour::works(600, 300, 100));
        Sim s({ awg("17", "EE"), awg("16", "NL") }, w, home);
        CHECK(s.tap(UserChoice::automatic()).connected);
        stopLive(s);
        s.world().set(k, QStringLiteral("17"), Behaviour::controlPlaneDown(600));
        s.world().set(k, QStringLiteral("16"), Behaviour::controlPlaneDown(600));
        const int reports = int(s.reports.size());
        const int from = int(s.legs.size());
        const AttemptResult r = s.tap(UserChoice::automatic());
        row("R1: control plane down after launch", s, r, from);
        CHECK(!r.connected && s.reports.size() == reports);
        CHECK(stateOf(s, awg("17", "EE")) == PathState::Working); // still the remembered path
        CHECK(legPaths(s, from).first() == QLatin1String("17") && s.rechecks >= 1);
    }
    // Slow control plane: the provider's lease answer comes after the lease share (a transport failure of OUR
    // request): the leg ends, the path is not refused; the next tap tries it again.
    {
        World w;
        w.set(k, QStringLiteral("up:sw"), Behaviour::startError(/*attributable=*/false));
        w.set(k, QStringLiteral("16"), Behaviour::works(800, 300, 100));
        Sim s({ prov("up:sw", UpstreamKind::Country, "CH", 0), awg("16", "NL") }, w, home);
        const AttemptResult r = s.tap(UserChoice::preferCountry(QStringLiteral("CH")));
        row("R1: slow lease answer (control plane)", s, r, 0);
        CHECK(r.connected && stateOf(s, prov("up:sw", UpstreamKind::Country, "CH", 0)) == PathState::Unknown);
        stopLive(s);
        const int from = int(s.legs.size());
        s.tap(UserChoice::preferCountry(QStringLiteral("CH")));
        CHECK(legPaths(s, from).first() == QLatin1String("up:sw")); // not skipped for an error that was ours
    }
    // A request stretched by a suspension: the check is run again, nothing is recorded.
    {
        World w;
        w.set(k, QStringLiteral("wl"), PathScript::always(Behaviour::silent(400)).then(10000, Behaviour::works(400, 300, 100)));
        Sim s({ prov("wl", UpstreamKind::Whitelist, "", 0) }, w, home);
        s.suspend(1000, 13800);
        const AttemptResult r = s.tap(UserChoice::automatic());
        row("R1: check stretched by a suspension", s, r, 0);
        CHECK(r.connected && s.rechecks == 1);
        for (const OutcomeReport &rep : s.reports)
            CHECK(rep.outcome == PathOutcome::DataOk);
    }
}

int main()
{
    testPathId();
    testNetworkKey();
    testLedger();
    testFailureSettle();
    testSelect();
    testChoiceCountryAndLanes();
    testSpeedOrder();
    testOwnerStale();
    testOwnerLive();
    testOwnerStarved();
    scenarioHomeWifi();
    scenarioClean();
    scenarioWhitelist();
    scenarioFlapping();
    scenarioNetworkChange();
    scenarioSuspended();
    scenarioSystemSleep();
    scenarioPermissionPrompt();
    scenarioLocalBuild();
    scenarioLocalBuildQueued();
    scenarioTraceAirB2411();
    scenarioIosStopDuringStart();
    scenarioAndroidLocalPhaseUnchanged();
    scenarioPreference();
    scenarioModeBeatsPreference();
    scenarioRevision();
    scenarioReview1811();
    scenarioRace();
    scenarioAttribution();

    std::printf("\n%-55s | %-40s | %8s | %5s | %s\n", "scenario", "outcome", "ms", "paths", "order");
    for (const Row &r : g_rows)
        std::printf("%-55s | %-40s | %8lld | %5d | %s\n", qPrintable(r.scenario), qPrintable(r.outcome),
                    static_cast<long long>(r.ms), r.paths, qPrintable(r.order));
    std::printf("\npath_engine_check: %d/%d passed\n", g_total - g_fail, g_total);
    return g_fail ? 1 : 0;
}
