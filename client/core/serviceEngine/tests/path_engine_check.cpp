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
    g_rows.append({ QString::fromLatin1(name), outcome, r.elapsedMs, r.paths, legPaths(s, legFrom).join(QLatin1Char(' ')) });
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
    NetworkObservation off;
    off.medium = NetMedium::Offline;
    CHECK(key(off).isEmpty());

    NetworkObservation withAsn = home;
    withAsn.asn = 12389;
    CHECK(coarseNetworkKey(withAsn) == QLatin1String("wifi:asn:12389"));
    CHECK(coarseNetworkKey(home).isEmpty());
    CHECK(coarseNetworkKey(cell("250-01", "lte")) == QLatin1String("cellular:250-01"));

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

    CHECK(l.record(net, p, PathOutcome::ProbeOk, t0 + 600000));
    v = l.view(net, p, t0 + 600000);
    CHECK(v.state == PathState::Working && v.strength == EvidenceStrength::Probe && v.failStreak == 0);
    CHECK(l.view(net, p, t0 + 600000 + lt.probeOkTtlMs + 1).state == PathState::Unknown); // a probe proof is short
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

    // preferred country: all its paths first (suspect included, manual_only not demoted), then the rest
    in.evidence.clear();
    in.evidence.insert(QStringLiteral("12"), viewState(PathState::Suspect));
    in.evidence.insert(QStringLiteral("16"), viewState(PathState::Working, false, 9));
    in.choice = UserChoice::preferCountry(QStringLiteral("de"));
    QList<RankedPath> r = selectPaths(in);
    CHECK(ids(r).mid(0, 2) == QStringList({ "12:xray", "12" }) && r[0].preferred && r[1].preferred);
    CHECK(r[2].path.id.id == QLatin1String("16") && !r[2].preferred);
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
    row("preferred DE unavailable, tap 2", s, r, from);
    CHECK(r.connected && r.fallbackNotice && legPaths(s, from) == QStringList({ "de1", "de1:xray", "nl1" }));
    stopLive(s);
    from = int(s.legs.size());
    r = s.tap(UserChoice::preferCountry(QStringLiteral("DE")));
    row("preferred DE unavailable, tap 3 (DE in quarantine)", s, r, from);
    CHECK(r.connected && r.fallbackNotice && r.path.id.id == QLatin1String("nl1") && r.paths == 1);
    // the preference is kept: once the quarantine is over, DE is tried first again
    stopLive(s);
    s.idle(s.ledger.tunables().quarantineMs[0] + 1000);
    from = int(s.legs.size());
    r = s.tap(UserChoice::preferCountry(QStringLiteral("DE")));
    CHECK(legPaths(s, from).first() == QLatin1String("de1") && r.fallbackNotice);
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

int main()
{
    testPathId();
    testNetworkKey();
    testLedger();
    testSelect();
    testOwnerStale();
    testOwnerLive();
    scenarioHomeWifi();
    scenarioClean();
    scenarioWhitelist();
    scenarioFlapping();
    scenarioNetworkChange();
    scenarioSuspended();
    scenarioPreference();
    scenarioModeBeatsPreference();
    scenarioRevision();

    std::printf("\n%-55s | %-40s | %8s | %5s | %s\n", "scenario", "outcome", "ms", "paths", "order");
    for (const Row &r : g_rows)
        std::printf("%-55s | %-40s | %8lld | %5d | %s\n", qPrintable(r.scenario), qPrintable(r.outcome),
                    static_cast<long long>(r.ms), r.paths, qPrintable(r.order));
    std::printf("\npath_engine_check: %d/%d passed\n", g_total - g_fail, g_total);
    return g_fail ? 1 : 0;
}
