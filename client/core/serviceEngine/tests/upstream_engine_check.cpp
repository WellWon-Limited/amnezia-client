// AVPN upstream nodes - the engine wiring of lane L1 (plan provider-pool v2, points 3-9, 11, 14, 16):
//  1) the policy tier in the automatic pick over realistic pools (whitelist mode with ICMP dead incl.),
//     the server priority inside a tier, a pin of a stub regardless of tiers, the rotation ring;
//  2) flag off = identical decisions (picker over random pools, reseed and switch log);
//  3) stub identity: reseed Unchanged for an unchanged stub, quiet switch log, Deferred on a new sha,
//     identification of an adopted stub session by node id;
//  4) the engine: attempt exclusions (start failures), the tier walk through verify failures, leaving
//     an upstream node, network memory inside a tier;
//  5) the lease owner (UpstreamLeaseOwner) with a fake I/O and a fake clock: acquire outcomes -> bring-up
//     / start failure / provisional start, the macOS owner's renew / terminal / release / rebaseline /
//     adoption, the iOS hand-over;
//  6) the data check: the tribe-probe-v1 digest against vectors derived from the contract text with an
//     independent implementation, facts -> verdict routing, the verify route, the fallback verdict;
//  7) the standby pack at rest, its candidate rule, the status handler, the network key, the envelope,
//     the lease record, the probe grant / meter tags parsing, the acquire timeout bound.
// Build/run: build_upstream_engine.sh (QtCore/QtNetwork + libcrypto; no network, no tunnel).
#include "../ConnectTunables.h"
#include "../NodeRanking.h" // pickerDisplay
#include "../NodeRotation.h"
#include "../ServiceEngine.h"
#include "../SubscriptionParser.h"
#include "../TransportPick.h"
#include "../TuningStore.h"
#include "../UpstreamEngine.h"
#include "../UpstreamLeaseOwner.h"
#include "../XrayConfigBuilder.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDateTime>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRandomGenerator>
#include <QTimeZone>

#include <openssl/evp.h>

#include <cstdio>
#include <functional>

using namespace avpn;

static int g_fail = 0, g_total = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        ++g_total;                                                                                 \
        if (!(cond)) {                                                                             \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                           \
            ++g_fail;                                                                              \
        }                                                                                          \
    } while (0)

// --- fixtures ------------------------------------------------------------------------------------------

static void setFlags(bool upstream, int failCap = -1)
{
    QMap<QString, bool> f{{QStringLiteral("upstream_nodes"), upstream}, {QStringLiteral("xray_client"), true},
                          {QStringLiteral("transport_auto_pick"), true}};
    QMap<QString, double> n;
    if (failCap > 0)
        n.insert(QStringLiteral("data_plane_fail_max_tries"), failCap);
    TuningStore::set(n, f, {}, {});
}

static QString sha64(char c) { return QString(64, QLatin1Char(c)); }

static QJsonObject awgNode(const QString &id, int hostId, const char *cc, double weight = 1.0)
{
    return QJsonObject{
        {"node_id", id}, {"region", "eu"}, {"host_id", hostId}, {"transport_rank", 10},
        {"endpoint", QStringLiteral("198.51.100.%1:585").arg(hostId)}, {"proto", "awg"},
        {"server_pubkey", "K1nDpUbLiCkEyExAmPlE0000000000000000000000="}, {"weight", weight},
        {"country_code", cc}, {"allowed_ips", QJsonArray{"0.0.0.0/0", "::/0"}}, {"dns", QJsonArray{"1.1.1.1", "1.0.0.1"}},
        {"mtu", 1280}, {"persistent_keepalive", 25},
        {"awg_params", QJsonObject{{"Jc", 4}, {"Jmin", 50}, {"Jmax", 1000}, {"S1", 86}, {"S2", 57},
                                   {"H1", 1}, {"H2", 2}, {"H3", 3}, {"H4", 4}}}};
}

static QJsonObject stubNode(const QString &profileId, int tier, int priority, const QString &sha = sha64('a'),
                            const char *cc = nullptr)
{
    const QJsonObject up{{"profile_id", profileId}, {"config_sha256", sha}, {"probe_class", "single"},
                         {"protocols", QJsonArray{"proto:vless", "net:tcp"}}, {"required_geo", QJsonArray{"geoip:ru"}},
                         {"size_bytes", 4096}, {"tier", tier}, {"priority", priority}};
    return QJsonObject{{"node_id", QStringLiteral("up:") + profileId}, {"region", "upstream"},
                       {"label", "Provider Name Ltd"}, {"country_code", cc ? QJsonValue(cc) : QJsonValue()},
                       {"endpoint", ""}, {"proto", "xray"}, {"upstream", up}, {"health", QJsonObject{}},
                       {"allowed_ips", QJsonArray{"0.0.0.0/0"}}, {"dns", QJsonArray{"1.1.1.1"}}};
}

static QByteArray body(const QJsonArray &nodes, double poolRev = 1, double upRev = 1763117000123.0)
{
    QJsonObject root{{"version", 1}, {"address", QJsonArray{"10.8.0.2/32"}}, {"status", "active"},
                     {"pool_revision", poolRev}, {"nodes", nodes}};
    if (upRev > 0)
        root.insert("upstream_revision", upRev);
    return QJsonDocument(root).toJson(QJsonDocument::Compact);
}

static Subscription parse(const QByteArray &b)
{
    Subscription s;
    QString err;
    const bool ok = SubscriptionParser::parse(b, s, err);
    if (!ok)
        std::printf("parse error: %s\n", qPrintable(err));
    CHECK(ok);
    return s;
}

// The realistic pool of the whitelist case: five own locations, two tier-1 profiles, one tier-2.
static QJsonArray realisticPool()
{
    return QJsonArray{awgNode("9", 9, "EE"), awgNode("2", 2, "PL"), awgNode("5", 5, "US"), awgNode("3", 3, "FI"),
                      awgNode("7", 7, "DE"), stubNode("aaaaaaaaaaaaaaa1", 1, 1), stubNode("aaaaaaaaaaaaaaa0", 1, 0),
                      stubNode("bbbbbbbbbbbbbbb0", 2, 0)};
}

struct FakeTunnel : ITunnelControl {
    QStringList ups;
    int downs = 0;
    TunnelStats st;
    TunnelResult up(const Subscription &, const SubscriptionNode &n) override
    {
        ups << n.nodeId;
        return TunnelResult::success();
    }
    TunnelResult applyPeer(const Subscription &, const SubscriptionNode &) override { return TunnelResult::success(); }
    TunnelStats readStats() override { return st; }
    void down() override { ++downs; }
};

static bool isStubId(const QString &id) { return id.startsWith(QLatin1String("up:")); }

// --- 1) the tier in the pure picker ---------------------------------------------------------------------
static void pickerTiers()
{
    setFlags(true);
    const Subscription sub = parse(body(realisticPool()));
    CHECK(sub.nodes.size() == 8);
    TransportHistory hist;
    const auto first = [](int) { return 0; };
    const auto pick = [&](const QSet<QString> &failed, const QHash<QString, int> &rtt, const QString &preferLoc = {}) {
        TransportPickInput in;
        in.excluded = failed;
        in.preferLocation = preferLoc;
        in.tierGate.enabled = true;
        in.tierGate.dataPlaneFailCap = 4; // K = min(6, 4 - 1) = 3
        in.tierGate.k = 6;
        in.tierGate.failed = failed;
        const SubscriptionNode *n = pickTransportNode(sub.nodes, rtt, hist, in, first);
        return n ? n->nodeId : QString();
    };
    // Whitelist mode: ICMP dead (no RTT anywhere). A stub is never the first pick - own nodes first.
    CHECK(!isStubId(pick({}, {})));
    for (int seed = 0; seed < 50; ++seed) {
        TransportPickInput in;
        in.tierGate.enabled = true;
        in.tierGate.dataPlaneFailCap = 4;
        const SubscriptionNode *n = pickTransportNode(sub.nodes, {}, hist, in, [seed](int size) { return seed % size; });
        CHECK(n && !isStubId(n->nodeId));
    }
    // K-1 own failures: still tier 0.
    CHECK(!isStubId(pick({"9", "2"}, {})));
    // K own failures: tier 1 commits, best priority first.
    CHECK(pick({"9", "2", "5"}, {}) == QLatin1String("up:aaaaaaaaaaaaaaa0"));
    // ... even when the leftover own nodes are MEASURED and fast (memory/RTT rank only inside a tier).
    CHECK(pick({"9", "2", "5"}, {{"3", 10}, {"7", 12}}) == QLatin1String("up:aaaaaaaaaaaaaaa0"));
    // The first profile failed: the next priority of the same tier.
    CHECK(pick({"9", "2", "5", "up:aaaaaaaaaaaaaaa0"}, {}) == QLatin1String("up:aaaaaaaaaaaaaaa1"));
    // Tier 1 exhausted (both failed): tier 2.
    CHECK(pick({"9", "2", "5", "up:aaaaaaaaaaaaaaa0", "up:aaaaaaaaaaaaaaa1"}, {}) == QLatin1String("up:bbbbbbbbbbbbbbb0"));
    // Everything failed: the retry without exclusions starts again from own nodes.
    {
        TransportPickInput in;
        in.tierGate.enabled = true;
        in.tierGate.dataPlaneFailCap = 4;
        for (const SubscriptionNode &n : sub.nodes)
            in.tierGate.failed.insert(n.nodeId);
        const SubscriptionNode *n = pickTransportNode(sub.nodes, {}, hist, in, first);
        CHECK(n && !isStubId(n->nodeId));
    }
    // Measured own nodes: the fastest own node (tiers do not change the order inside tier 0).
    CHECK(pick({}, {{"9", 30}, {"2", 20}, {"5", 150}, {"3", 25}, {"7", 40}}) == QLatin1String("2"));
    // A pin (preferLocation) of a stub is the user's choice: no tier applies.
    {
        const SubscriptionNode *stub = nullptr;
        for (const SubscriptionNode &n : sub.nodes)
            if (n.nodeId == QLatin1String("up:bbbbbbbbbbbbbbb0"))
                stub = &n;
        CHECK(stub && pick({}, {}, locationKeyOf(*stub)) == QLatin1String("up:bbbbbbbbbbbbbbb0"));
    }
    // A hard exclusion is never picked, not even without the session exclusions.
    {
        TransportPickInput in;
        in.tierGate.enabled = true;
        in.tierGate.dataPlaneFailCap = 4;
        in.tierGate.failed = {"9", "2", "5", "up:aaaaaaaaaaaaaaa0"};
        in.hardExcluded = {"up:aaaaaaaaaaaaaaa0"};
        const SubscriptionNode *n = pickTransportNode(sub.nodes, {}, hist, in, first);
        CHECK(n && n->nodeId == QLatin1String("up:aaaaaaaaaaaaaaa1"));
    }
    // Commit tier helper: -1 without upstream candidates (no gate at all).
    {
        const Subscription own = parse(body(QJsonArray{awgNode("9", 9, "EE"), awgNode("2", 2, "PL")}));
        UpstreamTierGate g;
        g.enabled = true;
        CHECK(autoCommitTier(own.nodes, TransportMode::Auto, g) == -1);
        CHECK(autoCommitTier(sub.nodes, TransportMode::Auto, g) == 0);
        g.enabled = false;
        CHECK(autoCommitTier(sub.nodes, TransportMode::Auto, g) == -1);
    }
    // Manual transport mode "Amnezia" never sees a stub; "Xray" sees only stubs (no own Xray here).
    {
        TransportPickInput in;
        in.mode = TransportMode::Awg;
        in.tierGate.enabled = true;
        in.tierGate.dataPlaneFailCap = 4;
        const SubscriptionNode *n = pickTransportNode(sub.nodes, {}, hist, in, first);
        CHECK(n && !isStubId(n->nodeId));
        in.mode = TransportMode::Xray;
        n = pickTransportNode(sub.nodes, {}, hist, in, first);
        CHECK(n && n->nodeId == QLatin1String("up:aaaaaaaaaaaaaaa0"));
    }
    // The rotation ring («Заменить сервер») holds our locations only.
    for (int i = 0; i < 12; ++i) {
        const QString id = nextLiveNodeId(sub.nodes, i % 2 ? QStringLiteral("9") : QStringLiteral("up:aaaaaaaaaaaaaaa0"));
        CHECK(!id.isEmpty() && !isStubId(id));
    }
    // Geo gate (macOS, point 14): a missing geo pair withholds stubs only.
    upstreamPlatformRuntimeReady().store(false);
    {
        const SubscriptionNode *own = nullptr, *stub = nullptr;
        for (const SubscriptionNode &n : sub.nodes)
            (isStubId(n.nodeId) ? stub : own) = &n;
        CHECK(own && isSupportedProtoNode(*own) && stub && !isSupportedProtoNode(*stub));
        CHECK(pick({"9", "2", "5", "3", "7"}, {}).isEmpty() || !isStubId(pick({"9", "2", "5", "3", "7"}, {})));
    }
    upstreamPlatformRuntimeReady().store(true);
}

// --- 2) flag off = identical decisions ----------------------------------------------------------------
static void flagOffIdentical()
{
    // A pool parsed with stubs (switch on), then the switch turned off, decides exactly like the pool
    // without stubs - over random pools, random failures and random RTTs.
    QRandomGenerator rnd(20261114);
    TransportHistory hist;
    for (int round = 0; round < 300; ++round) {
        QJsonArray own, all;
        const int nOwn = 1 + int(rnd.bounded(6));
        for (int i = 0; i < nOwn; ++i) {
            const QJsonObject n = awgNode(QString::number(10 + i), 10 + i, "EE", 1.0 + rnd.bounded(3));
            own << n;
            all << n;
        }
        const int nUp = int(rnd.bounded(5));
        for (int i = 0; i < nUp; ++i)
            all << stubNode(QStringLiteral("%1").arg(i, 16, 10, QLatin1Char('c')), 1 + int(rnd.bounded(3)), int(rnd.bounded(4)));
        setFlags(true);
        const Subscription withStubs = parse(body(all));
        setFlags(false);
        const Subscription without = parse(body(own));
        QHash<QString, int> rtt;
        QSet<QString> failed;
        for (int i = 0; i < nOwn; ++i) {
            if (rnd.bounded(2))
                rtt.insert(QString::number(10 + i), 5 + int(rnd.bounded(200)));
            if (rnd.bounded(3) == 0)
                failed.insert(QString::number(10 + i));
        }
        const int seed = int(rnd.bounded(1000));
        TransportPickInput in;
        in.excluded = failed;
        // As ServiceEngine::tierGate() builds it with the switch off: disabled.
        in.tierGate.enabled = upstreamNodesEnabled();
        const auto idx = [seed](int size) { return seed % size; };
        const SubscriptionNode *a = pickTransportNode(withStubs.nodes, rtt, hist, in, idx);
        const SubscriptionNode *b = pickTransportNode(without.nodes, rtt, hist, in, idx);
        CHECK((a ? a->nodeId : QString()) == (b ? b->nodeId : QString()));
        CHECK(nextLiveNodeId(withStubs.nodes, QStringLiteral("10")) == nextLiveNodeId(without.nodes, QStringLiteral("10")));
    }
    // With the switch off the parser drops stubs: the engine's pool, picks and reseed log are those of
    // the own pool (the same body twice = Unchanged, no switch log line).
    setFlags(false);
    ServiceEngine e;
    FakeTunnel t;
    e.setTunnel(&t);
    QString err;
    CHECK(e.loadSubscription(body(realisticPool()), err));
    CHECK(e.debugSnapshot().pool.size() == 5);
    const int logBefore = e.switchLog().size();
    CHECK(e.reseedPool(parse(body(realisticPool(), 1))) == ReseedResult::Unchanged);
    CHECK(e.switchLog().size() == logBefore);
    CHECK(e.connect(err) && !isStubId(t.ups.last()));
    CHECK(!e.hasAttemptExclusions());
}

// --- 3) identity / reseed -------------------------------------------------------------------------------
static void identityAndReseed()
{
    setFlags(true);
    ServiceEngine e;
    FakeTunnel t;
    e.setTunnel(&t);
    QString err;
    const QJsonArray pool{awgNode("9", 9, "EE"), stubNode("aaaaaaaaaaaaaaa0", 1, 0)};
    CHECK(e.loadSubscription(body(pool), err));
    // Unchanged stub: Unchanged reseed, quiet switch log (R2).
    const int logBefore = e.switchLog().size();
    for (int i = 0; i < 5; ++i)
        CHECK(e.reseedPool(parse(body(pool, 1))) == ReseedResult::Unchanged);
    CHECK(e.switchLog().size() == logBefore);
    // Connected on the stub (pin = the user's tap).
    CHECK(e.setPinnedNode(QStringLiteral("up:aaaaaaaaaaaaaaa0"), err));
    CHECK(e.connect(err) && t.ups.last() == QLatin1String("up:aaaaaaaaaaaaaaa0"));
    CHECK(e.onTunnelConnected() && e.isVerifying());
    CHECK(e.verifySucceeded() && e.state() == EngineState::Connected && e.currentNodeIsUpstream());
    // Another node changed, the stub did not: the refresh applies now (the pool is not frozen).
    QJsonArray changedOther{awgNode("9", 9, "EE", 3.0), stubNode("aaaaaaaaaaaaaaa0", 1, 0)};
    CHECK(e.reseedPool(parse(body(changedOther, 2))) == ReseedResult::Applied);
    // The provider rotated its servers (new sha): Deferred while connected on it.
    QJsonArray rotated{awgNode("9", 9, "EE", 3.0), stubNode("aaaaaaaaaaaaaaa0", 1, 0, sha64('b'))};
    CHECK(e.reseedPool(parse(body(rotated, 3))) == ReseedResult::Deferred);
    // Tier / priority change is content (Applied), not identity.
    {
        ServiceEngine e2;
        FakeTunnel t2;
        e2.setTunnel(&t2);
        CHECK(e2.loadSubscription(body(pool), err));
        CHECK(e2.reseedPool(parse(body(QJsonArray{awgNode("9", 9, "EE"), stubNode("aaaaaaaaaaaaaaa0", 2, 0)}, 2)))
              == ReseedResult::Applied);
    }
    // Adoption by node id (point 11): a stub session hint has no endpoint; the stub is not in the pool at
    // adoption (frozen switch at cold start), the reseed brings it - identified by id.
    {
        ServiceEngine a;
        FakeTunnel ta;
        a.setTunnel(&ta);
        CHECK(a.loadSubscription(body(QJsonArray{awgNode("9", 9, "EE")}), err));
        CHECK(a.adoptTunnelConnected(QStringLiteral("up:aaaaaaaaaaaaaaa0"), QStringLiteral("xray"), QString()));
        CHECK(!a.currentIdentityKnown());
        CHECK(a.reseedPool(parse(body(pool, 2))) == ReseedResult::Applied);
        CHECK(a.currentNodeId() == QLatin1String("up:aaaaaaaaaaaaaaa0") && a.currentNodeIsUpstream());
        // A stub hint with the wrong proto is not identified.
        ServiceEngine b;
        FakeTunnel tb;
        b.setTunnel(&tb);
        CHECK(b.loadSubscription(body(QJsonArray{awgNode("9", 9, "EE")}), err));
        b.adoptTunnelConnected(QStringLiteral("up:aaaaaaaaaaaaaaa0"), QStringLiteral("awg"), QString());
        b.reseedPool(parse(body(pool, 2)));
        CHECK(!b.currentIdentityKnown());
        // Direct adoption when the stub is already in the pool.
        ServiceEngine c;
        FakeTunnel tc;
        c.setTunnel(&tc);
        CHECK(c.loadSubscription(body(pool), err));
        c.adoptTunnelConnected(QStringLiteral("up:aaaaaaaaaaaaaaa0"), QStringLiteral("xray"), QString());
        CHECK(c.currentNodeId() == QLatin1String("up:aaaaaaaaaaaaaaa0"));
    }
    // The UI model: upstream roles, tier, no provider label.
    for (const NodeDebugRow &r : e.debugSnapshot().pool) {
        if (isStubId(r.nodeId)) {
            CHECK(r.upstream && r.upstreamTier == 1 && r.name.isEmpty() && r.endpoint.isEmpty());
        } else {
            CHECK(!r.upstream && r.upstreamTier == 0);
        }
    }
}

// --- 4) the engine ------------------------------------------------------------------------------------
static void engineAttempt()
{
    setFlags(true, /*failCap=*/4);
    QString err;
    // a) Start failures: excluded for the attempt; the restart never retries the same stub; stop clears.
    {
        ServiceEngine e;
        FakeTunnel t;
        e.setTunnel(&t);
        CHECK(e.loadSubscription(body(QJsonArray{stubNode("aaaaaaaaaaaaaaa0", 1, 0), stubNode("aaaaaaaaaaaaaaa1", 1, 1)}), err));
        CHECK(e.connect(err) && t.ups.last() == QLatin1String("up:aaaaaaaaaaaaaaa0"));
        e.excludeForAttempt(QStringLiteral("up:aaaaaaaaaaaaaaa0"), QStringLiteral("no_seat"));
        CHECK(e.switchLog().last().contains(QLatin1String("code=no_seat")));
        CHECK(e.onTunnelError());
        CHECK(e.connect(err) && t.ups.last() == QLatin1String("up:aaaaaaaaaaaaaaa1"));
        e.excludeForAttempt(QStringLiteral("up:aaaaaaaaaaaaaaa1"), QStringLiteral("not_entitled"));
        e.onTunnelError();
        // The engine's own stop inside the attempt (watchdog, restart) keeps the exclusions.
        e.requestStop();
        CHECK(e.hasAttemptExclusions());
        // Every candidate failed to start in this attempt: the exclusions are forgotten and the pick runs
        // again (the app keeps trying, never "no nodes" because of its own exclusions).
        CHECK(e.connect(err) && t.ups.last() == QLatin1String("up:aaaaaaaaaaaaaaa0"));
        CHECK(e.switchLog().join('\n').contains(QLatin1String("exclusions cleared")));
        e.excludeForAttempt(QStringLiteral("up:aaaaaaaaaaaaaaa0"), QStringLiteral("no_seat"));
        e.beginUserAttempt(); // a user start / stop: a new attempt
        CHECK(!e.hasAttemptExclusions());
    }
    // b) The tier walk through data-plane failures (whitelist mode: ICMP dead, own data-plane dead).
    for (int cap : {4, 10}) {
        setFlags(true, cap);
        ServiceEngine e;
        FakeTunnel t;
        e.setTunnel(&t);
        e.setVerifyEveryTransport(true); // every transport verifies (node_scan): a failed check = data-plane failure
        CHECK(e.loadSubscription(body(realisticPool()), err));
        CHECK(e.connect(err));
        for (int i = 0; i < 12 && e.state() != EngineState::Error; ++i) {
            if (!e.onTunnelConnected())
                break;
            e.verifyFailed(QStringLiteral("whoami no data (failover)"));
            if (e.state() == EngineState::Switching)
                e.onTunnelDisconnected();
        }
        const int k = qMin(upstreamTierK(6, cap), 5); // min(K, size of tier 0)
        CHECK(t.ups.size() >= k + 1);
        for (int i = 0; i < k && i < t.ups.size(); ++i)
            CHECK(!isStubId(t.ups.at(i))); // own nodes first
        if (t.ups.size() > k)
            CHECK(t.ups.at(k) == QLatin1String("up:aaaaaaaaaaaaaaa0")); // the first try after K: the best profile
        if (cap == 4)
            CHECK(t.ups.size() == 4 && e.dataPlaneExhausted()); // K = 3: exactly one profile try before giving up
        if (cap == 10)
            CHECK(t.ups.contains(QStringLiteral("up:bbbbbbbbbbbbbbb0"))); // tier 2 after tier 1 is used up
    }
    // c) Leaving an upstream node (lease terminal): step 3 to another node, the stub excluded.
    setFlags(true, 4);
    {
        ServiceEngine e;
        FakeTunnel t;
        e.setTunnel(&t);
        CHECK(e.loadSubscription(body(QJsonArray{awgNode("9", 9, "EE"), stubNode("aaaaaaaaaaaaaaa0", 1, 0)}), err));
        CHECK(e.setPinnedNode(QStringLiteral("up:aaaaaaaaaaaaaaa0"), err) && e.connect(err));
        e.onTunnelConnected();
        e.verifySucceeded();
        CHECK(e.leaveUpstreamNode(QStringLiteral("lease_gone"), QStringLiteral("seat_taken")));
        CHECK(e.state() == EngineState::Switching && t.downs == 1);
        bool named = false;
        for (const QString &l : e.switchLog())
            named = named || l.contains(QLatin1String("lease_gone (seat_taken)"));
        CHECK(named);
        e.onTunnelDisconnected();
        CHECK(t.ups.last() == QLatin1String("9"));
        CHECK(!e.leaveUpstreamNode(QStringLiteral("lease_gone"))); // not on an upstream node any more
        CHECK(e.attemptExclusionCode(QStringLiteral("up:aaaaaaaaaaaaaaa0")) == QLatin1String("lease_gone"));
    }
    // d) Network memory never crosses a tier; inside the upstream tier no RTT gate.
    {
        setFlags(true, 4);
        ServiceEngine e;
        FakeTunnel t;
        e.setTunnel(&t);
        CHECK(e.loadSubscription(body(realisticPool()), err));
        e.setNetworkMemoryNode(QStringLiteral("up:aaaaaaaaaaaaaaa1"));
        CHECK(e.connect(err) && !isStubId(t.ups.last())); // tier 0 open: the remembered stub is not used
        CHECK(e.networkMemorySkipReason() == QLatin1String("ineligible"));
        e.requestStop();
        // Own nodes exhausted in this attempt (start failures of stubs do not count for tier 0 - use
        // data-plane failures through verify).
        e.setVerifyEveryTransport(true);
        CHECK(e.connect(err));
        for (int i = 0; i < 3; ++i) {
            e.onTunnelConnected();
            e.verifyFailed(QStringLiteral("whoami no data (failover)"));
            if (i < 2)
                e.onTunnelDisconnected();
        }
        // Tier 1 is the commit tier now: the remembered profile (not the best priority) is usable with
        // no RTT at all - "not failed in this attempt" stands in for the reachability gate.
        CHECK(e.networkMemorySkipReason().isEmpty());
        e.onTunnelDisconnected();
        // The 4th up is the engine's own failover: the best profile of tier 1.
        CHECK(t.ups.last() == QLatin1String("up:aaaaaaaaaaaaaaa0"));
        // Its start fails (the switch's up phase): a new connect() of this attempt takes the remembered
        // profile of the commit tier (tier 1), with no RTT measured for it.
        e.onTunnelError();
        CHECK(e.connect(err) && t.ups.last() == QLatin1String("up:aaaaaaaaaaaaaaa1"));
        // An own remembered node with a fresh RTT is not used while tier 1 is the commit tier.
        e.setMeasuredRtt({{"3", 30}, {"7", 30}, {"9", 30}, {"2", 30}, {"5", 30}});
        e.setNetworkMemoryNode(QStringLiteral("3"));
        CHECK(e.networkMemorySkipReason() == QLatin1String("ineligible"));
    }
    // e) Own remembered node with fresh RTT while tier 0 is open: used as before.
    {
        setFlags(true, 4);
        ServiceEngine e;
        FakeTunnel t;
        e.setTunnel(&t);
        CHECK(e.loadSubscription(body(realisticPool()), err));
        e.setMeasuredRtt({{"3", 40}, {"9", 20}});
        e.setNetworkMemoryNode(QStringLiteral("3"));
        CHECK(e.connect(err) && t.ups.last() == QLatin1String("3"));
    }
}

// --- 5) the lease owner -------------------------------------------------------------------------------
struct FakeIo : IUpstreamLeaseIo {
    struct Call { QString what; quint64 id; QString profileOrLease; QString sha; LeaseRoute route; UpstreamMeter meter; };
    QVector<Call> calls;
    void acquire(quint64 id, const QString &profileId, LeaseKind, const QString &sha, const LeaseRoute &route) override
    {
        calls << Call{QStringLiteral("acquire"), id, profileId, sha, route, {}};
    }
    void renew(quint64 id, const QString &leaseId, const UpstreamMeter &m, const LeaseRoute &route) override
    {
        calls << Call{QStringLiteral("renew"), id, leaseId, {}, route, m};
    }
    void release(quint64 id, const QString &leaseId, const UpstreamMeter &m, const LeaseRoute &route) override
    {
        calls << Call{QStringLiteral("release"), id, leaseId, {}, route, m};
    }
    const Call *last(const char *what) const
    {
        for (int i = calls.size() - 1; i >= 0; --i)
            if (calls[i].what == QLatin1String(what))
                return &calls[i];
        return nullptr;
    }
};

static const char *kLease = "LeaseAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
static const qint64 kServerT0 = 1763120000000LL;

static AcquireReply granted(const QString &profile, const QString &sha, qint64 epoch = 1, bool withProbe = true,
                            const QStringList &tags = {}, const QString &base = QStringLiteral("https://t.example.net"))
{
    AcquireReply r;
    r.kind = LeaseReplyKind::Granted;
    UpstreamLeaseGrant &g = r.grant;
    g.leaseId = QLatin1String(kLease);
    g.profileId = profile;
    g.kind = LeaseKind::Session;
    g.expiresAtMs = kServerT0 + 900000;
    g.ttlS = 900;
    g.renewAfterS = 300;
    g.seq = 0;
    g.config = QByteArrayLiteral("{\"cfg\":1}");
    g.configSha256 = sha;
    g.upstreamRevision = 1763117000123LL;
    g.accountingEpoch = epoch;
    g.renewToken = QStringLiteral("tlr1.secret");
    g.tunnelApiBase = base;
    g.meterTags = tags;
    if (withProbe) {
        g.probe.present = true;
        g.probe.scanToken = QStringLiteral("tsc1.scan");
        g.probe.expiresInS = 600;
        g.probe.accessAsn = 12389;
        g.probe.accessNetToken = QStringLiteral("net-a");
    }
    return r;
}
static AcquireReply refused(UpstreamErrorCode c, const QString &reason = {})
{
    AcquireReply r;
    r.kind = LeaseReplyKind::Refused;
    r.error.code = c;
    r.error.reason = reason;
    return r;
}
static AcquireReply failed(const char *why)
{
    AcquireReply r;
    r.why = QLatin1String(why);
    return r;
}
static RenewReply renewedOk(qint64 seq, qint64 expires, bool rebaseline = false, qint64 epoch = 1)
{
    RenewReply r;
    r.kind = LeaseReplyKind::Granted;
    r.renewal.leaseId = QLatin1String(kLease);
    r.renewal.expiresAtMs = expires;
    r.renewal.renewAfterS = 300;
    r.renewal.seq = seq;
    r.renewal.upstreamRevision = 1763117000123LL;
    r.renewal.accountingEpoch = epoch;
    r.renewal.rebaseline = rebaseline;
    r.renewal.appliedBytes = 1000;
    return r;
}

static const UpstreamOwnerEvent *findEv(const QVector<UpstreamOwnerEvent> &ev, UpstreamOwnerEventKind k)
{
    for (const UpstreamOwnerEvent &e : ev)
        if (e.kind == k)
            return &e;
    return nullptr;
}

static SubscriptionNode stubOf(const QString &profile = QStringLiteral("aaaaaaaaaaaaaaa0"))
{
    setFlags(true);
    const Subscription s = parse(body(QJsonArray{stubNode(profile, 1, 0)}));
    return s.nodes.value(0);
}

static void ownerAcquireOutcomes()
{
    const SubscriptionNode stub = stubOf();
    const QString sha = stub.upstream->configSha256;
    StandbyCandidate sc;
    sc.config = QByteArrayLiteral("{\"pack\":1}");
    sc.configSha256 = sha64('c');
    sc.tunnelApiBase = QStringLiteral("https://pack.example.net");
    sc.packRevision = 5;
    const qint64 T = 5000000;
    // Grant -> BringUp with the lease (contract §1 upstream_lease), the sent acquire is DIRECT.
    {
        FakeIo io;
        UpstreamLeaseOwner o(&io);
        UpstreamLeaseOwner::Options op;
        op.keepOwnership = true;
        o.setOptions(op);
        QVector<UpstreamOwnerEvent> ev = o.begin(stub, 1, std::nullopt, T, 1700000000000LL);
        CHECK(io.calls.size() == 1 && io.calls[0].what == QLatin1String("acquire") && io.calls[0].route.apiBase.isEmpty()
              && io.calls[0].sha.isEmpty());
        ev = o.onAcquireReply(io.calls[0].id, granted(stub.upstream->profileId, sha), T + 300);
        const UpstreamOwnerEvent *b = findEv(ev, UpstreamOwnerEventKind::BringUp);
        CHECK(b && !b->provisional && b->config == QByteArrayLiteral("{\"cfg\":1}") && b->configSha256 == sha);
        CHECK(b && b->lease.value("lease_id").toString() == QLatin1String(kLease)
              && b->lease.value("renew_token").toString() == QLatin1String("tlr1.secret")
              && b->lease.value("api_base").toString() == QLatin1String("https://t.example.net")
              && b->lease.value("renew_after_s").toInt() == 300 && b->lease.value("ttl_s").toInt() == 900
              && b->lease.value("seq").toInteger() == 0 && b->lease.value("epoch").toInteger() == 1
              && b->lease.value("meter_scope").toString() == QLatin1String("tunnel")
              && b->lease.value("expires_in_ms").toInteger() == 900000 - 300 && b->lease.contains("revision")
              && b->lease.value("meter_tags").isArray());
        CHECK(findEv(ev, UpstreamOwnerEventKind::Persist) != nullptr);
        CHECK(o.probeGrant(T + 1000).present && o.probeGrant(T + 1000).accessAsn == 12389);
        CHECK(!o.probeGrant(T + 600001).present); // the scan token's own expiry from the acquire's send time
    }
    struct Case { const char *name; AcquireReply reply; bool withStandby; bool provisional; const char *code; };
    const QList<Case> cases{
        {"no_seat", refused(UpstreamErrorCode::NoSeat), true, false, "no_seat"},
        {"not_entitled", refused(UpstreamErrorCode::NotEntitled), true, false, "not_entitled"},
        {"disabled", refused(UpstreamErrorCode::Disabled), false, false, "disabled"},
        {"rate_limited", refused(UpstreamErrorCode::RateLimited), true, false, "rate_limited"},
        {"transport+standby", failed("transport"), true, true, nullptr},
        {"signature+standby", failed("signature"), true, true, nullptr},
        {"http_502+standby", failed("http_502"), true, true, nullptr},
        {"transport", failed("transport"), false, false, "transport"},
        {"malformed+standby", failed("config_sha256_mismatch"), true, false, "invalid_answer"},
    };
    for (const Case &c : cases) {
        FakeIo io;
        UpstreamLeaseOwner o(&io);
        o.begin(stub, 1, c.withStandby ? std::optional<StandbyCandidate>(sc) : std::nullopt, T, 1700000000000LL);
        const QVector<UpstreamOwnerEvent> ev = o.onAcquireReply(io.calls[0].id, c.reply, T + 100);
        const UpstreamOwnerEvent *b = findEv(ev, UpstreamOwnerEventKind::BringUp);
        const UpstreamOwnerEvent *f = findEv(ev, UpstreamOwnerEventKind::StartFailed);
        if (c.provisional) {
            CHECK(b && b->provisional && b->config == sc.config && b->configSha256 == sc.configSha256 && b->lease.isEmpty());
            CHECK(!f && o.provisionalPending());
        } else {
            if (!(f && !b && f->code == QLatin1String(c.code)))
                std::printf("case %s\n", c.name);
            CHECK(f && !b && f->code == QLatin1String(c.code));
            CHECK(!o.active());
        }
    }
    // Provisional: tunnelUp -> the standby acquire through the tunnel (pack base, pack sha); grant ->
    // LeaseConfirmed. macOS keeps ownership (Persist); iOS hands over (HandOver), never renews/releases.
    for (bool keep : {true, false}) {
        FakeIo io;
        UpstreamLeaseOwner o(&io);
        UpstreamLeaseOwner::Options op;
        op.keepOwnership = keep;
        op.provisionalConfirmBudgetMs = 18000;
        o.setOptions(op);
        o.begin(stub, 1, sc, T, 1700000000000LL);
        o.onAcquireReply(io.calls[0].id, failed("transport"), T + 100);
        CHECK(io.calls.size() == 1); // nothing sent before the tunnel is up
        o.tunnelUp(T + 2000);
        const FakeIo::Call *a = io.last("acquire");
        CHECK(io.calls.size() == 2 && a && a->sha == sc.configSha256 && a->route.apiBase == sc.tunnelApiBase);
        CHECK(o.provisionalPending());
        QVector<UpstreamOwnerEvent> ev = o.onAcquireReply(a->id, granted(stub.upstream->profileId, sc.configSha256, 1, true), T + 2500);
        CHECK(findEv(ev, UpstreamOwnerEventKind::LeaseConfirmed));
        CHECK(!o.provisionalPending());
        if (keep) {
            CHECK(findEv(ev, UpstreamOwnerEventKind::Persist) && !findEv(ev, UpstreamOwnerEventKind::HandOver));
        } else {
            const UpstreamOwnerEvent *h = findEv(ev, UpstreamOwnerEventKind::HandOver);
            CHECK(h && h->lease.value("lease_id").toString() == QLatin1String(kLease));
            const int before = io.calls.size();
            o.tick(T + 400000);
            o.disconnect(T + 400001);
            CHECK(io.calls.size() == before); // the extension owns the lease now
        }
    }
    // Provisional seat never confirmed inside the budget -> Leave(standby_unconfirmed).
    {
        FakeIo io;
        UpstreamLeaseOwner o(&io);
        UpstreamLeaseOwner::Options op;
        op.keepOwnership = true;
        op.provisionalConfirmBudgetMs = 18000;
        o.setOptions(op);
        o.begin(stub, 1, sc, T, 1);
        o.onAcquireReply(io.calls[0].id, failed("transport"), T + 100);
        o.tunnelUp(T + 1000);
        o.onAcquireReply(io.last("acquire")->id, failed("transport"), T + 2000);
        QVector<UpstreamOwnerEvent> ev;
        for (qint64 now = T + 2000; now < T + 40000 && !findEv(ev, UpstreamOwnerEventKind::Leave); now += 4000) {
            ev = o.tick(now);
            if (const FakeIo::Call *a = io.last("acquire"))
                if (!findEv(ev, UpstreamOwnerEventKind::Leave) && ev.isEmpty())
                    o.onAcquireReply(a->id, failed("transport"), now + 1);
        }
        const UpstreamOwnerEvent *l = findEv(ev, UpstreamOwnerEventKind::Leave);
        CHECK(l && l->code == QLatin1String("standby_unconfirmed"));
        // no_seat on the standby acquire -> no_seat_standby.
        FakeIo io2;
        UpstreamLeaseOwner o2(&io2);
        o2.setOptions(op);
        o2.begin(stub, 1, sc, T, 1);
        o2.onAcquireReply(io2.calls[0].id, failed("transport"), T + 100);
        o2.tunnelUp(T + 1000);
        ev = o2.onAcquireReply(io2.last("acquire")->id, refused(UpstreamErrorCode::NoSeat), T + 2000);
        CHECK(findEv(ev, UpstreamOwnerEventKind::Leave) && findEv(ev, UpstreamOwnerEventKind::Leave)->code == QLatin1String("no_seat_standby"));
    }
    // A disconnect while the first acquire is in flight; its late grant is given back at once.
    {
        FakeIo io;
        UpstreamLeaseOwner o(&io);
        UpstreamLeaseOwner::Options op;
        op.keepOwnership = true;
        o.setOptions(op);
        o.begin(stub, 1, std::nullopt, T, 1);
        o.disconnect(T + 10);
        CHECK(!o.releaseSent());
        const QVector<UpstreamOwnerEvent> ev = o.onAcquireReply(io.calls[0].id, granted(stub.upstream->profileId, sha), T + 50);
        CHECK(!findEv(ev, UpstreamOwnerEventKind::BringUp));
        CHECK(io.last("release") && io.last("release")->profileOrLease == QLatin1String(kLease));
    }
}

static void ownerMacRenewals()
{
    const SubscriptionNode stub = stubOf();
    const QString sha = stub.upstream->configSha256;
    const qint64 T = 9000000;
    FakeIo io;
    UpstreamLeaseOwner o(&io);
    UpstreamLeaseOwner::Options op;
    op.keepOwnership = true;
    o.setOptions(op);
    o.begin(stub, 1, std::nullopt, T, 1700000000000LL);
    o.onAcquireReply(io.calls[0].id, granted(stub.upstream->profileId, sha, 4), T + 200);
    o.tunnelUp(T + 3000);
    CHECK(o.wakeAtMs() == T + 200 + 300000);
    o.onBytes(1000, 100);
    CHECK(o.tick(T + 100000).isEmpty() && !io.last("renew")); // nothing due
    o.onBytes(5000, 600);
    o.tick(T + 300200);
    const FakeIo::Call *r = io.last("renew");
    CHECK(r && r->meter.seq == 1 && r->meter.rxDelta == 5000 && r->meter.txDelta == 600 && r->meter.epoch == 4
          && r->meter.scope == MeterScope::Tunnel && r->route.renewToken == QLatin1String("tlr1.secret")
          && r->route.apiBase == QLatin1String("https://t.example.net"));
    QVector<UpstreamOwnerEvent> ev = o.onRenewReply(r->id, renewedOk(1, kServerT0 + 1200000, false, 4), T + 300300, 1700000300000LL);
    CHECK(findEv(ev, UpstreamOwnerEventKind::Persist));
    CHECK(o.statusJson(T + 300400).value("state").toString() == QLatin1String("active")
          && o.statusJson(T + 300400).value("applied_bytes").toInteger() == 1000
          && o.statusJson(T + 300400).value("renewed_ms_ago").toInteger() == 100);
    // Rebaseline: counters re-base on the current totals - the next report carries only later bytes.
    o.onBytes(8000, 900);
    o.tick(o.wakeAtMs());
    r = io.last("renew");
    CHECK(r && r->meter.seq == 2 && r->meter.rxDelta == 3000);
    o.onRenewReply(r->id, renewedOk(2, kServerT0 + 1500000, /*rebaseline=*/true, /*epoch=*/5), o.wakeAtMs() - 299000);
    o.onBytes(8500, 950);
    o.tick(o.wakeAtMs());
    r = io.last("renew");
    CHECK(r && r->meter.seq == 3 && r->meter.rxDelta == 500 && r->meter.txDelta == 50 && r->meter.epoch == 5);
    // Terminal answer -> Leave(code, detail) + ClearRecord; no release after a terminal answer.
    RenewReply gone;
    gone.kind = LeaseReplyKind::Refused;
    gone.error.code = UpstreamErrorCode::LeaseGone;
    gone.error.reason = QStringLiteral("seat_taken");
    ev = o.onRenewReply(r->id, gone, o.wakeAtMs());
    const UpstreamOwnerEvent *l = findEv(ev, UpstreamOwnerEventKind::Leave);
    CHECK(l && l->code == QLatin1String("lease_gone") && l->detail == QLatin1String("seat_taken"));
    CHECK(findEv(ev, UpstreamOwnerEventKind::ClearRecord));
    const int before = io.calls.size();
    o.disconnect(T + 2000000);
    CHECK(io.calls.size() == before && !o.releaseSent());
    // A user disconnect of a live lease: the release carries the final deltas and the epoch.
    FakeIo io2;
    UpstreamLeaseOwner o2(&io2);
    o2.setOptions(op);
    o2.begin(stub, 1, std::nullopt, T, 1);
    o2.onAcquireReply(io2.calls[0].id, granted(stub.upstream->profileId, sha, 2), T + 100);
    o2.tunnelUp(T + 2000);
    o2.onBytes(700, 70);
    ev = o2.disconnect(T + 5000);
    const FakeIo::Call *rel = io2.last("release");
    CHECK(o2.releaseSent() && rel && rel->meter.seq == 1 && rel->meter.rxDelta == 700 && rel->meter.epoch == 2);
    CHECK(findEv(ev, UpstreamOwnerEventKind::ClearRecord));
    // no_seat on a re-acquire after the TTL passed -> Leave(no_seat_reacquire).
    FakeIo io3;
    UpstreamLeaseOwner o3(&io3);
    o3.setOptions(op);
    o3.begin(stub, 1, std::nullopt, T, 1);
    o3.onAcquireReply(io3.calls[0].id, granted(stub.upstream->profileId, sha), T + 100);
    o3.tunnelUp(T + 2000);
    QVector<UpstreamOwnerEvent> e3;
    for (int i = 0; i < 60 && !io3.last("acquire") ; ++i) {}
    qint64 now = T + 100;
    for (int i = 0; i < 80; ++i) {
        now = qMax(now + 1, o3.wakeAtMs());
        e3 = o3.tick(now);
        const FakeIo::Call &c = io3.calls.last();
        if (c.what == QLatin1String("acquire") && c.id != io3.calls[0].id) {
            e3 = o3.onAcquireReply(c.id, refused(UpstreamErrorCode::NoSeat), now + 1);
            break;
        }
        if (c.what == QLatin1String("renew"))
            o3.onRenewReply(c.id, RenewReply(), now + 1);
    }
    CHECK(findEv(e3, UpstreamOwnerEventKind::Leave) && findEv(e3, UpstreamOwnerEventKind::Leave)->code == QLatin1String("no_seat_reacquire"));
}

static void ownerAdoption()
{
    UpstreamLeaseRecord rec;
    rec.nodeId = QStringLiteral("up:aaaaaaaaaaaaaaa0");
    rec.profileId = QStringLiteral("aaaaaaaaaaaaaaa0");
    rec.configSha256 = sha64('a');
    rec.apiBase = QStringLiteral("https://t.example.net");
    rec.leaseId = QLatin1String(kLease);
    const qint64 wall = 1700000000000LL;
    rec.startedWallMs = wall - 3600000;
    rec.savedWallMs = wall - 60000;
    rec.expiresWallMs = wall + 400000;
    rec.meterTags = {QStringLiteral("proxy-a")};
    rec.scope = MeterScope::Tunnel;
    // JSON round trip; never a token in it.
    const QByteArray j = rec.toJson();
    CHECK(!j.contains("tlr1") && !j.contains("renew_token"));
    const UpstreamLeaseRecord back = UpstreamLeaseRecord::fromJson(j);
    CHECK(back.valid() && back.nodeId == rec.nodeId && back.startedWallMs == rec.startedWallMs
          && back.meterTags == rec.meterTags && back.expiresWallMs == rec.expiresWallMs);
    CHECK(upstreamRecordAdoptable(rec, wall));
    CHECK(!upstreamRecordAdoptable(rec, wall + kUpstreamRecordMaxAgeMs));
    // The record belongs to THE daemon session (started within the window after the bring-up).
    CHECK(upstreamRecordMatchesSession(rec, rec.startedWallMs + 4000));
    CHECK(!upstreamRecordMatchesSession(rec, rec.startedWallMs + kUpstreamRecordStartWindowMs + 1));
    CHECK(!upstreamRecordMatchesSession(rec, 0));
    CHECK(upstreamAdoptConfirmBudgetMs(rec, wall) == 400000);
    CHECK(upstreamAdoptConfirmBudgetMs(rec, wall + 1000000) == 60000);
    UpstreamLeaseRecord bad = rec;
    bad.nodeId = QStringLiteral("up:other");
    CHECK(!bad.valid());
    // Adoption: a standby acquire of the same profile with the record's sha through the record's base at
    // once; the first byte sample re-bases (the daemon's totals include old bytes).
    FakeIo io;
    UpstreamLeaseOwner o(&io);
    UpstreamLeaseOwner::Options op;
    op.keepOwnership = true;
    o.setOptions(op);
    const qint64 T = 777000;
    QVector<UpstreamOwnerEvent> ev = o.adopt(rec, T, wall);
    CHECK(!findEv(ev, UpstreamOwnerEventKind::BringUp)); // the tunnel already runs
    const FakeIo::Call *a = io.last("acquire");
    CHECK(a && a->sha == rec.configSha256 && a->route.apiBase == rec.apiBase && o.provisionalPending());
    o.onBytes(50000000, 4000000); // the daemon's cumulative: not counted
    ev = o.onAcquireReply(a->id, granted(rec.profileId, rec.configSha256, 3), T + 500);
    CHECK(findEv(ev, UpstreamOwnerEventKind::LeaseConfirmed) && findEv(ev, UpstreamOwnerEventKind::Persist));
    CHECK(findEv(ev, UpstreamOwnerEventKind::Persist)->record.startedWallMs == rec.startedWallMs);
    o.onBytes(50001000, 4000100);
    o.tick(o.wakeAtMs());
    const FakeIo::Call *r = io.last("renew");
    CHECK(r && r->meter.rxDelta == 1000 && r->meter.txDelta == 100);
    // An expired record is not adopted.
    FakeIo io2;
    UpstreamLeaseOwner o2(&io2);
    o2.setOptions(op);
    CHECK(o2.adopt(rec, T, wall + kUpstreamRecordMaxAgeMs + 1).isEmpty() && io2.calls.isEmpty());
}

// --- 6) the data check -------------------------------------------------------------------------------
static void dataCheck()
{
    // Vectors derived from the contract text (openapi /v1/probe, body scheme tribe-probe-v1) with an
    // independent implementation (Python hashlib, 14.11.2026).
    CHECK(tribeProbeBody("abcdefgh12345678", 40).left(8).toHex() == QByteArrayLiteral("494b8d5157dd5161"));
    CHECK(tribeProbeExpectedSha256Hex("abcdefgh12345678", 40)
          == QByteArrayLiteral("1a8a8ef14b12194c84e15ddd3a443bd99da626a2570b33222472313a5a6bd220"));
    CHECK(tribeProbeExpectedSha256Hex("abcdefgh12345678", 1024)
          == QByteArrayLiteral("5c86d6a852fa9f8d739c051e7afa15eeb6fb637bfe8f1de08e569bf7555b24e9"));
    CHECK(tribeProbeExpectedSha256Hex("abcdefgh12345678", 1)
          == QByteArrayLiteral("a83dd0ccbffe39d071cc317ddf6e97f5c6b1c87af91919271f9fa140b0508c6c"));
    CHECK(tribeProbeExpectedSha256Hex("Nonce.-_x", 131072)
          == QByteArrayLiteral("21eb1ab157da102fe50295581b954225b3a47ac95ec75a6393edc3f7c24dee6f"));
    CHECK(tribeProbeBody("x", 0).isEmpty() && tribeProbeBody("x", 33).size() == 33);

    const QByteArray nonce = "abcdefgh12345678";
    const qint64 n = 131072;
    UpstreamProbeGrant access;
    access.present = true;
    access.accessAsn = 12389;
    access.accessNetToken = QStringLiteral("net-a");
    const auto facts = [&](int http, qint64 bytes, const QByteArray &sha, const char *cls, const char *asn, const char *net) {
        UpstreamProbeFacts f;
        f.httpStatus = http;
        f.bytesRequested = n;
        f.bytesReceived = bytes;
        f.bodySha256Hex = sha;
        f.nonce = nonce;
        f.elapsedMs = 900;
        f.ttfbMs = 200;
        f.maxStallMs = 100;
        f.egressClass = QLatin1String(cls);
        f.egressAsnHeader = QLatin1String(asn);
        f.egressNetToken = QLatin1String(net);
        return f;
    };
    const QByteArray good = tribeProbeExpectedSha256Hex(nonce, n);
    const auto judge = [&](const UpstreamProbeFacts &f, bool strict = false, const UpstreamProbeGrant &acc = UpstreamProbeGrant()) {
        return judgeUpstreamCheck(upstreamCheckInputFrom(f, acc.present ? acc : access, strict));
    };
    CHECK(judge(facts(200, n, good, "other", "8881", "net-b")).verdict == UpstreamVerdict::Works);
    CHECK(judge(facts(200, n, good, "upstream-known", "12389", "net-b")).verdict == UpstreamVerdict::Works);
    // The header is not trusted: a body whose digest is not ours fails even with matching length.
    CHECK(judge(facts(200, n, QByteArray(64, 'f'), "other", "8881", "net-b")).reason == QLatin1String("digest_mismatch"));
    CHECK(judge(facts(200, n - 1, good, "other", "8881", "net-b")).reason == QLatin1String("incomplete"));
    CHECK(judge(facts(401, 120, good, "", "", "")).reason == QLatin1String("no_first_byte")); // a non-200 carries no data
    CHECK(judge(facts(200, n, good, "tribe-node", "8881", "net-b")).verdict == UpstreamVerdict::NotThroughProvider);
    CHECK(judge(facts(200, n, good, "other", "8881", "net-a")).reason == QLatin1String("egress_is_access_net"));
    // Same ASN as the access network (tokens differ): not through the provider (L0 rule d).
    CHECK(judge(facts(200, n, good, "other", "12389", "net-b")).reason == QLatin1String("egress_is_access_asn"));
    CHECK(judge(facts(200, n, good, "other", "unknown", "net-b")).pathReason == QLatin1String("verified_net_token"));
    // A standby acquire carries no access facts: Unverifiable, passes unless strict.
    UpstreamProbeGrant noAccess;
    noAccess.present = true;
    UpstreamProbeFacts sf = facts(200, n, good, "other", "8881", "net-b");
    CHECK(judgeUpstreamCheck(upstreamCheckInputFrom(sf, noAccess, false)).verdict == UpstreamVerdict::Unverifiable);
    CHECK(judgeUpstreamCheck(upstreamCheckInputFrom(sf, noAccess, false)).passes);
    CHECK(!judgeUpstreamCheck(upstreamCheckInputFrom(sf, noAccess, true)).passes);
    // Timings: past the hard limit -> no data; past the soft one -> slow but passes.
    UpstreamProbeFacts slow = facts(200, n, good, "other", "8881", "net-b");
    slow.elapsedMs = 4000;
    CHECK(judge(slow).verdict == UpstreamVerdict::Slow && judge(slow).passes);
    slow.elapsedMs = 6000;
    CHECK(judge(slow).reason == QLatin1String("total_timeout"));
    // The route.
    CHECK(decideUpstreamVerifyRoute(true, true, 0) == UpstreamVerifyRoute::Probe);
    CHECK(decideUpstreamVerifyRoute(false, true, 5000) == UpstreamVerifyRoute::WaitForGrant);
    CHECK(decideUpstreamVerifyRoute(false, true, 0) == UpstreamVerifyRoute::Fallback204);
    CHECK(decideUpstreamVerifyRoute(false, false, 5000) == UpstreamVerifyRoute::Fallback204);
    CHECK(upstreamFallbackVerdict(true, false).passes && upstreamFallbackVerdict(true, false).verdict == UpstreamVerdict::Unverifiable);
    CHECK(!upstreamFallbackVerdict(true, true).passes && !upstreamFallbackVerdict(false, false).passes);
}

// --- 7) standby, status, key, envelope, parsing ------------------------------------------------------
struct TestKey {
    EVP_PKEY *k = nullptr;
    TestKey()
    {
        const QByteArray seed = QCryptographicHash::hash("tribe-upstream-engine-test-NOT-A-REAL-KEY", QCryptographicHash::Sha256);
        k = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, reinterpret_cast<const unsigned char *>(seed.constData()),
                                         size_t(seed.size()));
    }
    ~TestKey() { EVP_PKEY_free(k); }
    QString pubHex() const
    {
        unsigned char raw[32];
        size_t len = sizeof raw;
        EVP_PKEY_get_raw_public_key(k, raw, &len);
        return QString::fromLatin1(QByteArray(reinterpret_cast<const char *>(raw), int(len)).toHex());
    }
    QByteArray sign(const QByteArray &msg) const
    {
        unsigned char sig[64];
        size_t len = sizeof sig;
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, k);
        EVP_DigestSign(ctx, sig, &len, reinterpret_cast<const unsigned char *>(msg.constData()), size_t(msg.size()));
        EVP_MD_CTX_free(ctx);
        return QByteArray(reinterpret_cast<const char *>(sig), int(len)).toBase64();
    }
};

static void standbyAndStatus()
{
    TestKey key;
    const QByteArray cfg = "{\"inbounds\":[]}";
    const QString cfgSha = QString::fromLatin1(QCryptographicHash::hash(cfg, QCryptographicHash::Sha256).toHex());
    const qint64 issued = 1763100000000LL;
    QJsonObject entry{{"profile_id", "aaaaaaaaaaaaaaa0"}, {"node_id", "up:aaaaaaaaaaaaaaa0"}, {"label", "x"},
                      {"country_code", QJsonValue()}, {"tier", 1}, {"probe_class", "single"},
                      {"config", QString::fromUtf8(cfg)}, {"config_sha256", cfgSha},
                      {"meter_tags", QJsonArray{"proxy-a", "proxy-b"}}};
    QJsonObject pack{{"type", "upstream_standby"}, {"version", 1},
                     {"issued_at", QDateTime::fromMSecsSinceEpoch(issued, QTimeZone::UTC).toString(Qt::ISODateWithMs)},
                     {"max_age_s", 259200}, {"upstream_revision", 1763117000999.0},
                     {"tunnel_api_base", "https://t.example.net"}, {"entries", QJsonArray{entry}}};
    const QByteArray bodyBytes = QJsonDocument(pack).toJson(QJsonDocument::Compact);
    const QByteArray sig = key.sign(QByteArrayLiteral("tribe-upstream-standby-v1\n") + bodyBytes);
    // Store/load round trip of the exact signed bytes.
    StandbyStored st{bodyBytes, sig, QStringLiteral("cell:250-02:4g"), issued + 1000};
    StandbyStored back;
    CHECK(parseStandbyStored(serializeStandbyStored(st), back));
    CHECK(back.body == bodyBytes && back.sigB64 == sig && back.networkKey == st.networkKey && back.fetchedWallMs == st.fetchedWallMs);
    CHECK(!parseStandbyStored("not json", back) && !parseStandbyStored("{}", back));
    const StandbyParse p = parseStandbyPack(back.body, back.sigB64, key.pubHex());
    CHECK(p.ok() && p.pack.entries.size() == 1 && p.pack.entries[0].meterTags == QStringList({"proxy-a", "proxy-b"}));
    // A tampered stored body never loads.
    QByteArray tampered = back.body;
    tampered.replace("\"tier\":1", "\"tier\":2");
    CHECK(!parseStandbyPack(tampered, back.sigB64, key.pubHex()).ok());
    // Candidate rule: fresh, same sha -> usable with the pack's base and tags; expired; stale; no entry.
    setFlags(true);
    const Subscription sameSha = parse(body(QJsonArray{stubNode("aaaaaaaaaaaaaaa0", 1, 0, cfgSha)}, 1, 1763117000123.0));
    StandbyCandidate c;
    QString why;
    CHECK(standbyCandidateFor(p.pack, sameSha.nodes[0], sameSha.upstreamRevision, issued + 3600000, upstreamStandbyMaxAgeSTuned(), c, &why));
    CHECK(c.config == cfg && c.tunnelApiBase == QLatin1String("https://t.example.net") && c.meterTags.size() == 2);
    CHECK(!standbyCandidateFor(p.pack, sameSha.nodes[0], sameSha.upstreamRevision, issued + 259200000LL, 259200, c, &why)
          && why == QLatin1String("expired"));
    const Subscription otherSha = parse(body(QJsonArray{stubNode("aaaaaaaaaaaaaaa0", 1, 0, sha64('d'))}, 1, 1763117009999.0));
    CHECK(!standbyCandidateFor(p.pack, otherSha.nodes[0], otherSha.upstreamRevision, issued + 1000, 259200, c, &why)
          && why == QLatin1String("entry_stale"));
    const Subscription none = parse(body(QJsonArray{stubNode("ccccccccccccccc0", 1, 0)}));
    CHECK(!standbyCandidateFor(p.pack, none.nodes[0], none.upstreamRevision, issued + 1000, 259200, c, &why)
          && why == QLatin1String("no_entry"));
    StandbyPack noBase = p.pack;
    noBase.tunnelApiBase.clear();
    CHECK(!standbyCandidateFor(noBase, sameSha.nodes[0], sameSha.upstreamRevision, issued + 1000, 259200, c, &why)
          && why == QLatin1String("no_tunnel_api_base"));

    // Status handler (contract §5).
    UpstreamStatusDecision d = decideUpstreamStatus(QJsonObject{{"state", "terminal"}, {"code", "over_quota"}, {"revision", 10.0}}, 10);
    CHECK(d.valid && d.leaveCode == QLatin1String("over_quota") && d.refreshRevision == 0);
    d = decideUpstreamStatus(QJsonObject{{"state", "active"}, {"revision", 11.0}, {"config_changed", true}}, 10);
    CHECK(d.leaveCode.isEmpty() && d.refreshRevision == 11 && d.configChanged);
    d = decideUpstreamStatus(QJsonObject{{"state", "terminal"}, {"code", "Bad Code!"}}, 0);
    CHECK(d.leaveCode == QLatin1String("terminal"));
    d = decideUpstreamStatus(QJsonObject{{"state", "weird"}}, 0);
    CHECK(d.valid && d.state == QLatin1String("none") && d.leaveCode.isEmpty());
    CHECK(!decideUpstreamStatus(QJsonObject(), 0).valid);
    // One refresh per newer revision.
    CHECK(upstreamRevisionNeedsRefresh(11, 10, 0) && !upstreamRevisionNeedsRefresh(11, 10, 11) && !upstreamRevisionNeedsRefresh(10, 10, 0)
          && !upstreamRevisionNeedsRefresh(0, 0, 0));
    CHECK(upstreamFlagFlippedOn(false, true) && !upstreamFlagFlippedOn(true, true) && !upstreamFlagFlippedOn(false, false));

    // Network key grammar: operator level only.
    CHECK(upstreamNetworkKey("cellular", "250-02", "lte", 0) == QLatin1String("cell:250-02:4g"));
    CHECK(upstreamNetworkKey("cellular", "", "5g", 31133) == QLatin1String("cell:asn:31133:5g"));
    CHECK(upstreamNetworkKey("cellular", "", "", 0) == QLatin1String("unknown"));
    CHECK(upstreamNetworkKey("cellular", "25002", "3g", 0) == QLatin1String("unknown")); // malformed code is never sent
    CHECK(upstreamNetworkKey("wifi", "250-02", "lte", 12389) == QLatin1String("wifi:asn:12389"));
    CHECK(upstreamNetworkKey("ethernet", "", "", 0) == QLatin1String("wifi"));
    CHECK(upstreamNetworkKey("", "", "", 0) == QLatin1String("unknown"));
    for (const QString &k : {upstreamNetworkKey("cellular", "250-020", "2g", 0), upstreamNetworkKey("wifi", "", "", 4294967295LL),
                             QStringLiteral("unknown")})
        CHECK(upstreamNetworkKeyValid(k));
    CHECK(!upstreamNetworkKeyValid("wifi:ssid:Home") && !upstreamNetworkKeyValid("wifi:aa:bb:cc:dd:ee:ff"));
}

static void envelopeAndParsing()
{
    setFlags(true);
    const SubscriptionNode stub = stubOf();
    XrayConfigBuilder::UpstreamEnvelopeInput in;
    in.nodeId = stub.nodeId;
    in.profileId = stub.upstream->profileId;
    in.configSha256 = stub.upstream->configSha256;
    in.coreConfig = "{\"outbounds\":[]}";
    in.dns = stub.dns;
    in.lease = QJsonObject{{"lease_id", "x"}};
    in.tunables = xrayTunablesFor(true);
    const QJsonObject env = XrayConfigBuilder::buildUpstream(in);
    CHECK(env.value("protocol").toString() == QLatin1String("xray") && env.value("splitTunnelType").toInt() == 0);
    CHECK(env.value("hostName").toString() == QLatin1String(kUpstreamDisplayHost)
          && env.value("xray_config_data").toObject().value("hostName").toString() == QLatin1String(kUpstreamDisplayHost));
    CHECK(env.value("xray_config_data").toObject().value("config").toString() == QLatin1String("{\"outbounds\":[]}"));
    CHECK(env.value("dns1").toString() == QLatin1String("1.1.1.1"));
    const QJsonObject meta = env.value("tribeSessionMetadata").toObject();
    CHECK(meta.value("node_id").toString() == stub.nodeId && meta.value("proto").toString() == QLatin1String("xray")
          && meta.value("upstream").toInt() == 1 && meta.value("profile_id").toString() == stub.upstream->profileId
          && meta.value("config_sha256").toString() == stub.upstream->configSha256 && meta.value("schema_version").toInt() == 1);
    CHECK(env.contains("upstream_lease") && env.value("xray_tunables").toObject().value("memory_limit_mib").toInt() == 30);
    in.lease = QJsonObject(); // provisional
    CHECK(!XrayConfigBuilder::buildUpstream(in).contains("upstream_lease"));
    in.coreConfig.clear();
    CHECK(XrayConfigBuilder::buildUpstream(in).isEmpty());
    // The report: no host, no config, no token.
    const QJsonObject rep = XrayConfigBuilder::reportSummaryUpstream(stub, true, QStringLiteral("tunnel"));
    CHECK(rep.value("profile_id").toString() == stub.upstream->profileId && rep.value("provisional").toBool()
          && !rep.contains("endpoint") && !rep.contains("config"));
    // Tunables: own Xray only with server keys (none = today's envelope); clamps.
    TuningStore::set({}, {{QStringLiteral("upstream_nodes"), true}, {QStringLiteral("xray_client"), true}}, {}, {});
    CHECK(xrayTunablesFor(false).isEmpty());
    TuningStore::set({{QStringLiteral("xray_memory_limit_mib"), 99}, {QStringLiteral("xray_hev_tcp_buffer_size"), 8192},
                      {QStringLiteral("xray_hev_max_session_count"), 5}},
                     {{QStringLiteral("upstream_nodes"), true}, {QStringLiteral("xray_client"), true}}, {}, {});
    const QJsonObject tun = xrayTunablesFor(false);
    CHECK(tun.value("memory_limit_mib").toInt() == 40 && tun.value("hev_tcp_buffer_size").toInt() == 8192
          && tun.value("hev_max_session_count").toInt() == 128 && !tun.contains("hev_task_stack_size"));
    TuningStore::set({{QStringLiteral("xray_hev_tcp_buffer_size"), 100}, {QStringLiteral("xray_hev_task_stack_size"), 1e9}}, {}, {}, {});
    CHECK(xrayTunablesFor(false).value("hev_tcp_buffer_size").toInt() == 4096
          && xrayTunablesFor(false).value("hev_task_stack_size").toInt() == 131072);
    setFlags(true);

    // Probe grant / meter tags / error reason parsing.
    UpstreamProbeGrant pg;
    CHECK(parseUpstreamProbeGrant(QJsonValue(), pg) && !pg.present);
    CHECK(parseUpstreamProbeGrant(QJsonObject{{"scan_token", "tsc1.abc"}, {"expires_in_s", 600}, {"access_asn", QJsonValue()},
                                              {"access_net_token", QJsonValue()}, {"path", "/v1/probe"}}, pg)
          && pg.present && pg.accessAsn == 0 && pg.accessNetToken.isEmpty() && pg.scanToken == QLatin1String("tsc1.abc"));
    CHECK(parseUpstreamProbeGrant(QJsonObject{{"scan_token", "t"}, {"expires_in_s", 60}, {"access_asn", 12389},
                                              {"access_net_token", "nt"}}, pg) && pg.accessAsn == 12389 && pg.path == QLatin1String("/v1/probe"));
    CHECK(!parseUpstreamProbeGrant(QJsonObject{{"expires_in_s", 60}}, pg));
    // The final contract's literal form: probe.scan_token is the whole opaque "tsc1.<base64url>" value and
    // goes into Authorization: Bearer exactly as delivered (no second prefix).
    CHECK(parseUpstreamProbeGrant(QJsonObject{{"scan_token", "tsc1.test-token"}, {"expires_in_s", 600},
                                              {"access_asn", QJsonValue()}, {"access_net_token", QJsonValue()},
                                              {"path", "/v1/probe"}}, pg)
          && pg.scanToken == QLatin1String("tsc1.test-token"));
    CHECK(upstreamProbeAuthorization(pg.scanToken) == QByteArrayLiteral("Bearer tsc1.test-token"));
    // Every report carries epoch (required by the final contract, minimum 1): the machine's epoch after a grant.
    CHECK(QJsonDocument::fromJson(upstreamMeterBody({1, 0, 0, MeterScope::Tunnel, 1})).object().value("epoch").toInteger() == 1);
    CHECK(!parseUpstreamProbeGrant(QJsonObject{{"scan_token", "t"}, {"expires_in_s", 60}, {"path", "/../x"}}, pg));
    CHECK(!parseUpstreamProbeGrant(QJsonObject{{"scan_token", "t t"}, {"expires_in_s", 60}}, pg));
    CHECK(!parseUpstreamProbeGrant(QJsonValue(5), pg));
    QStringList tags;
    CHECK(parseUpstreamMeterTags(QJsonValue(), tags) && tags.isEmpty());
    CHECK(parseUpstreamMeterTags(QJsonArray{"a", "b"}, tags) && tags.size() == 2);
    CHECK(!parseUpstreamMeterTags(QJsonArray{"a", "a"}, tags) && !parseUpstreamMeterTags(QJsonArray{1}, tags)
          && !parseUpstreamMeterTags(QJsonValue("a"), tags));
    CHECK(upstreamEffectiveScope(MeterScope::Proxy, {"a"}) == MeterScope::Proxy);
    CHECK(upstreamEffectiveScope(MeterScope::Proxy, {}) == MeterScope::Tunnel);
    CHECK(upstreamEffectiveScope(MeterScope::Tunnel, {"a"}) == MeterScope::Tunnel);
    CHECK(upstreamMeterScopeForBuild() == MeterScope::Tunnel); // no platform has a verified per-outbound read
    CHECK(parseUpstreamError(R"({"code":"lease_gone","reason":"seat_taken"})").reason == QLatin1String("seat_taken"));
    CHECK(parseUpstreamError(R"({"code":"lease_gone","reason":"Seat Taken"})").reason.isEmpty());
    // The acquire's bound is below the reconcile watchdog (bounds in code, §17.2).
    for (double wd : {5000.0, 15000.0, 120000.0})
        for (double v : {0.0, 6000.0, 1e9}) {
            TuningStore::set({{QStringLiteral("reconcile_watchdog_ms"), wd}, {QStringLiteral("upstream_acquire_timeout_ms"), v}}, {}, {}, {});
            CHECK(upstreamAcquireTimeoutMsTuned() >= 2000 && upstreamAcquireTimeoutMsTuned() <= qMax(2000, reconcileWatchdogMsTuned() - 4000));
        }
    TuningStore::set({}, {}, {}, {});
    CHECK(upstreamAcquireTimeoutMsTuned() == 6000);
}

// --- 8) cold start in a whitelist window (end to end at the engine level, fakes) ---------------------
// The phone: cached signed config (age in/out of its bound), LKG subscription (with or without the stubs),
// a stored standby pack (usable/expired). The API is unreachable directly (every direct acquire = no
// answer) and own nodes do not start. Auto tries own nodes, the upstream tier opens, a profile starts
// FROM THE PACK, the seat is acquired through the tunnel (grant / no_seat / terminal), the data check
// runs, Connected. The glue the facade does (reconcile restart after an Error, onTunnelUp, verification)
// is done by the loop below exactly in the facade's order.
enum class TunnelAnswer { Grant, NoSeat, Terminal };
struct ColdResult {
    bool connected = false;
    QString node;            // the node Connected on
    QStringList ups;         // every bring-up asked of the tunnel
    QStringList standbyAcquires; // profiles acquired through the tunnel
    QStringList leaves;      // codes of leave events
    bool provisionalUsed = false;
    int ownUps = 0;          // own nodes the tunnel was asked to start
    qint64 firstProviderAtMs = -1; // fake clock from the tap to the first provider bring-up
};

// The modelled costs on the fake clock (from the code, see the report): the start preparation's ICMP
// round (probeAll timeout 1500 ms < soft budget kStartPrepSoftBudgetMs 2000 ms), an own start that does
// not come up (iOS: the start watchdog, up to 3 x 15 s), a direct acquire without an answer (its bound).
static const qint64 kIcmpRoundMs = 1500;
static const qint64 kOwnStartFailMs = 45000;

static QByteArray standbyPackBody(const TestKey &key, qint64 issuedMs, qint64 revision, const QList<QPair<QString, int>> &profiles,
                                  QHash<QString, QByteArray> &configs)
{
    QJsonArray entries;
    int ordinal = 0;
    for (const auto &p : profiles) {
        ++ordinal;
        const QByteArray cfg = QByteArrayLiteral("{\"inbounds\":[],\"p\":\"") + p.first.toLatin1() + "\"}";
        configs.insert(p.first, cfg);
        entries << QJsonObject{{"profile_id", p.first}, {"node_id", QStringLiteral("up:") + p.first}, {"label", "L"},
                               {"country_code", "NL"}, {"tier", p.second}, {"probe_class", "single"},
                               {"config", QString::fromUtf8(cfg)},
                               {"config_sha256", QString::fromLatin1(QCryptographicHash::hash(cfg, QCryptographicHash::Sha256).toHex())},
                               {"meter_tags", QJsonArray{"proxy"}}, {"ordinal", ordinal}};
    }
    const QJsonObject pack{{"type", "upstream_standby"}, {"version", 1},
                           {"issued_at", QDateTime::fromMSecsSinceEpoch(issuedMs, QTimeZone::UTC).toString(Qt::ISODateWithMs)},
                           {"max_age_s", 259200}, {"upstream_revision", double(revision)},
                           {"tunnel_api_base", "https://tunnel-api.example.net"}, {"entries", entries}};
    Q_UNUSED(key)
    return QJsonDocument(pack).toJson(QJsonDocument::Compact);
}

static ColdResult coldStart(qint64 configAgeH, bool packFresh, bool lkgHasStubs, TunnelAnswer answer,
                            bool fastEvidence = false)
{
    const TestKey key;
    const qint64 now = 1763200000000LL;
    // 1) The cached signed config, judged exactly as ConfigService::start does (UpstreamNode.h).
    const bool flag = upstreamTrustedFromCache(true, now - configAgeH * 3600000LL, now, upstreamCacheMaxAgeMs(72));
    TuningStore::set({}, {{QStringLiteral("upstream_nodes"), flag}, {QStringLiteral("xray_client"), true},
                          {QStringLiteral("transport_auto_pick"), true}}, {}, {});
    // 2) The LKG subscription, parsed after the config (AvpnEngineQml constructor order).
    QJsonArray nodes{awgNode("9", 9, "EE"), awgNode("2", 2, "PL"), awgNode("5", 5, "US"), awgNode("3", 3, "FI")};
    QHash<QString, QByteArray> packConfigs;
    const QByteArray packBody = standbyPackBody(key, packFresh ? now - 3600000LL : now - 80LL * 3600000LL, 1763117000999LL,
                                                {{"aaaaaaaaaaaaaaa0", 1}, {"aaaaaaaaaaaaaaa1", 1}}, packConfigs);
    const QByteArray sig = key.sign(QByteArrayLiteral("tribe-upstream-standby-v1\n") + packBody);
    if (lkgHasStubs)
        for (const QString &pid : {QStringLiteral("aaaaaaaaaaaaaaa0"), QStringLiteral("aaaaaaaaaaaaaaa1")})
            nodes << stubNode(pid, 1, pid.endsWith('0') ? 0 : 1,
                              QString::fromLatin1(QCryptographicHash::hash(packConfigs.value(pid), QCryptographicHash::Sha256).toHex()));
    ServiceEngine e;
    FakeTunnel t;
    e.setTunnel(&t);
    QString err;
    CHECK(e.loadSubscriptionFromLkg(body(nodes, 1, 1763117000123.0), err));
    // 3) The stored pack (re-verified on load) and its candidates.
    const StandbyParse pp = parseStandbyPack(packBody, sig, key.pubHex());
    CHECK(pp.ok());
    if (flag)
        e.setStandbyCandidates(standbyPackCandidates(pp.pack, e.subscriptionNodes(), e.upstreamRevision(), now,
                                                     upstreamStandbyMaxAgeSTuned()));
    // 4) The tunnel owner of the adapter (iOS semantics: it hands over; the decisions are the same).
    FakeIo io;
    UpstreamLeaseOwner owner(&io);
    ColdResult res;
    e.beginUserAttempt();
    // The tap at fake time 0; the start preparation runs its ICMP round (own nodes: no answer).
    qint64 clock = kIcmpRoundMs;
    if (fastEvidence) {
        FastTierEvidence ev;
        ev.nowMs = now;
        ev.rttRoundAtMs = now;          // the round just completed
        ev.ownProbed = 4;
        ev.ownAnswered = 0;
        ev.apiTransportFailAtMs = now - 20000; // the startup /v1/config got no answer (its 15 s bound)
        e.setFastTierEvidence(ev);
    }
    bool connecting = e.connect(err);
    qint64 mono = 1000;
    for (int round = 0; round < 12 && connecting && !res.connected; ++round) {
        mono += 1000;
        const QString node = t.ups.isEmpty() ? QString() : t.ups.last();
        res.ups = t.ups;
        const SubscriptionNode *n = e.nodeById(node);
        CHECK(n != nullptr);
        if (!n)
            break;
        if (!isUpstreamNode(*n)) {
            // Own node: no handshake in the whitelist window -> native Error during the start.
            ++res.ownUps;
            clock += kOwnStartFailMs;
            e.onTunnelError();
            e.noteStartFailedForTier(QStringLiteral("native_error"));
            connecting = e.connect(err);
            continue;
        }
        // Upstream bring-up (VpnConnectionTunnelControl::upUpstream): the pack entry if usable.
        std::optional<StandbyCandidate> sc;
        StandbyCandidate c;
        if (standbyCandidateFor(pp.pack, *n, e.upstreamRevision(), now, upstreamStandbyMaxAgeSTuned(), c))
            sc = c;
        auto ev = owner.begin(*n, e.upstreamRevision(), sc, mono, now);
        ev = owner.onAcquireReply(io.last("acquire")->id, failed("transport"), mono + 50); // the API is unreachable
        clock += upstreamAcquireTimeoutMsTuned(); // the direct acquire's bound
        if (const UpstreamOwnerEvent *f = findEv(ev, UpstreamOwnerEventKind::StartFailed)) {
            e.excludeForAttempt(n->nodeId, f->code);
            e.onTunnelError();
            connecting = e.connect(err);
            continue;
        }
        const UpstreamOwnerEvent *b = findEv(ev, UpstreamOwnerEventKind::BringUp);
        CHECK(b && b->provisional && b->config == packConfigs.value(n->upstream->profileId));
        res.provisionalUsed = res.provisionalUsed || (b && b->provisional);
        if (res.firstProviderAtMs < 0)
            res.firstProviderAtMs = clock;
        // The core started from the pack; the platform reports Connected -> Verifying + tunnelUp.
        CHECK(e.onTunnelConnected() && e.isVerifying());
        owner.tunnelUp(mono + 200);
        const FakeIo::Call *a = io.last("acquire");
        CHECK(a && a->route.apiBase == QLatin1String("https://tunnel-api.example.net") && !a->sha.isEmpty());
        res.standbyAcquires << a->profileOrLease;
        AcquireReply r = answer == TunnelAnswer::Grant ? granted(n->upstream->profileId, a->sha, 1, true)
                         : answer == TunnelAnswer::NoSeat ? refused(UpstreamErrorCode::NoSeat)
                                                          : refused(UpstreamErrorCode::NotEntitled);
        if (answer == TunnelAnswer::Grant) {
            r.grant.probe.accessAsn = 0; // a standby acquire arrives through the provider: no access facts
            r.grant.probe.accessNetToken.clear();
        }
        ev = owner.onAcquireReply(a->id, r, mono + 400);
        if (const UpstreamOwnerEvent *l = findEv(ev, UpstreamOwnerEventKind::Leave)) {
            res.leaves << l->code;
            CHECK(e.leaveUpstreamNode(l->code));
            if (e.state() == EngineState::Switching) {
                e.onTunnelDisconnected();
                connecting = e.state() == EngineState::Switching || e.state() == EngineState::Connecting;
            } else {
                connecting = false;
            }
            continue;
        }
        CHECK(findEv(ev, UpstreamOwnerEventKind::LeaseConfirmed));
        // The data check (the facade): the probe grant of the confirmed lease, the verdict.
        const UpstreamProbeGrant g = owner.probeGrant(mono + 500);
        CHECK(decideUpstreamVerifyRoute(g.present, owner.provisionalPending(), 5000) == UpstreamVerifyRoute::Probe);
        UpstreamProbeFacts f;
        f.httpStatus = 200;
        f.nonce = "abcdefgh12345678";
        f.bytesRequested = f.bytesReceived = 131072;
        f.bodySha256Hex = tribeProbeExpectedSha256Hex(f.nonce, f.bytesRequested);
        f.elapsedMs = 900;
        f.egressClass = QStringLiteral("other");
        const UpstreamVerdictResult v = judgeUpstreamCheck(upstreamCheckInputFrom(f, g, false));
        CHECK(v.passes);
        CHECK(e.verifySucceeded());
        res.connected = e.state() == EngineState::Connected;
        res.node = e.currentNodeId();
    }
    res.ups = t.ups;
    return res;
}

static void coldStartWhitelistWindow()
{
    // The main case: config 1 day old (inside the 72 h bound), fresh pack, LKG with the stubs.
    ColdResult r = coldStart(24, true, true, TunnelAnswer::Grant);
    CHECK(r.connected && isStubId(r.node) && r.provisionalUsed);
    CHECK(r.ups.size() == 4);
    for (int i = 0; i < 3 && i < r.ups.size(); ++i)
        CHECK(!isStubId(r.ups.at(i))); // own nodes first, K = 3 of them
    CHECK(r.ups.value(3) == QLatin1String("up:aaaaaaaaaaaaaaa0") && r.standbyAcquires == QStringList({"aaaaaaaaaaaaaaa0"}));
    CHECK(r.ownUps == 3 && r.firstProviderAtMs == kIcmpRoundMs + 3 * kOwnStartFailMs + upstreamAcquireTimeoutMsTuned());
    // With the evidence of a whitelist window (no own node answered the round, the API got no answer):
    // the first provider start without any own bring-up, ~7.5 s after the tap instead of ~2.5 min.
    r = coldStart(24, true, true, TunnelAnswer::Grant, /*fastEvidence=*/true);
    CHECK(r.connected && isStubId(r.node) && r.ownUps == 0 && !r.ups.isEmpty() && isStubId(r.ups.first()));
    CHECK(r.firstProviderAtMs == kIcmpRoundMs + upstreamAcquireTimeoutMsTuned() && r.firstProviderAtMs <= 8000);
    r = coldStart(24, true, false, TunnelAnswer::Grant, true); // pack-sourced candidates: the same
    CHECK(r.connected && r.ownUps == 0);
    // Every provider refuses the seat: the attempt ends - never a silent fall-back into own-node starts.
    r = coldStart(24, true, true, TunnelAnswer::NoSeat, true);
    CHECK(!r.connected && r.ownUps == 0);
    for (const QString &u : r.ups)
        CHECK(isStubId(u));
    // The LKG subscription predates the profiles (no stubs): pack-sourced candidates, same result.
    r = coldStart(24, true, false, TunnelAnswer::Grant);
    CHECK(r.connected && isStubId(r.node) && r.provisionalUsed);
    // The config is older than the bound: the switch reads off - own nodes only, never a profile.
    r = coldStart(80, true, true, TunnelAnswer::Grant);
    CHECK(!r.connected && r.standbyAcquires.isEmpty());
    for (const QString &u : r.ups)
        CHECK(!isStubId(u));
    // The pack is expired: the profile cannot start (no provisional), excluded; no seat acquired.
    r = coldStart(24, false, true, TunnelAnswer::Grant);
    CHECK(!r.connected && !r.provisionalUsed && r.standbyAcquires.isEmpty());
    // The tunnel acquire answers no_seat: leave that profile, the next one is tried (and also refused).
    r = coldStart(24, true, true, TunnelAnswer::NoSeat);
    CHECK(!r.connected && r.leaves.value(0) == QLatin1String("no_seat_standby"));
    CHECK(r.standbyAcquires.size() >= 1 && r.standbyAcquires.value(0) == QLatin1String("aaaaaaaaaaaaaaa0"));
    // A terminal answer through the tunnel: leave with its code.
    r = coldStart(24, true, true, TunnelAnswer::Terminal);
    CHECK(!r.connected && r.leaves.value(0) == QLatin1String("not_entitled"));
    // Pack candidates are not synthesized when the subscription is newer than the pack, nor for a
    // profile the subscription has a stub for.
    {
        const TestKey key;
        QHash<QString, QByteArray> cfgs;
        const qint64 now = 1763200000000LL;
        const QByteArray b = standbyPackBody(key, now - 3600000LL, 100, {{"aaaaaaaaaaaaaaa0", 1}, {"ddddddddddddddd0", 2}}, cfgs);
        const StandbyParse p = parseStandbyPack(b, key.sign(QByteArrayLiteral("tribe-upstream-standby-v1\n") + b), key.pubHex());
        CHECK(p.ok());
        setFlags(true);
        const Subscription sub = parse(body(QJsonArray{awgNode("9", 9, "EE"), stubNode("aaaaaaaaaaaaaaa0", 1, 0)}, 1, 99));
        QList<SubscriptionNode> c = standbyPackCandidates(p.pack, sub.nodes, sub.upstreamRevision, now, 259200);
        CHECK(c.size() == 1 && c[0].nodeId == QLatin1String("up:ddddddddddddddd0") && c[0].upstream->packSourced
              && c[0].upstream->tier == 2 && c[0].countryCode == QLatin1String("NL") && c[0].endpoint.isEmpty());
        // Release A naming: a pack candidate carries the entry's display parts (label "L" is not custom).
        CHECK(c[0].upstream->ordinal == 2 && !c[0].upstream->labelCustom);
        CHECK(standbyPackCandidates(p.pack, sub.nodes, 100, now, 259200).isEmpty());        // the subscription is not older
        CHECK(standbyPackCandidates(p.pack, {}, 0, now, 259200).size() == 2);               // no pool at all
        CHECK(standbyPackCandidates(p.pack, sub.nodes, 99, now + 80LL * 3600000, 259200).isEmpty()); // pack expired
        // The engine: the candidates are pickable and marked pack-sourced in the snapshot; a refused
        // direct acquire never falls back to the pack (the owner rule) - see ownerAcquireOutcomes.
        ServiceEngine e;
        FakeTunnel t;
        e.setTunnel(&t);
        QString err;
        CHECK(e.loadSubscription(body(QJsonArray{awgNode("9", 9, "EE"), stubNode("aaaaaaaaaaaaaaa0", 1, 0)}, 1, 99), err));
        e.setStandbyCandidates(c);
        bool marked = false;
        for (const NodeDebugRow &r : e.debugSnapshot().pool)
            marked = marked || (r.nodeId == QLatin1String("up:ddddddddddddddd0") && r.packSourced && r.upstream && r.upstreamTier == 2);
        CHECK(marked);
        CHECK(e.setPinnedNode(QStringLiteral("up:ddddddddddddddd0"), err) && e.connect(err)
              && t.ups.last() == QLatin1String("up:ddddddddddddddd0"));
    }
    // Device-side geo check: a stub routing by a tag the build does not ship is never offered.
    setFlags(true);
    QJsonObject cn = stubNode("eeeeeeeeeeeeeee0", 1, 0);
    QJsonObject up = cn.value("upstream").toObject();
    up.insert("required_geo", QJsonArray{"geoip:ru", "geosite:cn"});
    cn.insert("upstream", up);
    const Subscription geo = parse(body(QJsonArray{cn, stubNode("aaaaaaaaaaaaaaa0", 1, 0)}));
    CHECK(geo.nodes.size() == 2 && !isSupportedProtoNode(geo.nodes[0]) && isSupportedProtoNode(geo.nodes[1]));
}

// --- 9) own tier pre-exhausted by evidence (D9 "unreachable in stage 1") -----------------------------
static void fastTierOpen()
{
    const qint64 now = 1763200000000LL, w = 60000;
    FastTierEvidence ev;
    ev.nowMs = now;
    ev.rttRoundAtMs = now - 2000;
    ev.ownProbed = 4;
    ev.ownAnswered = 0;
    ev.apiTransportFailAtMs = now - 10000;
    CHECK(decideFastTierOpen(ev, true, false, 4, true, w).fire);
    CHECK(decideFastTierOpen(ev, true, false, 4, true, w).evidence.contains(QLatin1String("own_probed=4")));
    const auto why = [&](const FastTierEvidence &x, bool en = true, bool manual = false, int own = 4, bool up = true) {
        return decideFastTierOpen(x, en, manual, own, up, w).why;
    };
    FastTierEvidence x = ev;
    x.ownAnswered = 1;
    CHECK(why(x) == QLatin1String("own_answered"));             // one own node answered: never
    x = ev;
    x.apiAnswerAtMs = now - 5000;                                // a refusal / HTTP answer after the failure
    CHECK(why(x) == QLatin1String("api_alive"));
    x.whitelistActive = true;                                     // ... unless the whitelist detector says so
    CHECK(why(x) == QLatin1String("fired"));
    x = ev;
    x.apiTransportFailAtMs = -1;
    CHECK(why(x) == QLatin1String("api_alive"));                  // ICMP blocked but the API path unknown/alive
    x.apiTransportFailAtMs = now - w - 1;
    CHECK(why(x) == QLatin1String("api_alive"));                  // the failure is older than the window
    CHECK(why(ev, true, false, 4, false) == QLatin1String("no_upstream"));
    x = ev;
    x.rttRoundAtMs = now - w - 1;
    CHECK(why(x) == QLatin1String("stale_round"));
    x.rttRoundAtMs = -1;
    CHECK(why(x) == QLatin1String("no_round"));
    x = ev;
    x.ownProbed = 1;
    CHECK(why(x) == QLatin1String("too_few_probed"));             // min(2, own count) must be probed
    CHECK(why(x, true, false, 1) == QLatin1String("fired"));      // a pool with one own node: one is enough
    x.ownProbed = 0;
    CHECK(why(x, true, false, 0) == QLatin1String("too_few_probed"));
    CHECK(why(ev, true, true) == QLatin1String("manual"));
    CHECK(why(ev, false) == QLatin1String("off"));
    CHECK(upstreamFastOpenWindowMsFrom(0) == 10000 && upstreamFastOpenWindowMsFrom(1e9) == 300000
          && upstreamFastOpenWindowMsFrom(std::numeric_limits<double>::quiet_NaN()) == 60000);

    // The engine: Auto goes straight to the upstream tier; a pin is unaffected; the next attempt decides
    // again; the kill switch off = the decision without the rule.
    QString err;
    const auto fresh = [&](bool fastSwitch) {
        TuningStore::set({}, {{QStringLiteral("upstream_nodes"), true}, {QStringLiteral("xray_client"), true},
                              {QStringLiteral("transport_auto_pick"), true},
                              {QLatin1String(kUpstreamFastTierFlag), fastSwitch}}, {}, {});
    };
    fresh(true);
    {
        ServiceEngine e;
        FakeTunnel t;
        e.setTunnel(&t);
        CHECK(e.loadSubscription(body(realisticPool()), err));
        e.setFastTierEvidence(ev);
        CHECK(e.connect(err) && t.ups.last() == QLatin1String("up:aaaaaaaaaaaaaaa0") && e.fastTierOpen());
        CHECK(e.switchLog().join('\n').contains(QLatin1String("own tier pre-exhausted by evidence: own_probed=4")));
        // The upstream tier used up too (both tier 1 and tier 2 fail their data check): no own node.
        e.setVerifyEveryTransport(true);
        for (int i = 0; i < 6 && e.state() != EngineState::Error; ++i) {
            if (!e.onTunnelConnected())
                break;
            e.verifyFailed(QStringLiteral("upstream no_data (failover)"));
            if (e.state() == EngineState::Switching)
                e.onTunnelDisconnected();
        }
        for (const QString &u : t.ups)
            CHECK(isStubId(u));
        CHECK(e.state() == EngineState::Error);
        // Next attempt: an own node answered the new round - own nodes again.
        e.requestStop();
        e.beginUserAttempt();
        FastTierEvidence recovered = ev;
        recovered.ownAnswered = 2;
        e.setFastTierEvidence(recovered);
        CHECK(e.connect(err) && !isStubId(t.ups.last()) && !e.fastTierOpen()
              && e.fastTierWhy() == QLatin1String("own_answered"));
        // A pin of an own node: never pre-exhausted.
        e.requestStop();
        e.beginUserAttempt();
        e.setFastTierEvidence(ev);
        CHECK(e.setPinnedNode(QStringLiteral("9"), err) && e.connect(err) && t.ups.last() == QLatin1String("9")
              && e.fastTierWhy() == QLatin1String("manual"));
    }
    // The facade's own restart inside the attempt (a start Error, no stop): connect() decides again on the
    // evidence of that moment - an own node answered now, so own nodes are used again.
    {
        ServiceEngine e;
        FakeTunnel t;
        e.setTunnel(&t);
        CHECK(e.loadSubscription(body(realisticPool()), err));
        e.setFastTierEvidence(ev);
        CHECK(e.connect(err) && isStubId(t.ups.last()));
        e.excludeForAttempt(t.ups.last(), QStringLiteral("transport"));
        e.onTunnelError();
        FastTierEvidence answered = ev;
        answered.ownAnswered = 1;
        e.setFastTierEvidence(answered);
        CHECK(e.connect(err) && !isStubId(t.ups.last()) && !e.fastTierOpen());
    }
    // Kill switch off: the same evidence changes nothing (own nodes first).
    fresh(false);
    {
        ServiceEngine e;
        FakeTunnel t;
        e.setTunnel(&t);
        CHECK(e.loadSubscription(body(realisticPool()), err));
        e.setFastTierEvidence(ev);
        CHECK(e.connect(err) && !isStubId(t.ups.last()) && !e.fastTierOpen() && e.fastTierWhy() == QLatin1String("off"));
    }
    // upstream_nodes off: identical picks with or without the evidence (deterministic pool: measured RTT).
    TuningStore::set({}, {{QStringLiteral("upstream_nodes"), false}, {QStringLiteral("xray_client"), true},
                          {QStringLiteral("transport_auto_pick"), true}}, {}, {});
    for (int k = 0; k < 2; ++k) {
        QStringList picks;
        for (bool withEvidence : {false, true}) {
            ServiceEngine e;
            FakeTunnel t;
            e.setTunnel(&t);
            CHECK(e.loadSubscription(body(realisticPool()), err));
            e.setMeasuredRtt({{"9", 40 + k}, {"2", 20}, {"5", 90}, {"3", 30}, {"7", 10 + 30 * k}});
            if (withEvidence)
                e.setFastTierEvidence(ev);
            CHECK(e.connect(err));
            picks << t.ups.last() + QLatin1Char('|') + e.switchLog().join('\n');
            CHECK(!e.fastTierOpen());
        }
        CHECK(picks[0].section('|', 0, 0) == picks[1].section('|', 0, 0));
    }
    setFlags(true);
}

// Lab 14.11 D3: the first seconds of a provider profile may refuse every connection. The data check's loop
// as the facade runs it (AvpnEngineQml::upstreamVerifyAttempt), on a fake clock: first attempt at 800 ms,
// each attempt then decideUpstreamEarlyRetry(upstreamProbeNotYet(facts), retries so far, budget left).
struct EarlyRun {
    UpstreamVerdictResult verdict;
    int attempts = 0;
    qint64 endedAtMs = 0;
    QList<qint64> spacing;
};
static EarlyRun runEarlyCheck(const std::function<UpstreamProbeFacts(qint64)> &attemptAt, qint64 budgetMs,
                              const UpstreamProbeGrant &access)
{
    EarlyRun r;
    qint64 t = 800;
    for (int guard = 0; guard < 100; ++guard) {
        ++r.attempts;
        const UpstreamProbeFacts f = attemptAt(t);
        t += qMax<qint64>(1, f.elapsedMs);
        r.verdict = judgeUpstreamCheck(upstreamCheckInputFrom(f, access, false));
        const UpstreamEarlyRetry next = decideUpstreamEarlyRetry(upstreamProbeNotYet(f), r.attempts - 1, budgetMs - t);
        if (!next.retry)
            break;
        r.spacing << next.delayMs;
        t += next.delayMs;
    }
    r.endedAtMs = t;
    return r;
}

static void earlyRefusals()
{
    // The spacing and the classification.
    CHECK(upstreamEarlyRetryDelayMs(1) == 300 && upstreamEarlyRetryDelayMs(2) == 600 && upstreamEarlyRetryDelayMs(3) == 1200
          && upstreamEarlyRetryDelayMs(4) == 2000 && upstreamEarlyRetryDelayMs(9) == 2000 && upstreamEarlyRetryDelayMs(0) == 300);
    UpstreamProbeFacts f;
    f.bytesRequested = 131072;
    CHECK(upstreamProbeNotYet(f));                       // refused / reset: no HTTP answer, no byte
    f.httpStatus = 200;
    CHECK(upstreamProbeNotYet(f));                       // headers but no first byte
    f.httpStatus = 401;
    CHECK(!upstreamProbeNotYet(f));                      // our server answered: judged at once
    f.httpStatus = 200;
    f.bytesReceived = 10;
    CHECK(!upstreamProbeNotYet(f));                      // data started: judged at once
    CHECK(!decideUpstreamEarlyRetry(false, 0, 12000).retry);
    CHECK(decideUpstreamEarlyRetry(true, 0, 12000).retry && decideUpstreamEarlyRetry(true, 0, 12000).delayMs == 300);
    CHECK(decideUpstreamEarlyRetry(true, 0, 1300).retry && !decideUpstreamEarlyRetry(true, 0, 1299).retry); // >= 1 s left after
    CHECK(!decideUpstreamEarlyRetry(true, 3, 2999).retry && decideUpstreamEarlyRetry(true, 3, 3000).delayMs == 2000);

    const QByteArray nonce = "abcdefgh12345678";
    const qint64 n = 131072;
    UpstreamProbeGrant access;
    access.present = true;
    access.accessAsn = 12389;
    access.accessNetToken = QStringLiteral("net-a");
    const auto refused = []() {
        UpstreamProbeFacts x;
        x.bytesRequested = 131072;
        x.elapsedMs = 3;
        return x;
    };
    const auto complete = [&](const char *net, const QByteArray &sha) {
        UpstreamProbeFacts x;
        x.httpStatus = 200;
        x.bytesRequested = n;
        x.bytesReceived = n;
        x.nonce = nonce;
        x.bodySha256Hex = sha;
        x.elapsedMs = 700;
        x.ttfbMs = 250;
        x.maxStallMs = 80;
        x.egressClass = QStringLiteral("other");
        x.egressAsnHeader = QStringLiteral("8881");
        x.egressNetToken = QLatin1String(net);
        return x;
    };
    const QByteArray good = tribeProbeExpectedSha256Hex(nonce, n);
    // Refused for the first 1.2 s after the core start, then the profile carries data: Works.
    EarlyRun w = runEarlyCheck([&](qint64 t) { return t < 1200 ? refused() : complete("net-b", good); }, 12000, access);
    CHECK(w.verdict.verdict == UpstreamVerdict::Works && w.verdict.passes);
    CHECK(w.attempts == 3 && w.spacing == QList<qint64>({300, 600})); // 800 refused, 1103 refused, 1706 data
    // A longer mobile warm-up (refused for 4 s): still Works inside the 12 s budget.
    w = runEarlyCheck([&](qint64 t) { return t < 4000 ? refused() : complete("net-b", good); }, 12000, access);
    CHECK(w.verdict.verdict == UpstreamVerdict::Works && w.spacing == QList<qint64>({300, 600, 1200, 2000}));
    // Refused for the whole budget: NoData from the last attempt, never past the budget.
    w = runEarlyCheck([&](qint64) { return refused(); }, 12000, access);
    CHECK(w.verdict.verdict == UpstreamVerdict::NoData && w.verdict.reason == QLatin1String("no_first_byte") && !w.verdict.passes);
    CHECK(w.endedAtMs <= 12000 && w.attempts >= 6);
    // The first COMPLETE answer says "not through the provider": final at once, no retries.
    w = runEarlyCheck([&](qint64) { return complete("net-a", good); }, 12000, access);
    CHECK(w.verdict.verdict == UpstreamVerdict::NotThroughProvider && w.attempts == 1 && w.spacing.isEmpty());
    // A complete download with a wrong digest: final at once.
    w = runEarlyCheck([&](qint64) { return complete("net-b", QByteArray(64, 'f')); }, 12000, access);
    CHECK(w.verdict.reason == QLatin1String("digest_mismatch") && w.attempts == 1);
    // Refused first, then a complete bad answer: that last answer decides.
    w = runEarlyCheck([&](qint64 t) { return t < 1000 ? refused() : complete("net-a", good); }, 12000, access);
    CHECK(w.verdict.verdict == UpstreamVerdict::NotThroughProvider && w.attempts == 2);
    // A tiny budget (the server's minimum 3 s): one early retry at most fits.
    w = runEarlyCheck([&](qint64) { return refused(); }, 3000, access);
    CHECK(w.verdict.verdict == UpstreamVerdict::NoData && w.endedAtMs <= 3000);
}

// Release A (point 16): the picker rows of provider profiles and the user's notices.
static void picker16AndNotices()
{
    // A stub is always its own location, also when the server sends the host_id of one of OUR hosts:
    // its row never merges with ours (label, exit RTT, transport badges, pin) and ours never with it.
    setFlags(true);
    QJsonObject collide = stubNode("aaaaaaaaaaaaaaa0", 1, 0, sha64('a'), "EE");
    collide.insert("host_id", 9);
    QJsonObject second = stubNode("aaaaaaaaaaaaaaa1", 1, 1, sha64('a'), "EE");
    second.insert("host_id", 9);
    const QJsonArray pool{awgNode("9", 9, "EE"), collide, second, stubNode("aaaaaaaaaaaaaaa2", 2, 0)};
    const Subscription sub = parse(body(pool));
    CHECK(sub.nodes.size() == 4);
    CHECK(locationKeyOf(sub.nodes.at(0)) == QLatin1String("h:9"));
    CHECK(locationKeyOf(sub.nodes.at(1)) == QLatin1String("u:up:aaaaaaaaaaaaaaa0"));
    CHECK(locationKeyOf(sub.nodes.at(2)) == QLatin1String("u:up:aaaaaaaaaaaaaaa1"));
    CHECK(locationKeyOf(sub.nodes.at(3)) == QLatin1String("u:up:aaaaaaaaaaaaaaa2")); // no country, no host
    ServiceEngine e;
    FakeTunnel t;
    e.setTunnel(&t);
    QString err;
    CHECK(e.loadSubscription(body(pool), err));
    const DebugSnapshot snap = e.debugSnapshot();
    QHash<QString, NodeDebugRow> rows;
    for (const NodeDebugRow &r : snap.pool)
        rows.insert(r.nodeId, r);
    CHECK(rows.size() == 4);
    const NodeDebugRow own = rows.value("9"), up0 = rows.value("up:aaaaaaaaaaaaaaa0"), up2 = rows.value("up:aaaaaaaaaaaaaaa2");
    CHECK(!own.upstream && own.location == QLatin1String("h:9") && own.transports == QStringList{"awg"});
    CHECK(up0.upstream && up0.upstreamTier == 1 && up0.location != own.location && up0.transports == QStringList{"xray"});
    CHECK(up0.name.isEmpty() && up0.endpoint.isEmpty());          // a non-custom label never reaches the row
    CHECK(up2.upstream && up2.upstreamTier == 2 && up2.countryCode.isEmpty());
    // The label shown for a row: pickerDisplay never borrows an own host's label for a stub.
    QList<PickerRow> display;
    for (const NodeDebugRow &r : snap.pool)
        display.append({r.location, r.proto, r.name, r.countryCode == QLatin1String("EE") ? QStringLiteral("Эстония") : QString(),
                        r.nodeId == QLatin1String("9") ? 40 : -1});
    display = pickerDisplay(display);
    for (int i = 0; i < snap.pool.size(); ++i)
        if (snap.pool.at(i).upstream)
            CHECK(display.at(i).rttMs == -1 && display.at(i).name != QLatin1String("Provider Name Ltd"));

    // Release A naming (owner decision 14.11): the admin's own label, else «<localized country> <n>», else
    // «Сервер <n>»; a server fallback such as "NL 1" is never shown.
    const QString srv = QStringLiteral("Сервер");
    CHECK(upstreamDisplayName("NL 1", false, 1, QStringLiteral("Нидерланды"), srv) == QStringLiteral("Нидерланды 1"));
    CHECK(upstreamDisplayName("NL 1", false, 0, QStringLiteral("Нидерланды"), srv) == QStringLiteral("Нидерланды"));
    CHECK(upstreamDisplayName("Быстрый Амстердам", true, 3, QStringLiteral("Нидерланды"), srv) == QStringLiteral("Быстрый Амстердам"));
    CHECK(upstreamDisplayName("  Свой  ", true, 3, QString(), srv) == QStringLiteral("Свой"));
    CHECK(upstreamDisplayName("   ", true, 3, QStringLiteral("Германия"), srv) == QStringLiteral("Германия 3")); // empty custom
    CHECK(upstreamDisplayName(QString(), false, 7, QString(), srv) == QStringLiteral("Сервер 7"));
    CHECK(upstreamDisplayName("Сервер 9", false, 0, QString(), srv) == QStringLiteral("Сервер"));
    CHECK(upstreamDisplayName("NL 1", false, 2, QStringLiteral("Netherlands"), QStringLiteral("Server")) == QStringLiteral("Netherlands 2"));
    // The engine row: the label only when custom, with the parts for the facade.
    {
        QJsonObject named = stubNode("aaaaaaaaaaaaaaa3", 1, 2, sha64('a'), "NL");
        QJsonObject plain = stubNode("aaaaaaaaaaaaaaa4", 1, 3, sha64('a'), "NL");
        QJsonObject nu = named.value("upstream").toObject();
        nu.insert("ordinal", 4);
        nu.insert("label_custom", true);
        named.insert("upstream", nu);
        named.insert("label", "Быстрый Амстердам");
        QJsonObject pu = plain.value("upstream").toObject();
        pu.insert("ordinal", 1);
        plain.insert("upstream", pu);
        plain.insert("label", "NL 1");
        ServiceEngine en;
        FakeTunnel tn;
        en.setTunnel(&tn);
        CHECK(en.loadSubscription(body(QJsonArray{awgNode("9", 9, "EE"), named, plain}), err));
        QHash<QString, NodeDebugRow> byId;
        for (const NodeDebugRow &r : en.debugSnapshot().pool)
            byId.insert(r.nodeId, r);
        const NodeDebugRow rn = byId.value("up:aaaaaaaaaaaaaaa3"), rp = byId.value("up:aaaaaaaaaaaaaaa4");
        CHECK(rn.name == QStringLiteral("Быстрый Амстердам") && rn.upstreamLabelCustom && rn.upstreamOrdinal == 4);
        CHECK(rp.name.isEmpty() && !rp.upstreamLabelCustom && rp.upstreamOrdinal == 1);
        CHECK(upstreamDisplayName(rp.name, rp.upstreamLabelCustom, rp.upstreamOrdinal, QStringLiteral("Нидерланды"), srv)
              == QStringLiteral("Нидерланды 1"));
        CHECK(byId.value("9").name.isEmpty() || byId.value("9").name != QStringLiteral("NL 1")); // own rows untouched
    }

    // Notices: one kind per outcome, a "code/detail" start failure by its code, nothing for the rest.
    CHECK(upstreamNoticeFor("no_seat") == UpstreamNotice::SeatsBusy);
    CHECK(upstreamNoticeFor("no_seat_reacquire") == UpstreamNotice::SeatsBusy);
    CHECK(upstreamNoticeFor("no_seat_standby") == UpstreamNotice::SeatsBusy);
    CHECK(upstreamNoticeFor("no_seat/retry") == UpstreamNotice::SeatsBusy);
    CHECK(upstreamNoticeFor(QLatin1String(upstreamVerdictName(UpstreamVerdict::NoData))) == UpstreamNotice::NoTraffic);
    CHECK(upstreamNoticeFor(QLatin1String(upstreamVerdictName(UpstreamVerdict::NotThroughProvider))) == UpstreamNotice::NoTraffic);
    CHECK(upstreamNoticeFor("standby_unconfirmed") == UpstreamNotice::NoTraffic);
    for (const char *c : {"disabled", "lease_gone", "not_entitled", "over_quota", "bridge_refused", "renew_rejected"})
        CHECK(upstreamNoticeFor(QLatin1String(c)) == UpstreamNotice::Unavailable);
    CHECK(upstreamNoticeFor(QLatin1String(upstreamVerdictName(UpstreamVerdict::Slow))) == UpstreamNotice::None);
    CHECK(upstreamNoticeFor(QLatin1String(upstreamVerdictName(UpstreamVerdict::Unverifiable))) == UpstreamNotice::None);
    CHECK(upstreamNoticeFor(QLatin1String(upstreamVerdictName(UpstreamVerdict::Works))) == UpstreamNotice::None);
    for (const char *c : {"transport", "http_429", "rate_limited", "invalid_answer", "profile_bad_json", "envelope",
                          "invoke", "", "something_new"})
        CHECK(upstreamNoticeFor(QLatin1String(c)) == UpstreamNotice::None);
}

// Point 15 (owner 15.11): a real quit of the macOS GUI ends an upstream session (release + stop); a hide, our
// own relaunch, own-node sessions and the switch off change nothing.
static void quitEndsUpstreamSession()
{
    // The decision table: kind x switch x session.
    for (AppExitKind k : {AppExitKind::Quit, AppExitKind::Restart, AppExitKind::Hide})
        for (bool on : {false, true})
            for (bool up : {false, true})
                CHECK(upstreamQuitEndsSession(k, on, up) == (k == AppExitKind::Quit && on && up));

    // With fakes: the engine, its tunnel and the macOS lease owner wired the way the facade's user stop is
    // (stop() -> engine requestStop, VpnConnectionTunnelControl::down -> owner.disconnect = the release).
    struct Rig {
        ServiceEngine e;
        FakeTunnel t;
        FakeIo io;
        UpstreamLeaseOwner owner{&io};
        qint64 clock = 0;
        int pumps = 0;
        bool disconnected = false;
        QStringList journal;
        UpstreamQuitHooks hooks(bool stopReachesService)
        {
            UpstreamQuitHooks h;
            h.userStop = [this]() {
                e.requestStop();
                owner.disconnect(clock);
                t.down();
            };
            h.stopped = [this]() { return disconnected; };
            h.pump = [this, stopReachesService](int ms) {
                ++pumps;
                clock += ms;
                if (stopReachesService && t.downs > 0 && clock >= 300)
                    disconnected = true; // the service reported Disconnected
            };
            h.nowMs = [this]() { return clock; };
            h.journal = [this](const QString &l) { journal << l; };
            return h;
        }
    };
    const SubscriptionNode stub = stubOf();
    const QString sha = stub.upstream->configSha256;
    UpstreamLeaseOwner::Options op;
    op.keepOwnership = true;
    const auto upstreamRig = [&](Rig &r) {
        QString err;
        setFlags(true);
        r.e.setTunnel(&r.t);
        CHECK(r.e.loadSubscription(body(QJsonArray{awgNode("9", 9, "EE"), stubNode("aaaaaaaaaaaaaaa0", 1, 0)}), err));
        CHECK(r.e.adoptTunnelConnected(QStringLiteral("up:aaaaaaaaaaaaaaa0"), QStringLiteral("xray"), QString()));
        r.owner.setOptions(op);
        r.owner.begin(stub, 1, std::nullopt, 1000, 1700000000000LL);
        r.owner.onAcquireReply(r.io.calls[0].id, granted(stub.upstream->profileId, sha, 3), 1100);
        r.owner.tunnelUp(1200);
        r.owner.onBytes(4096, 512);
    };
    {
        Rig r;
        upstreamRig(r);
        const bool session = r.e.currentNodeIsUpstream() || r.owner.active();
        CHECK(session);
        CHECK(runUpstreamQuit(AppExitKind::Quit, upstreamNodesEnabled(), session, r.hooks(true)));
        const FakeIo::Call *rel = r.io.last("release");
        CHECK(rel && r.owner.releaseSent() && rel->meter.rxDelta == 4096 && rel->meter.epoch == 3); // final report
        CHECK(r.t.downs == 1 && r.disconnected && r.clock <= kUpstreamQuitStopBoundMs);
        CHECK(r.journal == QStringList{QStringLiteral("upstream session ended on app quit")});
    }
    {
        // The stop never reaches the service: the quit still goes on at the bound (never hangs).
        Rig r;
        upstreamRig(r);
        CHECK(runUpstreamQuit(AppExitKind::Quit, true, true, r.hooks(false)));
        CHECK(r.io.last("release") && r.t.downs == 1 && !r.disconnected);
        CHECK(r.clock == kUpstreamQuitStopBoundMs && r.pumps == kUpstreamQuitStopBoundMs / 50);
    }
    for (AppExitKind k : {AppExitKind::Restart, AppExitKind::Hide}) {
        Rig r;
        upstreamRig(r);
        CHECK(!runUpstreamQuit(k, true, true, r.hooks(true)));
        CHECK(!r.io.last("release") && r.t.downs == 0 && r.journal.isEmpty() && r.pumps == 0 && r.owner.active());
    }
    {
        // Own node (AWG): BUG-6 - the service keeps the tunnel, nothing is sent, nothing waits.
        Rig r;
        QString err;
        setFlags(true);
        r.e.setTunnel(&r.t);
        CHECK(r.e.loadSubscription(body(QJsonArray{awgNode("9", 9, "EE"), stubNode("aaaaaaaaaaaaaaa0", 1, 0)}), err));
        CHECK(r.e.adoptTunnelConnected(QStringLiteral("9"), QStringLiteral("awg"), QString()));
        const bool session = r.e.currentNodeIsUpstream() || r.owner.active();
        CHECK(!session);
        CHECK(!runUpstreamQuit(AppExitKind::Quit, true, session, r.hooks(true)));
        CHECK(r.io.calls.isEmpty() && r.t.downs == 0 && r.journal.isEmpty() && r.pumps == 0);
    }
    {
        // Switch off: the quit is the one before, even if a provider session were somehow live.
        Rig r;
        upstreamRig(r);
        CHECK(!runUpstreamQuit(AppExitKind::Quit, false, true, r.hooks(true)));
        CHECK(!r.io.last("release") && r.t.downs == 0 && r.journal.isEmpty());
    }
}

// --- owner's iPhone 16.11 (build 140), D2 + D3: a refused bring-up -------------------------------------------
// The profile of up:2ea0 was refused after its seat was granted. On iOS the owner had marked the lease handed over
// at LeaseReady, so the adapter's disconnect() neither released the seat nor ended the machine's session: the seat
// stayed paid until its expiry, and the next node's begin() found the machine busy - start() ignored, "acquiring a
// seat" with no request, the 15 s start watchdog; its stop then "released" the old dead lease.
static void ownerRefusedBringUp()
{
    const SubscriptionNode a = stubOf(QStringLiteral("aaaaaaaaaaaaaaa0"));
    const SubscriptionNode b = stubOf(QStringLiteral("bbbbbbbbbbbbbbb0"));
    const qint64 T = 7000000;
    for (bool keep : {false, true}) {
        FakeIo io;
        UpstreamLeaseOwner o(&io);
        UpstreamLeaseOwner::Options op;
        op.keepOwnership = keep;
        o.setOptions(op);
        o.begin(a, 1, std::nullopt, T, 1);
        QVector<UpstreamOwnerEvent> ev = o.onAcquireReply(io.calls[0].id, granted(a.upstream->profileId, a.upstream->configSha256), T + 300);
        CHECK(findEv(ev, UpstreamOwnerEventKind::BringUp));
        // The adapter refuses the profile (bringUpUpstream): disconnect - the seat goes back from this process.
        o.disconnect(T + 310);
        const FakeIo::Call *rel = io.last("release");
        CHECK(rel && rel->profileOrLease == QLatin1String(kLease) && o.releaseSent());
        CHECK(o.phase() == LeasePhase::Released);
        // The next node's start sends its own acquire at once.
        const int before = io.calls.size();
        o.begin(b, 1, std::nullopt, T + 1000, 1);
        CHECK(io.calls.size() == before + 1 && io.calls.last().what == QLatin1String("acquire")
              && io.calls.last().profileOrLease == b.upstream->profileId);
        CHECK(o.phase() == LeasePhase::Acquiring && o.active() && o.nodeId() == b.nodeId);
        // ... and a stop now releases nothing of the old session (nothing granted for b yet).
        const int calls = io.calls.size();
        o.disconnect(T + 2000);
        CHECK(io.calls.size() == calls);
    }
    // iOS / Android after the tunnel came up: the tunnel owner releases on its stop, not the app; the machine's
    // session still ends, so a following start acquires.
    {
        FakeIo io;
        UpstreamLeaseOwner o(&io);
        o.begin(a, 1, std::nullopt, T, 1);
        o.onAcquireReply(io.calls[0].id, granted(a.upstream->profileId, a.upstream->configSha256), T + 300);
        o.tunnelUp(T + 2000);
        o.disconnect(T + 60000);
        CHECK(!io.last("release") && !o.releaseSent());
        o.begin(b, 1, std::nullopt, T + 61000, 1);
        CHECK(io.calls.last().what == QLatin1String("acquire") && io.calls.last().profileOrLease == b.upstream->profileId);
    }
    // A start of the next node straight away (begin() without a disconnect) after a refused bring-up: the same.
    {
        FakeIo io;
        UpstreamLeaseOwner o(&io);
        o.begin(a, 1, std::nullopt, T, 1);
        o.onAcquireReply(io.calls[0].id, granted(a.upstream->profileId, a.upstream->configSha256), T + 300);
        o.begin(b, 1, std::nullopt, T + 400, 1);
        CHECK(io.last("release") && io.calls.last().what == QLatin1String("acquire"));
    }
    // The rule.
    CHECK(upstreamAppReleasesSeat(true, true, true));    // macOS GUI owner: always
    CHECK(upstreamAppReleasesSeat(false, false, false)); // not handed over (prepared, provisional)
    CHECK(upstreamAppReleasesSeat(false, true, false));  // in the envelope, the tunnel never came up
    CHECK(!upstreamAppReleasesSeat(false, true, true));  // the tunnel owner has it
}

// --- D4 of 16.11: seat first - a provider pick while another node's tunnel works -----------------------------
static void ownerSeatFirst()
{
    const SubscriptionNode a = stubOf();
    const QString sha = a.upstream->configSha256;
    const qint64 T = 9000000;
    for (bool keep : {false, true}) {
        FakeIo io;
        UpstreamLeaseOwner o(&io);
        UpstreamLeaseOwner::Options op;
        op.keepOwnership = keep;
        o.setOptions(op);
        o.prepare(a, 1, T, 1);
        CHECK(io.calls.size() == 1 && io.calls[0].what == QLatin1String("acquire") && io.calls[0].route.apiBase.isEmpty());
        CHECK(o.preparing() && o.preparedUsable(a.nodeId, T));
        QVector<UpstreamOwnerEvent> ev = o.onAcquireReply(io.calls[0].id, granted(a.upstream->profileId, sha), T + 200);
        const UpstreamOwnerEvent *p = findEv(ev, UpstreamOwnerEventKind::Prepared);
        CHECK(p && p->config == QByteArrayLiteral("{\"cfg\":1}") && p->configSha256 == sha);
        CHECK(!findEv(ev, UpstreamOwnerEventKind::BringUp) && !findEv(ev, UpstreamOwnerEventKind::Persist));
        CHECK(o.preparedUsable(a.nodeId, T + 300) && !o.preparedUsable(QStringLiteral("up:other"), T + 300));
        ev = o.bringUpPrepared(T + 1500);
        const UpstreamOwnerEvent *b = findEv(ev, UpstreamOwnerEventKind::BringUp);
        CHECK(b && !b->provisional && b->lease.value("lease_id").toString() == QLatin1String(kLease));
        CHECK((findEv(ev, UpstreamOwnerEventKind::Persist) != nullptr) == keep);
        CHECK(!o.preparing() && io.calls.size() == 1); // the held seat - no second acquire
    }
    // Refusals before the switch are PrepareFailed, never StartFailed: the live tunnel is not touched.
    for (const AcquireReply &r : {refused(UpstreamErrorCode::NoSeat), failed("transport"), refused(UpstreamErrorCode::Disabled)}) {
        FakeIo io;
        UpstreamLeaseOwner o(&io);
        o.prepare(a, 1, T, 1);
        const QVector<UpstreamOwnerEvent> ev = o.onAcquireReply(io.calls[0].id, r, T + 100);
        CHECK(findEv(ev, UpstreamOwnerEventKind::PrepareFailed) && !findEv(ev, UpstreamOwnerEventKind::StartFailed)
              && !findEv(ev, UpstreamOwnerEventKind::Leave) && !o.active());
    }
    // A held seat that is not used (cancel, a refused profile) goes back from the app on every platform.
    {
        FakeIo io;
        UpstreamLeaseOwner o(&io);
        o.prepare(a, 1, T, 1);
        o.onAcquireReply(io.calls[0].id, granted(a.upstream->profileId, sha), T + 200);
        o.disconnect(T + 500);
        CHECK(io.last("release") && io.last("release")->profileOrLease == QLatin1String(kLease) && !o.active());
    }
    // up() while the acquire is still in flight: the grant brings up like begin()'s.
    {
        FakeIo io;
        UpstreamLeaseOwner o(&io);
        o.prepare(a, 1, T, 1);
        CHECK(o.bringUpPrepared(T + 50).isEmpty() && !o.preparing() && o.active());
        const QVector<UpstreamOwnerEvent> ev = o.onAcquireReply(io.calls[0].id, granted(a.upstream->profileId, sha), T + 200);
        CHECK(findEv(ev, UpstreamOwnerEventKind::BringUp) && !findEv(ev, UpstreamOwnerEventKind::Prepared));
    }
    // A held seat is never renewed: its first renewal falling due gives it back (the switch did not come).
    for (bool keep : {false, true}) {
        FakeIo io;
        UpstreamLeaseOwner o(&io);
        UpstreamLeaseOwner::Options op;
        op.keepOwnership = keep;
        o.setOptions(op);
        o.prepare(a, 1, T, 1);
        o.onAcquireReply(io.calls[0].id, granted(a.upstream->profileId, sha), T + 200);
        CHECK(o.tick(T + 10000).isEmpty() && o.preparing());
        o.tick(T + 200 + 300000);
        CHECK(io.last("release") && !io.last("renew") && !o.active());
    }
    // A held lease past its deadline is not brought up (up() starts afresh).
    {
        FakeIo io;
        UpstreamLeaseOwner o(&io);
        o.prepare(a, 1, T, 1);
        o.onAcquireReply(io.calls[0].id, granted(a.upstream->profileId, sha), T + 200);
        CHECK(o.preparedUsable(a.nodeId, T + 899999) && !o.preparedUsable(a.nodeId, T + 900001));
    }
}

// --- review round 1 of 17.11: who gives each seat back -----------------------------------------------------------
static AcquireReply grantedAs(const SubscriptionNode &n, const char *leaseId)
{
    AcquireReply r = granted(n.upstream->profileId, n.upstream->configSha256);
    r.grant.leaseId = QLatin1String(leaseId);
    return r;
}

static void ownerReviewRound1()
{
    const SubscriptionNode b = stubOf(QStringLiteral("bbbbbbbbbbbbbbb0"));
    const SubscriptionNode c = stubOf(QStringLiteral("ccccccccccccccc0"));
    const SubscriptionNode d = stubOf(QStringLiteral("ddddddddddddddd0"));
    const char *kB = "LeaseBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    const char *kC = "LeaseCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
    const char *kD = "LeaseDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD";
    const qint64 T = 11000000;
    // F2: quick picks B -> C -> D, every acquire still unanswered; the answers come back in any order. Each
    // cancelled acquire's grant is released by its own id; only D's grant is held (Prepared).
    for (bool reversed : {false, true}) {
        FakeIo io;
        UpstreamLeaseOwner o(&io);
        o.prepare(b, 1, T, 1);
        const quint64 idB = io.calls.last().id;
        o.prepare(c, 1, T + 100, 1);
        const quint64 idC = io.calls.last().id;
        o.prepare(d, 1, T + 200, 1);
        const quint64 idD = io.calls.last().id;
        CHECK(idB != idC && idC != idD && o.machine().cancelledAcquiresPending() == 2);
        QVector<UpstreamOwnerEvent> evB, evC;
        if (reversed) {
            evC = o.onAcquireReply(idC, grantedAs(c, kC), T + 300);
            evB = o.onAcquireReply(idB, grantedAs(b, kB), T + 400);
        } else {
            evB = o.onAcquireReply(idB, grantedAs(b, kB), T + 300);
            evC = o.onAcquireReply(idC, grantedAs(c, kC), T + 400);
        }
        QStringList released;
        for (const FakeIo::Call &call : io.calls)
            if (call.what == QLatin1String("release"))
                released << call.profileOrLease;
        CHECK(released.contains(QLatin1String(kB)) && released.contains(QLatin1String(kC)) && released.size() == 2);
        CHECK(!findEv(evB, UpstreamOwnerEventKind::Prepared) && !findEv(evC, UpstreamOwnerEventKind::Prepared));
        const QVector<UpstreamOwnerEvent> evD = o.onAcquireReply(idD, grantedAs(d, kD), T + 500);
        const UpstreamOwnerEvent *p = findEv(evD, UpstreamOwnerEventKind::Prepared);
        CHECK(p && p->prepareId == o.prepareSerial() && o.preparedUsable(d.nodeId, T + 600));
        CHECK(o.machine().cancelledAcquiresPending() == 0);
        // A refused or failed answer to a cancelled acquire releases nothing and is forgotten.
        FakeIo io2;
        UpstreamLeaseOwner o2(&io2);
        o2.prepare(b, 1, T, 1);
        const quint64 id2 = io2.calls.last().id;
        o2.disconnect(T + 10);
        o2.onAcquireReply(id2, failed("transport"), T + 20);
        CHECK(!io2.last("release") && o2.machine().cancelledAcquiresPending() == 0);
    }
    // F5: every prepare() has its own identity, carried by its answer; a second prepare of the SAME node cancels
    // the first one's acquire - its late grant is released and never reported as Prepared.
    {
        FakeIo io;
        UpstreamLeaseOwner o(&io);
        o.prepare(b, 1, T, 1);
        const quint64 first = o.prepareSerial();
        const quint64 idFirst = io.calls.last().id;
        o.prepare(b, 1, T + 50, 1);
        const quint64 second = o.prepareSerial();
        const quint64 idSecond = io.calls.last().id;
        CHECK(first != 0 && second != first);
        QVector<UpstreamOwnerEvent> ev = o.onAcquireReply(idFirst, grantedAs(b, kB), T + 100);
        CHECK(!findEv(ev, UpstreamOwnerEventKind::Prepared) && io.last("release")
              && io.last("release")->profileOrLease == QLatin1String(kB));
        ev = o.onAcquireReply(idSecond, grantedAs(b, kC), T + 200);
        const UpstreamOwnerEvent *p = findEv(ev, UpstreamOwnerEventKind::Prepared);
        CHECK(p && p->prepareId == second);
        // ... and a refusal answers with its prepare's id too.
        FakeIo io3;
        UpstreamLeaseOwner o3(&io3);
        o3.prepare(c, 1, T, 1);
        ev = o3.onAcquireReply(io3.calls.last().id, refused(UpstreamErrorCode::NoSeat), T + 100);
        const UpstreamOwnerEvent *f = findEv(ev, UpstreamOwnerEventKind::PrepareFailed);
        CHECK(f && f->prepareId == o3.prepareSerial() && f->prepareId != 0);
    }
    // F6: what the running (other) tunnel counts while a seat is held for the switch is not this session's traffic.
    for (bool keep : {false, true}) {
        FakeIo io;
        UpstreamLeaseOwner o(&io);
        UpstreamLeaseOwner::Options op;
        op.keepOwnership = keep;
        o.setOptions(op);
        o.prepare(b, 1, T, 1);
        o.onAcquireReply(io.calls.last().id, grantedAs(b, kB), T + 100);
        o.onBytes(5000000000LL, 4000000000LL); // the old Xray tunnel's cumulative (macOS / Windows statistics)
        CHECK(o.machine().unreportedRx() == 0 && o.machine().unreportedTx() == 0);
        o.bringUpPrepared(T + 1000);
        o.onBytes(1000, 2000); // the new tunnel's own counters, from zero
        CHECK(o.machine().unreportedRx() == 1000 && o.machine().unreportedTx() == 2000);
    }
    // Seat accounting of a held seat at every exit: refused profile / cancel / stop -> released from the app.
    for (int exitKind = 0; exitKind < 2; ++exitKind) {
        FakeIo io;
        UpstreamLeaseOwner o(&io);
        o.prepare(b, 1, T, 1);
        o.onAcquireReply(io.calls.last().id, grantedAs(b, kB), T + 100);
        if (exitKind == 0)
            o.disconnect(T + 200); // cancelUpstreamPrepare (any intent change, a stop) / the profile refused
        else
            o.begin(c, 1, std::nullopt, T + 200, 1); // up() of another node
        CHECK(io.last("release") && io.last("release")->profileOrLease == QLatin1String(kB));
    }
}

// Build 142 (S5, review round 2 N2): an own Xray listener.
static QJsonObject xrayOwnNode(const QString &id, int hostId, const char *cc)
{
    return QJsonObject{
        {"node_id", id}, {"region", "eu"}, {"host_id", hostId}, {"transport_rank", 20},
        {"endpoint", QStringLiteral("203.0.113.%1:443").arg(hostId)}, {"proto", "xray"}, {"weight", 1.0},
        {"country_code", cc},
        {"xray_params", QJsonObject{{"uuid", "8f14e45f-ceea-4a7c-9d6b-2a1b3c4d5e6f"},
                                    {"public_key", "SbVjZ9Yl3dR3QpG1v8k2Wx0aU7Hq4Nn6Tt5Bc8Jd1mE"},
                                    {"short_id", "a1b2c3d4"}, {"server_name", "vision.example.com"},
                                    {"fingerprint", "chrome"}, {"flow", "xtls-rprx-vision"}, {"network", "tcp"},
                                    {"security", "reality"}}}};
}

// Review round 2, N2: three own AmneziaWG, one own Xray, one working provider. AmneziaWG gets no handshake
// (banned for the attempt), the own Xray is refused - the provider tier must open. The tier rule sees the
// same pool as the picker: banned nodes are not candidates of tier 0 (neither untried nor failed).
static void awgBanOpensProviderTier()
{
    setFlags(true, /*failCap=*/4);
    QString err;
    ServiceEngine e;
    FakeTunnel t;
    e.setTunnel(&t);
    CHECK(e.loadSubscription(body(QJsonArray{awgNode("17", 17, "FI"), awgNode("16", 16, "DE"), awgNode("15", 15, "EE"),
                                             xrayOwnNode("12:xray", 12, "DE"), stubNode("aaaaaaaaaaaaaaa0", 1, 0)}), err));
    e.setMeasuredRtt({{QStringLiteral("17"), 20}, {QStringLiteral("16"), 30}, {QStringLiteral("15"), 40},
                      {QStringLiteral("12:xray"), 50}});
    e.beginUserAttempt();
    CHECK(e.connect(err) && t.ups.last() == QLatin1String("17"));
    CHECK(e.xrayPickWithoutAwg());
    e.banAwgForAttempt();                                   // the first handshake timeout of 17
    e.requestStop();
    CHECK(e.connect(err) && t.ups.last() == QLatin1String("12:xray")); // own Xray before any provider
    e.excludeForAttempt(QStringLiteral("12:xray"), QStringLiteral("start_failed")); // the Xray start is refused
    e.onTunnelError();
    e.requestStop();
    CHECK(e.connect(err) && isStubId(t.ups.last()));        // the provider tier opens: own tier exhausted
    CHECK(e.awgBanned());
    // No own Xray at all: the ban still has a target (the provider, Xray by nature) and the predicate says so.
    ServiceEngine p;
    FakeTunnel pt;
    p.setTunnel(&pt);
    CHECK(p.loadSubscription(body(QJsonArray{awgNode("17", 17, "FI"), awgNode("16", 16, "DE"),
                                             stubNode("aaaaaaaaaaaaaaa0", 1, 0)}), err));
    p.setMeasuredRtt({{QStringLiteral("17"), 20}, {QStringLiteral("16"), 30}});
    CHECK(p.connect(err) && pt.ups.last() == QLatin1String("17"));
    CHECK(p.xrayPickWithoutAwg());
    p.banAwgForAttempt();
    p.requestStop();
    CHECK(p.connect(err) && isStubId(pt.ups.last()));
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    earlyRefusals();
    quitEndsUpstreamSession();
    picker16AndNotices();
    pickerTiers();
    flagOffIdentical();
    identityAndReseed();
    engineAttempt();
    awgBanOpensProviderTier();
    ownerAcquireOutcomes();
    ownerRefusedBringUp();
    ownerSeatFirst();
    ownerReviewRound1();
    ownerMacRenewals();
    ownerAdoption();
    dataCheck();
    standbyAndStatus();
    envelopeAndParsing();
    coldStartWhitelistWindow();
    fastTierOpen();
    if (g_fail) {
        std::printf("upstream_engine_check: %d of %d FAILED\n", g_fail, g_total);
        return 1;
    }
    std::printf("upstream_engine_check: OK (%d checks)\n", g_total);
    return 0;
}

// --- link stubs: the network parts of the engine are not called by this check (as transport_pick_check).
namespace avpn {

bool Enrollment::enroll(QNetworkAccessManager *, const QString &, Identity &, SecureAppSettingsRepository *,
                        TrialResponse &, QString &error, FetchOutcome *)
{
    error = QStringLiteral("stub");
    return false;
}
bool Enrollment::fetchSubscription(QNetworkAccessManager *, const QString &, const QString &, QByteArray &,
                                   QString &error, FetchOutcome *)
{
    error = QStringLiteral("stub");
    return false;
}
void Enrollment::saveLkgSubscription(const QByteArray &) {}
QByteArray Enrollment::loadLkgSubscription() { return {}; }
QString Enrollment::loadToken() { return {}; }
void Enrollment::clearToken() {}
bool Identity::ensureKeys(SecureAppSettingsRepository *, QString &) { return true; }

} // namespace avpn
