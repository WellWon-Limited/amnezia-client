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
#include "../path/PathSelect.h"
#include "../TuningStore.h"
#include "../UpstreamEngine.h"
#include "../UpstreamLeaseClient.h"
#include "../UpstreamLeaseOwner.h"
#include "../WhoamiVerdict.h"
#include "../XrayConfigBuilder.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDateTime>
#include <QElapsedTimer>
#include <QNetworkAccessManager>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTimer>
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
    TunnelStats readStats() override { return st; }
    void down() override { ++downs; }
};

static bool isStubId(const QString &id) { return id.startsWith(QLatin1String("up:")); }


// --- 2) flag off = identical decisions ----------------------------------------------------------------
static void flagOffIdentical()
{
    // With the switch off the parser drops stubs: the engine's pool and reseed log are those of the own pool (the
    // same body twice = Unchanged, no switch log line), and a start never raises a stub.
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
            CHECK(r.activeProto == QLatin1String("xray")); // coordinator 18.11 (d): every provider card has its badge
        } else {
            CHECK(!r.upstream && r.upstreamTier == 0);
        }
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
    // Timings: a complete body past the soft or the hard limit -> slow but passes (review E4 of 18.11).
    UpstreamProbeFacts slow = facts(200, n, good, "other", "8881", "net-b");
    slow.elapsedMs = 4000;
    CHECK(judge(slow).verdict == UpstreamVerdict::Slow && judge(slow).passes);
    slow.elapsedMs = 6000;
    CHECK(judge(slow).verdict == UpstreamVerdict::Slow && judge(slow).passes);
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
    // The acquire is bounded by the lease share of the provider leg (review E6 of 18.11): the leg's start
    // deadline covers the lease and then the whole native start, whatever the server sets.
    for (double v : {0.0, 4000.0, 1e9}) {
        TuningStore::set({{QStringLiteral("attempt_provider_lease_ms"), v}}, {}, {}, {});
        const path::AttemptTimings t = attemptTimingsTuned();
        CHECK(upstreamAcquireTimeoutMsTuned() == t.providerLeaseMs && t.providerLeaseMs >= 1500 && t.providerLeaseMs <= 10000);
        CHECK(path::AttemptOwner(t).startTimeoutMs(path::PathKind::Provider) == t.providerLeaseMs + t.providerStartMs);
    }
    TuningStore::set({}, {}, {}, {});
    CHECK(upstreamAcquireTimeoutMsTuned() == 6000); // device round 4: sized against the server's 3.8-4.2 s
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

    // Release A naming (owner decisions 14.11 and 17.11, contract 1.10.0): the admin's own label, else
    // «<localized country> <n>» for a country row, «Белые списки <n>» for a white-list row, «Авто <n>» for the
    // provider's balancer (Connect card only); never «Сервер <n>»; a server fallback such as "NL 1" is never shown.
    const QString wl = QStringLiteral("Белые списки"), au = QStringLiteral("Авто");
    const auto name = [&](const QString &label, bool custom, int ordinal, UpstreamKind k, const QString &country) {
        return upstreamDisplayName(label, custom, ordinal, k, country, wl, au);
    };
    CHECK(name("NL 1", false, 1, UpstreamKind::Country, QStringLiteral("Нидерланды")) == QStringLiteral("Нидерланды 1"));
    CHECK(name("NL 1", false, 0, UpstreamKind::Country, QStringLiteral("Нидерланды")) == QStringLiteral("Нидерланды"));
    CHECK(name("Быстрый Амстердам", true, 3, UpstreamKind::Country, QStringLiteral("Нидерланды")) == QStringLiteral("Быстрый Амстердам"));
    CHECK(name("  Свой  ", true, 3, UpstreamKind::Whitelist, QString()) == QStringLiteral("Свой"));
    CHECK(name("   ", true, 3, UpstreamKind::Country, QStringLiteral("Германия")) == QStringLiteral("Германия 3")); // empty custom
    CHECK(name("Белые списки 2", false, 2, UpstreamKind::Whitelist, QString()) == QStringLiteral("Белые списки 2"));
    CHECK(name("LTE 1", false, 1, UpstreamKind::Whitelist, QStringLiteral("Польша")) == QStringLiteral("Белые списки 1")); // no flag, no country
    CHECK(name("Авто 3", false, 3, UpstreamKind::Auto, QString()) == QStringLiteral("Авто 3"));
    CHECK(name(QString(), false, 7, UpstreamKind::Country, QString()) == QStringLiteral("Авто 7")); // defensive: no country name
    CHECK(upstreamDisplayName("NL 1", false, 2, UpstreamKind::Country, QStringLiteral("Netherlands"), QStringLiteral("White lists"),
                              QStringLiteral("Auto")) == QStringLiteral("Netherlands 2"));
    for (UpstreamKind k : {UpstreamKind::Unspecified, UpstreamKind::Country, UpstreamKind::Whitelist, UpstreamKind::Auto})
        for (const QString &c : {QString(), QStringLiteral("Нидерланды")})
            for (int o : {0, 1, 9})
                CHECK(!name(QStringLiteral("Сервер 9"), false, o, k, c).contains(QStringLiteral("Сервер")));

    // The wire kind and the row kind (contract 1.10.0; an older server's stub without kind: country when it has
    // a country, else the provider's balancer - hidden from the list, kept for Auto).
    CHECK(upstreamKindFromWire(false, QString()) == UpstreamKind::Unspecified);
    CHECK(upstreamKindFromWire(true, QStringLiteral("country")) == UpstreamKind::Country);
    CHECK(upstreamKindFromWire(true, QStringLiteral("whitelist")) == UpstreamKind::Whitelist);
    CHECK(upstreamKindFromWire(true, QStringLiteral("auto")) == UpstreamKind::Auto);
    CHECK(upstreamKindFromWire(true, QStringLiteral("balancer-v2")) == UpstreamKind::Auto);
    CHECK(upstreamKindFromWire(true, QString()) == UpstreamKind::Auto); // present but not a string
    CHECK(upstreamRowKind(UpstreamKind::Unspecified, QStringLiteral("NL")) == UpstreamKind::Country);
    CHECK(upstreamRowKind(UpstreamKind::Unspecified, QString()) == UpstreamKind::Auto);
    CHECK(upstreamRowKind(UpstreamKind::Country, QStringLiteral(" ")) == UpstreamKind::Auto);
    CHECK(upstreamRowKind(UpstreamKind::Whitelist, QStringLiteral("PL")) == UpstreamKind::Whitelist);
    CHECK(upstreamRowKind(UpstreamKind::Auto, QStringLiteral("NL")) == UpstreamKind::Auto);
    CHECK(upstreamKindListed(UpstreamKind::Country) && upstreamKindListed(UpstreamKind::Whitelist));
    CHECK(!upstreamKindListed(UpstreamKind::Auto));

    // The engine row: the label only when custom, with the parts and the row kind for the facade.
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
        CHECK(rn.upstreamKind == UpstreamKind::Country && rp.upstreamKind == UpstreamKind::Country); // no kind + a country
        CHECK(name(rp.name, rp.upstreamLabelCustom, rp.upstreamOrdinal, rp.upstreamKind, QStringLiteral("Нидерланды"))
              == QStringLiteral("Нидерланды 1"));
        CHECK(byId.value("9").name.isEmpty() || byId.value("9").name != QStringLiteral("NL 1")); // own rows untouched
        CHECK(byId.value("9").upstreamKind == UpstreamKind::Unspecified);
    }

    // Hiding the balancer's row never removes the candidate (owner 17.11): the auto profile and an older server's
    // countryless stub stay in the pool and Auto commits them in their tier; only the list leaves them out.
    {
        const auto withKind = [](QJsonObject n, const char *kind, int ordinal) {
            QJsonObject u = n.value("upstream").toObject();
            if (kind)
                u.insert("kind", QLatin1String(kind));
            u.insert("ordinal", ordinal);
            n.insert("upstream", u);
            return n;
        };
        const QJsonArray nodes{awgNode("9", 9, "EE"), awgNode("2", 2, "PL"), awgNode("5", 5, "US"),
                               withKind(stubNode("cccccccccccccc01", 1, 0), "auto", 1),
                               withKind(stubNode("cccccccccccccc02", 1, 1), "whitelist", 1),
                               withKind(stubNode("cccccccccccccc03", 1, 2, sha64('a'), "NL"), "country", 1),
                               withKind(stubNode("cccccccccccccc04", 1, 3), nullptr, 2)}; // older server: no kind, no country
        const Subscription sub = parse(body(nodes));
        CHECK(sub.nodes.size() == 7);
        ServiceEngine en;
        FakeTunnel tn;
        en.setTunnel(&tn);
        CHECK(en.loadSubscription(body(nodes), err));
        QHash<QString, NodeDebugRow> byId;
        for (const NodeDebugRow &r : en.debugSnapshot().pool)
            byId.insert(r.nodeId, r);
        CHECK(byId.contains("up:cccccccccccccc01") && byId.contains("up:cccccccccccccc04")); // kept in the pool
        CHECK(byId.value("up:cccccccccccccc01").upstreamKind == UpstreamKind::Auto);
        CHECK(byId.value("up:cccccccccccccc02").upstreamKind == UpstreamKind::Whitelist);
        CHECK(byId.value("up:cccccccccccccc03").upstreamKind == UpstreamKind::Country);
        CHECK(byId.value("up:cccccccccccccc04").upstreamKind == UpstreamKind::Auto);
        CHECK(!upstreamKindListed(byId.value("up:cccccccccccccc01").upstreamKind)
              && !upstreamKindListed(byId.value("up:cccccccccccccc04").upstreamKind));
        CHECK(upstreamKindListed(byId.value("up:cccccccccccccc02").upstreamKind)
              && upstreamKindListed(byId.value("up:cccccccccccccc03").upstreamKind));
        // Auto (path engine): the provider's balancer - also an older server's countryless stub - is a candidate of an
        // automatic choice, never of the list (above): after our own nodes, in the provider's priority order.
        QList<path::PathCandidate> pool;
        for (const SubscriptionNode &node : sub.nodes)
            pool << path::pathCandidateFromNode(node);
        path::SelectInput in;
        in.pool = pool;
        in.tried = {"9", "2", "5"};
        QStringList order;
        for (const path::RankedPath &r : path::selectPaths(in))
            order << r.path.id.id;
        CHECK(order.contains("up:cccccccccccccc01") && order.contains("up:cccccccccccccc04"));
        // the parsed stub carries the wire kind (absent stays Unspecified; the row kind decides)
        CHECK(sub.nodes.at(3).upstream.has_value() && sub.nodes.at(3).upstream->kind == UpstreamKind::Auto);
        CHECK(sub.nodes.at(6).upstream.has_value() && sub.nodes.at(6).upstream->kind == UpstreamKind::Unspecified);
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
    // F2 + N1 (review rounds 1-2 of 17.11): ONE acquisition in flight per owner. Quick picks B -> C -> D: only B's
    // acquire is out; C replaces nothing on the wire, D replaces C in the queue. B's answer decides by the seat it
    // names: a grant of B (nobody waits for B) is released, and D's acquire goes out at once (another profile).
    for (bool grantB : {true, false}) {
        FakeIo io;
        UpstreamLeaseOwner o(&io);
        o.prepare(b, 1, T, 1);
        const quint64 idB = io.calls.last().id;
        o.prepare(c, 1, T + 100, 1);
        o.prepare(d, 1, T + 200, 1);
        CHECK(io.calls.size() == 1 && o.startQueued() && o.requestsOutstanding() == 1);
        const QVector<UpstreamOwnerEvent> evB =
            o.onAcquireReply(idB, grantB ? grantedAs(b, kB) : refused(UpstreamErrorCode::NoSeat), T + 300);
        CHECK(!findEv(evB, UpstreamOwnerEventKind::Prepared) && !findEv(evB, UpstreamOwnerEventKind::PrepareFailed));
        CHECK((io.last("release") != nullptr) == grantB);
        if (grantB)
            CHECK(io.last("release") && io.last("release")->profileOrLease == QLatin1String(kB));
        const FakeIo::Call *acqD = io.last("acquire");
        CHECK(acqD && acqD->id != idB && acqD->profileOrLease == d.upstream->profileId);
        if (!acqD)
            continue;
        const QVector<UpstreamOwnerEvent> evD = o.onAcquireReply(acqD->id, grantedAs(d, kD), T + 500);
        const UpstreamOwnerEvent *p = findEv(evD, UpstreamOwnerEventKind::Prepared);
        CHECK(p && p->prepareId == o.prepareSerial() && o.preparedUsable(d.nodeId, T + 600));
        int acquires = 0;
        for (const FakeIo::Call &call : io.calls)
            acquires += call.what == QLatin1String("acquire") ? 1 : 0;
        CHECK(acquires == 2); // B and D - never C
    }
    // N1: B -> C -> B, the server answering with the SAME lease for B (an acquire of a profile already held is
    // re-issued as the existing lease - api/openapi.yaml). Before: two acquires of B were out, and the cancelled
    // one's late answer sent DELETE for the seat the new B had just been given. Now the first B's answer IS the
    // waiting B's answer: no second acquire, no release, the seat held.
    {
        FakeIo io;
        UpstreamLeaseOwner o(&io);
        o.prepare(b, 1, T, 1);
        const quint64 idB1 = io.calls.last().id;
        o.prepare(c, 1, T + 100, 1);
        o.prepare(b, 1, T + 200, 1);
        CHECK(io.calls.size() == 1);
        const QVector<UpstreamOwnerEvent> ev = o.onAcquireReply(idB1, grantedAs(b, kB), T + 300);
        const UpstreamOwnerEvent *p = findEv(ev, UpstreamOwnerEventKind::Prepared);
        CHECK(p && p->prepareId == o.prepareSerial() && o.machine().leaseId() == QLatin1String(kB));
        CHECK(!io.last("release") && io.calls.size() == 1);
        // A later replay of the same lease (a duplicate answer) changes nothing.
        CHECK(o.onAcquireReply(idB1, grantedAs(b, kB), T + 400).isEmpty() && !io.last("release"));
        // brought up: still the same lease, still no release
        const QVector<UpstreamOwnerEvent> up = o.bringUpPrepared(T + 500);
        CHECK(findEv(up, UpstreamOwnerEventKind::BringUp) && !io.last("release"));
    }
    // A held seat given back, then the same profile picked again: the new acquire waits for that release (else the
    // server could re-issue the lease the release then ends).
    {
        FakeIo io;
        UpstreamLeaseOwner o(&io);
        o.prepare(b, 1, T, 1);
        o.onAcquireReply(io.calls.last().id, grantedAs(b, kB), T + 100);
        o.disconnect(T + 200);
        const FakeIo::Call *rel = io.last("release");
        CHECK(rel && rel->profileOrLease == QLatin1String(kB));
        const quint64 relId = rel ? rel->id : 0;
        const int before = io.calls.size();
        o.prepare(b, 1, T + 300, 1);
        CHECK(io.calls.size() == before && o.startQueued());
        o.onReleaseDone(relId, T + 400);
        CHECK(io.calls.size() == before + 1 && io.calls.last().what == QLatin1String("acquire"));
        // another profile does not wait for it
        FakeIo io2;
        UpstreamLeaseOwner o2(&io2);
        o2.prepare(b, 1, T, 1);
        o2.onAcquireReply(io2.calls.last().id, grantedAs(b, kB), T + 100);
        o2.disconnect(T + 200);
        o2.prepare(c, 1, T + 300, 1);
        CHECK(io2.calls.last().what == QLatin1String("acquire") && io2.calls.last().profileOrLease == c.upstream->profileId);
        // A refused or failed answer of a cancelled acquire releases nothing; the waiting acquire then goes out.
        FakeIo io3;
        UpstreamLeaseOwner o3(&io3);
        o3.prepare(b, 1, T, 1);
        const quint64 id3 = io3.calls.last().id;
        o3.disconnect(T + 10);
        o3.onAcquireReply(id3, failed("transport"), T + 20);
        CHECK(!io3.last("release") && o3.requestsOutstanding() == 0);
    }
    // F5: every prepare() has its own identity, carried by its answer; a second prepare of the same node takes the
    // first one's still-unanswered acquire over - its answer is reported once, with the NEW prepare's id.
    {
        FakeIo io;
        UpstreamLeaseOwner o(&io);
        o.prepare(b, 1, T, 1);
        const quint64 first = o.prepareSerial();
        const quint64 idFirst = io.calls.last().id;
        o.prepare(b, 1, T + 50, 1);
        const quint64 second = o.prepareSerial();
        CHECK(first != 0 && second != first && io.calls.size() == 1);
        const QVector<UpstreamOwnerEvent> ev = o.onAcquireReply(idFirst, grantedAs(b, kB), T + 100);
        const UpstreamOwnerEvent *p = findEv(ev, UpstreamOwnerEventKind::Prepared);
        CHECK(p && p->prepareId == second && !io.last("release"));
        // ... and a refusal answers with its prepare's id too.
        FakeIo io3;
        UpstreamLeaseOwner o3(&io3);
        o3.prepare(c, 1, T, 1);
        const QVector<UpstreamOwnerEvent> ev3 = o3.onAcquireReply(io3.calls.last().id, refused(UpstreamErrorCode::NoSeat), T + 100);
        const UpstreamOwnerEvent *f = findEv(ev3, UpstreamOwnerEventKind::PrepareFailed);
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


// --- review round 2 of 17.11: a model of the server's seat rules against random picks and answer orders ------
// The server (upstream_pool.acquire_lease, api/openapi.yaml): one live session lease per device; an acquire of the
// profile it holds is answered with THAT lease; a grant of another profile ends it (replaced); a refusal leaves
// it; DELETE ends it. The owner picks B or C (prepare / begin), cancels, brings up; every request is answered in a
// random order. Invariants after every step: at most one acquire out; a seat the owner holds is live on the server
// (it never released, or let something replace, its own seat); at the end every seat is given back.
static void ownerSeatModel()
{
    const SubscriptionNode nodes[2] = {stubOf(QStringLiteral("bbbbbbbbbbbbbbb0")), stubOf(QStringLiteral("ccccccccccccccc0"))};
    int violations = 0, steps = 0, releases = 0, reuses = 0;
    for (int seed = 1; seed <= 400; ++seed) {
        quint32 rng = quint32(seed) * 2654435761u;
        const auto rnd = [&rng](int n) { rng = rng * 1664525u + 1013904223u; return int((rng >> 8) % quint32(n)); };
        FakeIo io;
        UpstreamLeaseOwner o(&io);
        UpstreamLeaseOwner::Options op;
        op.keepOwnership = seed % 2 == 0;
        o.setOptions(op);
        struct Live { QString lease; QString profile; } live;
        int serial = 0, delivered = 0;
        QList<int> pending; // indices into io.calls not answered yet
        qint64 now = 20000000;
        const auto sync = [&]() {
            for (int i = delivered; i < io.calls.size(); ++i)
                pending << i;
            delivered = io.calls.size();
        };
        const auto check = [&](const char *where) {
            int acquiresOut = 0;
            for (int i : pending)
                acquiresOut += io.calls[i].what == QLatin1String("acquire") ? 1 : 0;
            bool bad = acquiresOut > 1;
            const bool holds = o.active() && o.machine().phase() == LeasePhase::Active && !o.machine().leaseId().isEmpty();
            bool releaseOut = false;
            for (int i : pending)
                releaseOut = releaseOut || (io.calls[i].what == QLatin1String("release") && io.calls[i].profileOrLease == o.machine().leaseId());
            if (holds && (live.lease != o.machine().leaseId() || releaseOut))
                bad = true;
            if (bad) {
                ++violations;
                std::printf("seat model seed %d step %d (%s): acquires out %d, held %s, live %s, release of held out %d\n", seed,
                            steps, where, acquiresOut, qPrintable(o.machine().leaseId()), qPrintable(live.lease), int(releaseOut));
            }
        };
        const auto answer = [&](int k) {
            const FakeIo::Call call = io.calls[pending.takeAt(k)];
            now += 37;
            if (call.what == QLatin1String("acquire")) {
                const SubscriptionNode &n = call.profileOrLease == nodes[0].upstream->profileId ? nodes[0] : nodes[1];
                AcquireReply r;
                if (!live.lease.isEmpty() && live.profile == call.profileOrLease) {
                    r = grantedAs(n, "");
                    r.grant.leaseId = live.lease; // re-issued: the same lease
                    ++reuses;
                } else if (rnd(10) < 3) {
                    r = refused(UpstreamErrorCode::NoSeat); // a refusal leaves the live lease alone
                } else {
                    live.lease = QStringLiteral("LeaseModel%1").arg(++serial, 30, 10, QLatin1Char('0'));
                    live.profile = call.profileOrLease; // replaces any other
                    r = grantedAs(n, "");
                    r.grant.leaseId = live.lease;
                }
                o.onAcquireReply(call.id, r, now);
            } else if (call.what == QLatin1String("release")) {
                ++releases;
                if (live.lease == call.profileOrLease)
                    live = Live();
                o.onReleaseDone(call.id, now);
            }
        };
        for (int step = 0; step < 40; ++step, ++steps) {
            now += 50;
            const int what = rnd(8);
            if (what == 0)
                o.prepare(nodes[rnd(2)], 1, now, 1);
            else if (what == 1)
                o.begin(nodes[rnd(2)], 1, std::nullopt, now, 1);
            else if (what == 2)
                o.disconnect(now);
            else if (what == 3)
                o.bringUpPrepared(now);
            else if (!pending.isEmpty())
                answer(rnd(pending.size()));
            sync();
            check("step");
        }
        // the end: stop, then every request answered - no seat may stay held on the server
        o.disconnect(now + 1);
        sync();
        while (!pending.isEmpty()) {
            answer(0);
            sync();
        }
        if (!live.lease.isEmpty()) {
            ++violations;
            std::printf("seat model seed %d: seat %s left held after the stop\n", seed, qPrintable(live.lease));
        }
    }
    CHECK(violations == 0);
    std::printf("seat model: %d steps, %d releases, %d same-lease re-issues\n", steps, releases, reuses);
    // The model really exercised releases. Same-lease re-issues happen only when two acquires of one profile are out
    // or an acquire overtakes a release of its profile - exactly what the owner no longer does (0 expected; with
    // acquireBlocked() disabled the model finds both, see the mutation check in the report of round 2).
    CHECK(releases > 100 && reuses == 0);
}

// Contract 1.14.0: a provider row of a Scanner batch beyond the 24 delivered stubs - offered, pinned (an exact Scanner
// row), connected through the attempt owner, stopped; Auto never starts it on its own; a revision change drops it.
static void scanOfferedRows()
{
    TuningStore::set({}, {{QStringLiteral("upstream_nodes"), true}, {QStringLiteral("xray_client"), true}}, {}, {});
    ServiceEngine e;
    FakeTunnel tun;
    e.setTunnel(&tun);
    QString err;
    CHECK(e.loadSubscription(body(realisticPool()), err));
    path::NetworkObservation home;
    home.medium = path::NetMedium::Wifi;
    home.gateway = QStringLiteral("192.168.3.1");
    e.observeNetwork(home);
    const QString offered = QStringLiteral("up:ccccccccccccccc9");
    CHECK(e.offerScanNodes(QJsonArray{ stubNode("ccccccccccccccc9", 1, 0, sha64('c'), "CH"),
                                       stubNode("aaaaaaaaaaaaaaa0", 1, 0) /* delivered already: not offered */ }) == 1);
    e.setStandbyCandidates(e.scanOfferedNodes());
    CHECK(e.nodeById(offered) && e.nodeById(offered)->upstream->scanOffered);
    // Auto does not start it on its own: the delivered candidates bound Auto
    for (const path::PathCandidate &c : e.pathPoolForTest())
        CHECK(c.id.id != offered);
    // S2 (device round 5): an adopted provider session is identified by its node id (a stub has no endpoint)
    {
        ServiceEngine a;
        FakeTunnel t2;
        a.setTunnel(&t2);
        CHECK(a.loadSubscription(body(realisticPool()), err));
        CHECK(a.adoptTunnelConnected(QStringLiteral("up:aaaaaaaaaaaaaaa0"), QStringLiteral("xray"), QStringLiteral("198.51.100.7:443")));
        CHECK(a.currentNodeId() == QLatin1String("up:aaaaaaaaaaaaaaa0"));
    }
    // an exact Scanner row: the one path, through the owner
    e.setUserChoice(path::UserChoice::exactPath(offered));
    CHECK(e.connect(err) && tun.ups == QStringList{ offered });
    const path::PathId id = path::derivePathId(*e.nodeById(offered));
    CHECK(id.id == offered && !id.revision.isEmpty()); // a provider path like any other
    e.requestStop();
    e.onTunnelDisconnected(); // the facade's stop confirmed
    CHECK(!e.attemptRunning());
    // capped, deduplicated, newest win
    QJsonArray many;
    for (int i = 0; i < 60; ++i)
        many << stubNode(QStringLiteral("d%1").arg(i, 15, 10, QLatin1Char('0')), 1, i, sha64('d'), "NL");
    CHECK(e.offerScanNodes(many) == ServiceEngine::kMaxScanOffered);
    // a new upstream revision drops every offered row
    QJsonArray next = realisticPool();
    next << awgNode("4", 4, "LV"); // a new pool body with a new upstream revision
    CHECK(e.reseedPool(parse(body(next, 2, 1763117000999.0))) == ReseedResult::Applied);
    CHECK(e.upstreamRevision() == qint64(1763117000999.0));
    CHECK(e.scanOfferedNodes().isEmpty());
    TuningStore::set({}, {}, {}, {});
}

// --- T1 for provider legs (lead 142): one starving rule for own and provider data checks ---------------------
// The provider leg's data check (the sized probe through the provider, UpstreamLeaseClient::runProbe) carries the
// same first-byte watch as the own-server check (whoami): no first byte past kWhoamiFirstByteShareMs = starving,
// a first byte after that = receiving again. With a path the race proved, a starving provider leg is left at once:
// nothing recorded against it (one starving check is not "dead"), its seat goes back through the tunnel adapter's
// down(), and the proven path comes up within the same attempt. A leg that is receiving is never abandoned.
// Real QNetworkAccessManager + loopback servers for the request; the engine on the test clock.
struct SeatTunnel : ITunnelControl {
    FakeIo io;
    UpstreamLeaseOwner owner{&io};
    qint64 now = 9000000;
    QStringList ups;
    int downs = 0;
    TunnelStats st;
    SeatTunnel()
    {
        UpstreamLeaseOwner::Options op;
        op.keepOwnership = true; // the macOS GUI owner: this process releases (iOS: the extension, on its stop)
        owner.setOptions(op);
    }
    TunnelResult up(const Subscription &, const SubscriptionNode &n) override
    {
        ups << n.nodeId;
        if (n.upstream.has_value()) { // the seat: acquired and granted, the core comes up on it
            owner.begin(n, 1, std::nullopt, now, 1);
            owner.onAcquireReply(io.last("acquire")->id, granted(n.upstream->profileId, n.upstream->configSha256), now + 100);
        }
        return TunnelResult::success();
    }
    TunnelStats readStats() override { return st; }
    // VpnConnectionTunnelControl::down(): an active session's seat goes back with the stop
    void down() override
    {
        ++downs;
        if (owner.active() && !owner.preparing())
            owner.disconnect(now);
    }
};

struct RaceProber : path::IPathProber {
    QList<std::pair<path::ProbeStamp, QString>> started;
    path::ProberCaps caps() const override
    {
        path::ProberCaps c;
        c.available = true;
        return c;
    }
    void start(const path::ProbeStamp &s, const path::PathCandidate &p, int) override { started.append({ s, p.id.id }); }
    void cancel(const path::ProbeStamp &) override {}
    path::ProbeStamp stampOf(const QString &node) const
    {
        for (const auto &e : started)
            if (e.second == node)
                return e.first;
        return {};
    }
};

// A loopback "provider edge": silent (accepts, never answers) or answering a first chunk after firstByteMs.
struct ProbeEdge {
    QTcpServer server;
    int firstByteMs = -1; // -1 = never
    ProbeEdge(int firstByte) : firstByteMs(firstByte)
    {
        server.listen(QHostAddress::LocalHost);
        QObject::connect(&server, &QTcpServer::newConnection, &server, [this]() {
            while (QTcpSocket *s = server.nextPendingConnection()) {
                QObject::connect(s, &QTcpSocket::readyRead, s, [this, s]() {
                    s->readAll();
                    if (firstByteMs >= 0)
                        QTimer::singleShot(firstByteMs, s, [s]() {
                            s->write("HTTP/1.1 200 OK\r\nContent-Length: 65536\r\n\r\n");
                            s->write(QByteArray(4096, 'x')); // the body keeps coming (the rest never: still running)
                        });
                });
            }
        });
    }
    QString base() const { return QStringLiteral("http://127.0.0.1:%1").arg(server.serverPort()); }
};

static void providerLegStarvedCheck()
{
    TuningStore::set({}, {{QStringLiteral("upstream_nodes"), true}, {QStringLiteral("xray_client"), true},
                          {QStringLiteral("path_race"), true}}, {}, {});
    QJsonObject own = awgNode("9", 9, "EE");
    own.insert("manual_only", true); // the own path is the race's: the owner's first leg is the provider
    const QJsonArray pool{stubNode("aaaaaaaaaaaaaaa0", 1, 0), own};
    const QString provider = QStringLiteral("up:aaaaaaaaaaaaaaa0");
    QNetworkAccessManager nam;
    UpstreamLeaseClient client;
    client.configure(&nam, [] { return QStringLiteral("http://127.0.0.1:1"); }, QStringLiteral("00"),
                     [] { return QStringLiteral("token"); });
    struct Run {
        ServiceEngine eng;
        SeatTunnel tun;
        RaceProber prober;
        QStringList journal;
        QList<bool> told; // what the provider check's watch told the engine, in order
    };
    // The facade's provider check (AvpnEngineQml::upstreamVerifyAttempt): the probe with the first-byte watch whose
    // sink is the engine's noteCheckStarved.
    // Returns when the request ended (its own bound: timeoutMs); starvedAtMs = when the watch first said "starving".
    const auto runCheck = [&client](Run &r, const ProbeEdge &edge, int timeoutMs) {
        UpstreamLeaseClient::ProbeRequest pr;
        pr.base = edge.base();
        pr.scanToken = QStringLiteral("tsc1.scan");
        pr.bytes = 65536;
        pr.nonce = QByteArrayLiteral("0123456789abcdef");
        pr.timeoutMs = timeoutMs;
        QElapsedTimer clock;
        clock.start();
        qint64 starvedAtMs = -1;
        pr.firstByteShareMs = kWhoamiFirstByteShareMs;
        pr.onStarved = [&r, &clock, &starvedAtMs](bool starved) {
            if (starved && starvedAtMs < 0)
                starvedAtMs = clock.elapsed();
            r.told << starved;
            r.eng.noteCheckStarved(starved);
        };
        bool done = false;
        client.runProbe(pr, [&done](const UpstreamProbeFacts &) { done = true; });
        while (!done && clock.elapsed() < timeoutMs + 3000)
            QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
        CHECK(done);
        return starvedAtMs;
    };
    const auto begin = [&](Run &r) {
        r.eng.setTunnel(&r.tun);
        r.eng.setNowMsForTest([&r] { return r.tun.now; });
        QString err;
        CHECK(r.eng.loadSubscription(body(pool), err));
        path::NetworkObservation cell;
        cell.medium = path::NetMedium::Cellular;
        cell.gateway = QStringLiteral("10.64.0.1");
        r.eng.observeNetwork(cell);
        r.eng.setProber(&r.prober);
        CHECK(r.eng.connect(err) && r.tun.ups == QStringList{ provider } && r.eng.raceRunning());
        for (int i = 0; i < 3; ++i) { // the race's stagger: the own path's probe starts too
            r.tun.now += 500;
            r.eng.attemptTick();
        }
        CHECK(r.prober.stampOf(QStringLiteral("9")).race != 0);
        r.eng.onTunnelConnected(); // the provider leg is up (its seat held), in its data check
        CHECK(r.eng.isVerifying() && r.tun.owner.active());
    };
    // 1. Starving + the race proved 9: the provider leg is left inside the check's budget, its seat released.
    {
        Run r;
        begin(r);
        r.tun.now += 500;
        r.eng.onProbeResult(r.prober.stampOf(QStringLiteral("9")), path::PathOutcome::ProbeOk, 1000);
        CHECK(r.tun.downs == 0 && r.eng.isVerifying()); // a proof alone never ends a check
        ProbeEdge silent(-1);
        const qint64 starvedAt = runCheck(r, silent, 2000);
        CHECK(r.told.value(0, false) && r.tun.downs == 1);
        // the attempt moves on at the share, inside the check's own budget
        CHECK(starvedAt >= kWhoamiFirstByteShareMs && starvedAt < r.eng.dataCheckMs());
        const FakeIo::Call *rel = r.tun.io.last("release");
        CHECK(rel && rel->profileOrLease == QLatin1String(kLease) && r.tun.owner.releaseSent());
        r.tun.now += 300;
        r.eng.onTunnelDisconnected(); // the stop confirmed
        CHECK(r.tun.ups.last() == QLatin1String("9") && r.eng.attemptRunning());
        CHECK(r.eng.pathStateHere(provider) == QLatin1String("unknown")); // one starving check: nothing recorded
        r.journal << r.eng.takeAttemptJournal();
        bool preempted = false;
        for (const QString &l : r.journal)
            preempted = preempted || l.contains(QStringLiteral("leg_preempted_for_proof node=") + provider);
        CHECK(preempted);
    }
    // 2. Receiving: the first byte came late (past the share) and bytes flow - a later proof keeps the provider leg.
    {
        Run r;
        begin(r);
        ProbeEdge late(1300);
        runCheck(r, late, 1800); // bytes flow from 1.3 s, the body never completes: our bound ends the request
        CHECK(r.told == (QList<bool>{ true, false }));
        r.tun.now += 500;
        r.eng.onProbeResult(r.prober.stampOf(QStringLiteral("9")), path::PathOutcome::ProbeOk, 1000);
        CHECK(r.tun.downs == 0 && r.eng.isVerifying() && !r.tun.io.last("release"));
    }
    // 3. An answer inside the share: the watch says nothing.
    {
        Run r;
        begin(r);
        ProbeEdge quick(50);
        runCheck(r, quick, 1500);
        CHECK(r.told.isEmpty() && r.tun.downs == 0);
    }
    TuningStore::set({}, {}, {}, {});
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    providerLegStarvedCheck();
    earlyRefusals();
    scanOfferedRows();
    quitEndsUpstreamSession();
    picker16AndNotices();
    flagOffIdentical();
    identityAndReseed();
    ownerAcquireOutcomes();
    ownerRefusedBringUp();
    ownerSeatFirst();
    ownerReviewRound1();
    ownerSeatModel();
    ownerMacRenewals();
    ownerAdoption();
    dataCheck();
    standbyAndStatus();
    envelopeAndParsing();
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
