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
#include <QSet>
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

static void setFlags(bool upstream)
{
    QMap<QString, bool> f{{QStringLiteral("upstream_nodes"), upstream}, {QStringLiteral("xray_client"), true},
                          {QStringLiteral("transport_auto_pick"), true}};
    TuningStore::set({}, f, {}, {});
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
    struct Call { QString what; quint64 id; QString profileOrLease; QString sha; LeaseRoute route; UpstreamMeter meter; QString nonce; qint64 order = -1; };
    QVector<Call> calls;
    void acquire(quint64 id, const QString &profileId, LeaseKind, const QString &sha, const LeaseRoute &route,
                 const QString &nonce, qint64 order) override
    {
        calls << Call{QStringLiteral("acquire"), id, profileId, sha, route, {}, nonce, order};
    }
    void renew(quint64 id, const QString &leaseId, const UpstreamMeter &m, const LeaseRoute &route) override
    {
        calls << Call{QStringLiteral("renew"), id, leaseId, {}, route, m, {}};
    }
    void release(quint64 id, const QString &leaseId, const UpstreamMeter &m, const LeaseRoute &route) override
    {
        calls << Call{QStringLiteral("release"), id, leaseId, {}, route, m, {}};
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
// as the facade runs it (AvpnEngineQml::upstreamVerifyAttempt), on a fake clock: first attempt as soon as the tunnel
// is up (floor 19.11: no 800 ms clock wait), each attempt then decideUpstreamEarlyRetry(upstreamProbeNotYet(facts),
// retries so far, budget left).
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
    qint64 t = 0;
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
    CHECK(w.attempts == 4 && w.spacing == QList<qint64>({300, 600, 1200})); // 0, 303, 906 refused; 2109 data
    CHECK(w.endedAtMs == 2109 + 700);
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
    CHECK(w.verdict.verdict == UpstreamVerdict::NotThroughProvider && w.attempts == 4);
    // A profile that answers at once is proven by its first probe, with no wait before it (floor 19.11): the check
    // ends one transfer after the tunnel is up (it used to start 800 ms later).
    w = runEarlyCheck([&](qint64) { return complete("net-b", good); }, 12000, access);
    CHECK(w.verdict.verdict == UpstreamVerdict::Works && w.attempts == 1 && w.endedAtMs == 700);
    // The shared rule: the provider check and the own-server whoami space their retries alike (DataCheckRetry.h).
    CHECK(decideUpstreamEarlyRetry(true, 2, 5000).delayMs == decideDataCheckRetry(true, 2, 5000).delayMs
          && kUpstreamEarlyRetryMinLeftMs == kDataCheckRetryMinLeftMs);
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
    // iOS / Android after the tunnel came up: the tunnel owner releases first, on its stop, with the final report -
    // nothing goes out from here at once; the app gives the seat back again after the confirmed stop
    // (ReleaseAfterStop, device round 19.11: a provider seat stopped right after Connected stayed 15 minutes). The
    // machine's session still ends, so a following start acquires.
    {
        FakeIo io;
        UpstreamLeaseOwner o(&io);
        o.begin(a, 1, std::nullopt, T, 1);
        o.onAcquireReply(io.calls[0].id, granted(a.upstream->profileId, a.upstream->configSha256), T + 300);
        o.tunnelUp(T + 2000);
        const QVector<UpstreamOwnerEvent> ev = o.disconnect(T + 60000);
        CHECK(!io.last("release") && !o.releaseSent());
        const UpstreamOwnerEvent *after = findEv(ev, UpstreamOwnerEventKind::ReleaseAfterStop);
        CHECK(after && after->leaseId == QLatin1String(kLease));
        CHECK(!findEv(o.disconnect(T + 61000), UpstreamOwnerEventKind::ReleaseAfterStop)); // once per session
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
    CHECK(!upstreamAppReleasesSeat(false, true, true));  // the tunnel owner has it (and ReleaseAfterStop after it)
    // A seat the app ends before the tunnel came up goes at once, never as ReleaseAfterStop.
    {
        FakeIo io;
        UpstreamLeaseOwner o(&io);
        o.begin(a, 1, std::nullopt, T, 1);
        o.onAcquireReply(io.calls[0].id, granted(a.upstream->profileId, a.upstream->configSha256), T + 300);
        const QVector<UpstreamOwnerEvent> ev = o.disconnect(T + 1000);
        CHECK(io.last("release") && !findEv(ev, UpstreamOwnerEventKind::ReleaseAfterStop));
    }
    // The release body: a report only when there is one (seq >= 1); seq 0 (a late grant, the app's release after
    // the tunnel owner's) goes without a body - the server refuses a report with seq 0 (422) and the seat stayed.
    CHECK(upstreamReleaseBody(UpstreamMeter{}).isEmpty());
    CHECK(!upstreamReleaseBody(UpstreamMeter{1, 10, 20, MeterScope::Tunnel, 0}).isEmpty());
    // Round 9 R1: the release carries the renew token of the grant it undoes, alone or next to the final report; a lease
    // without a token (a probe lease, an older server) is released exactly as before.
    {
        const QJsonObject alone = QJsonDocument::fromJson(upstreamReleaseBody(UpstreamMeter{}, QStringLiteral("tlr1.x"))).object();
        CHECK(alone.size() == 1 && alone.value(QLatin1String(kUpstreamReleaseTokenField)).toString() == QLatin1String("tlr1.x"));
        const QJsonObject both = QJsonDocument::fromJson(
            upstreamReleaseBody(UpstreamMeter{1, 10, 20, MeterScope::Tunnel, 0}, QStringLiteral("tlr1.x"))).object();
        CHECK(both.value(QLatin1String("seq")).toInt() == 1 && both.value(QLatin1String("rx_bytes_delta")).toInt() == 10
              && both.value(QLatin1String(kUpstreamReleaseTokenField)).toString() == QLatin1String("tlr1.x"));
        CHECK(upstreamReleaseBody(UpstreamMeter{}, QString()).isEmpty());
        CHECK(!QJsonDocument::fromJson(upstreamReleaseBody(UpstreamMeter{1, 10, 20, MeterScope::Tunnel, 0}, QString()))
                   .object().contains(QLatin1String(kUpstreamReleaseTokenField)));
    }
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
    // Quick picks B -> C -> D (contract 1.19.0): every start has its own nonce and sends its own acquire AT ONCE - nothing waits for
    // an older start's request, whatever its profile. The older requests are left to finish: a grant of a start nobody continues
    // is released with its own token (the machine's cancelled acquire), a refusal is ignored; only the last pick's answer is
    // Prepared. (Before, one acquisition was in flight at a time and the later picks waited in a queue.)
    for (bool grantB : {true, false}) {
        FakeIo io;
        UpstreamLeaseOwner o(&io);
        o.prepare(b, 1, T, 1);
        const quint64 idB = io.calls.last().id;
        o.prepare(c, 1, T + 100, 1);
        const quint64 idC = io.calls.last().id;
        o.prepare(d, 1, T + 200, 1);
        const quint64 idD = io.calls.last().id;
        CHECK(io.calls.size() == 3 && idB != idC && idC != idD && o.requestsOutstanding() == 2);
        CHECK(io.calls[0].nonce != io.calls[1].nonce && io.calls[1].nonce != io.calls[2].nonce && io.calls[0].nonce != io.calls[2].nonce);
        CHECK(io.calls[0].order < io.calls[1].order && io.calls[1].order < io.calls[2].order); // strictly increasing across starts
        const QVector<UpstreamOwnerEvent> evB =
            o.onAcquireReply(idB, grantB ? grantedAs(b, kB) : refused(UpstreamErrorCode::NoSeat), T + 300);
        CHECK(!findEv(evB, UpstreamOwnerEventKind::Prepared) && !findEv(evB, UpstreamOwnerEventKind::PrepareFailed));
        CHECK((io.last("release") != nullptr) == grantB);
        if (grantB)
            CHECK(io.last("release") && io.last("release")->profileOrLease == QLatin1String(kB));
        o.onAcquireReply(idC, refused(UpstreamErrorCode::NoSeat), T + 350); // an older start's refusal: nothing to tell
        const QVector<UpstreamOwnerEvent> evD = o.onAcquireReply(idD, grantedAs(d, kD), T + 500);
        const UpstreamOwnerEvent *p = findEv(evD, UpstreamOwnerEventKind::Prepared);
        CHECK(p && p->prepareId == o.prepareSerial() && o.preparedUsable(d.nodeId, T + 600));
        CHECK(o.requestsOutstanding() == (grantB ? 1 : 0)); // only B's release (when there was a grant) is out
    }
    // B -> C -> B: the second B is a start of its own (its own nonce, its own acquire). The first B's grant is the cancelled start's:
    // released with its own token, never the seat the second B holds (the server gives the second start ANOTHER lease and ends the
    // first as replaced, so that DELETE is a no-op there).
    {
        const char *kB2 = "LeaseB2BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        FakeIo io;
        UpstreamLeaseOwner o(&io);
        o.prepare(b, 1, T, 1);
        const quint64 idB1 = io.calls.last().id;
        o.prepare(c, 1, T + 100, 1);
        o.prepare(b, 1, T + 200, 1);
        const quint64 idB2 = io.calls.last().id;
        CHECK(io.calls.size() == 3 && idB2 != idB1 && io.calls[0].nonce != io.calls[2].nonce);
        const QVector<UpstreamOwnerEvent> ev1 = o.onAcquireReply(idB1, grantedAs(b, kB), T + 300);
        CHECK(!findEv(ev1, UpstreamOwnerEventKind::Prepared) && io.last("release") && io.last("release")->profileOrLease == QLatin1String(kB));
        AcquireReply g2 = grantedAs(b, kB2);
        const QVector<UpstreamOwnerEvent> ev2 = o.onAcquireReply(idB2, g2, T + 400);
        const UpstreamOwnerEvent *p = findEv(ev2, UpstreamOwnerEventKind::Prepared);
        CHECK(p && p->prepareId == o.prepareSerial() && o.machine().leaseId() == QLatin1String(kB2));
        // A later replay of the same answer changes nothing.
        const int calls = io.calls.size();
        CHECK(o.onAcquireReply(idB2, g2, T + 450).isEmpty() && io.calls.size() == calls);
        // brought up: still the second lease, no release of it
        const QVector<UpstreamOwnerEvent> up = o.bringUpPrepared(T + 500);
        CHECK(findEv(up, UpstreamOwnerEventKind::BringUp) && io.last("release")->profileOrLease == QLatin1String(kB));
    }
    // A held seat given back, then the same profile picked again, the DELETE still on the wire: the new acquire does
    // NOT wait for it (round 9 R1: a local timeout proves nothing about the server) and does NOT take it back either: the
    // new start has its own nonce, so the server gives it ANOTHER lease and the old DELETE can only end the old start's
    // own lease - it runs on (and keeps its final report if it carries one).
    {
        FakeIo io;
        UpstreamLeaseOwner o(&io);
        o.prepare(b, 1, T, 1);
        o.onAcquireReply(io.calls.last().id, grantedAs(b, kB), T + 100);
        o.disconnect(T + 200);
        const FakeIo::Call *rel = io.last("release");
        CHECK(rel && rel->profileOrLease == QLatin1String(kB) && rel->route.renewToken == QLatin1String("tlr1.secret"));
        const quint64 relId = rel ? rel->id : 0;
        const int before = io.calls.size();
        o.prepare(b, 1, T + 300, 1);
        CHECK(io.calls.size() == before + 1 && io.calls.last().what == QLatin1String("acquire"));
        QVector<UpstreamOwnerEvent> evW;
        CHECK(o.releaseWanted(relId, T + 350, evW)); // its resends go on: the old DELETE is harmless to the new start
        // A release that is NOT on the wire (waiting for its resend) is not taken back by the start either; the start goes at once
        {
            FakeIo io3;
            UpstreamLeaseOwner o3(&io3);
            o3.prepare(b, 1, T, 1);
            o3.onAcquireReply(io3.calls.last().id, grantedAs(b, kB), T + 100);
            o3.disconnect(T + 200);
            const quint64 id3 = io3.last("release")->id;
            const int n3 = io3.calls.size();
            o3.prepare(b, 1, T + 300, 1);
            CHECK(io3.calls.size() == n3 + 1 && io3.calls.last().what == QLatin1String("acquire"));
            QVector<UpstreamOwnerEvent> ev3;
            CHECK(o3.releaseWanted(id3, T + 350, ev3)); // the resend is still wanted
        }
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
    // F5: every prepare() has its own identity, carried by its answer. A second prepare of the same node is a start of its own
    // (own nonce, own acquire): the first one's grant is the cancelled start's (released), the answer of the second is reported
    // once, with the SECOND prepare's id.
    {
        const char *kB2 = "LeaseB2BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        FakeIo io;
        UpstreamLeaseOwner o(&io);
        o.prepare(b, 1, T, 1);
        const quint64 first = o.prepareSerial();
        const quint64 idFirst = io.calls.last().id;
        o.prepare(b, 1, T + 50, 1);
        const quint64 second = o.prepareSerial();
        const quint64 idSecond = io.calls.last().id;
        CHECK(first != 0 && second != first && io.calls.size() == 2 && idSecond != idFirst);
        const QVector<UpstreamOwnerEvent> evF = o.onAcquireReply(idFirst, grantedAs(b, kB), T + 100);
        CHECK(!findEv(evF, UpstreamOwnerEventKind::Prepared) && io.last("release") && io.last("release")->profileOrLease == QLatin1String(kB));
        const QVector<UpstreamOwnerEvent> ev = o.onAcquireReply(idSecond, grantedAs(b, kB2), T + 150);
        const UpstreamOwnerEvent *p = findEv(ev, UpstreamOwnerEventKind::Prepared);
        CHECK(p && p->prepareId == second);
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
// The server (contract 1.19.0 / 1.20.0): one live session lease per device; an acquire with the live lease's nonce is answered
// with THAT lease and token; another nonce takes the seat over (any profile: the old lease ends as replaced, a new one is made); a
// stale nonce or an order behind the highest seen is refused (404 lease_gone / stale_session) and changes nothing; a refusal for no
// seat leaves the live lease alone; DELETE ends the lease only with its current token. The owner picks B or C (prepare / begin),
// cancels, brings up; every request is answered in a random order. Invariants after every step: a seat the owner holds is live
// on the server (it never released, or let something replace, its own seat); at the end every seat is given back.
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
        struct Live { QString lease; QString profile; QString nonce; QString token; } live;
        QSet<QString> staleNonces;
        qint64 highestOrder = 0;
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
            bool bad = false;
            const bool holds = o.active() && o.machine().phase() == LeasePhase::Active && !o.machine().leaseId().isEmpty();
            bool releaseOut = false;
            for (int i : pending)
                releaseOut = releaseOut || (io.calls[i].what == QLatin1String("release") && io.calls[i].profileOrLease == o.machine().leaseId()
                                            && io.calls[i].route.renewToken == o.machine().route().renewToken); // the session's OWN grant released under it
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
                if (staleNonces.contains(call.nonce) || call.order < highestOrder) {
                    r = refused(UpstreamErrorCode::LeaseGone); // 404 lease_gone / stale_session: nothing changes
                    r.error.reason = QStringLiteral("stale_session");
                } else {
                    highestOrder = call.order;
                    if (!live.lease.isEmpty() && live.nonce == call.nonce) {
                        r = grantedAs(n, "");
                        r.grant.leaseId = live.lease; // the same start: the same lease and token
                        r.grant.renewToken = live.token;
                        ++reuses;
                    } else if (rnd(10) < 3) {
                        r = refused(UpstreamErrorCode::NoSeat); // a refusal leaves the live lease alone
                    } else {
                        if (!live.lease.isEmpty())
                            staleNonces.insert(live.nonce); // taken over: replaced
                        live.lease = QStringLiteral("LeaseModel%1").arg(++serial, 30, 10, QLatin1Char('0'));
                        live.profile = call.profileOrLease;
                        live.nonce = call.nonce;
                        r = grantedAs(n, "");
                        r.grant.leaseId = live.lease;
                        r.grant.renewToken = live.token = QStringLiteral("tlr1.%1.%2").arg(live.lease, call.nonce);
                    }
                }
                o.onAcquireReply(call.id, r, now);
            } else if (call.what == QLatin1String("release")) {
                ++releases;
                if (live.lease == call.profileOrLease && live.token == call.route.renewToken) {
                    staleNonces.insert(live.nonce); // released: its nonce is stale for good
                    live = Live(); // only the current token ends the lease
                }
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
    std::printf("seat model: %d steps, %d releases, %d same-start re-answers\n", steps, releases, reuses);
    // The model really exercised releases and same-lease re-issues (an acquire of a profile whose release is still out
    // is no longer held back, round 9 R1: the server's token rule makes the old release harmless).
    CHECK(releases > 100);
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
                          {avpn::ServiceEngine::raceFlagKey(), true}}, {}, {});
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
        // The leg raised beside the race at once (race_hedge_ms = 0): this block is about a starving check of a leg
        // that is up, whatever raised it (with the default the owner would wait for the race's first proof).
        path::RaceTimings atOnce;
        atOnce.hedgeMs = 0;
        r.eng.setRaceTimingsForTest(atOnce);
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

// Device round 19.11 08:18:42: a prod API restart answered the session seat's DELETE 502, nothing resent it and the
// seat stayed its full 15 minutes. The session release follows the one release rule (seatReleaseNext): 502 then 204
// -> released; 502 x N -> given up after the budget (not confirmed); 404 / 409 -> final at once.
static void sessionReleaseRetry()
{
    struct ReleaseEdge {
        QTcpServer server;
        QList<int> statuses; // answered in turn; then 204
        int deletes = 0;
        ReleaseEdge()
        {
            server.listen(QHostAddress::LocalHost);
            QObject::connect(&server, &QTcpServer::newConnection, &server, [this]() {
                while (QTcpSocket *s = server.nextPendingConnection()) {
                    QObject::connect(s, &QTcpSocket::readyRead, s, [this, s]() {
                        const QByteArray rq = s->readAll();
                        if (!rq.startsWith("DELETE /v1/upstream/lease/"))
                            return;
                        ++deletes;
                        const int st = statuses.isEmpty() ? 204 : statuses.takeFirst();
                        s->write("HTTP/1.1 " + QByteArray::number(st) + " X\r\nX-Tribe-Api: 1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"); // the API's own answer: it carries the mark
                        s->disconnectFromHost();
                    });
                }
            });
        }
        QString base() const { return QStringLiteral("http://127.0.0.1:%1").arg(server.serverPort()); }
    };
    const auto run = [](QList<int> statuses, qint64 budgetMs, int *deletes) {
        ReleaseEdge edge;
        edge.statuses = statuses;
        QNetworkAccessManager nam;
        UpstreamLeaseClient client;
        const QString base = edge.base();
        client.configure(&nam, [base] { return base; }, QStringLiteral("00"), [] { return QStringLiteral("token"); });
        client.releaseRetryBudgetMs = budgetMs;
        int result = -1; // -1 = not ended, 0 = not confirmed, 1 = confirmed
        client.onReleaseDone = [&result](quint64, bool confirmed) { result = confirmed ? 1 : 0; };
        client.release(7, QStringLiteral("LEASEIDLEASEIDLEASEIDLEASEID0007"), UpstreamMeter{}, LeaseRoute{});
        QElapsedTimer t;
        t.start();
        while (result < 0 && t.elapsed() < 9000)
            QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
        *deletes = edge.deletes;
        return result;
    };
    int deletes = 0;
    CHECK(run({502}, kSeatReleaseRetryBudgetMs, &deletes) == 1 && deletes == 2);          // 502 then 204: released
    CHECK(run({502, 502, 502, 502, 502}, 2500, &deletes) == 0 && deletes == 3);          // gives up after the bound
    CHECK(run({404}, kSeatReleaseRetryBudgetMs, &deletes) == 1 && deletes == 1);          // final, no resend
    CHECK(run({409}, kSeatReleaseRetryBudgetMs, &deletes) == 1 && deletes == 1);
}

// S3 (device round 10): a provider leg that never put a lease request or a tunnel start on the network (held by our own
// bookkeeping, refused locally) must not be written as the path's no_handshake - the server proven a minute ago was
// pushed behind every untried one by exactly that. A leg that really sent and got nothing is still recorded.
static void localRefusalRecordsNothing()
{
    struct QuietTunnel : SeatTunnel {
        bool sent = false;
        bool upstreamRequestSent() const override { return sent; }
    };
    for (const bool sent : {false, true}) {
        TuningStore::set({}, {{QStringLiteral("upstream_nodes"), true}, {QStringLiteral("xray_client"), true}}, {}, {});
        const QJsonArray pool{stubNode("aaaaaaaaaaaaaaa0", 1, 0)};
        const QString provider = QStringLiteral("up:aaaaaaaaaaaaaaa0");
        ServiceEngine eng;
        QuietTunnel tun;
        tun.sent = sent;
        eng.setTunnel(&tun);
        eng.setNowMsForTest([&tun] { return tun.now; });
        QString err;
        CHECK(eng.loadSubscription(body(pool), err));
        path::NetworkObservation wifi;
        wifi.medium = path::NetMedium::Wifi;
        wifi.gateway = QStringLiteral("192.168.9.1");
        eng.observeNetwork(wifi);
        CHECK(eng.connect(err) && tun.ups == QStringList{ provider });
        for (int i = 0; i < 30 && eng.attemptRunning() && eng.pathStateHere(provider) == QLatin1String("unknown"); ++i) {
            tun.now += 1000; // past the leg's start deadline: the leg ends with no_handshake
            eng.attemptTick();
        }
        QStringList journal = eng.takeAttemptJournal();
        bool noted = false;
        for (const QString &l : journal)
            noted = noted || l.contains(QStringLiteral("leg_nothing_sent"));
        if (sent)
            CHECK(eng.pathStateHere(provider) != QLatin1String("unknown") && !noted);
        else
            CHECK(eng.pathStateHere(provider) == QLatin1String("unknown") && noted);
    }
    TuningStore::set({}, {}, {}, {});
}

// Lease id ledger (UpstreamLeaseOwner.h; reviews R4, R5 of 19.11, F3, F4, F9 of round 2): the REAL
// UpstreamLeaseClient and UpstreamLeaseOwner against a loopback server that holds its answers until the test lets them
// go. The server hands the same lease id back to the same device and profile and any DELETE ends it, as the real one.
// Round 11 R3: ONE rule decides what is an answer of the API - the mark X-Tribe-Api: 1 - for acquire answers (a route is proved by
// an API answer only) and for release answers (a release is finished by an API answer only).
static void apiMarkRules()
{
    CHECK(upstreamFromTribeApi(QByteArrayLiteral("1")) && !upstreamFromTribeApi(QByteArray()) && !upstreamFromTribeApi(QByteArrayLiteral("0")));
    // acquire: the classification carries the mark; the route is proved by an API answer, whatever its status or body
    const AcquireReply foreign403 = classifyAcquireReply(403, QByteArrayLiteral("<html>blocked</html>"), {}, QString(), false);
    const AcquireReply api409 = classifyAcquireReply(409, QByteArrayLiteral("{\"code\":\"no_seat\"}"), {}, QString(), true);
    const AcquireReply api503 = classifyAcquireReply(503, QByteArrayLiteral("<html></html>"), {}, QString(), true);
    const AcquireReply transport = classifyAcquireReply(0, {}, {}, QString(), false);
    CHECK(foreign403.kind == LeaseReplyKind::Failed && foreign403.why == QLatin1String("http_403") && !upstreamRouteProved(foreign403));
    CHECK(upstreamRouteProved(api409) && upstreamRouteProved(api503) && !upstreamRouteProved(transport));
    // release: 2xx / 4xx of the API are final, a 5xx and anything without the mark are resent, then not confirmed
    const qint64 budget = kSeatReleaseRetryBudgetMs;
    CHECK(seatReleaseNext(204, 0, 0, budget, true).kind == UpstreamReleaseTry::Answered);
    CHECK(seatReleaseNext(404, 0, 0, budget, true).kind == UpstreamReleaseTry::Answered);
    CHECK(seatReleaseNext(204, 0, 0, budget, false).kind == UpstreamReleaseTry::Resend);  // a foreign "204" proves nothing
    CHECK(seatReleaseNext(403, 0, 0, budget, false).kind == UpstreamReleaseTry::Resend);  // a proxy's 403: not final
    CHECK(seatReleaseNext(403, 99, budget, budget, false).kind == UpstreamReleaseTry::NotConfirmed); // past the budget: kept, not final
    CHECK(seatReleaseNext(502, 0, 0, budget, true).kind == UpstreamReleaseTry::Resend);
    CHECK(seatReleaseNext(0, 0, 0, budget, true).kind == UpstreamReleaseTry::Resend);
}

static void lateGrantOwnership()
{
    TuningStore::set({{QStringLiteral("attempt_provider_lease_ms"), 1500}}, {}, {}, {}); // the floor: the wait ends fast
    struct LeaseEdge {
        TestKey key;
        QTcpServer server;
        QList<QTcpSocket *> posts;   // acquire requests, in arrival order
        QList<QTcpSocket *> pendingDeletes;
        QStringList deletes, log;    // lease ids of DELETEs; "POST" / "DELETE" in arrival order
        QStringList deleteTokens;    // the renew_token field of each DELETE's body ("" = none)
        QList<QJsonObject> deleteBodies; // the whole JSON body of each DELETE (the final report, if any, is in it)
        QString token;               // the renew token its grants carry (empty = an older server: none)
        bool holdDeletes = false;
        bool dropDeletes = false; // the direct API is dead for a release: the connection is cut, no answer
        // The answers carry the API's mark (X-Tribe-Api: 1) like the real server's. A blocking proxy in front of the API answers
        // without it: `foreignAnswers` = the POST answers carry no mark; `foreignDeletes` = every DELETE gets `foreignStatus`, no mark.
        bool foreignAnswers = false, foreignDeletes = false;
        int foreignStatus = 403;
        QList<qint64> deleteTimes;
        QElapsedTimer sinceStart;
        LeaseEdge()
        {
            sinceStart.start();
            server.listen(QHostAddress::LocalHost);
            QObject::connect(&server, &QTcpServer::newConnection, &server, [this]() {
                while (QTcpSocket *s = server.nextPendingConnection()) {
                    QObject::connect(s, &QTcpSocket::readyRead, s, [this, s]() {
                        const QByteArray rq = s->readAll();
                        if (rq.startsWith("DELETE /v1/upstream/lease/")) {
                            deletes << QString::fromLatin1(rq.mid(26, rq.indexOf(' ', 26) - 26));
                            const int bodyAt = rq.indexOf("\r\n\r\n");
                            deleteBodies << QJsonDocument::fromJson(bodyAt < 0 ? QByteArray() : rq.mid(bodyAt + 4)).object();
                            deleteTokens << deleteBodies.last().value(QLatin1String("renew_token")).toString();
                            log << QStringLiteral("DELETE");
                            deleteTimes << sinceStart.elapsed();
                            if (dropDeletes)
                                s->disconnectFromHost();
                            else if (holdDeletes)
                                pendingDeletes << s;
                            else
                                finishDelete(s);
                        } else if (rq.startsWith("POST /v1/upstream/lease ")) {
                            posts << s;
                            log << QStringLiteral("POST");
                        }
                    });
                }
            });
        }
        void finishDelete(QTcpSocket *s)
        {
            if (foreignDeletes)
                s->write("HTTP/1.1 " + QByteArray::number(foreignStatus) + " X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            else
                s->write("HTTP/1.1 204 X\r\nX-Tribe-Api: 1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            s->disconnectFromHost();
        }
        void releaseDeletes()
        {
            holdDeletes = false;
            for (QTcpSocket *s : std::exchange(pendingDeletes, {}))
                finishDelete(s);
        }
        QString base() const { return QStringLiteral("http://127.0.0.1:%1").arg(server.serverPort()); }
        void grant(int i) // the existing lease, as the server hands it back to the same device and profile
        {
            const QByteArray b = QJsonDocument(leaseObject()).toJson(QJsonDocument::Compact);
            answer(i, "200 OK", b, key.sign(QByteArrayLiteral("tribe-upstream-lease-v1\n") + b));
        }
        static QString cfgSha() { return QString::fromLatin1(QCryptographicHash::hash("{\"inbounds\":[]}", QCryptographicHash::Sha256).toHex()); }
        QString leaseId = QLatin1String(kLease);
        QJsonObject leaseObject() const
        {
            QJsonObject o{{"type", "upstream_lease"}, {"lease_id", leaseId},
                               {"profile_id", "aaaaaaaaaaaaaaa0"}, {"kind", "session"},
                               {"expires_at", QDateTime::fromMSecsSinceEpoch(kServerT0 + 900000, QTimeZone::UTC).toString(Qt::ISODateWithMs)},
                               {"ttl_s", 900}, {"renew_after_s", 300}, {"seq", 0}, {"config", QStringLiteral("{\"inbounds\":[]}")},
                               {"config_sha256", cfgSha()}, {"upstream_revision", 5}, {"traffic_accounting_epoch", 1}};
            if (!token.isEmpty())
                o.insert(QStringLiteral("renew_token"), token);
            return o;
        }
        void refuse(int i) { answer(i, "409 X", R"({"code":"no_seat","retry_after_s":30,"upstream_revision":1})", {}); }
        void answer(int i, const QByteArray &status, const QByteArray &body, const QByteArray &sig)
        {
            QTcpSocket *s = posts.value(i);
            if (!s)
                return;
            s->write("HTTP/1.1 " + status + "\r\nContent-Type: application/json\r\nContent-Length: "
                     + QByteArray::number(body.size()) + "\r\n" + (sig.isEmpty() ? QByteArray() : "X-Tribe-Sig: " + sig + "\r\n")
                     + (foreignAnswers ? QByteArray() : QByteArray("X-Tribe-Api: 1\r\n"))
                     + "Connection: close\r\n\r\n" + body);
            s->disconnectFromHost();
        }
    };
    // The wiring of VpnConnectionTunnelControl, in miniature: the client's facts go to the owner, the owner's
    // events that need the I/O (ReleaseAfterStop) are applied the way the adapter applies them.
    struct Rig {
        LeaseEdge edge;
        LeaseEdge edge2; // the tunnel's API base (row S2)
        QNetworkAccessManager nam;
        UpstreamLeaseClient client;
        UpstreamLeaseOwner owner;
        QElapsedTimer clock;
        SubscriptionNode node = stubOf();
        Rig()
        {
            node.upstream->configSha256 = LeaseEdge::cfgSha();
            TuningStore::set({{QStringLiteral("attempt_provider_lease_ms"), 1500}}, {{QStringLiteral("upstream_nodes"), true}}, {}, {}); // stubOf() reset it
            clock.start();
            const QString base = edge.base();
            client.configure(&nam, [base] { return base; }, edge.key.pubHex(), [] { return QStringLiteral("token"); });
            owner.setIo(&client);
            client.onAcquire = [this](quint64 id, const AcquireReply &r) { apply(owner.onAcquireReply(id, r, now())); };
            client.onReleaseDone = [this](quint64 id, bool confirmed) { apply(owner.onReleaseDone(id, now(), confirmed)); };
            client.onLateGrant = [this](const QString &p, const QString &l, const LeaseRoute &r, bool newer, quint64 id) {
                apply(owner.lateGrant(p, l, r, newer, id));
            };
            client.onAcquireEnded = [this](const QString &p, const QString &l, bool out) { apply(owner.acquireEnded(p, l, out)); };
            client.onRouteProved = [this](quint64 id) { owner.routeProved(id, now()); };
            client.hasStandbyFor = [this](const QString &p) { return owner.hasStandbyFor(p); };
            client.releaseWanted = [this](quint64 id) {
                QVector<UpstreamOwnerEvent> ev;
                const bool wanted = owner.releaseWanted(id, now(), ev);
                apply(ev);
                return wanted;
            };
        }
        qint64 now() const { return clock.elapsed(); }
        void apply(const QVector<UpstreamOwnerEvent> &ev)
        {
            for (const UpstreamOwnerEvent &e : ev)
                if (e.kind == UpstreamOwnerEventKind::ReleaseAfterStop) {
                    client.holdReleasesForStopIfRunning();
                    client.release(e.requestId, e.leaseId, UpstreamMeter{}, e.route);
                }
        }
        void begin(const std::optional<StandbyCandidate> &standby = std::nullopt)
        {
            apply(owner.begin(node, 1, standby, now(), 1));
        }
        // VpnConnectionTunnelControl::upstreamTunnelDown(endsSession = true)
        void disconnectedByTheSystem()
        {
            client.tunnelStopped();
            apply(owner.tunnelLost(now()));
        }
    };
    const auto pump = [](int ms) {
        QElapsedTimer t;
        t.start();
        while (t.elapsed() < ms)
            QCoreApplication::processEvents(QEventLoop::AllEvents, 10);
    };
    // The first request outlives the attempt's wait (the owner's session fails by transport, the HTTP request lives on).
    const auto firstTimesOut = [&](Rig &r) {
        r.begin();
        QElapsedTimer t;
        t.start();
        while (r.owner.active() && t.elapsed() < 6000) // the attempt's wait ends: a transport failure for the owner
            pump(10);
        CHECK(r.edge.posts.size() == 1 && !r.owner.active());
    };
    // Row R4: the live session holds L (granted by the second request); the first answer lands late -> nothing.
    {
        Rig r;
        firstTimesOut(r);
        r.begin();
        pump(200);
        CHECK(r.edge.posts.size() == 2);
        r.edge.grant(1);
        pump(300);
        CHECK(r.owner.holdsLease(QLatin1String(kLease)));
        r.edge.grant(0);
        pump(900);
        CHECK(r.edge.deletes.isEmpty());
    }
    // Row R4b: the late answer lands while the second request is still out; the second then gets the same id -> nothing.
    {
        Rig r;
        firstTimesOut(r);
        r.begin();
        pump(200);
        r.edge.grant(0);
        pump(300);
        CHECK(r.edge.deletes.isEmpty());
        r.edge.grant(1);
        pump(900);
        CHECK(r.edge.deletes.isEmpty() && r.owner.holdsLease(QLatin1String(kLease)));
    }
    // Row R4c: ... the second one is refused instead -> the deferred seat has no taker: released once, at its end.
    {
        Rig r;
        firstTimesOut(r);
        r.begin();
        pump(200);
        r.edge.grant(0);
        pump(300);
        r.edge.refuse(1);
        pump(900);
        CHECK(r.edge.deletes == QStringList{ QLatin1String(kLease) });
    }
    // Row F3 (round 9 R1: a start never waits for a release, not even for one on the wire): the late grant lands with NO
    // newer request and is released at once with ITS token; a connect to the same profile while that DELETE is in flight
    // (or being resent) goes out at once. The server rotates the token on the re-acquire, so the DELETE in flight, which
    // carries the late grant's token, can no longer end the new seat.
    {
        Rig r;
        r.edge.token = QStringLiteral("tlr1.lateone");
        firstTimesOut(r);
        r.edge.holdDeletes = true; // the DELETE is on its way (slow link / its retry)
        r.edge.grant(0);
        pump(300);
        CHECK(r.edge.deletes.size() == 1 && r.edge.deleteTokens == QStringList{ QStringLiteral("tlr1.lateone") });
        r.begin(); // the person connects to the same profile
        pump(300);
        CHECK(r.edge.posts.size() == 2); // no wait for the DELETE in flight
        CHECK(r.edge.log.lastIndexOf(QStringLiteral("DELETE")) < r.edge.log.lastIndexOf(QStringLiteral("POST")));
        r.edge.releaseDeletes();
    }
    // Rows R5 + F4 share the session of a running provider tunnel.
    const auto runningSession = [&](Rig &r) {
        r.begin();
        pump(200);
        r.edge.grant(0);
        pump(300);
        CHECK(r.owner.active() && r.owner.holdsLease(QLatin1String(kLease)));
        r.client.tunnelStarted();
        r.owner.tunnelUp(r.now()); // (handed over to the tunnel owner: the extension)
    };
    // Row R5: the app stops the tunnel; the extra release waits for the confirmed stop; an acquire of the profile does NOT wait for
    // it and does not take it back: the new start has its own nonce, the server gives it another lease (the loopback edge hands
    // out `leaseId`, set here to a second lease for the new start), and the old release - which can only end the old start's lease
    // - goes out at the confirmed stop.
    {
        Rig r;
        r.owner.setOptions({}); // iOS: the tunnel owner releases first; the app's own release follows the stop
        runningSession(r);
        r.client.holdReleasesForStop();
        r.apply(r.owner.disconnect(r.now()));
        CHECK(r.edge.deletes.isEmpty()); // held for the stop: not on the wire
        r.begin();
        pump(200);
        CHECK(r.edge.posts.size() == 2); // the start goes at once
        r.edge.leaseId = QStringLiteral("LeaseNewStartBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
        r.edge.grant(1);
        pump(300);
        r.client.tunnelStopped(); // the confirmed stop: the old start's release goes out (a no-op on the server: its lease was replaced)
        pump(500);
        CHECK(r.edge.deletes == QStringList{ QLatin1String(kLease) } && r.owner.holdsLease(r.edge.leaseId));
    }
    // Row F4: the tunnel is turned off from outside (Disconnected nobody asked for), then the same profile at once:
    // the release goes out at that Disconnected (nothing waits for a later one) and the acquire follows it - far
    // inside the start deadline.
    {
        Rig r;
        r.owner.setOptions({});
        runningSession(r);
        r.disconnectedByTheSystem();
        pump(300);
        CHECK(r.edge.deletes.size() == 1 && !r.owner.active());
        QElapsedTimer t;
        t.start();
        r.begin();
        while (r.edge.posts.size() < 2 && t.elapsed() < 3000)
            pump(10);
        CHECK(r.edge.posts.size() == 2 && t.elapsed() < 1500);
    }
    // Row F4b: the old session is still the owner's when the next start comes (no Disconnected seen yet), the stop
    // already happened before the ReleaseAfterStop is created: it is sent at once, not held for a stop that is past.
    {
        Rig r;
        r.owner.setOptions({});
        runningSession(r);
        r.client.tunnelStopped(); // the Disconnected came (not ended the session at the owner)
        r.begin();                // the new start ends the old session: ReleaseAfterStop
        pump(400);
        CHECK(r.edge.deletes.size() == 1);
    }
    // Row F9 (the owner event the Android denial produces): the seat is granted, the start never reaches the native
    // service (the person refuses the VPN permission): the seat goes back at once, with no stop to wait for.
    {
        Rig r;
        r.owner.setOptions({});
        r.begin();
        pump(200);
        r.edge.grant(0);
        pump(300);
        CHECK(r.owner.active() && !r.owner.preparing());
        r.apply(r.owner.abortStart(r.now())); // VpnConnectionTunnelControl::startRefused()
        pump(500);
        CHECK(r.edge.deletes == QStringList{ QLatin1String(kLease) } && !r.owner.active());
    }
    // Row S1 (device round 10): the direct API is dead for a release (the DELETE is cut every time, resent on the growing
    // spacing). Stop, then Connect to the same profile at once: the acquire goes out AT ONCE (it waits for nothing), the server
    // gives the new start ANOTHER lease, and the old release keeps its resends (it is not taken back: it can only end the old
    // start's own lease, and it may still carry the final report) - every DELETE that reaches the server names the old lease.
    {
        Rig r;
        r.owner.setOptions({});
        runningSession(r);
        r.edge.dropDeletes = true;
        r.client.holdReleasesForStop();
        r.apply(r.owner.disconnect(r.now()));
        r.client.tunnelStopped(); // the confirmed stop: the release goes out and is cut
        pump(450);                // one try failed, the next waits its spacing
        CHECK(!r.edge.deletes.isEmpty());
        const int triesBefore = r.edge.deletes.size();
        r.begin();
        QElapsedTimer t;
        t.start();
        while (r.edge.posts.size() < 2 && t.elapsed() < 2000)
            pump(10);
        CHECK(r.edge.posts.size() == 2 && t.elapsed() < 400); // not held for the release's retry budget
        r.edge.leaseId = QStringLiteral("LeaseNewStartBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
        r.edge.grant(1);                                      // the new start's own lease
        pump(3500);                                           // longer than every resend spacing
        CHECK(r.edge.deletes.size() > triesBefore);           // the old release ran on ...
        for (const QString &d : r.edge.deletes)
            CHECK(d == QLatin1String(kLease));                // ... and never named the new start's lease
        CHECK(r.owner.holdsLease(r.edge.leaseId) && r.owner.active());
    }
    // Row S2: the direct API cannot carry the release; it is kept (bounded) and goes out over the tunnel's API base as
    // soon as a session of the standby pack has its seat confirmed through it - not left to the lease's TTL.
    {
        Rig r;
        r.owner.setOptions({});
        r.client.releaseRetryBudgetMs = 900;
        r.edge2.leaseId = QStringLiteral("LeaseBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
        runningSession(r);
        r.edge.dropDeletes = true;
        r.client.holdReleasesForStop();
        r.apply(r.owner.disconnect(r.now()));
        r.client.tunnelStopped();
        QElapsedTimer t;
        t.start();
        while (r.owner.unsentCount() == 0 && t.elapsed() < 6000)
            pump(10);
        CHECK(r.owner.unsentCount() == 1 && r.edge2.deletes.isEmpty()); // kept, not abandoned
        StandbyCandidate sc;
        sc.config = QByteArrayLiteral("{\"inbounds\":[]}");
        sc.configSha256 = LeaseEdge::cfgSha();
        sc.tunnelApiBase = r.edge2.base();
        sc.packRevision = 5;
        r.begin(sc); // the direct API is dead: the acquire fails at once; the standby pack starts the tunnel
        t.start();
        while (r.edge.posts.size() < 2 && t.elapsed() < 2000)
            pump(10);
        r.edge.posts.value(1)->disconnectFromHost(); // the second session's acquire: no answer, a transport failure
        t.start();
        while (!r.owner.provisionalPending() && t.elapsed() < 6000)
            pump(10);
        r.client.tunnelStarted();
        r.apply(r.owner.tunnelUp(r.now())); // Connected: the seat is confirmed through the tunnel's API base
        t.start();
        while (r.edge2.posts.isEmpty() && t.elapsed() < 2000)
            pump(10);
        r.edge2.grant(0);
        t.start();
        while (r.edge2.deletes.isEmpty() && t.elapsed() < 3000)
            pump(10);
        CHECK(r.edge2.deletes == QStringList{ QLatin1String(kLease) } && r.owner.unsentCount() == 0);
    }
    // Round 10 R4: the release of profile A is kept (it could not reach the API). A start of profile B has a pack entry: its
    // direct request passes the 1.2 s hedge (the provisional start begins) and THEN gets an HTTP answer of the API (no seat).
    // That answer proves the direct route like any other; it reaches the owner only as the end of a request that the attempt
    // stopped waiting for - and the kept release of A must go out over that route all the same (not stay to the lease's TTL
    // because the provisional start never comes up).
    {
        Rig r;
        r.owner.setOptions({});
        r.client.releaseRetryBudgetMs = 900;
        runningSession(r);
        r.edge.dropDeletes = true;
        r.client.holdReleasesForStop();
        r.apply(r.owner.disconnect(r.now()));
        r.client.tunnelStopped();
        QElapsedTimer t;
        t.start();
        while (r.owner.unsentCount() == 0 && t.elapsed() < 6000)
            pump(10);
        CHECK(r.owner.unsentCount() == 1);
        r.edge.dropDeletes = false; // the direct API answers again
        const int deletesBefore = r.edge.deletes.size();
        SubscriptionNode b = stubOf(QStringLiteral("bbbbbbbbbbbbbbb0"));
        b.upstream->configSha256 = LeaseEdge::cfgSha();
        StandbyCandidate sc;
        sc.config = QByteArrayLiteral("{\"inbounds\":[]}");
        sc.configSha256 = LeaseEdge::cfgSha();
        sc.tunnelApiBase = r.edge2.base();
        sc.packRevision = 5;
        r.apply(r.owner.begin(b, 1, sc, r.now(), 1));
        t.start();
        while (!r.owner.provisionalPending() && t.elapsed() < 4000)
            pump(10);
        CHECK(r.owner.provisionalPending() && r.edge.posts.size() == 2);
        CHECK(r.owner.unsentCount() == 1 && r.edge.deletes.size() == deletesBefore); // nothing proved the route yet
        r.edge.refuse(1); // HTTP 409 after the hedge: the API answered
        t.start();
        while (r.owner.unsentCount() > 0 && t.elapsed() < 3000)
            pump(10);
        CHECK(r.owner.unsentCount() == 0 && r.edge.deletes.size() > deletesBefore); // the kept release went out, direct
        CHECK(r.edge2.deletes.isEmpty());
    }
    // Round 11 R3, the route half: an answer is the API's only if it carries the API's mark. The kept release of A must NOT be sent
    // when B's direct acquire gets an HTTP 403 from a blocking proxy (no mark): that is no proof the API is reachable by this route.
    {
        Rig r;
        r.owner.setOptions({});
        r.client.releaseRetryBudgetMs = 900;
        runningSession(r);
        r.edge.dropDeletes = true;
        r.client.holdReleasesForStop();
        r.apply(r.owner.disconnect(r.now()));
        r.client.tunnelStopped();
        QElapsedTimer t;
        t.start();
        while (r.owner.unsentCount() == 0 && t.elapsed() < 6000)
            pump(10);
        CHECK(r.owner.unsentCount() == 1);
        r.edge.dropDeletes = false;
        const int deletesBefore = r.edge.deletes.size();
        SubscriptionNode b = stubOf(QStringLiteral("bbbbbbbbbbbbbbb0"));
        b.upstream->configSha256 = LeaseEdge::cfgSha();
        StandbyCandidate sc;
        sc.config = QByteArrayLiteral("{\"inbounds\":[]}");
        sc.configSha256 = LeaseEdge::cfgSha();
        sc.tunnelApiBase = r.edge2.base();
        sc.packRevision = 5;
        r.apply(r.owner.begin(b, 1, sc, r.now(), 1));
        t.start();
        while (!r.owner.provisionalPending() && t.elapsed() < 4000)
            pump(10);
        CHECK(r.owner.provisionalPending() && r.edge.posts.size() == 2);
        r.edge.foreignAnswers = true;
        r.edge.answer(1, "403 X", "<html>blocked</html>", {}); // a proxy's page: HTTP 403, no mark
        pump(800);
        CHECK(r.owner.unsentCount() == 1 && r.edge.deletes.size() == deletesBefore); // nothing proved the route: nothing was sent
    }
    // ... the release half: a foreign answer to a DELETE is not an answer of the API. It is a transport-class failure: resent on the
    // shared spacing, then KEPT (unsent) for the next route that works - never taken as final and forgotten.
    {
        Rig r;
        r.owner.setOptions({});
        r.client.releaseRetryBudgetMs = 2500;
        runningSession(r);
        r.edge.foreignDeletes = true; // HTTP 403 of a blocking proxy to every DELETE
        r.client.holdReleasesForStop();
        r.apply(r.owner.disconnect(r.now()));
        r.client.tunnelStopped();
        QElapsedTimer t;
        t.start();
        while (r.owner.unsentCount() == 0 && t.elapsed() < 6000)
            pump(10);
        CHECK(r.owner.unsentCount() == 1 && r.owner.pendingReleases() == 1); // kept, not removed
        CHECK(r.edge.deletes.size() == 3);                                   // resent by the existing rule
        // the API itself answers (the mark): the very same release finishes at once
        r.edge.foreignDeletes = false;
        r.begin();
        t.start();
        while (r.edge.posts.size() < 2 && t.elapsed() < 2000)
            pump(10);
        r.edge.leaseId = QStringLiteral("LeaseNewStartBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"); // the new start's own lease
        const int deletesBefore = r.edge.deletes.size();
        r.edge.grant(1); // an answer of the API proves the direct route: the kept release goes out and is answered 204 + mark
        t.start();
        while (r.owner.pendingReleases() > 0 && t.elapsed() < 3000)
            pump(10);
        CHECK(r.owner.unsentCount() == 0 && r.owner.pendingReleases() == 0 && r.edge.deletes.size() == deletesBefore + 1
              && r.edge.deletes.last() == QLatin1String(kLease));
    }
    // Row S4 (device round 10): a profile WITH a standby-pack entry waits only the hedge for the direct lease, not the
    // lease share (here 5 s); the tunnel starts from the pack, the direct request lives on, and its grant that lands after
    // the provisional start is the SESSION's own seat (round 10: same start, same nonce, same token) - kept, not released; the
    // confirmation through the tunnel goes at once and confirms it.
    // A profile WITHOUT a pack entry keeps the full wait.
    {
        Rig r;
        TuningStore::set({{QStringLiteral("attempt_provider_lease_ms"), 5000}}, {{QStringLiteral("upstream_nodes"), true}}, {}, {});
        r.owner.setOptions({});
        StandbyCandidate sc;
        sc.config = QByteArrayLiteral("{\"inbounds\":[]}");
        sc.configSha256 = LeaseEdge::cfgSha();
        sc.tunnelApiBase = r.edge.base();
        sc.packRevision = 5;
        r.begin(sc);
        QElapsedTimer t;
        t.start();
        while (!r.owner.provisionalPending() && t.elapsed() < 4000)
            pump(10);
        CHECK(r.owner.provisionalPending() && t.elapsed() < 2500); // the hedge (1.2 s), not 5 s
        r.edge.grant(0); // the direct grant lands after the provisional start
        pump(300);
        CHECK(r.edge.deletes.isEmpty() && r.owner.pendingReleases() == 1); // the session's own: kept, not released (round 10)
        r.client.tunnelStarted();
        r.apply(r.owner.tunnelUp(r.now()));
        pump(300);
        CHECK(r.edge.posts.size() == 2); // the confirmation goes at once
        r.edge.grant(1);
        pump(300);
        CHECK(r.edge.deletes.isEmpty() && r.owner.pendingReleases() == 0 && r.owner.holdsLease(QLatin1String(kLease))); // confirmed
    }
    {
        Rig r;
        TuningStore::set({{QStringLiteral("attempt_provider_lease_ms"), 5000}}, {{QStringLiteral("upstream_nodes"), true}}, {}, {});
        r.owner.setOptions({});
        r.begin(); // no pack entry: nothing to start from, so the full wait
        pump(2500);
        CHECK(r.owner.active() && !r.owner.provisionalPending());
    }
    // Round 9 R2: the hedge belongs to ONE request kind - the direct acquire that precedes a provisional start. The seat
    // CONFIRMATION through the tunnel (a standby acquire on the pack's tunnel base) keeps the full bound: here the tunnel's
    // API answers in 1.35 s, slower than the hedge (1.2 s) and inside the bound (1.5 s). Before: every such confirmation
    // ended as a transport failure at the hedge, its late success went to lateGrant (released: the provisional session got
    // no seat) and the retries ended with the disconnect of a working tunnel.
    const auto confirmationRig = [&](Rig &r) {
        TuningStore::set({{QStringLiteral("attempt_provider_lease_ms"), 1500}}, {{QStringLiteral("upstream_nodes"), true}}, {}, {});
        r.owner.setOptions({});
        r.edge.token = QStringLiteral("tlr1.conf");
        StandbyCandidate sc;
        sc.config = QByteArrayLiteral("{\"inbounds\":[]}");
        sc.configSha256 = LeaseEdge::cfgSha();
        sc.tunnelApiBase = r.edge.base();
        sc.packRevision = 5;
        r.begin(sc); // the direct acquire is never answered: the hedge starts the pack tunnel
        QElapsedTimer t;
        t.start();
        while (!r.owner.provisionalPending() && t.elapsed() < 4000)
            pump(10);
        CHECK(r.owner.provisionalPending());
        r.client.tunnelStarted();
        r.apply(r.owner.tunnelUp(r.now())); // Connected: the seat is confirmed through the tunnel
        t.start();
        while (r.edge.posts.size() < 2 && t.elapsed() < 2000)
            pump(10);
        CHECK(r.edge.posts.size() == 2);
    };
    {
        Rig r;
        confirmationRig(r);
        pump(1350); // slower than the hedge, inside the full bound
        r.edge.grant(1);
        pump(400);
        CHECK(r.edge.deletes.isEmpty());                                                  // not released as a late grant
        CHECK(r.owner.holdsLease(QLatin1String(kLease)) && !r.owner.provisionalPending()); // the seat is confirmed
    }
    {
        Rig r; // what a SUCCESSFUL confirmation does when it is slower than even the full bound
        confirmationRig(r);
        pump(1900);
        r.edge.grant(1);
        pump(400);
        // It is a late grant and does NOT confirm the provisional session (which holds no lease to take it over). It is the
        // session's OWN start's (round 10: the nonce is the session's), so it stays the session's seat: kept, not released -
        // not when the direct acquire ends either - until the session confirms or ends; ended unconfirmed, it is released
        // with the confirmation's own token.
        CHECK(r.edge.deletes.isEmpty() && !r.owner.holdsLease(QLatin1String(kLease)));
        r.edge.refuse(0);
        pump(500);
        CHECK(r.edge.deletes.isEmpty() && r.owner.pendingReleases() == 1);
        r.apply(r.owner.disconnect(r.now()));
        pump(500);
        CHECK(r.edge.deletes.size() == 1 && r.edge.deleteTokens == QStringList{ QStringLiteral("tlr1.conf") });
    }
    // Row G1: the direct acquire exceeds its wait, the tunnel starts from the STANDBY pack (provisional); the original
    // request then returns L late: it is the session's OWN start (same nonce, hence the very token the confirmation will get),
    // so it is kept and NOT released (round 10; before, the DELETE carried a token the confirmation's re-acquire rotated).
    // Connected -> tunnelUp() confirms the seat at once. If the session ends before it confirmed, the kept grant is released
    // with its own token.
    {
        Rig r;
        r.owner.setOptions({});
        StandbyCandidate sc;
        sc.config = QByteArrayLiteral("{\"inbounds\":[]}");
        sc.configSha256 = LeaseEdge::cfgSha();
        sc.tunnelApiBase = r.edge.base();
        sc.packRevision = 5;
        r.begin(sc);
        QElapsedTimer t;
        t.start();
        while (r.edge.posts.size() < 1 && t.elapsed() < 2000)
            pump(10);
        t.start();
        while (!r.owner.provisionalPending() && t.elapsed() < 6000) // the wait ends: the standby start
            pump(10);
        CHECK(r.owner.active() && r.owner.provisionalPending() && r.edge.posts.size() == 1);
        r.edge.grant(0);
        pump(300);
        CHECK(r.edge.deletes.isEmpty() && r.owner.pendingReleases() == 1); // the session's own seat: kept
        r.client.tunnelStarted();
        r.apply(r.owner.tunnelUp(r.now())); // Connected: the standby confirmation asks the server for the seat
        pump(300);
        CHECK(r.edge.posts.size() == 2); // the confirmation goes at once
        r.edge.grant(1);
        pump(300);
        CHECK(r.edge.deletes.isEmpty() && r.owner.pendingReleases() == 0 && r.owner.holdsLease(QLatin1String(kLease)));
    }
    {
        Rig r; // the same, but the session ends before it confirmed: the kept grant goes back with its own token
        r.owner.setOptions({});
        r.edge.token = QStringLiteral("tlr1.own");
        StandbyCandidate sc;
        sc.config = QByteArrayLiteral("{\"inbounds\":[]}");
        sc.configSha256 = LeaseEdge::cfgSha();
        sc.tunnelApiBase = r.edge.base();
        sc.packRevision = 5;
        r.begin(sc);
        QElapsedTimer t;
        t.start();
        while (!r.owner.provisionalPending() && t.elapsed() < 6000)
            pump(10);
        r.edge.grant(0);
        pump(300);
        CHECK(r.edge.deletes.isEmpty() && r.owner.pendingReleases() == 1);
        r.apply(r.owner.disconnect(r.now()));
        pump(400);
        CHECK(r.edge.deletes.size() == 1 && r.edge.deleteTokens == QStringList{ QStringLiteral("tlr1.own") } && r.owner.pendingReleases() == 0);
    }
    // Round 11 R2: Stop while a seat confirmation retry is still late. The session (macOS GUI owner: it reports itself) confirmed its
    // seat with the retry C2; the first confirmation C1 is still unanswered; Stop holds the release that carries the FINAL meter
    // report until the tunnel is confirmed down. C1's answer (the same start: the same lease and token) lands while the release is
    // held. It must not replace that release with one that has no report: the DELETE that reaches the server is ONE and carries
    // the report (rx 4096). Before, the late answer re-registered the lease, the held release was dropped as "not wanted any more"
    // and the DELETE that went out had no body but the token - the session's accounting was lost.
    {
        Rig r;
        TuningStore::set({{QStringLiteral("attempt_provider_lease_ms"), 1500}}, {{QStringLiteral("upstream_nodes"), true}}, {}, {});
        UpstreamLeaseOwner::Options op;
        op.keepOwnership = true;
        r.owner.setOptions(op);
        r.edge.token = QStringLiteral("tlr1.report");
        StandbyCandidate sc;
        sc.config = QByteArrayLiteral("{\"inbounds\":[]}");
        sc.configSha256 = LeaseEdge::cfgSha();
        sc.tunnelApiBase = r.edge.base();
        sc.packRevision = 5;
        r.begin(sc); // the direct acquire is never answered: the hedge starts the pack tunnel
        QElapsedTimer t;
        t.start();
        while (!r.owner.provisionalPending() && t.elapsed() < 4000)
            pump(10);
        CHECK(r.owner.provisionalPending());
        r.client.tunnelStarted();
        r.apply(r.owner.tunnelUp(r.now())); // Connected: the confirmation C1 (post 1) goes through the tunnel's API base
        t.start();
        while (r.edge.posts.size() < 2 && t.elapsed() < 2000)
            pump(10);
        CHECK(r.edge.posts.size() == 2);
        t.start();
        while (r.edge.posts.size() < 3 && t.elapsed() < 15000) { // C1 times out; the retry C2 (post 2) is sent by the owner's tick
            pump(50);
            r.apply(r.owner.tick(r.now() + 8000));
        }
        CHECK(r.edge.posts.size() == 3);
        r.edge.grant(2); // C2: the seat is confirmed
        pump(300);
        CHECK(r.owner.holdsLease(QLatin1String(kLease)) && !r.owner.provisionalPending());
        r.owner.onBytes(0, 0);
        r.owner.onBytes(4096, 512); // what the session carried
        r.client.holdReleasesForStop();
        r.apply(r.owner.disconnect(r.now())); // Stop: the release with the final report is held for the confirmed stop
        CHECK(r.edge.deletes.isEmpty());
        r.edge.grant(1); // C1's answer (the same lease, the same token) lands while the release is held
        pump(300);
        CHECK(r.edge.deletes.isEmpty() && r.owner.pendingReleases() == 1);
        r.client.tunnelStopped(); // the confirmed stop
        pump(500);
        CHECK(r.edge.deletes == QStringList{ QLatin1String(kLease) } && r.edge.deleteTokens == QStringList{ QStringLiteral("tlr1.report") });
        const QJsonObject body = r.edge.deleteBodies.value(0);
        CHECK(body.value(QLatin1String("seq")).toInt() >= 1 && body.value(QLatin1String("rx_bytes_delta")).toInt() == 4096
              && body.value(QLatin1String("tx_bytes_delta")).toInt() == 512); // the final report travelled with the one DELETE
    }
    // Round 9 R1: the release of a session carries the token of ITS grant on the wire (and a lease whose grant had no token,
    // an older server, is released without the field).
    for (const bool withToken : {true, false}) {
        Rig r;
        r.edge.token = withToken ? QStringLiteral("tlr1.sessiontok") : QString();
        r.owner.setOptions({});
        runningSession(r);
        r.disconnectedByTheSystem();
        pump(400);
        CHECK(r.edge.deletes.size() == 1 && r.edge.deleteTokens == QStringList{ r.edge.token });
    }
    // Contract 1.19.0 (round 9 R6, rewritten): the old session's release cannot reach the API and waits for its resends; a new start
    // of the profile does not take it back. Its own direct acquire is slow (the hedge starts the pack tunnel) and gets ANOTHER lease
    // with another token - that late grant is the new start's own seat: kept, and the old chain runs on with the old lease and token.
    // The new session ends unconfirmed: ONE DELETE for the new lease with the new token.
    {
        Rig r;
        r.edge.token = QStringLiteral("tlr1.old");
        TuningStore::set({{QStringLiteral("attempt_provider_lease_ms"), 5000}}, {{QStringLiteral("upstream_nodes"), true}}, {}, {});
        r.owner.setOptions({});
        runningSession(r);
        r.edge.dropDeletes = true; // the old session's release cannot reach the API: it waits for its resend
        r.client.holdReleasesForStop();
        r.apply(r.owner.disconnect(r.now()));
        r.client.tunnelStopped();
        pump(450);
        const int triesBefore = r.edge.deletes.size();
        CHECK(triesBefore >= 1);
        r.edge.token = QStringLiteral("tlr1.new");
        r.edge.leaseId = QStringLiteral("LeaseNewStartBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
        StandbyCandidate sc;
        sc.config = QByteArrayLiteral("{\"inbounds\":[]}");
        sc.configSha256 = LeaseEdge::cfgSha();
        sc.tunnelApiBase = r.edge.base();
        sc.packRevision = 5;
        r.begin(sc); // the direct acquire is slow: the hedge starts the pack tunnel
        QElapsedTimer t;
        t.start();
        while (!r.owner.provisionalPending() && t.elapsed() < 4000)
            pump(10);
        CHECK(r.owner.provisionalPending());
        r.edge.dropDeletes = false;
        r.edge.grant(1); // the new start's own lease, late
        pump(3500);      // longer than every resend spacing of the old chain
        int oldTries = 0, newTries = 0;
        for (int i = 0; i < r.edge.deletes.size(); ++i) {
            oldTries += r.edge.deletes[i] == QLatin1String(kLease) ? 1 : 0;
            newTries += r.edge.deletes[i] == r.edge.leaseId ? 1 : 0;
            CHECK((r.edge.deletes[i] == QLatin1String(kLease)) == (r.edge.deleteTokens[i] == QLatin1String("tlr1.old"))); // a lease never changes its token
        }
        CHECK(oldTries > triesBefore && newTries == 0); // the old chain was not taken back; the new lease is the session's, kept
        r.apply(r.owner.disconnect(r.now())); // the session ends unconfirmed: ONE DELETE chain, the new lease and token
        pump(500);
        newTries = 0;
        for (int i = 0; i < r.edge.deletes.size(); ++i)
            newTries += (r.edge.deletes[i] == r.edge.leaseId && r.edge.deleteTokens[i] == QLatin1String("tlr1.new")) ? 1 : 0;
        CHECK(newTries == 1);
    }
    // Row G2: granted, the native start was asked for, a Disconnected comes before any Connected (the iOS extension
    // failed applying network settings / starting Xray and has no release handler): the app releases at once.
    {
        Rig r;
        r.owner.setOptions({});
        r.begin();
        pump(200);
        r.edge.grant(0);
        pump(300);
        CHECK(r.owner.active() && !r.edge.posts.isEmpty() && r.edge.deletes.isEmpty());
        r.disconnectedByTheSystem(); // Disconnected, tunnel never reported up
        pump(500);
        CHECK(r.edge.deletes == QStringList{ QLatin1String(kLease) } && !r.owner.active());
    }
    TuningStore::set({}, {}, {}, {});
}

// Round 9 R3: ANY answer of the API on a route proves that route - a grant, a refusal, an HTTP error status - and the releases
// that could not be carried go out by it; only a transport failure proves nothing. Before, only a grant of a DIRECT acquire
// flushed: after Stop of profile A (its DELETE could not reach the API, kept unsent) the acquire of profile B answered
// "no_seat" - the route works, the seat of A stayed taken until its lease expired.
static void unsentFlushOnAnyAnswer()
{
    const SubscriptionNode a = stubOf(QStringLiteral("aaaaaaaaaaaaaaa0")), b = stubOf(QStringLiteral("bbbbbbbbbbbbbbb0"));
    const char *kA = "LeaseAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const qint64 T = 12000000;
    struct Case { const char *name; AcquireReply reply; bool flushes; };
    const auto marked = [](AcquireReply r) { r.fromTribeApi = true; return r; }; // the answer carried X-Tribe-Api: 1
    const Case cases[] = {
        {"granted", marked(grantedAs(b, "LeaseBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")), true},
        {"no_seat", marked(refused(UpstreamErrorCode::NoSeat)), true},
        {"not_entitled", marked(refused(UpstreamErrorCode::NotEntitled)), true},
        {"http_503", marked(failed("http_503")), true},     // the API's own 503 (it carries the mark)
        {"foreign_403", failed("http_403"), false},         // a blocking proxy's page: no mark, no proof (round 11 R3)
        {"signature", failed("signature"), false},          // not our server's answer
        {"transport", failed("transport"), false},
    };
    for (const Case &c : cases) {
        for (const bool viaTunnel : {false, true}) {
            FakeIo io;
            UpstreamLeaseOwner o(&io);
            o.begin(a, 1, std::nullopt, T, 1);
            o.onAcquireReply(io.calls.last().id, grantedAs(a, kA), T + 100);
            o.disconnect(T + 200); // the release of A: its DELETE never reaches the API
            const quint64 relId = io.last("release")->id;
            o.onReleaseDone(relId, T + 300, /*confirmed=*/false);
            CHECK(o.unsentCount() == 1);
            const auto releases = [&io]() {
                int n = 0;
                for (const FakeIo::Call &call : io.calls)
                    n += call.what == QLatin1String("release") ? 1 : 0;
                return n;
            };
            const int before = releases();
            std::optional<StandbyCandidate> sc;
            if (viaTunnel) {
                StandbyCandidate s;
                s.config = QByteArrayLiteral("{\"pack\":1}");
                s.configSha256 = b.upstream->configSha256;
                s.tunnelApiBase = QStringLiteral("https://pack.example.net");
                s.packRevision = 5;
                sc = s;
            }
            o.begin(b, 1, sc, T + 400, 1);
            quint64 id = io.last("acquire")->id;
            if (viaTunnel) {
                // the direct acquire fails by transport: the provisional start; the confirmation goes through the tunnel
                o.onAcquireReply(id, failed("transport"), T + 500);
                CHECK(o.provisionalPending() && o.unsentCount() == 1); // transport proved nothing
                o.tunnelUp(T + 600);
                CHECK(o.unsentCount() == 1 && releases() == before); // the confirmation is in flight: the release waits for it
                id = io.last("acquire")->id;
            }
            o.onAcquireReply(id, c.reply, T + 700);
            if (upstreamRouteProved(c.reply))
                o.routeProved(id, T + 700); // UpstreamLeaseClient: any HTTP answer proves its route (round 10 R4: one place)
            const bool flushed = releases() == before + 1;
            CHECK(flushed == c.flushes);
            if (flushed) {
                const FakeIo::Call *rel = io.last("release");
                CHECK(rel && rel->profileOrLease == QLatin1String(kA) && o.unsentCount() == 0);
                CHECK(viaTunnel ? !rel->route.apiBase.isEmpty() : rel->route.apiBase.isEmpty()); // the route that answered
            } else {
                CHECK(o.unsentCount() == 1);
            }
        }
    }
}

// --- round 10 R2 + R3 (contract 1.18.0): one session nonce per START ----------------------------------------------
// One start sends several acquires for the same lease (the direct request that outlives the hedge, the seat confirmation
// through the tunnel, a retry); the server derives the renew token from (lease, device, nonce), so the requests of one start
// get ONE token whatever order the server processes them in. The nonce is a fact of the start: made where the start is made,
// carried by its requests, fresh for every start; a request that a new start takes over keeps the nonce it was sent with.
static bool nonceShape(const QString &n)
{
    static const QRegularExpression re(QStringLiteral("^[A-Za-z0-9_-]{32}$"));
    return re.match(n).hasMatch();
}
static StandbyCandidate packFor(const SubscriptionNode &n)
{
    StandbyCandidate sc;
    sc.config = QByteArrayLiteral("{\"pack\":1}");
    sc.configSha256 = n.upstream->configSha256;
    sc.tunnelApiBase = QStringLiteral("https://pack.example.net");
    sc.packRevision = 5;
    return sc;
}
static void sessionNonceCheck()
{
    const SubscriptionNode a = stubOf(QStringLiteral("aaaaaaaaaaaaaaa0"));
    const qint64 T = 13000000;
    const char *kA = "LeaseAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    // the wire: the field is named in one place and absent without a nonce
    {
        const QJsonObject with = QJsonDocument::fromJson(upstreamAcquireBody(QStringLiteral("p1"), LeaseKind::Session, QString(), QStringLiteral("N"))).object();
        CHECK(with.value(QLatin1String(kUpstreamAcquireNonceField)).toString() == QLatin1String("N"));
        CHECK(!QJsonDocument::fromJson(upstreamAcquireBody(QStringLiteral("p1"), LeaseKind::Session)).object().contains(QLatin1String(kUpstreamAcquireNonceField)));
        QSet<QString> seen;
        for (int i = 0; i < 50; ++i) {
            const QString n = upstreamNewSessionNonce();
            CHECK(nonceShape(n));
            seen.insert(n);
        }
        CHECK(seen.size() == 50); // a cryptographic source, not a constant or a counter
    }
    // every acquire of one start carries its nonce: the direct request, the confirmation through the tunnel; the next start another
    {
        FakeIo io;
        UpstreamLeaseOwner o(&io);
        o.begin(a, 1, packFor(a), T, 1);
        const FakeIo::Call direct = *io.last("acquire");
        CHECK(nonceShape(direct.nonce) && direct.sha.isEmpty());
        o.onAcquireReply(direct.id, failed("transport"), T + 1200); // the hedge: the provisional start
        CHECK(o.provisionalPending());
        o.tunnelUp(T + 1500);
        const FakeIo::Call confirm = *io.last("acquire");
        CHECK(confirm.id != direct.id && !confirm.sha.isEmpty());
        CHECK(confirm.nonce == direct.nonce); // the SAME start
        o.onAcquireReply(confirm.id, grantedAs(a, kA), T + 1700);
        o.disconnect(T + 2000);
        o.begin(a, 1, packFor(a), T + 3000, 1);
        const QString second = io.last("acquire")->nonce;
        CHECK(nonceShape(second) && second != direct.nonce); // a new start, a new nonce
        o.disconnect(T + 3100);
        o.onAcquireReply(io.last("acquire")->id, failed("transport"), T + 3150); // the cancelled request ends: nothing to take over
        o.prepare(a, 1, T + 3200, 1);
        CHECK(nonceShape(io.last("acquire")->nonce) && io.last("acquire")->nonce != second); // prepare is a start too
    }
    // a new start NEVER adopts the cancelled request of an older start (same profile, answer still pending): it has its own nonce and
    // its own order and sends its own request at once; the older request is left to finish
    {
        FakeIo io;
        UpstreamLeaseOwner o(&io);
        o.begin(a, 1, packFor(a), T, 1);
        const FakeIo::Call direct = *io.last("acquire");
        o.disconnect(T + 100); // cancelled: the request stays out
        const int sent = io.calls.size();
        o.begin(a, 1, packFor(a), T + 200, 1);
        CHECK(io.calls.size() == sent + 1 && io.last("acquire")->id != direct.id);
        CHECK(o.sessionNonce() != direct.nonce && io.last("acquire")->nonce == o.sessionNonce() && io.last("acquire")->order > direct.order);
        // the older start's request answers with a lease: released with its own token (no-op on the server, its lease was replaced)
        const QVector<UpstreamOwnerEvent> ev = o.onAcquireReply(direct.id, grantedAs(a, kA), T + 300);
        CHECK(ev.isEmpty() && io.last("release") && io.last("release")->profileOrLease == QLatin1String(kA)
              && io.last("release")->route.renewToken == QLatin1String("tlr1.secret"));
        CHECK(!o.holdsLease(QLatin1String(kA)));
    }
    // ... and the denial of a stale nonce for that older request: nothing to release, nothing to tell
    {
        FakeIo io;
        UpstreamLeaseOwner o(&io);
        o.begin(a, 1, packFor(a), T, 1);
        const FakeIo::Call direct = *io.last("acquire");
        o.disconnect(T + 100);
        o.begin(a, 1, packFor(a), T + 200, 1);
        const int calls = io.calls.size();
        AcquireReply stale = refused(UpstreamErrorCode::LeaseGone);
        stale.error.reason = QStringLiteral("stale_session");
        CHECK(o.onAcquireReply(direct.id, stale, T + 300).isEmpty() && io.calls.size() == calls && o.active());
        // the wire shape: HTTP 404 {"code":"lease_gone","reason":"stale_session"} classifies as that refusal
        const AcquireReply w = classifyAcquireReply(404, QByteArrayLiteral("{\"code\":\"lease_gone\",\"reason\":\"stale_session\"}"), {}, QString(), true);
        CHECK(w.kind == LeaseReplyKind::Refused && w.error.code == UpstreamErrorCode::LeaseGone && w.error.reason == QLatin1String("stale_session")
              && isTerminalUpstreamError(w.error.code) && w.error.retryAfterS < 0);
    }
    // the CURRENT start never gets that denial (its nonce and order are its own); if it did, it is a refusal of the leg like
    // lease_gone: the start fails with that code (the engine tries the next candidate) - never a retry loop
    {
        FakeIo io;
        UpstreamLeaseOwner o(&io);
        o.begin(a, 1, std::nullopt, T, 1);
        AcquireReply stale = refused(UpstreamErrorCode::LeaseGone);
        stale.error.reason = QStringLiteral("stale_session");
        const QVector<UpstreamOwnerEvent> ev = o.onAcquireReply(io.last("acquire")->id, stale, T + 100);
        const UpstreamOwnerEvent *f = findEv(ev, UpstreamOwnerEventKind::StartFailed);
        CHECK(f && f->code == QLatin1String("lease_gone") && f->detail == QLatin1String("stale_session") && !o.active());
        CHECK(!io.last("release"));
    }
    // a late grant for a lease whose release is already pending MERGES into that release (one entry per lease id, the token of a
    // lease never changes): no second chain, and the start's final report stays where it is (round 11 R2, at the owner level)
    {
        FakeIo io;
        UpstreamLeaseOwner o(&io);
        o.begin(a, 1, packFor(a), T, 1);
        const quint64 idA = io.last("acquire")->id;
        o.onAcquireReply(idA, failed("transport"), T + 1200);
        o.tunnelUp(T + 1500);
        const quint64 idB = io.last("acquire")->id;
        o.onAcquireReply(idB, grantedAs(a, kA), T + 1700);
        o.disconnect(T + 2000);
        CHECK(o.pendingReleases() == 1);
        const int calls = io.calls.size();
        o.lateGrant(a.upstream->profileId, QLatin1String(kA), LeaseRoute{QStringLiteral("tlr1.secret"), QString()}, false, idA);
        CHECK(o.pendingReleases() == 1 && io.calls.size() == calls); // the same start's late answer: merged, nothing sent
    }
    // a stray late grant of an OLDER start for a lease nobody holds is released with its own token
    {
        FakeIo io;
        UpstreamLeaseOwner o(&io);
        o.begin(a, 1, packFor(a), T, 1);
        const quint64 idOld = io.last("acquire")->id;
        o.onAcquireReply(idOld, failed("transport"), T + 1200); // the direct request of start 1 lives on
        o.disconnect(T + 1300);
        o.begin(a, 1, std::nullopt, T + 1400, 1); // start 2
        o.disconnect(T + 1500);
        const int before = io.calls.size();
        o.lateGrant(a.upstream->profileId, QLatin1String(kA), LeaseRoute{QStringLiteral("tokOld"), QString()}, false, idOld);
        CHECK(io.calls.size() == before + 1 && io.last("release")->route.renewToken == QLatin1String("tokOld"));
        CHECK(o.pendingReleases() == 1);
    }
}

// Contract 1.20.0: the start's order - created with the nonce, the same on every acquire of the start, strictly increasing across
// starts (also across a relaunch and a clock that went backwards), persisted by the store the app wires, sent next to the nonce only.
static void sessionOrderCheck()
{
    const SubscriptionNode a = stubOf(QStringLiteral("aaaaaaaaaaaaaaa0"));
    const qint64 T = 15000000;
    // the wire: named in one place, with a nonce on a session only
    {
        const QJsonObject with = QJsonDocument::fromJson(upstreamAcquireBody(QStringLiteral("p1"), LeaseKind::Session, QString(), QStringLiteral("N"), 1700000000123LL)).object();
        CHECK(qint64(with.value(QLatin1String(kUpstreamAcquireOrderField)).toDouble()) == 1700000000123LL && with.contains(QLatin1String(kUpstreamAcquireNonceField)));
        CHECK(!QJsonDocument::fromJson(upstreamAcquireBody(QStringLiteral("p1"), LeaseKind::Session, QString(), QString(), 5)).object().contains(QLatin1String(kUpstreamAcquireOrderField)));
        CHECK(!QJsonDocument::fromJson(upstreamAcquireBody(QStringLiteral("p1"), LeaseKind::Probe, QString(), QStringLiteral("N"), 5)).object().contains(QLatin1String(kUpstreamAcquireOrderField)));
    }
    qint64 stored = 0; // the app's setting
    const auto wire = [&stored](UpstreamLeaseOwner &o) {
        o.setOrderStore([&stored]() { return stored; }, [&stored](qint64 v) { stored = v; });
    };
    FakeIo io;
    UpstreamLeaseOwner o(&io);
    wire(o);
    // one value per start: the direct request and the confirmation through the tunnel carry the same one
    o.begin(a, 1, packFor(a), T, 1700000000000LL);
    const FakeIo::Call direct = *io.last("acquire");
    CHECK(direct.order == 1700000000000LL && direct.order == o.sessionOrder() && stored == direct.order); // wall clock, persisted
    o.onAcquireReply(direct.id, failed("transport"), T + 1200);
    o.tunnelUp(T + 1500);
    CHECK(io.last("acquire")->id != direct.id && io.last("acquire")->order == direct.order && io.last("acquire")->nonce == direct.nonce);
    o.disconnect(T + 2000);
    // strictly increasing across starts: the same wall clock, then a clock that went BACKWARDS
    o.begin(a, 1, std::nullopt, T + 3000, 1700000000000LL);
    const qint64 second = io.last("acquire")->order;
    CHECK(second == direct.order + 1);
    o.disconnect(T + 3100);
    o.prepare(a, 1, T + 3200, 1600000000000LL);
    const qint64 third = io.last("acquire")->order;
    CHECK(third == second + 1 && stored == third);
    o.disconnect(T + 3300);
    // a relaunch: a new owner reads the persisted value - the next start is above everything sent before (the wall clock may be
    // anything, here a fresh counter's default)
    {
        FakeIo io2;
        UpstreamLeaseOwner o2(&io2);
        wire(o2);
        o2.begin(a, 1, std::nullopt, T + 4000, 1);
        CHECK(io2.last("acquire")->order == third + 1);
        // an owner whose last value is NOT persisted starts below it again - exactly what the store prevents
        FakeIo io3;
        UpstreamLeaseOwner o3(&io3);
        o3.begin(a, 1, std::nullopt, T + 4000, 1);
        CHECK(io3.last("acquire")->order < third);
    }
    // a late acquire of an older start carries a lower order than the newer start's: the model's server refuses it (ledgerModel)
    CHECK(direct.order < second && second < third);
}

// Contract 1.19.0: an OLDER start's late grant while the CURRENT session holds a lease. The two starts never share a lease id, so the
// older start's lease is not the session's: it is released with its own token and the session's seat is never touched; the same
// start's own duplicate answer (same lease) releases nothing.
static void lateOlderStart()
{
    const SubscriptionNode a = stubOf(QStringLiteral("aaaaaaaaaaaaaaa0"));
    const qint64 T = 14000000;
    const char *kA = "LeaseAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const char *kOld = "LeaseOldOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO";
    const auto releases = [](const FakeIo &io) {
        int n = 0;
        for (const FakeIo::Call &c : io.calls)
            n += c.what == QLatin1String("release") ? 1 : 0;
        return n;
    };
    for (const bool viaTunnel : {false, true}) {
        FakeIo io;
        UpstreamLeaseOwner o(&io);
        o.begin(a, 1, packFor(a), T, 1); // start 1: its direct request outlives the hedge
        const quint64 idOld = io.last("acquire")->id;
        o.onAcquireReply(idOld, failed("transport"), T + 1200);
        o.disconnect(T + 1300);
        o.begin(a, 1, packFor(a), T + 1400, 1); // start 2
        quint64 idNew = io.last("acquire")->id;
        AcquireReply g = grantedAs(a, kA);
        g.grant.renewToken = QStringLiteral("tokNew");
        if (viaTunnel) { // the session came up from the pack and confirmed through the tunnel
            o.onAcquireReply(idNew, failed("transport"), T + 2600);
            o.tunnelUp(T + 2700);
            idNew = io.last("acquire")->id;
        }
        o.onAcquireReply(idNew, g, T + 2800);
        CHECK(o.holdsLease(QLatin1String(kA)));
        const int calls = io.calls.size();
        // the same start's duplicate answer: nothing
        o.lateGrant(a.upstream->profileId, QLatin1String(kA), LeaseRoute{QStringLiteral("tokNew"), QString()}, false, idNew);
        CHECK(io.calls.size() == calls);
        // an older start's late answer names ANOTHER lease: released with its own token, the session keeps its seat and sends no acquire
        o.lateGrant(a.upstream->profileId, QLatin1String(kOld), LeaseRoute{QStringLiteral("tokOld"), QString()}, false, idOld);
        CHECK(io.calls.size() == calls + 1 && releases(io) == 1 && io.last("release")->profileOrLease == QLatin1String(kOld)
              && io.last("release")->route.renewToken == QLatin1String("tokOld") && io.last("acquire")->id == idNew);
        CHECK(o.holdsLease(QLatin1String(kA)));
        // the session's stop releases the seat with the token it holds
        const QVector<UpstreamOwnerEvent> endEv = o.disconnect(T + 4000);
        QString relToken = io.last("release")->profileOrLease == QLatin1String(kA) ? io.last("release")->route.renewToken : QString();
        for (const UpstreamOwnerEvent &e : endEv)
            if (e.kind == UpstreamOwnerEventKind::ReleaseAfterStop) // a tunnel that came up: the release goes after its confirmed stop
                relToken = e.route.renewToken;
        CHECK(relToken == QLatin1String("tokNew"));
    }
}

// --- the lease id ledger as a random model (rounds 2 and 3 each found a table cell nobody had walked) --------------
// The real UpstreamLeaseOwner against a model of the server (one device, one profile: an acquire of the profile it
// holds is answered with THAT lease, DELETE ends it) and a model of the client's I/O (UpstreamLeaseClient: the late
// answer path, the hold of releases for a stop, the release resend). Random sequences of: acquire asked (with and
// without a standby pack), server processes / answers / times out an acquire, a late grant, tunnel up, Disconnected
// (asked or not), a stop, a refused start, a tick (provisional re-acquire), a DELETE reaching the server / answered
// ok / 5xx / cut. Invariants: (1) a seat a live session holds is never revoked (no DELETE hits a lease the owner holds;
// the server's lease is the owner's), (2) no acquire of profile P is sent while a release of P is pending, (3) after
// everything is answered and the session stopped no lease is left live on the server, (4) nothing waits for ever
// (no start queued, no gated acquire, no release pending or held).
struct LedgerWorld {
    struct Acq { quint64 id; bool processed = false, delivered = false, timedOut = false, lateDone = false; QString lease, token, nonce; qint64 order = -1; bool grant = false, stale = false; };
    struct Rel { quint64 id; QString lease, token; int unprocessed = 0, unanswered = 0, tries = 0; bool done = false, held = false, report = false; };
    struct Io : IUpstreamLeaseIo {
        LedgerWorld *w = nullptr;
        void acquire(quint64 id, const QString &, LeaseKind, const QString &, const LeaseRoute &, const QString &nonce, qint64 order) override { w->onAcquireSent(id, nonce, order); }
        void renew(quint64, const QString &, const UpstreamMeter &, const LeaseRoute &) override {}
        void release(quint64 id, const QString &lease, const UpstreamMeter &meter, const LeaseRoute &route) override { w->clientRelease(id, lease, route.renewToken, meter.seq >= 1); }
        bool acquireAlive(const QString &) const override { return w->acquireOut(); }
    };
    Io io;
    UpstreamLeaseOwner o;
    SubscriptionNode node = stubOf();
    // The server (contract 1.19.0): ONE nonce names ONE tenure of a seat. The same nonce as the live lease: the same lease, the same
    // token. Another nonce: it takes the seat over - the old lease ENDS (replaced), a NEW lease id with a new token is made. A nonce
    // whose lease ended as released (its own DELETE) or replaced is STALE: its acquire is denied and changes nothing. A lease that
    // expired (TTL) leaves its nonce fresh. A renewal never rotates the token; a DELETE ends the lease only with its current token.
    QString live, liveToken, liveNonce;
    QSet<QString> staleNonces, reportOwed, reportTaken, endedPlain; // reportOwed: leases the owner issued a final report for; reportTaken: leases a DELETE ended carrying it
    QHash<QString, QString> leaseNonce;                 // lease id -> the nonce of the start it was made for (a lease id never has two)
    QSet<QString> releasedNonces;                       // nonces of the starts the client has issued a release for (their tenure is over)
    QHash<QString, qint64> orderOfNonce;
    qint64 highestOrderSent = 0, highestOrderSeen = 0;  // the client's own sequence / the server's: the highest order it has seen from the device
    int serial = 0, tokenSerial = 0, staleDenials = 0, expiries = 0;
    QList<Acq> acqs;
    QList<Rel> rels;
    bool stopPending = false, tunnelDown = true, nativeStarted = false, forceGrant = false, deadApi = false;
    qint64 now = 40000000;
    QStringList violations, trace;
    int deletesSent = 0;
    LedgerWorld() : o(&io) { io.w = this; node.upstream->configSha256 = sha64('d'); }

    QString profile() const { return node.upstream->profileId; }
    bool releasePending() const
    {
        for (const Rel &r : rels)
            if (!r.done)
                return true;
        return false;
    }
    void onAcquireSent(quint64 id, const QString &nonce, qint64 order)
    {
        // A start waits for nothing: no release, no older request. The client's own rules, checked on every acquire it sends:
        if (nonce.isEmpty() || order < 0)
            violations << QStringLiteral("an acquire went out without a nonce or an order");
        if (releasedNonces.contains(nonce))
            violations << QStringLiteral("the client acquired with a nonce for which it had already issued a release");
        const auto known = orderOfNonce.constFind(nonce);
        if (known != orderOfNonce.constEnd()) {
            if (known.value() != order)
                violations << QStringLiteral("two acquires of one start carry different orders");
        } else {
            if (order <= highestOrderSent)
                violations << QStringLiteral("the order of a new start is not above every earlier start's");
            orderOfNonce.insert(nonce, order);
            highestOrderSent = qMax(highestOrderSent, order);
        }
        Acq a;
        a.id = id;
        a.nonce = nonce;
        a.order = order;
        acqs << a;
    }
    // UpstreamLeaseClient::release / sendRelease
    void clientRelease(quint64 id, const QString &lease, const QString &token, bool report)
    {
        if (leaseNonce.contains(lease))
            releasedNonces.insert(leaseNonce.value(lease));
        if (report)
            reportOwed.insert(lease);
        rels << Rel{id, lease, token};
        rels.last().report = report;
        if (stopPending) {
            rels.last().held = true;
            return;
        }
        rels.last().unprocessed = 1;
        ++deletesSent;
    }
    void flushHeld()
    {
        if (!stopPending)
            return;
        stopPending = false;
        for (Rel &r : rels)
            if (r.held) {
                r.held = false;
                if (!wanted(r))
                    continue; // taken back while it waited for the stop
                r.unprocessed = 1;
                ++deletesSent;
            }
    }
    // UpstreamLeaseClient::releaseWanted: asked before a held release is sent and before every resend
    bool wanted(Rel &r)
    {
        QVector<UpstreamOwnerEvent> ev;
        const bool w = o.releaseWanted(r.id, now, ev);
        if (!w)
            r.done = true; // dropped silently: no answer to the owner
        apply(ev);
        return w;
    }
    void apply(const QVector<UpstreamOwnerEvent> &ev) // VpnConnectionTunnelControl::applyUpstreamEvents, in miniature
    {
        for (const UpstreamOwnerEvent &e : ev) {
            if (e.kind == UpstreamOwnerEventKind::BringUp) {
                nativeStarted = true;
                tunnelDown = false; // the native state went to Connecting
            } else if (e.kind == UpstreamOwnerEventKind::ReleaseAfterStop) {
                if (!tunnelDown)
                    stopPending = true; // holdReleasesForStopIfRunning
                clientRelease(e.requestId, e.leaseId, e.route.renewToken, false);
            }
        }
    }
    // every answer naming this lease has reached the client (a lease expires on the server's clock, minutes after its answers landed)
    bool answeredEverywhere(const QString &lease) const
    {
        for (const Acq &a : acqs)
            if (a.lease == lease && !(a.delivered || (a.timedOut && a.lateDone)))
                return false;
        return true;
    }
    bool acquireOut() const
    {
        for (const Acq &a : acqs)
            if (!a.delivered && !(a.timedOut && a.lateDone))
                return true;
        return false;
    }
    bool newerOut(int except) const
    {
        for (int i = 0; i < acqs.size(); ++i)
            if (i != except && !acqs[i].delivered && !(acqs[i].timedOut && acqs[i].lateDone))
                return true;
        return false;
    }
    AcquireReply replyOf(const Acq &a) const
    {
        if (a.stale) {
            AcquireReply r = refused(UpstreamErrorCode::LeaseGone); // HTTP 404 {"code":"lease_gone","reason":"stale_session"}
            r.error.reason = QStringLiteral("stale_session");
            return r;
        }
        if (!a.grant)
            return refused(UpstreamErrorCode::NoSeat);
        AcquireReply r = granted(profile(), node.upstream->configSha256);
        r.grant.leaseId = a.lease;
        r.grant.renewToken = a.token;
        return r;
    }
    // the events
    void begin(bool standby)
    {
        trace << QStringLiteral("%1").arg(QLatin1String("begin")) + (QLatin1String(""));
        std::optional<StandbyCandidate> sc;
        if (standby) {
            StandbyCandidate c;
            c.config = QByteArrayLiteral("{\"pack\":1}");
            c.configSha256 = sha64('d');
            c.tunnelApiBase = QStringLiteral("https://pack.example.net");
            c.packRevision = 5;
            sc = c;
        }
        apply(o.begin(node, 1, sc, now, 1));
    }
    QString serverToken(const QString &lease, const QString &nonce) { return QStringLiteral("tlr1.%1.%2").arg(lease, nonce); }
    void newLease(Acq &a)
    {
        live = QStringLiteral("LeaseLedger%1").arg(++serial, 28, 10, QLatin1Char('0'));
        liveNonce = a.nonce;
        leaseNonce.insert(live, a.nonce);
        a.lease = live;
        a.token = liveToken = serverToken(live, a.nonce);
        a.grant = true;
    }
    void acqProcess(int i)
    {
        trace << QStringLiteral("%1").arg(QLatin1String("acqProcess")) + (QLatin1String("") + QString::number(i));
        Acq &a = acqs[i];
        a.processed = true;
        // a start whose lease was released or replaced, or whose order is behind a newer start's the server has seen: a late acquire of
        // it takes nothing (contract 1.19.0 / 1.20.0); the highest order seen is kept even when no seat is given
        if (staleNonces.contains(a.nonce) || a.order < highestOrderSeen) {
            a.stale = true;
            ++staleDenials;
            return;
        }
        highestOrderSeen = a.order;
        if (!live.isEmpty() && liveNonce == a.nonce) { // the same start: the same lease, the same token, in any order
            a.grant = true;
            a.lease = live;
            a.token = liveToken;
            return;
        }
        if (!live.isEmpty()) { // another start takes the seat over: the old lease ends (replaced), a NEW one is made
            if (o.holdsLease(live))
                violations << QStringLiteral("another start took over the seat the live session holds");
            staleNonces.insert(liveNonce);
            live.clear();
            liveToken.clear();
            liveNonce.clear();
            newLease(a);
            return;
        }
        // no lease live: a seat is needed; sometimes none
        a.grant = forceGrant || ((acqs.size() * 7 + serial) % 5 != 4 && serial % 5 != 4);
        if (a.grant)
            newLease(a);
    }
    // Round 12 R1: an answer of an OLDER start (a cancelled start's request) changes no field of the current session.
    QString sessionFingerprint() const
    {
        return QStringLiteral("%1|%2|%3|%4|%5|%6|%7|%8|%9").arg(o.wakeAtMs()).arg(int(o.phase())).arg(o.leaseId()).arg(o.releaseSent())
            .arg(o.active()).arg(o.provisionalPending()).arg(o.sessionNonce()).arg(o.sessionOrder())
            .arg(QString::fromUtf8(QJsonDocument(o.statusJson(0)).toJson(QJsonDocument::Compact)))
            + QString::fromUtf8(QJsonDocument(o.leaseJson(0)).toJson(QJsonDocument::Compact));
    }
    bool olderStart(const Acq &a) const { return a.nonce != o.sessionNonce(); }
    void acqDeliver(int i)
    {
        trace << QStringLiteral("%1").arg(QLatin1String("acqDeliver")) + (QLatin1String("") + QString::number(i));
        Acq &a = acqs[i];
        a.delivered = true;
        if (a.stale && o.machine().acquireInFlight() == a.id)
            violations << QStringLiteral("a stale_session denial reached the start that waits for its answer (a nonce was reused)");
        const QString before = sessionFingerprint();
        const bool older = olderStart(a);
        apply(o.onAcquireReply(a.id, replyOf(a), now));
        if (older && sessionFingerprint() != before)
            violations << QStringLiteral("an answer of an older start changed a field of the current session");
        apply(o.acquireEnded(profile(), a.grant ? a.lease : QString(), newerOut(i)));
        o.routeProved(a.id, now); // UpstreamLeaseClient: an HTTP answer, whichever path it took
    }
    void acqTimeout(int i)
    {
        trace << QStringLiteral("%1").arg(QLatin1String("acqTimeout")) + (QLatin1String("") + QString::number(i));
        acqs[i].timedOut = true;
        const QString before = sessionFingerprint();
        const bool older = olderStart(acqs[i]);
        apply(o.onAcquireReply(acqs[i].id, failed("transport"), now));
        if (older && sessionFingerprint() != before)
            violations << QStringLiteral("the timeout of an older start changed a field of the current session");
    }
    void acqLate(int i)
    {
        trace << QStringLiteral("%1").arg(QLatin1String("acqLate")) + (QLatin1String("") + QString::number(i));
        Acq &a = acqs[i];
        a.lateDone = true;
        // UpstreamLeaseClient: a late grant is reported as such; any other late end as the end of the request
        if (a.grant)
            apply(o.lateGrant(profile(), a.lease, LeaseRoute{a.token, QString()}, newerOut(i), a.id));
        else
            apply(o.acquireEnded(profile(), QString(), newerOut(i)));
        o.routeProved(a.id, now); // the same single place, for the late path too (round 10 R4)
    }
    void relHit(int i)
    {
        trace << QStringLiteral("%1").arg(QLatin1String("relHit")) + (QLatin1String("") + QString::number(i));
        Rel &r = rels[i];
        --r.unprocessed;
        ++r.unanswered;
        // the server ends the lease ONLY for the token that is its current one; any other DELETE is a no-op (204 either way)
        if (live == r.lease && r.token == liveToken) {
            if (o.holdsLease(r.lease))
                violations << QStringLiteral("a DELETE ended the seat a live session holds");
            if (r.report)
                reportTaken.insert(r.lease);
            else
                endedPlain.insert(r.lease);
            staleNonces.insert(liveNonce);
            live.clear();
            liveToken.clear();
            liveNonce.clear();
        }
    }
    void relAnswer(int i, int outcome) // 0 ok, 1 5xx / cut (resent while tries last)
    {
        trace << QStringLiteral("%1").arg(QLatin1String("relAnswer")) + (QLatin1String("") + QString::number(i));
        Rel &r = rels[i];
        --r.unanswered;
        finishTry(r, outcome == 0);
    }
    void relCut(int i)
    {
        trace << QStringLiteral("%1").arg(QLatin1String("relCut")) + (QLatin1String("") + QString::number(i));
        Rel &r = rels[i];
        --r.unprocessed;
        finishTry(r, false);
    }
    void finishTry(Rel &r, bool ok)
    {
        if (!ok && r.tries + 1 < 3) {
            ++r.tries;
            if (!wanted(r))
                return; // taken back by a newer start of the profile
            ++r.unprocessed; // seatReleaseNext: sent again
            ++deletesSent;
            return;
        }
        ++r.tries;
        r.done = true;
        apply(o.onReleaseDone(r.id, now, ok));
    }
    void tunnelUp()
    {
        trace << QStringLiteral("%1").arg(QLatin1String("tunnelUp")) + (QLatin1String(""));
        tunnelDown = false;
        apply(o.tunnelUp(now));
    }
    void disconnected() // from the system or the answer to our stop: either way the same handling
    {
        trace << QStringLiteral("%1").arg(QLatin1String("disconnected")) + (QLatin1String(""));
        nativeStarted = false;
        tunnelDown = true;
        flushHeld();
        apply(o.tunnelLost(now));
        // a seat's lifetime starts at the grant: after the native tunnel is gone no session that was brought up may
        // stay active holding it (a start that failed before any Connected included)
        if (o.active() && !o.preparing() && o.machine().phase() == LeasePhase::Active)
            violations << QStringLiteral("a granted seat survived the Disconnected of its start");
    }
    void stop() // VpnConnectionTunnelControl::down()
    {
        trace << QStringLiteral("%1").arg(QLatin1String("stop")) + (QLatin1String(""));
        if (o.active() && !o.preparing()) {
            if (!tunnelDown)
                stopPending = true; // holdReleasesForStopIfRunning
            apply(o.disconnect(now));
        }
    }
    bool unsentSeen = false;
    void checkSeat(const char *where)
    {
        unsentSeen = unsentSeen || o.unsentCount() > 0;
        if (o.active() && !o.provisionalPending() && o.holdsLease(live) == false) {
            // a live session whose machine holds a lease must have it live on the server
        }
        for (const Acq &a : acqs)
            (void)a;
        // round 9 R1: a start waits only for an acquire it takes over, never for a release
        const QString held = o.machine().leaseId();
        if (!held.isEmpty() && o.holdsLease(held) && live != held)
            violations << QStringLiteral("the live session's seat is not live on the server (") + QLatin1String(where) + QLatin1Char(')');
        checkToken();
        // Round 12 R1: a session that holds a lease (or waits for its confirmation through a tunnel that is up) has a wake time, as long as
        // it owns the renewals; without one the lease expires under a running tunnel
        if (o.active() && o.ownsRenewals() && !o.machine().requestInFlight()
            && (o.phase() == LeasePhase::Active || o.machine().provisionalTunnelUp()))
            if (o.wakeAtMs() < 0)
                violations << QStringLiteral("a session that holds a lease or is provisional has no wake time scheduled (") + QLatin1String(where) + QLatin1Char(')');
    }
    // Contract 1.19.0: within ONE start every answer names the same lease and the same token (unless the lease expired in between,
    // then it is a new id); two different starts never share a lease id. So a lease the live session holds is the server's lease of
    // the session's own nonce, with the very token the session holds.
    void checkToken()
    {
        const QString held = o.machine().leaseId();
        if (held.isEmpty() || !o.holdsLease(held))
            return;
        const auto n = leaseNonce.constFind(held);
        if (n == leaseNonce.constEnd() || n.value() != o.sessionNonce())
            violations << QStringLiteral("the live session holds a lease that was made for another start");
        if (live == held && liveToken != o.machine().route().renewToken)
            violations << QStringLiteral("the token of the live session's lease is not the one the session holds");
    }
    // every sequence ends: everything answered, the tunnel confirmed down, the session stopped
    void drain()
    {
        bool unsentTried = false;
        for (int guard = 0; guard < 400; ++guard) {
            bool did = false;
            for (int i = 0; i < acqs.size() && !did; ++i) {
                Acq &a = acqs[i];
                if (!a.processed) { acqProcess(i); did = true; }
                else if (!a.delivered && !a.timedOut) { acqDeliver(i); did = true; }
                else if (a.timedOut && !a.lateDone) { acqLate(i); did = true; }
            }
            for (int i = 0; i < rels.size() && !did; ++i) {
                Rel &r = rels[i];
                if (r.done || r.held)
                    continue;
                if (r.unprocessed > 0) { relHit(i); did = true; }
                else if (r.unanswered > 0) { relAnswer(i, 0); did = true; }
            }
            if (did)
                continue;
            checkToken();
            if (nativeStarted) {
                disconnected(); // the confirmed stop frees what was held for it
                continue;
            }
            if (o.active()) {
                stop();
                if (nativeStarted)
                    disconnected(); // with no native tunnel there is no state change, so no Disconnected comes
                continue;
            }
            if (o.unsentCount() > 0 && !unsentTried) {
                // row S2: releases that never reached the server wait for a route that works - a later direct answer
                unsentTried = true;
                forceGrant = true;
                begin(false);
                continue;
            }
            break;
        }
    }
};

static void ledgerModel()
{
    int sequences = 0, steps = 0, failedSeqs = 0, deletes = 0, unsentSeqs = 0, staleDenials = 0, expiries = 0, reports = 0;
    QMap<QString, int> kinds;
    for (int seed = 1; seed <= 6000; ++seed) {
        quint32 rng = quint32(seed) * 2654435761u + 12345u;
        const auto rnd = [&rng](int n) { rng = rng * 1664525u + 1013904223u; return int((rng >> 8) % quint32(n)); };
        LedgerWorld w;
        w.deadApi = seed % 3 == 0;
        UpstreamLeaseOwner::Options op;
        op.keepOwnership = seed % 4 == 0; // the macOS GUI owner releases itself; elsewhere the tunnel owner does
        w.o.setOptions(op);
        for (int step = 0; step < 36; ++step, ++steps) {
            w.now += 150;
            switch (rnd(18)) {
            case 0: case 1: w.begin(rnd(2) == 0); break;
            case 2: case 3: { // the server processes an acquire - in ANY order (round 10: the client cannot know it)
                QList<int> c;
                for (int i = 0; i < w.acqs.size(); ++i)
                    if (!w.acqs[i].processed) c << i;
                if (!c.isEmpty()) w.acqProcess(c[rnd(c.size())]);
                break;
            }
            case 4: case 5: { // an answer reaches the client (in time)
                QList<int> c;
                for (int i = 0; i < w.acqs.size(); ++i)
                    if (w.acqs[i].processed && !w.acqs[i].delivered && !w.acqs[i].timedOut) c << i;
                if (!c.isEmpty()) w.acqDeliver(c[rnd(c.size())]);
                break;
            }
            case 6: { // the attempt stops waiting: a transport failure for the owner; the request lives on
                QList<int> c;
                for (int i = 0; i < w.acqs.size(); ++i)
                    if (!w.acqs[i].delivered && !w.acqs[i].timedOut) c << i;
                if (!c.isEmpty()) w.acqTimeout(c[rnd(c.size())]);
                break;
            }
            case 7: { // a timed-out request's answer lands (late)
                QList<int> c;
                for (int i = 0; i < w.acqs.size(); ++i)
                    if (w.acqs[i].timedOut && !w.acqs[i].lateDone && w.acqs[i].processed) c << i;
                if (!c.isEmpty()) w.acqLate(c[rnd(c.size())]);
                break;
            }
            case 8: if (w.nativeStarted && w.o.active()) w.tunnelUp(); break;
            case 9: if (w.nativeStarted) w.disconnected(); break; // Disconnected, asked or not
            case 10: w.stop(); break;
            case 11: w.apply(w.o.abortStart(w.now)); break; // a start that never reached the native service
            case 12: w.now += 4000; w.apply(w.o.tick(w.now)); break;
            case 17: // the server expires a lease nobody live holds (its TTL ran out); the start's nonce stays fresh
                if (!w.live.isEmpty() && !w.o.holdsLease(w.live) && w.answeredEverywhere(w.live)) {
                    w.live.clear();
                    w.liveToken.clear();
                    w.liveNonce.clear();
                    ++w.expiries;
                }
                break;
            default: { // a DELETE reaches the server / is answered / is cut
                QList<int> c;
                for (int i = 0; i < w.rels.size(); ++i)
                    if (!w.rels[i].done && !w.rels[i].held && (w.rels[i].unprocessed > 0 || w.rels[i].unanswered > 0)) c << i;
                if (c.isEmpty()) break;
                const int i = c[rnd(c.size())];
                const int what = w.deadApi ? 4 : rnd(5); // a dead direct API: every DELETE is cut
                if (w.rels[i].unprocessed > 0 && (what < 3 || w.rels[i].unanswered == 0))
                    what == 4 ? w.relCut(i) : w.relHit(i);
                else if (w.rels[i].unanswered > 0)
                    w.relAnswer(i, what < 3 ? 0 : 1);
                break;
            }
            }
            w.checkSeat("step");
            if (!w.violations.isEmpty() && std::getenv("LEDGER_TRACE")) { std::printf("seed %d:", seed); for (const QString &t : w.trace) std::printf(" %s", qPrintable(t)); std::printf(" => %s\n", qPrintable(w.violations[0])); break; }
        }
        w.drain();
        // (3) no lease is left live on the server; (4) nothing waits for ever
        if (!w.live.isEmpty())
            w.violations << QStringLiteral("a granted seat was left live on the server after the stop");
        for (const QString &l : w.endedPlain)
            if (w.reportOwed.contains(l))
                w.violations << QStringLiteral("a final meter report was lost: a release without it ended the lease");
        if (w.o.requestsOutstanding() > 0 || w.releasePending())
            w.violations << QStringLiteral("something still waits after everything was answered and stopped");
        if (!w.violations.isEmpty() && std::getenv("LEDGER_TRACE")) { std::printf("seed %d:", seed); for (const QString &t : w.trace) std::printf(" %s", qPrintable(t)); std::printf(" => %s\n", qPrintable(w.violations[0])); }
        ++sequences;
        unsentSeqs += w.unsentSeen ? 1 : 0;
        deletes += w.deletesSent;
        staleDenials += w.staleDenials;
        expiries += w.expiries;
        reports += w.reportTaken.size();
        if (!w.violations.isEmpty()) {
            ++failedSeqs;
            for (const QString &v : w.violations)
                kinds[v] += 1;
        }
    }
    for (auto it = kinds.constBegin(); it != kinds.constEnd(); ++it)
        std::printf("ledger model violation x%d: %s\n", it.value(), qPrintable(it.key()));
    std::printf("ledger model: %d sequences, %d steps, %d DELETEs sent, %d sequences kept an unsent release, %d sequences broke an invariant\n",
                sequences, steps, deletes, unsentSeqs, failedSeqs);
    std::printf("ledger model server: %d stale_session denials, %d lease expiries, %d final reports taken\n", staleDenials, expiries, reports);
    CHECK(failedSeqs == 0 && deletes > 1000 && unsentSeqs > 100 && staleDenials > 100 && expiries > 100 && reports > 100);
}

// Round 11 R1 (the blocker) as a script on the model's server (contract 1.19.0): the first confirmation C1 of start A times out, its
// retry C2 gets lease L; Stop sends DELETE(L, TA), which is held for the stop; a new start B takes the seat (the server ends L as
// replaced, makes LB); only then does the server process C1 - a stale nonce, denied - and the held DELETE reaches it - a no-op. B's
// seat survives. (Before the tenure rule C1 returned L with TA again and the delayed DELETE ended B's seat.)
static void reviewerSequenceR1()
{
    LedgerWorld w;
    w.begin(true);                 // start A: the direct acquire (acq 0) and a standby entry
    w.acqTimeout(0);               // the hedge: the pack tunnel starts (provisional)
    CHECK(w.o.provisionalPending());
    w.tunnelUp();                  // Connected: the confirmation C1 (acq 1)
    w.acqTimeout(1);               // C1 times out; its request lives on
    w.now += 10000;
    w.apply(w.o.tick(w.now));      // the retry C2 (acq 2)
    CHECK(w.acqs.size() == 3);
    w.acqProcess(2);
    w.acqDeliver(2);               // C2: lease L, token TA - the seat is confirmed
    CHECK(w.o.holdsLease(w.live) && !w.live.isEmpty());
    const QString lease = w.live, tokenA = w.liveToken;
    w.stop();                      // Stop: DELETE(L, TA) is held for the confirmed stop
    w.disconnected();              // the stop is confirmed: the DELETE leaves the app - and is delayed on its way to the server
    CHECK(w.deletesSent >= 1);
    w.begin(false);                // start B: a new nonce, its own acquire (acq 3)
    CHECK(w.acqs.size() == 4 && w.acqs[3].nonce != w.acqs[1].nonce && w.acqs[3].order > w.acqs[1].order);
    w.acqProcess(3);               // the server takes the seat over: L ended (replaced), LB made
    CHECK(w.live != lease && w.liveToken != tokenA);
    w.acqDeliver(3);
    CHECK(w.o.holdsLease(w.live));
    const QString leaseB = w.live;
    w.acqProcess(1);               // only now the server processes C1 (the old start's request): stale, denied, changes nothing
    CHECK(w.acqs[1].stale && w.live == leaseB);
    w.acqLate(1);
    for (int i = 0; i < w.rels.size(); ++i) {
        if (w.rels[i].done || w.rels[i].held)
            continue;
        w.relHit(i);               // it reaches the server late
        w.relAnswer(i, 0);
    }
    CHECK(w.live == leaseB && w.o.holdsLease(leaseB)); // B's seat survived the late DELETE and the late acquire
    CHECK(w.violations.isEmpty() && w.staleDenials == 1);
}

// Round 12 R1: the answer (or the timeout) of a CANCELLED older start must change nothing of the current session - above all not its
// schedule: Connect A -> Stop -> Connect B, B gets its lease and a renewal is scheduled, then A's answer lands.
static void lateAnswerKeepsSession()
{
    const SubscriptionNode a = stubOf(QStringLiteral("aaaaaaaaaaaaaaa0"));
    const qint64 T = 16000000;
    const char *kB = "LeaseBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    const char *kOldLease = "LeaseOldOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO";
    for (int what = 0; what < 4; ++what) { // 0 timeout, 1 refusal, 2 late grant, 3 stale renew reply of the older session
        for (const bool provisional : {false, true}) {
            if (provisional && what == 3)
                continue;
            FakeIo io;
            UpstreamLeaseOwner o(&io);
            UpstreamLeaseOwner::Options op;
            op.keepOwnership = true;
            o.setOptions(op);
            quint64 idA = 0, renewA = 0;
            o.begin(a, 1, packFor(a), T, 1700000000000LL); // start A
            idA = io.last("acquire")->id;
            if (what == 3) {
                o.onAcquireReply(idA, grantedAs(a, kOldLease), T + 100);
                o.tick(o.wakeAtMs());
                renewA = io.last("renew")->id; // a renewal of A's lease is in flight when the person stops
            }
            o.disconnect(T + 400000);
            o.begin(a, 1, provisional ? std::optional<StandbyCandidate>(packFor(a)) : std::nullopt, T + 400100, 1700000400100LL); // start B
            const quint64 idB = io.last("acquire")->id;
            if (provisional) {
                o.onAcquireReply(idB, failed("transport"), T + 401200); // B starts from the pack
                CHECK(o.provisionalPending());
                o.tunnelUp(T + 401300); // the confirmation through the tunnel goes out and fails: its retry is scheduled
                o.onAcquireReply(io.last("acquire")->id, failed("transport"), T + 401400);
            } else {
                o.onAcquireReply(idB, grantedAs(a, kB), T + 400300);
                CHECK(o.holdsLease(QLatin1String(kB)));
            }
            const qint64 wake = o.wakeAtMs();
            const LeasePhase phase = o.phase();
            const QString lease = o.leaseId();
            const bool releaseSent = o.releaseSent();
            CHECK(wake >= 0);
            if (what == 0)
                o.onAcquireReply(idA, failed("transport"), T + 401500);
            else if (what == 1)
                o.onAcquireReply(idA, refused(UpstreamErrorCode::NoSeat), T + 401500);
            else if (what == 2)
                o.onAcquireReply(idA, grantedAs(a, kOldLease), T + 401500);
            else
                o.onRenewReply(renewA, renewedOk(1, kServerT0 + 1200000), T + 401500, 1700000401500LL);
            CHECK(o.wakeAtMs() == wake && o.phase() == phase && o.leaseId() == lease && o.releaseSent() == releaseSent && o.active());
            // the schedule still works: the renewal (or the provisional confirmation attempt) goes out when due
            const int calls = io.calls.size();
            o.tick(wake);
            CHECK(io.calls.size() > calls);
            if (!provisional)
                CHECK(io.last("renew") && io.last("renew")->profileOrLease == QLatin1String(kB));
        }
    }
}

// Round 12 R2: an acquire answer of the API that names the highest order the server has seen (`min_session_order`, contract 1.21.0)
// raises the installation's counter - persisted at once, for ANY such answer (also a late one) - so the next start passes. Nothing else.
static void orderFloorCheck()
{
    const QByteArray stale = QByteArrayLiteral("{\"code\":\"lease_gone\",\"reason\":\"stale_session\",\"min_session_order\":");
    const auto replyWith = [&stale](const QByteArray &value, bool api = true) {
        return classifyAcquireReply(404, stale + value + "}", {}, QString(), api);
    };
    // the wire: the field is read in one place, bounded to 0..2^53-1, integer only
    CHECK(replyWith("1763120000999").error.minSessionOrder == 1763120000999LL && upstreamOrderFloorOf(replyWith("1763120000999")) == 1763120000999LL);
    CHECK(replyWith("0").error.minSessionOrder == 0 && replyWith("9007199254740991").error.minSessionOrder == kUpstreamSessionOrderMax);
    for (const char *bad : {"-1", "9007199254740992", "1e30", "1.5", "\"77\"", "null", "true", "[5]"}) {
        CHECK(replyWith(bad).error.minSessionOrder == -1 && upstreamOrderFloorOf(replyWith(bad)) == -1);
        CHECK(replyWith(bad).kind == LeaseReplyKind::Refused && replyWith(bad).error.reason == QLatin1String("stale_session")); // still the same denial
    }
    // the nonce-tenure denial has no field; a foreign answer (no API mark) never moves the counter
    const AcquireReply tenure = classifyAcquireReply(404, QByteArrayLiteral("{\"code\":\"lease_gone\",\"reason\":\"stale_session\"}"), {}, QString(), true);
    CHECK(tenure.kind == LeaseReplyKind::Refused && upstreamOrderFloorOf(tenure) == -1);
    CHECK(replyWith("5000", /*api=*/false).error.minSessionOrder == 5000 && upstreamOrderFloorOf(replyWith("5000", false)) == -1);
    // the counter: raised monotonically, persisted at once, the next start is above it
    const SubscriptionNode a = stubOf(QStringLiteral("aaaaaaaaaaaaaaa0"));
    const qint64 T = 17000000;
    qint64 stored = 0;
    int saves = 0;
    FakeIo io;
    UpstreamLeaseOwner o(&io);
    o.setOrderStore([&stored]() { return stored; }, [&stored, &saves](qint64 v) { stored = v; ++saves; });
    o.begin(a, 1, std::nullopt, T, 1000); // the clock is far behind what the server has seen (a reinstall after a clock ahead)
    CHECK(io.last("acquire")->order == 1000 && stored == 1000);
    const qint64 N = 1763200000000LL; // the server's highest
    o.onAcquireReply(io.last("acquire")->id, refused(UpstreamErrorCode::LeaseGone, QStringLiteral("stale_session")), T + 100);
    o.raiseOrderFloor(upstreamOrderFloorOf(replyWith(QByteArray::number(N)))); // what the client does for that very answer
    CHECK(stored == N && !o.active());
    o.begin(a, 1, std::nullopt, T + 200, 2000);
    CHECK(io.last("acquire")->order > N && io.last("acquire")->order == N + 1);
    // a floor that is not above the counter, an invalid one and "none" change nothing and write nothing
    const qint64 before = stored;
    const int savesBefore = saves;
    for (const qint64 v : {qint64(-1), qint64(0), N - 5, N + 1, kUpstreamSessionOrderMax + 1, qint64(-12345)})
        o.raiseOrderFloor(v);
    CHECK(stored == before && saves == savesBefore);
    // monotonic across a second writer of the store: the counter is read again, never moved backwards
    stored = N + 500; // another process advanced it
    o.disconnect(T + 300);
    o.begin(a, 1, std::nullopt, T + 400, 1);
    CHECK(io.last("acquire")->order == N + 501);
    // a floor above a clock that is ahead: the next start is max(last + 1, wall) - above the floor either way
    o.raiseOrderFloor(N + 10000);
    o.disconnect(T + 500);
    o.begin(a, 1, std::nullopt, T + 600, N + 50000);
    CHECK(io.last("acquire")->order == N + 50000);

    // the client: ANY acquire answer of the API that carries the field reaches the counter - in time, late (the attempt stopped
    // waiting), and with the foreign/field-less answers left out
    TuningStore::set({{QStringLiteral("attempt_provider_lease_ms"), 1500}}, {}, {}, {});
    struct Edge {
        QTcpServer server;
        QByteArray body = QByteArrayLiteral("{\"code\":\"lease_gone\",\"reason\":\"stale_session\",\"min_session_order\":424242}");
        bool mark = true;
        int delayMs = 0;
        Edge()
        {
            server.listen(QHostAddress::LocalHost);
            QObject::connect(&server, &QTcpServer::newConnection, &server, [this]() {
                while (QTcpSocket *s = server.nextPendingConnection())
                    QObject::connect(s, &QTcpSocket::readyRead, s, [this, s]() {
                        s->readAll();
                        QTimer::singleShot(delayMs, s, [this, s]() {
                            s->write("HTTP/1.1 404 X\r\nContent-Type: application/json\r\nContent-Length: " + QByteArray::number(body.size()) + "\r\n"
                                     + (mark ? QByteArray("X-Tribe-Api: 1\r\n") : QByteArray()) + "Connection: close\r\n\r\n" + body);
                            s->disconnectFromHost();
                        });
                    });
            });
        }
        QString base() const { return QStringLiteral("http://127.0.0.1:%1").arg(server.serverPort()); }
    };
    const auto pump = [](int ms) {
        QElapsedTimer t;
        t.start();
        while (t.elapsed() < ms)
            QCoreApplication::processEvents(QEventLoop::AllEvents, 10);
    };
    for (int variant = 0; variant < 4; ++variant) { // 0 in time, 1 late (after the attempt moved on), 2 foreign answer, 3 no field
        Edge edge;
        edge.delayMs = variant == 1 ? 2200 : 50;
        edge.mark = variant != 2;
        if (variant == 3)
            edge.body = QByteArrayLiteral("{\"code\":\"lease_gone\",\"reason\":\"stale_session\"}");
        QNetworkAccessManager nam;
        UpstreamLeaseClient client;
        const QString base = edge.base();
        client.configure(&nam, [base] { return base; }, QStringLiteral("00"), [] { return QStringLiteral("token"); });
        QVector<qint64> floors;
        int answers = 0;
        client.onSessionOrderFloor = [&floors](qint64 v) { floors << v; };
        client.onAcquire = [&answers](quint64, const AcquireReply &) { ++answers; };
        client.acquire(7, QStringLiteral("aaaaaaaaaaaaaaa0"), LeaseKind::Session, QString(), LeaseRoute{}, QStringLiteral("NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN"), 5);
        pump(variant == 1 ? 3200 : 700);
        CHECK(answers >= 1);
        if (variant == 0 || variant == 1)
            CHECK(floors.size() == 1 && floors[0] == 424242);
        else
            CHECK(floors.isEmpty());
    }
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    providerLegStarvedCheck();
    sessionReleaseRetry();
    localRefusalRecordsNothing();
    apiMarkRules();
    lateGrantOwnership();
    ledgerModel();
    reviewerSequenceR1();
    lateAnswerKeepsSession();
    unsentFlushOnAnyAnswer();
    sessionNonceCheck();
    lateOlderStart();
    sessionOrderCheck();
    orderFloorCheck();
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
