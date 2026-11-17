// AVPN upstream nodes (plan provider-pool v2, §5.1): DTO, parser, kill switch, gate, identity, the
// clamped tunables, the cache freeze helper and the config-path refusal of typed bodies.
// Synthetic data only (neutral names, documentation addresses). Build/run: build_upstream_nodes.sh
#include "../ConfigTypes.h"
#include "../NodeRotation.h"
#include "../SubscriptionParser.h"
#include "../TuningStore.h"
#include "../UpstreamNode.h"

#include <QCoreApplication>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

#include <cmath>
#include <cstdio>
#include <limits>
#include <tuple>

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

static const char *kSha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

static void setFlags(bool upstream, bool xrayClient = true)
{
    QMap<QString, bool> f;
    f.insert(QStringLiteral("upstream_nodes"), upstream);
    f.insert(QStringLiteral("xray_client"), xrayClient);
    TuningStore::set({}, f);
}

static QJsonObject awgNode()
{
    return QJsonObject{
        {"node_id", "1"}, {"region", "eu"}, {"endpoint", "192.0.2.10:51820"}, {"proto", "awg"},
        {"server_pubkey", "cGxhY2Vob2xkZXItc2VydmVyLWtleS0wMDAwMDAwMDA="},
        {"awg_params", QJsonObject{{"Jc", 4}, {"Jmin", 10}, {"Jmax", 50}, {"S1", 1}, {"S2", 2},
                                   {"H1", 1}, {"H2", 2}, {"H3", 3}, {"H4", 4}}},
        {"health", QJsonObject{}}, {"allowed_ips", QJsonArray{"0.0.0.0/0"}},
        {"dns", QJsonArray{"1.1.1.1", "8.8.8.8"}}};
}

static QJsonObject ownXrayNode()
{
    return QJsonObject{
        {"node_id", "1:xray"}, {"region", "eu"}, {"endpoint", "192.0.2.10:443"}, {"proto", "xray"},
        {"host_id", 1},
        {"xray_params", QJsonObject{{"uuid", "8f14e45f-ceea-4a7c-9d6b-2a1b3c4d5e6f"},
                                    {"public_key", "SbVjZ9Yl3dR3QpG1v8k2Wx0aU7Hq4Nn6Tt5Bc8Jd1mE"},
                                    {"short_id", "a1b2"}, {"server_name", "example.com"}}},
        {"health", QJsonObject{}}, {"allowed_ips", QJsonArray{"0.0.0.0/0"}},
        {"dns", QJsonArray{"1.1.1.1"}}};
}

static QJsonObject stubBlock()
{
    return QJsonObject{{"profile_id", "3f9c2a7b1d4e8f60"}, {"config_sha256", kSha},
                       {"probe_class", "single"}, {"protocols", QJsonArray{"proto:vless", "net:tcp"}},
                       {"required_geo", QJsonArray{"geoip:ru"}}, {"size_bytes", 4096},
                       {"tier", 1}, {"priority", 0}};
}

static QJsonObject stubNode(const QJsonObject &upstream = stubBlock())
{
    return QJsonObject{{"node_id", QStringLiteral("up:") + upstream.value("profile_id").toString()},
                       {"region", "upstream"}, {"label", "Provider profile"}, {"country_code", QJsonValue()},
                       {"endpoint", ""}, {"host_id", QJsonValue()}, {"proto", "xray"},
                       {"upstream", upstream}, {"health", QJsonObject{}},
                       {"allowed_ips", QJsonArray{"0.0.0.0/0"}}, {"dns", QJsonArray{"1.1.1.1"}}};
}

static QByteArray body(const QJsonArray &nodes, bool withRevision = true)
{
    QJsonObject root{{"version", 1}, {"address", QJsonArray{"10.8.0.2/32"}}, {"status", "active"},
                     {"pool_revision", 1700000000000.0}, {"nodes", nodes}};
    if (withRevision)
        root.insert("upstream_revision", 1763117000123.0);
    return QJsonDocument(root).toJson(QJsonDocument::Compact);
}

static Subscription parse(const QByteArray &b)
{
    Subscription s;
    QString err;
    const bool ok = SubscriptionParser::parse(b, s, err);
    CHECK(ok);
    return s;
}

static const SubscriptionNode *byId(const Subscription &s, const QString &id)
{
    for (const SubscriptionNode &n : s.nodes)
        if (n.nodeId == id)
            return &n;
    return nullptr;
}

static bool sameNodes(const Subscription &a, const Subscription &b)
{
    if (a.nodes.size() != b.nodes.size() || a.upstreamRevision != b.upstreamRevision
        || a.poolRevision != b.poolRevision)
        return false;
    for (int i = 0; i < a.nodes.size(); ++i) {
        const SubscriptionNode &x = a.nodes[i], &y = b.nodes[i];
        if (x.nodeId != y.nodeId || x.proto != y.proto || x.endpoint != y.endpoint
            || x.xray.has_value() != y.xray.has_value() || x.upstream.has_value() != y.upstream.has_value())
            return false;
    }
    return true;
}

// 1) The same input on both settings of the kill switch.
static void flagGating()
{
    const QByteArray mixed = body({awgNode(), ownXrayNode(), stubNode()});
    const QByteArray without = body({awgNode(), ownXrayNode()});

    setFlags(false);
    const Subscription off = parse(mixed);
    CHECK(off.nodes.size() == 2);
    CHECK(!byId(off, "up:3f9c2a7b1d4e8f60"));
    CHECK(off.upstreamRevision == 0);              // the field is not even read with the switch off
    CHECK(sameNodes(off, parse(without)));         // = the body without the stub, as on 138/139
    CHECK(SubscriptionParser::validate(off) == SubscriptionParser::validate(parse(without)));

    setFlags(true);
    const Subscription on = parse(mixed);
    CHECK(on.nodes.size() == 3);
    const SubscriptionNode *up = byId(on, "up:3f9c2a7b1d4e8f60");
    CHECK(up && up->upstream.has_value() && !up->xray.has_value());
    CHECK(up && up->proto == QLatin1String("xray") && up->endpoint.isEmpty() && up->hostId == 0);
    CHECK(up && up->upstream->profileId == QLatin1String("3f9c2a7b1d4e8f60"));
    CHECK(up && up->upstream->configSha256 == QLatin1String(kSha));
    CHECK(up && up->upstream->probeClass == UpstreamProbeClass::Single);
    CHECK(up && up->upstream->protocols == QStringList({"proto:vless", "net:tcp"}));
    CHECK(up && up->upstream->requiredGeo == QStringList({"geoip:ru"}));
    CHECK(up && up->upstream->sizeBytes == 4096 && up->upstream->tier == 1 && up->upstream->priority == 0);
    CHECK(up && up->transportRank == kTransportRankXray);
    CHECK(on.upstreamRevision == 1763117000123LL);
    // The other nodes are exactly what the switch-off parse gives.
    CHECK(byId(on, "1") && byId(on, "1:xray") && byId(on, "1:xray")->xray.has_value());
    // validate(): a stub has no endpoint by contract and is not "xray without xray_params".
    CHECK(SubscriptionParser::validate(on) == SubscriptionParser::validate(off));

    // Gate: supported only with BOTH switches on (Xray engine + upstream nodes), read at every choice.
    CHECK(up && isSupportedProtoNode(*up));
    CHECK(up && isAutoEligibleNode(*up));
    if (up) {
        const SubscriptionNode copy = *up;
        setFlags(false, true);
        CHECK(!isSupportedProtoNode(copy));    // operator "off" removes it from every pick at once
        setFlags(true, false);
        CHECK(!isSupportedProtoNode(copy));    // Xray killed -> upstream nodes go too
        setFlags(true, true);
        CHECK(isSupportedProtoNode(copy));
        SubscriptionNode bare = copy;
        bare.upstream.reset();
        CHECK(!isSupportedProtoNode(bare));    // xray without params and without stub: never
        CHECK(transportAllowed(copy, TransportMode::Xray) && !transportAllowed(copy, TransportMode::Awg));
    }
}

// 2) upstream_revision absent = no upstream entry is usable.
static void revisionRequired()
{
    setFlags(true);
    const Subscription s = parse(body({awgNode(), stubNode()}, /*withRevision=*/false));
    CHECK(s.nodes.size() == 1 && !byId(s, "up:3f9c2a7b1d4e8f60"));
    CHECK(s.upstreamRevision == 0);
    QJsonObject root = QJsonDocument::fromJson(body({stubNode()})).object();
    root.insert("upstream_revision", "1763117000123"); // a string is not a revision
    CHECK(parse(QJsonDocument(root).toJson()).nodes.isEmpty());
    root.insert("upstream_revision", 0);
    CHECK(parse(QJsonDocument(root).toJson()).nodes.isEmpty());
    root.insert("upstream_revision", 1.5);
    CHECK(parse(QJsonDocument(root).toJson()).nodes.isEmpty());
}

static bool keptWith(const QJsonObject &upstream)
{
    const Subscription s = parse(body({awgNode(), stubNode(upstream)}));
    CHECK(byId(s, "1") != nullptr); // the rest of the answer always survives
    return s.nodes.size() == 2;
}

// 3) Stub validation: anything off -> dropped, never a crash, the answer stays.
static void stubValidation()
{
    setFlags(true);
    CHECK(keptWith(stubBlock()));
    // Release A display parts: optional and cosmetic - absent/malformed = 0 / false, never a refusal.
    {
        const auto parts = [](const QJsonValue &ordinal, const QJsonValue &custom) {
            QJsonObject o = stubBlock();
            if (!ordinal.isUndefined()) o.insert("ordinal", ordinal);
            if (!custom.isUndefined()) o.insert("label_custom", custom);
            UpstreamStub s;
            QString why;
            const bool ok = parseUpstreamStub(o, s, why);
            return std::make_tuple(ok, s.ordinal, s.labelCustom);
        };
        CHECK(parts(QJsonValue(QJsonValue::Undefined), QJsonValue(QJsonValue::Undefined)) == std::make_tuple(true, 0, false));
        CHECK(parts(3, true) == std::make_tuple(true, 3, true));
        CHECK(parts(9999, false) == std::make_tuple(true, 9999, false));
        CHECK(parts(0, "yes") == std::make_tuple(true, 0, false));
        CHECK(parts(-1, 1) == std::make_tuple(true, 0, false));
        CHECK(parts(10000, QJsonValue()) == std::make_tuple(true, 0, false));
        CHECK(parts("2", true) == std::make_tuple(true, 0, true));
        CHECK(parts(2.5, true) == std::make_tuple(true, 0, true));
        CHECK(keptWith([] { QJsonObject o = stubBlock(); o.insert("ordinal", "x"); return o; }()));
    }
    // Contract 1.10.0 `kind`: optional and cosmetic too - absent / null = Unspecified, unknown = auto, never a refusal.
    {
        const auto kindOf = [](const QJsonValue &k) {
            QJsonObject o = stubBlock();
            if (!k.isUndefined())
                o.insert("kind", k);
            UpstreamStub s;
            QString why;
            const bool ok = parseUpstreamStub(o, s, why);
            return ok ? s.kind : UpstreamKind::Unspecified;
        };
        CHECK(kindOf(QJsonValue(QJsonValue::Undefined)) == UpstreamKind::Unspecified);
        CHECK(kindOf(QJsonValue()) == UpstreamKind::Unspecified);
        CHECK(kindOf("country") == UpstreamKind::Country);
        CHECK(kindOf("whitelist") == UpstreamKind::Whitelist);
        CHECK(kindOf("auto") == UpstreamKind::Auto);
        CHECK(kindOf("fourth-kind") == UpstreamKind::Auto);
        CHECK(kindOf(3) == UpstreamKind::Auto);
        CHECK(keptWith([] { QJsonObject o = stubBlock(); o.insert("kind", "fourth-kind"); return o; }()));
    }
    const auto with = [](const char *key, const QJsonValue &v) {
        QJsonObject o = stubBlock();
        if (v.isUndefined())
            o.remove(QLatin1String(key));
        else
            o.insert(QLatin1String(key), v);
        return o;
    };
    // profile_id
    CHECK(!keptWith(with("profile_id", "")));
    CHECK(!keptWith(with("profile_id", QJsonValue())));
    CHECK(!keptWith(with("profile_id", 12345)));
    CHECK(!keptWith(with("profile_id", "bad id/../x")));
    CHECK(!keptWith(with("profile_id", QString(65, QLatin1Char('a')))));
    // config_sha256
    CHECK(!keptWith(with("config_sha256", QString::fromLatin1(kSha).left(63))));
    CHECK(!keptWith(with("config_sha256", QString::fromLatin1(kSha) + QLatin1Char('0'))));
    CHECK(!keptWith(with("config_sha256", QString(64, QLatin1Char('g')))));
    CHECK(!keptWith(with("config_sha256", QJsonValue::Undefined)));
    {
        const Subscription s = parse(body({stubNode(with("config_sha256", QString::fromLatin1(kSha).toUpper()))}));
        CHECK(s.nodes.size() == 1 && s.nodes[0].upstream->configSha256 == QLatin1String(kSha));
    }
    // probe_class
    CHECK(keptWith(with("probe_class", "composite")));
    CHECK(!keptWith(with("probe_class", "chain")));
    CHECK(!keptWith(with("probe_class", QJsonValue::Undefined)));
    // lists
    CHECK(keptWith(with("protocols", QJsonArray())));
    CHECK(!keptWith(with("protocols", "proto:vless")));
    CHECK(!keptWith(with("protocols", QJsonArray{"proto:vless", 7})));
    CHECK(!keptWith(with("protocols", QJsonValue::Undefined)));
    CHECK(!keptWith(with("required_geo", QJsonValue::Undefined)));
    CHECK(!keptWith(with("required_geo", QJsonArray{""})));
    {
        QJsonArray many;
        for (int i = 0; i < 65; ++i)
            many << QStringLiteral("geoip:t%1").arg(i);
        CHECK(!keptWith(with("required_geo", many)));
    }
    // sizes and numbers
    CHECK(keptWith(with("size_bytes", 262144)));
    CHECK(!keptWith(with("size_bytes", 262145)));
    CHECK(!keptWith(with("size_bytes", 0)));
    CHECK(!keptWith(with("size_bytes", -1)));
    CHECK(!keptWith(with("size_bytes", 100.5)));
    CHECK(!keptWith(with("size_bytes", "4096")));
    CHECK(!keptWith(with("size_bytes", 1e300)));
    CHECK(!keptWith(with("tier", 0)));
    CHECK(keptWith(with("tier", 1000)));
    CHECK(!keptWith(with("tier", 1001)));
    CHECK(!keptWith(with("priority", -1)));
    CHECK(keptWith(with("priority", 0)));
    CHECK(!keptWith(with("priority", QJsonValue::Undefined)));
    // the block itself
    {
        QJsonObject n = stubNode();
        n.insert("upstream", 5);
        CHECK(parse(body({awgNode(), n})).nodes.size() == 1);
        n.insert("upstream", QJsonValue());
        CHECK(parse(body({awgNode(), n})).nodes.size() == 1);
        n.remove("upstream");
        CHECK(parse(body({awgNode(), n})).nodes.size() == 1);
    }
    // node_id must be "up:" + profile_id (cannot collide with an own node id)
    {
        QJsonObject n = stubNode();
        n.insert("node_id", "7");
        CHECK(parse(body({awgNode(), n})).nodes.size() == 1);
    }
    // xray_params present (even invalid) next to a stub: not a stub - dropped as on 139
    {
        QJsonObject n = stubNode();
        n.insert("xray_params", QJsonObject{{"uuid", "x"}});
        CHECK(parse(body({awgNode(), n})).nodes.size() == 1);
        n.insert("xray_params", QJsonValue()); // explicit null = absent
        CHECK(parse(body({awgNode(), n})).nodes.size() == 2);
    }
    // valid xray_params next to an upstream block: an own Xray node, the block is ignored
    {
        QJsonObject n = ownXrayNode();
        n.insert("upstream", stubBlock());
        const Subscription s = parse(body({n}));
        CHECK(s.nodes.size() == 1 && s.nodes[0].xray.has_value() && !s.nodes[0].upstream.has_value());
    }
    // a stub with another proto is not an Xray stub (unknown-proto path, untouched)
    {
        QJsonObject n = stubNode();
        n.insert("proto", "future");
        const Subscription s = parse(body({n}));
        CHECK(s.nodes.size() == 1 && !s.nodes[0].upstream.has_value());
    }
}

// 4) Identity: profile + sha; a rotated sha is a changed node on the same row.
static void identity()
{
    setFlags(true);
    const Subscription a = parse(body({stubNode()}));
    QJsonObject rotated = stubBlock();
    rotated.insert("config_sha256", QString(64, QLatin1Char('f')));
    const Subscription b = parse(body({stubNode(rotated)}));
    CHECK(a.nodes.size() == 1 && b.nodes.size() == 1);
    if (a.nodes.size() == 1 && b.nodes.size() == 1) {
        CHECK(sameUpstreamIdentity(a.nodes[0], a.nodes[0]));
        CHECK(!sameUpstreamIdentity(a.nodes[0], b.nodes[0]));
        CHECK(a.nodes[0].nodeId == b.nodes[0].nodeId);  // the same row
        SubscriptionNode other = a.nodes[0];
        other.upstream->profileId = QStringLiteral("0000000000000000");
        CHECK(!sameUpstreamIdentity(a.nodes[0], other));
        SubscriptionNode plain = a.nodes[0];
        plain.upstream.reset();
        CHECK(!sameUpstreamIdentity(plain, plain));
        CHECK(isUpstreamNode(a.nodes[0]) && !isUpstreamNode(plain));
    }
    UpstreamStub s;
    s.requiredGeo = {"geoip:ru", "geosite:category-ru"};
    CHECK(!upstreamGeoSupported(s, {}));
    CHECK(!upstreamGeoSupported(s, {"geoip:ru"}));
    CHECK(upstreamGeoSupported(s, {"GEOIP:RU", "geosite:category-ru", "geoip:private"}));
    s.requiredGeo.clear();
    CHECK(upstreamGeoSupported(s, {}));
}

// 5) Tunables: defaults when absent, clamps, non-finite.
static void tunables()
{
    TuningStore::reset();
    CHECK(upstreamLeaseTtlSTuned() == 900);
    CHECK(upstreamRenewIntervalSTuned() == 300);
    CHECK(upstreamProbeTtlSTuned() == 60);
    CHECK(upstreamVerifyBytesTuned() == 131072);
    CHECK(xrayMemoryLimitMiBTuned() == 30);
    CHECK(!upstreamNodesEnabled()); // default OFF
    QMap<QString, double> n;
    n.insert("upstream_lease_ttl_s", 10);
    n.insert("upstream_renew_interval_s", 5000);
    n.insert("upstream_probe_ttl_s", 1e9);
    n.insert("upstream_verify_bytes", 1);
    n.insert("xray_memory_limit_mib", 100);
    TuningStore::set(n, {});
    CHECK(upstreamLeaseTtlSTuned() == 120);
    CHECK(upstreamRenewIntervalSTuned() == 60);   // ttl/2 of the clamped ttl
    CHECK(upstreamProbeTtlSTuned() == 300);
    CHECK(upstreamVerifyBytesTuned() == 16384);
    CHECK(xrayMemoryLimitMiBTuned() == 40);
    n.insert("upstream_lease_ttl_s", 1800);
    n.insert("upstream_renew_interval_s", 1);
    n.insert("xray_memory_limit_mib", 1);
    n.insert("upstream_verify_bytes", 5e6);
    TuningStore::set(n, {});
    CHECK(upstreamLeaseTtlSTuned() == 1800);
    CHECK(upstreamRenewIntervalSTuned() == 30);
    CHECK(xrayMemoryLimitMiBTuned() == 20);
    CHECK(upstreamVerifyBytesTuned() == 1048576);
    const double nan = std::numeric_limits<double>::quiet_NaN();
    CHECK(upstreamLeaseTtlSFrom(nan) == 900 && upstreamProbeTtlSFrom(nan) == 60);
    CHECK(xrayMemoryLimitMiBFrom(std::numeric_limits<double>::infinity()) == 30);
    CHECK(upstreamRenewIntervalSFrom(nan, 900) == 300 && upstreamRenewIntervalSFrom(nan, 120) == 60);
    CHECK(upstreamRenewIntervalSFrom(450, 900) == 450 && upstreamRenewIntervalSFrom(451, 900) == 450);
    TuningStore::reset();
}

// 6) Bounded trust of the cached switch + the config path refuses a typed body.
static void configPath()
{
    // Bounded trust of the cached signed value (replaces the hard freeze in ConfigService::start).
    const qint64 h = 3600LL * 1000, now = 1763100000000LL;
    CHECK(upstreamCacheMaxAgeMs(std::numeric_limits<double>::quiet_NaN()) == 72 * h);
    CHECK(upstreamCacheMaxAgeMs(0) == h && upstreamCacheMaxAgeMs(1e9) == 336 * h && upstreamCacheMaxAgeMs(24) == 24 * h);
    CHECK(upstreamTrustedFromCache(true, now - h, now, 72 * h));          // fresh cache trusted
    CHECK(!upstreamTrustedFromCache(true, now - 72 * h, now, 72 * h));    // stale not
    CHECK(!upstreamTrustedFromCache(false, now - h, now, 72 * h));        // false never upgraded
    CHECK(!upstreamTrustedFromCache(true, 0, now, 72 * h));               // no receive time
    CHECK(!upstreamTrustedFromCache(true, now + h, now, 72 * h));         // clock behind the stamp

    RemoteConfig c;
    QString err;
    const QByteArray today = R"({"min_app_version":{"ios":"5.1.0"},"recommended_version":{},"blocked_versions":{},)"
                             R"("probe_targets":[],"subscription_refresh_interval_s":43200,"edges":["https://a.example"],)"
                             R"("features":{"upstream_nodes":true},"urls":{},"numbers":{"upstream_lease_ttl_s":900},"lists":{}})";
    CHECK(parseConfig(today, c, err) && c.valid && c.features.value("upstream_nodes"));
    CHECK(parseConfig(R"({"edges":["https://a.example"],"ttl_s":3600})", c, err) && c.edges.size() == 1);
    QByteArray typed = today;
    typed.insert(1, R"("type":"upstream_lease",)");
    CHECK(!parseConfig(typed, c, err) && !c.valid && c.features.isEmpty());
    CHECK(!parseConfig(R"({"type":null,"features":{"xray_client":true}})", c, err));
    CHECK(!parseConfig(R"({"type":"","edges":["https://a.example"]})", c, err) && c.edges.isEmpty());
    // a nested "type" (probe target kind, list values) is not the root key
    CHECK(parseConfig(R"({"probe_targets":[{"target":"t","kind":"tcp","host":"h","type":"x"}]})", c, err));
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    std::setvbuf(stdout, nullptr, _IONBF, 0); // FAIL lines survive a crash of a mutated build
    flagGating();
    revisionRequired();
    stubValidation();
    identity();
    tunables();
    configPath();
    TuningStore::reset();
    if (g_fail) {
        std::printf("upstream_nodes_check: %d of %d FAILED\n", g_fail, g_total);
        return 1;
    }
    std::printf("upstream_nodes_check: OK (%d checks)\n", g_total);
    return 0;
}
