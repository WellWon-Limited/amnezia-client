// AVPN serviceEngine — автономная проверка выбора транспорта (волна awg31-xray-v1, спека
// 2026-09-01 §2.3): локации × транспорты, transport_rank + локальная история (TransportHistory),
// ручной режим Авто/Amnezia/Xray, kill-switch'и xray_client/transport_auto_pick, pin по локации,
// failover «другой транспорт той же локации → соседняя локация», фаза verifying для xray
// («Подключено» только после пробы через туннель), DEAD по провалу проб, ротация по локациям.
// Сборка/запуск: core/serviceEngine/tests/build_transport_pick.sh (по образцу build_proto_forward.sh).
#include "../NodeRotation.h"
#include "../ServiceEngine.h"
#include "../SubscriptionParser.h"
#include "../TransportPick.h"
#include "../TuningStore.h"

#include <QCoreApplication>
#include <QJsonDocument>
#include <cstdio>

using namespace avpn;

static int g_failed = 0;
static int g_total = 0;

#define CHECK(expr)                                                                                 \
    do {                                                                                            \
        ++g_total;                                                                                  \
        if (!(expr)) {                                                                              \
            ++g_failed;                                                                             \
            fprintf(stderr, "FAIL [%s:%d]: %s\n", __FILE__, __LINE__, #expr);                       \
        }                                                                                           \
    } while (0)

// Туннель-стаб (по образцу failover_check): фиксирует up/down, всегда успешен.
struct FakeTunnel : ITunnelControl {
    QString lastUpNodeId;
    QStringList ups;
    int upCalls = 0;
    int downCalls = 0;
    TunnelStats st;
    TunnelResult up(const Subscription &, const SubscriptionNode &node) override
    {
        ++upCalls;
        lastUpNodeId = node.nodeId;
        ups << node.nodeId;
        return TunnelResult::success();
    }
    TunnelResult applyPeer(const Subscription &, const SubscriptionNode &node) override
    {
        lastUpNodeId = node.nodeId;
        return TunnelResult::success();
    }
    TunnelStats readStats() override { return st; }
    void down() override { ++downCalls; }
};

static TunnelStats mkStats(qint64 hs, qint64 rx, qint64 tx)
{
    TunnelStats s; s.latestHandshakeEpoch = hs; s.rxBytes = rx; s.txBytes = tx; s.valid = true; return s;
}

// awg-узел: полный бандл + host_id/transport_rank.
static QByteArray awgNodeJson(const char *id, int hostId, const char *cc, double weight, int rank = 10,
                              const char *endpoint = "203.0.113.10:585")
{
    return QByteArray(R"({ "node_id": ")") + id + R"(", "region": "eu", "host_id": )" + QByteArray::number(hostId)
        + R"(, "transport_rank": )" + QByteArray::number(rank) + R"(,
        "endpoint": ")" + endpoint + R"(",
        "server_pubkey": "K1nDpUbLiCkEyExAmPlE0000000000000000000000=",
        "proto": "awg", "weight": )" + QByteArray::number(weight) + R"(,
        "country_code": ")" + cc + R"(",
        "allowed_ips": ["0.0.0.0/0", "::/0"], "dns": ["1.1.1.1", "1.0.0.1"],
        "mtu": 1280, "persistent_keepalive": 25,
        "awg_params": { "Jc": 4, "Jmin": 50, "Jmax": 1000, "S1": 86, "S2": 57,
                        "H1": 1, "H2": 2, "H3": 3, "H4": 4,
                        "RandomTrailers": "off", "DisableCookies": "on" } })";
}

// xray-узел: валидные xray_params (как в xray_config_check).
static QByteArray xrayNodeJson(const char *id, int hostId, const char *cc, double weight, int rank = 20,
                               const char *endpoint = "203.0.113.10:443")
{
    return QByteArray(R"({ "node_id": ")") + id + R"(", "region": "eu", "host_id": )" + QByteArray::number(hostId)
        + R"(, "transport_rank": )" + QByteArray::number(rank) + R"(,
        "endpoint": ")" + endpoint + R"(", "proto": "xray",
        "weight": )" + QByteArray::number(weight) + R"(, "country_code": ")" + cc + R"(",
        "xray_params": { "uuid": "8f14e45f-ceea-4a7c-9d6b-2a1b3c4d5e6f",
                         "public_key": "SbVjZ9Yl3dR3QpG1v8k2Wx0aU7Hq4Nn6Tt5Bc8Jd1mE",
                         "short_id": "a1b2c3d4", "server_name": "vision.example.com",
                         "fingerprint": "chrome", "flow": "xtls-rprx-vision",
                         "network": "tcp", "security": "reality" } })";
}

static QByteArray subJson(const QList<QByteArray> &nodes, int rev = 1)
{
    QByteArray joined;
    for (int i = 0; i < nodes.size(); ++i) {
        if (i) joined += ",";
        joined += nodes[i];
    }
    return R"({ "version": 1, "address": ["10.7.0.5/32"], "status": "active",
        "expires_at": "2026-09-01T00:00:00Z", "traffic": { "used": 0, "limit": 0 },
        "pool_revision": )" + QByteArray::number(rev) + R"(,
        "nodes": [)" + joined + "] }";
}

static QList<SubscriptionNode> parseNodes(const QByteArray &json)
{
    Subscription sub;
    QString err;
    if (!SubscriptionParser::parse(json, sub, err))
        fprintf(stderr, "parse error: %s\n", err.toUtf8().constData());
    return sub.nodes;
}

static const SubscriptionNode *byId(const QList<SubscriptionNode> &nodes, const char *id)
{
    for (const SubscriptionNode &n : nodes)
        if (n.nodeId == QLatin1String(id))
            return &n;
    return nullptr;
}

static void setFlags(bool xrayClient, bool autoPick)
{
    TuningStore::set({}, {{QStringLiteral("xray_client"), xrayClient},
                          {QStringLiteral("transport_auto_pick"), autoPick}}, {}, {});
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    setFlags(true, true);

    // --- 1) TransportHistory: EWMA, клампы, демоушен, JSON round-trip, вытеснение ---
    {
        TransportHistory h;
        CHECK(h.rankPenalty(QStringLiteral("h:9"), QStringLiteral("awg")) == 0);
        h.record(QStringLiteral("h:9"), QStringLiteral("awg"), true, 1200, 1000);
        TransportHistoryEntry e = h.entry(QStringLiteral("h:9"), QStringLiteral("awg"));
        CHECK(e.samples == 1 && e.successEwma == 1.0 && e.ttfMsEwma == 1200.0);
        h.record(QStringLiteral("h:9"), QStringLiteral("awg"), false, -1, 2000);
        e = h.entry(QStringLiteral("h:9"), QStringLiteral("awg"));
        CHECK(e.samples == 2 && e.successEwma > 0.69 && e.successEwma < 0.71); // 0.3*0 + 0.7*1
        CHECK(e.ttfMsEwma == 1200.0); // провал не трогает время до трафика
        CHECK(h.rankPenalty(QStringLiteral("h:9"), QStringLiteral("awg")) == 0); // 0.7 >= 0.5
        h.record(QStringLiteral("h:9"), QStringLiteral("awg"), false, -1, 3000);
        h.record(QStringLiteral("h:9"), QStringLiteral("awg"), false, -1, 4000);
        CHECK(h.rankPenalty(QStringLiteral("h:9"), QStringLiteral("awg")) == TransportHistory::kDemoteRank);
        // один провал без истории — не демоутим (kDemoteMinSamples=2)
        h.record(QStringLiteral("h:2"), QStringLiteral("xray"), false, -1, 5000);
        CHECK(h.rankPenalty(QStringLiteral("h:2"), QStringLiteral("xray")) == 0);
        // кламп времени до трафика
        h.record(QStringLiteral("h:3"), QStringLiteral("awg"), true, 999999, 6000);
        CHECK(h.entry(QStringLiteral("h:3"), QStringLiteral("awg")).ttfMsEwma == TransportHistory::kMaxTtfMs);
        // round-trip
        const TransportHistory h2 = TransportHistory::deserialize(h.serialize());
        CHECK(h2.size() == h.size());
        CHECK(h2.rankPenalty(QStringLiteral("h:9"), QStringLiteral("awg")) == TransportHistory::kDemoteRank);
        CHECK(h2.entry(QStringLiteral("h:3"), QStringLiteral("awg")).ttfMsEwma == TransportHistory::kMaxTtfMs);
        // мусор из настроек: не объект / мусорные ключи / значения вне диапазона
        CHECK(TransportHistory::deserialize(QByteArray("garbage")).size() == 0);
        const TransportHistory h3 = TransportHistory::deserialize(
            QByteArray(R"({"nokey":{"s":1},"h:1|awg":{"s":7,"t":-5,"n":99999,"ts":-1}})"));
        CHECK(h3.size() == 1);
        CHECK(h3.entry(QStringLiteral("h:1"), QStringLiteral("awg")).successEwma == 1.0);
        CHECK(h3.entry(QStringLiteral("h:1"), QStringLiteral("awg")).ttfMsEwma == -1.0);
        CHECK(h3.entry(QStringLiteral("h:1"), QStringLiteral("awg")).samples == TransportHistory::kMaxSamples);
        // вытеснение: 70 записей → 64, самые старые ушли
        TransportHistory big;
        for (int i = 0; i < 70; ++i)
            big.record(QStringLiteral("h:%1").arg(i), QStringLiteral("awg"), true, 100, 1000 + i);
        CHECK(big.size() == TransportHistory::kMaxEntries);
        CHECK(!big.has(QStringLiteral("h:0"), QStringLiteral("awg")));
        CHECK(big.has(QStringLiteral("h:69"), QStringLiteral("awg")));
    }

    // --- 2) locationKeyOf / locationTransports / хелперы proto ---
    {
        const QList<SubscriptionNode> nodes = parseNodes(subJson({
            awgNodeJson("9:awg", 9, "EE", 1.0), xrayNodeJson("9:xray", 9, "EE", 1.0),
            awgNodeJson("pl-old", 0, "PL", 1.0), awgNodeJson("noloc", 0, "", 1.0) }));
        CHECK(nodes.size() == 4);
        CHECK(locationKeyOf(*byId(nodes, "9:awg")) == QLatin1String("h:9"));
        CHECK(locationKeyOf(*byId(nodes, "9:xray")) == QLatin1String("h:9"));
        CHECK(locationKeyOf(*byId(nodes, "pl-old")) == QLatin1String("cr:PL/eu"));
        CHECK(locationKeyOf(*byId(nodes, "noloc")) == QLatin1String("n:noloc"));
        const QStringList tr = locationTransports(nodes, QStringLiteral("h:9"));
        CHECK(tr == QStringList({QStringLiteral("awg"), QStringLiteral("xray")}));
        CHECK(locationTransports(nodes, QStringLiteral("cr:PL/eu")) == QStringList{QStringLiteral("awg")});
        CHECK(isSupportedProto(QStringLiteral("xray")));      // macOS + kill-switch ВКЛ
        CHECK(isSupportedProtoNode(*byId(nodes, "9:xray")));
        SubscriptionNode noParams = *byId(nodes, "9:xray");
        noParams.xray.reset();
        CHECK(!isSupportedProtoNode(noParams));               // xray без параметров непригодна
        CHECK(!isSupportedProto(QStringLiteral("vless")));
        setFlags(false, true);
        CHECK(!isSupportedProto(QStringLiteral("xray")));     // kill-switch xray_client
        setFlags(true, false);
        CHECK(isSupportedProtoNode(*byId(nodes, "9:xray")));
        CHECK(!isAutoEligibleNode(*byId(nodes, "9:xray")));   // kill-switch transport_auto_pick
        CHECK(isAutoEligibleNode(*byId(nodes, "9:awg")));
        setFlags(true, true);
        CHECK(transportModeFromString(QStringLiteral("XRAY")) == TransportMode::Xray);
        CHECK(transportModeFromString(QStringLiteral("amnezia")) == TransportMode::Awg);
        CHECK(transportModeFromString(QStringLiteral("junk")) == TransportMode::Auto);
        CHECK(transportModeToString(TransportMode::Xray) == QLatin1String("xray"));
    }

    // --- 3) pickTransportNode: ранг, RTT-локация, история, режимы, kill-switch'и, pin, исключения ---
    {
        const QList<SubscriptionNode> nodes = parseNodes(subJson({
            awgNodeJson("9:awg", 9, "EE", 1.0), xrayNodeJson("9:xray", 9, "EE", 1.0),
            awgNodeJson("2:awg", 2, "PL", 1.0) }));
        TransportHistory hist;
        QHash<QString, int> rtt;
        TransportPickInput in;

        // 3a) без RTT: weight-ярус (все равны) → pickIndex решает локацию, внутри локации — ранг
        auto first = [](int) { return 0; };
        auto second = [](int) { return 1; };
        auto third = [](int) { return 2; };
        const SubscriptionNode *p = pickTransportNode(nodes, rtt, hist, in, first);
        CHECK(p && p->nodeId == QLatin1String("9:awg"));
        p = pickTransportNode(nodes, rtt, hist, in, second); // выпал 9:xray → локация h:9 → лучший по рангу = awg
        CHECK(p && p->nodeId == QLatin1String("9:awg"));
        p = pickTransportNode(nodes, rtt, hist, in, third);
        CHECK(p && p->nodeId == QLatin1String("2:awg"));

        // 3b) RTT: локация с минимальным замером
        rtt = {{QStringLiteral("2:awg"), 30}, {QStringLiteral("9:awg"), 50}, {QStringLiteral("9:xray"), 45}};
        p = pickTransportNode(nodes, rtt, hist, in);
        CHECK(p && p->nodeId == QLatin1String("2:awg"));
        rtt[QStringLiteral("2:awg")] = 60;
        p = pickTransportNode(nodes, rtt, hist, in); // h:9 (45) → внутри по рангу → awg, хотя xray быстрее на 5мс
        CHECK(p && p->nodeId == QLatin1String("9:awg"));

        // 3c) серверный ранг перекрывает дефолт: xray rank 5 → xray первым
        QList<SubscriptionNode> ranked = nodes;
        for (SubscriptionNode &n : ranked)
            if (n.nodeId == QLatin1String("9:xray")) n.transportRank = 5;
        p = pickTransportNode(ranked, rtt, hist, in);
        CHECK(p && p->nodeId == QLatin1String("9:xray"));

        // 3d) история: awg в h:9 дважды провалился → демоут → xray (20 < 110)
        hist.record(QStringLiteral("h:9"), QStringLiteral("awg"), false, -1, 1);
        hist.record(QStringLiteral("h:9"), QStringLiteral("awg"), false, -1, 2);
        p = pickTransportNode(nodes, rtt, hist, in);
        CHECK(p && p->nodeId == QLatin1String("9:xray"));
        hist.clear();

        // 3e) ручные режимы
        in.mode = TransportMode::Xray;
        p = pickTransportNode(nodes, rtt, hist, in);
        CHECK(p && p->nodeId == QLatin1String("9:xray"));
        in.mode = TransportMode::Awg;
        rtt[QStringLiteral("9:xray")] = 1; // приманка: xray быстрее всех
        p = pickTransportNode(nodes, rtt, hist, in);
        CHECK(p && p->nodeId == QLatin1String("9:awg"));
        in.mode = TransportMode::Xray;
        const QList<SubscriptionNode> awgOnly = parseNodes(subJson({ awgNodeJson("2:awg", 2, "PL", 1.0) }));
        CHECK(pickTransportNode(awgOnly, rtt, hist, in) == nullptr); // честно пусто
        in.mode = TransportMode::Auto;

        // 3f) kill-switch transport_auto_pick=false: авто не берёт xray даже с лучшим RTT
        setFlags(true, false);
        p = pickTransportNode(nodes, rtt, hist, in);
        CHECK(p && p->nodeId != QLatin1String("9:xray"));
        const QList<SubscriptionNode> xrayOnly = parseNodes(subJson({ xrayNodeJson("9:xray", 9, "EE", 1.0) }));
        CHECK(pickTransportNode(xrayOnly, rtt, hist, in) == nullptr);
        in.mode = TransportMode::Xray; // ручной режим — рубильник автоматики не касается
        p = pickTransportNode(xrayOnly, rtt, hist, in);
        CHECK(p && p->nodeId == QLatin1String("9:xray"));
        in.mode = TransportMode::Auto;
        in.preferLocation = QStringLiteral("h:9"); // pin тоже явная воля — xray допустим
        in.excluded.insert(QStringLiteral("9:awg"));
        p = pickTransportNode(nodes, rtt, hist, in);
        CHECK(p && p->nodeId == QLatin1String("9:xray"));
        in.excluded.clear();
        in.preferLocation.clear();
        // 3g) kill-switch xray_client=false: xray нигде, даже в ручном режиме
        setFlags(false, true);
        in.mode = TransportMode::Xray;
        CHECK(pickTransportNode(nodes, rtt, hist, in) == nullptr);
        in.mode = TransportMode::Auto;
        p = pickTransportNode(nodes, rtt, hist, in);
        CHECK(p && p->nodeId != QLatin1String("9:xray"));
        setFlags(true, true);

        // 3h) pin по локации + исключения (failover внутри локации)
        rtt = {{QStringLiteral("2:awg"), 30}, {QStringLiteral("9:awg"), 50}, {QStringLiteral("9:xray"), 45}};
        in.preferLocation = QStringLiteral("h:9");
        in.preferNodeId = QStringLiteral("9:xray");
        p = pickTransportNode(nodes, rtt, hist, in); // ранг важнее предпочтённого узла
        CHECK(p && p->nodeId == QLatin1String("9:awg"));
        in.excluded.insert(QStringLiteral("9:awg"));
        p = pickTransportNode(nodes, rtt, hist, in);
        CHECK(p && p->nodeId == QLatin1String("9:xray"));
        in.excluded.insert(QStringLiteral("9:xray"));
        CHECK(pickTransportNode(nodes, rtt, hist, in) == nullptr); // локация исчерпана → вызывающий идёт дальше
        in.preferLocation.clear();
        in.preferNodeId.clear();
        p = pickTransportNode(nodes, rtt, hist, in); // соседняя локация
        CHECK(p && p->nodeId == QLatin1String("2:awg"));
        in.excluded.clear();

        // 3i) manual_only-ярус: RU только фолбэком
        const QList<SubscriptionNode> withRu = parseNodes(subJson({
            awgNodeJson("ru", 4, "RU", 9.0), awgNodeJson("2:awg", 2, "PL", 1.0) }));
        QHash<QString, int> rttRu{{QStringLiteral("ru"), 5}};
        p = pickTransportNode(withRu, rttRu, hist, in);
        CHECK(p && p->nodeId == QLatin1String("2:awg"));
        const QList<SubscriptionNode> ruOnly = parseNodes(subJson({ awgNodeJson("ru", 4, "RU", 9.0) }));
        p = pickTransportNode(ruOnly, rttRu, hist, in);
        CHECK(p && p->nodeId == QLatin1String("ru"));
        // pin на RU-локацию — manual разрешён
        in.preferLocation = QStringLiteral("h:4");
        p = pickTransportNode(withRu, rttRu, hist, in);
        CHECK(p && p->nodeId == QLatin1String("ru"));
        in.preferLocation.clear();

        // 3j) мёртвая нода (health 0) не кандидат; исключения exclA/exclB
        QList<SubscriptionNode> dead = nodes;
        for (SubscriptionNode &n : dead)
            if (n.nodeId == QLatin1String("9:awg")) n.health.insert(QStringLiteral("telegram"), 0.0);
        rtt = {{QStringLiteral("9:awg"), 1}, {QStringLiteral("9:xray"), 45}, {QStringLiteral("2:awg"), 60}};
        p = pickTransportNode(dead, rtt, hist, in);
        CHECK(p && p->nodeId == QLatin1String("9:xray"));
        in.exclA = QStringLiteral("9:xray");
        p = pickTransportNode(dead, rtt, hist, in);
        CHECK(p && p->nodeId == QLatin1String("2:awg"));
        in.exclA.clear();
    }

    // --- 4) nextLiveNodeId: кольцо по ЛОКАЦИЯМ (xray той же локации — не «следующий сервер») ---
    {
        const QList<SubscriptionNode> nodes = parseNodes(subJson({
            awgNodeJson("9:awg", 9, "EE", 1.0), xrayNodeJson("9:xray", 9, "EE", 1.0),
            awgNodeJson("2:awg", 2, "PL", 1.0), awgNodeJson("5:awg", 5, "US", 1.0) }));
        // равные weight/health → порядок по nodeId представителей: 2:awg, 5:awg, 9:awg
        CHECK(nextLiveNodeId(nodes, QStringLiteral("9:awg")) == QLatin1String("2:awg"));
        CHECK(nextLiveNodeId(nodes, QStringLiteral("9:xray")) == QLatin1String("2:awg")); // та же локация
        CHECK(nextLiveNodeId(nodes, QStringLiteral("2:awg")) == QLatin1String("5:awg"));
        CHECK(nextLiveNodeId(nodes, QStringLiteral("5:awg")) == QLatin1String("9:awg"));
        // ручной режим xray: кольцо только из локаций с xray → единственная → некуда с неё
        CHECK(nextLiveNodeId(nodes, QStringLiteral("9:xray"), TransportMode::Xray).isEmpty());
        CHECK(nextLiveNodeId(nodes, QStringLiteral("2:awg"), TransportMode::Xray) == QLatin1String("9:xray"));
        // одна локация с двумя транспортами → ротировать некуда
        const QList<SubscriptionNode> one = parseNodes(subJson({
            awgNodeJson("9:awg", 9, "EE", 1.0), xrayNodeJson("9:xray", 9, "EE", 1.0) }));
        CHECK(nextLiveNodeId(one, QStringLiteral("9:awg")).isEmpty());
    }

    // --- 5) ServiceEngine: авто-коннект по рангу, xray → Verifying → Connected ---
    {
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson({ awgNodeJson("9:awg", 9, "EE", 1.0),
                                             xrayNodeJson("9:xray", 9, "EE", 1.0),
                                             awgNodeJson("2:awg", 2, "PL", 1.0) }), err));
        eng.setMeasuredRtt({{QStringLiteral("9:awg"), 40}, {QStringLiteral("9:xray"), 40},
                            {QStringLiteral("2:awg"), 80}});
        CHECK(eng.connect(err));
        CHECK(tun.lastUpNodeId == QLatin1String("9:awg"));
        CHECK(eng.onTunnelConnected());
        CHECK(eng.state() == EngineState::Connected); // awg: verifying не нужен
        CHECK(!eng.isVerifying());
        CHECK(eng.currentNodeProto() == QLatin1String("awg"));
        CHECK(eng.currentLocation() == QLatin1String("h:9"));
        CHECK(eng.recordTransportOutcome(true));
        CHECK(eng.transportHistoryDirty());
        CHECK(eng.transportHistory().entry(QStringLiteral("h:9"), QStringLiteral("awg")).samples == 1);
        eng.clearTransportHistoryDirty();

        // health-DEAD на awg → другой транспорт ТОЙ ЖЕ локации (xray), не соседняя локация
        tun.st = mkStats(0, 100, 100);
        CHECK(!eng.tick(1000));
        tun.st = mkStats(0, 100, 200);
        CHECK(!eng.tick(1004));
        tun.st = mkStats(0, 100, 300);
        CHECK(eng.tick(1008)); // 2 плохих цикла → DEAD
        CHECK(eng.state() == EngineState::Switching);
        CHECK(tun.downCalls == 1);
        CHECK(eng.transportHistory().entry(QStringLiteral("h:9"), QStringLiteral("awg")).samples == 2);
        CHECK(eng.onTunnelDisconnected()); // continuePendingSwitch → up(9:xray)
        CHECK(tun.lastUpNodeId == QLatin1String("9:xray"));
        CHECK(eng.onTunnelConnected());
        CHECK(eng.state() == EngineState::Verifying); // xray: «Подключено» только после пробы
        CHECK(eng.isVerifying());
        CHECK(eng.debugSnapshot().state == QLatin1String("verifying"));
        CHECK(eng.debugSnapshot().verifying);
        CHECK(!eng.tick(1020)); // в verifying health не тикает
        CHECK(eng.verifySucceeded());
        CHECK(eng.state() == EngineState::Connected);
        CHECK(eng.debugSnapshot().activeProto == QLatin1String("xray"));
        CHECK(eng.transportHistory().entry(QStringLiteral("h:9"), QStringLiteral("xray")).successEwma == 1.0);

        // снапшот пикера: hostId/location/transports/activeProto/transportRank
        const DebugSnapshot s = eng.debugSnapshot();
        bool rowsOk = true;
        for (const NodeDebugRow &r : s.pool) {
            if (r.nodeId == QLatin1String("9:awg")) {
                rowsOk = rowsOk && r.hostId == 9 && r.location == QLatin1String("h:9")
                         && r.transports == QStringList({QStringLiteral("awg"), QStringLiteral("xray")})
                         && r.activeProto == QLatin1String("xray") && r.transportRank == 10
                         && r.transportSupported && r.protoVersion == QLatin1String("3.1");
            } else if (r.nodeId == QLatin1String("9:xray")) {
                rowsOk = rowsOk && r.current && r.transportRank == 20 && r.protoVersion.isEmpty();
            } else if (r.nodeId == QLatin1String("2:awg")) {
                rowsOk = rowsOk && r.activeProto.isEmpty() && r.transports == QStringList{QStringLiteral("awg")};
            }
        }
        CHECK(rowsOk);
        CHECK(s.transportMode == QLatin1String("auto"));

        // DEAD по провалу проб на xray: N=3 (дефолт) провалов подряд → failover; успех сбрасывает
        CHECK(!eng.feedProbeResult(false));
        CHECK(!eng.feedProbeResult(true));
        CHECK(!eng.feedProbeResult(false));
        CHECK(!eng.feedProbeResult(false));
        CHECK(eng.feedProbeResult(false)); // третий подряд
        CHECK(eng.state() == EngineState::Switching);
        // awg h:9 провалился в этой сессии → следующая — соседняя локация
        CHECK(eng.onTunnelDisconnected());
        CHECK(tun.lastUpNodeId == QLatin1String("2:awg"));
        CHECK(eng.onTunnelConnected() && eng.state() == EngineState::Connected);
        CHECK(eng.recordTransportOutcome(true));
    }

    // --- 6) verifyFailed: xray не прошёл пробу → другой транспорт той же локации ---
    {
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson({ awgNodeJson("9:awg", 9, "EE", 1.0),
                                             xrayNodeJson("9:xray", 9, "EE", 1.0, /*rank=*/5),
                                             awgNodeJson("2:awg", 2, "PL", 1.0) }), err));
        eng.setMeasuredRtt({{QStringLiteral("9:awg"), 40}, {QStringLiteral("9:xray"), 40},
                            {QStringLiteral("2:awg"), 80}});
        CHECK(eng.connect(err));
        CHECK(tun.lastUpNodeId == QLatin1String("9:xray")); // серверный ранг: xray первым
        CHECK(eng.onTunnelConnected() && eng.state() == EngineState::Verifying);
        CHECK(eng.verifyFailed());
        CHECK(eng.state() == EngineState::Switching);
        CHECK(tun.downCalls == 1);
        CHECK(eng.transportHistory().entry(QStringLiteral("h:9"), QStringLiteral("xray")).successEwma == 0.0);
        CHECK(eng.onTunnelDisconnected());
        CHECK(tun.lastUpNodeId == QLatin1String("9:awg")); // та же локация, другой транспорт
        CHECK(eng.onTunnelConnected() && eng.state() == EngineState::Connected);
        // verifySucceeded/verifyFailed вне Verifying — no-op
        CHECK(!eng.verifySucceeded());
        CHECK(!eng.verifyFailed());
        // Disconnected из Verifying — честный терминал (внешний обрыв)
        ServiceEngine eng2;
        FakeTunnel tun2;
        eng2.setTunnel(&tun2);
        CHECK(eng2.loadSubscription(subJson({ xrayNodeJson("9:xray", 9, "EE", 1.0) }), err));
        CHECK(eng2.connect(err));
        CHECK(eng2.onTunnelConnected() && eng2.state() == EngineState::Verifying);
        CHECK(eng2.onTunnelDisconnected());
        CHECK(eng2.state() == EngineState::Disconnected);
        CHECK(eng2.currentNodeId().isEmpty());
        // Error из Verifying
        CHECK(eng2.connect(err));
        CHECK(eng2.onTunnelConnected() && eng2.state() == EngineState::Verifying);
        CHECK(eng2.onTunnelError());
        CHECK(eng2.state() == EngineState::Error);
        // requestStop из Verifying
        CHECK(eng2.connect(err));
        CHECK(eng2.onTunnelConnected() && eng2.state() == EngineState::Verifying);
        eng2.requestStop();
        CHECK(eng2.state() == EngineState::Disconnected && !eng2.isVerifying());
        // повторный Connected в Verifying (iOS Reconnecting→Connected) — не адопт, остаёмся в Verifying
        CHECK(eng2.connect(err));
        CHECK(eng2.onTunnelConnected() && eng2.state() == EngineState::Verifying);
        CHECK(!eng2.onTunnelConnected());
        CHECK(!eng2.adoptTunnelConnected());
        CHECK(eng2.state() == EngineState::Verifying);
        CHECK(eng2.verifySucceeded() && eng2.state() == EngineState::Connected);
    }

    // --- 7) ручной режим + pin по локации + честные ошибки ---
    {
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson({ awgNodeJson("9:awg", 9, "EE", 1.0),
                                             xrayNodeJson("9:xray", 9, "EE", 1.0),
                                             awgNodeJson("2:awg", 2, "PL", 1.0),
                                             xrayNodeJson("7:xray", 7, "NL", 1.0) }), err));
        eng.setMeasuredRtt({{QStringLiteral("2:awg"), 10}, {QStringLiteral("9:awg"), 40},
                            {QStringLiteral("9:xray"), 40}, {QStringLiteral("7:xray"), 90}});
        // ручной xray
        eng.setTransportMode(TransportMode::Xray);
        CHECK(eng.transportMode() == TransportMode::Xray);
        CHECK(eng.debugSnapshot().transportMode == QLatin1String("xray"));
        CHECK(eng.connect(err));
        CHECK(tun.lastUpNodeId == QLatin1String("9:xray"));
        eng.requestStop();
        // ручной awg + pin на локацию, где только xray (7) → no_transport
        eng.setTransportMode(TransportMode::Awg);
        QString pinErr;
        CHECK(!eng.setPinnedNode(QStringLiteral("7:xray"), pinErr));
        CHECK(pinErr.startsWith(QLatin1String("no_transport")));
        CHECK(eng.pinnedNodeId().isEmpty());
        // ручной awg + pin на xray-узел локации, где есть awg → pin по локации OK, коннект на awg
        CHECK(eng.setPinnedNode(QStringLiteral("9:xray"), pinErr));
        CHECK(eng.pinnedLocation() == QLatin1String("h:9"));
        CHECK(eng.connect(err));
        CHECK(tun.lastUpNodeId == QLatin1String("9:awg"));
        eng.requestStop();
        // авто + ручной режим xray: pin на awg-только локацию → no_transport; авто-коннект без pin — xray
        eng.setTransportMode(TransportMode::Xray);
        CHECK(!eng.setPinnedNode(QStringLiteral("2:awg"), pinErr));
        CHECK(pinErr.startsWith(QLatin1String("no_transport")));
        eng.clearPin();
        CHECK(eng.connect(err));
        CHECK(tun.lastUpNodeId == QLatin1String("9:xray")); // 9 быстрее 7
        eng.requestStop();
        // ручной xray, пул без xray → честный no_transport, туннель не трогаем
        ServiceEngine eng2;
        FakeTunnel tun2;
        eng2.setTunnel(&tun2);
        CHECK(eng2.loadSubscription(subJson({ awgNodeJson("2:awg", 2, "PL", 1.0) }), err));
        eng2.setTransportMode(TransportMode::Xray);
        CHECK(!eng2.connect(err));
        CHECK(err.startsWith(QLatin1String("no_transport")));
        CHECK(eng2.state() == EngineState::Error);
        CHECK(tun2.upCalls == 0);
        // kill-switch xray_client=false: pin на xray-узел локации с awg — OK (локация), без awg — unsupported_proto
        setFlags(false, true);
        eng.setTransportMode(TransportMode::Auto);
        CHECK(eng.setPinnedNode(QStringLiteral("9:xray"), pinErr));
        CHECK(eng.connect(err));
        CHECK(tun.lastUpNodeId == QLatin1String("9:awg"));
        eng.requestStop();
        CHECK(!eng.setPinnedNode(QStringLiteral("7:xray"), pinErr));
        CHECK(pinErr.startsWith(QLatin1String("unsupported_proto")));
        setFlags(true, true);
        // неизвестный proto — как раньше unsupported_proto
        Subscription tmp;
        QByteArray vless = xrayNodeJson("v-1", 8, "DE", 1.0);
        vless.replace(QByteArray("\"proto\": \"xray\""), QByteArray("\"proto\": \"vless\""));
        CHECK(eng.loadSubscription(subJson({ awgNodeJson("2:awg", 2, "PL", 1.0), vless }), err));
        CHECK(!eng.setPinnedNode(QStringLiteral("v-1"), pinErr));
        CHECK(pinErr.startsWith(QLatin1String("unsupported_proto")));
    }

    // --- 8) kill-switch transport_auto_pick=false: авто = только awg, xray — ручной режим ---
    {
        setFlags(true, false);
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson({ awgNodeJson("9:awg", 9, "EE", 1.0),
                                             xrayNodeJson("9:xray", 9, "EE", 1.0, /*rank=*/1) }), err));
        eng.setMeasuredRtt({{QStringLiteral("9:xray"), 5}, {QStringLiteral("9:awg"), 90}});
        CHECK(eng.connect(err));
        CHECK(tun.lastUpNodeId == QLatin1String("9:awg"));
        eng.requestStop();
        eng.setTransportMode(TransportMode::Xray);
        CHECK(eng.connect(err));
        CHECK(tun.lastUpNodeId == QLatin1String("9:xray"));
        setFlags(true, true);
    }

    // --- 9) rotateNext / nextLiveNodeId движка: по локациям ---
    {
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson({ awgNodeJson("9:awg", 9, "EE", 1.0),
                                             xrayNodeJson("9:xray", 9, "EE", 1.0),
                                             awgNodeJson("2:awg", 2, "PL", 1.0) }), err));
        eng.setMeasuredRtt({{QStringLiteral("9:awg"), 40}, {QStringLiteral("9:xray"), 40},
                            {QStringLiteral("2:awg"), 80}});
        CHECK(eng.connect(err));
        CHECK(tun.lastUpNodeId == QLatin1String("9:awg"));
        CHECK(eng.onTunnelConnected());
        CHECK(eng.nextLiveNodeId() == QLatin1String("2:awg"));
        QString rotErr;
        CHECK(eng.rotateNext(rotErr));
        CHECK(eng.state() == EngineState::Switching);
        CHECK(eng.onTunnelDisconnected());
        CHECK(tun.lastUpNodeId == QLatin1String("2:awg"));
    }

    if (g_failed) {
        fprintf(stderr, "transport_pick_check: FAILED %d/%d\n", g_failed, g_total);
        return 1;
    }
    printf("transport_pick_check: OK (%d checks — история, локации, pick, режимы, kill-switch'и, verifying, probe-DEAD, ротация)\n",
           g_total);
    return 0;
}

// --- линк-стабы: сетевые части движка тестом не вызываются, но нужны линкеру (как failover_check). ---
namespace avpn {

bool Enrollment::enroll(QNetworkAccessManager *, const QString &, Identity &,
                        SecureAppSettingsRepository *, TrialResponse &, QString &error,
                        FetchOutcome *)
{
    error = QStringLiteral("stub");
    return false;
}

bool Enrollment::fetchSubscription(QNetworkAccessManager *, const QString &, const QString &,
                                   QByteArray &, QString &error, FetchOutcome *)
{
    error = QStringLiteral("stub");
    return false;
}

void Enrollment::saveLkgSubscription(const QByteArray &) { }

QString Enrollment::loadToken()
{
    return {};
}

void Enrollment::clearToken() { }

bool Identity::ensureKeys(SecureAppSettingsRepository *, QString &)
{
    return true;
}

} // namespace avpn
