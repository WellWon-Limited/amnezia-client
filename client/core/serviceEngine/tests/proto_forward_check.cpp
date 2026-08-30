// AVPN serviceEngine — автономная проверка форвард-совместимости по протоколу нод (Task 10,
// backend-first-3): бэкенд добавляет в пул xray-ноды (proto:"xray"), клиентский слой умеет только awg.
// Требования: нода с неизвестным proto НЕ роняет парс/валидацию всего ответа, ОСТАЁТСЯ в пуле
// (диагностика/будущая эскалация), но НИКОГДА не выбирается (auto-выбор, failover, ротация, pin).
// Фолбэк ОБРАТНЫЙ manual_only: неподдерживаемая нода непригодна в принципе (коннект невозможен) —
// если поддерживаемых нет, выбор честно пуст (штатная ветка «нет нод»), без падений.
// Сборка/запуск: core/serviceEngine/tests/build_proto_forward.sh
#include "../NodeRotation.h"
#include "../Selector.h"
#include "../ServiceEngine.h"
#include "../SubscriptionParser.h"

#include <QCoreApplication>
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
    int upCalls = 0;
    int downCalls = 0;
    TunnelResult up(const Subscription &, const SubscriptionNode &node) override
    {
        ++upCalls;
        lastUpNodeId = node.nodeId;
        return TunnelResult::success();
    }
    TunnelResult applyPeer(const Subscription &, const SubscriptionNode &node) override
    {
        lastUpNodeId = node.nodeId;
        return TunnelResult::success();
    }
    TunnelStats readStats() override { return {}; }
    void down() override { ++downCalls; }
};

// Полный awg-узел (валидный по контракту: endpoint/pubkey/dns/полный AWG-бандл).
static QByteArray awgNodeJson(const char *id, const char *cc, double weight)
{
    return QByteArray(R"({ "node_id": ")") + id + R"(", "region": "eu",
        "endpoint": "203.0.113.10:51820",
        "server_pubkey": "K1nDpUbLiCkEyExAmPlE0000000000000000000000=",
        "proto": "awg", "weight": )" + QByteArray::number(weight) + R"(,
        "country_code": ")" + cc + R"(",
        "allowed_ips": ["0.0.0.0/0", "::/0"], "dns": ["1.1.1.1", "1.0.0.1"],
        "mtu": 1280, "persistent_keepalive": 25,
        "awg_params": { "Jc": 4, "Jmin": 50, "Jmax": 1000, "S1": 86, "S2": 57,
                        "H1": 1, "H2": 2, "H3": 3, "H4": 4 } })";
}

// Xray-узел будущего контракта: НЕТ server_pubkey/dns/awg_params (awg-поля к нему неприменимы).
static QByteArray xrayNodeJson(const char *id, double weight)
{
    return QByteArray(R"({ "node_id": ")") + id + R"(", "region": "asia",
        "endpoint": "vision.example.com:443", "proto": "xray",
        "weight": )" + QByteArray::number(weight) + R"(, "country_code": "NL" })";
}

static QByteArray subJson(const QList<QByteArray> &nodes)
{
    QByteArray joined;
    for (int i = 0; i < nodes.size(); ++i) {
        if (i) joined += ",";
        joined += nodes[i];
    }
    return R"({ "version": 1, "address": ["10.7.0.5/32"], "status": "active",
        "expires_at": "2026-09-01T00:00:00Z", "traffic": { "used": 0, "limit": 0 },
        "nodes": [)" + joined + "] }";
}

static SubscriptionNode mkNode(const QString &id, const QString &proto)
{
    SubscriptionNode n;
    n.nodeId = id;
    n.proto = proto;
    return n;
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);

    // --- 1) хелпер: пустой proto = awg = поддерживается; неизвестный — нет ---
    {
        CHECK(isSupportedProtoNode(mkNode("a", QStringLiteral("awg"))));
        CHECK(isSupportedProtoNode(mkNode("b", QString())));      // легаси: поле не пришло
        CHECK(isSupportedProtoNode(mkNode("c", QStringLiteral("")))); // явная пустая строка
        CHECK(!isSupportedProtoNode(mkNode("d", QStringLiteral("xray"))));
        CHECK(!isSupportedProtoNode(mkNode("e", QStringLiteral("vless")))); // любой будущий proto
    }

    // --- 2) парс/валидация: 2 awg + 1 xray → парс ок, пул = 3, поле proto сохранено,
    //        validate() НЕ выдаёт мусорных awg-претензий к xray-ноде (ответ не «роняется») ---
    {
        Subscription sub;
        QString err;
        const QByteArray json = subJson({ awgNodeJson("fra-01", "DE", 1.0),
                                          awgNodeJson("hel-01", "FI", 2.0),
                                          xrayNodeJson("x-1", 9.0) });
        CHECK(SubscriptionParser::parse(json, sub, err));
        CHECK(sub.nodes.size() == 3);
        CHECK(sub.nodes.at(2).proto == QLatin1String("xray")); // сохранено для диагностики
        const QStringList issues = SubscriptionParser::validate(sub);
        for (const QString &i : issues)
            fprintf(stderr, "  unexpected issue: %s\n", i.toUtf8().constData());
        CHECK(issues.isEmpty()); // xray без pubkey/dns/бандла — НЕ проблема (awg-контракт неприменим)

        // proto отсутствует → дефолт "awg" (легаси-тела без поля).
        Subscription legacy;
        QByteArray noProto = awgNodeJson("old-01", "DE", 1.0);
        noProto.replace(QByteArray("\"proto\": \"awg\","), QByteArray());
        CHECK(SubscriptionParser::parse(subJson({ noProto }), legacy, err));
        CHECK(legacy.nodes.size() == 1 && legacy.nodes.first().proto == QLatin1String("awg"));
    }

    // --- 3) Selector::choose: xray с лучшим score никогда не выбирается; все xray → nullopt ---
    {
        auto mk = [](const QString &id, const QString &proto, int rtt) {
            ScoredNodeS s;
            s.node = mkNode(id, proto);
            s.node.weight = 1.0;
            s.rttMs = rtt;
            s.score = Selector::score(rtt, 1.0);
            return s;
        };
        // xray быстрее всех — приманка: выбрать НЕЛЬЗЯ.
        auto pick = Selector::choose({ mk("x-1", QStringLiteral("xray"), 5),
                                       mk("a-1", QStringLiteral("awg"), 100),
                                       mk("a-2", QString(), 80) },
                                     QString(), 0, 0);
        CHECK(pick && pick->nodeId == QLatin1String("a-2"));
        // ТОЛЬКО xray → честно пусто (НЕ manual_only-фолбэк «оставить как есть»).
        auto none = Selector::choose({ mk("x-1", QStringLiteral("xray"), 5),
                                       mk("x-2", QStringLiteral("xray"), 7) },
                                     QString(), 0, 0);
        CHECK(!none.has_value());
    }

    // --- 4) nextLiveNodeId (ротация «Сменить сервер»): xray в кольцо не входит ---
    {
        auto liveAwg = [](const char *id) {
            SubscriptionNode n = mkNode(QLatin1String(id), QStringLiteral("awg"));
            n.weight = 1.0;
            return n;
        };
        SubscriptionNode xr = mkNode(QStringLiteral("x-1"), QStringLiteral("xray"));
        xr.weight = 9.0; // приманка: max weight
        const QList<SubscriptionNode> pool{ liveAwg("a-1"), liveAwg("a-2"), xr };
        CHECK(nextLiveNodeId(pool, QStringLiteral("a-1")) == QLatin1String("a-2"));
        CHECK(nextLiveNodeId(pool, QStringLiteral("a-2")) == QLatin1String("a-1"));
        // единственная альтернатива — xray → ротировать некуда.
        const QList<SubscriptionNode> pair{ liveAwg("a-1"), xr };
        CHECK(nextLiveNodeId(pair, QStringLiteral("a-1")).isEmpty());
    }

    // --- 5) connect(): авто-выбор не берёт xray ни по RTT-пути, ни по weight-фолбэку ---
    {
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson({ awgNodeJson("fra-01", "DE", 1.0),
                                             xrayNodeJson("x-1", 9.0) }),
                                   err));
        // RTT-путь: xray измерен лучшим — брать нельзя.
        QHash<QString, int> rtt;
        rtt.insert(QStringLiteral("x-1"), 5);
        rtt.insert(QStringLiteral("fra-01"), 90);
        eng.setMeasuredRtt(rtt);
        CHECK(eng.connect(err));
        CHECK(tun.lastUpNodeId == QLatin1String("fra-01"));

        // weight-фолбэк (кэш RTT пуст): xray с max weight — брать нельзя.
        ServiceEngine eng2;
        FakeTunnel tun2;
        eng2.setTunnel(&tun2);
        CHECK(eng2.loadSubscription(subJson({ awgNodeJson("fra-01", "DE", 1.0),
                                              xrayNodeJson("x-1", 9.0) }),
                                    err));
        CHECK(eng2.connect(err));
        CHECK(tun2.lastUpNodeId == QLatin1String("fra-01"));
    }

    // --- 6) пул ТОЛЬКО из xray: парс ок (пул не пуст), но выбор пуст → штатное «no nodes», без краша ---
    {
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson({ xrayNodeJson("x-1", 1.0), xrayNodeJson("x-2", 2.0) }),
                                   err));
        CHECK(eng.hasSubscription()); // ноды в пуле остались (диагностика)
        QHash<QString, int> rtt;
        rtt.insert(QStringLiteral("x-1"), 5);
        eng.setMeasuredRtt(rtt);
        CHECK(!eng.connect(err));
        printf("only-xray connect: err=%s\n", err.toUtf8().constData());
        CHECK(err == QLatin1String("no nodes available"));
        CHECK(eng.state() == EngineState::Error);
        CHECK(tun.upCalls == 0); // туннель на xray не поднимали
    }

    // --- 7) ручной pin: закрепить xray нельзя (коннект к ней невозможен — честная ошибка в UI) ---
    {
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson({ awgNodeJson("fra-01", "DE", 1.0),
                                             xrayNodeJson("x-1", 9.0) }),
                                   err));
        QString pinErr;
        CHECK(!eng.setPinnedNode(QStringLiteral("x-1"), pinErr));
        CHECK(!pinErr.isEmpty());
        CHECK(eng.pinnedNodeId().isEmpty());
        CHECK(eng.setPinnedNode(QStringLiteral("fra-01"), pinErr)); // awg по-прежнему закрепляется
    }

    // --- 8) failover: текущая умерла, xray с лучшим RTT — уходим на awg; альтернатив нет → Error ---
    {
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson({ awgNodeJson("cur", "FI", 5.0),
                                             awgNodeJson("fastA", "DE", 1.0),
                                             xrayNodeJson("x-1", 9.0) }),
                                   err));
        CHECK(eng.setPinnedNode(QStringLiteral("cur"), err));
        CHECK(eng.connect(err));
        eng.onTunnelConnected();
        CHECK(eng.state() == EngineState::Connected);

        QHash<QString, int> rtt;
        rtt.insert(QStringLiteral("x-1"), 5); // приманка
        rtt.insert(QStringLiteral("fastA"), 60);
        eng.setMeasuredRtt(rtt);
        CHECK(eng.notifyConnectionLost());
        CHECK(tun.lastUpNodeId == QLatin1String("fastA"));

        // единственная альтернатива — xray → failover честно не находит кандидата (Error, без краша).
        ServiceEngine eng2;
        FakeTunnel tun2;
        eng2.setTunnel(&tun2);
        CHECK(eng2.loadSubscription(subJson({ awgNodeJson("cur", "FI", 5.0),
                                              xrayNodeJson("x-1", 9.0) }),
                                    err));
        CHECK(eng2.setPinnedNode(QStringLiteral("cur"), err));
        CHECK(eng2.connect(err));
        eng2.onTunnelConnected();
        QHash<QString, int> rtt2;
        rtt2.insert(QStringLiteral("x-1"), 5);
        eng2.setMeasuredRtt(rtt2);
        const int upsBefore = tun2.upCalls;
        CHECK(!eng2.notifyConnectionLost());
        CHECK(eng2.state() == EngineState::Error);
        CHECK(tun2.upCalls == upsBefore); // на xray не поднимались
    }

    // --- 9) rotateNext: xray не считается «живой альтернативой» ---
    {
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson({ awgNodeJson("cur", "FI", 5.0),
                                             xrayNodeJson("x-1", 9.0) }),
                                   err));
        CHECK(eng.setPinnedNode(QStringLiteral("cur"), err));
        CHECK(eng.connect(err));
        eng.onTunnelConnected();
        QString rotErr;
        CHECK(!eng.rotateNext(rotErr)); // кроме xray ротировать не на что
        CHECK(tun.lastUpNodeId == QLatin1String("cur")); // up() на xray не было
    }

    // --- 10) monotonic v2 authority: после accepted v2 unsigned v1 не грузится/не стартует ---
    {
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        const QByteArray legacy = subJson({ awgNodeJson("old", "FI", 1.0) });
        CHECK(eng.loadSubscription(legacy, err));
        CHECK(eng.setPinnedNode(QStringLiteral("old"), err));
        CHECK(eng.legacyV1Allowed());
        eng.lockLegacyV1AfterAcceptedV2();
        CHECK(!eng.legacyV1Allowed());
        eng.clearPin();
        CHECK(eng.pinnedNodeId() == QLatin1String("old"));
        CHECK(!eng.loadSubscription(legacy, err));
        CHECK(!eng.connect(err));
        CHECK(!eng.rotateNext(err));
        CHECK(!eng.setPinnedNode(QStringLiteral("old"), err));
        CHECK(tun.upCalls == 0);
    }

    if (g_failed) {
        fprintf(stderr, "proto_forward_check: FAILED %d/%d\n", g_failed, g_total);
        return 1;
    }
    printf("proto_forward_check: OK (%d checks — парс/валидация с xray, хелпер, choose/pick*/ротация/pin/failover)\n",
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
