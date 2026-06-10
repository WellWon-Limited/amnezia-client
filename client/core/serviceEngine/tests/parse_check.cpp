// AVPN serviceEngine — автономная проверка парсера подписки (без Qt Test, только QtCore).
// Сборка/запуск: core/serviceEngine/tests/build_check.sh
#include "../AwgConfigBuilder.h"
#include "../Enrollment.h"
#include "../HealthLoop.h"
#include "../Selector.h"
#include "../SubscriptionParser.h"

#include <QCoreApplication>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <cstdio>

using namespace avpn;

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    const QString path = argc > 1 ? QString::fromLocal8Bit(argv[1])
                                  : QStringLiteral("fixtures/subscription.example.json");
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) {
        fprintf(stderr, "FAIL: cannot open %s\n", path.toUtf8().constData());
        return 2;
    }

    Subscription sub;
    QString err;
    if (!SubscriptionParser::parse(f.readAll(), sub, err)) {
        fprintf(stderr, "FAIL: parse error: %s\n", err.toUtf8().constData());
        return 1;
    }

    printf("parsed: version=%d address=%s status=%s nodes=%d traffic.used=%lld limit=%lld\n",
           sub.version,
           sub.address.value(0).toUtf8().constData(),
           sub.status == SubStatus::Degraded ? "degraded" : "active",
           int(sub.nodes.size()),
           static_cast<long long>(sub.trafficUsed),
           static_cast<long long>(sub.trafficLimit));

    bool ok = sub.version == 1 && sub.address.value(0) == QLatin1String("10.7.0.5/32")
              && sub.nodes.size() == 1;
    if (!sub.nodes.isEmpty()) {
        const SubscriptionNode &n = sub.nodes.first();
        printf("node0: id=%s endpoint=%s dns=%d awgFullBundle=%d keepalive=%d health.telegram=%.2f\n",
               n.nodeId.toUtf8().constData(), n.endpoint.toUtf8().constData(),
               int(n.dns.size()), n.awg.hasFullBundle() ? 1 : 0, n.persistentKeepalive,
               n.health.value(QStringLiteral("telegram"), -1.0));
        ok = ok && n.nodeId == QLatin1String("fra-01") && n.awg.hasFullBundle()
             && n.dns.size() == 2 && n.persistentKeepalive == 25;
    }

    const QStringList issues = SubscriptionParser::validate(sub);
    printf("validate issues: %d\n", int(issues.size()));
    for (const QString &i : issues)
        printf("  - %s\n", i.toUtf8().constData());

    if (!ok) { fprintf(stderr, "FAIL: parsed values mismatch\n"); return 4; }
    if (!issues.isEmpty()) { fprintf(stderr, "FAIL: unexpected validation issues\n"); return 3; }

    // --- AwgConfigBuilder: DTO -> QJsonObject для VpnConnection::connectToVpn ---
    if (!sub.nodes.isEmpty()) {
        const ClientKeys keys{QStringLiteral("PRIVb64..."), QStringLiteral("PUBb64...")};
        const QJsonObject cfg = AwgConfigBuilder::build(sub, sub.nodes.first(), keys);
        const QJsonObject inner = cfg.value(QStringLiteral("awg_config_data")).toObject();
        printf("config: protocol=%s host=%s port=%d dns2=%s isObf=%d innerKeys=%d\n",
               cfg.value(QStringLiteral("protocol")).toString().toUtf8().constData(),
               inner.value(QStringLiteral("hostName")).toString().toUtf8().constData(),
               inner.value(QStringLiteral("port")).toInt(),
               cfg.value(QStringLiteral("dns2")).toString().toUtf8().constData(),
               inner.value(QStringLiteral("isObfuscationEnabled")).toBool() ? 1 : 0,
               inner.size());
        const QString wg = inner.value(QStringLiteral("config")).toString();
        bool cfgOk = cfg.value(QStringLiteral("protocol")).toString() == QLatin1String("awg")
                     && inner.value(QStringLiteral("hostName")).toString() == QLatin1String("203.0.113.10")
                     && inner.value(QStringLiteral("port")).toInt() == 51820
                     && inner.value(QStringLiteral("client_ip")).toString() == QLatin1String("10.7.0.5/32")
                     && inner.value(QStringLiteral("Jc")).toInt() == 4
                     && inner.value(QStringLiteral("isObfuscationEnabled")).toBool()
                     && !cfg.value(QStringLiteral("dns2")).toString().isEmpty()
                     && wg.contains(QLatin1String("[Interface]")) && wg.contains(QLatin1String("Jc = 4"))
                     && wg.contains(QLatin1String("Endpoint = 203.0.113.10:51820"));
        if (!cfgOk) { fprintf(stderr, "FAIL: AwgConfigBuilder output mismatch\n"); return 5; }
        printf("config builder: OK (inner has client_ip/keys/awg, dns2 present, wg-quick text valid)\n");
    }

    // --- Enrollment: чистые builders/parsers ---
    {
        const QByteArray body = Enrollment::buildTrialBody(
            QStringLiteral("PUBKEY=="), QStringLiteral("dev-123"), Enrollment::detectPlatform());
        const QJsonObject bo = QJsonDocument::fromJson(body).object();
        TrialResponse tr;
        QString terr;
        const QByteArray sample = R"({"subscription_token":"tok_abc","account_id":"acc_1","expires_at":"2026-09-01T00:00:00Z","traffic_limit":104857600})";
        const bool tok = Enrollment::parseTrialResponse(sample, tr, terr);
        printf("enroll: body.public_key=%s platform=%s | resp.token=%s limit=%lld\n",
               bo.value(QStringLiteral("public_key")).toString().toUtf8().constData(),
               bo.value(QStringLiteral("platform")).toString().toUtf8().constData(),
               tr.subscriptionToken.toUtf8().constData(), (long long)tr.trafficLimit);
        bool eOk = bo.value(QStringLiteral("public_key")).toString() == QLatin1String("PUBKEY==")
                   && bo.value(QStringLiteral("device_id")).toString() == QLatin1String("dev-123")
                   && !bo.value(QStringLiteral("platform")).toString().isEmpty()
                   && tok && tr.subscriptionToken == QLatin1String("tok_abc")
                   && tr.trafficLimit == 104857600;
        if (!eOk) { fprintf(stderr, "FAIL: Enrollment build/parse mismatch (%s)\n", terr.toUtf8().constData()); return 6; }
        printf("enrollment: OK (trial body built, response parsed)\n");
    }

    // --- Selector: чистые score()/choose() (детерминированно) ---
    {
        auto mk = [](const QString &id, int rtt, double w) {
            ScoredNodeS s; s.node.nodeId = id; s.node.weight = w; s.rttMs = rtt;
            s.score = (rtt < 0) ? 0.0 : Selector::score(rtt, w);
            return s;
        };
        // score = rtt/weight
        bool sOk = qFuzzyCompare(Selector::score(100, 2.0), 50.0)
                   && qFuzzyCompare(Selector::score(100, 0.0), 100.0); // weight<=0 → 1
        // выбор лучшего по score (B: 60/1=60 < A:100/1=100, C недостижим)
        QList<ScoredNodeS> set{mk("A", 100, 1.0), mk("B", 60, 1.0), mk("C", -1, 1.0)};
        auto pick1 = Selector::choose(set, QString(), 75, 0);
        // гистерезис: текущая A (100), лучшая B (60). разница 40 ≤ tolerance 75 → остаёмся на A
        auto pickHyst = Selector::choose(set, QStringLiteral("A"), 75, 0);
        // без допуска (tolerance 10): 40 > 10 → переключаемся на B
        auto pickSwitch = Selector::choose(set, QStringLiteral("A"), 10, 0);
        // джиттер: две near-equal (A100,D110 при tol 75 → группа {лучшая=A, D}), seed=1 → второй (D)
        QList<ScoredNodeS> tie{mk("A", 100, 1.0), mk("D", 110, 1.0)};
        auto pickJit0 = Selector::choose(tie, QString(), 75, 0);
        auto pickJit1 = Selector::choose(tie, QString(), 75, 1);
        printf("selector: best=%s hyst=%s switch=%s jit0=%s jit1=%s\n",
               pick1 ? pick1->nodeId.toUtf8().constData() : "-",
               pickHyst ? pickHyst->nodeId.toUtf8().constData() : "-",
               pickSwitch ? pickSwitch->nodeId.toUtf8().constData() : "-",
               pickJit0 ? pickJit0->nodeId.toUtf8().constData() : "-",
               pickJit1 ? pickJit1->nodeId.toUtf8().constData() : "-");
        bool selOk = sOk
                     && pick1 && pick1->nodeId == QLatin1String("B")
                     && pickHyst && pickHyst->nodeId == QLatin1String("A")
                     && pickSwitch && pickSwitch->nodeId == QLatin1String("B")
                     && pickJit0 && pickJit0->nodeId == QLatin1String("A")
                     && pickJit1 && pickJit1->nodeId == QLatin1String("D")
                     && !Selector::choose({mk("X", -1, 1.0)}, QString(), 75, 0).has_value(); // все недостижимы → nullopt
        if (!selOk) { fprintf(stderr, "FAIL: Selector score/choose mismatch\n"); return 7; }
        printf("selector: OK (score, best-pick, hysteresis, switch, jitter, all-down=none)\n");

        // живой TCP-ping smoke (best-effort: сеть может быть недоступна в песочнице — не валит тест)
        int rtt = Prober::tcpPing(QStringLiteral("1.1.1.1"), 443, 1500);
        printf("tcpPing 1.1.1.1:443 -> %d ms (%s)\n", rtt, rtt >= 0 ? "reachable" : "n/a (offline?)");
    }

    // --- HealthLoop: DEAD-детект по последовательности замеров (детерминированно) ---
    {
        const qint64 now = 1000000;
        auto S = [](qint64 hs, qint64 rx, qint64 tx) {
            TunnelStats s; s.latestHandshakeEpoch = hs; s.rxBytes = rx; s.txBytes = tx; s.valid = true; return s;
        };
        // one-way death (handshake неизвестен=0): tx растёт, rx стоит → DEAD после 2 «плохих» циклов
        HealthLoop h1; h1.feed(S(0, 100, 100), now); h1.feed(S(0, 100, 200), now);
        bool dead1 = h1.feed(S(0, 100, 300), now);
        // здоровый: rx растёт → не DEAD
        HealthLoop h2; h2.feed(S(0, 100, 100), now); h2.feed(S(0, 200, 200), now);
        bool dead2 = h2.feed(S(0, 300, 300), now);
        // простой: tx не растёт → не DEAD
        HealthLoop h3; h3.feed(S(0, 100, 100), now); bool dead3 = h3.feed(S(0, 100, 100), now);
        // свежий handshake: tx растёт, rx стоит, но hs свежий (<180с) → не DEAD
        HealthLoop h4; h4.feed(S(now - 10, 100, 100), now); h4.feed(S(now - 5, 100, 200), now);
        bool dead4 = h4.feed(S(now - 3, 100, 300), now);
        printf("health: dead1=%d dead2=%d dead3=%d dead4=%d\n", dead1, dead2, dead3, dead4);

        // Selector: исключение мёртвой ноды — лучшая B исключена → выбираем A
        auto mk = [](const QString &id, int rtt, double w) {
            ScoredNodeS s; s.node.nodeId = id; s.node.weight = w; s.rttMs = rtt; s.score = Selector::score(rtt, w); return s;
        };
        auto exPick = Selector::choose({mk("A", 100, 1.0), mk("B", 60, 1.0)}, QString(), 75, 0, QStringLiteral("B"));
        printf("health/exclude: exPick=%s\n", exPick ? exPick->nodeId.toUtf8().constData() : "-");

        bool hOk = dead1 && !dead2 && !dead3 && !dead4 && exPick && exPick->nodeId == QLatin1String("A");
        if (!hOk) { fprintf(stderr, "FAIL: HealthLoop/exclude mismatch\n"); return 8; }
        printf("healthloop: OK (one-way death→DEAD, healthy/idle/fresh-handshake→alive, exclude works)\n");
    }

    printf("OK: parsed + config + enrollment + selector + healthloop\n");
    return 0;
}
