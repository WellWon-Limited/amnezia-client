// AVPN serviceEngine — автономная проверка парсера подписки (без Qt Test, только QtCore).
// Сборка/запуск: core/serviceEngine/tests/build_check.sh
#include "../AwgConfigBuilder.h"
#include "../BenchAnalysis.h" // AVPN (панель администратора): вердикты + A/B-сравнение замеров
#include "../BenchRunner.h" // AVPN (панель администратора): чистая математика бенча (median/mbit)
#include "../Enrollment.h"
#include "../GoodputProbe.h"
#include "../HealthLoop.h"
#include "../InstagramSource.h"
#include "../MtprotoProbe.h"
#include "../Selector.h"
#include "../SignalQuality.h"
#include "../SubscriptionParser.h"
#include "../YoutubeSource.h"
#include "../../utils/constants/protocolConstants.h" // AVPN: паритет-дефолты mtu (awg::defaultMtu)

#include <QCoreApplication>
#include <QFile>
#include <QJsonArray>
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
                     && inner.value(QStringLiteral("Jc")).toString() == QLatin1String("4") // AVPN: AWG-параметры — строки (контракт форка/iOS WGConfig)
                     && cfg.value(QStringLiteral("splitTunnelType")).toInt() == 0       // AVPN: iOS требует splitTunnelType в корне
                     && inner.value(QStringLiteral("isObfuscationEnabled")).toBool()
                     && !cfg.value(QStringLiteral("dns2")).toString().isEmpty()
                     && wg.contains(QLatin1String("[Interface]")) && wg.contains(QLatin1String("Jc = 4"))
                     && wg.contains(QLatin1String("Endpoint = 203.0.113.10:51820"));
        if (!cfgOk) { fprintf(stderr, "FAIL: AwgConfigBuilder output mismatch\n"); return 5; }
        printf("config builder: OK (inner has client_ip/keys/awg, dns2 present, wg-quick text valid)\n");
    }

    // --- AVPN parity: нода БЕЗ dns/mtu → билдер ОБЯЗАН подставить upstream-дефолты ---
    // Upstream подставляет их в ConnectionController::createConnectionConfiguration, который наш
    // service-путь ОБХОДИТ (VpnConnectionTunnelControl::invokeConnect → connectToVpn напрямую).
    // Без dns1 iOS WGConfig.swift (dns1/dns2 non-optional String) не декодится ⇒ туннель молча не
    // поднимается; без mtu демон берёт 1420 (daemon.cpp parseConfig) вместо awg-дефолта 1376/1280.
    if (!sub.nodes.isEmpty()) {
        const ClientKeys keys{QStringLiteral("PRIVb64..."), QStringLiteral("PUBb64...")};
        SubscriptionNode bare = sub.nodes.first();
        bare.dns.clear();
        bare.mtu = 0;
        const QJsonObject cfg = AwgConfigBuilder::build(sub, bare, keys);
        const QJsonObject inner = cfg.value(QStringLiteral("awg_config_data")).toObject();
        const QString wg = inner.value(QStringLiteral("config")).toString();
        const QString wantMtu = QLatin1String(amnezia::protocols::awg::defaultMtu);
        printf("defaults: dns1=%s dns2=%s mtu=%s (want %s)\n",
               cfg.value(QStringLiteral("dns1")).toString().toUtf8().constData(),
               cfg.value(QStringLiteral("dns2")).toString().toUtf8().constData(),
               inner.value(QStringLiteral("mtu")).toString().toUtf8().constData(),
               wantMtu.toUtf8().constData());
        const bool defOk = cfg.value(QStringLiteral("dns1")).toString() == QLatin1String("1.1.1.1")
                        && cfg.value(QStringLiteral("dns2")).toString() == QLatin1String("1.0.0.1")
                        && inner.value(QStringLiteral("mtu")).toString() == wantMtu
                        && wg.contains(QLatin1String("DNS = 1.1.1.1, 1.0.0.1"))
                        && wg.contains(QStringLiteral("MTU = %1").arg(wantMtu));
        if (!defOk) { fprintf(stderr, "FAIL: builder must inject upstream defaults (dns1/dns2/mtu)\n"); return 6; }
        printf("config builder defaults: OK (dns 1.1.1.1/1.0.0.1, mtu %s)\n", wantMtu.toUtf8().constData());
    }

    // --- AVPN bench v5: reportSummary — санитизированный дамп конфига для отчёта бенча ---
    // Даёт A/B с ванильной Amnezia интерпретируемость («mtu 1280 vs 1376», а не «TTFB хуже»).
    // ЖЁСТКО: ни ключей, ни endpoint-хоста, ни client_ip в выводе (отчёт уходит наружу).
    if (!sub.nodes.isEmpty()) {
        const SubscriptionNode &n = sub.nodes.first();
        const QJsonObject rep = AwgConfigBuilder::reportSummary(sub, n);
        const QJsonObject awg = rep.value(QStringLiteral("awg")).toObject();
        const QString flat = QString::fromUtf8(QJsonDocument(rep).toJson(QJsonDocument::Compact));
        printf("report summary: mtu=%d port=%d dns=%d jc=%d keys-leak=%d\n",
               rep.value(QStringLiteral("mtu")).toInt(), rep.value(QStringLiteral("port")).toInt(),
               int(rep.value(QStringLiteral("dns")).toArray().size()), awg.value(QStringLiteral("jc")).toInt(),
               flat.contains(QLatin1String("203.0.113.10")) ? 1 : 0);
        const bool repOk = rep.value(QStringLiteral("proto")).toString() == QLatin1String("awg")
                        && rep.value(QStringLiteral("mtu")).toInt() > 0            // эффективный (дефолт при 0)
                        && rep.value(QStringLiteral("port")).toInt() == 51820
                        && rep.value(QStringLiteral("keepalive")).toInt() == 25
                        && rep.value(QStringLiteral("dns")).toArray().size() == 2
                        && awg.value(QStringLiteral("jc")).toInt() == 4
                        && awg.contains(QStringLiteral("h1"))
                        && !flat.contains(QLatin1String("203.0.113.10"))           // endpoint-хост не течёт
                        && !flat.contains(QLatin1String("10.7.0.5"))               // client_ip не течёт
                        && !flat.contains(n.serverPubkey);                         // ключи не текут
        if (!repOk) { fprintf(stderr, "FAIL: reportSummary (sanitize/fields)\n"); return 5; }
        printf("report summary: OK (parity-поля есть, ключи/хост/ip не текут)\n");
    }

    // --- BenchRunner: чистая математика (median/mbit) ---
    {
        const bool medOk = BenchRunner::median({}) == -1.0                       // нет данных
                        && BenchRunner::median({42}) == 42.0                     // одиночное
                        && BenchRunner::median({3, 1, 2}) == 2.0                 // нечётное, несортированное
                        && BenchRunner::median({4, 1, 3, 2}) == 2.5;             // чётное → среднее середины
        const bool mbitOk = BenchRunner::mbit(0, 1000) == 0.0                    // нет байт
                         && BenchRunner::mbit(1000, 0) == 0.0                    // нет времени (защита от деления)
                         && BenchRunner::mbit(1250000, 1000) == 10.0             // 1.25МБ/с = 10 Mbit/s
                         && BenchRunner::mbit(26214400, 2000) > 104.0            // 25МБ за 2с ≈ 104.9 Mbit/s
                         && BenchRunner::mbit(26214400, 2000) < 105.0;
        printf("bench math: median=%d mbit=%d\n", medOk ? 1 : 0, mbitOk ? 1 : 0);
        if (!medOk || !mbitOk) { fprintf(stderr, "FAIL: BenchRunner math\n"); return 7; }
        printf("benchrunner: OK (median edge-cases, mbit conversion)\n");
    }

    // --- BenchAnalysis: вердикты по одному замеру + A/B-сравнение ---
    {
        auto mk = [](double dns, double ttfb, double down, double base, double loaded, int fails,
                     double lossPct = 0.0, int sent = 10) {
            QJsonObject r;
            r.insert("dns", QJsonObject{{"median_ms", dns}});
            r.insert("http", QJsonObject{{"median_ttfb_ms", ttfb}, {"median_total_ms", ttfb * 1.6}, {"failures", fails}});
            r.insert("throughput", QJsonObject{{"down_mbit", down}, {"up_mbit", down / 3}});
            r.insert("network_quality", QJsonObject{{"base_rtt_ms", base}, {"loaded_rtt_ms", loaded}});
            r.insert("tls", QJsonObject{{"median_tcp_ms", base / 3}, {"median_handshake_ms", base / 2}});
            r.insert("ping", QJsonArray{QJsonObject{{"target", "1.1.1.1"}, {"rtt_avg", base},
                                                    {"loss_pct", lossPct}, {"sent", sent}}});
            return r;
        };
        auto hasCode = [](const QJsonArray &vs, const char *code) {
            for (const QJsonValue &v : vs)
                if (v.toObject().value("code").toString() == QLatin1String(code)) return true;
            return false;
        };
        const QJsonArray good = bench::verdicts(mk(25, 250, 80, 90, 110, 0));
        const QJsonArray bloat = bench::verdicts(mk(25, 250, 80, 90, 400, 0));   // loaded/base > 2.5
        const QJsonArray slowDns = bench::verdicts(mk(120, 250, 80, 90, 110, 0));
        const QJsonArray lowGp = bench::verdicts(mk(25, 250, 2.0, 90, 110, 0));  // 2 Мбит при RTT 90
        // потери: 1 из 10 (10%) = шум → info, НЕ bad; 3 из 10 (30%) = bad; текст без «%%»
        const QJsonArray loss1 = bench::verdicts(mk(25, 250, 80, 90, 110, 0, 10.0, 10));
        const QJsonArray loss3 = bench::verdicts(mk(25, 250, 80, 90, 110, 0, 30.0, 10));
        bool lossTextOk = true;
        for (const QJsonValue &v : loss3)
            if (v.toObject().value("text").toString().contains(QLatin1String("%%"))) lossTextOk = false;
        // RU-direct: провалы ya.ru/vk при bypass_on → ru-direct-down (общий http-failures молчит:
        // заграничных провалов нет); тот же корпус при bypass_off → обычный http-failures (RU шёл
        // через туннель); замер без probes[] (старая схема) → прежнее поведение по failures
        auto mkRu = [&](bool bypassOn) {
            QJsonObject r = mk(25, 250, 80, 90, 110, 3);
            QJsonObject http = r.value("http").toObject();
            http.insert("probes", QJsonArray{
                QJsonObject{{"url", "https://www.google.com/"}, {"code", 200}},
                QJsonObject{{"url", "https://ya.ru/"}, {"error", true}, {"error_kind", "TimeoutError"}},
                QJsonObject{{"url", "https://ya.ru/"}, {"error", true}, {"error_kind", "HostNotFoundError"}},
                QJsonObject{{"url", "https://vk.com/"}, {"error", true}, {"error_kind", "TimeoutError"}}});
            r.insert("http", http);
            r.insert("extra", QJsonObject{{"bypass_on", bypassOn}});
            return r;
        };
        const QJsonArray ruOn = bench::verdicts(mkRu(true));
        const QJsonArray ruOff = bench::verdicts(mkRu(false));
        // bench v5: split-leak ТОЛЬКО при split_on&&reachable&&equals; ipv6-dead только при aaaa&&!https
        auto mkSplit = [&](bool splitOn, bool equals, bool aaaa, bool v6http) {
            QJsonObject r = mk(25, 250, 80, 90, 110, 0);
            r.insert("extra", QJsonObject{{"tunnel_config", QJsonObject{{"split_on", splitOn}}}});
            r.insert("split_check", QJsonObject{{"ru_reachable", true}, {"ru_equals_tunnel_egress", equals}});
            r.insert("ipv6", QJsonObject{{"aaaa_ok", aaaa}, {"https_ok", v6http}});
            return r;
        };
        const bool splitOk =
               hasCode(bench::verdicts(mkSplit(true, true, true, true)), "split-leak")     // сплит вкл, egress совпал → leak
            && !hasCode(bench::verdicts(mkSplit(true, false, true, true)), "split-leak")   // не совпал → ок
            && !hasCode(bench::verdicts(mkSplit(false, true, true, true)), "split-leak")   // сплит не сеялся (РФ-нода) → норма
            && hasCode(bench::verdicts(mkSplit(true, false, true, false)), "ipv6-dead")    // AAAA есть, v6 не ходит
            && !hasCode(bench::verdicts(mkSplit(true, false, false, false)), "ipv6-dead"); // v6 нет вовсе → молчим
        const QJsonArray legacy = bench::verdicts(mk(25, 250, 80, 90, 110, 3)); // failures без probes[]
        const bool ruOk = hasCode(ruOn, "ru-direct-down") && !hasCode(ruOn, "http-failures")
                       && !hasCode(ruOff, "ru-direct-down") && hasCode(ruOff, "http-failures")
                       && hasCode(legacy, "http-failures") && !hasCode(legacy, "ru-direct-down")
                       && splitOk;
        const bool vOk = good.isEmpty()
                      && hasCode(bloat, "bufferbloat") && !hasCode(bloat, "dns-slow")
                      && hasCode(slowDns, "dns-slow")
                      && hasCode(lowGp, "low-goodput")
                      && !hasCode(loss1, "packet-loss") && hasCode(loss1, "packet-loss-single")
                      && hasCode(loss3, "packet-loss") && lossTextOk && ruOk;
        // A/B: b хуже a по TTFB на 30% (существенно) и лучше по загрузке (не в significant)
        const QJsonObject cmp = bench::compare(mk(25, 200, 50, 90, 110, 0), mk(25, 260, 70, 90, 110, 0));
        const QJsonArray sig = cmp.value("significant").toArray();
        bool ttfbFlagged = false;
        for (const QJsonValue &s : sig)
            if (s.toString().startsWith(QLatin1String("TTFB"))) ttfbFlagged = true;
        const bool cOk = ttfbFlagged && sig.size() >= 2 /* TTFB + Страница */
                      && cmp.value("deltas").toArray().size() == 9; // 7 базовых + TCP/TLS-фазы
        printf("bench analysis: verdicts=%d compare=%d (sig=%d)\n", vOk ? 1 : 0, cOk ? 1 : 0, int(sig.size()));
        if (!vOk || !cOk) { fprintf(stderr, "FAIL: BenchAnalysis verdicts/compare\n"); return 8; }
        printf("benchanalysis: OK (bufferbloat/dns-slow/low-goodput, loss 1/10=info 3/10=bad, A/B deltas+tls)\n");
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

    // --- SignalQuality: RTT→5 баров + EWMA-сглаживание + гистерезис (детерминированно) ---
    {
        // 1) Чистая таблица порогов RTT→бары (ЩЕДРАЯ калибровка под VPN-туннель: 5:<150 4:<230 3:<330 2:<500 1:<800).
        bool mapOk = SignalQuality::barsForRtt(30) == 5
                     && SignalQuality::barsForRtt(149) == 5 && SignalQuality::barsForRtt(150) == 4
                     && SignalQuality::barsForRtt(147) == 5   // типичный туннельный RTT → ПОЛНЫЙ сигнал
                     && SignalQuality::barsForRtt(229) == 4 && SignalQuality::barsForRtt(230) == 3
                     && SignalQuality::barsForRtt(329) == 3 && SignalQuality::barsForRtt(330) == 2
                     && SignalQuality::barsForRtt(499) == 2 && SignalQuality::barsForRtt(500) == 1
                     && SignalQuality::barsForRtt(799) == 1 && SignalQuality::barsForRtt(800) == 0
                     && SignalQuality::barsForRtt(-1) == 0; // недостижимо → 0

        // 2) Первый сэмпл сидирует SRTT и показывает уровень сразу (без дебаунса).
        SignalQuality q;
        int b0 = q.feed(80, true);            // srtt=80 → 5 баров
        int srtt0 = q.smoothedRtt();

        // 3) Одиночный спайк поглощается EWMA(α=1/4): 80→spike240 ⇒ srtt=120, бар держится 5 (анти-дребезг).
        int b1 = q.feed(240, true);           // srtt=0.75*80+0.25*240=120; band5 [0,150) → остаёмся 5
        int srtt1 = q.smoothedRtt();

        // 4) Второй 240: srtt=150 — raw уже 4, но гистерезис (расширенная полоса band5 [0,162)) держит 5.
        int b2 = q.feed(240, true);           // srtt=0.75*120+0.25*240=150 → sticky → остаёмся 5

        // 5) Третий 240: srtt≈173 покидает расширенную полосу band5 → падаем до 4.
        int b3 = q.feed(240, true);           // srtt=0.75*150+0.25*240≈172.5→173 → 4
        int srtt3 = q.smoothedRtt();

        // 6) Hard-gate: недостижимо → немедленно 0 (мимо сглаживания/дебаунса), затем восстановление.
        SignalQuality q2;
        q2.feed(40, true);                    // 5 баров
        int down = q2.feed(-1, false);        // нет ответа → 0 сразу
        int up = q2.feed(40, true);           // вернулась связь → снова 5

        // 7) Регресс: после hard-gate первый достижимый сэмпл в «липкой» полосе bar1 (750мс) НЕ
        //    должен залипнуть на 0 — новая серия обязана сидироваться без гистерезиса.
        SignalQuality q3;
        q3.feed(750, true);                   // srtt 750 → 1 бар
        int gate = q3.feed(-1, false);        // обрыв → 0
        int recov = q3.feed(750, true);       // связь вернулась, медленно (750мс) → 1, не застрять на 0

        printf("signal: map=%d b0=%d srtt0=%d b1=%d srtt1=%d b2=%d b3=%d srtt3=%d down=%d up=%d gate=%d recov=%d\n",
               mapOk, b0, srtt0, b1, srtt1, b2, b3, srtt3, down, up, gate, recov);

        bool sigOk = mapOk
                     && b0 == 5 && srtt0 == 80
                     && b1 == 5 && srtt1 == 120      // спайк поглощён, бар не дрогнул
                     && b2 == 5                      // второй 240 ещё в липкой полосе → держим 5
                     && b3 == 4 && srtt3 == 173      // устойчивый рост RTT → -1 бар
                     && down == 0 && up == 5         // hard-gate вниз и восстановление вверх
                     && gate == 0 && recov == 1;     // восстановление в липкой полосе bar1 не залипает
        if (!sigOk) { fprintf(stderr, "FAIL: SignalQuality mapping/smoothing mismatch\n"); return 9; }
        printf("signalquality: OK (RTT→5 баров, EWMA-сглаживание, гистерезис, hard-gate недостижимости)\n");
    }

    // --- MtprotoProbe: req_pq_multi build + resPQ parse (детерминированно, login-free liveness) ---
    {
        auto le32 = [](QByteArray &b, quint32 v) {
            b.append(char(v & 0xff)); b.append(char((v >> 8) & 0xff));
            b.append(char((v >> 16) & 0xff)); b.append(char((v >> 24) & 0xff));
        };
        auto le64 = [](QByteArray &b, quint64 v) {
            for (int i = 0; i < 8; ++i) b.append(char((v >> (8 * i)) & 0xff));
        };

        // фиксированный nonce 01..10 + произвольный валидный-вид msg_id
        QByteArray nonce(16, Qt::Uninitialized);
        for (int i = 0; i < 16; ++i) nonce[i] = char(i + 1);
        const qint64 msgId = qint64(0x51E3025500000000LL);

        // 1) Сборка unencrypted message: auth_key_id=0(8) + msgId(8) + len(4) + ctor(4) + nonce(16) = 40.
        const QByteArray msg = MtprotoProbe::buildReqPqMulti(nonce, msgId);
        bool buildOk = msg.size() == 40;
        for (int i = 0; i < 8; ++i) buildOk = buildOk && msg[i] == 0;           // auth_key_id = 0
        qint64 gotMsgId = 0; for (int i = 0; i < 8; ++i) gotMsgId |= qint64(quint8(msg[8 + i])) << (8 * i);
        buildOk = buildOk && gotMsgId == msgId;
        buildOk = buildOk && quint8(msg[16]) == 0x14 && msg[17] == 0 && msg[18] == 0 && msg[19] == 0; // len=20
        buildOk = buildOk && quint8(msg[20]) == 0xf1 && quint8(msg[21]) == 0x8e   // be7e8ef1 (LE)
                  && quint8(msg[22]) == 0x7e && quint8(msg[23]) == 0xbe;
        buildOk = buildOk && msg.mid(24, 16) == nonce;                            // nonce на месте

        // 2) Intermediate-фрейминг: 4-байтный LE-префикс длины (+ const-тег коннекта 0xeeeeeeee).
        const QByteArray framed = MtprotoProbe::frameIntermediate(msg);
        quint32 flen = quint8(framed[0]) | (quint8(framed[1]) << 8)
                       | (quint8(framed[2]) << 16) | (quint32(quint8(framed[3])) << 24);
        bool frameOk = framed.size() == msg.size() + 4 && flen == quint32(msg.size())
                       && framed.mid(4) == msg && MtprotoProbe::kIntermediateTag == 0xeeeeeeeeu;

        // 3) Парсинг синтетического resPQ: nonce эхо ⇒ true + извлечён server_nonce.
        QByteArray sn(16, Qt::Uninitialized);
        for (int i = 0; i < 16; ++i) sn[i] = char(0x40 + i);
        auto makeResPq = [&](const QByteArray &nn, const QByteArray &svn) {
            QByteArray data; le32(data, 0x05162463u); data.append(nn); data.append(svn);
            data.append(char(0x08)); data.append(QByteArray(8, '\x11')); data.append(QByteArray(3, '\0')); // pq string (pad)
            le32(data, 0x1cb5c415u); le32(data, 1); le64(data, 0xABCDEF0123456789ULL);                     // Vector<long>=[fp]
            QByteArray m; le64(m, 0); le64(m, quint64(0x123400000000ULL)); le32(m, quint32(data.size())); m.append(data);
            return m;
        };
        const QByteArray resp = makeResPq(nonce, sn);
        QByteArray outSrv;
        bool parseOk = MtprotoProbe::parseResPq(resp, nonce, &outSrv) && outSrv == sn;

        // 4) Подделанный nonce и неверный конструктор ⇒ отказ (анти-false-positive).
        QByteArray badNonce = nonce; badNonce[0] = char(quint8(badNonce[0]) ^ 0xff);
        bool rejectNonce = !MtprotoProbe::parseResPq(resp, badNonce, nullptr);
        QByteArray wrongCtor = resp; wrongCtor[20] = char(0x00);
        bool rejectCtor = !MtprotoProbe::parseResPq(wrongCtor, nonce, nullptr);
        bool rejectShort = !MtprotoProbe::parseResPq(resp.left(40), nonce, nullptr); // обрезано → отказ

        printf("mtproto: build=%d frame=%d parse=%d rejN=%d rejC=%d rejS=%d srv=%s\n",
               buildOk, frameOk, parseOk, rejectNonce, rejectCtor, rejectShort,
               outSrv == sn ? "ok" : "bad");

        bool mtOk = buildOk && frameOk && parseOk && rejectNonce && rejectCtor && rejectShort;
        if (!mtOk) { fprintf(stderr, "FAIL: MtprotoProbe build/parse mismatch\n"); return 10; }
        printf("mtprotoprobe: OK (req_pq_multi build, intermediate frame, resPQ parse, nonce/ctor/short reject)\n");
    }

    // --- GoodputProbe: kbit/s + классификация works/slow/blocked (детерминированно, чистая арифметика) ---
    {
        using GP = GoodputProbe;
        const GP::Thresholds th; // works≥1000, slow≥100, minBytes=32768
        const qint64 N = 262144; // 256 КБ

        // kbit/s = bytes*8/ms. 1000 байт за 8 мс = 1000 кбит/с.
        bool rateOk = qFuzzyCompare(GP::kbitPerSec(1000, 8), 1000.0)
                      && GP::kbitPerSec(N, 0) == 0.0;      // деление на 0 → 0

        // 256КБ за 200мс ≈ 10485 кбит/с → works.
        int cFast = GP::classify(N, 200, th);
        // 256КБ за 15000мс ≈ 140 кбит/с (RU-троттл ~128) → slow.
        int cThrottle = GP::classify(N, 15000, th);
        // 256КБ за 30000мс ≈ 70 кбит/с → blocked (задушено ниже порога полезности).
        int cDead = GP::classify(N, 30000, th);
        // байт меньше minBytes → недостоверно → blocked.
        int cTiny = GP::classify(1024, 50, th);
        // ноль байт → blocked.
        int cZero = GP::classify(0, 100, th);

        printf("goodput: rate=%d fast=%d throttle=%d dead=%d tiny=%d zero=%d\n",
               rateOk, cFast, cThrottle, cDead, cTiny, cZero);

        bool gpOk = rateOk && cFast == 2 && cThrottle == 1 && cDead == 0 && cTiny == 0 && cZero == 0;
        if (!gpOk) { fprintf(stderr, "FAIL: GoodputProbe classify/rate mismatch\n"); return 11; }
        printf("goodputprobe: OK (kbit/s, works/slow/blocked, min-bytes/zero guard)\n");
    }

    // --- YoutubeSource: InnerTube билдер запроса + парс url + ranged-URL (чистая логика) ---
    {
        using YT = YoutubeSource;

        // 1) Evergreen-список непустой и содержит «Me at the zoo»; ключ непустой.
        bool listOk = YT::evergreenVideoIds().contains(QStringLiteral("jNQXAC9IVRw"))
                      && !YT::innerTubeKey().isEmpty();

        // 2) Тело player: context.client.clientName == "IOS", videoId прокинут.
        const QByteArray body = YT::buildPlayerRequest(QStringLiteral("jNQXAC9IVRw"),
                                                       QStringLiteral("IOS"), QStringLiteral("19.09.3"));
        const QJsonObject bo = QJsonDocument::fromJson(body).object();
        const QJsonObject client = bo.value(QStringLiteral("context")).toObject()
                                       .value(QStringLiteral("client")).toObject();
        bool bodyOk = client.value(QStringLiteral("clientName")).toString() == QLatin1String("IOS")
                      && client.value(QStringLiteral("clientVersion")).toString() == QLatin1String("19.09.3")
                      && bo.value(QStringLiteral("videoId")).toString() == QLatin1String("jNQXAC9IVRw");

        // 3) Парс прямого url из adaptiveFormats (поле `url`, googlevideo).
        const QByteArray okJson = R"({"streamingData":{"adaptiveFormats":[
            {"itag":140,"url":"https://rr3---sn-abc.googlevideo.com/videoplayback?a=1&b=2"}]}})";
        const QString url = YT::extractVideoplaybackUrl(okJson);
        bool urlOk = url == QLatin1String("https://rr3---sn-abc.googlevideo.com/videoplayback?a=1&b=2");

        // 4) Только signatureCipher (нет прямого url) ⇒ пусто (не дешифруем — деградация в reachability).
        const QByteArray cipherJson = R"({"streamingData":{"adaptiveFormats":[
            {"itag":140,"signatureCipher":"s=SIG&url=https%3A%2F%2Fx.googlevideo.com%2Fvideoplayback"}]}})";
        bool cipherSkipped = YT::extractVideoplaybackUrl(cipherJson).isEmpty();

        // 5) url не на googlevideo ⇒ пусто (бьём только реально-душимый путь).
        const QByteArray offJson = R"({"streamingData":{"adaptiveFormats":[
            {"itag":140,"url":"https://www.youtube.com/watch?v=x"}]}})";
        bool offSkipped = YT::extractVideoplaybackUrl(offJson).isEmpty();

        // 6) withRange добавляет &range=first-last.
        const QString ranged = YT::withRange(QStringLiteral("https://x.googlevideo.com/videoplayback?a=1"), 0, 262143);
        bool rangeOk = ranged == QLatin1String("https://x.googlevideo.com/videoplayback?a=1&range=0-262143");

        printf("youtube: list=%d body=%d url=%d cipher=%d off=%d range=%d\n",
               listOk, bodyOk, urlOk, cipherSkipped, offSkipped, rangeOk);

        bool ytOk = listOk && bodyOk && urlOk && cipherSkipped && offSkipped && rangeOk;
        if (!ytOk) { fprintf(stderr, "FAIL: YoutubeSource build/parse mismatch\n"); return 12; }
        printf("youtubesource: OK (evergreen+key, player body, direct-url parse, cipher/off-path skip, ranged url)\n");
    }

    // --- InstagramSource: парс публичного CDN-ассета из HTML (чистая логика) ---
    {
        using IG = InstagramSource;

        // 1) Достаём https://static.cdninstagram.com/....js из href/src.
        const QByteArray html = R"(<html><head>
            <link rel="preload" href="https://static.cdninstagram.com/rsrc.php/v3/yA/abc123.js" as="script"/>
            <script src="https://www.instagram.com/local.js"></script></head></html>)";
        const QString asset = IG::extractCdnAssetUrl(html);
        bool assetOk = asset == QLatin1String("https://static.cdninstagram.com/rsrc.php/v3/yA/abc123.js");

        // 2) Нет cdninstagram-ассета ⇒ пусто (раннер деградирует в reachability).
        const QByteArray htmlNone = R"(<html><head><script src="/only/local.js"></script></head></html>)";
        bool noneOk = IG::extractCdnAssetUrl(htmlNone).isEmpty();

        printf("instagram: asset=%d none=%d\n", assetOk, noneOk);

        bool igOk = assetOk && noneOk;
        if (!igOk) { fprintf(stderr, "FAIL: InstagramSource parse mismatch\n"); return 13; }
        printf("instagramsource: OK (cdn asset extract, no-asset guard)\n");
    }

    printf("OK: parsed + config + enrollment + selector + healthloop + signalquality + mtproto + goodput + youtube + instagram\n");
    return 0;
}
