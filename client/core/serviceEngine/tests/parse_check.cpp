// AVPN serviceEngine — автономная проверка парсера подписки (без Qt Test, только QtCore).
// Сборка/запуск: core/serviceEngine/tests/build_check.sh
#include "../AwgConfigBuilder.h"
#include "../BenchAnalysis.h" // AVPN (панель администратора): вердикты + A/B-сравнение замеров
#include "../BenchRunner.h" // AVPN (панель администратора): чистая математика бенча (median/mbit)
#include "../DeviceFingerprint.h" // AVPN (device_fingerprint): чистый hashAnchor
#include "../Enrollment.h"
#include "../GoodputProbe.h"
#include "../HealthLoop.h"
#include "../MtprotoProbe.h"
#include "../Selector.h"
#include "../SignalQuality.h"
#include "../SubscriptionParser.h"
#include "../SubscriptionRequest.h"
#include "../TuningStore.h" // AVPN backend-first (Task 2): health_dead_cycles/health_dead_max_age_s юнит
#include "../YoutubeSource.h"
#include "../../utils/constants/protocolConstants.h" // AVPN: паритет-дефолты mtu (awg::defaultMtu)

#include <QCoreApplication>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <cstdio>

using namespace avpn;

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    const QUrl versioned = versionedSubscriptionUrl(
        QStringLiteral("https://api.example"), QStringLiteral("5.1.68.97"));
    const QUrl fallback = versionedSubscriptionUrl(
        QStringLiteral("https://api.example"), QStringLiteral("97"));
    if (QUrlQuery(versioned).queryItemValue(QStringLiteral("app_version"))
            != QLatin1String("5.1.68.97")
        || fallback.toString() != QLatin1String("https://api.example/v1/subscription")) {
        fprintf(stderr, "FAIL: subscription app_version/fallback contract\n");
        return 16;
    }
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
               int(inner.size()));
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
        // bench v5: mtu-mismatch — path < config при probed=true и наличии tunnel_config
        auto mkMtu = [&](bool probed, int pathMtu, int cfgMtu) {
            QJsonObject r = mk(25, 250, 80, 90, 110, 0);
            r.insert("extra", QJsonObject{{"tunnel_config", QJsonObject{{"mtu", cfgMtu}}}});
            QJsonObject mp; mp.insert("probed", probed);
            if (pathMtu > 0) mp.insert("path_mtu", pathMtu);
            r.insert("mtu_probe", mp);
            return r;
        };
        const bool mtuOk =
               hasCode(bench::verdicts(mkMtu(true, 1380, 1420)), "mtu-mismatch")   // путь уже конфига → bad
            && !hasCode(bench::verdicts(mkMtu(true, 1420, 1376)), "mtu-mismatch")  // путь шире → ок
            && !hasCode(bench::verdicts(mkMtu(false, 0, 1420)), "mtu-mismatch");   // не мерили → молчим
        // build 62 «честные вердикты»: провал с HTTP-кодом (403 антибот Ozon) = сайт ОТВЕТИЛ →
        // site-refused (info), НЕ ru-direct-down/http-failures; смесь 403+timeout → оба вердикта
        auto mkRefused = [&](bool bypassOn, bool withTimeout) {
            QJsonObject r = mk(25, 250, 80, 90, 110, withTimeout ? 2 : 1);
            QJsonObject http = r.value("http").toObject();
            QJsonArray probes{
                QJsonObject{{"url", "https://www.google.com/"}, {"code", 200}},
                QJsonObject{{"url", "https://www.ozon.ru/"}, {"error", true},
                            {"error_kind", "ContentAccessDeniedError"}, {"code", 403}}};
            if (withTimeout)
                probes.append(QJsonObject{{"url", "https://ya.ru/"}, {"error", true},
                                          {"error_kind", "TimeoutError"}});
            http.insert("probes", probes);
            r.insert("http", http);
            r.insert("extra", QJsonObject{{"bypass_on", bypassOn}});
            return r;
        };
        const QJsonArray ref403 = bench::verdicts(mkRefused(true, false));
        const QJsonArray refMix = bench::verdicts(mkRefused(true, true));
        const QJsonArray refOff = bench::verdicts(mkRefused(false, false));
        const bool honestOk =
               hasCode(ref403, "site-refused") && !hasCode(ref403, "ru-direct-down")
            && !hasCode(ref403, "http-failures")                                     // 403 ≠ «не открылась»
            && hasCode(refMix, "site-refused") && hasCode(refMix, "ru-direct-down")  // timeout остался честным
            && hasCode(refOff, "site-refused") && !hasCode(refOff, "http-failures"); // bypass off: 403 тоже не «провал»
        // build 62 DNS-дуэль: dns-fwd-dead при провале любого плеча; молчит при обоих ok
        auto mkDuel = [&](bool ruLeg, bool fLeg) {
            QJsonObject r = mk(25, 250, 80, 90, 110, 0);
            r.insert("dns_duel", QJsonObject{{"ru_ok", ruLeg}, {"foreign_ok", fLeg}});
            return r;
        };
        const bool duelOk =
               hasCode(bench::verdicts(mkDuel(false, true)), "dns-fwd-dead")
            && hasCode(bench::verdicts(mkDuel(true, false)), "dns-fwd-dead")
            && !hasCode(bench::verdicts(mkDuel(true, true)), "dns-fwd-dead");
        // build 62 цензура-детект: молчит в baseline И открывается через VPN → censorship;
        // 403/flaky/RU-хост-при-bypass-on/baseline-под-туннелем → НЕ цензура
        auto mkRun = [&](const QJsonArray &probes, bool bypassOn, const char *tunnelState) {
            QJsonObject r = mk(25, 250, 80, 90, 110, 0);
            QJsonObject http = r.value("http").toObject();
            http.insert("probes", probes);
            r.insert("http", http);
            QJsonObject extra{{"bypass_on", bypassOn}};
            if (tunnelState) extra.insert("tunnel_state", tunnelState);
            r.insert("extra", extra);
            return r;
        };
        const QJsonArray deadBoth{QJsonObject{{"url", "https://www.google.com/"}, {"error", true}, {"error_kind", "TimeoutError"}},
                                  QJsonObject{{"url", "https://ya.ru/"}, {"error", true}, {"error_kind", "TimeoutError"}}};
        const QJsonArray okBoth{QJsonObject{{"url", "https://www.google.com/"}, {"code", 200}},
                                QJsonObject{{"url", "https://ya.ru/"}, {"code", 200}}};
        const QJsonObject baseDead = mkRun(deadBoth, false, nullptr);
        const QJsonObject vpnOffRun = mkRun(okBoth, false, "connected");
        const QJsonObject vpnOnRun = mkRun(okBoth, true, "connected");
        const QJsonArray base403{QJsonObject{{"url", "https://www.google.com/"}, {"error", true},
                                             {"error_kind", "ContentAccessDeniedError"}, {"code", 403}}};
        const QJsonArray baseFlaky{QJsonObject{{"url", "https://www.google.com/"}, {"code", 200}},
                                   QJsonObject{{"url", "https://www.google.com/"}, {"error", true}, {"error_kind", "TimeoutError"}}};
        const QJsonArray censOff = bench::censorship(baseDead, vpnOffRun); // google+ya.ru = 2
        const QJsonArray censOn = bench::censorship(baseDead, vpnOnRun);   // ya.ru мимо туннеля → только google
        const bool censOk =
               censOff.size() == 2 && hasCode(censOff, "censorship")
            && censOn.size() == 1
            && bench::censorship(mkRun(base403, false, nullptr), vpnOffRun).isEmpty()
            && bench::censorship(mkRun(baseFlaky, false, nullptr), vpnOffRun).isEmpty()
            && bench::censorship(mkRun(deadBoth, false, "connected"), vpnOffRun).isEmpty();
        const QJsonArray legacy = bench::verdicts(mk(25, 250, 80, 90, 110, 3)); // failures без probes[]
        const bool ruOk = hasCode(ruOn, "ru-direct-down") && !hasCode(ruOn, "http-failures")
                       && !hasCode(ruOff, "ru-direct-down") && hasCode(ruOff, "http-failures")
                       && hasCode(legacy, "http-failures") && !hasCode(legacy, "ru-direct-down")
                       && splitOk && mtuOk && honestOk && duelOk && censOk;
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
        printf("benchanalysis: OK (bufferbloat/dns-slow/low-goodput, loss 1/10=info 3/10=bad, "
               "site-refused/censorship/dns-fwd-dead, A/B deltas+tls)\n");
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

    // --- device_fingerprint: хеш якоря + поле в трёх телах + детект 403-мисматча ---
    {
        // sha256 lower-hex, 64 симв. (匹 паттерну бэка ^[A-Fa-f0-9._-]{16,128}$); детерминирован.
        const QString fp = DeviceFingerprint::hashAnchor(QStringLiteral("test-anchor"));
        const QRegularExpression hexRe(QStringLiteral("^[a-f0-9]{64}$"));
        bool hOk = hexRe.match(fp).hasMatch()
                   && fp == DeviceFingerprint::hashAnchor(QStringLiteral("test-anchor"))
                   && fp != DeviceFingerprint::hashAnchor(QStringLiteral("test-anchor2"))
                   // якорь известной формы → известный дайджест (фиксирует нормализацию НАВСЕГДА:
                   // смена = другой fingerprint у всего флота = массовые ложные 403)
                   && DeviceFingerprint::hashAnchor(QStringLiteral("abc"))
                          == QLatin1String("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

        // Поле кладётся во все ТРИ тела и опускается, когда якоря нет (инвариант «не слать пустое»).
        const QJsonObject t1 = QJsonDocument::fromJson(Enrollment::buildTrialBody(
            QStringLiteral("PK=="), QStringLiteral("dev-1234567890123456"),
            QStringLiteral("ios"), QString(), QString(), fp)).object();
        const QJsonObject t0 = QJsonDocument::fromJson(Enrollment::buildTrialBody(
            QStringLiteral("PK=="), QStringLiteral("dev-1234567890123456"),
            QStringLiteral("ios"))).object();
        const QJsonObject r1 = QJsonDocument::fromJson(Enrollment::buildRedeemBody(
            QStringLiteral("TRIBE-CODE"), QStringLiteral("PK=="),
            QStringLiteral("dev-1234567890123456"), QStringLiteral("ios"),
            QString(), QString(), fp)).object();
        const QJsonObject x1 = QJsonDocument::fromJson(Enrollment::buildTransferRedeemBody(
            QStringLiteral("ttok"), QStringLiteral("PK=="),
            QStringLiteral("dev-1234567890123456"), QStringLiteral("ios"), QString(), fp)).object();
        const QString k = QStringLiteral("device_fingerprint");
        bool bOk = t1.value(k).toString() == fp && !t0.contains(k)
                   && r1.value(k).toString() == fp && x1.value(k).toString() == fp;

        // 403-мисматч: детект СТРОГО по detail (иной 403 — например Zanaves-гейт transfer — не наш).
        bool mOk = Enrollment::isFingerprintMismatch(403, R"({"detail":"device fingerprint mismatch"})")
                   && !Enrollment::isFingerprintMismatch(403, R"({"detail":"transfer is not available for this key"})")
                   && !Enrollment::isFingerprintMismatch(401, R"({"detail":"device fingerprint mismatch"})")
                   && !Enrollment::isFingerprintMismatch(403, "not json")
                   && !Enrollment::isFingerprintMismatch(403, QByteArray());

        printf("fingerprint: hash=%d bodies=%d mismatch=%d\n", hOk ? 1 : 0, bOk ? 1 : 0, mOk ? 1 : 0);
        if (!hOk || !bOk || !mOk) { fprintf(stderr, "FAIL: device_fingerprint hash/bodies/403\n"); return 6; }
        printf("fingerprint: OK (sha256-hex, 3 bodies, omit-when-empty, 403 detail)\n");
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

        // --- HealthLoop: server-tunable пороги (backend-first Task 2) ---
        // Дефолт (пустой TuningStore) — DEAD только после 2 «плохих» циклов подряд (как раньше).
        avpn::TuningStore::reset();
        HealthLoop hDef; hDef.feed(S(0, 100, 100), now);
        bool defAliveAfter1 = !hDef.feed(S(0, 100, 200), now); // 1-й плохой цикл — ещё не DEAD
        bool defDeadAfter2 = hDef.feed(S(0, 100, 300), now);   // 2-й плохой цикл — DEAD (дефолт=2)

        // health_dead_cycles=1 с сервера → DEAD уже за ОДИН плохой цикл.
        avpn::TuningStore::set({{QStringLiteral("health_dead_cycles"), 1.0}}, {});
        HealthLoop hTuned; hTuned.feed(S(0, 100, 100), now);
        bool tunedDeadAfter1 = hTuned.feed(S(0, 100, 200), now); // 1-й плохой цикл уже DEAD

        // health_dead_max_age_s=5 с сервера (пол final review R-2 клампит 0/минус до 10 — см.
        // HealthThresholds::fromTuning) → эффективный порог 10с, handshake 15с уже вне него ⇒ DEAD
        // раньше дефолта (180с), но НЕ мгновенно от любого handshake (пол защищает от false-positive).
        avpn::TuningStore::set({{QStringLiteral("health_dead_cycles"), 1.0},
                                 {QStringLiteral("health_dead_max_age_s"), 5.0}}, {});
        HealthLoop hAge; hAge.feed(S(now - 15, 100, 100), now);
        bool tunedAgeDead = hAge.feed(S(now - 15, 100, 200), now); // hs 15с (> клампленных 10с) ⇒ stale

        // reset() → снова дефолт 2 (как в самом начале).
        avpn::TuningStore::reset();
        HealthLoop hReset; hReset.feed(S(0, 100, 100), now);
        bool resetAliveAfter1 = !hReset.feed(S(0, 100, 200), now);
        bool resetDeadAfter2 = hReset.feed(S(0, 100, 300), now);

        printf("health/tuning: defAliveAfter1=%d defDeadAfter2=%d tunedDeadAfter1=%d tunedAgeDead=%d "
               "resetAliveAfter1=%d resetDeadAfter2=%d\n",
               defAliveAfter1, defDeadAfter2, tunedDeadAfter1, tunedAgeDead, resetAliveAfter1, resetDeadAfter2);
        bool tuningOk = defAliveAfter1 && defDeadAfter2 && tunedDeadAfter1 && tunedAgeDead
                        && resetAliveAfter1 && resetDeadAfter2;
        if (!tuningOk) { fprintf(stderr, "FAIL: HealthLoop TuningStore override mismatch\n"); return 14; }
        printf("healthloop/tuning: OK (health_dead_cycles/health_dead_max_age_s override + reset→def)\n");
    }

    // --- TunnelStats-хелперы (ИНЦИДЕНТ 2026-07-11 «сам отключился и переподключился»):
    //     bytesChanged на ВСЕХ платформах = ДЕЛЬТЫ за период (vpnProtocol::setBytesChanged и
    //     ios_controller.mm эмитят diff), а HealthLoop ждёт КУМУЛЯТИВЫ; плюс iOS шлёт
    //     handshakeChanged(0)=«неизвестно» до первого отчёта wireguard-go → hsStale защёлкивался.
    {
        const qint64 now = 2000000;
        // 1) аккумуляция дельт в кумулятив
        TunnelStats s;
        accumulateByteDelta(s, 100, 50);
        accumulateByteDelta(s, 100, 50);
        bool accum = (s.rxBytes == 200 && s.txBytes == 100 && s.valid);
        // 2) регресс ложного DEAD: РОВНЫЙ rx-поток (равные дельты) + растущий tx + epoch=0.
        //    Старая запись дельт «как есть» давала rxStuck=true → DEAD за 2 цикла; кумулятив — жив.
        HealthLoop hb;
        TunnelStats a; accumulateByteDelta(a, 1000, 1000);
        TunnelStats b = a; accumulateByteDelta(b, 1000, 2000);
        TunnelStats c = b; accumulateByteDelta(c, 1000, 3000);
        hb.feed(a, now); hb.feed(b, now);
        bool aliveFlow = !hb.feed(c, now);
        // 3) epoch=0 НЕ затирает известный handshake
        TunnelStats h; updateHandshakeEpoch(h, now - 5); updateHandshakeEpoch(h, 0);
        bool keepEpoch = (h.latestHandshakeEpoch == now - 5);
        // 4) посев epoch≈now на Connected (паритет с desktop-UAPI: данные текут ⇒ handshake был
        //    только что) → пост-коннект тишина rx при tx-бёрстах проб НЕ роняет туннель (грейс 180с)
        HealthLoop hc;
        TunnelStats p; updateHandshakeEpoch(p, now); accumulateByteDelta(p, 0, 100);
        TunnelStats q = p; accumulateByteDelta(q, 0, 100);
        TunnelStats r = q; accumulateByteDelta(r, 0, 100);
        hc.feed(p, now); hc.feed(q, now);
        bool graceOk = !hc.feed(r, now);
        printf("tunnelstats: accum=%d flow=%d keep=%d grace=%d\n", accum, aliveFlow, keepEpoch, graceOk);
        if (!(accum && aliveFlow && keepEpoch && graceOk)) {
            fprintf(stderr, "FAIL: TunnelStats helpers mismatch\n");
            return 12;
        }
        
        // 5) защита от мусорной дельты (iOS: стейл-ответ checkStatus старой сессии → underflow
        //    quint64 → «дельта» ~2^64): абсурдный скачок игнорируется, счётчики не портятся
        TunnelStats g; accumulateByteDelta(g, 500, 500);
        accumulateByteDelta(g, Q_UINT64_C(18446744073709000000), 100); // rx-underflow, tx нормальный
        bool guardOk = (g.rxBytes == 500 && g.txBytes == 600 && g.valid);
        printf("tunnelstats-guard: %d\n", guardOk);
        if (!guardOk) { fprintf(stderr, "FAIL: absurd delta guard\n"); return 13; }
        printf("tunnelstats: OK (delta→cumulative, steady-flow alive, epoch-0 keep, connect-grace)\n");
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

    // Instagram-парсер HTML и вердикт «источник мёртв» удалены в чипах v2 (2026-07-12):
    // достижимость решает reachability-КВОРУМ лёгких эндпоинтов (ChipLogic::classifyReachVoice —
    // та же семантика RST-без-байта=HardFail, таймаут=SoftFail; TDD tests/build_chip_logic.sh),
    // HTML главной Instagram больше не парсим (гео-A/B вёрстка/бот-детект — источник флапа).

    // --- AWG 3.0/3.1: explicit typed keys only + keepalive clamp ---
    {
        const QByteArray v3json = R"({
            "version": 1, "address": ["10.7.0.9/32"], "status": "active",
            "nodes": [{
                "node_id": "lab-v3", "region": "fi", "endpoint": "203.0.113.99:585",
                "server_pubkey": "PUBKEY_V3", "proto": "awg",
                "dns": ["1.1.1.1", "1.0.0.1"], "mtu": 1280, "persistent_keepalive": 0,
                "awg_params": {
                    "Jc": 4, "Jmin": 10, "Jmax": 50, "S1": 15, "S2": 17, "S3": 20, "S4": 12,
                    "H1": 11, "H2": 12, "H3": 13, "H4": 14,
                    "I1": "<r 2><b 0x11>",
                    "HeaderProtectionKey": "aGVhZGVyLXByb3RlY3Rpb24ta2V5LTMyYnl0ZXM=",
                    "ContentPaddingAddition": "10-100",
                    "RekeyAfterTime": "100-120", "RekeyTimeout": "3-7",
                    "RejectAfterTime": "150-180", "KeepaliveTimeout": "5-15",
                    "MaxHandshakeAttempts": "15-20",
                    "RandomTrailers": true, "DisableCookies": true,
                    "FutureKey42": "future-value", "FutureNumeric": 7
                }
            }]
        })";
        Subscription v3sub; QString v3err;
        const bool parsed = SubscriptionParser::parse(v3json, v3sub, v3err);
        if (!parsed) { fprintf(stderr, "FAIL: awg3 parse: %s\n", v3err.toUtf8().constData()); return 13; }
        const SubscriptionNode &n = v3sub.nodes.first();
        const AwgParams &a = n.awg;
        const bool fieldsOk = a.hasFullBundle()
            && a.headerProtectionKey == QLatin1String("aGVhZGVyLXByb3RlY3Rpb24ta2V5LTMyYnl0ZXM=")
            && a.contentPaddingAddition == QLatin1String("10-100")
            && a.rekeyAfterTime == QLatin1String("100-120")
            && a.rekeyTimeout == QLatin1String("3-7")
            && a.rejectAfterTime == QLatin1String("150-180")
            && a.keepaliveTimeout == QLatin1String("5-15")
            && a.maxHandshakeAttempts == QLatin1String("15-20")
            && a.randomTrailers.value_or(false)
            && a.disableCookies.value_or(false);
        // кламп: явный persistent_keepalive=0 не должен молча выключить keepalive
        const bool kaOk = n.persistentKeepalive == 25;

        ClientKeys keys;
        keys.privateKey = QStringLiteral("PRIV"); keys.publicKey = QStringLiteral("PUB");
        const QJsonObject cfg = AwgConfigBuilder::build(v3sub, n, keys);
        const QJsonObject inner = cfg.value(QStringLiteral("awg_config_data")).toObject();
        const QString quick = inner.value(QStringLiteral("config")).toString();
        // 7 ключей доезжают и до inner-JSON (awgProtocolKeys-цикл платформ), и до wg-quick текста
        const bool emitOk = inner.value(QStringLiteral("HeaderProtectionKey")).toString() == a.headerProtectionKey
            && inner.value(QStringLiteral("ContentPaddingAddition")).toString() == QLatin1String("10-100")
            && inner.value(QStringLiteral("MaxHandshakeAttempts")).toString() == QLatin1String("15-20")
            && inner.value(QStringLiteral("RandomTrailers")).toString() == QLatin1String("1")
            && inner.value(QStringLiteral("DisableCookies")).toString() == QLatin1String("1")
            && quick.contains(QLatin1String("HeaderProtectionKey = "))
            && quick.contains(QLatin1String("RekeyTimeout = 3-7"))
            && quick.contains(QLatin1String("RandomTrailers = 1"))
            && quick.contains(QLatin1String("DisableCookies = 1"))
            && quick.contains(QLatin1String("PersistentKeepalive = 25"));
        // Unknown keys are ignored and never reach version-strict native parsers.
        const bool unknownKeyOk = !inner.contains(QStringLiteral("FutureKey42"))
            && !quick.contains(QLatin1String("FutureKey42"));
        // parity 2.0: у ноды без v3-ключей в конфиге не появляется ни одного нового ключа
        const QJsonObject cfg20 = AwgConfigBuilder::build(sub, sub.nodes.first(), keys);
        const QJsonObject inner20 = cfg20.value(QStringLiteral("awg_config_data")).toObject();
        const bool parityOk = !inner20.contains(QStringLiteral("HeaderProtectionKey"))
            && !inner20.contains(QStringLiteral("ContentPaddingAddition"))
            && !inner20.contains(QStringLiteral("RekeyAfterTime"))
            && !inner20.value(QStringLiteral("config")).toString().contains(QLatin1String("Rekey"));
        // отчёт: флаг v3 есть, сам ключ HPK в отчёт НЕ течёт (секрет)
        const QJsonObject rep = AwgConfigBuilder::reportSummary(v3sub, n);
        const QString repFlat = QString::fromUtf8(QJsonDocument(rep).toJson());
        const bool repOk = rep.value(QStringLiteral("awg")).toObject().value(QStringLiteral("v3")).toBool()
            && rep.value(QStringLiteral("awg")).toObject().value(QStringLiteral("v31")).toBool()
            && !repFlat.contains(a.headerProtectionKey);

        // protocolMajor: v3.1-нода → "3.1"; фикстура (только Jc..H4) → "1"; S4/I1 → "2"
        AwgParams v2probe; v2probe.S4 = 4; v2probe.I1 = QStringLiteral("<r 2>");
        const bool verOk = a.protocolMajor() == QLatin1String("3.1")
            && sub.nodes.first().awg.protocolMajor() == QLatin1String("1")
            && v2probe.protocolMajor() == QLatin1String("2");
        Subscription incomplete31 = v3sub;
        incomplete31.nodes.first().awg.disableCookies.reset();
        const bool bundleGateOk = !SubscriptionParser::validate(incomplete31).isEmpty();
        QByteArray invalidToggleJson = v3json;
        invalidToggleJson.replace("\"RandomTrailers\": true",
                                  "\"RandomTrailers\": \"maybe\"");
        Subscription invalidToggleSub; QString invalidToggleError;
        const bool invalidToggleParsed = SubscriptionParser::parse(
            invalidToggleJson, invalidToggleSub, invalidToggleError);
        const bool encodingGateOk = invalidToggleParsed
                                    && !SubscriptionParser::validate(invalidToggleSub).isEmpty();
        printf("awg31: fields=%d clamp=%d emit=%d unknown=%d parity20=%d report=%d ver=%d bundle=%d encoding=%d\n",
               fieldsOk, kaOk, emitOk, unknownKeyOk, parityOk, repOk, verOk,
               bundleGateOk, encodingGateOk);
        if (!verOk) { fprintf(stderr, "FAIL: protocolMajor mismatch\n"); return 15; }
        if (!(fieldsOk && kaOk && emitOk && unknownKeyOk && parityOk && repOk
              && bundleGateOk && encodingGateOk)) {
            fprintf(stderr, "FAIL: awg3.1 plumbing mismatch\n"); return 14;
        }
        printf("awg31: OK (typed bool parse→build, v3 keys, unknown-key drop, parity 2.0, secret-safe report)\n");
    }

    printf("OK: parsed + config + enrollment + selector + healthloop + signalquality + mtproto + goodput + youtube + awg3\n");
    return 0;
}
