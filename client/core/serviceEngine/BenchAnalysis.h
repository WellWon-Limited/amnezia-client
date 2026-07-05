// AVPN serviceEngine — ЧИСТАЯ аналитика результатов бенча (без I/O, header-only, тестируется в
// tests/parse_check.cpp). Два инструмента:
//   • verdicts(result)   — авто-диагнозы по ОДНОМУ замеру (bufferbloat, потери, низкий goodput...);
//   • compare(a, b)      — парное сравнение двух замеров (например tribe-bypass-off vs amnezia):
//                          дельты по ключевым метрикам + вердикт «где хуже» (методика A/B — та же,
//                          что tools/connect-bench: одна нода/ключ/сеть, меняется только клиент).
// Пороги — эмпирика индустрии: bufferbloat = loaded/base RTT (Apple RPM-подход), RU-троттл ~128 кбит/с,
// DNS >80мс = медленный резолвер (типичный ISP <30мс).
#pragma once

#include <QJsonArray>
#include <QJsonObject>
#include <QString>

#include <cmath>

namespace avpn {
namespace bench {

// пороги (задокументированы выше; менять синхронно с тестами)
constexpr double kDnsSlowMs = 80;          // медиана DNS выше — медленный/далёкий резолвер
constexpr double kBufferbloatRatio = 2.5;  // loaded_rtt/base_rtt выше — очередь на аплинке/в туннеле
constexpr double kLowGoodputMbit = 5.0;    // ниже при живом RTT — подозрение на MTU/троттлинг/потери
constexpr double kLossPctBad = 10.0;       // потери ICMP выше — плохой путь
constexpr double kDeltaTtfbPct = 15.0;     // A/B: TTFB хуже более чем на … % = существенно
constexpr double kDeltaDownPct = 20.0;     // A/B: скорость ниже более чем на … % = существенно
constexpr double kDeltaRttPct = 25.0;      // A/B: RTT хуже более чем на … % = существенно

inline double num(const QJsonObject &o, const char *k, double def = -1)
{
    const QJsonValue v = o.value(QLatin1String(k));
    return v.isDouble() ? v.toDouble() : def;
}

inline QJsonObject mkVerdict(const char *code, const char *severity, const QString &text)
{
    QJsonObject v;
    v.insert(QStringLiteral("code"), QLatin1String(code));
    v.insert(QStringLiteral("severity"), QLatin1String(severity)); // info | warn | bad
    v.insert(QStringLiteral("text"), text);
    return v;
}

// Авто-диагнозы по одному результату schema:1 (BenchRunner::assemble).
inline QJsonArray verdicts(const QJsonObject &r)
{
    QJsonArray out;
    const QJsonObject dns = r.value(QStringLiteral("dns")).toObject();
    const QJsonObject http = r.value(QStringLiteral("http")).toObject();
    const QJsonObject thr = r.value(QStringLiteral("throughput")).toObject();
    const QJsonObject nq = r.value(QStringLiteral("network_quality")).toObject();

    const double dnsMs = num(dns, "median_ms");
    if (dnsMs > kDnsSlowMs)
        out.append(mkVerdict("dns-slow", "warn",
                             QStringLiteral("DNS медленный (медиана %1 мс): далёкий/перегруженный резолвер").arg(qRound(dnsMs))));

    const double base = num(nq, "base_rtt_ms");
    const double loaded = num(nq, "loaded_rtt_ms");
    if (base > 0 && loaded > 0 && loaded / base > kBufferbloatRatio)
        out.append(mkVerdict("bufferbloat", "warn",
                             QStringLiteral("RTT под нагрузкой ×%1 от покоя (%2→%3 мс): буферизация — страницы «тупят» при загрузках")
                                 .arg(QString::number(loaded / base, 'f', 1)).arg(qRound(base)).arg(qRound(loaded))));

    const double down = num(thr, "down_mbit", 0);
    if (down > 0 && down < kLowGoodputMbit && base > 0 && base < 200)
        out.append(mkVerdict("low-goodput", "bad",
                             QStringLiteral("Скорость всего %1 Мбит/с при RTT %2 мс: подозрение на MTU/троттлинг/потери")
                                 .arg(QString::number(down, 'f', 1)).arg(qRound(base))));

    // HTTP-ошибки: RU-корпус (ya.ru/vk/ozon) при bypass_on идёт RU-direct МИМО туннеля — его провал
    // означает «прямой путь из текущей сети не работает» (за границей с ручным lock — норма), а НЕ
    // проблему туннеля. Поэтому провалы делим: RU-direct → отдельный вердикт с причиной по error_kind
    // (HostNotFound = DNS-маска не резолвит, Timeout = прямой маршрут молчит), заграничные — как раньше.
    const bool bypassOn = r.value(QStringLiteral("extra")).toObject()
                              .value(QStringLiteral("bypass_on")).toBool();
    auto isRuUrl = [](const QString &u) {
        return u.contains(QLatin1String("ya.ru")) || u.contains(QLatin1String("vk.com"))
            || u.contains(QLatin1String("ozon.ru"));
    };
    int ruFail = 0, ruDns = 0, ruTimeout = 0, foreignFail = 0;
    const QJsonArray httpProbes = http.value(QStringLiteral("probes")).toArray();
    for (const QJsonValue &v : httpProbes) {
        const QJsonObject p = v.toObject();
        if (!p.value(QStringLiteral("error")).toBool())
            continue;
        if (isRuUrl(p.value(QStringLiteral("url")).toString())) {
            ++ruFail;
            const QString kind = p.value(QStringLiteral("error_kind")).toString();
            if (kind.contains(QLatin1String("HostNotFound"))) ++ruDns;
            else if (kind.contains(QLatin1String("Timeout"))) ++ruTimeout;
        } else {
            ++foreignFail;
        }
    }
    const int failures = http.value(QStringLiteral("failures")).toInt();
    if (httpProbes.isEmpty())
        foreignFail = failures; // старые замеры без probes[]: прежнее поведение (без RU-разбора)
    if (ruFail > 0 && bypassOn && !httpProbes.isEmpty()) {
        QString cause;
        if (ruDns > 0 && ruTimeout > 0) cause = QStringLiteral("DNS-маска не отвечает и прямой маршрут молчит");
        else if (ruDns > 0)             cause = QStringLiteral("DNS-маска не резолвит (Host not found)");
        else if (ruTimeout > 0)         cause = QStringLiteral("прямой маршрут молчит (timeout)");
        else                            cause = QStringLiteral("см. error_kind проб");
        out.append(mkVerdict("ru-direct-down", "warn",
                             QStringLiteral("RU-direct не работает из текущей сети: %1 RU-сайт(а) идут напрямую мимо VPN и не открылись — %2. Туннель это не характеризует; за пределами РФ при включённом байпасе — ожидаемо")
                                 .arg(ruFail).arg(cause)));
    } else {
        foreignFail += (bypassOn && !httpProbes.isEmpty()) ? 0 : ruFail; // bypass off → RU шёл через туннель, считаем как обычные
    }
    if (foreignFail > 0)
        out.append(mkVerdict("http-failures", foreignFail > 2 ? "bad" : "warn",
                             QStringLiteral("HTTP-ошибок: %1 из корпуса — часть сайтов не открылась").arg(foreignFail)));

    // ICMP: unreachable по всем целям = info (часто фильтруется). Потери = bad ТОЛЬКО при ≥2
    // потерянных пакетах: серия короткая (sent=5–10), один недошедший пакет — 10–20% «потерь»,
    // но это шум замера/rate-limit цели, а не нестабильный путь (реальные данные: baseline 0%,
    // следом 20–40% на том же идеальном пути). Единичная потеря — отдельный info.
    int unreachable = 0, total = 0, lostMax = 0;
    double lossMax = 0;
    for (const QJsonValue &v : r.value(QStringLiteral("ping")).toArray()) {
        const QJsonObject p = v.toObject();
        ++total;
        if (p.value(QStringLiteral("unreachable")).toBool()) { ++unreachable; continue; }
        const double loss = num(p, "loss_pct", 0);
        const double sent = num(p, "sent", 0);
        // старые замеры без sent: любые потери считаем значимыми (прежнее поведение)
        const int lost = sent > 0 ? int(std::lround(loss * sent / 100.0)) : (loss > 0 ? 2 : 0);
        lossMax = std::max(lossMax, loss);
        lostMax = std::max(lostMax, lost);
    }
    if (total > 0 && unreachable == total)
        out.append(mkVerdict("icmp-blocked", "info",
                             QStringLiteral("ICMP не проходит (часто фильтруется — не обязательно проблема)")));
    else if (lossMax >= kLossPctBad && lostMax >= 2)
        out.append(mkVerdict("packet-loss", "bad",
                             QStringLiteral("Потери пакетов до %1% — нестабильный путь").arg(qRound(lossMax))));
    else if (lostMax == 1)
        out.append(mkVerdict("packet-loss-single", "info",
                             QStringLiteral("Единичная потеря ICMP-пакета — скорее шум замера, чем проблема пути")));

    // bench v5: сплит по ФАКТУ. Гейт по extra.tunnel_config.split_on (сеялся ли сплит ЭТИМ подъёмом):
    // на РФ-ноде или при выключенных тумблерах совпадение egress — норма, не leak.
    const QJsonObject extra = r.value(QStringLiteral("extra")).toObject();
    const QJsonObject split = r.value(QStringLiteral("split_check")).toObject();
    const bool splitOn = extra.value(QStringLiteral("tunnel_config")).toObject()
                              .value(QStringLiteral("split_on")).toBool();
    if (splitOn && split.value(QStringLiteral("ru_reachable")).toBool()
        && split.value(QStringLiteral("ru_equals_tunnel_egress")).toBool())
        out.append(mkVerdict("split-leak", "bad",
                             QStringLiteral("Split-leak: RU-чекер видит IP туннеля — рунет ушёл ЧЕРЕЗ VPN, хотя сплит включён (сев не применился/маршруты не встали)")));

    // bench v5: IPv6 — резолв есть, а v6-путь мёртв (класс IPv6-дыры RU-direct). info: у многих
    // сетей v6 нет вовсе (aaaa_ok=false) — это не проблема, молчим.
    const QJsonObject v6 = r.value(QStringLiteral("ipv6")).toObject();
    if (v6.value(QStringLiteral("aaaa_ok")).toBool()
        && !v6.value(QStringLiteral("https_ok")).toBool())
        out.append(mkVerdict("ipv6-dead", "info",
                             QStringLiteral("IPv6 резолвится, но соединение не проходит — v6-путь битый (проверь маршруты/утечку v6)")));

    // bench v5: path-MTU против конфигового. Меньше конфига = класс blackhole «большие пакеты
    // молча тонут» (страницы наполовину, TLS-обрывы). Гейт: замер шёл через НАШ туннель
    // (tunnel_config есть) и проба реально прошла.
    const QJsonObject mtuP = r.value(QStringLiteral("mtu_probe")).toObject();
    const int cfgMtu = int(num(extra.value(QStringLiteral("tunnel_config")).toObject(), "mtu", 0));
    const int pathMtu = int(num(mtuP, "path_mtu", 0));
    if (mtuP.value(QStringLiteral("probed")).toBool() && cfgMtu > 0 && pathMtu > 0 && pathMtu < cfgMtu)
        out.append(mkVerdict("mtu-mismatch", "bad",
                             QStringLiteral("MTU-конфликт: путь пропускает %1, конфиг туннеля %2 — пакеты полного размера тонут (класс «сайты наполовину грузятся»)")
                                 .arg(pathMtu).arg(cfgMtu)));

    // связность вовсе мертва? (все стадии пустые)
    if (dnsMs < 0 && num(http, "median_ttfb_ms") < 0 && down <= 0)
        out.append(mkVerdict("no-connectivity", "bad", QStringLiteral("Сеть не отвечает ни по одной пробе")));
    return out;
}

// Парное сравнение: b относительно a («b хуже a на X%»). a = эталон (обычно baseline или amnezia).
// Возвращает {deltas:[{metric,a,b,pct,worse}], significant:[тексты существенных ухудшений b]}.
inline QJsonObject compare(const QJsonObject &a, const QJsonObject &b)
{
    struct M { const char *sect; const char *key; const char *title; bool lowerBetter; double sigPct; };
    static const M metrics[] = {
        { "dns", "median_ms", "DNS", true, kDeltaRttPct },
        { "http", "median_ttfb_ms", "TTFB", true, kDeltaTtfbPct },
        { "http", "median_total_ms", "Страница", true, kDeltaTtfbPct },
        { "throughput", "down_mbit", "Загрузка", false, kDeltaDownPct },
        { "throughput", "up_mbit", "Отдача", false, kDeltaDownPct },
        { "network_quality", "base_rtt_ms", "RTT", true, kDeltaRttPct },
        { "network_quality", "loaded_rtt_ms", "RTT под нагрузкой", true, kDeltaRttPct },
        // TCP/TLS-фазы: разложение «где именно медленнее» (маршрут/DPI до хоста vs шифрование)
        { "tls", "median_tcp_ms", "TCP-connect", true, kDeltaRttPct },
        { "tls", "median_handshake_ms", "TLS-handshake", true, kDeltaRttPct },
    };
    QJsonArray deltas;
    QJsonArray significant;
    for (const M &m : metrics) {
        const double va = num(a.value(QLatin1String(m.sect)).toObject(), m.key);
        const double vb = num(b.value(QLatin1String(m.sect)).toObject(), m.key);
        if (va <= 0 || vb <= 0)
            continue;
        const double pct = (vb - va) / va * 100.0;         // + = b больше a
        const bool worse = m.lowerBetter ? pct > 0 : pct < 0;
        QJsonObject d;
        d.insert(QStringLiteral("metric"), QLatin1String(m.title));
        d.insert(QStringLiteral("a"), va);
        d.insert(QStringLiteral("b"), vb);
        d.insert(QStringLiteral("pct"), std::round(pct * 10) / 10);
        d.insert(QStringLiteral("worse"), worse);
        deltas.append(d);
        if (worse && std::abs(pct) >= m.sigPct)
            significant.append(QStringLiteral("%1: %2 (%3%)")
                                   .arg(QLatin1String(m.title),
                                        m.lowerBetter ? QStringLiteral("хуже") : QStringLiteral("ниже"),
                                        QString::number(std::abs(std::round(pct)))));
    }
    QJsonObject out;
    out.insert(QStringLiteral("deltas"), deltas);
    out.insert(QStringLiteral("significant"), significant);
    return out;
}

} // namespace bench
} // namespace avpn
