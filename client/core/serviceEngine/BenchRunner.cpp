#include "BenchRunner.h"

#include "BenchAnalysis.h"
#include "RttProbeIcmp.h"

#include <QDateTime>
#include <QDnsLookup>
#include <QHostInfo>
#include <QJsonDocument>
#include <QMetaEnum>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QRegularExpression> // bench v5: извлечение IPv4 из RU-чекера (stageSplit)
#include <QSslSocket>
#include <QTimer>
#include <QUrl>

#include <algorithm>
#include <memory>

namespace avpn {

// Корпус = tools/connect-bench/bench.sh (зарубежные + RU) — чтобы замеры сводились 1:1.
static const QStringList kHosts = {
    QStringLiteral("www.google.com"),   QStringLiteral("www.youtube.com"),
    QStringLiteral("en.wikipedia.org"), QStringLiteral("github.com"),
    QStringLiteral("www.apple.com"),    QStringLiteral("ya.ru"),
    QStringLiteral("vk.com"),           QStringLiteral("www.ozon.ru"),
};
// lite (свип по нодам): минимум, но с обеих сторон занавеса (заруб + RU)
static const QStringList kHostsLite = {
    QStringLiteral("www.google.com"), QStringLiteral("ya.ru"), QStringLiteral("en.wikipedia.org"),
};
static const qint64 kHttpReadCap = 1536 * 1024;      // страница: дальше 1.5МБ не читаем (total = до капа)
static const char *kDownUrl = "https://speed.cloudflare.com/__down?bytes=26214400"; // 25 МБ
static const char *kDownUrlLite = "https://speed.cloudflare.com/__down?bytes=8388608"; // 8 МБ
static const char *kUpUrl = "https://speed.cloudflare.com/__up";
static const qint64 kUpBytes = 5 * 1024 * 1024;      // 5 МБ (в lite отдача не меряется)
static const char *kRttUrl = "https://connectivitycheck.gstatic.com/generate_204";
static const int kLoadRttPeriodMs = 500;
static const int kStageTimeoutMs = 30000;
static const int kTlsTimeoutMs = 8000;

QStringList BenchRunner::hosts() const { return m_lite ? kHostsLite : kHosts; }
// TCP/TLS-фазы: хосты с обеих сторон занавеса (разложение DNS/TCP/TLS вместо общего TTFB).
// vk.com — второй RU-хост на другом AS: при bypass-on ya+vk идут direct, google через туннель —
// пара точек с каждой стороны отделяет «медленный маршрут» от «медленный конкретный хост».
QStringList BenchRunner::tlsHosts() const
{
    return { QStringLiteral("www.google.com"), QStringLiteral("ya.ru"), QStringLiteral("vk.com") };
}

BenchRunner::BenchRunner(QNetworkAccessManager *nam, QObject *parent)
    : QObject(parent), m_nam(nam), m_icmp(new RttProbeIcmp(this))
{
    m_loadTimer = new QTimer(this);
    m_loadTimer->setInterval(kLoadRttPeriodMs);
}

BenchRunner::~BenchRunner()
{
    cancel();
}

void BenchRunner::start(const QString &label, const QJsonObject &extra, bool lite)
{
    if (m_running)
        return;
    m_running = true;
    m_lite = lite;
    ++m_epoch;
    m_label = label.isEmpty() ? QStringLiteral("unlabeled") : label;
    m_extra = extra;
    m_loc.clear(); m_colo.clear(); m_traceIp.clear();
    m_splitCheck = QJsonObject(); m_ipv6 = QJsonObject();
    m_mtuIdx = 0; m_mtu = QJsonObject();
    m_dnsIdx = 0; m_dnsProbes = QJsonArray();
    m_tlsIdx = 0; m_tlsProbes = QJsonArray(); m_tlsTcpMs = -1;
    m_httpIdx = 0; m_httpProbes = QJsonArray();
    m_pingRound = 0; m_icmpSamples.clear(); m_pingProbes = QJsonArray();
    m_idleIdx = 0; m_idleRtt.clear(); m_loadedRtt.clear();
    m_downBytes = 0; m_downFirstByteMs = -1; m_downEndMs = -1;
    m_upMbit = -1;
    stageTrace();
}

void BenchRunner::cancel()
{
    ++m_epoch; // все висящие колбэки станут стейлом
    m_running = false;
    m_loadTimer->stop();
    m_loadTimer->disconnect(this); // иначе повторный start() навесит второй обработчик timeout
    if (m_loadPending) {
        m_loadPending->abort();
        m_loadPending.clear();
    }
    abortReply();
    if (m_dns) {
        m_dns->abort();
        m_dns->deleteLater();
        m_dns = nullptr;
    }
    if (m_hostLookup != -1) {
        QHostInfo::abortHostLookup(m_hostLookup);
        m_hostLookup = -1;
    }
    if (m_ssl) {
        m_ssl->disconnect(this);
        m_ssl->abort();
        m_ssl->deleteLater();
        m_ssl = nullptr;
    }
    m_icmp->cancel();
}

void BenchRunner::abortReply()
{
    if (m_reply) {
        QNetworkReply *r = m_reply;
        m_reply.clear();
        r->disconnect(this);
        r->abort();
        r->deleteLater();
    }
}

// --- стадия 0: egress-гео (loc/colo, БЕЗ ip) -------------------------------------------------
void BenchRunner::stageTrace()
{
    const int epoch = m_epoch;
    QNetworkRequest req{QUrl(QStringLiteral("https://www.cloudflare.com/cdn-cgi/trace"))};
    req.setTransferTimeout(10000);
    QNetworkReply *r = m_nam->get(req);
    m_reply = r;
    connect(r, &QNetworkReply::finished, this, [this, r, epoch] {
        r->deleteLater();
        if (epoch != m_epoch) return;
        const QString body = QString::fromUtf8(r->readAll());
        for (const QString &line : body.split(QLatin1Char('\n'))) {
            if (line.startsWith(QLatin1String("loc=")))  m_loc = line.mid(4).trimmed();
            if (line.startsWith(QLatin1String("colo="))) m_colo = line.mid(5).trimmed();
            // bench v5: ip= держим ТОЛЬКО в памяти для сравнения в stageSplit — в JSON не пишется (PII)
            if (line.startsWith(QLatin1String("ip=")))   m_traceIp = line.mid(3).trimmed();
        }
        stageDns();
    });
}

// --- стадия 1: DNS (query time + первая A-запись) --------------------------------------------
void BenchRunner::stageDns()
{
    emit stageChanged(QStringLiteral("dns"));
    m_dnsIdx = 0;
    dnsNext();
}

void BenchRunner::dnsNext()
{
    if (m_dnsIdx >= hosts().size()) {
        stageTls();
        return;
    }
    const int epoch = m_epoch;
    const QString host = hosts().at(m_dnsIdx);
    m_dns = new QDnsLookup(QDnsLookup::A, host, this);
    m_t.start();
    connect(m_dns, &QDnsLookup::finished, this, [this, epoch, host] {
        QDnsLookup *d = m_dns;
        m_dns = nullptr;
        if (d) d->deleteLater();
        if (epoch != m_epoch) return;
        if (d && d->error() == QDnsLookup::NoError && !d->hostAddressRecords().isEmpty()) {
            QJsonObject o;
            o.insert(QStringLiteral("host"), host);
            o.insert(QStringLiteral("query_ms"), double(m_t.elapsed()));
            o.insert(QStringLiteral("a"), d->hostAddressRecords().first().value().toString());
            m_dnsProbes.append(o);
            ++m_dnsIdx;
            dnsNext();
            return;
        }
        // iOS: QDnsLookup не реализован (нет res_*-API) — вся стадия молча давала null.
        // Fallback на системный резолвер: query_ms сопоставим, A-запись честная.
        dnsFallback(host);
    });
    m_dns->lookup();
}

void BenchRunner::dnsFallback(const QString &host)
{
    const int epoch = m_epoch;
    m_t.start();
    m_hostLookup = QHostInfo::lookupHost(host, this, [this, epoch, host](const QHostInfo &hi) {
        if (epoch != m_epoch) return;
        m_hostLookup = -1;
        QJsonObject o;
        o.insert(QStringLiteral("host"), host);
        if (hi.error() == QHostInfo::NoError && !hi.addresses().isEmpty()) {
            const double ms = double(m_t.elapsed());
            o.insert(QStringLiteral("query_ms"), ms);
            o.insert(QStringLiteral("a"), hi.addresses().first().toString());
            o.insert(QStringLiteral("method"), QStringLiteral("system")); // может отдать из OS-кэша
            // 0 мс = ответ из OS-кэша, не сетевой замер (реальные данные iOS: все 0 после первого
            // прогона) — помечаем, из медианы исключается в assemble
            if (ms <= 0)
                o.insert(QStringLiteral("cached"), true);
        } else {
            o.insert(QStringLiteral("query_ms"), QJsonValue::Null);
            o.insert(QStringLiteral("a"), QJsonValue::Null);
            o.insert(QStringLiteral("error"), hi.errorString()); // ПОЧЕМУ не разрезолвилось
        }
        m_dnsProbes.append(o);
        ++m_dnsIdx;
        dnsNext();
    });
}

// --- стадия 1b: TCP/TLS-фазы (разложение пути: connect vs handshake) ---------------------------
void BenchRunner::stageTls()
{
    emit stageChanged(QStringLiteral("tls"));
    m_tlsIdx = 0;
    tlsNext();
}

void BenchRunner::tlsNext()
{
    if (m_tlsIdx >= tlsHosts().size()) {
        stageHttp();
        return;
    }
    const int epoch = m_epoch;
    const QString host = tlsHosts().at(m_tlsIdx);
    m_tlsTcpMs = -1;
    m_ssl = new QSslSocket(this);
    m_t.start();
    QSslSocket *s = m_ssl;
    auto done = std::make_shared<bool>(false); // сторож-таймер может пережить deleteLater → один вызов
    auto finish = [this, s, epoch, host, done](qint64 tcpMs, qint64 tlsMs) {
        if (*done) return;
        *done = true;
        if (m_ssl == s) m_ssl = nullptr;
        s->disconnect(this);
        s->abort();
        s->deleteLater();
        if (epoch != m_epoch) return;
        QJsonObject o;
        o.insert(QStringLiteral("host"), host);
        if (tcpMs >= 0) o.insert(QStringLiteral("tcp_ms"), double(tcpMs));
        if (tlsMs >= 0) {
            o.insert(QStringLiteral("tls_ms"), double(tlsMs)); // полный до encrypted
            if (tcpMs >= 0)
                o.insert(QStringLiteral("handshake_ms"), double(tlsMs - tcpMs));
        }
        if (tlsMs < 0) o.insert(QStringLiteral("error"), true);
        m_tlsProbes.append(o);
        ++m_tlsIdx;
        tlsNext();
    };
    connect(s, &QSslSocket::connected, this, [this, epoch] {
        if (epoch != m_epoch) return;
        m_tlsTcpMs = m_t.elapsed();
    });
    connect(s, &QSslSocket::encrypted, this, [this, epoch, finish] {
        if (epoch != m_epoch) return;
        finish(m_tlsTcpMs, m_t.elapsed());
    });
    connect(s, &QSslSocket::errorOccurred, this, [this, epoch, finish](QAbstractSocket::SocketError) {
        if (epoch != m_epoch) return;
        finish(m_tlsTcpMs, -1);
    });
    QTimer::singleShot(kTlsTimeoutMs, s, [this, epoch, finish] {
        if (epoch != m_epoch) return;
        finish(m_tlsTcpMs, -1); // не дождались encrypted
    });
    s->connectToHostEncrypted(host, 443);
}

// --- стадия 2: HTTP-тайминги корпуса (TTFB/total; 2 прогона, lite — 1) --------------------------
void BenchRunner::stageHttp()
{
    emit stageChanged(QStringLiteral("http"));
    m_httpIdx = 0;
    httpNext();
}

void BenchRunner::httpNext()
{
    const int runs = m_lite ? 1 : 2;
    if (m_httpIdx >= hosts().size() * runs) {
        stagePing();
        return;
    }
    const int epoch = m_epoch;
    const QString host = hosts().at(m_httpIdx / runs);
    const int run = m_httpIdx % runs + 1;
    QNetworkRequest req{QUrl(QStringLiteral("https://%1/").arg(host))};
    req.setTransferTimeout(25000);
    m_httpTtfbMs = -1;
    m_httpBytes = 0;
    m_t.start();
    QNetworkReply *r = m_nam->get(req);
    m_reply = r;
    connect(r, &QNetworkReply::readyRead, this, [this, r, epoch] {
        if (epoch != m_epoch) return;
        if (m_httpTtfbMs < 0)
            m_httpTtfbMs = m_t.elapsed();
        m_httpBytes += r->readAll().size(); // дренируем; тело не нужно
        if (m_httpBytes > kHttpReadCap)
            r->abort(); // finished придёт с OperationCanceledError — total уже показателен
    });
    connect(r, &QNetworkReply::finished, this, [this, r, epoch, host, run] {
        r->deleteLater();
        if (epoch != m_epoch) return;
        const qint64 total = m_t.elapsed();
        const int code = r->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const bool truncated = (r->error() == QNetworkReply::OperationCanceledError && m_httpTtfbMs >= 0);
        const bool ok = (r->error() == QNetworkReply::NoError || truncated) && m_httpTtfbMs >= 0;
        QJsonObject o;
        o.insert(QStringLiteral("url"), QStringLiteral("https://%1/").arg(host));
        o.insert(QStringLiteral("run"), run);
        if (ok) {
            o.insert(QStringLiteral("ttfb_ms"), double(m_httpTtfbMs));
            o.insert(QStringLiteral("total_ms"), double(total));
            o.insert(QStringLiteral("code"), code);
            o.insert(QStringLiteral("bytes"), double(m_httpBytes)); // сколько реально дочитали (кап 1.5МБ)
        } else {
            // ПОЧЕМУ упало — без этого «error:true» неотличим: таймаут (блокировка/дроп) vs
            // TLS-ошибка (DPI/MitM) vs connection refused (гео-бан хоста, кейс ozon с загран-IP)
            o.insert(QStringLiteral("error"), true);
            o.insert(QStringLiteral("error_kind"), QLatin1String(
                QMetaEnum::fromType<QNetworkReply::NetworkError>().valueToKey(r->error())));
            o.insert(QStringLiteral("error_str"), r->errorString());
            if (code > 0) o.insert(QStringLiteral("code"), code);
        }
        m_httpProbes.append(o);
        ++m_httpIdx;
        httpNext();
    });
}

// --- стадия 3: серия ICMP → loss/jitter (1.1.1.1 / 8.8.8.8; unprivileged, Win — стаб) ----------
void BenchRunner::stagePing()
{
    emit stageChanged(QStringLiteral("ping"));
    m_pingRound = 0;
    m_icmpSamples.clear();
    pingRound();
}

void BenchRunner::pingRound()
{
    // 10/5 раундов: на 5 пингах один потерянный пакет = «20% потерь» — статистика из шума.
    // Раунд на здоровом пути ~RTT (probeAll ждёт оба ответа), полная серия — секунды.
    const int rounds = m_lite ? 5 : 10;
    if (m_pingRound >= rounds) {
        // финализация: loss = недошедшие раунды, jitter = max-min удачных
        for (auto it = m_icmpSamples.constBegin(); it != m_icmpSamples.constEnd(); ++it) {
            const QVector<double> &s = it.value();
            QJsonObject o;
            o.insert(QStringLiteral("target"), it.key());
            o.insert(QStringLiteral("sent"), rounds); // размер серии — для честной оценки потерь
            if (s.isEmpty()) {
                o.insert(QStringLiteral("unreachable"), true);
            } else {
                double mn = s.first(), mx = s.first(), sum = 0;
                for (double v : s) { mn = std::min(mn, v); mx = std::max(mx, v); sum += v; }
                o.insert(QStringLiteral("rtt_min"), mn);
                o.insert(QStringLiteral("rtt_avg"), sum / s.size());
                o.insert(QStringLiteral("rtt_max"), mx);
                o.insert(QStringLiteral("jitter_ms"), mx - mn);
                o.insert(QStringLiteral("loss_pct"), double(rounds - s.size()) / rounds * 100.0);
            }
            m_pingProbes.append(o);
        }
        stageSplit();
        return;
    }
    const int epoch = m_epoch;
    const QList<RttTarget> targets = {
        { QStringLiteral("1.1.1.1"), QStringLiteral("1.1.1.1"), 0 },
        { QStringLiteral("8.8.8.8"), QStringLiteral("8.8.8.8"), 0 },
    };
    // цели фиксируем в сэмплах заранее: полная тишина раунда тоже учитывается (loss)
    for (const RttTarget &t : targets)
        if (!m_icmpSamples.contains(t.nodeId))
            m_icmpSamples.insert(t.nodeId, {});
    m_icmp->probeAll(
        targets, 2000,
        [this, epoch](const QString &id, int rttMs) {
            if (epoch != m_epoch) return;
            if (rttMs >= 0)
                m_icmpSamples[id].append(double(rttMs));
        },
        [this, epoch] {
            if (epoch != m_epoch) return;
            ++m_pingRound;
            pingRound();
        });
}

// --- стадия 3b (bench v5): сплит по ФАКТУ + IPv6 ----------------------------------------------
// Сплит: RU-хостинговый чекер (2ip.ru ∈ рунет-CIDR ⇒ при bypass_on обязан идти direct) против
// egress туннеля (ip= из cf-trace). Пишем ТОЛЬКО булевы «дошёл/совпал» — сами IP не сохраняем (PII).
// ru_equals_tunnel_egress==true при включённом сплите = split-leak (рунет ушёл через туннель).
// IPv6: AAAA-резолв + v6-only цель — ловит «AAAA есть, а v6-путь мёртв» (класс IPv6-дыры RU-direct).
// lite-режим пропускает стадию (свип нод должен быть коротким).
void BenchRunner::stageSplit()
{
    if (m_lite) {
        stageIdleRtt();
        return;
    }
    emit stageChanged(QStringLiteral("split"));
    // Сплит-проверка имеет смысл ТОЛЬКО через НАШ туннель: у baseline/amnezia сплита нет по
    // определению (реальный фидбек: «зачем мерять сплит через нативную Amnezia?!»). IPv6/MTU
    // остаются — они полезны как референс любого пути.
    if (m_extra.value(QStringLiteral("tunnel_state")).toString() != QLatin1String("connected")) {
        splitIpv6Lookup();
        return;
    }
    const int epoch = m_epoch;
    QNetworkRequest req{QUrl(QStringLiteral("https://2ip.ru/"))};
    req.setTransferTimeout(6000);
    QNetworkReply *r = m_nam->get(req);
    m_reply = r;
    connect(r, &QNetworkReply::finished, this, [this, r, epoch] {
        r->deleteLater();
        if (epoch != m_epoch) return;
        const bool ok = (r->error() == QNetworkReply::NoError);
        m_splitCheck.insert(QStringLiteral("ru_reachable"), ok);
        if (ok && !m_traceIp.isEmpty()) {
            static const QRegularExpression ipRe(QStringLiteral("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b"));
            const QRegularExpressionMatch m = ipRe.match(QString::fromUtf8(r->readAll()));
            if (m.hasMatch())
                m_splitCheck.insert(QStringLiteral("ru_equals_tunnel_egress"),
                                    m.captured(0) == m_traceIp);
        }
        splitIpv6Lookup();
    });
}

void BenchRunner::splitIpv6Lookup()
{
    const int epoch = m_epoch;
    // QHostInfo (не QDnsLookup): работает и на iOS; AAAA-факт = есть ли v6-адреса в ответе системы
    m_hostLookup = QHostInfo::lookupHost(QStringLiteral("ipv6.google.com"), this,
                                         [this, epoch](const QHostInfo &info) {
        if (epoch != m_epoch) return;
        m_hostLookup = -1;
        bool hasV6 = false;
        for (const QHostAddress &a : info.addresses())
            if (a.protocol() == QAbstractSocket::IPv6Protocol) { hasV6 = true; break; }
        m_ipv6.insert(QStringLiteral("aaaa_ok"), hasV6);
        if (!hasV6) { // резолва нет — v6-HTTP заведомо не пойдёт, не тратим таймаут
            m_ipv6.insert(QStringLiteral("https_ok"), false);
            stageMtu(); // БАГ v5.0: уходили в stageIdleRtt — MTU-проба молча пропускалась без v6
            return;
        }
        splitIpv6Http();
    });
}

void BenchRunner::splitIpv6Http()
{
    const int epoch = m_epoch;
    QNetworkRequest req{QUrl(QStringLiteral("https://ipv6.google.com/generate_204"))}; // v6-only хост
    req.setTransferTimeout(6000);
    QNetworkReply *r = m_nam->get(req);
    m_reply = r;
    connect(r, &QNetworkReply::finished, this, [this, r, epoch] {
        r->deleteLater();
        if (epoch != m_epoch) return;
        const int code = r->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        m_ipv6.insert(QStringLiteral("https_ok"), r->error() == QNetworkReply::NoError
                                                  && (code == 204 || code == 200));
        stageMtu();
    });
}

// --- стадия 3c (bench v5): path-MTU через DF-ping ----------------------------------------------
// Нисходящий свип паддингов: первый прошедший размер = path-MTU ≈ payload+28. Ловит класс
// blackhole «конфиг MTU больше фактического пути» (страницы наполовину грузятся; awg S4-кейс).
// Через туннель EMSGSIZE на первом же размере > MTU utun — свип быстро скатывается к реальному.
namespace {
// payload'ы → пакеты 1500/1452/1420/1400/1380/1360/1308/1280 (частые пороги: ethernet/pppoe/awg/wg-mobile)
constexpr int kMtuPayloads[] = { 1472, 1424, 1392, 1372, 1352, 1332, 1280, 1252 };
constexpr int kMtuPayloadCount = int(sizeof(kMtuPayloads) / sizeof(kMtuPayloads[0]));
} // namespace

void BenchRunner::stageMtu()
{
    if (m_lite) {
        stageIdleRtt();
        return;
    }
    emit stageChanged(QStringLiteral("mtu"));
    m_mtuIdx = 0;
    mtuNext();
}

void BenchRunner::mtuNext()
{
    if (m_mtuIdx >= kMtuPayloadCount) {
        m_mtu.insert(QStringLiteral("probed"), false); // ни один размер не прошёл (ICMP фильтруется?)
        stageIdleRtt();
        return;
    }
    const int epoch = m_epoch;
    const int payload = kMtuPayloads[m_mtuIdx];
    m_icmp->probeMtuOne(QStringLiteral("1.1.1.1"), payload, 1200, [this, epoch, payload](bool ok) {
        if (epoch != m_epoch) return;
        if (ok) {
            m_mtu.insert(QStringLiteral("probed"), true);
            m_mtu.insert(QStringLiteral("path_mtu"), payload + 28); // ICMP(8) + IPv4(20)
            stageIdleRtt();
            return;
        }
        ++m_mtuIdx;
        mtuNext();
    });
}

QNetworkReply *BenchRunner::head204()
{
    QNetworkRequest req{QUrl(QString::fromLatin1(kRttUrl))};
    req.setTransferTimeout(8000);
    return m_nam->head(req);
}

// --- стадия 4: базовый app-layer RTT (idle) ---------------------------------------------------
// Первый HEAD несёт стоимость DNS+TCP+TLS до нового хоста (реальные данные: «базовый RTT 667 мс»
// при пинге 161 на дальней ноде) — он уходит в conn_setup_ms, медиана считается по остальным.
void BenchRunner::stageIdleRtt()
{
    emit stageChanged(QStringLiteral("rtt"));
    m_idleIdx = 0;
    idleRttNext();
}

void BenchRunner::idleRttNext()
{
    if (m_idleIdx >= (m_lite ? 4 : 6)) { // +1 к прежним 3/5: нулевой сэмпл — прогрев
        stageDown();
        return;
    }
    const int epoch = m_epoch;
    m_t.start();
    QNetworkReply *r = head204();
    m_reply = r;
    connect(r, &QNetworkReply::finished, this, [this, r, epoch] {
        r->deleteLater();
        if (epoch != m_epoch) return;
        if (r->error() == QNetworkReply::NoError)
            m_idleRtt.append(double(m_t.elapsed()));
        ++m_idleIdx;
        idleRttNext();
    });
}

// --- стадия 5: download 25МБ + latency-under-load (аналог RPM) --------------------------------
void BenchRunner::stageDown()
{
    emit stageChanged(QStringLiteral("down"));
    const int epoch = m_epoch;
    QNetworkRequest req{QUrl(QString::fromLatin1(m_lite ? kDownUrlLite : kDownUrl))};
    req.setTransferTimeout(kStageTimeoutMs * 2); // 25МБ на медленной сети
    QElapsedTimer *dl = new QElapsedTimer();
    dl->start();
    QNetworkReply *r = m_nam->get(req);
    m_reply = r;

    // rtt-зонды под нагрузкой: раз в 500мс, не более одного в полёте (m_loadPending)
    connect(m_loadTimer, &QTimer::timeout, this, [this, epoch] {
        if (epoch != m_epoch || m_loadPending) return;
        QElapsedTimer t; t.start();
        QNetworkReply *p = head204();
        m_loadPending = p;
        connect(p, &QNetworkReply::finished, this, [this, p, epoch, t] {
            p->deleteLater();
            if (m_loadPending == p) m_loadPending.clear();
            if (epoch != m_epoch) return;
            if (p->error() == QNetworkReply::NoError)
                m_loadedRtt.append(double(t.elapsed()));
        });
    });
    m_loadTimer->start();

    connect(r, &QNetworkReply::readyRead, this, [this, r, dl, epoch] {
        if (epoch != m_epoch) return;
        if (m_downFirstByteMs < 0)
            m_downFirstByteMs = dl->elapsed();
        m_downBytes += r->readAll().size();
    });
    connect(r, &QNetworkReply::finished, this, [this, r, dl, epoch] {
        r->deleteLater();
        const qint64 end = dl->elapsed();
        delete dl;
        if (epoch != m_epoch) return;
        m_loadTimer->stop();
        m_loadTimer->disconnect(this);
        m_downEndMs = end;
        stageUp();
    });
}

// --- стадия 6: upload 5МБ (в lite пропускается — экономия трафика при свипе) --------------------
void BenchRunner::stageUp()
{
    if (m_lite) {
        assemble();
        return;
    }
    emit stageChanged(QStringLiteral("up"));
    const int epoch = m_epoch;
    QNetworkRequest req{QUrl(QString::fromLatin1(kUpUrl))};
    req.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/octet-stream"));
    req.setTransferTimeout(kStageTimeoutMs * 2);
    m_t.start();
    QNetworkReply *r = m_nam->post(req, QByteArray(kUpBytes, '\0'));
    m_reply = r;
    connect(r, &QNetworkReply::finished, this, [this, r, epoch] {
        r->deleteLater();
        if (epoch != m_epoch) return;
        if (r->error() == QNetworkReply::NoError)
            m_upMbit = mbit(kUpBytes, m_t.elapsed());
        assemble();
    });
}

// --- сборка результата (форма = bench.sh schema:1) ---------------------------------------------
void BenchRunner::assemble()
{
    QVector<double> dnsMs, ttfbMs, totalMs;
    int httpFail = 0;
    for (const QJsonValue &v : m_dnsProbes)
        if (v.toObject().value(QStringLiteral("query_ms")).isDouble()
            && !v.toObject().value(QStringLiteral("cached")).toBool()) // OS-кэш ≠ замер DNS
            dnsMs.append(v.toObject().value(QStringLiteral("query_ms")).toDouble());
    for (const QJsonValue &v : m_httpProbes) {
        const QJsonObject o = v.toObject();
        if (o.value(QStringLiteral("error")).toBool()) { ++httpFail; continue; }
        ttfbMs.append(o.value(QStringLiteral("ttfb_ms")).toDouble());
        totalMs.append(o.value(QStringLiteral("total_ms")).toDouble());
    }
    const qint64 downWindow = (m_downFirstByteMs >= 0 && m_downEndMs > m_downFirstByteMs)
                                  ? m_downEndMs - m_downFirstByteMs : -1;

    auto num = [](double v) { return v < 0 ? QJsonValue(QJsonValue::Null) : QJsonValue(v); };

    QJsonObject egress;
    egress.insert(QStringLiteral("loc"), m_loc.isEmpty() ? QJsonValue(QJsonValue::Null) : QJsonValue(m_loc));
    egress.insert(QStringLiteral("cf_colo"), m_colo.isEmpty() ? QJsonValue(QJsonValue::Null) : QJsonValue(m_colo));
    QJsonObject network;
    network.insert(QStringLiteral("egress"), egress);

    QJsonObject dns;
    dns.insert(QStringLiteral("probes"), m_dnsProbes);
    dns.insert(QStringLiteral("median_ms"), num(median(dnsMs)));

    QJsonObject http;
    http.insert(QStringLiteral("probes"), m_httpProbes);
    http.insert(QStringLiteral("median_ttfb_ms"), num(median(ttfbMs)));
    http.insert(QStringLiteral("median_total_ms"), num(median(totalMs)));
    http.insert(QStringLiteral("failures"), httpFail);

    QJsonObject thr; // null = «не мерялось/упало», НЕ ноль (0 в сводке читается как «канал мёртв»)
    thr.insert(QStringLiteral("down_mbit"), downWindow > 0 ? QJsonValue(mbit(m_downBytes, downWindow))
                                                           : QJsonValue(QJsonValue::Null));
    thr.insert(QStringLiteral("up_mbit"), num(m_upMbit));

    // прогрев (DNS+TCP+TLS первого HEAD) — отдельная метрика, в медиану RTT не входит
    double connSetup = -1;
    QVector<double> idle = m_idleRtt;
    if (idle.size() >= 2)
        connSetup = idle.takeFirst();

    QJsonObject nq; // rpm считает только Apple networkQuality; наш аналог — loaded_rtt
    nq.insert(QStringLiteral("rpm"), QJsonValue::Null);
    nq.insert(QStringLiteral("base_rtt_ms"), num(median(idle)));
    nq.insert(QStringLiteral("loaded_rtt_ms"), num(median(m_loadedRtt)));
    nq.insert(QStringLiteral("conn_setup_ms"), num(connSetup));

    // TCP/TLS-фазы: медианы по пробам (разложение «где именно медленно»)
    QVector<double> tcpMs, hsMs;
    for (const QJsonValue &v : m_tlsProbes) {
        const QJsonObject o = v.toObject();
        if (o.value(QStringLiteral("tcp_ms")).isDouble()) tcpMs.append(o.value(QStringLiteral("tcp_ms")).toDouble());
        if (o.value(QStringLiteral("handshake_ms")).isDouble()) hsMs.append(o.value(QStringLiteral("handshake_ms")).toDouble());
    }
    QJsonObject tls;
    tls.insert(QStringLiteral("probes"), m_tlsProbes);
    tls.insert(QStringLiteral("median_tcp_ms"), num(median(tcpMs)));
    tls.insert(QStringLiteral("median_handshake_ms"), num(median(hsMs)));

    QJsonObject out;
    out.insert(QStringLiteral("schema"), 2); // bench v5: +split_check/ipv6/extra.tunnel_config (обратносовместимо)
    out.insert(QStringLiteral("label"), m_label);
    out.insert(QStringLiteral("mode"), m_lite ? QStringLiteral("lite") : QStringLiteral("full"));
    out.insert(QStringLiteral("ts"), QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd-HHmmss")));
    out.insert(QStringLiteral("network"), network);
    out.insert(QStringLiteral("dns"), dns);
    out.insert(QStringLiteral("tls"), tls);
    out.insert(QStringLiteral("http"), http);
    out.insert(QStringLiteral("ping"), m_pingProbes);
    out.insert(QStringLiteral("throughput"), thr);
    out.insert(QStringLiteral("network_quality"), nq);
    if (!m_splitCheck.isEmpty())
        out.insert(QStringLiteral("split_check"), m_splitCheck);
    if (!m_ipv6.isEmpty())
        out.insert(QStringLiteral("ipv6"), m_ipv6);
    if (!m_mtu.isEmpty())
        out.insert(QStringLiteral("mtu_probe"), m_mtu);
    out.insert(QStringLiteral("extra"), m_extra);
    out.insert(QStringLiteral("verdicts"), bench::verdicts(out)); // авто-диагнозы (BenchAnalysis.h)

    m_running = false;
    emit stageChanged(QStringLiteral("done"));
    emit finished(out);
}

} // namespace avpn
