#include "BenchRunner.h"

#include "RttProbeIcmp.h"

#include <QDateTime>
#include <QDnsLookup>
#include <QJsonDocument>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QTimer>
#include <QUrl>

#include <algorithm>

namespace avpn {

// Корпус = tools/connect-bench/bench.sh (зарубежные + RU) — чтобы замеры сводились 1:1.
static const QStringList kHosts = {
    QStringLiteral("www.google.com"),   QStringLiteral("www.youtube.com"),
    QStringLiteral("en.wikipedia.org"), QStringLiteral("github.com"),
    QStringLiteral("www.apple.com"),    QStringLiteral("ya.ru"),
    QStringLiteral("vk.com"),           QStringLiteral("www.ozon.ru"),
};
static const int kHttpRuns = 2;
static const qint64 kHttpReadCap = 1536 * 1024;      // страница: дальше 1.5МБ не читаем (total = до капа)
static const char *kDownUrl = "https://speed.cloudflare.com/__down?bytes=26214400"; // 25 МБ
static const char *kUpUrl = "https://speed.cloudflare.com/__up";
static const qint64 kUpBytes = 5 * 1024 * 1024;      // 5 МБ
static const char *kRttUrl = "https://connectivitycheck.gstatic.com/generate_204";
static const int kIdleRttCount = 5;
static const int kLoadRttPeriodMs = 500;
static const int kStageTimeoutMs = 30000;

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

void BenchRunner::start(const QString &label, const QJsonObject &extra)
{
    if (m_running)
        return;
    m_running = true;
    ++m_epoch;
    m_label = label.isEmpty() ? QStringLiteral("unlabeled") : label;
    m_extra = extra;
    m_loc.clear(); m_colo.clear();
    m_dnsIdx = 0; m_dnsProbes = QJsonArray();
    m_httpIdx = 0; m_httpProbes = QJsonArray();
    m_pingProbes = QJsonArray();
    m_idleIdx = 0; m_idleRtt.clear(); m_loadedRtt.clear();
    m_downBytes = 0; m_downFirstByteMs = -1; m_downEndMs = -1;
    m_upMbit = 0;
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
    if (m_dnsIdx >= kHosts.size()) {
        stageHttp();
        return;
    }
    const int epoch = m_epoch;
    const QString host = kHosts.at(m_dnsIdx);
    m_dns = new QDnsLookup(QDnsLookup::A, host, this);
    m_t.start();
    connect(m_dns, &QDnsLookup::finished, this, [this, epoch, host] {
        QDnsLookup *d = m_dns;
        m_dns = nullptr;
        if (d) d->deleteLater();
        if (epoch != m_epoch) return;
        QJsonObject o;
        o.insert(QStringLiteral("host"), host);
        if (d && d->error() == QDnsLookup::NoError && !d->hostAddressRecords().isEmpty()) {
            o.insert(QStringLiteral("query_ms"), double(m_t.elapsed()));
            o.insert(QStringLiteral("a"), d->hostAddressRecords().first().value().toString());
        } else {
            o.insert(QStringLiteral("query_ms"), QJsonValue::Null);
            o.insert(QStringLiteral("a"), QJsonValue::Null);
        }
        m_dnsProbes.append(o);
        ++m_dnsIdx;
        dnsNext();
    });
    m_dns->lookup();
}

// --- стадия 2: HTTP-тайминги корпуса (TTFB/total, 2 прогона) ----------------------------------
void BenchRunner::stageHttp()
{
    emit stageChanged(QStringLiteral("http"));
    m_httpIdx = 0;
    httpNext();
}

void BenchRunner::httpNext()
{
    if (m_httpIdx >= kHosts.size() * kHttpRuns) {
        stagePing();
        return;
    }
    const int epoch = m_epoch;
    const QString host = kHosts.at(m_httpIdx / kHttpRuns);
    const int run = m_httpIdx % kHttpRuns + 1;
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
        } else {
            o.insert(QStringLiteral("error"), true);
        }
        m_httpProbes.append(o);
        ++m_httpIdx;
        httpNext();
    });
}

// --- стадия 3: ICMP (1.1.1.1 / 8.8.8.8; unprivileged, Win — стаб → пусто) ---------------------
void BenchRunner::stagePing()
{
    emit stageChanged(QStringLiteral("ping"));
    const int epoch = m_epoch;
    const QList<RttTarget> targets = {
        { QStringLiteral("1.1.1.1"), QStringLiteral("1.1.1.1"), 0 },
        { QStringLiteral("8.8.8.8"), QStringLiteral("8.8.8.8"), 0 },
    };
    m_icmp->probeAll(
        targets, 3000,
        [this, epoch](const QString &id, int rttMs) {
            if (epoch != m_epoch) return;
            QJsonObject o;
            o.insert(QStringLiteral("target"), id);
            if (rttMs >= 0)
                o.insert(QStringLiteral("rtt_avg"), double(rttMs));
            else
                o.insert(QStringLiteral("unreachable"), true);
            m_pingProbes.append(o);
        },
        [this, epoch] {
            if (epoch != m_epoch) return;
            stageIdleRtt();
        });
}

QNetworkReply *BenchRunner::head204()
{
    QNetworkRequest req{QUrl(QString::fromLatin1(kRttUrl))};
    req.setTransferTimeout(8000);
    return m_nam->head(req);
}

// --- стадия 4: базовый app-layer RTT (idle) ---------------------------------------------------
void BenchRunner::stageIdleRtt()
{
    emit stageChanged(QStringLiteral("rtt"));
    m_idleIdx = 0;
    idleRttNext();
}

void BenchRunner::idleRttNext()
{
    if (m_idleIdx >= kIdleRttCount) {
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
    QNetworkRequest req{QUrl(QString::fromLatin1(kDownUrl))};
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

// --- стадия 6: upload 5МБ ----------------------------------------------------------------------
void BenchRunner::stageUp()
{
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
        if (v.toObject().value(QStringLiteral("query_ms")).isDouble())
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

    QJsonObject thr;
    thr.insert(QStringLiteral("down_mbit"), downWindow > 0 ? mbit(m_downBytes, downWindow) : 0);
    thr.insert(QStringLiteral("up_mbit"), m_upMbit);

    QJsonObject nq; // rpm считает только Apple networkQuality; наш аналог — loaded_rtt
    nq.insert(QStringLiteral("rpm"), QJsonValue::Null);
    nq.insert(QStringLiteral("base_rtt_ms"), num(median(m_idleRtt)));
    nq.insert(QStringLiteral("loaded_rtt_ms"), num(median(m_loadedRtt)));

    QJsonObject out;
    out.insert(QStringLiteral("schema"), 1);
    out.insert(QStringLiteral("label"), m_label);
    out.insert(QStringLiteral("ts"), QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd-HHmmss")));
    out.insert(QStringLiteral("network"), network);
    out.insert(QStringLiteral("dns"), dns);
    out.insert(QStringLiteral("http"), http);
    out.insert(QStringLiteral("ping"), m_pingProbes);
    out.insert(QStringLiteral("throughput"), thr);
    out.insert(QStringLiteral("network_quality"), nq);
    out.insert(QStringLiteral("extra"), m_extra);

    m_running = false;
    emit stageChanged(QStringLiteral("done"));
    emit finished(out);
}

} // namespace avpn
