#include "ServiceProbe.h"

#include "MtprotoProbe.h"

#include <QDateTime>
#include <QElapsedTimer>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QRandomGenerator>
#include <QTcpSocket>
#include <QTimer>
#include <QUrl>

namespace avpn {

ServiceProbe::ServiceProbe(QNetworkAccessManager *nam, QObject *parent)
    : QObject(parent), m_nam(nam)
{
}

void ServiceProbe::probeAll(int timeoutMs)
{
    if (m_remaining > 0 || m_cfgs.isEmpty())
        return;
    m_remaining = m_cfgs.size();
    for (const ServiceProbeConfig &c : m_cfgs) {
        if (c.kind == ServiceProbeConfig::Mtproto)
            probeMtproto(c, timeoutMs);
        else
            probeHttps(c, timeoutMs);
    }
}

void ServiceProbe::finish(const QString &key, ServiceState st, int rttMs)
{
    emit result(key, int(st), rttMs);
    if (--m_remaining <= 0) {
        m_remaining = 0;
        emit allDone();
    }
}

// Telegram: login-free MTProto handshake к seed-DC-IP через туннель. Пробуем seed-IP по очереди
// (первый ответивший resPQ ⇒ works), чтобы один сменившийся/легший IP не давал ложный «заблок».
void ServiceProbe::probeMtproto(const ServiceProbeConfig &c, int timeoutMs)
{
    QStringList hosts;
    hosts << c.host;
    hosts += c.fallbackHosts;
    // делим бюджет на seed'ы (мин. 1500мс на seed): худший случай (все молчат) ограничен timeoutMs·~.
    const int perHost = qMax(1500, timeoutMs / qMax(1, hosts.size()));
    attemptMtprotoHost(c.key, hosts, 0, c.port, perHost, c.slowMs);
}

void ServiceProbe::attemptMtprotoHost(const QString &key, const QStringList &hosts, int idx, int port,
                                      int perHostMs, int slowMs)
{
    if (idx >= hosts.size()) {     // все seed'ы молчат/ответили мусором ⇒ заблокировано
        finish(key, ServiceState::Blocked, -1);
        return;
    }

    // 16 случайных байт nonce — его эхо проверяем в resPQ (анти-false-positive).
    QByteArray nonce(MtprotoProbe::kNonceLen, Qt::Uninitialized);
    for (int i = 0; i < nonce.size(); ++i)
        nonce[i] = char(QRandomGenerator::global()->bounded(256));
    // msg_id ~ unixtime<<32, кратен 4 (требование MTProto).
    qint64 msgId = (qint64(QDateTime::currentSecsSinceEpoch()) << 32) & ~qint64(3);

    auto *sock = new QTcpSocket(this);
    auto *clock = new QElapsedTimer();
    auto *buf = new QByteArray();
    auto *done = new bool(false);

    // Примитивы (clock/buf/done) удаляем в destroyed(sock) — ПОСЛЕ всех очередных сигналов: иначе
    // второй queued-сигнал (например error после readyRead) прочитал бы освобождённый *done (UAF).
    // *done остаётся валиден до фактического удаления сокета, гасит повторный вход; connect'ы к sock
    // снимаются при его уничтожении.
    connect(sock, &QObject::destroyed, [clock, buf, done]() {
        delete clock; delete buf; delete done;
    });
    // Провал ЭТОГО seed'а → пробуем следующий (а не сразу «заблок»): один IP мог лечь/смениться.
    auto fail = [this, key, hosts, idx, port, perHostMs, slowMs, sock, done]() {
        if (*done) return;
        *done = true;
        sock->deleteLater();
        attemptMtprotoHost(key, hosts, idx + 1, port, perHostMs, slowMs);
    };
    auto ok = [this, key, slowMs, sock, done](int rtt) {
        if (*done) return;
        *done = true;
        sock->deleteLater();
        finish(key, rtt > slowMs ? ServiceState::Slow : ServiceState::Works, rtt);
    };

    // Таймаут на ОДИН seed.
    QTimer::singleShot(perHostMs, sock, [sock, done, fail]() {
        if (*done) return;
        sock->abort();
        fail();
    });

    connect(sock, &QTcpSocket::connected, sock, [sock, clock, nonce, msgId]() {
        // intermediate-транспорт: один раз тег 0xeeeeeeee, затем кадр [len LE][payload].
        QByteArray tag(4, char(0xee));
        sock->write(tag);
        const QByteArray msg = MtprotoProbe::buildReqPqMulti(nonce, msgId);
        sock->write(MtprotoProbe::frameIntermediate(msg));
        Q_UNUSED(clock);
    });
    connect(sock, &QTcpSocket::readyRead, sock, [sock, buf, nonce, clock, ok, fail]() {
        buf->append(sock->readAll());
        if (buf->size() < 4)
            return; // ещё нет длины кадра
        const quint32 len = quint32(quint8(buf->at(0))) | (quint32(quint8(buf->at(1))) << 8)
                            | (quint32(quint8(buf->at(2))) << 16) | (quint32(quint8(buf->at(3))) << 24);
        if (len > 1u << 20) { fail(); return; }      // защита от мусора
        if (quint32(buf->size()) < 4 + len)
            return;                                   // ждём весь payload
        const QByteArray payload = buf->mid(4, int(len));
        QByteArray serverNonce;
        if (MtprotoProbe::parseResPq(payload, nonce, &serverNonce))
            ok(int(clock->elapsed()));               // настоящий resPQ с нашим nonce ⇒ работает
        else
            fail();                                   // ответил, но не resPQ ⇒ DPI/мусор ⇒ заблокировано
    });
    connect(sock, &QAbstractSocket::errorOccurred, sock,
            [fail](QAbstractSocket::SocketError) { fail(); });

    clock->start();
    sock->connectToHost(hosts.at(idx), quint16(port));
}

// YouTube/прочие: TLS-complete с РЕАЛЬНЫМ SNI + TTFB. (Грубая reachability; точный троттл-детект
// YouTube требует *.googlevideo.com SNI + резолва videoplayback — TODO, см. заголовок.)
void ServiceProbe::probeHttps(const ServiceProbeConfig &c, int timeoutMs)
{
    if (!m_nam) { finish(c.key, ServiceState::Unknown, -1); return; }

    QUrl url;
    url.setScheme(QStringLiteral("https"));
    url.setHost(c.host);            // реальный SNI: иначе DPI-фильтр обходится и зелёный ложный
    url.setPath(QStringLiteral("/"));
    QNetworkRequest req(url);
    req.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::AlwaysNetwork);
    req.setRawHeader("Cache-Control", "no-cache");
    req.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::NoLessSafeRedirectPolicy);

    auto *clock = new QElapsedTimer();
    auto *ttfb = new qint64(-1);
    clock->start();
    QNetworkReply *reply = m_nam->head(req);

    auto *timer = new QTimer(reply);
    timer->setSingleShot(true);
    connect(timer, &QTimer::timeout, reply, [reply]() { reply->abort(); });
    timer->start(timeoutMs);

    connect(reply, &QNetworkReply::metaDataChanged, reply, [clock, ttfb]() {
        if (*ttfb < 0) *ttfb = clock->elapsed(); // TLS завершился, заголовки пошли
    });
    connect(reply, &QNetworkReply::finished, reply, [this, reply, c, clock, ttfb]() {
        const int httpStatus = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const bool tlsOk = (reply->error() == QNetworkReply::NoError
                            || reply->error() == QNetworkReply::ContentOperationNotPermittedError)
                           && httpStatus >= 200 && httpStatus < 400;
        const int rtt = (*ttfb >= 0) ? int(*ttfb) : int(clock->elapsed());
        ServiceState st = !tlsOk ? ServiceState::Blocked
                                 : (rtt > c.slowMs ? ServiceState::Slow : ServiceState::Works);
        delete clock; delete ttfb;
        reply->deleteLater();
        finish(c.key, st, tlsOk ? rtt : -1);
    });
}

} // namespace avpn
