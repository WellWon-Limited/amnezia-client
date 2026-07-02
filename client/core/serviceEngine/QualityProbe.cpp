#include "QualityProbe.h"

#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QTimer>
#include <QUrl>
#include <memory>

namespace avpn {

QualityProbe::QualityProbe(QNetworkAccessManager *nam, QObject *parent)
    : QObject(parent), m_nam(nam)
{
    m_timeout = new QTimer(this);
    m_timeout->setSingleShot(true);
    connect(m_timeout, &QTimer::timeout, this, [this]() {
        if (m_reply) m_reply->abort(); // → errorOccurred/finished с OperationCanceled → следующий эндпоинт
    });
}

void QualityProbe::measure(int timeoutMs)
{
    if (m_inFlight || !m_nam || m_endpoints.isEmpty())
        return;
    m_inFlight = true;
    m_timeoutMs = timeoutMs > 0 ? timeoutMs : 4000;
    m_curIdx = 0;
    tryEndpoint(0);
}

void QualityProbe::tryEndpoint(int idx)
{
    if (idx >= m_endpoints.size()) {
        finishFail();
        return;
    }
    m_curIdx = idx;

    QUrl url(m_endpoints.at(idx));
    // cache-bust: ?t=<монотонный счётчик> + no-cache, иначе RTT измерит кэш, а не путь.
    const QString q = url.query();
    url.setQuery(q.isEmpty() ? QStringLiteral("t=%1").arg(++m_bust)
                             : q + QStringLiteral("&t=%1").arg(++m_bust));

    QNetworkRequest req(url);
    req.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::AlwaysNetwork);
    req.setRawHeader("Cache-Control", "no-cache");
    req.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::NoLessSafeRedirectPolicy);

    m_clock.restart();
    QNetworkReply *reply = m_nam->head(req); // HEAD: 0 тела; если 405 — всё равно вернётся статус/TTFB
    m_reply = reply;

    // TTFB: заголовки получены = ~RTT пути. Завершаем по finished (для HEAD тело пустое).
    // AVPN (аудит N10): shared_ptr вместо голого new — при уничтожении реплая без finished
    // (shutdown) память освобождается вместе с лямбдами, ручной delete не нужен.
    auto ttfb = std::make_shared<qint64>(-1);
    connect(reply, &QNetworkReply::metaDataChanged, this, [this, ttfb]() {
        if (*ttfb < 0) *ttfb = m_clock.elapsed();
    });
    connect(reply, &QNetworkReply::finished, this, [this, reply, ttfb, idx]() {
        m_timeout->stop();
        const int httpStatus = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const bool ok = (reply->error() == QNetworkReply::NoError
                         || reply->error() == QNetworkReply::ContentOperationNotPermittedError) // HEAD не разрешён, но статус есть
                        && httpStatus >= 200 && httpStatus < 400;
        const int rtt = (*ttfb >= 0) ? int(*ttfb) : int(m_clock.elapsed());
        reply->deleteLater();
        m_reply.clear();
        if (ok)
            finishOk(rtt);
        else
            tryEndpoint(idx + 1); // этот не ответил корректно → следующий эндпоинт
    });

    m_timeout->start(m_timeoutMs);
}

void QualityProbe::finishOk(int rttMs)
{
    m_inFlight = false;
    // last-good вперёд: если сработал фолбэк (напр. свой /v1/ping ещё не развёрнут → 404), не долбим
    // мёртвый primary на каждом тике — следующий measure() начнёт с рабочего эндпоинта.
    if (m_curIdx > 0 && m_curIdx < m_endpoints.size())
        m_endpoints.move(m_curIdx, 0);
    emit result(rttMs, true);
}

void QualityProbe::finishFail()
{
    m_inFlight = false;
    emit result(-1, false);
}

} // namespace avpn
