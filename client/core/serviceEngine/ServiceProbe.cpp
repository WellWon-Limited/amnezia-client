#include "ServiceProbe.h"

#include "InstagramSource.h"
#include "MtprotoProbe.h"
#include "YoutubeSource.h"

#include <QDateTime>
#include <QElapsedTimer>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QRandomGenerator>
#include <QTcpSocket>
#include <QTimer>
#include <QUrl>
#include <QUrlQuery>

namespace {
// Goodput качает до 128 КБ; при жёстком троттле (128 кбит/с) это ~8с ⇒ таймаут щедрее обычных проб.
// Частично скачанное на таймауте всё равно классифицируется (медленно/мало ⇒ slow/blocked — честно).
constexpr int kGoodputTimeoutMs = 20000;
// InnerTube iOS-клиент: отдаёт ПРЯМОЙ videoplayback-url (без signature-cipher). Версия/UA/os ДОЛЖНЫ быть
// свежими — YouTube отклоняет устаревший клиент («Precondition check failed» 400). Держать в актуале по
// yt-dlp INNERTUBE_CLIENTS['ios']. Ключ НЕ нужен (и web-ключ ломает iOS-клиент). PoToken по политике
// «required», но GVS-семпл 128 КБ по факту отдаётся; при ужесточении → measureGoodput деградирует в fallback.
constexpr const char *kYtIosVersion   = "21.02.3";
constexpr const char *kYtIosOsVersion = "18.3.2.22D82";
constexpr const char *kYtIosUA        = "com.google.ios.youtube/21.02.3 (iPhone16,2; U; CPU iOS 18_3_2 like Mac OS X)";
constexpr const char *kYtClientNameId = "5"; // INNERTUBE_CONTEXT_CLIENT_NAME для IOS
} // namespace

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
        else if (c.kind == ServiceProbeConfig::Goodput)
            probeGoodput(c);
        else
            probeHttps(c, timeoutMs);
    }
}

// AVPN (анти-«вечно серый», 2026-07-03): повторная проба ОДНОГО сервиса — для авто-ретрая Unknown
// (транзиентный провал резолва сразу после коннекта не должен оставлять чип серым до ручного тапа).
// Тот же контракт, что probeAll: result(key) прилетит ровно один раз; идемпотентно пока серия в полёте.
void ServiceProbe::probeOne(const QString &key, int timeoutMs)
{
    if (m_remaining > 0)
        return;
    for (const ServiceProbeConfig &c : m_cfgs) {
        if (c.key != key)
            continue;
        m_remaining = 1;
        if (c.kind == ServiceProbeConfig::Mtproto)
            probeMtproto(c, timeoutMs);
        else if (c.kind == ServiceProbeConfig::Goodput)
            probeGoodput(c);
        else
            probeHttps(c, timeoutMs);
        return;
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
    auto *done = new bool(false);   // гасит повторную классификацию (encrypted vs finished)
    clock->start();
    QNetworkReply *reply = m_nam->head(req);

    auto *timer = new QTimer(reply);
    timer->setSingleShot(true);
    connect(timer, &QTimer::timeout, reply, [reply]() { reply->abort(); });
    timer->start(timeoutMs);

    // Единая точка классификации (works/slow/blocked). Идемпотентна по *done.
    auto settle = [this, c, done](bool reachable, int rtt) {
        if (*done) return;
        *done = true;
        ServiceState st = !reachable ? ServiceState::Blocked
                                     : (rtt > c.slowMs ? ServiceState::Slow : ServiceState::Works);
        finish(c.key, st, reachable ? rtt : -1);
    };

    // КЛЮЧЕВОЙ позитивный сигнал (фикс ложного «заблок» у YouTube/Instagram): TLS-handshake к РЕАЛЬНОМУ
    // SNI завершился ⇒ DPI путь к сервису НЕ срезал ⇒ works. НЕ ждём HTTP-ответ: HEAD к крупным CDN
    // (Google/Meta) часто не отдаёт заголовки/закрывает рано, и раньше это давало ЛОЖНЫЙ красный, хотя
    // сервис работает. SNI-блокировка/DPI-reset случились бы ДО `encrypted`, поэтому его приход = «жив». // AVPN
    connect(reply, &QNetworkReply::encrypted, reply, [clock, ttfb, settle]() {
        if (*ttfb < 0) *ttfb = clock->elapsed();
        settle(true, int(*ttfb));
    });
    connect(reply, &QNetworkReply::metaDataChanged, reply, [clock, ttfb]() {
        if (*ttfb < 0) *ttfb = clock->elapsed(); // заголовки пошли (фолбэк-метка времени)
    });
    connect(reply, &QNetworkReply::finished, reply, [reply, c, clock, ttfb, done, settle]() {
        // Фолбэк, если `encrypted` не пришёл (переиспользованное TLS-соединение / редкий plain-HTTP):
        // любой HTTP-статус или начавшиеся заголовки = достижимо (вкл. 4xx/405/redirect — SNI прошёл);
        // «заблок» только при сетевой/TLS-ошибке или таймауте БЕЗ единого признака ответа. // AVPN
        const int httpStatus = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const bool reachable = httpStatus > 0 || *ttfb >= 0;
        const int rtt = (*ttfb >= 0) ? int(*ttfb) : int(clock->elapsed());
        Q_UNUSED(c);
        settle(reachable, rtt);
        delete clock; delete ttfb; delete done;
        reply->deleteLater();
    });
}

// ─── Goodput: РЕАЛЬНЫЙ замер kbit/s на душимом пути (сильный сигнал, как MTProto у Telegram) ──────────
// reachability («TLS собрался») врёт зелёным при DPI-троттлинге. Правда — сколько байт/с реально идёт
// через туннель на CDN сервиса: качаем sampleBytes и классифицируем скорость (GoodputProbe). // AVPN

void ServiceProbe::probeGoodput(const ServiceProbeConfig &c)
{
    if (!m_nam) { finish(c.key, ServiceState::Unknown, -1); return; }
    if (c.key == QLatin1String("youtube"))
        resolveYoutube(c, YoutubeSource::evergreenVideoIds(), 0);
    else if (c.key == QLatin1String("instagram"))
        resolveInstagram(c);
    else
        goodputFallback(c); // неизвестный сервис goodput ⇒ хотя бы reachability
}

// YouTube: InnerTube `player` (iOS-клиент ⇒ прямой url без cipher) для evergreen-видео по очереди.
// Нашли googlevideo url → меряем; ни одно видео не резолвится → fail-safe reachability.
void ServiceProbe::resolveYoutube(const ServiceProbeConfig &c, const QStringList &videoIds, int idx)
{
    if (idx >= videoIds.size()) { goodputFallback(c); return; }

    // Хост = www.youtube.com, НЕ youtubei.googleapis.com (корень «серый чип при работающем YouTube»,
    // 2026-07-03): youtubei.googleapis.com резолвится в 216.239.3x.223, а 216.239.38.0/24 состоит в
    // kBypassExtra RU-direct (Госуслуги-attestation) → при включённом «Доступе к сайтам РФ» резолв уходил
    // МИМО туннеля через РФ, где youtubei.googleapis.com недоступен (timeout, проверено вживую с РФ-IP)
    // → fallback → Unknown. www.youtube.com несёт тот же InnerTube API (/youtubei/v1/player, путь yt-dlp),
    // резолвится в обычные Google-фронты вне байпас-CIDR → всегда идёт ЧЕРЕЗ туннель.
    QUrl url(QStringLiteral("https://www.youtube.com/youtubei/v1/player"));
    QUrlQuery q;
    q.addQueryItem(QStringLiteral("prettyPrint"), QStringLiteral("false")); // БЕЗ key: iOS-клиент не требует; web-ключ его ломает
    url.setQuery(q);

    QNetworkRequest req(url);
    req.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
    req.setRawHeader("User-Agent", kYtIosUA);
    req.setRawHeader("X-YouTube-Client-Name", kYtClientNameId);
    req.setRawHeader("X-YouTube-Client-Version", kYtIosVersion);
    req.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::AlwaysNetwork);

    const QByteArray body = YoutubeSource::buildPlayerRequest(
        videoIds.at(idx), QStringLiteral("IOS"), QString::fromLatin1(kYtIosVersion),
        QStringLiteral("iPhone16,2"), QString::fromLatin1(kYtIosOsVersion));

    auto *done = new bool(false);
    QNetworkReply *reply = m_nam->post(req, body);
    auto *timer = new QTimer(reply);
    timer->setSingleShot(true);
    connect(timer, &QTimer::timeout, reply, [reply]() { reply->abort(); });
    timer->start(6000); // резолв URL — лёгкий JSON, короткий таймаут

    connect(reply, &QNetworkReply::finished, reply, [this, c, videoIds, idx, reply, done]() {
        if (*done) return;
        *done = true;
        const QString url = (reply->error() == QNetworkReply::NoError)
                                ? YoutubeSource::extractVideoplaybackUrl(reply->readAll())
                                : QString();
        reply->deleteLater();
        delete done;
        if (url.isEmpty())
            resolveYoutube(c, videoIds, idx + 1); // это видео не отдало прямой url → следующее
        else
            measureGoodput(c, url, /*rangeAsQuery=*/true); // googlevideo уважает &range=
    });
}

// Instagram: публичная homepage (без логина) → вытащить sizeable ассет на *.cdninstagram.com → мерим.
void ServiceProbe::resolveInstagram(const ServiceProbeConfig &c)
{
    QUrl url(QStringLiteral("https://www.instagram.com/"));
    QNetworkRequest req(url);
    req.setRawHeader("User-Agent",
                     QByteArrayLiteral("Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) "
                                       "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"));
    req.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::AlwaysNetwork);
    req.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::NoLessSafeRedirectPolicy);

    auto *done = new bool(false);
    auto *buf = new QByteArray();
    auto *found = new QString();
    QNetworkReply *reply = m_nam->get(req);
    auto *timer = new QTimer(reply);
    timer->setSingleShot(true);
    connect(timer, &QTimer::timeout, reply, [reply]() { reply->abort(); });
    timer->start(6000);

    // ИНКРЕМЕНТАЛЬНЫЙ поиск ассета (фикс «серый Instagram», 2026-07-03): homepage ~600 КБ, а первый
    // cdninstagram-ассет (.css в <head>) появляется в первых десятках КБ. Раньше ждали ВЕСЬ body —
    // через нагруженный туннель 600 КБ часто не влезали в 6с → abort → Unknown. Теперь ищем по мере
    // прихода и рвём соединение сразу после находки. Гард «за матчем есть ещё байт» отсекает URL,
    // обрезанный границей чанка (нет терминатора — ждём следующий чанк).
    connect(reply, &QNetworkReply::readyRead, reply, [reply, buf, found]() {
        if (!found->isEmpty())
            return;
        buf->append(reply->readAll());
        const QString a = InstagramSource::extractCdnAssetUrl(*buf);
        if (!a.isEmpty() && buf->indexOf(a.toUtf8()) + a.toUtf8().size() < buf->size()) {
            *found = a;
            reply->abort(); // хвост HTML не нужен — экономим туннель и укладываемся в таймаут
        }
    });
    connect(reply, &QNetworkReply::finished, reply, [this, c, reply, done, buf, found]() {
        if (*done) return;
        *done = true;
        QString asset = *found;
        if (asset.isEmpty() && reply->error() == QNetworkReply::NoError) {
            buf->append(reply->readAll());
            asset = InstagramSource::extractCdnAssetUrl(*buf); // полный body — терминатор не требуем
        }
        reply->deleteLater();
        delete done; delete buf; delete found;
        if (asset.isEmpty())
            goodputFallback(c); // не нашли CDN-ассет / homepage недостижима → reachability(Unknown)/blocked
        else
            measureGoodput(c, asset, /*rangeAsQuery=*/false); // CDN уважает Range-заголовок
    });
}

// Скачать sampleBytes по готовому URL, померить скорость окна данных (firstByte→конец) → classify().
void ServiceProbe::measureGoodput(const ServiceProbeConfig &c, const QString &url, bool rangeAsQuery)
{
    const qint64 N = c.sampleBytes;
    QString finalUrl = url;
    QNetworkRequest req;
    if (rangeAsQuery) {
        finalUrl = YoutubeSource::withRange(url, 0, N - 1); // &range=0-(N-1)
    } else {
        req.setRawHeader("Range", QByteArrayLiteral("bytes=0-") + QByteArray::number(N - 1));
    }
    req.setUrl(QUrl(finalUrl));
    req.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::AlwaysNetwork);
    req.setRawHeader("Cache-Control", "no-cache");
    req.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::NoLessSafeRedirectPolicy);

    auto *clock = new QElapsedTimer();
    auto *firstByte = new qint64(-1);
    auto *bytes = new qint64(0);
    auto *done = new bool(false);
    clock->start();
    QNetworkReply *reply = m_nam->get(req);

    auto *timer = new QTimer(reply);
    timer->setSingleShot(true);
    connect(timer, &QTimer::timeout, reply, [reply]() { reply->abort(); }); // частичное всё равно классифицируем
    timer->start(kGoodputTimeoutMs);

    // Считаем принятые байты; окно замера стартует с ПЕРВОГО байта (исключаем TLS/TTFB — честнее для goodput).
    connect(reply, &QNetworkReply::readyRead, reply, [reply, clock, firstByte, bytes, N]() {
        if (*firstByte < 0) *firstByte = clock->elapsed();
        *bytes += reply->readAll().size();
        if (*bytes >= N) reply->abort(); // набрали семпл — стоп (не тянем всё видео)
    });
    connect(reply, &QNetworkReply::finished, reply, [this, c, reply, clock, firstByte, bytes, done]() {
        if (*done) return;
        *done = true;
        const qint64 dur = (*firstByte >= 0) ? (clock->elapsed() - *firstByte) : clock->elapsed();
        const int httpStatus = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const qint64 got = *bytes;
        delete clock; delete firstByte; delete bytes; delete done;
        reply->deleteLater();

        if (got >= c.goodput.minBytes) {
            // Честный замер: набрали достаточно байт ⇒ классифицируем скорость.
            const int state = GoodputProbe::classify(got, dur, c.goodput);
            finish(c.key, static_cast<ServiceState>(state), int(GoodputProbe::kbitPerSec(got, dur)));
        } else if (httpStatus == 200 || httpStatus == 206) {
            // Сервер ОТДАВАЛ данные (2xx/partial), но их пришло мало ⇒ реально задушено/рано закрыто ⇒ blocked.
            finish(c.key, ServiceState::Blocked, got > 0 ? int(GoodputProbe::kbitPerSec(got, dur)) : -1);
        } else {
            // Не-2xx (403 PoToken/auth) или сетевая ошибка без данных — это НЕ вердикт цензуры.
            // Деградируем в reachability CDN: reachable ⇒ Unknown (честно «не смогли измерить»), иначе Blocked.
            goodputFallback(c);
        }
    });
}

// Fail-safe: byte-source не резолвится → хотя бы TLS-достижимость душимого CDN. reachable ⇒ Unknown
// (честно «не смогли измерить скорость»), reset/timeout ⇒ Blocked. Никогда не ложный works.
void ServiceProbe::goodputFallback(const ServiceProbeConfig &c)
{
    if (!m_nam || c.host.isEmpty()) { finish(c.key, ServiceState::Unknown, -1); return; }

    QUrl url;
    url.setScheme(QStringLiteral("https"));
    url.setHost(c.host); // реальный SNI душимого CDN (redirector.googlevideo.com / static.cdninstagram.com)
    url.setPath(QStringLiteral("/"));
    QNetworkRequest req(url);
    req.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::AlwaysNetwork);
    req.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::NoLessSafeRedirectPolicy);

    auto *done = new bool(false);
    QNetworkReply *reply = m_nam->head(req);
    auto *timer = new QTimer(reply);
    timer->setSingleShot(true);
    connect(timer, &QTimer::timeout, reply, [reply]() { reply->abort(); });
    timer->start(6000);

    auto settle = [this, c, done](bool reachable) {
        if (*done) return;
        *done = true;
        finish(c.key, reachable ? ServiceState::Unknown : ServiceState::Blocked, -1);
    };
    connect(reply, &QNetworkReply::encrypted, reply, [settle]() { settle(true); });
    connect(reply, &QNetworkReply::finished, reply, [reply, done, settle]() {
        const int httpStatus = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        settle(httpStatus > 0); // ошибка/таймаут без ответа ⇒ Blocked
        delete done;
        reply->deleteLater();
    });
}

} // namespace avpn
