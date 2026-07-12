#include "ServiceProbe.h"

#include "MtprotoProbe.h"
#include "TuningStore.h"
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

#include <memory>

namespace {
// Goodput качает до 128 КБ; при жёстком троттле (128 кбит/с) это ~8с ⇒ таймаут щедрее обычных проб.
// Частично скачанное на таймауте всё равно классифицируется (медленно ⇒ slow — честно).
constexpr int kGoodputTimeoutMs = 20000;
// Лёгкий reachability-голос (generate_204/favicon/api): ответ приходит за сотни мс; 5с хватает
// с запасом даже нагруженному туннелю. Server-tunable chip_reach_timeout_ms (кламп 1..30с).
constexpr int kReachTimeoutMs = 5000;
// InnerTube iOS-клиент: отдаёт ПРЯМОЙ videoplayback-url (без signature-cipher). Версия/UA/os ДОЛЖНЫ быть
// свежими — YouTube отклоняет устаревший клиент («Precondition check failed» 400). Держать в актуале по
// yt-dlp INNERTUBE_CLIENTS['ios']. Ключ НЕ нужен (и web-ключ ломает iOS-клиент). PoToken по политике
// «required», но GVS-семпл 128 КБ по факту отдаётся; при ужесточении → вердикт останется works по кворуму
// (v2: провал качества больше НЕ красит чип — reachability уже решила).
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
    const int gen = m_gen;
    for (const ServiceProbeConfig &c : m_cfgs)
        startOne(c, timeoutMs, gen);
}

// AVPN (анти-«вечно серый», 2026-07-03; v2 — и подтверждение ухудшения гистерезиса): повторная
// проба ОДНОГО сервиса. Тот же контракт, что probeAll: result(key) прилетит ровно один раз;
// идемпотентно пока серия в полёте.
void ServiceProbe::probeOne(const QString &key, int timeoutMs)
{
    if (m_remaining > 0)
        return;
    for (const ServiceProbeConfig &c : m_cfgs) {
        if (c.key != key)
            continue;
        m_remaining = 1;
        startOne(c, timeoutMs, m_gen);
        return;
    }
}

void ServiceProbe::startOne(const ServiceProbeConfig &c, int timeoutMs, int gen)
{
    if (c.kind == ServiceProbeConfig::Mtproto)
        probeMtproto(c, timeoutMs, gen);
    else if (c.kind == ServiceProbeConfig::Goodput)
        probeGoodput(c, gen);
    else
        probeHttps(c, timeoutMs, gen);
}

void ServiceProbe::finish(int gen, const QString &key, ServiceState st, int rttMs)
{
    // Гейт поколения (v2): результат серии, начатой ДО invalidate() (смена ноды/обрыв), молча
    // выбрасывается — иначе вердикт старой ноды дописался бы в чипы новой (девайс-баг 2026-07-12).
    if (gen != m_gen)
        return;
    emit result(key, int(st), rttMs);
    if (--m_remaining <= 0) {
        m_remaining = 0;
        emit allDone();
    }
}

// Telegram: login-free MTProto handshake к seed-DC-IP через туннель. Пробуем seed-IP по очереди
// (первый ответивший resPQ ⇒ works), чтобы один сменившийся/легший IP не давал ложный «заблок».
void ServiceProbe::probeMtproto(const ServiceProbeConfig &c, int timeoutMs, int gen)
{
    QStringList hosts;
    hosts << c.host;
    hosts += c.fallbackHosts;
    // делим бюджет на seed'ы (мин. 1500мс на seed): худший случай (все молчат) ограничен timeoutMs·~.
    const int perHost = qMax(1500, timeoutMs / qMax(1, hosts.size()));
    const int slowMs = int(TuningStore::numberOr(QStringLiteral("svc_probe_slow_ms"), double(c.slowMs)));
    attemptMtprotoHost(gen, c.key, hosts, 0, c.port, perHost, slowMs);
}

void ServiceProbe::attemptMtprotoHost(int gen, const QString &key, const QStringList &hosts, int idx,
                                      int port, int perHostMs, int slowMs)
{
    if (gen != m_gen)
        return; // серия инвалидирована (смена ноды) — цепочку seed'ов не продолжаем
    if (idx >= hosts.size()) {     // все seed'ы молчат/ответили мусором ⇒ заблокировано
        finish(gen, key, ServiceState::Blocked, -1);
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
    auto fail = [this, gen, key, hosts, idx, port, perHostMs, slowMs, sock, done]() {
        if (*done) return;
        *done = true;
        sock->deleteLater();
        attemptMtprotoHost(gen, key, hosts, idx + 1, port, perHostMs, slowMs);
    };
    auto ok = [this, gen, key, slowMs, sock, done](int rtt) {
        if (*done) return;
        *done = true;
        sock->deleteLater();
        finish(gen, key, rtt > slowMs ? ServiceState::Slow : ServiceState::Works, rtt);
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

// Серверные цели без пары голосов: TLS-complete с РЕАЛЬНЫМ SNI + TTFB (грубая reachability).
void ServiceProbe::probeHttps(const ServiceProbeConfig &c, int timeoutMs, int gen)
{
    if (!m_nam) { finish(gen, c.key, ServiceState::Unknown, -1); return; }

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
    auto settle = [this, c, gen, done](bool reachable, int rtt) {
        if (*done) return;
        *done = true;
        const int slowMs = int(TuningStore::numberOr(QStringLiteral("svc_probe_slow_ms"), double(c.slowMs)));
        ServiceState st = !reachable ? ServiceState::Blocked
                                     : (rtt > slowMs ? ServiceState::Slow : ServiceState::Works);
        finish(gen, c.key, st, reachable ? rtt : -1);
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

// ─── Goodput v2: reachability-КВОРУМ решает зелёный/красный, качество уточняет жёлтый ────────────
// Одиночный goodput-сэмпл (InnerTube/HTML-парсинг + 128 КБ) флапал: пограничная скорость, протухание
// клиент-версии, consent/бот-детект, нагрузка ноды. Теперь вердикт достижимости — кворум ДВУХ лёгких
// официальных эндпоинтов разных контуров (generate_204/favicon/api; вкомпилено в ServiceProbeTargets.h,
// server-driven через lists.chip_reach_urls_<key>), а тяжёлый замер только уточняет works|slow. // AVPN

void ServiceProbe::probeGoodput(const ServiceProbeConfig &c, int gen)
{
    if (!m_nam) { finish(gen, c.key, ServiceState::Unknown, -1); return; }
    const QStringList urls =
            TuningStore::listOr(QStringLiteral("chip_reach_urls_") + c.key, c.reachUrls);
    if (!urls.isEmpty())
        probeReachPair(c, urls, gen);
    else
        goodputFallback(c, gen); // серверная цель без пары голосов ⇒ хотя бы reachability host
}

void ServiceProbe::probeReachPair(const ServiceProbeConfig &c, const QStringList &urls, int gen)
{
    const int tmo = qBound(1000, int(TuningStore::numberOr(QStringLiteral("chip_reach_timeout_ms"),
                                                           double(kReachTimeoutMs))), 30000);
    struct PairState {
        int left = 2;
        VoiceOutcome a = VoiceOutcome::SoftFail;
        VoiceOutcome b = VoiceOutcome::SoftFail;
        int rttA = -1;
        int rttB = -1;
    };
    auto ps = std::make_shared<PairState>();

    auto settle = [this, c, gen, ps]() {
        if (gen != m_gen)
            return; // серия инвалидирована — качество не стартуем, вердикт не шлём
        const ReachQuorum q = reachQuorum2(ps->a, ps->rttA, ps->b, ps->rttB);
        const int cap = reachCap(q);
        if (cap == 0) { // оба голоса упали (жёстко или тихим дропом) ⇒ заблокировано
            finish(gen, c.key, ServiceState::Blocked, -1);
            return;
        }
        if (c.key == QLatin1String("youtube")) {
            // Качество YouTube — реальный душимый путь googlevideo (троттл виден только там).
            qualityYoutube(c, cap, q.rttMs, YoutubeSource::evergreenVideoIds(), 0, gen);
            return;
        }
        // Прочие (instagram и будущие): качество = TTFB живых голосов против порога slow.
        const int slowMs = int(TuningStore::numberOr(QStringLiteral("svc_probe_slow_ms"),
                                                     double(c.slowMs)));
        const int quality = (q.rttMs >= 0 && q.rttMs > slowMs) ? 1 : 2;
        finish(gen, c.key, ServiceState(qMin(cap, refineReachable(quality))), q.rttMs);
    };

    // Один URL (оператор прислал без пары): второй «голос» остаётся дефолтным SoftFail —
    // семантика кворума сохраняется сама (живой единственный голос ⇒ достижим; его фейл ⇒ оба
    // голоса нежилые ⇒ blocked), лишний сетевой запрос не гоняем.
    if (urls.size() < 2)
        ps->left = 1;
    runReachVoice(urls.at(0), tmo, [ps, settle](VoiceOutcome o, int rtt) {
        ps->a = o; ps->rttA = rtt;
        if (--ps->left == 0) settle();
    });
    if (urls.size() > 1) {
        runReachVoice(urls.at(1), tmo, [ps, settle](VoiceOutcome o, int rtt) {
            ps->b = o; ps->rttB = rtt;
            if (--ps->left == 0) settle();
        });
    }
}

// Один лёгкий reachability-голос: GET url с коротким таймаутом; done(outcome, ttfbMs) ровно один раз.
// Любой валидный HTTP-статус (204/400/405/429) = Alive; RST/refused без байта = HardFail;
// наш таймаут-abort/тишина = SoftFail (ChipLogic::classifyReachVoice).
void ServiceProbe::runReachVoice(const QString &url, int timeoutMs,
                                 std::function<void(VoiceOutcome, int)> done)
{
    QNetworkRequest req{QUrl(url)};
    req.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::AlwaysNetwork);
    req.setRawHeader("Cache-Control", "no-cache");
    req.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::NoLessSafeRedirectPolicy);

    auto *clock = new QElapsedTimer();
    auto *ttfb = new qint64(-1);
    auto *timedOut = new bool(false);
    auto *gotBytes = new bool(false);
    clock->start();
    QNetworkReply *reply = m_nam->get(req);

    auto *timer = new QTimer(reply);
    timer->setSingleShot(true);
    connect(timer, &QTimer::timeout, reply, [reply, timedOut]() {
        *timedOut = true;
        reply->abort();
    });
    timer->start(timeoutMs);

    connect(reply, &QNetworkReply::metaDataChanged, reply, [clock, ttfb]() {
        if (*ttfb < 0) *ttfb = clock->elapsed();
    });
    connect(reply, &QNetworkReply::readyRead, reply, [reply, clock, ttfb, gotBytes]() {
        if (*ttfb < 0) *ttfb = clock->elapsed();
        *gotBytes = true;
        reply->readAll(); // тело не нужно (favicon/крошечный JSON) — только факт ответа
    });
    connect(reply, &QNetworkReply::finished, reply,
            [reply, clock, ttfb, timedOut, gotBytes, done]() {
                const bool netError = (reply->error() != QNetworkReply::NoError);
                const bool tOut = *timedOut
                                  || (reply->error() == QNetworkReply::OperationCanceledError);
                const int httpStatus =
                        reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
                const bool anySign = *gotBytes || *ttfb >= 0;
                const VoiceOutcome o = classifyReachVoice(netError, tOut, httpStatus, anySign);
                const int rtt = (*ttfb >= 0) ? int(*ttfb) : -1;
                delete clock; delete ttfb; delete timedOut; delete gotBytes;
                reply->deleteLater();
                done(o, rtt);
            });
}

// Качество YouTube: InnerTube `player` (iOS-клиент ⇒ прямой url без cipher) для evergreen-видео по
// очереди → ranged-GET по реально-душимому googlevideo. ЛЮБОЙ провал цепочки ⇒ works с потолком cap:
// reachability-кворум уже доказал «жив», протухший InnerTube/403 — не вердикт цензуры (анти-флап v2).
void ServiceProbe::qualityYoutube(const ServiceProbeConfig &c, int cap, int quorumRtt,
                                  const QStringList &videoIds, int idx, int gen)
{
    if (gen != m_gen)
        return;
    if (idx >= videoIds.size()) {
        finish(gen, c.key, ServiceState(qMin(cap, 2)), quorumRtt);
        return;
    }

    // Server-driven snapshot (backend-first, Task 3): один прочёт TuningStore на попытку резолва
    // (паттерн GoodputThresholds::fromTuning() — не дёргать TuningStore на каждое обращение к полю).
    // Пустая серверная строка = фолбэк на вкомпиленную константу — гарантия внутри TuningStore::stringOr.
    const QString ytVersion = TuningStore::stringOr(QStringLiteral("yt_client_version"),
                                                     QString::fromLatin1(kYtIosVersion));
    const QString ytOsVersion = TuningStore::stringOr(QStringLiteral("yt_ios_os_version"),
                                                       QString::fromLatin1(kYtIosOsVersion));
    const QString ytUA = TuningStore::stringOr(QStringLiteral("yt_ios_ua"), QString::fromLatin1(kYtIosUA));
    const QString ytClientNameId = TuningStore::stringOr(QStringLiteral("yt_client_name_id"),
                                                          QString::fromLatin1(kYtClientNameId));

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
    req.setRawHeader("User-Agent", ytUA.toUtf8());
    req.setRawHeader("X-YouTube-Client-Name", ytClientNameId.toUtf8());
    req.setRawHeader("X-YouTube-Client-Version", ytVersion.toUtf8());
    req.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::AlwaysNetwork);

    const QByteArray body = YoutubeSource::buildPlayerRequest(
        videoIds.at(idx), QStringLiteral("IOS"), ytVersion,
        QStringLiteral("iPhone16,2"), ytOsVersion);

    auto *done = new bool(false);
    QNetworkReply *reply = m_nam->post(req, body);
    auto *timer = new QTimer(reply);
    timer->setSingleShot(true);
    connect(timer, &QTimer::timeout, reply, [reply]() { reply->abort(); });
    timer->start(6000); // резолв URL — лёгкий JSON, короткий таймаут

    connect(reply, &QNetworkReply::finished, reply,
            [this, c, cap, quorumRtt, videoIds, idx, gen, reply, done]() {
                if (*done) return;
                *done = true;
                const QByteArray raw = reply->readAll();
                const QString url = (reply->error() == QNetworkReply::NoError)
                                        ? YoutubeSource::extractVideoplaybackUrl(raw)
                                        : QString();
                reply->deleteLater();
                delete done;
                if (url.isEmpty())
                    qualityYoutube(c, cap, quorumRtt, videoIds, idx + 1, gen); // следующее видео
                else
                    measureGoodput(c, cap, quorumRtt, url, /*rangeAsQuery=*/true, gen); // googlevideo уважает &range=
            });
}

// Скачать sampleBytes по готовому URL, померить скорость окна данных (firstByte→конец).
// Вердикт v2 = qMin(cap, refineReachable(classify)): качество даёт ТОЛЬКО works|slow — красный/серый
// при доказанной reachability запрещены (провал замера — не вердикт цензуры).
void ServiceProbe::measureGoodput(const ServiceProbeConfig &c, int cap, int quorumRtt,
                                  const QString &url, bool rangeAsQuery, int gen)
{
    const qint64 N = qint64(TuningStore::numberOr(QStringLiteral("svc_probe_sample_bytes"),
                                                  double(c.sampleBytes)));
    // Server-driven (backend-first, Task 3): свежий снапшот на весь замер (один прочёт, как N выше).
    const int goodputTimeoutMs = int(TuningStore::numberOr(QStringLiteral("svc_goodput_timeout_ms"),
                                                            double(kGoodputTimeoutMs)));
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
    timer->start(goodputTimeoutMs);

    // Считаем принятые байты; окно замера стартует с ПЕРВОГО байта (исключаем TLS/TTFB — честнее для goodput).
    connect(reply, &QNetworkReply::readyRead, reply, [reply, clock, firstByte, bytes, N]() {
        if (*firstByte < 0) *firstByte = clock->elapsed();
        *bytes += reply->readAll().size();
        if (*bytes >= N) reply->abort(); // набрали семпл — стоп (не тянем всё видео)
    });
    connect(reply, &QNetworkReply::finished, reply,
            [this, c, cap, quorumRtt, gen, reply, clock, firstByte, bytes, done]() {
                if (*done) return;
                *done = true;
                const qint64 dur = (*firstByte >= 0) ? (clock->elapsed() - *firstByte) : clock->elapsed();
                const qint64 got = *bytes;
                delete clock; delete firstByte; delete bytes; delete done;
                reply->deleteLater();

                const GoodputThresholds th = GoodputThresholds::fromTuning();
                if (got >= th.minBytes) {
                    // Честный замер ⇒ классифицируем скорость; blocked-класс при живом кворуме = slow.
                    const int refined = refineReachable(GoodputProbe::classify(got, dur, th));
                    finish(gen, c.key, ServiceState(qMin(cap, refined)),
                           int(GoodputProbe::kbitPerSec(got, dur)));
                } else if (got > 0) {
                    // Данные шли, но еле-еле (не добрали даже minBytes за весь таймаут) ⇒ троттл ⇒ slow.
                    finish(gen, c.key, ServiceState(qMin(cap, 1)),
                           int(GoodputProbe::kbitPerSec(got, dur)));
                } else {
                    // Ни байта семпла (403 PoToken/редирект/обрыв) — качество не измерилось;
                    // reachability уже доказана кворумом ⇒ works с потолком cap, НЕ серый/красный.
                    finish(gen, c.key, ServiceState(qMin(cap, 2)), quorumRtt);
                }
            });
}

// Деградация для серверных goodput-целей БЕЗ пары голосов: TLS-достижимость host.
// reachable ⇒ Unknown (честно «не смогли измерить»), reset/timeout ⇒ Blocked. Никогда не ложный works.
void ServiceProbe::goodputFallback(const ServiceProbeConfig &c, int gen)
{
    if (!m_nam || c.host.isEmpty()) { finish(gen, c.key, ServiceState::Unknown, -1); return; }

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

    auto settle = [this, c, gen, done](bool reachable) {
        if (*done) return;
        *done = true;
        finish(gen, c.key, reachable ? ServiceState::Unknown : ServiceState::Blocked, -1);
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
