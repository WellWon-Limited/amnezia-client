// AVPN — Tribe: чат поддержки, реализация. Комментарии по-русски (конвенция слоя).
#include "TribeSupportChat.h"

#include <QBuffer>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHttpMultiPart>
#include <QHttpPart>
#include <QImageReader>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMimeDatabase>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QStandardPaths>

#include "Enrollment.h"
#include "NetAwait.h"

namespace avpn {

namespace {

// Единственный инстанс (создаёт coreController) — для колбэка нативного iOS-пикера.
// Паттерн AvpnPushBridge: натив зовёт C-функцию, та маршалит в Qt-поток.
TribeSupportChat *s_instance = nullptr;

} // namespace

} // namespace avpn

// Колбэк TribeMediaPicker.mm (main queue iOS ≠ гарантированно Qt-поток) — маршалим.
extern "C" void Tribe_supportPickedMedia(const char *utf8Path)
{
    const QString path = QString::fromUtf8(utf8Path ? utf8Path : "");
    auto *chat = avpn::s_instance;
    if (path.isEmpty() || chat == nullptr)
        return;
    QMetaObject::invokeMethod(
        chat, [chat, path]() { chat->sendAttachmentFile(QUrl::fromLocalFile(path)); },
        Qt::QueuedConnection);
}

#ifdef Q_OS_IOS
extern "C" bool TribeMediaPicker_present(); // TribeMediaPicker.mm
#endif

namespace avpn {

namespace {

// Поллинг: открытый чат — часто (живой диалог), фон — только счётчик, редко.
constexpr int kActivePollMs = 5000;
constexpr int kIdlePollMs = 60000;
// Таймауты: короткие запросы — kNetTimeoutMs (15с); медиа вверх/вниз — с запасом
// на 25 МиБ по мобильной сети (armTimeout всё равно разблокирует по истечении).
constexpr int kMediaTimeoutMs = 180000;
constexpr int kThumbTimeoutMs = 30000;

// Лимиты бэкенда (support.py) — дублируем на клиенте, чтобы не гонять байты зря.
constexpr qint64 kImageMaxBytes = 10 * 1024 * 1024;
constexpr qint64 kVideoMaxBytes = 25 * 1024 * 1024;
// Пережатие фото (паритет с canvas-компрессией Занавеса): крупнее порога —
// в JPEG ≤1600px q85; мельче — как есть.
constexpr qint64 kImageShrinkThresholdBytes = qint64(1.5 * 1024 * 1024);
constexpr int kImageMaxDimension = 1600;
constexpr int kJpegQuality = 85;

// Белые списки MIME бэкенда (415 на прочее).
bool isAllowedImageMime(const QString &mime)
{
    return mime == QLatin1String("image/jpeg") || mime == QLatin1String("image/png")
        || mime == QLatin1String("image/webp") || mime == QLatin1String("image/gif")
        || mime == QLatin1String("image/heic") || mime == QLatin1String("image/heif");
}

bool isAllowedVideoMime(const QString &mime)
{
    return mime == QLatin1String("video/mp4") || mime == QLatin1String("video/quicktime")
        || mime == QLatin1String("video/webm");
}

// created_at бэкенда: ISO с микросекундами ("…T12:34:56.789012+00:00").
// Qt переваривает длинную дробь не во всех версиях — режем её до миллисекунд.
qint64 parseIsoMs(const QString &iso)
{
    QDateTime dt = QDateTime::fromString(iso, Qt::ISODateWithMs);
    if (!dt.isValid()) {
        QString s = iso;
        const int dot = s.indexOf(QLatin1Char('.'));
        if (dot > 0) {
            int end = dot + 1;
            while (end < s.size() && s.at(end).isDigit())
                ++end;
            const int keep = qMin(3, end - (dot + 1));
            s = s.left(dot + 1 + keep) + s.mid(end);
            dt = QDateTime::fromString(s, Qt::ISODateWithMs);
        }
    }
    return dt.isValid() ? dt.toMSecsSinceEpoch() : QDateTime::currentMSecsSinceEpoch();
}

QString humanSendError(int httpCode, bool netError)
{
    if (netError && httpCode == 0)
        return QStringLiteral("Нет сети — сообщение не отправлено");
    switch (httpCode) {
    case 429: return QStringLiteral("Слишком часто — подождите минуту");
    case 413: return QStringLiteral("Файл слишком большой");
    case 415: return QStringLiteral("Формат файла не поддерживается");
    case 401: return QStringLiteral("Нет авторизации");
    default:  return QStringLiteral("Не отправлено (ошибка %1)").arg(httpCode);
    }
}

} // namespace

TribeSupportChat::TribeSupportChat(QNetworkAccessManager *nam, QObject *parent)
    : QObject(parent), m_nam(nam), m_baseUrl(QStringLiteral("https://api.tribevpn.com"))
{
    // dev/E2E: тот же оверрайд control plane, что у AvpnEngineQml.
    const QByteArray envUrl = qgetenv("AVPN_API_URL");
    if (!envUrl.isEmpty())
        m_baseUrl = QString::fromUtf8(envUrl);

    s_instance = this; // колбэк нативного пикера (создаётся один раз в coreController)

    m_pollTimer.setInterval(kIdlePollMs);
    connect(&m_pollTimer, &QTimer::timeout, this, [this]() {
        if (m_active)
            refresh();
        else
            refreshUnread();
    });
    m_pollTimer.start();

    // Бейдж вкладки актуален вскоре после старта, не через минуту (но и не в
    // конструкторе: enroll/токен могли ещё не подняться).
    QTimer::singleShot(3000, this, &TribeSupportChat::refreshUnread);
}

QString TribeSupportChat::authToken() const
{
    return Enrollment::loadToken();
}

QNetworkReply *TribeSupportChat::authedGet(const QString &path, int timeoutMs)
{
    const QString token = authToken();
    if (!m_nam || token.isEmpty())
        return nullptr;
    QNetworkRequest req{QUrl(m_baseUrl + path)};
    req.setRawHeader(QByteArrayLiteral("Authorization"),
                     QByteArrayLiteral("Bearer ") + token.toUtf8());
    // Редиректы обрабатываем вручную (см. шапку .h): авто-follow повторил бы
    // Authorization на подписанном R2-URL — S3 отвечает 400 на двойную авторизацию.
    req.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                     QNetworkRequest::ManualRedirectPolicy);
    QNetworkReply *reply = m_nam->get(req);
    armTimeout(reply, timeoutMs);
    return reply;
}

void TribeSupportChat::setActive(bool on)
{
    if (m_active == on)
        return;
    m_active = on;
    m_pollTimer.setInterval(on ? kActivePollMs : kIdlePollMs);
    emit activeChanged();
    if (on)
        refresh(); // мгновенный фетч при открытии страницы (не ждать первый тик)
}

bool TribeSupportChat::pickMediaNative()
{
#ifdef Q_OS_IOS
    return TribeMediaPicker_present();
#else
    return false; // десктоп/Android → QML FileDialog (нативный системный пикер)
#endif
}

void TribeSupportChat::onSupportPush()
{
    if (m_active)
        refresh();
    else
        refreshUnread();
}

// ── тред ─────────────────────────────────────────────────────────────────────

void TribeSupportChat::refresh()
{
    if (m_postsInFlight > 0) {
        m_refreshPending = true; // выстрелит по завершении POST (см. postEcho)
        return;
    }
    if (m_refreshInFlight)
        return;
    QNetworkReply *reply = authedGet(QStringLiteral("/v1/support/thread"), kNetTimeoutMs);
    if (!reply)
        return; // ещё нет токена (до enroll) — просто ждём следующий тик
    m_refreshInFlight = true;
    if (!m_threadLoadedOnce && !m_loading) {
        m_loading = true;
        emit loadingChanged();
    }
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        reply->deleteLater();
        m_refreshInFlight = false;
        const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (code >= 200 && code < 300) {
            applyThread(reply->readAll());
            m_threadLoadedOnce = true;
            // GET /thread пометил прочитанным на бэке — бейдж гаснет сразу.
            if (m_unread != 0) {
                m_unread = 0;
                emit unreadChanged();
            }
        }
        if (m_loading) {
            m_loading = false;
            emit loadingChanged();
        }
    });
}

void TribeSupportChat::refreshUnread()
{
    if (m_unreadInFlight || m_active) // при открытом чате счётчик ведёт refresh()
        return;
    QNetworkReply *reply = authedGet(QStringLiteral("/v1/support/unread"), kNetTimeoutMs);
    if (!reply)
        return;
    m_unreadInFlight = true;
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        reply->deleteLater();
        m_unreadInFlight = false;
        const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (code < 200 || code >= 300)
            return;
        const QJsonObject o = QJsonDocument::fromJson(reply->readAll()).object();
        const int n = o.value(QStringLiteral("count")).toInt();
        if (n != m_unread) {
            m_unread = n;
            emit unreadChanged();
        }
    });
}

QVariantMap TribeSupportChat::parseMessage(const QJsonObject &m)
{
    QVariantList atts;
    const QJsonArray aArr = m.value(QStringLiteral("attachments")).toArray();
    for (const QJsonValue &av : aArr) {
        const QJsonObject a = av.toObject();
        const int attId = a.value(QStringLiteral("id")).toInt();
        const bool hasThumb = a.value(QStringLiteral("has_thumb")).toBool();
        QVariantMap am;
        am.insert(QStringLiteral("id"), attId);
        am.insert(QStringLiteral("kind"), a.value(QStringLiteral("kind")).toString());
        am.insert(QStringLiteral("mime"), a.value(QStringLiteral("mime")).toString());
        am.insert(QStringLiteral("name"), a.value(QStringLiteral("name")).toString());
        am.insert(QStringLiteral("bytes"), qint64(a.value(QStringLiteral("bytes")).toDouble()));
        am.insert(QStringLiteral("width"), a.value(QStringLiteral("width")).toInt());
        am.insert(QStringLiteral("height"), a.value(QStringLiteral("height")).toInt());
        am.insert(QStringLiteral("hasThumb"), hasThumb);
        am.insert(QStringLiteral("thumbUrl"), QString()); // впрыснет rebuildMessages
        am.insert(QStringLiteral("localUrl"), QString());
        atts.append(am);
        if (hasThumb && !m_thumbCache.contains(attId))
            queueThumb(attId);
    }

    QVariantMap mm;
    mm.insert(QStringLiteral("id"), m.value(QStringLiteral("id")).toInt());
    mm.insert(QStringLiteral("sender"), m.value(QStringLiteral("sender")).toString());
    mm.insert(QStringLiteral("body"), m.value(QStringLiteral("body")).toString());
    mm.insert(QStringLiteral("operatorName"), m.value(QStringLiteral("operator_name")).toString());
    mm.insert(QStringLiteral("isAuto"), m.value(QStringLiteral("is_auto")).toBool());
    mm.insert(QStringLiteral("atMs"), parseIsoMs(m.value(QStringLiteral("created_at")).toString()));
    mm.insert(QStringLiteral("pending"), false);
    mm.insert(QStringLiteral("failed"), false);
    mm.insert(QStringLiteral("attachments"), atts);
    return mm;
}

void TribeSupportChat::applyThread(const QByteArray &json)
{
    const QJsonObject root = QJsonDocument::fromJson(json).object();
    m_status = root.value(QStringLiteral("status")).toString(QStringLiteral("open"));

    QVariantList msgs;
    const QJsonArray arr = root.value(QStringLiteral("messages")).toArray();
    for (const QJsonValue &v : arr)
        msgs.append(parseMessage(v.toObject()));
    m_serverMessages = msgs;

    // Эхо, чей POST успел завершиться и чьё сообщение уже приехало с сервера,
    // здесь не живёт (снимается в postEcho); подвисшие pending-эхо остаются в хвосте.
    rebuildMessages();
}

void TribeSupportChat::rebuildMessages()
{
    QVariantList list = m_serverMessages;
    // Впрыснуть подъехавшие превью в копию серверной истории.
    for (auto &mv : list) {
        QVariantMap mm = mv.toMap();
        QVariantList atts = mm.value(QStringLiteral("attachments")).toList();
        bool touched = false;
        for (auto &av : atts) {
            QVariantMap am = av.toMap();
            const int attId = am.value(QStringLiteral("id")).toInt();
            const QString cached = m_thumbCache.value(attId);
            if (!cached.isEmpty() && am.value(QStringLiteral("thumbUrl")).toString() != cached) {
                am.insert(QStringLiteral("thumbUrl"), cached);
                av = am;
                touched = true;
            }
        }
        if (touched) {
            mm.insert(QStringLiteral("attachments"), atts);
            mv = mm;
        }
    }

    for (const Echo &e : m_echoes) {
        QVariantMap mm;
        mm.insert(QStringLiteral("id"), e.localId);
        mm.insert(QStringLiteral("sender"), QStringLiteral("client"));
        mm.insert(QStringLiteral("body"), e.body);
        mm.insert(QStringLiteral("operatorName"), QString());
        mm.insert(QStringLiteral("isAuto"), false);
        mm.insert(QStringLiteral("atMs"), e.atMs);
        mm.insert(QStringLiteral("pending"), e.pending);
        mm.insert(QStringLiteral("failed"), e.failed);
        QVariantList atts;
        if (!e.kind.isEmpty()) {
            QVariantMap am;
            am.insert(QStringLiteral("id"), e.localId);
            am.insert(QStringLiteral("kind"), e.kind);
            am.insert(QStringLiteral("mime"), e.mime);
            am.insert(QStringLiteral("name"), e.fileName);
            am.insert(QStringLiteral("bytes"), qint64(0));
            am.insert(QStringLiteral("width"), 0);
            am.insert(QStringLiteral("height"), 0);
            am.insert(QStringLiteral("hasThumb"), false);
            am.insert(QStringLiteral("thumbUrl"), QString());
            am.insert(QStringLiteral("localUrl"), e.localUrl);
            atts.append(am);
        }
        mm.insert(QStringLiteral("attachments"), atts);
        list.append(mm);
    }

    // Анти-дребезг: поллинг каждые 5с не должен перерисовывать ListView без
    // изменений (сброс позиции скролла + лишний layout).
    QByteArray snapshot =
        QJsonDocument(QJsonArray::fromVariantList(list)).toJson(QJsonDocument::Compact);
    snapshot += m_status.toUtf8();
    if (snapshot == m_lastSnapshot)
        return;
    m_lastSnapshot = snapshot;
    m_messages = list;
    emit messagesChanged();
}

// ── отправка ─────────────────────────────────────────────────────────────────

void TribeSupportChat::sendText(const QString &body)
{
    const QString text = body.trimmed();
    if (text.isEmpty())
        return;
    Echo e;
    e.localId = -(++m_localSeq);
    e.body = text;
    e.atMs = QDateTime::currentMSecsSinceEpoch();
    m_echoes.append(e);
    rebuildMessages();
    postEcho(m_echoes.last());
}

void TribeSupportChat::sendAttachmentFile(const QUrl &fileUrl)
{
    const QString path = fileUrl.isLocalFile() ? fileUrl.toLocalFile() : fileUrl.toString();
    QFileInfo fi(path);
    if (!fi.exists() || fi.size() <= 0) {
        emit sendFailed(QStringLiteral("Файл недоступен"));
        return;
    }

    const QMimeDatabase db;
    const QString mime = db.mimeTypeForFile(fi).name();

    Echo e;
    e.localId = -(++m_localSeq);
    e.atMs = QDateTime::currentMSecsSinceEpoch();
    e.fileName = sanitizeFileName(fi.fileName());
    e.localUrl = QUrl::fromLocalFile(fi.absoluteFilePath()).toString();

    if (mime.startsWith(QLatin1String("video/"))) {
        if (!isAllowedVideoMime(mime)) {
            emit sendFailed(QStringLiteral("Формат видео не поддерживается (mp4/mov/webm)"));
            return;
        }
        if (fi.size() > kVideoMaxBytes) {
            emit sendFailed(QStringLiteral("Видео больше 25 МБ"));
            return;
        }
        e.kind = QStringLiteral("video");
        e.mime = mime;
        e.filePath = fi.absoluteFilePath(); // стримим с диска, в память не тащим
    } else if (mime.startsWith(QLatin1String("image/"))) {
        // Паритет с Занавесом: крупные/непереваримые бэкендом форматы пережимаем
        // в JPEG ≤1600px q85 (заодно чинит EXIF-поворот через setAutoTransform).
        QImageReader reader(fi.absoluteFilePath());
        reader.setAutoTransform(true);
        QImage img = reader.read();
        // HEIC/HEIF перекодируем ВСЕГДА (Chrome оператора их не показывает; на Apple
        // Qt декодирует нативно через ImageIO, на прочих платформах img.isNull() →
        // ветка «как есть» ниже).
        const bool needShrink = fi.size() > kImageShrinkThresholdBytes
            || img.width() > kImageMaxDimension || img.height() > kImageMaxDimension
            || !isAllowedImageMime(mime) || mime == QLatin1String("image/heic")
            || mime == QLatin1String("image/heif");
        if (!img.isNull() && needShrink) {
            if (img.width() > kImageMaxDimension || img.height() > kImageMaxDimension)
                img = img.scaled(kImageMaxDimension, kImageMaxDimension, Qt::KeepAspectRatio,
                                 Qt::SmoothTransformation);
            QBuffer buf(&e.imageBytes);
            buf.open(QIODevice::WriteOnly);
            img.save(&buf, "JPEG", kJpegQuality);
            e.mime = QStringLiteral("image/jpeg");
            const int dot = e.fileName.lastIndexOf(QLatin1Char('.'));
            e.fileName = (dot > 0 ? e.fileName.left(dot) : e.fileName) + QStringLiteral(".jpg");
        } else if (isAllowedImageMime(mime)) {
            // Мелкий файл или недекодируемый (HEIC без кодека) — как есть.
            QFile f(fi.absoluteFilePath());
            if (!f.open(QIODevice::ReadOnly)) {
                emit sendFailed(QStringLiteral("Файл недоступен"));
                return;
            }
            e.imageBytes = f.readAll();
            e.mime = mime;
        } else {
            emit sendFailed(QStringLiteral("Формат изображения не поддерживается"));
            return;
        }
        if (e.imageBytes.size() > kImageMaxBytes) {
            emit sendFailed(QStringLiteral("Фото больше 10 МБ"));
            return;
        }
        e.kind = QStringLiteral("image");
    } else {
        emit sendFailed(QStringLiteral("Можно отправить только фото или видео"));
        return;
    }

    m_echoes.append(e);
    rebuildMessages();
    postEcho(m_echoes.last());
}

void TribeSupportChat::postEcho(Echo &echo)
{
    const QString token = authToken();
    const int localId = echo.localId;
    if (!m_nam || token.isEmpty()) {
        echo.pending = false;
        echo.failed = true;
        rebuildMessages();
        emit sendFailed(QStringLiteral("Нет авторизации"));
        return;
    }

    QNetworkReply *reply = nullptr;
    if (echo.kind.isEmpty()) {
        QNetworkRequest req{QUrl(m_baseUrl + QStringLiteral("/v1/support/messages"))};
        req.setRawHeader(QByteArrayLiteral("Authorization"),
                         QByteArrayLiteral("Bearer ") + token.toUtf8());
        req.setHeader(QNetworkRequest::ContentTypeHeader,
                      QStringLiteral("application/json"));
        const QJsonObject body{{QStringLiteral("body"), echo.body}};
        reply = m_nam->post(req, QJsonDocument(body).toJson(QJsonDocument::Compact));
        armTimeout(reply, kNetTimeoutMs);
    } else {
        QNetworkRequest req{QUrl(m_baseUrl + QStringLiteral("/v1/support/attachments"))};
        req.setRawHeader(QByteArrayLiteral("Authorization"),
                         QByteArrayLiteral("Bearer ") + token.toUtf8());
        auto *multi = new QHttpMultiPart(QHttpMultiPart::FormDataType);
        QHttpPart part;
        part.setHeader(QNetworkRequest::ContentTypeHeader, echo.mime);
        part.setHeader(QNetworkRequest::ContentDispositionHeader,
                       QStringLiteral("form-data; name=\"file\"; filename=\"%1\"")
                           .arg(echo.fileName.isEmpty() ? QStringLiteral("file") : echo.fileName));
        if (!echo.filePath.isEmpty()) {
            auto *file = new QFile(echo.filePath, multi); // умирает вместе с multipart
            if (!file->open(QIODevice::ReadOnly)) {
                delete multi;
                echo.pending = false;
                echo.failed = true;
                rebuildMessages();
                emit sendFailed(QStringLiteral("Файл недоступен"));
                return;
            }
            part.setBodyDevice(file);
        } else {
            part.setBody(echo.imageBytes);
        }
        multi->append(part);
        reply = m_nam->post(req, multi);
        multi->setParent(reply); // multipart живёт, пока идёт запрос
        armTimeout(reply, kMediaTimeoutMs);
    }

    ++m_postsInFlight;
    connect(reply, &QNetworkReply::finished, this, [this, reply, localId]() {
        reply->deleteLater();
        m_postsInFlight = qMax(0, m_postsInFlight - 1);
        const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const bool netErr = (reply->error() != QNetworkReply::NoError);
        if (code >= 200 && code < 300) {
            // Сервер вернул сохранённое сообщение — эхо больше не нужно.
            for (int i = 0; i < m_echoes.size(); ++i) {
                if (m_echoes[i].localId == localId) {
                    m_echoes.removeAt(i);
                    break;
                }
            }
            // Кладём серверную копию в историю СРАЗУ (иначе сообщение мигает:
            // эхо уже снято, а поллинг ещё не привёз строку) и перечитываем тред
            // (подтянет автоответ и постер видео после постпроцесса).
            const QJsonObject saved = QJsonDocument::fromJson(reply->readAll()).object();
            const int savedId = saved.value(QStringLiteral("id")).toInt();
            bool known = false;
            for (const auto &mv : m_serverMessages) {
                if (mv.toMap().value(QStringLiteral("id")).toInt() == savedId) {
                    known = true;
                    break;
                }
            }
            if (savedId > 0 && !known)
                m_serverMessages.append(parseMessage(saved));
            rebuildMessages();
            m_refreshPending = true; // подтянуть автоответ/постер (уйдёт в хвосте ниже)
        } else {
            if (Echo *e = echoByLocalId(localId)) {
                e->pending = false;
                e->failed = true;
            }
            rebuildMessages();
            emit sendFailed(humanSendError(code, netErr));
        }
        // Отложенные во время POST'ов запросы (поллинг/пуш) — одним refresh(),
        // когда последний POST завершился (любой исход).
        if (m_postsInFlight == 0 && m_refreshPending) {
            m_refreshPending = false;
            refresh();
        }
    });
}

TribeSupportChat::Echo *TribeSupportChat::echoByLocalId(int localId)
{
    for (auto &e : m_echoes) {
        if (e.localId == localId)
            return &e;
    }
    return nullptr;
}

void TribeSupportChat::retryMessage(int localId)
{
    Echo *e = echoByLocalId(localId);
    if (!e || !e->failed)
        return;
    e->failed = false;
    e->pending = true;
    e->atMs = QDateTime::currentMSecsSinceEpoch();
    rebuildMessages();
    postEcho(*e);
}

void TribeSupportChat::discardMessage(int localId)
{
    for (int i = 0; i < m_echoes.size(); ++i) {
        if (m_echoes[i].localId == localId) {
            m_echoes.removeAt(i);
            rebuildMessages();
            return;
        }
    }
}

// ── медиа: превью и оригиналы ────────────────────────────────────────────────

void TribeSupportChat::queueThumb(int attachmentId)
{
    if (m_thumbQueued.contains(attachmentId))
        return;
    m_thumbQueued.insert(attachmentId);
    m_thumbQueue.append(attachmentId);
    fetchNextThumb();
}

void TribeSupportChat::fetchNextThumb()
{
    if (m_thumbInFlight || m_thumbQueue.isEmpty())
        return;
    const int attId = m_thumbQueue.takeFirst();
    QNetworkReply *reply = authedGet(
        QStringLiteral("/v1/support/attachments/%1?thumb=1").arg(attId), kThumbTimeoutMs);
    if (!reply) {
        m_thumbQueued.remove(attId); // нет токена — вернёмся при следующем applyThread
        return;
    }
    m_thumbInFlight = true;
    connect(reply, &QNetworkReply::finished, this, [this, reply, attId]() {
        reply->deleteLater();
        m_thumbInFlight = false;
        const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (code >= 200 && code < 300) {
            const QString mime =
                reply->header(QNetworkRequest::ContentTypeHeader).toString();
            const QByteArray data = reply->readAll();
            // Превью без миниатюры (видео до постпроцесса) может «тихо» отдать
            // оригинал видео — data:-URL из него в Image бесполезен, пропускаем.
            if (!data.isEmpty() && mime.startsWith(QLatin1String("image/"))) {
                m_thumbCache.insert(attId,
                                    QStringLiteral("data:%1;base64,%2")
                                        .arg(mime, QString::fromLatin1(data.toBase64())));
                rebuildMessages();
            }
        } else {
            m_thumbQueued.remove(attId); // дать шанс перезапросить следующим поллом
        }
        fetchNextThumb();
    });
}

void TribeSupportChat::openAttachment(int attachmentId)
{
    // Метаданные вложения — из серверной истории (kind/mime/name).
    QString kind, mime, name;
    for (const auto &mv : m_serverMessages) {
        const QVariantList atts = mv.toMap().value(QStringLiteral("attachments")).toList();
        for (const auto &av : atts) {
            const QVariantMap am = av.toMap();
            if (am.value(QStringLiteral("id")).toInt() == attachmentId) {
                kind = am.value(QStringLiteral("kind")).toString();
                mime = am.value(QStringLiteral("mime")).toString();
                name = am.value(QStringLiteral("name")).toString();
            }
        }
    }
    if (kind.isEmpty()) {
        emit attachmentFailed(attachmentId);
        return;
    }

    const QString cached = m_originalPath.value(attachmentId);
    if (!cached.isEmpty() && QFile::exists(cached)) {
        emit attachmentReady(attachmentId, kind, QUrl::fromLocalFile(cached));
        return;
    }
    if (m_originalInFlight.contains(attachmentId))
        return;

    QNetworkReply *reply = authedGet(
        QStringLiteral("/v1/support/attachments/%1").arg(attachmentId), kMediaTimeoutMs);
    if (!reply) {
        emit attachmentFailed(attachmentId);
        return;
    }
    m_originalInFlight.insert(attachmentId);
    connect(reply, &QNetworkReply::finished, this, [this, reply, attachmentId, kind, mime]() {
        reply->deleteLater();
        const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (code == 302 || code == 301 || code == 307) {
            // Подписанный R2-URL: повторный GET БЕЗ Authorization (см. шапку .h).
            const QUrl target =
                reply->attribute(QNetworkRequest::RedirectionTargetAttribute).toUrl();
            const QUrl resolved = reply->url().resolved(target);
            if (!resolved.isValid() || !m_nam) {
                m_originalInFlight.remove(attachmentId);
                emit attachmentFailed(attachmentId);
                return;
            }
            QNetworkReply *r2 = m_nam->get(QNetworkRequest(resolved));
            armTimeout(r2, kMediaTimeoutMs);
            connect(r2, &QNetworkReply::finished, this, [this, r2, attachmentId, kind, mime]() {
                r2->deleteLater();
                m_originalInFlight.remove(attachmentId);
                const int c2 = r2->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
                if (c2 >= 200 && c2 < 300)
                    finishOriginal(attachmentId, kind, mime, r2->readAll());
                else
                    emit attachmentFailed(attachmentId);
            });
            return;
        }
        m_originalInFlight.remove(attachmentId);
        if (code >= 200 && code < 300)
            finishOriginal(attachmentId, kind, mime, reply->readAll());
        else
            emit attachmentFailed(attachmentId);
    });
}

void TribeSupportChat::finishOriginal(int attachmentId, const QString &kind,
                                      const QString &mime, const QByteArray &data)
{
    if (data.isEmpty()) {
        emit attachmentFailed(attachmentId);
        return;
    }
    QDir dir(QStandardPaths::writableLocation(QStandardPaths::TempLocation)
             + QStringLiteral("/tribe-support"));
    if (!dir.exists())
        dir.mkpath(QStringLiteral("."));

    // Расширение — из MIME (name может отсутствовать/врать).
    QString ext = QStringLiteral("bin");
    const QMimeDatabase db;
    const QMimeType mt = db.mimeTypeForName(mime);
    if (mt.isValid() && !mt.preferredSuffix().isEmpty())
        ext = mt.preferredSuffix();

    const QString path = dir.filePath(QStringLiteral("att-%1.%2").arg(attachmentId).arg(ext));
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly) || f.write(data) != data.size()) {
        emit attachmentFailed(attachmentId);
        return;
    }
    f.close();
    m_originalPath.insert(attachmentId, path);
    emit attachmentReady(attachmentId, kind, QUrl::fromLocalFile(path));
}

QString TribeSupportChat::sanitizeFileName(const QString &name)
{
    QString out;
    out.reserve(name.size());
    for (const QChar c : name) {
        if (c == QLatin1Char('"') || c == QLatin1Char('\\') || c == QLatin1Char('\n')
            || c == QLatin1Char('\r'))
            continue;
        out.append(c);
    }
    return out.left(200);
}

} // namespace avpn
