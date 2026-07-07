// AVPN — E2E-проверка TribeSupportChat против ЛОКАЛЬНОГО бэкенда (ветка
// feat/support-device-bearer): текст → аплоад фото (с даунскейлом) → превью
// (data:-URL) → скачивание оригинала → ответ оператора (admin API) → unread.
// Запуск: tests/build_e2e_support.sh (нужны env AVPN_API_URL / TEST_TOKEN /
// E2E_ADMIN_TOKEN и живой бэкенд). Enrollment подменён стабом (токен из env).
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QImage>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QTimer>

#include "../TribeSupportChat.h"

using avpn::TribeSupportChat;

namespace {

int g_step = 0;

void fail(const QString &why)
{
    fprintf(stderr, "FAIL step %d: %s\n", g_step, qPrintable(why));
    ::exit(1);
}

void pass()
{
    printf("PASS: все шаги E2E чата поддержки прошли\n");
    ::exit(0);
}

QVariantMap findMessage(const QVariantList &msgs, const std::function<bool(const QVariantMap &)> &pred)
{
    for (const auto &v : msgs) {
        const QVariantMap m = v.toMap();
        if (pred(m))
            return m;
    }
    return {};
}

} // namespace

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    const QString base = QString::fromUtf8(qgetenv("AVPN_API_URL"));
    const QString adminToken = QString::fromUtf8(qgetenv("E2E_ADMIN_TOKEN"));
    if (base.isEmpty() || qgetenv("TEST_TOKEN").isEmpty() || adminToken.isEmpty())
        fail(QStringLiteral("нужны env AVPN_API_URL / TEST_TOKEN / E2E_ADMIN_TOKEN"));

    QNetworkAccessManager nam;
    TribeSupportChat chat(&nam);
    chat.setActive(true);

    QObject::connect(&chat, &TribeSupportChat::sendFailed,
                     [](const QString &r) { fail(QStringLiteral("sendFailed: %1").arg(r)); });
    QObject::connect(&chat, &TribeSupportChat::attachmentFailed,
                     [](int id) { fail(QStringLiteral("attachmentFailed: %1").arg(id)); });

    // тестовое фото 2000x1500 (форсит клиентский даунскейл ≤1600 → JPEG)
    const QString photoPath = QDir::temp().filePath(QStringLiteral("tribe-e2e-photo.png"));
    {
        QImage img(2000, 1500, QImage::Format_RGB32);
        img.fill(0xFF20406E);
        if (!img.save(photoPath, "PNG"))
            fail(QStringLiteral("не сохранилось тестовое фото"));
    }

    static int attachmentId = 0;
    static qint64 openedSize = 0;

    QObject::connect(&chat, &TribeSupportChat::attachmentReady,
                     [](int id, const QString &kind, const QUrl &fileUrl) {
                         QFile f(fileUrl.toLocalFile());
                         openedSize = f.size();
                         printf("  attachmentReady id=%d kind=%s size=%lld\n", id,
                                qPrintable(kind), (long long)openedSize);
                     });

    auto *adminReplySent = new bool(false);

    // финальный сторож
    QTimer::singleShot(120000, [] { fail(QStringLiteral("глобальный таймаут 120с")); });

    auto *tick = new QTimer(&app);
    tick->setInterval(700);
    QObject::connect(tick, &QTimer::timeout, [&, adminReplySent]() {
        const QVariantList msgs = chat.messages();
        switch (g_step) {
        case 0: // тред загрузился → шлём текст
            if (!chat.loading()) {
                printf("step 0: тред загружен (%d сообщений), шлём текст\n", int(msgs.size()));
                chat.sendText(QStringLiteral("e2e: привет, это автотест"));
                g_step = 1;
            }
            break;
        case 1: { // текст подтверждён сервером (эхо заменилось серверным id)
            const QVariantMap m = findMessage(msgs, [](const QVariantMap &m) {
                return m.value("body").toString().startsWith(QStringLiteral("e2e:"))
                    && !m.value("pending").toBool() && m.value("id").toInt() > 0;
            });
            if (!m.isEmpty()) {
                printf("step 1: текст доставлен (id=%d), шлём фото\n", m.value("id").toInt());
                chat.sendAttachmentFile(QUrl::fromLocalFile(photoPath));
                g_step = 2;
            }
            break;
        }
        case 2: { // вложение подтверждено сервером
            const QVariantMap m = findMessage(msgs, [](const QVariantMap &m) {
                const QVariantList atts = m.value("attachments").toList();
                return !atts.isEmpty() && m.value("id").toInt() > 0
                    && atts.first().toMap().value("kind").toString() == QLatin1String("image");
            });
            if (!m.isEmpty()) {
                attachmentId = m.value("attachments").toList().first().toMap().value("id").toInt();
                printf("step 2: фото доставлено (att=%d), ждём превью\n", attachmentId);
                g_step = 3;
            }
            break;
        }
        case 3: { // превью приехало data:-URL'ом
            const QVariantMap m = findMessage(msgs, [](const QVariantMap &m) {
                const QVariantList atts = m.value("attachments").toList();
                return !atts.isEmpty()
                    && atts.first().toMap().value("thumbUrl").toString()
                           .startsWith(QLatin1String("data:image"));
            });
            if (!m.isEmpty()) {
                printf("step 3: превью получено, качаем оригинал\n");
                chat.openAttachment(attachmentId);
                g_step = 4;
            }
            break;
        }
        case 4: // оригинал скачан (attachmentReady выставил openedSize)
            if (openedSize > 0) {
                // маленькое «видео» (валидный ftyp-заголовок mp4) — проверяет
                // multipart-стриминг из файла (setBodyDevice), не память
                const QString videoPath = QDir::temp().filePath(QStringLiteral("tribe-e2e-video.mp4"));
                QFile vf(videoPath);
                if (!vf.open(QIODevice::WriteOnly))
                    fail(QStringLiteral("не создалось тестовое видео"));
                vf.write(QByteArray::fromHex("00000018667479706d703432") + QByteArray(4096, 'v'));
                vf.close();
                printf("step 4: оригинал скачан, шлём видео\n");
                chat.sendAttachmentFile(QUrl::fromLocalFile(videoPath));
                g_step = 41;
            }
            break;
        case 41: { // видео подтверждено сервером
            const QVariantMap m = findMessage(msgs, [](const QVariantMap &m) {
                const QVariantList atts = m.value("attachments").toList();
                return !atts.isEmpty() && m.value("id").toInt() > 0
                    && atts.first().toMap().value("kind").toString() == QLatin1String("video");
            });
            if (!m.isEmpty()) {
                printf("step 4v: видео доставлено, шлём ответ оператора\n");
                g_step = 5;
            }
            break;
        }
        case 5: { // ответ оператора через admin API (по account треда)
            if (*adminReplySent)
                break;
            *adminReplySent = true;
            QNetworkRequest listReq{QUrl(base + QStringLiteral("/admin/support/threads?brand=tribe"))};
            listReq.setRawHeader("Authorization", "Bearer " + adminToken.toUtf8());
            QNetworkReply *lr = nam.get(listReq);
            QObject::connect(lr, &QNetworkReply::finished, [&nam, lr, base, adminToken]() {
                lr->deleteLater();
                const QJsonArray arr = QJsonDocument::fromJson(lr->readAll()).array();
                if (arr.isEmpty())
                    fail(QStringLiteral("админ-список тредов пуст"));
                const int threadId = arr.first().toObject().value("id").toInt();
                QNetworkRequest req{QUrl(base
                                         + QStringLiteral("/admin/support/threads/%1/messages")
                                               .arg(threadId))};
                req.setRawHeader("Authorization", "Bearer " + adminToken.toUtf8());
                req.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
                const QByteArray body =
                    QJsonDocument(QJsonObject{{"body", "e2e: ответ оператора"}}).toJson();
                QNetworkReply *pr = nam.post(req, body);
                QObject::connect(pr, &QNetworkReply::finished, [pr]() {
                    pr->deleteLater();
                    const int code =
                        pr->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
                    if (code < 200 || code >= 300)
                        fail(QStringLiteral("операторский ответ: HTTP %1").arg(code));
                    printf("step 5: операторский ответ отправлен, ждём его в треде\n");
                    g_step = 6;
                });
            });
            break;
        }
        case 6: { // ответ оператора дошёл поллингом; unread 0 (чат открыт)
            const QVariantMap m = findMessage(msgs, [](const QVariantMap &m) {
                return m.value("sender").toString() == QLatin1String("operator")
                    && m.value("body").toString().startsWith(QStringLiteral("e2e:"));
            });
            if (!m.isEmpty()) {
                if (chat.unread() != 0)
                    fail(QStringLiteral("unread=%1 при открытом чате").arg(chat.unread()));
                pass();
            }
            break;
        }
        default:
            break;
        }
    });
    tick->start();

    return app.exec();
}
