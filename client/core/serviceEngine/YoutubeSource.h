// AVPN serviceEngine — byte-source для goodput-пробы YouTube на реально-душимом пути. [чистая логика — тестируема]
//
// RU душит YouTube по SNI *.googlevideo.com (видео-CDN), НЕ по www.youtube.com. Чтобы правдиво измерить
// скорость, нужен реальный videoplayback-URL на googlevideo. Берём его через InnerTube `player` API с
// клиент-контекстом iOS/Android — он отдаёт ПРЯМОЙ url БЕЗ signature-cipher (не хрупкая n-sig-логика
// yt-dlp; парсим только поле `url`). Затем ranged-GET N байт по этому URL (реальный googlevideo SNI).
//
// Этот класс — ЧИСТЫЙ билдер запроса + парсер JSON-ответа + сборка ranged-URL. Сеть — в ServiceProbe.cpp.
#pragma once

#include <QByteArray>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QString>
#include <QStringList>

namespace avpn {

class YoutubeSource {
public:
    // Evergreen-видео (годами не удаляют): jNQXAC9IVRw = «Me at the zoo» (первое видео YouTube);
    // BaW_jenozKc = публичный тест-клип (используется yt-dlp как стабильный). Фолбэки на случай гео-блока одного.
    static QStringList evergreenVideoIds()
    {
        return {QStringLiteral("jNQXAC9IVRw"), QStringLiteral("BaW_jenozKc")};
    }

    // Публичный ключ web-InnerTube (константа из клиента YouTube, НЕ секрет).
    static QString innerTubeKey()
    {
        return QStringLiteral("AIzaSyAO_FJ2SlqU8Q4STEHLGCilw_Y9_11qcW8");
    }

    // Тело POST для https://youtubei.googleapis.com/youtubei/v1/player?key=...
    // Клиент-контекст (iOS/Android) заставляет InnerTube отдать прямой url без cipher. deviceModel/osVersion
    // опциональны: iOS-клиент требует девайс-контекст, иначе может не отдать streamingData.
    static QByteArray buildPlayerRequest(const QString &videoId, const QString &clientName,
                                         const QString &clientVersion,
                                         const QString &deviceModel = QString(),
                                         const QString &osVersion = QString())
    {
        QJsonObject client{
            {QStringLiteral("clientName"), clientName},
            {QStringLiteral("clientVersion"), clientVersion},
            {QStringLiteral("hl"), QStringLiteral("en")},
            {QStringLiteral("gl"), QStringLiteral("US")},
        };
        if (!deviceModel.isEmpty()) {
            client.insert(QStringLiteral("deviceMake"), QStringLiteral("Apple"));
            client.insert(QStringLiteral("deviceModel"), deviceModel);
            client.insert(QStringLiteral("osName"), QStringLiteral("iOS"));
            if (!osVersion.isEmpty())
                client.insert(QStringLiteral("osVersion"), osVersion);
        }
        QJsonObject context{{QStringLiteral("client"), client}};
        QJsonObject root{
            {QStringLiteral("context"), context},
            {QStringLiteral("videoId"), videoId},
            {QStringLiteral("contentCheckOk"), true},
            {QStringLiteral("racyCheckOk"), true},
        };
        return QJsonDocument(root).toJson(QJsonDocument::Compact);
    }

    // Из JSON-ответа player вытащить ПРЯМОЙ googlevideo videoplayback URL (поле `url`, не cipher).
    // Пусто ⇒ не нашли пригодный формат (API сменился/только cipher) ⇒ раннер деградирует в reachability.
    static QString extractVideoplaybackUrl(const QByteArray &playerJson)
    {
        const QJsonObject sd = QJsonDocument::fromJson(playerJson).object()
                                   .value(QStringLiteral("streamingData")).toObject();
        for (const char *field : {"formats", "adaptiveFormats"}) {
            const QJsonArray arr = sd.value(QLatin1String(field)).toArray();
            for (const QJsonValue &v : arr) {
                const QString url = v.toObject().value(QStringLiteral("url")).toString();
                // Только прямой url на реально-душимом googlevideo (cipher-only форматы игнорируем).
                if (!url.isEmpty() && url.contains(QLatin1String(".googlevideo.com/")))
                    return url;
            }
        }
        return QString();
    }

    // Ограничить скачивание диапазоном байт (googlevideo уважает &range=first-last).
    static QString withRange(const QString &url, qint64 first, qint64 last)
    {
        const QChar sep = url.contains(QLatin1Char('?')) ? QLatin1Char('&') : QLatin1Char('?');
        return url + sep + QStringLiteral("range=%1-%2").arg(first).arg(last);
    }
};

} // namespace avpn
