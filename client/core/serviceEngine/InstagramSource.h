// AVPN serviceEngine — byte-source для goodput-пробы Instagram на реально-душимом/блокируемом пути. [чистая логика — тестируема]
//
// Медиа/статику Instagram отдаёт CDN *.cdninstagram.com (в РФ его режут/душат), а НЕ www.instagram.com.
// Правдивый замер — скачать реальный публичный ассет CDN (без логина) и померить скорость. URL берём из
// публичной HTML-страницы www.instagram.com/ (ссылки на static.cdninstagram.com/*.js — sizeable, без auth).
//
// Этот класс — ЧИСТЫЙ парсер HTML → URL ассета. Сеть — в ServiceProbe.cpp.
#pragma once

#include <QByteArray>
#include <QRegularExpression>
#include <QString>

namespace avpn {

class InstagramSource {
public:
    // Найти в HTML публичный sizeable ассет (.js/.css) на *.cdninstagram.com. Пусто ⇒ не нашли
    // (раннер деградирует в reachability-пробу CDN, не выдавая ложный «works»).
    static QString extractCdnAssetUrl(const QByteArray &html)
    {
        static const QRegularExpression re(
            QStringLiteral(R"(https://[^"'\s]*cdninstagram\.com/[^"'\s]+\.(?:js|css))"));
        const QRegularExpressionMatch m = re.match(QString::fromUtf8(html));
        return m.hasMatch() ? m.captured(0) : QString();
    }
};

} // namespace avpn
