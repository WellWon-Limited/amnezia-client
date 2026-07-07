// AVPN: нативный системный share sheet для произвольного текста/ссылки (рефералка, перенос
// подписки). НЕ путать с апстрим SystemController::saveFile — тот шарит только файлы-конфиги.
// Возвращает false, если нативного пути на платформе нет (desktop) — вызывающий QML делает
// fallback (копирование в буфер + тост).
#pragma once

#include <QString>

namespace AvpnShare
{
    // iOS: UIActivityViewController (non-blocking, без вложенного QEventLoop — правило движка);
    // Android: Intent.ACTION_SEND + createChooser; прочее: false.
    bool shareText(const QString &text);

    // Текст/ссылка + картинка (PNG на диске; Android: путь ОБЯЗАН лежать в files-dir — FileProvider
    // org.amnezia.vpn.qtprovider покрывает только его, см. res/xml/qtprovider_paths.xml).
    // iOS: UIActivityViewController [текст|NSURL, UIImage]; Android: ACTION_SEND image/png +
    // EXTRA_STREAM (content:// через FileProvider) + EXTRA_TEXT; прочее: false → QML-fallback.
    bool shareTextWithImage(const QString &text, const QString &imagePath);
}
