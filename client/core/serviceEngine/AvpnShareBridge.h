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
}
