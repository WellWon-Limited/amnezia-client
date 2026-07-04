#pragma once
// AVPN (Tribe): гео-зависимый АВТО-режим тумблера «АвтоVPN» (AvpnBypass/masterOn).
// Чистая решающая логика без I/O — юнит-тест tests/geo_auto_bypass_check.cpp.
// Спека: tribe-front docs/superpowers/specs/2026-07-04-geo-auto-bypass-toggle-design.md.
//
// Правила (анти-дёрганье):
//  - userLock (ручной тап по тумблеру) — вечный: гео больше НИКОГДА не трогает значение;
//  - неизвестный egress (проба молчит/нет сети) ничего не меняет;
//  - авто-ВКЛ по одному фактору (egress==RU);
//  - авто-ВЫКЛ двухфакторный: egress!=RU И локальные сигналы устройства не-RU
//    (закрывает «юзер в РФ с чужим VPN»: egress покажет Европу, таймзона — Moscow);
//  - возвращаем действие только при РЕАЛЬНОЙ смене значения (иначе -1), чтобы
//    вызывающий не писал QSettings и не эмитил сигналов вхолостую.

#include <QLocale>
#include <QString>
#include <QTimeZone>

namespace avpn {

// Что сделать с тумблером после гео-пробы: -1 = не трогать; 0 = выключить; 1 = включить.
inline int decideAutoBypass(bool userLock, bool currentOn, const QString &egressLoc, bool localRu)
{
    if (userLock) return -1;
    if (egressLoc.trimmed().isEmpty()) return -1;
    const bool egressRu = (egressLoc.trimmed().compare(QStringLiteral("RU"), Qt::CaseInsensitive) == 0);
    if (egressRu) return currentOn ? -1 : 1;
    if (localRu) return -1;
    return currentOn ? 0 : -1;
}

// Локальные сигналы «устройство в РФ»: территория системной таймзоны ИЛИ локали == Россия.
// (Таймзону iOS/Android выставляют сами по сети/GPS — сигнал живой, не «настройка юзера».)
inline bool localSignalsRu()
{
    const QTimeZone tz = QTimeZone::systemTimeZone();
    if (tz.isValid() && tz.territory() == QLocale::Russia) return true;
    return QLocale::system().territory() == QLocale::Russia;
}

} // namespace avpn
