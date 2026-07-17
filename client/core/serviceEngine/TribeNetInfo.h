#pragma once
// AVPN (Доктор D-3, 2026-07-17): платформенные сигналы сети для диагностики — поколение
// сотовой (3G медленный сам по себе, не вина VPN), metered/data-saver, роуминг.
// Кросс-обёртка; реализация: iOS — client/platforms/ios/TribeNetInfoIos.mm (CoreTelephony),
// Android — JNI к TelephonyManager (внутри .cpp), десктопы — заглушки.
// Приватность: наружу только обезличенные категории ("lte"/"3g"/флаги), никаких имён
// сетей/операторов/BSSID (роадмап §C-доп: BSSID на сервер НИКОГДА).

#include <QString>

namespace avpn {

// "5g" | "lte" | "3g" | "2g" | "" (не сотовая / неизвестно / нет разрешения).
QString cellularGeneration();

// 1 = metered (лимитный тариф/Data Saver), 0 = нет, -1 = неизвестно/не поддержано.
int meteredState();

// 1 = роуминг, 0 = нет, -1 = неизвестно (iOS API мёртв — всегда -1 там).
int roamingState();

} // namespace avpn
