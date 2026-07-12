// AVPN serviceEngine (announce-quiet) — «тихое окно» popup-объявлений после первого онбординга.
// [header-only, чистая логика — тестируема: tests/build_announce_gate.sh]
//
// Инцидент 2026-07-12: rich-попап объявления (TribeAnnouncementSheet) визуально дублирует
// PageOnboardingTribe и всплывал через 900мс после «Приступим» — пользователь видел «два
// онбординга подряд». Решение backend-first: N минут после завершения онбординга popup-слой
// молчит (бейдж колокольчика и лента живут — глушится ТОЛЬКО автопоказ попапа), размер окна
// и рубильник приезжают с бэка без релиза:
//   · numbers.announce_onboarding_quiet_min (фолбэк 60) — размер окна в минутах;
//     0/минус = окно выключено (легитимно: «показывать сразу»), кап 7 суток — опечатка
//     оператора не глушит объявления новым юзерам навсегда;
//   · kill-switch features.announce_onboarding_quiet (default TRUE) — false возвращает
//     старое поведение целиком (читается на точке вызова в AvpnEngineQml, не здесь).
// doneAt <= 0 (старые установки, онбординг пройден ДО этой фичи) — окна нет.
#pragma once

#include "TuningStore.h"

#include <QtGlobal>

namespace avpn {

class AnnounceGate {
public:
    // true ⇔ онбординг завершён недавно (окно quietMin минут ещё не истекло).
    // Граница строгая: ровно quietMin минут -> окно уже кончилось. now < doneAt (часы
    // прыгнули назад) — консервативно тихо: окно всё равно истечёт от doneAt.
    static bool quietActive(qint64 doneAtEpochSec, double quietMin, qint64 nowEpochSec)
    {
        if (doneAtEpochSec <= 0)
            return false; // онбординга не было / пройден до фичи
        if (quietMin <= 0)
            return false; // оператор выключил окно значением
        const double capped = qMin(quietMin, 7.0 * 24 * 60); // кап 7 суток
        return nowEpochSec - doneAtEpochSec < qint64(capped * 60);
    }

    // Server-tunable размер окна: numbers.announce_onboarding_quiet_min, фолбэк 60 мин.
    // Кламп сверху здесь же (точка сева, REMOTE-TUNING.md §4); низ не клампим — 0 легитимен.
    static double quietMinTuned()
    {
        return qMin(TuningStore::numberOr(QStringLiteral("announce_onboarding_quiet_min"), 60),
                    7.0 * 24 * 60);
    }
};

} // namespace avpn
