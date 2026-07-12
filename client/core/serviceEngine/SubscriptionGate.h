// AVPN serviceEngine (sub-grace) — гейт «подписка истекла И грейс прошёл» → управляемый stop.
// [header-only, чистая логика — тестируема: tests/build_subscription_gate.sh]
//
// Клиент никогда не рвал активный туннель по истечении подписки — гасил только бэкенд (degraded/
// пустой пул на следующем bootstrap). Этот гейт даёт движку право самому опустить туннель, но
// СТРОГО консервативно:
//   · пустой/невалидный expiresAt → false ВСЕГДА (бессрочная/неизвестная подписка НЕ рвётся);
//   · graceHours клампится >=1 ВНУТРИ функции — опечатка оператора (0/минус в PATCH /admin/config)
//     не должна убивать грейс мгновенно (тот же класс защиты, что ConnectTunables.h);
//   · граница строгая: now == expiresAt + grace → ещё НЕ истёк.
// Remote-ключи (REMOTE-TUNING.md): numbers.subscription_grace_hours (фолбэк 24) — размер грейса;
// kill-switch features.subscription_grace_enforce (default TRUE) читается на точке вызова
// (AvpnEngineQml::enforceSubscriptionGrace), не здесь — чистая функция про время, не про фичефлаги.
#pragma once

#include "TuningStore.h"

#include <QDateTime>
#include <QString>

namespace avpn {

class SubscriptionGate {
public:
    // true ⇔ expiresAt валиден И nowUtc СТРОГО позже expiresAt + graceHours.
    static bool graceExpired(const QString &expiresAtIso, int graceHours, const QDateTime &nowUtc)
    {
        if (expiresAtIso.isEmpty())
            return false; // бессрочно/ещё не загружено — не рвём НИКОГДА
        const QDateTime exp = QDateTime::fromString(expiresAtIso, Qt::ISODate);
        if (!exp.isValid())
            return false; // мусор с бэка — не повод гасить туннель
        const int hours = qMax(1, graceHours); // кламп: 0/минус ≠ «без грейса»
        return nowUtc.toUTC() > exp.toUTC().addSecs(qint64(hours) * 3600);
    }

    // Server-tunable размер грейса: numbers.subscription_grace_hours, вкомпиленный фолбэк 24 ч,
    // кламп >=1 на точке сева (REMOTE-TUNING.md §4 — клампы на точке сева обязательны).
    static int graceHoursTuned()
    {
        return qMax(1, int(TuningStore::numberOr(QStringLiteral("subscription_grace_hours"), 24)));
    }
};

} // namespace avpn
