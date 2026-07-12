// AVPN serviceEngine (sub-grace): юнит чистой функции SubscriptionGate::graceExpired —
// «подписка истекла И грейс (+N ч) прошёл» → движок гасит туннель (enforceSubscriptionGrace).
// Контракт: пустой/невалидный expiresAt НИКОГДА не true (бессрочная/неизвестная подписка не
// рвётся); graceHours клампится >=1 ВНУТРИ функции (0/минус с бэка не убивают грейс мгновенно);
// граница строгая (now == expiresAt+grace → ещё НЕ истёк). Только QtCore.
#include "../SubscriptionGate.h"
#include "../TuningStore.h"
#include <QCoreApplication>
#include <QDateTime>
#include <cstdio>

static int g_fail = 0;
#define CHECK(cond, msg) do { if (cond) printf("OK   %s\n", msg); \
    else { printf("FAIL %s\n", msg); ++g_fail; } } while (0)

using avpn::SubscriptionGate;

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);

    const QDateTime exp = QDateTime::fromString(QStringLiteral("2026-07-01T00:00:00Z"), Qt::ISODate);
    const QString iso = QStringLiteral("2026-07-01T00:00:00Z");

    // (а) валидный ISO: далеко за пределами грейса → true
    CHECK(SubscriptionGate::graceExpired(iso, 24, exp.addDays(3)),
          "expired 3 days ago, grace 24h => true");
    // (б) ещё не истекла → false
    CHECK(!SubscriptionGate::graceExpired(iso, 24, exp.addSecs(-3600)),
          "not expired yet => false");
    // (в) истекла, но внутри грейса → false
    CHECK(!SubscriptionGate::graceExpired(iso, 24, exp.addSecs(23 * 3600)),
          "expired but inside 24h grace => false");
    // (г) пустой expiresAt (бессрочная/неизвестная) → НИКОГДА не рвём
    CHECK(!SubscriptionGate::graceExpired(QString(), 24, exp.addDays(365)),
          "empty expiresAt => false (never enforce)");
    // (д) мусор вместо ISO → false
    CHECK(!SubscriptionGate::graceExpired(QStringLiteral("not-a-date"), 24, exp.addDays(365)),
          "garbage expiresAt => false");
    // (е) РОВНО на границе (now == expiresAt + grace) → ещё false (строгое >)
    CHECK(!SubscriptionGate::graceExpired(iso, 24, exp.addSecs(24 * 3600)),
          "exactly at boundary => false (strict >)");
    CHECK(SubscriptionGate::graceExpired(iso, 24, exp.addSecs(24 * 3600 + 1)),
          "boundary + 1s => true");
    // (ж) кламп graceHours: 0 с бэка НЕ убивает грейс мгновенно — ведёт себя как 1 час
    CHECK(!SubscriptionGate::graceExpired(iso, 0, exp.addSecs(30 * 60)),
          "graceHours=0 clamped to 1h: +30min => false");
    CHECK(SubscriptionGate::graceExpired(iso, 0, exp.addSecs(61 * 60)),
          "graceHours=0 clamped to 1h: +61min => true");
    // (з) отрицательный graceHours → тот же кламп
    CHECK(!SubscriptionGate::graceExpired(iso, -5, exp.addSecs(30 * 60)),
          "graceHours=-5 clamped to 1h: +30min => false");
    // (и) ISO с таймзоной-смещением (бэк может слать +00:00/+03:00) — парсится и сравнивается в UTC
    CHECK(SubscriptionGate::graceExpired(QStringLiteral("2026-07-01T03:00:00+03:00"), 24,
                                         exp.addSecs(24 * 3600 + 1)),
          "ISO with +03:00 offset == same UTC instant => true past boundary");

    // (к) server-tunable: numbers.subscription_grace_hours (фолбэк 24, кламп >=1 на точке сева)
    avpn::TuningStore::reset();
    CHECK(SubscriptionGate::graceHoursTuned() == 24, "tuned: empty store => fallback 24");
    avpn::TuningStore::set({{QStringLiteral("subscription_grace_hours"), 48.0}}, {});
    CHECK(SubscriptionGate::graceHoursTuned() == 48, "tuned: server 48 => 48");
    avpn::TuningStore::set({{QStringLiteral("subscription_grace_hours"), 0.0}}, {});
    CHECK(SubscriptionGate::graceHoursTuned() == 1, "tuned: server 0 => clamped 1");
    avpn::TuningStore::set({{QStringLiteral("subscription_grace_hours"), -7.0}}, {});
    CHECK(SubscriptionGate::graceHoursTuned() == 1, "tuned: server -7 => clamped 1");
    avpn::TuningStore::reset();
    CHECK(SubscriptionGate::graceHoursTuned() == 24, "tuned: after reset => fallback 24");

    printf(g_fail ? "\n%d FAIL\n" : "\nALL OK\n", g_fail);
    return g_fail ? 1 : 0;
}
