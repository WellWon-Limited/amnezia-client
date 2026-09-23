// AVPN (разбор 2026-09-23, журнал iPhone владельца): iOS замораживает приложение между нашим
// стопом и стартом (перезапуск reconcile/свитч/сторож) → VPN выключен до следующего открытия.
// RestartGuard.h решает, когда держать фоновое время iOS, чтобы начатый приложением перезапуск
// дошёл до старта. Здесь — чистые решения: предикат и защёлка «истекло — не просить снова».
#include "../RestartGuard.h"

#include <cstdio>

using namespace avpn;

static int g_failed = 0;
static int g_total = 0;

#define CHECK(expr, what)                                                                           \
    do {                                                                                            \
        ++g_total;                                                                                  \
        if (!(expr)) {                                                                              \
            ++g_failed;                                                                             \
            std::printf("FAIL: %s (%s:%d)\n", what, __FILE__, __LINE__);                            \
        }                                                                                           \
    } while (0)

static RestartGuardInputs in(bool want, bool connected, bool op, bool restart)
{
    RestartGuardInputs i;
    i.wantConnected = want;
    i.tunnelConnected = connected;
    i.opInFlight = op;
    i.needsRestart = restart;
    return i;
}

static void predicate()
{
    // Намерение ON, туннель не поднят (стоп в пути, Disconnected между стопом и стартом, Connecting).
    CHECK(restartGuardWanted(in(true, false, false, false)), "want on, tunnel down -> hold");
    CHECK(restartGuardWanted(in(true, false, true, false)), "want on, op in flight, down -> hold");
    // Поднят, но наш стоп/старт ещё в пути или перезапуск запрошен.
    CHECK(restartGuardWanted(in(true, true, true, false)), "connected but op in flight -> hold");
    CHECK(restartGuardWanted(in(true, true, false, true)), "connected but restart pending -> hold");
    // Устоялось: поднят, операций нет — отпускаем, iOS может заморозить приложение, туннель живёт в NE.
    CHECK(!restartGuardWanted(in(true, true, false, false)), "settled connected -> release");
    // Намерение OFF: пользовательский стоп не требует продолжения — фоновое время не нужно.
    CHECK(!restartGuardWanted(in(false, false, false, false)), "want off, down -> release");
    CHECK(!restartGuardWanted(in(false, true, true, false)), "want off, stopping -> release");
    CHECK(!restartGuardWanted(in(false, false, true, true)), "want off never holds");
}

static void latchBasics()
{
    RestartGuardLatch l;
    CHECK(!l.held(), "initially not held");
    CHECK(l.sync(true) == RestartGuardLatch::Action::Begin, "wanted -> Begin");
    CHECK(l.held(), "held after Begin");
    CHECK(l.sync(true) == RestartGuardLatch::Action::None, "still wanted -> no second Begin");
    CHECK(l.sync(false) == RestartGuardLatch::Action::End, "not wanted -> End");
    CHECK(!l.held(), "released after End");
    CHECK(l.sync(false) == RestartGuardLatch::Action::None, "not wanted twice -> None");
}

static void latchExpiry()
{
    // iOS истекло фоновое время (~30 с): система уже закончила задачу — не просим снова в том же
    // фоне (иначе цикл begin/expire), пока приложение не вернулось на экран.
    RestartGuardLatch l;
    CHECK(l.sync(true) == RestartGuardLatch::Action::Begin, "begin");
    l.onExpired();
    CHECK(!l.held(), "expired -> not held");
    CHECK(l.sync(true) == RestartGuardLatch::Action::None, "expired: no re-Begin while still wanted");
    CHECK(l.sync(true) == RestartGuardLatch::Action::None, "expired: repeated sync stays None");
    l.onForeground();
    CHECK(l.sync(true) == RestartGuardLatch::Action::Begin, "foreground resets expiry -> Begin");
}

static void latchExpiryThenSettle()
{
    // После истечения состояние устоялось (Connected) — следующий перезапуск снова защищён,
    // даже если приложение не выходило на экран (запрос в ещё живом фоне).
    RestartGuardLatch l;
    l.sync(true);
    l.onExpired();
    CHECK(l.sync(false) == RestartGuardLatch::Action::None, "settle after expiry: nothing to End");
    CHECK(l.sync(true) == RestartGuardLatch::Action::Begin, "new transition after settle -> Begin");
}

static void latchExpiredWhileNotHeld()
{
    // Лишний/поздний колбэк истечения без удержания не ломает защёлку.
    RestartGuardLatch l;
    l.onExpired();
    CHECK(!l.held(), "stray expiry -> not held");
    l.onForeground();
    CHECK(l.sync(true) == RestartGuardLatch::Action::Begin, "after foreground -> Begin");
}

int main()
{
    predicate();
    latchBasics();
    latchExpiry();
    latchExpiryThenSettle();
    latchExpiredWhileNotHeld();
    std::printf("restart_guard_check: %d/%d passed\n", g_total - g_failed, g_total);
    return g_failed == 0 ? 0 : 1;
}
