// AVPN service/server — автономная проверка reset-safe аккумулятора статистики xray-пути
// (XrayTrafficAccumulator из xray.h; демон macOS отдаёт его кумулятивы через IPC xrayRuntimeStatus).
// Требования (CONNECT-INVARIANTS §17.1): наружу — кумулятив с подъёма сессии; первый замер = база;
// откат счётчика (utun пересоздан) — без underflow, новое значение = набрано после отката;
// «интерфейса нет» замером не считается. Сборка/запуск: service/server/tests/build_xray_traffic.sh
#include "../xray.h"

#include <cstdio>

static int g_failed = 0;
static int g_total = 0;

#define CHECK(expr)                                                                                 \
    do {                                                                                            \
        ++g_total;                                                                                  \
        if (!(expr)) {                                                                              \
            ++g_failed;                                                                             \
            fprintf(stderr, "FAIL [%s:%d]: %s\n", __FILE__, __LINE__, #expr);                       \
        }                                                                                           \
    } while (0)

int main()
{
    // 1. Пустой аккумулятор — нули, базы нет.
    {
        XrayTrafficAccumulator acc;
        CHECK(!acc.haveBase);
        CHECK(acc.totalRx == 0 && acc.totalTx == 0 && acc.resets == 0);
    }

    // 2. Первый замер — база: utun мог жить до нас с чужими байтами, они в кумулятив не идут.
    {
        XrayTrafficAccumulator acc;
        acc.sample(5000, 7000);
        CHECK(acc.haveBase);
        CHECK(acc.totalRx == 0 && acc.totalTx == 0);
        CHECK(acc.lastRx == 5000 && acc.lastTx == 7000);
    }

    // 3. Монотонный рост — кумулятив = сумма дельт.
    {
        XrayTrafficAccumulator acc;
        acc.sample(100, 200);
        acc.sample(150, 260);
        acc.sample(150, 260); // без трафика — не меняется
        acc.sample(400, 300);
        CHECK(acc.totalRx == 300);
        CHECK(acc.totalTx == 100);
        CHECK(acc.resets == 0);
    }

    // 4. Откат обоих счётчиков (интерфейс пересоздан): без underflow, новое значение — трафик
    //    новой инкарнации, откат посчитан.
    {
        XrayTrafficAccumulator acc;
        acc.sample(1000, 2000);
        acc.sample(1500, 2500); // +500/+500
        acc.sample(40, 60);     // откат → +40/+60
        CHECK(acc.totalRx == 540);
        CHECK(acc.totalTx == 560);
        CHECK(acc.resets == 1);
        acc.sample(90, 60);     // после отката снова монотонно: +50/+0
        CHECK(acc.totalRx == 590);
        CHECK(acc.totalTx == 560);
        CHECK(acc.resets == 1);
    }

    // 5. Откат только одного счётчика — тоже новая инкарнация (оба стартуют с нуля):
    //    второй счётчик не должен дать «дельту размером с аптайм».
    {
        XrayTrafficAccumulator acc;
        acc.sample(1000, 1000);
        acc.sample(10, 1200); // rx откатился, tx «вырос» — считаем оба с нуля
        CHECK(acc.totalRx == 10);
        CHECK(acc.totalTx == 1200);
        CHECK(acc.resets == 1);
    }

    // 6. Несколько откатов подряд — считаются каждый, кумулятив не убывает.
    {
        XrayTrafficAccumulator acc;
        acc.sample(500, 500);
        acc.sample(100, 100);
        acc.sample(50, 50);
        acc.sample(70, 80);
        CHECK(acc.resets == 2);
        CHECK(acc.totalRx == 100 + 50 + 20);
        CHECK(acc.totalTx == 100 + 50 + 30);
    }

    // 7. reset() — новая сессия: база и кумулятив обнулены, следующий замер снова база.
    {
        XrayTrafficAccumulator acc;
        acc.sample(10, 10);
        acc.sample(20, 30);
        acc.reset();
        CHECK(!acc.haveBase);
        CHECK(acc.totalRx == 0 && acc.totalTx == 0 && acc.resets == 0);
        acc.sample(999, 999);
        CHECK(acc.totalRx == 0 && acc.totalTx == 0);
        acc.sample(1000, 1001);
        CHECK(acc.totalRx == 1 && acc.totalTx == 2);
    }

    // 8. Большие значения (64-бит) без переполнения дельты.
    {
        XrayTrafficAccumulator acc;
        const quint64 big = 0xFFFFFFFF00000000ULL;
        acc.sample(big, big);
        acc.sample(big + 12345, big + 1);
        CHECK(acc.totalRx == 12345);
        CHECK(acc.totalTx == 1);
    }

    if (g_failed == 0) {
        fprintf(stderr, "xray_traffic_check: OK (%d checks)\n", g_total);
        return 0;
    }
    fprintf(stderr, "xray_traffic_check: FAILED %d/%d\n", g_failed, g_total);
    return 1;
}
