// Юнит AnnounceGate::quietActive — «тихое окно» popup-объявлений после онбординга.
// Автономно (только QtCore), без сети/движка. Запуск: build_announce_gate.sh
#include "../AnnounceGate.h"

#include <QtGlobal>
#include <cstdio>

static int g_fail = 0;
#define CHECK(cond, name)                                                                          \
    do {                                                                                           \
        if (cond) {                                                                                \
            std::printf("OK   %s\n", name);                                                        \
        } else {                                                                                   \
            std::printf("FAIL %s\n", name);                                                        \
            ++g_fail;                                                                              \
        }                                                                                          \
    } while (0)

int main()
{
    using avpn::AnnounceGate;
    const qint64 done = 1'000'000; // условный epoch завершения онбординга, сек

    // нет отметки онбординга (старые установки/до фичи) — окна нет
    CHECK(!AnnounceGate::quietActive(0, 60, done + 10), "doneAt=0 -> not quiet");
    CHECK(!AnnounceGate::quietActive(-5, 60, done + 10), "doneAt<0 -> not quiet");

    // внутри окна — тихо; строгая граница: ровно N минут -> окно уже кончилось
    CHECK(AnnounceGate::quietActive(done, 60, done + 1), "1s after done -> quiet");
    CHECK(AnnounceGate::quietActive(done, 60, done + 60 * 60 - 1), "last second -> quiet");
    CHECK(!AnnounceGate::quietActive(done, 60, done + 60 * 60), "exactly 60min -> not quiet");
    CHECK(!AnnounceGate::quietActive(done, 60, done + 60 * 60 + 1), "after window -> not quiet");

    // оператор прислал 0/минус — окно выключено (0 легитимен: «показывать сразу»)
    CHECK(!AnnounceGate::quietActive(done, 0, done + 1), "quietMin=0 -> off");
    CHECK(!AnnounceGate::quietActive(done, -10, done + 1), "quietMin<0 -> off");

    // кап сверху: опечатка оператора (huge) не глушит объявления навсегда — максимум 7 суток
    CHECK(AnnounceGate::quietActive(done, 999999, done + 7 * 24 * 3600 - 1),
          "huge quietMin -> capped, still quiet at 7d-1s");
    CHECK(!AnnounceGate::quietActive(done, 999999, done + 7 * 24 * 3600),
          "huge quietMin -> capped at 7d");

    // часы устройства прыгнули назад (now < doneAt) — консервативно тихо (окно не «вечное»:
    // истечёт от doneAt), но не показываем попап при явно битом времени
    CHECK(AnnounceGate::quietActive(done, 60, done - 100), "clock skew back -> quiet");

    if (g_fail) {
        std::printf("FAILED: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL OK\n");
    return 0;
}
