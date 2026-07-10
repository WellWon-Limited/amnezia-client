// AVPN: проверка политики ретраев тихого bootstrap (BootstrapRetry.h — чистые inline-функции).
// Корень бага «на сотовой ∞ навсегда»: старый бэкофф сдавался после 5 попыток (~60с) и больше
// никогда не пробовал. Новая политика: быстрый бэкофф {2,4,8,16,30}с, затем БЕСКОНЕЧНЫЙ
// медленный цикл 60с — движок не имеет права «сдаться» пока подписка не загружена.
#include "../BootstrapRetry.h"
#include "../TuningStore.h"

#include <QtGlobal>

#include <cstdio>

static int failures = 0;

#define CHECK(cond, msg)                                                                           \
    do {                                                                                           \
        if (cond) {                                                                                \
            std::printf("ok   - %s\n", msg);                                                       \
        } else {                                                                                   \
            std::printf("FAIL - %s\n", msg);                                                       \
            ++failures;                                                                            \
        }                                                                                          \
    } while (0)

int main()
{
    using avpn::nextBootstrapDelayMs;
    using avpn::kBootstrapSlowRetryMs;

    // Быстрая фаза — прежний бэкофф 2/4/8/16/30с (покрытие первой минуты не меняем).
    CHECK(nextBootstrapDelayMs(0) == 2000,  "attempt 0 -> 2s");
    CHECK(nextBootstrapDelayMs(1) == 4000,  "attempt 1 -> 4s");
    CHECK(nextBootstrapDelayMs(2) == 8000,  "attempt 2 -> 8s");
    CHECK(nextBootstrapDelayMs(3) == 16000, "attempt 3 -> 16s");
    CHECK(nextBootstrapDelayMs(4) == 30000, "attempt 4 -> 30s");

    // Медленная фаза — НИКОГДА не сдаёмся: любая попытка после 5-й даёт ровно 60с.
    CHECK(nextBootstrapDelayMs(5) == kBootstrapSlowRetryMs,    "attempt 5 -> slow cycle");
    CHECK(nextBootstrapDelayMs(6) == kBootstrapSlowRetryMs,    "attempt 6 -> slow cycle");
    CHECK(nextBootstrapDelayMs(100) == kBootstrapSlowRetryMs,  "attempt 100 -> slow cycle (never gives up)");
    CHECK(nextBootstrapDelayMs(1000000) == kBootstrapSlowRetryMs, "attempt 1e6 -> slow cycle, no overflow");
    CHECK(kBootstrapSlowRetryMs == 60000, "slow cycle is 60s");

    // Защита от мусора: отрицательная попытка не роняет и даёт валидную задержку.
    CHECK(nextBootstrapDelayMs(-1) == 2000, "attempt -1 clamps to first delay");

    // Задержка всегда положительная (таймер с 0/отрицательной задержкой = busy-loop по сети).
    bool allPositive = true;
    for (int i = -3; i < 50; ++i)
        if (nextBootstrapDelayMs(i) < 1000)
            allPositive = false;
    CHECK(allPositive, "every delay >= 1s");

    // Backend-first (T10): медленный вечный цикл читает TuningStore (numbers.bootstrap_slow_retry_ms),
    // фолбэк 60с сохраняется офлайн. Быстрая фаза {2,4,8,16,30}с server-tunable НЕ подлежит.
    avpn::TuningStore::set({{QStringLiteral("bootstrap_slow_retry_ms"), 120000}}, {});
    CHECK(nextBootstrapDelayMs(7) == 120000, "server override: attempt 7 -> tuned 120s slow cycle");
    avpn::TuningStore::reset();
    CHECK(nextBootstrapDelayMs(7) == 60000, "after reset: attempt 7 -> baked 60s fallback");
    CHECK(nextBootstrapDelayMs(0) == 2000,  "fast phase unaffected: attempt 0 -> 2s");
    CHECK(nextBootstrapDelayMs(1) == 4000,  "fast phase unaffected: attempt 1 -> 4s");
    CHECK(nextBootstrapDelayMs(2) == 8000,  "fast phase unaffected: attempt 2 -> 8s");
    CHECK(nextBootstrapDelayMs(3) == 16000, "fast phase unaffected: attempt 3 -> 16s");
    CHECK(nextBootstrapDelayMs(4) == 30000, "fast phase unaffected: attempt 4 -> 30s");

    if (failures) {
        std::printf(">>> bootstrap_retry_check: %d FAILURE(S)\n", failures);
        return 1;
    }
    std::printf(">>> bootstrap_retry_check: все проверки прошли\n");
    return 0;
}
