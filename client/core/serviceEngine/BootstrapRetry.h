#pragma once

// AVPN: политика ретраев ТИХОГО bootstrap-фетча подписки (AvpnEngineQml::tryBootstrapSubscription).
//
// Корень бага «на сотовой сети ∞ навсегда»: старый бэкофф {2,4,8,16,30}с сдавался после 5 попыток
// (~60с покрытия) и больше НИКОГДА не пробовал — ни по смене сети, ни по foreground. Если первое
// окно пришлось на холодное радио/слабый сигнал (каждый sync-запрос ограничен kSyncTimeoutMs=4с,
// поднимать нельзя — iOS-watchdog, см. NetAwait.h), пул нод оставался пустым до перезапуска.
//
// Новая политика: та же быстрая фаза {2,4,8,16,30}с, затем БЕСКОНЕЧНЫЙ медленный цикл 60с.
// Движок не имеет права «сдаться», пока подписка не загружена: следующая попытка стоит дёшево
// (один GET с 4с-капом раз в минуту), а восстановление сети ускоряется извне через
// kickBootstrap() (reachabilityChanged / выход из фона) — он просто поджимает таймер.
// Чистые inline-функции (только QtCore) — тестируются автономно: tests/build_bootstrap_retry.sh.
// Backend-first (T10): длительность медленного цикла — server-tunable (numbers.bootstrap_slow_retry_ms
// через TuningStore), фолбэк kBootstrapSlowRetryMs=60с офлайн/на первом запуске. Быстрая фаза
// {2,4,8,16,30}с — вкомпилированная константа, не читает бэкенд (первая минута не должна зависеть от сети).

#include "TuningStore.h"

namespace avpn {

inline constexpr int kBootstrapSlowRetryMs = 60000; // медленный вечный цикл после быстрой фазы

// Задержка перед попыткой №(attempt+1). attempt — сколько попыток уже провалилось (0-based).
inline int nextBootstrapDelayMs(int attempt)
{
    static constexpr int kFast[] = {2000, 4000, 8000, 16000, 30000};
    static constexpr int kFastCount = int(sizeof(kFast) / sizeof(kFast[0]));
    if (attempt < 0)
        attempt = 0;
    if (attempt < kFastCount)
        return kFast[attempt];
    // Медленный вечный цикл — server-tunable (numbers.bootstrap_slow_retry_ms), фолбэк 60с.
    return int(TuningStore::numberOr(QStringLiteral("bootstrap_slow_retry_ms"),
                                     double(kBootstrapSlowRetryMs)));
}

} // namespace avpn
