// AVPN serviceEngine — клампованные server-tunable пороги КОННЕКТ-ПУТИ. [header-only, QtCore]
//
// Ревью 2026-07-11: три ревьюера независимо нашли одни и те же дыры волны backend-first —
// пороги, при опечатке оператора в PATCH /admin/config ломающие коннект ВСЕМ устройствам без
// релиза: handshake_timeout_ms=0 ⇒ каждый iOS-коннект умирает на первом тике checkStatus;
// reconcile_watchdog_ms=5000 < handshake-бюджета ⇒ сторож рвёт ещё живой коннект на медленных
// сетях. Правило: ЛЮБОЕ число с бэка на коннект-пути читается ТОЛЬКО через кламп, а связанные
// пороги (watchdog > handshake_timeout — инвариант из комментария у m_watchdog) связаны ПОЛОМ,
// не комментарием. TDD: tests/test_tuning_store.cpp блок connecttunables.
#pragma once

#include "TuningStore.h"

#include <QtGlobal>

namespace avpn {

// iOS NE: бюджет ожидания одного AWG-handshake (checkStatus). Пол 2с (ниже — ложные таймауты
// на любой сотовой), потолок 60с (выше — юзер смотрит на вечный Connecting).
inline int handshakeTimeoutMsTuned()
{
    return qBound(2000, int(TuningStore::numberOr(QStringLiteral("handshake_timeout_ms"), 12000)), 60000);
}

// iOS NE: сколько handshake-таймаутов подряд = Error + stopTunnel. Пол 1 (0/минус с бэка =
// мгновенный Error на первом тике), потолок 10.
inline int handshakeMaxTimeoutsTuned()
{
    return qBound(1, int(TuningStore::numberOr(QStringLiteral("handshake_max_timeouts"), 3)), 10);
}

// Сторож reconcile-машины (Op::Starting/Stopping). ИНВАРИАНТ: всегда > handshake_timeout_ms
// (иначе рвёт штатный медленный коннект — см. комментарий у конструкторного setInterval(15000)).
// Пол = handshake-бюджет + 3с запаса на NE-обвязку, и не ниже 5с; потолок 120с.
inline int reconcileWatchdogMsTuned()
{
    const int wd = qBound(5000, int(TuningStore::numberOr(QStringLiteral("reconcile_watchdog_ms"), 15000)),
                          120000);
    return qMax(handshakeTimeoutMsTuned() + 3000, wd);
}

// Health-tick (HealthLoop/ре-синк подписки). Пол 1с (0/минус с бэка = spin-loop event loop,
// CPU/батарея), потолок 60с (выше — DEAD-детект слепнет).
inline int healthTickMsTuned()
{
    return qBound(1000, int(TuningStore::numberOr(QStringLiteral("health_tick_ms"), 4000)), 60000);
}

} // namespace avpn
