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

// BUG-4 auto-heal (2026-07-22): кап попыток ребайнда сокета (новый локальный порт = новый
// 5-tuple flow, лечит сессионный блок ТСПУ) на ТЕКУЩЕЙ ноде перед failover. Пол 0 — «0 с бэка»
// легитимно глушит heal числом (есть и kill-switch features.rebind_heal); потолок 5 — выше
// начинается вечная борьба с реально мёртвой нодой вместо честной смены сервера.
inline int rebindHealMaxTriesTuned()
{
    return qBound(0, int(TuningStore::numberOr(QStringLiteral("rebind_heal_max_tries"), 2)), 5);
}

// macOS wake-рестарт (спека 2026-07-17): кап НАШИХ попыток переподнять туннель после пробуждения
// (ретраи цепляются к reachabilityChanged). После капа — честный OFF («усталость = внешние
// обстоятельства», дух §13). Пол 1 (0/минус с бэка = wake-фикс молча выключен — для этого есть
// kill-switch features.wake_restart), потолок 10 (выше — вечная борьба с реально мёртвой сетью).
inline int wakeRestartMaxTriesTuned()
{
    return qBound(1, int(TuningStore::numberOr(QStringLiteral("wake_restart_max_tries"), 5)), 10);
}

// AVPN awg31-xray-v1 (спека 2026-09-01 §2.3, инвариант волны §4.3): «Подключено» по xray — ТОЛЬКО
// после первой удачной пробы (DNS+HTTPS generate_204) ЧЕРЕЗ туннель; handshake/порт/процесс — не
// успех. Бюджет верификации (numbers.xray_verify_timeout_ms): пол 3с (ниже — ложные провалы на
// любой сотовой: Reality-рукопожатие + маршруты), потолок 60с (выше — вечный «Проверяем трафик»).
// По истечении — провал data-plane → другой транспорт той же локации (failover).
inline int xrayVerifyTimeoutMsTuned()
{
    return qBound(3000, int(TuningStore::numberOr(QStringLiteral("xray_verify_timeout_ms"), 12000)), 60000);
}

// AVPN awg31-xray-v1: у xray нет handshake по определению — вторая половина DEAD-критерия =
// провал живой пробы через туннель N тиков ПОДРЯД (numbers.xray_probe_fail_cycles). Пол 1
// (0/минус = никогда не DEAD по пробе), потолок 10 (выше — мёртвый туннель висит минуту+).
inline int xrayProbeFailCyclesTuned()
{
    return qBound(1, int(TuningStore::numberOr(QStringLiteral("xray_probe_fail_cycles"), 3)), 10);
}

} // namespace avpn
