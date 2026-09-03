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

// AVPN seamless roaming (2026-09-03, CONNECT-INVARIANTS §23): числа политики адаптера AWG в iOS NE.
// Пауза устройства при ДОЛГОЙ потере пути (numbers.ios_roam_pause_after_s): 0 = никогда (дефолт,
// консенсус Tailscale/Proton/sing-box), потолок 600 (выше — бессмысленно, WG сам переживает часы).
inline int roamPauseAfterSTuned()
{
    return qBound(0, int(TuningStore::numberOr(QStringLiteral("ios_roam_pause_after_s"), 0)), 600);
}

// Сторож застоя в NE (numbers.ios_roam_stall_probe_s): исходящее растёт, входящее/handshake стоят
// столько секунд на живом пути -> bump сокета (тот же порт). 0 = сторож выключен; потолок 60.
inline int roamStallProbeSTuned()
{
    return qBound(0, int(TuningStore::numberOr(QStringLiteral("ios_roam_stall_probe_s"), 4)), 60);
}

// Вторая ступень сторожа (numbers.ios_roam_stall_rebind_s): застой продолжается ещё столько секунд
// ПОСЛЕ bump -> listen_port=0 (новый 5-tuple). 0 = только bump; потолок 120.
inline int roamStallRebindSTuned()
{
    return qBound(0, int(TuningStore::numberOr(QStringLiteral("ios_roam_stall_rebind_s"), 10)), 120);
}

// AVPN seamless roaming (§23.9, macOS демон): сколько раз ПОВТОРИТЬ пробу живости после смены
// BSSID/пробуждения, прежде чем считать туннель мёртвым и рестартовать (numbers.wake_probe_retries).
// 0 = одна проба (поведение до 2026-09-03); потолок 5 (шаг 4 с → до 20 с терпения).
inline int wakeProbeRetriesTuned()
{
    return qBound(0, int(TuningStore::numberOr(QStringLiteral("wake_probe_retries"), 2)), 5);
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

// AVPN awg31-xray-v1 (независимое ревью волны, MAJOR-1): кап ПОДРЯД идущих провалов data-plane
// за сессию. Без него failover крутится вечно: при реально мёртвом data-plane (captive portal,
// ТСПУ режет всё) цикл up → verifying → verifyFailed → down → up повторяется бесконечно, и
// пользователь не видит ни ошибки, ни причины. По исчерпании капа движок уходит в Error, фасад
// показывает честный текст и снимает намерение (§13 — поднять туннель может только пользователь).
// Пол 1 (0/минус с бэка не должен выключать механизм — он обязателен), потолок 10 (выше —
// та же вечная карусель). Дефолт 4: хватает обойти оба транспорта двух локаций.
inline int dataPlaneFailMaxTriesTuned()
{
    return qBound(1, int(TuningStore::numberOr(QStringLiteral("data_plane_fail_max_tries"), 4)), 10);
}

// AVPN awg31-xray-v1 (независимое ревью волны, MAJOR-3; инвариант §22.5 «Подключено по xray —
// только после реального трафика ЧЕРЕЗ туннель»). Успешный HEAD generate_204 доказывает ИНТЕРНЕТ,
// а не туннель: если tun2socks/маршруты не встали, а протокол уже отдал Connected, проба уходит
// напрямую мимо xray. Поэтому решение о верификации принимает эта чистая функция:
//   • httpOk=false                → продолжать попытки в пределах бюджета;
//   • rx>0                        → доказано: трафик реально пришёл ЧЕРЕЗ туннель;
//   • rx==0 при живом источнике   → доказательства ещё нет, ждём (0 = «неизвестно», §17.1);
//   • источника статистики нет вовсе (statsValid=false: демон молчит по IPC / NE не прислал
//     ни одного bytesChanged) — провалить коннект на этом НЕЛЬЗЯ (иначе всякий сбой IPC оставляет
//     пользователя без VPN): принимаем пробу, но помечаем «без доказательства» (лог + отчёт).
enum class VerifyStep {
    KeepTrying,           // ждём следующей попытки (бюджет ещё есть)
    Confirmed,            // проба прошла И rx через туннель > 0
    AcceptedWithoutStats, // проба прошла, но источник rx/tx недоступен — принимаем с оговоркой
};

inline VerifyStep verifyStepFor(bool httpOk, bool statsValid, qint64 rxBytes)
{
    if (!httpOk)
        return VerifyStep::KeepTrying;
    if (rxBytes > 0)
        return VerifyStep::Confirmed;
    if (!statsValid)
        return VerifyStep::AcceptedWithoutStats;
    return VerifyStep::KeepTrying;
}

} // namespace avpn
