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
#include "path/PathTunables.h"
#include "path/PathRace.h"

#include <QtGlobal>

#include <cmath>   // AVPN (iOS data watch, 141): std::isfinite / std::llround of the table below
#include <cstring> // AVPN (iOS data watch, 141): std::strcmp

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

// AVPN (фикс-волна 2026-09-22, B6): кап переподъёмов ТОЙ ЖЕ ноды (шаг 2 лестницы лечения DEAD:
// rebind → переподъём → другая нода) на ноду-сессию. Пол 0 (легитимно глушит шаг числом, есть и
// kill-switch features.dead_reup_same_node), потолок 3 (выше — борьба с реально мёртвой нодой).
inline int deadReupMaxTriesTuned()
{
    return qBound(0, int(TuningStore::numberOr(QStringLiteral("dead_reup_max_tries"), 1)), 3);
}

// AVPN (фикс-волна 2026-09-22, B6, ревью CL-B REV-1): через сколько секунд ЗДОРОВОГО туннеля на
// той же ноде (rx растёт или свежий handshake, ни одного плохого цикла) бюджет лечения (rebind/
// переподъём) возвращается (numbers.heal_budget_restore_s). Без этого за долгую сессию с частыми
// сменами точки доступа лестница выгорала и каждый следующий ложный DEAD уводил EE→US. Пол 60
// (ниже — вечная лестница против реально мёртвой ноды), потолок 3600.
inline int healBudgetRestoreSTuned()
{
    return qBound(60, int(TuningStore::numberOr(QStringLiteral("heal_budget_restore_s"), 300)), 3600);
}

// AVPN (фикс-волна 2026-09-22, B8, роуминг): окно после смены сети (numbers.health_network_grace_s),
// в котором HealthLoop не выносит DEAD — NE сам лечит путь (bump/rebind ≤ ~15 с), ложный DEAD уводил
// EE→US. Пол 0 (окно выключено), потолок 120 (выше — мёртвый туннель висит без failover).
// Ревью CL-B (REV-5): серия частых смен продлевает окно не дальше 2×grace от первой смены серии,
// затем grace секунд «остывания» — смены не открывают окно и не сбрасывают выборку (флаппинг
// Wi-Fi/LTE не должен навсегда глушить DEAD при реально мёртвом data-plane).
inline int healthNetworkGraceSTuned()
{
    return qBound(0, int(TuningStore::numberOr(QStringLiteral("health_network_grace_s"), 20)), 120);
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

// iOS tunnel-side data watch (design docs/specs/2026-11-14-ios-tunnel-side-data-watch-design.md §5.6 and
// §0a, build 141, iOS only). ONE table of every number of the mechanism: a default or a bound moves by
// editing one row. toPlan: the number goes into TribeWatchPlan.json for the extension (it clamps again);
// false = read by the app only. Every value is an integer: clamp, then round to the nearest integer.
// Absent, non-finite or garbage from the server -> the default; out of range -> the nearest bound.
struct TunnelWatchNumberSpec {
    const char *key;
    double def;
    double lo;
    double hi;
    bool toPlan;
};
inline constexpr TunnelWatchNumberSpec kIosTunnelWatchNumbers[] = {
    // key                              default     floor      ceiling   plan
    {"ios_tw_cycle_s",                       25,       10,         120, true},  // dead cycle; > fleet keepalive 5-15 s
    {"ios_tw_cycle_min_tx_bytes",          1024,     1024,     1048576, true},  // demand per cycle
    {"ios_tw_dead_cycles",                    3,        2,          20, true},  // cycles in a row before no_data
    {"ios_tw_cycle_chain_gap_s",             30,        0,         300, true},  // gap between "neighbour" cycles
    {"ios_tw_recover_rx_bytes",           16384,     1024,     1048576, true},  // data that closes an episode
    {"ios_tw_min_episode_tx_bytes",        3072,     2048,     1048576, true},  // sent in the episode before a verdict
    {"ios_tw_hs_rx_allowance_bytes",        148,       92,        4096, true},  // handshake reply is not data
    {"ios_tw_hs_tx_allowance_bytes",       1024,      148,        8192, true},  // handshake initiation is not demand
    {"ios_tw_path_stable_s",                 20,        0,         120, true},  // quiet after a path change
    {"ios_tw_start_grace_s",                 20,        5,         120, true},  // grace after start / peer change
    {"ios_tw_wake_grace_s",                  10,        0,          60, true},  // grace after device sleep
    {"ios_tw_app_alive_s",                   10,        3,          60, true},  // no status request this long = app asleep
    {"ios_tw_max_switches",                   5,        0,           5, true},  // stage 2 only; 0 = never switch
    {"ios_tw_suspect_window_s",              60,       30,         600, true},  // window of the low-rx probe reason
    {"ios_tw_suspect_min_tx_bytes",       65536,     4096,    16777216, true},
    {"ios_tw_suspect_max_rx_bytes",        4096,        0,     1048576, true},
    {"ios_tw_probe_timeout_ms",            4000,     1000,       15000, true},  // probe through the tunnel
    {"ios_tw_probe_max_per_episode",          3,        1,          10, true},
    {"ios_tw_probe_max_per_hour",            12,        1,          60, true},
    {"ios_tw_probe_low_rx_max_per_hour",      2,        0,          12, true},  // the low-inbound trigger's own budget; 0 = off
    {"ios_tw_sanity_max_per_hour",           12,        1,          60, true},  // requests outside the tunnel
    {"ios_tw_switch_heal_steps",              2,        0,           2, true},  // stage 2: same-node heals the arbiter runs before a switch
    {"ios_tw_trial_probe_max_per_hour",      30,        1,          60, true},  // stage 2: trial probes (one per heal / switch) per hour
    {"ios_tw_switch_max_per_hour",            6,        1,          30, true},  // stage 2: in-place switches per hour, a hard ceiling
    {"ios_tw_switch_lease_min",             360,       10,        1440, true},  // stage 2: the switch permission lapses this long after the last plan write
    {"ios_tw_sanity_required",                1,        0,           1, true},  // physical-network check required
    {"ios_tw_probe",                          1,        0,           1, true},  // 0 = no probe through the tunnel
    {"ios_tw_plan_ttl_h",                    24,        1,         168, true},  // plan expires_ms = written + this
    {"ios_tw_policy_max_age_h",              24,        0,         168, true},  // trust in the policy after the config
    // App only. How long the app holds its own decisions on return to the foreground waiting for the
    // extension's snapshot (TunnelWatchStatus.h::decideResumeFreeze): floor 0.5 s (one status round
    // trip), ceiling 10 s (longer and the user waits for nothing).
    {"ios_tw_resume_wait_ms",              3000,      500,       10000, false},
    // App only. How long the On-Demand arming may hold background time after the app leaves the
    // screen: ceiling 28 s - iOS grants about 30 s and kills an app that overstays its task.
    {"ios_on_demand_bg_arm_max_s",           25,        5,          28, false},
};

inline long long clampTunnelWatchNumber(const TunnelWatchNumberSpec &spec, double raw)
{
    const double v = std::isfinite(raw) ? qBound(spec.lo, raw, spec.hi) : spec.def;
    return std::llround(v);
}

inline const TunnelWatchNumberSpec *tunnelWatchNumberSpec(const char *key)
{
    for (const TunnelWatchNumberSpec &s : kIosTunnelWatchNumbers)
        if (std::strcmp(s.key, key) == 0)
            return &s;
    return nullptr;
}

// The clamped value of a table key from the current TuningStore snapshot; an unknown key is 0 (the
// table test proves every key the code reads is in the table).
inline long long iosTunnelWatchNumberTuned(const char *key)
{
    const TunnelWatchNumberSpec *s = tunnelWatchNumberSpec(key);
    if (!s)
        return 0;
    return clampTunnelWatchNumber(*s, TuningStore::numberOr(QLatin1String(key), s->def));
}

inline int iosTwResumeWaitMsTuned() { return int(iosTunnelWatchNumberTuned("ios_tw_resume_wait_ms")); }
inline int iosOnDemandBgArmMaxSTuned() { return int(iosTunnelWatchNumberTuned("ios_on_demand_bg_arm_max_s")); }

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
// Ranking penalty of an Xray listener whose exit RTT is unknown (decision 2026-11-05 after the
// owner test of 5.1.102): its own ICMP measures the RU entry shared by every listener (~14 ms), so
// it ranks as entry + penalty, never ahead of a measured exit (TransportPick.h::rankingRtt).
// numbers.xray_exit_rtt_penalty_ms: floor 0, ceiling 5000 ms, default 150.
inline int xrayExitRttPenaltyMsTuned()
{
    return qBound(0, int(TuningStore::numberOr(QStringLiteral("xray_exit_rtt_penalty_ms"), 150)), 5000);
}

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

// Path engine, stage 1 (design 2026-11-17): the numbers of one connect attempt (path/PathTunables.h holds the
// compiled defaults, measured on the iPhone Air 17-18.11). Every number is a server number with a clamp:
//   attempt_awg_start_ms 4500 [2000..20000], attempt_xray_start_ms 5000 [2000..20000],
//   attempt_provider_start_ms 6000 [2000..20000], attempt_data_check_ms 4000 [1500..15000],
//   attempt_budget_ms 45000 [10000..120000], attempt_max_paths 12 [1..32], attempt_stop_confirm_ms 10000
//   [2000..30000].
inline path::AttemptTimings attemptTimingsTuned()
{
    const path::AttemptTimings d;
    const auto num = [](const char *key, int def, int lo, int hi) {
        return qBound(lo, int(TuningStore::numberOr(QLatin1String(key), def)), hi);
    };
    path::AttemptTimings t = d;
    t.awgStartMs = num("attempt_awg_start_ms", d.awgStartMs, 2000, 20000);
    t.xrayStartMs = num("attempt_xray_start_ms", d.xrayStartMs, 2000, 20000);
    t.providerStartMs = num("attempt_provider_start_ms", d.providerStartMs, 2000, 20000);
    t.providerLeaseMs = num("attempt_provider_lease_ms", d.providerLeaseMs, 1500, 10000);
    t.dataCheckMs = num("attempt_data_check_ms", d.dataCheckMs, 1500, 15000);
    t.budgetMs = num("attempt_budget_ms", d.budgetMs, 10000, 120000);
    t.maxPaths = num("attempt_max_paths", d.maxPaths, 1, 32);
    t.stopConfirmMs = num("attempt_stop_confirm_ms", d.stopConfirmMs, 2000, 30000);
    return t;
}

// Stage 2: the probe race's numbers (path/PathRace.h), server-tunable; compiled defaults to be calibrated on device.
inline path::RaceTimings raceTimingsTuned()
{
    const path::RaceTimings d;
    const auto num = [](const char *key, int def, int lo, int hi) {
        return qBound(lo, int(TuningStore::numberOr(QLatin1String(key), def)), hi);
    };
    path::RaceTimings t = d;
    t.parallelism = num("race_parallelism", d.parallelism, 1, 8);
    t.staggerMs = num("race_stagger_ms", d.staggerMs, 0, 2000);
    t.waveSize = num("race_wave_size", d.waveSize, 1, 32);
    t.raceBudgetMs = num("race_budget_ms", d.raceBudgetMs, 2000, 30000);
    t.probeTimeoutMs = num("race_probe_timeout_ms", d.probeTimeoutMs, 1000, 15000);
    t.providerPerRace = num("race_provider_per_race", d.providerPerRace, 0, 8);
    t.hedgeMs = num("race_hedge_ms", d.hedgeMs, -1, 10000); // -1: derived (RaceTimings::hedgeAfterMs), 0: at once
    t.spareProofs = num("race_spare_proofs", d.spareProofs, 0, 8);
    t.knownFreshMin = num("race_known_fresh_min", d.knownFreshMin, 0, 1440);
    t.cellularMaxBytes = num("race_cellular_max_bytes", d.cellularMaxBytes, 0, 4 * 1024 * 1024);
    return t;
}

// Upstream nodes (plan provider-pool v2, point 6; CONNECT-INVARIANTS §1, §17.2): the lease acquire runs INSIDE the
// provider leg of the attempt owner, before the native start (VpnConnectionTunnelControl::up). The leg's start
// deadline is the lease share plus the native start share (path::AttemptTimings providerLeaseMs + providerStartMs,
// review E6 of 18.11), so the acquire is bounded by the lease share - one number: numbers.attempt_provider_lease_ms
// (attemptTimingsTuned). Floor 1.5 s (a direct TLS round trip on a slow cellular link).
inline int upstreamAcquireTimeoutMsTuned()
{
    return attemptTimingsTuned().providerLeaseMs;
}

// The release on a user disconnect goes through the tunnel BEFORE the core stops (contract §6) and the
// stop waits for it at most this long (the request's own transfer timeout; no timer of its own).
inline constexpr int kUpstreamReleaseTimeoutMs = 1500;
// A renewal through the tunnel: the API client's usual bound.
inline constexpr int kUpstreamRenewTimeoutMs = 15000;

} // namespace avpn
