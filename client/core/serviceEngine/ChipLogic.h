// AVPN serviceEngine — чистая логика чипов доступности v2. [чистая логика — тестируема]
//
// Корень флапа чипов (девайс-баг 2026-07-12 «то все зелёные, то серые/красные, на разных нодах
// по-разному»): ОДИН сырой сэмпл писался прямо в UI — без кворума и без гистерезиса. Пограничная
// скорость/транзиент туннеля = дёргающийся чип. Дизайн v2 (ресёрч 2026-07-12: OONI ts-020/ts-019,
// sing-box urltest tolerance, health-checks балансировщиков AWS/GCP «3 подряд до down, recovery
// сразу»):
//   1) КВОРУМ: у сервиса 2 независимых reachability-голоса разных контуров (web/API-tier +
//      CDN/DC-tier). «Заблокировано» — ТОЛЬКО когда упали ОБА. Любой валидный HTTP-статус
//      (даже 400/405/429) = сервис ОТВЕЧАЕТ.
//   2) КАЧЕСТВО только уточняет: при доказанной reachability goodput/TTFB могут дать works|slow,
//      но НИКОГДА blocked/unknown (провал замера — не вердикт цензуры).
//   3) ГИСТЕРЕЗИС: ухудшение статуса — после confirmN согласных прогонов ПОДРЯД (между ними
//      движок шлёт быструю пере-пробу, wantConfirm); восстановление — с первого успешного.
//      unknown не понижает известное и не сбивает начатое подтверждение.
// Раннер (ServiceProbe/AvpnEngineQml) поставляет сырые сигналы; здесь — только решения.
// Тесты: tests/build_chip_logic.sh (chip_logic_check.cpp).
#pragma once

#include <QtGlobal>

namespace avpn {

// ── Классификация одного reachability-голоса ────────────────────────────────────────────────────
// Alive: сервис ОТВЕТИЛ (любой HTTP-статус — 204/400/429 равнозначны «жив»; или TLS/байты дошли).
// HardFail: соединительная смерть без единого признака ответа (RST/refused/TLS-fail) — сигнал DPI.
// SoftFail: наш таймаут-abort или «тишина без ошибки» — сеть/потери, НЕ вердикт цензуры.
enum class VoiceOutcome { Alive, HardFail, SoftFail };

inline VoiceOutcome classifyReachVoice(bool netError, bool timedOut, int httpStatus, bool anyBytesOrTls)
{
    if (httpStatus > 0 || anyBytesOrTls)
        return VoiceOutcome::Alive;
    if (netError && !timedOut)
        return VoiceOutcome::HardFail;
    return VoiceOutcome::SoftFail;
}

// ── Кворум двух голосов (OONI-принцип: blocked только когда упали ВСЕ) ──────────────────────────
struct ReachQuorum {
    bool reachable = false;
    int  rttMs = -1;      // минимум по живым голосам; -1 = ни один живой rtt не принёс
    bool anyHard = false; // хотя бы один жёсткий фейл (RST/DPI) — сильнее таймаутов
};

inline ReachQuorum reachQuorum2(VoiceOutcome a, int rttA, VoiceOutcome b, int rttB)
{
    ReachQuorum q;
    if (a == VoiceOutcome::Alive) {
        q.reachable = true;
        q.rttMs = rttA;
    }
    if (b == VoiceOutcome::Alive) {
        q.reachable = true;
        if (rttB >= 0)
            q.rttMs = (q.rttMs >= 0) ? qMin(q.rttMs, rttB) : rttB;
    }
    q.anyHard = (a == VoiceOutcome::HardFail || b == VoiceOutcome::HardFail);
    return q;
}

// ── Потолок вердикта по кворуму ─────────────────────────────────────────────────────────────────
// Оба голоса упали => 0 (blocked; тихий дроп-таймаут ОБОИХ — тоже блок: null-route без RST —
// обычный способ блокировки). Живы, но один контур ЖЁСТКО срезан (RST при живом втором — напр.
// видео-CDN мёртв при живом вебе) => максимум 1 (slow: сервис деградирован, но отвечает).
// Мягкий фейл одного голоса при живом втором не наказываем => 2.
// Финальный вердикт сервиса = qMin(reachCap(q), refineReachable(quality)).
inline int reachCap(const ReachQuorum &q)
{
    if (!q.reachable)
        return 0;
    return q.anyHard ? 1 : 2;
}

// ── Уточнение качеством при доказанной reachability ─────────────────────────────────────────────
// qualityState: ServiceState-int замера (goodput/TTFB) либо -1 «не измерилось».
// Возвращает ТОЛЬКО 1 (slow) или 2 (works): reachability уже доказана, красный/серый запрещены.
// quality==0 (данные едва идут при живых голосах) => честный slow, не красный.
inline int refineReachable(int qualityState)
{
    if (qualityState == 1 || qualityState == 0)
        return 1;
    return 2;
}

// ── Гистерезис показа ───────────────────────────────────────────────────────────────────────────
// shown — что видит UI (-1 неизв / 0 заблок / 1 медленно / 2 работает).
// pending/count — кандидат-ухудшение и сколько согласных прогонов подряд он набрал.
struct ChipHyst {
    int shown = -1;
    int pending = -100; // -100 = кандидата нет (валидные значения -1..2)
    int count = 0;
};

struct ChipHystStep {
    ChipHyst next;
    bool changed = false;     // shown изменился — UI надо обновить
    bool wantConfirm = false; // начато подтверждение ухудшения — движку стоит пере-пробить быстро
};

inline ChipHystStep chipHystStep(ChipHyst cur, int raw, int confirmN)
{
    ChipHystStep out;
    out.next = cur;
    if (confirmN < 1)
        confirmN = 1; // мусор с бэка (0/минус) не должен вешать подтверждение навсегда

    if (raw < -1 || raw > 2)
        return out; // мусорный сэмпл — игнор

    if (raw == -1) {
        // «Не измерилось» никогда не понижает известное и не трогает начатое подтверждение.
        if (cur.shown == -1)
            return out;
        return out;
    }

    // AVPN BUG-13 (2026-07-30): красный «с чистого листа» подтверждаем, как любое ухудшение.
    // Первая проба стартует через секунду после коннекта, когда маршруты и DNS свежего туннеля
    // ещё оседают: одиночный провал — не доказательство блокировки, а чип уже утверждал
    // «не работает». Зелёный и жёлтый по-прежнему принимаются с первого раза (быстрая
    // первая отрисовка), при confirmN=1 поведение прежнее для всех вердиктов.
    const bool coldBlocked = (cur.shown == -1 && raw == 0);

    if (!coldBlocked && (cur.shown == -1 || raw >= cur.shown)) {
        // Первый вердикт или улучшение/подтверждение текущего — принимаем сразу (recovery fast).
        out.next.shown = raw;
        out.next.pending = -100;
        out.next.count = 0;
        out.changed = (raw != cur.shown);
        return out;
    }

    // Ухудшение: копим согласные прогоны подряд; смена кандидата перезапускает счёт.
    if (cur.pending == raw)
        out.next.count = cur.count + 1;
    else {
        out.next.pending = raw;
        out.next.count = 1;
    }
    if (out.next.count >= confirmN) {
        out.next.shown = raw;
        out.next.pending = -100;
        out.next.count = 0;
        out.changed = true;
    } else {
        out.wantConfirm = true;
    }
    return out;
}

} // namespace avpn
