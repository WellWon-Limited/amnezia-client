// AVPN serviceEngine — health-loop поверх «медленных» таймеров WG (CLIENT §5). [чистая логика — тестируема]
// Драйвер (QTimer каждые 3–5с) и реактивный сигнал connectionStateChanged — тонкая обвязка в ServiceEngine.
//
// DEAD-правило (анти-ложно-срабатывание на простое): «плохой» цикл = tx РАСТЁТ, rx СТОИТ и handshake
// устарел (>maxAge) ИЛИ неизвестен. DEAD = N «плохих» циклов подряд. На простое tx не растёт → не DEAD.
// PersistentKeepalive=25 держит handshake свежим на живом туннеле.
#pragma once

#include "ConnectTunables.h"
#include "ITunnelControl.h"
#include "TuningStore.h"

namespace avpn {

// Пороги DEAD-детекта. Серверный оверрайд (numbers.*, план backend-first 2026-07-10); пусто → те же
// вкомпиленные дефолты, что были раньше (180с / 2 цикла).
struct HealthThresholds {
    int maxAgeSec = 180;
    int cyclesToDead = 2;

    static HealthThresholds fromTuning()
    {
        HealthThresholds t;
        // AVPN backend-first (final review R-2): пол на серверные оверрайды — 0/минус сломали бы
        // DEAD-детект (мгновенный false-positive failover).
        t.maxAgeSec = qMax(10,
            (int) TuningStore::numberOr(QStringLiteral("health_dead_max_age_s"), t.maxAgeSec));
        t.cyclesToDead = qMax(1,
            (int) TuningStore::numberOr(QStringLiteral("health_dead_cycles"), t.cyclesToDead));
        return t;
    }
};

class HealthLoop {
public:
    // Один «плохой» цикл по двум замерам (чистая функция).
    static bool badCycle(const TunnelStats &prev, const TunnelStats &cur, qint64 nowEpoch, int maxAgeSec = 180)
    {
        if (!cur.valid || !prev.valid)
            return false;
        const bool txGrew = cur.txBytes > prev.txBytes;
        const bool rxStuck = cur.rxBytes == prev.rxBytes;
        const bool hsStale = (cur.latestHandshakeEpoch <= 0)
                                 ? true // handshake неизвестен → опираемся на rx/tx
                                 : (nowEpoch - cur.latestHandshakeEpoch) > maxAgeSec;
        return txGrew && rxStuck && hsStale;
    }

    // Скормить очередной замер. true ⇒ нода признана DEAD (≥ cyclesToDead «плохих» циклов подряд).
    bool feed(const TunnelStats &cur, qint64 nowEpoch)
    {
        if (!cur.valid)
            return m_dead; // нет данных — состояние не меняем
        // AVPN (фикс-волна 2026-09-22, B8): окно grace после смены сети — выборку держим свежей
        // (prev обновляется), но «плохие» циклы не копим и DEAD не выносим: NE сам лечит путь.
        if (inNetworkGrace(nowEpoch)) {
            m_prev = cur;
            m_hasPrev = true;
            m_bad = 0;
            m_dead = false;
            return false;
        }
        // Снапшот порогов ОДИН раз на вызов (= один тик ServiceEngine::tick() для этой ноды),
        // не дёргать TuningStore на каждое внутреннее сравнение.
        const HealthThresholds th = HealthThresholds::fromTuning();
        TunnelStats judged = cur; // K1 (air-D): a handshake is never older than what was observed on this network
        judged.latestHandshakeEpoch = handshakeForVerdict(cur.latestHandshakeEpoch);
        if (m_hasPrev && badCycle(m_prev, judged, nowEpoch, th.maxAgeSec))
            ++m_bad;
        else
            m_bad = 0;
        m_prev = cur;
        m_hasPrev = true;
        m_dead = m_bad >= th.cyclesToDead;
        return m_dead;
    }

    void reset() { resetSampling(); }

    // AVPN (фикс-волна 2026-09-22, K5/B8, роуминг): смена сети (путь/интерфейс/reachability) —
    // сброс выборки (дельты старого пути против нового ложны) и запрет DEAD-вердикта на graceSec.
    // graceSec <0 → серверный health_network_grace_s (ConnectTunables, клампован, деф. 20 с).
    // reset() окно НЕ снимает: свитч/ре-синк внутри окна не должен возвращать ложный DEAD.
    // Ревью CL-B (REV-5): окно серии частых смен не длиннее 2×grace от первой смены серии; после —
    // grace секунд «остывания», в которые смены НЕ открывают окно и НЕ сбрасывают выборку (иначе
    // смена каждые <grace с глушила DEAD навсегда). Возвращает true, если окно открыто/продлено.
    bool noteNetworkChange(qint64 nowEpoch, int graceSec = -1)
    {
        const int g = graceSec >= 0 ? graceSec : healthNetworkGraceSTuned();
        if (g <= 0) {
            resetSampling(); // окно выключено: только свежая выборка, как reset()
            return false;
        }
        const qint64 cap = m_graceSeriesStart + 2 * qint64(g);
        if (m_hasGraceSeries && nowEpoch >= m_graceSeriesStart && nowEpoch < cap + qint64(g)) {
            if (nowEpoch >= cap)
                return false; // остывание флаппинга: DEAD-детект идёт по накопленной выборке
            resetSampling();
            m_graceUntilEpoch = qMin(cap, qMax(m_graceUntilEpoch, nowEpoch + qint64(g)));
            return true;
        }
        resetSampling(); // новая серия
        m_hasGraceSeries = true;
        m_graceSeriesStart = nowEpoch;
        m_graceUntilEpoch = nowEpoch + qint64(g);
        return true;
    }
    bool inNetworkGrace(qint64 nowEpoch) const { return nowEpoch < m_graceUntilEpoch; }
    qint64 networkGraceUntil() const { return m_graceUntilEpoch; }

    int  badCycles() const { return m_bad; }
    bool isDead() const { return m_dead; }

    // The live probe's part of the AmneziaWG DEAD rule (device round 19.11; fourth review of 141, H1/H2). The
    // in-tunnel probe failing `cycles` times in a row ends the session only when the tunnel's own evidence agrees:
    // its handshake is older than `maxHandshakeAgeSec` (a healthy session rekeys every 120 s, so about 135 s means
    // rekeys are failing), and no network change opened the grace window (the extension is healing the path).
    // An unknown handshake time cannot corroborate anything: no verdict. rx/tx are NOT used here - every handshake
    // the server starts adds bytes to rx, which is what kept a dead session "alive" for the byte-based rule.
    // Device round 24.11 (case B1, LTE -> Wi-Fi): handshakes kept completing while no data came back for 8 minutes, so
    // the handshake never aged and the rule waited. The extension (awg-apple tribe.17) reports its stall verdict
    // (`dataStallSec`: while its ladder sees a stall right now - nothing in for 4 s while the user sends - how long the
    // path has gone without data that proved it; 0 while data comes in, also right after a repair, and while nobody
    // sends: an idle phone whose probes fail locally is never corroborated). `minDataStallSec` or more of that
    // corroborates the failing probe as well. -1 / 0 = unknown / off: the handshake age alone, as before (every
    // platform but iOS, an extension before tribe.17, a stale reading - freshDataStall).
    static bool probeDeadCorroborated(int failStreak, int cycles, bool inGrace, qint64 latestHandshakeEpoch,
                                      qint64 nowEpoch, int maxHandshakeAgeSec, qint64 dataStallSec = -1,
                                      int minDataStallSec = 0)
    {
        if (cycles <= 0 || failStreak < cycles || inGrace)
            return false;
        if (minDataStallSec > 0 && dataStallSec >= minDataStallSec)
            return true;
        if (latestHandshakeEpoch <= 0)
            return false;
        return nowEpoch - latestHandshakeEpoch > maxHandshakeAgeSec;
    }
    // tribe.17 (review Q6): the extension's stall verdict counts only while fresh - applied at most kDataStallMaxAgeMs
    // ago by the wall clock (the status poll answers every second while the app runs; a reading from before a
    // suspension or a sleep is stale). -1 = no fresh reading.
    static constexpr qint64 kDataStallMaxAgeMs = 5000;
    static qint64 freshDataStall(qint64 dataStallSec, qint64 dataStallAtMs, qint64 nowMs)
    {
        if (dataStallSec < 0 || dataStallAtMs <= 0)
            return -1;
        const qint64 age = nowMs - dataStallAtMs;
        return (age >= 0 && age <= kDataStallMaxAgeMs) ? dataStallSec : -1;
    }
    // tribe.18 (second review, G1): a probe whose wall-clock duration exceeds what its own timeouts allow (every endpoint
    // timing out, plus kProbeSuspensionSlackMs) has spanned a suspension of the app: its failure says nothing about the
    // tunnel. A clock that went backwards is treated the same.
    static constexpr qint64 kProbeSuspensionSlackMs = 2000;
    static bool probeSpannedSuspension(qint64 startedMs, qint64 nowMs, qint64 timeoutBudgetMs)
    {
        if (startedMs <= 0)
            return false;
        return nowMs < startedMs || nowMs - startedMs > timeoutBudgetMs + kProbeSuspensionSlackMs;
    }
    // Device round air-D (K1): the "how long without a handshake / without data" inputs of a verdict count only what was
    // observed on the CURRENT network. A network change restarts them (evidenceSinceEpoch) - but never later than
    // kEvidenceDeferralMaxSec after the first change of a series of changes less than that apart, so a flapping network
    // cannot mute the verdict forever. 0 = never noted: every platform that does not opt in (the rule of 141).
    static constexpr qint64 kEvidenceDeferralMaxSec = 120;
    void noteEvidenceRestart(qint64 nowEpoch)
    {
        if (m_lastEvidenceChange <= 0 || nowEpoch - m_lastEvidenceChange >= kEvidenceDeferralMaxSec)
            m_evidenceSeriesStart = nowEpoch;
        m_lastEvidenceChange = nowEpoch;
        m_evidenceSinceEpoch = qMin(nowEpoch, m_evidenceSeriesStart + kEvidenceDeferralMaxSec);
    }
    qint64 evidenceSinceEpoch() const { return m_evidenceSinceEpoch; }
    // A known handshake as the verdicts read it: not older than the start of the evidence (0 = unknown stays 0).
    qint64 handshakeForVerdict(qint64 hs) const { return (hs > 0 && m_evidenceSinceEpoch > hs) ? m_evidenceSinceEpoch : hs; }
    // The newest handshake time the loop has seen (0 = none since the last reset), as the verdicts read it.
    qint64 latestHandshakeEpoch() const { return m_hasPrev ? handshakeForVerdict(m_prev.latestHandshakeEpoch) : 0; }

private:
    void resetSampling()
    {
        m_prev = TunnelStats{};
        m_hasPrev = false;
        m_bad = 0;
        m_dead = false;
    }

    TunnelStats m_prev;
    bool m_hasPrev = false;
    int  m_bad = 0;
    bool m_dead = false;
    qint64 m_graceUntilEpoch = 0;  // B8: до этого момента (epoch сек) DEAD не выносим
    qint64 m_graceSeriesStart = 0; // REV-5: первая смена текущей серии
    bool m_hasGraceSeries = false;
    qint64 m_evidenceSinceEpoch = 0;  // K1 (air-D): what the verdicts count from (0 = not opted in)
    qint64 m_evidenceSeriesStart = 0;
    qint64 m_lastEvidenceChange = 0;
};

} // namespace avpn
