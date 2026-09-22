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
        if (m_hasPrev && badCycle(m_prev, cur, nowEpoch, th.maxAgeSec))
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
};

} // namespace avpn
