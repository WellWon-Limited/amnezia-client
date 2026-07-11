// AVPN serviceEngine — health-loop поверх «медленных» таймеров WG (CLIENT §5). [чистая логика — тестируема]
// Драйвер (QTimer каждые 3–5с) и реактивный сигнал connectionStateChanged — тонкая обвязка в ServiceEngine.
//
// DEAD-правило (анти-ложно-срабатывание на простое): «плохой» цикл = tx РАСТЁТ, rx СТОИТ и handshake
// устарел (>maxAge) ИЛИ неизвестен. DEAD = N «плохих» циклов подряд. На простое tx не растёт → не DEAD.
// PersistentKeepalive=25 держит handshake свежим на живом туннеле.
#pragma once

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

    void reset()
    {
        m_prev = TunnelStats{};
        m_hasPrev = false;
        m_bad = 0;
        m_dead = false;
    }

    int  badCycles() const { return m_bad; }
    bool isDead() const { return m_dead; }

private:
    TunnelStats m_prev;
    bool m_hasPrev = false;
    int  m_bad = 0;
    bool m_dead = false;
};

} // namespace avpn
