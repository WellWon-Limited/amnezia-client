// AVPN serviceEngine — health-loop поверх «медленных» таймеров WG (CLIENT §5). [чистая логика — тестируема]
// Драйвер (QTimer каждые 3–5с) и реактивный сигнал connectionStateChanged — тонкая обвязка в ServiceEngine.
//
// DEAD-правило (анти-ложно-срабатывание на простое): «плохой» цикл = tx РАСТЁТ, rx СТОИТ и handshake
// устарел (>maxAge) ИЛИ неизвестен. DEAD = N «плохих» циклов подряд. На простое tx не растёт → не DEAD.
// PersistentKeepalive=25 держит handshake свежим на живом туннеле.
#pragma once

#include "ITunnelControl.h"

namespace avpn {

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
        if (m_hasPrev && badCycle(m_prev, cur, nowEpoch, m_maxAgeSec))
            ++m_bad;
        else
            m_bad = 0;
        m_prev = cur;
        m_hasPrev = true;
        m_dead = m_bad >= m_cyclesToDead;
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
    int  m_maxAgeSec = 180;
    int  m_cyclesToDead = 2;
};

} // namespace avpn
