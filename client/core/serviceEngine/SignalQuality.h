// AVPN serviceEngine — «реальные палочки» сигнала из app-layer RTT через туннель. [чистая логика — тестируема]
//
// Почему так: AWG = UDP-only ⇒ ICMP/TCP-пинг до эндпоинта бессмыслен. Реальный RTT меряет QualityProbe
// (HTTPS-проба generate_204 ЧЕРЕЗ туннель), а этот класс превращает поток RTT-сэмплов в стабильный
// уровень 0..5 баров для UI. Источники порогов/сглаживания (research, см. memory tribe-real-signal-quality):
//   • RTT→бары: ITU-T G.114 (one-way 150/400мс, RTT≈2×) + Cisco VoIP + игровой консенсус.
//   • EWMA α=1/8 — как TCP SRTT (RFC 6298 §2.3): одиночный спайк не роняет бар.
//   • Асимметричный гистерезис (dead-band ±kHystFrac у границ корзины) — как AOSP Wi-Fi RSSI-leveling:
//     апать бар только когда явно лучше, ронять только когда явно хуже ⇒ нет дребезга 3↔4.
//   • Недостижимость = hard-gate: 0 баров немедленно (мимо сглаживания), кэш RTT не маскирует обрыв.
// Минимальное удержание уровня (≤ раз в 3с) обеспечивает каденс вызова из QML-таймера, не этот класс.
#pragma once

namespace avpn {

class SignalQuality {
public:
    static constexpr int kMaxBars = 5;

    // Чистая таблица RTT(мс)→бары. rttMs<0 (недостижимо) → 0.
    // AVPN: шкала откалибрована под VPN-туннель (RTT включает путь до удалённой ноды), а не под
    // локальную сеть — иначе реальные 100–250мс почти всегда давали 1–2 бара и 4–5 были недостижимы.
    // 5:<100  4:<160  3:<250  2:<400  1:<800  0:>=800/недостижимо. (147мс ⇒ 4 бара.)
    static int barsForRtt(int rttMs)
    {
        if (rttMs < 0) return 0;
        if (rttMs < 100) return 5;
        if (rttMs < 160) return 4;
        if (rttMs < 250) return 3;
        if (rttMs < 400) return 2;
        if (rttMs < 800) return 1;
        return 0;
    }

    // Скормить очередной RTT-сэмпл (мс; reachable=false или rttMs<0 ⇒ нет ответа). Возвращает
    // отображаемый уровень 0..5 (сглаженный + с гистерезисом). Недостижимость → немедленно 0.
    int feed(int rttMs, bool reachable)
    {
        if (!reachable || rttMs < 0) {     // hard-gate: обрыв пути → 0 сразу, RTT-стейт сбрасываем
            m_bars = 0;
            m_hasSrtt = false;
            m_init = false;                // НОВАЯ серия: первый достижимый сэмпл сидируется БЕЗ
                                           // гистерезиса, иначе медленный (704–800мс) reconnect залипал
                                           // бы в «липкой» полосе bar0 и не показывал 1 бар.
            return m_bars;
        }
        if (!m_hasSrtt) {                  // первый сэмпл серии сидирует SRTT
            m_srtt = rttMs;
            m_hasSrtt = true;
        } else {
            m_srtt = (1.0 - kAlpha) * m_srtt + kAlpha * rttMs; // EWMA α=1/8 (RFC 6298 SRTT)
        }
        const int raw = barsForRtt(static_cast<int>(m_srtt + 0.5));
        if (!m_init) {                     // самый первый показ — без гистерезиса (UI сразу правдив)
            m_bars = raw;
            m_init = true;
        } else if (raw != m_bars && !sticky(m_srtt, m_bars)) {
            m_bars = raw;                  // вышли за расширенную полосу текущего бара → меняем уровень
        }
        return m_bars;
    }

    void reset()
    {
        m_srtt = 0.0;
        m_hasSrtt = false;
        m_init = false;
        m_bars = 0;
    }

    int  bars() const { return m_bars; }
    // Сглаженный RTT (мс) или -1, если серия ещё не начиналась / путь оборван.
    int  smoothedRtt() const { return m_hasSrtt ? static_cast<int>(m_srtt + 0.5) : -1; }

private:
    static constexpr double kAlpha = 1.0 / 8.0; // RFC 6298 SRTT
    static constexpr double kHystFrac = 0.12;   // ±12% dead-band у границ корзины

    static double bandLo(int bar)
    {
        switch (bar) { case 5: return 0; case 4: return 100; case 3: return 160;
                       case 2: return 250; case 1: return 400; default: return 800; }
    }
    static double bandHi(int bar)
    {
        switch (bar) { case 5: return 100; case 4: return 160; case 3: return 250;
                       case 2: return 400; case 1: return 800; default: return 1e12; }
    }
    // «Залипание»: SRTT всё ещё внутри расширенной (±kHystFrac) полосы текущего бара ⇒ не меняем уровень.
    bool sticky(double srtt, int bar) const
    {
        return srtt >= bandLo(bar) * (1.0 - kHystFrac) && srtt < bandHi(bar) * (1.0 + kHystFrac);
    }

    double m_srtt = 0.0;
    bool   m_hasSrtt = false;
    bool   m_init = false;
    int    m_bars = 0;
};

} // namespace avpn
