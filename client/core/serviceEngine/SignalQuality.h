// AVPN serviceEngine — «реальные палочки» сигнала из app-layer RTT через туннель. [чистая логика — тестируема]
//
// Почему так: AWG = UDP-only ⇒ TCP-пинг до AWG-порта не достукивается. RTT ТЕКУЩЕЙ ноды (через туннель)
// меряет QualityProbe (HTTPS generate_204), а этот класс превращает поток RTT-сэмплов в стабильный
// уровень 0..5 баров для UI. (Прямой per-node RTT остальных нод off-tunnel меряет RttProbeIcmp — ICMP,
// тот же barsForRtt; см. NodeRanking.h.) Источники порогов/сглаживания (research, memory tribe-real-signal-quality):
//   • RTT→бары: ITU-T G.114 (one-way 150/400мс, RTT≈2×) + Cisco VoIP + игровой консенсус,
//     сдвинуто щедрее под реальный туннельный путь (147мс ⇒ 5 баров, а не 4).
//   • EWMA α=1/4 — сглаживание SRTT (как RFC 6298, но быстрее сходится вниз): спайк не роняет бар,
//     но улучшение видно за 2–3 сэмпла, а не за 5 ⇒ меньше «залипания» на низком уровне.
//   • Асимметричный гистерезис (dead-band ±kHystFrac у границ корзины) — как AOSP Wi-Fi RSSI-leveling:
//     апать бар только когда явно лучше, ронять только когда явно хуже ⇒ нет дребезга 3↔4.
//   • Недостижимость = hard-gate: 0 баров немедленно (мимо сглаживания), кэш RTT не маскирует обрыв.
// Минимальное удержание уровня (≤ раз в 3с) обеспечивает каденс вызова из QML-таймера, не этот класс.
#pragma once

#include "TuningStore.h"

namespace avpn {

// Пороги RTT(мс)→бары (щедрая VPN-шкала — см. обоснование ниже). Серверный оверрайд (numbers.*,
// план backend-first 2026-07-10); пусто → те же вкомпиленные дефолты, что были раньше.
struct RttBands {
    double b5 = 150, b4 = 230, b3 = 330, b2 = 500, b1 = 800;
    static RttBands fromTuning()
    {
        RttBands b;
        b.b5 = TuningStore::numberOr(QStringLiteral("rtt_bar5_ms"), b.b5);
        b.b4 = TuningStore::numberOr(QStringLiteral("rtt_bar4_ms"), b.b4);
        b.b3 = TuningStore::numberOr(QStringLiteral("rtt_bar3_ms"), b.b3);
        b.b2 = TuningStore::numberOr(QStringLiteral("rtt_bar2_ms"), b.b2);
        b.b1 = TuningStore::numberOr(QStringLiteral("rtt_bar1_ms"), b.b1);
        return b;
    }
};

class SignalQuality {
public:
    static constexpr int kMaxBars = 5;

    // Чистая таблица RTT(мс)→бары. rttMs<0 (недостижимо) → 0.
    // AVPN: ЩЕДРАЯ шкала под VPN-туннель (RTT включает путь до удалённой ноды + TLS-handshake), а не
    // под локальную сеть — типичные 120–200мс через туннель это «хорошо» и должны давать 4–5 баров,
    // иначе индикатор почти всегда залипал на 1–2. 5:<150 4:<230 3:<330 2:<500 1:<800 0:>=800. (147мс ⇒ 5.)
    static int barsForRtt(int rttMs)
    {
        if (rttMs < 0) return 0;
        const RttBands b = RttBands::fromTuning();
        if (rttMs < b.b5) return 5;
        if (rttMs < b.b4) return 4;
        if (rttMs < b.b3) return 3;
        if (rttMs < b.b2) return 2;
        if (rttMs < b.b1) return 1;
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
            m_srtt = (1.0 - kAlpha) * m_srtt + kAlpha * rttMs; // EWMA α=1/4 (быстрее сходится вниз, меньше залипания)
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
    static constexpr double kAlpha = 1.0 / 4.0; // быстрее реагирует на улучшение (было 1/8) — меньше «залипания»
    static constexpr double kHystFrac = 0.08;   // ±8% dead-band у границ корзины (было 12% — реже тормозит апгрейд бара)

    static double bandLo(int bar, const RttBands &b)
    {
        switch (bar) { case 5: return 0; case 4: return b.b5; case 3: return b.b4;
                       case 2: return b.b3; case 1: return b.b2; default: return b.b1; }
    }
    static double bandHi(int bar, const RttBands &b)
    {
        switch (bar) { case 5: return b.b5; case 4: return b.b4; case 3: return b.b3;
                       case 2: return b.b2; case 1: return b.b1; default: return 1e12; }
    }
    // «Залипание»: SRTT всё ещё внутри расширенной (±kHystFrac) полосы текущего бара ⇒ не меняем уровень.
    // Один RttBands::fromTuning() на вызов (не по разу на bandLo/bandHi).
    bool sticky(double srtt, int bar) const
    {
        const RttBands b = RttBands::fromTuning();
        return srtt >= bandLo(bar, b) * (1.0 - kHystFrac) && srtt < bandHi(bar, b) * (1.0 + kHystFrac);
    }

    double m_srtt = 0.0;
    bool   m_hasSrtt = false;
    bool   m_init = false;
    int    m_bars = 0;
};

} // namespace avpn
