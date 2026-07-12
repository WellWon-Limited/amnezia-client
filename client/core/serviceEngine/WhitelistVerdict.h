#pragma once

// AVPN: чистая вердикт-логика детекта РКН-режима «белых списков» на сотовой сети.
// Спека: tribe-front docs/superpowers/specs/2026-07-12-whitelist-mode-detector-design.md (§2 матрица).
//
// Сигнатура: на Cellular ВСЕ control-домены (наша инфра + независимые сторонние якоря)
// мертвы, а >=2 whitelist-доменов живы (полный TLS-handshake), причём хотя бы один — из
// маркетплейс-tier (ozon/wb: есть в РКН-whitelist, НЕТ в законном списке соц-значимых при
// нулевом балансе тарифа — это отличает РКН-режим от исчерпанного пакета оператора).
// При обычном обрыве мертво ВСЁ (NoNetwork); при живой сети жив хоть один control (Normal);
// без опрошенного стороннего якоря вердикта НЕТ (Inconclusive — иначе падение нашего
// бэкенда даёт ложный whitelist); живы только соц-значимые — SocialOnly (похоже на нулевой
// баланс, UI молчит). Ложное срабатывание хуже пропуска: гистерезис входа >=2
// последовательных Candidate-раундов, маргинальная сеть (все фейлы = таймауты + высокий
// RTT живых whitelist) требует +1 раунд.
//
// Только чистые inline-функции/структуры (QtCore) — юнит: tests/build_whitelist_verdict.sh.
// Backend-first: пороги server-tunable через TuningStore, клампы на точке сева ОБЯЗАТЕЛЬНЫ.

#include "TuningStore.h"

#include <QList>
#include <QString>

#include <algorithm>

namespace avpn {

enum class WlFail { None, Dns, Tcp, Tls, Timeout };

struct WlSample {
    bool   ok = false;
    WlFail fail = WlFail::None;
    int    rttMs = -1;
    bool   isControl = false; // control-набор (наша инфра ИЛИ сторонний якорь)
    bool   isAnchor = false;  // сторонний якорь, независимый от нашей инфры
    bool   isSocial = false;  // whitelist social-tier: соц-значимые, живые И при нулевом
                              // балансе (госуслуги/ya/vk) — сами режим не объявляют
};

enum class WlVerdict {
    NotApplicable, // не сотовая сеть — детект не применим
    Normal,        // жив хоть один control — сеть в порядке
    NoNetwork,     // мертво всё, включая whitelist — обычный обрыв, НЕ белые списки
    Inconclusive,  // ни один сторонний якорь не опрошен — вердикта нет
    SocialOnly,    // живы ТОЛЬКО соц-значимые = похоже на нулевой баланс тарифа, НЕ РКН
                   // (маркетплейсов нет в законном списке соц-значимых) — UI молчит
    Candidate      // сигнатура белых списков в ЭТОМ раунде (ещё не режим — см. WlHysteresis)
};

// Раунд -> вердикт. cellular — снапшот транспорта на СТАРТЕ раунда (смена сети посреди
// раунда обязана отбрасывать раунд ещё в детекторе — сюда такой раунд не попадает).
inline WlVerdict decideWhitelistRound(const QList<WlSample> &samples, bool cellular)
{
    if (!cellular)
        return WlVerdict::NotApplicable;
    int aliveControl = 0, aliveWhitelist = 0, aliveMarketplace = 0, probedAnchors = 0;
    for (const auto &s : samples) {
        if (s.isControl) {
            if (s.isAnchor)
                ++probedAnchors;
            if (s.ok)
                ++aliveControl;
        } else if (s.ok) {
            ++aliveWhitelist;
            if (!s.isSocial)
                ++aliveMarketplace;
        }
    }
    if (aliveControl >= 1)
        return WlVerdict::Normal;
    if (aliveWhitelist < 2)      // один живой мог быть флюком/кешем — не сигнатура
        return WlVerdict::NoNetwork;
    if (probedAnchors < 1)
        return WlVerdict::Inconclusive;
    if (aliveMarketplace < 1)    // живы только соц-значимые — почерк нулевого баланса
        return WlVerdict::SocialOnly;
    return WlVerdict::Candidate;
}

// Guard слабой сети (сценарий 3 матрицы): все фейлы control = таймауты (почерк плохого
// покрытия — ру-CDN ближе и успевает, дальние якоря нет) И медиана RTT живых whitelist
// высокая -> сеть «на издыхании», Candidate требует +1 подтверждающий раунд.
// Быстрый отлуп (DNS/TCP/TLS-fail) хоть на одном control = почерк фильтра -> НЕ marginal.
inline bool whitelistMarginalNetwork(const QList<WlSample> &samples)
{
    bool anyControlFail = false;
    QList<int> wlRtts;
    for (const auto &s : samples) {
        if (s.isControl && !s.ok) {
            anyControlFail = true;
            if (s.fail != WlFail::Timeout)
                return false;
        } else if (!s.isControl && s.ok && s.rttMs >= 0) {
            wlRtts.append(s.rttMs);
        }
    }
    if (!anyControlFail || wlRtts.isEmpty())
        return false;
    std::sort(wlRtts.begin(), wlRtts.end());
    const int median = wlRtts[wlRtts.size() / 2];
    // Кламп 300..10000: 0/минус с бэка не должен превращать любую сеть в «маргинальную».
    const int thr = qBound(300,
                           int(TuningStore::numberOr(QStringLiteral("whitelist_marginal_rtt_ms"), 1500)),
                           10000);
    return median > thr;
}

// Гистерезис входа/выхода. Вход: N последовательных Candidate (server-tunable
// whitelist_confirm_rounds, кламп-пол 2 — ОДИН раунд никогда не объявляет режим),
// маргинальная сеть -> +1. Выход: Normal (жив control) или NotApplicable (ушли с сотовой).
// NoNetwork/SocialOnly рвут стрик набора, но АКТИВНЫЙ режим НЕ снимают (полная потеря сети
// или сужение до соц-значимых во время отключения — совет «перейдите на Wi-Fi» остаётся
// честным). Inconclusive — раунд впустую.
struct WlHysteresis {
    int  streak = 0;
    bool active = false;

    bool feed(WlVerdict v, bool marginal)
    {
        switch (v) {
        case WlVerdict::NotApplicable:
        case WlVerdict::Normal:
            streak = 0;
            active = false;
            break;
        case WlVerdict::NoNetwork:
        case WlVerdict::SocialOnly: // нулевой баланс: стрик рвём, активный режим держим
            streak = 0;
            break;
        case WlVerdict::Inconclusive:
            break;
        case WlVerdict::Candidate: {
            ++streak;
            int need = qBound(2, int(TuningStore::numberOr(
                                  QStringLiteral("whitelist_confirm_rounds"), 2)), 5);
            if (marginal)
                ++need;
            if (streak >= need)
                active = true;
            break;
        }
        }
        return active;
    }
};

} // namespace avpn
