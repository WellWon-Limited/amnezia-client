// AVPN: проверка чистой вердикт-логики детекта «белых списков» (WhitelistVerdict.h).
// Матрица сценариев — спека 2026-07-12-whitelist-mode-detector-design.md §2: детект ОБЯЗАН
// отличать whitelist-режим от «нет сети вообще», «слабая сотовая», «упал наш бэкенд»,
// «наш домен заблокирован точечно», «нулевой баланс тарифа» (живы только соц-значимые).
// Ложное срабатывание хуже пропуска.
#include "../WhitelistVerdict.h"
#include "../TuningStore.h"

#include <QtGlobal>
#include <cstdio>

static int failures = 0;

#define CHECK(cond, msg)                                                                           \
    do {                                                                                           \
        if (cond) {                                                                                \
            std::printf("ok   - %s\n", msg);                                                       \
        } else {                                                                                   \
            std::printf("FAIL - %s\n", msg);                                                       \
            ++failures;                                                                            \
        }                                                                                          \
    } while (0)

using avpn::WlFail;
using avpn::WlSample;
using avpn::WlVerdict;

// Хелперы сборки раунда: c=наша инфра, a=сторонний якорь, w=whitelist маркетплейс-tier
// (ozon/wb — решающий), soc=whitelist social-tier (госуслуги/ya/vk — живы и при нулевом балансе).
static WlSample c(bool ok, WlFail f = WlFail::None, int rtt = 100)
{ WlSample s; s.ok = ok; s.fail = f; s.rttMs = rtt; s.isControl = true; return s; }
static WlSample a(bool ok, WlFail f = WlFail::None, int rtt = 100)
{ WlSample s; s.ok = ok; s.fail = f; s.rttMs = rtt; s.isControl = true; s.isAnchor = true; return s; }
static WlSample w(bool ok, WlFail f = WlFail::None, int rtt = 100)
{ WlSample s; s.ok = ok; s.fail = f; s.rttMs = rtt; return s; }
static WlSample soc(bool ok, WlFail f = WlFail::None, int rtt = 100)
{ WlSample s; s.ok = ok; s.fail = f; s.rttMs = rtt; s.isSocial = true; return s; }

int main()
{
    using avpn::decideWhitelistRound;
    using avpn::whitelistMarginalNetwork;

    avpn::TuningStore::reset();

    // §2.10: не сотовая сеть -> NotApplicable, что бы ни было в пробах.
    CHECK(decideWhitelistRound({c(false), a(false), w(true), w(true)}, false)
              == WlVerdict::NotApplicable, "wifi -> NotApplicable");

    // §2.1: whitelist-режим — вся инфра+якоря мертвы, >=2 whitelist живы (есть маркетплейс).
    CHECK(decideWhitelistRound({c(false, WlFail::Tcp), a(false, WlFail::Tcp),
                                a(false, WlFail::Tcp), w(true), w(true), soc(false)}, true)
              == WlVerdict::Candidate, "все control мертвы + 2 маркетплейса живы -> Candidate");

    // Смешанный ярус: 1 маркетплейс + 1 соцзначимый = 2 живых + решающий есть -> Candidate.
    CHECK(decideWhitelistRound({c(false), a(false), w(true), soc(true)}, true)
              == WlVerdict::Candidate, "ozon + gosuslugi живы -> Candidate");

    // §2.8: нулевой баланс — живы ТОЛЬКО соц-значимые (маркетплейсы мертвы, их нет в законном
    // списке при нулевом балансе) -> SocialOnly, попап показывать НЕЛЬЗЯ.
    CHECK(decideWhitelistRound({c(false), a(false), w(false), w(false),
                                soc(true), soc(true), soc(true)}, true)
              == WlVerdict::SocialOnly, "живы только соцзначимые -> SocialOnly (нулевой баланс)");

    // §2.2: нет сети вообще — мертво ВСЁ -> NoNetwork (попап показывать нельзя).
    CHECK(decideWhitelistRound({c(false, WlFail::Timeout), a(false, WlFail::Timeout),
                                w(false, WlFail::Timeout), w(false, WlFail::Timeout)}, true)
              == WlVerdict::NoNetwork, "мертво всё -> NoNetwork, не whitelist");

    // Один живой whitelist = возможный флюк/кеш -> тоже NoNetwork.
    CHECK(decideWhitelistRound({c(false), a(false), w(true), w(false), soc(false)}, true)
              == WlVerdict::NoNetwork, "1 живой whitelist < 2 -> NoNetwork");
    // Один живой соцзначимый — тем более не сигнатура.
    CHECK(decideWhitelistRound({c(false), a(false), w(false), soc(true)}, true)
              == WlVerdict::NoNetwork, "1 живой соцзначимый -> NoNetwork");

    // §2.4: упал НАШ бэкенд — сторонний якорь жив -> Normal (НЕ whitelist).
    CHECK(decideWhitelistRound({c(false, WlFail::Timeout), a(true), w(true), w(true)}, true)
              == WlVerdict::Normal, "наша инфра мертва, якорь жив -> Normal");

    // §2.5: наш домен заблокирован точечно, всё остальное живо -> Normal.
    CHECK(decideWhitelistRound({c(false, WlFail::Tls), a(true), a(true), w(true), w(true)}, true)
              == WlVerdict::Normal, "SNI-блок нашего домена -> Normal");

    // Любой живой control (даже наш) -> Normal мгновенно.
    CHECK(decideWhitelistRound({c(true), a(false), w(true), w(true)}, true)
              == WlVerdict::Normal, "живой control -> Normal");

    // Защита: ни один сторонний якорь не опрошен -> вердикта нет (Inconclusive),
    // даже при идеальной сигнатуре — иначе падение нашего бэка = ложный whitelist.
    CHECK(decideWhitelistRound({c(false), w(true), w(true)}, true)
              == WlVerdict::Inconclusive, "нет опрошенных якорей -> Inconclusive");

    // Пустой раунд не роняет.
    CHECK(decideWhitelistRound({}, true) == WlVerdict::NoNetwork, "пустой раунд -> NoNetwork");

    // --- Guard слабой сети (§2.3, §3.4 спеки) ---
    // Все фейлы control = таймауты И медиана RTT живых whitelist высокая -> маргинальная сеть.
    CHECK(whitelistMarginalNetwork({c(false, WlFail::Timeout), a(false, WlFail::Timeout),
                                    w(true, WlFail::None, 2500), w(true, WlFail::None, 3000)}),
          "таймауты + высокий RTT -> marginal");
    // Быстрый отлуп (RST/TCP) хоть на одном control = почерк фильтра, НЕ маргинальная.
    CHECK(!whitelistMarginalNetwork({c(false, WlFail::Tcp), a(false, WlFail::Timeout),
                                     w(true, WlFail::None, 2500)}),
          "есть быстрый отлуп -> НЕ marginal (почерк фильтра)");
    // Низкий RTT whitelist = сеть живая и быстрая -> НЕ маргинальная.
    CHECK(!whitelistMarginalNetwork({c(false, WlFail::Timeout), a(false, WlFail::Timeout),
                                     w(true, WlFail::None, 80), w(true, WlFail::None, 120)}),
          "низкий RTT -> НЕ marginal");
    // Server-tunable порог с клампом: 0 с бэка -> пол 300мс, не «всегда marginal».
    avpn::TuningStore::set({{QStringLiteral("whitelist_marginal_rtt_ms"), 0.0}}, {});
    CHECK(!whitelistMarginalNetwork({c(false, WlFail::Timeout),
                                     w(true, WlFail::None, 200), w(true, WlFail::None, 250)}),
          "server 0 -> кламп-пол 300мс");
    avpn::TuningStore::reset();

    // --- Гистерезис (§3.4) ---
    {
        avpn::WlHysteresis h;
        // Один Candidate НИКОГДА не включает режим.
        CHECK(!h.feed(WlVerdict::Candidate, false), "1-й Candidate -> ещё не режим");
        CHECK(h.feed(WlVerdict::Candidate, false), "2-й Candidate -> режим ВКЛ");
        // Выход по первому живому control.
        CHECK(!h.feed(WlVerdict::Normal, false), "Normal -> режим ВЫКЛ");
        CHECK(h.streak == 0, "Normal сбрасывает стрик");
    }
    {
        avpn::WlHysteresis h;
        // NoNetwork рвёт последовательность Candidate (не консекутивные).
        h.feed(WlVerdict::Candidate, false);
        h.feed(WlVerdict::NoNetwork, false);
        CHECK(!h.feed(WlVerdict::Candidate, false), "Candidate,NoNetwork,Candidate -> НЕ режим");
    }
    {
        avpn::WlHysteresis h;
        // SocialOnly для гистерезиса = NoNetwork: рвёт стрик, режим не объявляет...
        h.feed(WlVerdict::Candidate, false);
        h.feed(WlVerdict::SocialOnly, false);
        CHECK(!h.feed(WlVerdict::Candidate, false), "Candidate,SocialOnly,Candidate -> НЕ режим");
        // ...и активный режим НЕ снимает (сужение до соцзначимых во время отключения).
        h.feed(WlVerdict::Candidate, false);
        CHECK(h.active, "режим набрался");
        CHECK(h.feed(WlVerdict::SocialOnly, false), "SocialOnly в активном режиме -> держится");
    }
    {
        avpn::WlHysteresis h;
        // Полная потеря сети в АКТИВНОМ режиме режим НЕ снимает (§3.4: совет Wi-Fi честен).
        h.feed(WlVerdict::Candidate, false);
        h.feed(WlVerdict::Candidate, false);
        CHECK(h.feed(WlVerdict::NoNetwork, false), "NoNetwork в активном режиме -> режим держится");
        // Уход с сотовой (Wi-Fi) снимает режим сразу.
        CHECK(!h.feed(WlVerdict::NotApplicable, false), "NotApplicable -> режим ВЫКЛ");
    }
    {
        avpn::WlHysteresis h;
        // Inconclusive не двигает стрик ни туда ни сюда.
        h.feed(WlVerdict::Candidate, false);
        h.feed(WlVerdict::Inconclusive, false);
        CHECK(h.feed(WlVerdict::Candidate, false), "Candidate,Inconclusive,Candidate -> режим ВКЛ");
    }
    {
        avpn::WlHysteresis h;
        // Маргинальная сеть требует +1 подтверждающий раунд.
        h.feed(WlVerdict::Candidate, true);
        CHECK(!h.feed(WlVerdict::Candidate, true), "marginal: 2 раундов НЕ хватает");
        CHECK(h.feed(WlVerdict::Candidate, true), "marginal: 3-й раунд -> режим ВКЛ");
    }
    {
        avpn::WlHysteresis h;
        // Server-tunable confirm_rounds с клампом: 0/1 с бэка -> пол 2 (один раунд не решает).
        avpn::TuningStore::set({{QStringLiteral("whitelist_confirm_rounds"), 1.0}}, {});
        CHECK(!h.feed(WlVerdict::Candidate, false), "server confirm=1 -> кламп-пол 2");
        CHECK(h.feed(WlVerdict::Candidate, false), "2-й раунд при клампе -> режим ВКЛ");
        avpn::TuningStore::reset();
    }

    if (failures) {
        std::printf(">>> whitelist_verdict_check: %d FAILURE(S)\n", failures);
        return 1;
    }
    std::printf(">>> whitelist_verdict_check: все проверки прошли\n");
    return 0;
}
