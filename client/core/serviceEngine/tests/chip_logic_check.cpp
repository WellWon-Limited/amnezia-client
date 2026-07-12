// AVPN: проверка чистой логики чипов доступности v2 (ChipLogic.h).
// Корень флапа чипов (девайс-баг 2026-07-12 «то все зелёные, то серые/красные»): одиночный сырой
// сэмпл писался прямо в UI — без кворума независимых сигналов и без гистерезиса. Новая логика
// (по образцу OONI/балансировщиков): вердикт «заблокировано» только когда упали ВСЕ голоса,
// ухудшение статуса — только после N согласных прогонов подряд, восстановление — с первого.
#include "../ChipLogic.h"

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

int main()
{
    using namespace avpn;

    // ── classifyReachVoice: любой HTTP-статус = сервис ОТВЕЧАЕТ (даже 4xx/429 — это ответ,
    // не блокировка); RST/refused без байта = жёсткий фейл; таймаут = мягкий (сеть, не блок).
    CHECK(classifyReachVoice(false, false, 204, false) == VoiceOutcome::Alive,
          "204 -> Alive (generate_204 счастливый путь)");
    CHECK(classifyReachVoice(false, false, 400, false) == VoiceOutcome::Alive,
          "400 -> Alive (API ответил — значит достижим)");
    CHECK(classifyReachVoice(true, false, 429, false) == VoiceOutcome::Alive,
          "429 + netError -> Alive (rate-limit = сервис отвечает)");
    CHECK(classifyReachVoice(false, false, 0, true) == VoiceOutcome::Alive,
          "TLS encrypted/байты без статуса -> Alive");
    CHECK(classifyReachVoice(true, false, 0, false) == VoiceOutcome::HardFail,
          "RST/refused без байта и статуса -> HardFail");
    CHECK(classifyReachVoice(true, true, 0, false) == VoiceOutcome::SoftFail,
          "наш таймаут-abort -> SoftFail (сеть, не вердикт цензуры)");
    CHECK(classifyReachVoice(false, false, 0, false) == VoiceOutcome::SoftFail,
          "ничего не пришло без ошибки -> SoftFail (недоказуемо)");

    // ── reachQuorum2: «заблокировано» ТОЛЬКО когда упали ОБА голоса (OONI-принцип).
    {
        const ReachQuorum q = reachQuorum2(VoiceOutcome::Alive, 120, VoiceOutcome::HardFail, -1);
        CHECK(q.reachable && q.rttMs == 120, "Alive+HardFail -> reachable, rtt живого голоса");
    }
    {
        const ReachQuorum q = reachQuorum2(VoiceOutcome::HardFail, -1, VoiceOutcome::Alive, 300);
        CHECK(q.reachable && q.rttMs == 300, "HardFail+Alive -> reachable (порядок не важен)");
    }
    {
        const ReachQuorum q = reachQuorum2(VoiceOutcome::Alive, 250, VoiceOutcome::Alive, 90);
        CHECK(q.reachable && q.rttMs == 90, "Alive+Alive -> rtt = минимум голосов");
    }
    {
        const ReachQuorum q = reachQuorum2(VoiceOutcome::HardFail, -1, VoiceOutcome::HardFail, -1);
        CHECK(!q.reachable && q.anyHard, "оба HardFail -> не достижим, есть жёсткий сигнал (DPI)");
    }
    {
        const ReachQuorum q = reachQuorum2(VoiceOutcome::SoftFail, -1, VoiceOutcome::SoftFail, -1);
        CHECK(!q.reachable && !q.anyHard, "оба SoftFail -> не достижим, но без жёсткого сигнала");
    }
    {
        const ReachQuorum q = reachQuorum2(VoiceOutcome::Alive, -1, VoiceOutcome::SoftFail, -1);
        CHECK(q.reachable && q.rttMs == -1, "Alive без rtt -> reachable, rtt честно неизвестен");
    }

    // ── refineReachable: качество ТОЛЬКО уточняет works/slow, НИКОГДА не даёт красный/серый
    // при доказанной reachability (провал goodput-стадии — не вердикт цензуры).
    CHECK(refineReachable(2) == 2, "quality works -> works");
    CHECK(refineReachable(1) == 1, "quality slow -> slow (троттлинг виден)");
    CHECK(refineReachable(0) == 1,
          "quality blocked при живой reachability -> slow (данные едва идут), НЕ красный");
    CHECK(refineReachable(-1) == 2, "quality не измерилось -> works (reachability уже доказана)");

    // ── chipHystStep: гистерезис. Ухудшение — после confirmN согласных прогонов подряд;
    // восстановление — с первого успешного; unknown не понижает известное и не сбивает pending.
    const int N = 2;
    {
        // Первый вердикт принимается сразу (быстрая первая отрисовка).
        ChipHyst h;
        auto s = chipHystStep(h, 2, N);
        CHECK(s.next.shown == 2 && s.changed && !s.wantConfirm, "первый raw=works -> принят сразу");
    }
    {
        // Ухудшение works->blocked: первый прогон удерживается, второй согласный — принимается.
        ChipHyst h; h.shown = 2;
        auto s1 = chipHystStep(h, 0, N);
        CHECK(s1.next.shown == 2 && !s1.changed && s1.wantConfirm,
              "works, raw=blocked #1 -> удержан, нужна быстрая пере-проба");
        auto s2 = chipHystStep(s1.next, 0, N);
        CHECK(s2.next.shown == 0 && s2.changed, "raw=blocked #2 подряд -> принят (подтверждено)");
    }
    {
        // Отскок: blocked не подтвердился — pending сброшен, статус не дёрнулся.
        ChipHyst h; h.shown = 2;
        auto s1 = chipHystStep(h, 0, N);
        auto s2 = chipHystStep(s1.next, 2, N);
        CHECK(s2.next.shown == 2 && s2.next.count == 0,
              "blocked-блип + works -> pending сброшен, чип не мигнул красным");
    }
    {
        // Восстановление немедленно (как арбитр бэка/балансировщики).
        ChipHyst h; h.shown = 0;
        auto s = chipHystStep(h, 2, N);
        CHECK(s.next.shown == 2 && s.changed, "blocked -> raw=works -> зелёный сразу");
    }
    {
        // Смена кандидата ухудшения перезапускает счёт (slow-блип не приближает красный).
        ChipHyst h; h.shown = 2;
        auto s1 = chipHystStep(h, 1, N);   // pending slow #1
        auto s2 = chipHystStep(s1.next, 0, N); // кандидат сменился на blocked -> счёт заново
        CHECK(s2.next.shown == 2 && !s2.changed && s2.wantConfirm,
              "slow-блип, затем blocked #1 -> всё ещё удержан works");
        auto s3 = chipHystStep(s2.next, 0, N);
        CHECK(s3.next.shown == 0, "blocked #2 подряд -> принят");
    }
    {
        // Unknown: не понижает известный статус и НЕ сбивает начатое подтверждение.
        ChipHyst h; h.shown = 2;
        auto s1 = chipHystStep(h, -1, N);
        CHECK(s1.next.shown == 2 && !s1.changed && !s1.wantConfirm,
              "raw=unknown при известном works -> без изменений и без пере-пробы");
        auto s2 = chipHystStep(s1.next, 0, N);  // pending blocked #1
        auto s3 = chipHystStep(s2.next, -1, N); // unknown между подтверждениями
        auto s4 = chipHystStep(s3.next, 0, N);  // blocked #2
        CHECK(s4.next.shown == 0, "unknown между двумя blocked не сбивает подтверждение");
    }
    {
        // Ничего не известно и не измерилось.
        ChipHyst h;
        auto s = chipHystStep(h, -1, N);
        CHECK(s.next.shown == -1 && !s.changed && !s.wantConfirm, "unknown поверх unknown -> тишина");
    }
    {
        // confirmN<=1 (или мусор с бэка) => поведение без гистерезиса, но не ломается.
        ChipHyst h; h.shown = 2;
        auto s = chipHystStep(h, 0, 1);
        CHECK(s.next.shown == 0 && s.changed, "confirmN=1 -> ухудшение принимается сразу");
        auto s0 = chipHystStep(h, 0, 0);
        CHECK(s0.next.shown == 0 && s0.changed, "confirmN=0 клампится к 1 (не зависаем навсегда)");
    }
    {
        // works -> slow тоже требует подтверждения (жёлтый флап на пограничной скорости).
        ChipHyst h; h.shown = 2;
        auto s1 = chipHystStep(h, 1, N);
        CHECK(s1.next.shown == 2 && s1.wantConfirm, "works, raw=slow #1 -> удержан зелёный");
        auto s2 = chipHystStep(s1.next, 1, N);
        CHECK(s2.next.shown == 1, "raw=slow #2 подряд -> жёлтый принят");
    }

    if (failures) {
        std::printf(">>> chip_logic_check: %d FAILURE(S)\n", failures);
        return 1;
    }
    std::printf(">>> chip_logic_check: все проверки прошли\n");
    return 0;
}
