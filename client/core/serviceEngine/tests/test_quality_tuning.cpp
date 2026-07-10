// AVPN backend-first (план 2026-07-10): юнит порогов качества/троттлинга — GoodputThresholds::fromTuning()
// и SignalQuality::RttBands::fromTuning() читают TuningStore (numbers.*), пусто/офлайн → те же
// вкомпиленные константы, что были ДО задачи (1000/100/32768 и 150/230/330/500/800). Только QtCore.
#include "../GoodputProbe.h"
#include "../SignalQuality.h"
#include "../TuningStore.h"

#include <QCoreApplication>
#include <cstdio>

static int g_fail = 0;
#define CHECK(cond, msg) do { if (cond) printf("OK   %s\n", msg); \
    else { printf("FAIL %s\n", msg); ++g_fail; } } while (0)

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);

    // ─── GoodputThresholds::fromTuning() ────────────────────────────────────────────────────────
    // 75000 байт / 1000 мс = 600 кбит/с (фикс. арифметика, см. GoodputProbe::kbitPerSec).
    const qint64 kBytes = 75000;
    const qint64 kMs = 1000;

    // (а) пустой store → дефолты идентичны старым константам (works=1000, slow=100, minBytes=32768).
    {
        const avpn::GoodputThresholds t = avpn::GoodputThresholds::fromTuning();
        CHECK(t.worksKbps == 1000.0 && t.slowKbps == 100.0 && t.minBytes == 32768,
              "goodput: empty store => compiled defaults (1000/100/32768)");
        CHECK(avpn::GoodputProbe::classify(kBytes, kMs, t) == 1,
              "goodput: empty store, 600kbps => slow(1) [default worksKbps=1000]");
    }

    // (б) TuningStore::set(goodput_works_kbps=500) → 600 кбит/с теперь >= works-порога => works(2).
    avpn::TuningStore::set({{"goodput_works_kbps", 500.0}}, {});
    {
        const avpn::GoodputThresholds t = avpn::GoodputThresholds::fromTuning();
        CHECK(t.worksKbps == 500.0, "goodput: after set => worksKbps overridden to 500");
        CHECK(avpn::GoodputProbe::classify(kBytes, kMs, t) == 2,
              "goodput: after set(works=500), 600kbps => works(2)");
    }

    // (в) reset() → снова дефолт => 600 кбит/с снова slow(1).
    avpn::TuningStore::reset();
    {
        const avpn::GoodputThresholds t = avpn::GoodputThresholds::fromTuning();
        CHECK(t.worksKbps == 1000.0, "goodput: after reset => worksKbps back to default 1000");
        CHECK(avpn::GoodputProbe::classify(kBytes, kMs, t) == 1,
              "goodput: after reset, 600kbps => slow(1) again");
    }

    // (г) прочие поля тоже читаются из store (slow_kbps, min_bytes) — не только works.
    avpn::TuningStore::set({{"goodput_slow_kbps", 50.0}, {"goodput_min_bytes", 1000.0}}, {});
    {
        const avpn::GoodputThresholds t = avpn::GoodputThresholds::fromTuning();
        CHECK(t.slowKbps == 50.0 && t.minBytes == 1000,
              "goodput: slow_kbps/min_bytes overridden independently");
    }
    avpn::TuningStore::reset();

    // ─── SignalQuality::RttBands::fromTuning() / barsForRtt() ───────────────────────────────────

    // (д) пустой store → дефолты идентичны старой таблице (150/230/330/500/800) — та же карта, что
    // уже фиксирует parse_check.cpp; здесь дублируем через явный RttBands для полноты.
    {
        const avpn::RttBands b = avpn::RttBands::fromTuning();
        CHECK(b.b5 == 150 && b.b4 == 230 && b.b3 == 330 && b.b2 == 500 && b.b1 == 800,
              "rtt: empty store => compiled defaults (150/230/330/500/800)");
        CHECK(avpn::SignalQuality::barsForRtt(120) == 5, "rtt: empty store, 120ms => 5 bars");
    }

    // (е) TuningStore::set(rtt_bar5_ms=100) → RTT 120 больше не входит в топ-полосу => 4 бара.
    avpn::TuningStore::set({{"rtt_bar5_ms", 100.0}}, {});
    {
        const avpn::RttBands b = avpn::RttBands::fromTuning();
        CHECK(b.b5 == 100.0, "rtt: after set => bar5 overridden to 100");
        CHECK(avpn::SignalQuality::barsForRtt(120) == 4,
              "rtt: after set(bar5=100), 120ms => 4 bars (was 5)");
    }

    // (ж) reset() → снова дефолт => 120мс снова 5 баров.
    avpn::TuningStore::reset();
    {
        const avpn::RttBands b = avpn::RttBands::fromTuning();
        CHECK(b.b5 == 150.0, "rtt: after reset => bar5 back to default 150");
        CHECK(avpn::SignalQuality::barsForRtt(120) == 5, "rtt: after reset, 120ms => 5 bars again");
    }

    printf(g_fail ? "\n%d FAIL\n" : "\nALL OK\n", g_fail);
    return g_fail ? 1 : 0;
}
