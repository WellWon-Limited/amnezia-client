// AVPN backend-first (план 2026-07-10): юнит порогов качества/троттлинга — GoodputThresholds::fromTuning()
// и SignalQuality::RttBands::fromTuning() читают TuningStore (numbers.*), пусто/офлайн → те же
// вкомпиленные константы, что были ДО задачи (1000/100/32768 и 150/230/330/500/800). Только QtCore.
//
// Task 3 (2026-07-10): + YoutubeSource::evergreenVideoIds()/innerTubeKey() (реальные обёртки над
// TuningStore.listOr/stringOr, header-only ⇒ линкуются сюда без ServiceProbe.cpp) и прямой паттерн
// чтения svc_goodput_timeout_ms/svc_probe_retry_ms (как svc_probe_slow_ms/svc_probe_sample_bytes
// выше — ServiceProbe.cpp/AvpnEngineQml.cpp сюда не линкуются, тестируем пару key/default).
#include "../GoodputProbe.h"
#include "../SignalQuality.h"
#include "../TuningStore.h"
#include "../YoutubeSource.h"

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

    // ─── svc_probe_* — прямые ключи чтения из TuningStore (тот же паттерн, что ServiceProbe.cpp) ──
    // Сам ServiceProbe.cpp в этот standalone-юнит не линкуется (QNetworkAccessManager и т.п.),
    // поэтому тестируем паттерн чтения TuningStore::numberOr(key, compiled-default) напрямую —
    // именно так его читает ServiceProbe.cpp:94/207/358.

    // (з) svc_probe_slow_ms: override 700 → дефолт 1500 не используется; reset() → снова 1500.
    avpn::TuningStore::set({{"svc_probe_slow_ms", 700.0}}, {});
    CHECK(int(avpn::TuningStore::numberOr(QStringLiteral("svc_probe_slow_ms"), 1500.0)) == 700,
          "svc_probe_slow_ms: override 700 wins over compiled default 1500");
    avpn::TuningStore::reset();
    CHECK(int(avpn::TuningStore::numberOr(QStringLiteral("svc_probe_slow_ms"), 1500.0)) == 1500,
          "svc_probe_slow_ms: after reset() => back to compiled default 1500");

    // (и) svc_probe_sample_bytes: override 65536 → дефолт 131072 не используется; reset() → снова 131072.
    avpn::TuningStore::set({{"svc_probe_sample_bytes", 65536.0}}, {});
    CHECK(int(avpn::TuningStore::numberOr(QStringLiteral("svc_probe_sample_bytes"), 131072.0)) == 65536,
          "svc_probe_sample_bytes: override 65536 wins over compiled default 131072");
    avpn::TuningStore::reset();
    CHECK(int(avpn::TuningStore::numberOr(QStringLiteral("svc_probe_sample_bytes"), 131072.0)) == 131072,
          "svc_probe_sample_bytes: after reset() => back to compiled default 131072");

    // ─── Fix 1: goodput_min_bytes — единый снапшот th покрывает и внешний гейт, и classify() ──────
    // Регрессия для половинчатого knob: bytes=2000 в диапазоне [tuned min=1000, compiled default
    // 32768) должен пройти внешний гейт ServiceProbe.cpp (>= th.minBytes) и классифицироваться
    // classify() по скорости (не blocked по minBytes), т.к. ОБА чтения берут th = fromTuning().

    // (к) tuned goodput_min_bytes=1000, bytes=2000 >= th.minBytes(1000) => внешний гейт пройден,
    // classify() уже НЕ блокирует по minBytes (только по скорости).
    avpn::TuningStore::set({{"goodput_min_bytes", 1000.0}}, {});
    {
        const avpn::GoodputThresholds th = avpn::GoodputThresholds::fromTuning();
        CHECK(th.minBytes == 1000, "fix1: tuned goodput_min_bytes => th.minBytes == 1000");
        CHECK(2000 >= th.minBytes, "fix1: bytes=2000 passes external gate with tuned th (was stuck at 32768)");
        // 2000 байт / 1000 мс = 16 кбит/с — ниже дефолтного slowKbps(100) => классифицируется по
        // скорости как blocked(0), НЕ по minBytes (bytes >= th.minBytes уже выполнено).
        CHECK(avpn::GoodputProbe::classify(2000, 1000, th) == 0,
              "fix1: classify(2000B,1000ms,tuned th) => blocked by SPEED, not by minBytes gate");
    }

    // (л) после reset() тот же bytes=2000 снова < вкомпиленного minBytes(32768) => blocked ОБОИМИ путями.
    avpn::TuningStore::reset();
    {
        const avpn::GoodputThresholds th = avpn::GoodputThresholds::fromTuning();
        CHECK(th.minBytes == 32768, "fix1: after reset() => th.minBytes back to compiled default 32768");
        CHECK(!(2000 >= th.minBytes), "fix1: bytes=2000 fails external gate again after reset()");
        CHECK(avpn::GoodputProbe::classify(2000, 1000, th) == 0,
              "fix1: classify(2000B,1000ms,default th) => blocked by minBytes gate after reset()");
    }

    // ─── svc_goodput_timeout_ms / svc_probe_retry_ms — прямые ключи (паттерн svc_probe_slow_ms
    // выше): ServiceProbe.cpp:measureGoodput/AvpnEngineQml.cpp:351 сюда не линкуются, тестируем
    // тот же key/default, что читает продакшен-код. ────────────────────────────────────────────

    // (м) svc_goodput_timeout_ms: override 8000 → дефолт 20000 не используется; reset() → снова 20000.
    avpn::TuningStore::set({{"svc_goodput_timeout_ms", 8000.0}}, {});
    CHECK(int(avpn::TuningStore::numberOr(QStringLiteral("svc_goodput_timeout_ms"), 20000.0)) == 8000,
          "svc_goodput_timeout_ms: override 8000 wins over compiled default 20000");
    avpn::TuningStore::reset();
    CHECK(int(avpn::TuningStore::numberOr(QStringLiteral("svc_goodput_timeout_ms"), 20000.0)) == 20000,
          "svc_goodput_timeout_ms: after reset() => back to compiled default 20000");

    // (н) svc_probe_retry_ms: override 5000 → дефолт 20000 не используется; reset() → снова 20000.
    avpn::TuningStore::set({{"svc_probe_retry_ms", 5000.0}}, {});
    CHECK(int(avpn::TuningStore::numberOr(QStringLiteral("svc_probe_retry_ms"), 20000.0)) == 5000,
          "svc_probe_retry_ms: override 5000 wins over compiled default 20000");
    avpn::TuningStore::reset();
    CHECK(int(avpn::TuningStore::numberOr(QStringLiteral("svc_probe_retry_ms"), 20000.0)) == 20000,
          "svc_probe_retry_ms: after reset() => back to compiled default 20000");

    // ─── YoutubeSource::evergreenVideoIds() / innerTubeKey() — реальные обёртки TuningStore ────────
    // Фолбэк ОБЯЗАН быть byte-for-byte старыми константами; пустой серверный список/строка = фолбэк,
    // не «пусто» (ревью Task 3, 2026-07-11: гарантия теперь внутри самого TuningStore.listOr/stringOr —
    // единый источник правды, YoutubeSource.h больше не отбрасывает пустое значение локально;
    // прямой юнит на этот контракт — test_tuning_store.cpp, блок «г2»).

    // (о) пустой store → дефолт-видео {"jNQXAC9IVRw","BaW_jenozKc"}, дефолт-ключ непустой.
    {
        const QStringList ids = avpn::YoutubeSource::evergreenVideoIds();
        CHECK(ids == QStringList({QStringLiteral("jNQXAC9IVRw"), QStringLiteral("BaW_jenozKc")}),
              "yt video-ids: empty store => compiled defaults (jNQXAC9IVRw,BaW_jenozKc)");
        CHECK(avpn::YoutubeSource::innerTubeKey()
                      == QStringLiteral("AIzaSyAO_FJ2SlqU8Q4STEHLGCilw_Y9_11qcW8"),
              "yt innertube key: empty store => compiled default");
    }

    // (п) TuningStore::set(yt_probe_video_ids=[...]) → новый список побеждает; yt_innertube_key
    // тоже переопределяется.
    avpn::TuningStore::set({}, {}, {{"yt_probe_video_ids", QStringList{"abc123", "def456"}}},
                           {{"yt_innertube_key", "server-key-999"}});
    {
        CHECK(avpn::YoutubeSource::evergreenVideoIds() == QStringList({"abc123", "def456"}),
              "yt video-ids: after set => server list overrides compiled default");
        CHECK(avpn::YoutubeSource::innerTubeKey() == QStringLiteral("server-key-999"),
              "yt innertube key: after set => server value overrides compiled default");
    }

    // (р) reset() → снова дефолты.
    avpn::TuningStore::reset();
    CHECK(avpn::YoutubeSource::evergreenVideoIds()
                  == QStringList({QStringLiteral("jNQXAC9IVRw"), QStringLiteral("BaW_jenozKc")}),
          "yt video-ids: after reset() => back to compiled default");
    CHECK(avpn::YoutubeSource::innerTubeKey()
                  == QStringLiteral("AIzaSyAO_FJ2SlqU8Q4STEHLGCilw_Y9_11qcW8"),
          "yt innertube key: after reset() => back to compiled default");

    // (с) пустой серверный список/строка (край, который parseConfig() в проде не пропускает, но
    // TuningStore.h теперь гарантирует и на уровне store) => фолбэк, а НЕ пустое значение.
    avpn::TuningStore::set({}, {}, {{"yt_probe_video_ids", QStringList{}}},
                           {{"yt_innertube_key", QString()}});
    CHECK(!avpn::YoutubeSource::evergreenVideoIds().isEmpty(),
          "yt video-ids: empty server list => falls back to compiled default, not empty");
    CHECK(!avpn::YoutubeSource::innerTubeKey().isEmpty(),
          "yt innertube key: empty server string => falls back to compiled default, not empty");
    avpn::TuningStore::reset();

    // ─── chat_media_timeout_ms / chat_thumb_timeout_ms / chat_image_max_dimension /
    // chat_jpeg_quality — Task 8 (2026-07-11): TribeSupportChat.cpp сюда не линкуется
    // (QNetworkAccessManager/QImageReader и т.п.), поэтому тестируем ТОТ ЖЕ паттерн
    // key/default/qBound, что читает продакшен-код (mediaTimeoutMs/thumbTimeoutMs/
    // imageMaxDimension/jpegQuality, TribeSupportChat.cpp:118-148).

    // (т) chat_media_timeout_ms: override 90000 (в допустимом диапазоне) → побеждает
    // дефолт 180000; reset() → снова дефолт.
    avpn::TuningStore::set({{"chat_media_timeout_ms", 90000.0}}, {});
    CHECK(qBound(5000, int(avpn::TuningStore::numberOr(QStringLiteral("chat_media_timeout_ms"),
                                                        180000.0)),
                 600000) == 90000,
          "chat_media_timeout_ms: override 90000 wins over compiled default 180000");
    avpn::TuningStore::reset();
    CHECK(qBound(5000, int(avpn::TuningStore::numberOr(QStringLiteral("chat_media_timeout_ms"),
                                                        180000.0)),
                 600000) == 180000,
          "chat_media_timeout_ms: after reset() => back to compiled default 180000");

    // (у) chat_media_timeout_ms: злой конфиг (1 мс) клампится к минимуму 5000, не проходит как есть.
    avpn::TuningStore::set({{"chat_media_timeout_ms", 1.0}}, {});
    CHECK(qBound(5000, int(avpn::TuningStore::numberOr(QStringLiteral("chat_media_timeout_ms"),
                                                        180000.0)),
                 600000) == 5000,
          "chat_media_timeout_ms: server value below floor clamped to 5000");
    avpn::TuningStore::reset();

    // (ф) chat_thumb_timeout_ms: override 15000 → побеждает дефолт 30000; reset() → снова дефолт.
    avpn::TuningStore::set({{"chat_thumb_timeout_ms", 15000.0}}, {});
    CHECK(qBound(5000, int(avpn::TuningStore::numberOr(QStringLiteral("chat_thumb_timeout_ms"),
                                                        30000.0)),
                 600000) == 15000,
          "chat_thumb_timeout_ms: override 15000 wins over compiled default 30000");
    avpn::TuningStore::reset();
    CHECK(qBound(5000, int(avpn::TuningStore::numberOr(QStringLiteral("chat_thumb_timeout_ms"),
                                                        30000.0)),
                 600000) == 30000,
          "chat_thumb_timeout_ms: after reset() => back to compiled default 30000");

    // (х) chat_image_max_dimension: override 2048 → побеждает дефолт 1600; reset() → снова дефолт;
    // злой конфиг (100) клампится к полу 320, а не проходит как есть.
    avpn::TuningStore::set({{"chat_image_max_dimension", 2048.0}}, {});
    CHECK(qBound(320, int(avpn::TuningStore::numberOr(QStringLiteral("chat_image_max_dimension"),
                                                       1600.0)),
                 8192) == 2048,
          "chat_image_max_dimension: override 2048 wins over compiled default 1600");
    avpn::TuningStore::reset();
    CHECK(qBound(320, int(avpn::TuningStore::numberOr(QStringLiteral("chat_image_max_dimension"),
                                                       1600.0)),
                 8192) == 1600,
          "chat_image_max_dimension: after reset() => back to compiled default 1600");
    avpn::TuningStore::set({{"chat_image_max_dimension", 100.0}}, {});
    CHECK(qBound(320, int(avpn::TuningStore::numberOr(QStringLiteral("chat_image_max_dimension"),
                                                       1600.0)),
                 8192) == 320,
          "chat_image_max_dimension: server value below floor clamped to 320");
    avpn::TuningStore::reset();

    // (ц) chat_jpeg_quality: override 60 → побеждает дефолт 85; reset() → снова дефолт;
    // злой конфиг (999) клампится к потолку 100.
    avpn::TuningStore::set({{"chat_jpeg_quality", 60.0}}, {});
    CHECK(qBound(1, int(avpn::TuningStore::numberOr(QStringLiteral("chat_jpeg_quality"), 85.0)),
                 100) == 60,
          "chat_jpeg_quality: override 60 wins over compiled default 85");
    avpn::TuningStore::reset();
    CHECK(qBound(1, int(avpn::TuningStore::numberOr(QStringLiteral("chat_jpeg_quality"), 85.0)),
                 100) == 85,
          "chat_jpeg_quality: after reset() => back to compiled default 85");
    avpn::TuningStore::set({{"chat_jpeg_quality", 999.0}}, {});
    CHECK(qBound(1, int(avpn::TuningStore::numberOr(QStringLiteral("chat_jpeg_quality"), 85.0)),
                 100) == 100,
          "chat_jpeg_quality: server value above ceiling clamped to 100");
    avpn::TuningStore::reset();

    printf(g_fail ? "\n%d FAIL\n" : "\nALL OK\n", g_fail);
    return g_fail ? 1 : 0;
}
