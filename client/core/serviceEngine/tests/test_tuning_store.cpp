// AVPN backend-first (план 2026-07-10): юнит TuningStore — потокобезопасный снапшот
// numbers/features/lists из последнего применённого /v1/config. Только QtCore.
#include "../TuningStore.h"
#include "../ConnectTunables.h"
#include <QCoreApplication>
#include <cstdio>

static int g_fail = 0;
#define CHECK(cond, msg) do { if (cond) printf("OK   %s\n", msg); \
    else { printf("FAIL %s\n", msg); ++g_fail; } } while (0)

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);

    // (а) пустой store → все геттеры возвращают def; flag() без def → true (kill-switch default)
    CHECK(avpn::TuningStore::numberOr("probe_interval_s", 30.0) == 30.0, "empty store: numberOr => def");
    CHECK(avpn::TuningStore::flag("chat_enabled") == true, "empty store: flag default arg => true");
    CHECK(avpn::TuningStore::flag("chat_enabled", false) == false, "empty store: flag explicit def => def");
    CHECK(avpn::TuningStore::listOr("bypass_extra", QStringList{"a", "b"}) == QStringList({"a", "b"}),
          "empty store: listOr => def");
    CHECK(avpn::TuningStore::stringOr("yt_innertube_key", "fallback") == QStringLiteral("fallback"),
          "empty store: stringOr => def");

    // (б) после set — значения из store
    QMap<QString, double> numbers{{"probe_interval_s", 15.0}};
    QMap<QString, bool> features{{"chat_enabled", false}};
    QMap<QString, QStringList> lists{{"bypass_extra", QStringList{"x.com", "y.com"}}};
    QMap<QString, QString> strings{{"yt_innertube_key", "server-key-123"}};
    avpn::TuningStore::set(numbers, features, lists, strings);
    CHECK(avpn::TuningStore::numberOr("probe_interval_s", 30.0) == 15.0, "after set: numberOr => stored value");
    CHECK(avpn::TuningStore::flag("chat_enabled", true) == false, "after set: flag => stored value");
    CHECK(avpn::TuningStore::listOr("bypass_extra", {}) == QStringList({"x.com", "y.com"}),
          "after set: listOr => stored value");
    CHECK(avpn::TuningStore::stringOr("yt_innertube_key", "fallback") == QStringLiteral("server-key-123"),
          "after set: stringOr => stored value");

    // (в) отсутствующий ключ при непустом store → def
    CHECK(avpn::TuningStore::numberOr("missing_key", 42.0) == 42.0, "missing key: numberOr => def");
    CHECK(avpn::TuningStore::flag("missing_flag") == true, "missing key: flag default => true (kill-switch)");
    CHECK(avpn::TuningStore::flag("missing_flag", false) == false, "missing key: flag explicit def => def");
    CHECK(avpn::TuningStore::listOr("missing_list", QStringList{"fallback"}) == QStringList({"fallback"}),
          "missing key: listOr => def");
    CHECK(avpn::TuningStore::stringOr("missing_string", "fallback") == QStringLiteral("fallback"),
          "missing key: stringOr => def");

    // (г) reset() → снова дефолты
    avpn::TuningStore::reset();
    CHECK(avpn::TuningStore::numberOr("probe_interval_s", 30.0) == 30.0, "after reset: numberOr => def");
    CHECK(avpn::TuningStore::flag("chat_enabled") == true, "after reset: flag => def (true)");
    CHECK(avpn::TuningStore::listOr("bypass_extra", {"z"}) == QStringList({"z"}), "after reset: listOr => def");
    CHECK(avpn::TuningStore::stringOr("yt_innertube_key", "fallback") == QStringLiteral("fallback"),
          "after reset: stringOr => def");

    // (г2) контракт «пусто с сервера = фолбэк» (ревью Task 3, 2026-07-11): ключ ЕСТЬ в store, но
    // хранимое значение пустое (строка/список) → stringOr/listOr отдают def, ТАК ЖЕ как для
    // отсутствующего ключа. Раньше эта семантика жила локальными guard'ами в ServiceProbe.cpp
    // и YoutubeSource.h — теперь единственный источник правды — сам TuningStore.
    avpn::TuningStore::set({}, {}, {{"empty_list_key", QStringList{}}}, {{"empty_string_key", QString()}});
    CHECK(avpn::TuningStore::listOr("empty_list_key", QStringList{"fallback"}) == QStringList({"fallback"}),
          "key present, empty QStringList value: listOr => def (empty != override)");
    CHECK(avpn::TuningStore::stringOr("empty_string_key", "fallback") == QStringLiteral("fallback"),
          "key present, empty QString value: stringOr => def (empty != override)");
    avpn::TuningStore::reset();

    // (д) set полностью замещает (не мержит): второй set без "probe_interval_s" => пропадает
    avpn::TuningStore::set(numbers, features, lists, strings);
    QMap<QString, double> numbers2{{"other_key", 99.0}};
    avpn::TuningStore::set(numbers2, {}, {}, {});
    CHECK(avpn::TuningStore::numberOr("probe_interval_s", -1.0) == -1.0,
          "set replaces, not merges: old key gone => def");
    CHECK(avpn::TuningStore::numberOr("other_key", -1.0) == 99.0, "set replaces: new key present");
    CHECK(avpn::TuningStore::flag("chat_enabled") == true,
          "set replaces: features cleared => flag back to def");
    CHECK(avpn::TuningStore::listOr("bypass_extra", {}).isEmpty(), "set replaces: lists cleared => def empty");
    CHECK(avpn::TuningStore::stringOr("yt_innertube_key", "fallback") == QStringLiteral("fallback"),
          "set replaces: strings cleared => def");

    printf(g_fail ? "\n%d FAIL\n" : "\nALL OK\n", g_fail);
        // --- ConnectTunables (ревью 2026-07-11): клампы handshake-порогов + связка watchdog ---
    {
        avpn::TuningStore::reset();
        bool defOk = avpn::handshakeTimeoutMsTuned() == 12000
                     && avpn::handshakeMaxTimeoutsTuned() == 3
                     && avpn::reconcileWatchdogMsTuned() == 15000;
        CHECK(defOk, "connecttunables: пустой store => вкомпиленные дефолты");
        // мусор с бэка: 0/минус/гигант — клампится, коннект не ломается
        avpn::TuningStore::set({{"handshake_timeout_ms", 0.0}, {"handshake_max_timeouts", -5.0}}, {}, {}, {});
        CHECK(avpn::handshakeTimeoutMsTuned() >= 2000, "connecttunables: timeout=0 => пол 2000");
        CHECK(avpn::handshakeMaxTimeoutsTuned() >= 1, "connecttunables: maxTimeouts<1 => пол 1");
        avpn::TuningStore::set({{"handshake_timeout_ms", 999999.0}, {"handshake_max_timeouts", 999.0}}, {}, {}, {});
        CHECK(avpn::handshakeTimeoutMsTuned() <= 60000, "connecttunables: timeout-гигант => потолок");
        CHECK(avpn::handshakeMaxTimeoutsTuned() <= 10, "connecttunables: maxTimeouts-гигант => потолок");
        // --- seamless roaming (2026-09-03, §23): дефолты = «никогда не паузить, сторож 4/+10 с» ---
        avpn::TuningStore::reset();
        CHECK(avpn::roamPauseAfterSTuned() == 0 && avpn::roamStallProbeSTuned() == 4
                  && avpn::roamStallRebindSTuned() == 10,
              "connecttunables: roaming — пустой store => 0/4/10");
        avpn::TuningStore::set({{"ios_roam_pause_after_s", -1.0}, {"ios_roam_stall_probe_s", 999.0},
                                {"ios_roam_stall_rebind_s", -7.0}}, {}, {}, {});
        CHECK(avpn::roamPauseAfterSTuned() == 0, "connecttunables: roaming pause<0 => 0 (никогда)");
        CHECK(avpn::roamStallProbeSTuned() == 60, "connecttunables: roaming probe-гигант => потолок 60");
        CHECK(avpn::roamStallRebindSTuned() == 0, "connecttunables: roaming rebind<0 => 0 (только bump)");
        avpn::TuningStore::set({{"ios_roam_pause_after_s", 30.0}}, {}, {}, {});
        CHECK(avpn::roamPauseAfterSTuned() == 30, "connecttunables: roaming pause=30 проходит как есть");
        // ИНВАРИАНТ (CONNECT-INVARIANTS, коммент у m_watchdog): watchdog ВСЕГДА > handshake_timeout —
        // оператор ставит watchdog=5000 при timeout=12000 => пол поднимает до timeout+запас
        avpn::TuningStore::set({{"reconcile_watchdog_ms", 5000.0}}, {}, {}, {});
        CHECK(avpn::reconcileWatchdogMsTuned() > avpn::handshakeTimeoutMsTuned(),
              "connecttunables: watchdog всегда > handshake_timeout (пол связан)");
        avpn::TuningStore::set({{"reconcile_watchdog_ms", 5000.0}, {"handshake_timeout_ms", 30000.0}}, {}, {}, {});
        CHECK(avpn::reconcileWatchdogMsTuned() >= 33000,
              "connecttunables: пол watchdog следует за timeout");
        avpn::TuningStore::reset();
        // AVPN awg31-xray-v1: бюджет верификации xray и порог DEAD по пробам — клампы
        CHECK(avpn::xrayVerifyTimeoutMsTuned() == 12000 && avpn::xrayProbeFailCyclesTuned() == 3,
              "connecttunables: xray дефолты 12000 / 3");
        avpn::TuningStore::set({{"xray_verify_timeout_ms", 0.0}, {"xray_probe_fail_cycles", 0.0}}, {}, {}, {});
        CHECK(avpn::xrayVerifyTimeoutMsTuned() == 3000, "connecttunables: xray_verify_timeout_ms=0 => пол 3000");
        CHECK(avpn::xrayProbeFailCyclesTuned() == 1, "connecttunables: xray_probe_fail_cycles=0 => пол 1");
        avpn::TuningStore::set({{"xray_verify_timeout_ms", 9e9}, {"xray_probe_fail_cycles", 999.0}}, {}, {}, {});
        CHECK(avpn::xrayVerifyTimeoutMsTuned() == 60000, "connecttunables: xray_verify_timeout_ms-гигант => потолок 60000");
        CHECK(avpn::xrayProbeFailCyclesTuned() == 10, "connecttunables: xray_probe_fail_cycles-гигант => потолок 10");
        avpn::TuningStore::reset();
    }

    // --- localizedOr (Task 3, 2026-07-12): язык-суффиксные строки с цепочкой фолбэков
    // <key>_<lang> -> <key>_en -> <key> -> def, контракт "пусто = фолбэк" на КАЖДОМ уровне ---
    {
        avpn::TuningStore::reset();

        // (е1) отсутствие всех уровней => def
        CHECK(avpn::TuningStore::localizedOr("cta_incident", "ru", "def") == QStringLiteral("def"),
              "localizedOr: пустой store => def");

        // (е2) точный lang-ключ побеждает над _en и базовым
        avpn::TuningStore::set({}, {}, {}, {
            {"cta_incident_ru", QStringLiteral("Заявка отправлена")},
            {"cta_incident_en", QStringLiteral("Report sent")},
            {"cta_incident", QStringLiteral("Sent")},
        });
        CHECK(avpn::TuningStore::localizedOr("cta_incident", "ru", "def") == QStringLiteral("Заявка отправлена"),
              "localizedOr: точный lang-ключ побеждает");
        // нормализация: "ru_RU" => "ru" (split('_').first().toLower())
        CHECK(avpn::TuningStore::localizedOr("cta_incident", "ru_RU", "def") == QStringLiteral("Заявка отправлена"),
              "localizedOr: lang нормализуется (ru_RU => ru)");

        // (е3) нет ключа под нужный lang => фолбэк на _en
        CHECK(avpn::TuningStore::localizedOr("cta_incident", "fr", "def") == QStringLiteral("Report sent"),
              "localizedOr: нет _fr => фолбэк на _en");

        // (е4) нет ни lang, ни _en => фолбэк на базовый ключ
        avpn::TuningStore::set({}, {}, {}, {
            {"cta_incident", QStringLiteral("Sent")},
        });
        CHECK(avpn::TuningStore::localizedOr("cta_incident", "fr", "def") == QStringLiteral("Sent"),
              "localizedOr: нет lang и _en => фолбэк на базовый ключ");

        // (е5) пустое значение НА КАЖДОМ уровне проваливается ниже (контракт "пусто = фолбэк")
        avpn::TuningStore::set({}, {}, {}, {
            {"cta_incident_ru", QString()},
            {"cta_incident_en", QString()},
            {"cta_incident", QString()},
        });
        CHECK(avpn::TuningStore::localizedOr("cta_incident", "ru", "def") == QStringLiteral("def"),
              "localizedOr: пустые значения на всех уровнях => def");
        avpn::TuningStore::set({}, {}, {}, {
            {"cta_incident_ru", QString()},
            {"cta_incident_en", QStringLiteral("Report sent")},
            {"cta_incident", QStringLiteral("Sent")},
        });
        CHECK(avpn::TuningStore::localizedOr("cta_incident", "ru", "def") == QStringLiteral("Report sent"),
              "localizedOr: пустой lang-уровень проваливается на _en");
        avpn::TuningStore::set({}, {}, {}, {
            {"cta_incident_ru", QString()},
            {"cta_incident_en", QString()},
            {"cta_incident", QStringLiteral("Sent")},
        });
        CHECK(avpn::TuningStore::localizedOr("cta_incident", "ru", "def") == QStringLiteral("Sent"),
              "localizedOr: пустые lang и _en проваливаются на базовый ключ");

        // (е6) reset() очищает
        avpn::TuningStore::reset();
        CHECK(avpn::TuningStore::localizedOr("cta_incident", "ru", "def") == QStringLiteral("def"),
              "localizedOr: после reset() => def");
    }

    // --- Task 8 (backend-first-3, 2026-07-12): клампы трёх остаточных чисел ---
    // BypassListService.cpp/vpnConnection.cpp/AvpnEngineQml.h читают TuningStore напрямую
    // (не header-only helper'ы — эти TU не линкуются в standalone-тест: сеть/QNetworkAccessManager
    // и QQmlEngine соответственно), поэтому формулы qBound здесь ЗЕРКАЛЯТ продакшен-код 1:1
    // (тот же паттерн, что и блок svc_probe_slow_ms/svc_probe_sample_bytes в test_quality_tuning.cpp).
    {
        avpn::TuningStore::reset();

        auto bypassRefetchMsTuned = []() {
            return qBound(900000, int(avpn::TuningStore::numberOr(QStringLiteral("bypass_refetch_ms"),
                                                                   double(6 * 60 * 60 * 1000))),
                          86400000);
        };
        auto statusPollMsTuned = []() {
            return qBound(250, (int)avpn::TuningStore::numberOr(QStringLiteral("status_poll_ms"), 1000), 5000);
        };
        auto fgRefreshThrottleMsTuned = []() {
            return qBound(1000, int(avpn::TuningStore::numberOr(QStringLiteral("fg_refresh_throttle_ms"), 30000)),
                          600000);
        };

        // (о1) пустой store => вкомпиленные дефолты
        CHECK(bypassRefetchMsTuned() == 21600000, "bypass_refetch_ms: пустой store => дефолт 6ч (21600000)");
        CHECK(statusPollMsTuned() == 1000, "status_poll_ms: пустой store => дефолт 1000");
        CHECK(fgRefreshThrottleMsTuned() == 30000, "fg_refresh_throttle_ms: пустой store => дефолт 30000");

        // (о2) валидное значение в диапазоне => как есть
        avpn::TuningStore::set({{"bypass_refetch_ms", 3600000.0}, {"status_poll_ms", 500.0},
                                {"fg_refresh_throttle_ms", 60000.0}}, {}, {}, {});
        CHECK(bypassRefetchMsTuned() == 3600000, "bypass_refetch_ms: валидное значение проходит без клампа");
        CHECK(statusPollMsTuned() == 500, "status_poll_ms: валидное значение проходит без клампа");
        CHECK(fgRefreshThrottleMsTuned() == 60000, "fg_refresh_throttle_ms: валидное значение проходит без клампа");

        // (о3) мусор с бэка снизу (0/минус) => пол
        avpn::TuningStore::set({{"bypass_refetch_ms", 0.0}, {"status_poll_ms", -5.0},
                                {"fg_refresh_throttle_ms", 0.0}}, {}, {}, {});
        CHECK(bypassRefetchMsTuned() == 900000, "bypass_refetch_ms: 0 => пол 900000 (15мин)");
        CHECK(statusPollMsTuned() == 250, "status_poll_ms: минус => пол 250");
        CHECK(fgRefreshThrottleMsTuned() == 1000, "fg_refresh_throttle_ms: 0 => пол 1000");

        // (о4) гигант с бэка => потолок
        avpn::TuningStore::set({{"bypass_refetch_ms", 999999999.0}, {"status_poll_ms", 999999.0},
                                {"fg_refresh_throttle_ms", 999999999.0}}, {}, {}, {});
        CHECK(bypassRefetchMsTuned() == 86400000, "bypass_refetch_ms: гигант => потолок 86400000 (24ч)");
        CHECK(statusPollMsTuned() == 5000, "status_poll_ms: гигант => потолок 5000");
        CHECK(fgRefreshThrottleMsTuned() == 600000, "fg_refresh_throttle_ms: гигант => потолок 600000 (10мин)");

        avpn::TuningStore::reset();
    }

    return g_fail ? 1 : 0;
}
