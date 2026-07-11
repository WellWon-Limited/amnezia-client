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
        // ИНВАРИАНТ (CONNECT-INVARIANTS, коммент у m_watchdog): watchdog ВСЕГДА > handshake_timeout —
        // оператор ставит watchdog=5000 при timeout=12000 => пол поднимает до timeout+запас
        avpn::TuningStore::set({{"reconcile_watchdog_ms", 5000.0}}, {}, {}, {});
        CHECK(avpn::reconcileWatchdogMsTuned() > avpn::handshakeTimeoutMsTuned(),
              "connecttunables: watchdog всегда > handshake_timeout (пол связан)");
        avpn::TuningStore::set({{"reconcile_watchdog_ms", 5000.0}, {"handshake_timeout_ms", 30000.0}}, {}, {}, {});
        CHECK(avpn::reconcileWatchdogMsTuned() >= 33000,
              "connecttunables: пол watchdog следует за timeout");
        avpn::TuningStore::reset();
    }

    return g_fail ? 1 : 0;
}
