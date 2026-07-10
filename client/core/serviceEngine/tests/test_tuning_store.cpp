// AVPN backend-first (план 2026-07-10): юнит TuningStore — потокобезопасный снапшот
// numbers/features/lists из последнего применённого /v1/config. Только QtCore.
#include "../TuningStore.h"
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

    // (б) после set — значения из store
    QMap<QString, double> numbers{{"probe_interval_s", 15.0}};
    QMap<QString, bool> features{{"chat_enabled", false}};
    QMap<QString, QStringList> lists{{"bypass_extra", QStringList{"x.com", "y.com"}}};
    avpn::TuningStore::set(numbers, features, lists);
    CHECK(avpn::TuningStore::numberOr("probe_interval_s", 30.0) == 15.0, "after set: numberOr => stored value");
    CHECK(avpn::TuningStore::flag("chat_enabled", true) == false, "after set: flag => stored value");
    CHECK(avpn::TuningStore::listOr("bypass_extra", {}) == QStringList({"x.com", "y.com"}),
          "after set: listOr => stored value");

    // (в) отсутствующий ключ при непустом store → def
    CHECK(avpn::TuningStore::numberOr("missing_key", 42.0) == 42.0, "missing key: numberOr => def");
    CHECK(avpn::TuningStore::flag("missing_flag") == true, "missing key: flag default => true (kill-switch)");
    CHECK(avpn::TuningStore::flag("missing_flag", false) == false, "missing key: flag explicit def => def");
    CHECK(avpn::TuningStore::listOr("missing_list", QStringList{"fallback"}) == QStringList({"fallback"}),
          "missing key: listOr => def");

    // (г) reset() → снова дефолты
    avpn::TuningStore::reset();
    CHECK(avpn::TuningStore::numberOr("probe_interval_s", 30.0) == 30.0, "after reset: numberOr => def");
    CHECK(avpn::TuningStore::flag("chat_enabled") == true, "after reset: flag => def (true)");
    CHECK(avpn::TuningStore::listOr("bypass_extra", {"z"}) == QStringList({"z"}), "after reset: listOr => def");

    // (д) set полностью замещает (не мержит): второй set без "probe_interval_s" => пропадает
    avpn::TuningStore::set(numbers, features, lists);
    QMap<QString, double> numbers2{{"other_key", 99.0}};
    avpn::TuningStore::set(numbers2, {}, {});
    CHECK(avpn::TuningStore::numberOr("probe_interval_s", -1.0) == -1.0,
          "set replaces, not merges: old key gone => def");
    CHECK(avpn::TuningStore::numberOr("other_key", -1.0) == 99.0, "set replaces: new key present");
    CHECK(avpn::TuningStore::flag("chat_enabled") == true,
          "set replaces: features cleared => flag back to def");
    CHECK(avpn::TuningStore::listOr("bypass_extra", {}).isEmpty(), "set replaces: lists cleared => def empty");

    printf(g_fail ? "\n%d FAIL\n" : "\nALL OK\n", g_fail);
    return g_fail ? 1 : 0;
}
