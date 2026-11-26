// AVPN «Доступ к сайтам РФ» (owner 26.11.2026, AND-67): the decision table of the switch's effective value
// (BypassMaster.h) - unavailable where the platform's route budget is 0 (RouteBudget.h: Android 13+ at the compiled N = 0;
// off whatever is stored, the stored keys untouched); elsewhere the person's choice, a legacy false, else the platform
// default (off on Android 13+) - plus the store reading in a scratch settings file. Build/run: tests/build_bypass_master.sh
#include "../BypassMaster.h"

#include <QCoreApplication>
#include <QSettings>
#include <QTemporaryDir>
#include <cstdio>

using namespace avpn;

static int g_fail = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                            \
            ++g_fail;                                                                              \
        }                                                                                          \
    } while (0)

static const std::optional<bool> kAbsent = std::nullopt;

static void platformRules()
{
    // the two constants the owner flips after the phone measurement (26.11): the compiled N and the Android 13+ default
    CHECK(kAndroidBypassRouteBudget == 0); // this commit: unavailable on Android 13+
    CHECK(kBypassMasterOffByDefaultOnAndroid13); // this commit: off by default where it becomes available
    // unavailable = budget 0, nothing else
    CHECK(bypassMasterUnavailable(0));
    CHECK(!bypassMasterUnavailable(1500));
    CHECK(!bypassMasterUnavailable(kRouteBudgetUnlimited));
    // the default: off on Android 13+ only (the same boundary as the budget)
    CHECK(bypassMasterDefaultOff(true, 33) == kBypassMasterOffByDefaultOnAndroid13);
    CHECK(bypassMasterDefaultOff(true, 36) == kBypassMasterOffByDefaultOnAndroid13);
    CHECK(!bypassMasterDefaultOff(true, 32)); // Android 12L: unchanged
    CHECK(!bypassMasterDefaultOff(true, 28));
    CHECK(!bypassMasterDefaultOff(false, 0)); // iOS, macOS, Windows
    CHECK(!bypassMasterDefaultOff(false, 99));
}

// the effective value on a platform with a route budget (budget: nullopt = the platform's own, from RouteBudget.h with
// no server number and no developer file; else that number on Android 13+)
static bool on(bool android, int sdk, std::optional<int> budget, std::optional<bool> choice, std::optional<bool> legacy)
{
    const int b = budget.has_value() && androidRoutesLimited(android, sdk)
                      ? *budget
                      : bypassRouteBudget(android, sdk, std::nullopt, std::nullopt);
    return bypassMasterEffective(choice, legacy, bypassMasterUnavailable(b), bypassMasterDefaultOff(android, sdk));
}

static void table()
{
    const std::optional<int> compiled; // the compiled N (0)
    // Android 13+ at the compiled N = 0: off whatever is stored
    for (const int sdk : {33, 34, 35, 36}) {
        CHECK(!on(true, sdk, compiled, kAbsent, kAbsent)); // new install
        CHECK(!on(true, sdk, compiled, kAbsent, true));    // upgrade from 141 with the switch ON (Qt's default or the
                                                           // toggle: 141 has only the legacy key)
        CHECK(!on(true, sdk, compiled, kAbsent, false));   // upgrade with the switch off
        CHECK(!on(true, sdk, compiled, true, kAbsent));    // chose on in an earlier 143 build: not honoured now...
        CHECK(!on(true, sdk, compiled, true, true));
        CHECK(!on(true, sdk, compiled, false, kAbsent));
    }
    // ...and not lost: the same keys with a budget give the choice back; with no choice the Android 13+ default (off)
    for (const int sdk : {33, 36}) {
        CHECK(on(true, sdk, 1500, true, kAbsent));
        CHECK(on(true, sdk, 1500, true, true));
        CHECK(!on(true, sdk, 1500, false, kAbsent));
        CHECK(on(true, sdk, 1500, kAbsent, kAbsent) == !kBypassMasterOffByDefaultOnAndroid13); // new install: default
        CHECK(on(true, sdk, 1500, kAbsent, true) == !kBypassMasterOffByDefaultOnAndroid13); // 141 ON: not a choice
        CHECK(!on(true, sdk, 1500, kAbsent, false)); // a legacy false is a choice
        CHECK(!on(true, sdk, 0, true, kAbsent));     // a server or developer N = 0: unavailable again
    }
    // Android 12 and lower (budget unlimited), and every other platform: exactly as before
    for (const int sdk : {28, 31, 32}) {
        CHECK(on(true, sdk, compiled, kAbsent, kAbsent)); // never chose: on
        CHECK(on(true, sdk, compiled, kAbsent, true));    // upgrade from 141 with the switch ON: on
        CHECK(!on(true, sdk, compiled, kAbsent, false));  // a legacy false is a choice: off
        CHECK(on(true, sdk, compiled, true, kAbsent));
        CHECK(on(true, sdk, compiled, true, false));      // chose on after an old off
        CHECK(!on(true, sdk, compiled, false, kAbsent));
        CHECK(!on(true, sdk, compiled, false, true));     // chose off; the legacy mirror lagged
        CHECK(on(true, sdk, 0, true, kAbsent));           // a budget number has no effect below Android 13
    }
    for (const int sdk : {0, 99}) { // iOS, macOS, Windows
        CHECK(on(false, sdk, compiled, kAbsent, kAbsent));
        CHECK(on(false, sdk, compiled, kAbsent, true));
        CHECK(!on(false, sdk, compiled, kAbsent, false));
        CHECK(on(false, sdk, compiled, true, false));
        CHECK(!on(false, sdk, compiled, false, true));
        CHECK(on(false, sdk, 0, true, kAbsent));
    }
}

static void migration()
{
    CHECK(bypassMasterMigratesLegacy(kAbsent, false)); // the legacy off moves into the choice key once
    CHECK(!bypassMasterMigratesLegacy(kAbsent, true)); // a legacy true says nothing
    CHECK(!bypassMasterMigratesLegacy(kAbsent, kAbsent));
    CHECK(!bypassMasterMigratesLegacy(true, false));   // a choice exists: nothing to move
    CHECK(!bypassMasterMigratesLegacy(false, false));
    // after the move the value is the same: off
    CHECK(!bypassMasterEffective(false, false, false, false));
    // the move does not depend on the platform: a legacy false is the person's choice on Android 13+ too (kept for the
    // day the mode returns)
    CHECK(bypassMasterMigratesLegacy(kAbsent, false));
}

// The store reading (host build: not Android, available): absent keys, a stored legacy true, false, a choice.
static void store()
{
    QTemporaryDir dir;
    CHECK(dir.isValid());
    QSettings s(dir.filePath(QStringLiteral("t.ini")), QSettings::IniFormat);
    CHECK(!bypassMasterUnavailableHere()); // the host is not Android
    CHECK(!storedBool(s, kBypassMasterChoiceKey).has_value());
    CHECK(bypassMasterOn(s)); // nothing stored: on here (host = not Android)
    s.setValue(kBypassMasterLegacyKey, true);
    CHECK(bypassMasterOn(s));
    s.setValue(kBypassMasterLegacyKey, false);
    CHECK(!bypassMasterOn(s));
    s.setValue(kBypassMasterChoiceKey, true);
    CHECK(bypassMasterOn(s)); // the choice wins over the legacy false
    s.sync();
    QSettings again(dir.filePath(QStringLiteral("t.ini")), QSettings::IniFormat); // survives a restart (a new store)
    CHECK(storedBool(again, kBypassMasterChoiceKey) == std::optional<bool>(true));
    CHECK(bypassMasterOn(again));
    again.setValue(kBypassMasterChoiceKey, false);
    CHECK(!bypassMasterOn(again));
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    platformRules();
    table();
    migration();
    store();
    if (g_fail == 0)
        std::printf("bypass_master_check: OK\n");
    return g_fail == 0 ? 0 : 1;
}
