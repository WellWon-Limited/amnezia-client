// AVPN «Доступ к сайтам РФ» (owner 26.11.2026, AND-67): the decision table of the switch's effective value
// (BypassMaster.h) - unavailable on Android API 33+ in this release (off whatever is stored, the stored keys untouched);
// elsewhere the person's choice, a legacy false, else on - plus the store reading in a scratch settings file.
// Build/run: tests/build_bypass_master.sh
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

static void platformCapability()
{
    // THE boundary: Android 13+ follows kBypassMasterUnavailableOnAndroid13 (one constant, the engine and the UI read it)
    const bool gone13 = kBypassMasterUnavailableOnAndroid13;
    CHECK(gone13); // this release: unavailable on Android 13+ (owner 26.11: 0 of 3 connects with it on, phone + emulator)
    CHECK(bypassMasterUnavailable(true, 33) == gone13); // Android 13
    CHECK(bypassMasterUnavailable(true, 36) == gone13); // Android 16 (the phone of 26.11)
    CHECK(!bypassMasterUnavailable(true, 32)); // Android 12L: available, unchanged
    CHECK(!bypassMasterUnavailable(true, 28)); // the minimum SDK
    CHECK(!bypassMasterUnavailable(false, 0)); // iOS, macOS, Windows
    CHECK(!bypassMasterUnavailable(false, 99));
}

// the effective value on a platform: the predicate and the table together, as bypassMasterOn(s) composes them
static bool on(bool android, int sdk, std::optional<bool> choice, std::optional<bool> legacy)
{
    return bypassMasterEffective(choice, legacy, bypassMasterUnavailable(android, sdk));
}

static void table()
{
    // Android 13+ (this release): off whatever is stored - no choice, a choice on, a choice off, a legacy true or false
    for (const int sdk : {33, 34, 35, 36}) {
        CHECK(!on(true, sdk, kAbsent, kAbsent)); // new install
        CHECK(!on(true, sdk, kAbsent, true));    // upgrade from 141 with the switch ON (Qt's default or the toggle: 141
                                                 // has no choice key, only the legacy one)
        CHECK(!on(true, sdk, kAbsent, false));   // upgrade with the switch off
        CHECK(!on(true, sdk, true, kAbsent));    // chose on in an earlier 143 build: the choice is not honoured now...
        CHECK(!on(true, sdk, true, true));
        CHECK(!on(true, sdk, false, kAbsent));
    }
    // ...and is not lost: the same stored keys where the split can be applied give the choice back
    CHECK(bypassMasterEffective(true, true, /*unavailable=*/false));
    CHECK(!bypassMasterEffective(false, true, /*unavailable=*/false));
    // Android 12 and lower, and every other platform: exactly as before
    for (const int sdk : {28, 31, 32}) {
        CHECK(on(true, sdk, kAbsent, kAbsent)); // never chose: on
        CHECK(on(true, sdk, kAbsent, true));    // upgrade from 141 with the switch ON: on
        CHECK(!on(true, sdk, kAbsent, false));  // a legacy false is a choice: off
        CHECK(on(true, sdk, true, kAbsent));
        CHECK(on(true, sdk, true, false));      // chose on after an old off
        CHECK(!on(true, sdk, false, kAbsent));
        CHECK(!on(true, sdk, false, true));     // chose off; the legacy mirror lagged
    }
    for (const int sdk : {0, 99}) { // iOS, macOS, Windows
        CHECK(on(false, sdk, kAbsent, kAbsent));
        CHECK(on(false, sdk, kAbsent, true));
        CHECK(!on(false, sdk, kAbsent, false));
        CHECK(on(false, sdk, true, false));
        CHECK(!on(false, sdk, false, true));
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
    CHECK(!bypassMasterEffective(false, false, false));
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
    platformCapability();
    table();
    migration();
    store();
    if (g_fail == 0)
        std::printf("bypass_master_check: OK\n");
    return g_fail == 0 ? 0 : 1;
}
