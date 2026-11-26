// AVPN «Доступ к сайтам РФ» (owner 26.11.2026, AND-67 temporary variant): the decision table of the switch's effective
// value (BypassMaster.h) - the person's choice, a legacy false, and the platform default (off on Android API 33+), plus
// the store reading in a scratch settings file. Build/run: tests/build_bypass_master.sh
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

static void platformDefault()
{
    CHECK(bypassMasterDefaultOff(true, 33));  // Android 13
    CHECK(bypassMasterDefaultOff(true, 36));  // Android 16
    CHECK(!bypassMasterDefaultOff(true, 32)); // Android 12L: unchanged
    CHECK(!bypassMasterDefaultOff(true, 28)); // the minimum SDK
    CHECK(!bypassMasterDefaultOff(false, 0)); // iOS, macOS, Windows
    CHECK(!bypassMasterDefaultOff(false, 99));
}

static void table()
{
    for (bool defaultOff : {false, true}) {
        // the person's explicit choice wins everywhere
        CHECK(bypassMasterEffective(true, kAbsent, defaultOff));
        CHECK(!bypassMasterEffective(false, kAbsent, defaultOff));
        CHECK(bypassMasterEffective(true, false, defaultOff));  // chose on after an old off
        CHECK(!bypassMasterEffective(false, true, defaultOff)); // chose off; the legacy mirror lagged
        // a legacy false is a choice: off everywhere
        CHECK(!bypassMasterEffective(kAbsent, false, defaultOff));
    }
    // legacy true or absent, nothing chosen: the platform default
    const bool android33 = bypassMasterDefaultOff(true, 33), android32 = bypassMasterDefaultOff(true, 32),
               other = bypassMasterDefaultOff(false, 0);
    CHECK(!bypassMasterEffective(kAbsent, true, android33));    // upgrade from 139 on Android 13+: off (the decision)
    CHECK(!bypassMasterEffective(kAbsent, kAbsent, android33)); // new install on Android 13+: off
    CHECK(bypassMasterEffective(kAbsent, true, android32));     // Android below 13: on, as today
    CHECK(bypassMasterEffective(kAbsent, kAbsent, android32));
    CHECK(bypassMasterEffective(kAbsent, true, other));         // iOS / macOS / Windows: on, as today
    CHECK(bypassMasterEffective(kAbsent, kAbsent, other));
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
}

// The store reading (host build: not Android, default on): absent keys, a stored legacy true, false, a choice.
static void store()
{
    QTemporaryDir dir;
    CHECK(dir.isValid());
    QSettings s(dir.filePath(QStringLiteral("t.ini")), QSettings::IniFormat);
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
    platformDefault();
    table();
    migration();
    store();
    if (g_fail == 0)
        std::printf("bypass_master_check: OK\n");
    return g_fail == 0 ? 0 : 1;
}
