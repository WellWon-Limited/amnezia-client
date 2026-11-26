// AVPN «Доступ к сайтам РФ» (owner 26.11.2026): the switch's value (BypassMaster.h) - the stored AvpnBypass/masterOn, on
// when absent, on every platform - and the store reading in a scratch settings file. Where the mode's sites go directly is
// the route budget's business (RouteBudget.h, tests/route_budget_check.cpp). Build/run: tests/build_bypass_master.sh
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

static void value()
{
    CHECK(bypassMasterValue(std::nullopt));  // never stored (new install): on, as on every platform
    CHECK(bypassMasterValue(true));          // stored on - also 141's Qt-written default or its toggle: on
    CHECK(!bypassMasterValue(false));        // stored off: off
    CHECK(kBypassMasterKey == QStringLiteral("AvpnBypass/masterOn"));
}

static void store()
{
    QTemporaryDir dir;
    CHECK(dir.isValid());
    QSettings s(dir.filePath(QStringLiteral("t.ini")), QSettings::IniFormat);
    CHECK(!storedBool(s, kBypassMasterKey).has_value());
    CHECK(bypassMasterOn(s));
    s.setValue(kBypassMasterKey, false);
    CHECK(!bypassMasterOn(s));
    s.setValue(kBypassMasterKey, true);
    CHECK(bypassMasterOn(s));
    // a test build of 15210ecdf..e8a24fa0a left AvpnBypass/masterOnChoice: ignored (the switch mirrored it into masterOn)
    s.setValue(QStringLiteral("AvpnBypass/masterOnChoice"), false);
    CHECK(bypassMasterOn(s));
    s.setValue(kBypassMasterKey, false);
    s.sync();
    QSettings again(dir.filePath(QStringLiteral("t.ini")), QSettings::IniFormat); // survives a restart (a new store)
    CHECK(storedBool(again, kBypassMasterKey) == std::optional<bool>(false));
    CHECK(!bypassMasterOn(again));
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    value();
    store();
    if (g_fail == 0)
        std::printf("bypass_master_check: OK\n");
    return g_fail == 0 ? 0 : 1;
}
