// Device round of 142 (B2, airplane mode with the tunnel up): the fact behind AvpnEngineQml::tunnelUpNoUplink - the
// device is KNOWN to have no physical network (UplinkMonitor.h physicalUplinkKnownDown). The property itself is
// `tunnel Connected && that fact` (wiring: check_tunnel_no_uplink_wiring.sh).
// Build + run: tests/build_uplink_known_down.sh (--mutate: each rule broken in a copy of the header must fail here).
#include "UplinkMonitor.h"

#include <cstdio>

using namespace avpn;

static int g_fail = 0, g_checks = 0;
#define CHECK(cond, what)                                                                                  \
    do {                                                                                                   \
        ++g_checks;                                                                                        \
        if (!(cond)) {                                                                                     \
            ++g_fail;                                                                                      \
            std::fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, what);                             \
        }                                                                                                  \
    } while (0)

int main()
{
    // macOS (nw_path_monitor without utun) and Android (the NOT_VPN set): the authoritative monitor decides alone
    CHECK(physicalUplinkKnownDown(true, false, AppPathFact::None), "authoritative down = known down");
    CHECK(!physicalUplinkKnownDown(true, true, AppPathFact::None), "authoritative up = network");
    // ... even if an app path fact were present (no platform has both; the monitor wins)
    CHECK(!physicalUplinkKnownDown(true, true, AppPathFact::NoPhysical), "authoritative up wins over the app path");
    CHECK(physicalUplinkKnownDown(true, false, AppPathFact::Physical), "authoritative down wins over the app path");

    // iOS, round 142 B2: the QNetworkInformation fallback stayed "up" (our utun is the default path) while the app's
    // own path monitor saw no physical interface - the app path decides
    CHECK(physicalUplinkKnownDown(false, true, AppPathFact::NoPhysical), "iOS airplane mode: no physical interface = known down");
    CHECK(!physicalUplinkKnownDown(false, true, AppPathFact::Physical), "iOS Wi-Fi under the tunnel (path unsatisfied, interface seen) = network");
    CHECK(!physicalUplinkKnownDown(false, false, AppPathFact::Physical), "iOS: a physical interface beats a fallback 'down'");
    CHECK(physicalUplinkKnownDown(false, false, AppPathFact::NoPhysical), "iOS: both say none");

    // no app path seen yet (iOS at start) / no app path monitor (Windows, Linux, macOS NE): the fallback only when it
    // says Disconnected - unknown never shows «Нет сети»
    CHECK(!physicalUplinkKnownDown(false, true, AppPathFact::None), "fallback up (or unknown: up() is lenient) = network");
    CHECK(physicalUplinkKnownDown(false, false, AppPathFact::None), "fallback Disconnected = known down");

    if (g_fail) {
        std::fprintf(stderr, "uplink_known_down_check: %d of %d checks FAILED\n", g_fail, g_checks);
        return 1;
    }
    std::printf("uplink_known_down_check: OK (%d checks)\n", g_checks);
    return 0;
}
