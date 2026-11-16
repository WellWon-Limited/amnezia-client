// AVPN Scanner: the physical uplink's kind under the Mac's own VPN (UplinkMonitor.h uplinkPhysicalKind /
// uplinkPhysicalIfname - the route table's physical default routes with their SystemConfiguration medium).
// Build + run: tests/build_uplink_kind.sh (--mutate: each rule broken in a copy of the header must fail here).
#include "UplinkMonitor.h"

#include <cstdio>

using namespace avpn;

static int g_fail = 0, g_checks = 0;
#define CHECK_EQ(a, b)                                                                                     \
    do {                                                                                                   \
        ++g_checks;                                                                                        \
        if (!((a) == (b))) {                                                                               \
            ++g_fail;                                                                                      \
            std::fprintf(stderr, "FAIL %s:%d %s == %s (%s)\n", __FILE__, __LINE__, #a, #b, qPrintable(a)); \
        }                                                                                                  \
    } while (0)

int main()
{
    const UplinkRouteIface wifi{QStringLiteral("en0"), UplinkIfaceMedium::Wifi};
    const UplinkRouteIface wired{QStringLiteral("en7"), UplinkIfaceMedium::Ethernet};
    const UplinkRouteIface other{QStringLiteral("en9"), UplinkIfaceMedium::Unknown}; // e.g. iPhone USB tethering
    // Wi-Fi under utun: the only physical default route is en0
    CHECK_EQ(uplinkPhysicalKind({wifi}), QStringLiteral("wifi"));
    CHECK_EQ(uplinkPhysicalIfname({wifi}), QStringLiteral("en0"));
    // Ethernet under utun
    CHECK_EQ(uplinkPhysicalKind({wired}), QStringLiteral("ethernet"));
    CHECK_EQ(uplinkPhysicalIfname({wired}), QStringLiteral("en7"));
    // both carry a default route: wired wins, in any order
    CHECK_EQ(uplinkPhysicalKind({wifi, wired}), QStringLiteral("ethernet"));
    CHECK_EQ(uplinkPhysicalKind({wired, wifi}), QStringLiteral("ethernet"));
    CHECK_EQ(uplinkPhysicalIfname({wifi, wired}), QStringLiteral("en7"));
    // none, or only an interface of another medium: empty (the engine's next sources decide)
    CHECK_EQ(uplinkPhysicalKind({}), QString());
    CHECK_EQ(uplinkPhysicalIfname({}), QString());
    CHECK_EQ(uplinkPhysicalKind({other}), QString());
    CHECK_EQ(uplinkPhysicalIfname({other}), QString());
    // another medium next to Wi-Fi does not hide it
    CHECK_EQ(uplinkPhysicalKind({other, wifi}), QStringLiteral("wifi"));
    if (g_fail) {
        std::fprintf(stderr, "uplink_kind_check: %d of %d checks FAILED\n", g_fail, g_checks);
        return 1;
    }
    std::printf("uplink_kind_check: OK (%d checks)\n", g_checks);
    return 0;
}
