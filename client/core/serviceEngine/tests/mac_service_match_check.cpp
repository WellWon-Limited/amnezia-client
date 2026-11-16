// AVPN Scanner (lane L6b, second pass): the warning before connecting (MacServiceInstaller.mm macForeignVpnName)
// counts only the tunnel's own amneziawg-go process as "our tunnel is up" - never the Scanner's AmneziaWG
// mini-probe child `amneziawg-go probe ...`, which runs the same binary (MacServiceInstaller.h
// macOwnTunnelProcessLine). Build and run: tests/build_mac_service_match.sh (QtCore only).
#include "../MacServiceInstaller.h"

#include <cstdio>

using namespace avpn;

static int g_fail = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                           \
            ++g_fail;                                                                              \
        }                                                                                          \
    } while (0)

int main()
{
    const QString wg = QStringLiteral("/Library/PrivilegedHelperTools/TribeVPN/amneziawg-go");
    // The live tunnel, as the daemon starts it (wireguardutilsmacos.cpp: `amneziawg-go -f utun`).
    CHECK(macOwnTunnelProcessLine(QStringLiteral("4242 /Library/PrivilegedHelperTools/TribeVPN/amneziawg-go -f utun"), wg));
    CHECK(macOwnTunnelProcessLine(QStringLiteral("4242 /Library/PrivilegedHelperTools/TribeVPN/amneziawg-go"), wg));
    // The Scanner's probe child: never our tunnel.
    CHECK(!macOwnTunnelProcessLine(QStringLiteral("5151 /Library/PrivilegedHelperTools/TribeVPN/amneziawg-go probe -bound-if 6"), wg));
    CHECK(!macOwnTunnelProcessLine(QStringLiteral("5151 /Library/PrivilegedHelperTools/TribeVPN/amneziawg-go probe --abi"), wg));
    // Another binary or a path that merely contains ours, a malformed line.
    CHECK(!macOwnTunnelProcessLine(QStringLiteral("77 /usr/local/bin/amneziawg-go -f utun"), wg));
    CHECK(!macOwnTunnelProcessLine(QStringLiteral("77 /tmp/x/Library/PrivilegedHelperTools/TribeVPN/amneziawg-go -f utun"), wg));
    CHECK(!macOwnTunnelProcessLine(QStringLiteral("pgrep: illegal option"), wg));
    CHECK(!macOwnTunnelProcessLine(QString(), wg));
    // The whole pgrep output: only the probe child running = not our tunnel; both = our tunnel.
    CHECK(!macOwnTunnelRunning(QStringLiteral("5151 /Library/PrivilegedHelperTools/TribeVPN/amneziawg-go probe -bound-if 6\n"), wg));
    CHECK(macOwnTunnelRunning(QStringLiteral("5151 /Library/PrivilegedHelperTools/TribeVPN/amneziawg-go probe -bound-if 6\n"
                                             "4242 /Library/PrivilegedHelperTools/TribeVPN/amneziawg-go -f utun\n"), wg));
    CHECK(!macOwnTunnelRunning(QString(), wg));
    if (g_fail) {
        std::printf("mac_service_match_check: %d FAILED\n", g_fail);
        return 1;
    }
    std::printf("mac_service_match_check: OK\n");
    return 0;
}
