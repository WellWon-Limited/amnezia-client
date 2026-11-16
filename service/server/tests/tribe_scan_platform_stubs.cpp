// service/server/tests/tribe_scan_platform_stubs.cpp - AVPN: link-only stand-ins for the production
// uplink reader and pf exemption of tribe_scan.cpp. The tests replace both through TribeScanDeps; these
// exist only so tribe_scan.cpp links without NetworkUtilities / MacOSFirewall, and fail loudly if reached.
#include <QNetworkInterface>
#include <QPair>

#include <cstdio>
#include <cstdlib>

#include "core/utils/networkUtilities.h"
#ifdef Q_OS_MACOS
    #include "platforms/macos/daemon/macosfirewall.h"
#endif

namespace avpn {
int tribeScanDaemonLivePeer(QString *, QString *)
{
    std::fprintf(stderr, "FATAL: the production daemon live peer was reached in a test\n");
    std::abort();
}
} // namespace avpn

QPair<QString, QNetworkInterface> NetworkUtilities::getGatewayAndIface()
{
    std::fprintf(stderr, "FATAL: the production uplink reader was reached in a test\n");
    std::abort();
}

#ifdef Q_OS_MACOS
int MacOSFirewall::setScanExemption(const QString &)
{
    std::fprintf(stderr, "FATAL: the production pf exemption was reached in a test\n");
    std::abort();
}

void MacOSFirewall::clearScanExemption()
{
    std::fprintf(stderr, "FATAL: the production pf exemption was reached in a test\n");
    std::abort();
}
#endif
