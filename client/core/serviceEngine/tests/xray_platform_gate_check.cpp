// AVPN (upstream nodes, release C, lane P1): the per-platform Xray gate (XrayPlatformGate.h) and the real
// callers in NodeRotation.h, compiled for each platform with -DAVPN_TEST_XRAY_PLATFORM=<Apple|Android|
// Windows|Other> (build_xray_platform_gate.sh builds this file five times: four forced + the host's own).
// QtCore only. Proves:
//  - the full switch matrix of the pure decisions on every platform;
//  - Apple (iOS/macOS) reads exactly what it read before release C: xray_client AND the runtime; the new
//    switches never change its answer;
//  - Android/Windows with the new switch absent = today's answer (no Xray), whatever xray_client says;
//  - the runtime-presence checks of a Windows install (files, links, empties, the geo manifest).
#include "../NodeRotation.h"

#include <QByteArray>
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QTemporaryDir>

#include <cstdio>

using namespace avpn;

static int g_fail = 0;
static int g_ok = 0;

static void check(bool ok, const QString &what)
{
    if (ok) {
        ++g_ok;
        return;
    }
    std::printf("FAIL %s\n", qPrintable(what));
    ++g_fail;
}

static const char *platformName(XrayPlatform p)
{
    switch (p) {
    case XrayPlatform::Apple: return "Apple";
    case XrayPlatform::Android: return "Android";
    case XrayPlatform::Windows: return "Windows";
    case XrayPlatform::Other: return "Other";
    }
    return "?";
}

// The expected answer, written out independently of the code under test.
static bool expectedSupported(XrayPlatform p, bool xrayClient, bool platformSwitch, bool runtimeReady)
{
    switch (p) {
    case XrayPlatform::Apple: return xrayClient && runtimeReady; // release A/B behaviour, untouched
    case XrayPlatform::Android:
    case XrayPlatform::Windows: return xrayClient && platformSwitch && runtimeReady;
    case XrayPlatform::Other: return false;
    }
    return false;
}

static void pureMatrix()
{
    const XrayPlatform all[] = {XrayPlatform::Apple, XrayPlatform::Android, XrayPlatform::Windows, XrayPlatform::Other};
    for (XrayPlatform p : all) {
        for (int bits = 0; bits < 8; ++bits) {
            const bool xc = bits & 1, ps = bits & 2, rr = bits & 4;
            const QString tag = QStringLiteral("%1 xray_client=%2 platform_switch=%3 runtime=%4")
                                    .arg(QLatin1String(platformName(p))).arg(xc).arg(ps).arg(rr);
            check(decideXrayClientSupported(p, xc, ps, rr) == expectedSupported(p, xc, ps, rr),
                  QStringLiteral("decideXrayClientSupported ") + tag);
            const bool platformExpected = p == XrayPlatform::Apple ? true
                                          : (p == XrayPlatform::Other ? false : (ps && rr));
            check(decideXrayPlatform(p, ps, rr) == platformExpected, QStringLiteral("decideXrayPlatform ") + tag);
        }
    }
    check(xrayPlatformSwitchKey(XrayPlatform::Android) == QLatin1String("xray_client_android"), "android switch key");
    check(xrayPlatformSwitchKey(XrayPlatform::Windows) == QLatin1String("xray_client_windows"), "windows switch key");
    check(xrayPlatformSwitchKey(XrayPlatform::Apple).isEmpty(), "apple has no platform switch");
    check(xrayPlatformSwitchKey(XrayPlatform::Other).isEmpty(), "other has no platform switch");
    // The switch is read only under its own platform's key; absent = false (compiled default).
    const QMap<QString, bool> both{{QStringLiteral("xray_client_android"), true}, {QStringLiteral("xray_client_windows"), true}};
    const QMap<QString, bool> onlyAndroid{{QStringLiteral("xray_client_android"), true}};
    check(xrayPlatformSwitchIn(both, XrayPlatform::Android) && xrayPlatformSwitchIn(both, XrayPlatform::Windows), "both keys read");
    check(!xrayPlatformSwitchIn(onlyAndroid, XrayPlatform::Windows), "android switch never opens windows");
    check(!xrayPlatformSwitchIn({}, XrayPlatform::Android) && !xrayPlatformSwitchIn({}, XrayPlatform::Windows),
          "absent switch = false");
    check(!xrayPlatformSwitchIn(both, XrayPlatform::Apple) && !xrayPlatformSwitchIn(both, XrayPlatform::Other),
          "apple/other read no switch");
}

// The real NodeRotation.h functions as compiled for xrayBuildPlatform(), fed through TuningStore like the
// facade does from /v1/config.
static void compiledPlatformMatrix()
{
    constexpr XrayPlatform p = xrayBuildPlatform();
    const QString own = xrayPlatformSwitchKey(p);
    const QString other = p == XrayPlatform::Android ? QStringLiteral("xray_client_windows")
                                                     : QStringLiteral("xray_client_android");
    // bits: 0 xray_client, 1 own switch (Apple: the Android key), 2 the other platform's switch, 3 runtime
    for (int bits = 0; bits < 16; ++bits) {
        const bool xc = bits & 1, ownSw = bits & 2, otherSw = bits & 4, rr = bits & 8;
        QMap<QString, bool> f;
        if (xc)
            f.insert(QStringLiteral("xray_client"), true);
        if (ownSw)
            f.insert(own.isEmpty() ? QStringLiteral("xray_client_android") : own, true);
        if (otherSw)
            f.insert(other, true);
        TuningStore::set({}, f);
        xrayPlatformRuntimeReady().store(rr);
        const bool platformSwitch = !own.isEmpty() && ownSw;
        const bool want = expectedSupported(p, xc, platformSwitch, rr);
        const QString tag = QStringLiteral("[%1] xray_client=%2 own=%3 other=%4 runtime=%5")
                                .arg(QLatin1String(platformName(p))).arg(xc).arg(ownSw).arg(otherSw).arg(rr);
        check(xrayClientSupported() == want, QStringLiteral("xrayClientSupported ") + tag);
        check(isSupportedProto(QStringLiteral("xray")) == want, QStringLiteral("isSupportedProto(xray) ") + tag);
        check(isSupportedProto(QStringLiteral("awg")) && isSupportedProto(QString()), QStringLiteral("awg always ") + tag);
        check(!isSupportedProto(QStringLiteral("vless")), QStringLiteral("unknown proto never ") + tag);
        check(effectiveTransportMode(TransportMode::Xray) == (want ? TransportMode::Xray : TransportMode::Auto),
              QStringLiteral("effectiveTransportMode ") + tag);
        // The former kXrayPlatform of ConfigService.cpp, read from the features the caller holds.
        const bool platformWant = p == XrayPlatform::Apple ? true
                                  : (p == XrayPlatform::Other ? false : (platformSwitch && rr));
        check(xrayPlatformEnabledBy(f) == platformWant, QStringLiteral("xrayPlatformEnabledBy ") + tag);
    }
    // Today's behaviour on Android/Windows: with the new switch absent there is no Xray, even with
    // xray_client on and the runtime present.
    TuningStore::set({}, {{QStringLiteral("xray_client"), true}});
    xrayPlatformRuntimeReady().store(true);
    if (p == XrayPlatform::Android || p == XrayPlatform::Windows || p == XrayPlatform::Other)
        check(!xrayClientSupported(), "new switch absent: no Xray (as before release C)");
    else
        check(xrayClientSupported(), "Apple: xray_client + runtime = Xray (as before release C)");

    // An upstream stub needs the Xray gate AND its own switches on top (unchanged rule).
    SubscriptionNode stub;
    stub.nodeId = QStringLiteral("up:p1");
    stub.proto = QStringLiteral("xray");
    UpstreamStub s;
    s.profileId = QStringLiteral("p1");
    stub.upstream = s;
    QMap<QString, bool> f{{QStringLiteral("xray_client"), true}, {QStringLiteral("upstream_nodes"), true}};
    if (!own.isEmpty())
        f.insert(own, true);
    TuningStore::set({}, f);
    upstreamPlatformRuntimeReady().store(true);
    const bool gateOpen = p != XrayPlatform::Other;
    check(isSupportedProtoNode(stub) == gateOpen, "upstream stub with every switch on");
    upstreamPlatformRuntimeReady().store(false);
    check(!isSupportedProtoNode(stub), "upstream stub withheld without the geo pair");
    upstreamPlatformRuntimeReady().store(true);
    f.insert(QStringLiteral("upstream_nodes"), false);
    TuningStore::set({}, f);
    check(!isSupportedProtoNode(stub), "upstream stub withheld with upstream_nodes off");
    TuningStore::reset();
    xrayPlatformRuntimeReady().store(true);
}

static bool writeFile(const QString &path, const QByteArray &data)
{
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly))
        return false;
    return f.write(data) == data.size();
}

static void windowsRuntimeFiles()
{
    QTemporaryDir dir;
    check(dir.isValid(), "temp dir");
    const QString d = dir.path();
    check(!windowsXrayRuntimePresentIn(d), "empty install dir: no runtime");
    check(!windowsXrayRuntimePresentIn(QString()), "no dir: no runtime");
    check(writeFile(d + "/tun2socks.exe", "MZ"), "write tun2socks.exe");
    check(writeFile(d + "/amnezia_xray.dll", "MZ"), "write amnezia_xray.dll");
    check(!windowsXrayRuntimePresentIn(d), "wintun.dll missing: no runtime");
    check(writeFile(d + "/wintun.dll", QByteArray()), "write empty wintun.dll");
    check(!windowsXrayRuntimePresentIn(d), "empty wintun.dll: no runtime");
    check(writeFile(d + "/wintun.dll", "MZ"), "write wintun.dll");
    check(windowsXrayRuntimePresentIn(d), "all three present: runtime");
    QFile::remove(d + "/amnezia_xray.dll");
    check(QFile::link(d + "/tun2socks.exe", d + "/amnezia_xray.dll"), "link amnezia_xray.dll");
    check(!windowsXrayRuntimePresentIn(d), "a link is not a runtime file");

    // The geo pair against the manifest of the same install (MacUpstreamGeo.h rule).
    const QByteArray ip = "geoip-bytes", site = "geosite-bytes";
    check(writeFile(d + "/geoip.dat", ip) && writeFile(d + "/geosite.dat", site), "write geo pair");
    check(!windowsUpstreamGeoPresentIn(d), "no manifest: no upstream geo");
    const QByteArray sums = QCryptographicHash::hash(ip, QCryptographicHash::Sha256).toHex() + "  geoip.dat\n"
                            + QCryptographicHash::hash(site, QCryptographicHash::Sha256).toHex() + "  geosite.dat\n";
    check(writeFile(d + "/" + QLatin1String(kWindowsUpstreamGeoManifest), sums), "write manifest");
    check(windowsUpstreamGeoPresentIn(d), "pair matches its manifest");
    check(writeFile(d + "/geosite.dat", "other"), "tamper geosite");
    check(!windowsUpstreamGeoPresentIn(d), "a changed file fails the manifest");
    check(!windowsUpstreamGeoPresentIn(QString()), "no dir: no upstream geo");
    check(kAndroidXrayRuntimeBundled, "android runtime is a compile-time fact");
}

int main()
{
    pureMatrix();
    compiledPlatformMatrix();
    windowsRuntimeFiles();
    std::printf("xray_platform_gate_check [%s]: %d ok, %d failed\n", platformName(xrayBuildPlatform()), g_ok, g_fail);
    return g_fail == 0 ? 0 : 1;
}
