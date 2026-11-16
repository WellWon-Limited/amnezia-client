// client/core/serviceEngine/XrayPlatformGate.h
// AVPN serviceEngine (upstream nodes, release C, lane P1) - may THIS build raise an Xray tunnel: the pure
// per-platform decision behind NodeRotation.h::xrayClientSupported and the S4.1 platform switch of
// ConfigService.cpp, plus the pure runtime-presence checks of a Windows install.
// [header-only, QtCore; pure: no globals, no I/O except the file checks named below]
//
// iOS / macOS (the shipped wave): Xray = features.xray_client AND the platform runtime (macOS: tun2socks
// next to Tribe-service; iOS: always) - exactly as before release C; the new switches are never read.
// Android / Windows: additionally the platform's OWN server switch (xray_client_android /
// xray_client_windows, compiled default FALSE, the same features map of /v1/config) AND the platform
// runtime. With the new switch absent nothing changes on those platforms (Xray off, as before).
// Linux and anything else: off.
//
// Plan: ~/avpn-build/plans/provider-pool/platforms-release-plan.md §2, §3 (lane P1).
// Tests: tests/xray_platform_gate_check.cpp (build_xray_platform_gate.sh) - the switch matrix per platform.
#pragma once

#include "MacUpstreamGeo.h" // upstreamGeoPresentAt: the pure geo-pair check (platform-neutral despite the name)

#include <QDir>
#include <QFileInfo>
#include <QMap>
#include <QString>
#include <QStringList>

namespace avpn {

enum class XrayPlatform { Apple, Android, Windows, Other };

// The platform this translation unit is built for. AVPN_TEST_XRAY_PLATFORM (tests only, e.g. -D
// AVPN_TEST_XRAY_PLATFORM=Windows) runs the real callers' decision for another platform on the host.
constexpr XrayPlatform xrayBuildPlatform()
{
#if defined(AVPN_TEST_XRAY_PLATFORM)
    return XrayPlatform::AVPN_TEST_XRAY_PLATFORM;
#elif defined(Q_OS_IOS) || defined(Q_OS_MACOS)
    return XrayPlatform::Apple;
#elif defined(Q_OS_ANDROID)
    return XrayPlatform::Android;
#elif defined(Q_OS_WIN)
    return XrayPlatform::Windows;
#else
    return XrayPlatform::Other;
#endif
}

// The platform's own client switch in features (default FALSE). Empty = the platform has none.
inline QString xrayPlatformSwitchKey(XrayPlatform p)
{
    switch (p) {
    case XrayPlatform::Android: return QStringLiteral("xray_client_android");
    case XrayPlatform::Windows: return QStringLiteral("xray_client_windows");
    case XrayPlatform::Apple:
    case XrayPlatform::Other: break;
    }
    return QString();
}

// The platform's own switch read from a features map; absent key = false (compiled default).
inline bool xrayPlatformSwitchIn(const QMap<QString, bool> &features, XrayPlatform p)
{
    const QString key = xrayPlatformSwitchKey(p);
    return !key.isEmpty() && features.value(key, false);
}

// Is this platform an Xray platform right now (the old constant kXrayPlatform of ConfigService.cpp)?
// Apple: always. Android / Windows: their own switch AND the runtime. Other: never.
inline bool decideXrayPlatform(XrayPlatform p, bool platformSwitch, bool runtimeReady)
{
    switch (p) {
    case XrayPlatform::Apple: return true;
    case XrayPlatform::Android:
    case XrayPlatform::Windows: return platformSwitch && runtimeReady;
    case XrayPlatform::Other: break;
    }
    return false;
}

// May the client pick Xray nodes (NodeRotation.h::xrayClientSupported). Apple: xray_client AND the runtime
// (unchanged). Android / Windows: xray_client AND their own switch AND the runtime.
inline bool decideXrayClientSupported(XrayPlatform p, bool xrayClient, bool platformSwitch, bool runtimeReady)
{
    if (p == XrayPlatform::Apple)
        return xrayClient && runtimeReady;
    return xrayClient && decideXrayPlatform(p, platformSwitch, runtimeReady);
}

// --- runtime presence -------------------------------------------------------------------------------------

// Android: the Xray runtime (module :xray with the libXray AAR, service :amneziaXrayService) is linked into
// every Android build (client/android/build.gradle.kts `implementation(project(":xray"))`) - a compile-time
// fact. No cheap runtime check exists in the app process: the native libraries are not extracted to disk.
inline constexpr bool kAndroidXrayRuntimeBundled = true;

// Windows: what Tribe-service.exe needs next to it to raise Xray (service/server/CMakeLists.txt installs all
// three into the install dir; the core is amnezia_xray.dll, tun2socks.exe drives the wintun adapter).
inline QStringList windowsXrayRuntimeFiles()
{
    return {QStringLiteral("tun2socks.exe"), QStringLiteral("amnezia_xray.dll"), QStringLiteral("wintun.dll")};
}

// Every name is a regular file (not a link), non-empty, directly in dir.
inline bool runtimeFilesPresentIn(const QString &dir, const QStringList &names)
{
    if (dir.isEmpty() || names.isEmpty())
        return false;
    for (const QString &name : names) {
        const QFileInfo info(QDir(dir).filePath(name));
        if (!info.isFile() || info.isSymLink() || info.size() <= 0)
            return false;
    }
    return true;
}

// Windows install dir (the GUI and Tribe-service.exe share it): the Xray runtime is present.
inline bool windowsXrayRuntimePresentIn(const QString &installDir)
{
    return runtimeFilesPresentIn(installDir, windowsXrayRuntimeFiles());
}

// The manifest of the cut geo pair a Windows install carries next to the service (the sha256 sums of
// recipes/tribe-xray-geo, `<64 hex>  <name>` per line; lane W2 installs it on Windows).
inline constexpr char kWindowsUpstreamGeoManifest[] = "tribe-xray-geo.sha256";

// Windows, upstream nodes: the cut geo pair sits next to the service and matches the manifest shipped with
// the same install, byte for byte (mirrors MacUpstreamGeo.h). No manifest = false: upstream candidates are
// withheld (own Xray nodes are untouched - a separate input, NodeRotation.h::upstreamPlatformRuntimeReady).
inline bool windowsUpstreamGeoPresentIn(const QString &installDir)
{
    if (installDir.isEmpty())
        return false;
    return upstreamGeoPresentAt(installDir, QDir(installDir).filePath(QLatin1String(kWindowsUpstreamGeoManifest)));
}

} // namespace avpn
