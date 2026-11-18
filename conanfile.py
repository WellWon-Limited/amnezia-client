from conan import ConanFile

class AmneziaVPN(ConanFile):
    settings = "os", "compiler", "build_type", "arch"
    generators = "VirtualBuildEnv", "CMakeConfigDeps"

    options = {
        "macos_ne": [True, False]
    }
    default_options = {
        "macos_ne": False
    }

    def requirements(self):
        os = str(self.settings.os)

        has_ne = os == "iOS" or (os == "Macos" and self.options.macos_ne)
        has_service = os == "Windows" or os == "Linux" or (os == "Macos" and not has_ne)

        if has_service:
            if os == "Windows":
                self.requires("awg-windows/3.1.20260814-tribe.1")
                self.requires("tap-windows6/9.27.0")
                self.requires("win-split-tunnel/1.2.5.0")
                self.requires("wintun/0.14.1")
            else:
                self.requires("awg-go/3.1.20260828", options={"tribe_probe": os == "Macos"})

            # AVPN: 1.4.0 sources, Xray core amnezia-xray-core v1.261101.0 (Go 1.27.4).
            self.requires("amnezia-xray-bindings/1.4.0-tribe.1")
            self.requires("tun2socks/2.6.0")
            self.requires("openvpn/2.7.0")
            # AVPN: the one pinned, cut geo pair (v2fly, tags private/category-ru/tiktok/
            # speedtest/youtube + private/ru); installed next to Tribe-service on every desktop OS
            # (service/server/CMakeLists.txt). It replaces v2ray-rules-dat (Loyalsoldier), whose
            # only consumer was that CMake file; the recipe stays for rebuilding old releases.
            self.requires("tribe-xray-geo/1.0.0")

        if has_ne:
            # Official parser-fixed 3.1.4 plus the existing Tribe
            # dnsfwd/warmup/rebind patch set.
            # tribe.15: tribe.14 + the probe engine's host limits (in-app probe host). tribe.14: tribe.12 (Xray core amnezia-xray-core v1.261101.0 on Go 1.27.4, LibXrayTribeHTTP,
            # FreeOSMemory loop once per process, the Scanner's probe engine) + the tunnel-side data
            # watch (patches 0012 and 0016).
            self.requires("awg-apple/3.1.4-tribe.15")
            # Cut geo pair, shipped as appex resources and passed as datDir.
            self.requires("tribe-xray-geo/1.0.0")
            self.requires("hev-socks5-tunnel/2.15.0", options={"as_framework": True})
            self.requires("openvpnadapter/1.0.0")

        if os == "Android":
            # tribe.3: tribe.2 (core v1.261101.0, root TribeOutboundStatsJSON, no geo in the AAR) +
            # the Scanner's probe engine (TribeScanMessage / TribeScanStopAll / TribeScanSetProtector).
            self.requires("amnezia-libxray/1.0.3-tribe.3")
            # Cut geo pair, packed as APK assets tribe-geo/ and installed on disk by Xray.kt as datDir.
            self.requires("tribe-xray-geo/1.0.0")
            self.requires("awg-android/3.1.20260814-tribe.1")
            self.requires("openvpn-pt-android/1.0.0")

        # expicitly use libssh@amnezia to prevent it from being downloaded from conan-center
        self.requires("libssh/0.11.3@amnezia")
        self.requires("openssl/3.6.2")
        self.requires("zlib/1.3.2")
