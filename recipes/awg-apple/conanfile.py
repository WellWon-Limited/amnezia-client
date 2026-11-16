from conan import ConanFile
from conan.errors import ConanException, ConanInvalidConfiguration
from conan.tools.layout import basic_layout
from conan.tools.files import (
    apply_conandata_patches,
    collect_libs,
    copy,
    export_conandata_patches,
    get,
    patch,
)
from conan.tools.apple import is_apple_os
from conan.tools.env import Environment
from conan.tools.gnu import AutotoolsToolchain, Autotools

import io
import os

class AwgApple(ConanFile):
    name = "awg-apple"
    # AVPN: official v3.1.4 contains the AWG 3.1 parser fix.  The package
    # suffix is deliberate: it also carries the small, reviewable Tribe
    # split-DNS/warmup/rebind patch from the old fork.
    # tribe.8: tribe.7 (0001-0003 byte-identical to tribe.5 + 0005 bounded recovery) + 0006
    # persistent heal / in-place soft restart (conandata.yml). TribeRoaming.swift is NOT shared
    # across versions any more: a released version builds from its own frozen snapshot
    # (_roaming_snapshots), so tribe.5/tribe.7 rebuilt from this recipe behave as shipped.
    # tribe.9: tribe.8 + 0007 fresh port on a returning path / interface change, ladder
    # fresh port -> soft restart -> backoff cycle, no stall-clock reset on path events.
    # tribe.10: tribe.9 + 0008 immortal logger context (the real NE crash), real-loss gate for
    # the roam fresh port, no stale fresh-port flag; roam fresh port spends the budget's fresh port.
    # tribe.11: tribe.10 + 0009 userspace direct split (directsplit.go): destinations from a list
    # file leave through the extension's own sockets instead of 10.8k system excluded routes.
    # Swift sources and TribeRoaming.swift are those of tribe.10.
    # tribe.12: tribe.11 + Xray core amnezia-xray-core v1.261101.0 (Go 1.27.4) with its own
    # controller-error patch, 0010 LibXrayTribeHTTP (one HTTPS request through the core's local
    # SOCKS5 inbound), FreeOSMemory loop started once per process and the Xray memory regime
    # undone by StopXray (vendored libxray, shared patches ../amnezia-libxray/patches/0005, 0006).
    # Swift sources and TribeRoaming.swift are those of tribe.11 (= tribe.10).
    # tribe.12 (unreleased) also carries 0013 (the Scanner's probe engine, ABI libxray-tribe-scan-v1):
    # the shared engine ../amnezia-libxray/patches/0012-tribe-scan-engine.patch (package tribescan,
    # applied to this tree before `go mod vendor`) and core 0011 (per-instance dialer state, so a probe
    # instance never changes how the tunnel core resolves or chains, and its sockets run only the
    # probe's own protector, never the LibXraySetSockCallback slot). Slot 0012 belongs to the data
    # watch branch (its tribe.13); rebased onto it, this package becomes 3.1.4-tribe.14.
    # tribe.14: tribe.12 + the data watch. Patch 0012 (the slot tribe.12 left for it) is the Go half:
    # tribeprobe.go, the probe through the tunnel. Patch 0016 is the adapter half: the adapter feeds
    # TribeDataWatch.swift (pure verdict rule and arbiter, own gate) on its stall tick and executes
    # its commands; the engine stop of an in-place switch runs through 0015's backend hook. Two
    # patches because patch_ng matches hunks at exact lines and 0015 was recorded on an adapter
    # without the data watch (conandata.yml). Core, toolchain and gates are those of tribe.12.
    # tribe.13 was the data watch branch's own number before the merge (tribe.11 + 0012 in one
    # patch) and never left that branch.
    version = "3.1.4-tribe.14"
    settings = "os", "arch", "compiler"

    _upstream_version = "3.1.4"

    # Released version -> frozen copy of TribeRoaming.swift + its build-gate test
    # (tribe/snapshots/<v>/, tests/snapshots/<v>/). Absent = the current tribe/TribeRoaming.swift.
    # tribe.4 and tribe.5 shipped the same file (git 0d2dd24c); tribe.3 has no roaming patch.
    _roaming_snapshots = {
        "3.1.4-tribe.4": "3.1.4-tribe.5",
        "3.1.4-tribe.5": "3.1.4-tribe.5",
        "3.1.4-tribe.7": "3.1.4-tribe.7",
        "3.1.4-tribe.8": "3.1.4-tribe.8",
        "3.1.4-tribe.9": "3.1.4-tribe.9",
    }

    # Xray core + Go toolchain per released version. Absent = the tribe.3-tribe.11 pins (the
    # upstream go.mod replace to amnezia-xray-core v1.260728.0, Go 1.26.0, patch 0004).
    # core_patches and libxray_patches live in ../amnezia-libxray/patches (shared with Android) and
    # are applied to the vendored modules after `go mod vendor`.
    _xray_pins_default = {
        "go": "1.26.0",
        "core": "1.260728.0",
        "core_patches": ("0004-xray-core-controller-errors.patch",),
        "libxray_patches": (),
        "engine_patches": (),
        "tribe_http": False,
        "tribe_stats": False,
        "tribe_scan": False,
    }
    _xray_pins = {
        "3.1.4-tribe.12": {
            "go": "1.27.4",
            "core": "1.261101.0",
            "core_patches": ("0004-xray-core-261101-controller-errors.patch",
                             "0008-xray-core-261101-counted-buffered-flush.patch",
                             "0011-xray-core-261101-instance-dialer-state.patch"),
            "libxray_patches": ("0005-libxray-forcefree-once.patch",
                                "0006-libxray-restore-runtime-on-stop.patch",
                                "0007-libxray-outbound-stats.patch"),
            # New files only (tribescan/), module-agnostic: the same patch builds into
            # amnezia-xray-bindings and amnezia-libxray. Applied before `go mod vendor`.
            "engine_patches": ("0012-tribe-scan-engine.patch",),
            "tribe_http": True,
            "tribe_stats": True,
            "tribe_scan": True,
            "tribe_awg": True,
            "tribe_backend_hook": True,
        },
    }
    # tribe.14 = tribe.12 + the data watch (0012, 0016): the same core, toolchain, shared patches
    # and gates; the typecheck of 0015 then covers the data watch's adapter code as well.
    _xray_pins["3.1.4-tribe.14"] = _xray_pins["3.1.4-tribe.12"]

    @property
    def _pins(self):
        return self._xray_pins.get(str(self.version), self._xray_pins_default)

    def _roaming_sources(self):
        snapshot = self._roaming_snapshots.get(str(self.version))
        if snapshot is None:
            return (os.path.join(self.source_folder, "tribe", "TribeRoaming.swift"),
                    os.path.join(self.source_folder, "tests", "TribeRoamingTests.swift"))
        return (os.path.join(self.source_folder, "tribe", "snapshots", snapshot, "TribeRoaming.swift"),
                os.path.join(self.source_folder, "tests", "snapshots", snapshot, "TribeRoamingTests.swift"))

    @property
    def _has_data_watch(self):
        # Present from patch 0012 on (tribeprobe.go is added by it).
        return os.path.exists(os.path.join(self.source_folder, "Sources", "WireGuardKitGo", "tribeprobe.go"))

    def export_sources(self):
        export_conandata_patches(self)
        # The app's shared tribe-scan-v1 vectors (client/core/serviceEngine/tests/vectors), replayed by
        # tribescan's TestTribeScanSharedVectors; absent in a tree without them (the test then skips).
        copy(self, "scan_host_vectors.json",
             src=os.path.join(self.recipe_folder, "..", "..", "client", "core", "serviceEngine", "tests", "vectors"),
             dst=os.path.join(self.export_sources_folder, "vectors"))
        # Tribe seamless roaming: pure policy/watchdog logic + its executable unit test travel
        # with the recipe (tribe.4). The .swift is copied next to WireGuardAdapter.swift in
        # build(); the test is a build gate (see build()).
        copy(self, "*.swift", src=os.path.join(self.recipe_folder, "tribe"),
             dst=os.path.join(self.export_sources_folder, "tribe"))
        copy(self, "*", src=os.path.join(self.recipe_folder, "tests"),
             dst=os.path.join(self.export_sources_folder, "tests"))
        # Both mobile adapters bind the same pinned Xray core. Reuse its reviewed error-
        # propagation delta, but copy it into this recipe's immutable exported sources.
        for shared in (tuple(self._pins["core_patches"]) + tuple(self._pins["libxray_patches"])
                       + tuple(self._pins.get("engine_patches", ()))):
            copy(
                self,
                shared,
                src=os.path.join(self.recipe_folder, "..", "amnezia-libxray", "patches"),
                dst=os.path.join(self.export_sources_folder, "patches"),
            )

    @property
    def _goarch(self):
        arch_map = {
            "armv8": "arm64",
            "x86_64": "x86_64",
        }
        archs = str(self.settings.arch).split("|")
        return " ".join(arch_map.get(arch, arch) for arch in archs)

    def configure(self):
        self.settings.rm_safe("compiler.libcxx")
        self.settings.rm_safe("compiler.cppstd")

    def layout(self):
        basic_layout(self, build_folder=os.path.join(self.folders.source, "Sources/WireGuardKitGo"))

    def build_requirements(self):
        self.tool_requires(f"go/{self._pins['go']}")

    def validate(self):
        if not is_apple_os(self):
            raise ConanInvalidConfiguration(
                f"{self.name} v{self.version} does not support {self.settings.os}"
            )

    def source(self):
        # AVPN: source is immutable official upstream; local behavior is
        # applied from conandata.yml instead of relying on a mutable fork.
        get(self, f"https://github.com/amnezia-vpn/amneziawg-apple/archive/refs/tags/v{self._upstream_version}.zip",
            sha256="09d7b760d18232fdf121ed2286b2f171b501dc31137e5e7d557c1ee3a99ef772", strip_root=True
        )

    def generate(self):
        tc = AutotoolsToolchain(self)
        sdk = str(self.settings.get_safe("os.sdk", "macosx"))
        tc.make_args = [
            f"ARCHS={self._goarch}",
            f"PLATFORM_NAME={sdk}"
        ]
        deployment_target = self.settings.get_safe("os.version")
        if not deployment_target:
            raise ConanInvalidConfiguration(
                f"{self.name} requires an explicit Apple deployment target"
            )
        target_flags = {
            "iphoneos": ("miphoneos-version-min", "IPHONEOS_DEPLOYMENT_TARGET"),
            "macosx": ("mmacosx-version-min", "MACOSX_DEPLOYMENT_TARGET"),
        }
        if sdk not in target_flags:
            raise ConanInvalidConfiguration(
                f"{self.name} does not support Apple SDK {sdk!r}"
            )
        flag_name, environment_name = target_flags[sdk]
        tc.make_args.extend([
            f"DEPLOYMENT_TARGET_CLANG_FLAG_NAME={flag_name}",
            f"DEPLOYMENT_TARGET_CLANG_ENV_NAME={environment_name}",
            f"{environment_name}={deployment_target}",
        ])
        tc.generate()

    def build(self):
        apply_conandata_patches(self)
        # Tribe seamless roaming (tribe.4): the adapter patch 0003 references TribeRoaming.swift;
        # gate the package on its unit test first (plain swiftc, host toolchain), then ship the
        # file alongside the adapter so the NE target compiles it from AWG_APPLE_SOURCE_DIR.
        # tribe.8: the version's own snapshot of the file and of its test (see _roaming_snapshots).
        roaming_swift, roaming_test = self._roaming_sources()
        self.run(f'sh "{os.path.join(self.source_folder, "tests", "run_tribe_roaming_tests.sh")}" '
                 f'"{roaming_swift}" "{roaming_test}"')
        copy(self, "TribeRoaming.swift", src=os.path.dirname(roaming_swift),
             dst=os.path.join(self.source_folder, "Sources", "WireGuardKit"), keep_path=False)
        # tribe.14: patch 0016 makes the adapter reference TribeDataWatch.swift (absent before it;
        # tribeprobe.go of patch 0012 marks the versions that have the data watch).
        # Same rule as the roaming logic: gate the package on its unit test, then ship the file
        # next to the adapter. The first released version that changes it later must freeze a
        # snapshot the way _roaming_snapshots does.
        if self._has_data_watch:
            watch_swift = os.path.join(self.source_folder, "tribe", "TribeDataWatch.swift")
            # Two binaries: the rule alone, and the rule wired to this version's own stall ladder.
            self.run(f'sh "{os.path.join(self.source_folder, "tests", "run_tribe_data_watch_tests.sh")}" '
                     f'"{watch_swift}" "{os.path.join(self.source_folder, "tests", "TribeDataWatchTests.swift")}" '
                     f'"{roaming_swift}" "{os.path.join(self.source_folder, "tests", "TribeDataWatchLadderTests.swift")}"')
            copy(self, "TribeDataWatch.swift", src=os.path.dirname(watch_swift),
                 dst=os.path.join(self.source_folder, "Sources", "WireGuardKit"), keep_path=False)
        if self._pins.get("tribe_backend_hook"):
            # tribe.12 (0015): every backend stop / pause / replace / rebind of the adapter runs the
            # optional tribeBackendWillRestart first (structure check), and the patched WireGuardKit
            # Swift typechecks for macOS and iOS against the package's own C headers.
            adapter = os.path.join(self.source_folder, "Sources", "WireGuardKit", "WireGuardAdapter.swift")
            self.run(f'sh "{os.path.join(self.source_folder, "tests", "check_backend_hook.sh")}" "{adapter}"')
            self.run(f'sh "{os.path.join(self.source_folder, "tests", "typecheck_adapter.sh")}" "{self.source_folder}"')
        # tribe.12 (0013): the shared probe engine (new package tribescan/) must exist before
        # `go mod tidy/vendor`, which vendor its imports; 0013's api-tribescan.go imports it.
        for engine_patch in self._pins.get("engine_patches", ()):
            patch(self, base_path=self.build_folder,
                  patch_file=os.path.join(self.source_folder, "patches", engine_patch))
        if self._pins.get("engine_patches"):
            copy(self, "scan_host_vectors.json", src=os.path.join(self.source_folder, "vectors"),
                 dst=os.path.join(self.build_folder, "tribescan", "testdata"))
        go_path = os.path.join(self.build_folder, ".tribe-go-path")
        go_cache = os.path.join(self.build_folder, ".tribe-go-cache")
        prep_env = Environment()
        prep_env.define("GOPATH", go_path)
        prep_env.define("GOCACHE", go_cache)
        prep_env.define("GOTOOLCHAIN", "local")
        prep_env.define("GOFLAGS", "")
        with prep_env.vars(self).apply():
            # AVPN: upstream wrapper is unchanged; ship the verified AWG fixes
            # for DisableCookies under load and UDP-window padding on every platform.
            self.run("go mod edit -require=github.com/amnezia-vpn/amneziawg-go/v3@v3.1.20260828")
            if self._pins is not self._xray_pins_default:
                # tribe.12+: our own core pin; no upstream wrapper pins it (the tidy below also
                # raises the module's `go` line to what the core requires).
                self.run("go mod edit -replace=github.com/xtls/xray-core="
                         f"github.com/amnezia-vpn/amnezia-xray-core@v{self._pins['core']}")
            self.run("go mod tidy")
            self.run("go mod vendor")
            resolved = io.StringIO()
            self.run("go list -m -f '{{.Replace.Path}}@{{.Replace.Version}}' github.com/xtls/xray-core",
                     stdout=resolved)
            expected = f"github.com/amnezia-vpn/amnezia-xray-core@v{self._pins['core']}"
            if resolved.getvalue().strip() != expected:
                raise ConanException(
                    f"xray-core resolves to {resolved.getvalue().strip()!r}, expected {expected!r}")
        for core_patch in self._pins["core_patches"]:
            patch(
                self,
                base_path=os.path.join(self.build_folder, "vendor", "github.com", "xtls", "xray-core"),
                patch_file=os.path.join(self.source_folder, "patches", core_patch),
            )
        for libxray_patch in self._pins["libxray_patches"]:
            patch(
                self,
                base_path=os.path.join(self.build_folder, "vendor", "github.com", "amnezia-vpn",
                                       "amnezia-libxray"),
                patch_file=os.path.join(self.source_folder, "patches", libxray_patch),
            )
        vendor_env = Environment()
        vendor_env.define("GOPATH", go_path)
        vendor_env.define("GOCACHE", go_cache)
        vendor_env.define("GOTOOLCHAIN", "local")
        # Define rather than append: a builder-level GOFLAGS=-mod=mod must never bypass the
        # reviewed vendored core patch in either tests or the final c-archive.
        vendor_env.define("GOFLAGS", "-mod=vendor -trimpath -buildvcs=false")
        with vendor_env.vars(self).apply():
            self.run(
                "go test -count=1 -run '^TestTribeExternalControllerErrorsArePropagated$' "
                "github.com/xtls/xray-core/transport/internet"
            )
            # Exercise the actual singleton callback slot and its RWMutex drain receipt before
            # producing any Apple archive.
            self.run(
                "go test -tags tribe_callback_test -count=1 "
                "-run '^TestTribeXraySockCallbackSlot' "
                "api-xray.go api-xray_testhelper.go api-xray_callback_test.go"
            )
            if self._pins["libxray_patches"]:
                # tribe.12 (libxray 0005): N RunXray-equivalent starts leave one FreeOSMemory loop.
                # (0006): GOGC/memory limit restored and the loop parked by StopXray or a failed
                # RunXray, so a later AWG session in the same extension keeps its own settings.
                self.run(
                    "go test -count=1 -run '^TestTribe(ForceFreeLoopStartsOnce|RestoreRuntimeAfterSession)$' "
                    "github.com/amnezia-vpn/amnezia-libxray/nodep"
                )
                self.run(
                    "go test -count=1 -run '^TestTribeXraySessionRestoresRuntime$' "
                    "github.com/amnezia-vpn/amnezia-libxray/xray"
                )
            if self._pins["tribe_stats"]:
                # tribe.12 (core 0008): the buffered first write (VLESS header + first payload) is
                # counted; (libxray 0007 + 0011): per-outbound counters of a real core against
                # known payloads, chain case, concurrent readers across start/stop, under -race.
                self.run(
                    "go test -count=1 -run '^TestTribeBufferedFlushIsCounted$' "
                    "github.com/xtls/xray-core/common/buf"
                )
                self.run(
                    "go test -race -count=1 -run '^TestTribeOutboundStats$' "
                    "github.com/amnezia-vpn/amnezia-libxray/xray"
                )
            if self._pins["tribe_http"]:
                # tribe.12 (0010): LibXrayTribeHTTP against a local SOCKS5 + local HTTPS servers.
                self.run("go test -count=1 -run '^TestTribeHTTP' tribehttp.go tribehttp_test.go")
            if self._pins.get("tribe_scan"):
                # tribe.12 (core 0011): a second core instance no longer changes how the first one
                # resolves (domainStrategy) or finds its dialerProxy hop (failed before the patch), and
                # a dial with its own socket protector never runs the process-wide controllers; a
                # scoped instance logs into its scope only, context-free lines get the terms masked.
                self.run(
                    "go test -race -count=1 "
                    "-run '^(TestTribeDialerStatePerInstance|TestTribeSocketProtectorReplacesControllers|TestTribeLogScopePerInstance|TestTribePoolsPerInstance)$' "
                    "github.com/xtls/xray-core/transport/internet"
                )
                self.run("go test -race -count=1 -run '^TestTribeLogScopeAndRedaction$' "
                         "github.com/xtls/xray-core/common/log")
                # (engine 0012): full and leg probes through real core instances against local
                # VLESS + HTTPS /v1/probe servers: every failure class, retry, cancel, deadlines,
                # memory guard, panics, leaks, DNS plan, the probe's own socket protection, the
                # tunnel's state left alone; the app's shared tribe-scan-v1 vectors when present.
                self.run("go test -race -count=1 -tags tribescan_testkit ./tribescan")
                # (0013): the C exports next to libXray's own tunnel core restarting; probe sockets
                # never reach the real LibXraySetSockCallback slot (rejecting / cleared: probes work).
                self.run(
                    "go test -race -count=1 -tags 'tribe_callback_test tribescan_testkit' "
                    "api-xray.go api-xray_testhelper.go api-tribescan.go tribescan_other.go "
                    "api-tribescan_test.go"
                )
            if self._pins.get("tribe_awg"):
                # (0014): the AmneziaWG runner against userspace nodes on 127.0.0.1 (the loopback
                # harness of awg-probe-plan §6.4: happy path through the engine, unknown key and wrong
                # H1, a live session on node A with the same key while B is probed, one session per
                # node, spacing, cancel closes the device, interface binding, S4 prime echo,
                # goroutine and fd leaks). Not under -race: amneziawg-go's own peer timer writes
                # `duration` outside its lock (device/timers.go:41) and the detector reports it.
                self.run("go test -count=1 -tags tribescan_testkit ./tribeawg")
            # tribe.11: the userspace direct split is a build gate too (absent before 0009).
            # tribe.14: api-apple.go calls into tribeprobe.go (patch 0012), so the file list of
            # this gate carries it when it exists.
            probe_go = (" tribeprobe.go tribeprobe_engine.go"
                        if os.path.exists(os.path.join(self.build_folder, "tribeprobe.go")) else "")
            if os.path.exists(os.path.join(self.build_folder, "directsplit.go")):
                self.run(
                    "go test -count=1 -run '^(TestDirect|TestForeign)' "
                    f"api-apple.go api-xray.go dnsfwd.go directsplit.go{probe_go} directsplit_test.go"
                )
            # tribe.14: the probe through the tunnel is a build gate too (absent before 0012).
            if os.path.exists(os.path.join(self.build_folder, "tribeprobe.go")):
                self.run(
                    "go test -count=1 -run '^TestTribeProbe' "
                    "dnsfwd.go tribeprobe.go tribeprobe_test.go"
                )
            autotools = Autotools(self)
            autotools.make()
            autotools.make("version-header")

    def package(self):
        copy(self, "wireguard.h", src=self.build_folder, dst=os.path.join(self.package_folder, "include"))
        # WireGuardKitC.h includes key.h and x25519.h by name; package the
        # complete public C header set so Swift bridging headers are hermetic.
        copy(self, "*.h", src=os.path.join(self.source_folder, "Sources", "WireGuardKitC"),
             dst=os.path.join(self.package_folder, "include"))
        copy(self, "*.h", src=os.path.join(self.build_folder, "out"), dst=os.path.join(self.package_folder, "include"))
        copy(self, "*.a", src=os.path.join(self.build_folder, "out"), dst=os.path.join(self.package_folder, "lib"))
        # AVPN: the app/NE compile Swift and x25519 directly.  Ship the exact
        # patched sources alongside the archive so CMake cannot silently use
        # the stale git submodule with a different parser/ABI.  WireGuardKitGo is
        # also this recipe's in-source build directory; never package its transient
        # `.tmp` Go toolchain/module cache or generated `out` tree as source input.
        copy(self, "*", src=os.path.join(self.source_folder, "Sources"),
             dst=os.path.join(self.package_folder, "src", "Sources"),
             excludes=("WireGuardKitGo/.tmp/*", "WireGuardKitGo/out/*",
                       "WireGuardKitGo/vendor/*",
                       # tribe.7: build()'s private GOPATH/GOCACHE (~1.4 GB in tribe.6) and the
                       # generator scripts are build-only state, never Swift/C source input.
                       "WireGuardKitGo/.tribe-go-path/*", "WireGuardKitGo/.tribe-go-cache/*",
                       "WireGuardKitGo/conan/*"))

    def package_info(self):
        self.cpp_info.set_property("cmake_target_name", "amnezia::awg-apple")
        self.cpp_info.libs = collect_libs(self)
        self.cpp_info.set_property("cmake_extra_variables", {
            "AWG_APPLE_SOURCE_DIR": os.path.join(self.package_folder, "src", "Sources"),
            "AWG_APPLE_ADAPTER_VERSION": self.version,
            "AWG_APPLE_UPSTREAM_VERSION": self._upstream_version,
            "AWG_APPLE_SOURCE_COMMIT": "811f5c8213e6b257e9520fff713ec4d22086e9ac",
            "AWG_APPLE_AWG_CORE_VERSION": "3.1.20260828",
            "AWG_APPLE_XRAY_ADAPTER_VERSION": "1.0.3",
            "AWG_APPLE_XRAY_SOURCE_COMMIT": "e8cc06d7427251fa549093e7cc32c28b0f5fbafa",
            "AWG_APPLE_XRAY_CORE_VERSION": self._pins["core"],
            "AWG_APPLE_GO_VERSION": self._pins["go"],
            "AWG_APPLE_XRAY_SOCKET_ABI": "awg-apple-libxray-c-v2-protect-result",
            # tribe.12+: LibXrayTribeHTTP present (README "tribe.12"); "" = absent.
            "AWG_APPLE_TRIBE_HTTP_ABI": "libxray-tribe-http-v1" if self._pins["tribe_http"] else "",
            # tribe.12+: LibXrayTribeOutboundStats present (README "tribe.12"); "" = absent.
            "AWG_APPLE_TRIBE_STATS_ABI": "libxray-tribe-stats-v1" if self._pins["tribe_stats"] else "",
            # 0013: LibXrayTribeScanMessage / LibXrayTribeScanStopAll present (README "tribe-scan"); "" = absent.
            "AWG_APPLE_TRIBE_SCAN_ABI": "libxray-tribe-scan-v1" if self._pins.get("tribe_scan") else "",
            "AWG_APPLE_ENGINE_CAPABILITIES": "awg.random_trailers;awg.disable_cookies",
            # Tribe seamless roaming (patch 0003 + TribeRoaming.swift): the NE CMake target
            # compiles TribeRoaming.swift only when the package declares it.
            "AWG_APPLE_TRIBE_ROAMING": "1",
            # tribe.14: the adapter needs TribeDataWatch.swift next to it (patch 0016).
            "AWG_APPLE_TRIBE_DATA_WATCH": "1" if os.path.exists(
                os.path.join(self.package_folder, "src", "Sources", "WireGuardKit", "TribeDataWatch.swift")) else "0",
        })
