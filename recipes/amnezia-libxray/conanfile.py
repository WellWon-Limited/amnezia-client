from conan import ConanFile
from conan.tools.files import (
    apply_conandata_patches,
    copy,
    download,
    export_conandata_patches,
    get,
    mkdir,
    patch,
    save,
)
from conan.tools.layout import basic_layout
from conan.errors import ConanException, ConanInvalidConfiguration
from conan.tools.env import Environment

import os
import stat
import hashlib
import io
import zipfile

from pathlib import Path

class AmneziaLibxray(ConanFile):
    name = "amnezia-libxray"
    # tribe.2: tribe.1 + Xray core moved to amnezia-xray-core v1.261101.0 (Go 1.27.4) with its
    # own controller-error patch, 0005 (FreeOSMemory loop started once per process) and 0006
    # (StopXray restores the Go memory settings), 0007 (in-process per-outbound counters,
    # xray.OutboundStatsJSON) with core 0008 (the buffered first write is counted), 0009 (root
    # gomobile export TribeOutboundStatsJSON + const TribeStatsABI, ABI libxray-tribe-stats-v1;
    # reserved place for the scanner exports) and 0010 (no geo data in the AAR: the core never
    # reads APK assets, the app ships the cut tribe-xray-geo pair on disk). package() refuses an
    # artifact whose sha256 differs from the lock recorded in _pins_by_version.
    # tribe.3: tribe.2 (all unchanged) + the Scanner's probe engine: shared core 0011 (per-instance
    # dialer state and the probe's own socket protector), shared engine 0012 (package tribescan, the
    # same file as awg-apple's and amnezia-xray-bindings') and 0013 (root gomobile exports
    # TribeScanMessage / TribeScanStopAll / TribeScanSetProtector + const TribeScanABI, in the place
    # 0009 reserved). Locked below; the app requires tribe.3. Rebuilding tribe.2 from this recipe:
    # set `version` back to it (its pins are unchanged; rebuilt to its lock on 2026-11-16).
    version = "1.0.3-tribe.3"
    settings = "os", "arch", "compiler"

    # Core + Go per version (absent = tribe.1: the upstream go.mod pin v1.260728.0, Go 1.26.0).
    # ndk: Pkg.BaseRevision of tools.android:ndk_path. gomobile otherwise takes the newest NDK
    # under $ANDROID_HOME/ndk, so the bytes would depend on what else is installed (tribe.1's
    # .note.android.ident says 11718014; this Mac also has 27.0.12077973). javac: the JDK
    # major that compiles classes.jar (tribe.1's locked jar is javac 21 output; the app and CI
    # build Android with JDK 17, so tribe.2 is locked on 17).
    _pins_default = {
        "go": "1.26.0",
        "core": "1.260728.0",
        "core_patches": ("0004-xray-core-controller-errors.patch",),
        "ndk": "27.0.11718014",
        "javac": 21,
        "embedded_geo": True,
        "tribe_stats": False,
        "tribe_scan": False,
        "artifact_sha256": "3bc7786bc21db0a5af66a268ab9ab34ad1158ad0fbd8cc63d2b9513eabf4984c",
    }
    _pins_by_version = {
        "1.0.3-tribe.2": {
            "go": "1.27.4",
            "core": "1.261101.0",
            "core_patches": ("0004-xray-core-261101-controller-errors.patch",
                             "0008-xray-core-261101-counted-buffered-flush.patch"),
            "ndk": "27.0.11718014",
            "javac": 17,
            "embedded_geo": False,
            "tribe_stats": True,
            "tribe_scan": False,
            # Clean Conan homes at different paths, built in parallel, JDK 17 and NDK
            # 27.0.11718014, gave these bytes three times (2026-11-16).
            "artifact_sha256": "df35c00cb5fa4478cbcc323b153dc31b0c1af68b1ab62b6c4c1a6310c4478deb",
        },
        "1.0.3-tribe.3": {
            "go": "1.27.4",
            "core": "1.261101.0",
            "core_patches": ("0004-xray-core-261101-controller-errors.patch",
                             "0008-xray-core-261101-counted-buffered-flush.patch",
                             "0011-xray-core-261101-instance-dialer-state.patch"),
            "ndk": "27.0.11718014",
            "javac": 17,
            "embedded_geo": False,
            "tribe_stats": True,
            "tribe_scan": True,
            # Two clean Conan homes at different paths, built one after the other, JDK 17 and NDK
            # 27.0.11718014, gave these bytes (2026-11-16, engine 0012 of feat/scan-probe 8e4175f1b:
            # deadline verdict, leg slot after close, stop-vs-start epoch, stop reply counts, fake
            # fixtures, a stop ends only its host epoch and older, admission never measures memory
            # while an instance closes).
            "artifact_sha256": "008d5649ea498a053bcad36b9596d4f8b56d9023f378dc5d7acbf61df927eeba",
        },
    }
    # Every ABI gomobile emits; the app's deploy/build.sh ships the same four.
    _android_abis = ("arm64-v8a", "armeabi-v7a", "x86", "x86_64")

    @property
    def _pins(self):
        return self._pins_by_version.get(str(self.version), self._pins_default)

    _upstream_version = "1.0.3"
    _geosite_release = "20260827152101"
    _geosite_sha256 = "ba1adf51d4d724abbc157c53234a02bda00c94cdb8211709682e51a6855520b7"
    _geoip_release = "202608050239"
    _geoip_sha256 = "c67bd077eb102cec74fab759b73d17f99275f56af10a87c14d9fd983508f5ce1"
    # Release time of the newer pinned data set (domain-list-community), not build time.
    _geo_data_epoch = "1787844067"
    # Artifact lock per version (_pins["artifact_sha256"]): tribe.1 was rebuilt from the
    # controller-slot/core patches in independent clean Conan homes and compared byte-for-byte
    # before its lock was recorded.  The release-packaged per-ABI hashes are a separate Gradle gate.

    def export_sources(self):
        export_conandata_patches(self)
        # The app's shared tribe-scan-v1 vectors (client/core/serviceEngine/tests/vectors), replayed by
        # tribescan's TestTribeScanSharedVectors; absent in a tree without them (the test then skips).
        copy(self, "scan_host_vectors.json",
             src=os.path.join(self.recipe_folder, "..", "..", "client", "core", "serviceEngine", "tests", "vectors"),
             dst=os.path.join(self.export_sources_folder, "vectors"))
        for core_patch in self._pins["core_patches"]:
            copy(
                self,
                core_patch,
                src=os.path.join(self.recipe_folder, "patches"),
                dst=os.path.join(self.export_sources_folder, "patches"),
            )

    def configure(self):
        self.settings.rm_safe("compiler.libcxx")
        self.settings.rm_safe("compiler.cppstd")

    def package_id(self):
        # gomobile always emits one AAR containing the complete four-ABI
        # matrix at the recipe-pinned Android API level.  Host arch/compiler
        # and the consumer API level therefore do not describe this package;
        # retaining them would rebuild the same locked bytes four times.
        self.info.settings.rm_safe("arch")
        self.info.settings.rm_safe("compiler")
        self.info.settings.rm_safe("os.api_level")

    def layout(self):
        basic_layout(self, build_folder=".")

    def build_requirements(self):
        self.tool_requires(f"go/{self._pins['go']}")
    
    def validate(self):
        if self.settings.os != "Android":
            raise ConanInvalidConfiguration(f"{self.name} v{self.version} does not support {self.settings.os}")

    def source(self):
        get(self, f"https://github.com/amnezia-vpn/amnezia-libxray/archive/refs/tags/v{self._upstream_version}.zip",
            sha256="3b1194c2a76e73913fdae49983c40a219c45a164ebdae72ef1297469348de730", strip_root=True
        )
        if not self._pins["embedded_geo"]:
            # tribe.2+ (0010): the AAR carries no geo data, so the full pair is not fetched.
            return
        data_dir = os.path.join(self.source_folder, "dat")
        mkdir(self, data_dir)
        download(
            self,
            f"https://github.com/v2fly/domain-list-community/releases/download/"
            f"{self._geosite_release}/dlc.dat",
            os.path.join(data_dir, "geosite.dat"),
            sha256=self._geosite_sha256,
        )
        download(
            self,
            f"https://github.com/v2fly/geoip/releases/download/"
            f"{self._geoip_release}/geoip.dat",
            os.path.join(data_dir, "geoip.dat"),
            sha256=self._geoip_sha256,
        )
        save(self, os.path.join(data_dir, "timestamp.txt"), self._geo_data_epoch)

    def generate(self):
        env = Environment()
        ndk_path_str = self.conf.get("tools.android:ndk_path")
        if not ndk_path_str:
            raise ConanException(
                f"{self.name}: tools.android:ndk_path is required (NDK {self._pins['ndk']})")
        ndk_path = Path(ndk_path_str)
        ndk_revision = None
        properties = ndk_path / "source.properties"
        if properties.is_file():
            for line in properties.read_text(encoding="utf-8").splitlines():
                key, _, value = line.partition("=")
                if key.strip() == "Pkg.BaseRevision":
                    ndk_revision = value.strip()
        if ndk_revision != self._pins["ndk"]:
            raise ConanException(
                f"{self.name}/{self.version} is locked to NDK {self._pins['ndk']}; "
                f"tools.android:ndk_path={ndk_path_str} is {ndk_revision!r}")
        if len(ndk_path.parts) > 2:
            sdk_path = ndk_path.parents[1]
            env.define("ANDROID_HOME", str(sdk_path))
        # gomobile prefers ANDROID_NDK_HOME over the newest NDK under $ANDROID_HOME/ndk.
        env.define("ANDROID_NDK_HOME", str(ndk_path))
        env.vars(self).save_script("conan_provide_androidhome")

    def _patch_sources(self):
        apply_conandata_patches(self)
        build_path = os.path.join(self.build_folder, "build.sh")
        build_stat = os.stat(build_path)
        os.chmod(build_path, build_stat.st_mode | stat.S_IEXEC)

    def _javac_bin(self):
        # gomobile compiles classes.jar with whatever `javac` is first on PATH, and the bytes
        # differ between majors (javac 21 adds a MethodParameters attribute to the anonymous
        # class in go/Seq$GoRefQueue$1 that javac 17 does not). JAVA_HOME, when set, goes first
        # on PATH for build.sh; the major must be the version's pin.
        java_home = os.environ.get("JAVA_HOME")
        javac_bin = os.path.join(java_home, "bin") if java_home else None
        javac = os.path.join(javac_bin, "javac") if javac_bin else "javac"
        version = io.StringIO()
        self.run(f'"{javac}" -version', stdout=version, stderr=version)
        words = version.getvalue().split()
        major = None
        if len(words) >= 2 and words[0] == "javac":
            major = words[1].split(".")[0]
        if major != str(self._pins["javac"]):
            raise ConanException(
                f"{self.name}/{self.version} is locked to javac {self._pins['javac']}; "
                f"{javac} is {version.getvalue().strip()!r} (set JAVA_HOME to a JDK "
                f"{self._pins['javac']})")
        return javac_bin

    def build(self):
        javac_bin = self._javac_bin()
        self._patch_sources()
        # The pinned Xray core currently logs and ignores dial/listener controller errors.
        # Vendor the go.sum-locked graph, apply the narrow propagation patch, and prove both
        # the wrapper slot and patched core before gomobile sees the sources.
        go_path = os.path.join(self.build_folder, ".tribe-go-path")
        go_cache = os.path.join(self.build_folder, ".tribe-go-cache")
        prep_env = Environment()
        prep_env.define("GOPATH", go_path)
        prep_env.define("GOCACHE", go_cache)
        prep_env.define("GOFLAGS", "")
        prep_env.define("GOTOOLCHAIN", "local")
        with prep_env.vars(self).apply():
            if self._pins is not self._pins_default:
                # tribe.2+: our own core pin (upstream libxray v1.0.3 pins v1.260728.0).
                self.run("go mod edit -replace=github.com/xtls/xray-core="
                         f"github.com/amnezia-vpn/amnezia-xray-core@v{self._pins['core']}")
            self.run("go mod tidy")
            self.run("go mod vendor")
            # gomobile creates its own temporary module and therefore cannot
            # run globally under ``-mod=vendor``.  Turn the exact vendored,
            # subsequently patched Xray tree into a local module replacement;
            # gomobile may then use normal module mode without ever escaping
            # to the unpatched upstream core.
            xray_modules = list(
                (Path(go_path) / "pkg" / "mod" / "github.com" / "amnezia-vpn").glob(
                    f"amnezia-xray-core@v{self._pins['core']}"
                )
            )
            if len(xray_modules) != 1:
                raise ConanException(
                    "expected exactly one pinned amnezia-xray-core module, "
                    f"found {len(xray_modules)}"
                )
            local_xray_core = Path(self.build_folder) / "vendor" / "github.com" / "xtls" / "xray-core"
            for module_file in ("go.mod", "go.sum"):
                copy(
                    self,
                    module_file,
                    src=str(xray_modules[0]),
                    dst=str(local_xray_core),
                    keep_path=False,
                )
        for core_patch in self._pins["core_patches"]:
            patch(
                self,
                base_path=os.path.join(self.source_folder, "vendor", "github.com", "xtls", "xray-core"),
                patch_file=os.path.join(self.source_folder, "patches", core_patch),
            )
        vendor_env = Environment()
        vendor_env.define("GOPATH", go_path)
        vendor_env.define("GOCACHE", go_cache)
        vendor_env.define("GOFLAGS", "-mod=vendor -trimpath -buildvcs=false")
        vendor_env.define("GOTOOLCHAIN", "local")
        with vendor_env.vars(self).apply():
            self.run("go test -count=1 -run '^TestTribeAndroidControllerSlot' .")
            if os.path.exists(os.path.join(self.source_folder, "nodep", "memory_tribe_test.go")):
                # tribe.2 (0005): N RunXray-equivalent starts leave one FreeOSMemory loop;
                # (0006): StopXray / a failed RunXray restore GOGC and the memory limit.
                self.run("go test -count=1 -run "
                         "'^TestTribe(ForceFreeLoopStartsOnce|RestoreRuntimeAfterSession)$' ./nodep")
                self.run("go test -count=1 -run '^TestTribeXraySessionRestoresRuntime$' ./xray")
            if os.path.exists(os.path.join(self.source_folder, "xray", "stats_tribe_test.go")):
                # tribe.2 (0007 + core 0008): per-outbound counters of a real core, under -race.
                self.run("go test -count=1 -run '^TestTribeBufferedFlushIsCounted$' "
                         "github.com/xtls/xray-core/common/buf")
                self.run("go test -race -count=1 -run '^TestTribeOutboundStats$' ./xray")
            if self._pins["tribe_stats"]:
                # tribe.2 (0009): the root export Kotlin calls reads the instance the root
                # RunXray started, with the protect callback armed; idle/stopped JSON frozen.
                self.run("go test -count=1 -run '^TestTribeRootExports$' .")
            if self._pins["tribe_scan"]:
                # tribe.3 (core 0011 + engine 0012 + 0013): a second core instance no longer changes
                # how the first one dials, probe sockets run only their own protector, probe instances
                # log into their own scope (context-free lines masked); full and leg
                # probes through real core instances (and the app's vectors when present); the root
                # exports: probe protector required, the tunnel's protect slot never called.
                copy(self, "scan_host_vectors.json", src=os.path.join(self.source_folder, "vectors"),
                     dst=os.path.join(self.source_folder, "tribescan", "testdata"))
                self.run("go test -race -count=1 "
                         "-run '^(TestTribeDialerStatePerInstance|TestTribeSocketProtectorReplacesControllers|TestTribeLogScopePerInstance|TestTribePoolsPerInstance)$' "
                         "github.com/xtls/xray-core/transport/internet")
                self.run("go test -race -count=1 -run '^TestTribeLogScopeAndRedaction$' "
                         "github.com/xtls/xray-core/common/log")
                self.run("go test -race -count=1 -tags tribescan_testkit ./tribescan")
                self.run("go test -race -count=1 -tags tribescan_testkit -run '^TestTribeScanAndroidExport$' .")
            self.run(
                "go test -count=1 -run '^TestTribeExternalControllerErrorsArePropagated$' "
                "github.com/xtls/xray-core/transport/internet"
            )

        self.run(
            "go mod edit "
            "-replace=github.com/xtls/xray-core=./vendor/github.com/xtls/xray-core"
        )
        gomobile_env = Environment()
        gomobile_env.define("GOPATH", go_path)
        gomobile_env.define("GOCACHE", go_cache)
        gomobile_env.define("GOFLAGS", "-mod=mod -trimpath -buildvcs=false")
        gomobile_env.define("GOTOOLCHAIN", "local")
        if javac_bin:
            gomobile_env.prepend_path("PATH", javac_bin)
        with gomobile_env.vars(self).apply():
            replacement = io.StringIO()
            self.run(
                "go list -m -f '{{.Replace.Dir}}' github.com/xtls/xray-core",
                stdout=replacement,
            )
            resolved = replacement.getvalue().strip()
            if Path(resolved).resolve() != local_xray_core.resolve():
                raise ConanException("gomobile graph escaped the patched local Xray core")
            self.run(
                "go test -count=1 -run '^TestTribeExternalControllerErrorsArePropagated$' "
                "github.com/xtls/xray-core/transport/internet"
            )
            self.run("./build.sh android")
        self._check_aar(os.path.join(self.build_folder, "libxray.aar"))

    def _check_aar(self, artifact):
        # The AAR's shape: four ABIs, the bound root class, the Tribe exports the version
        # declares, and geo data only where the version embeds it.
        with zipfile.ZipFile(artifact) as aar:
            names = set(aar.namelist())
            missing = [f"jni/{abi}/libgojni.so" for abi in self._android_abis
                       if f"jni/{abi}/libgojni.so" not in names]
            if missing or "classes.jar" not in names:
                raise ConanException(f"libxray.aar lacks {missing or ['classes.jar']}")
            geo = sorted(n for n in names if n.startswith("assets/"))
            if self._pins["embedded_geo"] != bool(geo):
                raise ConanException(f"libxray.aar geo assets {geo} contradict embedded_geo")
            with zipfile.ZipFile(io.BytesIO(aar.read("classes.jar"))) as jar:
                bound = jar.read("org/amnezia/vpn/protocol/xray/libXray/LibXray.class")
        expected = [b"runXray", b"stopXray", b"registerSocketControllers", b"clearSocketControllers"]
        if self._pins["tribe_stats"]:
            expected += [b"tribeOutboundStatsJSON", b"TribeStatsABI", b"libxray-tribe-stats-v1"]
        if self._pins.get("tribe_scan"):
            expected += [b"tribeScanMessage", b"tribeScanStopAll", b"tribeScanSetProtector", b"TribeScanABI",
                         b"libxray-tribe-scan-v1"]
        absent = [name.decode() for name in expected if name not in bound]
        if absent:
            raise ConanException(f"LibXray.class does not bind {absent}")

    def package(self):
        copy(self, "libxray.aar", src=self.build_folder, dst=os.path.join(self.package_folder, "aar"))
        artifact = os.path.join(self.package_folder, "aar", "libxray.aar")
        with open(artifact, "rb") as handle:
            digest = hashlib.sha256(handle.read()).hexdigest()
        locked = self._pins["artifact_sha256"]
        if locked is None:
            raise ConanException(
                f"amnezia-libxray/{self.version} artifact lock is pending: "
                f"candidate universal AAR SHA-256 is {digest}; do not release"
            )
        if digest != locked:
            raise ConanException(
                "amnezia-libxray Android artifact reproducibility drift: "
                f"expected {locked}, got {digest}"
            )
        save(self, os.path.join(self.package_folder, "aar", "libxray.aar.sha256"), digest + "\n")

    def package_info(self):
        artifact = os.path.join(self.package_folder, "aar", "libxray.aar")
        digest_file = artifact + ".sha256"
        with open(digest_file, "r", encoding="ascii") as handle:
            artifact_sha256 = handle.read().strip()
        self.cpp_info.set_property("cmake_extra_variables", {
            "AMNEZIA_LIBXRAY_PATH": artifact,
            "AMNEZIA_LIBXRAY_ARTIFACT_SHA256": artifact_sha256,
            "AMNEZIA_LIBXRAY_ADAPTER_VERSION": self.version,
            "AMNEZIA_LIBXRAY_SOURCE_COMMIT": "e8cc06d7427251fa549093e7cc32c28b0f5fbafa",
            "AMNEZIA_LIBXRAY_CORE_VERSION": self._pins["core"],
            "AMNEZIA_LIBXRAY_GO_VERSION": self._pins["go"],
            "AMNEZIA_LIBXRAY_ABI": "gomobile-libxray-v2-controller-slot",
            # tribe.2+: LibXray.tribeOutboundStatsJSON() present (0009); "" = absent.
            "AMNEZIA_LIBXRAY_TRIBE_STATS_ABI":
                "libxray-tribe-stats-v1" if self._pins["tribe_stats"] else "",
            # tribe.3+: TribeScanMessage / TribeScanStopAll / TribeScanSetProtector (0013); "" = absent.
            "AMNEZIA_LIBXRAY_TRIBE_SCAN_ABI":
                "libxray-tribe-scan-v1" if self._pins.get("tribe_scan") else "",
            # "0" (tribe.2+): no assets/geo in the AAR; the app must ship tribe-xray-geo.
            "AMNEZIA_LIBXRAY_GEO_EMBEDDED": "1" if self._pins["embedded_geo"] else "0",
        })
