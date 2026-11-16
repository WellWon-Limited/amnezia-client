from conan import ConanFile
from conan.tools.files import (
    apply_conandata_patches,
    chdir,
    collect_libs,
    copy,
    export_conandata_patches,
    get,
    patch,
    rename,
)
from conan.tools.layout import basic_layout
from conan.errors import ConanException, ConanInvalidConfiguration
from conan.tools.gnu import Autotools, AutotoolsToolchain
from conan.tools.apple import XCRun, is_apple_os
from conan.tools.apple.apple import _to_apple_arch
from conan.tools.env import Environment

import io
import os
import shlex
import shutil
import stat


class AmneziaXrayBindings(ConanFile):
    name = "amnezia-xray-bindings"
    # AVPN: tribe.1 = upstream v1.4.0 sources with the Xray core moved from the upstream pin
    # (amnezia-xray-core v1.260728.0) to v1.261101.0 by a `go mod edit -replace` in build(); no
    # source patch. Built with Go 1.27.4 (the new core declares `go 1.27`). Upstream v1.5.0 still
    # pins 260728, so there is no upstream tag to move to.
    # tribe.1 (unreleased) also carries the Scanner's probe engine: 0001 (C exports
    # amnezia_xray_scan_message / amnezia_xray_scan_stop_all, ABI libxray-tribe-scan-v1), the shared engine
    # ../amnezia-libxray/patches/0012-tribe-scan-engine.patch (package tribescan) and core 0011
    # (per-instance dialer state and the probe's own socket protector, applied to a local copy of the
    # pinned core that replaces it).
    version = "1.4.0-tribe.1"
    settings = "os", "arch", "compiler"

    _upstream_version = "1.4.0"
    _xray_core_version = "1.261101.0"
    _go_version = "1.27.4"
    # Shared with awg-apple / amnezia-libxray (../amnezia-libxray/patches).
    _core_patches = ("0011-xray-core-261101-instance-dialer-state.patch",)
    _engine_patches = ("0012-tribe-scan-engine.patch",)
    _local_core = "tribe-xray-core"

    _arch_map = {
        "x86": "386",
        "x86_64": "amd64",
        "armv8": "arm64"
    }

    @property
    def _goos(self):
        return {
            "Linux": "linux",
            "iOS": "ios",
            "Macos": "darwin",
            "Windows": "windows"
        }.get(str(self.settings.os))

    @property
    def _archs(self):
        return str(self.settings.arch).split("|")

    @property
    def _is_multiarch(self):
        return len(self._archs) > 1

    @property
    def _is_windows(self):
        return str(self.settings.os).startswith("Windows")

    def export_sources(self):
        export_conandata_patches(self)
        # The app's shared tribe-scan-v1 vectors (client/core/serviceEngine/tests/vectors), replayed by
        # tribescan's TestTribeScanSharedVectors; absent in a tree without them (the test then skips).
        copy(self, "scan_host_vectors.json",
             src=os.path.join(self.recipe_folder, "..", "..", "client", "core", "serviceEngine", "tests", "vectors"),
             dst=os.path.join(self.export_sources_folder, "vectors"))
        for shared in self._core_patches + self._engine_patches:
            copy(self, shared, src=os.path.join(self.recipe_folder, "..", "amnezia-libxray", "patches"),
                 dst=os.path.join(self.export_sources_folder, "patches"))

    def config_options(self):
        self.package_type = "shared-library" if self._is_windows else "static-library"

    def configure(self):
        self.settings.rm_safe("compiler.libcxx")
        self.settings.rm_safe("compiler.cppstd")
        if self._is_windows:
            # mingw-builds is being used on Windows
            del self.settings.compiler

    def layout(self):
        basic_layout(self)

    def build_requirements(self):
        self.tool_requires(f"go/{self._go_version}")
        if self._is_windows:
            self.win_bash = True
            if not self.conf.get("tools.microsoft.bash:path", check_type=str):
                self.tool_requires("msys2/cci.latest")
            self.tool_requires("mingw-builds/15.1.0")

    def validate(self):
        if not self._goos or not all(arch in self._arch_map for arch in self._archs):
            raise ConanInvalidConfiguration(
                f"{self.name} v{self.version} does not support {self.settings.os} {self.settings.arch}"
            )

        if self._is_multiarch and not is_apple_os(self):
            raise ConanInvalidConfiguration(
                f"{self.name} v{self.version} does not support multiarch builds"
            )

    def source(self):
        get(self, f"https://github.com/amnezia-vpn/amnezia-xray-bindings/archive/refs/tags/v{self._upstream_version}.zip",
            sha256="8977896bba99f1a3bad61d734b2929ec3d01c3ca0e206ee8ce5eb013d38ab118", strip_root=True)

    def generate(self):
        tc = AutotoolsToolchain(self)
        tc.apple_arch_flag = None
        env = tc.environment()
        env.define("GOPATH", os.path.join(self.build_folder, "gopath"))
        env.define("GOMODCACHE", os.path.join(self.build_folder, "gopath", "pkg", "mod"))
        env.define("GOCACHE", os.path.join(self.build_folder, "gocache"))
        env.define("GOOS", self._goos)
        if self._is_windows:
            env.define("OS", "windows")
        self._ldflags = tc.ldflags
        self._cflags = tc.cflags
        tc.generate(env)

    def _pin_core(self):
        env = Environment()
        env.define("GOFLAGS", "")
        env.define("GOTOOLCHAIN", "local")
        with env.vars(self).apply():
            self.run("go mod edit -replace=github.com/xtls/xray-core="
                     f"github.com/amnezia-vpn/amnezia-xray-core@v{self._xray_core_version}")
            # `go get .`, not `go mod tidy`: GOPATH (generate()) lives inside the module root,
            # and tidy would walk the module cache as packages of this module.
            self.run("go get .")
            resolved = io.StringIO()
            self.run("go list -m -f '{{.Replace.Path}}@{{.Replace.Version}}' github.com/xtls/xray-core",
                     stdout=resolved)
        expected = f"github.com/amnezia-vpn/amnezia-xray-core@v{self._xray_core_version}"
        if resolved.getvalue().strip() != expected:
            raise ConanException(
                f"xray-core resolves to {resolved.getvalue().strip()!r}, expected {expected!r}")

    def _patch_core_locally(self):
        """Copy the pinned core out of the module cache, apply the core patches to the copy and
        replace the module with it (module mode; no vendor tree)."""
        env = Environment()
        env.define("GOFLAGS", "")
        env.define("GOTOOLCHAIN", "local")
        with env.vars(self).apply():
            pinned = io.StringIO()
            self.run("go list -m -f '{{.Dir}}' github.com/xtls/xray-core", stdout=pinned)
            local = os.path.join(self.source_folder, self._local_core)
            if os.path.exists(local):
                shutil.rmtree(local)
            shutil.copytree(pinned.getvalue().strip(), local)
            for root, dirs, files in os.walk(local):
                for name in dirs + files:
                    path = os.path.join(root, name)
                    os.chmod(path, os.stat(path).st_mode | stat.S_IWUSR)
            for core_patch in self._core_patches:
                patch(self, base_path=local, patch_file=os.path.join(self.source_folder, "patches", core_patch))
            self.run(f"go mod edit -replace=github.com/xtls/xray-core=./{self._local_core}")
            self.run("go get .")
            resolved = io.StringIO()
            self.run("go list -m -f '{{.Replace.Path}}' github.com/xtls/xray-core", stdout=resolved)
        if resolved.getvalue().strip() != f"./{self._local_core}":
            raise ConanException(f"xray-core is not the patched local copy: {resolved.getvalue().strip()!r}")

    def _gates(self):
        env = Environment()
        env.define("GOFLAGS", "")
        env.define("GOTOOLCHAIN", "local")
        env.define("GOOS", "")  # host tests
        env.define("CGO_ENABLED", "1")
        with env.vars(self).apply():
            # core 0011: a second core instance no longer changes how the first one dials, and probe
            # sockets run only their own protector.
            self.run("go test -race -count=1 "
                     "-run '^(TestTribeDialerStatePerInstance|TestTribeSocketProtectorReplacesControllers|TestTribeLogScopePerInstance|TestTribePoolsPerInstance)$' "
                     "github.com/xtls/xray-core/transport/internet")
            # core 0011: a scoped instance logs into its scope only; context-free lines are masked.
            self.run("go test -race -count=1 -run '^TestTribeLogScopeAndRedaction$' "
                     "github.com/xtls/xray-core/common/log")
            # engine 0012 and the exports of 0001 next to a restarting singleton core.
            self.run("go test -race -count=1 -tags tribescan_testkit ./tribescan")
            self.run("go test -race -count=1 -tags tribescan_testkit -run '^TestTribeScan(BindingsExport|BindingsAwgChild|StopAllHungChild)$' .")

    def build(self):
        with chdir(self, self.source_folder):
            apply_conandata_patches(self)
            for engine_patch in self._engine_patches:
                patch(self, base_path=self.source_folder,
                      patch_file=os.path.join(self.source_folder, "patches", engine_patch))
            copy(self, "scan_host_vectors.json", src=os.path.join(self.source_folder, "vectors"),
                 dst=os.path.join(self.source_folder, "tribescan", "testdata"))
            self._pin_core()
            self._patch_core_locally()
            if not self._is_windows and str(self.settings.os) == str(self._host_os()):
                self._gates()
            for arch in self._archs:
                build_dir = os.path.join(self.build_folder, arch) if self._is_multiarch else self.build_folder
                goarch = self._arch_map.get(arch)

                cflags = list(self._cflags)
                ldflags = list(self._ldflags)
                if is_apple_os(self):
                    cflags.append(f"-arch {_to_apple_arch(arch)}")
                    ldflags.append(f"-arch {_to_apple_arch(arch)}")

                env = Environment()
                env.define("ARCH", goarch)
                env.define("CGO_CFLAGS", " ".join(cflags))
                env.define("CGO_LDFLAGS", " ".join(ldflags))
                with env.vars(self).apply():
                    at = Autotools(self)
                    make_build_dir = build_dir.replace("\\", "/") if self._is_windows else build_dir
                    at.make(args=[
                        f"BUILD_DIR={make_build_dir}"
                    ])

            if is_apple_os(self) and self._is_multiarch:
                lipo = XCRun(self).find('lipo')
                archives = [os.path.join(self.build_folder, arch, "amnezia_xray.a") for arch in self._archs]
                output = os.path.join(self.build_folder, "amnezia_xray.a")
                self.run("{} -create -output {} {}".format(
                    shlex.quote(lipo),
                    shlex.quote(output),
                    shlex.join(archives)
                ))

                copy(self, "*.h", os.path.join(self.build_folder, self._archs[0]), self.build_folder)

    def _host_os(self):
        import platform
        return {"Darwin": "Macos", "Linux": "Linux", "Windows": "Windows"}.get(platform.system(), "")

    def _rename_header(self):
        if not self._is_windows:
            rename(self,
                os.path.join(self.package_folder, "lib", "amnezia_xray.a"),
                os.path.join(self.package_folder, "lib", "libamnezia_xray.a")
            )

    def package(self):
        copy(self, "amnezia_xray.h", src=self.build_folder, dst=os.path.join(self.package_folder, "include"), keep_path=False)
        copy(self, "amnezia_xray.a", src=self.build_folder, dst=os.path.join(self.package_folder, "lib"), keep_path=False)
        copy(self, "amnezia_xray.lib", src=self.build_folder, dst=os.path.join(self.package_folder, "lib"), keep_path=False)
        copy(self, "amnezia_xray.dll", src=self.build_folder, dst=os.path.join(self.package_folder, "bin"), keep_path=False)
        self._rename_header()

    def package_info(self):
        self.cpp_info.set_property("cmake_target_name", "amnezia::xray-bindings")
        self.cpp_info.set_property("cmake_extra_variables", {
            # amnezia_xray_scan_message / amnezia_xray_scan_stop_all (patch 0001, recipes/amnezia-xray-bindings/README.md).
            "AMNEZIA_XRAY_BINDINGS_TRIBE_SCAN_ABI": "libxray-tribe-scan-v1",
            "AMNEZIA_XRAY_BINDINGS_UPSTREAM_VERSION": self._upstream_version,
            "AMNEZIA_XRAY_BINDINGS_CORE_VERSION": self._xray_core_version,
            "AMNEZIA_XRAY_BINDINGS_GO_VERSION": self._go_version,
        })
        self.cpp_info.libs = collect_libs(self)
