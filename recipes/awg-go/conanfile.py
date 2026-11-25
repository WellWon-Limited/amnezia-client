from conan import ConanFile
from conan.errors import ConanInvalidConfiguration
from conan.tools.layout import basic_layout
from conan.tools.files import get, chdir, save, patch
from conan.tools.apple import XCRun
from conan.tools.gnu import Autotools, AutotoolsToolchain
from conan.tools.apple import is_apple_os
from conan.tools.apple.apple import _to_apple_arch
from conan.tools.env import Environment

import os
import shlex


class AwgGo(ConanFile):
    name = "awg-go"
    version = "3.1.20261116"
    package_type = "application"
    settings = "os", "arch"
    # AVPN tribe_probe: `amneziawg-go probe`, the Scanner's AmneziaWG mini-session for the service's
    # probe engine (patches/0001-tribe-probe-subcommand.patch; protocol tribe-awg-probe-v1). Off by
    # default: the shipped daemon stays byte-identical until the service lane turns it on. With it the
    # binary also links gVisor's netstack (about +5 MB on macOS arm64).
    options = {"tribe_probe": [True, False]}
    default_options = {"tribe_probe": False}
    exports_sources = "patches/*"

    _binary_name = "amneziawg-go"

    _arch_map = {
        "x86": "386",
        "x86_64": "amd64",
        "armv8": "arm64"
    }

    @property
    def _goos(self):
        return {
            "Linux": "linux",
            "Macos": "darwin",
            "Windows": "windows"
        }.get(str(self.settings.os))

    @property
    def _archs(self):
        return str(self.settings.arch).split("|")
    
    @property
    def _is_multiarch(self):
        return len(self._archs) > 1

    def layout(self):
        basic_layout(self, build_folder=".")

    def build_requirements(self):
        self.tool_requires("go/1.26.0")

    def config_options(self):
        if self.settings.os == "Windows":
            del self.options.tribe_probe  # the probe needs a per-socket interface binding

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
        get(self, f"https://github.com/amnezia-vpn/amneziawg-go/archive/refs/tags/v{self.version}.zip",
            sha256="a3c565f66075201aded8e3e331be7630d525db2518e28a31eb5301a23ebd33c1", strip_root=True
        )

    def generate(self):
        tc = AutotoolsToolchain(self)
        tc.apple_arch_flag = None
        env = tc.environment()
        env.define("GOPATH", os.path.join(self.build_folder, "gopath"))
        env.define("GOMODCACHE", os.path.join(self.build_folder, "gopath", "pkg", "mod"))
        env.define("GOCACHE", os.path.join(self.build_folder, "gocache"))
        env.define("GOTELEMETRY", "off")
        # Reproducible release binaries must not retain Conan's per-user Go
        # toolchain/module cache paths or a volatile linker build id.
        env.define("GOFLAGS", "-trimpath -buildvcs=false -ldflags=-buildid=")
        env.define("GOOS", self._goos)
        self._ldflags = tc.ldflags
        self._cflags = tc.cflags
        tc.generate(env)

    def build(self):
        # GitHub release archives intentionally contain no .git directory.  Upstream's
        # Makefile therefore cannot derive the release tag with `git describe` and silently
        # keeps the stale version.go shipped in the archive (v3.1.20260814 currently reports
        # 0.0.20250522).  Runtime identity must describe the bytes we actually package, so make
        # the immutable Conan version authoritative before invoking the upstream build.
        save(
            self,
            os.path.join(self.source_folder, "version.go"),
            f'package main\n\nconst Version = "{self.version}"\n',
        )
        tribe_probe = bool(self.options.get_safe("tribe_probe"))
        if tribe_probe:
            patch(self, base_path=self.source_folder,
                  patch_file=os.path.join(self.source_folder, "patches", "0001-tribe-probe-subcommand.patch"))
        with chdir(self, self.source_folder):
            if tribe_probe:
                # The probe against a userspace node on 127.0.0.1 (handshake, prime echo, 64 KiB
                # over TLS through the tunnel, unknown key, bad job, impossible binding), native
                # architecture only.
                test_env = Environment()
                test_env.define("GOARCH", "")
                test_env.define("CGO_ENABLED", "1")
                with test_env.vars(self).apply():
                    self.run("go test -count=1 -run '^TestTribeProbe$' .")
            for arch in self._archs:
                goarch = self._arch_map.get(arch)

                ldflags = list(self._ldflags)
                cflags = list(self._cflags)
                if is_apple_os(self):
                    ldflags.append(f"-arch {_to_apple_arch(arch)}")
                    cflags.append(f"-arch {_to_apple_arch(arch)}")
                    for build_root in (self.source_folder, self.build_folder):
                        cflags.extend([
                            f"-ffile-prefix-map={build_root}=.",
                            f"-fdebug-prefix-map={build_root}=.",
                            f"-fmacro-prefix-map={build_root}=.",
                        ])

                env = Environment()
                env.define("GOARCH", goarch)
                env.define("CGO_LDFLAGS", " ".join(ldflags))
                env.define("CGO_CFLAGS", " ".join(cflags))
                with env.vars(self).apply():
                    at = Autotools(self)
                    at.make()
                    if self._is_multiarch:
                        os.rename(
                            os.path.join(self.source_folder, self._binary_name),
                            os.path.join(self.source_folder, f"{self._binary_name}-{arch}")
                        )

            if is_apple_os(self) and self._is_multiarch:
                lipo = XCRun(self).find("lipo")
                output = os.path.join(self.build_folder, self._binary_name)
                binaries = [os.path.join(self.build_folder, f"{self._binary_name}-{arch}") for arch in self._archs]
                self.run("{} -create -output {} {}".format(
                    shlex.quote(lipo),
                    shlex.quote(output),
                    shlex.join(binaries)
                ))

    def package(self):
        with chdir(self, self.source_folder):
            at = Autotools(self)
            at.make("install", args=[
                f"BINDIR={self.package_folder}",
            ])

    def package_info(self):
        self.cpp_info.exe = True
        self.cpp_info.location = os.path.join(self.package_folder, self._binary_name)
        self.cpp_info.set_property("cmake_target_name", "amnezia::awg-go")
        self.cpp_info.set_property("cmake_extra_variables", {
            "AWG_GO_ENGINE_VERSION": self.version,
            # The tag commit of self.version (proxy.golang.org Origin.Hash); 0828's label named a commit two
            # before its tag.
            "AWG_GO_SOURCE_COMMIT": "08fe3d33bbb116be09a6183d02609311b8b0c9e8",
            "AWG_GO_UAPI_ABI": "awg-uapi-v3.1",
            "AWG_GO_TRIBE_PROBE_ABI": "tribe-awg-probe-v1" if self.options.get_safe("tribe_probe") else "",
        })
