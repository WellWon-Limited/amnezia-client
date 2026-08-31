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

from pathlib import Path

class AmneziaLibxray(ConanFile):
    name = "amnezia-libxray"
    version = "1.0.3-tribe.1"
    settings = "os", "arch", "compiler"

    _upstream_version = "1.0.3"
    _geosite_release = "20260827152101"
    _geosite_sha256 = "ba1adf51d4d724abbc157c53234a02bda00c94cdb8211709682e51a6855520b7"
    _geoip_release = "202608050239"
    _geoip_sha256 = "c67bd077eb102cec74fab759b73d17f99275f56af10a87c14d9fd983508f5ce1"
    # Release time of the newer pinned data set (domain-list-community), not build time.
    _geo_data_epoch = "1787844067"
    # Rebuilt from the controller-slot/core patches in independent clean Conan
    # homes and compared byte-for-byte before this lock was recorded.  The
    # release-packaged per-ABI hashes are a separate Gradle gate.
    _android_artifact_sha256 = "3bc7786bc21db0a5af66a268ab9ab34ad1158ad0fbd8cc63d2b9513eabf4984c"

    def export_sources(self):
        export_conandata_patches(self)
        copy(
            self,
            "0004-xray-core-controller-errors.patch",
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
        self.tool_requires("go/1.26.0")
    
    def validate(self):
        if self.settings.os != "Android":
            raise ConanInvalidConfiguration(f"{self.name} v{self.version} does not support {self.settings.os}")

    def source(self):
        get(self, f"https://github.com/amnezia-vpn/amnezia-libxray/archive/refs/tags/v{self._upstream_version}.zip",
            sha256="3b1194c2a76e73913fdae49983c40a219c45a164ebdae72ef1297469348de730", strip_root=True
        )
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
        if ndk_path_str:
            ndk_path = Path(ndk_path_str)
            if len(ndk_path.parts) > 2:
                sdk_path = ndk_path.parents[1]
                env.define("ANDROID_HOME", str(sdk_path))
        env.vars(self).save_script("conan_provide_androidhome")

    def _patch_sources(self):
        apply_conandata_patches(self)
        build_path = os.path.join(self.build_folder, "build.sh")
        build_stat = os.stat(build_path)
        os.chmod(build_path, build_stat.st_mode | stat.S_IEXEC)

    def build(self):
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
        with prep_env.vars(self).apply():
            self.run("go mod tidy")
            self.run("go mod vendor")
            # gomobile creates its own temporary module and therefore cannot
            # run globally under ``-mod=vendor``.  Turn the exact vendored,
            # subsequently patched Xray tree into a local module replacement;
            # gomobile may then use normal module mode without ever escaping
            # to the unpatched upstream core.
            xray_modules = list(
                (Path(go_path) / "pkg" / "mod" / "github.com" / "amnezia-vpn").glob(
                    "amnezia-xray-core@v1.260728.0"
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
        patch(
            self,
            base_path=os.path.join(self.source_folder, "vendor", "github.com", "xtls", "xray-core"),
            patch_file=os.path.join(self.source_folder, "patches", "0004-xray-core-controller-errors.patch"),
        )
        vendor_env = Environment()
        vendor_env.define("GOPATH", go_path)
        vendor_env.define("GOCACHE", go_cache)
        vendor_env.define("GOFLAGS", "-mod=vendor -trimpath -buildvcs=false")
        with vendor_env.vars(self).apply():
            self.run("go test -count=1 -run '^TestTribeAndroidControllerSlot' .")
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

    def package(self):
        copy(self, "libxray.aar", src=self.build_folder, dst=os.path.join(self.package_folder, "aar"))
        artifact = os.path.join(self.package_folder, "aar", "libxray.aar")
        with open(artifact, "rb") as handle:
            digest = hashlib.sha256(handle.read()).hexdigest()
        if self._android_artifact_sha256 is None:
            raise ConanException(
                "amnezia-libxray/1.0.3-tribe.1 artifact lock is pending: "
                f"candidate universal AAR SHA-256 is {digest}; do not release"
            )
        if digest != self._android_artifact_sha256:
            raise ConanException(
                "amnezia-libxray Android artifact reproducibility drift: "
                f"expected {self._android_artifact_sha256}, got {digest}"
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
            "AMNEZIA_LIBXRAY_CORE_VERSION": "1.260728.0",
            "AMNEZIA_LIBXRAY_ABI": "gomobile-libxray-v2-controller-slot",
        })
