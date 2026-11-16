from conan import ConanFile
from conan.errors import ConanException
from conan.tools.env import Environment
from conan.tools.files import copy, download, save
from conan.tools.layout import basic_layout

import hashlib
import json
import os


class TribeXrayGeo(ConanFile):
    """One pinned, cut geo pair for every Tribe Xray runner.

    Source: the same v2fly releases the Android libxray recipe embeds
    (recipes/amnezia-libxray/conanfile.py: _geosite_release/_geoip_release), so every platform
    sees the same `category-ru`. Cut with the Xray core's own protobuf types (tool/, built against
    the pinned amnezia-xray-core) and gated by tool/geo_test.go through the core's own asset
    loader and matchers. Output bytes are locked below; a data or tool change must update the
    locks deliberately.

    Consumers (install path contract, see README.md in this directory):
      iOS packet tunnel: both files are resources of the appex bundle; the extension passes the
        bundle's resource directory as `datDir` to LibXrayRunXray.
      macOS service: both files sit in the same directory as `Tribe-service`; the daemon leaves
        `xray.location.asset` unset, so the core reads them from the executable directory.
    """

    name = "tribe-xray-geo"
    version = "1.0.0"

    # Data pins: keep equal to recipes/amnezia-libxray/conanfile.py.
    _geosite_release = "20260827152101"
    _geosite_sha256 = "ba1adf51d4d724abbc157c53234a02bda00c94cdb8211709682e51a6855520b7"
    _geoip_release = "202608050239"
    _geoip_sha256 = "c67bd077eb102cec74fab759b73d17f99275f56af10a87c14d9fd983508f5ce1"
    _xray_core_version = "1.261101.0"

    # Order is irrelevant (the tool sorts); the set is the contract with the backend
    # normalizer's `required_geo` (a profile needing any other tag is withheld).
    _geosite_tags = ("private", "category-ru", "tiktok", "speedtest", "youtube")
    _geoip_tags = ("private", "ru")

    # Output locks (deterministic protobuf encoding of the selected entries).
    _cut_geosite_sha256 = "c0afbbc3b8c307e3fe5700ea941ba258319508f545cfa0e6b75a154520622162"
    _cut_geoip_sha256 = "c13c6463b5203768a94693d176d97f3e9b3fff93ecd288b6c215908baec0faee"

    def export_sources(self):
        copy(self, "*", src=os.path.join(self.recipe_folder, "tool"),
             dst=os.path.join(self.export_sources_folder, "tool"))

    def layout(self):
        basic_layout(self)

    def build_requirements(self):
        self.tool_requires("go/1.27.4")

    def source(self):
        download(
            self,
            f"https://github.com/v2fly/domain-list-community/releases/download/"
            f"{self._geosite_release}/dlc.dat",
            os.path.join(self.source_folder, "input", "dlc.dat"),
            sha256=self._geosite_sha256,
        )
        download(
            self,
            f"https://github.com/v2fly/geoip/releases/download/{self._geoip_release}/geoip.dat",
            os.path.join(self.source_folder, "input", "geoip.dat"),
            sha256=self._geoip_sha256,
        )

    @staticmethod
    def _sha256(path):
        with open(path, "rb") as handle:
            return hashlib.sha256(handle.read()).hexdigest()

    def build(self):
        tool_dir = os.path.join(self.source_folder, "tool")
        out_dir = os.path.join(self.build_folder, "geo")
        env = Environment()
        env.define("GOPATH", os.path.join(self.build_folder, ".tribe-go-path"))
        env.define("GOCACHE", os.path.join(self.build_folder, ".tribe-go-cache"))
        # -modcacherw: the private module cache lives in the build folder; read-only module files
        # would make Conan fail to remove or rebuild the package folder.
        env.define("GOFLAGS", "-mod=readonly -modcacherw -trimpath -buildvcs=false")
        env.define("GOTOOLCHAIN", "local")
        env.define("TRIBE_GEO_DIR", out_dir)
        with env.vars(self).apply():
            self.run(
                "go run . "
                f'-site "{os.path.join(self.source_folder, "input", "dlc.dat")}" '
                f'-ip "{os.path.join(self.source_folder, "input", "geoip.dat")}" '
                f'-sites {",".join(self._geosite_tags)} -ips {",".join(self._geoip_tags)} '
                f'-out "{out_dir}"',
                cwd=tool_dir,
            )
            # Every tag loads through the core's loader, known members match (build gate).
            self.run("go test -count=1 .", cwd=tool_dir)
        locks = {
            "geosite.dat": self._cut_geosite_sha256,
            "geoip.dat": self._cut_geoip_sha256,
        }
        for name, expected in locks.items():
            got = self._sha256(os.path.join(out_dir, name))
            if got != expected:
                raise ConanException(
                    f"{self.name}: {name} drifted: expected {expected}, got {got}"
                )
        save(self, os.path.join(out_dir, "MANIFEST.json"), json.dumps({
            "artifact": f"{self.name}/{self.version}",
            "cut_with": f"github.com/amnezia-vpn/amnezia-xray-core v{self._xray_core_version} common/geodata",
            "geosite": {
                "file": "geosite.dat",
                "sha256": self._cut_geosite_sha256,
                "tags": list(self._geosite_tags),
                "source": f"https://github.com/v2fly/domain-list-community/releases/download/{self._geosite_release}/dlc.dat",
                "source_sha256": self._geosite_sha256,
            },
            "geoip": {
                "file": "geoip.dat",
                "sha256": self._cut_geoip_sha256,
                "tags": list(self._geoip_tags),
                "source": f"https://github.com/v2fly/geoip/releases/download/{self._geoip_release}/geoip.dat",
                "source_sha256": self._geoip_sha256,
            },
        }, indent=2, sort_keys=True) + "\n")

    def package(self):
        for pattern in ("geosite.dat", "geoip.dat", "SHA256SUMS", "MANIFEST.json"):
            copy(self, pattern, src=os.path.join(self.build_folder, "geo"),
                 dst=os.path.join(self.package_folder, "geo"), keep_path=False)

    def package_id(self):
        # Pure data: independent of every setting.
        self.info.clear()

    def package_info(self):
        geo_dir = os.path.join(self.package_folder, "geo").replace("\\", "/")
        self.cpp_info.bindirs = []
        self.cpp_info.libdirs = []
        self.cpp_info.includedirs = []
        self.cpp_info.set_property("cmake_target_name", "tribe::xray-geo")
        self.cpp_info.set_property("cmake_extra_variables", {
            "TRIBE_XRAY_GEO_DIR": geo_dir,
            "TRIBE_XRAY_GEOSITE_DAT_PATH": f"{geo_dir}/geosite.dat",
            "TRIBE_XRAY_GEOIP_DAT_PATH": f"{geo_dir}/geoip.dat",
            "TRIBE_XRAY_GEO_SHA256SUMS_PATH": f"{geo_dir}/SHA256SUMS",
            "TRIBE_XRAY_GEOSITE_SHA256": self._cut_geosite_sha256,
            "TRIBE_XRAY_GEOIP_SHA256": self._cut_geoip_sha256,
            "TRIBE_XRAY_GEOSITE_TAGS": ";".join(self._geosite_tags),
            "TRIBE_XRAY_GEOIP_TAGS": ";".join(self._geoip_tags),
            "TRIBE_XRAY_GEO_VERSION": self.version,
        })
