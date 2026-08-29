from conan import ConanFile
from conan.tools.layout import basic_layout
from conan.tools.apple import is_apple_os
from conan.errors import ConanInvalidConfiguration
from conan.tools.scm import Git
from conan.internal.model.pkg_type import PackageType
from conan.tools.files import chdir
from conan.tools.apple import XCRun

import os
import shutil

class OpenVPNAdapter(ConanFile):
    name = "openvpnadapter"
    version = "1.0.0"
    _source_commit = "20b82af890bdf946f82d6efaacb5acc07c61f8de"
    _openvpn3_commit = "12563d7853384983de50f12ff7f679a95f547aaa"
    settings = "os", "build_type"

    @property
    def _sdk(self):
        return str(self.settings.get_safe("os.sdk", "macosx"))

    @property
    def _platform(self):
        return {
            "macosx": "macOS",
            "iphoneos": "iOS",
            "iphonesimulator": "iOS Simulator"
        }.get(self._sdk)

    @property
    def _configuration(self):
        return "Debug" if self.settings.get_safe("build_type") == "Debug" else "Release"

    def layout(self):
        basic_layout(self)

    def validate(self):
        if not is_apple_os(self) or self._platform is None:
            raise ConanInvalidConfiguration(
                f"There is absolutely no point building Apple framework for {self.settings.os}"
            )
        if not self.settings.get_safe("os.version"):
            raise ConanInvalidConfiguration(
                f"{self.name} requires an explicit Apple deployment target"
            )

    def source(self):
        git = Git(self)
        git.clone(
            url="https://github.com/amnezia-vpn/OpenVPNAdapter.git",
            target=".",
            args=["--recurse-submodules", "--branch", "master-amnezia"]
        )
        actual_commit = git.get_commit().strip()
        if actual_commit != self._source_commit:
            raise ConanInvalidConfiguration(
                f"OpenVPNAdapter branch resolved to {actual_commit}, expected {self._source_commit}"
            )
        openvpn3_commit = Git(
            self, folder=os.path.join(self.source_folder, "Sources", "OpenVPN3")
        ).get_commit().strip()
        if openvpn3_commit != self._openvpn3_commit:
            raise ConanInvalidConfiguration(
                f"OpenVPN3 submodule resolved to {openvpn3_commit}, expected {self._openvpn3_commit}"
            )

    def build(self):
        with chdir(self, self.source_folder):
            xcrun = XCRun(self)

            xcodebuild = xcrun.find("xcodebuild")
            deployment_target = self.settings.get_safe("os.version")
            deployment_setting = (
                "MACOSX_DEPLOYMENT_TARGET"
                if self._sdk == "macosx"
                else "IPHONEOS_DEPLOYMENT_TARGET"
            )
            self.run(f"{xcodebuild}"
                " -project OpenVPNAdapter.xcodeproj"
                " -scheme OpenVPNAdapter"
                " -configuration Release"
                f" -destination 'generic/platform={self._platform}'"
                f" -sdk {self._sdk}"
                f' "CONFIGURATION_BUILD_DIR={self.build_folder}"'
                f' "BUILT_PRODUCTS_DIR={self.build_folder}"'
                f' "{deployment_setting}={deployment_target}"'
                " MACH_O_TYPE=staticlib"
                " BUILD_LIBRARY_FOR_DISTRIBUTION=YES"
                " CODE_SIGNING_ALLOWED=NO"
            )

            openvpnadapter = os.path.join(self.build_folder, "OpenVPNAdapter.framework", "OpenVPNAdapter")
            self.run(f"{xcrun.libtool} -static -o"
                     f" {openvpnadapter}"
                     f" {openvpnadapter}"
                     f' {os.path.join(self.build_folder, "OpenVPNClient.framework", "OpenVPNClient")}'
                     f' {os.path.join(self.build_folder, "LZ4.framework", "LZ4")}'
                     f' {os.path.join(self.build_folder, "mbedTLS.framework", "mbedTLS")}'
            )

    def package(self):
        shutil.copytree(os.path.join(self.build_folder, "OpenVPNAdapter.framework"),
                        os.path.join(self.package_folder, "OpenVPNAdapter.framework"))

    def package_info(self):
        self.cpp_info.set_property("cmake_target_name", "amnezia::openvpnadapter")
        self.cpp_info.type = PackageType.STATIC
        self.cpp_info.package_framework = True
        self.cpp_info.location = os.path.join(self.package_folder, "OpenVPNAdapter.framework")
        self.cpp_info.frameworks = ["SystemConfiguration"]
