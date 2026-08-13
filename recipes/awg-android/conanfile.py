from conan import ConanFile
from conan.tools.cmake import cmake_layout, CMake, CMakeToolchain
from conan.tools.files import copy, load, replace_in_file
from conan.errors import ConanInvalidConfiguration
from conan.tools.scm import Git

import os
import platform

class AwgAndroid(ConanFile):
    name = "awg-android"
    version = "2.0.1"
    settings = "os", "arch", "build_type", "compiler"

    def configure(self):
        self.settings.rm_safe("compiler.libcxx")
        self.settings.rm_safe("compiler.cppstd")

    def layout(self):
        cmake_layout(self)

    def build_requirements(self):
        self.tool_requires("cmake/[>=3.4.1 <4]")

    def validate(self):
        if self.settings.os != "Android":
            raise ConanInvalidConfiguration(f"{self.name} v{self.version} does not support {self.settings.os}")

    def source(self):
        git = Git(self)
        git.clone(
            url="https://github.com/amnezia-vpn/amneziawg-android.git",
            target=".",
            args=["--recurse-submodules", "--branch", f"v{self.version}"]
        )

    def generate(self):
        tc = CMakeToolchain(self)
        tc.variables["GRADLE_USER_HOME"] = os.path.join(self.build_folder, "gradle_user_home")
        tc.variables["CMAKE_LIBRARY_OUTPUT_DIRECTORY"] = os.path.join(self.build_folder, "out")
        # not to warn in case of strtok() usage
        tc.extra_cflags = ["-Wno-deprecated-declarations"]
        tc.generate()

    # AVPN: гвард версии amneziawg-go внутри обёртки. История: (1) S4 keepalive-паддинг чинится
    # только >=0.2.18 — CONNECT-INVARIANTS §14.1; (2) апстрим ПЕРЕДВИГАЛ тег обёртки v2.0.1
    # (2026-06-12: внутри 0.2.16 -> 0.2.18), а conan снапшотит источники — кеш тихо собирал
    # старый движок во все APK. Поэтому содержимому тега не доверяем и валидируем go.mod явно.
    # С awg-android 3.0.1 обёртка пинит amneziawg-go/v3 (module path сменился) — переписывать
    # go.mod больше не нужно, гвард только проверяет, что снапшот тега не откатился на 2.0-эру.
    _AWG_GO_V3_REQ = "github.com/amnezia-vpn/amneziawg-go/v3 v3."

    def _check_awg_go_v3(self):
        d = os.path.join(self.source_folder, "tunnel", "tools", "libwg-go")
        gomod = load(self, os.path.join(d, "go.mod"))
        if self._AWG_GO_V3_REQ not in gomod:
            raise ConanInvalidConfiguration(
                "awg-android: go.mod без amneziawg-go/v3 — conan затянул СТАРЫЙ снапшот тега "
                "(2.0-эра, тег обёртки передвинут?). Очисти кеш: "
                "conan remove 'awg-android/*' -c и пересобери; сверь go.mod тега на GitHub")
        gosum = load(self, os.path.join(d, "go.sum"))
        if "amneziawg-go/v3 v3." not in gosum:
            raise ConanInvalidConfiguration(
                "awg-android: go.sum без строк amneziawg-go/v3 — снапшот источников "
                "не соответствует go.mod, пересобери с чистым кешем")

    def _patch_sources(self):
        self._check_awg_go_v3()
        if platform.system() == 'Darwin':
            replace_in_file(self,
                os.path.join(self.source_folder, "tunnel", "tools", "libwg-go", "Makefile"),
                'flock "$@.lock" -c \' \\\n',
                "",
            )
            replace_in_file(self,
                os.path.join(self.source_folder, "tunnel", "tools", "libwg-go", "Makefile"),
                'mv "$@.tmp" "$@"\'',
                'mv "$@.tmp" "$@"',
            )
            replace_in_file(self,
                os.path.join(self.source_folder, "tunnel", "tools", "libwg-go", "Makefile"),
                'touch "$@"\'',
                'touch "$@"',
            )
            replace_in_file(self,
                os.path.join(self.source_folder, "tunnel", "tools", "libwg-go", "Makefile"),
                'sha256sum -c',
                'shasum -a 256 -c'
            )

    def build(self):
        self._patch_sources()
        cmake = CMake(self)
        cmake.configure(build_script_folder=os.path.join(self.source_folder, "tunnel", "tools"))
        cmake.build(target=["libwg-go.so", "libwg.so", "libwg-quick.so"])

    def package(self):
        copy(self, "libwg-go.h", src=os.path.join(self.build_folder, "out"), dst=os.path.join(self.package_folder, "include"))
        copy(self, "libwg-go.so", src=os.path.join(self.build_folder, "out"), dst=os.path.join(self.package_folder, "lib"))
        copy(self, "libwg.so", src=os.path.join(self.build_folder, "out"), dst=os.path.join(self.package_folder, "bin"))
        copy(self, "libwg-quick.so", src=os.path.join(self.build_folder, "out"), dst=os.path.join(self.package_folder, "bin"))

    def package_info(self):
        self.cpp_info.set_property("cmake_target_name", "amnezia::awg-android")
        self.cpp_info.libs = [ "wg-go" ]
        self.cpp_info.set_property("cmake_extra_variables", {
            "AMNEZIA_ANDROID_LIBWG_PATH": os.path.join(self.package_folder, "bin", "libwg.so"),
            "AMNEZIA_ANDROID_LIBWG_QUICK_PATH": os.path.join(self.package_folder, "bin", "libwg-quick.so"),
        })
