from conan import ConanFile
from conan.tools.cmake import cmake_layout, CMake, CMakeToolchain
from conan.tools.files import copy, load, replace_in_file, save
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

    # AVPN: явный пин amneziawg-go (S4 keepalive-паддинг чинится только >=0.2.18 —
    # CONNECT-INVARIANTS §14.1; 0.2.19 = 0.2.18 + handle empty I1-I5, go.mod идентичен).
    # Апстрим ПЕРЕДВИГАЛ тег обёртки v2.0.1 (2026-06-12: внутри 0.2.16 -> 0.2.18), а conan
    # снапшотит источники — кеш от 2026-06-04 тихо собирал 0.2.16 во все APK. Поэтому версию
    # движка фиксируем здесь явно и валидируем, а не доверяем содержимому тега.
    _AWG_GO_PIN = "v0.2.19"

    def _pin_awg_go(self):
        d = os.path.join(self.source_folder, "tunnel", "tools", "libwg-go")
        gomod = os.path.join(d, "go.mod")
        for old in ("v0.2.16", "v0.2.17", "v0.2.18"):
            replace_in_file(self, gomod,
                f"github.com/amnezia-vpn/amneziawg-go {old}",
                f"github.com/amnezia-vpn/amneziawg-go {self._AWG_GO_PIN}",
                strict=False)
        if f"amneziawg-go {self._AWG_GO_PIN}" not in load(self, gomod):
            raise ConanInvalidConfiguration(
                f"awg-android: go.mod без пина amneziawg-go {self._AWG_GO_PIN} — апстрим сменил "
                "раскладку libwg-go, пин надо перепроверить руками")
        gosum = os.path.join(d, "go.sum")
        sum_content = load(self, gosum)
        # граф зависимостей 0.2.19 совпадает с 0.2.18 (go.mod идентичны) — go.sum обёртки
        # с 0.2.18-эры полон; нужен только хеш самого модуля (sum.golang.org, /go.mod-хеш общий)
        if "amneziawg-go v0.2.18" not in sum_content:
            raise ConanInvalidConfiguration(
                "awg-android: go.sum без строк v0.2.18 — conan затянул СТАРЫЙ снапшот тега "
                "(0.2.16-эра, граф зависимостей не совпадает). Очисти кеш: "
                "conan remove 'awg-android/*' -c и пересобери")
        if f"amneziawg-go {self._AWG_GO_PIN} h1:" not in sum_content:
            save(self, gosum, sum_content
                + f"github.com/amnezia-vpn/amneziawg-go {self._AWG_GO_PIN} h1:l3rOmrA4o5z38kpgnA5iSk1yOm7Cv3AafIi4vxpSEV0=\n"
                + f"github.com/amnezia-vpn/amneziawg-go {self._AWG_GO_PIN}/go.mod h1:aMgOk9MuX0xI7b5TKAYp8pLM54RlXcOPzDvYw3YEO5A=\n")

    def _patch_sources(self):
        self._pin_awg_go()
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
