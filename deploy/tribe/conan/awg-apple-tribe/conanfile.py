# AVPN (Tribe, split-DNS форвардер): наш awg-apple с dnsfwd.go — вместо апстрим-пакета awg-apple/2.0.2.
# Апстрим-рецепт качает GitHub-архив amnezia-vpn/amneziawg-apple; наш — клонирует ФОРК
# wellwon/amneziawg-apple (ветка tribe-dnsfwd, пин по коммиту ниже). Сборка идентична апстриму
# (Makefile + go из conan tool_requires). Регистрация: `conan export deploy/tribe/conan/awg-apple-tribe`
# → conanfile.py форка требует awg-apple/3.0.1-tribe.1 → cmake-conan строит из кэша (--build=missing).
from conan import ConanFile
from conan.errors import ConanInvalidConfiguration
from conan.tools.layout import basic_layout
from conan.tools.files import copy, collect_libs
from conan.tools.apple import is_apple_os
from conan.tools.gnu import AutotoolsToolchain, Autotools
from conan.tools.scm import Git

import os

TRIBE_GIT_URL = "https://github.com/wellwon/amneziawg-apple.git"
# de8b6ea = ветка tribe-awg3 (тег 3.0.1-tribe.1): merge апстрим-4bafa595 (AWG 3.0, awg-go/v3 3.0.1)
# поверх tribe-dnsfwd (dnsfwd.go + wgSetSplitDns + warmup + rebind-heal) + log+skip неизвестных
# wg-quick ключей (реш. владельца 2026-08-13, план awg3-migration §8 Q4).
TRIBE_GIT_REF = "de8b6ea"  # tribe-awg3 / тег 3.0.1-tribe.1

class AwgAppleTribe(ConanFile):
    name = "awg-apple"
    version = "3.0.1-tribe.1"
    settings = "os", "arch", "compiler"

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
        self.tool_requires("go/1.26.0")

    def validate(self):
        if not is_apple_os(self):
            raise ConanInvalidConfiguration(
                f"{self.name} v{self.version} does not support {self.settings.os}"
            )

    def source(self):
        git = Git(self)
        git.clone(url=TRIBE_GIT_URL, target=".")
        git.checkout(TRIBE_GIT_REF)

    def generate(self):
        tc = AutotoolsToolchain(self)
        sdk = self.settings.get_safe("os.sdk", "macosx")
        tc.make_args = [
            f"ARCHS={self._goarch}",
            f"PLATFORM_NAME={sdk}"
        ]
        tc.generate()

    def build(self):
        autotools = Autotools(self)
        autotools.make()
        autotools.make("version-header")

    def package(self):
        copy(self, "wireguard.h", src=self.build_folder, dst=os.path.join(self.package_folder, "include"))
        copy(self, "*.h", src=os.path.join(self.build_folder, "out"), dst=os.path.join(self.package_folder, "include"))
        copy(self, "*.a", src=os.path.join(self.build_folder, "out"), dst=os.path.join(self.package_folder, "lib"))

    def package_info(self):
        self.cpp_info.set_property("cmake_target_name", "amnezia::awg-apple")
        self.cpp_info.libs = collect_libs(self)
