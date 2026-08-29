from conan import ConanFile
from conan.tools.layout import basic_layout
from conan.tools.files import apply_conandata_patches, collect_libs, copy, get
from conan.internal.model.pkg_type import PackageType
from conan.tools.gnu import AutotoolsToolchain, Autotools
from conan.tools.apple import is_apple_os

import os
import shutil


required_conan_version = ">=2.26"


class HevSocks5Tunnel(ConanFile):
    name = "hev-socks5-tunnel"
    version = "2.15.0"
    _source_commit = "00c7eb9ad7ca381b0f1fee880abc1077fe9b93be"
    settings = "os", "arch", "compiler"
    options = {
        "shared": [True, False],
        "as_framework": [True, False],
    }
    default_options = {
        "shared": False,
        "as_framework": False
    }
    exports_sources = "patches/*"

    def config_options(self):
        if not is_apple_os(self):
            del self.options.as_framework

    def configure(self):
        self.settings.rm_safe("compiler.libcxx")
        self.settings.rm_safe("compiler.cppstd")
        if self.options.get_safe("as_framework"):
            self.options.shared = False

    def layout(self):
        basic_layout(self, build_folder=".")

    def _restore_archive_symlinks(self):
        """Restore git symlinks flattened by GitHub source archives.

        Conan's archive extraction intentionally leaves GitHub's one-line
        symlink payloads as regular files.  The HEV public include trees use
        those links, so compiling the untouched archive would feed relative
        path text to the C compiler instead of headers.
        """
        include_dirs = (
            "include",
            "src/core/include",
            "third-part/hev-task-system/include",
            "third-part/yaml/include",
        )
        source_root = os.path.realpath(self.source_folder)
        link_count = 0
        for relative_dir in include_dirs:
            directory = os.path.join(self.source_folder, relative_dir)
            for name in sorted(os.listdir(directory)):
                path = os.path.join(directory, name)
                if os.path.islink(path):
                    link_count += 1
                    continue
                if not os.path.isfile(path):
                    continue
                with open(path, "rb") as handle:
                    payload = handle.read()
                try:
                    target = payload.decode("utf-8")
                except UnicodeDecodeError:
                    continue
                if not target.startswith("../") or "\n" in target or "\r" in target:
                    continue
                resolved = os.path.realpath(os.path.join(directory, target))
                if os.path.commonpath((source_root, resolved)) != source_root:
                    raise RuntimeError(f"HEV archive symlink escapes source root: {path}")
                if not os.path.isfile(resolved):
                    raise RuntimeError(f"HEV archive symlink target is missing: {path} -> {target}")
                os.unlink(path)
                os.symlink(target, path)
                link_count += 1

        if link_count != 31:
            raise RuntimeError(f"unexpected HEV archive symlink count: {link_count} (expected 31)")

    def source(self):
        # Git tags and recursive submodule heads are mutable. Materialize the
        # exact v2.15.0 superproject and every gitlink from immutable commit
        # archives with independent SHA-256 checks.
        get(self,
            "https://github.com/heiher/hev-socks5-tunnel/archive/refs/tags/2.15.0.zip",
            sha256="2420c6ac117c25b0c8ee98e845d1ad0a4e1d79de487e15fbe06935512707cf7b",
            strip_root=True)
        submodules = (
            ("src/core", "hev-socks5-core", "ee0f24505d344f14b14624fa2249e6ccfaed138b",
             "9ed7a6278d89534c99952d141a548902a6735c2473ccefe13c22e8c56baa343e"),
            ("third-part/hev-task-system", "hev-task-system", "8d83bbbf79557138726c8ee5a5fae99cbb978d61",
             "2d5b3dbd5a66c963747736453811027f0519a8a53b97b4653b0fdd8b8a897a25"),
            ("third-part/lwip", "lwip", "8c69dfbe537835d5f2a5fd8c08c859f667b108ea",
             "ec8169ac24fe1e77591812fd3fee7509a849fcf4ff315faadbae7be747d65cde"),
            ("third-part/yaml", "yaml", "efa36117a8646d26d12b58e05bac472d7854a70d",
             "211f8d5b67942af1108a5655d309ed32c1df51b19c2444a58ddf5b188405e8cc"),
        )
        for destination, repository, commit, digest in submodules:
            get(self, f"https://github.com/heiher/{repository}/archive/{commit}.zip",
                sha256=digest, destination=os.path.join(self.source_folder, destination),
                strip_root=True)
        self._restore_archive_symlinks()
        # The public 2.15 API exposes only a blocking quit call.  On Apple a
        # failed asynchronous initialization can therefore make the Network
        # Extension wait forever.  Keep the safety extension as an explicit,
        # reviewable local patch rather than relying on an unpublished fork.
        apply_conandata_patches(self)

    def generate(self):
        tc = AutotoolsToolchain(self)
        tc.generate()

    def build(self):
        autotools = Autotools(self)
        autotools.make("shared" if self.options.shared else "static")

        if self.options.get_safe("as_framework"):
            lib_path = os.path.join(self.build_folder, "bin", "libhev-socks5-tunnel.a")
            self.run(
                f"libtool -static -o {lib_path}"
                f" {lib_path}"
                f" {os.path.join(self.build_folder, "third-part", "lwip", "bin", "liblwip.a")}"
                f" {os.path.join(self.build_folder, "third-part", "yaml", "bin", "libyaml.a")}"
                f" {os.path.join(self.build_folder, "third-part", "hev-task-system", "bin", "libhev-task-system.a")}"
            )

            include_dir = os.path.join(self.build_folder, "framework_include")
            copy(self, "hev-main.h", src=os.path.join(self.source_folder, "src"), dst=include_dir)
            copy(self, "module.modulemap", src=os.path.join(self.source_folder), dst=include_dir)

            self.run('xcodebuild -create-xcframework'
                f' -library {lib_path}'
                f' -headers {include_dir}'
                f' -output {os.path.join(self.build_folder, "HevSocks5Tunnel.xcframework")}'
            )

    def package(self):
        if self.options.get_safe("as_framework"):
            shutil.copytree(src=os.path.join(self.build_folder, "HevSocks5Tunnel.xcframework"),
                            dst=os.path.join(self.package_folder, "HevSocks5Tunnel.xcframework"))
        else:
            copy(self, "hev-main.h", src=os.path.join(self.source_folder, "src"), dst=os.path.join(self.package_folder, "include"))
            copy(self, "*.a", src=os.path.join(self.build_folder, "bin"), dst=os.path.join(self.package_folder, "lib"))
            copy(self, "*.so", src=os.path.join(self.build_folder, "bin"), dst=os.path.join(self.package_folder, "lib"))
            copy(self, "*.a", src=os.path.join(self.build_folder, "bin", "third-part", "lwip"), dst=os.path.join(self.package_folder, "lib"))
            copy(self, "*.so", src=os.path.join(self.build_folder, "bin", "third-part", "lwip"), dst=os.path.join(self.package_folder, "lib"))
            copy(self, "*.a", src=os.path.join(self.build_folder, "bin", "third-part", "yaml"), dst=os.path.join(self.package_folder, "lib"))
            copy(self, "*.so", src=os.path.join(self.build_folder, "bin", "third-part", "yaml"), dst=os.path.join(self.package_folder, "lib"))
            copy(self, "*.a", src=os.path.join(self.build_folder, "bin", "third-part", "hev-task-system"), dst=os.path.join(self.package_folder, "lib"))
            copy(self, "*.so", src=os.path.join(self.build_folder, "bin", "third-part", "hev-task-system"), dst=os.path.join(self.package_folder, "lib"))

    def package_info(self):
        self.cpp_info.set_property("cmake_target_name", "heiher::hev-socks5-tunnel")
        if self.options.get_safe("as_framework"):
            self.cpp_info.type = PackageType.STATIC
            self.cpp_info.package_framework = True
            self.cpp_info.location = os.path.join(self.package_folder, "HevSocks5Tunnel.xcframework")
        else:
            self.cpp_info.libraries = collect_libs(self)
