import shutil
import os
import sys
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PAYLOAD_TOOL = ROOT / "deploy" / "tribe" / "macos-service-payload.sh"
PREPARE_TOOL = ROOT / "deploy" / "tribe" / "prepare-macos-service-payload.sh"
INSTALLER_TOOL = ROOT / "deploy" / "tribe" / "tribe-svc-install.sh"
PF_FILES = (
    "tribe.000.allowLoopback.conf",
    "tribe.100.blockAll.conf",
    "tribe.110.allowNets.conf",
    "tribe.120.blockNets.conf",
    "tribe.150.allowExcludedApps.conf",
    "tribe.200.allowVPN.conf",
    "tribe.250.blockIPv6.conf",
    "tribe.290.allowDHCP.conf",
    "tribe.300.allowLAN.conf",
    "tribe.310.blockDNS.conf",
    "tribe.350.allowHnsd.conf",
    "tribe.400.allowPIA.conf",
    "tribe.999.quarantine.conf",
    "tribe.conf",
)


@unittest.skipUnless(sys.platform == "darwin", "macOS payload fixture requires BSD tools")
class MacosServicePayloadTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = Path(tempfile.mkdtemp(prefix="tribe-payload-test-"))
        self.payload = self.temp / "payload"
        self.payload.mkdir()
        for name in ("Tribe-service", "amneziawg-go", "openvpn", "tun2socks"):
            path = self.payload / name
            path.write_bytes(f"executable:{name}\n".encode())
            path.chmod(0o755)
        for name in ("geoip.dat", "geosite.dat"):
            (self.payload / name).write_bytes(f"data:{name}\n".encode())
        (self.payload / "INSTALL-EPOCH").write_text("96\n", encoding="utf-8")

        framework = self.payload / "Frameworks" / "QtCore.framework" / "Versions" / "A"
        framework.mkdir(parents=True)
        (framework / "QtCore").write_bytes(b"fake QtCore\n")
        versions = framework.parent
        (versions / "Current").symlink_to("A")
        (self.payload / "Frameworks" / "QtCore.framework" / "QtCore").symlink_to(
            "Versions/Current/QtCore"
        )
        (self.payload / "Frameworks" / "libssl.3.dylib").write_bytes(b"ssl\n")
        (self.payload / "Frameworks" / "libcrypto.3.dylib").write_bytes(b"crypto\n")

        pf = self.payload / "pf"
        pf.mkdir()
        for name in PF_FILES:
            (pf / name).write_text(f"# {name}\n", encoding="utf-8")

    def tearDown(self) -> None:
        shutil.rmtree(self.temp)

    def run_tool(self, mode: str, *extra: Path, ok: bool = True) -> subprocess.CompletedProcess:
        result = subprocess.run(
            ["/bin/bash", str(PAYLOAD_TOOL), mode, str(self.payload), *(str(p) for p in extra)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if ok and result.returncode != 0:
            self.fail(f"payload tool failed: {result.stdout}\n{result.stderr}")
        if not ok and result.returncode == 0:
            self.fail("payload tool unexpectedly accepted an invalid payload")
        return result

    def seal(self) -> Path:
        self.run_tool("seal")
        expected = self.temp / "tribe-svc.version"
        shutil.copyfile(self.payload / "VERSION", expected)
        return expected

    def test_seal_covers_every_transport_runtime_and_verifies_anchor(self) -> None:
        expected = self.seal()
        self.run_tool("verify", expected)
        manifest = (self.payload / "PAYLOAD-MANIFEST.sha256").read_text(encoding="utf-8")
        for name in (
            "Tribe-service",
            "amneziawg-go",
            "openvpn",
            "tun2socks",
            "geoip.dat",
            "geosite.dat",
            "INSTALL-EPOCH",
            "INSTALL-CONTRACT",
            "PAYLOAD-SYMLINKS",
        ):
            self.assertIn(f"  {name}\n", manifest)
        self.assertEqual(len((self.payload / "VERSION").read_text().strip()), 64)

    def test_content_tamper_is_rejected(self) -> None:
        expected = self.seal()
        with (self.payload / "tun2socks").open("ab") as stream:
            stream.write(b"tamper")
        result = self.run_tool("verify", expected, ok=False)
        self.assertIn("checksum failed", result.stderr)

    def test_signed_app_version_anchor_mismatch_is_rejected(self) -> None:
        expected = self.seal()
        expected.write_text("0" * 64 + "\n", encoding="utf-8")
        result = self.run_tool("verify", expected, ok=False)
        self.assertIn("signed app version anchor", result.stderr)

    def test_unexpected_root_or_pf_file_is_rejected_before_seal(self) -> None:
        (self.payload / "surprise").write_text("no", encoding="utf-8")
        result = self.run_tool("seal", ok=False)
        self.assertIn("unexpected payload path", result.stderr)

    def test_escaping_framework_symlink_is_rejected(self) -> None:
        (self.payload / "Frameworks" / "escape").symlink_to("../..")
        result = self.run_tool("seal", ok=False)
        self.assertIn("parent traversal", result.stderr)

    def test_absolute_framework_symlink_is_rejected(self) -> None:
        (self.payload / "Frameworks" / "absolute").symlink_to("/private/tmp")
        result = self.run_tool("seal", ok=False)
        self.assertIn("unsafe symlink target", result.stderr)

    def test_install_contract_and_modes_are_versioned(self) -> None:
        self.run_tool("normalize")
        expected = self.seal()
        self.run_tool("verify", expected)
        contract = (self.payload / "INSTALL-CONTRACT").read_text(encoding="utf-8")
        self.assertIn("schema=2\n", contract)
        self.assertIn("installer_sha256=", contract)
        self.assertIn("launchctl_parser_sha256=", contract)
        self.assertIn("verifier_sha256=", contract)

        framework = self.payload / "Frameworks" / "libssl.3.dylib"
        framework.chmod(0o666)
        result = self.run_tool("verify", expected, ok=False)
        self.assertIn("unsafe payload mode", result.stderr)

    def test_ambiguous_symlink_target_is_rejected(self) -> None:
        (self.payload / "Frameworks" / "ambiguous").symlink_to("bad\ttarget")
        result = self.run_tool("seal", ok=False)
        self.assertIn("unsupported symlink target", result.stderr)

    def test_hard_linked_payload_file_is_rejected(self) -> None:
        source = self.payload / "tun2socks"
        os.link(source, self.payload / "Frameworks" / "hardlink")
        result = self.run_tool("seal", ok=False)
        self.assertIn("hard-linked payload file", result.stderr)

    def test_scoped_bsdtar_extraction_preserves_exact_sealed_modes(self) -> None:
        self.run_tool("normalize")
        expected = self.seal()
        archive = self.temp / "payload.tar.gz"
        extracted = self.temp / "extracted"
        extracted.mkdir(mode=0o700)
        subprocess.run(
            ["/usr/bin/bsdtar", "-czf", str(archive), "-C", str(self.payload), "."],
            check=True,
        )
        command = (
            "umask 027; destination=$1; archive=$2; "
            # --chroot itself requires root and is pinned by the static release
            # gate.  This unprivileged fixture isolates the umask/mode behavior.
            "(umask 022; /usr/bin/bsdtar -xzf \"$archive\" -C \"$destination\" "
            "--no-same-owner --no-same-permissions --no-acls "
            "--no-fflags --no-mac-metadata --no-xattrs)"
        )
        subprocess.run(
            ["/bin/bash", "-c", command, "--", str(extracted), str(archive)],
            check=True,
        )
        original = self.payload
        self.payload = extracted
        try:
            self.run_tool("verify", expected)
            self.assertEqual((extracted / "Tribe-service").stat().st_mode & 0o777, 0o755)
            self.assertEqual((extracted / "geoip.dat").stat().st_mode & 0o777, 0o644)
        finally:
            self.payload = original

    def test_generator_verifier_and_installer_share_the_closed_runtime_root(self) -> None:
        prepare = PREPARE_TOOL.read_text(encoding="utf-8")
        verifier = PAYLOAD_TOOL.read_text(encoding="utf-8")
        installer = INSTALLER_TOOL.read_text(encoding="utf-8")
        runtime_files = {
            "Tribe-service",
            "amneziawg-go",
            "openvpn",
            "tun2socks",
            "geoip.dat",
            "geosite.dat",
            "INSTALL-EPOCH",
        }
        for name in runtime_files:
            with self.subTest(name=name):
                self.assertIn(name, prepare)
                self.assertIn(name, verifier)
                self.assertIn(name, installer)
        for source in (prepare, verifier, installer):
            self.assertNotIn("update-resolv-conf.sh", source)
        self.assertIn("tribe.999.quarantine.conf", verifier)
        self.assertIn("pf/*", installer)


if __name__ == "__main__":
    unittest.main()
