#!/usr/bin/env python3
"""Exercise the embedded macOS rollback script (LaunchGuard.cpp) with isolated fixtures.

No network, real applications, signing identities or GUI launches are used.
Run: WW_TEST=1 WW_TEST_ID=launch-guard python3 -m unittest discover -s
client/core/serviceEngine/tests -p test_launch_guard.py -v
"""
import os
from pathlib import Path
import plistlib
import re
import subprocess
import sys
import tempfile
import unittest


MOCK = r'''
import os, pathlib, sys
root = pathlib.Path(os.environ["WW_ROLLBACK_TEST_ROOT"])
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
fault = os.environ.get("WW_ROLLBACK_TEST_FAULT", "")
with (root / "commands").open("a") as f:
    f.write(name + " " + repr(args) + "\n")
if name == "codesign":
    if fault == "signature" and "-R=notarized" not in args: sys.exit(1)
    if fault == "notarization" and "-R=notarized" in args: sys.exit(1)
elif name == "mv":
    src, dst = args[-2:]
    if fault == "swap" and src.endswith("previous.app"): sys.exit(1)
    os.rename(src, dst)
elif name == "open":
    with (root / "opened").open("a") as f:
        f.write((pathlib.Path(args[-1]) / "version").read_text() + "\n")
    if fault == "launch": sys.exit(1)
elif name == "osascript":
    (root / "alert").write_text(args[-1])
else:
    raise AssertionError(name)
'''


class RollbackScriptTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="tribe-rollback-test-", dir="/tmp")
        self.root = Path(self.temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name in ("codesign", "mv", "open", "osascript"):
            command = self.bin / name
            command.write_text(f"#!{sys.executable}\n" + MOCK)
            command.chmod(0o700)
        self.dst = self.root / "Applications" / "Tribe VPN.app"
        self.state = self.root / "state"
        self.prev = self.state / "previous.app"
        for app, version, marketing in ((self.dst, "new", "5.1.80"), (self.prev, "old", "5.1.79")):
            (app / "Contents").mkdir(parents=True)
            (app / "version").write_text(version)
            self.set_plist(app, marketing)
        (self.state / "pending.json").write_text(
            '{"from":"5.1.79","to":"5.1.80","app":"%s","installed_at":1,"attempts":2,"mode":"auto"}\n' % self.dst)
        (self.state / "previous.json").write_text('{"version":"5.1.79","path":"%s","kept_at":1}\n' % self.prev)
        (self.state / "confirmed").write_text("")
        source = (Path(__file__).parent.parent / "LaunchGuard.cpp").read_text()
        script = re.search(r'R"SH\((.*?)\)SH";', source, re.S).group(1)
        script = script.replace("sleep 0.5", "sleep 0.01")
        script = script.replace("/usr/bin/osascript", str(self.bin / "osascript"))
        self.script = self.state / "rollback.sh"
        self.script.write_text(script)
        self.script.chmod(0o700)
        self.env = dict(os.environ, PATH=f"{self.bin}:/usr/bin:/bin:/usr/sbin:/sbin",
                        WW_TEST="1", WW_TEST_ID="launch-guard", WW_ROLLBACK_TEST_ROOT=str(self.root))

    def tearDown(self):
        self.temporary.cleanup()

    def set_plist(self, app, version, bundle="hk.wellwon.vpn"):
        (app / "Contents" / "Info.plist").write_bytes(plistlib.dumps({
            "CFBundleIdentifier": bundle, "CFBundleShortVersionString": version,
        }))

    def run_rollback(self, reason="crash_loop", parent="0", fault="", dst=None):
        self.env["WW_ROLLBACK_TEST_FAULT"] = fault
        return subprocess.run(["/bin/bash", str(self.script), str(dst or self.dst), str(self.state),
                               reason, parent, "Q7DVH5MCWF", "hk.wellwon.vpn", str(self.root / "logs")],
                              env=self.env, capture_output=True, text=True, timeout=15)

    def assert_untouched(self):
        self.assertEqual((self.dst / "version").read_text(), "new")
        self.assertEqual((self.prev / "version").read_text(), "old")
        # Провал отката снимает pending (→ pending.failed): иначе каждый следующий старт снова
        # получает вердикт crash-loop, снова падает на откате и приложение не запускается вовсе.
        self.assertFalse((self.state / "pending.json").exists())
        self.assertTrue((self.state / "pending.failed").exists())
        self.assertFalse((self.state / "rollback.json").exists())
        self.assertFalse((self.root / "opened").exists())

    def test_rollback_swaps_keeps_failed_copy_and_reports(self):
        result = self.run_rollback()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.dst / "version").read_text(), "old")
        self.assertEqual((self.state / "failed.app" / "version").read_text(), "new")
        self.assertFalse(self.prev.exists())
        report = (self.state / "rollback.json").read_text()
        for needle in ('"from":"5.1.80"', '"to":"5.1.79"', '"reason":"crash_loop"', '"attempts":2', '"mode":"auto"'):
            self.assertIn(needle, report)
        self.assertFalse((self.state / "pending.json").exists())
        self.assertFalse((self.state / "previous.json").exists())
        self.assertFalse((self.state / "confirmed").exists())
        self.assertEqual((self.root / "opened").read_text(), "old\n")
        log = (self.root / "logs" / "self-update.log").read_text()
        self.assertIn("rollback ok: 5.1.80 -> 5.1.79", log)

    def test_rollback_waits_for_parent_and_gives_up_if_it_stays(self):
        parent = subprocess.Popen(["/bin/sleep", "60"], env=self.env)
        try:
            result = self.run_rollback(parent=str(parent.pid))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("не завершилось", (self.root / "alert").read_text())
            self.assert_untouched()
        finally:
            parent.terminate()
            parent.wait(timeout=2)

    def test_rollback_proceeds_after_parent_exits(self):
        # The real parent is reaped by launchd the moment it exits; here a helper thread reaps
        # it, otherwise the zombie would still answer `kill -0` and the script would wait forever.
        import threading
        parent = subprocess.Popen(["/bin/sleep", "0.2"], env=self.env)
        reaper = threading.Thread(target=parent.wait, daemon=True)
        reaper.start()
        result = self.run_rollback(parent=str(parent.pid), reason="blocked")
        reaper.join(timeout=2)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.dst / "version").read_text(), "old")
        self.assertIn('"reason":"blocked"', (self.state / "rollback.json").read_text())

    def test_missing_previous_copy_is_refused(self):
        for f in sorted(self.prev.rglob("*"), reverse=True):
            f.unlink() if f.is_file() else f.rmdir()
        self.prev.rmdir()
        result = self.run_rollback()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Сохранённой предыдущей версии нет", (self.root / "alert").read_text())
        self.assertEqual((self.dst / "version").read_text(), "new")
        self.assertFalse((self.state / "rollback.json").exists())

    def test_untrusted_previous_copy_is_refused(self):
        for fault in ("signature", "notarization"):
            with self.subTest(fault=fault):
                self.assertNotEqual(self.run_rollback(fault=fault).returncode, 0)
                self.assert_untouched()
        self.set_plist(self.prev, "5.1.79", bundle="other.app")
        self.assertNotEqual(self.run_rollback().returncode, 0)
        self.assert_untouched()

    def test_failed_swap_restores_current_version(self):
        result = self.run_rollback(fault="swap")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.dst / "version").read_text(), "new")
        self.assertFalse((self.state / "failed.app").exists())
        self.assertFalse((self.state / "pending.json").exists())
        self.assertTrue((self.state / "pending.failed").exists())

    def test_launch_failure_after_swap_keeps_previous_version_installed(self):
        result = self.run_rollback(fault="launch")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.dst / "version").read_text(), "old")
        self.assertIn("не запустилась", (self.root / "alert").read_text())
        self.assertTrue((self.state / "rollback.json").exists())

    def test_symlinked_previous_copy_is_refused(self):
        # Ссылка на рабочий бандл проходит codesign/нотаризацию, а mv перенёс бы в /Applications
        # саму ссылку: содержимое меняется после проверки, финишер потом отказывает навсегда.
        real = self.root / "elsewhere.app"
        self.prev.rename(real)
        self.prev.symlink_to(real)
        result = self.run_rollback()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ссылка", (self.root / "alert").read_text())
        self.assertEqual((self.dst / "version").read_text(), "new")
        self.assertFalse((self.state / "rollback.json").exists())

    def test_translocated_or_volume_app_is_refused(self):
        for bad in ("/Volumes/Tribe VPN/Tribe VPN.app", "/private/var/folders/x/AppTranslocation/y/d/Tribe VPN.app"):
            with self.subTest(dst=bad):
                self.assertNotEqual(self.run_rollback(dst=bad).returncode, 0)
                self.assert_untouched()


if __name__ == "__main__":
    unittest.main()
