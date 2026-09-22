#!/usr/bin/env python3
"""Exercise the actual embedded macOS installer with isolated app/command fixtures.

No network, real applications, mounts, signing identities or GUI launches are used.
Run: WW_TEST=1 WW_TEST_ID=self-update python3 -m unittest discover -s
client/core/serviceEngine/tests -p test_self_update.py -v
"""
import os
from pathlib import Path
import plistlib
import re
import subprocess
import sys
import tempfile
import time
import unittest


MOCK = r'''
import os, pathlib, shutil, subprocess, sys
root = pathlib.Path(os.environ["WW_UPDATE_TEST_ROOT"])
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
fault = os.environ.get("WW_UPDATE_TEST_FAULT", "")
with (root / "commands").open("a") as f:
    f.write(name + " " + repr(args) + "\n")
if name == "curl":
    if "-fsSI" in args:  # HEAD for the download size (percent); 11 = len("fixture dmg")
        print("HTTP/2 200\r\ncontent-length: 11\r\n\r\n", end="")
        sys.exit(0)
    if fault == "download": sys.exit(28)
    pathlib.Path(args[args.index("-o") + 1]).write_text("fixture dmg")
    print("302" if fault == "redirect" else "200", end="")
elif name == "hdiutil":
    if args[0] == "attach":
        if fault == "mount": sys.exit(1)
        print("/dev/fixture\tApple_HFS\t" + str(root / "mount"))
    elif fault == "detach": sys.exit(1)
elif name == "codesign":
    if "-dv" in args:
        print("TeamIdentifier=" + ("OTHERTEAM" if fault == "team" else "Q7DVH5MCWF"))
    elif fault == "signature" or (fault == "notarization" and "-R=notarized" in args):
        sys.exit(1)
    elif fault == "staged_signature" and args[-1].endswith("staged.app"):
        sys.exit(1)
elif name == "ditto":
    if fault == "copy": sys.exit(1)
    shutil.copytree(args[0], args[1])
elif name == "mv":
    src, dst = args[-2:]
    if fault in ("replace", "rollback") and src.endswith("staged.app"): sys.exit(1)
    if fault == "rollback" and src.endswith("previous.app"): sys.exit(1)
    if fault == "backup" and dst.endswith("previous.app"): sys.exit(1)
    os.rename(src, dst)
elif name == "pgrep":
    sys.exit(0 if (root / "alive").exists() else 1)
elif name == "open":
    with (root / "open_args").open("a") as f:
        f.write(" ".join(args[:-1]) + "\n")
    with (root / "opened").open("a") as f:
        f.write((pathlib.Path(args[-1]) / "version").read_text() + "\n")
    if fault == "launch" and (pathlib.Path(args[-1]) / "version").read_text() == "new":
        sys.exit(1)
elif name == "osascript":
    (root / "alert").write_text(args[-1])
elif name == "nohup":
    if fault == "runner": sys.exit(1)
    os.execv(args[0], args)
else:
    raise AssertionError(name)
'''


class SelfUpdateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="tribe-self-update-test-", dir="/tmp")
        self.root = Path(self.temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name in ("curl", "hdiutil", "codesign", "ditto", "mv", "open", "osascript", "nohup", "pgrep"):
            command = self.bin / name
            command.write_text(f"#!{sys.executable}\n" + MOCK)
            command.chmod(0o700)
        self.dst = self.root / "Applications" / "Tribe VPN.app"
        self.src = self.root / "mount" / "Tribe VPN.app"
        for app, version in ((self.dst, "old"), (self.src, "new")):
            (app / "Contents").mkdir(parents=True)
            (app / "version").write_text(version)
        self.set_plist()
        self.set_plist(version="5.1.79", app=self.dst)
        self.state = self.root / "state"
        source = (Path(__file__).parent.parent / "SelfUpdate.cpp").read_text()
        script = re.search(r'R"SH\((.*?)\)SH";', source, re.S).group(1)
        # Only shorten parent-exit wait and redirect the error dialog in this fixture.
        # Production plist parsing uses the real system PlistBuddy on fixture files.
        script = script.replace("sleep 0.5", "sleep 0.01")
        script = script.replace("/usr/bin/osascript", str(self.bin / "osascript"))
        # Keep all installer scratch files inside this test's temporary directory.
        script = script.replace("/tmp/tribe-update.XXXXXX", str(self.root / "scratch.XXXXXX"))
        self.script = self.root / "prepare.sh"
        self.script.write_text(script)
        self.commit = self.root / "commit"
        self.env = dict(os.environ, PATH=f"{self.bin}:/usr/bin:/bin:/usr/sbin:/sbin",
                        WW_TEST="1", WW_TEST_ID="self-update", WW_UPDATE_TEST_ROOT=str(self.root))
        self.parent = subprocess.Popen(["/bin/sleep", "60"], env=self.env)

    def tearDown(self):
        self.stop_parent()
        # All detached fixture runners terminate within the shortened wait interval.
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            runners = subprocess.check_output(["/bin/ps", "-axo", "command="], text=True)
            if not any(str(self.root) in line and "/finish.sh" in line for line in runners.splitlines()):
                break
            time.sleep(0.03)
        else:
            self.fail("fixture runner did not terminate")
        self.temporary.cleanup()

    def set_plist(self, version="5.1.80", bundle="hk.wellwon.vpn", app=None):
        ((app or self.src) / "Contents" / "Info.plist").write_bytes(plistlib.dumps({
            "CFBundleIdentifier": bundle, "CFBundleShortVersionString": version,
        }))

    def prepare(self, fault="", state=None, mode="manual", blocked=""):
        self.env["WW_UPDATE_TEST_FAULT"] = fault
        return subprocess.run(["/bin/bash", str(self.script), "https://tribevpn.com/dl/TribeVPN.dmg",
                               "5.1.79", "Q7DVH5MCWF", "hk.wellwon.vpn", str(self.dst),
                               str(self.parent.pid), str(self.commit), str(self.root / "logs"),
                               str(self.state if state is None else state), mode, blocked],
                              env=self.env, capture_output=True, text=True, timeout=15)

    def install_rollback_script(self):
        """Real rollback.sh from LaunchGuard.cpp, with the same fixture shortcuts as prepare.sh."""
        source = (Path(__file__).parent.parent / "LaunchGuard.cpp").read_text()
        script = re.search(r'R"SH\((.*?)\)SH";', source, re.S).group(1)
        script = script.replace("sleep 0.5", "sleep 0.01")
        script = script.replace("/usr/bin/osascript", str(self.bin / "osascript"))
        self.state.mkdir(exist_ok=True)
        (self.state / "rollback.sh").write_text(script)
        (self.state / "rollback.sh").chmod(0o700)

    def wait_runner_done(self):
        def done():
            runners = subprocess.check_output(["/bin/ps", "-axo", "command="], text=True)
            return not any(str(self.root) in line and "/finish.sh" in line for line in runners.splitlines())
        self.wait_for(done)

    def stop_parent(self):
        if self.parent.poll() is None:
            self.parent.terminate()
        self.parent.wait(timeout=2)

    def authorize_and_exit(self):
        self.commit.write_text("install\n")
        self.stop_parent()

    def wait_for(self, predicate):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.02)
        self.fail("timed out waiting for installer result")

    def assert_old(self):
        self.assertEqual((self.dst / "version").read_text(), "old")

    def test_prepare_never_replaces_live_app_then_installs_after_exit(self):
        result = self.prepare()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ok:5.1.80", result.stdout)
        self.assert_old()
        self.assertFalse((self.root / "opened").exists())
        self.authorize_and_exit()
        self.wait_for(lambda: not list(self.dst.parent.glob(".tribe-update.*")))
        self.assertEqual((self.dst / "version").read_text(), "new")
        self.assertEqual((self.root / "opened").read_text(), "new\n")
        self.assertFalse(self.commit.exists())

    def test_exit_without_handoff_does_not_install(self):
        self.assertEqual(self.prepare().returncode, 0)
        self.stop_parent()
        self.wait_for(lambda: not list(self.dst.parent.glob(".tribe-update.*")))
        self.assert_old()
        self.assertFalse((self.root / "opened").exists())

    def test_parent_timeout_never_replaces_running_app(self):
        self.assertEqual(self.prepare().returncode, 0)
        self.commit.write_text("install\n")
        self.wait_for(lambda: (self.root / "alert").exists())
        self.assert_old()
        self.assertFalse(self.commit.exists())
        self.assertIn("не завершилось", (self.root / "alert").read_text())

    def test_launch_failure_restores_and_reopens_old_app(self):
        self.assertEqual(self.prepare("launch").returncode, 0)
        self.authorize_and_exit()
        self.wait_for(lambda: (self.root / "alert").exists())
        self.assert_old()
        self.assertEqual((self.root / "opened").read_text(), "new\nold\n")

    def test_replace_failure_restores_old_app(self):
        self.assertEqual(self.prepare("replace").returncode, 0)
        self.authorize_and_exit()
        self.wait_for(lambda: (self.root / "alert").exists())
        self.assert_old()

    def test_backup_failure_preserves_old_app(self):
        self.assertEqual(self.prepare("backup").returncode, 0)
        self.authorize_and_exit()
        self.wait_for(lambda: (self.root / "alert").exists())
        self.assert_old()

    def test_failed_rollback_preserves_backup(self):
        self.assertEqual(self.prepare("rollback").returncode, 0)
        self.authorize_and_exit()
        self.wait_for(lambda: (self.root / "alert").exists())
        backup = list(self.dst.parent.glob(".tribe-update.*/previous.app/version"))
        self.assertEqual(len(backup), 1)
        self.assertEqual(backup[0].read_text(), "old")

    def test_preparation_failures_preserve_installed_app(self):
        for fault in ("download", "redirect", "mount", "signature", "team", "notarization",
                      "copy", "staged_signature", "detach", "runner"):
            with self.subTest(fault=fault):
                result = self.prepare(fault)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("fail:", result.stdout)
                self.assertNotIn("ok:", result.stdout)
                self.assert_old()
                self.assertFalse(list(self.dst.parent.glob(".tribe-update.*")))

    def test_old_equal_and_wrong_bundle_rejected(self):
        for version, bundle in (("5.1.78", "hk.wellwon.vpn"), ("5.1.79", "hk.wellwon.vpn"),
                                ("invalid", "hk.wellwon.vpn"), ("", "hk.wellwon.vpn"),
                                ("5.1.80", "other.app")):
            with self.subTest(version=version, bundle=bundle):
                self.set_plist(version, bundle)
                self.assertNotEqual(self.prepare().returncode, 0)
                self.assert_old()

    # ── LaunchGuard: previous copy, pending, watchdog, blocked, percent, auto mode ──────────

    def test_install_keeps_previous_and_pending_then_confirm_stops_watchdog(self):
        self.install_rollback_script()
        (self.root / "alive").write_text("")           # the new version "is running"
        self.assertEqual(self.prepare().returncode, 0)
        self.authorize_and_exit()
        self.wait_for(lambda: (self.state / "pending.json").exists())
        (self.state / "confirmed").write_text("5.1.80\n")   # the new version confirms itself
        self.wait_runner_done()
        self.assertEqual((self.dst / "version").read_text(), "new")
        self.assertEqual((self.state / "previous.app" / "version").read_text(), "old")
        previous = (self.state / "previous.json").read_text()
        self.assertIn('"version":"5.1.79"', previous)
        pending = (self.state / "pending.json").read_text()
        self.assertIn('"from":"5.1.79"', pending)
        self.assertIn('"to":"5.1.80"', pending)
        self.assertIn('"app":"%s"' % self.dst, pending)
        self.assertIn('"attempts":0', pending)
        self.assertIn('"mode":"manual"', pending)
        self.assertFalse((self.state / "rollback.json").exists())
        self.assertFalse(list(self.dst.parent.glob(".tribe-update.*")))

    def assert_rolled_back(self, reason="watchdog"):
        self.assertEqual((self.dst / "version").read_text(), "old")
        self.assertEqual((self.state / "failed.app" / "version").read_text(), "new")
        report = (self.state / "rollback.json").read_text()
        self.assertIn('"from":"5.1.80"', report)
        self.assertIn('"to":"5.1.79"', report)
        self.assertIn('"reason":"%s"' % reason, report)
        self.assertFalse((self.state / "pending.json").exists())
        self.assertFalse((self.state / "previous.json").exists())
        self.assertEqual((self.root / "opened").read_text(), "new\nold\n")

    def test_watchdog_rolls_back_when_new_version_dies_before_confirming(self):
        self.install_rollback_script()
        (self.root / "alive").write_text("")
        self.assertEqual(self.prepare().returncode, 0)
        self.authorize_and_exit()
        self.wait_for(lambda: (self.state / "pending.json").exists())
        (self.root / "alive").unlink()                  # …and then it crashes
        self.wait_runner_done()
        self.assert_rolled_back("watchdog")
        self.assertIn('"mode":"manual"', (self.state / "rollback.json").read_text())

    def test_watchdog_rolls_back_when_new_version_never_appears(self):
        self.install_rollback_script()
        self.assertEqual(self.prepare(mode="auto").returncode, 0)
        self.authorize_and_exit()
        self.wait_runner_done()
        self.assert_rolled_back("watchdog")
        self.assertIn('"mode":"auto"', (self.state / "rollback.json").read_text())

    def test_watchdog_without_rollback_script_leaves_new_version(self):
        self.assertEqual(self.prepare().returncode, 0)
        self.authorize_and_exit()
        self.wait_runner_done()
        self.assertEqual((self.dst / "version").read_text(), "new")
        self.assertFalse((self.state / "rollback.json").exists())

    def test_blocked_version_is_refused_before_install(self):
        result = self.prepare(blocked="5.1.77,5.1.80")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("отозвана", result.stdout)
        self.assertNotIn("ok:", result.stdout)
        self.assert_old()
        self.assertFalse(list(self.dst.parent.glob(".tribe-update.*")))
        # A different blocked version does not interfere.
        self.assertEqual(self.prepare(blocked="5.1.77").returncode, 0)

    def test_download_reports_percent(self):
        result = self.prepare()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        lines = result.stdout.splitlines()
        self.assertIn("percent:100", lines)
        self.assertLess(lines.index("stage:Скачиваем обновление"), lines.index("percent:100"))
        self.assertLess(lines.index("percent:100"), lines.index("stage:Проверяем подпись"))

    def test_auto_mode_opens_new_version_in_background(self):
        (self.root / "alive").write_text("")
        self.assertEqual(self.prepare(mode="auto").returncode, 0)
        self.authorize_and_exit()
        self.wait_for(lambda: (self.root / "open_args").exists())
        self.assertIn("-g", (self.root / "open_args").read_text().splitlines()[0])
        (self.state / "confirmed").write_text("")
        self.wait_runner_done()

    def test_manual_mode_opens_new_version_in_foreground(self):
        (self.root / "alive").write_text("")
        self.assertEqual(self.prepare(mode="manual").returncode, 0)
        self.authorize_and_exit()
        self.wait_for(lambda: (self.root / "open_args").exists())
        self.assertEqual((self.root / "open_args").read_text().splitlines()[0], "-n")
        (self.state / "confirmed").write_text("")
        self.wait_runner_done()

    def test_installed_symlink_rejected(self):
        actual = self.dst.with_name("Actual.app")
        self.dst.rename(actual)
        self.dst.symlink_to(actual, target_is_directory=True)
        self.assertNotEqual(self.prepare().returncode, 0)
        self.assert_old()


if __name__ == "__main__":
    unittest.main()
