import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "deploy" / "tribe" / "tribe-svc-install.sh"
POSTINSTALL = ROOT / "deploy" / "data" / "macos" / "post_install.sh"


class MacosInstallerTransactionTests(unittest.TestCase):
    def test_dns_state_is_recovered_before_runtime_or_state_removal(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        recovery = source.index("--tribe-openvpn-dns-recover-v1")
        remove_state = source.index('rm -rf "$dns_state_dir"', recovery)
        remove_runtime = source.index('rm -rf "$DEST"', recovery)
        self.assertLess(source.index("codesign --verify", source.index("dns_state_dir")), recovery)
        self.assertLess(recovery, remove_state)
        self.assertLess(remove_state, remove_runtime)
        self.assertIn("preserving runtime and state", source)

    def test_durable_journal_and_outer_finalize_order(self) -> None:
        installer = INSTALLER.read_text(encoding="utf-8")
        self.assertIn(
            'TX_ROOT="/Library/PrivilegedHelperTools/.TribeVPN.install-transaction"',
            installer,
        )
        self.assertNotIn(".TribeVPN.old.$$", installer)
        self.assertNotIn(".TribeVPN.new.XXXXXX", installer)
        recovery = installer.index(
            'recover_pending_transaction "$expected_epoch" "$expected_tar_sha"'
        )
        epoch_gate = installer.index('if [ -e "$DEST/INSTALL-EPOCH" ]', recovery)
        begin = installer.index("\nbegin_transaction\n", epoch_gate)
        group_create = installer.index('dscl . -create "/Groups/$GROUP"', begin)
        stopped = installer.index("\nstop_exact_launchd_job\n", begin)
        stopped_phase = installer.index("write_journal old_stopped", stopped)
        save_runtime = installer.index('mv "$DEST" "$OLD"', stopped_phase)
        saved_phase = installer.index("write_journal old_saved", save_runtime)
        install_runtime = installer.index('mv "$NEW" "$DEST"', saved_phase)
        runtime_phase = installer.index("write_journal new_runtime", install_runtime)
        install_plist = installer.index('mv "$PLIST_TMP" "$PLIST"', runtime_phase)
        plist_phase = installer.index("write_journal new_plist", install_plist)
        stable = installer.index('start_launchd_job_and_verify "$PLIST"', plist_phase)
        healthy = installer.index("write_journal healthy", stable)
        commit = installer.index("write_journal committed", healthy)
        relaxed = installer.index("set +e", commit)
        warning_gc = installer.index("cleanup_proven_legacy_tribe_runtime", relaxed)
        success = installer.index("exit 0", warning_gc)
        self.assertLess(recovery, epoch_gate)
        self.assertLess(begin, group_create)
        self.assertEqual(
            [begin, stopped, stopped_phase, save_runtime, saved_phase,
             install_runtime, runtime_phase, install_plist, plist_phase,
             stable, healthy, commit, relaxed, warning_gc, success],
            sorted([begin, stopped, stopped_phase, save_runtime, saved_phase,
                    install_runtime, runtime_phase, install_plist, plist_phase,
                    stable, healthy, commit, relaxed, warning_gc, success]),
        )
        self.assertIn("/bin/sync", installer[installer.index("write_journal() {"):begin])
        self.assertIn("trap 'exit 0' HUP INT TERM", installer[commit:success])
        rollback = installer.index("rollback_transaction() {")
        rollback_start = installer.index('start_launchd_job_and_verify "$PLIST"', rollback)
        rollback_remove = installer.index("remove_transaction_root", rollback_start)
        self.assertLess(rollback_start, rollback_remove)

        postinstall = POSTINSTALL.read_text(encoding="utf-8")
        preflight = postinstall.index('"$EXPECTED_APP_VERSION" preflight')
        service_install = postinstall.index(
            'bash "$INSTALLER" "$TARBALL" --defer-finalize', preflight
        )
        lsof = postinstall.index("/usr/sbin/lsof", service_install)
        finalize = postinstall.index(
            'bash "$INSTALLER" "$TARBALL" --finalize-pending', lsof
        )
        committed = postinstall.index("SERVICE_COMMITTED=1", finalize)
        postcommit_relaxed = postinstall.index("set +e", committed)
        migrate = postinstall.index('"$EXPECTED_APP_VERSION" migrate', postcommit_relaxed)
        final_success = postinstall.rindex("exit 0")
        self.assertEqual(
            [preflight, service_install, lsof, finalize, committed,
             postcommit_relaxed, migrate, final_success],
            sorted([preflight, service_install, lsof, finalize, committed,
                    postcommit_relaxed, migrate, final_success]),
        )
        self.assertIn('bash "$INSTALLER" --rollback-pending', postinstall)
        self.assertNotIn('bash "$INSTALLER" --cleanup-committed', postinstall)

    def test_committed_journal_never_authorizes_signed_downgrade(self) -> None:
        installer = INSTALLER.read_text(encoding="utf-8")
        recovery_start = installer.index("recover_pending_transaction() {")
        recovery_end = installer.index("\n}\n\nfinalize_pending_transaction()", recovery_start)
        recovery = installer[recovery_start:recovery_end]
        older = recovery.index('if [ "$incoming_epoch" -lt "$JOURNAL_EPOCH" ]')
        collision = recovery.index(
            'if [ "$incoming_epoch" -eq "$JOURNAL_EPOCH" ]', older
        )
        older_branch = recovery[older:collision]
        self.assertIn("refusing signed daemon downgrade against committed journal", older_branch)
        self.assertIn("return 1", older_branch)
        self.assertNotIn("rollback_transaction", older_branch)
        self.assertNotIn("remove_transaction_root", older_branch)

    def test_committed_crash_recovery_rejects_lower_and_same_epoch_collision(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        start = source.index("recover_pending_transaction() {")
        end = source.index("\n}\n\nfinalize_pending_transaction()", start) + 2
        recovery_function = source[start:end]
        with tempfile.TemporaryDirectory(prefix="tribe-committed-recovery-") as raw:
            root = Path(raw)
            transaction = root / "transaction"
            transaction.mkdir()
            (transaction / "JOURNAL").write_text("durable committed fixture\n", encoding="utf-8")
            marker = root / "marker"
            committed_hash = "a" * 64
            colliding_hash = "b" * 64
            harness = f"""set -euo pipefail
TX_ROOT=$1
JOURNAL=$TX_ROOT/JOURNAL
MARKER=$2
TRANSACTION_STARTED=0
TRANSACTION_COMMITTED=0
JOURNAL_PHASE=
JOURNAL_EPOCH=
JOURNAL_TAR_SHA=
load_journal() {{
  JOURNAL_PHASE=committed
  JOURNAL_EPOCH=97
  JOURNAL_TAR_SHA={committed_hash}
}}
discard_unstarted_transaction() {{ echo discard >> "$MARKER"; }}
rollback_transaction() {{ echo rollback >> "$MARKER"; }}
verify_current_transaction() {{ echo verify >> "$MARKER"; return 0; }}
cleanup_committed_transaction() {{ echo cleanup >> "$MARKER"; }}
{recovery_function}

# Models a crash immediately after the durable committed journal rename but
# before any caller-side in-memory commit flag was assigned.
if recover_pending_transaction 96 {committed_hash}; then exit 70; fi
test ! -e "$MARKER"
test "$TRANSACTION_STARTED" = 1

TRANSACTION_STARTED=0
if recover_pending_transaction 97 {colliding_hash}; then exit 71; fi
test ! -e "$MARKER"
test "$TRANSACTION_STARTED" = 1

TRANSACTION_STARTED=0
recover_pending_transaction 97 {committed_hash}
test "$(cat "$MARKER")" = $'verify\ncleanup'
test "$TRANSACTION_STARTED" = 0
"""
            result = subprocess.run(
                ["/bin/bash", "-c", harness, "--", str(transaction), str(marker)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_journal_atomic_phase_roundtrip_and_duplicate_rejection(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        start = source.index("journal_value() {")
        end = source.index("\nremove_transaction_root() {", start)
        functions = source[start:end]
        with tempfile.TemporaryDirectory(prefix="tribe-journal-") as raw:
            temp = Path(raw)
            fake_bin = temp / "bin"
            fake_bin.mkdir()
            for name, body in {
                "chown": "#!/bin/bash\nexit 0\n",
                "stat": "#!/bin/bash\necho root:wheel:600:1\n",
            }.items():
                path = fake_bin / name
                path.write_text(body, encoding="utf-8")
                path.chmod(0o755)
            tx = temp / "transaction"
            tx.mkdir(mode=0o700)
            harness = f"""set -euo pipefail
TX_ROOT=$1
JOURNAL=$TX_ROOT/JOURNAL
JOURNAL_HAD_DEST=1
JOURNAL_HAD_PLIST=1
JOURNAL_EPOCH=96
JOURNAL_TAR_SHA={'a' * 64}
JOURNAL_RUNTIME_VERSION={'b' * 64}
JOURNAL_GROUP_CREATED=0
JOURNAL_PHASE=
validate_transaction_root() {{ return 0; }}
{functions}
write_journal prepared
write_journal healthy
load_journal
test "$JOURNAL_PHASE" = healthy
test "$(wc -l < "$JOURNAL" | tr -d ' ')" = 8
cp "$JOURNAL" "$JOURNAL.good"
printf 'phase=committed\n' >> "$JOURNAL"
if load_journal; then exit 70; fi
mv "$JOURNAL.good" "$JOURNAL"
write_journal committed
load_journal
test "$JOURNAL_PHASE" = committed
"""
            env = os.environ.copy()
            env["PATH"] = f"{fake_bin}:/usr/bin:/bin"
            result = subprocess.run(
                ["/bin/bash", "-c", harness, "--", str(tx)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_every_interrupted_filesystem_phase_restores_old_runtime_and_health(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        start = source.index("rollback_transaction() {")
        end = source.index("\n}\n\ncleanup_proven_legacy_tribe_runtime()", start) + 2
        rollback_function = source[start:end]
        phases = {
            "prepared": ("dest-old", "plist-old"),
            # Crash between the two old-tree moves while the durable phase is
            # still old_stopped.
            "old_stopped": ("old-saved", "plist-old"),
            "old_saved": ("old-saved", "plist-saved"),
            "new_runtime": ("old-and-new", "plist-saved"),
            "new_plist": ("old-and-new", "plist-old-and-new"),
            "healthy": ("old-and-new", "plist-old-and-new"),
            "committed": ("old-and-new", "plist-old-and-new"),
        }
        for phase, (runtime_state, plist_state) in phases.items():
            with self.subTest(phase=phase), tempfile.TemporaryDirectory(
                prefix=f"tribe-crash-{phase}-"
            ) as raw:
                root = Path(raw)
                tx = root / "transaction"
                tx.mkdir()
                dest = root / "TribeVPN"
                old = tx / "old-runtime"
                failed = tx / "failed-runtime"
                new = tx / "new-runtime"
                plist = root / "Tribe-service.plist"
                plist_old = tx / "old-launchd.plist"
                plist_tmp = tx / "new-launchd.plist"

                if runtime_state in {"dest-old", "old-and-new"}:
                    dest.mkdir()
                    (dest / ("new.marker" if runtime_state == "old-and-new" else "old.marker")).touch()
                if runtime_state in {"old-saved", "old-and-new"}:
                    old.mkdir()
                    (old / "old.marker").touch()
                if phase == "prepared":
                    new.mkdir()
                    (new / "staged.marker").touch()
                if plist_state in {"plist-old", "plist-old-and-new"}:
                    plist.write_text(
                        "new\n" if plist_state == "plist-old-and-new" else "old\n",
                        encoding="utf-8",
                    )
                if plist_state in {"plist-saved", "plist-old-and-new"}:
                    plist_old.write_text("old\n", encoding="utf-8")

                harness = f"""set -euo pipefail
DEST=$1
OLD=$2
FAILED=$3
NEW=$4
PLIST=$5
PLIST_OLD=$6
PLIST_TMP=$7
TX_ROOT=$8
LABEL=Tribe-service
JOURNAL_PHASE={phase}
JOURNAL_HAD_DEST=1
JOURNAL_HAD_PLIST=1
JOURNAL_GROUP_CREATED=0
TRANSACTION_RECOVERED=0
load_journal() {{ return 0; }}
stop_exact_launchd_job() {{ return 0; }}
validate_launchd_plist_file() {{ test -f "$1" && test ! -L "$1"; }}
start_launchd_job_and_verify() {{
  test -f "$DEST/old.marker"
  test "$(cat "$1")" = old
  touch "$TX_ROOT/old-health-proven"
}}
remove_transaction_root() {{
  test -f "$TX_ROOT/old-health-proven"
  rm -rf "$TX_ROOT"
}}
{rollback_function}
rollback_transaction
test -f "$DEST/old.marker"
test ! -e "$DEST/new.marker"
test "$(cat "$PLIST")" = old
test ! -e "$TX_ROOT"
test "$TRANSACTION_RECOVERED" = 1
"""
                result = subprocess.run(
                    [
                        "/bin/bash", "-c", harness, "--", str(dest), str(old),
                        str(failed), str(new), str(plist), str(plist_old),
                        str(plist_tmp), str(tx),
                    ],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_journal_less_begin_crash_is_cleaned_only_without_staged_state(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        start = source.index("discard_unstarted_transaction() {")
        end = source.index("\n}\n\nvalidate_service_binary()", start) + 2
        function_source = source[start:end]
        with tempfile.TemporaryDirectory(prefix="tribe-unstarted-") as raw:
            root = Path(raw)
            clean = root / "clean"
            clean.mkdir()
            interrupted = root / "interrupted"
            interrupted.mkdir()
            (interrupted / ".JOURNAL.new").write_text("partial\n", encoding="utf-8")
            staged = root / "staged"
            staged.mkdir()
            (staged / "new-runtime").mkdir()
            symlinked = root / "symlinked"
            symlinked.mkdir()
            (symlinked / ".JOURNAL.new").symlink_to(root / "foreign")
            harness = f"""set -euo pipefail
{function_source}
validate_transaction_root() {{ test -d "$TX_ROOT" && test ! -L "$TX_ROOT"; }}
remove_transaction_root() {{ rm -rf "$TX_ROOT"; }}
stat() {{ printf 'root:wheel:600:1\n'; }}
for accepted in "$1" "$2"; do
  TX_ROOT=$accepted
  JOURNAL=$TX_ROOT/JOURNAL
  discard_unstarted_transaction
  test ! -e "$TX_ROOT"
done
for rejected in "$3" "$4"; do
  TX_ROOT=$rejected
  JOURNAL=$TX_ROOT/JOURNAL
  if discard_unstarted_transaction; then exit 71; fi
  test -d "$TX_ROOT"
done
"""
            result = subprocess.run(
                ["/bin/bash", "-c", harness, "--", str(clean), str(interrupted),
                 str(staged), str(symlinked)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_injected_postcommit_legacy_gc_failure_returns_success(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        start = source.index("cleanup_proven_legacy_tribe_runtime() {")
        end = source.index("\n}\n\ncleanup_committed_transaction()", start) + 2
        function_source = source[start:end].replace(
            'legacy_dir="/Library/PrivilegedHelperTools/Tribe"',
            'legacy_dir="$TRIBE_TEST_LEGACY_DIR"',
        )

        with tempfile.TemporaryDirectory(prefix="tribe-postcommit-gc-") as raw:
            temp = Path(raw)
            fake_bin = temp / "bin"
            fake_bin.mkdir()
            legacy = temp / "Tribe"
            legacy.mkdir()
            (legacy / "Tribe-service").write_text("signed fixture\n", encoding="utf-8")
            plist = temp / "old.plist"
            plist.write_text("fixture\n", encoding="utf-8")

            commands = {
                "plutil": """#!/bin/bash
case "$2" in Label) echo Tribe-service ;; ProgramArguments.0) printf '%s/Tribe-service\n' "$TRIBE_TEST_LEGACY_DIR" ;; *) exit 1 ;; esac
""",
                "stat": "#!/bin/bash\necho root\n",
                "codesign": "#!/bin/bash\nexit 0\n",
                "rm": "#!/bin/bash\nexit 71\n",
            }
            for name, body in commands.items():
                path = fake_bin / name
                path.write_text(body, encoding="utf-8")
                path.chmod(0o755)

            harness = (
                "set -euo pipefail\n"
                "LABEL=Tribe-service\n"
                "PLIST_OLD=$1\n"
                "TEAM_REQUIREMENT=fixture\n"
                f"{function_source}\n"
                "cleanup_proven_legacy_tribe_runtime\n"
            )
            env = os.environ.copy()
            env["PATH"] = f"{fake_bin}:/usr/bin:/bin"
            env["TRIBE_TEST_LEGACY_DIR"] = str(legacy)
            result = subprocess.run(
                ["/bin/bash", "-c", harness, "--", str(plist)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("cleanup failed after commit", result.stdout)
            self.assertTrue(legacy.is_dir())


if __name__ == "__main__":
    unittest.main()
