# Tribe VPN macOS release runbook

## Supported release shape

- The only shippable macOS flavor is the normal daemon-based, arm64
  `TribeVPN_<version>_macos_arm64.pkg` produced by CPack/productbuild.
- macOS Network Extension remains an unsigned arm64/x86_64 compile proof. It
  has no runtime receipt, signing inputs, package, upload, or support claim.
- `make-macos-dist.sh` and `post_uninstall.sh` are retired fail-closed helpers.
  They are not alternate release or cleanup paths.

## Release prerequisites

1. Start from an exact clean commit, including no untracked files.
2. Use Qt 6.11.1, Xcode 26.4, and deployment target macOS 13.
3. The four-part version must be monotonic, for example `5.1.68.97`:
   `5.1.68` is `CFBundleShortVersionString`; `97` is both
   `CFBundleVersion` and the privileged payload `INSTALL-EPOCH`.
4. Supply the reviewed catalog root, the commit-bound `macos_daemon` runtime
   receipt, explicit Developer ID Application/Installer identities and
   keychains, independently pinned lowercase DER SHA-256 values in
   `MAC_APP_CERT_SHA256` and `MAC_INSTALLER_CERT_SHA256`, and a validated
   notarytool keychain profile bound to Team `Q7DVH5MCWF`. Never pass
   notarization passwords on the command line. Set a fresh absolute
   `TRIBE_MACOS_DSYM_OUTPUT_DIR` outside the checkout/build/app trees.
5. Run `metadata/run_tribe_release_gates.sh --release macos_daemon`. The gate
   must leave the clean source snapshot byte-for-byte clean.
6. The signed job may run only from a `macos-v*` tag or an explicit `macos`
   manual selection after approval by the protected `tribe-macos-release`
   environment. Ordinary branch pushes run source/unsigned gates and cannot
   access signing, receipt, or notarization secrets.

## Required artifact gates

The shipping CI job must produce exactly one pkg and prove all of the
following before upload:

- Developer ID Installer Team ID `Q7DVH5MCWF`, successful notarization,
  stapling validation, and `spctl --type install` acceptance;
- root-only product domains and pkg install location `/`;
- one non-relocatable, strict, version-checked, upgrade bundle at
  `Applications/TribeVPN.app`;
- PackageInfo version equals the full four-part release version;
- expanded app identifier `hk.wellwon.vpn`, executable `TribeVPN`, exact
  marketing/build versions, and exact Developer ID Application Team;
- exactly one configured preinstall and postinstall script, with no remaining
  `@...@` placeholder;
- signed resources include the service tar, its SHA-256/version/epoch anchors,
  installer, payload verifier, and legacy migrator.
- five detached dSYMs (GUI, daemon, AWG, OpenVPN and tun2socks) have exact
  UUID/architecture parity, a verified `SHA256SUMS`, and are retained beside
  the pkg; strip runs only after these symbols exist and before signing;
- neither the expanded app nor detached symbols contains the checkout, build
  directory or a per-user `.conan2` path. Apple SDK/toolchain paths are allowed.
- the unsigned staging app, relocated privileged payload and final expanded
  pkg each pass `check_macos_engine_artifact.py` under a no-write/no-network
  sandbox: AWG reports `3.1.20260814`; the daemon contains the closed Xray C
  ABI and linked core module `1.260728.0`; OpenVPN reports `2.7.0` with linked
  OpenSSL `3.6.2`; tun2socks reports `2.6.0` plus its pinned source commit; and
  both geodata files match `engine-lock.json`.

The closed privileged runtime is `Tribe-service`, `amneziawg-go`, `openvpn`,
`tun2socks`, `geoip.dat`, `geosite.dat`, the Qt/OpenSSL Frameworks closure, PF
rules, manifest, symlink inventory, install contract, version and epoch. The
payload must contain no `qsqlmimer` plugin and must pass independent app and
service dyld-closure checks.

## Installation and upgrade invariants

1. Package code copies the entire newly installed app into an unpredictable,
   root-owned `0700` snapshot.
2. It verifies the snapshot's exact signature, identifier, Team ID,
   four-part version, node types, modes and hard-link count before executing a
   resource from it.
3. Legacy migration policy is decided before the service transaction.
4. The service installer authenticates and extracts the signed tar into a
   private directory, verifies its closed manifest and exact modes, verifies
   every Mach-O Team signature, and rejects epoch downgrade/equivocation.
5. The fixed root-owned transaction journal records `prepared`, `old_stopped`,
   `old_saved`, `new_runtime`, `new_plist`, `healthy`, and `committed` with the
   exact epoch, tar digest, runtime version and group-creation fact. Every live
   rename/phase transition crosses a `sync(2)` durability barrier; PID-suffixed
   rollback paths are forbidden.
6. The old service/runtime/plist remain available until launchd reports one
   stable running PID whose text vnode is the new sealed `Tribe-service`.
   Package postflight leaves this as a reversible `healthy` transaction while
   independently rechecking VERSION, launchd identity and the text vnode, and
   only then performs the durable `committed` transition.
7. Productbuild intentionally retains the committed journal and old runtime.
   A later matching/newer signed app proves the package can no longer roll
   back and garbage-collects it; an older signed app first restores and proves
   the retained old launchd job before evaluating downgrade policy. A stopped
   same-version daemon is repaired through the sealed installer rather than a
   passive process-name wait.
8. Only after durable commit may optional legacy garbage collection run. No
   post-commit failure is allowed to make productbuild roll back just the app.
9. The old spaced app `/Applications/Tribe VPN.app` is migrated only when it
   is the proven Q7-signed Tribe bundle and is not newer than the package. The
   known field fixture is version `5.1.64`, build `93`. Foreign bundles,
   symlinks, inode races and newer signed bundles are preserved. Deletion is
   performed only from a root-owned same-volume quarantine after a second
   signature/inode check.
10. `com.antivpn.helper` and the AntiVPN/NeVPN runtime belong to another
   product and must never be inferred, stopped, migrated, or deleted.

## Rollback policy

Never ship a lower `CFBundleVersion`/`INSTALL-EPOCH`, even if its source code is
older and known-good. An emergency rollback is a newly signed/notarized pkg
with the next higher monotonic build/epoch and the selected prior code. A
same-epoch payload with different bytes is rejected.

Before service commit, any failure restores the old runtime and launchd plist,
re-bootstraps it and proves stable launchd PID/text-vnode health before removing
failed/new staging. Signals in product postflight invoke the same rollback;
only the durable `committed` journal phase suppresses app-only rollback. After
commit, diagnostics and legacy cleanup are warning-only. The retained journal
is the recovery proof for power loss or SIGKILL in the narrow productbuild
completion window.

## Supported removal UX

Use **Settings → Remove system service** in the signed app. After confirmation
and the administrator prompt, the fixed bootstrap takes and verifies a
root-owned app snapshot and invokes only its sealed installer in `--uninstall`
mode. Removal:

- stops only the exact Tribe launchd job and exact-path AWG/OpenVPN/Xray
  helpers, with TERM/wait/KILL and zero-process assertions;
- restores native OpenVPN DNS state with the exact signed `Tribe-service`
  before deleting its durable `/private/var/db/TribeVPN` state;
- flushes only Tribe PF anchors and removes only the exact Tribe runtime,
  plist, logs and an unused validated `tribevpn` group;
- does not delete the app, account data, foreign processes, or another VPN.

After the service-removal success message, the user can move `TribeVPN.app` to
Trash. If DNS recovery, provenance, group ownership, or process termination
cannot be proven, removal fails closed and preserves the runtime/state for
diagnosis.

## Operator evidence

Retain the CI log for source/runtime gates, expanded PackageInfo/app checks,
codesign, pkg signature, notarization, stapler and spctl. On a test Mac, record
the installed `VERSION`/`INSTALL-EPOCH`, exact launchd PID/program/state, and a
successful authenticated client connection before widening rollout. Logs are
under `/var/log/TribeVPN`; do not collect credentials or sanitized VPN config
contents.
