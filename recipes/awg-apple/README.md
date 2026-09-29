# awg-apple (Tribe recipe)

Official `amneziawg-apple` v3.1.4 plus reviewable Tribe patches. The package ships the Go
c-archive (`libwg-go.a`) and the exact patched Swift sources (`AWG_APPLE_SOURCE_DIR`) that the iOS
and macOS Network Extension targets compile.

## Versions and patch sets (`conandata.yml`)

| Version | Patches | Notes |
|---|---|---|
| `3.1.4-tribe.10` | 0001 + 0002 + 0003 + 0005 + 0006 + 0007 + 0008 | current; 0008 = immortal logger context (NE crash), real-loss gate, no stale flag |
| `3.1.4-tribe.9` | 0001 + 0002 + 0003 + 0005 + 0006 + 0007 | built for iOS 5.1.97 (127, not released to users); 0007 = fresh port on a returning path, ladder fresh port -> soft restart |
| `3.1.4-tribe.8` | 0001 + 0002 + 0003 + 0005 + 0006 | shipped (iOS 5.1.90-5.1.96); 0006 = persistent heal (stage 3) + in-place soft restart |
| `3.1.4-tribe.7` | 0001 + 0002 + 0003 + 0005 | rollback target; 0005 = bounded GUI/NE recovery (see below) |
| `3.1.4-tribe.5` | 0001 + 0002 + 0003 | shipped (AWG core v3.1.20260828) |
| `3.1.4-tribe.4` | 0001 + 0002 + 0003 | shipped (seamless roaming) |
| `3.1.4-tribe.3` | 0001 + 0002 | shipped |

Rules:

- A released patch file is **never edited**. A behaviour change is a new patch file + a new
  version. `0003-tribe-seamless-roaming.patch` is byte-identical to the one tribe.4/tribe.5 were
  built from (git `0d2dd24c`).
- `3.1.4-tribe.6` was an unpublished review build that edited 0003 in place; it is superseded by
  tribe.7 and intentionally absent from `conandata.yml`.
- Patch slot 0004 is used by `../amnezia-libxray/patches/0004-xray-core-controller-errors.patch`,
  which `export_sources()` copies here and `build()` applies to the vendored xray-core.
- `TribeRoaming.swift` and its build-gate test are **frozen per released version** (tribe.8):
  `tribe/snapshots/<version>/TribeRoaming.swift` + `tests/snapshots/<version>/TribeRoamingTests.swift`
  (tribe.4 and tribe.5 shipped the same file, git `0d2dd24c`; tribe.7 = the file its package was
  built from, RREV `a0d56f8b`). `conanfile.py` (`_roaming_snapshots`) picks the snapshot by
  `self.version`; a version without a snapshot (the current one) builds from `tribe/TribeRoaming.swift`
  and `tests/TribeRoamingTests.swift`. So a tribe.5/tribe.7 rebuilt from this recipe behaves as
  shipped again (until tribe.7 the one shared file made that false). When a version is released and
  the next one changes `TribeRoaming.swift`, copy both files into `snapshots/<released version>/`
  first and add the version to `_roaming_snapshots`.
- The recipe revision changes with every edit of `conanfile.py`, `conandata.yml`, `patches/`,
  `tribe/` or `tests/`; `README.md` is not exported.

## tribe.7 behaviour (patch 0005 + TribeRoaming.swift)

- One owner (`TribeRecoveryArbiter` on the adapter's workQueue) for the stall tracker and the shared
  GUI/NE recovery budget. The budget is asked **before** the escalation stage moves; a refusal
  (rolling cap 4 per 120 s, same-kind cooldown) leaves the stage in place and is retried on the next
  tick, so the fresh-port step fires as soon as the budget frees up.
- Episode = one bump + one fresh port; a fresh port (NE or GUI) closes it; only inbound progress
  (rx bytes / newer handshake) re-arms it. Cooldown separates actions of the same kind only.
- Every recovery step ends with a keepalive (`listen_port=0` is followed by `wgBumpSockets`), so the
  server learns the new port at once and inbound call traffic is not sent to the old address.
- `rebindListenPortResult` reports why a GUI rebind did nothing; the NE answers the `rebind`
  provider message with `{"rebind":"performed"}` or
  `{"rebind":"denied","reason":"budget"|"not_started"|"offline"}` (contract K4).
- A server-provided long-offline pause below 15 s is lifted to 15 s: short flaps never pause the
  device.

## tribe.8 behaviour (patch 0006 + TribeRoaming.swift)

- **Stage 3 of the stall watchdog (U9).** tribe.7 stopped after the fresh port until inbound progress:
  with the GUI suspended a stalled tunnel was never healed again. Now, while the path is satisfied
  and outbound grew since the previous step (>= `stallMinTxBytes`, 256 B during bootstrap) without
  any rx/handshake, the watchdog repeats `bump -> fresh port -> soft restart` (cycling) with a backoff
  of 30, 60, 120 s from the previous step, then 120 s. Every step goes through the shared budget
  (rolling cap 4 per 120 s, same-kind cooldown; the episode limit does not apply to stage 3); a
  refusal does not advance the sequence or the backoff and is retried on the next tick. Inbound
  progress resets the stage and the backoff. A path event (roam rearm) does not reset the backoff.
  At 1 KB/s: bump 6 s, fresh port 15 s, bump 45 s, fresh port 105 s, soft restart 225 s, then every
  120 s.
- **Soft restart (U6).** `wgTurnOff` + `wgTurnOn` with the same configuration on the same TUN fd,
  without `setTunnelNetworkSettings`: new device, new socket, new handshake, while utun, routes and
  app flows (VoIP) survive. Used as stage-3 step and by the new provider message
  `{"action":"soft_restart"}` (engine step 2a before a full re-up of the same node). Reply:
  `{"soft_restart":"performed"}` or `{"soft_restart":"denied","reason":"budget"|"not_started"|"offline"|"failed"}`.
  GUI soft restart = one per episode through the same budget; it consumes the episode's bump and
  fresh port. The arbiter is rebased on the new device's zero counters (not progress). If `wgTurnOn`
  fails, the adapter is left in `temporaryShutdown` (the upstream resume path brings it back on the
  next satisfied path) and 3 in-place retries run 2 s apart.
- **Keepalive only after a fresh port (REV-3).** New Go export `wgSendKeepalives(handle)`
  (`SendKeepalivesToPeersWithCurrentKeypair`, no `BindUpdate`): `listen_port=0` is followed by one
  keepalive instead of a second rebind of the new socket through `wgBumpSockets`.
- Counter drops (new device) are rebased in the budget instead of hiding the new device's first
  inbound bytes; a resume after a long-offline pause re-arms the episode (rolling cap stays).
- New counters `stall_persistent`, `soft_restarts`; NE journal labels `stall_persistent`,
  `soft_restart`, `soft_restart_failed`, `gui_soft_restart[_denied|_not_started]`.

## tribe.9 behaviour (patch 0007 + TribeRoaming.swift)

Field data 24-28.09 (4 iOS devices, 9 device-days, tester journal): in 38 of 44 long "connected
but no data" episodes on cellular the node received nothing from the phone (the carrier NAT/DPI had
killed the UDP flow); a fresh local port healed 31 of 82 stalls, the same-port bump 4 of 27, and the
tribe.4-8 ladder rarely reached its fresh-port step because `rearm` zeroed the stall clock on every
path event (~200/h on cellular). Upstream heals such cases by accident: a real loss restarts the
whole device with a new port.

- **Fresh port on return.** `didReceivePathUpdate`: a satisfied path after a real loss
  (`pathLostAt != nil`) or on another physical interface than the previous satisfied path (Wi-Fi <->
  cellular; `.other` interfaces such as utun are skipped) performs `listen_port=0` + keepalive
  (`TribeRoaming.roamRebindAction`, counter `roam_fresh_ports`, log `Tribe roaming: path returned,
  fresh local port ...`). A path event without a loss on the same interface keeps the upstream
  reaction (same-port `wgBumpSockets`, counter `roam_bumps`).
- **Roam steps do not restart the stall clock.** `TribeRecoveryArbiter.noteRoamRebind(sample,
  freshPort:)` replaces `rearmAfterRoam`: a roam fresh port is recorded as the episode's fresh port
  (`TribeStallTracker.noteExternalStep(.freshPort)`), a bump is not a step; only inbound progress
  resets the clock and the stage.
- **Ladder.** stage 0 -> fresh port after `stallProbeSeconds` (4 s; bootstrap 12 s) with
  `stallMinTxBytes` of demand -> soft restart after `stallProbeSeconds + stallRebindSeconds` (14 s;
  bootstrap 30 s) with double demand and >= 3 s after the fresh port -> stage 3: fresh port, soft
  restart, ... with a backoff of 30, 60, 120 s from the previous step (then 120 s), demand required,
  path satisfied. There is no same-port bump stage any more. GUI fresh port / soft restart
  (provider messages) are recorded as the corresponding step. Budget rules unchanged (episode,
  rolling cap 4 per 120 s, same-kind cooldown 8-10 s).
- Log prefixes for the app's journal labels: `inbound stalled ... fresh local port` (first step),
  `still stalled after the fresh port, soft restart` (second), `persistent heal step N` (stage 3),
  `path returned, fresh local port` (roam).

## tribe.10 behaviour (patch 0008 + TribeRoaming.swift)

- **Logger context (the real NE crash).** Upstream `setupLogHandler` passed `self` unretained to
  `wgSetLogger` and re-retained it inside Go's callback; when that temporary reference was the last
  one (stop() releasing the adapter on workQueue while a goroutine still logs), the adapter was
  deallocated inside `callLogger` (MetricKit 121/122: `WireGuardAdapter.__deallocating_deinit <-
  closure in setupLogHandler <- callLogger`). `wgSetLogger(nil, nil)` in deinit could not help
  (deinit runs after the refcount is zero; Go reads the pointers unsynchronised). Now the context
  is a `LoggerContext` box holding only the log closure, retained forever (one per adapter start);
  deinit no longer touches the global logger. The app's closure must not hold the adapter strongly
  (it reads counters through a weak box on its journal queue).
- **Real loss only.** The roam fresh port needs `everHadHandshake` and an elapsed upstream grace
  window (12 s after `setNetworkSettings`): the route flip right after applying routes is not a loss,
  and a fresh port during the first handshake would lose its response (+5 s REKEY_TIMEOUT).
- **No stale flag.** `roamWantsFreshPort` is read and cleared before the `.started` guard.
- **Budget.** A roam fresh port marks the budget's fresh port spent (`noteExternalFreshPort`), so the
  GUI `rebind` right after it is refused (`episode`) and the engine moves on to `soft_restart`. At
  stage 2 an external fresh port postpones the soft restart only when the previous step is >= 10 s
  old; at stage 3 it never touches the backoff. The soft restart waits a full `stallRebindSeconds`
  after the last step. An `.episode` refusal below stage 3 re-syncs the tracker with the budget.
- Rebuilding a released version from this recipe: set `version` in `conanfile.py` to that version
  first (Conan 2 refuses `--version` that differs from the recipe); the snapshot rule then gives the
  shipped `TribeRoaming.swift`.

## Tests

```sh
sh recipes/awg-apple/tests/run_tribe_roaming_tests.sh   # current version; also the build() gate
# a released version's snapshot (what build() runs for tribe.5/tribe.7):
sh recipes/awg-apple/tests/run_tribe_roaming_tests.sh \
  recipes/awg-apple/tribe/snapshots/3.1.4-tribe.7/TribeRoaming.swift \
  recipes/awg-apple/tests/snapshots/3.1.4-tribe.7/TribeRoamingTests.swift
```

## Rebuilding the package (isolated Conan home, nothing in the global cache changes)

```sh
export CONAN_HOME=/path/to/scratch/conan2           # empty or restored cache
conan profile detect
cat > ios-host-profile <<'EOF'
[settings]
arch=armv8
os=iOS
os.version=16.0
os.sdk=iphoneos
compiler=apple-clang
compiler.version=21
compiler.cppstd=17
compiler.libcxx=libc++
[conf]
tools.cmake.cmaketoolchain:generator=Xcode
EOF
conan export recipes/go --version 1.26.0            # or `conan cache restore` a go/1.26.0 package
conan create recipes/awg-apple \
  --profile:host=default --profile:host=ios-host-profile --profile:build=default \
  -s build_type=Release --build="missing:awg-apple/*"
```

macOS Network Extension (`-DMACOS_NE=ON`): the root `conanfile.py` requires
`awg-apple/3.1.4-tribe.10` there too (tribe.9/tribe.10 have not been built for macOS; the macOS app does not use the NE), and `cmake/platform_settings.cmake` configures it as universal
`arm64;x86_64` with deployment target 12.0. tribe.8 was built for macOS with the profile below
(universal `x86_64 arm64` `libwg-go.a`, `minos 12.0`, `_wgSendKeepalives` in both slices; package id
`744edb127c3ec4851841205920a44fb06d950e81`); the macOS NE Swift sources were typechecked against the
tribe.8 sources. A macOS NE **link** test (it needs the macOS OpenVPNAdapter/HEV packages) was not
run. No macOS binary of tribe.7 exists (tribe.7 is an iOS-only rollback target).

```sh
cat > macos-ne-host-profile <<'EOF'
[settings]
arch=armv8|x86_64
os=Macos
os.version=12.0
compiler=apple-clang
compiler.version=21
compiler.cppstd=17
compiler.libcxx=libc++
[conf]
tools.cmake.cmaketoolchain:generator=Xcode
EOF
conan create recipes/awg-apple \
  --profile:host=default --profile:host=macos-ne-host-profile --profile:build=default \
  -s build_type=Release --build="missing:awg-apple/*"
```

or let the macOS NE CMake configure build it (`--build=missing`), then link-test the NE target.

Moving built packages into the release `CONAN_HOME` (no rebuild):

```sh
CONAN_HOME=<build home> conan cache save 'awg-apple/3.1.4-tribe.8:*' --file awg-tribe8.tgz
CONAN_HOME=<release home> conan cache restore awg-tribe8.tgz
```

The CMake configure export of this recipe must give the same recipe revision as the restored package
(tribe.8: `7c8e0e0254d9e332e935e5b5c35ff165`); otherwise `--build=missing` rebuilds it.

`build()` downloads Go modules (`go mod tidy/vendor`). Offline, or when IPv6 is routed into a
v4-only VPN (sum.golang.org writes fail), point Go at an already verified module download cache:
`GOPROXY=file://<GOPATH>/pkg/mod/cache/download GOSUMDB=off GOTOOLCHAIN=local`.

The app build picks the package up through the root `conanfile.py`
(`self.requires("awg-apple/3.1.4-tribe.10")`); CMake configure exports all `recipes/` itself
(`client/cmake/recipes_bootstrap.cmake`), so use the same `CONAN_HOME` for configure. Rollback =
pin the root requirement back to `awg-apple/3.1.4-tribe.9` or `3.1.4-tribe.8` (iOS; both binaries are
in the release cache), `3.1.4-tribe.7` (the NE sources then lose the `soft_restart` provider message:
revert `PacketTunnelProvider*.swift` to their tribe.7 state) or `3.1.4-tribe.5`. Both can be resolved from a cache that holds their binaries or rebuilt from this
recipe: their `TribeRoaming.swift` and test are frozen snapshots (rule above), their patch lists are
unchanged. The rebuilt recipe revision differs from the original one (the recipe files changed), the
package content does not.
