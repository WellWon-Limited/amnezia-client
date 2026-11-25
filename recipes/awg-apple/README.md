# awg-apple (Tribe recipe)

Official `amneziawg-apple` v3.1.4 plus reviewable Tribe patches. The package ships the Go
c-archive (`libwg-go.a`) and the exact patched Swift sources (`AWG_APPLE_SOURCE_DIR`) that the iOS
and macOS Network Extension targets compile.

## Versions and patch sets (`conandata.yml`)

| Version | Patches | Notes |
|---|---|---|
| `3.1.4-tribe.19` | the patches of tribe.18 | current (iOS 142, not released); tribe.18 after device round air-D (section "tribe.19 behaviour"): a fresh-port roam is another network, a stale session is proved at once on the new path. TribeRoaming.swift only |
| `3.1.4-tribe.18` | the patches of tribe.17 | superseded by tribe.19, not released; tribe.17 after the second review (section "tribe.18 behaviour"): a handshake only by its time moving, RandomTrailers as the engine reads it, service TX settled over the handshake window. TribeRoaming.swift + the gate `tests/check_engine_spellings.sh` |
| `3.1.4-tribe.17` | the patches of tribe.16 (0017 included) | superseded by tribe.18, not released; tribe.16 after its review (section "tribe.17 behaviour"): service traffic from the session's configuration, idle end of an episode, sampling gaps, the stall verdict `data_stall_s` for the app. TribeRoaming.swift only |
| `3.1.4-tribe.16` | the patches of tribe.15 + 0017 | built into 142 dev builds of 24-25.11, not released, superseded by tribe.17 (rebuilt from this recipe it gets tribe.17's TribeRoaming.swift); one definition of "data is flowing" for the stall ladder, its budget and the app's failover (`TribeDataFlow` in `TribeRoaming.swift`, section "tribe.16 behaviour"); 0017 = the adapter's `roamingCounters()` also reads `dataQuietSeconds`, the provider replies it as `data_quiet_s`. tribe.14 and tribe.15 were never released: no `TribeRoaming.swift` snapshot is frozen for them (rebuilt from this recipe they get tribe.16's ladder) |
| `3.1.4-tribe.15` | the patches of tribe.14 (+ engine patch 0014, host limits) | built into 5.1.111 / 142 dev builds before tribe.16, not released |
| `3.1.4-tribe.14` | 0001 + 0002 + 0003 + 0005 + 0006 + 0007 + 0008 + 0009 + 0010 + 0011 + 0012 + 0013 + 0014 + 0015 + 0016 (+ the engine and vendored patches of tribe.12) | iOS 5.1.111 / 141, not released; tribe.12 + the data watch in two patches: 0012 = the Go half, the in-tunnel probe (`tribeprobe.go`), in the slot tribe.12 left for it; 0016 = the adapter half (`TribeDataWatch.swift` fed on the stall tick, the arbiter's commands; the engine stop of an in-place switch runs through 0015's backend hook). Off unless the app's plan file enables it. Two patches because the recipe's patch tool matches hunks at exact line numbers and 0015 was recorded on an adapter without the data watch. `3.1.4-tribe.13` was the data watch branch's own number before the merge and is not kept |
| `3.1.4-tribe.12` | 0001 + 0002 + 0003 + 0005 + 0006 + 0007 + 0008 + 0009 + 0010 + 0011 + 0013 + 0014 (+ before vendoring: engine 0012-tribe-scan-engine; vendored: core 0004-261101 + 0008-261101 + 0011-261101, libxray 0005 + 0006 + 0007) | built into 5.1.110 / 140; Xray core v1.261101.0 on Go 1.27.4, 0010 = `LibXrayTribeHTTP`, 0011 = `LibXrayTribeOutboundStats` (libxray 0007, core 0008), 0013 = the Scanner's probe engine (`LibXrayTribeScanMessage` / `LibXrayTribeScanStopAll`, core 0011), 0014 = its AmneziaWG mini-session runner (`awg_mini`, no new export), libxray 0005 = FreeOSMemory loop once per process, libxray 0006 = StopXray restores the Go memory settings. 0015 (in `conandata.yml`) = the adapter's backend-restart hook. Slot 0012 was left for the data watch; merged with it this version became `3.1.4-tribe.14` |
| `3.1.4-tribe.11` | 0001 + 0002 + 0003 + 0005 + 0006 + 0007 + 0008 + 0009 | shipped (5.1.109 / 139); 0009 = userspace direct split (`directsplit.go`), off unless the app configures it |
| `3.1.4-tribe.10` | 0001 + 0002 + 0003 + 0005 + 0006 + 0007 + 0008 | shipped (iOS 5.1.98-5.1.99); 0008 = immortal logger context (NE crash), real-loss gate, no stale flag |
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
- Patch slot 0004 is used by `../amnezia-libxray/patches/0004-xray-core-controller-errors.patch`
  (core v1.260728.0, tribe.3-tribe.11) or `0004-xray-core-261101-controller-errors.patch` (core
  v1.261101.0, tribe.12), which `export_sources()` copies here and `build()` applies to the
  vendored xray-core. The same holds for libxray patches such as
  `../amnezia-libxray/patches/0005-libxray-forcefree-once.patch` (applied to the vendored
  `amnezia-libxray`). Which core, Go toolchain and shared patches a version uses is the
  `_xray_pins` table in `conanfile.py` (absent = the tribe.3-tribe.11 pins).
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

## tribe.11 behaviour (patch 0009, Go only)

Swift sources and `TribeRoaming.swift` are those of tribe.10. The patch adds `directsplit.go` and
one line in `wgTurnOn`.

- `wgSetDirectSplit(listPath, enabled)` (before `wgTurnOn`) loads a CIDR list (one per line, IPv4
  and IPv6) into a sorted range set. Returns the number of ranges, 0 on reset, -1 when the list
  cannot be read: the split is then off and all traffic goes into the tunnel.
- `wrapDirectSplitIfEnabled` wraps the TUN device (outside the `dnsfwd` wrapper). `Read` classifies
  every packet by destination: TCP/UDP to an address in the set is injected into a gVisor stack,
  everything else (other destinations, ICMP to listed addresses) is returned to the WireGuard device
  untouched. gVisor is already vendored through xray-core; no new module is added.
- TCP: the forwarder dials the real destination from an ordinary extension socket first and
  completes the app's handshake only after that, so an outside refusal reaches the app as a reset.
  A break is passed on as a break in both directions (outside reset -> reset to the app, app reset
  -> reset to the server); a clean half-close leaves the other direction open with no time limit,
  as the kernel does. An app that vanished is found by keepalive (10 min idle, 4 probes 30 s apart).
- UDP: one outer socket per app source address and port (the mapping does not depend on the
  destination); replies are accepted only from addresses the app has written to. Idle is counted
  per flow (2 min); a failed send or a deferred receive error drops a datagram, never the session,
  so the outer port stays the same. The outer socket's datagram limit is raised to 128 KiB (darwin
  defaults to 9216 bytes) and replies are read into a full-size buffer taken only when the socket
  is readable.
- `wgDirectSplitPathChanged()` resets all direct TCP flows (the app gets a reset and reconnects at
  once). The provider calls it when the physical uplink changes (Wi-Fi <-> cellular): the outer
  sockets stay on the old interface while the app's side, which runs over the TUN, sees nothing.
- The engine outlives the device: `wgTurnOff` + `wgTurnOn` on the same TUN (soft restart) keeps
  direct flows. `wgSetDirectSplit(_, 0)` shuts it down.
- Limits (the extension has 50 MB): 192 TCP flows including those still connecting, 64 SYNs in
  flight, TCP buffers 32 KiB default / 64 KiB max per direction, TIME_WAIT 5 s (default 60 s keeps
  ~8 KiB per closed flow), 256 UDP sessions (the least recently active one is evicted), 64 flows
  per session (the least recently active one is evicted), 512 UDP flows in total, Go soft memory
  limit 36 MiB (set only when no lower limit is already in place).
- `wgDirectSplitStats()` returns
  `tcp=open/total fail=N reset=N udp=sessions/total flows=N up=bytes down=bytes` or `off`.
- The basis is the same as for `dnsfwd.go` and WireGuard's own socket: iOS does not route the
  provider's sockets into its tunnel.
- Not covered: ICMP to listed addresses stays in the tunnel; the engine keeps the MTU of the first
  device.

Build gate: `go test -run '^(TestDirect|TestForeign)'` (a second gVisor stack plays the phone; real
loopback sockets play the servers): range set, classification, TCP echo over IPv4 and IPv6 (2 MiB),
fast failure on refusal, a server reset reaching the app as a reset, a path change resetting flows,
foreign traffic reaching the tunnel, one outer UDP port for two servers with correct reply sources,
a 20 KiB datagram, the per-session flow cap and per-flow idle, the outer port surviving a failed
send, a flow surviving a device restart, toggle. An independent review (Opus) preceded the merge:
its three blocking findings (unbounded UDP flows, TCP memory sizing, session torn down by a send
error) and the reset, path-change, buffer and clock findings are fixed in this patch.

## tribe.12 behaviour (core v1.261101.0, patches 0010 + 0011, libxray 0005-0007, core 0008)

Swift sources and `TribeRoaming.swift` are those of tribe.11 (= tribe.10).

- **Core.** `go mod edit -replace github.com/xtls/xray-core=github.com/amnezia-vpn/amnezia-xray-core@v1.261101.0`
  (Xray 26.10.31; no upstream wrapper pins it), Go 1.27.4 (the core's `go.mod` says `go 1.27`;
  `go mod tidy` raises the wrapper's `go` line). `build()` fails unless `go list -m` resolves the
  replacement to exactly that tag. libxray stays v1.0.3 (compiles unchanged against the new core).
- **Core patch.** Since 261101 the system dialer itself returns controller errors (TCP and UDP);
  the listener still logged and continued. `0004-xray-core-261101-controller-errors.patch` patches
  only the listener and its test pins all three paths (listener, TCP dial, UDP dial) fail-closed.
- **Go runtime diff.** `goruntime-boottime-over-monotonic.diff` applies to Go 1.27.4 unchanged
  (offsets only); `nanotime` uses `mach_continuous_time` in both darwin assembly files.
- **Go 1.27 minimum macOS.** The Go 1.27 linker stamps `go.o` with macOS 13.0 (`cmd/link`
  `macOS = macVersionFlag{13, 0, 0}`), so the macOS NE package (deployment target 12.0) now has
  one object with minos 13.0. The macOS app uses the daemon (target 13.0), not the NE; iOS objects
  stay at 16.0.
- **FreeOSMemory loop once (libxray 0005).** libxray v1.0.3 `nodep.InitForceFree` started a new,
  unstoppable `debug.FreeOSMemory` goroutine on every `RunXray`; each core restart in one extension
  process (reconnect, uplink change) added one. The loop now starts once per process
  (`sync.Once`) and survives `StopXray`/`RunXray`; every call still applies its own
  `SetGCPercent(10)` and `SetMemoryLimit(maxMemory)`, and updates the interval. Gate:
  `TestTribeForceFreeLoopStartsOnce` (51 starts -> 1 loop, no goroutine growth).
- **Xray memory regime ends with the session (libxray 0006).** The first `InitForceFree` of a
  session saves the process's GC percent and soft memory limit; `StopXray` (and a `RunXray` that
  failed) restores them and parks the release loop. Before, a later AWG session in the same
  extension process kept `GOGC=10`, the Xray limit and a `FreeOSMemory` call every second (the
  AWG path sets only a 36 MiB limit, only with the direct split on and only when no lower limit is
  in place, and never touches the GC percent). Gates: `TestTribeRestoreRuntimeAfterSession`
  (nodep: restore, parked loop, resume, still one loop) and `TestTribeXraySessionRestoresRuntime`
  (xray: a real core start/stop and a failed start).
- **`LibXrayTribeHTTP` (0010).** One HTTPS request through the running core's local SOCKS5
  inbound, for the lease renewer in the iOS extension (its own sockets bypass its tunnel, and
  iOS 16 has no URLSession SOCKS proxy). Frozen ABI `libxray-tribe-http-v1`
  (`AWG_APPLE_TRIBE_HTTP_ABI`):

  ```c
  extern char *LibXrayTribeHTTP(const char *socksAddr, const char *user, const char *pass,
                                const char *method, const char *url, const char *headersJSON,
                                const char *body, int64_t timeoutMs, int64_t maxBodyBytes);
  ```

  - Arguments may be NULL (= empty). `socksAddr` must be a loopback IP literal with port
    (`[::1]:10808`, `127.0.0.1:10808`); `user`/`pass` empty = no auth, else RFC 1929.
    `method`: GET, HEAD, POST, PUT, PATCH, DELETE (case-insensitive). `url`: `https://` only, no
    userinfo. `headersJSON`: a JSON object of strings (`{"Authorization":"Bearer ..."}`) or empty;
    Host, Content-Length, Transfer-Encoding, Connection, Proxy-*, Upgrade, TE, Trailer and
    Keep-Alive are refused. `body`: the request body as text (no NUL bytes), at most 256 KiB.
    `timeoutMs` <= 0 -> 10 s, clamped to 60 s; it bounds the whole call (SOCKS handshake, TLS,
    headers, body). `maxBodyBytes` <= 0 -> 64 KiB, clamped to 1 MiB.
  - Returns a malloc'd UTF-8 JSON string that the caller releases with `free()`; never NULL:

    ```json
    {"status":200,"headers":{"Content-Type":"application/json","X-Multi":"a, b"},
     "body_base64":"eyJvayI6dHJ1ZX0=","error":"","error_code":""}
    ```

    `status` = 0 when no HTTP response arrived; header names are canonical, repeated values are
    joined with `", "`. On failure `error` carries Go's text and `error_code` one of
    `bad_request`, `socks_auth` (wrong or missing credentials), `socks` (the proxy refused the
    CONNECT, e.g. host unreachable), `timeout`, `tls` (certificate or handshake), `redirect_refused`
    (a redirect to another scheme/host/port, or more than 3 same-origin hops; `status` = the 3xx),
    `body_too_large` (`status` kept, body dropped), `transport` (anything else).
  - The host NAME goes to the proxy (SOCKS5 ATYP domain), so the profile's routing and DNS decide
    where the request leaves; the extension never resolves it. TLS is Go's `crypto/tls` (TLS 1.2+)
    with the platform verifier and system roots (`RootCAs` nil; on `GOOS=ios` that is
    Security.framework). Each call builds its own transport (no keep-alive, no proxy environment,
    no compression) and touches no global state: safe concurrently with itself and with a running
    core.
  - Gate: `go test -run '^TestTribeHTTP' tribehttp.go tribehttp_test.go`: local SOCKS5 server with
    password auth + local HTTPS servers behind names only the proxy resolves (success with method,
    headers, body and the ATYP-domain check; wrong/missing credentials; total timeout with a stalled
    body and a stalled proxy; body cap exact/over/explicit; cross-host redirect refused without
    dialling the target, same-origin redirect followed, loop refused; bad input; system roots refuse
    an unknown CA; 32 concurrent calls; also clean under `-race`).

- **`LibXrayTribeOutboundStats` (0011 + libxray 0007 + core 0008).** Per-outbound byte counters of
  the running core, read in process: no gRPC API inbound, no listener, the export never changes the
  config. Frozen ABI `libxray-tribe-stats-v1` (`AWG_APPLE_TRIBE_STATS_ABI`):

  ```c
  extern char *LibXrayTribeOutboundStats(void);
  ```

  - Returns a malloc'd JSON string, never NULL; the caller releases it with `free()`:

    ```json
    {"running":true,"outbounds":{"proxy":{"uplink":150034,"downlink":250002}},
     "error":"","error_code":""}
    ```

    `running:false` with `"outbounds":{}` when no core runs (also right after `StopXray`);
    `error_code:"stats_disabled"` (`outbounds` empty) when the running config has no stats feature.
    Counters are cumulative since this core instance started, never reset by the call; a new
    `RunXray` starts from zero. Tagged outbounds are present from start (zeros); an outbound that
    never carried traffic may also be absent. `uplink` = bytes the outbound wrote to its peer,
    `downlink` = bytes it read, on the outbound's own connection: the proxy protocol's framing is
    included (VLESS: 26 B request header + 2 B response header per connection in the test), TLS /
    REALITY record overhead is not (the counter sits above the transport's security layer).
  - Safe from any thread, concurrently with traffic and with `RunXray`/`StopXray`: libxray's
    instance pointer is now guarded by an RWMutex (`coreMu`); counters are atomics.
  - **The caller enables the counters before start** by MERGING into the config (never replacing
    an existing `policy`, which may carry `levels` and other `system` keys):

    ```json
    "stats": {},
    "policy": {"system": {"statsOutboundUplink": true, "statsOutboundDownlink": true}}
    ```

    No `api` section, no extra inbound. Only outbounds with a non-empty `tag` get counters (the
    core skips untagged ones), so the sanitizer must keep or assign a tag on every outbound.
  - **What to bill.** Count only user-facing tags (outbounds that routing rules or balancers
    send user traffic to). A `sockopt.dialerProxy` hop counts the same bytes again: measured,
    `chainA` (dialled through `hopB`) = `{uplink 120034, downlink 220002}` and `hopB` = the same
    `{120034, 220002}` for a 120 008 / 220 000 B payload, so summing every tag double-counts chains.
    `direct`/freedom outbounds count what the profile sends past the provider (exactly the payload:
    200 008 / 300 000 B). Also counted under a proxy tag: DNS queries the profile routes through it
    and observatory / balancer probes (`burstObservatory` downloads through every subject).
  - **Core 0008 (a counter bug in Xray 26.10.31).** `buf.NewWriter` unwraps the stats connection
    into a `BufferToBytesWriter` whose embedded writer's `Write` was promoted, so the buffered first
    write of a stream outbound (the VLESS header plus the first payload, up to 8 KiB) bypassed the
    uplink counter: before the fix `proxy` showed 141 816 for a 150 034 B wire upload (-8 218 B per
    connection). `BufferToBytesWriter.Write` now counts. Gate `TestTribeBufferedFlushIsCounted`
    (counted 3 000 of 7 014 bytes without the fix).
  - Gate `TestTribeOutboundStats` (`-race`): a real client core (SOCKS5 inbound; `direct`
    freedom, `proxy` VLESS to a second local core, `chainA` VLESS through `hopB` freedom) against
    local sinks with known payloads; each tag within payload .. payload + 1 % + 1 KiB, no
    cross-tag leakage, cumulative, `stats_disabled` for a config without stats, four readers
    hammering the export through the traffic and through three stop/start cycles, zero after a
    restart, `running:false` after stop. Measured (uplink / downlink, payload 8 + N bytes up):
    direct 200 008 / 300 000 for 200 008 / 300 000; proxy 150 034 / 250 002 for 150 008 / 250 000;
    chainA and hopB 120 034 / 220 002 each for 120 008 / 220 000. Verified on plain VLESS over TCP
    only; TLS, REALITY, xhttp, gRPC, WebSocket, Hysteria2 and Vision splice paths are not covered
    by this test.

## tribe-scan (patch 0013, engine 0012, core 0011; ABI `libxray-tribe-scan-v1`)

The Scanner's probe engine, package `tribescan` (shared, module-agnostic engine patch
`../amnezia-libxray/patches/0012-tribe-scan-engine.patch`, applied to `Sources/WireGuardKitGo`
before `go mod vendor`; the same file builds into `amnezia-xray-bindings` and the Android
`amnezia-libxray` AAR). It is the HOST side of the app's `tribe-scan-v1` contract, whose owner is
`client/core/serviceEngine/ScanHostContract.h` (requests, replies, item fields, error names,
`reason`s, host behaviour); the app's shared vectors
(`client/core/serviceEngine/tests/vectors/scan_host_vectors.json`) are replayed by
`TestTribeScanSharedVectors` (the recipe copies the file into the build when it exists).
`AWG_APPLE_TRIBE_SCAN_ABI` = `libxray-tribe-scan-v1`.

```c
extern char *LibXrayTribeScanMessage(const char *messageJSON, const char *hostOptionsJSON);
extern char *LibXrayTribeScanStopAll(int64_t waitMs);
```

- `LibXrayTribeScanMessage`: one app message (`scan_caps`, `scan_start`, `scan_add`, `scan_poll`,
  `scan_freeze`, `scan_cancel`) relayed AS IS from the `{"action":...}` channel; returns the reply (`scan_caps`,
  `scan_ack`, `scan_progress` or `{"error":...}`, including `unknown_action` for any action this host
  does not know). Malloc'd JSON, never NULL; the caller frees it with `free()`.
  `hostOptionsJSON` (NULL = none): `scan_start` reads
  `{"bind_interface_index": <the physical interface's index>}` - required (`bad_request` /
  `host_options.bind_interface` without it); `"bind_interface": "en0"` is accepted too; optional
  `"mem_start_min_mb"` / `"mem_run_min_mb"` override the 12 / 8 MB guard. EVERY message may carry
  `"gen": {"source": "ne", "epoch": "<16 lower-case hex>", "counter": n}` - the host's own path
  monitor element (`ScanNetworkGeneration.h`); the engine passes the latest one through as the
  progress `gen` and stamps it on each access attempt when the attempt starts (a malformed `gen`
  is ignored; send it with `scan_start`, every poll and `scan_cancel`).
- `LibXrayTribeScanStopAll(waitMs)`: tears the scan down (reason `tunnel_stopped`) and waits up to
  `waitMs` (max 10000); `{"stopped":true}` = NOTHING of any scan is alive any more: no probe
  instance (full or leg, the background leg closes included), no reach / data job, no AmneziaWG
  device, no desktop probe child (killed with SIGKILL and reaped), no access attempt (a stop
  cancels the closing attempt: it is then not attempted, log code `stopped`), no goroutine that can
  still open a socket. `{"stopped":false,...}` = the wait ran out: the teardown goes on in the
  background, every `scan_start` is refused with `{"error":"internal","detail":"stopping"}` until it
  has finished, and a later StopAll waits for it again. The false reply names what is still alive at
  that moment, top-level numbers in a fixed order (`LiveWork()`):
  `{"stopped":false,"instances":1,"jobs":0,"closers":1,"attempts":0,"awg":0,"children":0}` -
  `instances` probe core instances (a leg instance still closing included, also counted in
  `closers`), `jobs` reach / data jobs, `attempts` direct access attempts, `awg` the runner's
  AmneziaWG devices (tribeawg, registered by 0014), `children` the desktop service's probe children;
  `{"stopped":true}` stays exactly that. Hosts read only `stopped`; the service journals the rest
  (`tribeScanParseStopReply`: every top-level number). Call it under `xrayNativeLifecycleGate` before
  the tunnel core stops, restarts or changes peer. Its epoch variant goes through the message
  channel, no new export: `LibXrayTribeScanMessage("{\"action\":\"scan_stop_all\",\"wait_ms\":n}",
  "{\"host_epoch\":E}")` (host-only, never from the app) remembers E (the highest wins) and answers
  the same reply (`{"stopped":true}`, or `false` with the flat counts above). Every message may carry `"host_epoch"` in its host options; a
  `scan_start` / `scan_add` whose `host_epoch` is lower than the last stop's is refused with
  `{"error":"stale_epoch","detail":"host_epoch"}` and opens nothing (no epoch = no check). A
  `scan_start` that replaces a running scan tears it down the same way and waits up to 3 s for it
  (else `internal` / `stopping`). A stop with epoch E ends the scan work of epoch E and older -
  never a scan the host started in a newer epoch (review followup 2, F3: a stop delayed on its way
  to the engine, e.g. the adapter's backend-restart stop on its own thread, must not end the scan
  the host started after a later stop); its reply is about its own epoch (nothing of E or older
  alive -> `{"stopped":true}`, without waiting for newer work). Equal is covered: the desktop
  service's app stop and its teardown check carry the current, unbumped epoch of the scan they end;
  the iOS and Android hosts bump their epoch before every stop (Android stops carry none). A stop
  without an epoch ends everything. A stop wins over a start in flight (F2): the
  stop records its epoch under the lock every start and add check it with, and a start checks it
  again at the moment it installs its scan, after any wait; a stop of the start's epoch or newer that
  comes while it waits for a teardown cancels it at once - `stale_epoch` when its epoch is now older,
  else `internal` / `stopping` - so no scan of a covered epoch starts after a stop that returned
  `{"stopped":true}`; an older stop leaves it waiting. An add
  checks the epoch and enqueues under that same lock (before, an older add racing a stop could get
  `scan_ack` with `accepted` 0 instead of `stale_epoch`; it never opened anything: the stop's
  teardown ends the scan it would add to). Gates: `TestTribeScanStopAllNothingAlive` (stop during AmneziaWG
  sessions, during a slow leg-instance close, during the closing attempt against a black hole; the
  timeout path; `host_epoch`; zero `LiveWork()` counted at the moment StopAll returns, a goroutine
  leak check), `TestTribeScanStopRacesStart` (a start waiting for the old scan's teardown, the old
  instance's close held by a hook, then a stop with a newer epoch / without one: the start is
  refused and opens nothing; the stop first, then the older start), `TestTribeScanStaleStop` (a
  stale stop after a newer scan is installed and while a newer start waits: nothing touched, the
  stop answers true at once; an equal-epoch stop ends the scan and cancels a waiting start; a stop
  without an epoch ends a newer-epoch scan), the runner's `StopAll during a
  session` (device count 0), the service's `TestTribeScanStopAllHungChild` (a child that never
  answers is killed and reaped).
- iOS adapter restarts (patch 0015): `WireGuardAdapter.tribeBackendWillRestart:
  ((TribeBackendRestart) -> Void)?` runs synchronously on the adapter's work queue right before it
  stops (`.stop`), pauses (`.pause`, pauseBackend), replaces (`.restart`, restartBackendInPlace: soft
  restart and stall watchdog) or rebinds (`.rebind`: roam endpoint re-set, fresh listen port, socket
  bump) its backend; nil (default) = no call, today's behaviour. It may fire more than once per
  recovery step: the provider's reaction (StopAll of the probes) must be idempotent. Gates:
  `tests/check_backend_hook.sh` (every such call site goes through `TribeBackendHook.before`, only
  deinit calls `wgTurnOff` bare), `tests/typecheck_adapter.sh` (the patched WireGuardKit Swift
  typechecks for macOS and iOS) and `TribeRoamingTests` (the callback runs before the operation, a
  nil callback changes nothing).
- Threading: every function is safe from any thread, concurrently with itself, with
  `LibXrayRunXray` / `LibXrayStopXray` / `LibXraySetSockCallback` and with a running tunnel. Nothing
  blocks on the network: `scan_poll` / `scan_add` / `scan_caps` / `scan_freeze` / `scan_cancel`
  return at once; a `scan_start` that replaces a running scan waits up to 3 s for the old scan's
  instances. Call it from the provider's message
  handler queue as is; poll every 300 ms with `since` = the last seen `seq`.
- Example (`scan_start` with one leg, values shortened): request
  `{"action":"scan_start","version":"tribe-scan-v1","scan_id":"scan-1","deadline_ms":9000,
  "max_bytes":1572864,"limits":{"stage1_sockets":16,"stage1_stagger_ms":50,"per_entry_ip":2,
  "entry_ip_spacing_ms":300,"stage1_timeout_ms":1500,"concurrency":1,"leg_concurrency":6,
  "ttfb_ms":3000,"stall_ms":1500,"stall_after_bytes":16384,"total_ms":5000},"probe":{"base":
  "https://api.example","path":"/v1/probe","token":"tsc1.…","warm_bytes":1024,"bytes":65536,
  "access_asn":64500,"access_net_token":"…"},"candidates":[{"id":"up:…#leg1","kind":"xray_leg",
  "config":"{\"outbound\":{…},\"dns\":[{\"address\":\"1.1.1.1\",\"transport\":\"udp\"}]}",
  "entry":{"ip":"203.0.113.7","port":443},"reach_at_ms":0,"profile_id":"00000000000000a1",
  "early_retry":true,"dns_plan":true,"cost_bytes":83456}]}` -> `{"type":"scan_ack","scan_id":
  "scan-1","accepted":1,"mem_mb":31}`; a poll -> `{"type":"scan_progress","scan_id":"scan-1",
  "seq":2,"phase":"done","items":[{"seq":1,"id":"up:…#leg1","stage":"reach","ok":true,"ms":84,
  "error":""},{"seq":2,"id":"up:…#leg1","stage":"data","http_status":200,"ttfb1_ms":410,"rtt_ms":62,
  "t64_ms":180,"duration_ms":760,"bytes_requested":65536,"bytes":65536,"sha_ok":true,"egress_class":
  "other","egress_node":null,"egress_asn":64600,"net_token":"…","error":"","spent_bytes":75708,
  "retries":0,"dns_exercised":true,"dns":[{"address":"1.1.1.1","transport":"udp","ok":true,"ms":41,
  "rcode":0,"answers":1,"error":""}],"start_ms":96,"end_ms":860}],"bytes_spent":84910,
  "bytes_reserved":10240,"mem_mb":34,"done":true,"reason":"complete","access":{"attempted":true,
  "http_answered":true,"asn":64500,"net_token":"…","at_ms":0,"gen":{…}},"access_close":null,"gen":{…}}`
  (complete, not final: the closing attempt's 10240 stay reserved until the stop).

**Socket protection (review F3).** Probe sockets are the probe's own, never the tunnel's: every
socket of a probe instance (each outbound, its DNS, its observatory) and every reach dial runs only
the scan's protector, which binds it to `bind_interface_index` here in Go (`IP_BOUND_IF` /
`IPV6_BOUND_IF`). Core patch 0011 (`../amnezia-libxray/patches/0011-xray-core-261101-instance-dialer-state.patch`) (`internet.ContextWithSocketProtector`, carried by
`core.NewWithContext` and every `core.Dial` of the probe) makes those sockets skip the process-wide
controllers, so a probe socket never reaches the `LibXraySetSockCallback` slot and its Swift
`protectXraySocket` -> `xraySocketProtectionFailed` path (which cancels the tunnel). A failed probe
bind fails that probe only (`"error":"bind_failed"`, a named item error of the contract: that probe
only, no verdict). The tunnel's callback may be armed, rejecting or cleared: probes do not depend on it
(gate `TestTribeScanExportOwnProtection`). The Swift host implements no socket callback for probes.

**What one scan does.** Per-kind pools (`limits.concurrency` for `xray_full`, capped by this host at
1 on iOS / 2 on the macOS NE; `limits.leg_concurrency` for `xray_leg`, capped at 6; `limits.awg_concurrency` for `awg_mini`, capped
at 2 on iOS / 4 on the macOS NE, offered only with patch 0014 - see "awg_mini" below), at most ONE
probe core instance alive at
once on iOS (a full probe, or one leg instance with up to 24 legs), in queue order; a leg instance
closes in the background after its last leg, and its slot is free only once it has closed (gate
`TestTribeScanInstanceCapSlowClose`: a slow close, the live count sampled every millisecond, the
memory guard never measuring during a close). `xray_full`: the
whole sanitized profile with its inbounds, `api`, `stats`, `metrics` and `log` removed, dialled with
`core.Dial` carrying the removed inbound's tag (routing rules on `inboundTag` still match): no
listener, no port, no credential. `xray_leg`: config `{"outbound": ..., "dns": [...]}` (host
additions: `"dialers": [outbounds]` for a `dialerProxy` hop, `"dialer": {"tag","protocol":"freedom"}`
for a freedom hop the projection names but does not carry); up to 24 legs of one message share ONE
outbounds-only instance (tags namespaced per candidate, `dialerProxy` / `proxySettings` rewritten),
each probe forced onto its leg (`SetForcedOutboundTagToContext` + `core.Dial`, the technique of
libXray's upstream `PingBatch`; the vendored libXray v1.0.3 has no batch ping); with `dns_plan` one
A query for the probe host's name per listed resolver through the leg (UDP, TCP, DoH, h2c; others
`skipped`), `dns_exercised` = all answered. Reach: one TCP connect per candidate with an entry, not
before `reach_at_ms`, `stage1_sockets` at once, `stage1_stagger_ms` apart, `per_entry_ip` per IP,
`entry_ip_spacing_ms` between opens to one IP (data connections too), `reach_timeout` /
`reach_refused`. Data: ONE TLS connection (Go `crypto/tls`, system roots, ALPN http/1.1), warm-up
GET then the sized GET on it, digest of the body computed locally (`tribe-probe-v1`), limits
`ttfb_ms` per request (from the attempt start for the first: all handshakes), `stall_ms` after
`stall_after_bytes`, `total_ms` per probe; `early_retry` retries a probe that got nothing back after
300 / 600 / 1200 / 2000 ms while 1 s of `total_ms` is left (lab D3). Budget (review F6): one
`ByteGate` per scan, the twin of `ScanHostByteGate` (its `byte_gate` vectors are replayed): a probe
is admitted atomically only if `spent + reserved + cost_bytes <= max_bytes` (`max_bytes` is the app's
hard grant), by the one dispatcher, for every pool and every retry; its `cost_bytes` stays reserved
until its final item and is then replaced by what it used, never more: a probe that would pass its
`cost_bytes` is cut (`budget`, its reads are capped at the limit). A reach socket is charged 512 only
if it fits (else its reach item says `budget`). Used bytes = plaintext bytes read (headers and
bodies, cut ones included) + 8192 per TLS connection; an attempt that got nothing back (no
certificate, no body) costs 512. `scan_progress` carries `bytes_reserved`.
Memory guard: `os_proc_available_memory()` >= 12 MB before an instance or an AmneziaWG session (else the item gets `memory`
and the scan ends with reason `memory`; at `scan_start` the reply is `{"error":"memory",...}`) and
>= 8 MB while it runs (checked every 250 ms). An admission never measures while an instance of the
scan is still closing (review followup 2, F4: on iOS a session is admitted next to the single leg
instance closing in the background - that memory is about to come back): it waits for the close, at
most 3 s, then measures; the running probes' 8 MB watchdog keeps measuring during a close (gate
`TestTribeScanMemoryGuardWaitsForClose`: cap 1, a session active through a slow leg close, another
admitted during it). Item errors: `dial`, `tls`, `ttfb_timeout`, `stalled`,
`total_timeout`, `http` (with `http_status`: anything but a 200 of our server, i.e. without
`X-Tribe-Api: 1`, a redirect, 401/404/429), `short`, `digest`, `memory`, `budget`, `cancelled`,
`deadline`, `config`, `internal`, `bind_failed`. A stream that the job's `total_ms` or the scan's
stop closes is named as the watchdog names it whichever closes it first (an Xray stream ends with
the dial's context, possibly before the watchdog's 20 ms tick): `total_timeout` (`ttfb_timeout` when
nothing came back) or the stop code, never `short` / `http` / `dial` from the truncated read (gate
`TestTribeScanDeadlineVerdict`). Every goroutine recovers a panic (`internal`); a
panic inside xray-core's own goroutines cannot be caught (plan R3).

Stop (review v2.1 F7, contract `tribe-scan-v1` final) is two-step: `scan_freeze` freezes the byte
gate at once (nothing admitted or charged afterwards) and answers
`{"type":"scan_freeze_ack","scan_id":S,"spent":n,"reserved":n}` while probes in flight keep
draining; `scan_cancel` stops them and answers at once `{"type":"scan_ack",...,"accepted":0,
"mem_mb":n}` (with `"final":true,"bytes_spent":n` only when the scan is already over); the host then
makes the closing access attempt and the last progress carries `"done":true,"final":true`, the
final `bytes_spent`, `bytes_reserved` 0 and `access_close`; every later poll answers the same. A
scan that ends by itself (deadline, budget, memory, tunnel stop, internal) also ends with `final`;
`complete` (queue drained) is NOT final - the scan stays open for `scan_add` until `deadline_ms`
(a drained scan reaching its deadline ends with reason `deadline`).

Access attempts (plan §2.2c, proof by exclusion): the opening attempt is admitted by the byte gate
first (`netinfo_cost_bytes`, id `netinfo_open`), before any probe; the closing attempt's reservation
(`netinfo_close`) is held from the start, so a frozen scan can still make it during the stop. Each
is one HTTPS `GET <probe.base><probe.netinfo_path>` (default `/v1/netinfo`) with the scan token on a
socket that runs the probe protector (bound to the physical interface), timeout
`stage1_timeout_ms`, charged what it used (8192 for the TLS connection + the plaintext read, or 512
when TLS never came up). Reported as `access` (opening, repeated once made) / `access_close`
(closing, in the final progress) = `{"attempted":true,"http_answered":bool,"asn":n|null,
"net_token":s|null,"at_ms":n,"gen":GEN|null}`; `http_answered` = an HTTP answer of any status (a
DNS, TCP or TLS failure or a timeout is false); a 200 of our server fills `asn` / `net_token`;
`at_ms` = the attempt's start on the scan's clock. Only a failure AFTER packets left on the physical
interface is an attempt (`http_answered` false: refused, reset, timeout, TLS or HTTP failure). Not
an attempt (`null`, released from the gate at 0 bytes, one log line `tribescan: scan=<id>
access=<opening|closing> attempted=false code=<code>`): `budget` (the grant cannot cover it), `dns`
(the probe host's name did not resolve), `bind` (the probe's socket protection failed), `no_route`
(ENETUNREACH / EHOSTUNREACH / EADDRNOTAVAIL / ENETDOWN at connect on the bound interface). The name
never goes through Xray's DNS: Go's system resolver answers it (darwin / iOS: libSystem, i.e. the
system DNS configuration - with a tunnel up usually the tunnel's resolver; Android: bionic / netd;
Windows: GetAddrInfo; Linux: /etc/resolv.conf), so a DNS failure says nothing about the access
network. To make the attempts independent of DNS the app sends the probe host's addresses in
`scan_start` `probe.base_ips` (contract field, 1-8 IP literals; an empty list, more than 8 or a name
is `bad_request` / `probe.base_ips`); they are dialled in order with the name as the TLS name and
Host. ONE source: `probe.base_ips` always wins; the host option `"probe_base_ips": ["ip", ...]`
(scan_start) is only a fallback for a request without it; an IP-literal `probe.base` needs neither. Data items carry `start_ms` / `end_ms` (the probe's first attempt and last byte, ms after
`scan_start`, the same monotonic clock); items never started (e.g. `budget`) have them `null`.

Fields this host added first are contract fields since `ScanHostContract.h` @ `174e99e83`:
candidate `bytes` (1024-4194304) / `total_ms` (1000-30000) - per-job size and limit, e.g. a 24 KiB
race probe; out of range is `bad_request` / `candidates` -, `probe.base_ips`, the awg_mini config's
`address` / `mtu`, data item `dns` (per-resolver detail) and the item error `bind_failed`. The
engine replays the app's vectors (24 requests, the 23 replies the host can send - the other 11 are
malformed on purpose and test the app's decoder - and 5 `byte_gate` cases).

**Log privacy.** The tunnel's Xray log (`xray-core.log` at info, whose tail the status reply
carries into diagnostics) or, without a tunnel core, Xray's default stdout handler never sees what a
probe dials. Core 0011 adds log scopes: every probe instance is created, and every probe dial made,
under a scope (`log.ContextWithScope`) whose handler drops all of Xray's messages before they are
built; `errors.LogX`, the access log, the DNS log and the WireGuard outbound's logger honour it.
Lines Xray writes without a context still reach the process log, so the hosts, addresses,
credentials, paths and keys of every queued candidate (and its entry IP) are registered as terms
(`log.RedactTerms`) until 30 s after the scan stops; such a line keeps its place, type and severity
with each term replaced by `[redacted]` (REALITY `serverName` and the profile's DNS servers are not
terms: public names the tunnel's own lines carry too). gRPC's own stderr logger gets the same masking
(set once at package init, same env levels as gRPC's default). REALITY `show` (stdout prints of the
session id, which holds the shortId) is removed from every probe config. A probe leaves exactly one
line: `tribescan: scan=<id> probe=<id> kind=<kind> error=<code|ok> reach_ms= ttfb_ms= duration_ms=
bytes= spent= retries=` (an id that is unsafe or names a term becomes `#<n>`), written to the
extension's WireGuard logger when one is set (`api-tribescan-log.go`), else to the process Xray log at
info. Gates: core `TestTribeLogScopePerInstance` + `TestTribeLogScopeAndRedaction`, engine
`TestTribeScanLogPrivacy` (stdout, stderr and the tunnel's error/access/DNS log captured during a scan
with recognisable fake provider hosts and a REALITY `show` profile, with Xray's default handler and
then next to a tunnel instance logging its own traffic at debug: no host, no REALITY print, the
tunnel's own lines present, a context-free line masked not dropped, one line per probe).

**Untouched process state.** A probe instance never calls `RunXray` / `InitEnv`, never touches
libXray's `coreServer`, never registers a log handler (Xray's handler is process-wide; the log app is
removed from every probe config; its messages go to its scope, above) and enables no stats (the tunnel's meter never counts a probe byte,
gate). Core patch 0011 (`../amnezia-libxray/patches/0011-xray-core-261101-instance-dialer-state.patch`) also fixes a real cross-instance bug of xray-core 26.10.31: every `core.New`
replaced the process-wide DNS client (`domainStrategy` lookups) and outbound manager (`dialerProxy`
hops) with its own, so a second instance made the tunnel resolve with the probe's DNS and look its
chain hops up in the probe's outbounds (and in a closed instance's after the probe). The instance in
the dial's context is used now; the global pair (atomic) remains the fallback.

**Transport pools (core 0011).** Two transports keep connections across dials in process-wide maps
keyed by (destination, stream settings): XHTTP (`XmuxManager` and its HTTP clients) and gRPC
(`grpc.ClientConn`). Unpatched, neither entry ever left the map, so a probe instance's pooled
connections outlived it (in the gate, 2 XHTTP connections were still open 23 s after the probe
instance closed; HTTP/2 ones keep pinging up to the 300 s idle timeout), and gRPC dialled from its
own context, dropping the probe's: its socket ran the process-wide controllers - the tunnel's
protect callback - not the probe's protector. Not shared across instances (the stream settings
pointer differs), but leaked. Core 0011 keys both pools by the instance in the dial's context too,
closes an instance's entries in `Instance.Close` (XHTTP: every connection it dialled, idle or in
use, and its HTTP/3 transport; gRPC: the ClientConn), and gives gRPC's dialer the first dial's
context values (protector, log scope, instance). The tunnel's pools are untouched by a probe's
close (and the tunnel no longer leaks its old entries on a restart). Hysteria already tracks its
instance and closes a stopped instance's QUIC client within 1 s. Gate
`TestTribePoolsPerInstance` (fails before the fix on both counts). Process-wide but not a
connection pool: `tls` keeps one client session cache (only with `enableSessionResumption`), so a
probe's and the tunnel's session tickets share it.

**Protocol coverage (engine, local servers from the same core).** `TestTribeScanProtocols`: VLESS +
REALITY + Vision, VLESS + XHTTP (HTTP/1.1 packet-up, no TLS), VLESS + gRPC (no TLS), Hysteria2 (QUIC
with TLS, pinned certificate), and a chain (`sockopt.dialerProxy` through a second VLESS server):
each probe passes with a verified digest, its sockets run only the probe's protector, and no
connection of the probe stays open at the server after its instance closed (a chain's inner
connection ends with the hop server's own 1 s + 1 s policy timers). Not set up locally: XHTTP over
HTTP/2 and HTTP/3 (need TLS / QUIC on the XHTTP server: the HTTP/2 path is the same `tribeCloseAll`
code, HTTP/3 uses the transport's own Close), REALITY with XHTTP, WebSocket / HTTPUpgrade / mKCP
(no pool in those transports), UDP accounting of Hysteria (its server connections are not counted).
Probe configs are also cleaned of what would touch the system: a WireGuard outbound gets
`noKernelTun` (on Linux as root it would create an interface and routes), a `quic+local` DNS server
is dropped (quic-go dials it on a raw socket past the probe's protector).

**Memory (this Mac, probe-only process, servers in another, footprint = `phys_footprint`).** Warm
runtime 9.7-10.2 MB; a full single-outbound probe instance +0.2-0.4 MB at its peak; one leg instance
+3.4 MB with 12 legs and +5.0 MB with 24 legs in flight (6 at once; GOGC=10 + 30 MiB limit: +2.4 / +2.6-3.3
MB). Wall time against local servers holding each sized body 300 ms: full probe 0.31 s, 12 legs
0.65-0.70 s, 24 legs 1.28-1.49 s; a full probe end to end without the hold 4-36 ms (median ~8 ms).
The NE adds the tunnel core, hev and Swift (lane-memory §2); the iPhone number is device-only.

Gates (all `-race`): `TestTribeDialerStatePerInstance` + `TestTribeSocketProtectorReplacesControllers`
+ `TestTribeLogScopePerInstance` + `TestTribeLogScopeAndRedaction` + `TestTribePoolsPerInstance`
(vendored core), `go test -tags tribescan_testkit ./tribescan` (full and leg probes through real core
instances against a local VLESS server core and an HTTPS `/v1/probe`: success timings and same
connection, every failure class, early retry, cancel / replace / StopAll, deadline, pools and
instance caps, queue order with one slot, leaks of goroutines and fds, panic, memory guard at start /
launch / run, reach pacing, budget, `scan_add`, messages, own protection with a live core, interface
binding, the tunnel's log handler and counters untouched, leg batches, leg config shapes, DNS plan,
per-job bytes, log privacy, awg_mini scheduling with a stand-in runner, the protocol matrix, probe
config cleaning), and the export test (`api-tribescan_test.go`, tags `tribe_callback_test
tribescan_testkit`: libXray's tunnel core restarted while probes run, probes with the tunnel callback
rejecting or cleared, StopAll).

**awg_mini (patch 0014, package `tribeawg`).** The engine schedules the session (its pool, the shared
byte gate, queue order, the memory guard before each session, initiations at least
`awg_spacing_ms` apart, ONE session per node in a scan - a second candidate for the same peer key is
`config` - and never the live tunnel's peer); `tribeawg.Open` runs it: a userspace AmneziaWG device
(`device.NewDevice` on `tun/netstack.CreateNetTUN`, `conn.NewStdNetBind`) with its own locked
registry (not `tunnelHandles`), its own silent logger (not the extension's C logger: nothing of a
session reaches a log) and no dnsfwd / directsplit wrapper; the candidate's UAPI lines (the device's
OWN key; keepalive lines dropped) are set, the device comes up, and its UDP sockets
(`PeekLookAtSocketFd4/6`) run the probe's protector (`bind_interface_index` / the candidate's
`bound_if` -> `IP_BOUND_IF`) BEFORE the first packet; one persistent keepalive triggers the
handshake, awaited up to `awg_handshake_ms` (none -> `"error":"dial"`, `handshake_ok` false; the
awg block is then left out like the app's encoder does); `awg_prime_echoes` ICMP echoes to
`prime_echo_target`, 150 ms each; then the engine's normal data probe over TCP inside the tunnel to
`probe.ip:port` with `probe.host` as the TLS name and Host (no DNS in the session). `spent_bytes` =
the probe's bytes + the echoes' IP bytes both ways. The device closes on every path (done, cancel,
deadline, memory, `LibXrayTribeScanStopAll` under the lifecycle gate). The runner itself also refuses
a second open session to one node (`ErrAwgBusy`) and spaces the identity's initiations
process-wide. Candidate config: the contract's `{"uapi","address","mtu","probe":{"host","ip","port"},
"prime_echo_target","bound_if"}` as the app's `scanAwgMiniConfig` builds it: UAPI `private_key`,
`listen_port=0`, the obfuscation lines (`jc`... `h4`, `i1`-`i5`), `replace_peers=true`, the peer's
`public_key`, an optional `preshared_key`, `endpoint`, `replace_allowed_ips=true`, `allowed_ip` = the
probe IP /32 (+ the echo target /32); no `set=1`, no keepalive (a keepalive line would be dropped).
`address` (the device's tunnel address) is required - UAPI carries none and the node drops packets
from any other source -, `mtu` defaults to 1280. `prime_echo_target` null = no echo; `bound_if` null =
the host option's interface, a candidate's own `bound_if` wins. The handshake wait
(`awg_handshake_ms`) and the echo count (`awg_prime_echoes`) are scan-wide `limits`. Gates
`TestTribeScanAwgContractFixture` and `TestTribeAwgContractConfig` feed the app's own fixture
(`testAwgInput()`, the vector `start_awg_mini_typed_config_and_base_ips`); every line is taken. Host option `"awg_live_peer": {"public_key": hex|base64,
"endpoint": "ip:port"}` (scan_start): the live AmneziaWG tunnel's peer; a candidate for it is refused
(`config`). Measured on this Mac (18 cores; sessions in the test process, nodes in another; each
session: handshake + 1 echo + 1 KiB + 64 KiB HTTPS, held open; a fresh process per count): RSS +5.1-5.5
MB with 1 session, +6.9-7.2 MB with 2, +10.2-10.3 MB with 4 (Go heap +2.3-2.8 / +3.7-3.8 / +5.8-5.9 MB;
82 goroutines per session: amneziawg-go runs 3 workers per CPU, an iPhone has 6). Loopback: handshake
5-6 ms, a whole probe 11-12 ms; S4=4 without a prime echo: ttfb1 ~2 s (the first packets after the
handshake are lost), with one echo 1-2 ms. Archive: `libwg-go.a` (iOS arm64, `-ldflags=-w`) 45,358,704
-> 45,592,392 bytes (+233,688; gVisor was already linked by 0009, netstack adds its own package and
gVisor's ICMP transport). Gate: `go test -tags tribescan_testkit ./tribeawg` (not `-race`:
amneziawg-go's peer timer writes `duration` outside its lock, `device/timers.go:41`, and the detector
reports it under load - an upstream data race that can drop a timer re-armed while it fires).

Files the extension build already compiles from this package: none new outside `libwg-go.a`; the
Swift host adds its own `PacketTunnelProvider+Scan.swift` (lane L4).

Merged with the data watch (`3.1.4-tribe.14` = tribe.12 + patches 0012 and 0016): no file and no Go
symbol is shared. 0012 adds `tribeprobe.go`, `tribeprobe_engine.go`, `tribeprobe_test.go`, edits
`api-apple.go` (`wgTurnOn`) and appends `wgSetTribeProbe` / `wgTribeProbeStart` /
`wgTribeProbeResult` at the end of `wireguard.h`; 0013 adds `api-tribescan.go`,
`api-tribescan-log.go` (reads `loggerFunc` / `CLogger` of `api-apple.go`, which 0012 keeps),
`api-tribescan_test.go`, `tribescan_ios.go`, `tribescan_other.go` and inserts its declarations after
`LibXrayTribeOutboundStats` (0011), above 0012's - so 0013 still applies at its recorded lines. Its
package-main identifiers (`tribeScan*`, `tribeXray*`, `LibXrayTribeScan*`, `tribeTunnelStats`) do not
meet 0012's (`tribeProbe*`, `probe*`, `itoa`, `readOne`, `wantState`, `writeBatch`). 0014 adds only
`api-tribescan-awg.go` and `tribeawg/` (identifiers `tribeScanAwgOpen`, package `tribeawg`): no
conflict with 0012. The data watch's changes to `WireGuardAdapter.swift` are a patch of their own,
0016, AFTER 0015: `patch_ng` matches every hunk at its recorded line number, 0015's hunks were
recorded on an adapter without the data watch, and any line added before them would make 0015 fail.
0013-0015 are byte for byte those of tribe.12. 0016 stops the engine of an in-place switch through
`TribeBackendHook.before(.restart, self.tribeBackendWillRestart)`, so `tests/check_backend_hook.sh`
(every `wgTurnOff` / `wgBumpSockets` / `wgSetConfig` of the fully patched adapter) holds for it too.

## Tests

```sh
sh recipes/awg-apple/tests/run_tribe_roaming_tests.sh   # current version; also the build() gate
# a released version's snapshot (what build() runs for tribe.5/tribe.7):
sh recipes/awg-apple/tests/run_tribe_roaming_tests.sh \
  recipes/awg-apple/tribe/snapshots/3.1.4-tribe.7/TribeRoaming.swift \
  recipes/awg-apple/tests/snapshots/3.1.4-tribe.7/TribeRoamingTests.swift
sh recipes/awg-apple/tests/run_tribe_data_watch_tests.sh   # tribe.14 data watch; also a build() gate
```

## tribe.14 behaviour: the data watch (patches 0012 + 0016, TribeDataWatch.swift)

Everything of tribe.12, plus a verdict about DATA (design:
`docs/specs/2026-11-14-ios-tunnel-side-data-watch-design.md` in tribe-backend, sections 0 and 0a).
The stall watchdog answers "is the session alive" and counts a new handshake as inbound progress; on
13.11.2026 a node completed handshakes for 6 min 50 s and returned no data, and nothing in the
extension said so. tribe.14 adds a second question to the SAME one-second tick, "does data come
back", and an active probe that judges the answer. Stage 1 (features.ios_tunnel_watch) only
reports. Stage 2 (features.ios_tunnel_watch_switch, off by default) adds an arbiter that, while the
app sleeps, treats the node and then replaces the peer in place. The text below is the state after
both independent reviews (stage 1; stage 2 with the server-change key).

- `TribeDataWatch` (pure, `tribe/TribeDataWatch.swift`): the statistics sample is cut into cycles of
  `cycleSeconds` (25). A cycle is dead when at least `cycleMinTxBytes` (1024) went out and NO
  transport packet (data or keepalive) came back; the bytes of a handshake are deducted from both
  directions first
  (`handshakeRxAllowanceBytes` 148, `handshakeTxAllowanceBytes` 1024 per change of the handshake
  time). `deadCycles` (3) dead cycles in a chain (gap at most `cycleChainGapSeconds`) with
  `minEpisodeTxBytes` (3072) sent in the episode make the passive rule. Start, wake-up and path
  changes open quiet periods; a change of the physical interface voids the verdict.
- The rule does NOT look at what the stall ladder did (review of stage 1: the ladder acts only after
  4096 bytes of demand since the last progress, so below about 270 B/s it never steps and a rule
  that waited for its steps never judged the 13.11 path). The judge is the probe.
- The passive rule alone is never the final word. It first asks for a request that bypasses the
  tunnel (the provider sends it; no reply = `network`, a foreign reply = `captive`), then for the
  probe:
  - `answered` refutes the rule (`refuted` counter), also when the answer comes after the poll
    (`lateAnswerAt`: a `no_data` confirmed by the probe is taken back) and also when it comes
    after the NEXT probe was started (third review: the provider turns the engine's
    ` prev_late=<id>` into the same `lateAnswerAt`). A late refutation is a refutation in full:
    counted as `refuted`, the verdict withdrawn, a trial probe in flight cancelled and its budget
    given back, no new trial ordered on that step;
  - `silent` confirms `no_data` (`evidence=probe`) only when the wait was UNDISTURBED: no inbound
    data, no quiet period, no device restart, no new handshake, no path event. A disturbed wait is
    void: report `disturbed`, counted separately, asked again after `probeRetryGapSeconds` (10)
    within the limits;
  - `noSession` - the engine has no keypair that can send, nothing was injected and no budget is
    spent. The node is then judged by the handshake itself: no handshake for `cycleSeconds x
    deadCycles` (75 s) since the device start / the last handshake while dead cycles go on
    confirms `no_data` (`evidence=handshake`); a transmit counter that grows without a keypair can
    only be handshake initiations. Before that the rule waits;
  - `staged`, `notSent`, `unavailable` judge nothing.
  `unconfirmed` (nothing can judge the rule) asks nobody again: neither the probe nor the bypass
  request.
- An in-place restart of the backend (`noteBackendRestarted`) voids a probe in flight and holds the
  next one for one start grace; the chain of dead cycles goes on (the path did not change).
- A second trigger asks for the probe only: at least `suspectMinTxBytes` (64 KiB) sent and less than
  `suspectMaxRxBytes` (4 KiB) of data received over `suspectWindowSeconds` (60) while no episode is
  open. It has its own budget (`probeLowRxMaxPerHour`, 2) and a back-off after an answered probe
  (10 min, doubled up to an hour); it never spends the passive rule's budget.
- Bounds: `probeMaxPerEpisode` (3), `probeMaxPerHour` (12), `sanityMaxPerHour` (12 requests outside
  the tunnel per hour). They survive a device start.
- Every change of the verdict is reported, the end of one too: the outputs (journal, status reply,
  shared file) never keep a verdict the rule no longer holds.
- `tribeprobe.go` + `tribeprobe_engine.go`: `wgSetTribeProbe(clientIp, target, enabled)` before
  `wgTurnOn`, `wgTribeProbeStart(handle, timeoutMs)`, `wgTribeProbeResult(handle)` ->
  `state=<pending|answered|silent|no_session|not_sent|unavailable|none> id=<n> ms=<n> late=<0|1>`,
  followed by ` prev_late=<id>` once the reply to the probe BEFORE this one has come in.
  `wrapTribeProbeIfEnabled` is the outermost pass-through wrapper of the TUN device. The probe is one
  DNS query for the root name (type A, 17 bytes of payload: the query the split-DNS forwarder warms
  up with) from the tunnel address to the session's first DNS server, source port 50100-50199,
  repeated once after 1.5 s, injected as an inner IPv4/UDP packet; the reply is taken out of the
  device's output and never reaches the OS. Without a configuration the wrapper is not created and
  `wgTurnOn` behaves as tribe.12.
- What "sent" means (the truthful signal, not a guess from timing). amneziawg-go encrypts a packet
  read from the TUN only when the peer has a current keypair younger than `RejectAfterTime`
  (180 s); otherwise the packet is STAGED and a handshake is started. The wrapper therefore reads
  the engine's own `last_handshake_time` through the UAPI dump (`IpcGet`, from the adapter's work
  queue only - never from a device goroutine) at the start and at the result, and its own time of
  the device consuming the packet (`Read`):
  - start is refused with -2 (`no_session`, nothing injected) when there is no handshake or the
    keypair is within 5 s of its expiry; -1 when the resolver is not routed through the tunnel
    (allowed IPs / the direct-split list) or the engine cannot be read;
  - `silent` is reported only if the packet was consumed while the keypair of the SAME handshake
    could still send and the handshake time has not changed by the end of the wait; otherwise
    `no_session`. The timeout counts from the consumption, not from the request.
  A late answer is accepted for 30 s after the timeout (`late=1`); the look-out on the write path
  ends by a deadline of its own, without polling. The look-out survives the start of the next
  probe (`tribeProbePrev`, only for a probe told `silent` / `no_session` whose 30 s are not over):
  its reply is still taken off the write path and told as ` prev_late=<id>`, the current probe is
  judged by its own reply only. A new device or an aborted probe drops it.
- Limits of the probe, to be read literally: it is a DNS root query to the session's `dns1`; an
  answer proves the path phone -> node -> forwarding -> that resolver and back for a SMALL packet.
  `silent` proves that the engine had a sending keypair and took the packet; it does not prove the
  datagram left the radio. Inner IPv4 only. It says nothing about bulk transfer: a freeze that
  depends on size (about 16 KB and more) is invisible to it.
- `WireGuardAdapter`: `setDataWatchPolicy(_:)`, `dataWatchSnapshot(completionHandler:)`,
  `dataWatchInputs`, `dataWatchHandler` (both get the engine handle). The watch is fed by
  `dataWatchTick` right before `recovery.tick` in `stallTick` and told about real path events,
  device starts and in-place restarts. With the policy off (the default) every hook is one
  comparison and the adapter behaves as tribe.12; nothing is counted unconditionally any more.
- Stage 2, the arbiter (inside `TribeDataWatch`, pure). `step` returns `command`
  (`TribeWatchCommand.heal(.freshPort | .softRestart)` or `.switchPeer(to:why:)`) and `exhausted`
  only when ALL hold: `policy.switchEnabled`, `maxSwitches > 0`, the app shows no sign of life
  (`appAliveSeconds`), the verdict is a confirmed `no_data` (never `unconfirmed`), the provider
  offers candidates (`env.candidates`, never the current node), no quiet period, no probe in flight.
  One round: the same-node heals (`switchHealSteps`, 2; counted for the whole episode) -> the
  candidates in the given order, each once, at most `maxSwitches` (5) -> exhausted: back to the
  node that received the most inbound data in the round (a tie goes to where the round began; only
  if that node is on offer), then a pause of 5 min after the first failed round and 30 min after
  every later one (`roundPauseSeconds`) until the network changes or the app writes a new plan
  (`env.planEpoch`). Rules of the second review:
  - a node is LEFT only after two silent, undisturbed judgments at least `healTrialSeconds` (10 s)
    apart with nothing inbound between them (`silences`): the confirming probe plus one more trial,
    whatever happened to the heals. ANY inbound transport data, a late answer, a device start,
    another network and the pause between rounds start the count over - this is also how a late
    answer to either probe cancels the leave (the engine counts the reply as inbound data);
  - every heal - performed, refused by the shared budget (`denied`) or failed - is followed by its
    own trial probe; a refused heal is `healsAsked`, not `healsDone`;
  - a switch is `performed | denied | failed | rejected`. `denied` (the shared budget) changed
    nothing and is asked again 10 s later; `failed` / `rejected` count as tried and against the
    hourly ceiling `switchMaxPerHour` (6, `ios_tw_switch_max_per_hour`, 1..30) - every switch counts
    against it, also the way back and the move at a network change; at the ceiling the arbiter
    waits and declares nothing. The rule does not keep the history itself (third review): it
    compares `env.switchesLastHour`, counted by the provider, which keeps the switch times across
    a policy off/on and across an extension restart (`switch_times` in its state file);
  - while a round is in progress (`arbiterOwnsRecovery`: active and not exhausted) the adapter
    does not run the stall ladder: its steps would spend the shared budget the switch needs. Between
    rounds and with the key off the ladder works as in tribe.12;
  - a node reached by a switch is `untrusted` until it answers its trial or passes `recoverRxBytes`.
    If the physical interface changes while it is untrusted, the next satisfied sample orders
    `.switchPeer(to: env.networkChoice, why: .network)` - where a start on the new network would go
    (the provider computes it with the start-choice function) - if that node differs and is on
    offer; inbound data cancels it. A trusted node is never moved for the sake of a better choice.
  After every action the node is judged by a TRIAL probe (`TribeProbeReason.trial`) once its wait is
  over (10 s after a fresh port or a refused heal, one start grace after a restart or a switch):
  answered = trusted (report `trial`, a standing verdict is taken back, not counted as refuted).
  Trial probes have their own hourly budget (`trialProbeMaxPerHour`, 30). The round is forgotten at
  once when the app is seen alive, the key goes off, somebody else starts a device, the data
  comes back or the physical interface changes.
- Stage 2, the adapter (`WireGuardAdapter`, patch 0016). A command is executed inside
  `dataWatchTick`, on the tick that produced it, and the stall ladder skips that sample (one
  executor per tick); `noteCommandResult` tells the rule what happened. Everything goes through the
  shared recovery budget: the heals as the ladder's own steps (`recovery.requestFreshPort` /
  `requestSoftRestart`), a switch through `recovery.requestPeerSwitch` (the rolling cap of
  interventions and the cooldown between two new devices; not the episode of the node being left).
  `switchBackend` replaces the peer in place - the upstream `update(tunnelConfiguration:)` path
  with the backend stopped across the settings change. The order and every way it can fail are the
  pure `TribeSwitchSequence.run(TribeSwitchSteps)` (host-tested with a fake engine that fails at
  each step):
  1. `prepare`: the new endpoint is resolved while the old backend still runs (a failure changes
     nothing: `failed`, the engine is up);
  2. `stopEngine`: `wgTurnOff` of the old backend - nothing reads the TUN any more;
  3. `applySettings(new)`: `setTunnelNetworkSettings` of the new configuration, CONFIRMED by the
     system within 5 s (`applySettingsConfirmed`; no answer = failure);
  4. `startEngine(new)`: a new backend on the same TUN. `performed` is told only here.
  If 3 fails (`failed`) or 4 fails (`rejected`: the candidate is never offered again while the plan
  lives), the previous node is put back: its settings, then - only on confirmed settings - its
  engine. If no engine can be started at all, the adapter is in `.temporaryShutdown`,
  `dataWatchEngineHandler(true)` tells the provider, and the stall tick (which keeps running: the
  retry is its first statement) retries the previous configuration 2, 4, 8 ... 60 s apart
  (`TribeEngineRetry`), settings first when they are not in force; `dataWatchEngineHandler(false)`
  when an engine runs again. An engine is started only right after its own settings were confirmed,
  so at no moment does a running engine have a peer whose endpoint is routed into its own tunnel.
  The candidate's `TunnelConfiguration` comes from the provider (`dataWatchCandidate`); without one
  the switch is `rejected`. The adapter cannot be built into a host test: its call sites are pinned
  by the wiring check of the client repo, the types by a host type-check of the patched sources
  together with the rule.

Build gates: `tests/run_tribe_data_watch_tests.sh` builds two binaries - the named scenarios of the
rule (the 13.11 replay, the 60 / 120 / 200 / 260 B/s vectors of the review, every false-positive case
of the design's table, the probe outcomes, disturbance, the handshake judge, late answers, limits,
clamps, and the arbiter of stage 2: heals then switch, two silent probes before a node is left,
never on `unconfirmed`, the keys-off ownership of recovery, a heal that cures, refused heals, a
living app, the order of candidates, the bound per round, the hourly ceiling, exhausted and the
rounds, a new plan, a failed switch, a node without a handshake, the trial budget, a disturbed
trial, the ends of a round, a change of network with an unproven node, the switch sequence with a
failing engine) and `TribeDataWatchLadderTests.swift`, the rule next to the REAL stall ladder
(`TribeRecoveryArbiter`): the vectors of the reviews with a fixed seed - the 13.11 path (verdict
100 s, left 128..138 s), a blocked node, a late answer, a lossy one-way upload (300 runs at 10 / 20 /
30 % loss: nobody is moved), six hours with every node dead (6 switches an hour), an outage that
hits every node and a change of network - and `go test -run '^TestTribeProbe'` (a fake TUN, a fake forwarder and a
fake engine dump: packet layout and checksums, answer, silence, repeat, one probe at a time, a
foreign packet passed through untouched, restart during the wait, no configuration, departure
through the forwarder, a refused start without a keypair, a staged packet, an expired keypair, a
handshake during the wait, a late answer, a late answer after the next probe started and the end
of that look-out, a resolver in the direct list). `replay/` holds the
offline tooling (not exported): the replay of a tester journal through the real function
(aggregates only) and the mutation run of the rule
(`python3 recipes/awg-apple/replay/tribe_data_watch_mutants.py`).

## tribe.16 behaviour: one definition of "data is flowing" (TribeRoaming.swift, patch 0017)

Device round 24.11, case B1 (iPhone Air, AmneziaWG, LTE -> Wi-Fi): after the roam fresh port the
path passed about 1 s of data after every new local port and then nothing, for 8 minutes, while
handshakes kept completing. tribe.4-15 counted that burst (and every handshake) as inbound progress
and reset the ladder to its first step: 17 fresh ports, `soft_restarts=0`, `recovery_denied` 0 -> 15
(the same-kind cooldown and the rolling cap). The app's probe failover waited for a handshake older
than 135 s, which never came while handshakes passed.

- `TribeDataFlow`: data = rx growth minus one handshake (148 B) in a sample whose handshake time
  moved; demand = tx growth minus one handshake (1024 B). The data watch deducts the same amounts
  (`TribeDataWatchPolicy` defaults, pinned by `TribeDataWatchLadderTests`: its file compiles alone).
- Data proves the path only when it still arrives `stallRebindSeconds` (10 s) after the last repair
  step of any origin (watchdog, GUI, roam fresh port; not a same-port bump). Earlier data is the echo
  of that step: it restarts the stall clock and the demand count, the stage and the stage-3 backoff
  stay. So after a fresh port that brings back only a burst the next step is the soft restart
  (B1 replay: soft restart 15 s after the roam; tribe.15 on the same replay: 17 fresh ports, none).
- A handshake is no longer progress. It only proves an idle tunnel: a handshake while less than
  `stallMinTxBytes` (its own 1024 B not counted) went out since the last baseline starts the demand
  count over (the stall clock keeps running). Below ~270 B/s of demand per 15 s re-key the ladder
  stays as still as in tribe.15 (the data watch judges such paths); an idle tunnel never steps.
- Stage 3 steps also need a current stall (`stallProbeSeconds` without data): with a server-set
  second stage longer than the backoff the echo could otherwise coincide with a due step.
- The budget re-arms its episode on the same rule (`observe(_:proofWindow:)`, the arbiter passes its
  policy's second stage); a handshake alone no longer re-arms it. Since the echo window (10 s) is not
  shorter than the same-kind cooldown (8-10 s), the watchdog's fresh port right after another fresh
  port can no longer be refused by the cooldown.
- Rates (unchanged caps: 4 interventions per 120 s, cooldown 8-10 s per kind, one fresh port and one
  soft restart per episode, stage-3 backoff 30/60/120 s): within one episode the soft restarts come
  at +0, +90, +330 s ... (at most 2 per 120 s); a new episode needs data that outlasts the echo
  window and then a new stall of 14 s without any data under 8 KB of demand. Without roams at most 2
  soft restarts per 120 s (each episode spends 2 of the 4 interventions), with a roam fresh port
  (not capped) before every episode at most 4. A path whose inbound gaps are shorter than 14 s never
  gets one (replays: data every 7 s / 13 s for 20 min: fresh ports within the cap, no soft restart).
- `TribeRecoveryArbiter.dataQuietSeconds(at:)`: seconds since data last proved the path (from the
  first sample when none has), -1 without a sample in the last 12 s (paused backend, stopped
  watchdog, a tick skipped while the data watch's arbiter owns recovery). Patch 0017 copies it into
  `TribeRoamingCounters.dataQuietSeconds` in `roamingCounters()`; it is a reading, never part of
  `asDictionary` / `summary` (journaled on every change). The provider replies it at top level as
  `data_quiet_s` (absent when -1). The app (iOS only) uses it in `HealthLoop::probeDeadCorroborated`:
  4 failed in-tunnel probes, outside the network-change grace, and either the handshake older than
  135 s (as in 141) or `awg_probe_dead_quiet_s` (45 s) without data. An older extension sends no
  key: the app keeps the rule of 141; an older app ignores the key.
- Tests: `TribeRoamingTests` (B1 replay, healthy roam, two slow paths, idle re-keying for 2 h, echo
  vs data at stage 3, the export) and the existing vectors with the expectations that changed by
  design; the B1 replay section uses only the API of tribe.15 and is run against both files.

## tribe.17 behaviour: the review of tribe.16 (TribeRoaming.swift only)

An independent review of tribe.16 found that an idle healthy tunnel could still take ladder steps and
that the app could fail over a path that had just recovered (`~/avpn-build/phone-diag/reviews/round42-wifi-out.md`).

- **Service traffic is the session's own (`TribeServiceTraffic`).** The provider computes it from the
  session's AmneziaWG parameters (`WGConfig.serviceTraffic`) into `TribeRoamingPolicy.serviceTraffic`:
  a handshake = I1-I5 (their tag lengths) + Jc x Jmax + S1 + 148 (+ a random trailer bound with
  RandomTrailers) + its confirming keepalive; a keepalive = S4 + 32 + the ContentPaddingAddition
  maximum (or the trailer bound). Sizes are those amneziawg-go v3.1.20260828 counts in tx_bytes
  (send.go SendHandshakeInitiation / JunkPackets, RoutineEncryption; peer.go SendBuffers). Fleet bundle
  at its maxima (AWG 3.1: Jc 6, Jmax 50, S1=S4=64, I1 44 B, ContentPaddingAddition 10-100, RandomTrailers
  off, PersistentKeepalive 25): keepalive 196 B, handshake 752 B. tribe.16 deducted a fixed 1024 B per
  handshake and nothing for keepalives.
- **Demand = outbound minus service traffic, for every stage** (`TribeServiceTraffic.demand`: a completed
  handshake costs its size, keepalives are paid from an allowance of one keepalive per interval, at most
  two). tribe.16 judged stage 3 by raw tx since the step: after any repair an idle tunnel took a false
  fresh port after ~1500 s (plain sizes; after ~250 s with the fleet's), then a soft restart, forever.
  A handshake retry is demand (an unanswered session is what the ladder is for).
- The floor of tribe.15 is kept explicitly: a completed handshake while less than `stallMinTxBytes` of
  demand went out since a count began starts that count over (both counts; never the stall clock or the
  stage). Below ~270 B/s on a path that re-keys every 15 s the ladder stays still; the data watch judges
  such paths (its ladder vectors unchanged; their rig now states its session's 422-byte handshake).
- **Idle end** (`TribeDataFlow.idleSeconds`, 60 s): no demand at all for a minute ends an open episode
  (stage 0, budget episode re-armed) and starts the demand count over: without user traffic nothing can
  prove or disprove a repair. The next stall starts at the fresh port again.
- **Sampling gaps** (`samplingGapSeconds`, 10 s; the watchdog ticks every 1 s, 5 s when idle): a sample
  after a longer pause (the extension suspended while the system is awake) is not an observation: the
  stall clock, the demand counts and the exported verdict start again from it; no step on it.
- **RX**: a sample whose rx growth is exactly 148 B with the handshake time unchanged is a server's
  initiation (counted before the time moves), not data. An incoming keepalive is still data: a passive
  keepalive proves the path both ways, and bytes cannot tell it from a lone TCP ACK (not counting either
  would make an ACK-only upload look stalled).
- **The app's verdict** (`dataQuietSeconds`, replied as `data_stall_s`; tribe.16 sent `data_quiet_s`
  with another meaning): the time without data that proved the path, reported only while the tracker
  sees a stall right now (`stalledNow`: nothing in for `stallProbeSeconds` while `stallMinTxBytes` of
  demand went out); 0 while data comes in (also inside a repair's echo window) and while nobody sends.
- The data watch's handshake tx allowance is raised to the session's handshake by its runtime
  (`TribeDataWatchDeps.sessionHandshakeTxBytes`, the same number); its policy is otherwise unchanged.
- Tests: `TribeRoamingTests` "REVIEW REPLAYS" (idle after a repair for 1 h and idle from stage 0 for 2 h
  with plain, fleet and heavy-junk sessions; the review's F3 sequence; a 300 s sampling gap), B1 with the
  fleet and heavy sessions, the size function. The replay section uses only the API of 40f74845a besides a
  policy helper: against that file it fails (F1 false steps at 1501/3025 s plain, from 251 s fleet; F2
  heavy from 126 s; F3 reports 48 s at 48 s; F4 restarts at once after the gap).

## tribe.18 behaviour: the second review of the 24.11 fix (TribeRoaming.swift only)

Second review (`~/avpn-build/phone-diag/reviews/round45-wifi2-out.md`): four rare cases left after tribe.17.

- **A handshake by its time only (G2).** tribe.17 also took a 148-byte rx growth with the handshake time
  unchanged for a server's initiation; a padded TCP ACK is 148 B too (52 + content padding 64 + 32,
  receive.go counts before trimming to the IP length), so a steady upload acked once a second got a false
  fresh port after 4 s. Now only a moving handshake time marks a handshake. A server's lone initiation is
  data in its own sample again (rare: the server re-keys only when it has data for us).
- **RandomTrailers as the engine reads it (G3).** `TribeServiceTraffic.engineBool` = the generator's
  `uapiBool` set ("on", "1", "true", "t", "yes"; trimmed, case-insensitive); `tests/check_engine_spellings.sh`
  (a build gate) fails when the pinned PacketTunnelSettingsGenerator.swift accepts another set. Our app
  writes "1"/"0" (AwgConfigBuilder); the fleet's bundles carry `RandomTrailers: off` (tribe-backend
  `awg31_random_trailers` default; live values not read from production). With trailers a keepalive and
  an initiation stay below the peer's UDP window (send.go randomTrailer): bounded by
  max(MTU + S4 + 32 + content padding, 1500). The other keys read (Jc, Jmax, S1, S4, I1-I5,
  ContentPaddingAddition, MTU, PersistentKeepalive) reach the engine as the same strings: no other
  spelling gap (PersistentKeepalive "off" = 0 in both).
- **A handshake's bytes over its whole window (G4).** The initiation leaves in one sample and the response
  arrives in a later one (send.go / receive.go); tribe.17 deducted the handshake only inside the sample
  whose handshake time moved. Now `demand()` pays keepalives only; the tracker settles `handshakeTxBytes`
  against the demand added since the previous handshake when the time moves (and restores the idle clock
  when that was all), and while a handshake is not settled one handshake's worth of that window is held
  back from every stall decision (an initiation may still wait for its response: re-key, retry). On a
  dead path the threshold is therefore 4096 B plus one handshake (fleet 752 B, heavy junk 3726 B): B1
  still restarts the engine at +15 s with every session.
- The export is not 0 the moment nobody sends any more: it stays reported until the idle end (60 s
  without demand) if the last demand went unanswered (review 2, Q5).
- **A dead data path while the user sends nothing (review 2, Q2; unchanged, decided).** Handshakes keep
  completing and push notifications are small: the demand never reaches a stall, the ladder does not
  repair, the export stays 0 and the app's probe rule is not corroborated. What the user sees when he
  picks the phone up: the first requests hang; their demand is unanswered; the ladder's fresh port
  comes about 4 s after the demand starts, the engine restart about 14 s; if that does not help, the
  app fails over at about 45-50 s (the export counts the stall from the last proven data, including the
  idle time before). **Push notifications sent to the phone in the meantime are lost** (they go into a
  tunnel that passes no data); this is the behaviour of every earlier build. The data watch (off by
  default) is the only part that judges such a path without user traffic.
- App (tribe.18, outside the package): the stall verdict is dated by the time its status request was sent
  (a reply applied after a suspension is stale), and a failed live probe whose wall-clock duration exceeds
  its own timeouts (+2 s) spanned a suspension of the app and is not fed.
- Tests: `TribeRoamingTests` "REVIEW 2 REPLAYS" (the review's tables: G2 an upload acked by 148-byte ACKs,
  G3 trailers "1" with 1100-byte keepalives, G4 initiation and response in different samples and 5 s
  late); against 2e641743d: G2 fresh port at 4 s and restart at 14 s, G3 fresh port at 100 s, G4 fresh port
  at 4 s; here none.

## tribe.19 behaviour: device round air-D (TribeRoaming.swift only)

Device round air-D (iPhone, build 4039020f9 = tribe.17; `~/avpn-build/phone-diag/air-D/RESULTS.txt` W1, U1): Германия 1
(AWG) on Wi-Fi, Wi-Fi off -> LTE, on which AmneziaWG passed no data and completed no handshake that night, Wi-Fi back after
46-61 s. The old tunnel never recovered in place on the Wi-Fi (roam_fresh_ports +1, soft_restarts +0) and the app failed
over at +15.6 / +22.0 / +28.4 s, marking Германия 1 "в этой сети не отвечает" on the Wi-Fi where it connects in 2 s.

- **K1, a roam is another network.** A fresh-port roam (a path back after a real loss, or another interface) ends the
  episode, restarts the stall clock and the demand counts (`TribeStallTracker.noteNewNetwork`), re-arms the budget episode
  and restarts the exported verdict (`observedSince`): silence observed on the old network is not evidence here. A
  same-port bump (path event without a loss) is unchanged. (tribe.9-18 kept the stall clock across a roam.)
- **K2, prove a stale session at once.** If the session had no confirmed data path at that roam - stalled, a repair
  episode open, or no inbound data since the previous fresh-port roam - the arbiter asks for ONE soft restart on the next
  tick (`roamRestartSince`): `wgTurnOff` + `wgTurnOn` on the same TUN (the existing in-place restart): a new device with a
  new socket, whose first packet starts a new handshake on the new path at once: uapi.go:568-573 (`if peer.device.isUp()
  { peer.Start(); if peer.pkaOn { peer.SendKeepalive() }; peer.SendStagedPackets() }` - a new device's peer with
  PersistentKeepalive set), then send.go:438-439 (`if keypair == nil ... { peer.SendHandshakeInitiation(false) }`). The fresh port alone keeps the old keypair (send.go: a keepalive starts a handshake only for
  an expiring key). Through the shared budget (rolling cap 4 / 120 s, same-kind cooldown 8-10 s); given up once data
  comes in, after 30 s or at the next roam; never more than one per roam.
- Timelines after a roam: (a) a server that works on the new network: the fresh port at once, the soft restart on the
  next tick when the session was stale (<= 1 s; <= 5 s when the watchdog idled), the handshake one round trip later, data
  within ~1-3 s (replay: data at +1 s); no failover, no mark. (b) A server dead on the new network: the ladder goes on
  (stage-3 fresh port +30 s, soft restart +90 s), the exported verdict counts from the roam and reaches 45 s at +45 s
  (fleet bundle: its own unanswered initiations are the demand), the app fails over at ~+48 s and marks the node on that
  network - correctly. (c) Flapping every 20-30 s on a dead path: one soft restart per roam at most, never more than 4 in
  any 120 s (replay: 19 in 10 min); the app's evidence restarts at most until 120 s after the first change of the series.
- App side (outside the package, iOS): the path engine's network key is a network change for the verdicts
  (`ServiceEngine::observeNetwork`; the system's own notification sees our tunnel, not the Wi-Fi return, and did not fire
  in air-D): grace window, probe count, and the evidence restart (`HealthLoop::noteEvidenceRestart`): the handshake age,
  the stall verdict and the byte rule count from the change; a failed probe that started before it is not counted.
- Not changed: during an app failover (a server switch) iOS sends traffic outside the VPN for the ~2-6 s between the old
  tunnel's stop and the new one's start (air-D W1 r3-r5: a page from a Russian exit); with K2 a roam onto a network where
  the server works no longer needs a switch at all.

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
conan export recipes/go --version 1.27.4            # tribe.12 (1.26.0 for tribe.3-tribe.11)
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
(`self.requires("awg-apple/3.1.4-tribe.19")`); CMake configure exports all `recipes/` itself
(`client/cmake/recipes_bootstrap.cmake`), so use the same `CONAN_HOME` for configure. Rollback =
pin the root requirement back to `awg-apple/3.1.4-tribe.12` (then drop `TribeDataWatch.swift` and the
three data-watch provider files from the two `networkextension/CMakeLists.txt` and their calls from
`PacketTunnelProvider*.swift`), `awg-apple/3.1.4-tribe.11` (then also drop the `LibXrayTribeHTTP`
calls; the extension keeps working on core v1.260728.0), `awg-apple/3.1.4-tribe.10` (then also drop the `wgSetDirectSplit` /
`wgDirectSplitStats` calls from `PacketTunnelProvider+WireGuard.swift`), `3.1.4-tribe.9` or `3.1.4-tribe.8` (iOS; all binaries are
in the release cache), `3.1.4-tribe.7` (the NE sources then lose the `soft_restart` provider message:
revert `PacketTunnelProvider*.swift` to their tribe.7 state) or `3.1.4-tribe.5`. Both can be resolved from a cache that holds their binaries or rebuilt from this
recipe: their `TribeRoaming.swift` and test are frozen snapshots (rule above), their patch lists are
unchanged. The rebuilt recipe revision differs from the original one (the recipe files changed), the
package content does not.
