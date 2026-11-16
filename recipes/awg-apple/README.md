# awg-apple (Tribe recipe)

Official `amneziawg-apple` v3.1.4 plus reviewable Tribe patches. The package ships the Go
c-archive (`libwg-go.a`) and the exact patched Swift sources (`AWG_APPLE_SOURCE_DIR`) that the iOS
and macOS Network Extension targets compile.

## Versions and patch sets (`conandata.yml`)

| Version | Patches | Notes |
|---|---|---|
| `3.1.4-tribe.12` | 0001 + 0002 + 0003 + 0005 + 0006 + 0007 + 0008 + 0009 + 0010 + 0011 + 0013 + 0014 (+ before vendoring: engine 0012-tribe-scan-engine; vendored: core 0004-261101 + 0008-261101 + 0011-261101, libxray 0005 + 0006 + 0007) | current, unreleased; Xray core v1.261101.0 on Go 1.27.4, 0010 = `LibXrayTribeHTTP`, 0011 = `LibXrayTribeOutboundStats` (libxray 0007, core 0008), 0013 = the Scanner's probe engine (`LibXrayTribeScanMessage` / `LibXrayTribeScanStopAll`, core 0011), 0014 = its AmneziaWG mini-session runner (`awg_mini`, no new export), libxray 0005 = FreeOSMemory loop once per process, libxray 0006 = StopXray restores the Go memory settings. Slot 0012 is the data watch branch's (its `3.1.4-tribe.13`); rebased onto it this version becomes `3.1.4-tribe.14` |
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

Rebase onto the data watch branch (patch 0012, `3.1.4-tribe.13` based on tribe.11): no file and no
Go symbol is shared. 0012 adds `tribeprobe.go`, `tribeprobe_engine.go`, `tribeprobe_test.go`, edits
`api-apple.go` (`wgTurnOn`), `WireGuardAdapter.swift` and appends `wgSetTribeProbe` /
`wgTribeProbeStart` / `wgTribeProbeResult` at the end of `wireguard.h`; 0013 adds `api-tribescan.go`,
`api-tribescan-log.go` (reads `loggerFunc` / `CLogger` of `api-apple.go`, which 0012 keeps),
`api-tribescan_test.go`, `tribescan_ios.go`, `tribescan_other.go` and inserts its declarations after
`LibXrayTribeOutboundStats` (0011) - both apply in either order. Its package-main identifiers
(`tribeScan*`, `tribeXray*`, `LibXrayTribeScan*`, `tribeTunnelStats`) do not meet 0012's (`tribeProbe*`,
`probe*`, `itoa`, `readOne`, `wantState`, `writeBatch`). Textual conflicts, mechanical: the comment
above `version`, `_xray_pins` (tribe.14 = the tribe.12 pins incl. `engine_patches` and core 0011),
the gate block in `build()` and `package_info()` of `conanfile.py`, the version blocks of
`conandata.yml` (tribe.14 = 0001-0011 + 0012 + 0013 + 0014), and the version table of this README.
0014 adds only `api-tribescan-awg.go` and `tribeawg/` (identifiers `tribeScanAwgOpen`, package
`tribeawg`): no conflict with 0012.

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
(`self.requires("awg-apple/3.1.4-tribe.12")`); CMake configure exports all `recipes/` itself
(`client/cmake/recipes_bootstrap.cmake`), so use the same `CONAN_HOME` for configure. Rollback =
pin the root requirement back to `awg-apple/3.1.4-tribe.11` (then drop the `LibXrayTribeHTTP`
calls; the extension keeps working on core v1.260728.0), `awg-apple/3.1.4-tribe.10` (then drop the `wgSetDirectSplit` /
`wgDirectSplitStats` calls from `PacketTunnelProvider+WireGuard.swift`), `3.1.4-tribe.9` or `3.1.4-tribe.8` (iOS; all binaries are
in the release cache), `3.1.4-tribe.7` (the NE sources then lose the `soft_restart` provider message:
revert `PacketTunnelProvider*.swift` to their tribe.7 state) or `3.1.4-tribe.5`. Both can be resolved from a cache that holds their binaries or rebuilt from this
recipe: their `TribeRoaming.swift` and test are frozen snapshots (rule above), their patch lists are
unchanged. The rebuilt recipe revision differs from the original one (the recipe files changed), the
package content does not.
