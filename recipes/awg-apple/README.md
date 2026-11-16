# awg-apple (Tribe recipe)

Official `amneziawg-apple` v3.1.4 plus reviewable Tribe patches. The package ships the Go
c-archive (`libwg-go.a`) and the exact patched Swift sources (`AWG_APPLE_SOURCE_DIR`) that the iOS
and macOS Network Extension targets compile.

## Versions and patch sets (`conandata.yml`)

| Version | Patches | Notes |
|---|---|---|
| `3.1.4-tribe.13` | 0001 + 0002 + 0003 + 0005 + 0006 + 0007 + 0008 + 0009 + 0012 | current (iOS 5.1.110 / 140, not released); tribe.11 + 0012 = data watch (`TribeDataWatch.swift`) and in-tunnel probe (`tribeprobe.go`), off unless the app's plan file enables it. The number skips 12 and the patch slot skips 0010/0011: both are taken by the unmerged branch `feat/upstream-nodes` (Xray core bump), whose changes tribe.13 does NOT contain |
| `3.1.4-tribe.11` | 0001 + 0002 + 0003 + 0005 + 0006 + 0007 + 0008 + 0009 | shipped (iOS 5.1.109 / 139); 0009 = userspace direct split (`directsplit.go`), off unless the app configures it |
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

## Tests

```sh
sh recipes/awg-apple/tests/run_tribe_roaming_tests.sh   # current version; also the build() gate
# a released version's snapshot (what build() runs for tribe.5/tribe.7):
sh recipes/awg-apple/tests/run_tribe_roaming_tests.sh \
  recipes/awg-apple/tribe/snapshots/3.1.4-tribe.7/TribeRoaming.swift \
  recipes/awg-apple/tests/snapshots/3.1.4-tribe.7/TribeRoamingTests.swift
sh recipes/awg-apple/tests/run_tribe_data_watch_tests.sh   # tribe.13 data watch; also a build() gate
```

## tribe.13 behaviour (patch 0012 + TribeDataWatch.swift)

Everything of tribe.11, plus a verdict about DATA (design:
`docs/specs/2026-11-14-ios-tunnel-side-data-watch-design.md` in tribe-backend, sections 0 and 0a).
The stall watchdog answers "is the session alive" and counts a new handshake as inbound progress; on
13.11.2026 a node completed handshakes for 6 min 50 s and returned no data, and nothing in the
extension said so. tribe.13 adds a second question to the SAME one-second tick, "does data come
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
    (`lateAnswerAt`: a `no_data` confirmed by the probe is taken back);
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
  `state=<pending|answered|silent|no_session|not_sent|unavailable|none> id=<n> ms=<n> late=<0|1>`.
  `wrapTribeProbeIfEnabled` is the outermost pass-through wrapper of the TUN device. The probe is one
  DNS query for the root name (type A, 17 bytes of payload: the query the split-DNS forwarder warms
  up with) from the tunnel address to the session's first DNS server, source port 50100-50199,
  repeated once after 1.5 s, injected as an inner IPv4/UDP packet; the reply is taken out of the
  device's output and never reaches the OS. Without a configuration the wrapper is not created and
  `wgTurnOn` behaves as tribe.11.
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
  ends by a deadline of its own, without polling.
- Limits of the probe, to be read literally: it is a DNS root query to the session's `dns1`; an
  answer proves the path phone -> node -> forwarding -> that resolver and back for a SMALL packet.
  `silent` proves that the engine had a sending keypair and took the packet; it does not prove the
  datagram left the radio. Inner IPv4 only. It says nothing about bulk transfer: a freeze that
  depends on size (about 16 KB and more) is invisible to it.
- `WireGuardAdapter`: `setDataWatchPolicy(_:)`, `dataWatchSnapshot(completionHandler:)`,
  `dataWatchInputs`, `dataWatchHandler` (both get the engine handle). The watch is fed by
  `dataWatchTick` right before `recovery.tick` in `stallTick` and told about real path events,
  device starts and in-place restarts. With the policy off (the default) every hook is one
  comparison and the adapter behaves as tribe.11; nothing is counted unconditionally any more.
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
    waits and declares nothing;
  - while a round is in progress (`arbiterOwnsRecovery`: active and not exhausted) the adapter
    does not run the stall ladder: its steps would spend the shared budget the switch needs. Between
    rounds and with the key off the ladder works as in tribe.11;
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
- Stage 2, the adapter (`WireGuardAdapter`, patch 0012). A command is executed inside
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
handshake during the wait, a late answer, a resolver in the direct list). `replay/` holds the
offline tooling (not exported): the replay of a tester journal through the real function
(aggregates only) and the mutation run of the rule
(`python3 recipes/awg-apple/replay/tribe_data_watch_mutants.py`).

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
(`self.requires("awg-apple/3.1.4-tribe.13")`); CMake configure exports all `recipes/` itself
(`client/cmake/recipes_bootstrap.cmake`), so use the same `CONAN_HOME` for configure. Rollback =
pin the root requirement back to `awg-apple/3.1.4-tribe.11` (then drop `TribeDataWatch.swift` and the
three data-watch provider files from the two `networkextension/CMakeLists.txt` and their calls from
`PacketTunnelProvider*.swift`), `awg-apple/3.1.4-tribe.10` (then also drop the `wgSetDirectSplit` /
`wgDirectSplitStats` calls from `PacketTunnelProvider+WireGuard.swift`), `3.1.4-tribe.9` or `3.1.4-tribe.8` (iOS; all binaries are
in the release cache), `3.1.4-tribe.7` (the NE sources then lose the `soft_restart` provider message:
revert `PacketTunnelProvider*.swift` to their tribe.7 state) or `3.1.4-tribe.5`. Both can be resolved from a cache that holds their binaries or rebuilt from this
recipe: their `TribeRoaming.swift` and test are frozen snapshots (rule above), their patch lists are
unchanged. The rebuilt recipe revision differs from the original one (the recipe files changed), the
package content does not.
