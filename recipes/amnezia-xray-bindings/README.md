# amnezia-xray-bindings (Tribe recipe)

Upstream `amnezia-xray-bindings` v1.4.0 (the desktop service's Xray: `amnezia_xray_configure`,
`_start`, `_stop`, `_setsockcallback`, `_setloghandler`) with the Xray core moved to
`amnezia-xray-core` v1.261101.0 (Go 1.27.4) and, in `1.4.0-tribe.1` (unreleased), the Scanner's
probe engine.

## Build

`build()` applies `patches/0001-tribe-scan-probe.patch` (conandata) and the shared engine
`../amnezia-libxray/patches/0012-tribe-scan-engine.patch` (package `tribescan/`, the same file as
awg-apple's and the Android AAR's) to the source tree, pins the core with `go mod edit -replace`
+ `go get .`, then copies the pinned core out of the module cache into `tribe-xray-core/`, applies
`../amnezia-libxray/patches/0011-xray-core-261101-instance-dialer-state.patch` to that copy and
replaces the module with it (module mode, no vendor tree); the build fails unless `go list -m`
resolves `github.com/xtls/xray-core` to `./tribe-xray-core`. Host builds run the gates (all
`-race`): core `TestTribeDialerStatePerInstance` + `TestTribeSocketProtectorReplacesControllers`,
`go test -tags tribescan_testkit ./tribescan`, and `TestTribeScanBindingsExport` (probes while the
service's singleton core restarts, the service's own socket callback never reached by a probe
socket). `AMNEZIA_XRAY_BINDINGS_TRIBE_SCAN_ABI` = `libxray-tribe-scan-v1`.

## Scanner C API (ABI `libxray-tribe-scan-v1`, for the service lane)

```c
char *amnezia_xray_scan_message(char *message, char *host_options);  /* free with amnezia_xray_free */
char *amnezia_xray_scan_stop_all(int64_t waitMs);                     /* free with amnezia_xray_free */
```

(cgo writes them into `amnezia_xray.h`; the arguments are `char *` there.)

- `amnezia_xray_scan_message`: one app message of the `tribe-scan-v1` contract
  (`client/core/serviceEngine/ScanHostContract.h`: `scan_caps`, `scan_start`, `scan_add`,
  `scan_poll`, `scan_freeze`, `scan_cancel`) passed AS IS from the QtRO slot, and its reply JSON.
  `host_options` (NULL = none): `scan_start` reads `{"bind_interface": "en0"}` or
  `{"bind_interface_index": n}` - the physical uplink; REQUIRED on macOS (`bad_request` /
  `host_options.bind_interface` without it), optional on Windows / Linux; `"probe_base_ips":
  ["ip", ...]` (the probe host's addresses for the access attempts - only a FALLBACK: the contract
  field `probe.base_ips` of scan_start always wins); `"awg_live_peer"`; `"awg_probe_binary"`
  (also read by scan_caps). Every message may carry
  `"gen": {"source", "epoch": 16 hex, "counter"}` (the service's path monitor), passed through as
  the progress `gen` and the access attempts' `gen`.
- `amnezia_xray_scan_stop_all(waitMs)`: tears the scan down and waits up to `waitMs` (max 10000);
  `{"stopped":true}` = nothing of any scan is alive (instances, jobs, probe children - killed and
  reaped -, access attempts); `false` = the teardown goes on and `scan_start` is refused
  (`internal` / `stopping`) until it is done; the false reply carries what is still alive, e.g.
  `{"stopped":false,"instances":0,"jobs":1,"closers":0,"attempts":0,"awg":0,"children":1}`
  (`children` = probe children, registered by `tribescan_awg.go`). With an epoch: `amnezia_xray_scan_message(
  "{\"action\":\"scan_stop_all\",\"wait_ms\":n}", "{\"host_epoch\":E}")`; a later `scan_start` /
  `scan_add` with a lower `host_epoch` is refused (`stale_epoch`), also a start that was already
  waiting for the old scan's teardown when the stop came (a stop cancels a waiting start of its epoch
  or older: no such scan starts after `{"stopped":true}`). A stop with epoch E ends the work of E and
  older only - never a scan started in a newer epoch - and E equal to the running scan's epoch ends it
  (the service's app stop and teardown check carry the current epoch). Same guarantees as the NE export
  (`recipes/awg-apple/README.md`). Call it before the service stops or reconfigures its tunnel.
- Threading: safe from any thread, concurrently with `amnezia_xray_configure/start/stop`. Nothing
  blocks on the network: `scan_poll` / `scan_add` / `scan_caps` / `scan_freeze` / `scan_cancel`
  answer at once (the final byte total arrives in the final `scan_progress`), a replacing
  `scan_start` waits up to 3 s.
- Caps: `platform` `macos` / `windows` / `linux`, 2 full probes at once (composites verified), 6
  legs at once on one shared instance, no `awg_mini` (a separate runner), `needs_vpn` false.
- A probe instance is a SECOND core in the service's Go runtime, independent of the singleton
  (`server` is never touched). Its sockets - every outbound, DNS, the reach dial and the direct
  access check - are bound to `bind_interface` in Go (`IP_BOUND_IF` / `IPV6_BOUND_IF` on macOS,
  `SO_BINDTODEVICE` on Linux, `IP_UNICAST_IF` on Windows) and do NOT pass the callback registered
  with `amnezia_xray_setsockcallback` (core 0011); a probe therefore never enters a tunnel that owns
  the default route (a live AWG `amneziawg-go` or Xray utun), and a failed bind is the probe's
  error `bind_failed`. HTTPS is Go's own `crypto/tls` with the system roots: the service needs no TLS
  stack (no Qt TLS plugin).
- awg_mini: offered (4 sessions at once) only when the host options of the message name the probe
  binary, `"awg_probe_binary": "/absolute/path/amneziawg-go"` - the service's own `amneziawg-go`
  built with `recipes/awg-go` option `tribe_probe=True` (scan_caps reads it too). Each session is a
  child `amneziawg-go probe` (protocol `tribe-awg-probe-v1`, `tribescan_awg.go`): the engine sends
  the job (UAPI, address, MTU, interface index, echoes, handshake timeout) on its stdin, reads the
  handshake / echo status, asks it to connect to `probe.ip:port` inside the tunnel and runs the
  normal data probe over its stdin / stdout; the child binds its UDP socket to the interface
  (`IP_BOUND_IF` / `SO_BINDTODEVICE`) before its first packet and is killed at the probe's deadline,
  on cancel and on close. The live AmneziaWG tunnel (the `amneziawg-go` daemon) is another process
  and is never touched; `awg_live_peer` (scan_start) refuses its node. Gate:
  `TestTribeScanBindingsAwgChild` (this test binary as a stand-in child: protocol, data probe,
  refusals, no fd left); the real child's gate is the awg-go recipe's `TestTribeProbe`. Windows: no
  awg_mini.
- Logs: probe instances log into their own scope (core 0011), never into the handler that
  `amnezia_xray_setloghandler` feeds or, when no tunnel Xray ever started, xray-core's default
  stdout handler (`/tmp/tribe-daemon.log`); context-free Xray lines and gRPC's stderr lines reach
  them with every queued candidate's hosts, addresses and credentials masked (`[redacted]`). Each
  probe leaves one line `tribescan: scan=... probe=... kind=... error=... reach_ms=... ...` in the
  process Xray log at info (the tunnel's handler shows it at its level; the default handler always).
  Details: `recipes/awg-apple/README.md` ("Log privacy").
- Known limits: the macOS kill switch's pf anchors may drop probe traffic to node IPs (plan R6, not
  checked here).

Message formats, items, errors, byte gate, freeze / cancel: `recipes/awg-apple/README.md`
("tribe-scan"), the same engine.

Build lists: no new file for the service's CMake (the exports live in `libamnezia_xray.a` and its
header); the service lane adds its own `service/server/tribe_scan.{h,cpp}` to
`service/server/CMakeLists.txt` and the QtRO slots in `ipc/ipc_interface.rep` / `ipc/ipcserver.*`.

Checked on this Mac: macOS arm64 build and gates; Windows amd64 (`c-shared` DLL) and Linux amd64 /
arm64 (`c-shared` .so) cross-builds of the patched tree link with `zig cc` (the Linux c-archive needs
a Linux `ar`); no Windows or Linux run.
