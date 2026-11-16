#!/bin/bash
# AVPN (Scanner, lane L4): source-level gate of the extension's probe host wiring (plan scanner-client-plan.md
# v2.2 §2.2a, §2.3; CONNECT-INVARIANTS §32). The provider files have no host harness (NetworkExtension, the Go
# engine), so the places where the scan meets them are checked here; the relay itself is tested by
# ScanBridgeTests.swift.
#  1. Nothing the scan host runs can reach the tunnel's failure path: TribeScanHost.swift and
#     PacketTunnelProvider+Scan.swift never name xraySocketProtectionFailed, cancelTunnelWithError, the
#     tunnel's socket callback slot or its runtime session, and never stop, start or reconfigure the tunnel
#     (the WireGuard adapter is only read: getRuntimeConfiguration for the live peer).
#  2. handleAppMessage: the scan dispatch comes before the line that logs the message; the unknown-action
#     reply comes before the branches, and every branch's action is in tribeAppActionsWithBranch.
#  3. Stop-all comes first at every place the tunnel core stops, restarts or changes peer: stopTunnel,
#     stopXray (inside the lifecycle gate, before hev and the core stop), the terminal lease answer (inside
#     the gate, before the core stop), the WireGuard soft restart and configuration switch.
#  4. Both new Swift files are in the NE build list and in the --ne-typecheck list.
#  5. The tunnel lifecycle (review F1, F2): stopTunnel closes the host, a successful startTunnel reopens it, the
#     dispatch takes the epoch of its receipt before going async, the WireGuard adapter gets the backend-restart
#     callback when it is made (before it starts), that callback stops the engine synchronously and bounded but
#     never takes the lifecycle gate, and a start's late success reopens the host only if no stop came since.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IOS_DIR="$(cd "$HERE/.." && pwd)"
CLIENT_DIR="$(cd "$IOS_DIR/../.." && pwd)"
python3 -I - "$IOS_DIR" "$CLIENT_DIR" "$HERE/run_ios_swift_checks.sh" <<'PY'
import re, sys

ios, client, runner = sys.argv[1], sys.argv[2], sys.argv[3]
fails = []
checks = 0

def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()

def code(text):
    # Comments out (line comments only; these files have no "//" inside strings).
    return "\n".join(line.split("//", 1)[0] for line in text.splitlines())

def body(text, signature):
    i = text.find(signature)
    if i < 0:
        return None
    j = text.find("{", i)
    depth = 0
    for k in range(j, len(text)):
        if text[k] == "{":
            depth += 1
        elif text[k] == "}":
            depth -= 1
            if depth == 0:
                return text[j:k + 1]
    return None

def check(cond, what):
    global checks
    checks += 1
    if not cond:
        fails.append(what)

def before(text, first, second, what):
    a, b = text.find(first), text.find(second)
    check(a >= 0 and b >= 0 and a < b, what)

# 1. no path from the scan host to the tunnel
forbidden = ["xraySocketProtectionFailed", "cancelTunnelWithError", "LibXraySetSockCallback", "xrayRuntimeSession",
             "xraySocketCallbackRegistry", "xrayProtectCounters", "protectXraySocket", "retireXrayCallback",
             "LibXrayStopXray", "LibXrayRunXray", "stopTunnel(", "startTunnel(", "setTunnelNetworkSettings",
             "reasserting", "stopXray(", "startXray(", "Socks5Tunnel", ".update(tunnelConfiguration",
             "softRestartBackend", "rebindListenPort", "adapter.stop(", "adapter.start(", "wgSetConfig", "wgTurnO"]
for name in ["TribeScanHost.swift", "PacketTunnelProvider+Scan.swift"]:
    src = code(read(f"{ios}/{name}"))
    for word in forbidden:
        check(word not in src, f"{name} must not reference {word}")
scan_glue = code(read(f"{ios}/PacketTunnelProvider+Scan.swift"))
check(scan_glue.count("LibXrayTribeScanMessage") == 1 and scan_glue.count("LibXrayTribeScanStopAll") == 1,
      "the engine's C symbols are used only through TribeScanEngine (one place)")
adapter_uses = re.findall(r"(?:wgAdapter|adapter)\.([A-Za-z_]+)", scan_glue)
check(set(adapter_uses) <= {"getRuntimeConfiguration"},
      f"the scan glue only reads the WireGuard adapter (getRuntimeConfiguration), uses: {sorted(set(adapter_uses))}")

# 2. handleAppMessage
provider = code(read(f"{ios}/PacketTunnelProvider.swift"))
ham = body(provider, "override func handleAppMessage(")
check(ham is not None, "handleAppMessage found")
ham = ham or ""
before(ham, "tribeHandleScanMessageIfScan(", 'title: "App said: "', "scan dispatch before the line that logs the message")
before(ham, "guard tribeAppActionHasBranch(action)", "if action ==", "unknown-action reply before the first branch")
branches = re.findall(r"if action == ([A-Za-z_][A-Za-z0-9_.]*)", ham)
check(len(branches) >= 4, f"branches of handleAppMessage found ({branches})")
m = re.search(r"tribeAppActionsWithBranch: Set<String> = \[(.*?)\]", scan_glue, re.S)
listed = set(x.strip() for x in (m.group(1) if m else "").split(",") if x.strip())
for b in branches:
    check(b in listed, f"branch action {b} is listed in tribeAppActionsWithBranch")

# 3. stop-all first
stop_tunnel = body(provider, "override func stopTunnel(") or ""
before(stop_tunnel, "tribeScanStopAllIfUsed(", "switch protoType", "stopTunnel: stop-all before the core stops")
check(re.search(r"tribeScanStopAllIfUsed\(reason: \"[a-z_]+\", close: true\)", stop_tunnel) is not None,
      "stopTunnel: the stop-all closes the host")
start_tunnel = body(provider, "override func startTunnel(") or ""
before(start_tunnel, "let completionHandler = tribeScanReopenOnSuccess(completionHandler)", "switch protoType",
       "startTunnel: a successful start reopens the host (its completion wrapped before any start path)")
xray = code(read(f"{ios}/PacketTunnelProvider+Xray.swift"))
stop_xray = body(xray, "func stopXray(") or ""
gate = body(stop_xray, "xrayNativeLifecycleGate.withExclusive") or ""
before(gate, "tribeScanStopAllIfUsed(", "Socks5Tunnel.quit()", "stopXray: stop-all inside the gate, before hev stops")
before(gate, "tribeScanStopAllIfUsed(", "LibXrayStopXray", "stopXray: stop-all inside the gate, before the core stops")
before(gate, "tribeScanStopAllIfUsed(", "retireXrayCallback", "stopXray: stop-all before the callback teardown")
upstream = code(read(f"{ios}/PacketTunnelProvider+Upstream.swift"))
terminal = body(upstream, "func upstreamLeaseTerminal(") or ""
tgate = body(terminal, "xrayNativeLifecycleGate.withExclusive") or ""
before(tgate, "tribeScanStopAllIfUsed(", "LibXrayStopXray", "terminal lease answer: stop-all inside the gate, before the core stops")
before(tgate, "tribeScanStopAllIfUsed(", "retireXrayCallback", "terminal lease answer: stop-all before the callback teardown")
wg = code(read(f"{ios}/PacketTunnelProvider+WireGuard.swift"))
soft = body(wg, "func handleSoftRestartAppMessage(") or ""
before(soft, "tribeScanStopAllIfUsed(", "softRestartBackendResult", "soft restart: stop-all before the backend restarts")
switch = body(wg, "func handleWireguardAppMessage(") or ""
before(switch, "tribeScanStopAllIfUsed(", ".update(tunnelConfiguration", "configuration switch: stop-all before the peer changes")
start_wg = body(wg, "func startWireguard(") or ""
before(start_wg, "WireGuardAdapter(with:", "tribeScanAttachAdapter(adapter)", "startWireguard: the backend-restart callback once the adapter exists")
before(start_wg, "tribeScanAttachAdapter(adapter)", ".start(tunnelConfiguration", "startWireguard: the callback is set before the adapter starts")
restart_cb = body(scan_glue, "func tribeScanBackendWillRestart(") or ""
check(restart_cb != "" and "withExclusive" not in restart_cb and ".async" not in restart_cb
      and "stopForBackendRestart(" in restart_cb, "the adapter's callback stops the engine synchronously (bounded), without the gate")
backend_stop = body(code(read(f"{ios}/TribeScanHost.swift")), "func stopForBackendRestart(") or ""
check(backend_stop != "" and "withExclusive" not in backend_stop and "backendStopBoundMs" in backend_stop
      and "stopAll(waitMs: Self.backendStopWaitMs, epoch:" in backend_stop,
      "stopForBackendRestart: no lifecycle gate, the engine stop with the new epoch, a bounded wait")
reopen = body(scan_glue, "func tribeScanReopenOnSuccess(") or ""
before(reopen, "let token = lifecycle.reopenToken", "return {", "the reopen token is taken when the start begins")
check("reopen(token: token)" in reopen, "the reopen is bound to that start's token")
check(re.search(r"case \.rebind:\s*return", restart_cb) is not None and re.search(r"case \.stop, \.pause, \.restart:", restart_cb) is not None,
      "the adapter's callback: stop / pause / restart request a stop, rebind keeps the scans")
check("extension WireGuardAdapter: TribeBackendRestartObservable {}" in scan_glue, "the adapter's callback is active (conformance)")
dispatch = body(scan_glue, "func tribeHandleScanMessageIfScan(") or ""
before(dispatch, "lifecycle.epoch", ".async", "the dispatch takes the epoch of its receipt before going async")
check("receivedEpoch: received" in dispatch, "the dispatch passes the epoch of its receipt to the host")
check("override func sleep(" in scan_glue and "tribeScanStopAllIfUsed(" in (body(scan_glue, "override func sleep(") or ""),
      "sleep: stop-all")

# 4. build lists
ne_list = read(f"{client}/ios/networkextension/CMakeLists.txt")
runner_src = read(runner)
for name in ["TribeScanHost.swift", "PacketTunnelProvider+Scan.swift"]:
    check(f"platforms/ios/{name}" in ne_list, f"{name} in client/ios/networkextension/CMakeLists.txt")
    check(f'"$IOS_DIR/{name}"' in runner_src, f"{name} in the --ne-typecheck list")

if fails:
    for f in fails:
        print("FAIL:", f)
    print(f"iOS scan wiring: {len(fails)} of {checks} checks FAILED")
    sys.exit(1)
print(f"iOS scan wiring checks passed ({checks} checks)")
PY
