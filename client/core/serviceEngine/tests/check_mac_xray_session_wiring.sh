#!/bin/bash
# AVPN (macOS own-Xray no-data, owner's Mac 23.11): where the service's Xray core session rule and its
# diagnostics are CALLED FROM. The rule itself is tested by behaviour in
# service/server/tests/xray_session_check.cpp (build_xray_session.sh); each line below fails if its call
# site in service/server/xray.cpp or ipc/ipcserver.cpp is reverted.
#   X1  a start runs only on a closed core: an open instance is closed before routes and configure;
#   X2  the instance counts as open from a successful configure, closed after amnezia_xray_stop;
#   X3  a stop closes the core only when an instance is open (the second stop of XrayProtocol is a no-op);
#   X4  diagnostics: the service log switch reaches Xray; the config the core gets is the diag config;
#       the log handler filters the raised Info lines.
# Run by the check sweep (every check_*.sh of this directory).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../../.." && pwd)"
XRAY="$ROOT/service/server/xray.cpp"
IPC="$ROOT/ipc/ipcserver.cpp"
fail=0
bad() { echo "FAIL: $1"; fail=1; }
code() { grep -v '^[[:space:]]*//' "$1" || true; }
# The body of a C++ function: from its definition line to the first line that is exactly "}".
body() { code "$1" | awk -v sig="$2" 'index($0, sig) == 1 { on = 1 } on { print } on && /^}$/ { exit }'; }
has() { printf '%s\n' "$1" | grep -F -- "$2" > /dev/null; }
# Line number of the first line of $1 (text) containing fixed string $2; 0 when absent.
at() { printf '%s\n' "$1" | grep -nF -- "$2" | head -1 | cut -d: -f1 | sed 's/^$/0/'; }

start="$(body "$XRAY" 'bool Xray::startXray(const QString &cfg)')"
stop="$(body "$XRAY" 'bool Xray::stopXray()')"
logh="$(body "$XRAY" 'void Xray::logHandler(char* str)')"

# ---- X1 ------------------------------------------------------------------------------------------------
guard=$(at "$start" 'm_core.beforeStart() == avpn::XrayCoreSession::StartStep::CloseOpenFirst')
closeFirst=$(at "$start" 'stopXray();')
routes=$(at "$start" 'RouterMac::Instance().routeAddXray(')
configure=$(at "$start" 'amnezia_xray_configure(')
[ "${guard:-0}" -gt 0 ] || bad "X1: startXray does not ask the session rule before a start"
[ "${closeFirst:-0}" -gt "${guard:-0}" ] || bad "X1: an open instance is not closed (stopXray) at a start"
[ "${routes:-0}" -gt "${closeFirst:-0}" ] || bad "X1: the uplink routes are installed before the open instance is closed"
[ "${configure:-0}" -gt "${closeFirst:-0}" ] || bad "X1: configure runs before the open instance is closed"

# ---- X2 ------------------------------------------------------------------------------------------------
configured=$(at "$start" 'm_core.onConfigured();')
[ "${configured:-0}" -gt "${configure:-0}" ] || bad "X2: the instance is not marked open after configure"
coreStop=$(at "$stop" 'amnezia_xray_stop()')
closed=$(at "$stop" 'm_core.onClosed();')
[ "${closed:-0}" -gt "${coreStop:-0}" ] || bad "X2: the instance is not marked closed after amnezia_xray_stop"

# ---- X3 ------------------------------------------------------------------------------------------------
asked=$(at "$stop" 'const bool closeCore = m_core.beforeStop() == avpn::XrayCoreSession::StopStep::Close;')
gated=$(at "$stop" 'if (closeCore) {')
[ "${asked:-0}" -gt 0 ] || bad "X3: stopXray does not ask the session rule"
[ "${gated:-0}" -gt "${asked:-0}" ] && [ "${coreStop:-0}" -gt "${gated:-0}" ] \
    || bad "X3: amnezia_xray_stop is not gated by the session rule"
[ "$(printf '%s\n' "$stop" | grep -cF 'amnezia_xray_stop()')" = "1" ] || bad "X3: stopXray closes the core in more than one place"
[ "$(code "$XRAY" | grep -cF 'amnezia_xray_stop()')" = "1" ] || bad "X3: the core is closed outside stopXray"

# ---- X4 ------------------------------------------------------------------------------------------------
has "$(body "$IPC" 'void IpcServer::setLogsEnabled(bool enabled)')" 'Xray::getInstance().setDiagnosticsEnabled(enabled);' \
    || bad "X4: the service log switch does not reach Xray"
has "$start" 'avpn::xrayDiagConfig(cfg, m_diagnostics);' || bad "X4: startXray does not build the diag config"
has "$start" 'QByteArray bytes = diag.config.toUtf8();' || bad "X4: the core does not get the diag config"
has "$start" 'm_levelRaised = diag.raised;' || bad "X4: the log handler does not learn that the level was raised"
has "$logh" 'avpn::xrayKeepCoreLine(line, m_levelRaised.load())' || bad "X4: the log handler does not filter the raised Info lines"

[ "$fail" = "0" ] && echo "check_mac_xray_session_wiring: ok"
exit "$fail"
