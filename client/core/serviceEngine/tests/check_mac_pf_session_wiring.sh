#!/bin/bash
# AVPN (macOS pf state ownership, 2026-11-24): where the kill switch's pf state is written and flushed FROM.
# The behaviour of MacOSFirewall itself is tested against a model of the pf kernel state in
# mac_pf_session_check.cpp (build_mac_pf_session.sh); each line below fails if a call site is reverted.
#   K1  no caller enables a session anchor (macospfanchors.h: SessionRule / ScanRule) with the load-if-empty
#       call (setAnchorEnabled(<it>, true) / enableAnchor(<it>)): the kernel copy is an earlier session's;
#   K2  both macOS kill switches write their session through MacOSFirewall::applySessionRules and name no
#       anchor themselves: AmneziaWG with its own utun and 400.allowPIA off, Xray with the tun it brought up;
#   K3  the tun of a service-routed session is the one IpcServer::createTun brought up, forgotten at deleteTun;
#       the client gives the same name to createTun and to tun2socks, and the service keeps no copy of it
#       for pf;
#   K4  a stop: KillSwitch::disableKillSwitch -> applyStrictBlock (strict) or uninstall; the AWG stop
#       (deleteInterface) reaches it; disableAllTraffic (and so the service start with strict on) ->
#       applyStrictBlock; the service start without strict -> disableKillSwitch;
#   K5  uninstall flushes every sub-anchor after the main ruleset dropped them; install starts with uninstall.
# Run by the check sweep (every check_*.sh of this directory).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../../.." && pwd)"
KS="$ROOT/service/server/killswitch.cpp"
WG="$ROOT/client/platforms/macos/daemon/wireguardutilsmacos.cpp"
FW="$ROOT/client/platforms/macos/daemon/macosfirewall.cpp"
OWN="$ROOT/client/platforms/macos/daemon/macospfanchors.h"
IPC="$ROOT/ipc/ipcserver.cpp"
XRAY="$ROOT/client/core/protocols/xrayProtocol.cpp"
fail=0
bad() { echo "FAIL: $1"; fail=1; }
code() { grep -v '^[[:space:]]*//' "$1" || true; }
# The body of a C++ function: from its definition line to the first line that is exactly "}".
body() { code "$1" | awk -v sig="$2" 'index($0, sig) == 1 { on = 1 } on { print } on && /^}$/ { exit }'; }
# The first "#ifdef Q_OS_MACOS" block of a text.
macblock() { printf '%s\n' "$1" | awk '/^#ifdef Q_OS_MACOS/ { on = 1; next } on && /^#endif/ { exit } on { print }'; }
has() { printf '%s\n' "$1" | grep -F -- "$2" > /dev/null; }
count() { printf '%s\n' "$1" | grep -cF -- "$2" || true; }
at() { printf '%s\n' "$1" | grep -nF -- "$2" | head -1 | cut -d: -f1 | sed 's/^$/0/'; }

# ---- K1 ------------------------------------------------------------------------------------------------------
session=$(grep -E 'AnchorKind::(SessionRule|ScanRule)' "$OWN" | grep -oE '"[0-9]{3}\.[A-Za-z]+"' | tr -d '"')
[ -n "$session" ] || bad "K1: no session anchor found in macospfanchors.h"
echo "$session" | grep -qx '200.allowVPN' || bad "K1: 200.allowVPN is not a session anchor in macospfanchors.h"
sources=$(find "$ROOT/client" "$ROOT/service" "$ROOT/ipc" \( -name '*.cpp' -o -name '*.h' -o -name '*.mm' \) \
          -not -path '*/3rd/*' -not -path '*/tests/*' 2>/dev/null)
for a in $session; do
  aq="${a//./\\.}"
  hits=$(printf '%s\n' "$sources" | while read -r f; do
           code "$f" | grep -nE "(setAnchorEnabled|enableAnchor)\(QStringLiteral\(\"$aq\"\)" \
             | grep -vE "setAnchorEnabled\(QStringLiteral\(\"$aq\"\), *false\)" | sed "s|^|$f:|"
         done)
  [ -z "$hits" ] || bad "K1: $a is enabled with the load-if-empty call: $hits"
done
fwtext="$(code "$FW")"
has "$(body "$FW" 'void MacOSFirewall::enableAnchor(const QString& anchor)')" 'if (!avpn::pf::kernelCopyIsCurrent(anchor)) {' \
  || bad "K1: enableAnchor keeps the kernel copy of a session anchor"

# ---- K2 ------------------------------------------------------------------------------------------------------
ksEnable="$(macblock "$(body "$KS" 'bool KillSwitch::enableKillSwitch(const QJsonObject &configStr, int vpnAdapterIndex) {')")"
has "$ksEnable" 'MacOSFirewall::applySessionRules(params, m_tunnelIfname);' || bad "K2: the Xray kill switch does not write its session through applySessionRules with its tun"
has "$ksEnable" 'params.allowPIA = true;' || bad "K2: the Xray kill switch does not pass the service's sockets (400.allowPIA)"
[ "$(count "$ksEnable" 'MacOSFirewall::setAnchor')" = "0" ] || bad "K2: the Xray kill switch writes an anchor itself"
[ "$(count "$ksEnable" 'MacOSFirewall::enableAnchor')" = "0" ] || bad "K2: the Xray kill switch enables an anchor itself"
wgApply="$(body "$WG" 'void WireguardUtilsMacos::applyFirewallRules(FirewallParams& params)')"
pia=$(at "$wgApply" 'params.allowPIA = false;')
apply=$(at "$wgApply" 'MacOSFirewall::applySessionRules(params, m_ifname);')
[ "${apply:-0}" -gt 0 ] || bad "K2: the AmneziaWG kill switch does not write its session through applySessionRules with its utun"
[ "${pia:-0}" -gt 0 ] && [ "${apply:-0}" -gt "${pia:-0}" ] || bad "K2: the AmneziaWG kill switch does not set 400.allowPIA off before applying"
[ "$(count "$wgApply" 'MacOSFirewall::setAnchor')" = "0" ] || bad "K2: the AmneziaWG kill switch writes an anchor itself"
[ "$(count "$(code "$WG")" 'MacOSFirewall::')" = "1" ] || bad "K2: wireguardutilsmacos.cpp calls MacOSFirewall outside applyFirewallRules"
has "$(body "$WG" 'bool WireguardUtilsMacos::addInterface(const InterfaceConfig& config) {')" 'applyFirewallRules(params);' \
  || bad "K2: addInterface no longer applies the AmneziaWG kill switch"

# ---- K3 ------------------------------------------------------------------------------------------------------
create="$(body "$IPC" 'bool IpcServer::createTun(const QString &dev, const QString &subnet)')"
made=$(at "$create" 'const bool created = Router::createTun(dev, subnet);')
noted=$(at "$create" 'KillSwitch::instance()->setTunnelInterface(dev);')
gate=$(at "$create" 'if (created)')
[ "${made:-0}" -gt 0 ] && [ "${gate:-0}" -gt "${made:-0}" ] && [ "${noted:-0}" -gt "${gate:-0}" ] \
  || bad "K3: createTun does not record the tun it brought up (after a successful Router::createTun)"
has "$(body "$IPC" 'bool IpcServer::deleteTun(const QString &dev)')" 'KillSwitch::instance()->clearTunnelInterface(dev);' \
  || bad "K3: deleteTun does not forget the session's tun"
xr="$(code "$XRAY")"
has "$xr" 'iface->createTun(tunName, ' || bad "K3: the client does not create the Xray tun by tunName"
has "$xr" 'QString("tun://%1").arg(tunName)' || bad "K3: tun2socks does not run on the tun the client creates"
for f in "$KS" "$FW" "$IPC" "$OWN"; do
  if code "$f" | grep -nE '"utun[0-9]+"' > /dev/null; then bad "K3: $(basename "$f") keeps a hard-coded tun name"; fi
done

# ---- K4 ------------------------------------------------------------------------------------------------------
ksDisable="$(macblock "$(body "$KS" 'bool KillSwitch::disableKillSwitch() {')")"
strict=$(at "$ksDisable" 'if (isStrictKillSwitchEnabled()) {')
block=$(at "$ksDisable" 'MacOSFirewall::applyStrictBlock();')
uninst=$(at "$ksDisable" 'MacOSFirewall::uninstall();')
[ "${strict:-0}" -gt 0 ] && [ "${block:-0}" -gt "${strict:-0}" ] && [ "${uninst:-0}" -gt "${block:-0}" ] \
  || bad "K4: disableKillSwitch does not end the session with applyStrictBlock (strict) / uninstall"
[ "$(count "$ksDisable" 'MacOSFirewall::setAnchor')" = "0" ] || bad "K4: disableKillSwitch writes an anchor itself"
has "$(macblock "$(body "$KS" 'bool KillSwitch::disableAllTraffic() {')")" 'MacOSFirewall::applyStrictBlock();' \
  || bad "K4: disableAllTraffic does not apply the strict block"
init="$(body "$KS" 'bool KillSwitch::init()')"
has "$init" 'return disableAllTraffic();' || bad "K4: the service start with strict on does not apply the strict block"
has "$init" 'return disableKillSwitch();' || bad "K4: the service start does not flush what a previous process left"
has "$(body "$WG" 'bool WireguardUtilsMacos::deleteInterface() {')" 'KillSwitch::instance()->disableKillSwitch();' \
  || bad "K4: the AmneziaWG stop does not end its kill switch"

# ---- K5 ------------------------------------------------------------------------------------------------------
un="$(body "$FW" 'void MacOSFirewall::uninstall()')"
conf=$(at "$un" 'pfctl -F all -f /etc/pf.conf')
flush=$(at "$un" 'flushAnchors(avpn::pf::stopFlushList());')
[ "${conf:-0}" -gt 0 ] && [ "${flush:-0}" -gt "${conf:-0}" ] || bad "K5: uninstall does not flush every sub-anchor after the main ruleset dropped them"
has "$(body "$FW" 'void MacOSFirewall::install()')" '    uninstall();' || bad "K5: install does not start from a clean state"
st="$(body "$FW" 'void MacOSFirewall::applyStrictBlock()')"
rl=$(at "$st" 'reloadAnchor(anchor);')
sf=$(at "$st" 'flushAnchors(avpn::pf::strictFlushList());')
[ "${rl:-0}" -gt 0 ] && [ "${sf:-0}" -gt "${rl:-0}" ] || bad "K5: the strict block is not reloaded before the session anchors are flushed"
has "$fwtext" 'static MacOSFirewall::CommandRunner s_commandRunner = nullptr;' || bad "K5: the command seam is not off by default"

[ "$fail" = "0" ] && echo "check_mac_pf_session_wiring: ok"
exit "$fail"
