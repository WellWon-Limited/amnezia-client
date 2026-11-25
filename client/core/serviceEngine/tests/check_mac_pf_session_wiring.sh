#!/bin/bash
# AVPN (macOS pf state ownership, 2026-11-24): where the kill switch's pf state is written and flushed FROM.
# The behaviour of MacOSFirewall itself is tested against a model of the pf kernel state in
# mac_pf_session_check.cpp (build_mac_pf_session.sh); each line below fails if a call site is reverted.
#   K1  no caller enables a session anchor (macospfanchors.h: SessionRule / ScanRule) with the load-if-empty
#       call (setAnchorEnabled(<it>, true) / enableAnchor(<it>)): the kernel copy is an earlier session's;
#   K2  both macOS kill switches open a KillSwitch session and write it through MacOSFirewall::applySessionRules,
#       naming no anchor themselves: AmneziaWG (openTunnelSession) with its own utun and 400.allowPIA off, Xray
#       (enableKillSwitch) with the tun created for it;
#   K3  the tun of a service-routed session: IpcServer::createTun records it (tunnelCreated, its only caller),
#       enableKillSwitch takes it, a stop or an AmneziaWG open drops it; IpcServer::deleteTun never touches the
#       kill switch; the client gives the same name to createTun and to tun2socks; no hard-coded tun in pf code;
#   K4  a stop (disableKillSwitch) closes the session and drops the created tun, then applyStrictBlock (strict)
#       or uninstall; the AWG stop (deleteInterface) reaches it; disableAllTraffic: a session up ->
#       addBlockToSession, none -> applyStrictBlock; refresh: strict on -> disableAllTraffic, off ->
#       disableKillSwitch; the service start: strict -> disableAllTraffic, else disableKillSwitch;
#   K5  uninstall flushes every sub-anchor after the main ruleset dropped them; install starts with uninstall;
#       the strict block is reloaded before the flush; the block over a live session never installs.
#   K6  (round mac-C, review N1) DNS passes only through a tunnel: a session writes 310.blockDNS for its own tun
#       (setDnsPass, before its table), the static file's pass names the utun interfaces, no 310 pass rule without "on".
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
took=$(at "$ksEnable" 'const QString tunnel = m_createdTun;')
dropped=$(at "$ksEnable" 'm_createdTun.clear();')
xapply=$(at "$ksEnable" 'MacOSFirewall::applySessionRules(params, tunnel);')
xopen=$(at "$ksEnable" 'm_sessionOpen = true;')
[ "${took:-0}" -gt 0 ] && [ "${dropped:-0}" -gt "${took:-0}" ] && [ "${xapply:-0}" -gt "${dropped:-0}" ] \
  || bad "K2: the Xray kill switch does not take the tun created for it (and clear it) before writing its session"
[ "${xopen:-0}" -gt "${xapply:-0}" ] || bad "K2: the Xray kill switch does not open the session"
has "$ksEnable" 'params.allowPIA = true;' || bad "K2: the Xray kill switch does not pass the service's sockets (400.allowPIA)"
[ "$(count "$ksEnable" 'MacOSFirewall::setAnchor')" = "0" ] || bad "K2: the Xray kill switch writes an anchor itself"
[ "$(count "$ksEnable" 'MacOSFirewall::enableAnchor')" = "0" ] || bad "K2: the Xray kill switch enables an anchor itself"
ksOpen="$(body "$KS" 'void KillSwitch::openTunnelSession(const FirewallParams &params, const QString &tunnelIfname)')"
odrop=$(at "$ksOpen" 'm_createdTun.clear();')
oapply=$(at "$ksOpen" 'MacOSFirewall::applySessionRules(params, tunnelIfname);')
oopen=$(at "$ksOpen" 'm_sessionOpen = true;')
[ "${odrop:-0}" -gt 0 ] && [ "${oapply:-0}" -gt "${odrop:-0}" ] && [ "${oopen:-0}" -gt "${oapply:-0}" ] \
  || bad "K2: openTunnelSession does not drop a created tun, write the session and open it"
wgApply="$(body "$WG" 'void WireguardUtilsMacos::applyFirewallRules(FirewallParams& params)')"
pia=$(at "$wgApply" 'params.allowPIA = false;')
apply=$(at "$wgApply" 'KillSwitch::instance()->openTunnelSession(params, m_ifname);')
[ "${apply:-0}" -gt 0 ] || bad "K2: the AmneziaWG kill switch does not open its session with its utun"
[ "${pia:-0}" -gt 0 ] && [ "${apply:-0}" -gt "${pia:-0}" ] || bad "K2: the AmneziaWG kill switch does not set 400.allowPIA off before applying"
[ "$(count "$(code "$WG")" 'MacOSFirewall::')" = "0" ] || bad "K2: wireguardutilsmacos.cpp writes pf itself"
has "$(body "$WG" 'bool WireguardUtilsMacos::addInterface(const InterfaceConfig& config) {')" 'applyFirewallRules(params);' \
  || bad "K2: addInterface no longer applies the AmneziaWG kill switch"

# ---- K3 ------------------------------------------------------------------------------------------------------
create="$(body "$IPC" 'bool IpcServer::createTun(const QString &dev, const QString &subnet)')"
made=$(at "$create" 'const bool created = Router::createTun(dev, subnet);')
noted=$(at "$create" 'KillSwitch::instance()->tunnelCreated(dev);')
gate=$(at "$create" 'if (created)')
[ "${made:-0}" -gt 0 ] && [ "${gate:-0}" -gt "${made:-0}" ] && [ "${noted:-0}" -gt "${gate:-0}" ] \
  || bad "K3: createTun does not record the tun it brought up (after a successful Router::createTun)"
if has "$(body "$IPC" 'bool IpcServer::deleteTun(const QString &dev)')" 'KillSwitch'; then
  bad "K3: deleteTun touches the kill switch (a late delete would change a newer session)"
fi
callers=$(printf '%s\n' "$sources" | while read -r f; do if code "$f" | grep -qF 'tunnelCreated('; then echo "$f"; fi; done)
[ "$(printf '%s\n' "$callers" | grep -cv 'killswitch.h$')" = "1" ] && printf '%s\n' "$callers" | grep -q 'ipc/ipcserver.cpp$' \
  || bad "K3: tunnelCreated is not called from IpcServer::createTun alone (callers: ${callers:-none})"
[ "$(code "$ROOT/service/server/killswitch.h" | grep -cF 'm_createdTun = ')" = "1" ] && [ "$(code "$KS" | grep -cF 'm_createdTun = ')" = "0" ] \
  || bad "K3: the created tun is set outside tunnelCreated"
xr="$(code "$XRAY")"
has "$xr" 'iface->createTun(tunName, ' || bad "K3: the client does not create the Xray tun by tunName"
has "$xr" 'QString("tun://%1").arg(tunName)' || bad "K3: tun2socks does not run on the tun the client creates"
for f in "$KS" "$FW" "$IPC" "$OWN"; do
  if code "$f" | grep -nE '"utun[0-9]+"' > /dev/null; then bad "K3: $(basename "$f") keeps a hard-coded tun name"; fi
done

# ---- K4 ------------------------------------------------------------------------------------------------------
ksDisable="$(macblock "$(body "$KS" 'bool KillSwitch::disableKillSwitch() {')")"
closed=$(at "$ksDisable" 'm_sessionOpen = false;')
cdrop=$(at "$ksDisable" 'm_createdTun.clear();')
strict=$(at "$ksDisable" 'if (isStrictKillSwitchEnabled()) {')
block=$(at "$ksDisable" 'MacOSFirewall::applyStrictBlock();')
uninst=$(at "$ksDisable" 'MacOSFirewall::uninstall();')
[ "${closed:-0}" -gt 0 ] && [ "${cdrop:-0}" -gt 0 ] && [ "${strict:-0}" -gt "${closed:-0}" ] && [ "${strict:-0}" -gt "${cdrop:-0}" ] \
  || bad "K4: disableKillSwitch does not close the session and drop the created tun first"
[ "${strict:-0}" -gt 0 ] && [ "${block:-0}" -gt "${strict:-0}" ] && [ "${uninst:-0}" -gt "${block:-0}" ] \
  || bad "K4: disableKillSwitch does not end the session with applyStrictBlock (strict) / uninstall"
[ "$(count "$ksDisable" 'MacOSFirewall::setAnchor')" = "0" ] || bad "K4: disableKillSwitch writes an anchor itself"
ksAll="$(macblock "$(body "$KS" 'bool KillSwitch::disableAllTraffic() {')")"
live=$(at "$ksAll" 'if (m_sessionOpen)')
addb=$(at "$ksAll" 'MacOSFirewall::addBlockToSession();')
alone=$(at "$ksAll" 'MacOSFirewall::applyStrictBlock();')
[ "${live:-0}" -gt 0 ] && [ "${addb:-0}" -gt "${live:-0}" ] && [ "${alone:-0}" -gt "${addb:-0}" ] \
  || bad "K4: disableAllTraffic does not keep a live session's rules (addBlockToSession) / block alone without one"
refresh="$(body "$KS" 'bool KillSwitch::refresh(bool enabled)')"
has "$refresh" 'return disableAllTraffic();' && has "$refresh" 'return disableKillSwitch();' \
  || bad "K4: refresh does not go through disableAllTraffic (strict on) / disableKillSwitch (off)"
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
ab="$(body "$FW" 'void MacOSFirewall::addBlockToSession()')"
has "$ab" 'enableAnchor(anchor);' || bad "K5: the block over a live session does not switch the block anchors on"
if has "$ab" 'install();'; then bad "K5: the block over a live session installs (flushes the session's anchors)"; fi
if has "$ab" 'flushAnchors('; then bad "K5: the block over a live session flushes anchors"; fi

# ---- K6 ------------------------------------------------------------------------------------------------------
asr="$(body "$FW" 'void MacOSFirewall::applySessionRules(const FirewallParams& params, const QString& tunnelIfname)')"
dp=$(at "$asr" 'setDnsPass(tunnelIfname);')
dt=$(at "$asr" 'setAnchorTable(QStringLiteral("310.blockDNS"), true, QStringLiteral("dnsaddr"), params.dnsServers);')
[ "${dp:-0}" -gt 0 ] && [ "${dt:-0}" -gt "${dp:-0}" ] || bad "K6: a session does not write its DNS pass for its own tun before its table"
sdp="$(body "$FW" 'void MacOSFirewall::setDnsPass(const QString& tunnelIfname)')"
has "$sdp" 'avpn::pf::dnsSessionRules(tunnelIfname)' && has "$sdp" 'reloadAnchor(QStringLiteral("310.blockDNS"));' \
  || bad "K6: setDnsPass does not write the session's rules (or the static file for an unknown tun)"
dnsFile="$ROOT/deploy/data/macos/pf/tribe.310.blockDNS.conf"
if grep -v '^[[:space:]]*#' "$dnsFile" | grep -E '^[[:space:]]*pass' | grep -vqE '^[[:space:]]*pass out on \$utunInterfaces '; then
  bad "K6: tribe.310.blockDNS.conf passes DNS without naming the tunnel interfaces"
fi
grep -q 'pass out on %1 proto { tcp, udp } to <dnsaddr> port 53' "$OWN" || bad "K6: dnsSessionRules does not name the session's tun"

# ---- K7 (round mac-D3): the block lives as long as the person's intent, not one session -----------------------
dks="$(body "$KS" 'bool KillSwitch::disableKillSwitch() {')"
hb=$(at "$dks" 'if (hadBlock && holdActive() && !isStrictKillSwitchEnabled()) {')
un=$(at "$dks" 'MacOSFirewall::uninstall();')
[ "${hb:-0}" -gt 0 ] && [ "${un:-0}" -gt "${hb:-0}" ] || bad "K7: a stop under the lease on the intent does not keep the block before the uninstall"
kb="$(body "$KS" 'void KillSwitch::keepBlockForNextSession()')"
for forbidden in 'uninstall(' 'install(' 'applyStrictBlock(' 'flushAnchors('; do
  if has "$kb" "$forbidden"; then bad "K7: the kept block runs $forbidden (a moment without the block)"; fi
done
has "$(body "$KS" 'bool KillSwitch::init()')" 'MacOSFirewall::isInstalled()' || bad "K7: the service start does not look for a lease a previous process held"
has "$(body "$KS" 'bool KillSwitch::refresh(bool enabled)')" 'm_holdUntilMs = 0;' || bad "K7: the kill switch turned off does not clear the lease"
grep -q 'SLOT( bool setKillSwitchHold( int ttlMs, const QStringList &controlPlaneAddrs ) );' "$ROOT/ipc/ipc_interface.rep" || bad "K7: no IPC slot for the lease"
has "$(body "$IPC" 'bool IpcServer::setKillSwitchHold(int ttlMs, const QStringList &controlPlaneAddrs)')" 'KillSwitch::instance()->setHold(ttlMs, controlPlaneAddrs)' \
  || bad "K7: the IPC slot does not reach KillSwitch::setHold"
VC="$ROOT/client/vpnConnection.cpp"
has "$(body "$VC" 'void VpnConnection::syncKillSwitchHold(bool intentOn, const QStringList &controlPlaneAddrs)')" 'iface->setKillSwitchHold(ttl,' \
  || bad "K7: VpnConnection does not send the lease"
ENG="$ROOT/client/core/serviceEngine/AvpnEngineQml.cpp"
has "$(body "$ENG" 'void AvpnEngineQml::syncKillSwitchHold()')" 'Q_ARG(bool, m_wantConnected)' || bad "K7: the lease does not follow the person's intent"
has "$(body "$ENG" 'void AvpnEngineQml::syncIntent()')" 'syncKillSwitchHold();' || bad "K7: an intent change (Stop / Connect) does not reach the lease at once"
grep -q 'connect(&m_killSwitchHoldTimer, &QTimer::timeout, this, \[this\]() { syncKillSwitchHold(); });' "$ENG" || bad "K7: the lease is not renewed"
qr=$(grep -n '"syncKillSwitchHold", Qt::QueuedConnection, Q_ARG(bool, false)' "$ENG" | head -1 | cut -d: -f1)
qe=$(grep -n 'aboutToQuit, this, \[this\] { endUpstreamSessionOnQuit(); });' "$ENG" | head -1 | cut -d: -f1)
[ -n "$qr" ] && [ -n "$qe" ] && [ "$qr" -lt "$qe" ] || bad "K7: a quit does not give the lease back ahead of the stop it sends"

[ "$fail" = "0" ] && echo "check_mac_pf_session_wiring: ok"
exit "$fail"
