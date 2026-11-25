#!/bin/bash
# AVPN (awg audit 25.11.2026, round mac-D): every interface-level setting that a desktop daemon applies when it creates
# the interface and does not re-send with the peer is compared before an in-place server switch.
#   P1  for each desktop WireguardUtils (macOS, Linux, Windows): the InterfaceConfig fields read by addInterface (Windows:
#       + toWgConf, which it calls; macOS/Linux: + the IPUtils address and MTU setup, the bring-up in activate) minus
#       the fields read by updatePeer (what Daemon::switchServer re-sends) - each must be compared by
#       Daemon::supportServerSwitching itself (current.<field>) or by avpn::interfaceSettingsThatDiffer (live.<field>,
#       client/daemon/serverswitchpolicy.h). A new AmneziaWG parameter written by addInterface fails here until the
#       switch decision knows it.
#   P3  Windows: the per-peer firewall rules of WindowsFirewall::enablePeerTraffic (tagged by the peer key, removed only
#       with a peer of another key) - every field it reads but the key itself must be compared too: on a switch with the
#       same key the old config's rules stay (review of f37b06b0e: the extra allowed DNS servers).
#   P2  supportServerSwitching refuses an in-place switch when interfaceSettingsThatDiffer names a setting.
# The decision itself runs on the real daemon in build_daemon_server_switch.sh. Run by the check sweep.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../../.." && pwd)"
C="$ROOT/client"
DAEMON="$C/daemon/daemon.cpp"
POLICY="$C/daemon/serverswitchpolicy.h"
fail=0
bad() { echo "FAIL: $1"; fail=1; }
code() { grep -v '^[[:space:]]*//' "$1" || true; }
body() { code "$1" | awk -v sig="$2" 'index($0, sig) == 1 { on = 1 } on { print } on && /^}$/ { exit }'; }
fields() { grep -oE "$2m_[A-Za-z0-9]+" <<< "$1" | sed -E "s/^$2//" | sort -u; }

[ -f "$POLICY" ] || { echo "FAIL: P1: $POLICY is missing"; exit 1; }
sw="$(body "$DAEMON" 'bool Daemon::supportServerSwitching(const InterfaceConfig& config) const {')"
[ -n "$sw" ] || bad "P1: Daemon::supportServerSwitching not found"
pol="$(code "$POLICY")"
compared() { grep -qF "current.$1 " <<< "$sw" || grep -qF "live.$1 " <<< "$pol"; }

check_platform() {  # <label> <wireguardutils.cpp> <class> [extra source:signature:prefix ...]
  local label="$1" file="$2" cls="$3"; shift 3
  local add peer extra f sig pre src n=0
  add="$(fields "$(body "$file" "bool $cls::addInterface(const InterfaceConfig& config) {")" 'config\.')"
  [ -n "$add" ] || { bad "P1 $label: $cls::addInterface reads no config field (signature moved?)"; return; }
  for extra in "$@"; do
    src="${extra%%|*}"; sig="${extra#*|}"; pre="${sig##*|}"; sig="${sig%|*}"
    f="$(fields "$(body "$src" "$sig")" "$pre")"
    [ -n "$f" ] || bad "P1 $label: '$sig' in $(basename "$src") reads no config field (signature moved?)"
    add="$(printf '%s\n%s\n' "$add" "$f" | sort -u)"
  done
  peer="$(fields "$(body "$file" "bool $cls::updatePeer(const InterfaceConfig& config) {")" 'config\.')"
  [ -n "$peer" ] || { bad "P1 $label: $cls::updatePeer reads no config field (signature moved?)"; return; }
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    grep -qx -- "$f" <<< "$peer" && continue
    n=$((n + 1))
    [ -n "${SWITCH_CHECK_VERBOSE:-}" ] && echo "  $label interface-level: $f"
    compared "$f" || bad "P1 $label: addInterface applies $f, updatePeer does not re-send it, and the switch decision does not compare it"
  done <<< "$add"
  echo "P1 $label: $n interface-level fields, all compared"
}

check_platform macOS "$C/platforms/macos/daemon/wireguardutilsmacos.cpp" WireguardUtilsMacos \
  "$C/platforms/macos/daemon/iputilsmacos.cpp|bool IPUtilsMacos::addIP4AddressToDevice(const InterfaceConfig& config) {|config\." \
  "$C/platforms/macos/daemon/iputilsmacos.cpp|bool IPUtilsMacos::addIP6AddressToDevice(const InterfaceConfig& config) {|config\." \
  "$C/platforms/macos/daemon/iputilsmacos.cpp|bool IPUtilsMacos::setMTUAndUp(const InterfaceConfig& config) {|config\."
check_platform Linux "$C/platforms/linux/daemon/wireguardutilslinux.cpp" WireguardUtilsLinux \
  "$C/platforms/linux/daemon/iputilslinux.cpp|bool IPUtilsLinux::addIP4AddressToDevice(const InterfaceConfig& config) {|config\." \
  "$C/platforms/linux/daemon/iputilslinux.cpp|bool IPUtilsLinux::addIP6AddressToDevice(const InterfaceConfig& config) {|config\." \
  "$C/platforms/linux/daemon/iputilslinux.cpp|bool IPUtilsLinux::setMTUAndUp(const InterfaceConfig& config) {|config\."
# Windows: the [Interface] section of toWgConf (members read without "config.")
check_platform Windows "$C/platforms/windows/daemon/wireguardutilswindows.cpp" WireguardUtilsWindows \
  "$C/daemon/interfaceconfig.cpp|QString InterfaceConfig::toWgConf(const QMap<QString, QString>& extra) const {|"

# ---- P3 ------------------------------------------------------------------------------------------------------
peerfw="$(fields "$(body "$C/platforms/windows/daemon/windowsfirewall.cpp" 'bool WindowsFirewall::enablePeerTraffic(const InterfaceConfig& config) {')" 'config\.')"
if [ -z "$peerfw" ]; then
  bad "P3 Windows: WindowsFirewall::enablePeerTraffic reads no config field (signature moved?)"
else
  n=0
  while IFS= read -r f; do
    [ -n "$f" ] && [ "$f" != m_serverPublicKey ] || continue # the key is the rules' tag: another key removes them
    n=$((n + 1))
    compared "$f" || bad "P3 Windows: enablePeerTraffic applies $f per peer, kept on a same-key switch, and the switch decision does not compare it"
  done <<< "$peerfw"
  echo "P3 Windows: $n per-peer firewall fields, all compared"
fi

# ---- P2 ------------------------------------------------------------------------------------------------------
grep -qF 'const QStringList differ = avpn::interfaceSettingsThatDiffer(current, config);' <<< "$sw" \
  && grep -A3 -F 'if (!differ.isEmpty()) {' <<< "$sw" | grep -qF 'return false;' \
  || bad "P2: supportServerSwitching does not refuse an in-place switch when interface settings differ"
grep -qF '#include "serverswitchpolicy.h"' "$DAEMON" || bad "P2: daemon.cpp does not include serverswitchpolicy.h"

[ "$fail" = 0 ] && echo "check_daemon_server_switch_params: ok"
exit "$fail"
