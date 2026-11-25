#!/bin/bash
# AVPN (awg audit 25.11.2026, round mac-D): build + run daemon_server_switch_check - the real shared desktop daemon
# (client/daemon/daemon.cpp + interfaceconfig.cpp + mozilla ipaddress.cpp) against a fake WireguardUtils: a switch of a
# live tunnel to another server is in place only when the interface keeps nothing of the old server
# (client/daemon/serverswitchpolicy.h); otherwise deactivate + activate. Qt only; the logger is stubbed
# (tests/daemon_stub), the Scanner hook and the macOS split-DNS files are stubbed in the check. Nothing is executed.
# DAEMON_CHECK_ROOT=<tree> builds the daemon sources of another checkout (the test is always this one).
set -eu
QT="${QT_ROOT:-$HOME/Qt/6.11.1/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="${DAEMON_CHECK_ROOT:-$(cd "$HERE/../../../.." && pwd)}"
OUT="$(mktemp -d "${TMPDIR:-/tmp}/tribe-daemon-server-switch.XXXXXX")"
trap 'rm -rf -- "${OUT:?}"' EXIT
INC=(-I"$HERE/daemon_stub" -I"$ROOT/client/daemon" -I"$ROOT/client" -I"$ROOT/client/mozilla/shared")
QTI=(-F"$QT/lib" -I"$QT/include" -I"$QT/lib/QtCore.framework/Headers" -I"$QT/lib/QtNetwork.framework/Headers")
for h in daemon wireguardutils dnsutils iputils interfaceconfig; do
  "$QT/libexec/moc" "${INC[@]}" "$ROOT/client/daemon/$h.h" -o "$OUT/moc_$h.cpp"
done
clang++ -std=c++17 -fPIC -Wall -Wno-unused-parameter -Wno-deprecated-declarations \
  "${INC[@]}" "${QTI[@]}" \
  "$HERE/daemon_server_switch_check.cpp" "$ROOT/client/daemon/daemon.cpp" "$ROOT/client/daemon/interfaceconfig.cpp" \
  "$ROOT/client/mozilla/shared/ipaddress.cpp" \
  "$OUT/moc_daemon.cpp" "$OUT/moc_wireguardutils.cpp" "$OUT/moc_dnsutils.cpp" "$OUT/moc_iputils.cpp" \
  "$OUT/moc_interfaceconfig.cpp" \
  -framework QtCore -framework QtNetwork -Wl,-rpath,"$QT/lib" -o "$OUT/daemon_server_switch_check"
echo ">>> build ok: daemon_server_switch_check"
"$OUT/daemon_server_switch_check"
