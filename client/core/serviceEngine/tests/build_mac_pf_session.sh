#!/bin/bash
# AVPN (macOS pf state ownership, 2026-11-24): build + run mac_pf_session_check - the real KillSwitch
# (service/server/killswitch.cpp) and MacOSFirewall (client/platforms/macos/daemon/macosfirewall.cpp) against a
# model of the pf kernel state behind the firewall's command seam, with the real anchor files
# (deploy/data/macos/pf). Nothing is executed and pfctl is never run: the check fails on any command the model
# does not know. Qt only; the service's Logger, SecureQSettings and version.h are stubbed (tests/pf_stub).
# PF_CHECK_OUT=<dir> keeps the binary there (default: a temporary directory); PF_CHECK_ROOT=<tree> builds the
# sources of another checkout (with PF_CHECK_DEFINES, e.g. -DPF_CHECK_API_57F10A133) - the test is always this one.
set -eu
QT="${QT_ROOT:-$HOME/Qt/6.11.1/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="${PF_CHECK_ROOT:-$(cd "$HERE/../../../.." && pwd)}"
if [ -n "${PF_CHECK_OUT:-}" ]; then
  OUT="$PF_CHECK_OUT"
  mkdir -p "$OUT"
else
  OUT="$(mktemp -d "${TMPDIR:-/tmp}/tribe-mac-pf-session.XXXXXX")"
  trap 'rm -rf -- "${OUT:?}"' EXIT
fi
INC=(-I"$HERE/pf_stub" -I"$ROOT/service/server" -I"$ROOT/client" -I"$ROOT/client/platforms/macos/daemon")
QTI=(-F"$QT/lib" -I"$QT/include" -I"$QT/lib/QtCore.framework/Headers" -I"$QT/lib/QtGui.framework/Headers"
     -I"$QT/lib/QtWidgets.framework/Headers" -I"$QT/lib/QtNetwork.framework/Headers")
"$QT/libexec/moc" "${INC[@]}" "$ROOT/service/server/killswitch.h" -o "$OUT/moc_killswitch.cpp"
# shellcheck disable=SC2086
clang++ -std=c++17 -fPIC -Wall -Wextra -Wno-unused-parameter -Wno-unused-but-set-variable ${PF_CHECK_DEFINES:-} \
  "${INC[@]}" "${QTI[@]}" \
  "$HERE/mac_pf_session_check.cpp" "$ROOT/client/platforms/macos/daemon/macosfirewall.cpp" \
  "$ROOT/service/server/killswitch.cpp" "$OUT/moc_killswitch.cpp" \
  -framework QtCore -framework QtGui -framework QtWidgets -framework QtNetwork -Wl,-rpath,"$QT/lib" -o "$OUT/mac_pf_session_check"
"$OUT/mac_pf_session_check" "$ROOT/deploy/data/macos/pf"
