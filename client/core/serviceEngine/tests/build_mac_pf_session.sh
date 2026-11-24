#!/bin/bash
# AVPN (macOS pf state ownership, 2026-11-24): build + run mac_pf_session_check - the real MacOSFirewall
# (client/platforms/macos/daemon/macosfirewall.cpp) against a model of the pf kernel state behind its command
# seam, with the real anchor files (deploy/data/macos/pf). Nothing is executed and pfctl is never run: the
# check fails on any command the model does not know. QtCore only; the service's Logger is stubbed
# (tests/pf_stub/logger.h). PF_CHECK_OUT=<dir> keeps the binary there (default: a temporary directory).
set -eu
QT="${QT_ROOT:-$HOME/Qt/6.11.1/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../../.." && pwd)"
if [ -n "${PF_CHECK_OUT:-}" ]; then
  OUT="$PF_CHECK_OUT"
  mkdir -p "$OUT"
else
  OUT="$(mktemp -d "${TMPDIR:-/tmp}/tribe-mac-pf-session.XXXXXX")"
  trap 'rm -rf -- "${OUT:?}"' EXIT
fi
clang++ -std=c++17 -fPIC -Wall -Wextra -Wno-unused-parameter \
  -I"$HERE/pf_stub" -I"$ROOT/client" -I"$ROOT/client/platforms/macos/daemon" \
  -I"$QT/include" -I"$QT/include/QtCore" -I"$QT/lib/QtCore.framework/Headers" -F"$QT/lib" \
  "$HERE/mac_pf_session_check.cpp" "$ROOT/client/platforms/macos/daemon/macosfirewall.cpp" \
  -framework QtCore -Wl,-rpath,"$QT/lib" -o "$OUT/mac_pf_session_check"
"$OUT/mac_pf_session_check" "$ROOT/deploy/data/macos/pf"
