#!/bin/bash
# AVPN (Scanner): build + run the checks of the desktop probe host (service/server/tribe_scan.{h,cpp},
# ipc/ipc_scan_interface.rep, the macOS pf exemption, client/core/serviceEngine/DaemonScanHost.cpp).
#   1. tribe_scan_check       - the host on stub bindings (fake_bindings/amnezia_xray.h): relay round trip,
#                               shared host vectors through the relay byte for byte, no-uplink refusal,
#                               stop-all ordering, exemption lifetime, size / rate / queue bounds, path
#                               generation, no tunnel API, no secret / host / interface name in the log.
#   2. tribe_scan_ipc_check   - a real QtRO round trip DaemonScanHost <-> TribeScanHost on a local socket,
#                               older service / no service / service gone.
#   3. pf_scan_exemption_check - the real pf anchors (deploy/data/macos/pf) read by a pf-subset evaluator:
#                               AWG kill switch drops the probes without the exemption, passes them with it,
#                               never a user application's packets; the Xray kill switch already passes them.
#   4. tribe_scan_engine_check - against the REAL bindings archive (also: the request vectors replayed through
#                               it without host options, and DaemonScanHost::compiledCaps() == its caps with
#                               the probe-capable amneziawg-go of the conan cache) (newest conan package with the
#                               tribe-scan exports, or TRIBE_SCAN_ENGINE_PKG=<package dir>; TRIBE_SCAN_ENGINE=0
#                               skips): loopback-only probes, the tunnel socket callback is never invoked,
#                               every reply decodes with ScanHostContract.h.
#   5. source gates           - tribe_scan.cpp never calls the tunnel's bindings API and never streams a
#                               message, a reply or an interface name into a log line.
# Nothing is installed, no service is started, pfctl is never run; probes of (4) stay on lo0.
set -euo pipefail
QT="${QT_ROOT:-$HOME/Qt/6.11.1/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
VECTORS="$ROOT/client/core/serviceEngine/tests/vectors/scan_host_vectors.json"
GEN="$(mktemp -d /tmp/avpn_tribe_scan.XXXXXX)"
trap 'rm -rf "${GEN:?}"' EXIT
# Any failing step ends the script with its status (set -e); say so in the log as well, so a failed run is
# never read as a pass from its last lines. Read the exit status of this script itself, never through a pipe.
trap 'rc=$?; echo ">>> build_tribe_scan.sh: FAILED (exit $rc at line $LINENO)" >&2' ERR
# Every check binary runs as a stage with its status recorded here; the script's own status is the
# count of failed stages (not only set -e), and a stage that cannot run is a failure unless skipped on
# purpose (TRIBE_SCAN_ENGINE=0).
FAILED=()
stage() {
  local name="$1"; shift
  if "$@"; then
    echo ">>> stage $name: ok"
  else
    local rc=$?
    echo ">>> stage $name: FAILED (exit $rc)" >&2
    FAILED+=("$name")
  fi
}

MOCI=(-F"$QT/lib" -I"$QT/lib/QtCore.framework/Headers" -I"$QT/lib/QtRemoteObjects.framework/Headers" -I"$QT/include"
      -I"$ROOT/ipc" -I"$ROOT/client/mozilla/shared")
"$QT/libexec/repc" -o source "$ROOT/ipc/ipc_scan_interface.rep" "$GEN/rep_ipc_scan_interface_source.h"
"$QT/libexec/repc" -o replica "$ROOT/ipc/ipc_scan_interface.rep" "$GEN/rep_ipc_scan_interface_replica.h"
"$QT/libexec/repc" -o source "$ROOT/ipc/ipc_interface.rep" "$GEN/rep_ipc_interface_source.h"
"$QT/libexec/repc" -o replica "$ROOT/ipc/ipc_interface.rep" "$GEN/rep_ipc_interface_replica.h"
for h in rep_ipc_scan_interface_source rep_ipc_scan_interface_replica rep_ipc_interface_source rep_ipc_interface_replica; do
  "$QT/libexec/moc" "${MOCI[@]}" "$GEN/$h.h" -o "$GEN/moc_$h.cpp"
done

# The awg-go packages in the conan cache: the probe-capable amneziawg-go (tribe_probe=True answers
# `probe --abi` with tribe-awg-probe-v1) and a plain one (prints its usage), for the binary check and the
# compiledCaps comparison. Running them only prints a line; nothing is installed.
TRIBE_AWG_PROBE_BIN="${TRIBE_AWG_PROBE_BIN:-}"
TRIBE_AWG_PLAIN_BIN="${TRIBE_AWG_PLAIN_BIN:-}"
for b in "$HOME"/.conan2/p/b/awg-g*/p/amneziawg-go; do
  [ -x "$b" ] || continue
  if [ "$("$b" probe --abi 2>/dev/null | head -1)" = "tribe-awg-probe-v1" ]; then
    [ -n "$TRIBE_AWG_PROBE_BIN" ] || TRIBE_AWG_PROBE_BIN="$b"
  else
    [ -n "$TRIBE_AWG_PLAIN_BIN" ] || TRIBE_AWG_PLAIN_BIN="$b"
  fi
done
export TRIBE_AWG_PROBE_BIN TRIBE_AWG_PLAIN_BIN
export TRIBE_SCAN_VECTORS="$VECTORS"

QTI=(-F"$QT/lib" -I"$QT/lib/QtCore.framework/Headers" -I"$QT/lib/QtNetwork.framework/Headers"
     -I"$QT/lib/QtRemoteObjects.framework/Headers" -I"$QT/lib/QtCore5Compat.framework/Headers" -I"$QT/include")
QTL=(-framework QtCore -framework QtNetwork -framework QtRemoteObjects -Wl,-rpath,"$QT/lib")
INC=(-I"$HERE" -I"$ROOT/service/server" -I"$ROOT/client" -I"$ROOT/ipc" -I"$ROOT/client/mozilla/shared" -I"$GEN")
CXX=(clang++ -std=c++17 -fPIC -Wall -Wno-deprecated-declarations)

# The test stand-in (scan_helper.c): a sleeper, a hung `amneziawg-go probe`, a TCP holder.
cc -o "$GEN/scan_helper" "$HERE/scan_helper.c"
export TRIBE_SCAN_SLEEPER="$GEN/scan_helper"

# 1
"${CXX[@]}" -I"$HERE/fake_bindings" "${INC[@]}" "${QTI[@]}" \
  "$ROOT/service/server/tribe_scan.cpp" "$HERE/tribe_scan_fakes.cpp" "$HERE/tribe_scan_platform_stubs.cpp" \
  "$HERE/tribe_scan_check.cpp" "$GEN/moc_rep_ipc_scan_interface_source.cpp" "${QTL[@]}" -o "$GEN/tribe_scan_check"
echo ">>> build ok: tribe_scan_check"
stage tribe_scan_check "$GEN/tribe_scan_check" "$VECTORS"

# 2
"${CXX[@]}" -I"$HERE/fake_bindings" "${INC[@]}" "${QTI[@]}" \
  "$ROOT/service/server/tribe_scan.cpp" "$HERE/tribe_scan_fakes.cpp" "$HERE/tribe_scan_platform_stubs.cpp" \
  "$ROOT/client/core/serviceEngine/DaemonScanHost.cpp" "$HERE/tribe_scan_ipc_check.cpp" \
  "$GEN/moc_rep_ipc_scan_interface_source.cpp" "$GEN/moc_rep_ipc_scan_interface_replica.cpp" \
  "$GEN/moc_rep_ipc_interface_source.cpp" "$GEN/moc_rep_ipc_interface_replica.cpp" "${QTL[@]}" -o "$GEN/tribe_scan_ipc_check"
echo ">>> build ok: tribe_scan_ipc_check"
stage tribe_scan_ipc_check "$GEN/tribe_scan_ipc_check"

# 3 (macOS pf)
if [ "$(uname -s)" = "Darwin" ]; then
  "${CXX[@]}" -I"$ROOT/client" "${QTI[@]}" "$HERE/pf_scan_exemption_check.cpp" "${QTL[@]}" -o "$GEN/pf_scan_exemption_check"
  echo ">>> build ok: pf_scan_exemption_check"
  stage pf_scan_exemption_check "$GEN/pf_scan_exemption_check" "$ROOT/deploy/data/macos/pf" "$ROOT/deploy/tribe/tribe-svc-install.sh"
fi

# 4 (the real engine)
if [ "${TRIBE_SCAN_ENGINE:-1}" != "0" ]; then
  PKG="${TRIBE_SCAN_ENGINE_PKG:-}"
  if [ -z "$PKG" ]; then
    # shellcheck disable=SC2012
    for h in $(ls -t "$HOME"/.conan2/p/b/amnez*/p/include/amnezia_xray.h 2>/dev/null); do
      if grep -q amnezia_xray_scan_message "$h"; then PKG="$(cd "$(dirname "$h")/.." && pwd)"; break; fi
    done
  fi
  if [ -n "$PKG" ] && [ -f "$PKG/lib/libamnezia_xray.a" ]; then
    "${CXX[@]}" -I"$PKG/include" "${INC[@]}" "${QTI[@]}" \
      "$ROOT/service/server/tribe_scan.cpp" "$HERE/tribe_scan_platform_stubs.cpp" "$HERE/tribe_scan_engine_check.cpp" \
      "$ROOT/client/core/serviceEngine/DaemonScanHost.cpp" "$GEN/moc_rep_ipc_scan_interface_replica.cpp" \
      "$GEN/moc_rep_ipc_interface_replica.cpp" \
      "$GEN/moc_rep_ipc_scan_interface_source.cpp" "$PKG/lib/libamnezia_xray.a" \
      -framework CoreFoundation -framework Security -lresolv "${QTL[@]}" -o "$GEN/tribe_scan_engine_check"
    echo ">>> build ok: tribe_scan_engine_check (engine $(basename "$(dirname "$PKG")"))"
    stage tribe_scan_engine_check "$GEN/tribe_scan_engine_check"
  else
    echo ">>> stage tribe_scan_engine_check: FAILED - no bindings package with amnezia_xray_scan_message at '${PKG:-<none>}' (TRIBE_SCAN_ENGINE=0 skips it on purpose)" >&2
    FAILED+=("tribe_scan_engine_check")
  fi
else
  echo ">>> stage tribe_scan_engine_check: skipped on purpose (TRIBE_SCAN_ENGINE=0)"
fi

# 5
SRC="$ROOT/service/server/tribe_scan.cpp"
if grep -nE 'amnezia_xray_(setsockcallback|configure|start|stop|setloghandler)\b|Xray::' "$SRC"; then
  echo "FAIL: tribe_scan.cpp reaches the tunnel's bindings API"; exit 1
fi
if perl -ne 'print "$.: $_" if /q(Info|Warning|Debug|Critical)\(/ && /<<\s*(message|reply|bytes|opts|options|ifname|name|gateway|addresses|uplink|up|json)(\.(name|gateway|addresses|constData\(\)))?\s*(<<|;|\))/' "$SRC" | grep .; then
  echo "FAIL: a log line streams a message, a reply or a path fact"; exit 1
fi
echo ">>> source gates ok"
if [ "${#FAILED[@]}" -ne 0 ]; then
  echo ">>> build_tribe_scan.sh: FAILED stages: ${FAILED[*]}" >&2
  exit 1
fi
echo ">>> build_tribe_scan.sh: all checks passed"
