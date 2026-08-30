#!/bin/bash
# Exercise the exact --up argv ABI through the real bundled OpenVPN binary.
# The null device avoids root/network mutations; the probe never touches DNS.
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 /absolute/path/to/bundled/openvpn" >&2
    exit 2
fi

OPENVPN="$1"
HERE="$(cd "$(dirname "$0")" && pwd -P)"
HARNESS="${TMPDIR:-/tmp}/tribe_openvpn_config_security_check"
case "$OPENVPN" in
    /*) ;;
    *) echo "OpenVPN path must be absolute" >&2; exit 2 ;;
esac
[ -x "$OPENVPN" ] || { echo "OpenVPN binary is not executable: $OPENVPN" >&2; exit 1; }

QT_ROOT="${QT_ROOT:-$HOME/Qt/6.11.1/macos}" \
    sh "$HERE/build_openvpn_config_security.sh"
[ -x "$HARNESS" ] || { echo "hook probe harness missing" >&2; exit 1; }

WORK="$(mktemp -d /private/tmp/tribe-openvpn-hook-smoke.XXXXXX)"
case "$WORK" in
    /private/tmp/tribe-openvpn-hook-smoke.*) ;;
    *) echo "unsafe smoke directory" >&2; exit 1 ;;
esac
cleanup() {
    /bin/rm -rf "$WORK"
}
trap cleanup EXIT HUP INT TERM

KEY="$WORK/static.key"
LOG="$WORK/openvpn.log"
"$OPENVPN" --genkey secret "$KEY"

# Static-key mode is used only for this local, loopback, null-device smoke. It
# reaches run_up_down without certificates, privileges, routes, or live traffic.
"$OPENVPN" \
    --allow-deprecated-insecure-static-crypto \
    --dev null \
    --script-security 2 \
    --up "$HARNESS --argv-probe" \
    --ping-exit 1 \
    --remote 127.0.0.1 9 \
    --proto udp \
    --secret "$KEY" \
    --cipher AES-256-CBC \
    --verb 3 >"$LOG" 2>&1

grep -F "OpenVPN real hook argv smoke passed" "$LOG" >/dev/null \
    || { sed -n '1,240p' "$LOG" >&2; exit 1; }
echo "Bundled OpenVPN hook argv smoke passed"
