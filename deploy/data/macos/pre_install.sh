#!/bin/bash
# CPack productbuild preflight for install/upgrade. Stop only the Tribe GUI so
# productbuild can replace its bundle. The known-good daemon and application
# remain intact until the new package payload is ready. Service removal is a
# separate signed in-app action and is never a selectable package component.
set -euo pipefail
export PATH="/usr/sbin:/usr/bin:/sbin:/bin"
[ "${3:-}" = "/" ] || {
    echo "TribeVPN may only be upgraded on the boot/system volume" >&2
    exit 1
}

if ! pgrep -x "TribeVPN" >/dev/null 2>&1; then
    exit 0
fi

osascript -e 'tell application "TribeVPN" to quit' 2>/dev/null || true
for _ in 1 2 3 4 5 6 7 8 9 10; do
    pgrep -x "TribeVPN" >/dev/null 2>&1 || exit 0
    sleep 1
done

# A hung GUI cannot retain an installation transaction indefinitely. TERM is
# scoped to our branded process and never touches the privileged service.
pkill -TERM -x "TribeVPN" 2>/dev/null || true
for _ in 1 2 3 4 5; do
    pgrep -x "TribeVPN" >/dev/null 2>&1 || exit 0
    sleep 1
done

echo "TribeVPN GUI did not stop; refusing an unsafe in-place upgrade" >&2
exit 1
