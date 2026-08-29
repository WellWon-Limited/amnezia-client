#!/bin/bash
# CPack productbuild POSTFLIGHT.  This script is trusted package code; it never
# executes a resource through mutable /Applications.  It takes a private
# root-owned snapshot, verifies the exact Tribe Developer ID, installs and
# health-checks that snapshot's daemon, and only then migrates the legacy app.
set -euo pipefail
export PATH="/usr/sbin:/usr/bin:/sbin:/bin"
umask 027
[ "${3:-}" = "/" ] || {
    echo "TribeVPN may only be installed on the boot/system volume" >&2
    exit 1
}

APP="/Applications/TribeVPN.app"
LEGACY_APP="/Applications/Tribe VPN.app"
DEST="/Library/PrivilegedHelperTools/TribeVPN"
LABEL="Tribe-service"
LOG_DIR="/var/log/TribeVPN"
LOG="$LOG_DIR/post-install.log"
REQUIREMENT='identifier "hk.wellwon.vpn" and anchor apple generic and certificate leaf[subject.OU] = "Q7DVH5MCWF" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists'
EXPECTED_APP_VERSION="@AMNEZIAVPN_VERSION@"

[ ! -L "$LOG_DIR" ] || { echo "unsafe Tribe postflight log directory" >&2; exit 1; }
mkdir -p "$LOG_DIR"
chown root:wheel "$LOG_DIR"
chmod 750 "$LOG_DIR"
[ ! -L "$LOG" ] || { echo "unsafe Tribe postflight log" >&2; exit 1; }
touch "$LOG"
chown root:wheel "$LOG"
chmod 640 "$LOG"
echo "$(date) postflight start" >> "$LOG"

SNAPSHOT="$(mktemp -d /private/var/tmp/tribevpn-pkg-bootstrap.XXXXXX)"
# shellcheck disable=SC2329  # invoked by the EXIT/signal trap below
cleanup() { /bin/rm -rf "$SNAPSHOT"; }
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
chmod 700 "$SNAPSHOT"
/usr/bin/ditto --norsrc --noqtn "$APP" "$SNAPSHOT/TribeVPN.app"
TRUSTED_APP="$SNAPSHOT/TribeVPN.app"
[ -d "$TRUSTED_APP" ] && [ ! -L "$TRUSTED_APP" ] \
    || { echo "$(date) ERROR: app snapshot is not a real directory" >> "$LOG"; exit 1; }
/usr/bin/codesign --verify --deep --strict --all-architectures \
    -R="$REQUIREMENT" "$TRUSTED_APP" >> "$LOG" 2>&1 \
    || { echo "$(date) ERROR: exact app signature check failed" >> "$LOG"; exit 1; }
SNAPSHOT_APP_SHORT="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' \
    "$TRUSTED_APP/Contents/Info.plist")"
SNAPSHOT_APP_BUILD="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' \
    "$TRUSTED_APP/Contents/Info.plist")"
[ "$SNAPSHOT_APP_SHORT.$SNAPSHOT_APP_BUILD" = "$EXPECTED_APP_VERSION" ] \
    || { echo "$(date) ERROR: app snapshot version does not match this package" >> "$LOG"; exit 1; }
[ -z "$(find "$TRUSTED_APP" ! -type d ! -type f ! -type l -print -quit)" ] \
    || { echo "$(date) ERROR: app snapshot contains a special node" >> "$LOG"; exit 1; }
[ -z "$(find "$TRUSTED_APP" -type f -links +1 -print -quit)" ] \
    || { echo "$(date) ERROR: app snapshot contains a hard-linked file" >> "$LOG"; exit 1; }
while IFS= read -r -d '' node; do
    mode="$(stat -f '%Lp' "$node")"
    if (( (8#$mode & 06022) != 0 )); then
        echo "$(date) ERROR: unsafe app snapshot mode $mode: $node" >> "$LOG"
        exit 1
    fi
done < <(find "$TRUSTED_APP" ! -type l -print0)
chown -R -P root:wheel "$TRUSTED_APP"

RESOURCES="$TRUSTED_APP/Contents/Resources"
INSTALLER="$RESOURCES/tribe-svc-install.sh"
TARBALL="$RESOURCES/tribe-svc.tar.gz"
VERSION="$RESOURCES/tribe-svc.version"
MIGRATOR="$RESOURCES/migrate-macos-legacy-app.sh"
LAUNCHCTL_PARSER="$RESOURCES/launchctl-job-field.sh"
VER="$(/usr/bin/defaults read "$TRUSTED_APP/Contents/Info" CFBundleShortVersionString 2>/dev/null || echo unknown)"

for critical in "$INSTALLER" "$TARBALL" "$VERSION" \
                "$RESOURCES/tribe-svc.tar.sha256" \
                "$RESOURCES/tribe-svc.epoch" \
                "$RESOURCES/macos-service-payload.sh" "$MIGRATOR" \
                "$LAUNCHCTL_PARSER"; do
    if [ ! -f "$critical" ] || [ -L "$critical" ] \
            || [ "$(stat -f '%l' "$critical")" -ne 1 ]; then
        echo "$(date) ERROR: unsafe/missing signed resource $critical" >> "$LOG"
        exit 1
    fi
done
if [ ! -x "$INSTALLER" ] || [ ! -x "$MIGRATOR" ] \
        || [ ! -x "$LAUNCHCTL_PARSER" ]; then
    echo "$(date) ERROR: signed daemon payload resources are missing" >> "$LOG"
    exit 1
fi
EXPECTED_BUILD="${EXPECTED_APP_VERSION##*.}"
SIGNED_INSTALL_EPOCH="$(tr -d '\r\n' < "$RESOURCES/tribe-svc.epoch")"
[ "$SIGNED_INSTALL_EPOCH" = "$EXPECTED_BUILD" ] \
    || { echo "$(date) ERROR: CFBundleVersion/install epoch mismatch" >> "$LOG"; exit 1; }

SERVICE_PENDING=0
SERVICE_COMMITTED=0
# shellcheck disable=SC2329  # installed as the signal trap below
handle_service_transaction_signal() {
    trap - HUP INT TERM
    set +e
    if [ "$SERVICE_PENDING" -eq 1 ] && [ "$SERVICE_COMMITTED" -ne 1 ]; then
        if bash "$INSTALLER" --is-committed >> "$LOG" 2>&1; then
            # The fixed journal phase is the crash-safe authority if a signal
            # lands immediately after finalize's durable phase rename.
            SERVICE_COMMITTED=1
        else
            bash "$INSTALLER" --rollback-pending >> "$LOG" 2>&1 \
                || echo "$(date) CRITICAL: pending daemon rollback failed" >> "$LOG"
        fi
    fi
    if [ "$SERVICE_COMMITTED" -eq 1 ]; then exit 0; fi
    exit 1
}
trap handle_service_transaction_signal HUP INT TERM

# Decide every fallible legacy-version policy before the service transaction.
# This prevents an older package from committing its daemon and only then
# discovering a newer exact-signed spaced app that must not be removed.
if ! bash "$MIGRATOR" "$APP" "$LEGACY_APP" "$LOG" \
        "$EXPECTED_APP_VERSION" preflight; then
    echo "$(date) ERROR: legacy migration preflight is unresolved" >> "$LOG"
    exit 1
fi

SERVICE_PENDING=1
if ! bash "$INSTALLER" "$TARBALL" --defer-finalize >> "$LOG" 2>&1; then
    bash "$INSTALLER" --rollback-pending >> "$LOG" 2>&1 || true
    echo "$(date) ERROR: sealed daemon payload installation failed" >> "$LOG"
    exit 1
fi
# The inner installer has proven the new service but deliberately retains the
# old runtime and journal. All fallible outer checks remain package-fatal and
# reversible until the explicit finalize call below.
PRECOMMIT_HEALTHY=1
if [ ! -f "$DEST/VERSION" ] || ! cmp -s "$VERSION" "$DEST/VERSION"; then
    echo "$(date) ERROR: installed daemon VERSION mismatch before commit" >> "$LOG"
    PRECOMMIT_HEALTHY=0
fi

# Independently prove launchd identity and one stable exact-path process after
# the transactional installer has committed.  Legacy app removal is below this
# gate, so any earlier failure preserves the old app and old service rollback.
stable_pid=""
for _ in 1 2 3 4 5; do
    launch_state="$(launchctl print "system/$LABEL" 2>/dev/null || true)"
    launch_program="$(printf '%s\n' "$launch_state" | "$LAUNCHCTL_PARSER" program)"
    launch_job_state="$(printf '%s\n' "$launch_state" | "$LAUNCHCTL_PARSER" state)"
    launch_pid="$(printf '%s\n' "$launch_state" | "$LAUNCHCTL_PARSER" pid)"
    if [ "$launch_program" != "$DEST/$LABEL" ] \
            || [ "$launch_job_state" != running ]; then
        echo "$(date) ERROR: launchd job identity/state drifted after commit" >> "$LOG"
        PRECOMMIT_HEALTHY=0
        break
    fi
    case "$launch_pid" in
        ''|*[!0-9]*) echo "$(date) ERROR: launchd returned invalid daemon PID" >> "$LOG"; PRECOMMIT_HEALTHY=0; break ;;
    esac
    image_matches="$(/usr/sbin/lsof -a -p "$launch_pid" -d txt -Fn 2>/dev/null \
        | awk -v expected="n$DEST/$LABEL" '$0 == expected { n++ } END { print n + 0 }')"
    [ "$image_matches" = 1 ] \
        || { echo "$(date) ERROR: launchd PID text vnode mismatch" >> "$LOG"; PRECOMMIT_HEALTHY=0; break; }
    if [ -z "$stable_pid" ]; then
        stable_pid="$launch_pid"
    elif [ "$stable_pid" != "$launch_pid" ]; then
        echo "$(date) ERROR: daemon restarted after commit" >> "$LOG"
        PRECOMMIT_HEALTHY=0
        break
    fi
    sleep 1
done
if [ "$PRECOMMIT_HEALTHY" -ne 1 ]; then
    bash "$INSTALLER" --rollback-pending >> "$LOG" 2>&1 \
        || echo "$(date) CRITICAL: verified daemon rollback failed" >> "$LOG"
    echo "$(date) ERROR: daemon health proof failed before commit (app v$VER)" >> "$LOG"
    exit 1
fi
echo "$(date) complete daemon payload is healthy before commit (app v$VER)" >> "$LOG"

if ! bash "$INSTALLER" "$TARBALL" --finalize-pending >> "$LOG" 2>&1; then
    bash "$INSTALLER" --rollback-pending >> "$LOG" 2>&1 || true
    echo "$(date) ERROR: daemon transaction finalize failed" >> "$LOG"
    exit 1
fi
SERVICE_COMMITTED=1
# The committed journal and retained OLD runtime are intentionally left in
# place until a later matching/newer signed app proves productbuild can no
# longer roll this app back. From this point every operation is warning-only.
set +e
trap cleanup EXIT
trap 'exit 0' HUP INT TERM

# Optional compatibility migration runs last.  It re-verifies both the current
# canonical app and the old spaced bundle, quarantines by same-volume rename,
# verifies again, and never deletes a foreign/raced path.
if ! bash "$MIGRATOR" "$APP" "$LEGACY_APP" "$LOG" \
        "$EXPECTED_APP_VERSION" migrate; then
    # Never make productbuild roll back the app after the external daemon
    # transaction has committed. The proven legacy app remains untouched;
    # a later higher-version package can retry migration.
    echo "$(date) WARNING: legacy app migration unresolved after daemon commit" >> "$LOG"
fi
# Never launch a GUI from productbuild's root context. The user (or MDM) can
# start the signed app in the correct login session after installation.
echo "$(date) postflight done" >> "$LOG"
exit 0
