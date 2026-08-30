#!/bin/bash
# Migrate only the old spaced Tribe bundle after the new signed app and its
# daemon are known-good.  Refusals are non-destructive: a foreign/symlinked or
# raced legacy path is left in place (or restored from quarantine).
set -euo pipefail
export PATH="/usr/sbin:/usr/bin:/sbin:/bin"
umask 077

NEW_APP="${1:?usage: $0 NEW_APP LEGACY_APP LOG EXPECTED_VERSION [migrate|preflight] [TEST_CODESIGN]}"
LEGACY_APP="${2:?missing legacy app path}"
LOG="${3:?missing migration log path}"
EXPECTED_VERSION="${4:?missing expected app version}"
MODE="${5:-migrate}"
TEST_CODESIGN="${6:-}"
case "$MODE" in migrate|preflight) ;; *) echo "invalid migration mode" >&2; exit 1 ;; esac
REQUIREMENT='identifier "hk.wellwon.vpn" and anchor apple generic and certificate leaf[subject.OU] = "Q7DVH5MCWF" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists'
[[ "$EXPECTED_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] \
    || { echo "invalid expected app version" >&2; exit 1; }

version_is_newer() {
    local left="$1" right="$2" index
    local left_parts right_parts
    IFS=. read -r -a left_parts <<< "$left"
    IFS=. read -r -a right_parts <<< "$right"
    [ "${#left_parts[@]}" -eq 4 ] && [ "${#right_parts[@]}" -eq 4 ] \
        || return 2
    for index in 0 1 2 3; do
        if (( 10#${left_parts[$index]} > 10#${right_parts[$index]} )); then
            return 0
        fi
        if (( 10#${left_parts[$index]} < 10#${right_parts[$index]} )); then
            return 1
        fi
    done
    return 1
}

if [ -n "$TEST_CODESIGN" ]; then
    # An injectable verifier exists solely for the unprivileged regression
    # fixture.  A root invocation can only use Apple's fixed codesign binary.
    [ "$(id -u)" -ne 0 ] \
        || { echo "test codesign override is forbidden for root" >&2; exit 1; }
    [ -x "$TEST_CODESIGN" ] \
        || { echo "test codesign override is not executable" >&2; exit 1; }
    CODESIGN="$TEST_CODESIGN"
else
    [ "$(id -u)" -eq 0 ] \
        || { echo "legacy migration must run as root" >&2; exit 1; }
    [ "$NEW_APP" = "/Applications/TribeVPN.app" ] \
        && [ "$LEGACY_APP" = "/Applications/Tribe VPN.app" ] \
        || { echo "legacy migration paths are not canonical" >&2; exit 1; }
    CODESIGN=/usr/bin/codesign
fi

[ ! -L "$LOG" ] || { echo "unsafe migration log" >&2; exit 1; }
log() { printf '%s %s\n' "$(date)" "$*" >> "$LOG"; }
verify_app() {
    "$CODESIGN" --verify --deep --strict --all-architectures \
        -R="$REQUIREMENT" "$1"
}

# Re-authenticate the canonical app at the moment migration begins.  The
# postflight daemon transaction has already succeeded before this helper is
# called, but a substituted canonical bundle must still block legacy deletion.
if [ ! -d "$NEW_APP" ] || [ -L "$NEW_APP" ]; then
    log "legacy migration refused: canonical TribeVPN.app is not a real directory"
    exit 1
fi
new_short="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' \
    "$NEW_APP/Contents/Info.plist" 2>/dev/null || true)"
new_build="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' \
    "$NEW_APP/Contents/Info.plist" 2>/dev/null || true)"
if [ "$new_short.$new_build" != "$EXPECTED_VERSION" ] || ! verify_app "$NEW_APP"; then
    log "legacy migration refused: canonical TribeVPN.app is not exact signed code"
    exit 1
fi

if [ ! -e "$LEGACY_APP" ] && [ ! -L "$LEGACY_APP" ]; then
    log "legacy migration: no spaced Tribe app is present"
    exit 0
fi
if [ ! -d "$LEGACY_APP" ] || [ -L "$LEGACY_APP" ]; then
    log "legacy migration refused: legacy path is not a real application directory"
    exit 0
fi
legacy_identity="$(stat -f '%d:%i' "$LEGACY_APP")"
if ! verify_app "$LEGACY_APP"; then
    log "legacy migration refused: legacy app has a foreign signature"
    exit 0
fi
legacy_short="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' \
    "$LEGACY_APP/Contents/Info.plist" 2>/dev/null || true)"
legacy_build="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' \
    "$LEGACY_APP/Contents/Info.plist" 2>/dev/null || true)"
legacy_version="$legacy_short.$legacy_build"
if [[ ! "$legacy_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    log "legacy migration unresolved: exact signed legacy version is invalid"
    exit 1
fi
if version_is_newer "$legacy_version" "$EXPECTED_VERSION"; then
    log "legacy migration unresolved: refusing to remove newer signed legacy $legacy_version"
    exit 1
fi

if [ "$MODE" = preflight ]; then
    log "legacy migration preflight passed for $legacy_version"
    exit 0
fi

# Deletion must not encounter immutable flags or ACL policy halfway through an
# app tree.  Refuse before the atomic move while the known-good legacy path is
# still intact.  Quarantine metadata/xattrs are not ACLs and remain harmless.
while IFS= read -r -d '' node; do
    flags="$(stat -f '%Sf' "$node")"
    case "$flags" in
        *uchg*|*schg*)
            log "legacy migration unresolved: immutable filesystem flags are present"
            exit 1
            ;;
    esac
    # macOS exposes extended ACL entries through ls -le; find has no equivalent.
    # shellcheck disable=SC2012
    if ls -lde "$node" | awk 'NR > 1 && /^[[:space:]]*[0-9]+:/ { found=1 } END { exit !found }'; then
        log "legacy migration unresolved: ACL-bearing legacy node is present"
        exit 1
    fi
done < <(find "$LEGACY_APP" -print0)

legacy_parent="$(dirname "$LEGACY_APP")"
quarantine="$(mktemp -d "$legacy_parent/.tribe-legacy-quarantine.XXXXXX")"
quarantined_app="$quarantine/Tribe VPN.app"
QUARANTINED=0
MIGRATION_COMMITTED=0
chmod 700 "$quarantine"
if [ -z "$TEST_CODESIGN" ]; then
    chown root:wheel "$quarantine"
fi

restore_quarantine() {
    if [ -e "$quarantined_app" ] || [ -L "$quarantined_app" ]; then
        if [ ! -e "$LEGACY_APP" ] && [ ! -L "$LEGACY_APP" ]; then
            mv "$quarantined_app" "$LEGACY_APP"
            QUARANTINED=0
        else
            log "legacy migration race: quarantine retained at $quarantined_app"
            return
        fi
    fi
    rmdir "$quarantine" 2>/dev/null || true
}

migration_cleanup() {
    rc=$?
    trap - EXIT
    if [ "$QUARANTINED" -eq 1 ] && [ "$MIGRATION_COMMITTED" -ne 1 ]; then
        restore_quarantine
    fi
    exit "$rc"
}
trap migration_cleanup EXIT
trap 'exit 1' HUP INT TERM

# This same-volume rename(2) within /Applications is atomic. Prove that the exact inode checked
# above is what moved, then verify the signature a second time while isolated
# beneath a root-owned 0700 directory.  Any race restores instead of deleting.
if ! mv "$LEGACY_APP" "$quarantined_app"; then
    rmdir "$quarantine" 2>/dev/null || true
    log "legacy migration refused: atomic quarantine move failed"
    exit 1
fi
QUARANTINED=1
quarantined_identity="$(stat -f '%d:%i' "$quarantined_app" 2>/dev/null || true)"
if [ "$quarantined_identity" != "$legacy_identity" ] \
        || [ -L "$quarantined_app" ] \
        || ! verify_app "$quarantined_app"; then
    log "legacy migration refused: identity/signature changed during quarantine"
    exit 1
fi

if [ -z "$TEST_CODESIGN" ]; then
    chown -R -P root:wheel "$quarantined_app"
fi
# After the same-volume move, inode check, second signature verification and
# root-only quarantine are complete, the visible migration is committed.  From
# here deletion is garbage collection: a partial failure must never restore a
# partially deleted application into /Applications.
if [ -n "$TEST_CODESIGN" ] && [ "${TRIBE_TEST_DELETE_FAIL:-0}" = 1 ]; then
    log "legacy migration fixture: injected pre-delete failure"
    exit 1
fi
MIGRATION_COMMITTED=1
if [ -n "$TEST_CODESIGN" ] && [ "${TRIBE_TEST_PARTIAL_DELETE_FAIL:-0}" = 1 ]; then
    first_file="$(find "$quarantined_app" -type f -print -quit)"
    [ -z "$first_file" ] || rm -f "$first_file"
    log "legacy migration fixture: injected partial quarantine deletion failure"
    exit 1
fi
if ! find "$quarantined_app" -depth -delete; then
    log "legacy migration warning: root-only quarantine cleanup is incomplete"
    exit 1
fi
QUARANTINED=0
rmdir "$quarantine" \
    || { log "legacy migration warning: empty quarantine cleanup is incomplete"; exit 1; }
trap - EXIT HUP INT TERM
log "legacy migration complete: removed exact signed /Applications/Tribe VPN.app"
