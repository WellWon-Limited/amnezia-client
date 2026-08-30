#!/bin/bash
# Materialize the complete signed daemon runtime as sealed app resources.
# Call only after every nested Mach-O in the staged app has been signed and
# before signing the containing .app bundle.
set -euo pipefail

APP="${1:?usage: $0 STAGED_APP_BUNDLE CODESIGN_IDENTITY CODESIGN_KEYCHAIN INSTALL_EPOCH}"
CODESIGN_IDENTITY="${2:?missing Developer ID Application identity}"
CODESIGN_KEYCHAIN="${3:?missing explicit release signing keychain}"
INSTALL_EPOCH="${4:?missing monotonic install epoch}"
case "$INSTALL_EPOCH" in
    ''|*[!0-9]*) echo "invalid monotonic install epoch" >&2; exit 1 ;;
esac
[ "$INSTALL_EPOCH" -gt 0 ] \
    || { echo "install epoch must be positive" >&2; exit 1; }
[ -f "$CODESIGN_KEYCHAIN" ] \
    || { echo "release signing keychain does not exist: $CODESIGN_KEYCHAIN" >&2; exit 1; }
[ -d "$APP/Contents/MacOS" ] && [ -d "$APP/Contents/Frameworks" ] \
    || { echo "invalid staged macOS app: $APP" >&2; exit 1; }
APP="$(cd "$APP" && pwd -P)"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
MACOS="$APP/Contents/MacOS"
RESOURCES="$APP/Contents/Resources"
RUNTIME_FILES=(Tribe-service amneziawg-go openvpn tun2socks \
               geoip.dat geosite.dat)

for runtime_file in "${RUNTIME_FILES[@]}"; do
    [ -f "$MACOS/$runtime_file" ] \
        || { echo "staged app lacks daemon runtime file: $runtime_file" >&2; exit 1; }
done
[ -d "$MACOS/pf" ] || { echo "staged app lacks build-owned PF rules" >&2; exit 1; }

# Re-check the final app after the service install rules have run. This catches
# dependencies that the earlier client-only macdeployqt pass could not see.
"$SCRIPT_DIR/sanitize-macos-app.sh" "$APP"

STAGING="$(mktemp -d "${TMPDIR:-/tmp}/tribe-service-payload.XXXXXX")"
TARBALL_TMP="$(mktemp "${TMPDIR:-/tmp}/tribe-service-payload.XXXXXX.tar.gz")"
cleanup() {
    rm -rf "$STAGING"
    rm -f "$TARBALL_TMP"
}
trap cleanup EXIT

for runtime_file in "${RUNTIME_FILES[@]}"; do
    cp -p "$MACOS/$runtime_file" "$STAGING/$runtime_file"
done
cp -aR "$MACOS/pf" "$STAGING/pf"
printf '%s\n' "$INSTALL_EPOCH" > "$STAGING/INSTALL-EPOCH"

# App-contained service binaries use @executable_path/../Frameworks. Relocate
# copies to the privileged layout and rewrite all four independent roots to
# @loader_path/Frameworks before signing the bytes that enter the tarball.
"$SCRIPT_DIR/bundle-daemon-qt.sh" \
    "$STAGING" "$APP/Contents/Frameworks" "$APP/Contents/Frameworks"

# Normalize the security-relevant mode contract before signing. The payload
# verifier rejects any later mode drift, including group/world-writable dylibs.
"$SCRIPT_DIR/macos-service-payload.sh" normalize "$STAGING"
"$SCRIPT_DIR/verify-macos-build-paths.sh" "$STAGING"

SIGN=(codesign --force --options runtime --timestamp \
      --sign "$CODESIGN_IDENTITY" --keychain "$CODESIGN_KEYCHAIN")
while IFS= read -r -d '' candidate; do
    file -b "$candidate" | grep -q 'Mach-O' || continue
    "${SIGN[@]}" "$candidate"
done < <(find "$STAGING/Frameworks" -type f -print0)
while IFS= read -r framework; do
    "${SIGN[@]}" "$framework"
done < <(find "$STAGING/Frameworks" -depth -type d -name '*.framework' -print)
for executable in Tribe-service amneziawg-go openvpn tun2socks; do
    "${SIGN[@]}" "$STAGING/$executable"
done

TEAM_REQUIREMENT='anchor apple generic and certificate leaf[subject.OU] = "Q7DVH5MCWF" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists'
for executable in Tribe-service amneziawg-go openvpn tun2socks; do
    codesign --verify --strict --verbose=2 -R="$TEAM_REQUIREMENT" "$STAGING/$executable"
done
while IFS= read -r -d '' candidate; do
    file -b "$candidate" | grep -q 'Mach-O' || continue
    codesign --verify --strict --verbose=2 -R="$TEAM_REQUIREMENT" "$candidate"
done < <(find "$STAGING/Frameworks" -type f -print0)

"$SCRIPT_DIR/verify-macos-runtime.sh" service "$STAGING"
PYTHONDONTWRITEBYTECODE=1 python3 \
    "$SCRIPT_DIR/../../metadata/check_macos_engine_artifact.py" \
    --runtime-root "$STAGING" \
    --app-info "$APP/Contents/Info.plist" \
    --lock "$SCRIPT_DIR/../../metadata/engine-lock.json"
"$SCRIPT_DIR/macos-service-payload.sh" seal "$STAGING"

mkdir -p "$RESOURCES"
rm -f "$RESOURCES/tribe-daemon.sh" \
      "$RESOURCES/tribe-svc.tar.gz" \
      "$RESOURCES/tribe-svc.tar.sha256" \
      "$RESOURCES/tribe-svc.version" \
      "$RESOURCES/tribe-svc.epoch" \
      "$RESOURCES/tribe-svc-install.sh" \
      "$RESOURCES/macos-service-payload.sh" \
      "$RESOURCES/migrate-macos-legacy-app.sh" \
      "$RESOURCES/launchctl-job-field.sh"

(
    cd "$STAGING"
    COPYFILE_DISABLE=1 tar czf "$TARBALL_TMP" \
        Tribe-service amneziawg-go openvpn tun2socks \
        geoip.dat geosite.dat INSTALL-CONTRACT INSTALL-EPOCH Frameworks pf \
        PAYLOAD-MANIFEST.sha256 PAYLOAD-SYMLINKS VERSION
)
mv "$TARBALL_TMP" "$RESOURCES/tribe-svc.tar.gz"
shasum -a 256 "$RESOURCES/tribe-svc.tar.gz" | awk '{print $1}' \
    > "$RESOURCES/tribe-svc.tar.sha256"
cp -p "$STAGING/VERSION" "$RESOURCES/tribe-svc.version"
cp -p "$STAGING/INSTALL-EPOCH" "$RESOURCES/tribe-svc.epoch"
cp -p "$SCRIPT_DIR/tribe-svc-install.sh" "$RESOURCES/tribe-svc-install.sh"
cp -p "$SCRIPT_DIR/macos-service-payload.sh" "$RESOURCES/macos-service-payload.sh"
cp -p "$SCRIPT_DIR/migrate-macos-legacy-app.sh" \
    "$RESOURCES/migrate-macos-legacy-app.sh"
cp -p "$SCRIPT_DIR/launchctl-job-field.sh" \
    "$RESOURCES/launchctl-job-field.sh"
chmod 755 "$RESOURCES/tribe-svc-install.sh" \
          "$RESOURCES/macos-service-payload.sh" \
          "$RESOURCES/migrate-macos-legacy-app.sh" \
          "$RESOURCES/launchctl-job-field.sh"
chmod 644 "$RESOURCES/tribe-svc.tar.gz" "$RESOURCES/tribe-svc.tar.sha256" \
          "$RESOURCES/tribe-svc.version" "$RESOURCES/tribe-svc.epoch"

"$SCRIPT_DIR/macos-service-payload.sh" verify "$STAGING" \
    "$RESOURCES/tribe-svc.version"

# Contents/MacOS is a code-only bundle location.  Keeping PF configuration or geodata beside
# the executables makes modern codesign treat those ordinary files as unsigned nested code.
# The privileged installer consumes the sealed copies above; retain a reviewable app copy under
# Resources for the final artifact identity gate and keep MacOS strictly executable-only.
APP_DAEMON_DATA="$RESOURCES/daemon-runtime"
[ ! -e "$APP_DAEMON_DATA" ] && [ ! -L "$APP_DAEMON_DATA" ] \
    || { echo "stale app daemon data directory" >&2; exit 1; }
mkdir -m 755 "$APP_DAEMON_DATA"
mv "$MACOS/geoip.dat" "$APP_DAEMON_DATA/geoip.dat"
mv "$MACOS/geosite.dat" "$APP_DAEMON_DATA/geosite.dat"
mv "$MACOS/pf" "$APP_DAEMON_DATA/pf"
chmod 644 "$APP_DAEMON_DATA/geoip.dat" "$APP_DAEMON_DATA/geosite.dat"
find "$APP_DAEMON_DATA/pf" -type d -exec chmod 755 {} +
find "$APP_DAEMON_DATA/pf" -type f -exec chmod 644 {} +
echo "sealed macOS daemon payload embedded in $APP"
