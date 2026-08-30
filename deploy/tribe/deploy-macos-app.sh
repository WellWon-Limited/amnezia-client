#!/bin/bash
# macdeployqt 6.10 reports a failure when its optional qsqlmimer plugin points
# at the developer-only Mimer SDK. Tribe does not use that driver. Continue
# only for this known condition; the sanitizer below still proves that every
# shipped Mach-O dependency is closed inside the bundle.
set -euo pipefail

APP="${1:?usage: $0 APP_BUNDLE MACDEPLOYQT QML_DIR}"
MACDEPLOYQT="${2:?usage: $0 APP_BUNDLE MACDEPLOYQT QML_DIR}"
QML_DIR="${3:?usage: $0 APP_BUNDLE MACDEPLOYQT QML_DIR}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
LOG="$(mktemp -t tribe-macdeployqt.XXXXXX)"
trap 'rm -f "$LOG"' EXIT

set +e
"$MACDEPLOYQT" "$APP" -appstore-compliant -qmldir="$QML_DIR" -no-codesign \
    2>&1 | tee "$LOG"
deploy_status=${PIPESTATUS[0]}
set -e

if [ "$deploy_status" -ne 0 ]; then
    grep -q '/usr/local/lib/libmimerapi\.dylib' "$LOG" \
        || { echo "macdeployqt failed for an unexpected reason" >&2; exit "$deploy_status"; }
fi

"$SCRIPT_DIR/sanitize-macos-app.sh" "$APP"
