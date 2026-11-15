#!/bin/bash
# AVPN (build 140, data watch): host checks of the tunnel-extension side, no device and no Xcode
# project. 1) the pure verdict rule of the awg-apple package (the package's own build gate);
# 2) the extension's Foundation-only half: plan file, bypass-check reply, journal line.
# Usage: bash client/platforms/ios/tests/run_ios_data_watch_checks.sh
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../../../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "${work:?}"' EXIT

echo "== 1/2 TribeDataWatch (package gate) =="
sh "$repo/recipes/awg-apple/tests/run_tribe_data_watch_tests.sh"

echo "== 2/2 plan file, bypass reply, journal line =="
xcrun --sdk macosx swiftc -Onone -parse-as-library -o "$work/watch-plan-tests" \
    "$repo/recipes/awg-apple/tribe/TribeDataWatch.swift" \
    "$here/../TribeWatchPlan.swift" \
    "$here/TribeWatchPlanTests.swift"
"$work/watch-plan-tests"
