#!/bin/bash
# AVPN (build 140, data watch): host checks of the tunnel-extension side, no device and no Xcode
# project. 1) the pure verdict rule of the awg-apple package, alone and wired to the real stall
# ladder (the package's own build gate); 2) the extension's Foundation-only half: plan file, bypass
# reply, journal line; 3) the provider's runtime with fakes for the adapter, the Go layer and the
# shared container: plan -> policy -> rule -> checks -> log, journal, status block, state file.
# Usage: bash client/platforms/ios/tests/run_ios_data_watch_checks.sh
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../../../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "${work:?}"' EXIT

echo "== 1/3 TribeDataWatch (package gate) =="
sh "$repo/recipes/awg-apple/tests/run_tribe_data_watch_tests.sh"

echo "== 2/3 plan file, bypass reply, journal line =="
xcrun --sdk macosx swiftc -Onone -parse-as-library -o "$work/watch-plan-tests" \
    "$repo/recipes/awg-apple/tribe/TribeDataWatch.swift" \
    "$here/../TribeWatchPlan.swift" \
    "$here/TribeWatchPlanTests.swift"
"$work/watch-plan-tests"

echo "== 3/3 the provider's runtime =="
xcrun --sdk macosx swiftc -Onone -parse-as-library -o "$work/watch-runtime-tests" \
    "$repo/recipes/awg-apple/tribe/TribeDataWatch.swift" \
    "$here/../TribeWatchPlan.swift" \
    "$here/../TribeDataWatchRuntime.swift" \
    "$here/TribeDataWatchRuntimeTests.swift"
"$work/watch-runtime-tests"
