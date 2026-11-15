#!/bin/sh
# Compiles the pure data-watch logic + its executable tests with the host swiftc and runs them.
# Invoked by recipes/awg-apple/conanfile.py build() (gate) and usable standalone.
#   1. the rule alone (TribeDataWatchTests.swift);
#   2. the rule together with the real stall ladder (TribeDataWatchLadderTests.swift).
# Usage: run_tribe_data_watch_tests.sh [TribeDataWatch.swift [TribeDataWatchTests.swift
#                                       [TribeRoaming.swift [TribeDataWatchLadderTests.swift]]]]
set -eu
here=$(cd "$(dirname "$0")" && pwd)
watch=${1:-"$here/../tribe/TribeDataWatch.swift"}
tests=${2:-"$here/TribeDataWatchTests.swift"}
roaming=${3:-"$here/../tribe/TribeRoaming.swift"}
ladder=${4:-"$here/TribeDataWatchLadderTests.swift"}
work=$(mktemp -d "${TMPDIR:-/tmp}/tribe-data-watch-test.XXXXXX")
trap 'rm -rf "${work:?}"' EXIT
# swiftc allows top-level statements only in main.swift
mkdir "$work/rule" "$work/ladder"
cp "$tests" "$work/rule/main.swift"
xcrun swiftc -O "$watch" "$work/rule/main.swift" -o "$work/tribe-data-watch-test"
"$work/tribe-data-watch-test"
cp "$ladder" "$work/ladder/main.swift"
xcrun swiftc -O "$roaming" "$watch" "$work/ladder/main.swift" -o "$work/tribe-data-watch-ladder-test"
"$work/tribe-data-watch-ladder-test"
