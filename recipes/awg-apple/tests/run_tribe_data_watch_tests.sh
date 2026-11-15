#!/bin/sh
# Compiles the pure data-watch logic + its executable test with the host swiftc and runs it.
# Invoked by recipes/awg-apple/conanfile.py build() (gate) and usable standalone.
# Usage: run_tribe_data_watch_tests.sh [TribeDataWatch.swift [TribeDataWatchTests.swift]]
set -eu
here=$(cd "$(dirname "$0")" && pwd)
watch=${1:-"$here/../tribe/TribeDataWatch.swift"}
tests=${2:-"$here/TribeDataWatchTests.swift"}
work=$(mktemp -d "${TMPDIR:-/tmp}/tribe-data-watch-test.XXXXXX")
trap 'rm -rf "${work:?}"' EXIT
# swiftc allows top-level statements only in main.swift
cp "$tests" "$work/main.swift"
xcrun swiftc -O "$watch" "$work/main.swift" -o "$work/tribe-data-watch-test"
"$work/tribe-data-watch-test"
