#!/bin/sh
# Compiles the pure roaming logic + its executable test with the host swiftc and runs it.
# Invoked by recipes/awg-apple/conanfile.py build() (gate) and usable standalone.
# Usage: run_tribe_roaming_tests.sh [TribeRoaming.swift [TribeRoamingTests.swift]]
#   no arguments = the current version (tribe/TribeRoaming.swift + tests/TribeRoamingTests.swift);
#   the recipe passes a released version's snapshot (tribe/snapshots/<v>/, tests/snapshots/<v>/).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
roaming=${1:-"$here/../tribe/TribeRoaming.swift"}
tests=${2:-"$here/TribeRoamingTests.swift"}
work=$(mktemp -d "${TMPDIR:-/tmp}/tribe-roaming-test.XXXXXX")
trap 'rm -rf "$work"' EXIT
# swiftc allows top-level statements only in main.swift
cp "$tests" "$work/main.swift"
xcrun swiftc -O "$roaming" "$work/main.swift" -o "$work/tribe-roaming-test"
"$work/tribe-roaming-test"
