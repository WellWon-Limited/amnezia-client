#!/bin/sh
# Compiles the pure roaming logic + its executable test with the host swiftc and runs it.
# Invoked by recipes/awg-apple/conanfile.py build() (gate) and usable standalone.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/tribe-roaming-test.XXXXXX")
trap 'rm -rf "$work"' EXIT
# swiftc allows top-level statements only in main.swift
cp "$here/TribeRoamingTests.swift" "$work/main.swift"
xcrun swiftc -O "$here/../tribe/TribeRoaming.swift" "$work/main.swift" -o "$work/tribe-roaming-test"
"$work/tribe-roaming-test"
