#!/bin/sh
set -eu
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/tribe-native-reliability.XXXXXX")
trap 'rm -rf "$work"' EXIT
xcrun clang++ -std=c++17 -pthread "$here/IosStatusRequestTests.cpp" -o "$work/status-tests"
"$work/status-tests"
xcrun --sdk macosx swiftc -parse-as-library "$here/../TribeSharedState.swift" "$here/TribeSharedStateTests.swift" -o "$work/shared-tests"
"$work/shared-tests"
sdk=$(xcrun --sdk iphoneos --show-sdk-path)
xcrun --sdk iphoneos swiftc -typecheck -target arm64-apple-ios16.0 -sdk "$sdk" \
    "$here/../TribeSharedState.swift" "$here/../AvpnAppIntents.swift"
echo "App Intents: iPhoneOS SDK typecheck passed"
