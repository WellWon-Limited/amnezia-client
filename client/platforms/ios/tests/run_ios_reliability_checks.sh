#!/bin/sh
set -eu
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/tribe-native-reliability.XXXXXX")
trap 'rm -rf "$work"' EXIT
xcrun clang++ -std=c++17 -pthread "$here/IosStatusRequestTests.cpp" -o "$work/status-tests"
# AVPN (фикс-волна 2026-09-22, CL-C): чистая логика натива (K2 причины обрыва, K4 rebind, C1 backoff,
# C5 accept позднего status, C6 LOCK_NB, C8 схлопывание журнала).
xcrun clang++ -std=c++17 -pthread "$here/IosNativePolicyTests.cpp" -o "$work/policy-tests"
"$work/policy-tests"
# AVPN (build 141, data watch): background-time ownership by reason and the background arming rule.
xcrun clang++ -std=c++17 -pthread "$here/IosDataWatchTests.cpp" -o "$work/data-watch-tests"
"$work/data-watch-tests"
# Поведенческий харнесс настоящего ios_controller.mm / AvpnIntentController.mm (нужен Qt для macOS).
if [ -d "${QT_ROOT:-$HOME/Qt/6.11.1/macos}" ] || [ -d "$HOME/Qt/6.10.2/macos" ]; then
    OUT="$work/harness" "$here/build_ios_controller_harness.sh"
else
    echo "IosController harness: SKIPPED (no Qt for macOS; set QT_ROOT)"
fi
"$work/status-tests"
xcrun --sdk macosx swiftc -parse-as-library "$here/../TribeSharedState.swift" "$here/TribeSharedStateTests.swift" -o "$work/shared-tests"
"$work/shared-tests"
sdk=$(xcrun --sdk iphoneos --show-sdk-path)
xcrun --sdk iphoneos swiftc -typecheck -target arm64-apple-ios16.0 -sdk "$sdk" \
    "$here/../TribeSharedState.swift" "$here/../AvpnAppIntents.swift"
echo "App Intents: iPhoneOS SDK typecheck passed"
# AVPN (build 141, data watch): the verdict rule of the package and the extension's plan file.
bash "$here/run_ios_data_watch_checks.sh"
