#!/bin/bash
# Standalone build + run of the upstream engine wiring check (lane L1): tiers in the picker, flag-off
# identity of decisions, stub identity/reseed, attempt exclusions, the lease owner with a fake I/O and
# clock, the tribe-probe-v1 digest and verdict routing, standby pack at rest, status rules, network key,
# envelope. QtCore/QtNetwork + libcrypto (a test key from a public seed). No tunnel; the provider check's request
# (UpstreamLeaseClient::runProbe, its first-byte watch) runs against loopback servers.
set -eu
QT="${QT_ROOT:-$HOME/Qt/6.11.1/macos}"
SSL="${OPENSSL_ROOT:-$(brew --prefix openssl@3)}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$HERE/../../.."
MAIN_CLIENT="${AVPN_MAIN_CLIENT:-$HOME/amnezia-client/client}"
OUT_DIR="${OUT_DIR:-$(mktemp -d /tmp/tribe-upstream-engine.XXXXXX)}"
mkdir -p "$OUT_DIR"
SHIM="$(mktemp -d)"
trap 'rm -rf "$SHIM"' EXIT
printf '#pragma once\n#define QKEYCHAIN_EXPORT\n' > "$SHIM/qkeychain_export.h"
"$QT/libexec/moc" -f"UpstreamLeaseClient.h" "$HERE/../UpstreamLeaseClient.h" -o "$SHIM/moc_UpstreamLeaseClient.cpp"
clang++ -std=c++17 -fPIC -include arm_acle.h -Wall -Wextra -Wno-unused-parameter \
  -I"$SHIM" -I"$QT/include" -I"$QT/include/QtCore" -I"$QT/include/QtNetwork" \
  -I"$QT/lib/QtCore.framework/Headers" -I"$QT/lib/QtNetwork.framework/Headers" -I"$SSL/include" \
  -I"$CLIENT" -I"$MAIN_CLIENT" -I"$HERE/.." -F"$QT/lib" \
  "$HERE/../ServiceEngine.cpp" "$HERE/../SubscriptionParser.cpp" "$HERE/../Prober.cpp" \
  "$HERE/../AwgConfigBuilder.cpp" "$HERE/../XrayConfigBuilder.cpp" "$HERE/../Ed25519Verify.cpp" \
  "$HERE/../UpstreamLeaseClient.cpp" "$SHIM/moc_UpstreamLeaseClient.cpp" \
  "$HERE/upstream_engine_check.cpp" \
  -framework QtCore -framework QtNetwork -framework Foundation -L"$SSL/lib" -lcrypto \
  -Wl,-rpath,"$QT/lib" -o "$OUT_DIR/upstream_engine_check"
cd "$HERE"
"$OUT_DIR/upstream_engine_check"
