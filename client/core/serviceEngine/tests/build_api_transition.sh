#!/bin/bash
# Decision 2026-11-05 + owner test 06.11: tunnel transitions on the shared QNAM (clear + abort of
# requests in flight, NetAwait.h + DebugSnapshot.h) with a real QNetworkAccessManager and a loopback server.
set -euo pipefail
QT="${QT_ROOT:-$HOME/Qt/6.11.1/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$HERE/../../.."
OUT="$(mktemp -d /tmp/tribe-api-transition.XXXXXX)"
trap 'rm -rf -- "$OUT"' EXIT
"$QT/libexec/moc" "$HERE/api_transition_check.cpp" -o "$OUT/api_transition_check.moc"
clang++ -std=c++17 -fPIC -include arm_acle.h \
  -I"$QT/include" -I"$QT/lib/QtCore.framework/Headers" -I"$QT/lib/QtNetwork.framework/Headers" \
  -I"$QT/lib/QtTest.framework/Headers" -I"$OUT" -I"$CLIENT" -F"$QT/lib" \
  "$HERE/api_transition_check.cpp" \
  -framework QtCore -framework QtNetwork -framework QtTest -framework Foundation \
  -Wl,-rpath,"$QT/lib" -o "$OUT/api_transition_check"
# android5 H1/H3: a self-signed loopback certificate for the mid-handshake case (skipped without openssl)
if command -v openssl >/dev/null 2>&1; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1" \
    -keyout "$OUT/tls.key" -out "$OUT/tls.crt" >/dev/null 2>&1 \
    && export AVPN_TEST_TLS_CERT="$OUT/tls.crt" AVPN_TEST_TLS_KEY="$OUT/tls.key"
fi
WW_TEST=1 WW_TEST_ID=api-transition "$OUT/api_transition_check"
