#!/bin/bash
# Decision 2026-11-05, owner test 06.11, android5 H1/H3: tunnel transitions on the app's shared API manager (a new
# generation + abort of requests in flight, NetAwait.h + DebugSnapshot.h) with real QNAMs and loopback HTTP/TLS servers.
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
# TLS on loopback (skipped without openssl): a test CA and two server certificates - A for https://127.0.0.1 (the
# mid-handshake and exit cases, the redirect source), B for https://localhost (the redirect target, review R3)
tls_certs() {
  local D="$1"
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=Tribe test CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout "$D/ca.key" -out "$D/ca.crt" || return 1
  local name san
  for pair in "a IP:127.0.0.1" "b DNS:localhost"; do
    name="${pair%% *}"; san="${pair#* }"
    openssl req -newkey rsa:2048 -nodes -subj "/CN=$name" -keyout "$D/$name.key" -out "$D/$name.csr" || return 1
    printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=%s\n' \
      "$san" > "$D/$name.ext"
    openssl x509 -req -in "$D/$name.csr" -CA "$D/ca.crt" -CAkey "$D/ca.key" -CAcreateserial -days 1 \
      -extfile "$D/$name.ext" -out "$D/$name.crt" || return 1
  done
}
if command -v openssl >/dev/null 2>&1 && tls_certs "$OUT" >/dev/null 2>&1; then
  export AVPN_TEST_TLS_CA="$OUT/ca.crt" AVPN_TEST_TLS_CERT="$OUT/a.crt" AVPN_TEST_TLS_KEY="$OUT/a.key" \
         AVPN_TEST_TLS_CERT_B="$OUT/b.crt" AVPN_TEST_TLS_KEY_B="$OUT/b.key"
fi
WW_TEST=1 WW_TEST_ID=api-transition "$OUT/api_transition_check"
