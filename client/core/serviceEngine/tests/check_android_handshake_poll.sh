#!/bin/bash
# AVPN (item 2, Android): the handshake of a starting tunnel is noticed within ~0.125 s, not up to 1 s later, so a
# handshake 4.1 s after the tunnel was built is seen before the attempt's 4.5 s leg limit. The status job of the
# AmneziaWG tunnel (Wireguard.kt launchStatusJob) runs only while the tunnel starts; it polls fast for the first
# 10 s and at the upstream 1 s after. Source-level wiring check (the module has no unit harness).
set -eu
KT="$(cd "$(dirname "$0")/../../.." && pwd)/android/wireguard/src/main/kotlin/org/amnezia/vpn/protocol/wireguard/Wireguard.kt"
fail=0
bad() { echo "FAIL: $1"; fail=1; }
code="$(grep -v '^[[:space:]]*//' "$KT")"
has() { printf '%s\n' "$code" | grep -qF -- "$1"; }
has 'private const val START_POLL_MS = 125L' || bad "fast start cadence is not 125 ms"
has 'private const val START_POLL_WINDOW_MS = 10_000L' || bad "fast window is not 10 s"
has 'private const val STEADY_POLL_MS = 1000L' || bad "steady cadence is not 1 s"
has 'if (sinceBuiltMs < START_POLL_WINDOW_MS) START_POLL_MS else STEADY_POLL_MS' || bad "delay rule moved"
has 'delay(handshakePollDelayMs((System.nanoTime() - startedAt) / 1_000_000))' || bad "the status job does not use the rule"
printf '%s\n' "$code" | grep -qF 'delay(1000)' && bad "a fixed 1 s delay is back in the status job"
[ "$fail" = 0 ] && echo "check_android_handshake_poll: OK"
exit "$fail"
