#!/bin/bash
# AVPN (android3 runs a, f, 21.11, Android): first Connect after an app start, Wi-Fi lost 1.3 s later - the engine's stop
# went out before the VPN service was bound and vanished, the queued start brought a tunnel up behind a «Connect» screen,
# and the engine sat in a state where neither the uplink's return nor a tap did anything. The rules are pure and tested
# by behaviour (ServiceCommandQueue: client/android/utils src/test ServiceCommandQueueTest; the facade's status rule:
# facade_policy_check). What is checked here is where they are wired - each line fails if its call site is reverted:
#   Q1  the activity gives every start/stop messenger command through the queue and flushes it, in order, on the bind;
#       a start behind a waiting command does not overtake it as a second intent.
# Run by the check sweep (every check_*.sh of this directory).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$(cd "$HERE/../../.." && pwd)"
fail=0
bad() { echo "FAIL: $1"; fail=1; }
code() { grep -v '^[[:space:]]*//' "$1" || true; }
has() { printf '%s\n' "$1" | grep -F -- "$2" > /dev/null; }
count() { printf '%s\n' "$1" | grep -cF -- "$2" || true; }

ACT="$CLIENT/android/src/org/amnezia/vpn/AmneziaActivity.kt"

# ---- Q1 ----
act="$(code "$ACT")"
has "$act" 'serviceCommands.onBound().forEach(::sendServiceCommand)' || bad "Q1: the bind must deliver the waiting commands"
has "$act" 'giveServiceCommand(ServiceCommand.Disconnect)' || bad "Q1: the stop must go through the queue"
has "$act" 'giveServiceCommand(ServiceCommand.Connect(vpnConfig))' || bad "Q1: a bound start must go through the queue"
has "$act" 'if (serviceCommands.startWaits(ServiceCommand.Connect(vpnConfig), bound = false)) {' \
    || bad "Q1: a start behind a waiting command must wait behind it"
[ "$(count "$act" 'vpnServiceMessenger.send(Action.DISCONNECT)')" = "1" ] \
    || bad "Q1: DISCONNECT may be sent only by sendServiceCommand"
has "$act" 'serviceCommands.offer(command, bound = isServiceConnected, binding = isInBoundState && !isServiceConnected)' \
    || bad "Q1: the queue must know whether the service is bound or a bind is in progress"

[ "$fail" = "0" ] && echo "check_android_service_order_wiring: OK"
exit "$fail"
