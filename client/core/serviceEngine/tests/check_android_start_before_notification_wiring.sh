#!/bin/bash
# AVPN (emulator round 26.11.2026, D5, Android): the first Connect waited 71 s for the answer to «Show the VPN state in the
# status bar?» (the notification question, then Android's POST_NOTIFICATIONS dialog) while the screen said «trying 1 of 6»:
# upstream started the service only after that answer. Android's rule: an app does not need POST_NOTIFICATIONS to start a
# foreground service (it must still give the notification); a denial only hides it from the drawer. Each line fails if
# its call site is reverted:
#   N1  start(): the VPN consent, then the tunnel start, then the notification question - the question never gates the start;
#   N2  only the VPN dialog pauses the engine's clock (c2ff72b32): the notification dialog reports no permission prompt;
#   N3  a grant reaches the running service (Action.NOTIFICATION_PERMISSION_GRANTED -> enableNotification), and one given
#       before the bind is sent on the bind;
#   N4  the service registers its screen receivers once, however often it hears of a grant.
# Run by the check sweep (every check_*.sh of this directory).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$(cd "$HERE/../../.." && pwd)"
fail=0
bad() { echo "FAIL: $1"; fail=1; }
code() { grep -v '^[[:space:]]*//' "$1" || true; }
has() { printf '%s\n' "$1" | grep -F -- "$2" > /dev/null; }
# a Kotlin member function: from its signature line to the class-level closing brace (4 spaces)
kfun() { code "$1" | awk -v sig="$2" 'index($0, sig) > 0 { on = 1 } on { print } on && /^    }$/ { exit }'; }
lineof() { printf '%s\n' "$1" | grep -nF -- "$2" | head -1 | cut -d: -f1; }

ACT="$CLIENT/android/src/org/amnezia/vpn/AmneziaActivity.kt"
SVC="$CLIENT/android/src/org/amnezia/vpn/AmneziaVpnService.kt"

# ---- N1 ----
st="$(kfun "$ACT" 'fun start(vpnConfig: String)')"
[ -n "$st" ] || bad "N1: AmneziaActivity.start(vpnConfig) not found"
v=$(lineof "$st" 'checkVpnPermission {'); s=$(lineof "$st" 'startVpn(vpnConfig)'); n=$(lineof "$st" 'checkNotificationPermission')
if [ -z "$v" ] || [ -z "$s" ] || [ -z "$n" ] || [ "$v" -ge "$s" ] || [ "$s" -ge "$n" ]; then
    bad "N1: start() must run checkVpnPermission { startVpn(vpnConfig); checkNotificationPermission ... } in this order"
fi
printf '%s\n' "$st" | tr -s ' \n' ' ' | grep -qF 'checkNotificationPermission { startVpn' \
    && bad "N1: the tunnel start is back inside the notification question"

# ---- N2 ----
dlg="$(kfun "$ACT" 'private fun showNotificationPermissionDialog(')"
[ -n "$dlg" ] || bad "N2: showNotificationPermissionDialog not found"
has "$dlg" 'reportPermissionPrompt(' && bad "N2: the notification dialog must not pause the engine's clock"
vpn="$(kfun "$ACT" 'private fun checkVpnPermission(')"
for p in PROMPT_PENDING PROMPT_GRANTED PROMPT_DENIED; do
    has "$vpn" "reportPermissionPrompt($p)" || bad "N2: the VPN dialog lost its $p report (c2ff72b32)"
done

# ---- N3 ----
has "$dlg" 'tellServiceNotificationGranted()' || bad "N3: a grant in the notification dialog must tell the service"
tell="$(kfun "$ACT" 'private fun tellServiceNotificationGranted()')"
has "$tell" 'vpnServiceMessenger.send(Action.NOTIFICATION_PERMISSION_GRANTED)' || bad "N3: the grant must reach a bound service"
has "$tell" 'notificationGrantForService = true' || bad "N3: a grant before the bind must wait for it"
act="$(code "$ACT")"
printf '%s\n' "$act" | awk '/override fun onServiceConnected/ { on = 1 } on { print } on && /^            }$/ { exit }' \
    | grep -qF 'if (notificationGrantForService)' || bad "N3: the bind must send a grant that waited for it"
svc="$(code "$SVC")"
printf '%s\n' "$svc" | grep -A2 -F 'Action.NOTIFICATION_PERMISSION_GRANTED ->' | grep -qF 'enableNotification()' \
    || bad "N3: the service must enable its notification on the grant"

# ---- N4 ----
reg="$(kfun "$SVC" 'private fun registerScreenStateBroadcastReceivers()')"
has "$reg" 'if (screenOnReceiver != null) return' || bad "N4: the screen receivers must be registered once"

[ "$fail" -eq 0 ] && echo "android start before notification wiring: OK"
exit "$fail"
