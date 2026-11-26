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
#   N4  the service registers its screen receivers once, however often it hears of a grant;
#   N5  (round 2, F3) the question is asked once - marked asked when shown;
#   N6  Android's dialog is never raised without the person's tap (the engine's push authorization raises nothing);
#   N7  a grant made outside the app's dialogs reaches the running service (onResume, once per activity).
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
# (round 2, F3) any POST_NOTIFICATIONS grant, whatever dialog and request code, tells the running service
res="$(kfun "$ACT" 'override fun onRequestPermissionsResult(')"
has "$res" 'val notifications = permissions.indexOf(Manifest.permission.POST_NOTIFICATIONS)' \
    && has "$res" 'tellServiceNotificationGranted()' || bad "N3: a notification grant from any dialog must tell the service"
r1=$(printf '%s\n' "$res" | grep -nF 'tellServiceNotificationGranted()' | head -1 | cut -d: -f1)
r2=$(printf '%s\n' "$res" | grep -nF 'permissionRequestHandlers[requestCode]' | head -1 | cut -d: -f1)
[ -n "$r1" ] && [ -n "$r2" ] && [ "$r1" -lt "$r2" ] || bad "N3: the grant must be told before the handler dispatch (codes without a handler too)"
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

# ---- N5 (round 2, F3) ---- the question is asked once: marked asked the moment it is shown (each leg calls start())
dl1="$(printf '%s\n' "$dlg" | sed -n '2,3p')"
has "$dl1" 'Prefs.save(PREFS_NOTIFICATION_PERMISSION_ASKED, true)' || bad "N5: the question must be marked asked when shown"

# ---- N6 ---- Android's notification dialog is never raised without the person's tap: the engine's push authorization
# (shared with iOS) raises nothing on Android
FCM="$CLIENT/android/src/org/amnezia/vpn/AvpnFcmService.kt"
fcm="$(kfun "$FCM" 'fun requestPermission(ctx: Context)')"
[ -n "$fcm" ] || bad "N6: AvpnFcmService.requestPermission must stay (the engine's JNI call resolves it)"
has "$fcm" 'requestPermissions(' && bad "N6: the push authorization raises Android's dialog by itself"

# ---- N7 ---- a grant made outside the app's dialogs reaches the running service once per activity (onResume)
rsm="$(kfun "$ACT" 'override fun onResume()')"
printf '%s\n' "$rsm" | tr -s ' \n' ' ' | grep -qF 'if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && !notificationToldGranted && isNotificationPermissionGranted() ) { tellServiceNotificationGranted()' \
    || bad "N7: onResume must tell the service of a grant it has not heard of"

[ "$fail" -eq 0 ] && echo "android start before notification wiring: OK"
exit "$fail"
