#!/usr/bin/env bash
# Emulator round 3 (26.11), C1: the notification question's "asked" mark was lost - asked again 3 times. Android's
# SharedPreferences live per process: a process loads a file once and each of its writes puts its WHOLE copy back. The
# VPN service, started by the same tap, loaded the app's file before the question was shown; its next leg saved the
# config and with it a copy without the mark (the file shrank by one entry 100 ms after the service's leg). Rule: one
# writing process per preference file (Prefs.kt).
#   P1  the VPN service code never writes the app's file (Prefs); its keys go to its own file (ServicePrefs);
#   P2  the service reads its keys from its own file, the app's file only for an install that has not written it yet;
#   P3  the app's file is written only where the app's (UI) process runs: the activity and Log's own setter (called by
#       the activity); nothing else in the Android code writes it;
#   P4  Log.init (every process) and the service's SET_SAVE_LOGS take the flag without writing it;
#   P5  the two files are two different files, and only the service code touches the service's file.
# Run by the check sweep (every check_*.sh of this directory).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$(cd "$HERE/../../.." && pwd)"
AND="$CLIENT/android"
fail=0
bad() { echo "FAIL: $1"; fail=1; }
code() { grep -v '^[[:space:]]*//' "$1" || true; }
has() { printf '%s\n' "$1" | grep -F -- "$2" > /dev/null; }

SVC="$AND/src/org/amnezia/vpn/AmneziaVpnService.kt"
ACT="$AND/src/org/amnezia/vpn/AmneziaActivity.kt"
PREFS="$AND/utils/src/main/kotlin/Prefs.kt"
LOG="$AND/utils/src/main/kotlin/Log.kt"
for f in "$SVC" "$ACT" "$PREFS" "$LOG"; do [ -f "$f" ] || { echo "FAIL: missing $f"; exit 1; }; done
svc="$(code "$SVC")"

# ---- P1 ----
printf '%s\n' "$svc" | grep -E '(^|[^A-Za-z])Prefs\.save\(' > /dev/null \
    && bad "P1: the VPN service must not write the app's preference file (Prefs.save)"
for k in 'ServicePrefs.save(PREFS_CONFIG_KEY, vpnConfig)' 'ServicePrefs.save(PREFS_SERVER_NAME, serverName ?: "")' \
         'ServicePrefs.save(PREFS_SERVER_INDEX, serverIndex)'; do
    has "$svc" "$k" || bad "P1: the service must keep its key in its own file: $k"
done

# ---- P2 ----
has "$svc" 'if (ServicePrefs.contains(key)) ServicePrefs.load(key) else Prefs.load(key)' \
    || bad "P2: the service must read its keys from its own file first"
has "$svc" 'connectToVpn(loadServiceKey(PREFS_CONFIG_KEY), seq, leg, begin)' \
    || bad "P2: a start without a config must read the service's own file"
has "$svc" 'serverName = loadServiceKey<String>(PREFS_SERVER_NAME).ifBlank { null }' \
    && has "$svc" 'serverIndex = loadServiceKey(PREFS_SERVER_INDEX)' \
    || bad "P2: the server data must be read from the service's own file"
printf '%s\n' "$svc" | grep -E '(^|[^A-Za-z])Prefs\.load(<[A-Za-z]+>)?\(PREFS_' > /dev/null \
    && bad "P2: the service must not read its keys from the app's file directly"

# ---- P3 ---- every write of the app's file in the Android sources: the activity, or Log's setter
writers="$(grep -rlE '(^|[^A-Za-z])Prefs\.save\(' "$AND" --include='*.kt' --include='*.java' 2>/dev/null \
    | grep -v '/build/' | sed "s#^$AND/##" | sort || true)"
for w in $writers; do
    case "$w" in
        src/org/amnezia/vpn/AmneziaActivity.kt) ;;
        utils/src/main/kotlin/Log.kt) ;;
        *) bad "P3: $w writes the app's preference file - only the app's (UI) process may" ;;
    esac
done
logc="$(code "$LOG")"
[ "$(printf '%s\n' "$logc" | grep -cE '(^|[^A-Za-z])Prefs\.save\(')" -eq 1 ] \
    && has "$logc" 'if (useSaveLogs(value)) Prefs.save(PREFS_SAVE_LOGS_KEY, value)' \
    || bad "P3: Log writes the app's file only in the setter the activity calls"

# ---- P4 ----
has "$logc" 'useSaveLogs(Prefs.load(PREFS_SAVE_LOGS_KEY))' || bad "P4: Log.init must take the flag without writing it"
printf '%s\n' "$logc" | grep -qF 'saveLogs = Prefs.load(' && bad "P4: Log.init must not write the flag it just read"
has "$svc" 'Log.useSaveLogs(msg.data.getBoolean(MSG_SAVE_LOGS))' || bad "P4: the service must take SET_SAVE_LOGS without writing it"
printf '%s\n' "$svc" | grep -qE 'Log\.saveLogs[[:space:]]*=' && bad "P4: the service must not set the persisting flag"
code "$ACT" | grep -qF 'Log.saveLogs = enabled' || bad "P4: the activity keeps the one persisting set of the flag"

# ---- P5 ----
pc="$(code "$PREFS")"
has "$pc" 'private const val SERVICE_PREFS_FILE = "org.amnezia.vpn.service.prefs"' \
    && has "$pc" 'object Prefs : PrefsFile(PREFS_FILE, SECURE_PREFS_FILE)' \
    && has "$pc" 'object ServicePrefs : PrefsFile(SERVICE_PREFS_FILE, SECURE_SERVICE_PREFS_FILE)' \
    || bad "P5: Prefs and ServicePrefs must be two files"
users="$(grep -rlE 'ServicePrefs\.' "$AND" --include='*.kt' --include='*.java' 2>/dev/null | grep -v '/build/' \
    | sed "s#^$AND/##" | sort || true)"
for u in $users; do
    [ "$u" = "src/org/amnezia/vpn/AmneziaVpnService.kt" ] || bad "P5: $u touches the service's file - only the service may"
done

[ "$fail" -eq 0 ] && echo "android prefs one-writer wiring: OK"
exit "$fail"
