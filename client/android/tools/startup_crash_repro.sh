#!/bin/bash
# Reproduce the Android start-up SIGSEGV of the app process (several cgo Go runtimes preloaded into one process,
# go_runtimes_probe.c) on the TribeTest emulator and count it per launch from ApplicationExitInfo: the crash leaves
# no tombstone, only an exit record with reason=2 (SIGNALED) status=11. Emulator only, never a phone with user data.
# The app keeps its data (install -r, no pm clear): no new trial enrolment per run.
#
# Modes (one line per launch goes to $OUTDIR/launches.tsv, a summary per condition to stdout):
#   boot   <delay_s> <cycles>        per cycle: cold boot (-no-snapshot, swiftshader, no window), install -r (INSTALL=0
#                                    skips it), launch <delay_s> after sys.boot_completed
#   sweep  <cycles> [delay_s ...]    boot cycles round-robin over the delays (default 5 15 30 60 120)
#   install <launches>               on a running emulator: pm install -r, then launch at once (no reboot)
#   load   <launches> <busy_loops>   on a running emulator: am force-stop + cold launch under N busy loops in the guest
# Env: APK (required for boot/sweep/install), LABEL (condition label, default the APK file name), WAIT_S (seconds
# watched per launch, default 15), OUTDIR (default ~/avpn-build/dist/android-startup-crash/runs), AVD (TribeTest).
set -u
ADB=${ADB:-$HOME/Library/Android/sdk/platform-tools/adb}
EMU=${EMU:-$HOME/Library/Android/sdk/emulator/emulator}
AVD=${AVD:-TribeTest}
PKG=com.tribevpn.client
ACT=$PKG/org.amnezia.vpn.AmneziaActivity
WAIT_S=${WAIT_S:-15}
INSTALL=${INSTALL:-1}
OUTDIR=${OUTDIR:-$HOME/avpn-build/dist/android-startup-crash/runs}
APK=${APK:-}
LABEL=${LABEL:-$(basename "${APK:-none}" .apk)}
mkdir -p "$OUTDIR"
WORK=$(mktemp -d "$OUTDIR/.work.XXXXXX")
trap 'rm -rf "${WORK:?}"' EXIT

log() { printf '%s %s\n' "$(date '+%H:%M:%S')" "$*" >&2; }

# One line per ApplicationExitInfo record of the package: "<timestamp>|<pid> process=... reason=... status=..."
exit_records() {
    $ADB shell dumpsys activity exit-info "$PKG" | tr -d '\r' | awk '
        /timestamp=/ { split($0, a, "timestamp="); split(a[2], b, " pid="); split(b[2], c, " "); key = b[1] "|" c[1]; next }
        /process=/ && key != "" { sub(/^ +/, ""); print key " " $0; key = "" }' | sort
}

# Cold launch, watched WAIT_S seconds. Appends one row to launches.tsv and prints "<segv> <alive>".
# The exit-info ring keeps 16 records per package, so the records are diffed around every single launch.
launch() {
    local mode=$1 param=$2 cycle=$3 since_boot=$4 segv native alive new
    $ADB shell am force-stop "$PKG"
    sleep 1
    exit_records > "$WORK/before"
    $ADB shell am start -n "$ACT" > /dev/null 2>&1
    sleep "$WAIT_S"
    exit_records > "$WORK/after"
    comm -13 "$WORK/before" "$WORK/after" > "$WORK/new"
    segv=$(grep -c 'reason=2 (SIGNALED).*status=11' "$WORK/new")
    native=$(grep -c 'reason=5 ' "$WORK/new")
    new=$(wc -l < "$WORK/new" | tr -d ' ')
    alive=$($ADB shell pidof "$PKG" | tr -d '\r' | grep -c .)
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$(date '+%F %T')" "$LABEL" "$mode" "$param" "$cycle" \
        "$since_boot" "$segv" "$native" "$alive" "$new" >> "$OUTDIR/launches.tsv"
    cat "$WORK/new" >> "$OUTDIR/exit-records.txt"
    echo "$segv $alive"
}

emu_stop() {
    $ADB emu kill > /dev/null 2>&1
    while $ADB devices | grep -q '^emulator-'; do sleep 1; done
    while pgrep -f "qemu-system.*-avd $AVD" > /dev/null; do sleep 1; done
}

# Cold boot; sets BOOTED to the host epoch second at which sys.boot_completed was first seen. Not called through
# $(...): the emulator (and an adb server it may start) would inherit the substitution pipe and block it.
emu_boot() {
    "$EMU" -avd "$AVD" -no-snapshot -gpu swiftshader_indirect -no-window -no-boot-anim -no-audio \
        > "$OUTDIR/emulator.log" 2>&1 &
    $ADB wait-for-device
    until [ "$($ADB shell getprop sys.boot_completed 2> /dev/null | tr -d '\r')" = "1" ]; do sleep 1; done
    BOOTED=$(date +%s)
}

clock_sync() {
    local guest host
    guest=$($ADB shell date +%s | tr -d '\r')
    host=$(date +%s)
    if [ $((guest > host ? guest - host : host - guest)) -gt 5 ]; then
        log "guest clock off by $((guest - host)) s, setting it"
        $ADB root > /dev/null 2>&1
        $ADB wait-for-device
        $ADB shell date -u "$(date -u +%m%d%H%M%Y.%S)" > /dev/null
        $ADB unroot > /dev/null 2>&1
        $ADB wait-for-device
    fi
}

boot_cycle() {
    local delay=$1 cycle=$2 now pause res
    emu_stop
    emu_boot
    clock_sync
    if [ "$INSTALL" = 1 ]; then $ADB install -r "$APK" > "$WORK/install" 2>&1 || { cat "$WORK/install" >&2; exit 1; }; fi
    now=$(date +%s)
    pause=$((BOOTED + delay - now))
    [ "$pause" -gt 0 ] && sleep "$pause"
    now=$(date +%s)
    res=$(launch boot "$delay" "$cycle" $((now - BOOTED)))
    $ADB logcat -d -b main,system,crash 2> /dev/null | tr -d '\r' \
        | grep -E 'exited due to signal|Start proc .*tribevpn|has died|QtLoader|nativeloader.*tribevpn' \
        > "$OUTDIR/logcat-$LABEL-boot$delay-c$cycle.txt"
    log "$LABEL boot delay=${delay}s cycle=$cycle launched_at=+$((now - BOOTED))s segv,alive=$res"
}

busy() {
    local i
    for i in $(seq 1 "$1"); do $ADB shell 'nohup sh -c "while :; do :; done" > /dev/null 2>&1 &'; done
}

unbusy() { $ADB shell 'pkill -f "while :"' > /dev/null 2>&1; }

summary() { # mode filter on launches.tsv for this LABEL
    awk -F'\t' -v label="$LABEL" -v mode="$1" '$2 == label && $3 == mode {
            k = $4; n[k]++; s[k] += $7; if ($7 > 0) h[k]++; if ($9 == 0) d[k]++ }
        END { for (k in n) printf "%s %s param=%s launches=%d launches_with_segv=%d segv_exits=%d dead_at_end=%d\n",
                  label, mode, k, n[k], h[k] + 0, s[k] + 0, d[k] + 0 }' "$OUTDIR/launches.tsv" | sort -t= -k2 -n
}

need_apk() { [ -n "$APK" ] && [ -f "$APK" ] || { echo "APK=<path> required" >&2; exit 2; }; }

mode=${1:-}
case "$mode" in
boot)
    need_apk
    for c in $(seq 1 "$3"); do boot_cycle "$2" "$c"; done
    emu_stop
    summary boot ;;
sweep)
    need_apk
    cycles=$2; shift 2
    delays=${*:-5 15 30 60 120}
    for c in $(seq 1 "$cycles"); do for d in $delays; do boot_cycle "$d" "$c"; done; done
    emu_stop
    summary boot ;;
install)
    need_apk
    for i in $(seq 1 "$2"); do
        $ADB install -r "$APK" > /dev/null 2>&1 || exit 1
        log "$LABEL install launch $i segv,alive=$(launch install 0 "$i" -)"
    done
    summary install ;;
load)
    unbusy
    busy "$3"
    for i in $(seq 1 "$2"); do log "$LABEL load launch $i segv,alive=$(launch load "$3" "$i" -)"; done
    unbusy
    summary load ;;
*)
    sed -n '2,15p' "$0"
    exit 2 ;;
esac
