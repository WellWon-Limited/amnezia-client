#!/bin/bash
# Static check of an APK: how many Go runtimes (cgo c-shared libraries) does Qt's loader start in the UI process?
# Two or more in one process crash it at start-up (startup_crash_repro.sh, go_runtimes_probe.c): they share the
# Android TLS slot for g and the last one loaded owns the signal handlers. The UI process loads libs.xml qt_libs,
# bundled_libs, load_local_libs and the main library (android.app.lib_name), each with its DT_NEEDED closure;
# the VPN service processes load their Go library from Kotlin, one per process, and are not counted here.
# Usage: check_ui_go_runtimes.sh <apk> [abi]   exit 0 = at most one Go runtime, 1 = two or more, 2 = usage/tools
set -u
APK=${1:?usage: check_ui_go_runtimes.sh <apk> [abi]}
ABI=${2:-arm64-v8a}
NDK=${NDK:-$HOME/Library/Android/sdk/ndk/27.0.11718014}
READELF=${READELF:-$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-readelf}
AAPT2=${AAPT2:-$HOME/Library/Android/sdk/build-tools/36.0.0/aapt2}
[ -x "$READELF" ] && [ -x "$AAPT2" ] || { echo "llvm-readelf or aapt2 not found" >&2; exit 2; }

WORK=$(mktemp -d)
trap 'rm -rf "${WORK:?}"' EXIT
unzip -q -o "$APK" "lib/$ABI/*.so" -d "$WORK" || { echo "no lib/$ABI in $APK" >&2; exit 2; }
LIBDIR=$WORK/lib/$ABI

# Library names Qt's loader preloads, as file names.
"$AAPT2" dump resources "$APK" 2> /dev/null | awk -v abi="$ABI" '
    /array\/(qt_libs|bundled_libs|load_local_libs)$/ { on = 1; next }
    /resource 0x/ { on = 0 }
    on { while (match($0, "\"" abi ";[^\"]+\"")) { print substr($0, RSTART + length(abi) + 2, RLENGTH - length(abi) - 3);
                                                   $0 = substr($0, RSTART + RLENGTH) } }' \
    | sed -E 's/^lib//; s/\.so$//; s/^(.*)$/lib\1.so/' > "$WORK/queue"
main=$("$AAPT2" dump xmltree --file AndroidManifest.xml "$APK" 2> /dev/null \
    | awk '/android:name.*"android.app.lib_name"/ { getline; if (match($0, /"[^"]+"/)) print substr($0, RSTART + 1, RLENGTH - 2) }' \
    | head -1)
[ -n "$main" ] && echo "lib${main}_$ABI.so" >> "$WORK/queue"

# DT_NEEDED closure inside the APK; remember who pulled each library in.
: > "$WORK/seen"
while read -r lib; do
    grep -qx "$lib" "$WORK/seen" && continue
    echo "$lib" >> "$WORK/seen"
    [ -f "$LIBDIR/$lib" ] || continue
    "$READELF" -d "$LIBDIR/$lib" 2> /dev/null | sed -nE 's/.*\(NEEDED\).*\[(.*)\]/\1/p' | while read -r dep; do
        [ -f "$LIBDIR/$dep" ] || continue
        echo "$dep" >> "$WORK/queue"
        echo "$dep <- $lib" >> "$WORK/via"
    done
done < "$WORK/queue"

count=0
while read -r lib; do
    [ -f "$LIBDIR/$lib" ] || continue
    "$READELF" -S "$LIBDIR/$lib" 2> /dev/null | grep -q '\.go\.buildinfo' || continue
    count=$((count + 1))
    version=$(strings -n 6 "$LIBDIR/$lib" | grep -m1 -E '^go1\.[0-9]+(\.[0-9]+)?$')
    via=$(grep "^$lib <- " "$WORK/via" 2> /dev/null | sed 's/.* <- //' | sort -u | tr '\n' ' ')
    echo "go-runtime $lib ${version:-go?} preloaded${via:+ via NEEDED of: $via}"
done < "$WORK/seen"
echo "UI process Go runtimes: $count ($(basename "$APK"))"
[ "$count" -le 1 ]
