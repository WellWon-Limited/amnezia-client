#!/bin/bash
# AVPN (emulator round 26.11.2026, D1, Android): a swipe from recents ended the UI process with SIGABRT «FORTIFY:
# pthread_mutex_lock called on a destroyed mutex», 10 ms after «main() returned 0»: Qt's Android plugin calls exit() after
# main, and the C++ static destructors ran while system threads (the view layer's render pool) still waited on one of
# them. The UI process now ends with _exit once main's work is done (as iOS ends with _exit). Each line fails if reverted:
#   X1  main.cpp declares the Android ending first in main, under Q_OS_ANDROID only, so it runs after every other local
#       (~AmneziaApplication included);
#   X2  it syncs the settings, then _exit()s with main's own result (the return assigns the code).
# Run by the check sweep (every check_*.sh of this directory).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$(cd "$HERE/../../.." && pwd)"
fail=0
bad() { echo "FAIL: $1"; fail=1; }
code() { grep -v '^[[:space:]]*//' "$1" || true; }

MAIN="$CLIENT/main.cpp"
m="$(code "$MAIN")"
body="$(printf '%s\n' "$m" | awk '/^int main\(int argc, char \*argv\[\]\)$/ { on = 1 } on { print } on && /^}$/ { exit }')"
[ -n "$body" ] || bad "X1: main() not found in main.cpp"

# ---- X1 ----
# the first statement after '{' is the Android guard block, and the ending object is declared there
first="$(printf '%s\n' "$body" | sed -n '3,4p' | tr -s ' \n' ' ')"
printf '%s\n' "$first" | grep -qF '#if defined(Q_OS_ANDROID) struct AndroidUiProcessEnd {' \
    || bad "X1: main() must open with the Android-only AndroidUiProcessEnd"
decl=$(printf '%s\n' "$body" | grep -nF '} androidUiProcessEnd;' | head -1 | cut -d: -f1)
app=$(printf '%s\n' "$body" | grep -nF 'AmneziaApplication app(argc, argv);' | head -1 | cut -d: -f1)
mig=$(printf '%s\n' "$body" | grep -nF 'Migrations migrationsManager;' | head -1 | cut -d: -f1)
if [ -z "$decl" ] || [ -z "$app" ] || [ -z "$mig" ] || [ "$decl" -ge "$mig" ] || [ "$decl" -ge "$app" ]; then
    bad "X1: androidUiProcessEnd must be declared before every other local of main"
fi
printf '%s\n' "$body" | sed -n "1,${decl:-1}p" | grep -qF '#endif' && bad "X1: the ending must sit inside the Android guard"

# ---- X2 ----
dtor="$(printf '%s\n' "$body" | awk '/~AndroidUiProcessEnd\(\)/ { on = 1 } on { print } on && /^        }$/ { exit }')"
s=$(printf '%s\n' "$dtor" | grep -nF 'settings.sync();' | head -1 | cut -d: -f1)
e=$(printf '%s\n' "$dtor" | grep -nF '::_exit(code);' | head -1 | cut -d: -f1)
if [ -z "$s" ] || [ -z "$e" ] || [ "$s" -ge "$e" ]; then bad "X2: the ending must sync the settings, then _exit(code)"; fi
printf '%s\n' "$body" | grep -qF 'return androidUiProcessEnd.code = app.exec();' \
    || bad "X2: the Android return must hand main's result to the ending"

[ "$fail" -eq 0 ] && echo "android ui exit wiring: OK"
exit "$fail"
