#!/bin/bash
# AVPN (emulator round 26.11.2026, D1, Android): a swipe from recents ended the UI process with SIGABRT «FORTIFY:
# pthread_mutex_lock called on a destroyed mutex», 10 ms after «main() returned 0»: Qt's Android plugin calls exit() after
# main, and the C++ static destructors ran while system threads (the view layer's render pool) still waited on one of
# them. The UI process now ends with _exit once main's work is done (as iOS ends with _exit). Each line fails if reverted:
#   X1  main.cpp declares the Android ending first in main, under Q_OS_ANDROID only, so it runs after every other local
#       (~AmneziaApplication included);
#   X2  it syncs the settings, then _exit()s with main's own result (the return assigns the code);
#   X3  (round 2, F1) the activity's destroy for good ends the process before Qt's teardown, a configuration change
#       keeps Qt's path, and without the native the activity falls back to Qt;
#   X4  the native syncs the settings and marks the clean exit on its own thread, then _exit(0), waiting for nothing.
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

# ---- X3 (emulator round 2, F1) ---- the activity's destroy for good ends the process BEFORE Qt's teardown (its
# terminateQtNativeApplication froze in a three-thread wait); a configuration change keeps Qt's path; without the native,
# Qt's teardown as before.
ACT="$CLIENT/android/src/org/amnezia/vpn/AmneziaActivity.kt"
dest="$(code "$ACT" | awk '/override fun onDestroy\(\) \{/ { on = 1 } on { print } on && /^    }$/ { exit }')"
fd=$(printf '%s\n' "$dest" | grep -nF 'QtAndroidController.onActivityFinalDestroy()' | head -1 | cut -d: -f1)
sd=$(printf '%s\n' "$dest" | grep -nF 'super.onDestroy()' | head -1 | cut -d: -f1)
if [ -z "$fd" ] || [ -z "$sd" ] || [ "$fd" -ge "$sd" ]; then bad "X3: onDestroy must end the process before super.onDestroy()"; fi
printf '%s\n' "$dest" | grep -qF 'if (!isChangingConfigurations) {' || bad "X3: only a destroy for good may end the process"
printf '%s\n' "$dest" | grep -qF 'catch (e: UnsatisfiedLinkError)' || bad "X3: without the native half the activity must fall back to Qt"
grep -qF 'external fun onActivityFinalDestroy()' "$CLIENT/android/src/org/amnezia/vpn/qt/QtAndroidController.kt" \
    || bad "X3: QtAndroidController must declare onActivityFinalDestroy"

# ---- X4 ---- the native: registered optional; settings synced on the calling thread, a clean exit marked, then _exit -
# nothing that waits for another thread (no queued/blocking call, no event loop)
AC="$CLIENT/platforms/android/android_controller.cpp"
ac="$(code "$AC")"
printf '%s\n' "$ac" | grep -qF '{"onActivityFinalDestroy", "()V", reinterpret_cast<void *>(onActivityFinalDestroy)},' \
    || bad "X4: onActivityFinalDestroy must be registered"
nat="$(printf '%s\n' "$ac" | awk 'index($0, "void AndroidController::onActivityFinalDestroy(JNIEnv *env, jobject thiz)") == 1 { on = 1 } on { print } on && /^}$/ { exit }')"
s=$(printf '%s\n' "$nat" | grep -nF 'settings.sync();' | head -1 | cut -d: -f1)
c=$(printf '%s\n' "$nat" | grep -nF 'CrashGuard::instance().markCleanExit();' | head -1 | cut -d: -f1)
e=$(printf '%s\n' "$nat" | grep -nF '::_exit(0);' | head -1 | cut -d: -f1)
if [ -z "$s" ] || [ -z "$c" ] || [ -z "$e" ] || [ "$s" -ge "$e" ] || [ "$c" -ge "$e" ]; then
    bad "X4: the native must sync the settings and mark the clean exit before _exit(0)"
fi
printf '%s\n' "$nat" | grep -qE 'invokeMethod|BlockingQueued|QEventLoop|waitFor|QWaitCondition' \
    && bad "X4: the final destroy must not wait for another thread"

[ "$fail" -eq 0 ] && echo "android ui exit wiring: OK"
exit "$fail"
