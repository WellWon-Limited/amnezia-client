#!/bin/bash
# AVPN (android5 H1/H3, 21.11): after a return from the background with requests in flight the app's main thread stood
# ~5 s right after the native state: the tunnel transition's QNetworkAccessManager::clearConnectionCache() waits on the
# caller's thread for Qt's HTTP thread (destroyThread: quit + wait up to 5 s). The behaviour is tested with a real QNAM
# (api_transition_check ApiTransitionNoWaitTest); what is checked here is where it is wired - each line fails if reverted:
#   N1  nobody calls clearConnectionCache() directly - only NetAwait.h's clearCacheWhenIdle, once no request runs;
#   N2  resetApiConnections does nothing inside the caller: the abort and the drop run on a later event-loop turn;
#   N3  the native-state handler and upstream's ConnectionUiController go through resetApiConnections; the foreground
#       return path of the facade runs no synchronous network wait (awaitReply / a nested QEventLoop).
# Run by the check sweep (every check_*.sh of this directory).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ENGINE="$HERE/.."
CLIENT="$(cd "$HERE/../../.." && pwd)"
fail=0
bad() { echo "FAIL: $1"; fail=1; }
code() { grep -v '^[[:space:]]*//' "$1" || true; }
body() { code "$1" | awk -v sig="$2" 'index($0, sig) == 1 { on = 1 } on { print } on && /^}$/ { exit }'; }
has() { printf '%s\n' "$1" | grep -F -- "$2" > /dev/null; }

NET="$ENGINE/NetAwait.h"
FACADE="$ENGINE/AvpnEngineQml.cpp"
UI="$CLIENT/ui/controllers/connectionUiController.cpp"

# ---- N1 ----
for f in $(grep -rl --include=*.cpp --include=*.h --include=*.mm 'clearConnectionCache()' "$CLIENT" \
             | grep -v '/tests/' | grep -v '/3rd' | grep -v '/NetAwait.h$' || true); do
    code "$f" | grep -qF 'clearConnectionCache()' && bad "N1: clearConnectionCache() called outside NetAwait.h: $f"
done
idle="$(body "$NET" 'inline void clearCacheWhenIdle(QNetworkAccessManager *nam)')"
has "$idle" 'if (!runningReplies(nam).isEmpty()) {' && has "$idle" 'nam->clearConnectionCache();' \
    || bad "N1: the drop must wait for an idle QNAM"

# ---- N2 ----
reset="$(body "$NET" 'inline void resetApiConnections(QNetworkAccessManager *nam, bool clearCache, bool abortInFlight)')"
first_turn="$(printf '%s\n' "$reset" | grep -nF 'QTimer::singleShot(0, nam,' | head -1 | cut -d: -f1)"
for step in 'r->abort();' 'detail::clearCacheWhenIdle(nam);'; do
    at="$(printf '%s\n' "$reset" | grep -nF -- "$step" | head -1 | cut -d: -f1)"
    [ -n "$first_turn" ] && [ -n "$at" ] && [ "$at" -gt "$first_turn" ] || bad "N2: '$step' must run on a later turn"
done

printf '%s\n' "$reset" | grep -qF 'clearConnectionCache()' && bad "N2: resetApiConnections must not drop the cache itself"

# ---- N3 ----
has "$(code "$FACADE")" 'avpn::resetApiConnections(m_nam, net.clearCache, net.abortInFlight);' \
    || bad "N3: the native-state handler must reset through resetApiConnections"
has "$(code "$UI")" 'avpn::resetApiConnections(amnApp->networkManager(), /*clearCache=*/true, /*abortInFlight=*/true);' \
    || bad "N3: upstream's Connected must reset through resetApiConnections"
fg="$(code "$FACADE" | awk '/&QGuiApplication::applicationStateChanged, this,/{f=1} f{print} f&&/^    }\);$/{f=0}')"
[ -n "$fg" ] || bad "N3: the foreground handlers were not found"
printf '%s\n' "$fg" | grep -qE 'awaitReply\(|QEventLoop|\.exec\(' && bad "N3: the foreground return must not wait on the network"

[ "$fail" = "0" ] && echo "check_net_reset_wiring: OK"
exit "$fail"
