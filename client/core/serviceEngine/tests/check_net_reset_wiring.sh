#!/bin/bash
# AVPN (android5 H1/H3, 21.11; review of 0e31a2571): the GUI thread never waits for Qt's HTTP thread. Qt 6.11.1:
# clearConnectionCache() and the destruction of a QNetworkAccessManager quit the HTTP thread and wait for it on the
# caller's thread (up to 5 s), and the HTTP thread reports a TLS handshake to the GUI with a BlockingQueuedConnection -
# so a transition mid-handshake stood 5 s. The design (NetAwait.h): a per-generation connection key on every request,
# no idle pooled connection, no clear. Behaviour: api_transition_check ApiTransitionNoWaitTest (real QNAM, TLS on
# loopback). What is checked here is where it is wired - each line fails if reverted:
#   N1  nothing in the client calls clearConnectionCache() or deletes a QNetworkAccessManager (the GUI would wait);
#   N2  resetApiConnections only starts the next generation and aborts the requests in flight on a later turn;
#   N3  the app's shared QNAM is TribeNetworkAccessManager (every request gets the policy); the native-state handler and
#       upstream's Connected go through resetApiConnections; the foreground handlers run no synchronous network wait.
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
APP="$CLIENT/amneziaApplication.cpp"

# ---- N1 ----
for f in $(grep -rlE --include=*.cpp --include=*.h --include=*.mm 'clearConnectionCache\(\)|delete (m_)?nam\b|nam->deleteLater' "$CLIENT" \
             | grep -v '/tests/' | grep -v '/3rd' || true); do
    code "$f" | sed 's#//.*##' | grep -qE 'clearConnectionCache\(\)|delete (m_)?nam\b|nam->deleteLater' \
        && bad "N1: $f clears Qt's connection cache or deletes a QNAM (the GUI would wait for the HTTP thread)"
done

# ---- N2 ----
reset="$(body "$NET" 'inline void resetApiConnections(QNetworkAccessManager *nam, bool clearCache, bool abortInFlight)')"
has "$reset" 'nam->setProperty(kConnGeneration, nam->property(kConnGeneration).toULongLong() + 1);' \
    || bad "N2: a transition must start the next connection generation"
first_turn="$(printf '%s\n' "$reset" | grep -nF 'QTimer::singleShot(0, nam,' | head -1 | cut -d: -f1)"
at="$(printf '%s\n' "$reset" | grep -nF 'r->abort();' | head -1 | cut -d: -f1)"
[ -n "$first_turn" ] && [ -n "$at" ] && [ "$at" -gt "$first_turn" ] || bad "N2: the abort must run on a later turn"
policy="$(body "$NET" 'inline QNetworkRequest withConnectionPolicy(QNetworkRequest r, quint64 generation)')"
has "$policy" 'r.setAttribute(QNetworkRequest::ConnectionCacheExpiryTimeoutSecondsAttribute, 0);' \
    && has "$policy" 'r.setPeerVerifyName(r.url().host());' || bad "N2: every request must carry the connection policy"

# ---- N3 ----
has "$(code "$APP")" 'm_nam = new avpn::TribeNetworkAccessManager(this);' || bad "N3: the app's QNAM must apply the policy"
has "$(code "$FACADE")" 'avpn::resetApiConnections(m_nam, net.clearCache, net.abortInFlight);' \
    || bad "N3: the native-state handler must reset through resetApiConnections"
has "$(code "$UI")" 'avpn::resetApiConnections(amnApp->networkManager(), /*clearCache=*/true, /*abortInFlight=*/true);' \
    || bad "N3: upstream's Connected must reset through resetApiConnections"
fg="$(code "$FACADE" | awk '/&QGuiApplication::applicationStateChanged, this,/{f=1} f{print} f&&/^    }\);$/{f=0}')"
[ -n "$fg" ] || bad "N3: the foreground handlers were not found"
printf '%s\n' "$fg" | grep -qE 'awaitReply\(|QEventLoop|\.exec\(' && bad "N3: the foreground return must not wait on the network"

[ "$fail" = "0" ] && echo "check_net_reset_wiring: OK"
exit "$fail"
