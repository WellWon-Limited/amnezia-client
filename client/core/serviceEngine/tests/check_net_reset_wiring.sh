#!/bin/bash
# AVPN (android5 H1/H3, 21.11; reviews of 0e31a2571 and 5c354b603): the GUI thread never waits for Qt's HTTP thread, and
# after a tunnel transition no request can use a connection opened before it. Qt 6.11.1: clearConnectionCache() and the
# destruction of a QNetworkAccessManager wait for its HTTP thread on the caller's thread (up to 5 s) while that thread may
# wait for the GUI (BlockingQueuedConnection). The design (NetAwait.h TribeNetworkAccessManager): one plain manager per
# tunnel generation behind the facade every holder keeps; old generations are retired on a retirement thread. Behaviour:
# api_transition_check. What is checked here is where it is wired - each line fails if reverted:
#   N1  with the engine, nothing in the client clears Qt's connection cache or deletes a QNetworkAccessManager;
#   N2  the facade: every request on the current generation (never on the facade's own HTTP thread), requests untouched
#       (no peer name, no pool attribute), a transition drops the current generation, aborts on a later turn, and a
#       generation is destroyed only after a move to the retirement thread;
#   N3  one owner: the app's manager is the facade; only the native-state handler resets, on newApiGeneration; upstream's
#       Connected does nothing with the engine; the foreground handlers run no synchronous network wait;
#   N4  AVPN_ENGINE=OFF is upstream: a plain QNetworkAccessManager and upstream's clear on Connected, no avpn:: symbol.
# Needs unifdef (macOS: /usr/bin/unifdef). Run by the check sweep (every check_*.sh of this directory).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ENGINE="$(cd "$HERE/.." && pwd)"
CLIENT="$(cd "$HERE/../../.." && pwd)"
fail=0
bad() { echo "FAIL: $1"; fail=1; }
code() { grep -v '^[[:space:]]*//' "$1" | sed 's#[[:space:]]//.*##' || true; }
body() { code "$1" | awk -v sig="$2" 'index($0, sig) == 1 { on = 1 } on { print } on && /^}$/ { exit }'; }
mbody() { code "$1" | awk -v sig="$2" 'index($0, sig) { on = 1 } on { print } on && /^    }$/ { exit }'; }
has() { printf '%s\n' "$1" | grep -F -- "$2" > /dev/null; }
command -v unifdef > /dev/null || { echo "FAIL: unifdef is needed"; exit 1; }
# the source as the compiler sees it with AVPN_ENGINE ON / OFF (unifdef exits 1 when it changed something)
view() { local rc=0; unifdef "$1" "$2" > "$VIEW" || rc=$?; [ "$rc" -le 1 ] || { echo "FAIL: unifdef $2"; exit 1; }; code "$VIEW"; }
VIEW="$(mktemp /tmp/net_reset_wiring.XXXXXX)"
trap 'rm -f -- "$VIEW"' EXIT

NET="$ENGINE/NetAwait.h"
FACADE="$ENGINE/AvpnEngineQml.cpp"
UI="$CLIENT/ui/controllers/connectionUiController.cpp"
APP="$CLIENT/amneziaApplication.cpp"

# ---- N1 ----
for f in $(grep -rlE --include=*.cpp --include=*.h --include=*.mm 'clearConnectionCache\(\)|delete (m_)?nam\b|nam->deleteLater' "$CLIENT" \
             | grep -v '/tests/' | grep -v '/3rd' || true); do
    view -DAVPN_ENGINE_ENABLED=1 "$f" | grep -qE 'clearConnectionCache\(\)|delete (m_)?nam\b|nam->deleteLater' \
        && bad "N1: $f clears Qt's connection cache or deletes a QNAM with the engine (the GUI would wait for the HTTP thread)"
done

# ---- N2 ----
create="$(mbody "$NET" 'QNetworkReply *createRequest(Operation op, const QNetworkRequest &request')"
has "$create" 'QNetworkAccessManager *gen = current();' && has "$create" 'gen->get(req);' \
    || bad "N2: every request must run on the current generation's manager"
has "$create" 'QNetworkAccessManager::createRequest(' && bad "N2: the facade must never run a request itself (its own HTTP thread)"
code "$NET" | grep -qE 'setPeerVerifyName|ConnectionCacheExpiryTimeoutSecondsAttribute' \
    && bad "N2: requests must reach Qt untouched (no peer name, no pool attribute)"
begin="$(mbody "$NET" 'void beginGeneration(bool abortInFlight)')"
has "$begin" 'std::exchange(m_current, nullptr)' || bad "N2: a transition must end the current generation"
first_turn="$(printf '%s\n' "$begin" | grep -nF 'QTimer::singleShot(0, this,' | head -1 | cut -d: -f1)"
at="$(printf '%s\n' "$begin" | grep -nF 'r->abort();' | head -1 | cut -d: -f1)"
[ -n "$first_turn" ] && [ -n "$at" ] && [ "$at" -gt "$first_turn" ] || bad "N2: the abort must run on a later turn"
retire="$(mbody "$NET" 'static void retire(QNetworkAccessManager *gen)')"
moved="$(printf '%s\n' "$retire" | grep -nF 'gen->moveToThread(apiRetirementThread());' | head -1 | cut -d: -f1)"
deleted="$(printf '%s\n' "$retire" | grep -nF 'gen->deleteLater();' | head -1 | cut -d: -f1)"
[ -n "$moved" ] && [ -n "$deleted" ] && [ "$deleted" -gt "$moved" ] \
    || bad "N2: a generation must be moved to the retirement thread before it is deleted"
idle="$(mbody "$NET" 'void retireIfIdle(QNetworkAccessManager *gen)')"
has "$idle" 'if (gen == m_current || !it->isEmpty())' || bad "N2: a generation retires only when it is old and its replies are gone"
code "$NET" | grep -qE '^[[:space:]]*(delete gen|delete m_current)' && bad "N2: a generation must never be deleted on the GUI thread"

# ---- N3 ----
has "$(view -DAVPN_ENGINE_ENABLED=1 "$APP")" 'm_nam = new avpn::TribeNetworkAccessManager(this);' \
    || bad "N3: the app's shared manager must be the facade"
has "$(code "$FACADE")" 'if (m_nam && newApiGeneration(observedTunnelOf(m_lastTunnelState), observedTunnelOf(s))) {' \
    && has "$(code "$FACADE")" 'avpn::resetApiConnections(m_nam);' \
    || bad "N3: the native-state handler must start a new generation on newApiGeneration"
calls="$(grep -rlE --include=*.cpp --include=*.h --include=*.mm 'resetApiConnections\(' "$CLIENT" | grep -v '/tests/' | grep -v '/3rd' \
           | grep -vxF "$NET" || true)"
[ "$calls" = "$FACADE" ] || bad "N3: only the native-state handler may reset the API connections (found: $calls)"
ui_on="$(view -DAVPN_ENGINE_ENABLED=1 "$UI")"
printf '%s\n' "$ui_on" | grep -qE 'networkManager\(\)|resetApiConnections|clearConnectionCache' \
    && bad "N3: upstream's Connected must leave the API connections to the engine"
fg="$(code "$FACADE" | awk '/&QGuiApplication::applicationStateChanged, this,/{f=1} f{print} f&&/^    }\);$/{f=0}')"
[ -n "$fg" ] || bad "N3: the foreground handlers were not found"
printf '%s\n' "$fg" | grep -qE 'awaitReply\(|QEventLoop|\.exec\(' && bad "N3: the foreground return must not wait on the network"

# ---- N4 ----
app_off="$(view -UAVPN_ENGINE_ENABLED "$APP")"
has "$app_off" 'm_nam = new QNetworkAccessManager(this);' || bad "N4: OFF must create upstream's QNetworkAccessManager"
ui_off="$(view -UAVPN_ENGINE_ENABLED "$UI")"
has "$ui_off" 'amnApp->networkManager()->clearConnectionCache();' || bad "N4: OFF must keep upstream's clear on Connected"
printf '%s\n%s\n' "$app_off" "$ui_off" | grep -qE 'avpn::|NetAwait\.h' && bad "N4: OFF must not name the overlay"

[ "$fail" = "0" ] && echo "check_net_reset_wiring: OK"
exit "$fail"
