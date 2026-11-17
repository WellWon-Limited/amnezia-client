#!/bin/bash
# AVPN build 142 (owner's iPhone, build 140, 16.11): the wiring of the lifecycle fixes that the pure rules'
# tests cannot reach. The RULES are tested by behaviour: facade_policy_check (decideScanCancel,
# decideAwgNoHandshake, verifyFailsOnHandshakeTimeout), tunnel_watch_check (decideAdoptedProofCheck and the
# hand-over object), transport_pick_check (the AmneziaWG ban on a real ServiceEngine) and the iOS controller
# harness (the native facts). What is checked here is where they are CALLED FROM - each line below fails
# if its call site is reverted (independent review, round 1: "the facade policy tests still pass if the
# production wiring is reverted").
#   S1/S2  the Scanner's cancel: latched on «Подключено» as the orb shows it; refused with no event loop;
#   S3+S5  one rule: the native tells every no-handshake timeout with its request's send time; the facade hands
#          a fresh one to handleNoHandshakeFact, which ends the session through our guarded stop (the ordinary
#          restart / failed start) after banning AmneziaWG where allowed; no special check of an adopted session;
#          the data check keeps its original guards; any action of the person lifts the ban; every pick and the
#          provider tier rule read the ban through its one reader.
# Run by the check sweep (every check_*.sh of this directory).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ENGINE="$HERE/.."
IOS="$(cd "$HERE/../../../platforms/ios" && pwd)"
fail=0
bad() { echo "FAIL: $1"; fail=1; }
code() { grep -v '^[[:space:]]*//' "$1" || true; }        # a file without full-line comments
count() { code "$1" | grep -cF -- "$2" || true; }
# The body of a C++ function: from its definition line to the first line that is exactly "}".
body() { code "$1" | awk -v sig="$2" 'index($0, sig) == 1 { on = 1 } on { print } on && /^}$/ { exit }'; }
has() { printf '%s\n' "$1" | grep -F -- "$2" > /dev/null; }  # fixed strings: the code is full of ( and *

FACADE="$ENGINE/AvpnEngineQml.cpp"
ENGINE_CPP="$ENGINE/ServiceEngine.cpp"
RESUME="$ENGINE/TunnelWatchResume.h"
CONTROLLER="$IOS/ios_controller.mm"

# ---- S1/S2 -------------------------------------------------------------------------------------------------
cancel="$(body "$FACADE" 'void AvpnEngineQml::scanCancelPendingConnect()')"
has "$cancel" 'scanOwnConnectShownConnected()' || bad "S1: the cancel latch is not «Подключено» as the orb shows it"
has "$cancel" 'QThread::currentThread()->loopLevel() > 0' || bad "S2: the cancel does not know whether the event loop runs"
has "$cancel" 'shownConnected, eventLoopRunning);' || bad "S2: decideScanCancel does not get the event-loop fact"
has "$(body "$FACADE" 'void AvpnEngineQml::scanSyncState()')" 'noteScanOwnConnectProgress(m_scanOwnConnect, scanOwnConnectShownConnected());' \
    || bad "S1: scanSyncState does not latch «Подключено» as the orb shows it"

# ---- S3 + S5: the one no-handshake rule (review round 3: no special check of an adopted session) ---------------
# The native tells every no-handshake timeout with its request's send time; the facade hands it to the one
# handler; the adopted session is never sent into the data check by this rule; the attempt guards of the data
# check are the originals (a stored native state is never a verdict).
[ "$(count "$CONTROLLER" 'emit handshakeNeverCompleted(m_handshakeTimeouts, sentMs);')" = "1" ] \
    || bad "S3/S5: the native does not tell the no-handshake timeout (once, with its number and send time)"
[ "$(count "$CONTROLLER" 'sendVpnExtensionMessage(tunnel, message, [this, gen, request, sentMs]')" = "1" ] \
    || bad "S3/S5: the status request does not carry its send time into the reply"
[ "$(count "$CONTROLLER" 'adoptedSessionUnproven')" = "0" ] && [ "$(count "$FACADE" 'adoptedSessionUnproven')" = "0" ] \
    || bad "S3: the special re-check of an adopted session is back"
has "$(code "$FACADE")" '&IosController::handshakeNeverCompleted, this,' || bad "S3/S5: the facade does not listen to the fact"
rule="$(body "$FACADE" 'void AvpnEngineQml::onHandshakeNeverCompleted(int timeouts, qint64 requestSentMs)')"
has "$rule" 'avpn::handleNoHandshakeFact(timeouts, m_engine.currentNodeId(), ops);' || bad "S3/S5: the facade bypasses the one handler"
has "$rule" 'in.fresh = avpn::nativeFactFresh(requestSentMs, freezeBoundaryMs());' || bad "S3/S5: the fact is not checked for freshness"
has "$rule" 'in.alreadyLeft = m_engine.awgBanned();' || bad "S5: 'already left' is not the engine's ban"
has "$rule" 'm_engine.banAwgForAttempt();' || bad "S5: the ban is not the engine's"
has "$rule" 'guardedStop("no_handshake");' || bad "S3/S5: the session does not end through our guarded stop"
has "$rule" 'reenterVerifying' && bad "S3: the rule sends the adopted session into the data check"
handler="$(code "$ENGINE/DebugSnapshot.h" | awk '/^inline NoHandshake handleNoHandshakeFact\(/ { on = 1 } on { print } on && /^}$/ { exit }')"
ban_line="$(printf '%s\n' "$handler" | grep -nF 'ops.banAwg();' | cut -d: -f1)"
end_line="$(printf '%s\n' "$handler" | grep -nF 'ops.endSession(in.ownStartInFlight);' | cut -d: -f1)"
[ -n "$ban_line" ] && [ -n "$end_line" ] && [ "$ban_line" -lt "$end_line" ] \
    || bad "S5: AmneziaWG is not banned before the session ends"
[ "$(count "$FACADE" 'failVerifyOnHandshakeTimeout')" = "0" ] && [ "$(count "$FACADE" 'verifyAttemptGoesOn')" = "0" ] \
    || bad "N4/M1: the data check judges a stored native state again"
for fn in 'void AvpnEngineQml::verifyAttempt(int epoch)' 'void AvpnEngineQml::whoamiAttempt(int epoch)'; do
    has "$(body "$FACADE" "$fn")" 'if (epoch != m_verifyEpoch || !m_engine.isVerifying() || m_lastTunnelState != Vpn::Connected)' \
        || bad "N4/M1: $fn lost its original guard"
done
[ "$(code "$ENGINE/TunnelWatchResume.h" | grep -cF 'm_ops.reenterVerifying()')" = "1" ] || bad "§33: reenterVerifying has more than one caller in TunnelWatchResume"
[ "$(code "$FACADE" | grep -cF 'm_engine.reenterVerifying()')" = "1" ] || bad "§33: the facade calls reenterVerifying outside the hand-over's op"
has "$(body "$FACADE" 'void AvpnEngineQml::noteIntentChange()')" 'm_engine.clearAwgBan();' \
    || bad "S5: an action of the person on the intent does not lift the ban"
# The ban: one piece of state, one reader, read by every pick.
[ "$(code "$ENGINE_CPP" | grep -cF 'm_awgBanned = ')" = "2" ] \
    || bad "S5: m_awgBanned is written outside banAwgForAttempt / the lift in connect() (and the header's clear/attempt)"
has "$(body "$ENGINE_CPP" 'const SubscriptionNode *ServiceEngine::pickTransport(')" 'if (bannedByAttempt(n))' \
    || bad "S5: pickTransport does not read the ban"
has "$(body "$ENGINE_CPP" 'const SubscriptionNode *ServiceEngine::hintedCandidate(')" 'bannedByAttempt(*n)' \
    || bad "S5: the row-tap hint does not read the ban"
has "$(body "$ENGINE_CPP" 'const SubscriptionNode *ServiceEngine::networkMemoryCandidate()')" 'bannedByAttempt(*n)' \
    || bad "S5: network memory does not read the ban"
has "$(body "$ENGINE_CPP" 'const SubscriptionNode *ServiceEngine::pickByMeasuredRtt(')" 'bannedByAttempt(n)' \
    || bad "S5: the legacy RTT picker does not read the ban"
has "$(body "$ENGINE_CPP" 'const SubscriptionNode *ServiceEngine::pickByWeight(')" 'bannedByAttempt(n)' \
    || bad "S5: the legacy weight picker does not read the ban"
has "$(code "$ENGINE_CPP")" '&& !m_attemptExcluded.contains(t->nodeId) && !bannedByAttempt(*t))' \
    || bad "S5: the interrupted-switch replay does not read the ban"
[ "$(code "$ENGINE_CPP" | grep -cF 'm_awgBanned && isOwnAwgNode(n)')" = "1" ] || bad "S5: the ban has more than one reader"
# N2 (review round 2): the provider tier rule sees the pool the picker sees - banned nodes are not candidates.
has "$(body "$ENGINE_CPP" 'UpstreamTierGate ServiceEngine::tierGate() const')" 'if (bannedByAttempt(n))' \
    && has "$(body "$ENGINE_CPP" 'UpstreamTierGate ServiceEngine::tierGate() const')" 'g.ineligible.insert(n.nodeId);' \
    || bad "N2: the provider tier rule does not read the ban"
has "$(code "$ENGINE/UpstreamTier.h")" 'if (!n || gate.ineligible.contains(n->nodeId))' || bad "N2: the tier rule does not drop ineligible nodes"
# N3: the ban yields (no Xray this start could take) BEFORE any pick of connect(), so the pin keeps priority.
conn="$(body "$ENGINE_CPP" 'bool ServiceEngine::connect(QString &error)')"
lift="$(printf '%s\n' "$conn" | grep -nF 'if (m_awgBanned && !xrayPickWithoutAwg()) {' | cut -d: -f1)"
pin="$(printf '%s\n' "$conn" | grep -nF 'pinnedCandidate()' | head -1 | cut -d: -f1)"
[ -n "$lift" ] && [ -n "$pin" ] && [ "$lift" -lt "$pin" ] || bad "N3: the ban is lifted after the pinned pick (or not at all)"

if [ "$fail" -ne 0 ]; then
    echo "check_lifecycle_142_wiring: FAILED"
    exit 1
fi
echo "check_lifecycle_142_wiring: OK"
