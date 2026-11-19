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
CLIENT="$HERE/../../.."
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

# ---- Path engine (design 2026-11-17, coordinator 18.11): one judge of a start ---------------------------------------
# The native no longer tells a no-handshake fact for the app's start (the attempt owner's own deadline judges it), the
# facade does not listen for one, and no transport ban, attempt exclusion, network memory or picker of the engine
# remains - every choice of a path is the owner's (PathSelect through AttemptOwner).
[ "$(count "$CONTROLLER" 'handshakeNeverCompleted')" = "0" ] || bad "PE: the native still tells a no-handshake fact"
[ "$(count "$FACADE" 'handshakeNeverCompleted')" = "0" ] || bad "PE: the facade still listens to a no-handshake fact"
for token in 'm_awgBanned' 'bannedByAttempt' 'pickTransport(' 'm_attemptExcluded' 'networkMemoryCandidate' 'hintedCandidate' \
             'requestSwitch(' 'expireSwitch(' 'm_failedThisSession' 'm_transportHistory'; do
    [ "$(count "$ENGINE_CPP" "$token")" = "0" ] || bad "PE: the engine still has a second owner of a choice ($token)"
done
has "$(body "$ENGINE_CPP" 'bool ServiceEngine::connect(QString &error)')" 'feedOwner(path::AttemptEvent::userStart(' \
    || bad "PE: connect() must begin an attempt of the owner"
for token in 'm_startAttempts' 'startRetryBackoffMs' 'surrenderIfDataPlaneDead' 'rememberNetworkPath' 'onSwitchDeadline' 'startWatchdogMs'; do
    [ "$(count "$FACADE" "$token")" = "0" ] || bad "PE: the facade still runs a replaced mechanism ($token)"
done
has "$(body "$FACADE" 'void AvpnEngineQml::reconcile()')" 'if (m_engine.attemptRunning() || m_engine.state() == avpn::EngineState::Switching) {' \
    || bad "PE: reconcile must leave a running attempt to its owner"
[ "$(code "$ENGINE/TunnelWatchResume.h" | grep -cF 'm_ops.reenterVerifying()')" = "1" ] || bad "§33: reenterVerifying has more than one caller in TunnelWatchResume"
[ "$(code "$FACADE" | grep -cF 'm_engine.reenterVerifying()')" = "1" ] || bad "§33: the facade calls reenterVerifying outside the hand-over's op"

# Coordinator 18.11 (c): the Scanner hears a network change when the path engine's network generation moved (one
# rule with the attempt owner) or the network's key as the Scanner reads it moved (device round air9 19.11 10:08: the
# key completed with the same generation, the cached result never came back) - scanNetworkNoticeDue, tested in
# facade_policy_check; our own tunnel going up or down is compared once it settled.
scan_net="$(code "$FACADE" | awk '/^void AvpnEngineQml::scanNotifyNetwork\(\)/{f=1} f{print} f&&/^}/{exit}')"
has "$scan_net" 'networkChangeIsOwnTunnel(' && has "$scan_net" 'm_engine.observeNetwork(currentNetworkObservation());' \
    && has "$scan_net" 'if (!scanNetworkNoticeDue(before, m_engine.network().generation, m_scanNetKeyTold, key))' \
    && has "$scan_net" 'const ScanNetFacts f = m_scanAdapter->network();' && has "$scan_net" 'm_scanNetKeyTold = key;' \
    || bad "(c): scanNotifyNetwork must filter our own tunnel and notify on a new generation or a new Scanner key"
# Review E1/E2 of 18.11: the facade drops obsolete native events first and settles its operation in one place.
for slot in 'void AvpnEngineQml::onConnectionStateChanged(' 'void AvpnEngineQml::onVpnProtocolError('; do
    first="$(code "$FACADE" | awk -v s="$slot" 'index($0,s)==1{f=1;n=0} f{n++; if(n>1 && $0 !~ /^[{[:space:]]*$/){print; exit}}')"
    has "$first" 'm_engine.nativeEventStale(m_tunnel.nativeLegSeen())' || bad "E2: $slot must drop an obsolete native event first"
done
[ "$(code "$FACADE" | grep -cF 'm_opInFlight = false;')" = "1" ] || bad "E1: the operation latches are released only in settleOperation"

# Stage 2: the Scanner's proven rows are probe proofs in the one ledger; a whoami we cancelled is no evidence.
has "$(code "$FACADE")" 'scanner->onResultsSaved = [this](const avpn::ScanCachedResult &c) {' \
    && has "$(code "$FACADE")" 'm_engine.recordProbeProof(node, QStringLiteral("scanner"))' \
    || bad "stage 2: the Scanner's results must reach the path engine's ledger"
has "$(code "$ENGINE/TribeScanner.cpp")" 'onResultsSaved(c);' || bad "stage 2: the Scanner must hand its saved results over"
has "$(code "$FACADE")" 'if (r->error() == QNetworkReply::OperationCanceledError && !o.timedOut) {' \
    || bad "stage 2: a whoami cancelled by our own reset must be no evidence (devicectl relaunch, net_error 5)"

# Device round 4: R1 the attribution gate before a check failure reaches the ledger; R3 a Scanner row is one request;
# R5 the button below the orb follows the orb's own stop state; R6 the empty-ledger control file is dev-only.
has "$(code "$FACADE")" 'const avpn::CheckBlame blame = avpn::checkFailureBlame(' || bad "R1: finishVerify must ask checkFailureBlame"
has "$(code "$ENGINE/ServiceEngine.cpp")" 'feedOwner(path::AttemptEvent::pathFailed(nowMs(), m_owner.currentLeg(), o));' \
    || bad "R1: a provider start failure must go through startFailureOutcome"
has "$(code "$FACADE")" 'endExactRowRequest(r->connected);' || bad "R3: the end of a Scanner row's request must restore or demote the choice"
has "$(code "$CLIENT/ui/qml/Tribe/Pages/PageConnectTribe.qml")" ': root.engineOwnStopping ? qsTr("Отключаемся…")' \
    && [ "$(grep -c 'root.engineOwnStopping ? qsTr("Отключаемся…")' "$CLIENT/ui/qml/Tribe/Pages/PageConnectTribe.qml")" = "2" ] \
    || bad "R5: the caption and the button say «Отключаемся…» from the orb's own state only"
awk '/#ifdef AVPN_DEV_TOOLS/{f=1} f&&/tribe-reset-ledger/{print "ok"; exit} f&&/#endif/{exit}' "$FACADE" | grep -q ok \
    || bad "R6: the empty-ledger control file must exist only in AVPN_DEV_TOOLS builds"

# S1 (device round 5): every Scanner row request that does not connect ends through endScanRowRequest - the owner's
# failed result and a seat-first failure with the live tunnel kept; the seat client follows the request's route.
has "$(code "$FACADE")" 'endScanRowRequest(QString(), "attempt_failed");' \
    && has "$(code "$FACADE")" 'endScanRowRequest(nodeId, "seat_first_failed");' \
    || bad "S1: a Scanner row request must end on the owner's failure and on a seat-first failure"
[ "$(code "$FACADE" | grep -c 'm_scanner->attemptEnded();')" -le 2 ] || bad "S1: the row's end is told from one function (and the chain observer)"
has "$(code "$FACADE")" 'm_tunnel.configureUpstream(m_nam, [this]() { return m_configSvc ? m_configSvc->activeBaseUrl() : m_baseUrl; },' \
    || bad "S1: the seat client must take the edge of the route the request takes now"

# B1 (race measurement): a stop that finds nothing native (the race prelude) settles at once through settleOperation.
stop_fn="$(code "$FACADE" | awk '/^void AvpnEngineQml::guardedStop\(const char \*why\)/{f=1} f{print} f&&/^}/{exit}')"
l1="$(printf '%s\n' "$stop_fn" | grep -nF 'avpn::stopFindsNothingNative(observedTunnelOf(m_lastTunnelState), m_engine.ownerHoldsNativeLeg())' | head -1 | cut -d: -f1)"
l2="$(printf '%s\n' "$stop_fn" | grep -nF 'settleOperation("stop_nothing_native");' | head -1 | cut -d: -f1)"
l3="$(printf '%s\n' "$stop_fn" | grep -nF 'm_tunnel.down();' | head -1 | cut -d: -f1)"
{ [ -n "$l1" ] && [ -n "$l2" ] && [ -n "$l3" ] && [ "$l1" -lt "$l2" ] && [ "$l2" -lt "$l3" ]; } \
    || bad "B1: a stop with nothing native must settle before any native stop is asked"

# R3 + F2 (reviews of 141): a Scanner row's request is ONE object (avpn::ExactRowRequest: the exact row, the choice
# before it, the live session before it). It is set in one place - pinAndReconnectImpl, right after its intent move -
# and ended by noteIntentChange (any other action), by the owner's result (endExactRowRequest) or by the person's
# stop (the choice from before the tap comes back); no second flag holds "the row is exact".
ni_fn="$(code "$FACADE" | awk '/^void AvpnEngineQml::noteIntentChange\(\)/{f=1} f{print} f&&/^}/{exit}')"
printf '%s\n' "$ni_fn" | grep -qF 'm_exactReq.clear();' || bad "F2: noteIntentChange must end an exact row request"
[ "$(count "$FACADE" 'm_exactReq = *exact;')" = 1 ] || bad "F2: one place sets the exact row request"
[ "$(count "$FACADE" 'm_exactRow')" = 0 ] && [ "$(count "$FACADE" 'm_exactRestoreArmed')" = 0 ] \
    || bad "F2: no second holder of the row (m_exactRow / m_exactRestoreArmed)"
pin_fn="$(code "$FACADE" | awk '/^void AvpnEngineQml::pinAndReconnectImpl/{f=1} f{print} f&&/^}/{exit}')"
c1="$(printf '%s\n' "$pin_fn" | grep -nF 'noteIntentChange();' | head -1 | cut -d: -f1)"
c2="$(printf '%s\n' "$pin_fn" | grep -nF 'm_exactReq = *exact;' | head -1 | cut -d: -f1)"
{ [ -n "$c1" ] && [ -n "$c2" ] && [ "$c1" -lt "$c2" ]; } || bad "F2: the request is armed after the intent move (which drops an older one)"
stop_fn2="$(code "$FACADE" | awk '/^void AvpnEngineQml::stop\(\)/{f=1} f{print} f&&/^}/{exit}')"
d1="$(printf '%s\n' "$stop_fn2" | grep -nF 'const avpn::ExactRowRequest cancelledRow = m_exactReq;' | head -1 | cut -d: -f1)"
d2="$(printf '%s\n' "$stop_fn2" | grep -nF 'noteIntentChange();' | head -1 | cut -d: -f1)"
d3="$(printf '%s\n' "$stop_fn2" | grep -nF 'restoreChoiceBeforeRow(cancelledRow);' | head -1 | cut -d: -f1)"
{ [ -n "$d1" ] && [ -n "$d2" ] && [ -n "$d3" ] && [ "$d1" -lt "$d2" ] && [ "$d2" -lt "$d3" ]; } \
    || bad "F2: a stop must read the request, then end it, then restore the choice from before the tap"

# T1 (one starving rule): both data checks - own (whoami) and provider (the probe) - feed the engine through the one
# first-byte watch and the one sink (behaviour: upstream_engine_check providerLegStarvedCheck).
has "$(body "$FACADE" 'void AvpnEngineQml::whoamiAttempt(int epoch)')" 'avpn::watchFirstByte(r, avpn::kWhoamiFirstByteShareMs, checkStarvedSink(epoch));' \
    || bad "T1: the own-server check's request must carry the first-byte watch"
has "$(body "$FACADE" 'void AvpnEngineQml::upstreamVerifyAttempt(int epoch)')" 'pr.onStarved = checkStarvedSink(epoch);' \
    || bad "T1: the provider check's request must carry the first-byte watch"
has "$(body "$ENGINE/UpstreamLeaseClient.cpp" 'void UpstreamLeaseClient::runProbe(')" 'watchFirstByte(r, pr.firstByteShareMs, pr.onStarved);' \
    || bad "T1: the probe request must arm the watch it was given"
[ "$(count "$FACADE" 'm_engine.noteCheckStarved(')" = 1 ] || bad "T1: the engine hears starving from the one sink only"

# BG (device log 13:22:02-13:23:18): the connect attempt and a seat release being resent hold iOS background time
# through the ONE platform hook (BackgroundTaskHook.h; behaviour: ios BackgroundTaskBookTests). The attempt: begun
# after connect() started it (guardedStart), level-synced on every change and at the end of syncAttempt (where the
# owner's result is taken); each seat release path begins on a resend and ends on its final answer; the iOS half
# runs on the one UIKit task of AvpnBackgroundGuard, not a second one.
[ "$(count "$FACADE" 'avpn::bgtask::begin(')" = 1 ] || bad "BG: the facade must begin the attempt's hold in one place"
[ "$(count "$FACADE" 'avpn::bgtask::end(')" = 1 ] || bad "BG: the facade must end the attempt's hold in one place"
has "$(body "$FACADE" 'void AvpnEngineQml::syncAttemptBgHold()')" 'm_engine.attemptRunning() || m_engine.isVerifying()' \
    || bad "BG: the hold must follow the attempt owner / the verifying engine"
has "$(body "$FACADE" 'bool AvpnEngineQml::syncAttempt()')" 'syncAttemptBgHold();' \
    || bad "BG: syncAttempt must end the hold when the owner's result is taken"
[ "$(count "$FACADE" 'syncAttemptBgHold)')" = 1 ] || bad "BG: every state change must sync the attempt's hold"
[ "$(count "$FACADE" 'syncAttemptBgHold(); // build 142: the attempt began')" = 1 ] || bad "BG: the start must sync the hold right after connect() began the attempt"
for f in UpstreamLeaseClient.cpp ScanApiClient.cpp; do
    [ "$(count "$ENGINE/$f" 'avpn::bgtask::begin(avpn::bgtask::Reason::Release')" = 1 ] || bad "BG: $f must begin a release hold when it schedules a resend"
    [ "$(count "$ENGINE/$f" 'avpn::bgtask::end(avpn::bgtask::Reason::Release')" -ge 2 ] || bad "BG: $f must end the release hold on every final outcome"
done
BGMM="$IOS/AvpnBackgroundGuard.mm"
[ "$(count "$BGMM" 'beginBackgroundTaskWithName')" = 1 ] || bad "BG: exactly one UIKit background task owner"
has "$(code "$BGMM")" 'taskBook()' || bad "BG: the hook must run on the task book"
for f in "$ENGINE"/*.cpp "$ENGINE"/*.h; do
    case "$f" in */BackgroundTaskHook.h) continue ;; esac
    [ "$(count "$f" 'UIApplication')" = 0 ] || bad "BG: shared code must not reference UIKit ($f)"
done

[ "$fail" = 0 ] && echo "check_lifecycle_142_wiring: OK" || echo "check_lifecycle_142_wiring: FAILED"
exit $fail
