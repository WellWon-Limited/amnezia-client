#!/bin/bash
# AVPN (owner road 26.11, S1 / journal J2): a Scanner row is the person's exact choice of server AND transport. The rules
# are pure (DebugSnapshot.h serverTapSwitchesModeToAuto, scanRowEndOf - facade_policy_check s1ExactRowWinsOverTheMode;
# ServiceEngine::modeAllowsExactPath - path_integration_check 6a; the machine's connectRefused("") - scan_core_check
# S1 rule 2). AvpnEngineQml.cpp has no unit harness, so where they are wired is checked here - each line fails if reverted:
#   E1  the row tap pins as an exact row, and the one switch of the mode (pinServer) asks whether the attempt ranks the
#       row now and would in Auto (review C4: no switch for a row Auto would not dial either);
#   E2  the engine answers with the pool's own admission (poolCandidate, the one pathPool uses) and path::modeAllows;
#   E3  the attempt that ended inside connect() is remembered before its result is judged, and that result ends the
#       row's request without a verdict (connectRefused(""), never exactRowFailed / attemptEnded).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
SE="$HERE/.."
FAC="$SE/AvpnEngineQml.cpp"
ENG="$SE/ServiceEngine.cpp"
fail=0
bad() { echo "FAIL: $1"; fail=1; }
code() { grep -v '^[[:space:]]*//' "$1" | sed 's#[[:space:]]//.*##' || true; }
body_of() { code "$2" | awk -v start="$1" 'index($0, start) == 1 { on = 1 } on { print } on && /^}/ { exit }'; }
has() { printf '%s\n' "$1" | grep -F -- "$2" > /dev/null; }

# ---- E1 ----
tap="$(body_of 'void AvpnEngineQml::connectToNode(' "$FAC")"
has "$tap" 'if (!pinServer(nodeId, err, /*exactRow=*/true)) {' || bad "E1: the Scanner row must be pinned as an exact row"
pin="$(body_of 'bool AvpnEngineQml::pinServer(const QString &nodeId, QString &err, bool exactRow)' "$FAC")"
printf '%s\n' "$pin" | tr -s ' \n' ' ' | grep -qF 'avpn::serverTapSwitchesModeToAuto(pinned, err, exactRow, pinned && m_engine.exactPathRanked(nodeId, m_engine.transportMode()), m_engine.exactPathRanked(nodeId, avpn::TransportMode::Auto))' \
    || bad "E1: the mode switch must ask whether the attempt ranks the row now and in Auto"
has "$pin" 'setTransportMode(QStringLiteral("auto"));' || bad "E1: the switch itself stays in pinServer"
[ "$(code "$FAC" | grep -cF 'transport_mode_auto why=server_tap')" = "1" ] || bad "E1: one owner of the server-tap switch"

# ---- E2 ----
rule="$(body_of 'bool ServiceEngine::exactPathRanked(const QString &nodeId, TransportMode mode) const' "$ENG")"
has "$rule" 'poolCandidate(*n, path::UserChoice::exactPath(nodeId));' && has "$rule" 'return c && path::modeAllows(c->kind, mode);' \
    || bad "E2: the exact path must be judged by the pool's own admission and the mode rule"
pool="$(body_of 'QList<path::PathCandidate> ServiceEngine::pathPool() const' "$ENG")"
has "$pool" 'if (std::optional<path::PathCandidate> c = poolCandidate(n, m_choice))' || bad "E2: the pool must use the same admission"

# ---- E3 ----
start="$(code "$FAC" | awk '/settleOperation\("attempt_not_started"\);/{f=1} f{print} f&&/syncAttempt\(\);/{exit}')"
has "$start" 'm_notStartedAttempt = endedAttempt;' || bad "E3: the attempt that ended inside connect() must be remembered before its result is judged"
has "$(code "$FAC")" 'if (avpn::scanRowEndOf(r->attempt, m_notStartedAttempt) == avpn::ScanRowEnd::NoVerdict)' \
    && has "$(code "$FAC")" 'endScanRowRequestNotStarted();' || bad "E3: the result of a not-started attempt must end the row without a verdict"
ns="$(body_of 'void AvpnEngineQml::endScanRowRequestNotStarted()' "$FAC")"
has "$ns" 'm_scanner->connectRefused(QString());' || bad "E3: a not-started row request ends with connectRefused(\"\")"
printf '%s\n' "$ns" | grep -qE 'exactRowFailed|attemptEnded|connectFailed' && bad "E3: a not-started row request must not be a verdict"

[ "$fail" = "0" ] && echo "check_scan_row_exact_tap_wiring: OK"
exit "$fail"
