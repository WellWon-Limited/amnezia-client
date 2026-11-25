#!/bin/bash
# AVPN (review of 2af7b3a52, finding 3, round mac-D3): the quit of the macOS / Windows GUI waits for the seat's release
# through the PRODUCTION hook - AvpnEngineQml::endUpstreamSessionOnQuit sets UpstreamQuitHooks::releaseSettled from the
# lease client's releasesSettled() and hands those hooks to runUpstreamQuit; runUpstreamQuit asks releaseSettled before
# it decides there is nothing to do. The host cases (upstream_engine_check) build the hooks by hand, so without this
# check they would still pass with the production wiring removed.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../../.." && pwd)"
ENG="$ROOT/client/core/serviceEngine/AvpnEngineQml.cpp"
UE="$ROOT/client/core/serviceEngine/UpstreamEngine.h"
fail=0
bad() { echo "FAIL: $*"; fail=1; }
body() { awk -v sig="$2" 'index($0, sig) == 1 { on = 1 } on { print } on && /^}$/ { exit }' "$1"; }
q="$(body "$ENG" 'void AvpnEngineQml::endUpstreamSessionOnQuit()')"
[ -n "$q" ] || bad "Q1: endUpstreamSessionOnQuit not found"
printf '%s\n' "$q" | grep -qF 'h.releaseSettled = [this]()' || bad "Q1: the quit does not set the releaseSettled hook"
printf '%s\n' "$q" | grep -qF 'c->releasesSettled()' || bad "Q1: the releaseSettled hook does not read the lease client's releasesSettled()"
printf '%s\n' "$q" | grep -qE 'avpn::runUpstreamQuit\(m_appExitKind, avpn::upstreamNodesEnabled\(\), upstreamSession, h\)' \
  || bad "Q2: the quit does not hand these hooks to runUpstreamQuit"
r="$(body "$UE" 'inline bool runUpstreamQuit(')"
first=$(printf '%s\n' "$r" | grep -nE 'upstreamQuitWaitsForRelease\(kind, upstreamNodesOn, h\)' | head -1 | cut -d: -f1)
ret=$(printf '%s\n' "$r" | grep -nF 'return false;' | head -1 | cut -d: -f1)
[ -n "$first" ] && [ -n "$ret" ] && [ "$first" -lt "$ret" ] || bad "Q3: runUpstreamQuit can return before it asks whether a release is pending"
grep -qF 'return kind != AppExitKind::Hide && upstreamNodesOn && h.releaseSettled && !h.releaseSettled();' "$UE" \
  || bad "Q3: the pending-release rule changed"
# Q4 (round mac-D4, review finding 5): once the exit has begun nothing new starts - one latch the facade sets at its
# first aboutToQuit handler, read where attempts start (guardedStart) and passed to the engine's gate (connect, every leg).
be="$(body "$ENG" 'void AvpnEngineQml::beginExit()')"
printf '%s\n' "$be" | grep -qF 'm_exiting = true;' && printf '%s\n' "$be" | grep -qF 'm_engine.setExiting();' || bad "Q4: beginExit does not latch the facade and the engine"
printf '%s\n' "$q" | grep -qF 'beginExit();' || bad "Q4: the quit path does not begin the exit before it pumps the event loop"
fq=$(grep -n 'beginExit(); // round mac-D4: the first aboutToQuit handler' "$ENG" | head -1 | cut -d: -f1)
first=$(grep -n 'QCoreApplication::aboutToQuit, this' "$ENG" | head -1 | cut -d: -f1)
[ -n "$fq" ] && [ -n "$first" ] && [ "$fq" -gt "$first" ] && [ $((fq - first)) -le 2 ] || bad "Q4: the first aboutToQuit handler does not begin the exit"
printf '%s\n' "$(body "$ENG" 'void AvpnEngineQml::guardedStart()')" | sed -n 2,4p | grep -qF 'if (m_exiting)' || bad "Q4: guardedStart does not read the latch first"
SE="$ROOT/client/core/serviceEngine/ServiceEngine.cpp"
printf '%s\n' "$(body "$SE" 'bool ServiceEngine::connect(QString &error)')" | grep -qF 'if (m_exiting) {' || bad "Q4: the engine's connect does not refuse once the exit has begun"
awk '/case path::EffectType::StartPath: \{/ { on = 1; n = 0 } on { n++; if ($0 ~ /if \(m_exiting\)/) found = 1; if (n > 3) on = 0 } END { exit found ? 0 : 1 }' "$SE" \
  || bad "Q4: a leg is raised without asking whether the exit has begun"

[ "$fail" = 0 ] && echo "check_upstream_quit_wiring: ok"
exit "$fail"
