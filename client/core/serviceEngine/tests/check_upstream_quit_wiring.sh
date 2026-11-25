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
[ "$fail" = 0 ] && echo "check_upstream_quit_wiring: ok"
exit "$fail"
