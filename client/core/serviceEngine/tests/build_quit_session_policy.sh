#!/bin/bash
# Round mac-B review M2: build + run tests/quit_session_policy_check.cpp - the macOS quit hands only an UP AmneziaWG
# session to the daemon (QuitSessionPolicy.h, pure; no Qt needed).
#   --mutate : each rule broken in a copy of the header must fail the check ("rule-d0f0b0f8b" = every AmneziaWG session
#              released whatever its state, the rule of d0f0b0f8b).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SE="$(cd "$HERE/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/tribe-quit-policy.XXXXXX")"
trap 'rm -rf -- "${WORK:?}"' EXIT
build() { clang++ -std=c++17 -Wall -Wextra -I"$1" -I"$SE" "$HERE/quit_session_policy_check.cpp" -o "$2"; }
if [ "${1:-}" = "--mutate" ]; then
  caught=0; missed=0; total=0
  while IFS='|' read -r name from to; do
    total=$((total + 1)); dir="$WORK/m-$name"; mkdir -p "$dir"
    FROM="$from" TO="$to" python3 -I -c 'import os,sys; s=open(sys.argv[1]).read(); f=os.environ["FROM"]; assert s.count(f)==1; open(sys.argv[2],"w").write(s.replace(f, os.environ["TO"]))' \
      "$SE/QuitSessionPolicy.h" "$dir/QuitSessionPolicy.h" || { echo "$name NOT APPLIED"; missed=$((missed + 1)); continue; }
    build "$dir" "$dir/check"
    if "$dir/check" >"$dir/run.log" 2>&1; then echo "$name MISSED"; missed=$((missed + 1)); else echo "$name caught: $(grep -m1 FAIL "$dir/run.log")"; caught=$((caught + 1)); fi
  done <<'LIST'
rule-d0f0b0f8b|    if (daemonHeldSession && sessionUp)|    if (daemonHeldSession)
xray-released|    if (daemonHeldSession && sessionUp)|    if (sessionUp)
adopted-ended|    if (!hasProtocol)|    if (!hasProtocol && !sessionUp)
LIST
  echo ">>> mutations: $total, caught $caught, missed $missed"
  [ "$missed" -eq 0 ]; exit $?
fi
build "$SE" "$WORK/quit_session_policy_check"
"$WORK/quit_session_policy_check"
