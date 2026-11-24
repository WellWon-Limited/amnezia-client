#!/bin/bash
# tribe-mac.sh - drive the Tribe VPN desktop app on a test Mac through its test command channel (development builds
# with AVPN_DEV_TOOLS=ON only: client/core/serviceEngine/DevControl.h, DevControlApp.h).
#
#   tribe-mac.sh [--timeout S] [--socket PATH] <ssh-target> <command> [json-args]
#   tribe-mac.sh [--timeout S] --socket PATH --local <command> [json-args]      (this machine: the host test only)
#
# Prints the reply line (one JSON object). Exit: 0 = "ok":true, 1 = "ok":false, 2 = usage, 3 = no channel (no socket,
# connect refused, no zsh socket module), 4 = no reply within the timeout, 5 = ssh failed.
# Examples:
#   tribe-mac.sh tribe-air state
#   tribe-mac.sh tribe-air choose '{"id":"a1b2c3d4"}'
#   tribe-mac.sh tribe-air wait '{"for":"verified","timeout_ms":45000}'
# Commands: help, state, connect, stop, nav {page}, servers, choose {id|row|name, kind?}, auto, mode {value},
# scan.open, scan.select {scope}, scan.start, scan.stop, scan.rows, scan.connect {row, ref?}, scan.back, window.show,
# shot {path?}, mark {text}, wait {for, timeout_ms}, quit.
#
# Transport on the target: /bin/zsh with its zsh/net/socket module (stock macOS). Not nc: the macOS nc has no -N or
# -q and shuts its sending side down at the end of its input, which the app reads as the client leaving - a `wait`
# would be cancelled at once. For a one-shot command other than wait, `printf '%s\n' "$json" | nc -U "$sock"` works.
set -u

usage() { sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }

TIMEOUT=""
SOCK=""
while [ $# -gt 0 ]; do
  case "$1" in
    --timeout) TIMEOUT="${2:-}"; shift 2 ;;
    --socket) SOCK="${2:-}"; shift 2 ;;
    -h|--help) usage ;;
    *) break ;;
  esac
done
[ $# -ge 2 ] || usage
TARGET="$1"; CMD="$2"; ARGS="${3:-}"
[ -n "$ARGS" ] || ARGS='{}'

printf '%s' "$CMD" | grep -Eq '^[a-z][a-z.]{0,31}$' || { echo "tribe-mac.sh: bad command '$CMD'" >&2; exit 2; }
case "$ARGS" in \{*\}) ;; *) echo "tribe-mac.sh: json-args must be one JSON object" >&2; exit 2 ;; esac
case "$SOCK" in *\'*) echo "tribe-mac.sh: a socket path with a quote" >&2; exit 2 ;; esac
[ "$TARGET" = "--local" ] && [ -z "$SOCK" ] && { echo "tribe-mac.sh: --local needs --socket" >&2; exit 2; }

# The reply's own deadline: a wait's timeout_ms + 10 s, else 20 s.
if [ -z "$TIMEOUT" ]; then
  TIMEOUT=20
  if [ "$CMD" = wait ]; then
    ms="$(printf '%s' "$ARGS" | sed -n 's/.*"timeout_ms"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p')"
    TIMEOUT=$(( ${ms:-60000} / 1000 + 10 ))
  fi
fi
printf '%s' "$TIMEOUT" | grep -Eq '^[0-9]+$' || { echo "tribe-mac.sh: bad --timeout" >&2; exit 2; }

ID="tm-$$-$RANDOM"
REQ="{\"id\":\"$ID\",\"cmd\":\"$CMD\",\"args\":$ARGS}"
REQ_B64="$(printf '%s' "$REQ" | base64 | tr -d '\n')"

# The client, run by /bin/zsh -f on the target (or here with --local); every value is base64 or digits.
read -r -d '' CLIENT <<EOF
REQ_B64='$REQ_B64'
T=$TIMEOUT
SOCK='$SOCK'
[[ -n \$SOCK ]] || SOCK="\$HOME/Library/Application Support/AVPN.ORG/AVPN/dev/control.sock"
zmodload zsh/net/socket 2>/dev/null || { print -u2 "tribe-mac: no zsh/net/socket module"; exit 3; }
[[ -S \$SOCK ]] || { print -u2 "tribe-mac: no channel socket (a development build running?): \$SOCK"; exit 3; }
zsocket "\$SOCK" 2>/dev/null || { print -u2 "tribe-mac: connect refused: \$SOCK"; exit 3; }
fd=\$REPLY
print -r -u \$fd -- "\$(print -r -- \$REQ_B64 | base64 --decode)"
if read -r -t \$T -u \$fd line; then
  print -r -- "\$line"
  exec {fd}>&-
  exit 0
fi
print -u2 "tribe-mac: no reply in \$T s"
exit 4
EOF

if [ "$TARGET" = "--local" ]; then
  OUT="$(printf '%s\n' "$CLIENT" | /bin/zsh -f -s)"; rc=$?
else
  OUT="$(printf '%s\n' "$CLIENT" | ssh -o BatchMode=yes -o ConnectTimeout=8 "$TARGET" '/bin/zsh -f -s')"; rc=$?
  [ "$rc" = 255 ] && { echo "tribe-mac.sh: ssh to $TARGET failed" >&2; exit 5; }
fi
[ "$rc" = 0 ] || exit "$rc"
printf '%s\n' "$OUT"
case "$OUT" in
  "{\"id\":\"$ID\",\"ok\":true,"*) exit 0 ;;
  *) exit 1 ;;
esac
