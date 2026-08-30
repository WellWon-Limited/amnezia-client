#!/bin/bash
# Extract one scalar from the top-level launchctl job dictionary. launchctl
# also prints nested coalition/jetsam dictionaries with their own `state =`
# fields, so an unscoped awk match is not an identity/health proof.
set -euo pipefail

FIELD="${1:-}"
case "$FIELD" in path|program|state|pid) ;; *) exit 64 ;; esac

/usr/bin/awk -v requested="$FIELD" '
function indentation(line, prefix) {
    prefix = line
    sub(/[^ \t].*$/, "", prefix)
    return length(prefix)
}
BEGIN { top_indent = -1; matches = 0 }
$1 == "path" && $2 == "=" && top_indent < 0 {
    top_indent = indentation($0)
}
top_indent >= 0 && indentation($0) == top_indent \
        && $1 == requested && $2 == "=" {
    value = $3
    matches++
}
END {
    if (matches != 1 || value == "") exit 2
    print value
}
'
