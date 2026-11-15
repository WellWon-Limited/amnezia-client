#!/bin/sh
# Builds the offline replay of tester journals through the real TribeDataWatch and runs it.
# Usage: run_tribe_data_watch_replay.sh <journal.tsv> [replay options]
# The journal is private tester data: it is read where it lies; the tool prints aggregates only.
# The binary is cached in $TRIBE_REPLAY_CACHE (default: a temporary directory removed on exit).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
if [ -n "${TRIBE_REPLAY_CACHE:-}" ]; then
    work=$TRIBE_REPLAY_CACHE
    mkdir -p "$work"
else
    work=$(mktemp -d "${TMPDIR:-/tmp}/tribe-data-watch-replay.XXXXXX")
    trap 'rm -rf "${work:?}"' EXIT
fi
bin="$work/tribe-data-watch-replay"
if [ ! -x "$bin" ] || [ "$here/TribeDataWatchReplay.swift" -nt "$bin" ] || [ "$here/../tribe/TribeDataWatch.swift" -nt "$bin" ]; then
    # swiftc allows top-level statements only in main.swift
    cp "$here/TribeDataWatchReplay.swift" "$work/main.swift"
    xcrun swiftc -O "$here/../tribe/TribeDataWatch.swift" "$work/main.swift" -o "$bin"
fi
"$bin" "$@"
