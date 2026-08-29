#!/bin/bash
# Keep a closed SQL plugin surface and prove the deployed Mach-O closure.  A
# Qt deployment with no QtSql consumer legitimately has no sqldrivers folder;
# if Qt adds one, only its self-contained SQLite driver is accepted.
set -euo pipefail

APP="${1:?usage: $0 APP_BUNDLE}"
[ -d "$APP" ] || { echo "macOS app bundle is missing: $APP" >&2; exit 1; }
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
APP="$(cd "$APP" && pwd -P)"

executable_dir_for() {
    binary="$1"
    case "$binary" in
        *.appex/Contents/*)
            printf '%s\n' "${binary%%.appex/Contents/*}.appex/Contents/MacOS"
            ;;
        *) printf '%s\n' "$APP/Contents/MacOS" ;;
    esac
}

rpath_is_artifact_safe() {
    binary="$1"
    rpath="$2"
    case "$rpath" in
        /usr/lib/swift|/System/Library/*) return 0 ;;
        @loader_path) candidate="$(dirname "$binary")" ;;
        @loader_path/*) candidate="$(dirname "$binary")/${rpath#@loader_path/}" ;;
        @executable_path) candidate="$(executable_dir_for "$binary")" ;;
        @executable_path/*)
            candidate="$(executable_dir_for "$binary")/${rpath#@executable_path/}"
            ;;
        *) return 1 ;;
    esac
    parent="$(cd "$(dirname "$candidate")" 2>/dev/null && pwd -P)" || return 1
    canonical="$parent/$(basename "$candidate")"
    case "$canonical" in "$APP"|"$APP"/*) return 0 ;; *) return 1 ;; esac
}

# macdeployqt can retain stale Qt build-tree rpaths on deeply nested plugins.
# Remove every runpath that can leave the relocatable signed bundle; actual
# @rpath resolution is then proven by verify-macos-runtime.sh.
while IFS= read -r -d '' binary; do
    file -b "$binary" | grep -q 'Mach-O' || continue
    while IFS= read -r rpath; do
        [ -n "$rpath" ] || continue
        if ! rpath_is_artifact_safe "$binary" "$rpath"; then
            install_name_tool -delete_rpath "$rpath" "$binary"
        fi
    done < <(otool -l "$binary" | awk '
        $1 == "cmd" && $2 == "LC_RPATH" {want=1; next}
        want && $1 == "path" {print $2; want=0}' | LC_ALL=C sort -u)
done < <(find "$APP" -type f -print0)

while IFS= read -r -d '' sql_entry; do
    if [ "$(basename "$sql_entry")" = libqsqlite.dylib ] \
       && [ -f "$sql_entry" ] && [ ! -L "$sql_entry" ]; then
        continue
    fi
    rm -rf "$sql_entry"
done < <(find "$APP" -depth -path '*/sqldrivers/*' -print0)

while IFS= read -r -d '' sqlite_plugin; do
    [ ! -L "$sqlite_plugin" ] \
        || { echo "SQLite plugin must not be a symlink: $sqlite_plugin" >&2; exit 1; }
    file -b "$sqlite_plugin" | grep -q 'Mach-O' \
        || { echo "SQLite plugin is not Mach-O: $sqlite_plugin" >&2; exit 1; }
done < <(find "$APP" -path '*/sqldrivers/libqsqlite.dylib' -type f -print0)

if find "$APP" -name 'libqsqlmimer.dylib' -print -quit | grep -q .; then
    echo "qsqlmimer survived the SQL plugin allowlist" >&2
    exit 1
fi

"$SCRIPT_DIR/verify-macos-runtime.sh" app "$APP"
