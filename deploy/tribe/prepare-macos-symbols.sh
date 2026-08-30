#!/bin/bash
# Generate a detached symbol set, prove UUID parity, strip only after symbols
# exist, then reject developer/cache paths before release signing.
set -euo pipefail

APP="${1:?usage: $0 APP OUTPUT_DIR SOURCE_ROOT BUILD_ROOT}"
OUTPUT="${2:?missing detached dSYM output directory}"
SOURCE_ROOT="${3:?missing source root}"
BUILD_ROOT="${4:?missing build root}"

die() {
    echo "macOS symbol preparation rejected: $*" >&2
    exit 1
}

[ -d "$APP/Contents/MacOS" ] && [ ! -L "$APP" ] \
    || die "invalid staged app bundle"
APP="$(cd "$APP" && pwd -P)"
[ -d "$SOURCE_ROOT" ] && [ ! -L "$SOURCE_ROOT" ] \
    || die "source root is not a real directory"
[ -d "$BUILD_ROOT" ] && [ ! -L "$BUILD_ROOT" ] \
    || die "build root is not a real directory"
SOURCE_ROOT="$(cd "$SOURCE_ROOT" && pwd -P)"
BUILD_ROOT="$(cd "$BUILD_ROOT" && pwd -P)"
case "$OUTPUT" in /*) ;; *) die "dSYM output must be an absolute path" ;; esac
[ ! -e "$OUTPUT" ] && [ ! -L "$OUTPUT" ] \
    || die "dSYM output already exists"
output_leaf="$(basename "$OUTPUT")"
output_parent="$(dirname "$OUTPUT")"
case "$output_leaf" in ''|.|..) die "invalid dSYM output name" ;; esac
[ -d "$output_parent" ] && [ ! -L "$output_parent" ] \
    || die "dSYM output parent is not a real directory"
OUTPUT="$(cd "$output_parent" && pwd -P)/$output_leaf"
case "$OUTPUT" in
    "$APP"|"$APP"/*|"$SOURCE_ROOT"|"$SOURCE_ROOT"/*|"$BUILD_ROOT"|"$BUILD_ROOT"/*)
        die "dSYM output must be outside app/source/build trees" ;;
esac
mkdir -m 700 "$OUTPUT"

runtime_execs=(TribeVPN Tribe-service amneziawg-go openvpn tun2socks)
: > "$OUTPUT/UUIDS.txt"
for name in "${runtime_execs[@]}"; do
    binary="$APP/Contents/MacOS/$name"
    if [ ! -f "$binary" ] || [ -L "$binary" ]; then
        die "runtime executable is missing or is a symlink: $name"
    fi
    if ! file -b "$binary" | grep -q 'Mach-O'; then
        die "runtime executable is not Mach-O: $name"
    fi

    /usr/bin/dsymutil "$binary" -o "$OUTPUT/$name.dSYM"
    dwarf="$OUTPUT/$name.dSYM/Contents/Resources/DWARF/$name"
    [ -s "$dwarf" ] || die "dsymutil produced no DWARF companion for $name"
    binary_uuids="$(/usr/bin/dwarfdump --uuid "$binary" \
        | sed -nE 's/^UUID: ([0-9A-F-]+) \(([^)]+)\).*/\1 \2/p' | LC_ALL=C sort)"
    dsym_uuids="$(/usr/bin/dwarfdump --uuid "$OUTPUT/$name.dSYM" \
        | sed -nE 's/^UUID: ([0-9A-F-]+) \(([^)]+)\).*/\1 \2/p' | LC_ALL=C sort)"
    if [ -n "$binary_uuids" ] || [ -n "$dsym_uuids" ]; then
        [ -n "$binary_uuids" ] && [ "$binary_uuids" = "$dsym_uuids" ] \
            || die "dSYM UUID/architecture mismatch for $name"
        while IFS= read -r uuid; do
            printf '%s %s\n' "$name" "$uuid" >> "$OUTPUT/UUIDS.txt"
        done <<< "$binary_uuids"
    else
        # Go's internal Darwin linker deliberately emits no LC_UUID.  dsymutil preserves
        # that property, so an ordinary UUID equality check cannot identify its companion.
        # Keep this exception closed to the two reviewed Go executables and prove that the
        # generated DWARF has the same complete architecture set plus Go runtime symbols.
        # C++ GUI/service/openvpn binaries still require byte-exact UUID parity above.
        case "$name" in
            amneziawg-go|tun2socks) ;;
            *) die "dSYM UUID is missing for non-Go executable $name" ;;
        esac
        binary_archs="$(/usr/bin/lipo -archs "$binary" | tr ' ' '\n' | LC_ALL=C sort)"
        dsym_archs="$(/usr/bin/lipo -archs "$dwarf" | tr ' ' '\n' | LC_ALL=C sort)"
        [ -n "$binary_archs" ] && [ "$binary_archs" = "$dsym_archs" ] \
            || die "UUID-less Go dSYM architecture mismatch for $name"
        # Do not use grep -q under pipefail: its early close makes nm exit with SIGPIPE and
        # falsely rejects a valid companion.  awk consumes the full symbol table.
        /usr/bin/nm -nm "$dwarf" 2>/dev/null \
            | awk '/(_runtime\.main| runtime\.main)$/ { found = 1 } END { exit !found }' \
            || die "UUID-less Go dSYM has no runtime.main symbol for $name"
        printf '%s NO_UUID %s\n' "$name" \
            "$(printf '%s' "$binary_archs" | tr '\n' ',' | sed 's/,$//')" \
            >> "$OUTPUT/UUIDS.txt"
    fi

    chmod u+w "$binary"
    /usr/bin/strip -S "$binary"
done

find "$OUTPUT" -type d -exec chmod 755 {} +
find "$OUTPUT" -type f -exec chmod 644 {} +
hash_file="$(mktemp "${TMPDIR:-/tmp}/tribe-dsym-sha256.XXXXXX")"
trap 'rm -f "$hash_file"' EXIT
(
    cd "$OUTPUT"
    find . -type f -print | LC_ALL=C sort \
        | while IFS= read -r symbol_file; do
            shasum -a 256 "$symbol_file"
        done
) > "$hash_file"
chmod 644 "$hash_file"
mv "$hash_file" "$OUTPUT/SHA256SUMS"
trap - EXIT

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
"$SCRIPT_DIR/verify-macos-runtime.sh" app "$APP"
"$SCRIPT_DIR/verify-macos-build-paths.sh" "$APP" "$SOURCE_ROOT" "$BUILD_ROOT"
"$SCRIPT_DIR/verify-macos-build-paths.sh" "$OUTPUT" "$SOURCE_ROOT" "$BUILD_ROOT"
echo "detached macOS dSYMs prepared in $OUTPUT"
