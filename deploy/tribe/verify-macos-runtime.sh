#!/bin/bash
# Validate that a deployed macOS app/service has no developer-machine dependencies.
set -euo pipefail

MODE="${1:-}"
ROOT="${2:-}"

die() {
    echo "macOS runtime closure rejected: $*" >&2
    exit 1
}

require_thin_arm64() {
    binary="$1"
    arches="$(lipo -archs "$binary")"
    [ "$arches" = arm64 ] \
        || die "shipping executable must be thin arm64, found '$arches': $binary"
}

case "$MODE" in app|service) ;; *) die "usage: $0 app|service PATH" ;; esac
[ -n "$ROOT" ] && [ -d "$ROOT" ] || die "runtime path is missing"
ROOT="$(cd "$ROOT" && pwd -P)"

if [ "$MODE" = app ]; then
    [ -d "$ROOT/Contents/Frameworks" ] || die "app Frameworks directory is missing"
    if [ -x "$ROOT/Contents/MacOS/TribeVPN" ]; then
        APP_EXECUTABLE="$ROOT/Contents/MacOS/TribeVPN"
    elif [ -x "$ROOT/Contents/MacOS/AmneziaVPN" ]; then
        APP_EXECUTABLE="$ROOT/Contents/MacOS/AmneziaVPN"
    else
        die "app executable is missing"
    fi
    expected_arches="$(lipo -archs "$APP_EXECUTABLE")"
    APP_RUNTIME_ROOTS=("$APP_EXECUTABLE")
    for executable in Tribe-service amneziawg-go openvpn tun2socks; do
        candidate="$ROOT/Contents/MacOS/$executable"
        if [ -f "$candidate" ]; then
            file -b "$candidate" | grep -q 'Mach-O' \
                || die "app runtime root is not Mach-O: $candidate"
            APP_RUNTIME_ROOTS+=("$candidate")
        fi
    done
    while IFS= read -r -d '' extension_plist; do
        extension_root="${extension_plist%/Contents/Info.plist}"
        extension_executable="$(/usr/libexec/PlistBuddy \
            -c 'Print :CFBundleExecutable' "$extension_plist" 2>/dev/null)" \
            || die "extension lacks CFBundleExecutable: $extension_plist"
        case "$extension_executable" in
            ''|*/*|.|..) die "unsafe extension executable name: $extension_executable" ;;
        esac
        candidate="$extension_root/Contents/MacOS/$extension_executable"
        if [ ! -f "$candidate" ] || ! file -b "$candidate" | grep -q 'Mach-O'; then
            die "extension executable is missing or not Mach-O: $candidate"
        fi
        APP_RUNTIME_ROOTS+=("$candidate")
    done < <(find "$ROOT/Contents" -type d -name '*.appex' -prune \
        -exec printf '%s\0' '{}/Contents/Info.plist' \;)
    # The daemon flavor is intentionally Apple-Silicon-only.  Universal Qt frameworks are a
    # valid dependency closure, but every executable shipping root must be a thin arm64 Mach-O;
    # otherwise the package would silently acquire an untested Intel execution path.
    if [ -f "$ROOT/Contents/MacOS/Tribe-service" ]; then
        for runtime_root in "${APP_RUNTIME_ROOTS[@]}"; do
            require_thin_arm64 "$runtime_root"
        done
    fi
    while IFS= read -r -d '' sql_entry; do
        [ "$(basename "$sql_entry")" = libqsqlite.dylib ] \
            && [ -f "$sql_entry" ] && [ ! -L "$sql_entry" ] \
            || die "non-hermetic SQL plugin entry was deployed: $sql_entry"
        file -b "$sql_entry" | grep -q 'Mach-O' \
            || die "SQLite plugin is not Mach-O: $sql_entry"
    done < <(find "$ROOT" -path '*/sqldrivers/*' -print0)
    find "$ROOT" -name 'libqsqlmimer.dylib' -print -quit | grep -q . \
        && die "qsqlmimer has an undeclared /usr/local libmimerapi dependency"
else
    for executable in Tribe-service amneziawg-go openvpn tun2socks; do
        [ -x "$ROOT/$executable" ] || die "$executable is missing"
    done
    [ -s "$ROOT/geoip.dat" ] && [ -s "$ROOT/geosite.dat" ] \
        || die "Xray geodata is missing"
    service_arches="$(lipo -archs "$ROOT/Tribe-service")"
    require_thin_arm64 "$ROOT/Tribe-service"
    expected_arches="$service_arches"
    SERVICE_RUNTIME_ROOTS=(
        "$ROOT/Tribe-service"
        "$ROOT/amneziawg-go"
        "$ROOT/openvpn"
        "$ROOT/tun2socks"
    )
    for executable in amneziawg-go openvpn tun2socks; do
        require_thin_arm64 "$ROOT/$executable"
    done
fi

version_not_newer_than_13() {
    value="$1"
    major="${value%%.*}"
    remainder="${value#*.}"
    [ "$remainder" = "$value" ] && remainder=0
    minor="${remainder%%.*}"
    case "$major:$minor" in *[!0-9:]*) return 1 ;; esac
    [ "$major" -lt 13 ] || { [ "$major" -eq 13 ] && [ "$minor" -le 0 ]; }
}

executable_dir_for() {
    binary="$1"
    if [ "$MODE" = service ]; then
        printf '%s\n' "$ROOT"
        return
    fi
    case "$binary" in
        *.appex/Contents/*)
            printf '%s\n' "${binary%%.appex/Contents/*}.appex/Contents/MacOS"
            ;;
        *) printf '%s\n' "$ROOT/Contents/MacOS" ;;
    esac
}

canonical_artifact_path() {
    candidate="$1"
    [ -e "$candidate" ] || return 1
    canonical="$(realpath "$candidate")" || return 1
    case "$canonical" in
        "$ROOT"|"$ROOT"/*) printf '%s\n' "$canonical" ;;
        *) return 1 ;;
    esac
}

canonical_macho_path() {
    candidate="$(canonical_artifact_path "$1")" || return 1
    [ -f "$candidate" ] && file -b "$candidate" | grep -q 'Mach-O' || return 1
    printf '%s\n' "$candidate"
}

lexical_artifact_path() {
    candidate="$1"
    parent="$(cd "$(dirname "$candidate")" 2>/dev/null && pwd -P)" || return 1
    canonical="$parent/$(basename "$candidate")"
    case "$canonical" in
        "$ROOT"|"$ROOT"/*) printf '%s\n' "$canonical" ;;
        *) return 1 ;;
    esac
}

expand_runtime_path() {
    binary="$1"
    spelling="$2"
    case "$spelling" in
        @loader_path) candidate="$(dirname "$binary")" ;;
        @loader_path/*) candidate="$(dirname "$binary")/${spelling#@loader_path/}" ;;
        @executable_path) candidate="$(executable_dir_for "$binary")" ;;
        @executable_path/*)
            candidate="$(executable_dir_for "$binary")/${spelling#@executable_path/}"
            ;;
        *) return 1 ;;
    esac
    canonical_artifact_path "$candidate"
}

expand_runtime_path_lexical() {
    binary="$1"
    spelling="$2"
    case "$spelling" in
        @loader_path) candidate="$(dirname "$binary")" ;;
        @loader_path/*) candidate="$(dirname "$binary")/${spelling#@loader_path/}" ;;
        @executable_path) candidate="$(executable_dir_for "$binary")" ;;
        @executable_path/*)
            candidate="$(executable_dir_for "$binary")/${spelling#@executable_path/}"
            ;;
        *) return 1 ;;
    esac
    lexical_artifact_path "$candidate"
}

rpaths_for() {
    otool -l "$1" | awk '
        $1 == "cmd" && $2 == "LC_RPATH" {want=1; next}
        want && $1 == "path" {print $2; want=0}'
}

is_runtime_root() {
    binary="$1"
    if [ "$MODE" = service ]; then
        roots=("${SERVICE_RUNTIME_ROOTS[@]}")
    else
        roots=("${APP_RUNTIME_ROOTS[@]}")
    fi
    for runtime_root in "${roots[@]}"; do
        [ "$binary" = "$runtime_root" ] && return 0
    done
    return 1
}

extension_runtime_root_for() {
    binary="$1"
    case "$binary" in
        *.appex/Contents/*) extension_root="${binary%%.appex/Contents/*}.appex" ;;
        *) return 1 ;;
    esac
    for runtime_root in "${APP_RUNTIME_ROOTS[@]}"; do
        case "$runtime_root" in
            "$extension_root"/Contents/MacOS/*)
                printf '%s\n' "$runtime_root"
                return 0
                ;;
        esac
    done
    return 1
}

runtime_roots_for() {
    binary="$1"
    # An executable is an independent dyld root. It must never borrow another
    # executable's LC_RPATH merely because both happen to ship in one artifact.
    if is_runtime_root "$binary"; then
        printf '%s\n' "$binary"
        return
    fi
    if [ "$MODE" = service ]; then
        # Every service root is normalized to the same closed Frameworks
        # directory below, so a nested framework has the same resolution
        # context no matter which executable loaded it.
        printf '%s\n' "${SERVICE_RUNTIME_ROOTS[@]}"
        return
    fi
    case "$binary" in
        *.appex/Contents/*)
            extension_runtime_root_for "$binary" \
                || die "cannot determine extension dyld root for $binary"
            ;;
        "$ROOT"/Contents/Frameworks/*)
            # macdeployqt's shared Frameworks directory is reachable from the
            # main app, daemon helpers and each embedded extension. Direct
            # dependencies of every independent root are still checked using
            # only that root above.
            printf '%s\n' "${APP_RUNTIME_ROOTS[@]}"
            ;;
        *) printf '%s\n' "$APP_EXECUTABLE" ;;
    esac
}

rpath_records_for_resolution() {
    binary="$1"
    while IFS= read -r rpath; do
        printf '%s\t%s\n' "$binary" "$rpath"
    done < <(rpaths_for "$binary")
    while IFS= read -r runtime_root; do
        [ "$runtime_root" = "$binary" ] && continue
        while IFS= read -r rpath; do
            printf '%s\t%s\n' "$runtime_root" "$rpath"
        done < <(rpaths_for "$runtime_root")
    done < <(runtime_roots_for "$binary")
}

resolve_dependency() {
    binary="$1"
    dependency="$2"
    case "$dependency" in
        /System/Library/*|/usr/lib/*) return 0 ;;
        /*) die "$binary has non-system absolute dependency $dependency" ;;
        @loader_path/*|@executable_path/*)
            resolved_path="$(expand_runtime_path "$binary" "$dependency")" \
                || die "$binary resolves $dependency outside or missing from the artifact"
            canonical_macho_path "$resolved_path" >/dev/null \
                || die "$binary resolves $dependency to a non-Mach-O artifact"
            ;;
        @rpath/*)
            relative="${dependency#@rpath/}"
            resolved=0
            while IFS=$'\t' read -r rpath_owner rpath; do
                [ -n "$rpath" ] || continue
                case "$rpath" in
                    @loader_path|@loader_path/*|@executable_path|@executable_path/*)
                        expanded="$(expand_runtime_path "$rpath_owner" "$rpath")" || continue
                        canonical_macho_path "$expanded/$relative" >/dev/null || continue
                        resolved=1
                        break
                        ;;
                esac
            done < <(rpath_records_for_resolution "$binary")
            [ "$resolved" -eq 1 ] \
                || die "$binary cannot resolve $dependency through its LC_RPATH entries"
            ;;
        *) die "$binary has unsupported dependency spelling $dependency" ;;
    esac
}

checked=0

if [ "$MODE" = service ]; then
    # bundle-daemon-qt deliberately makes all four privileged entry points
    # independent. Requiring this exact rpath prevents one helper from passing
    # only because another helper can see Frameworks.
    for runtime_root in "${SERVICE_RUNTIME_ROOTS[@]}"; do
        artifact_rpaths=0
        while IFS= read -r rpath; do
            case "$rpath" in
                /usr/lib/swift|/System/Library/*) ;;
                @loader_path/Frameworks) artifact_rpaths=$((artifact_rpaths + 1)) ;;
                *) die "$runtime_root must use only @loader_path/Frameworks, found $rpath" ;;
            esac
        done < <(rpaths_for "$runtime_root")
        [ "$artifact_rpaths" -eq 1 ] \
            || die "$runtime_root must contain exactly one @loader_path/Frameworks LC_RPATH"
    done
fi

while IFS= read -r -d '' binary; do
    file -b "$binary" | grep -q 'Mach-O' || continue
    checked=$((checked + 1))

    binary_arches="$(lipo -archs "$binary")"
    for arch in $expected_arches; do
        case " $binary_arches " in
            *" $arch "*) ;;
            *) die "$binary lacks artifact architecture $arch" ;;
        esac
    done

    while IFS= read -r dependency; do
        [ -n "$dependency" ] && resolve_dependency "$binary" "$dependency"
    done < <(otool -L "$binary" | awk 'index($0, "(compatibility version") {print $1}')

    while IFS= read -r rpath; do
        [ -z "$rpath" ] && continue
        case "$rpath" in
            @loader_path|@loader_path/*|@executable_path|@executable_path/*)
                expand_runtime_path_lexical "$binary" "$rpath" >/dev/null \
                    || die "$binary LC_RPATH escapes the artifact: $rpath"
                ;;
            /usr/lib/swift|/System/Library/*) ;;
            *) die "$binary retains non-artifact LC_RPATH $rpath" ;;
        esac
    done < <(rpaths_for "$binary")

    minos_count=0
    while IFS= read -r minos; do
        [ -z "$minos" ] && continue
        minos_count=$((minos_count + 1))
        version_not_newer_than_13 "$minos" \
            || die "$binary requires macOS $minos, above the advertised macOS 13 minimum"
    done < <(xcrun vtool -show-build "$binary" 2>/dev/null | awk '$1 == "minos" {print $2}')
    # vtool emits one deployment record for each architecture slice.
    read -r -a binary_arch_list <<< "$binary_arches"
    [ "$minos_count" -eq "${#binary_arch_list[@]}" ] \
        || die "$binary has incomplete macOS deployment-target metadata"
done < <(find "$ROOT" -type f -print0)

[ "$checked" -gt 0 ] || die "no Mach-O runtime files were found"
echo "macOS $MODE runtime closure verified across $checked Mach-O files"
