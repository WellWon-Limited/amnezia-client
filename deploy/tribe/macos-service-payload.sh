#!/bin/bash
# Seal or verify the exact privileged macOS daemon payload shipped inside TribeVPN.app.
# The signed app resource `tribe-svc.version` anchors the manifest digest at install time.
set -euo pipefail

MODE="${1:-}"
PAYLOAD="${2:-}"
EXPECTED_VERSION_FILE="${3:-}"

die() {
    echo "macOS service payload rejected: $*" >&2
    exit 1
}

case "$MODE" in
    normalize|seal|verify) ;;
    *) die "usage: $0 normalize|seal|verify PAYLOAD_DIR [EXPECTED_VERSION_FILE]" ;;
esac

[ -n "$PAYLOAD" ] && [ -d "$PAYLOAD" ] || die "payload directory is missing"
PAYLOAD="$(cd "$PAYLOAD" && pwd -P)"

sha256_file() {
    shasum -a 256 "$1" | awk '{print $1}'
}

required_executables=(Tribe-service amneziawg-go openvpn tun2socks)
required_data=(geoip.dat geosite.dat INSTALL-CONTRACT INSTALL-EPOCH)
required_pf=(
    tribe.000.allowLoopback.conf
    tribe.100.blockAll.conf
    tribe.110.allowNets.conf
    tribe.120.blockNets.conf
    tribe.150.allowExcludedApps.conf
    tribe.200.allowVPN.conf
    tribe.250.blockIPv6.conf
    tribe.290.allowDHCP.conf
    tribe.300.allowLAN.conf
    tribe.310.blockDNS.conf
    tribe.350.allowHnsd.conf
    tribe.400.allowPIA.conf
    tribe.999.quarantine.conf
    tribe.conf
)

for name in "${required_executables[@]}"; do
    [ -f "$PAYLOAD/$name" ] && [ -x "$PAYLOAD/$name" ] \
        || die "required executable $name is missing"
done
for name in geoip.dat geosite.dat; do
    [ -s "$PAYLOAD/$name" ] || die "required runtime data $name is missing or empty"
done
[ -d "$PAYLOAD/Frameworks" ] && [ ! -L "$PAYLOAD/Frameworks" ] \
    || die "Frameworks must be a real directory"
[ -d "$PAYLOAD/pf" ] && [ ! -L "$PAYLOAD/pf" ] \
    || die "pf must be a real directory"
for name in "${required_pf[@]}"; do
    [ -f "$PAYLOAD/pf/$name" ] && [ ! -L "$PAYLOAD/pf/$name" ] \
        || die "required PF rule $name is missing"
done
for required_framework in \
    QtCore.framework/Versions/A/QtCore \
    libssl.3.dylib \
    libcrypto.3.dylib; do
    [ -f "$PAYLOAD/Frameworks/$required_framework" ] \
        || die "required daemon dependency $required_framework is missing"
done

# The installed VERSION must change when privileged installation/verification
# logic changes even if engine bytes do not. This prevents an app-only update
# from incorrectly deciding that an older install contract is current.
script_dir="$(cd "$(dirname "$0")" && pwd -P)"
installer_script="$script_dir/tribe-svc-install.sh"
launchctl_parser="$script_dir/launchctl-job-field.sh"
[ -f "$installer_script" ] && [ ! -L "$installer_script" ] \
    || die "installer contract source is missing"
[ -f "$launchctl_parser" ] && [ ! -L "$launchctl_parser" ] \
    || die "launchctl parser contract source is missing"
contract="$PAYLOAD/INSTALL-CONTRACT"
contract_tmp="$(mktemp "${TMPDIR:-/tmp}/tribe-install-contract.XXXXXX")"
trap 'rm -f "$contract_tmp"' EXIT
{
    printf 'schema=2\n'
    printf 'mode_contract=dirs-0755,macho-0755,data-0644,no-special-bits\n'
    printf 'installer_sha256=%s\n' "$(sha256_file "$installer_script")"
    printf 'launchctl_parser_sha256=%s\n' "$(sha256_file "$launchctl_parser")"
    printf 'verifier_sha256=%s\n' "$(sha256_file "$0")"
} > "$contract_tmp"
if [ "$MODE" = normalize ] || [ "$MODE" = seal ]; then
    mv "$contract_tmp" "$contract"
    chmod 644 "$contract"
else
    cmp -s "$contract_tmp" "$contract" \
        || die "payload install contract does not match this signed installer"
    rm -f "$contract_tmp"
fi
trap - EXIT

normalize_modes() {
    find "$PAYLOAD" -type d -exec chmod 755 {} +
    find "$PAYLOAD" -type f -exec chmod 644 {} +
    for name in "${required_executables[@]}"; do
        chmod 755 "$PAYLOAD/$name"
    done
    while IFS= read -r -d '' path; do
        if file -b "$path" | grep -q 'Mach-O'; then
            chmod 755 "$path"
        fi
    done < <(find "$PAYLOAD/Frameworks" -type f -print0)
}

verify_modes() {
    while IFS= read -r -d '' path; do
        [ -L "$path" ] && continue
        if [ -f "$path" ] && [ "$(stat -f '%l' "$path")" -ne 1 ]; then
            die "hard-linked payload file is forbidden: ${path#"$PAYLOAD"/}"
        fi
        mode="$(stat -f '%Lp' "$path")"
        # The extraction container is deliberately root-owned 0700; the same
        # closed payload is normalized to 0755 at its final installed root.
        # Neither container mode changes any sealed child path.
        if [ "$path" = "$PAYLOAD" ]; then
            [ "$mode" = 700 ] || [ "$mode" = 755 ] \
                || die "unsafe payload root mode $mode"
            continue
        fi
        expected_mode=644
        if [ -d "$path" ]; then
            expected_mode=755
        else
            case "$path" in
                "$PAYLOAD/Tribe-service"|"$PAYLOAD/amneziawg-go"|\
                "$PAYLOAD/openvpn"|"$PAYLOAD/tun2socks") expected_mode=755 ;;
                "$PAYLOAD/Frameworks"/*)
                    if file -b "$path" | grep -q 'Mach-O'; then
                        expected_mode=755
                    fi
                    ;;
            esac
        fi
        [ "$mode" = "$expected_mode" ] \
            || die "unsafe payload mode $mode (expected $expected_mode): ${path#"$PAYLOAD"/}"
    done < <(find "$PAYLOAD" -print0)
}

if [ "$MODE" = normalize ]; then
    normalize_modes
    verify_modes
    echo "macOS service payload modes normalized"
    exit 0
fi

verify_modes

# A signed resource must have a closed root and a closed PF rule set. Framework internals
# are variable across Qt patch releases, but every regular file and symlink is sealed below.
while IFS= read -r -d '' path; do
    [ "$path" = "$PAYLOAD" ] && continue
    relative="${path#"$PAYLOAD"/}"
    case "$relative" in
        *$'\n'*|*$'\t'*|*\\*) die "unsupported path spelling in payload: $relative" ;;
    esac
    case "$relative" in
        Tribe-service|amneziawg-go|openvpn|tun2socks|\
        geoip.dat|geosite.dat|Frameworks|Frameworks/*|pf) ;;
        pf/tribe.000.allowLoopback.conf|pf/tribe.100.blockAll.conf|\
        pf/tribe.110.allowNets.conf|pf/tribe.120.blockNets.conf|\
        pf/tribe.150.allowExcludedApps.conf|pf/tribe.200.allowVPN.conf|\
        pf/tribe.250.blockIPv6.conf|pf/tribe.290.allowDHCP.conf|\
        pf/tribe.300.allowLAN.conf|pf/tribe.310.blockDNS.conf|\
        pf/tribe.350.allowHnsd.conf|pf/tribe.400.allowPIA.conf|\
        pf/tribe.999.quarantine.conf|pf/tribe.conf) ;;
        INSTALL-CONTRACT|INSTALL-EPOCH) ;;
        PAYLOAD-MANIFEST.sha256|PAYLOAD-SYMLINKS|VERSION)
            [ "$MODE" != seal ] || die "stale seal metadata exists before sealing: $relative"
            ;;
        *) die "unexpected payload path: $relative" ;;
    esac
    if [ -L "$path" ]; then
        case "$relative" in Frameworks/*) ;; *) die "symlink outside Frameworks: $relative" ;; esac
        target="$(readlink "$path")"
        case "$target" in /*|'') die "unsafe symlink target for $relative" ;; esac
        case "$target" in *$'\n'*|*$'\t'*|*\\*) die "unsupported symlink target for $relative" ;; esac
        case "/$target/" in */../*) die "parent traversal in symlink $relative" ;; esac
    elif [ ! -d "$path" ] && [ ! -f "$path" ]; then
        die "special filesystem node is forbidden: $relative"
    fi
done < <(find "$PAYLOAD" -print0)

manifest="$PAYLOAD/PAYLOAD-MANIFEST.sha256"
symlinks="$PAYLOAD/PAYLOAD-SYMLINKS"
version="$PAYLOAD/VERSION"

make_regular_file_list() {
    (
        cd "$PAYLOAD"
        printf '%s\n' "${required_executables[@]}" \
            "${required_data[@]}" PAYLOAD-SYMLINKS
        find Frameworks pf -type f -print
    ) | LC_ALL=C sort -u
}

make_symlink_list() {
    (
        cd "$PAYLOAD"
        find Frameworks -type l -print | LC_ALL=C sort | while IFS= read -r link; do
            target="$(readlink "$link")"
            printf '%s\t%s\n' "$link" "$target"
        done
    )
}

if [ "$MODE" = seal ]; then
    symlink_tmp="$(mktemp "${TMPDIR:-/tmp}/tribe-payload-symlinks.XXXXXX")"
    manifest_tmp="$(mktemp "${TMPDIR:-/tmp}/tribe-payload-manifest.XXXXXX")"
    trap 'rm -f "$symlink_tmp" "$manifest_tmp"' EXIT
    make_symlink_list > "$symlink_tmp"
    mv "$symlink_tmp" "$symlinks"
    : > "$manifest_tmp"
    while IFS= read -r relative; do
        digest="$(sha256_file "$PAYLOAD/$relative")"
        printf '%s  %s\n' "$digest" "$relative" >> "$manifest_tmp"
    done < <(make_regular_file_list)
    mv "$manifest_tmp" "$manifest"
    sha256_file "$manifest" > "$version"
    chmod 644 "$manifest" "$symlinks" "$version"
    trap - EXIT
    MODE=verify
fi

[ -f "$manifest" ] && [ ! -L "$manifest" ] || die "manifest is missing"
[ -f "$symlinks" ] && [ ! -L "$symlinks" ] || die "symlink manifest is missing"
[ -f "$version" ] && [ ! -L "$version" ] || die "version anchor is missing"

actual_files="$(mktemp "${TMPDIR:-/tmp}/tribe-payload-files.XXXXXX")"
listed_files="$(mktemp "${TMPDIR:-/tmp}/tribe-payload-listed.XXXXXX")"
actual_symlinks="$(mktemp "${TMPDIR:-/tmp}/tribe-payload-links.XXXXXX")"
trap 'rm -f "$actual_files" "$listed_files" "$actual_symlinks"' EXIT
make_regular_file_list > "$actual_files"
: > "$listed_files"
while IFS= read -r line || [ -n "$line" ]; do
    digest="${line%%  *}"
    relative="${line#*  }"
    [ "$relative" != "$line" ] || die "malformed manifest line"
    [ "${#digest}" -eq 64 ] || die "manifest digest has wrong length"
    case "$digest" in *[!0-9a-f]*) die "manifest digest is not lowercase SHA-256" ;; esac
    case "$relative" in /*|../*|*/../*|*'/..'|''|*'  '*) die "unsafe manifest path: $relative" ;; esac
    printf '%s\n' "$relative" >> "$listed_files"
done < "$manifest"
LC_ALL=C sort -u "$listed_files" -o "$listed_files"
cmp -s "$actual_files" "$listed_files" || die "manifest file set is incomplete or has extras"

(
    cd "$PAYLOAD"
    shasum -a 256 -c PAYLOAD-MANIFEST.sha256 >/dev/null
) || die "payload content checksum failed"

make_symlink_list > "$actual_symlinks"
cmp -s "$actual_symlinks" "$symlinks" || die "Framework symlink set changed"

version_value="$(tr -d '\r\n' < "$version")"
[ "${#version_value}" -eq 64 ] || die "VERSION is not a full SHA-256"
case "$version_value" in *[!0-9a-f]*) die "VERSION is not lowercase SHA-256" ;; esac
[ "$version_value" = "$(sha256_file "$manifest")" ] \
    || die "VERSION does not anchor the manifest"

if [ -n "$EXPECTED_VERSION_FILE" ]; then
    [ -f "$EXPECTED_VERSION_FILE" ] && [ ! -L "$EXPECTED_VERSION_FILE" ] \
        || die "signed app version anchor is missing"
    expected="$(tr -d '\r\n' < "$EXPECTED_VERSION_FILE")"
    [ "$expected" = "$version_value" ] \
        || die "payload does not match the signed app version anchor"
fi

echo "macOS service payload verified: $version_value"
