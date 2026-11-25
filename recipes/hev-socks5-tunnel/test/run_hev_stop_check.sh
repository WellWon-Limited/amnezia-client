#!/bin/bash
# Host check of the hev stop contract on the REAL library (reviews R46, R47): fetches the pinned 2.15.0 sources and
# submodules (the archives and SHA-256 of ../conanfile.py), applies the recipe's patches, builds the static libraries
# for this Mac and runs hev_stop_check.c and hev_stop_session_check.c against them (a socketpair stands in for the tun
# fd; a SOCKS server double answers hev's UDP_ASSOCIATE at the stop).
#   bash recipes/hev-socks5-tunnel/test/run_hev_stop_check.sh                   # 0001 + 0002 + 0003 (the package)
#   PATCHES="0001 0002" bash recipes/hev-socks5-tunnel/test/run_hev_stop_check.sh # session check fails (R47 H1a)
#   PATCHES="0001" bash recipes/hev-socks5-tunnel/test/run_hev_stop_check.sh      # stop checks 1 and 2 fail (R46)
# Needs network (github.com). Work dir: HEV_CHECK_DIR (default: a new mktemp dir under TMPDIR). Exit 0 = passed.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
RECIPE="$(cd "$HERE/.." && pwd)"
PATCHES="${PATCHES:-0001 0002 0003}"
WORK="${HEV_CHECK_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/hev-stop-check.XXXXXX")}"
mkdir -p "$WORK/dl"
fetch() { # <url> <sha256> <file>
    [[ -f "$WORK/dl/$3" ]] || curl -sSL -o "$WORK/dl/$3" "$1"
    echo "$2  $WORK/dl/$3" | shasum -a 256 -c - > /dev/null
}
fetch "https://github.com/heiher/hev-socks5-tunnel/archive/refs/tags/2.15.0.zip" \
    2420c6ac117c25b0c8ee98e845d1ad0a4e1d79de487e15fbe06935512707cf7b hev.zip
fetch "https://github.com/heiher/hev-socks5-core/archive/ee0f24505d344f14b14624fa2249e6ccfaed138b.zip" \
    9ed7a6278d89534c99952d141a548902a6735c2473ccefe13c22e8c56baa343e core.zip
fetch "https://github.com/heiher/hev-task-system/archive/8d83bbbf79557138726c8ee5a5fae99cbb978d61.zip" \
    2d5b3dbd5a66c963747736453811027f0519a8a53b97b4653b0fdd8b8a897a25 task.zip
fetch "https://github.com/heiher/lwip/archive/8c69dfbe537835d5f2a5fd8c08c859f667b108ea.zip" \
    ec8169ac24fe1e77591812fd3fee7509a849fcf4ff315faadbae7be747d65cde lwip.zip
fetch "https://github.com/heiher/yaml/archive/efa36117a8646d26d12b58e05bac472d7854a70d.zip" \
    211f8d5b67942af1108a5655d309ed32c1df51b19c2444a58ddf5b188405e8cc yaml.zip
TREE="$WORK/tree-${PATCHES// /-}"
rm -rf "${TREE:?}"
mkdir -p "$WORK/x"
unzip -q -o "$WORK/dl/hev.zip" -d "$WORK/x"
mv "$WORK/x/hev-socks5-tunnel-2.15.0" "$TREE"
for pair in "src/core:core" "third-part/hev-task-system:task" "third-part/lwip:lwip" "third-part/yaml:yaml"; do
    dst="${pair%%:*}"
    zip="${pair##*:}"
    rm -rf "${WORK:?}/x/"*
    unzip -q -o "$WORK/dl/$zip.zip" -d "$WORK/x"
    mkdir -p "$TREE/$dst"
    cp -R "$WORK/x"/*/. "$TREE/$dst"/
done
for n in $PATCHES; do
    patch -p1 -s -d "$TREE" < "$(ls "$RECIPE/patches/$n"-*.patch)"
done
make -C "$TREE" -j8 static > "$WORK/build.log" 2>&1
rc=0
for check in hev_stop_check hev_stop_session_check; do
    clang -O1 -o "$WORK/$check" "$HERE/$check.c" "$TREE/bin/libhev-socks5-tunnel.a" \
        "$TREE/third-part/lwip/bin/liblwip.a" "$TREE/third-part/yaml/bin/libyaml.a" \
        "$TREE/third-part/hev-task-system/bin/libhev-task-system.a" -lpthread
    echo "== $check, patches: $PATCHES"
    "$WORK/$check" || rc=1
done
exit $rc
