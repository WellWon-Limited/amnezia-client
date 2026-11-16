#!/bin/bash
# Scan lab: build the two lab binaries in the scratch dir ($SCAN_LAB_DIR, default ~/avpn-build/scan-lab), from the
# conan build tree of amnezia-xray-bindings 1.4.0-tribe.1 that carries the scan engine (newest package whose header
# has amnezia_xray_scan_message, or TRIBE_SCAN_ENGINE_PKG=<package dir>):
#   1. engine/lib-pkg/{include/amnezia_xray.h, lib/libamnezia_xray.a}: the SAME engine source plus ONE lab file,
#      engine/tribescan_lab_roots.go (build tag tribescan_lab), which sets the engine's existing test seam
#      tribeScanTestRootCAs from the PEM named by TRIBE_SCAN_LAB_ROOTS. The production archive trusts the system roots
#      only; a loopback probe host has no publicly trusted certificate.
#   2. bin/scanlab-world (world/main.go): the lab's network - edge fronts, Xray servers, access-link meters,
#      subscription server - built against the same patched xray-core.
# Nothing is installed; the conan cache is only read (copied).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
L="${SCAN_LAB_DIR:-$HOME/avpn-build/scan-lab}"
GO="${GO_BIN:-}"
if [ -z "$GO" ]; then
  for g in "$HOME"/.conan2/p/b/go*/p/bin/go "$HOME"/.conan2/p/go*/p/bin/go; do
    if [ -x "$g" ] && "$g" version 2>/dev/null | grep -q 'go1\.2[7-9]'; then GO="$g"; break; fi
  done
fi
[ -x "$GO" ] || { echo "make-lab-bins.sh: no Go >= 1.27 (GO_BIN=...)"; exit 1; }
PKG="${TRIBE_SCAN_ENGINE_PKG:-}"
if [ -z "$PKG" ]; then
  # shellcheck disable=SC2012
  for h in $(ls -t "$HOME"/.conan2/p/b/amnez*/p/include/amnezia_xray.h 2>/dev/null); do
    if grep -q amnezia_xray_scan_message "$h"; then PKG="$(cd "$(dirname "$h")/.." && pwd)"; break; fi
  done
fi
SRC_TREE="$(dirname "$PKG")/b"
[ -d "$SRC_TREE/tribescan" ] || { echo "make-lab-bins.sh: no engine source tree next to '$PKG'"; exit 1; }
E="$L/engine"
mkdir -p "$E/src" "$E/gopath" "$E/lib" "$E/lib-pkg/include" "$E/lib-pkg/lib" "$L/bin"
rsync -a --delete --exclude build --exclude gopath --exclude gocache --exclude cmd --exclude tribescan_lab_roots.go "$SRC_TREE/" "$E/src/"
rsync -a "$SRC_TREE/build/gopath/" "$E/gopath/"
cp "$HERE/engine/tribescan_lab_roots.go" "$E/src/"
mkdir -p "$E/src/cmd/scanlab-world" && cp "$HERE/world/main.go" "$E/src/cmd/scanlab-world/main.go"
export GOFLAGS=-mod=mod GOPROXY=off GOTOOLCHAIN=local GOSUMDB=off GOPATH="$E/gopath" GOMODCACHE="$E/gopath/pkg/mod" GOCACHE="$E/gocache" CGO_ENABLED=1
export CGO_CFLAGS="-isysroot $(xcrun --sdk macosx --show-sdk-path) -arch arm64" CGO_LDFLAGS="-arch arm64"
cd "$E/src"
"$GO" build -tags tribescan_lab -ldflags=-w -buildmode=c-archive -o "$E/lib/libamnezia_xray.a" .
ln -sf "$E/lib/libamnezia_xray.h" "$E/lib-pkg/include/amnezia_xray.h"
ln -sf "$E/lib/libamnezia_xray.a" "$E/lib-pkg/lib/libamnezia_xray.a"
diff <(grep -v '^#line\|^$' "$E/lib/libamnezia_xray.h") <(grep -v '^#line\|^$' "$PKG/include/amnezia_xray.h") >/dev/null \
  || { echo "make-lab-bins.sh: the lab archive's header differs from the package's"; exit 1; }
"$GO" build -o "$L/bin/scanlab-world" ./cmd/scanlab-world
echo ">>> lab binaries ok: engine $(basename "$(dirname "$PKG")") -> $E/lib-pkg, world -> $L/bin/scanlab-world"
