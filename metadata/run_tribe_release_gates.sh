#!/bin/bash
# Source/release gates for the server-driven AWG/Xray catalog runtime.
set -euo pipefail
# Python/unit discovery must never dirty a commit-bound release checkout.
export PYTHONDONTWRITEBYTECODE=1

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODE="${1:---source-only}"
PLATFORM="${2:-}"

case "$MODE" in
    --source-only) ;;
    --release)
        case "$PLATFORM" in
            android|ios|macos_daemon|macos_ne) ;;
            *) echo "invalid release platform: $PLATFORM" >&2; exit 2 ;;
        esac
        ;;
    *) echo "usage: $0 [--source-only | --release PLATFORM]" >&2; exit 2 ;;
esac

cd "$ROOT"
SOURCE_BASELINE="$(git status --porcelain=v1 --untracked-files=all)"
if [[ "$MODE" == "--release" && -n "$SOURCE_BASELINE" ]]; then
    echo "release source tree must be clean before gates (including untracked files)" >&2
    exit 1
fi

python3 metadata/check_release_version.py
python3 metadata/check_engine_lock.py
python3 metadata/check_platform_runtime.py
python3 metadata/check_ios_appicon.py
python3 -m unittest discover -s metadata/tests -p 'test_*.py'
git diff --check

# These focused native policy suites run before every Apple-side archive. The
# Linux Android builder still gets the static gates above; its commit-bound
# receipt can only be produced after the separate target/device matrix passes.
if [[ "$(uname -s)" == "Darwin" ]]; then
    python3 metadata/check_ios_appicon.py --compile-source
    sh ipc/tests/build_openvpn_config_security.sh
    sh client/core/serviceEngine/tests/build_catalog_v2.sh
    sh client/core/serviceEngine/tests/build_catalog_security.sh
    sh client/core/serviceEngine/tests/build_transport_runtime.sh
    sh client/core/serviceEngine/tests/build_catalog_coordinator.sh
    bash client/platforms/ios/tests/run_swift_host_tests.sh
    bash client/platforms/macos/tests/run_macos_native_session_guard_tests.sh
fi

SOURCE_AFTER="$(git status --porcelain=v1 --untracked-files=all)"
if [[ "$SOURCE_AFTER" != "$SOURCE_BASELINE" ]]; then
    echo "release gates changed the source tree" >&2
    GATE_DIFF_DIR="$(mktemp -d "${TMPDIR:-/tmp}/tribe-release-gate-diff.XXXXXX")"
    printf '%s\n' "$SOURCE_BASELINE" > "$GATE_DIFF_DIR/before"
    printf '%s\n' "$SOURCE_AFTER" > "$GATE_DIFF_DIR/after"
    diff -u "$GATE_DIFF_DIR/before" "$GATE_DIFF_DIR/after" || true
    rm -rf "$GATE_DIFF_DIR"
    exit 1
fi

if [[ "$MODE" == "--release" ]]; then
    COMMIT="$(git rev-parse --verify HEAD)"
    if [[ ! "$COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
        echo "release source commit is not a full Git SHA-1" >&2
        exit 1
    fi
fi

echo "Tribe catalog/runtime gates passed${PLATFORM:+ for $PLATFORM}"
