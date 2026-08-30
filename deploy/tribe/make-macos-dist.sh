#!/bin/bash
# Retired legacy macOS distribution helper.
#
# The old local path duplicated the daemon manifest/tar/resource/signing logic
# and repeatedly drifted from CPack (missing Xray/OpenVPN data, install epoch,
# DNS hook and Qt closure). There is now exactly one packaging implementation:
# receipt-gated `deploy/build.sh --installer all` / CPack productbuild.
set -euo pipefail

case "${1:-}" in
    sign|dmg|notarize)
        echo "retired unsafe release route; use receipt-gated deploy/build.sh --installer all" >&2
        exit 2
        ;;
    *)
        echo "make-macos-dist.sh is retired; no local packaging mode is supported" >&2
        exit 2
        ;;
esac
