#!/bin/bash
# Retired fail-closed. A package post-uninstall script cannot authenticate the
# mutable app/runtime namespace well enough to remove privileged files safely.
# The supported UX is the signed in-app "Remove system service" action; the
# user can then move TribeVPN.app to Trash normally.
set -euo pipefail
echo "post_uninstall.sh is retired; remove the system service from Tribe VPN settings" >&2
exit 1
