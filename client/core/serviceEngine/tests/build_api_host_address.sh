#!/bin/bash
# Device round air-I review F4 (25.11): which resolved addresses of our API hosts the app keeps (ApiHostAddress.h) -
# the public-unicast table and the one recording rule of AvpnEngineQml::resolveApiCarveHosts. QtCore + QtNetwork
# (QHostAddress), no network.
set -eu
QT="${QT_ROOT:-$HOME/Qt/6.11.1/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$HERE/../../.."
OUT="$(mktemp -d /tmp/tribe-api-host-address.XXXXXX)"
trap 'rm -rf -- "$OUT"' EXIT
clang++ -std=c++17 -fPIC -F"$QT/lib" \
  -I"$QT/lib/QtCore.framework/Headers" -I"$QT/lib/QtNetwork.framework/Headers" -I"$CLIENT" -I"$HERE/.." \
  "$HERE/api_host_address_check.cpp" \
  -framework QtCore -framework QtNetwork -Wl,-rpath,"$QT/lib" -o "$OUT/api_host_address_check"
"$OUT/api_host_address_check"
