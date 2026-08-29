#!/bin/bash
set -e

QT="${QT_ROOT:-$HOME/Qt/6.10.2/macos}"
SSL="${OPENSSL_ROOT:-$(brew --prefix openssl@3)}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$(cd "$HERE/../../.." && pwd)"

# Production-shaped compile gate for the composition root and concrete native adapter.  It uses
# audited-format host facts only to exercise the preprocessor branches; no fixture is linked into
# the product and no platform readiness receipt is enabled.
clang++ -std=c++17 -fsyntax-only -fPIC -include arm_acle.h \
  -include "$HERE/catalog_product_compile_stubs.h" \
  -I"$HERE" -I"$CLIENT" -I"$HERE/.." \
  -I"$QT/include" -I"$QT/include/QtCore" -I"$QT/include/QtNetwork" \
  -I"$QT/include/QtQml" -I"$QT/include/QtGui" -I"$QT/include/QtRemoteObjects" \
  -I"$QT/lib/QtCore.framework/Headers" -I"$QT/lib/QtNetwork.framework/Headers" \
  -I"$QT/lib/QtQml.framework/Headers" -I"$QT/lib/QtGui.framework/Headers" \
  -I"$QT/lib/QtRemoteObjects.framework/Headers" -I"$SSL/include" -F"$QT/lib" \
  -DTRIBE_MACOS_AWG_ADAPTER_VERSION='"3.1.20260814"' \
  -DTRIBE_MACOS_AWG_CORE_VERSION='"3.1.20260814"' \
  -DTRIBE_MACOS_AWG_SOURCE_COMMIT='"0123456789abcdef0123456789abcdef01234567"' \
  -DTRIBE_MACOS_AWG_ABI='"awg-go-uapi-v3.1"' \
  -DTRIBE_MACOS_XRAY_ADAPTER_VERSION='"1.0.3"' \
  -DTRIBE_MACOS_XRAY_CORE_VERSION='"1.260728.0"' \
  -DTRIBE_MACOS_XRAY_SOURCE_COMMIT='"abcdef0123456789abcdef0123456789abcdef01"' \
  -DTRIBE_MACOS_XRAY_ABI='"libxray-c-v1"' \
  -DTRIBE_CATALOG_ROOT_KID='"root-k1"' \
  -DTRIBE_CATALOG_ROOT_PUBLIC_KEY_HEX='"95da1bb537bf6b8b6f57fcf16d943092017987e9050143bbc04f9710b094075a"' \
  "$HERE/../CatalogProductRuntime.cpp" \
  "$HERE/../VpnConnectionTransportAdapter.cpp"

echo ">>> product composition/native adapter syntax ok"
