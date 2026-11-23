#!/bin/bash
# AVPN_ENGINE=OFF (the pure upstream fork, client/cmake/avpn.cmake returns before add_compile_definitions) still compiles
# the upstream files the overlay touches (review R2 of 5c354b603: amneziaApplication.cpp named TribeNetworkAccessManager
# outside #ifdef AVPN_ENGINE_ENABLED). Syntax-level compile (clang -fsyntax-only: no object, no link, no moc) with the
# include paths and defines of a real macOS desktop build tree (its flags.make; generated headers are read from that
# tree, the sources from THIS checkout), once with AVPN_ENGINE_ENABLED removed and once as configured.
#   BUILD_DIR=<macOS build tree> (default ~/amnezia-client/deploy/build-macos-desktop)
# What the OFF build does there (upstream's QNetworkAccessManager and clear on Connected) - check_net_reset_wiring.sh N4.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$(cd "$HERE/../../.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$HOME/amnezia-client/deploy/build-macos-desktop}"
FLAGS_MAKE="$BUILD_DIR/client/CMakeFiles/AmneziaVPN.dir/flags.make"
[ -f "$FLAGS_MAKE" ] || { echo "no flags.make at $FLAGS_MAKE"; exit 2; }
ORIG_CLIENT="$(grep -E '^CXX_INCLUDES' "$FLAGS_MAKE" | tr ' ' '\n' | grep -E '^-I.*/client$' | grep -vxF -- "-I${BUILD_DIR%/}/client" | grep -v deploy | head -1 | sed 's/^-I//')"
rewrite() { sed "s#${ORIG_CLIENT}#${CLIENT}#g"; }
INCLUDES="$(grep -E '^CXX_INCLUDES' "$FLAGS_MAKE" | sed 's/^CXX_INCLUDES = //' | rewrite)"
MAIN_CLIENT="${AVPN_MAIN_CLIENT:-$HOME/amnezia-client/client}"
INCLUDES="$INCLUDES -I$MAIN_CLIENT -I$MAIN_CLIENT/3rd/qtkeychain"
DEFINES_ON="$(grep -E '^CXX_DEFINES' "$FLAGS_MAKE" | sed 's/^CXX_DEFINES = //')"
printf '%s\n' "$DEFINES_ON" | grep -q -- '-DAVPN_ENGINE_ENABLED' || { echo "the build tree is not an AVPN_ENGINE=ON tree"; exit 2; }
DEFINES_OFF="$(printf '%s\n' "$DEFINES_ON" | sed 's/-DAVPN_ENGINE_ENABLED[=0-9]*//g') -UAVPN_ENGINE_ENABLED"
CXXFLAGS="$(grep -E '^CXX_FLAGS =' "$FLAGS_MAKE" | sed 's/^CXX_FLAGS = //')"
TUS=(
  "$CLIENT/amneziaApplication.cpp"
  "$CLIENT/ui/controllers/connectionUiController.cpp"
)
ERR="$(mktemp /tmp/engine_off_compile.XXXXXX)"
trap 'rm -f -- "$ERR"' EXIT
fail=0
for mode in OFF ON; do
  if [ "$mode" = OFF ]; then defs="$DEFINES_OFF"; else defs="$DEFINES_ON"; fi
  for tu in "${TUS[@]}"; do
    # shellcheck disable=SC2086
    if eval clang++ $CXXFLAGS $defs $INCLUDES -fsyntax-only -Wno-deprecated-declarations "\"$tu\"" 2>"$ERR"; then
      echo "AVPN_ENGINE=$mode syntax OK: ${tu#$CLIENT/}"
    else
      echo "AVPN_ENGINE=$mode syntax FAIL: ${tu#$CLIENT/}"; grep -m 20 "error:" "$ERR"; fail=1
    fi
  done
done
[ "$fail" = "0" ] && echo "check_engine_off_compile: OK"
exit "$fail"
