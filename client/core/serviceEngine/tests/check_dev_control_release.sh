#!/bin/bash
# AVPN (desktop test rig): a build without the desktop development tools carries no byte of the test command channel
# (core/serviceEngine/DevControl.h, DevControlApp.h).
#   D1  cmake/avpn.cmake: AVPN_DEV_TOOLS defaults OFF; the channel's sources and its define AVPN_DESKTOP_TEST_CHANNEL
#       appear only inside `if(AVPN_DEV_TOOLS AND NOT IOS AND NOT ANDROID AND NOT MACOS_NE)`; no other CMake file
#       names them.
#   D2  every other source that names the channel does so only between #ifdef AVPN_DESKTOP_TEST_CHANNEL and its
#       #endif (today: core/controllers/coreController.cpp, one include and one install line).
#   D3  no QML, qrc or resource file carries a marker string of the channel (QML ships as text in every build).
#   D4  compile proof with the flags of a real macOS build tree (BUILD_DIR; objects into a temporary directory, no
#       link): coreController.cpp as the tree is configured (AVPN_DEV_TOOLS=OFF, the release configuration) has no
#       channel symbol and no marker string; with AVPN_DEV_TOOLS=1 + AVPN_DESKTOP_TEST_CHANNEL=1 it calls
#       avpn::devctl::install, and the three channel sources compile with the app's flags.
#   --binary <file>  also: a built app binary (Contents/MacOS/TribeVPN) has no marker string - for a release script
#       after its build.
#   BUILD_DIR=<macOS build tree, ninja or make> (default ~/avpn-build/lead-142-mac-xray-mac-build, else
#   ~/amnezia-client/deploy/build-macos-desktop); without one D4 is reported SKIPPED, D1-D3 still decide.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$(cd "$HERE/../../.." && pwd)"
CMAKE="$CLIENT/cmake/avpn.cmake"
BIN=""
[ "${1:-}" = "--binary" ] && BIN="${2:?--binary <file>}"
# Marker strings: in the channel's sources only (DevControl*.cpp); none of them is a word the app uses elsewhere.
MARKERS='avpn-devctl|avpn devctl|AVPN-devctl-|/control\.sock|devctl::|DevControl|AVPN_DESKTOP_TEST_CHANNEL'
fail=0
bad() { echo "FAIL: $1"; fail=1; }

# ---- D1 ------------------------------------------------------------------------------------------------------------
grep -Eq '^option\(AVPN_DEV_TOOLS "[^"]*" OFF\)' "$CMAKE" || bad "D1: option AVPN_DEV_TOOLS does not default to OFF"
GUARD='if(AVPN_DEV_TOOLS AND NOT IOS AND NOT ANDROID AND NOT MACOS_NE)'
grep -qxF "$GUARD" "$CMAKE" || bad "D1: the channel's guard block is missing in avpn.cmake"
# lines naming the channel outside the guard block (comments stripped; nested if/endif counted)
outside="$(sed 's/#.*$//' "$CMAKE" | awk -v g="$GUARD" '
  { line = $0; t = line; gsub(/^[ \t]+|[ \t]+$/, "", t) }
  depth == 0 && t == g { depth = 1; next }
  depth > 0 && t ~ /^if\(/ { depth++ }
  depth > 0 && t ~ /^endif\(/ { depth--; next }
  depth == 0 && line ~ /DevControl|AVPN_DESKTOP_TEST_CHANNEL/ { print NR": "line }')"
[ -z "$outside" ] || bad "D1: the channel is named outside its guard in avpn.cmake: $outside"
inside="$(sed 's/#.*$//' "$CMAKE" | awk -v g="$GUARD" '
  { t = $0; gsub(/^[ \t]+|[ \t]+$/, "", t) }
  depth == 0 && t == g { depth = 1; next }
  depth > 0 && t ~ /^if\(/ { depth++ }
  depth > 0 && t ~ /^endif\(/ { depth--; next }
  depth > 0 && /DevControl\.cpp/ { n++ } END { print n + 0 }')"
[ "$inside" -ge 1 ] || bad "D1: the guard block does not add the channel's sources"
others="$(grep -RlE 'DevControl|AVPN_DESKTOP_TEST_CHANNEL' "$CLIENT/CMakeLists.txt" "$CLIENT/cmake" 2>/dev/null | grep -vxF "$CMAKE")"
[ -z "$others" ] || bad "D1: another CMake file names the channel: $others"

# ---- D2 ------------------------------------------------------------------------------------------------------------
# Outside the channel's own files and the tests, a line naming the channel must sit inside #ifdef
# AVPN_DESKTOP_TEST_CHANNEL (preprocessor nesting followed).
while IFS= read -r f; do
  case "$f" in
    */core/serviceEngine/DevControl*|*/core/serviceEngine/tests/*|*/tests/tools/*) continue ;;
  esac
  leak="$(awk '
    /^[ \t]*#[ \t]*if/ { depth++; ch[depth] = ($0 ~ /^[ \t]*#[ \t]*ifdef[ \t]+AVPN_DESKTOP_TEST_CHANNEL([ \t]|$)/) ? 1 : 0; next }
    /^[ \t]*#[ \t]*(else|elif)/ { if (ch[depth]) ch[depth] = 0; next }
    /^[ \t]*#[ \t]*endif/ { ch[depth] = 0; depth--; next }
    /DevControl|devctl::/ { ok = 0; for (i = 1; i <= depth; i++) if (ch[i]) ok = 1; if (!ok) print FILENAME":"NR": "$0 }' "$f")"
  [ -z "$leak" ] || bad "D2: the channel is named outside #ifdef AVPN_DESKTOP_TEST_CHANNEL: $leak"
done < <(grep -RlE 'DevControl|devctl::' "$CLIENT" --include='*.cpp' --include='*.h' --include='*.mm' 2>/dev/null)

# ---- D3 ------------------------------------------------------------------------------------------------------------
qmlhits="$(grep -RlE "$MARKERS" "$CLIENT/ui" "$CLIENT/resources" --include='*.qml' --include='*.js' --include='*.qrc' \
           --include='*.json' 2>/dev/null)"
[ -z "$qmlhits" ] || bad "D3: a QML/resource file carries a channel marker: $qmlhits"

# ---- D4 ------------------------------------------------------------------------------------------------------------
if [ -z "${BUILD_DIR:-}" ]; then
  BUILD_DIR="$HOME/avpn-build/lead-142-mac-xray-mac-build"
  [ -f "$BUILD_DIR/build.ninja" ] || BUILD_DIR="$HOME/amnezia-client/deploy/build-macos-desktop"
fi
REL="client/CMakeFiles/AmneziaVPN.dir/core/controllers/coreController.cpp.o"
DEFS=""; FLAGS=""; INCS=""; ORIG=""
if [ -f "$BUILD_DIR/build.ninja" ]; then
  blk="$(awk -v r="build $REL:" 'index($0, r) == 1 { f = 1; print; next } f && /^  / { print; next } f { exit }' "$BUILD_DIR/build.ninja")"
  ORIG="$(printf '%s\n' "$blk" | head -1 | sed -E 's#^build [^:]+: [^ ]+ ([^ ]+)/core/controllers/coreController\.cpp.*#\1#')"
  DEFS="$(printf '%s\n' "$blk" | sed -n 's/^  DEFINES = //p')"
  FLAGS="$(printf '%s\n' "$blk" | sed -n 's/^  FLAGS = //p')"
  INCS="$(printf '%s\n' "$blk" | sed -n 's/^  INCLUDES = //p')"
elif [ -f "$BUILD_DIR/client/CMakeFiles/AmneziaVPN.dir/flags.make" ]; then
  FM="$BUILD_DIR/client/CMakeFiles/AmneziaVPN.dir/flags.make"
  DEFS="$(sed -n 's/^CXX_DEFINES = //p' "$FM")"
  FLAGS="$(sed -n 's/^CXX_FLAGS = //p' "$FM")"
  INCS="$(sed -n 's/^CXX_INCLUDES = //p' "$FM")"
  ORIG="$(printf '%s\n' "$INCS" | tr ' ' '\n' | grep -E '^-I.*/client$' | grep -vxF -- "-I${BUILD_DIR%/}/client" | grep -v deploy | head -1 | sed 's/^-I//')"
fi
if [ -z "$DEFS" ] || [ -z "$ORIG" ]; then
  echo "D4: SKIPPED - no macOS build tree at $BUILD_DIR (set BUILD_DIR)"
else
  case "$DEFS" in *-DAVPN_ENGINE_ENABLED*) ;; *) bad "D4: $BUILD_DIR is not an AVPN_ENGINE=ON tree" ;; esac
  case "$DEFS" in *-DAVPN_DEV_TOOLS*) bad "D4: $BUILD_DIR is configured with AVPN_DEV_TOOLS - not a release configuration" ;; esac
  # sources from THIS checkout; what a worktree lacks (the 3rd/ submodules) from the tree's own checkout, searched last
  INCS="${INCS//$ORIG/$CLIENT} -I$ORIG -I$ORIG/3rd/qtkeychain"
  QT_BIN_DIR="${QT_ROOT:-$HOME/Qt/6.11.1/macos}"
  W="$(mktemp -d "${TMPDIR:-/tmp}/avpn_devctl_rel.XXXXXX")"
  trap 'rm -rf "${W:?}"' EXIT
  compile() { # <out.o> <extra defines> <source> [extra flags]
    eval clang++ $FLAGS $DEFS $2 $INCS ${4:-} -Wno-deprecated-declarations -c "\"$3\"" -o "\"$1\"" 2>"$W/err.txt"
  }
  if compile "$W/off.o" "" "$CLIENT/core/controllers/coreController.cpp"; then
    syms="$(nm -u "$W/off.o" | c++filt | grep -c 'devctl' || true)"
    strs="$(strings -a "$W/off.o" | grep -cE "$MARKERS" || true)"
    [ "$syms" = 0 ] && [ "$strs" = 0 ] && echo "D4: release configuration: coreController.o has no channel symbol and no marker" \
      || bad "D4: the release configuration's coreController.o carries the channel ($syms symbols, $strs strings)"
  else
    bad "D4: coreController.cpp does not compile in the release configuration"; grep -m 10 'error:' "$W/err.txt"
  fi
  ON="-DAVPN_DEV_TOOLS=1 -DAVPN_DESKTOP_TEST_CHANNEL=1"
  if compile "$W/on.o" "$ON" "$CLIENT/core/controllers/coreController.cpp"; then
    nm -u "$W/on.o" | c++filt | grep -q 'avpn::devctl::install' \
      && echo "D4: development configuration: coreController.o calls avpn::devctl::install" \
      || bad "D4: with the channel on, coreController.o does not install it"
  else
    bad "D4: coreController.cpp does not compile with the channel on"; grep -m 10 'error:' "$W/err.txt"
  fi
  "$QT_BIN_DIR/libexec/moc" -I"$CLIENT/core/serviceEngine" "$CLIENT/core/serviceEngine/DevControlApp.cpp" -o "$W/DevControlApp.moc"
  label=""; [ -f "$BUILD_DIR/client/avpn_git_commit.h" ] && label="-include $BUILD_DIR/client/avpn_git_commit.h"
  for src in DevControl.cpp DevControlApp.cpp DevControlInstall.cpp; do
    extra="-I$W -Werror=return-type"; [ "$src" = DevControlInstall.cpp ] && extra="$extra $label"
    if compile "$W/$src.o" "$ON" "$CLIENT/core/serviceEngine/$src" "$extra"; then
      warn="$(grep -c 'warning:' "$W/err.txt" || true)"
      echo "D4: $src compiles with the app's flags (warnings: $warn)"
    else
      bad "D4: $src does not compile with the app's flags"; grep -m 10 'error:' "$W/err.txt"
    fi
  done
fi

# ---- --binary ------------------------------------------------------------------------------------------------------
if [ -n "$BIN" ]; then
  [ -f "$BIN" ] || bad "--binary: no file $BIN"
  hits="$(strings -a "$BIN" 2>/dev/null | grep -cE "$MARKERS" || true)"
  [ "$hits" = 0 ] && echo "binary: no channel marker in $BIN" || bad "binary: $hits channel marker strings in $BIN"
fi

[ "$fail" = 0 ] && echo "check_dev_control_release: OK"
exit "$fail"
