#!/bin/bash
# bundle-daemon-qt.sh — делает root-демон Tribe-service самодостаточным:
# вшивает транзитивное замыкание его не-системных зависимостей (Qt + openssl)
# в <daemon_dir>/Frameworks и переписывает rpath на @loader_path/Frameworks,
# убирая dev-пути (~/Qt, ~/.conan2). После этого демон запускается на машине БЕЗ Qt.
#
# Использование: bundle-daemon-qt.sh SERVICE_DIR APP_FRAMEWORKS_DIR QT_LIB_DIR [service|app]
# Источники фреймворков: уже развёрнутый TribeVPN.app/Contents/Frameworks (macdeployqt),
# затем ~/Qt/<ver>/macos/lib, затем conan-каталог из текущего rpath бинаря.
set -euo pipefail

SRVDIR="${1:?укажи каталог с Tribe-service}"
DAEMON="$SRVDIR/Tribe-service"
[ -x "$DAEMON" ] || { echo "нет $DAEMON"; exit 1; }

APP_FW="${TRIBE_APP_FRAMEWORKS_DIR:-${2:-}}"
QT_LIB="${TRIBE_QT_LIB_DIR:-${3:-}}"
LAYOUT="${4:-service}"
[ -d "$APP_FW" ] || { echo "нет app Frameworks: $APP_FW"; exit 1; }
[ -d "$QT_LIB" ] || { echo "нет Qt lib: $QT_LIB"; exit 1; }
case "$LAYOUT" in service|app) ;; *) echo "unknown daemon layout: $LAYOUT" >&2; exit 1 ;; esac

RUNTIME_EXECUTABLES=(Tribe-service amneziawg-go openvpn tun2socks)
for executable in "${RUNTIME_EXECUTABLES[@]}"; do
  [ -x "$SRVDIR/$executable" ] || { echo "нет runtime helper $SRVDIR/$executable"; exit 1; }
done
[ -s "$SRVDIR/geoip.dat" ] && [ -s "$SRVDIR/geosite.dat" ] \
  || { echo "нет Xray geodata рядом с демоном"; exit 1; }

if [ "$LAYOUT" = service ]; then
  FW="$SRVDIR/Frameworks"
  rm -rf "$FW"
  mkdir -p "$FW"
  RUNTIME_RPATH="@loader_path/Frameworks"
else
  # CPack initially stages helpers next to the GUI executable. Add any
  # service-only Qt module (notably QtDBus) to the app's notarization-visible
  # Frameworks closure before the first sanitizer/signing pass.
  FW="$(cd "$APP_FW" && pwd -P)"
  APP_ROOT="$(cd "$SRVDIR/../.." && pwd -P)"
  [ "$FW" = "$APP_ROOT/Contents/Frameworks" ] \
    || { echo "app layout Frameworks does not belong to $APP_ROOT" >&2; exit 1; }
  RUNTIME_RPATH="@loader_path/../Frameworks"
fi

# Conan-каталоги из rpath всех запускаемых файлов (для libssl/libcrypto).
CONAN_DIRS=""
for executable in "${RUNTIME_EXECUTABLES[@]}"; do
  rpaths="$(otool -l "$SRVDIR/$executable" \
    | awk '/LC_RPATH/{f=1} f&&/path/{print $2; f=0}' \
    | grep -E 'conan2|/p/lib' || true)"
  [ -z "$rpaths" ] || CONAN_DIRS="$CONAN_DIRS $rpaths"
done

# Найти исходник зависимости по её @rpath-имени (framework path или dylib).
find_src() {
  local dep="$1"               # напр. QtCore.framework/Versions/A/QtCore  или  libssl.3.dylib
  case "$dep" in
    *.framework/*)
      local fwname="${dep%%.framework/*}.framework"   # QtCore.framework
      for base in "$APP_FW" "$QT_LIB"; do
        [ -d "$base/$fwname" ] && { echo "$base/$fwname"; return; }
      done ;;
    *)
      local b
      b="$(basename "$dep")"
      [ -f "$APP_FW/$b" ] && { echo "$APP_FW/$b"; return; }
      for d in $CONAN_DIRS "$QT_LIB"; do
        [ -f "$d/$b" ] && { echo "$d/$b"; return; }
      done ;;
  esac
  return 1
}

# /bin/bash on supported macOS is still 3.2 and has no associative arrays.
# A newline-delimited set is sufficient because Mach-O dependency paths cannot contain newlines.
DONE=$'\n'
queue=()

enqueue_deps() {  # вытащить @rpath-зависимости из бинаря, добавить в очередь
  local bin="$1"
  while read -r dep; do
    [ -z "$dep" ] && continue
    queue+=("${dep#@rpath/}")
  done < <(otool -L "$bin" | awk '/@rpath\//{print $1}')
}

for executable in "${RUNTIME_EXECUTABLES[@]}"; do
  enqueue_deps "$SRVDIR/$executable"
done

while [ ${#queue[@]} -gt 0 ]; do
  dep="${queue[0]}"; queue=("${queue[@]:1}")
  case "$DONE" in *$'\n'"$dep"$'\n'*) continue ;; esac
  DONE="${DONE}${dep}"$'\n'
  src="$(find_src "$dep")" || { echo "НЕ НАЙДЕН источник: $dep" >&2; exit 1; }
  case "$dep" in
    *.framework/*)
      fwname="${dep%%.framework/*}.framework"
      if [ ! -d "$FW/$fwname" ]; then
        cp -aR "$src" "$FW/$fwname"
        echo "  + $fwname"
        enqueue_deps "$FW/$fwname/Versions/A/${fwname%.framework}"
      fi ;;
    *)
      b="$(basename "$dep")"
      if [ ! -f "$FW/$b" ]; then
        cp -aL "$src" "$FW/$b"; chmod u+w "$FW/$b"
        echo "  + $b"
        enqueue_deps "$FW/$b"
      fi ;;
  esac
done

# Every privileged executable must be independent of ~/Qt and ~/.conan2.
for executable in "${RUNTIME_EXECUTABLES[@]}"; do
  binary="$SRVDIR/$executable"
  # CMake's install(FILES ... PERMISSIONS) stages helpers read/execute-only.
  # install_name_tool needs owner write access before the final signed/mode-
  # normalized payload is produced.
  chmod u+w "$binary"
  while IFS= read -r rp; do
    [ -z "$rp" ] || install_name_tool -delete_rpath "$rp" "$binary" 2>/dev/null || true
  done < <(otool -l "$binary" | awk '/LC_RPATH/{f=1} f&&/path/{print $2; f=0}')
  install_name_tool -add_rpath "$RUNTIME_RPATH" "$binary"
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
if [ "$LAYOUT" = service ]; then
  "$SCRIPT_DIR/verify-macos-runtime.sh" service "$SRVDIR"
else
  # The CPack caller immediately runs sanitize-macos-app.sh, which removes
  # unsupported SQL plugins and then verifies the complete GUI/helper closure.
  echo "app daemon closure staged; final app verification is pending sanitizer"
fi

echo "=== Готово. Вшито в $FW: ==="
ls "$FW"
echo "=== rpath runtime helpers теперь: ==="
for executable in "${RUNTIME_EXECUTABLES[@]}"; do
  echo "  $executable"
  otool -l "$SRVDIR/$executable" | awk '/LC_RPATH/{f=1} f&&/path/{print "    ",$2; f=0}'
done
