#!/bin/bash
# Автономная сборка+запуск проверки политики фонового времени iOS для перезапуска туннеля
# (RestartGuard.h, разбор 2026-09-23). Заголовок без Qt — только C++17.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="${OUT_DIR:-$(mktemp -d /tmp/tribe-restart-guard.XXXXXX)}"
mkdir -p "$OUT_DIR"
clang++ -std=c++17 -Wall -Wextra -Werror -I"$HERE/.." \
  "$HERE/restart_guard_check.cpp" -o "$OUT_DIR/restart_guard_check"
"$OUT_DIR/restart_guard_check"
