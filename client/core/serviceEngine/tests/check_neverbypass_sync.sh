#!/bin/bash
# H-4 (HARDENING-BACKLOG): гейт сверки never-bypass. Клиент (BypassListTypes.h::
# neverBypassRanges) и бэкенд (src/tribe_backend/bypass_lists.py::NEVER_BYPASS) держат
# по РУЧНОЙ копии одного списка; расхождение = диапазон уходит мимо туннеля на одной
# из сторон. Гейт сверяет копии побайтово (как множества CIDR). Правишь список —
# правь ОБЕ копии одним заходом; этот скрипт не даст забыть.
# Нет локального чекаута бэкенда → SKIP (exit 0 с предупреждением), не ложный FAIL.
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT_H="$HERE/../BypassListTypes.h"
BACKEND_PY="${TRIBE_BACKEND_DIR:-$HOME/IdeaProjects/Tribe Backend}/src/tribe_backend/bypass_lists.py"

if [ ! -f "$BACKEND_PY" ]; then
    echo ">>> SKIP neverbypass-sync: нет локальной копии бэкенда ($BACKEND_PY)"
    exit 0
fi

client=$(awk '/neverBypassRanges/,/^}/' "$CLIENT_H" \
    | grep -o 'QStringLiteral("[^"]*")' | sed 's/QStringLiteral("//;s/")//' | sort)
backend=$(awk '/^NEVER_BYPASS/,/^\]/' "$BACKEND_PY" \
    | grep -o '"[^"]*"' | tr -d '"' | sort)

if [ -z "$client" ] || [ -z "$backend" ]; then
    echo "FAIL neverbypass-sync: не смог извлечь список (клиент: $(echo "$client" | grep -c .), бэк: $(echo "$backend" | grep -c .)) — парсер сломался о рефакторинг?"
    exit 1
fi

if [ "$client" != "$backend" ]; then
    echo "FAIL neverbypass-sync: копии разошлись (клиент vs бэкенд):"
    diff <(echo "$client") <(echo "$backend") || true
    exit 1
fi

echo ">>> neverbypass-sync ок: $(echo "$client" | grep -c .) диапазонов идентичны в обеих копиях"
