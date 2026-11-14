#!/bin/bash
# H-4 (HARDENING-BACKLOG): гейт сверки never-bypass. Клиент (BypassListTypes.h::
# neverBypassRanges) и бэкенд (src/tribe_backend/bypass_lists.py::NEVER_BYPASS_CIDRS) держат
# по РУЧНОЙ копии одного списка; расхождение = диапазон уходит мимо туннеля на одной
# из сторон. Гейт сверяет копии побайтово (как множества CIDR). Правишь список —
# правь ОБЕ копии одним заходом; этот скрипт не даст забыть.
# Форма бэкенда с PR #388: `NEVER_BYPASS_CIDRS: tuple[str, ...] = (...)` (кортеж строк), рядом
# `NEVER_BYPASS = [ipaddress.ip_network(c) for c in NEVER_BYPASS_CIDRS]`. Старая форма
# `NEVER_BYPASS = [...]` со строками тоже понимается. Не нашли список — FAIL, а не тихий SKIP.
# Нет локального чекаута бэкенда (каталога) → SKIP (exit 0 с предупреждением), не ложный FAIL.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT_H="$HERE/../BypassListTypes.h"
BACKEND_DIR="${TRIBE_BACKEND_DIR:-$HOME/IdeaProjects/Tribe Backend}"
BACKEND_PY="$BACKEND_DIR/src/tribe_backend/bypass_lists.py"

if [ ! -d "$BACKEND_DIR" ]; then
    echo ">>> SKIP neverbypass-sync: нет локальной копии бэкенда ($BACKEND_DIR)"
    exit 0
fi
if [ ! -f "$BACKEND_PY" ]; then
    echo "FAIL neverbypass-sync: бэкенд есть ($BACKEND_DIR), а файла списка нет: $BACKEND_PY — список переехал?"
    exit 1
fi

# Блок списка бэкенда: от строки объявления до закрывающей скобки в начале строки.
# 1) NEVER_BYPASS_CIDRS[: аннотация] = (   ...   )
# 2) старая форма NEVER_BYPASS = [   ...   ]
backend_block() {
    awk '
        BEGIN { inside = 0; found = 0; closed = 0 }
        !found && /^NEVER_BYPASS_CIDRS[^=]*=[[:space:]]*\([[:space:]]*(#.*)?$/ { found = 1; inside = 1; next }
        inside && /^\)/ { inside = 0; closed = 1; exit }
        inside { print }
        END { if (!found) exit 2; if (!closed) exit 3 }
    ' "$BACKEND_PY"
}
backend_block_legacy() {
    awk '
        BEGIN { inside = 0; found = 0; closed = 0 }
        !found && /^NEVER_BYPASS[[:space:]]*(:[^=]*)?=[[:space:]]*\[[[:space:]]*(#.*)?$/ { found = 1; inside = 1; next }
        inside && /^\]/ { inside = 0; closed = 1; exit }
        inside { print }
        END { if (!found) exit 2; if (!closed) exit 3 }
    ' "$BACKEND_PY"
}

rc=0
block=$(backend_block) || rc=$?
if [ "$rc" -eq 2 ]; then
    rc=0
    block=$(backend_block_legacy) || rc=$?
fi
case "$rc" in
    0) ;;
    2) echo "FAIL neverbypass-sync: в $BACKEND_PY нет ни NEVER_BYPASS_CIDRS = (...), ни NEVER_BYPASS = [...] — парсер устарел?"; exit 1 ;;
    3) echo "FAIL neverbypass-sync: список в $BACKEND_PY не закрыт скобкой в начале строки — парсер устарел?"; exit 1 ;;
    *) echo "FAIL neverbypass-sync: awk упал (код $rc) на $BACKEND_PY"; exit 1 ;;
esac

client=$(awk '/neverBypassRanges/,/^}/' "$CLIENT_H" \
    | grep -o 'QStringLiteral("[^"]*")' | sed 's/QStringLiteral("//;s/")//' | sort || true)
backend=$(printf '%s\n' "$block" | sed 's/#.*//' | grep -o '"[^"]*"' | tr -d '"' | sort || true)

if [ -z "$client" ] || [ -z "$backend" ]; then
    echo "FAIL neverbypass-sync: не смог извлечь список (клиент: $(printf '%s' "$client" | grep -c . || true), бэк: $(printf '%s' "$backend" | grep -c . || true)) — парсер сломался о рефакторинг?"
    exit 1
fi
# Каждая строка обеих копий обязана быть CIDR (иначе парсер зацепил чужие строки).
cidr_re='^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$|^[0-9a-fA-F:]+/[0-9]{1,3}$'
bad=$(printf '%s\n%s\n' "$client" "$backend" | grep -Ev "$cidr_re" || true)
if [ -n "$bad" ]; then
    echo "FAIL neverbypass-sync: не CIDR в извлечённом списке — парсер зацепил лишнее:"
    printf '%s\n' "$bad"
    exit 1
fi

if [ "$client" != "$backend" ]; then
    echo "FAIL neverbypass-sync: копии разошлись (клиент vs бэкенд):"
    diff <(echo "$client") <(echo "$backend") || true
    exit 1
fi

echo ">>> neverbypass-sync ок: $(echo "$client" | grep -c .) диапазонов идентичны в обеих копиях"
