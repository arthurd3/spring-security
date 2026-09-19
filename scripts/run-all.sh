#!/usr/bin/env bash
#
# Runs every self-contained attack demo in order (01..26). No server needed - each demo compiles
# and runs its own .java (the vulnerable code + the safe code + an attacker), printing the result.
#
# Usage:
#   scripts/run-all.sh              # pause between each (press ENTER)
#   scripts/run-all.sh --no-pause   # run straight through
#
DIR="$(cd "$(dirname "$0")" && pwd)"; source "$DIR/lib/common.sh"; ensure_java
PAUSE=1; [ "${1:-}" = "--no-pause" ] && PAUSE=0

count=0
for d in "$DIR"/attacks/[0-9]*/; do
  script=$(ls "$d"/*.sh 2>/dev/null | head -1)
  [ -n "$script" ] || continue
  count=$((count + 1))
  bash "$script"
  if [ "$PAUSE" = "1" ]; then
    printf '\n%s[ENTER para o proximo, Ctrl-C para sair]%s ' "${C_DIM}" "${C_RESET}"
    read -r _ </dev/tty || break
  fi
done
printf '\n%s%d ataques demonstrados.%s Cada um roda o codigo em attacks/<nn-nome>/*.java\n' \
  "${C_BOLD}" "$count" "${C_RESET}"
