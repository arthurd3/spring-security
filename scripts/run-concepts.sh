#!/usr/bin/env bash
# Runs the cross-cutting concept demos (the "connected knowledge" behind the attacks).
# Usage: scripts/run-concepts.sh [--no-pause]
DIR="$(cd "$(dirname "$0")" && pwd)"; source "$DIR/lib/common.sh"; ensure_java
PAUSE=1; [ "${1:-}" = "--no-pause" ] && PAUSE=0
count=0
for d in "$DIR"/concepts/*/; do
  script=$(ls "$d"/*.sh 2>/dev/null | head -1); [ -n "$script" ] || continue
  count=$((count+1)); bash "$script"
  if [ "$PAUSE" = "1" ]; then printf '\n%s[ENTER para o proximo, Ctrl-C para sair]%s ' "${C_DIM}" "${C_RESET}"; read -r _ </dev/tty || break; fi
done
printf '\n%s%d conceitos demonstrados.%s Volte aos ataques em scripts/attacks/ ; veja as "Trilhas" em cada DEEP-DIVE.md\n' "${C_BOLD}" "$count" "${C_RESET}"
