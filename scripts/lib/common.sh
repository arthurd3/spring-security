#!/usr/bin/env bash
#
# Shared helpers for the self-contained attack demos under scripts/attacks/<nn-name>/.
#
# Each demo is a folder with:
#   - <nn-name>.sh      : the layperson explanation, then it SHOWS and RUNS the .java below
#   - <Name>Demo.java   : self-contained code = the VULNERABLE version + the SAFE version + a
#                         tiny attacker `main` that runs both and prints the result
#
# The .java is executed with `java` in single-file source mode (JDK 17+). Demos that need real
# libraries (H2, Jackson, SpEL, BCrypt, Nimbus) get them from scripts/lib/classpath.txt, generated
# once by scripts/build-classpath.sh. No server is required.
#
# Config (env): NO_COLOR to disable colours.

set -uo pipefail

LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLASSPATH_FILE="${LIB_DIR}/classpath.txt"

# ----- colours -------------------------------------------------------------------------------------
if [ -n "${NO_COLOR:-}" ] || [ ! -t 1 ]; then
  C_RESET=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_CYAN=""; C_DIM=""; C_BOLD=""
else
  ESC=$(printf '\033')
  C_RESET="${ESC}[0m"; C_RED="${ESC}[31m"; C_GREEN="${ESC}[32m"; C_YELLOW="${ESC}[33m"
  C_BLUE="${ESC}[34m"; C_CYAN="${ESC}[36m"; C_DIM="${ESC}[2m"; C_BOLD="${ESC}[1m"
fi

hr() { printf '%s\n' "${C_DIM}------------------------------------------------------------------------${C_RESET}"; }

title() {
  printf '\n%s\n' "${C_BOLD}========================================================================${C_RESET}"
  printf '%s\n'   "${C_BOLD}  $1${C_RESET}"
  printf '%s\n'   "${C_BOLD}========================================================================${C_RESET}"
}

section() { printf '\n%s\n' "${C_BOLD}${C_BLUE}$1. $2${C_RESET}"; }
para()    { printf '%s\n' "$1" | fold -s -w 86 | sed 's/^/  /'; }
term()    { printf '  %s%s%s: ' "${C_CYAN}" "$1" "${C_RESET}"; printf '%s\n' "$2" | fold -s -w 82 | sed '1s/^/ /; 2,$s/^/    /'; }
ref()     { printf '  %s->%s %s\n' "${C_DIM}" "${C_RESET}" "$1"; }

# show_code FILE -> prints the source (numbered, dimmed) so the learner sees the exact code that runs.
show_code() {
  local file="$1"
  printf '  %s%s%s\n' "${C_DIM}" "--- $(basename "$file") ---------------------------------------------" "${C_RESET}"
  nl -ba -w2 -s'  ' "$file" | sed "s/^/  ${C_DIM}/; s/\$/${C_RESET}/"
}

# run_demo FILE -> compiles+runs the .java in source mode, colouring [VULNERAVEL]/[DEFENDIDO] lines.
run_demo() {
  local file="$1" cp=""
  [ -s "$CLASSPATH_FILE" ] && cp="$(cat "$CLASSPATH_FILE")"
  local out
  if [ -n "$cp" ]; then
    out="$(java -cp "$cp" "$file" 2>&1)"
  else
    out="$(java "$file" 2>&1)"
  fi
  printf '%s\n' "$out" | while IFS= read -r line; do
    case "$line" in
      "[VARIANT]"*)    printf '\n  %s%s%s\n' "${C_BOLD}${C_CYAN}" "${line#\[VARIANT\] }" "${C_RESET}" ;;
      "[VULNERAVEL]"*) printf '  %sXX %s%s\n' "${C_RED}"    "${line#\[VULNERAVEL\] }" "${C_RESET}" ;;
      "[VULNERAVEL]")  printf '  %sXX%s\n'     "${C_RED}"    "${C_RESET}" ;;
      "[DEFENDIDO]"*)  printf '  %sOK %s%s\n'  "${C_GREEN}"  "${line#\[DEFENDIDO\] }"  "${C_RESET}" ;;
      "[INFO]"*)       printf '  %s.. %s%s\n'  "${C_YELLOW}" "${line#\[INFO\] }"       "${C_RESET}" ;;
      *)               printf '       %s\n' "$line" ;;
    esac
  done
}

# level "Basico" "texto..." -> a labelled paragraph for the layered explanation.
level() {
  printf '  %s%s%s\n' "${C_BOLD}${C_YELLOW}" "[$1]" "${C_RESET}"
  printf '%s\n' "$2" | fold -s -w 84 | sed 's/^/    /'
}

# doc_pointer DIR -> points the reader to the deep-dive and the payload cheatsheet in this folder.
doc_pointer() {
  local dir="$1"
  printf '  %s->%s Aprofundamento completo: %sDEEP-DIVE.md%s   |   cheatsheet: %spayloads.txt%s\n' \
    "${C_DIM}" "${C_RESET}" "${C_CYAN}" "${C_RESET}" "${C_CYAN}" "${C_RESET}"
  printf '     %s%s%s\n' "${C_DIM}" "$dir" "${C_RESET}"
}

footer() {
  hr
  para "${C_DIM}Verde = a versao segura barrou o ataque. Vermelho = o mesmo ataque teve sucesso contra o codigo vulneravel (ambos estao no .java acima).${C_RESET}"
  para "${C_DIM}O codigo que roda esta no arquivo .java desta pasta. Rode todos com: scripts/run-all.sh${C_RESET}"
}

# ensure_java -> checks the JDK is present (source-file mode needs 11+; project targets 17+).
ensure_java() {
  if ! command -v java >/dev/null 2>&1; then
    printf '%sJava nao encontrado no PATH. Instale um JDK 17+ para rodar os exploits.%s\n' "${C_RED}" "${C_RESET}"
    exit 1
  fi
}
