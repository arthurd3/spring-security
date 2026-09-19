#!/usr/bin/env bash
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/../../lib/common.sh"; ensure_java
title "CONCEITO: comparacao em tempo constante"
section 1 "O que e (para leigos)"
para "Se o servidor compara o seu token com o segredo parando no primeiro caractere diferente, ele responde um POUQUINHO mais rapido quando voce erra logo no comeco. Medindo esse tempo, o atacante descobre o segredo caractere por caractere."
section 2 "Conceitos tecnicos"
term "Early return" "equals que para no 1o mismatch -> tempo proporcional ao prefixo correto."
term "Timing side-channel" "Diferenca de tempo que vaza informacao (aqui, quantos bytes casaram)."
term "Tempo constante" "MessageDigest.isEqual compara sempre o buffer todo -> tempo estavel."
section 3 "O codigo (roda offline)"; show_code "$HERE/ConstantTimeCompare.java"
section 4 "Executando (mede os tempos)"; run_demo "$HERE/ConstantTimeCompare.java"
para "${C_DIM}Os tempos variam por maquina/JIT; o ponto e o PADRAO: o naive cresce com o prefixo correto, o de tempo constante nao.${C_RESET}"
section 5 "Conhecimentos conectados"
ref "Leva a: #14 enumeracao por timing e #06 jwt (verificar assinatura em tempo constante)"
ref "Pratique a seguir: scripts/concepts/totp-mfa e o ataque #14"
section 6 "Referencias"
ref "OWASP - Timing attacks / comparacao segura: https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html"
ref "JDK MessageDigest.isEqual: https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/MessageDigest.html"
footer
