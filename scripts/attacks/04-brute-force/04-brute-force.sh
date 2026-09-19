#!/usr/bin/env bash
# 04 - Brute Force / Credential Stuffing (CWE-307 / OWASP A07:2021) - deep dive
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/../../lib/common.sh"; ensure_java
title "04. Brute Force / Credential Stuffing  -  CWE-307 (deep dive)"
section 1 "Entenda em 3 niveis"
level "Basico" "Login com tentativas infinitas e um cadeado que se gira para sempre: um robo testa milhoes de senhas ate abrir, ou reusa senhas vazadas de outros sites."
level "Intermediario" "Tres formatos: vertical (1 user, N senhas), spraying (1 senha, N users), stuffing (pares vazados). Cada um exige uma defesa diferente."
level "Avancado" "Lockout por conta resolve o vertical, mas o spraying o dribla (1 tentativa por conta) - precisa limite global/IP + MFA. Stuffing: MFA + bloquear senhas vazadas (HIBP)."
section 2 "Conceitos tecnicos"
term "Vertical vs spraying" "Vertical: muitas senhas num user. Spraying: uma senha em muitos users (evita lockout por conta)."
term "Credential stuffing" "Reusar pares user:senha vazados apostando na repeticao."
term "Lockout / backoff" "Travar/atrasar apos N falhas; backoff exponencial encarece o ataque."
term "MFA / HIBP" "Segundo fator neutraliza senha correta roubada; checar senha contra listas de vazadas."
section 3 "O codigo (3 variantes, nesta pasta)"; show_code "$HERE/BruteForceDemo.java"
section 4 "Executando as variantes"; run_demo "$HERE/BruteForceDemo.java"
section 5 "Por que a defesa funciona"
para "Lockout corta o vertical; limite global/IP + deteccao cortam o spraying; MFA e bloqueio de senhas vazadas cortam o stuffing. No app: src/main/java/com/arthur/security/login/LoginAttemptService.java (+ ataque 26 para rate limit)."
doc_pointer "$HERE"
section 6 "Referencias"
ref "OWASP Blocking Brute Force: https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks"
ref "OWASP Credential Stuffing Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html"
ref "Real: Collections #1-5; Akamai stuffing reports; Verizon DBIR"
ref "CWE-307: https://cwe.mitre.org/data/definitions/307.html"
footer
