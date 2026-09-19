#!/usr/bin/env bash
# 17 - OS Command Injection (CWE-78 / OWASP A03:2021) - deep dive
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/../../lib/common.sh"; ensure_java
title "17. OS Command Injection  -  CWE-78 / OWASP A03:2021 (deep dive)"
section 1 "Entenda em 3 niveis"
level "Basico" "O servidor monta uma frase de comando com o que voce digita e manda o sistema executar. Voce escreve o endereco, um ';' e um segundo comando - e a maquina obedece aos dois."
level "Intermediario" "O perigo e o shell (sh -c) interpretando metacaracteres: ; | && \$() crase. Tecnicas: separador, substituicao, pipe, blind por tempo, bypass de blacklist."
level "Avancado" "Regra de ouro: nunca montar linha de comando com input - use lista de argumentos (ProcessBuilder), sem shell. Allowlist estrita; blacklist perde para \${IFS}, encoding, novas linhas."
section 2 "Conceitos tecnicos"
term "Shell" "Interpreta a linha de comando; se input vira parte dela, o usuario manda no sistema."
term "Metacaractere" "; separa, | encadeia, \$() e crase executam outro comando."
term "ProcessBuilder (lista de args)" "Passar programa+argumentos separados; o shell nunca parseia o texto."
term "Allowlist x blacklist" "Aceitar so o valido (letras/numeros/.-) e robusto; listar o proibido sempre falha."
section 3 "O codigo (5 variantes, nesta pasta)"; show_code "$HERE/CommandInjectionDemo.java"
section 4 "Executando as variantes"; run_demo "$HERE/CommandInjectionDemo.java"
section 5 "Por que a defesa funciona"
para "A allowlist recusa qualquer metacaractere ANTES de montar comando; e usar lista de argumentos (sem sh -c) faz o texto nunca ser interpretado. No app: src/main/java/com/arthur/security/system/CommandService.java."
doc_pointer "$HERE"
section 6 "Referencias"
ref "OWASP OS Command Injection Defense: https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"
ref "Real: Shellshock CVE-2014-6271 | appliances/IoT (CISA KEV) | injecao em 2026"
ref "Repos: WebGoat, swisskyrepo/PayloadsAllTheThings (ver DEEP-DIVE.md)"
ref "CWE-78: https://cwe.mitre.org/data/definitions/78.html"
footer
