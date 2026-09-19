#!/usr/bin/env bash
# 23 - CRLF / Log Injection (CWE-117/113 / OWASP A09:2021) - deep dive
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/../../lib/common.sh"; ensure_java
title "23. CRLF / Log Injection  -  CWE-117 / CWE-113 (deep dive)"
section 1 "Entenda em 3 niveis"
level "Basico" "Logs e cabecalhos HTTP sao 'linhas'. Se o servidor escreve o que voce digitou sem tratar e voce poe uma quebra de linha, injeta uma LINHA falsa: forja um log ou injeta um cabecalho/cookie."
level "Intermediario" "\\r e \\n terminam linhas. Em logs = log forging (mina auditoria). Em HTTP = response splitting (injeta Set-Cookie/corpo). Tambem \\r isolado e tab."
level "Avancado" "Defesa: remover/neutralizar CR/LF e controles antes de usar; logging estruturado (JSON). Conteineres modernos ja rejeitam CR/LF em setHeader, mas log forging segue vivo."
section 2 "Conceitos tecnicos"
term "CRLF" "CR e LF terminam linhas; injeta-los cria linhas novas onde nao deveria."
term "Log forging" "Falsificar entradas de log injetando linhas; engana auditoria/alertas."
term "Response splitting" "CRLF no valor de um header injeta novos headers ou um corpo (CWE-113)."
term "Logging estruturado" "Valor vira um campo (JSON/key-value), nao texto livre concatenado."
section 3 "O codigo (3 variantes, nesta pasta)"; show_code "$HERE/LogInjectionDemo.java"
section 4 "Executando as variantes"; run_demo "$HERE/LogInjectionDemo.java"
section 5 "Por que a defesa funciona"
para "Sanitizar CR/LF/controles antes de logar/usar em header mantem o valor em UMA linha - impossivel forjar log ou injetar cabecalho. No app: src/main/java/com/arthur/security/logging/AuditController.java."
doc_pointer "$HERE"
section 6 "Referencias"
ref "OWASP Log Injection: https://owasp.org/www-community/attacks/Log_Injection"
ref "OWASP Logging Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html"
ref "Repos: swisskyrepo/PayloadsAllTheThings (CRLF) (ver DEEP-DIVE.md)"
ref "CWE-117: https://cwe.mitre.org/data/definitions/117.html | CWE-113: https://cwe.mitre.org/data/definitions/113.html"
footer
