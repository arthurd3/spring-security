#!/usr/bin/env bash
# 08 - SQL Injection (CWE-89 / OWASP A03:2021) - deep dive, multiplas variantes
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/../../lib/common.sh"; ensure_java
title "08. SQL Injection  -  CWE-89 / OWASP A03:2021 (deep dive)"

section 1 "Entenda em 3 niveis"
level "Basico" "O site monta uma 'pergunta' ao banco juntando texto com o que voce digitou. Se ele so COLA o que voce digitou, voce escreve um pedaco de pergunta: 'me traga a conta X' vira 'me traga TODAS'. Da para vazar dados ou logar sem senha."
level "Intermediario" "A consulta tem estrutura (SELECT...WHERE...) e dados. Uma aspa fecha o literal e o resto vira SQL. Tecnicas: tautologia, UNION (roubar outra tabela), blind booleano (inferir 1 char por vez), blind por tempo, error-based, second-order, ORDER BY."
level "Avancado" "A correcao real e separar estrutura de dados com prepared statement (bind param). Partes que nao aceitam bind (nomes de coluna em ORDER BY) exigem allowlist. Escapar aspas NAO resolve: varia por banco e contexto."

section 2 "Conceitos tecnicos"
term "Prepared statement (bind)" "Consulta enviada com ? e o valor separado; o banco ja compilou a estrutura, o valor so e dado - aspas nao viram comando."
term "UNION-based" "Anexa uma segunda consulta (UNION SELECT) para ler dados de outra tabela; precisa casar numero/tipo de colunas."
term "Blind (booleano/tempo)" "Sem dados/erro visiveis, o atacante infere segredos por respostas true/false ou por atraso (SLEEP)."
term "Second-order" "Payload gravado por um insert seguro que dispara depois, quando outra query concatena esse valor."

section 3 "O codigo (5 variantes reais, nesta pasta)"
para "Cada variante tem a versao vulneravel e a segura. Roda tudo:"
show_code "$HERE/SqlInjectionDemo.java"

section 4 "Executando as variantes"
run_demo "$HERE/SqlInjectionDemo.java"

section 5 "Por que a defesa funciona"
para "Com bind parameter, o payload e comparado como DADO literal (um nome que nao existe), nunca como SQL - some a tautologia, o UNION, o oraculo blind. Para ORDER BY use allowlist de colunas. No app real: src/main/java/com/arthur/security/account/AccountService.java (derived query do Spring Data)."

doc_pointer "$HERE"

section 6 "Referencias"
ref "OWASP SQL Injection Prevention: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
ref "PortSwigger - SQL injection: https://portswigger.net/web-security/sql-injection"
ref "Real: MOVEit CVE-2023-34362 | FortiClient EMS CVE-2023-48788 | WordPress CVE-2026-60137"
ref "Repos: WebGoat, JoyChou93/java-sec-code, swisskyrepo/PayloadsAllTheThings, sqlmap (ver DEEP-DIVE.md)"
ref "CWE-89: https://cwe.mitre.org/data/definitions/89.html"
footer
