#!/usr/bin/env bash
# 20 - ReDoS (CWE-1333) - deep dive
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/../../lib/common.sh"; ensure_java
title "20. ReDoS - Regular Expression Denial of Service  -  CWE-1333 (deep dive)"
section 1 "Entenda em 3 niveis"
level "Basico" "Regex validam texto. Uma regex mal escrita, diante de uma entrada quase-certa, faz o motor tentar combinacoes astronomicas antes de desistir - poucas dezenas de chars prendem a CPU por segundos. Varios pedidos = servico fora do ar."
level "Intermediario" "Motores com backtracking (Java/PCRE/JS) exploram todas as formas de casar. Quantificadores aninhados/limitados de grupo guloso ((a+)+, (.*a){20}) explodem sobre um quase-casamento."
level "Avancado" "Depende do motor: JDK 21 otimiza (a+)+ mas ainda explode com (.*a){20}. Correcao: length cap + verificacao linear (ou motor RE2 sem backtracking) + timeout."
section 2 "Conceitos tecnicos"
term "Backtracking" "O motor volta e tenta outra divisao quando falha; com aninhamento, isso explode."
term "Evil regex" "Padroes ambiguos/aninhados que causam blow-up exponencial."
term "RE2 / linear" "Motor de tempo linear (sem backtracking); mitigacao para input nao confiavel."
term "Timeout + length cap" "Limitar tempo e tamanho remove o risco na raiz."
section 3 "O codigo (4 variantes, nesta pasta)"; show_code "$HERE/ReDoSDemo.java"
section 4 "Executando as variantes"; run_demo "$HERE/ReDoSDemo.java"
section 5 "Por que a defesa funciona"
para "Length cap + verificacao linear resolvem a mesma entrada em milissegundos; nao depender do motor evita surpresas entre versoes. No app: src/main/java/com/arthur/security/validation/ValidationController.java."
doc_pointer "$HERE"
section 6 "Referencias"
ref "OWASP ReDoS: https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS"
ref "Real: Cloudflare 2019 (outage 27min); Stack Overflow 2016"
ref "Motor linear: google/re2j (ver DEEP-DIVE.md)"
ref "CWE-1333: https://cwe.mitre.org/data/definitions/1333.html"
footer
