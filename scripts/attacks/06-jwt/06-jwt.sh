#!/usr/bin/env bash
# 06 - JWT Forgery (CWE-345/347 / OWASP A02/A07) - deep dive
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/../../lib/common.sh"; ensure_java
title "06. JWT Forgery  -  CWE-345 / CWE-347 (deep dive)"
section 1 "Entenda em 3 niveis"
level "Basico" "JWT e um cracha digital com assinatura que prova que o servidor o emitiu. Se o servidor nao confere a assinatura (ou aceita 'sem assinatura', ou usa segredo fraco), o atacante fabrica o cracha e vira admin."
level "Intermediario" "JWT = header.payload.assinatura. Falhas: alg=none, segredo HMAC fraco (dicionario), nao checar exp, confusao de algoritmo (RS256->HS256 com a chave publica)."
level "Avancado" "Defesa: FIXAR o algoritmo esperado, verificar assinatura E claims (exp/iss/aud), segredo forte ou chaves assimetricas, usar lib madura (Nimbus), nunca parse manual."
section 2 "Conceitos tecnicos"
term "JWT" "header.payload.assinatura; as 2 primeiras partes sao Base64 legivel, a 3a e a prova."
term "alg=none" "'Sem assinatura'; verificador correto DEVE recusar."
term "Confusao de algoritmo" "Verificador le o alg do header; atacante troca RS256->HS256 e assina com a chave publica."
term "exp/nbf/iss/aud" "Claims de validade/emissor/audiencia; devem ser verificados, nao so a assinatura."
section 3 "O codigo (4 variantes, nesta pasta)"; show_code "$HERE/JwtDemo.java"
section 4 "Executando as variantes"; run_demo "$HERE/JwtDemo.java"
section 5 "Por que a defesa funciona"
para "Fixar o algoritmo e verificar assinatura + exp derruba alg=none, confusao e tokens eternos; segredo forte derruba o dicionario. No app: src/main/java/com/arthur/security/config/JwtConfig.java (OAuth2 Resource Server/Nimbus)."
doc_pointer "$HERE"
section 6 "Referencias"
ref "PortSwigger JWT: https://portswigger.net/web-security/jwt"
ref "OWASP JWT Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"
ref "Repos: JoyChou93/java-sec-code (ver DEEP-DIVE.md)"
ref "CWE-347: https://cwe.mitre.org/data/definitions/347.html"
footer
