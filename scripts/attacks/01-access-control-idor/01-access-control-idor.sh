#!/usr/bin/env bash
# 01 - Broken Access Control / IDOR (CWE-639 / OWASP A01:2021) - deep dive
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/../../lib/common.sh"; ensure_java
title "01. Broken Access Control / IDOR  -  CWE-639 / OWASP A01:2021 (deep dive)"
section 1 "Entenda em 3 niveis"
level "Basico" "O site mostra 'sua conta' por /conta/1. Se voce troca para 2 e o servidor entrega sem conferir se e SUA, voce leu dados de outra pessoa. O atacante so troca um numero."
level "Intermediario" "IDOR e falha de autorizacao no nivel do OBJETO: logar nao basta, tem que checar 'voce e dono DESTE registro'. Sabores: horizontal e vertical; ids sequenciais permitem enumeracao."
level "Avancado" "Defesa: checagem de posse por objeto (@PostAuthorize / escopo por dono na query), deny-by-default, checar vinculo em recursos aninhados. UUID dificulta adivinhar mas NAO e autorizacao."
section 2 "Conceitos tecnicos"
term "Autorizacao no nivel do objeto (BOLA)" "Para cada objeto, checar se o caller e dono/autorizado - a API1 do OWASP."
term "Horizontal x vertical" "Horizontal: outro usuario de mesmo nivel. Vertical: alcancar funcao de nivel maior."
term "Enumeracao" "Varrer ids sequenciais para raspar todos os objetos."
term "id opaco (UUID)" "Dificulta adivinhar; reforco, nunca substitui a checagem de posse."
section 3 "O codigo (4 variantes, nesta pasta)"; show_code "$HERE/IdorDemo.java"
section 4 "Executando as variantes"; run_demo "$HERE/IdorDemo.java"
section 5 "Por que a defesa funciona"
para "A versao segura confere o DONO do objeto (e o papel, no vertical) antes de devolver - inclusive em recursos aninhados. Trocar o numero nao adianta. No app: src/main/java/com/arthur/security/account/AccountService.java (@PostAuthorize)."
doc_pointer "$HERE"
section 6 "Referencias"
ref "OWASP API1:2023 BOLA: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"
ref "Real: USPS 2018 (60M); OWASP Top 10:2025 (Broken Access Control em 1o)"
ref "PortSwigger IDOR: https://portswigger.net/web-security/access-control/idor"
ref "CWE-639: https://cwe.mitre.org/data/definitions/639.html"
footer
