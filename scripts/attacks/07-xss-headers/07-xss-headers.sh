#!/usr/bin/env bash
# 07 - XSS + Security Headers (CWE-79 / OWASP A03:2021) - deep dive
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/../../lib/common.sh"; ensure_java
title "07. XSS + Security Headers  -  CWE-79 / OWASP A03:2021 (deep dive)"
section 1 "Entenda em 3 niveis"
level "Basico" "XSS e quando o site devolve na pagina um texto do usuario sem tratar. Se voce manda <script>, o navegador da vitima EXECUTA - rouba sessao, digitacao, age como a vitima."
level "Intermediario" "A defesa e escapar a saida NO CONTEXTO certo: HTML, atributo, JS, URL, CSS tem regras diferentes. Tipos: refletido, armazenado, DOM."
level "Avancado" "Output encoding por contexto (libs), CSP (com nonce, sem unsafe-inline), nosniff, cookies HttpOnly/SameSite, sanitizacao com allowlist para HTML rico."
section 2 "Conceitos tecnicos"
term "Refletido/Armazenado/DOM" "Volta na resposta / persiste e atinge todos / o JS do cliente escreve input no DOM."
term "Output encoding por contexto" "HTML vs atributo vs JS vs URL exigem encodings diferentes."
term "CSP" "Politica que diz de onde o navegador pode executar script; barra XSS mesmo que um passe."
term "HttpOnly" "Cookie que o JS nao le -> XSS nao rouba a sessao diretamente."
section 3 "O codigo (5 variantes, nesta pasta)"; show_code "$HERE/XssDemo.java"
section 4 "Executando as variantes"; run_demo "$HERE/XssDemo.java"
section 5 "Por que a defesa funciona"
para "Escapar a saida no contexto certo faz o navegador exibir texto, nao executar; CSP/nosniff/HttpOnly sao camadas extras. No app: HtmlUtils.htmlEscape em src/main/java/com/arthur/security/web/MainController.java + headers em ApiSecurityConfig."
doc_pointer "$HERE"
section 6 "Referencias"
ref "OWASP XSS Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
ref "Real: Samy worm 2005; British Airways/Magecart 2018"
ref "PortSwigger XSS: https://portswigger.net/web-security/cross-site-scripting"
ref "CWE-79: https://cwe.mitre.org/data/definitions/79.html"
footer
