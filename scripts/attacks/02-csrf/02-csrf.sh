#!/usr/bin/env bash
# 02 - CSRF (CWE-352 / OWASP A01:2021) - deep dive
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/../../lib/common.sh"; ensure_java
title "02. CSRF - Cross-Site Request Forgery  -  CWE-352 / OWASP A01:2021 (deep dive)"
section 1 "Entenda em 3 niveis"
level "Basico" "Voce esta logado no banco. Outro site dispara, escondido, uma transferencia. O navegador anexa o cookie de sessao automaticamente, entao o pedido chega 'assinado como voce'."
level "Intermediario" "CSRF abusa do envio automatico de cookies. Defesas: synchronizer token, double-submit cookie, SameSite. GET nao deve mudar estado; text/plain evita preflight (nao confie no CORS)."
level "Avancado" "Login tambem precisa de token (login CSRF). APIs com Authorization no header sao imunes (navegador nao anexa sozinho). SameSite=Lax por padrao ajuda, mas nao elimina."
section 2 "Conceitos tecnicos"
term "Envio automatico de cookie" "O navegador reenvia o cookie de sessao a cada request ao site, inclusive os disparados por outro site."
term "Synchronizer token" "Valor secreto por sessao no formulario; outro site nao o conhece."
term "Double-submit cookie" "Cookie token deve casar com um header/campo enviado pela pagina."
term "SameSite" "Lax/Strict: o navegador nao anexa o cookie em requisicoes cross-site."
section 3 "O codigo (6 variantes, nesta pasta)"; show_code "$HERE/CsrfDemo.java"
section 4 "Executando as variantes"; run_demo "$HERE/CsrfDemo.java"
section 5 "Por que a defesa funciona"
para "Exigir um token que so a pagina legitima conhece (ou cookie==header) faz o pedido forjado morrer com 403; SameSite impede o cookie de ir cross-site. No app: src/main/java/com/arthur/security/config/WebSecurityConfig.java."
doc_pointer "$HERE"
section 6 "Referencias"
ref "OWASP CSRF Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"
ref "Spring Security CSRF: https://docs.spring.io/spring-security/reference/servlet/exploits/csrf.html"
ref "CWE-352: https://cwe.mitre.org/data/definitions/352.html"
footer
