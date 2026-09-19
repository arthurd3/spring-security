#!/usr/bin/env bash
# 03 - Session Fixation (CWE-384 / OWASP A07:2021) - deep dive
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/../../lib/common.sh"; ensure_java
title "03. Session Fixation  -  CWE-384 / OWASP A07:2021 (deep dive)"
section 1 "Entenda em 3 niveis"
level "Basico" "A sessao tem um 'numero de cracha'. O atacante forca a vitima a usar um cracha que ele conhece; ao logar, o cracha vira autenticado e o atacante entra com o mesmo numero. Defesa: trocar o cracha no login."
level "Intermediario" "Se o id nao muda antes/depois do login, um id plantado (via URL ;jsessionid=, cookie forcado ou XSS) vale como sessao autenticada. Tecnicas: sem rotacao, aceitar id do cliente, sem invalidacao no logout."
level "Avancado" "Defesas: changeSessionId no login; nunca aceitar id do cliente (gerar so no servidor); HttpOnly/Secure/SameSite; invalidar no logout e por timeout."
section 2 "Conceitos tecnicos"
term "Id de sessao" "Identificador (cookie) que liga suas requisicoes a uma sessao; quem tem o id, tem a sessao."
term "Fixacao" "Plantar um id conhecido na vitima ANTES do login para herda-lo depois."
term "changeSessionId()" "Gera novo id no login, invalidando o antigo."
term "Invalidacao" "Encerrar a sessao no logout e por timeout (absoluto/inatividade)."
section 3 "O codigo (3 variantes, nesta pasta)"; show_code "$HERE/SessionFixationDemo.java"
section 4 "Executando as variantes"; run_demo "$HERE/SessionFixationDemo.java"
section 5 "Por que a defesa funciona"
para "Rotacionar o id no login torna inutil qualquer id plantado; nao aceitar id do cliente e invalidar no logout fecham os outros vetores. No app: src/main/java/com/arthur/security/config/WebSecurityConfig.java."
doc_pointer "$HERE"
section 6 "Referencias"
ref "OWASP Session fixation: https://owasp.org/www-community/attacks/Session_fixation"
ref "OWASP Session Management: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"
ref "CWE-384: https://cwe.mitre.org/data/definitions/384.html"
footer
