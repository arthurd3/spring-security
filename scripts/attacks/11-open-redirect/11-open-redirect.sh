#!/usr/bin/env bash
# 11 - Open Redirect (CWE-601) - deep dive
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/../../lib/common.sh"; ensure_java
title "11. Open Redirect  -  CWE-601 (deep dive)"
section 1 "Entenda em 3 niveis"
level "Basico" "O 'voltar para onde voce estava' recebe o destino pela URL. Se aceita qualquer endereco, o atacante faz um link que comeca no site confiavel e joga a vitima no site dele (phishing)."
level "Intermediario" "Checagens ingenuas falham: startsWith('/') deixa passar //evil e /\\evil; contains('trusted.com') deixa passar trusted.com.evil e trusted.com@evil."
level "Avancado" "Correcao: caminho relativo (uma /) OU host PARSEADO em allowlist; normalizar \\, rejeitar //, control chars, javascript:/data:. Em OAuth, casar redirect_uri exatamente."
section 2 "Conceitos tecnicos"
term "Protocolo-relativo //host" "Comeca com // e o navegador trata como URL absoluta (outro dominio)."
term "userinfo @" "https://trusted@evil: o host real e 'evil'; 'trusted' e so usuario."
term "Host parseado" "Comparar o host de uma URI, nunca startsWith/contains na string crua."
term "redirect_uri (OAuth)" "Destino pos-login; se frouxo, vaza code/token (account takeover)."
section 3 "O codigo (6 variantes, nesta pasta)"; show_code "$HERE/OpenRedirectDemo.java"
section 4 "Executando as variantes"; run_demo "$HERE/OpenRedirectDemo.java"
section 5 "Por que a defesa funciona"
para "A checagem robusta compara o host de uma URI parseada contra a allowlist e trata caminho relativo com cuidado (rejeita //, normaliza \\) - por isso os bypasses caem. No app: src/main/java/com/arthur/security/web/SafeRedirectController.java."
doc_pointer "$HERE"
section 6 "Referencias"
ref "OWASP Unvalidated Redirects: https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"
ref "Repos: swisskyrepo/PayloadsAllTheThings (Open Redirect) (ver DEEP-DIVE.md)"
ref "CWE-601: https://cwe.mitre.org/data/definitions/601.html"
footer
