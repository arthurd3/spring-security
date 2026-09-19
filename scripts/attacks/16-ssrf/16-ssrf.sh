#!/usr/bin/env bash
# 16 - SSRF (CWE-918 / OWASP A10:2021) - deep dive
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/../../lib/common.sh"; ensure_java
title "16. SSRF - Server-Side Request Forgery  -  CWE-918 / OWASP A10:2021 (deep dive)"
section 1 "Entenda em 3 niveis"
level "Basico" "Recursos que 'buscam uma URL para voce' fazem o SERVIDOR fazer o pedido - de dentro da rede. O atacante aponta a URL para o que ele nao alcanca de fora: paineis internos, banco, metadata da nuvem (169.254.169.254) com credenciais."
level "Intermediario" "Vetores: file://, http://interno, IMDS, DNS rebinding (nome permitido resolve p/ interno), redirect (host permitido -> 302 -> interno)."
level "Avancado" "Defesa (tudo junto): allowlist de esquema + host, revalidar o ENDERECO resolvido (pos-DNS), nao seguir redirects, egress filtering, IMDSv2."
section 2 "Conceitos tecnicos"
term "IMDS 169.254.169.254" "Endpoint de metadata da nuvem (link-local) que entrega credenciais da instancia."
term "DNS rebinding" "Nome permitido resolve p/ IP interno; por isso checar o IP resolvido, nao so o nome."
term "Bypass por redirect" "Host permitido responde 302 para o interno; desabilitar redirects barra."
term "Egress filtering" "Filtrar o trafego de SAIDA do servidor limita o alcance do SSRF."
section 3 "O codigo (4 variantes, nesta pasta)"; show_code "$HERE/SsrfDemo.java"
section 4 "Executando as variantes"; run_demo "$HERE/SsrfDemo.java"
section 5 "Por que a defesa funciona"
para "As quatro guardas juntas (esquema, host, endereco resolvido, sem redirect) barram file://, IMDS, rebinding e redirect. No app: src/main/java/com/arthur/security/net/UrlFetchService.java."
doc_pointer "$HERE"
section 6 "Referencias"
ref "OWASP SSRF Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"
ref "Real: Capital One 2019 (106M, IMDS); ProxyLogon CVE-2021-26855; Angular CVE-2026-27739; Spring Authz CVE-2026-22752"
ref "PortSwigger SSRF: https://portswigger.net/web-security/ssrf"
ref "CWE-918: https://cwe.mitre.org/data/definitions/918.html"
footer
