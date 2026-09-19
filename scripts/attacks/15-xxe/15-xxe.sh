#!/usr/bin/env bash
# 15 - XXE (CWE-611 / OWASP A05:2021) - deep dive
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/../../lib/common.sh"; ensure_java
title "15. XXE - XML External Entity  -  CWE-611 / OWASP A05:2021 (deep dive)"
section 1 "Entenda em 3 niveis"
level "Basico" "O XML permite 'atalhos' (entidades) que podem apontar para um ARQUIVO ou URL do servidor. Se o leitor aceita, o documento manda o servidor devolver /etc/passwd ou buscar enderecos internos."
level "Intermediario" "Entidade externa faz o parser LER o recurso. Vira leitura de arquivo, SSRF (metadata da nuvem) e DoS (billion laughs). Default inseguro na maioria das libs."
level "Avancado" "Defesa mais eficaz: proibir DOCTYPE (disallow-doctype-decl). Tambem desligar entidades externas e load-external-dtd; XInclude off; secure processing on."
section 2 "Conceitos tecnicos"
term "Entidade externa" "<!ENTITY x SYSTEM 'file:///...'>; ao expandir, o parser le o recurso."
term "DTD / DOCTYPE" "Onde entidades sao declaradas; proibir DOCTYPE impede declara-las."
term "SSRF via XXE" "Entidade http:// faz o servidor buscar servicos internos por voce."
term "Billion laughs" "Entidades aninhadas que expandem exponencialmente -> DoS."
section 3 "O codigo (3 variantes, nesta pasta)"; show_code "$HERE/XxeDemo.java"
section 4 "Executando as variantes"; run_demo "$HERE/XxeDemo.java"
section 5 "Por que a defesa funciona"
para "disallow-doctype-decl faz o parser recusar qualquer DOCTYPE: a entidade nunca e declarada, quanto mais resolvida. XML normal continua funcionando. No app: src/main/java/com/arthur/security/xml/SafeXmlParser.java."
doc_pointer "$HERE"
section 6 "Referencias"
ref "OWASP XXE Prevention: https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html"
ref "PortSwigger XXE: https://portswigger.net/web-security/xxe"
ref "Repos: WebGoat, swisskyrepo/PayloadsAllTheThings (ver DEEP-DIVE.md)"
ref "CWE-611: https://cwe.mitre.org/data/definitions/611.html"
footer
