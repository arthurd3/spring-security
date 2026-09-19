#!/usr/bin/env bash
# 10 - Path Traversal (CWE-22 / OWASP A01:2021) - deep dive
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/../../lib/common.sh"; ensure_java
title "10. Path Traversal  -  CWE-22 / OWASP A01:2021 (deep dive)"
section 1 "Entenda em 3 niveis"
level "Basico" "Um endpoint serve arquivos por nome. Se o servidor so junta pasta+nome, voce escreve ../ e sai da area publica, lendo arquivos do sistema (senhas de config)."
level "Intermediario" "'..' sobe um nivel. Bypasses: URL-encode (%2e%2e%2f), double-encode (%252e), caminho absoluto (resolve ignora a base), Zip Slip (entrada de zip com ../)."
level "Avancado" "Correcao: normalizar e checar contencao (startsWith(base)); nunca blacklist de '..'; preferir id->caminho mapeado; validar cada entrada na extracao; toRealPath da base."
section 2 "Conceitos tecnicos"
term "../ (dot-dot-slash)" "Sobe um nivel; encadeado, escapa da pasta base."
term "Normalizar + contencao" "Resolver os '..' e exigir que o resultado comece pela base."
term "resolve() com absoluto" "No Java, resolver um caminho absoluto DESCARTA a base -> perigoso."
term "Zip Slip" "Entrada de arquivo compactado com ../ escreve fora do diretorio na extracao."
section 3 "O codigo (5 variantes, nesta pasta)"; show_code "$HERE/PathTraversalDemo.java"
section 4 "Executando as variantes"; run_demo "$HERE/PathTraversalDemo.java"
section 5 "Por que a defesa funciona"
para "normalize() + startsWith(base) barra ../, encoding e caminho absoluto (o resultado final sai da base -> 400); a mesma checagem valida cada entrada de zip. No app: src/main/java/com/arthur/security/files/FileStorageService.java."
doc_pointer "$HERE"
section 6 "Referencias"
ref "OWASP Path Traversal: https://owasp.org/www-community/attacks/Path_Traversal"
ref "Real: Zip Slip (Snyk 2018); appliances Ivanti/Fortinet; Spring Cloud Config CVE-2026-40982"
ref "PortSwigger: https://portswigger.net/web-security/file-path-traversal"
ref "CWE-22: https://cwe.mitre.org/data/definitions/22.html"
footer
