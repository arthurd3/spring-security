#!/usr/bin/env bash
# 21 - Unrestricted File Upload (CWE-434 / OWASP A05:2021) - deep dive
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/../../lib/common.sh"; ensure_java
title "21. Unrestricted File Upload  -  CWE-434 / OWASP A05:2021 (deep dive)"
section 1 "Entenda em 3 niveis"
level "Basico" "Um 'envie sua foto' que aceita qualquer arquivo, com qualquer nome, numa pasta servida e uma porta dos fundos: o atacante envia .html com <script> ou .jsp/.php e acessa -> XSS armazenado ou RCE."
level "Intermediario" "Erros: confiar na extensao e no Content-Type do cliente, manter o nome do cliente, servir de diretorio executavel. Bypasses: shell.jsp.png, %00, ponto final, content-type falso, polyglot."
level "Avancado" "Correcao: allowlist de extensao final + validar magic bytes + nome aleatorio + remover path + limite de tamanho + storage fora do webroot; re-encode de imagem contra polyglot."
section 2 "Conceitos tecnicos"
term "Extensao x conteudo" "Extensao/Content-Type do cliente mentem; validar o conteudo (magic bytes)."
term "Dupla extensao" "shell.jsp.png: servidor mal-config executa pela primeira extensao."
term "Magic bytes" "Assinatura no inicio do arquivo (ex.: PNG 89 50 4E 47) para checar o tipo real."
term "Storage sem execucao" "Guardar fora do webroot / em bucket que nao interpreta codigo."
section 3 "O codigo (5 variantes, nesta pasta)"; show_code "$HERE/FileUploadDemo.java"
section 4 "Executando as variantes"; run_demo "$HERE/FileUploadDemo.java"
section 5 "Por que a defesa funciona"
para "Allowlist de extensao + magic bytes + nome aleatorio + remover path barram extensao perigosa, dupla extensao, content-type falso e path no nome. No app: src/main/java/com/arthur/security/upload/UploadService.java."
doc_pointer "$HERE"
section 6 "Referencias"
ref "OWASP File Upload: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"
ref "Repos: swisskyrepo/PayloadsAllTheThings (Upload) (ver DEEP-DIVE.md)"
ref "CWE-434: https://cwe.mitre.org/data/definitions/434.html"
footer
