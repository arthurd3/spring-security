#!/usr/bin/env bash
# 22 - Host Header Injection (CWE-644) - deep dive
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/../../lib/common.sh"; ensure_java
title "22. Host Header Injection  -  CWE-644 (deep dive)"
section 1 "Entenda em 3 niveis"
level "Basico" "O cabecalho Host diz qual site voce quer - e quem escolhe e quem faz o pedido. Se o servidor usa o Host para montar o link de 'redefinir senha', o atacante faz a vitima receber um link que aponta para ele."
level "Intermediario" "Host e X-Forwarded-Host sao input nao confiavel. Usa-los para URLs absolutas, rotas ou refletir em cache leva a reset poisoning, cache poisoning e bypass de roteamento."
level "Avancado" "Correcao: base URL configurada no servidor para tudo sensivel; allowlist de hosts; ignorar X-Forwarded-* exceto de proxy confiavel; nao refletir Host em conteudo cacheavel."
section 2 "Conceitos tecnicos"
term "Cabecalho Host" "Diz o dominio desejado; controlado pelo cliente -> nao confiavel."
term "X-Forwarded-Host" "Header de proxy que pode sobrescrever o Host se confiado cegamente."
term "Reset poisoning" "Envenenar o link de redefinicao via Host para capturar o token."
term "Cache poisoning" "Header refletido nao incluido na chave do cache -> 1 atacante afeta todos."
section 3 "O codigo (4 variantes, nesta pasta)"; show_code "$HERE/HostHeaderDemo.java"
section 4 "Executando as variantes"; run_demo "$HERE/HostHeaderDemo.java"
section 5 "Por que a defesa funciona"
para "Montar links a partir de uma base configurada (e ignorar Host/XFH) torna o header spoofado irrelevante; allowlist de hosts fecha roteamento e cache. No app: src/main/java/com/arthur/security/auth/PasswordResetController.java."
doc_pointer "$HERE"
section 6 "Referencias"
ref "PortSwigger Host header: https://portswigger.net/web-security/host-header"
ref "OWASP WSTG Host Header Injection: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection"
ref "CWE-644: https://cwe.mitre.org/data/definitions/644.html"
footer
