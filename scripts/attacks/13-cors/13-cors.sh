#!/usr/bin/env bash
# 13 - CORS Misconfiguration (CWE-942 / OWASP A05:2021) - deep dive
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/../../lib/common.sh"; ensure_java
title "13. CORS Misconfiguration  -  CWE-942 / OWASP A05:2021 (deep dive)"
section 1 "Entenda em 3 niveis"
level "Basico" "O navegador impede o site A de LER respostas do site B. CORS abre excecoes. Se o servidor diz 'qualquer site pode me ler' E 'pode mandar cookies', a pagina do atacante le os dados autenticados da vitima."
level "Intermediario" "Refletir a origem recebida = liberar todas. Com Allow-Credentials:true vira leitura autenticada cross-site. Erros: aceitar null, match ingenuo (startsWith/endsWith)."
level "Avancado" "Defesa: allowlist EXATA, nunca refletir, nunca null, nunca * com credenciais. CORS nao e autorizacao - authz e sessao/token no servidor."
section 2 "Conceitos tecnicos"
term "Origin / ACAO" "Origem = protocolo+dominio+porta; ACAO diz qual origem pode ler a resposta."
term "Refletir origem" "Ecoar o Origin recebido no ACAO = liberar todas."
term "null origin" "Forjavel por iframe sandbox/redirect; nunca deve ser permitido."
term "CORS != autorizacao" "CORS controla leitura no navegador; authz e no servidor."
section 3 "O codigo (5 variantes, nesta pasta)"; show_code "$HERE/CorsDemo.java"
section 4 "Executando as variantes"; run_demo "$HERE/CorsDemo.java"
section 5 "Por que a defesa funciona"
para "Allowlist exata (sem refletir, sem null, sem match por sufixo) faz origens desconhecidas nao receberem ACAO - o navegador bloqueia a leitura. No app: src/main/java/com/arthur/security/config/ApiSecurityConfig.java."
doc_pointer "$HERE"
section 6 "Referencias"
ref "PortSwigger CORS: https://portswigger.net/web-security/cors"
ref "MDN CORS: https://developer.mozilla.org/docs/Web/HTTP/CORS"
ref "CWE-942: https://cwe.mitre.org/data/definitions/942.html"
footer
