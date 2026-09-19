#!/usr/bin/env bash
# 26 - Missing Rate Limiting (CWE-770 / OWASP API4:2023) - deep dive
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/../../lib/common.sh"; ensure_java
title "26. Missing Rate Limiting  -  CWE-770 / OWASP API4:2023 (deep dive)"
section 1 "Entenda em 3 niveis"
level "Basico" "Se verificar um OTP aceita tentativas infinitas, o atacante testa os 10.000 codigos em segundos. Rate limiting e o freio: contar tentativas e recusar o excedente (429)."
level "Intermediario" "Erros comuns: chavear por header spoofavel (X-Forwarded-For) - o atacante rotaciona e zera o contador; e janela fixa, que deixa um burst de 2x na virada."
level "Avancado" "Correcao: contar por identidade confiavel (IP real/usuario), janela deslizante ou token bucket, 429 + Retry-After, limites por rota e globais, CAPTCHA/MFA em endpoints criticos."
section 2 "Conceitos tecnicos"
term "429 Too Many Requests" "Status que sinaliza limite excedido; acompanhar de Retry-After."
term "Chave spoofavel" "Contar por X-Forwarded-For deixa o atacante rotacionar e escapar; use o IP real."
term "Janela fixa x deslizante" "Fixa permite burst na virada; deslizante conta a ultima janela movel."
term "Token bucket" "Balde de fichas que recarrega no tempo; suaviza rajadas."
section 3 "O codigo (4 variantes, nesta pasta)"; show_code "$HERE/RateLimitDemo.java"
section 4 "Executando as variantes"; run_demo "$HERE/RateLimitDemo.java"
section 5 "Por que a defesa funciona"
para "Contar por IP real (nao por header) impede o bypass de XFF; janela deslizante/token bucket impede o burst da janela fixa; 429+Retry-After comunica o limite. No app: src/main/java/com/arthur/security/ratelimit/RateLimiter.java."
doc_pointer "$HERE"
section 6 "Referencias"
ref "OWASP API4:2023: https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/"
ref "Libs: bucket4j, resilience4j (ver DEEP-DIVE.md)"
ref "CWE-770: https://cwe.mitre.org/data/definitions/770.html"
footer
