#!/usr/bin/env bash
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/../../lib/common.sh"; ensure_java
title "CONCEITO: HIBP Pwned Passwords via k-anonymity"
section 1 "O que e (para leigos)"
para "Como saber se a sua senha ja apareceu em vazamentos SEM entregar a senha a ninguem? Voce manda so um pedacinho do 'resumo' (hash) dela; o servidor devolve varios candidatos; e voce compara o resto no seu proprio computador. Assim da para bloquear senhas vazadas sem expo-las."
section 2 "Conceitos tecnicos"
term "SHA-1 + prefixo/sufixo" "Calcula-se o SHA-1 da senha; envia-se so os 5 primeiros hex (prefixo). O sufixo fica local."
term "Range query / k-anonymity" "O servidor responde TODOS os sufixos daquele prefixo (o 'k' anonimato); voce nao revela qual e o seu."
term "Bloquear senhas vazadas" "No cadastro/login, recusar senhas presentes na lista - corta credential stuffing (ver #04)."
section 3 "O codigo (roda offline)"; show_code "$HERE/HibpKAnonymity.java"
section 4 "Executando"; run_demo "$HERE/HibpKAnonymity.java"
section 5 "Conhecimentos conectados"
ref "Leva a: #04 brute-force (defesa: bloquear senhas vazadas + MFA) e #05 password storage"
ref "Pratique a seguir: scripts/concepts/totp-mfa (segundo fator) e scripts/concepts/password-entropy"
section 6 "Referencias"
ref "HIBP Pwned Passwords: https://haveibeenpwned.com/Passwords"
ref "k-anonymity (Cloudflare): https://blog.cloudflare.com/validating-leaked-passwords-with-k-anonymity/"
ref "NIST SP 800-63B (memorized secrets): https://pages.nist.gov/800-63-3/sp800-63b.html"
footer
