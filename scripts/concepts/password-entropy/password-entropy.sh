#!/usr/bin/env bash
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/../../lib/common.sh"; ensure_java
title "CONCEITO: entropia de senha e tempo de quebra"
section 1 "O que e (para leigos)"
para "Entropia mede o quao dificil e ADIVINHAR a senha. Depende do tamanho do alfabeto usado e, principalmente, do COMPRIMENTO. Com a velocidade do hash, da para estimar quanto tempo um atacante levaria."
section 2 "Conceitos tecnicos"
term "Entropia (bits)" "len * log2(pool); cada bit dobra o espaco de busca."
term "Velocidade do hash" "MD5/SHA: bilhoes/s em GPU. bcrypt/argon2: milhares/s -> quebra fica inviavel."
term "Passphrase" "Frase longa: muito comprimento -> alta entropia, facil de lembrar."
section 3 "O codigo (roda offline)"; show_code "$HERE/PasswordEntropy.java"
section 4 "Executando"; run_demo "$HERE/PasswordEntropy.java"
section 5 "Conhecimentos conectados"
ref "Leva a: #05 password storage (hash lento) e #04 brute-force (custo do ataque)"
ref "Pratique a seguir: scripts/concepts/hibp-k-anonymity (bloquear vazadas) e totp-mfa (2FA)"
section 6 "Referencias"
ref "NIST SP 800-63B: https://pages.nist.gov/800-63-3/sp800-63b.html"
ref "OWASP Password Storage: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html"
footer
