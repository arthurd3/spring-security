#!/usr/bin/env bash
# 24 - Insecure Randomness (CWE-330 / OWASP A02:2021) - deep dive
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/../../lib/common.sh"; ensure_java
title "24. Insecure Randomness  -  CWE-330 / OWASP A02:2021 (deep dive)"
section 1 "Entenda em 3 niveis"
level "Basico" "Tokens de seguranca precisam ser imprevisiveis. Geradores 'aleatorios' comuns nao sao: dada a semente (muitas vezes o horario), da para reproduzir tudo. O atacante preve o proximo token e sequestra a conta."
level "Intermediario" "java.util.Random e um PRNG deterministico (48 bits): mesma semente = mesma sequencia; poucas saidas revelam o estado. Semente pelo tempo -> brute force numa janela."
level "Avancado" "Correcao: SecureRandom (CSPRNG) com >=128-256 bits. UUID.randomUUID() ja usa SecureRandom; UUID de Random nao e seguro. Nunca semear com tempo nem aceitar semente do cliente."
section 2 "Conceitos tecnicos"
term "PRNG (java.util.Random)" "Pseudo-aleatorio deterministico; otimo p/ simulacao, pessimo p/ seguranca."
term "Semente pelo tempo" "Previsivel -> brute force da semente numa janela de segundos."
term "CSPRNG (SecureRandom)" "Gerador criptografico: imprevisivel mesmo conhecendo saidas anteriores."
term "Entropia" "Bits de imprevisibilidade; token deve ter >=128-256 bits."
section 3 "O codigo (4 variantes, nesta pasta)"; show_code "$HERE/RandomnessDemo.java"
section 4 "Executando as variantes"; run_demo "$HERE/RandomnessDemo.java"
section 5 "Por que a defesa funciona"
para "SecureRandom com 256 bits nao tem semente adivinhavel nem repete, entao nao ha como recuperar estado ou prever o proximo token. No app: src/main/java/com/arthur/security/token/TokenController.java."
doc_pointer "$HERE"
section 6 "Referencias"
ref "OWASP Insecure Randomness: https://owasp.org/www-community/vulnerabilities/Insecure_Randomness"
ref "OWASP Cryptographic Storage: https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html"
ref "CWE-330: https://cwe.mitre.org/data/definitions/330.html"
footer
