#!/usr/bin/env bash
# 05 - Weak Password Storage (CWE-256/916 / OWASP A02:2021) - deep dive
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/../../lib/common.sh"; ensure_java
title "05. Armazenamento de Senha  -  CWE-256 / CWE-916 (deep dive)"
section 1 "Entenda em 3 niveis"
level "Basico" "Guardar a senha como foi digitada entrega tudo num vazamento. O certo guarda um resumo embaralhado (hash) irreversivel, e esse hash precisa ser LENTO de proposito."
level "Intermediario" "Hash rapido (MD5/SHA) e ruim: GPU testa bilhoes/s. Sem sal, senha igual = hash igual (reuso) e cai em rainbow table. Sal resolve reuso, nao a velocidade."
level "Avancado" "Use funcao de senha lenta e ajustavel: Argon2id (preferido), bcrypt, scrypt, PBKDF2. Reforcos: pepper (fora do DB) e upgrade-on-login."
section 2 "Conceitos tecnicos"
term "Hash" "Funcao de mao unica; guarda-se o resumo, nunca a senha."
term "Sal" "Aleatorio por senha; mata rainbow tables e esconde reuso."
term "Rainbow table" "Tabela precomputada hash->senha; funciona contra hash sem sal."
term "bcrypt/argon2" "Hash de senha LENTO e ajustavel; encarece a quebra em massa."
section 3 "O codigo (5 variantes, nesta pasta)"; show_code "$HERE/PasswordStorageDemo.java"
section 4 "Executando as variantes"; run_demo "$HERE/PasswordStorageDemo.java"
section 5 "Por que a defesa funciona"
para "BCrypt (salgado, lento) torna a quebra em massa inviavel, e a senha nunca e devolvida. No app: src/main/java/com/arthur/security/config/AppConfig.java (DelegatingPasswordEncoder)."
doc_pointer "$HERE"
section 6 "Referencias"
ref "OWASP Password Storage: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html"
ref "Real: LinkedIn 2012 (SHA1 sem sal); Adobe 2013 (3DES ECB)"
ref "Spring password storage: https://docs.spring.io/spring-security/reference/features/authentication/password-storage.html"
ref "CWE-916: https://cwe.mitre.org/data/definitions/916.html"
footer
