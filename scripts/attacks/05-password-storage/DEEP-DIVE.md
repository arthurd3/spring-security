# Armazenamento de Senha — dissecação completa (CWE-256 · CWE-916 · OWASP A02:2021)

> Código: [`PasswordStorageDemo.java`](PasswordStorageDemo.java) · notas: [`payloads.txt`](payloads.txt)

## 1. Para leigos
Se o site guarda a senha como você digitou, um vazamento do banco entrega a senha de todos. O certo
nunca guarda a senha: guarda um "resumo embaralhado" (hash) do qual não dá para voltar, mas que ainda
permite conferir. E esse hash precisa ser **lento** de propósito, para encarecer a quebra em massa.

## 2. Como funciona tecnicamente
- **Hash** = função de mão única. Mas hash **rápido** (MD5/SHA) é péssimo para senha: GPUs testam
  bilhões/s. **Sem sal**, senhas iguais viram hashes iguais (revela reuso) e caem para **rainbow tables**.
- **Sal** (aleatório por senha) mata rainbow tables e esconde reuso — mas não resolve a velocidade.
- **Funções de senha** (bcrypt, scrypt, Argon2, PBKDF2) são **lentas e com custo ajustável** — a resposta
  certa. **Pepper** (segredo fora do DB) e **upgrade-on-login** (re-hash com custo maior) são reforços.

## 3. Variantes/técnicas (rodam no `.java`)
1. **Texto puro** — vazamento entrega a senha.
2. **MD5/SHA sem sal** — reuso visível + quebra por rainbow table.
3. **SHA + sal** — esconde reuso, mas rápido → ainda quebrável em GPU.
4. **BCrypt** — salgado, lento, verificável (o certo).
5. **Pepper + upgrade-on-login** — reforços operacionais.

## 4. Casos reais
- **LinkedIn (2012):** ~6,5M hashes **SHA-1 sem sal** vazados e quebrados em massa.
- **Adobe (2013):** ~150M senhas cifradas com **3DES em modo ECB** (+ dicas), permitindo recuperação.
- Vazamentos seguem constantes; **OWASP Top 10:2025** mantém falhas criptográficas/armazenamento.

## 5. Trechos de repositórios (reimplementados, com crédito)
- **OWASP Password Storage Cheat Sheet** — base de todas as variantes (bcrypt/argon2/pepper).
  https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- No app: `DelegatingPasswordEncoder`/BCrypt em `src/main/java/com/arthur/security/config/AppConfig.java`.

## 6. Defesa em profundidade
1. **Argon2id** (preferido) ou **bcrypt/scrypt/PBKDF2** com custo adequado.
2. **Sal único** por senha (as libs acima já fazem).
3. **Pepper** guardado fora do banco (HSM/secret manager).
4. **Upgrade-on-login** para elevar o custo ao longo do tempo.
5. Nunca logar/serializar a senha (ver ataque 12); MFA reduz impacto de vazamento.

## 7. Como testar/detectar
- Inspecionar o formato armazenado: `{bcrypt}$2a$...` (ok) vs hex de MD5/SHA (ruim) vs texto (péssimo).
- Testes: `src/test/java/com/arthur/security/attacks/bruteforce/PasswordStorageTest.java`.

## 8. Leitura adicional
- OWASP Password Storage: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- Spring password storage: https://docs.spring.io/spring-security/reference/features/authentication/password-storage.html
- CWE-916: https://cwe.mitre.org/data/definitions/916.html

## 9. Trilhas de aprendizado (conhecimentos que levam a outros)
- **Pré-requisitos:** funções de hash; sal; por que "rápido" é ruim para senha.
- **Conecta com:** [#04 brute force](../04-brute-force/DEEP-DIVE.md) (o hash lento encarece a quebra), [#12 data exposure](../12-data-exposure/DEEP-DIVE.md) (vazamento de hashes), [#24 aleatoriedade](../24-insecure-randomness/DEEP-DIVE.md) (sal/pepper).
- **Conceitos rodáveis:** `scripts/concepts/password-entropy`, `scripts/concepts/hibp-k-anonymity`, `scripts/concepts/totp-mfa`, `scripts/concepts/constant-time-compare`.
- **Aprofundar:** OWASP Password Storage Cheat Sheet · NIST SP 800-63B · Spring `DelegatingPasswordEncoder`.
