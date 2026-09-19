# Brute Force / Credential Stuffing — dissecação completa (CWE-307 · OWASP A07:2021)

> Código: [`BruteForceDemo.java`](BruteForceDemo.java) · payloads: [`payloads.txt`](payloads.txt)

## 1. Para leigos
Se o login aceita tentativas infinitas, um robô testa milhões de senhas até acertar (força bruta), ou
reusa listas de senhas vazadas de outros sites (credential stuffing). Um cadeado que se pode girar para
sempre acaba aberto.

## 2. Como funciona tecnicamente
Três formatos distintos, com defesas distintas:
- **Vertical** (1 usuário, N senhas) → **lockout por conta** e backoff resolvem.
- **Spraying** (1 senha comum, N usuários, 1 tentativa cada) → **driblа o lockout por conta**; exige
  limite **global/por-IP**, detecção de padrão e **MFA**.
- **Credential stuffing** (pares user:senha vazados) → **MFA** e **bloqueio de senhas vazadas** (checar
  contra listas tipo HaveIBeenPwned) são o que realmente ajuda.

## 3. Variantes/técnicas (rodam no `.java`)
1. **Vertical** sem lockout vs com lockout após N falhas.
2. **Spraying** — mostra que 1 tentativa por conta não dispara lockout por conta.
3. **Credential stuffing** — par vazado funciona; defesa = lista de vazadas + MFA.

## 4. Casos reais
- **Credential stuffing** movido por vazamentos massivos (Collections #1–5); a Akamai reporta bilhões de
  tentativas por ano contra varejo/finanças.
- **Verizon DBIR** aponta credenciais como principal vetor de invasão web ano após ano.
- **OWASP Top 10:2025** mantém "Identification and Authentication Failures". https://owasp.org/Top10/2025/

## 5. Trechos de repositórios (reimplementados, com crédito)
- **OWASP Authentication Cheat Sheet** — lockout, backoff, MFA, senhas vazadas (base das defesas aqui).
  https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- No app: lockout dirigido por eventos em
  `src/main/java/com/arthur/security/login/LoginAttemptService.java`.

## 6. Defesa em profundidade
1. **Lockout por conta** + **backoff exponencial** (vertical).
2. **Rate limit global/por-IP** + detecção de spraying (ver ataque 26).
3. **MFA** — neutraliza stuffing e spraying mesmo com senha correta.
4. **Bloquear senhas vazadas** no cadastro/login (k-anonymity HIBP).
5. **CAPTCHA** adaptativo; alertas de login anômalo; senhas fortes.

## 7. Como testar/detectar
- Automatizar N logins e ver se há lockout/429; medir se spraying passa.
- Monitorar taxa de falha por IP/ASN e por conta.
- Testes: `src/test/java/com/arthur/security/attacks/bruteforce/*`.

## 8. Leitura adicional
- OWASP Blocking Brute Force: https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks
- OWASP Credential Stuffing Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html
- CWE-307: https://cwe.mitre.org/data/definitions/307.html

## 9. Trilhas de aprendizado (conhecimentos que levam a outros)

- **Pré-requisitos:** como funciona o login/sessão HTTP; noções de **hashing de senha** (veja o ataque
  **[#05 password storage](../05-password-storage/DEEP-DIVE.md)**) — a lentidão do hash é o que encarece a força bruta.
- **Este ataque se conecta com:**
  - **[#26 rate limiting](../26-rate-limiting/DEEP-DIVE.md)** — o limite global/por-IP é o que barra spraying/reverse (lockout por conta não pega).
  - **[#14 enumeração de usuários](../14-user-enumeration/DEEP-DIVE.md)** — descobrir usuários válidos torna o spraying muito mais eficiente.
  - **[#06 jwt](../06-jwt/DEEP-DIVE.md)** e **[#05 password storage](../05-password-storage/DEEP-DIVE.md)** — o que o atacante ganha se a senha cai.
- **Conceitos rodáveis relacionados (pratique a seguir):**
  - `scripts/concepts/hibp-k-anonymity` — bloquear senhas vazadas sem expô-las (mata credential stuffing).
  - `scripts/concepts/totp-mfa` — MFA/TOTP (RFC 6238): a senha correta sozinha deixa de bastar.
  - `scripts/concepts/password-entropy` — por que comprimento + hash lento tornam a quebra inviável.
- **Aprofundar:** NIST SP 800-63B (senhas/MFA) https://pages.nist.gov/800-63-3/sp800-63b.html ·
  OWASP Credential Stuffing Prevention · MITRE ATT&CK T1110 (Brute Force) https://attack.mitre.org/techniques/T1110/
