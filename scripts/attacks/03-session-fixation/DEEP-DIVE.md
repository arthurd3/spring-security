# Session Fixation — dissecação completa (CWE-384 · OWASP A07:2021)

> Código: [`SessionFixationDemo.java`](SessionFixationDemo.java) · notas: [`payloads.txt`](payloads.txt)

## 1. Para leigos
Toda sessão tem um "número de crachá" (id de sessão). No ataque, o criminoso força a vítima a usar um
crachá que ELE conhece; quando a vítima faz login, esse crachá vira "autenticado" e o atacante entra com
o mesmo número. A defesa: no login, TROCAR o número do crachá.

## 2. Como funciona tecnicamente
Se o servidor mantém o mesmo id de sessão **antes e depois** do login, um id plantado pelo atacante
(via link `;jsessionid=`, cookie forçado, ou XSS) passa a valer como sessão autenticada. Correções:
**rotacionar o id no login** (`changeSessionId`), **nunca aceitar id vindo do cliente** (gerar só no
servidor; `HttpOnly`/`Secure`/`SameSite`), e **invalidar** a sessão no logout e por timeout.

## 3. Variantes/técnicas (rodam no `.java`)
1. **Fixação clássica** — id mantido no login (vuln) vs rotacionado (safe).
2. **Aceitar id do cliente** — servidor confia no `;jsessionid=` da URL (vuln) vs sempre gera no servidor.
3. **Sem invalidação no logout** — sessão continua válida após "sair" (vuln) vs invalidada (safe).

## 4. Casos reais
- Session fixation é descrita desde o paper da ACROS (2002); ainda aparece em apps que expõem o id na
  URL ou não rotacionam no login.
- **OWASP Top 10:2025** mantém falhas de identificação/autenticação e gestão de sessão. https://owasp.org/Top10/2025/

## 5. Trechos de repositórios (reimplementados, com crédito)
- **OWASP Session Management Cheat Sheet** — rotacionar no login, `HttpOnly/Secure/SameSite`, timeout,
  invalidação. https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- No app: `sessionFixation().changeSessionId()` em
  `src/main/java/com/arthur/security/config/WebSecurityConfig.java`.

## 6. Defesa em profundidade
1. **Rotacionar** o id no login (`changeSessionId`).
2. **Nunca** aceitar id de sessão vindo do cliente (URL/param); gerar só no servidor.
3. Cookies `HttpOnly`, `Secure`, `SameSite`.
4. **Invalidar** no logout e por **timeout** (absoluto e por inatividade).
5. Vincular a sessão a atributos (User-Agent/IP) com cautela; MFA em ações sensíveis.

## 7. Como testar/detectar
- Capturar o id antes do login e ver se muda depois.
- Tentar impor `;jsessionid=` via URL; verificar logout/timeout.
- Testes: `src/test/java/com/arthur/security/attacks/sessionfixation/*`.

## 8. Leitura adicional
- OWASP Session fixation: https://owasp.org/www-community/attacks/Session_fixation
- OWASP Session Management: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- CWE-384: https://cwe.mitre.org/data/definitions/384.html

## 9. Trilhas de aprendizado (conhecimentos que levam a outros)
- **Pré-requisitos:** cookies/sessão; por que o id de sessão precisa ser imprevisível.
- **Conecta com:** [#02 CSRF](../02-csrf/DEEP-DIVE.md), [#07 XSS](../07-xss-headers/DEEP-DIVE.md) (roubar/fixar sessão via JS), [#24 aleatoriedade](../24-insecure-randomness/DEEP-DIVE.md) (id de sessão previsível).
- **Conceitos rodáveis:** `scripts/concepts/constant-time-compare` (comparar id/token de sessão).
- **Aprofundar:** OWASP Session Management Cheat Sheet · OWASP ASVS V3 (Session).
