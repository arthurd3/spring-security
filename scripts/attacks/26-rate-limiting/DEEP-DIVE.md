# Missing Rate Limiting — dissecação completa (CWE-770 · OWASP API4:2023)

> Código: [`RateLimitDemo.java`](RateLimitDemo.java) · notas: [`payloads.txt`](payloads.txt)

## 1. Para leigos
Se uma ação sensível (verificar um código OTP, tentar cupom, pedir reset) aceita quantas tentativas o
cliente quiser, o atacante automatiza e testa tudo. Um OTP de 4 dígitos tem 10.000 possibilidades — sem
limite, cai em segundos. Rate limiting é o freio.

## 2. Como funciona tecnicamente
Limitar exige **contar por identidade** dentro de uma **janela de tempo** e recusar o excedente (HTTP
**429**). Dois erros comuns: (1) **chavear por header spoofável** (`X-Forwarded-For`) — o atacante rotaciona
e zera o contador; use o **IP real da conexão** (ou identidade autenticada); (2) **janela fixa**, que
permite um **burst na virada** (MAX no fim de uma janela + MAX no início da próxima = 2×MAX num instante).
**Janela deslizante** ou **token bucket** corrigem isso.

## 3. Variantes/técnicas (rodam no `.java`)
1. **Sem limite** — tudo processado.
2. **Bypass por X-Forwarded-For** — chave spoofável zera o contador; chave por IP real resiste.
3. **Burst de janela fixa** vs **janela deslizante**.
4. **Token bucket** + `Retry-After` (suave e informativo).

## 4. Casos reais
- Bypass de rate limit por rotação de `X-Forwarded-For`/IP é achado clássico em bug bounties (OTP, login,
  reset) — inclusive em grandes plataformas.
- **OWASP API4:2023 — Unrestricted Resource Consumption** trata exatamente disso.
  https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/

## 5. Trechos de repositórios (reimplementados, com crédito)
- **OWASP API Security / DoS Cheat Sheet** — base das defesas (429, backoff, chaves confiáveis).
  https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html
- Bibliotecas de referência: **Bucket4j** (token bucket em Java), **Resilience4j RateLimiter**.
  https://github.com/bucket4j/bucket4j
- No app: `src/main/java/com/arthur/security/ratelimit/RateLimiter.java`.

## 6. Defesa em profundidade
1. **Contar por identidade confiável** (IP real da conexão / usuário autenticado), não por header.
2. **Janela deslizante** ou **token bucket** (evita burst de janela fixa).
3. Responder **429** com **Retry-After**; aplicar **backoff exponencial** e lockout onde couber.
4. Limites por rota **e** globais; proteção distribuída (limitador central: Redis).
5. Combinar com **CAPTCHA/MFA** em endpoints críticos; alertar em picos.

## 7. Como testar/detectar
- Automatizar N chamadas e ver se surge 429; tentar bypass rotacionando XFF/IP.
- Medir burst na virada da janela.
- Testes: `src/test/java/com/arthur/security/attacks/ratelimit/*`.

## 8. Leitura adicional
- OWASP API4:2023: https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/
- OWASP DoS Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html
- CWE-770: https://cwe.mitre.org/data/definitions/770.html
