# JWT Forgery — dissecação completa (CWE-345 · CWE-347 · OWASP A02/A07)

> Código: [`JwtDemo.java`](JwtDemo.java) · payloads: [`payloads.txt`](payloads.txt)

## 1. Para leigos
Um JWT é um "crachá digital" que diz quem você é e quais papéis tem, com uma ASSINATURA que prova que o
servidor o emitiu. Se o servidor esquece de CONFERIR a assinatura — ou aceita crachás "sem assinatura",
ou usa um segredo fraco — o atacante fabrica o próprio crachá e vira admin.

## 2. Como funciona tecnicamente
JWT = `header.payload.signature`. Header e payload são só Base64 (legíveis por todos); a assinatura é a
prova. Falhas comuns: (a) **`alg=none`** aceito; (b) **segredo HMAC fraco** (quebrável por dicionário);
(c) **não checar `exp`** (token eterno); (d) **confusão de algoritmo** — o verificador escolhe o alg pelo
header; o atacante troca RS256→HS256 e assina com a **chave pública** (que é pública) usada como segredo
HMAC. Defesa: **fixar o algoritmo esperado**, **verificar assinatura e `exp`**, e usar **segredo forte**.

## 3. Variantes/técnicas (rodam no `.java`)
1. **alg=none** — sem assinatura; verificador correto rejeita.
2. **Segredo fraco** — HS256 com `secret` quebrado por wordlist → forja qualquer token.
3. **Sem checar `exp`** — token expirado aceito porque só se confere a assinatura.
4. **Confusão RS256→HS256** — assina com a chave pública; verificador que confia no header aceita.

## 4. Casos reais
- **Confusão de algoritmo** afetou várias libs de JWT (aceitar HS256 quando esperavam RS256) — estudo
  de referência da PortSwigger. https://portswigger.net/web-security/jwt/algorithm-confusion
- **`alg=none`** e **kid/jwk injection** foram bugs recorrentes em libs populares (2015→hoje).
- **OWASP Top 10:2025** mantém falhas de identificação/autenticação. https://owasp.org/Top10/2025/

## 5. Trechos de repositórios (reimplementados, com crédito)
- **PortSwigger Web Security Academy — JWT** — base das 4 variantes. https://portswigger.net/web-security/jwt
- **JoyChou93/java-sec-code** — exemplos de JWT inseguro. https://github.com/JoyChou93/java-sec-code
- No app: OAuth2 Resource Server (Nimbus) em `src/main/java/com/arthur/security/config/JwtConfig.java`.

## 6. Defesa em profundidade
1. **Fixar o algoritmo** esperado no verificador (nunca ler do header).
2. **Verificar assinatura E claims** (`exp`, `nbf`, `iss`, `aud`).
3. **Segredo HMAC forte** (256+ bits) ou chaves assimétricas bem geridas (RS256/ES256).
4. Usar biblioteca madura (Nimbus) — não fazer parse manual.
5. Rotação de chaves via `kid` validado contra um conjunto confiável; revogação/expiração curta.

## 7. Como testar/detectar
- Trocar `alg` para `none`/`HS256`; remover a assinatura; usar `exp` no passado; tentar segredos comuns.
- Ferramentas: jwt_tool, PortSwigger JWT labs.
- Testes: `src/test/java/com/arthur/security/attacks/jwt/*`.

## 8. Leitura adicional
- PortSwigger JWT: https://portswigger.net/web-security/jwt
- OWASP JWT Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html
- CWE-347: https://cwe.mitre.org/data/definitions/347.html

## 9. Trilhas de aprendizado (conhecimentos que levam a outros)
- **Pré-requisitos:** HMAC/assinatura, base64url, chaves simétricas x assimétricas.
- **Conecta com:** [#24 aleatoriedade](../24-insecure-randomness/DEEP-DIVE.md) (segredo/chave forte), [#19 deserialização](../19-insecure-deserialization/DEEP-DIVE.md) (parsers de token), [#16 SSRF](../16-ssrf/DEEP-DIVE.md) (`jwks_uri`/`jku`).
- **Conceitos rodáveis:** `scripts/concepts/totp-mfa` (mesmo HMAC), `scripts/concepts/constant-time-compare` (comparar assinatura).
- **Aprofundar:** PortSwigger JWT · RFC 7519 (JWT)/7515 (JWS) · OWASP JWT Cheat Sheet.
