# Conceito: comparação em tempo constante

Comparar segredos (tokens, HMAC, códigos) com `equals` que retorna no primeiro caractere diferente
**vaza**, pelo tempo, quantos caracteres o atacante acertou — permitindo recuperar o segredo byte a byte.
Use comparação em **tempo constante** (`MessageDigest.isEqual`).

- Roda: `scripts/concepts/constant-time-compare/constant-time-compare.sh` (mede os dois casos).
- Liga a: **#14 enumeração (timing)** e **#06 jwt (verificação de assinatura)**.
- Referências: OWASP (timing attacks); `MessageDigest.isEqual` (JDK).
