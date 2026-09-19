# Conceito: MFA com TOTP (RFC 6238)

Segundo fator baseado em tempo: app (Google Authenticator/Authy) e servidor compartilham um segredo e
derivam um código de 6 dígitos a cada 30s via HMAC-SHA1 (HOTP + tempo). Uma senha roubada não basta.

- Roda: `scripts/concepts/totp-mfa/totp-mfa.sh` (offline, tempo fixo p/ determinismo).
- Liga a: **#04 brute-force** (MFA derruba stuffing/spraying) e **#06 jwt** (HMAC).
- Referências: RFC 6238 (TOTP) https://datatracker.ietf.org/doc/html/rfc6238 · RFC 4226 (HOTP)
  https://datatracker.ietf.org/doc/html/rfc4226 · OWASP MFA Cheat Sheet.
