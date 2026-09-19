# Conceito: HIBP Pwned Passwords via k-anonymity

Checar se uma senha já vazou **sem enviar a senha** (nem o hash completo). Envia-se só os **5 primeiros
caracteres hex** do SHA-1; o servidor devolve todos os sufixos+contagens daquele prefixo; o casamento do
sufixo é **local**. É o modelo *k-anonymity* das Pwned Passwords.

- Roda: `scripts/concepts/hibp-k-anonymity/hibp-k-anonymity.sh` (offline, corpus local de exemplo).
- Liga a: **#04 brute-force** (bloquear senhas vazadas mata credential stuffing) e **#05 password storage**.
- Referências: Have I Been Pwned — Pwned Passwords (Troy Hunt) https://haveibeenpwned.com/Passwords ·
  modelo k-anonymity (Cloudflare) https://blog.cloudflare.com/validating-leaked-passwords-with-k-anonymity/ ·
  NIST SP 800-63B (checar senhas contra listas de comprometidas).
