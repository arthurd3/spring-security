# Conceito: entropia de senha e tempo de quebra

Entropia (bits) mede a imprevisibilidade: `len * log2(tamanho_do_alfabeto)`. Combinada com a velocidade
do hash, estima o tempo de força bruta. Lição: **comprimento** domina, e um **hash lento** (bcrypt/argon2)
multiplica o custo do atacante.

- Roda: `scripts/concepts/password-entropy/password-entropy.sh`.
- Liga a: **#04 brute-force** e **#05 password storage**.
- Referências: NIST SP 800-63B (comprimento, passphrases, listas de vazadas).
