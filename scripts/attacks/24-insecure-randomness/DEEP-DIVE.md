# Insecure Randomness — dissecação completa (CWE-330 · OWASP A02:2021)

> Código: [`RandomnessDemo.java`](RandomnessDemo.java) · notas: [`payloads.txt`](payloads.txt)

## 1. Para leigos
Tokens de segurança (link de redefinir senha, id de sessão, chave de API) precisam ser IMPREVISÍVEIS.
Muitos geradores "aleatórios" comuns não são: dada a "semente" (muitas vezes o horário), dá para
reproduzir toda a sequência. Se o token vem de um gerador desses, o atacante PREVÊ o próximo e sequestra
a conta.

## 2. Como funciona tecnicamente
`java.util.Random` é um **PRNG determinístico** (LCG de 48 bits): mesma semente → mesma sequência, e a
partir de poucas saídas dá para recuperar o estado. Se a semente é **o tempo**, o atacante faz **força
bruta numa janela** de segundos até casar um token observado — e então **prevê os próximos**. Correção:
**`SecureRandom`** (CSPRNG, imprevisível mesmo conhecendo saídas anteriores) com **entropia suficiente**
(≥128–256 bits). `UUID.randomUUID()` já usa `SecureRandom`; UUID feito de `Random` **não** é seguro.

## 3. Variantes/técnicas (rodam no `.java`)
1. **Semente conhecida** → saída reproduzível.
2. **Semente pelo tempo** → força bruta da semente + **previsão do próximo token**.
3. **UUID/token previsível** (de `Random`) vs `UUID.randomUUID()`/`SecureRandom`.
4. **Entropia/comprimento** — token curto é força-bruteável.

## 4. Casos reais
- Múltiplos bugs de **reset de senha/sessão previsíveis** por uso de `Random`/tempo já renderam takeover
  de conta (bug bounties e CVEs em frameworks/apps).
- Loterias/jogos com PRNG previsível foram explorados para prever resultados.
- **OWASP Top 10:2025** mantém falhas criptográficas (aleatoriedade insegura incluída). https://owasp.org/Top10/2025/

## 5. Trechos de repositórios (reimplementados, com crédito)
- **OWASP - Insecure Randomness** e **Cryptographic Storage Cheat Sheet** (base do `.java`).
  https://owasp.org/www-community/vulnerabilities/Insecure_Randomness
- No app: `SecureRandom` + 256 bits em `src/main/java/com/arthur/security/token/TokenController.java`.

## 6. Defesa em profundidade
1. **`SecureRandom`** (CSPRNG) para tudo que é segredo/token.
2. **≥128–256 bits** de entropia; codificar em base64url/hex.
3. `UUID.randomUUID()` (usa SecureRandom) quando UUID servir; nunca UUID de `Random`.
4. Nunca semear com **tempo/valores previsíveis**; nunca expor/permitir semente do cliente.
5. Tokens de uso único, curta expiração e vinculados ao usuário/ação.

## 7. Como testar/detectar
- Procurar `new Random(...)`, `Math.random()`, `nextInt` para tokens/ids/segredos.
- Coletar tokens e testar previsibilidade (reconstruir estado do LCG).
- Testes: `src/test/java/com/arthur/security/attacks/randomness/*`.

## 8. Leitura adicional
- OWASP Insecure Randomness: https://owasp.org/www-community/vulnerabilities/Insecure_Randomness
- OWASP Cryptographic Storage: https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
- CWE-330: https://cwe.mitre.org/data/definitions/330.html
