# Broken Access Control / IDOR — dissecação completa (CWE-639 · OWASP A01:2021 / API1 BOLA)

> Código: [`IdorDemo.java`](IdorDemo.java) · notas: [`payloads.txt`](payloads.txt)

## 1. Para leigos
O site mostra "sua conta" pela URL `/conta/1`. Se você troca para `2` e o servidor entrega sem conferir
se a conta é SUA, você leu os dados de outra pessoa. O atacante não invade nada — só troca um número.

## 2. Como funciona tecnicamente
IDOR é falha de **autorização no nível do objeto**: o app autentica ("quem é você") mas não checa "você
é dono DESTE registro". Estar logado não basta. Existem dois sabores: **horizontal** (outro usuário de
mesmo nível) e **vertical** (alcançar função de nível maior). Ids sequenciais facilitam **enumeração em
massa**; UUID dificulta adivinhar, mas **não é autorização** — a checagem de posse continua obrigatória.

## 3. Variantes/técnicas (rodam no `.java`)
1. **Horizontal** — ler o objeto de outro usuário.
2. **Vertical** — chamar função de admin sem papel.
3. **Enumeração** — varrer ids sequenciais e raspar tudo.
4. **Recurso aninhado** — `/accounts/{a}/docs/{d}` sem checar que o doc pertence ao account do caller.

## 4. Casos reais
- **USPS (2018):** IDOR em API expôs dados de ~60 milhões de usuários.
- **BOLA/IDOR** é a **API1:2023** do OWASP API Top 10 — a falha nº1 em APIs.
  https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
- **OWASP Top 10:2025:** **Broken Access Control** segue em 1º (e agora absorve SSRF).
  https://owasp.org/Top10/2025/

## 5. Trechos de repositórios (reimplementados, com crédito)
- **OWASP WebGoat** — lições de Access Control/IDOR (mesmo padrão de fetch sem checagem).
  https://github.com/WebGoat/WebGoat
- No app: `@PostAuthorize("returnObject.owner == authentication.name or hasRole('ADMIN')")` em
  `src/main/java/com/arthur/security/account/AccountService.java`.

## 6. Defesa em profundidade
1. **Checagem de posse no nível do objeto** (`@PostAuthorize`/`@PreAuthorize` ou escopo por dono na query
   `findByIdAndOwner`).
2. **Deny-by-default** nas rotas; papéis para função (vertical).
3. **Não confiar em ids do cliente**; validar o vínculo dono↔objeto em cada acesso, inclusive aninhado.
4. UUID/id opaco como reforço contra enumeração (nunca como autorização).
5. Rate limit/detecção contra varredura (ver ataque 26).

## 7. Como testar/detectar
- Trocar ids na URL/body/JWT; comparar com dois usuários; varrer faixas de id.
- Ferramentas: Burp Autorize, ZAP Access Control testing.
- Testes: `src/test/java/com/arthur/security/attacks/accesscontrol/*`.

## 8. Leitura adicional
- OWASP IDOR Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html
- PortSwigger Access control: https://portswigger.net/web-security/access-control/idor
- CWE-639: https://cwe.mitre.org/data/definitions/639.html

## 9. Trilhas de aprendizado (conhecimentos que levam a outros)
- **Pré-requisitos:** autenticação x autorização; como ids viajam em URL/body/JWT.
- **Conecta com:** [#14 enumeração](../14-user-enumeration/DEEP-DIVE.md) (achar ids/usuários válidos), [#09 mass assignment](../09-mass-assignment/DEEP-DIVE.md) (autorização no nível de propriedade), [#26 rate limiting](../26-rate-limiting/DEEP-DIVE.md) (barrar varredura).
- **Conceitos rodáveis:** `scripts/concepts/constant-time-compare` (comparar tokens de acesso com segurança).
- **Aprofundar:** OWASP API1:2023 BOLA · OWASP ASVS V4 (Access Control) · MITRE ATT&CK T1190.
