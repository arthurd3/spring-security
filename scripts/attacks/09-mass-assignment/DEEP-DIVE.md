# Mass Assignment (over-posting) — dissecação completa (CWE-915 · OWASP A08:2021 / API6)

> Código: [`MassAssignmentDemo.java`](MassAssignmentDemo.java) · notas: [`payloads.txt`](payloads.txt)

## 1. Para leigos
O cadastro tem usuário e senha, mas por baixo o servidor copia AUTOMATICAMENTE tudo o que veio no pedido
para o registro. O atacante adiciona um campo que o formulário nunca mostrou — `role: ADMIN`, `admin:
true`, `balance: 1000000` — e o servidor obedece.

## 2. Como funciona tecnicamente
O binder (Jackson, data binding do Spring MVC) preenche o objeto **campo a campo** a partir do JSON. Se
o objeto alvo tem propriedades sensíveis (`role`, `admin`, `balance`), um JSON com esses nomes as
preenche. A correção é **allowlist**: vincular a um DTO/record que **só** tem os campos permitidos; o
servidor decide os valores privilegiados. Blocklist (`@JsonIgnore` campo a campo) é frágil — cada coluna
nova é um risco novo.

## 3. Variantes/técnicas (rodam no `.java`)
1. **Role escalation** — `"role":"ADMIN"`.
2. **isAdmin** — flag booleana privilegiada.
3. **Price/balance tampering** — sobrescrever valor de negócio.
4. **Defesa por rejeição** — `@JsonIgnoreProperties(ignoreUnknown=false)` recusa campos extras.

## 4. Casos reais
- **GitHub (2012):** Egor Homakov explorou mass assignment do Rails para se adicionar como colaborador
  de um repositório — o caso que popularizou o termo. https://github.com/rails/rails/issues/5228
- **Spring4Shell — CVE-2022-22965 (2022):** primo direto — abuso do **data binding** do Spring MVC
  (propriedades encadeadas até o ClassLoader) → RCE. https://nvd.nist.gov/vuln/detail/CVE-2022-22965
- **OWASP API6:2023** (Mass Assignment / property-level authorization). https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/

## 5. Trechos de repositórios (reimplementados, com crédito)
- **OWASP Mass Assignment Cheat Sheet** — allowlist/DTO (base do `.java`).
  https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
- No app: record `RegistrationRequest(username,password)` em
  `src/main/java/com/arthur/security/auth/RegistrationController.java`.

## 6. Defesa em profundidade
1. **DTO/record com allowlist** de campos (a correção real).
2. Servidor **define** valores privilegiados (role, saldo, flags), nunca o cliente.
3. `@JsonIgnoreProperties(ignoreUnknown=false)` para **rejeitar** campos extras.
4. No Spring MVC, restringir data binding (`@InitBinder setAllowedFields`) e manter o framework atualizado.
5. Testes que enviam campos extras e verificam que são ignorados/rejeitados.

## 7. Como testar/detectar
- Enviar campos além do formulário (`role`, `isAdmin`, `balance`) e checar o registro salvo.
- SAST para `@RequestBody <Entity>` / bind direto na entidade JPA.
- Testes: `src/test/java/com/arthur/security/attacks/massassignment/*`.

## 8. Leitura adicional
- OWASP Mass Assignment: https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
- OWASP API6:2023: https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/
- CWE-915: https://cwe.mitre.org/data/definitions/915.html
