# XPath Injection — dissecação completa (CWE-643 · OWASP A03:2021 Injection)

> Código: [`XpathDemo.java`](XpathDemo.java) · payloads: [`payloads.txt`](payloads.txt)

## 1. Para leigos
Alguns sistemas guardam dados em XML e "perguntam" a esse XML com XPath (uma linguagem de busca). Se a
pergunta é montada colando o que você digitou, vale o mesmo truque do SQL injection: com aspas e um "ou
verdadeiro", você reescreve a busca para casar com todos os usuários — e loga sem senha.

## 2. Como funciona tecnicamente
XPath não tem "contas de usuário" nem permissões: se o atacante controla parte da expressão, controla a
**consulta inteira**. A correção é a mesma ideia do bind parameter do SQL: **variáveis vinculadas** via
`XPathVariableResolver` — o valor entra como dado, nunca como sintaxe. Não há como "escapar" com
segurança de forma portável.

## 3. Variantes/técnicas (rodam no `.java`)
1. **Tautologia** `' or '1'='1` — bypass de autenticação.
2. **Blind XPath** — a app só diz "existe/não existe"; com `substring(pass,i,1)='x'` o atacante extrai a
   senha caractere por caractere (o `.java` reconstrói `S3cr3t`).
3. **Divulgação por reescrita** `']|//user['1'='1` — o operador `|` (union) retorna todos os nós.

## 4. Casos reais
- XPath injection aparece em produtos que autenticam/consultam contra XML (LDAP-como, config, SAML).
  Menos comum que SQLi, mas mesma raiz e impacto (bypass/exfiltração).
- Injeção em geral segue no **OWASP Top 10:2025** (categoria Injection). https://owasp.org/Top10/2025/

## 5. Trechos de repositórios (reimplementados, com crédito)
- **OWASP** — XPath Injection e WSTG (teste 4.7.9) descrevem a tautologia e o blind que replicamos.
  https://owasp.org/www-community/attacks/XPATH_Injection
- **PayloadsAllTheThings — XPath Injection** — fonte dos payloads de blind e union.
  https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XPATH%20Injection

## 6. Defesa em profundidade
1. **`XPathVariableResolver`** (variáveis `$var`) — a correção real (ver
   `src/main/java/com/arthur/security/xpath/XpathLoginService.java`).
2. Compilar a expressão uma vez (`XPath.compile`) com placeholders.
3. Preferir um formato/consulta que não misture dados e sintaxe; validar tipos.
4. Se o XML vier de fora, também desligar DTD (evita XXE junto) — ver ataque 15.

## 7. Como testar/detectar
- Enviar `'`, `' or '1'='1`, `']|//*` e observar bypass/dump.
- SAST para `XPath.evaluate(<string concatenada>)`.
- Testes: `src/test/java/com/arthur/security/attacks/xpath/*`.

## 8. Leitura adicional
- OWASP XPath Injection: https://owasp.org/www-community/attacks/XPATH_Injection
- OWASP WSTG XPath: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/09-Testing_for_XPath_Injection
- CWE-643: https://cwe.mitre.org/data/definitions/643.html

## 9. Trilhas de aprendizado (conhecimentos que levam a outros)
- **Pré-requisitos:** XML/XPath; separar consulta de dados.
- **Conecta com:** [#08 SQLi](../08-sql-injection/DEEP-DIVE.md) (mesma raiz), [#15 XXE](../15-xxe/DEEP-DIVE.md) (XML), família injeção.
- **Conceitos rodáveis:** — (foco em `XPathVariableResolver`/variáveis vinculadas).
- **Aprofundar:** OWASP XPath Injection · OWASP WSTG (XPath).
