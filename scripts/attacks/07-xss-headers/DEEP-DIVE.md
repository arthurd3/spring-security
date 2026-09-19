# Cross-Site Scripting (XSS) — dissecação completa (CWE-79 · OWASP A03:2021)

> Código: [`XssDemo.java`](XssDemo.java) · payloads: [`payloads.txt`](payloads.txt)

## 1. Para leigos
XSS acontece quando o site devolve, dentro da página, um texto que veio do usuário SEM tratar. Se você
manda `<script>...</script>` e o site cola cru no HTML, o navegador da vítima EXECUTA esse script —
roubando sessão, digitação, ou agindo como a vítima.

## 2. Como funciona tecnicamente
A defesa principal é **escapar a saída no contexto certo**: HTML, atributo, JavaScript, URL e CSS têm
regras diferentes. `htmlEscape` resolve o corpo HTML; dentro de um atributo é preciso **aspas + escape**;
dentro de `<script>` é preciso **encoding `\uXXXX`**. Tipos de XSS: **refletido** (volta na resposta),
**armazenado** (persistido, atinge todos) e **DOM** (o JS do cliente escreve input no DOM). **CSP** e
`nosniff` são camadas extras que reduzem o impacto quando algo escapa.

## 3. Variantes/técnicas (rodam no `.java`)
1. **Refletido** (contexto HTML).
2. **Armazenado** (persistido e servido a todos).
3. **Contexto de atributo** (quebrar o atributo → `onmouseover`).
4. **Contexto JavaScript** (fechar a string → executar).
5. **Cabeçalhos** (CSP/nosniff como defesa em profundidade).

## 4. Casos reais
- **Samy worm (MySpace, 2005):** XSS armazenado que se auto-propagou a ~1M perfis em ~20h.
- **British Airways / Magecart (2018):** script malicioso (skimmer) roubou dados de cartão de ~380k
  clientes — XSS/JS injection na cadeia de pagamento.
- **OWASP Top 10:2025** mantém Injection (XSS incluído). https://owasp.org/Top10/2025/

## 5. Trechos de repositórios (reimplementados, com crédito)
- **OWASP XSS Prevention Cheat Sheet** — as regras por contexto (HTML/attr/JS/URL/CSS) que o `.java`
  aplica. https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- **OWASP WebGoat / DVWA** — laboratórios de XSS refletido/armazenado/DOM. https://github.com/WebGoat/WebGoat
- No app: `HtmlUtils.htmlEscape` em `src/main/java/com/arthur/security/web/MainController.java`.

## 6. Defesa em profundidade
1. **Output encoding por contexto** (a defesa real) — usar libs (OWASP Java Encoder, `HtmlUtils`, o
   auto-escaping do Thymeleaf).
2. **CSP** (idealmente com nonce/hash; sem `unsafe-inline`) + `X-Content-Type-Options: nosniff`.
3. Cookies `HttpOnly` (o JS não lê a sessão) + `SameSite`.
4. Sanitização de HTML rico com allowlist (OWASP Java HTML Sanitizer) quando HTML é permitido.
5. Frameworks com escaping por padrão; evitar `innerHTML`/`v-html`/`dangerouslySetInnerHTML`.

## 7. Como testar/detectar
- Injetar `<script>`, `"><svg onload=alert(1)>`, `';alert(1);//` em cada contexto.
- Ferramentas: OWASP ZAP, Burp, DOM Invader; revisar sinks (`innerHTML`, template não escapado).
- Testes: `src/test/java/com/arthur/security/attacks/headers/*`.

## 8. Leitura adicional
- OWASP XSS Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- PortSwigger XSS: https://portswigger.net/web-security/cross-site-scripting
- CWE-79: https://cwe.mitre.org/data/definitions/79.html

## 9. Trilhas de aprendizado (conhecimentos que levam a outros)
- **Pré-requisitos:** contextos HTML/atributo/JS/URL; DOM; codificação de saída.
- **Conecta com:** [#02 CSRF](../02-csrf/DEEP-DIVE.md) (XSS derrota CSRF), [#23 CRLF/log](../23-crlf-log-injection/DEEP-DIVE.md) e [#08 SQLi](../08-sql-injection/DEEP-DIVE.md) (família injeção), [#21 file upload](../21-file-upload/DEEP-DIVE.md) (HTML armazenado).
- **Conceitos rodáveis:** — (foco em codificação por contexto e CSP).
- **Aprofundar:** OWASP XSS Prevention · MDN Content-Security-Policy · PortSwigger XSS.
