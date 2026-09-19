# CRLF / Log Injection — dissecação completa (CWE-117 log · CWE-113 response splitting)

> Código: [`LogInjectionDemo.java`](LogInjectionDemo.java) · payloads: [`payloads.txt`](payloads.txt)

## 1. Para leigos
Sistemas registram eventos em log e montam respostas HTTP com cabeçalhos. Ambos são "linhas". Se o
servidor escreve o que você digitou sem tratar e você inclui uma quebra de linha, você injeta uma LINHA
INTEIRA falsa: forja "admin logou com sucesso", esconde rastros, ou injeta um cabeçalho/cookie.

## 2. Como funciona tecnicamente
`\r` (CR) e `\n` (LF) terminam linhas. Em **logs**, uma LF cria uma nova entrada (log forging), o que
mina auditoria e engana dashboards/alertas. Em **HTTP** (response splitting/CWE-113), um CRLF no valor
de um cabeçalho injeta novos cabeçalhos (ex.: `Set-Cookie`) ou até um corpo. A defesa é **remover/
neutralizar** CR/LF e demais controles antes de usar o valor; e usar **logging estruturado**.

## 3. Variantes/técnicas (rodam no `.java`)
1. **Log forging** — `\n` no valor cria uma entrada de log falsa.
2. **HTTP response splitting** — `\r\n` no `Location`/header injeta `Set-Cookie`/corpo.
3. **Outros controles** — `\r` isolado, tab (quebram parsers de log e visualizadores).

## 4. Casos reais
- **HTTP response splitting** foi comum nos anos 2000; hoje Tomcat/Jetty rejeitam CR/LF em `setHeader`,
  mitigando o vetor — mas o **log forging** continua vivo e subestimado.
- **Log4Shell (CVE-2021-44228)** reforçou a lição "não confie no que vai pro log" (ali foi interpolação
  `${jndi:...}`, não CRLF). https://nvd.nist.gov/vuln/detail/CVE-2021-44228
- Falhas de logging/monitoramento: OWASP A09:2021. https://owasp.org/Top10/2021/A09_2021-Security_Logging_and_Monitoring_Failures/

## 5. Trechos de repositórios (reimplementados, com crédito)
- **OWASP Log Injection** — descreve o log forging por CR/LF da Variante 1.
  https://owasp.org/www-community/attacks/Log_Injection
- **PayloadsAllTheThings — CRLF Injection** — fonte dos payloads de response splitting.
  https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CRLF%20Injection

## 6. Defesa em profundidade
1. **Sanitizar** CR/LF/controles antes de logar/usar em header (ver
   `src/main/java/com/arthur/security/logging/AuditController.java`).
2. **Logging estruturado** (JSON/key-value) — o valor vira um campo, não texto livre.
3. Usar APIs de header que **rejeitam** CR/LF (contêineres modernos já fazem).
4. Codificar ao exibir logs em web/terminal (evita XSS/ANSI em visualizadores).

## 7. Como testar/detectar
- Enviar valores com `%0d%0a` (CRLF) em parâmetros que vão para header/redirect/log.
- Revisar `log.info(userInput)` e `response.setHeader(name, userInput)`.
- Testes: `src/test/java/com/arthur/security/attacks/loginjection/*`.

## 8. Leitura adicional
- OWASP Log Injection: https://owasp.org/www-community/attacks/Log_Injection
- OWASP Logging Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- CWE-117: https://cwe.mitre.org/data/definitions/117.html · CWE-113: https://cwe.mitre.org/data/definitions/113.html
