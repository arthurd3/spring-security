# SpEL / Server-Side Template Injection — dissecação completa (CWE-917 · OWASP A03:2021)

> Código: [`SpelDemo.java`](SpelDemo.java) · payloads: [`payloads.txt`](payloads.txt)

## 1. Para leigos
Alguns sistemas "montam texto" avaliando pequenas fórmulas/expressões (em templates, regras, roteamento).
Se o servidor **avalia** o que você digitou como fórmula, você deixa de ser usuário e vira programador
dentro do servidor: em vez de um nome, escreve "me diga o usuário do sistema" ou "rode este comando".

## 2. Como funciona tecnicamente
SpEL (Spring Expression Language) avalia expressões em runtime. Com o contexto padrão
(`StandardEvaluationContext`), a expressão tem acesso a **tipos** (`T(...)`), **construtores** (`new ...`)
e **métodos** — inclusive `Runtime.exec`. A correção primária é **não avaliar entrada do usuário**
(tratar como texto). Quando avaliar é inevitável, use `SimpleEvaluationContext` (proíbe `T()`,
construtores e a maioria dos métodos). Template engines (Thymeleaf, Freemarker, Velocity) têm a mesma
classe de falha: SSTI.

## 3. Variantes/técnicas (rodam no `.java`)
1. **Avaliação básica** — `7*7` volta `49`: prova que o input roda como código.
2. **Acesso a tipos** — `T(java.lang.System).getProperty('user.name')` vaza dados do servidor.
3. **RCE** — `T(java.lang.Runtime).getRuntime().exec(...)` executa comando do SO (o `.java` roda `echo`).
4. **Bypass de blacklist** — bloquear `Runtime` não basta: `ProcessBuilder` (ou reflexão/concatenção
   de strings dentro do SpEL) contorna. Allowlist/​não-avaliar vence.

## 4. Casos reais
- **Spring4Shell — CVE-2022-22965 (2022):** data binding do Spring MVC permitia manipular o ClassLoader
  via propriedades encadeadas → escrever um webshell JSP (RCE). https://nvd.nist.gov/vuln/detail/CVE-2022-22965
- **Spring Cloud Function — CVE-2022-22963 (2022):** header `spring.cloud.function.routing-expression`
  avaliado como SpEL → RCE. https://nvd.nist.gov/vuln/detail/CVE-2022-22963
- **Recente (2026): CVE-2026-59283** — bypass do "safety guard" de SpEL no Spring Framework
  (compilação de expressão), classificado crítico (CVSS ~9.1). Confirmar detalhes no advisory da Spring.

## 5. Trechos de repositórios (reimplementados, com crédito)
- **JoyChou93/java-sec-code** — `SpEL.java` avalia `parseExpression(input).getValue()` exatamente como a
  Variante 1–3. https://github.com/JoyChou93/java-sec-code
- **javaspringvulny** — app Spring vulnerável de propósito, com SpEL/SSTI. https://github.com/(veja topic vulnerable-app)
- Análises Spring4Shell (Securelist/JFrog) — base da explicação da Variante de data binding.
  https://securelist.com/spring4shell-cve-2022-22965/106239/

## 6. Defesa em profundidade
1. **Não avaliar entrada** como expressão (a regra principal).
2. Se precisar avaliar: **`SimpleEvaluationContext`** (sem `T()`/construtores) e allowlist de variáveis.
3. Manter o Spring **atualizado** (Spring4Shell e CVE-2026-59283 são correções de versão).
4. Em templates, usar apenas variáveis pré-computadas; nunca renderizar template vindo do usuário.
5. Menor privilégio + egress filtering reduzem o impacto de um RCE.

## 7. Como testar/detectar
- Enviar `7*7` e ver se volta `49`; `${7*7}`/`#{7*7}` em campos que alimentam templates.
- SAST para `parseExpression(<input>)` e `StandardEvaluationContext` sobre dados do usuário.
- Testes: `src/test/java/com/arthur/security/attacks/spel/*`.

## 8. Leitura adicional
- OWASP SSTI: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection
- PortSwigger — SSTI: https://portswigger.net/web-security/server-side-template-injection
- Spring Expression: https://docs.spring.io/spring-framework/reference/core/expressions.html
- CWE-917: https://cwe.mitre.org/data/definitions/917.html

## 9. Trilhas de aprendizado (conhecimentos que levam a outros)
- **Pré-requisitos:** avaliação de expressões/templates; reflexão em Java.
- **Conecta com:** [#17 command injection](../17-command-injection/DEEP-DIVE.md) e [#08 SQLi](../08-sql-injection/DEEP-DIVE.md) (injeção), [#09 mass assignment](../09-mass-assignment/DEEP-DIVE.md) (Spring4Shell/data binding), [#19 deserialização](../19-insecure-deserialization/DEEP-DIVE.md).
- **Conceitos rodáveis:** — (foco em não avaliar input / `SimpleEvaluationContext`).
- **Aprofundar:** PortSwigger SSTI · Spring4Shell (CVE-2022-22965) · docs SpEL.
