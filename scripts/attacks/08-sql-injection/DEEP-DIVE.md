# SQL Injection — dissecação completa (CWE-89 · OWASP A03:2021 Injection)

> Código executável: [`SqlInjectionDemo.java`](SqlInjectionDemo.java) · payloads: [`payloads.txt`](payloads.txt)
> Rode: `scripts/attacks/08-sql-injection/08-sql-injection.sh`

## 1. Para leigos
O site conversa com o banco de dados usando frases (SQL). Ele monta a frase juntando um texto fixo com
o que você digitou. Se ele só **cola** o que você digitou, você pode escrever não um "nome", mas um
**pedaço de frase**. Com aspas e um truque, "me traga a conta do fulano" vira "me traga TODAS as contas",
ou "me deixe entrar sem senha", ou "me diga a senha do admin, letra por letra".

## 2. Como funciona tecnicamente
Uma consulta tem **estrutura** (`SELECT ... FROM ... WHERE ...`) e **dados** (o valor procurado).
Concatenar o dado dentro do texto faz o banco não distinguir mais um do outro: uma aspa simples fecha o
literal de string e tudo depois é **interpretado como SQL**. A correção real é **separar estrutura de
dados**: um *prepared statement* envia a consulta com um marcador `?` e o valor por um canal à parte —
o banco já compilou a estrutura e o valor jamais vira comando. Escapar aspas **não** é a solução (varia
por banco e por contexto: string, número, identificador, LIKE, ORDER BY...).

## 3. Variantes/técnicas (cada uma roda no `.java`)
1. **Tautologia** `' OR '1'='1` — condição sempre-verdadeira: dump total ou bypass de login.
2. **UNION SELECT** — anexa uma segunda consulta e rouba dados de **outra** tabela (ex.: `users.password`).
   Requer o mesmo número/tipos de colunas; o atacante ajusta com `NULL`s.
3. **Blind booleano** — a app só mostra "existe/não existe"; com `SUBSTRING(...)='a'` o atacante
   **infere a senha caractere por caractere** (o `.java` reconstrói `S3cr3t`).
4. **Blind por tempo** — quando nem true/false aparece: injeta `SLEEP(5)`/`pg_sleep(5)` e mede o tempo
   de resposta (o H2 do lab não tem `SLEEP`, então aqui demonstramos o blind **booleano**; o princípio
   por tempo está no `payloads.txt`).
5. **Error-based** — força o banco a revelar dados dentro de mensagens de erro verbosas.
6. **Second-order** — o payload é **gravado** por um insert seguro e dispara **depois**, quando outra
   funcionalidade concatena esse valor "confiável" em SQL cru.
7. **ORDER BY / identificador** — nome de coluna **não** aceita bind param; sink clássico. Defesa é
   **allowlist** de colunas (nunca concatenar).

## 4. Casos reais
- **MOVEit Transfer — CVE-2023-34362 (2023):** SQLi explorada pelo grupo Clop; vazou dados de centenas
  de organizações (BBC, British Airways, Dept. de Energia dos EUA). https://nvd.nist.gov/vuln/detail/CVE-2023-34362
- **Fortinet FortiClient EMS — CVE-2023-48788 (2024, CVSS 9.3):** SQLi não autenticada → execução remota
  de código. https://nvd.nist.gov/vuln/detail/CVE-2023-48788
- **Recente (2026):** WordPress core **CVE-2026-60137** (author__not_in → SQLi → RCE em cadeia);
  **Kestra** (orquestrador) SQLi autenticada escalando para RCE; **OpenProject** com vetor SQLi não
  autenticado. Veja o resumo da CISA/CVE do período. https://www.cvedetails.com/vulnerability-list/opsqli-1/sql-injection.html
- Verizon DBIR 2024: ataques a aplicações web (SQLi incluído) foram ~26% das violações.

## 5. Trechos de repositórios (reimplementados, com crédito)
- **OWASP WebGoat** — lições `SqlInjection` mostram o mesmo `Statement` concatenado que reescrevemos
  na Variante 1/2. https://github.com/WebGoat/WebGoat
- **JoyChou93/java-sec-code** — `SQLI.java` contrasta `Statement` vulnerável com `PreparedStatement`
  seguro; nossa Variante 1 segue esse padrão. https://github.com/JoyChou93/java-sec-code
- **PayloadsAllTheThings** — coleção de payloads UNION/blind que resumimos no `payloads.txt`.
  https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection
- **sqlmap** — a lógica de blind booleano/por tempo que a Variante 3 imita. https://github.com/sqlmapproject/sqlmap

## 6. Defesa em profundidade (camadas)
1. **Prepared statements / bind parameters** sempre (a correção real). No Spring Data, *derived queries*
   e `@Query` com parâmetros nomeados já fazem isso — veja `src/main/java/com/arthur/security/account/AccountService.java`.
2. **Allowlist** para partes que não aceitam bind (nomes de coluna/tabela em ORDER BY).
3. **ORM/consultas parametrizadas** em vez de SQL cru; se usar `JdbcTemplate`, sempre com `?`.
4. **Menor privilégio** do usuário do banco (sem DROP/DDL para a conta da aplicação).
5. **Validação de entrada** como reforço (nunca como defesa principal).
6. **WAF** e monitoramento como rede de contenção — não substituem parametrização.

## 7. Como testar/detectar
- Enviar `'` e observar erro 500 / mudança de comportamento; `' OR '1'='1` e `' AND '1'='2`.
- Ferramentas: **sqlmap** (`--batch --risk 3 --level 5`), scanners SAST/DAST, OWASP ZAP.
- Testes automatizados: ver `src/test/java/com/arthur/security/attacks/sqli/*` (roda no `./mvnw test`).

## 8. Leitura adicional
- OWASP SQL Injection Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- OWASP Injection: https://owasp.org/www-community/attacks/SQL_Injection
- PortSwigger Web Security Academy — SQL injection: https://portswigger.net/web-security/sql-injection
- CWE-89: https://cwe.mitre.org/data/definitions/89.html

## 9. Trilhas de aprendizado (conhecimentos que levam a outros)
- **Pré-requisitos:** SQL básico; diferença entre estrutura da query e dados.
- **Conecta com:** [#25 XPath](../25-xpath-injection/DEEP-DIVE.md), [#17 command injection](../17-command-injection/DEEP-DIVE.md), [#18 SpEL](../18-spel-injection/DEEP-DIVE.md) (mesma raiz: dado virando código), [#12 data exposure](../12-data-exposure/DEEP-DIVE.md).
- **Conceitos rodáveis:** — (foco em prepared statements/allowlist).
- **Aprofundar:** OWASP SQL Injection Prevention · PortSwigger SQLi · Bobby Tables.
