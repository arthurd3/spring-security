# 🧪 Laboratório de ataques — o código está aqui, dissecado ao máximo

Uma pasta por ataque. Cada pasta é um **mini-curso executável**, com quatro artefatos:

```
scripts/attacks/08-sql-injection/
├── 08-sql-injection.sh     # explica em 3 niveis, MOSTRA o codigo e o EXECUTA
├── SqlInjectionDemo.java   # VARIAS variantes reais (vulneravel + seguro + atacante), tudo rodando
├── DEEP-DIVE.md            # teoria em camadas + CVEs/incidentes reais (com links) + defesa em profundidade
└── payloads.txt            # cheatsheet de payloads reais + efeito + mitigacao
```

- O `.java` traz **várias técnicas por ataque** (ex.: SQLi = tautologia, UNION, blind booleano,
  second-order, ORDER BY), cada uma com a versão **VULNERÁVEL** 🔴 e a **SEGURA** 🟢, executando de
  verdade e imprimindo o resultado.
- O `DEEP-DIVE.md` vai **do "para leigos" ao avançado**: como funciona, cada variante, **casos reais
  (clássicos e de 2025–2026)** com links, trechos de repositórios reimplementados (OWASP WebGoat,
  java-sec-code, PayloadsAllTheThings, ysoserial…), defesa em camadas, como testar e leitura adicional.
- O `payloads.txt` é um cheatsheet real (com aviso de uso autorizado).

Nada de servidor: cada demo compila e roda o próprio `.java`.

---

## Como usar

```bash
# um ataque (explica + mostra + roda + aponta o deep-dive):
scripts/attacks/08-sql-injection/08-sql-injection.sh

# todos, em sequencia (ENTER avanca; --no-pause vai direto):
scripts/run-all.sh
scripts/run-all.sh --no-pause

# so o codigo, sem o wrapper:
java scripts/attacks/17-command-injection/CommandInjectionDemo.java

# ler o aprofundamento de um ataque:
less scripts/attacks/19-insecure-deserialization/DEEP-DIVE.md
```

Sem cores: `NO_COLOR=1 scripts/attacks/08-sql-injection/08-sql-injection.sh`.

---

## Requisitos

- **JDK 17+** (`java`). Os demos usam o modo "single-file source" (`java Arquivo.java`).
- A maioria é **JDK puro**; alguns usam bibliotecas reais do projeto: `05` BCrypt, `08` H2, `09`/`12`
  Jackson, `14` BCrypt, `18` Spring Expression, `19` Jackson. Elas vêm de `scripts/lib/classpath.txt`
  (gere/atualize com `scripts/build-classpath.sh`); o `run_demo` usa esse classpath quando existe.
- Nada é instalado nem alterado no sistema (os demos que tocam arquivos usam apenas `/tmp`).

Se um exploit com biblioteca reclamar de classe faltando: `scripts/build-classpath.sh`.

---

## Política de citação e segurança

- **Reimplementado, não copiado**: cada demo traz o **padrão real** (o mesmo bug/técnica de CVEs e repos
  como WebGoat/java-sec-code/PayloadsAllTheThings), reescrito para rodar aqui, com **crédito/link** à
  fonte no `.java` e no `DEEP-DIVE.md`.
- **Sem armas reais**: nenhum payload de RCE contra terceiros, gadget chain weaponizada, JNDI de
  Log4Shell ou webshell. Demonstramos o **mecanismo** localmente (arquivo temporário, efeito em memória,
  medição de tempo, loopback) e **explicamos** a weaponização real em prosa + links.
- `payloads.txt` traz aviso: uso **somente** em sistemas próprios ou com autorização.

---

## Os 26 ataques

| # | Pasta | Ataque | Variantes no `.java` |
|---|-------|--------|----------------------|
| 01 | `01-access-control-idor` | IDOR / BOLA | horizontal, vertical, enumeração, aninhado |
| 02 | `02-csrf` | CSRF | GET-state, POST sem token, simple-request, double-submit, SameSite, login-CSRF |
| 03 | `03-session-fixation` | Session Fixation | sem rotação, aceitar id do cliente, sem invalidação |
| 04 | `04-brute-force` | Brute Force | vertical, spraying, credential stuffing |
| 05 | `05-password-storage` | Armazenamento de senha | plaintext, MD5/SHA sem sal, SHA+sal, BCrypt, pepper |
| 06 | `06-jwt` | JWT | alg=none, segredo fraco, sem exp, confusão RS256→HS256 |
| 07 | `07-xss-headers` | XSS + headers | refletido, armazenado, atributo, JS, CSP/nosniff |
| 08 | `08-sql-injection` | SQL Injection | tautologia, UNION, blind, second-order, ORDER BY |
| 09 | `09-mass-assignment` | Mass Assignment | role, isAdmin, price, rejeição estrita |
| 10 | `10-path-traversal` | Path Traversal | `../`, encoded, absoluto, Zip Slip |
| 11 | `11-open-redirect` | Open Redirect | absoluto, `//`, `\`, userinfo `@`, subdomínio |
| 12 | `12-data-exposure` | Exposição de dados | entidade, erro verboso, campos excessivos, PII, actuator |
| 13 | `13-cors` | CORS | reflect+creds, null, regex frouxa, Origin p/ auth |
| 14 | `14-user-enumeration` | Enumeração | mensagem, **timing**, cadastro, reset |
| 15 | `15-xxe` | XXE | file read, SSRF-via-XXE, billion laughs |
| 16 | `16-ssrf` | SSRF | file, IMDS, DNS rebinding, redirect |
| 17 | `17-command-injection` | Command Injection | `;`, `$()`, `\|`, blind, bypass de blacklist |
| 18 | `18-spel-injection` | SpEL / SSTI | eval, `T()`, RCE, bypass |
| 19 | `19-insecure-deserialization` | Desserialização | readObject nativo, ObjectInputFilter, Jackson polimórfico |
| 20 | `20-redos` | ReDoS | `(.*a){20}`, `(.*@){12}`, dependência do motor, mitigação |
| 21 | `21-file-upload` | Upload | extensão, dupla extensão, content-type spoof, path |
| 22 | `22-host-header-injection` | Host Header | reset poisoning, XFH, cache poisoning, roteamento |
| 23 | `23-crlf-log-injection` | CRLF / Log | log forging, response splitting, controles |
| 24 | `24-insecure-randomness` | Aleatoriedade | semente conhecida, brute force do tempo, UUID, entropia |
| 25 | `25-xpath-injection` | XPath | tautologia, blind, union/dump |
| 26 | `26-rate-limiting` | Rate Limiting | sem limite, bypass XFF, janela fixa vs deslizante, token bucket |

Cada demo espelha a defesa real da aplicação (o `.sh`/`DEEP-DIVE.md` aponta o arquivo equivalente em
`src/main/...`). Os mesmos ataques têm **testes JUnit** (`./mvnw test`, 100 testes) contra a app real.

## Estrutura

```
scripts/
├── run-all.sh                 # roda os 26 em sequencia
├── build-classpath.sh         # (re)gera o classpath para os exploits que usam libs reais
├── lib/
│   ├── common.sh              # cores, layout, show_code, run_demo, level, doc_pointer
│   └── classpath.txt          # classpath do projeto (gerado)
└── attacks/<nn-nome>/         # 4 artefatos por ataque (.sh, *Demo.java, DEEP-DIVE.md, payloads.txt)
```
