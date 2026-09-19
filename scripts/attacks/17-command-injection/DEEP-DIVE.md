# OS Command Injection — dissecação completa (CWE-78 · OWASP A03:2021 Injection)

> Código: [`CommandInjectionDemo.java`](CommandInjectionDemo.java) · payloads: [`payloads.txt`](payloads.txt)

## 1. Para leigos
O servidor "conversa" com o sistema operacional montando uma frase de comando e mandando executar. Se
ele cola o que você digitou nessa frase, você escreve o endereço, um ponto-e-vírgula e um SEGUNDO
comando — e o sistema obedece aos dois. Vira controle total da máquina.

## 2. Como funciona tecnicamente
O perigo é o **shell** (`sh -c "..."`): ele interpreta metacaracteres (`;`, `|`, `&&`, `` ` ``, `$()`).
A regra de ouro tem duas partes: (1) **nunca** montar uma linha de comando com entrada do usuário — use
uma **lista de argumentos** (`ProcessBuilder("ping","-c","1",host)`), assim nenhum shell parseia o texto;
(2) **allowlist** estrita do valor. Blacklist de caracteres perde (há `${IFS}`, encodings, `|`, `\n`).

## 3. Variantes/técnicas (rodam no `.java`)
1. **Separador `;`** — encerra um comando e inicia outro.
2. **Substituição `$(...)` / crase** — executa e injeta a saída.
3. **Pipe `|` / `&&` / `||`** — encadeia programas.
4. **Blind por tempo** — sem saída visível, injeta `sleep`/`ping -c` e mede o atraso.
5. **Bypass de blacklist** — filtro que remove só `;` é driblado com `|`, `${IFS}`, nova linha.

## 4. Casos reais
- **Shellshock — CVE-2014-6271 (2014):** bug no Bash permitia injeção de comando via variáveis de
  ambiente em CGIs; exploração em massa na internet. https://nvd.nist.gov/vuln/detail/CVE-2014-6271
- Injeção de comando é sink recorrente em **roteadores/appliances/câmeras** (interfaces que chamam
  `ping`/`traceroute` com o host do usuário) — dezenas de CVEs por ano na CISA KEV.
- **2026:** injeção segue no topo das ameaças de aplicação; panorama recente:
  https://www.cryptus.in/hackingnews/10-most-dangerous-injection-attacks-in-2026/

## 5. Trechos de repositórios (reimplementados, com crédito)
- **OWASP WebGoat** — lição de command injection com o mesmo padrão `Runtime.exec("sh -c " + input)`.
  https://github.com/WebGoat/WebGoat
- **PayloadsAllTheThings** — Command Injection: fonte dos payloads de `${IFS}`, `$()`, `|`.
  https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection

## 6. Defesa em profundidade
1. **Não chamar o shell**: `ProcessBuilder` com lista de argumentos (sem `sh -c`).
2. **Allowlist** estrita do valor (ex.: host = `^[a-zA-Z0-9.-]+$`).
3. Preferir **APIs nativas** (ex.: `InetAddress.isReachable`) a chamar binários externos.
4. **Menor privilégio** do processo; sandbox/seccomp.
5. Validação/normalização como reforço — nunca como defesa única.

## 7. Como testar/detectar
- Injetar `; id`, `| id`, `$(id)`, `` `id` ``; para blind, `; sleep 5` e medir o tempo.
- SAST para `Runtime.exec`/`ProcessBuilder("sh","-c",...)`; DAST (ZAP) para o endpoint.
- Testes: `src/test/java/com/arthur/security/attacks/commandinjection/*`.

## 8. Leitura adicional
- OWASP OS Command Injection Defense: https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html
- PortSwigger — OS command injection: https://portswigger.net/web-security/os-command-injection
- CWE-78: https://cwe.mitre.org/data/definitions/78.html

## 9. Trilhas de aprendizado (conhecimentos que levam a outros)
- **Pré-requisitos:** shell e metacaracteres; `ProcessBuilder` vs `sh -c`.
- **Conecta com:** [#08 SQLi](../08-sql-injection/DEEP-DIVE.md), [#18 SpEL](../18-spel-injection/DEEP-DIVE.md), [#25 XPath](../25-xpath-injection/DEEP-DIVE.md) (família injeção), [#19 deserialização](../19-insecure-deserialization/DEEP-DIVE.md) (RCE).
- **Conceitos rodáveis:** — (foco em lista de argumentos + allowlist).
- **Aprofundar:** OWASP OS Command Injection Defense · PortSwigger · MITRE ATT&CK T1059.
