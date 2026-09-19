# SSRF — Server-Side Request Forgery — dissecação completa (CWE-918 · OWASP A10:2021)

> Código: [`SsrfDemo.java`](SsrfDemo.java) · payloads: [`payloads.txt`](payloads.txt)

## 1. Para leigos
Alguns recursos pedem ao servidor "busque esta URL para mim" (prévia de link, importar de um endereço,
webhook). Como quem faz o pedido é o SERVIDOR — de dentro da rede — o atacante aponta a URL para lugares
que ele não alcança de fora: painéis internos, bancos de dados, e o endpoint de metadados da nuvem
(`169.254.169.254`), que guarda credenciais.

## 2. Como funciona tecnicamente
O servidor vira um **proxy involuntário**. Vetores: `file://` (leitura de arquivo), `http://interno`,
**IMDS** da nuvem, **DNS rebinding** (um nome permitido resolve para IP interno) e **redirect** (um host
permitido responde `302` para o interno). Defesa (todas juntas): **allowlist de esquema** (http/https),
**allowlist de host**, **revalidar o ENDEREÇO resolvido** (rejeitar loopback/link-local/privado) e
**não seguir redirecionamentos** (ou revalidar cada hop).

## 3. Variantes/técnicas (rodam no `.java`)
1. **`file://`** — leitura arbitrária de arquivo.
2. **Serviço interno / IMDS** — alcança `127.0.0.1`/`169.254.169.254` (o `.java` usa loopback).
3. **DNS rebinding** — nome permitido resolve para endereço interno; a checagem pós-DNS barra.
4. **Bypass por redirect** — host permitido → `302` → interno; desabilitar redirects barra.

## 4. Casos reais
- **Capital One (2019):** SSRF num WAF alcançou o **IMDS** (`169.254.169.254`), pegou credenciais IAM e
  exfiltrou **~106 milhões** de registros de S3. A AWS respondeu com **IMDSv2** (exige token).
  https://dev.to/roxdavirox/capital-one-2019-ssrf-aws-imds-and-106-million-exposed-records-4ha6
- **ProxyLogon — CVE-2021-26855 (MS Exchange):** SSRF como porta de entrada para RCE.
- **Recente (2026):** **Angular SSR — CVE-2026-27739** (validação de header → SSRF/leak de metadata);
  **Spring Authorization Server — CVE-2026-22752** (`logo_uri`/`policy_uri` forçam requisições internas).

## 5. Trechos de repositórios (reimplementados, com crédito)
- **OWASP SSRF Prevention Cheat Sheet** — as 4 guardas do `.java`.
  https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- **JoyChou93/java-sec-code** — `SSRF.java` (mesmos vetores). https://github.com/JoyChou93/java-sec-code
- No app: `src/main/java/com/arthur/security/net/UrlFetchService.java`.

## 6. Defesa em profundidade
1. **Allowlist de esquema e host**; nunca blocklist.
2. **Revalidar o endereço resolvido** (pós-DNS) — bloqueia rebinding e IPs internos.
3. **Não seguir redirects** (ou revalidar cada hop).
4. **Egress filtering** de rede; **IMDSv2** na nuvem; sem credenciais amplas na instância.
5. Timeouts curtos; não devolver o corpo bruto (reduz blind/exfiltração).

## 7. Como testar/detectar
- Testar `file://`, `http://127.0.0.1`, `http://169.254.169.254/`, nomes que rebindam, e redirects.
- Ferramentas: Burp Collaborator (blind SSRF), SSRFmap.
- Testes: `src/test/java/com/arthur/security/attacks/ssrf/*`.

## 8. Leitura adicional
- OWASP SSRF Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- PortSwigger SSRF: https://portswigger.net/web-security/ssrf
- CWE-918: https://cwe.mitre.org/data/definitions/918.html

## 9. Trilhas de aprendizado (conhecimentos que levam a outros)
- **Pré-requisitos:** HTTP, DNS, URLs, redes internas/IMDS.
- **Conecta com:** [#15 XXE](../15-xxe/DEEP-DIVE.md) (XXE→SSRF), [#11 open redirect](../11-open-redirect/DEEP-DIVE.md) (bypass por redirect), [#10 path traversal](../10-path-traversal/DEEP-DIVE.md) (`file://`).
- **Conceitos rodáveis:** — (foco em allowlist + checagem do IP resolvido).
- **Aprofundar:** OWASP SSRF Prevention · PortSwigger SSRF · Capital One (IMDSv2).
