# Host Header Injection — dissecação completa (CWE-644)

> Código: [`HostHeaderDemo.java`](HostHeaderDemo.java) · payloads: [`payloads.txt`](payloads.txt)

## 1. Para leigos
Todo pedido HTTP traz um cabeçalho `Host` dizendo qual site você quer — e ele é escolhido por QUEM FAZ o
pedido, inclusive um atacante. Se o servidor usa o `Host` para montar, por exemplo, o link de "redefinir
senha", o atacante pede a redefinição para a vítima com `Host: evil.example`. A vítima recebe um e-mail
legítimo cujo link aponta para o atacante — e, ao clicar, entrega o token.

## 2. Como funciona tecnicamente
`Host` (e `X-Forwarded-Host`) são **entrada não confiável**. Usá-los para construir URLs absolutas
(reset, e-mails, links canônicos), decidir rotas/tenant, ou refleti-los em conteúdo **cacheável** leva a:
**password-reset poisoning**, **web cache poisoning** (um atacante envenena a resposta de todos) e até
SSRF/bypass de roteamento. Correção: usar uma **base URL configurada** no servidor para tudo que é
sensível, e **validar** o `Host` contra uma allowlist de domínios conhecidos.

## 3. Variantes/técnicas (rodam no `.java`)
1. **Reset poisoning** via `Host`.
2. **Override** via `X-Forwarded-Host` (mesmo com `Host` correto).
3. **Cache poisoning** — header refletido não incluído na chave do cache.
4. **Roteamento por Host** — decidir tenant/backend a partir de valor spoofável.

## 4. Casos reais
- **Password-reset poisoning** é técnica documentada e recorrente em bug bounties (PortSwigger a cataloga).
- **Web cache poisoning** via headers não-chaveados (pesquisa de James Kettle/PortSwigger) afetou grandes
  sites. https://portswigger.net/web-security/host-header
- Frameworks passaram a exigir **allowlist de hosts** por causa disso (ex.: `ALLOWED_HOSTS` do Django).

## 5. Trechos de repositórios (reimplementados, com crédito)
- **PortSwigger — Host header attacks** — base das variantes (reset/cache/routing).
  https://portswigger.net/web-security/host-header
- No app: base URL configurada em `src/main/java/com/arthur/security/auth/PasswordResetController.java`.

## 6. Defesa em profundidade
1. **Base URL configurada** no servidor para links/e-mails/canônicos (nunca `Host`).
2. **Allowlist de hosts** válidos; rejeitar requisições com `Host` desconhecido.
3. Ignorar `X-Forwarded-*` a menos que venham de um proxy confiável (e então saneá-los).
4. **Não refletir** `Host` em conteúdo cacheável; incluir headers relevantes na **chave de cache**.
5. Tokens de reset de uso único, curta expiração e vinculados ao usuário.

## 7. Como testar/detectar
- Enviar `Host: evil` / `X-Forwarded-Host: evil` e ver se o link de reset/o conteúdo muda.
- Testar cache poisoning com headers não-chaveados (Param Miner).
- Testes: `src/test/java/com/arthur/security/attacks/hostheader/*`.

## 8. Leitura adicional
- PortSwigger Host header: https://portswigger.net/web-security/host-header
- OWASP WSTG Host Header Injection: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection
- CWE-644: https://cwe.mitre.org/data/definitions/644.html

## 9. Trilhas de aprendizado (conhecimentos que levam a outros)
- **Pré-requisitos:** headers HTTP, proxies (`X-Forwarded-*`), cache.
- **Conecta com:** [#11 open redirect](../11-open-redirect/DEEP-DIVE.md), [#16 SSRF](../16-ssrf/DEEP-DIVE.md), [#12 data exposure](../12-data-exposure/DEEP-DIVE.md) (cache poisoning).
- **Conceitos rodáveis:** — (foco em base URL configurada + allowlist de hosts).
- **Aprofundar:** PortSwigger Host header · OWASP WSTG (Host Header Injection).
