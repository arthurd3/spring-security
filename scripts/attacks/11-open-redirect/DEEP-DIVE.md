# Open Redirect — dissecação completa (CWE-601)

> Código: [`OpenRedirectDemo.java`](OpenRedirectDemo.java) · payloads: [`payloads.txt`](payloads.txt)

## 1. Para leigos
Muitos sites têm um "voltar para onde você estava" que recebe o destino pela URL. Se o site redireciona
para QUALQUER endereço, o atacante monta um link que começa no domínio confiável e joga a vítima no site
dele — ótimo para phishing, porque o começo do link parece legítimo.

## 2. Como funciona tecnicamente
O erro é confiar no destino sem validar. Checagens ingênuas falham: `startsWith("/")` deixa passar
`//evil` (protocolo-relativo, que o navegador lê como absoluto) e `/\evil`; `contains("trusted.com")`
deixa passar `trusted.com.evil.com` e `https://trusted.com@evil.com` (userinfo). A correção robusta:
aceitar **caminho relativo** (uma única `/`, nunca `//`) OU uma URL cujo **host parseado** esteja numa
**allowlist** — comparando o host de uma `URI`, nunca `startsWith`/`contains` na string crua.

## 3. Variantes/técnicas (rodam no `.java`)
1. **Absoluto off-site** — `https://evil/login`.
2. **Protocolo-relativo** — `//evil` (navegador trata como absoluto).
3. **Backslash** — `/\evil` (navegador normaliza `\`→`/`).
4. **userinfo `@`** — `https://trusted.com@evil` (host real é `evil`).
5. **Subdomínio** — `trusted.com.evil` (contém "trusted.com", mas host é `evil`).

## 4. Casos reais
- **OAuth `redirect_uri`** frouxo é um clássico: leva à exfiltração de `code`/token (account takeover).
- Open redirect é degrau comum em cadeias de phishing e em bypass de SSRF/filtros.
- Aparece com frequência em programas de bug bounty (o `next=`/`returnUrl=` de sempre).

## 5. Trechos de repositórios (reimplementados, com crédito)
- **PortSwigger** e **PayloadsAllTheThings — Open Redirect** — fonte dos bypasses (`//`, `@`, `\`).
  https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect
- No app: `src/main/java/com/arthur/security/web/SafeRedirectController.java`.

## 6. Defesa em profundidade
1. **Não redirecionar para URL do usuário**; usar um mapa de destinos (id → URL fixa).
2. Se precisar: **caminho relativo** (uma `/`) ou **allowlist de host parseado** (nunca string crua).
3. Normalizar `\`→`/`; rejeitar `//`, control chars, esquemas não-http(s), `javascript:`/`data:`.
4. Em OAuth, **casar `redirect_uri` exatamente** com o registrado.
5. Página intersticial ("você está saindo do site") para redirects externos legítimos.

## 7. Como testar/detectar
- Testar `//evil`, `/\evil`, `https://trusted@evil`, `https://trusted.evil`, `javascript:`.
- Revisar parâmetros `next/url/returnUrl/redirect/dest`.
- Testes: `src/test/java/com/arthur/security/attacks/openredirect/*`.

## 8. Leitura adicional
- OWASP Unvalidated Redirects: https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
- PortSwigger (SSRF/redirect filters): https://portswigger.net/web-security/ssrf
- CWE-601: https://cwe.mitre.org/data/definitions/601.html
