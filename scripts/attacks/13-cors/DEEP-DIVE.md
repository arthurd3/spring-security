# CORS Misconfiguration — dissecação completa (CWE-942 · OWASP A05:2021)

> Código: [`CorsDemo.java`](CorsDemo.java) · payloads: [`payloads.txt`](payloads.txt)

## 1. Para leigos
O navegador impede o site A de LER as respostas do site B (same-origin). O CORS abre exceções. Se o
servidor, por descuido, responde "qualquer site pode me ler" E "pode mandar os cookies junto", a página
do atacante consegue ler os dados autenticados da vítima.

## 2. Como funciona tecnicamente
`Access-Control-Allow-Origin` (ACAO) diz **qual** origem pode ler a resposta. **Refletir** a origem
recebida = liberar todas. Combinar com `Access-Control-Allow-Credentials: true` permite leitura
**autenticada** cross-site. A spec proíbe `*` **com** credenciais — por isso o erro comum é **refletir**
a origem. Outros erros: aceitar **`null`** (forjável por iframe sandbox/redirect) e **match ingênuo**
(`startsWith`/`endsWith`) que aceita `nottrusted.com` ou `app.trusted.com.evil.com`. E lembrar: **CORS
não é autorização** — ele controla leitura no navegador; a autorização real é sessão/token no servidor.

## 3. Variantes/técnicas (rodam no `.java`)
1. **Refletir origin + credenciais** — leitura autenticada por qualquer site.
2. **`null` permitido** — forjável via iframe sandbox/redirect.
3. **Bypass de regex** — `startsWith`/`endsWith` aceitam domínios do atacante.
4. **Confiar no Origin para autorizar** — `Origin` é spoofável fora do navegador (curl).

## 4. Casos reais
- CORS mal configurado (reflexão + credenciais) rendeu muitos bug bounties (leitura de dados de conta).
- **PortSwigger** documenta os labs de origem refletida, `null` e trust de subdomínio.
  https://portswigger.net/web-security/cors
- **OWASP Top 10:2025** — Security Misconfiguration segue relevante. https://owasp.org/Top10/2025/

## 5. Trechos de repositórios (reimplementados, com crédito)
- **PortSwigger CORS** — origem refletida, `null`, e trust por sufixo (base das variantes).
  https://portswigger.net/web-security/cors
- No app: allowlist explícita em `src/main/java/com/arthur/security/config/ApiSecurityConfig.java`.

## 6. Defesa em profundidade
1. **Allowlist exata** de origens; **nunca refletir** a origem recebida.
2. **Nunca** aceitar `null`; **nunca** `*` com credenciais.
3. Comparar a origem por **igualdade exata** (não `startsWith`/`endsWith`/regex frouxa).
4. Restringir métodos/headers permitidos; `Vary: Origin` para o cache.
5. Lembrar que **CORS ≠ autorização**: manter authn/z no servidor (sessão/token).

## 7. Como testar/detectar
- Enviar `Origin: https://evil.example` e ver se volta em `ACAO` (+ `ACAC:true`); testar `null` e
  variações de subdomínio.
- Ferramentas: Burp, CORScanner.
- Testes: `src/test/java/com/arthur/security/attacks/cors/*`.

## 8. Leitura adicional
- PortSwigger CORS: https://portswigger.net/web-security/cors
- MDN CORS: https://developer.mozilla.org/docs/Web/HTTP/CORS
- CWE-942: https://cwe.mitre.org/data/definitions/942.html

## 9. Trilhas de aprendizado (conhecimentos que levam a outros)
- **Pré-requisitos:** same-origin policy, preflight, headers CORS.
- **Conecta com:** [#02 CSRF](../02-csrf/DEEP-DIVE.md) (CORS ≠ CSRF ≠ autorização), [#16 SSRF](../16-ssrf/DEEP-DIVE.md), [#07 XSS](../07-xss-headers/DEEP-DIVE.md).
- **Conceitos rodáveis:** — (foco em allowlist exata de origem).
- **Aprofundar:** PortSwigger CORS · MDN CORS · OWASP HTML5 Security.
