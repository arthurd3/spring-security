# CSRF — Cross-Site Request Forgery — dissecação completa (CWE-352 · OWASP A01:2021)

> Código: [`CsrfDemo.java`](CsrfDemo.java) · payloads: [`payloads.txt`](payloads.txt)

## 1. Para leigos
Você está logado no banco. Em outra aba, um site qualquer dispara, escondido, uma transferência para o
banco. Como o navegador anexa AUTOMATICAMENTE o cookie de sessão, o pedido chega "assinado como você" —
e o banco obedece. Você nem clicou de propósito.

## 2. Como funciona tecnicamente
CSRF abusa do **envio automático de cookies** pelo navegador. Defesas: **synchronizer token** (valor
secreto por sessão embutido no formulário; o site atacante não o conhece), **double-submit cookie**
(cookie == header/campo, comparados no servidor), e **`SameSite`** (o navegador não anexa o cookie em
requisições cross-site com `Lax`/`Strict`). Detalhes que importam: **GET não deve mudar estado**;
requisições "simples" (`text/plain`) **evitam o preflight** do CORS, então não conte com CORS para CSRF;
e o **login** também precisa de token (login CSRF). APIs com token no header `Authorization` são imunes
(o navegador não o anexa sozinho).

## 3. Variantes/técnicas (rodam no `.java`)
1. **GET muda estado** — um `<img src>` já forja.
2. **POST sem token** — aceito sem synchronizer token.
3. **"Simple request"** (`text/plain`) — evita preflight; não confie no CORS.
4. **Double-submit cookie** — cookie deve casar com o header.
5. **`SameSite`** — cookie não vai cross-site com Lax/Strict.
6. **Login CSRF** — forçar login na conta do atacante.

## 4. Casos reais
- CSRF foi endêmico nos anos 2000–2010 (routers, webmail, admin panels). Hoje **`SameSite=Lax` por
  padrão** nos navegadores modernos reduz muito o vetor — mas **não elimina** (POSTs same-site, `None`,
  GET-state, e navegadores antigos).
- Bug bounties ainda encontram CSRF onde o token falta e o `SameSite` está `None`.

## 5. Trechos de repositórios (reimplementados, com crédito)
- **OWASP CSRF Prevention Cheat Sheet** — synchronizer/double-submit/SameSite (base do `.java`).
  https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- **Spring Security** — token CSRF por padrão na cadeia de sessão. https://docs.spring.io/spring-security/reference/servlet/exploits/csrf.html
- No app: `src/main/java/com/arthur/security/config/WebSecurityConfig.java`.

## 6. Defesa em profundidade
1. **Synchronizer token** em toda ação que muda estado (o Spring faz por padrão em apps de sessão).
2. **`SameSite=Lax/Strict`** + `Secure` + `HttpOnly` nos cookies.
3. **GET idempotente**; mudanças só via POST/PUT/DELETE.
4. Para APIs stateless: credencial no header `Authorization` (não em cookie) → sem CSRF; se usar cookie,
   manter o token.
5. Token também no **login** (login CSRF); revalidar em ações sensíveis.

## 7. Como testar/detectar
- Remover o token e reenviar; testar GET-state; `SameSite` dos cookies; enctype `text/plain`.
- Testes: `src/test/java/com/arthur/security/attacks/csrf/*`.

## 8. Leitura adicional
- OWASP CSRF Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- Spring Security CSRF: https://docs.spring.io/spring-security/reference/servlet/exploits/csrf.html
- CWE-352: https://cwe.mitre.org/data/definitions/352.html
