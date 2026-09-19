# Username Enumeration — dissecação completa (CWE-204 · OWASP A07:2021)

> Código: [`UserEnumerationDemo.java`](UserEnumerationDemo.java) · notas: [`payloads.txt`](payloads.txt)

## 1. Para leigos
Quando o login responde de formas DIFERENTES para "usuário não existe" e "senha errada", ele vira um
consultor grátis de quem tem conta ali. O atacante testa uma lista de e-mails e separa os que existem —
essa lista de contas confirmadas alimenta ataques de senha e phishing dirigido.

## 2. Como funciona tecnicamente
Qualquer diferença observável é um **oráculo**: mensagem, status HTTP, tamanho da resposta, e — o mais
sutil — **tempo**. Se o caminho "usuário existe" roda o hash de senha (lento) e "não existe" retorna na
hora, o atacante mede o atraso e enumera contas mesmo com mensagens iguais. Defesa: **respostas
uniformes** e **tempo constante** (rodar o hash mesmo para usuário inexistente, contra um hash dummy).

## 3. Variantes/técnicas (rodam no `.java`)
1. **Mensagem** — 404 "no account" vs 401 "wrong password".
2. **Tempo** — inexistente rápido vs existente lento (o `.java` mede o gap com BCrypt).
3. **Cadastro** — "e-mail já registrado".
4. **Recuperação de senha** — "no such user" vs "reset enviado".

## 4. Casos reais
- Enumeração é achado recorrente em bug bounties (login, registro, reset, 2FA), muitas vezes por **timing**.
- **OWASP WSTG 4.3.4** dedica um teste específico a enumeração de contas.
  https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account

## 5. Trechos de repositórios (reimplementados, com crédito)
- **OWASP Authentication Cheat Sheet** — respostas genéricas e mitigação de timing (base do `.java`).
  https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- No app: `DaoAuthenticationProvider` usa `hideUserNotFoundExceptions` e roda o encoder contra um usuário
  dummy — ver `src/main/java/com/arthur/security/user/JpaUserDetailsService.java`.

## 6. Defesa em profundidade
1. **Mensagens/status idênticos** para todas as falhas de login/registro/reset.
2. **Tempo constante**: sempre executar o hash (contra dummy) para o caminho "usuário inexistente".
3. Respostas genéricas em registro/reset ("se o e-mail existir, enviamos…").
4. **Rate limit/CAPTCHA** para dificultar a varredura (ver ataque 26).
5. `server.error.include-message=never` para não vazar detalhe no corpo.

## 7. Como testar/detectar
- Comparar status/corpo/tamanho entre user existente e inexistente; medir tempos (estatística).
- Ferramentas: Burp Intruder (compare responses), scripts de timing.
- Testes: `src/test/java/com/arthur/security/attacks/enumeration/*`.

## 8. Leitura adicional
- OWASP WSTG Account Enumeration (link acima)
- OWASP Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- CWE-204: https://cwe.mitre.org/data/definitions/204.html

## 9. Trilhas de aprendizado (conhecimentos que levam a outros)
- **Pré-requisitos:** respostas HTTP (status/corpo/tamanho) e noção de timing.
- **Conecta com:** [#04 brute force](../04-brute-force/DEEP-DIVE.md) (usuários válidos turbinam spraying), [#26 rate limiting](../26-rate-limiting/DEEP-DIVE.md), [#06 jwt](../06-jwt/DEEP-DIVE.md) (timing na verificação).
- **Conceitos rodáveis:** `scripts/concepts/constant-time-compare` (fechar o canal de timing).
- **Aprofundar:** OWASP WSTG (Account Enumeration) · OWASP Authentication Cheat Sheet.
