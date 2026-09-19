# Sensitive Data Exposure — dissecação completa (CWE-200 · OWASP A02:2021)

> Código: [`DataExposureDemo.java`](DataExposureDemo.java) · notas: [`payloads.txt`](payloads.txt)

## 1. Para leigos
Um endpoint devolve "o perfil". Por comodidade, retorna o REGISTRO INTEIRO do banco — e junto vai o hash
da senha, o token de reset, o CPF. Ninguém decidiu publicar isso; o conversor objeto→JSON manda todos os
campos. Erros verbosos, logs com PII e endpoints de debug expostos são a mesma família.

## 2. Como funciona tecnicamente
A raiz é **expor mais do que o necessário**: (1) serializar a **entidade** em vez de um **DTO**;
(2) **erros verbosos** com stack trace/SQL; (3) **campos excessivos** por conveniência; (4) **PII em
logs**; (5) **endpoints de debug** (`/actuator/env`, `/actuator/heapdump`), **`.git/`** ou backups
acessíveis. Correção: **DTO por caso de uso**, **erros genéricos** (com id de correlação), **mascarar
PII** e **restringir** superfícies operacionais.

## 3. Variantes/técnicas (rodam no `.java`)
1. **Entidade serializada** — vaza hash/token/SSN.
2. **Erro verboso** — stack trace, SQL, tecnologia.
3. **Campos excessivos** — over-exposure de dados internos.
4. **PII em log** — e-mail/cartão em claro.
5. **Debug/.git/actuator** — segredos e código-fonte expostos.

## 4. Casos reais
- **Optus (2022):** ~9,8M registros expostos por uma **API sem autenticação** com dados excessivos.
- **`/actuator/env` e `/.git/`** expostos são achados clássicos de recon (credenciais, código).
- **OWASP Top 10:2025** cria a categoria **"Mishandling of Exceptional Conditions"** (erros verbosos
  entram aqui) e mantém falhas criptográficas. https://owasp.org/Top10/2025/

## 5. Trechos de repositórios (reimplementados, com crédito)
- **OWASP** — Error Handling e API3 (Excessive Data Exposure) fundamentam o `.java`.
  https://owasp.org/API-Security/editions/2019/en/0xa3-excessive-data-exposure/
- No app: DTO `UserProfile` + `@JsonIgnore` na senha
  (`src/main/java/com/arthur/security/user/UserProfile.java`) e
  `server.error.include-stacktrace=never` em `application.properties`.

## 6. Defesa em profundidade
1. **DTO por endpoint** (nunca serializar a entidade); `@JsonIgnore` como rede.
2. **Erros genéricos** ao cliente + **id de correlação**; detalhes só no log interno.
3. **Mascarar PII** em logs; classificar dados sensíveis.
4. **Restringir actuator** (`management.endpoints.web.exposure.include=health`); não publicar `.git`/backups.
5. **Criptografia** em repouso/trânsito; segregar segredos (vault) fora do artefato.

## 7. Como testar/detectar
- Inspecionar respostas JSON em busca de campos sensíveis; forçar erros e ler o corpo.
- Recon: `/.git/`, `/actuator/*`, `/swagger`, backups (`.bak`, `.zip`).
- Testes: `src/test/java/com/arthur/security/attacks/dataexposure/*`.

## 8. Leitura adicional
- OWASP A02:2021: https://owasp.org/Top10/A02_2021-Cryptographic_Failures/
- OWASP Error Handling: https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html
- CWE-200: https://cwe.mitre.org/data/definitions/200.html
