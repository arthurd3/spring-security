# Path Traversal — dissecação completa (CWE-22 · OWASP A01:2021)

> Código: [`PathTraversalDemo.java`](PathTraversalDemo.java) · payloads: [`payloads.txt`](payloads.txt)

## 1. Para leigos
Um endpoint serve arquivos de uma pasta pública pelo nome. Se o servidor só junta pasta + nome, você
escreve `../` e sai da área pública, lendo arquivos do sistema (senhas de configuração). "O documento da
gaveta 3" vira "e também o cofre no andar de cima".

## 2. Como funciona tecnicamente
`..` significa "subir um nível". Encadeado, escapa da pasta base. Variações driblam filtros ingênuos:
**URL-encode** (`%2e%2e%2f`), **double-encode** (`%252e`), **caminho absoluto** (o `resolve()` do Java
com input absoluto **descarta a base**), e **Zip Slip** (uma entrada de arquivo compactado com `../`
escreve fora do diretório na extração). Correção: **normalizar** e então **verificar contenção**
(`target.startsWith(base)`) — nunca blacklist de `".."`.

## 3. Variantes/técnicas (rodam no `.java`)
1. **`../` básico**.
2. **URL-encoded** `%2e%2e%2f` (o servidor decodifica antes).
3. **Caminho absoluto** (`resolve()` ignora a base).
4. **Zip Slip** (entrada de arquivo com `../` na extração).

## 4. Casos reais
- **Zip Slip (Snyk, 2018):** classe de bug em extração de arquivos que afetou milhares de projetos.
  https://security.snyk.io/research/zip-slip-vulnerability
- Path traversal domina CVEs de **appliances** (Ivanti, Fortinet, Citrix) usados para ler config/roubar
  credenciais e encadear RCE.
- **Recente (2026):** **Spring Cloud Config Server — CVE-2026-40982** (directory traversal). Confirmar no
  advisory da Spring.

## 5. Trechos de repositórios (reimplementados, com crédito)
- **OWASP / PortSwigger** — travessia e bypasses de encoding (base das variantes).
  https://portswigger.net/web-security/file-path-traversal
- **Snyk Zip Slip** — a checagem de contenção na extração (Variante 4). https://github.com/snyk/zip-slip-vulnerability
- No app: `src/main/java/com/arthur/security/files/FileStorageService.java`.

## 6. Defesa em profundidade
1. **Normalizar + contenção**: `base.resolve(name).normalize()` e exigir `startsWith(base)`.
2. **Nunca** blacklist de `".."` (perde p/ encoding/absoluto).
3. Preferir **id → caminho mapeado** no servidor a nome livre.
4. Na extração de arquivos, **validar cada entrada** (Zip Slip) e limitar tamanho/quantidade.
5. `toRealPath()` da base (resolve symlinks) antes de comparar; menor privilégio de FS.

## 7. Como testar/detectar
- Testar `../`, `%2e%2e%2f`, `%252e`, caminho absoluto, `....//`, e entradas de zip com `../`.
- Testes: `src/test/java/com/arthur/security/attacks/pathtraversal/*`.

## 8. Leitura adicional
- OWASP Path Traversal: https://owasp.org/www-community/attacks/Path_Traversal
- PortSwigger: https://portswigger.net/web-security/file-path-traversal
- CWE-22: https://cwe.mitre.org/data/definitions/22.html

## 9. Trilhas de aprendizado (conhecimentos que levam a outros)
- **Pré-requisitos:** caminhos de arquivo, normalização, encoding de URL.
- **Conecta com:** [#16 SSRF](../16-ssrf/DEEP-DIVE.md) (`file://`), [#21 file upload](../21-file-upload/DEEP-DIVE.md) (onde os arquivos vão parar), [#15 XXE](../15-xxe/DEEP-DIVE.md) (leitura de arquivo).
- **Conceitos rodáveis:** — (foco em normalize + contenção).
- **Aprofundar:** OWASP Path Traversal · Snyk Zip Slip · PortSwigger file path traversal.
