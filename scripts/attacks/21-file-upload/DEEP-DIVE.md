# Unrestricted File Upload — dissecação completa (CWE-434 · OWASP A05:2021)

> Código: [`FileUploadDemo.java`](FileUploadDemo.java) · payloads: [`payloads.txt`](payloads.txt)

## 1. Para leigos
Um campo "envie sua foto" que aceita QUALQUER arquivo, com QUALQUER nome, guardado numa pasta que o site
serve, é uma porta dos fundos. O atacante envia uma página `.html` com `<script>` (ou um `.jsp`/`.php`) e
depois a acessa: o navegador executa (XSS armazenado) ou o servidor executa (RCE).

## 2. Como funciona tecnicamente
Erros: confiar na **extensão** e no **Content-Type** enviados pelo cliente (ambos mentíveis), manter o
**nome do cliente** (permite `../` e dupla extensão), e servir de um diretório **executável**. Bypasses:
`shell.jsp.png`, `shell.jsp%00.png` (null byte, histórico), `shell.jsp.` (ponto final), maiúsculas,
**content-type spoof** (extensão de imagem, conteúdo PHP), **polyglot** (arquivo válido como imagem E
script). Correção: **allowlist de extensão**, **validar magic bytes/conteúdo**, **nome aleatório** gerado
no servidor, **limite de tamanho**, e armazenar **fora do webroot** (ou sem execução).

## 3. Variantes/técnicas (rodam no `.java`)
1. **Extensão perigosa** (`.jsp`/`.html`).
2. **Dupla extensão / ponto final** (`shell.jsp.png`, `shell.jsp.`).
3. **Content-Type spoof** vs validação de **magic bytes**.
4. **Caminho no nome** (`../../.../shell.jsp`).

## 4. Casos reais
- Upload irrestrito é caminho frequente para **webshell → RCE** em CMSs, uploaders e APIs; dezenas de
  CVEs por ano. https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
- **Polyglots** (GIFAR, PNG+PHP) burlam validações que olham só o começo do arquivo.
- **OWASP Top 10:2025** — Security Misconfiguration/Injection cobrem o vetor. https://owasp.org/Top10/2025/

## 5. Trechos de repositórios (reimplementados, com crédito)
- **OWASP File Upload Cheat Sheet** — allowlist, magic bytes, rename, storage seguro (base do `.java`).
  https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
- **PayloadsAllTheThings — Upload Insecure Files** — bypasses de extensão/content-type.
  https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files
- No app: `src/main/java/com/arthur/security/upload/UploadService.java`.

## 6. Defesa em profundidade
1. **Allowlist de extensão** (final) + **validar conteúdo/magic bytes** (não confiar no Content-Type).
2. **Nome aleatório** gerado no servidor; **remover o path** do nome do cliente.
3. **Limite de tamanho**; antivírus/CDR para conteúdo ativo.
4. Armazenar **fora do webroot** ou em bucket **sem execução**; servir com `Content-Disposition: attachment`.
5. Reprocessar imagens (re-encode) para destruir polyglots.

## 7. Como testar/detectar
- Enviar `.jsp/.php/.html`, dupla extensão, content-type falso, `../` no nome, arquivo grande, polyglot.
- Testes: `src/test/java/com/arthur/security/attacks/fileupload/*`.

## 8. Leitura adicional
- OWASP File Upload: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
- OWASP Unrestricted File Upload: https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
- CWE-434: https://cwe.mitre.org/data/definitions/434.html

## 9. Trilhas de aprendizado (conhecimentos que levam a outros)
- **Pré-requisitos:** multipart/MIME, extensões vs conteúdo (magic bytes).
- **Conecta com:** [#10 path traversal](../10-path-traversal/DEEP-DIVE.md) (nome do arquivo), [#07 XSS](../07-xss-headers/DEEP-DIVE.md) (HTML servido), [#17 command injection](../17-command-injection/DEEP-DIVE.md) (webshell→RCE).
- **Conceitos rodáveis:** — (foco em allowlist + magic bytes + nome aleatório).
- **Aprofundar:** OWASP File Upload Cheat Sheet · PayloadsAllTheThings (Upload).
