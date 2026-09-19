# XXE — XML External Entity — dissecação completa (CWE-611 · OWASP A05:2021)

> Código: [`XxeDemo.java`](XxeDemo.java) · payloads: [`payloads.txt`](payloads.txt)

## 1. Para leigos
O XML permite criar "atalhos" (entidades) e até apontar um atalho para um ARQUIVO do servidor ou uma
URL. Se o leitor de XML aceita isso, um documento pode dizer "onde eu escrever &x; coloque /etc/passwd"
— e o servidor obedece, devolvendo arquivos internos, ou buscando endereços internos por você.

## 2. Como funciona tecnicamente
Uma **entidade externa** (`<!ENTITY x SYSTEM "...">`) faz o parser LER o recurso apontado (arquivo ou
URL) e inserir no documento. Isso vira: leitura de arquivo, **SSRF** (alcança serviços internos/metadata
da nuvem), e **DoS** (billion laughs: entidades que se referenciam explodem em memória). É o caso
clássico de **default inseguro**: a maioria das libs resolve DTD/entidades a menos que você desligue.
A defesa mais eficaz é **proibir DOCTYPE** (`disallow-doctype-decl`).

## 3. Variantes/técnicas (rodam no `.java`)
1. **Leitura de arquivo** — `SYSTEM "file:///..."` devolve o conteúdo no documento.
2. **SSRF via XXE** — `SYSTEM "http://interno/..."` faz o servidor buscar recursos internos (o `.java`
   sobe um HTTP em loopback e a entidade o lê).
3. **Billion laughs** — entidades aninhadas que expandem exponencialmente → DoS (aqui, limitado).
4. **Blind/OOB e parameter entities** — quando a saída não é ecoada, usa-se entidades de parâmetro e um
   servidor externo para exfiltrar (explicado no `payloads.txt`, não weaponizado aqui).

## 4. Casos reais
- XXE foi campeã de bug bounty em uploads de XML/DOCX/SVG e APIs SOAP; muitos CVEs em parsers e apps.
- **SSRF via XXE** foi caminho para ler metadata de nuvem (mesma joia da coroa do caso **Capital One**,
  ataque 16). https://portswigger.net/web-security/xxe
- Injeção/parsing inseguro seguem no **OWASP Top 10:2025**. https://owasp.org/Top10/2025/

## 5. Trechos de repositórios (reimplementados, com crédito)
- **OWASP WebGoat** — lição XXE com o mesmo `DocumentBuilderFactory` inseguro que reescrevemos.
  https://github.com/WebGoat/WebGoat
- **PayloadsAllTheThings — XXE** — fonte dos payloads de file/SSRF/OOB/billion laughs.
  https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection

## 6. Defesa em profundidade
1. **`disallow-doctype-decl = true`** (a defesa principal) — ver
   `src/main/java/com/arthur/security/xml/SafeXmlParser.java`.
2. Desligar entidades gerais/parâmetro externas e `load-external-dtd`; `setXIncludeAware(false)`.
3. Ativar `FEATURE_SECURE_PROCESSING` e limites de expansão.
4. Preferir **JSON**; se precisar XML, centralizar num único parser endurecido.
5. Egress filtering reduz SSRF/OOB.

## 7. Como testar/detectar
- Enviar um DOCTYPE com entidade `file:///etc/hostname` e ver se o conteúdo volta.
- Para blind: entidade apontando para um Collaborator/servidor seu e observar a requisição.
- Testes: `src/test/java/com/arthur/security/attacks/xxe/*`.

## 8. Leitura adicional
- OWASP XXE Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
- PortSwigger — XXE: https://portswigger.net/web-security/xxe
- CWE-611: https://cwe.mitre.org/data/definitions/611.html
