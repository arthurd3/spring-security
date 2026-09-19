# Insecure Deserialization — dissecação completa (CWE-502 · OWASP A08:2021)

> Código: [`DeserializationDemo.java`](DeserializationDemo.java) · notas: [`payloads.txt`](payloads.txt)

## 1. Para leigos
Serializar é "congelar" um objeto em bytes; desserializar é "descongelar". No Java, ao descongelar, o
programa RECONSTRÓI os objetos e executa trechos de código no processo. Se você descongela bytes de um
atacante, ele monta um "quebra-cabeça" de objetos que, ao ser remontado, roda o código dele.

## 2. Como funciona tecnicamente
`ObjectInputStream.readObject()` invoca `readObject`/`readResolve`/finalizers das classes envolvidas. Um
atacante encadeia classes já presentes no classpath (uma **gadget chain**) cujo efeito combinado executa
comandos — é o que a ferramenta **ysoserial** automatiza (Commons-Collections, Spring, etc.). Além do
formato nativo, **JSON polimórfico** (Jackson com *default typing*, XStream) permite instanciar um **tipo
escolhido pelo atacante** a partir do dado. Defesas: **não desserializar dados não confiáveis**;
**`ObjectInputFilter`** (allowlist de classes, JDK 9+); e, em JSON, **tipo fixo** sem *default typing*.

## 3. Variantes/técnicas (rodam no `.java`)
1. **`readObject` nativo** executa código (mecanismo da gadget chain).
2. **`ObjectInputFilter`** (allowlist) rejeita a classe inesperada — defesa.
3. **Jackson polimórfico** (*default typing*) instancia um tipo nomeado pelo atacante; tipo fixo não.

## 4. Casos reais
- **ysoserial (2015):** Frohoff & Lawrence publicaram 20+ gadget chains prontas (Commons-Collections,
  Groovy, Spring...). https://github.com/frohoff/ysoserial
- **Log4Shell — CVE-2021-44228 (2021):** `${jndi:ldap://...}` fez a JVM buscar e desserializar um objeto
  remoto via LDAP → RCE; >800k tentativas na 1ª semana. https://nvd.nist.gov/vuln/detail/CVE-2021-44228
- **Apache Struts — CVE-2017-9805 (2017):** desserialização XML (REST plugin) → RCE.
- **Recente (2026):** **Spring — CVE-2026-41855** (JMS/Jackson), **CVE-2026-47864**
  (`SerializingHttpMessageConverter`), **CVE-2026-41699** (Spring GraphQL) — desserialização insegura.

## 5. Trechos de repositórios (reimplementados, com crédito)
- **ysoserial** — a ideia de gadget chain (citada; não embarcada). https://github.com/frohoff/ysoserial
- **OWASP Deserialization Cheat Sheet** — `ObjectInputFilter`/JSON tipo fixo (base do `.java`).
  https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
- No app: JSON em tipo fixo em `src/main/java/com/arthur/security/imports/ImportController.java`.

## 6. Defesa em profundidade
1. **Não desserializar** streams nativos não confiáveis; preferir **JSON/dados** para **tipo fixo**.
2. **`ObjectInputFilter`** com allowlist de classes/pacotes (JDK 9+; `jdk.serialFilter`).
3. Em Jackson, **nunca** `enableDefaultTyping/activateDefaultTyping` sobre dados não confiáveis; usar
   tipos concretos e `@JsonTypeInfo` com validador restrito quando polimorfismo for necessário.
4. Manter libs atualizadas (gadgets moram em dependências); remover as vulneráveis.
5. Assinar/lacrar dados serializados internos; segmentar e menor privilégio.

## 7. Como testar/detectar
- Procurar `ObjectInputStream.readObject`, `enableDefaultTyping`, XStream sem allowlist.
- Ferramentas: ysoserial (autorizado), gadget scanners, SAST.
- Testes: `src/test/java/com/arthur/security/attacks/deserialization/*`.

## 8. Leitura adicional
- OWASP Deserialization: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
- OWASP - Deserialization of untrusted data: https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data
- CWE-502: https://cwe.mitre.org/data/definitions/502.html

## 9. Trilhas de aprendizado (conhecimentos que levam a outros)
- **Pré-requisitos:** serialização Java/JSON; classpath e reflexão.
- **Conecta com:** [#06 jwt](../06-jwt/DEEP-DIVE.md) (parsear tokens), [#15 XXE](../15-xxe/DEEP-DIVE.md) (parsear dado não confiável), [#17](../17-command-injection/DEEP-DIVE.md)/[#18](../18-spel-injection/DEEP-DIVE.md) (RCE).
- **Conceitos rodáveis:** — (foco em `ObjectInputFilter`/JSON tipo fixo).
- **Aprofundar:** OWASP Deserialization Cheat Sheet · ysoserial · Log4Shell (CVE-2021-44228).
