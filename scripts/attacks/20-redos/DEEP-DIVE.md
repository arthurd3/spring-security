# ReDoS — Regular Expression Denial of Service — dissecação completa (CWE-1333)

> Código: [`ReDoSDemo.java`](ReDoSDemo.java) · payloads: [`payloads.txt`](payloads.txt)

## 1. Para leigos
Expressões regulares (regex) validam texto (e-mail, senha...). Algumas regex mal escritas, diante de uma
entrada quase-certa, fazem o motor tentar um número astronômico de combinações antes de desistir — poucas
dezenas de caracteres prendem um núcleo de CPU por segundos. Vários pedidos assim derrubam o serviço,
sem exploit, só texto.

## 2. Como funciona tecnicamente
Motores com **backtracking** (Java, PCRE, JS) exploram todas as formas de casar uma parte. Com
**quantificadores aninhados/ambíguos** (`(a+)+`, `(.*a){20}`), o número de tentativas cresce
exponencialmente sobre um quase-casamento. Importante: **depende do motor** — o JDK 21 otimiza vários
clássicos (`(a+)+`) mas ainda explode com repetição **limitada** de grupo guloso (`(.*a){20}`, `(.*@){12}`).
Correção: **limitar o tamanho** da entrada, usar verificação **linear** (ou motor sem backtracking, tipo
**RE2**), e rodar regex de entrada não confiável sob **timeout**.

## 3. Variantes/técnicas (rodam no `.java`)
1. **`(.*a){20}`** — repetição limitada de grupo guloso: catastrófico mesmo no JDK moderno.
2. **`(.*@){12}`** — regex "de e-mail" mal escrita, também catastrófica.
3. **`(a+)+`** — clássico, mas otimizado neste JDK (lição: comportamento depende do motor/versão).
4. **Mitigação genérica** — timeout + length cap.

## 4. Casos reais
- **Cloudflare (2 jul 2019):** uma regra de WAF com regex de backtracking causou 100% de CPU e **~27
  min de outage global**. https://blog.cloudflare.com/details-of-the-cloudflare-outage-on-july-2-2019/
- **Stack Overflow (2016):** outage por regex de trim com backtracking.
- ReDoS é recorrente em libs de validação (e-mail/URL) e regras de WAF.

## 5. Trechos de repositórios (reimplementados, com crédito)
- **Cloudflare postmortem** — o padrão de backtracking que derrubou o WAF (base da lição).
  https://blog.cloudflare.com/details-of-the-cloudflare-outage-on-july-2-2019/
- **Google RE2 / RE2J** — motor de tempo linear (mitigação recomendada). https://github.com/google/re2j
- No app: length cap + verificação linear em `src/main/java/com/arthur/security/validation/ValidationController.java`.

## 6. Defesa em profundidade
1. **Length cap** na entrada antes de qualquer regex.
2. **Verificação linear** (char a char) ou **quantificador possessivo/atômico** (`a++`, `(?>...)`).
3. Motor **sem backtracking** (**RE2/RE2J**) para regex sobre entrada não confiável.
4. **Timeout** ao rodar regex não confiável (executar em thread com deadline).
5. Revisar/estaticamente analisar regexes; nunca compor regex a partir de input.

## 7. Como testar/detectar
- Ferramentas: **recheck**, **safe-regex**, análises de "evil regex"; fuzzing com entradas quase-casadas.
- Medir tempo de match com entradas crescentes.
- Testes: `src/test/java/com/arthur/security/attacks/redos/*`.

## 8. Leitura adicional
- OWASP ReDoS: https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS
- Cloudflare 2019: https://blog.cloudflare.com/details-of-the-cloudflare-outage-on-july-2-2019/
- CWE-1333: https://cwe.mitre.org/data/definitions/1333.html
