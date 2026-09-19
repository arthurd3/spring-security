#!/usr/bin/env bash
# 19 - Insecure Deserialization (CWE-502 / OWASP A08:2021) - deep dive
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/../../lib/common.sh"; ensure_java
title "19. Insecure Deserialization  -  CWE-502 / OWASP A08:2021 (deep dive)"
section 1 "Entenda em 3 niveis"
level "Basico" "Desserializar e 'descongelar' bytes em objetos. No Java, ao descongelar, o programa executa codigo. Se voce descongela bytes do atacante, ele monta um quebra-cabeca que ao ser remontado roda o codigo dele."
level "Intermediario" "readObject invoca metodos das classes. O atacante encadeia classes ja presentes (gadget chain, via ysoserial). JSON polimorfico (Jackson default typing/XStream) instancia tipos escolhidos pelo atacante."
level "Avancado" "Defesas: nao desserializar dados nao confiaveis; ObjectInputFilter (allowlist, JDK9+); em JSON, tipo fixo sem default typing; manter libs (onde moram os gadgets) atualizadas."
section 2 "Conceitos tecnicos"
term "Serializacao nativa" "ObjectOutputStream/ObjectInputStream; readObject pode rodar codigo."
term "Gadget chain" "Sequencia de classes do classpath cujo efeito combinado executa comandos (ysoserial)."
term "ObjectInputFilter" "Allowlist de classes na desserializacao (JDK 9+); rejeita o inesperado."
term "Default typing (Jackson)" "Instancia o tipo nomeado no JSON -> perigoso sobre dados nao confiaveis."
section 3 "O codigo (3 variantes, nesta pasta)"; show_code "$HERE/DeserializationDemo.java"
section 4 "Executando as variantes"; run_demo "$HERE/DeserializationDemo.java"
section 5 "Por que a defesa funciona"
para "Ler JSON para um tipo FIXO (sem default typing) so preenche aquele tipo; ObjectInputFilter rejeita classes fora da allowlist. Nada de gadget executa. No app: src/main/java/com/arthur/security/imports/ImportController.java."
doc_pointer "$HERE"
section 6 "Referencias"
ref "OWASP Deserialization: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html"
ref "Real: ysoserial; Log4Shell CVE-2021-44228; Struts CVE-2017-9805; Spring CVE-2026-41855/47864/41699"
ref "Repos: frohoff/ysoserial (citado) (ver DEEP-DIVE.md)"
ref "CWE-502: https://cwe.mitre.org/data/definitions/502.html"
footer
