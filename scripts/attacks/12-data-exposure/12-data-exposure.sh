#!/usr/bin/env bash
# 12 - Sensitive Data Exposure (CWE-200 / OWASP A02:2021) - deep dive
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/../../lib/common.sh"; ensure_java
title "12. Sensitive Data Exposure  -  CWE-200 / OWASP A02:2021 (deep dive)"
section 1 "Entenda em 3 niveis"
level "Basico" "Um endpoint devolve o registro inteiro do banco - e junto vai o hash da senha, token, CPF. Ninguem decidiu publicar; o conversor objeto->JSON manda tudo."
level "Intermediario" "A raiz e expor mais do que o necessario: entidade em vez de DTO, erros verbosos, campos excessivos, PII em log, endpoints de debug (/actuator/.git)."
level "Avancado" "Correcao: DTO por caso de uso, erros genericos com id de correlacao, mascarar PII, restringir actuator, criptografia, segredos em vault fora do artefato."
section 2 "Conceitos tecnicos"
term "Entidade x DTO" "Entidade = todos os campos do banco; DTO = so o que a API deve expor."
term "Erro verboso" "Stack trace/SQL/versao no corpo do erro ajudam o atacante."
term "PII" "Dados pessoais (email, CPF, cartao) que precisam de mascaramento em log."
term "Actuator/.git" "Superficies operacionais que, expostas, vazam segredos/codigo."
section 3 "O codigo (5 variantes, nesta pasta)"; show_code "$HERE/DataExposureDemo.java"
section 4 "Executando as variantes"; run_demo "$HERE/DataExposureDemo.java"
section 5 "Por que a defesa funciona"
para "DTO por endpoint garante que so o publico sai; erro generico nao vaza internals; mascaramento protege PII; restringir actuator/.git fecha o recon. No app: UserProfile + include-stacktrace=never."
doc_pointer "$HERE"
section 6 "Referencias"
ref "OWASP A02:2021: https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
ref "Real: Optus 2022 (API sem auth, dados excessivos); /actuator e /.git expostos"
ref "OWASP Error Handling: https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html"
ref "CWE-200: https://cwe.mitre.org/data/definitions/200.html"
footer
