#!/usr/bin/env bash
# 09 - Mass Assignment (CWE-915 / OWASP A08:2021) - deep dive
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/../../lib/common.sh"; ensure_java
title "09. Mass Assignment (over-posting)  -  CWE-915 / OWASP A08:2021 (deep dive)"
section 1 "Entenda em 3 niveis"
level "Basico" "O cadastro tem usuario e senha, mas o servidor copia tudo do pedido para o registro. O atacante adiciona 'role: ADMIN' (ou admin:true, balance:1000000) e o servidor obedece."
level "Intermediario" "O binder preenche o objeto campo a campo pelo JSON. Se o alvo tem campos sensiveis, o JSON os preenche. Tecnicas: role, isAdmin, price tampering, objeto aninhado."
level "Avancado" "Correcao = allowlist: vincular a um DTO/record so com os campos permitidos; servidor decide o privilegiado. Blocklist campo a campo e fragil. Spring4Shell foi abuso do data binding."
section 2 "Conceitos tecnicos"
term "Data binding" "Framework preenche o objeto a partir do JSON, campo a campo."
term "Over-posting" "Enviar campos alem do esperado para atingir propriedades sensiveis."
term "DTO/record (allowlist)" "Objeto so com os campos permitidos; o extra nao tem onde encaixar."
term "ignoreUnknown=false" "Rejeitar campos desconhecidos em vez de ignora-los."
section 3 "O codigo (4 variantes, nesta pasta)"; show_code "$HERE/MassAssignmentDemo.java"
section 4 "Executando as variantes"; run_demo "$HERE/MassAssignmentDemo.java"
section 5 "Por que a defesa funciona"
para "Vincular a um record com so username/password nao deixa 'role/admin/balance' pousarem; o servidor grava o valor certo. No app: src/main/java/com/arthur/security/auth/RegistrationController.java."
doc_pointer "$HERE"
section 6 "Referencias"
ref "OWASP Mass Assignment: https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html"
ref "Real: GitHub/Rails 2012 (Homakov); Spring4Shell CVE-2022-22965 (data binding)"
ref "OWASP API6:2023: https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"
ref "CWE-915: https://cwe.mitre.org/data/definitions/915.html"
footer
