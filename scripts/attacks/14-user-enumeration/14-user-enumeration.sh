#!/usr/bin/env bash
# 14 - Username Enumeration (CWE-204 / OWASP A07:2021) - deep dive
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/../../lib/common.sh"; ensure_java
title "14. Username Enumeration  -  CWE-204 / OWASP A07:2021 (deep dive)"
section 1 "Entenda em 3 niveis"
level "Basico" "Se o login responde diferente para 'usuario nao existe' e 'senha errada', ele confirma quem tem conta ali. O atacante testa e-mails e separa os que existem."
level "Intermediario" "Qualquer diferenca observavel e um oraculo: mensagem, status, tamanho e - o mais sutil - TEMPO. Se 'existe' roda o hash (lento) e 'nao existe' e instantaneo, da para enumerar por tempo."
level "Avancado" "Defesa: respostas uniformes E tempo constante (rodar o hash contra um dummy para usuario inexistente). Genericar cadastro/reset; rate limit dificulta a varredura."
section 2 "Conceitos tecnicos"
term "Enumeracao" "Descobrir quais usuarios/e-mails existem a partir de diferencas nas respostas."
term "Oraculo" "Diferenca observavel (status/texto/tempo/tamanho) que responde 'essa conta existe?'."
term "Timing side-channel" "O tempo de resposta vaza informacao (hash roda so p/ usuario existente)."
term "Resposta uniforme" "Mesma mensagem/status/tempo para todas as falhas."
section 3 "O codigo (4 variantes, nesta pasta)"; show_code "$HERE/UserEnumerationDemo.java"
section 4 "Executando as variantes"; run_demo "$HERE/UserEnumerationDemo.java"
section 5 "Por que a defesa funciona"
para "Respostas identicas fecham o oraculo de mensagem/status; rodar sempre o hash (contra dummy) fecha o de tempo. No app: hideUserNotFoundExceptions + encoder contra dummy (JpaUserDetailsService/DaoAuthenticationProvider)."
doc_pointer "$HERE"
section 6 "Referencias"
ref "OWASP WSTG - Account Enumeration: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account"
ref "OWASP Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"
ref "CWE-204: https://cwe.mitre.org/data/definitions/204.html"
footer
