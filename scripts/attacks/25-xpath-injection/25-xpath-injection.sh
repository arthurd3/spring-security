#!/usr/bin/env bash
# 25 - XPath Injection (CWE-643 / OWASP A03:2021) - deep dive
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/../../lib/common.sh"; ensure_java
title "25. XPath Injection  -  CWE-643 / OWASP A03:2021 (deep dive)"
section 1 "Entenda em 3 niveis"
level "Basico" "Dados em XML sao consultados com XPath. Se a consulta e montada colando o que voce digitou, com aspas e um 'ou verdadeiro' voce reescreve a busca e loga sem senha."
level "Intermediario" "XPath nao tem contas/permissoes: quem controla parte da expressao controla a consulta toda. Tecnicas: tautologia, blind (extrai char por char), union (dump)."
level "Avancado" "Correcao = variaveis vinculadas (XPathVariableResolver): o valor entra como dado, nunca como sintaxe. Escapar aspas nao e portavel/seguro."
section 2 "Conceitos tecnicos"
term "XPath" "Linguagem de busca para XML (//user[name='x' and pass='y'])."
term "Tautologia" "' or '1'='1 injeta condicao sempre verdadeira."
term "Blind XPath" "So true/false visivel; substring(pass,i,1)='x' vaza a senha aos poucos."
term "XPathVariableResolver" "Fornece \$user/\$pass como valores; o motor nunca os interpreta como sintaxe."
section 3 "O codigo (3 variantes, nesta pasta)"; show_code "$HERE/XpathDemo.java"
section 4 "Executando as variantes"; run_demo "$HERE/XpathDemo.java"
section 5 "Por que a defesa funciona"
para "Variavel vinculada faz as aspas do atacante virarem DADO, nunca sintaxe - some a tautologia, o union e o oraculo blind. No app: src/main/java/com/arthur/security/xpath/XpathLoginService.java."
doc_pointer "$HERE"
section 6 "Referencias"
ref "OWASP XPath Injection: https://owasp.org/www-community/attacks/XPATH_Injection"
ref "Repos: OWASP WSTG, swisskyrepo/PayloadsAllTheThings (ver DEEP-DIVE.md)"
ref "CWE-643: https://cwe.mitre.org/data/definitions/643.html"
footer
