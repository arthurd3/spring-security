#!/usr/bin/env bash
# 18 - SpEL / SSTI (CWE-917 / OWASP A03:2021) - deep dive
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/../../lib/common.sh"; ensure_java
title "18. SpEL / Server-Side Template Injection  -  CWE-917 (deep dive)"
section 1 "Entenda em 3 niveis"
level "Basico" "Alguns sistemas avaliam pequenas formulas para montar texto. Se o servidor AVALIA o que voce digitou, voce vira programador dentro dele: em vez de um nome, roda um comando."
level "Intermediario" "SpEL com o contexto padrao da acesso a tipos T(...), construtores new... e metodos - inclusive Runtime.exec. Tecnicas: eval basico, acesso a tipos, RCE, bypass de blacklist."
level "Avancado" "Correcao principal: NAO avaliar input. Se precisar, SimpleEvaluationContext (sem T()/construtores). Template engines tem a mesma falha (SSTI). Spring4Shell foi data binding; CVE-2026-59283 e bypass do guard de SpEL."
section 2 "Conceitos tecnicos"
term "SpEL" "Mini-linguagem do Spring avaliada em runtime; poderosa e perigosa sobre input."
term "StandardEvaluationContext" "Contexto padrao: permite T(), new, metodos -> caminho ate RCE."
term "SimpleEvaluationContext" "Contexto restrito (data binding read-only): sem T()/construtores."
term "SSTI" "Server-Side Template Injection: input interpretado como codigo do template."
section 3 "O codigo (4 variantes, nesta pasta)"; show_code "$HERE/SpelDemo.java"
section 4 "Executando as variantes"; run_demo "$HERE/SpelDemo.java"
section 5 "Por que a defesa funciona"
para "A app nunca chama parseExpression sobre input (trata como texto); quando avaliacao e necessaria, SimpleEvaluationContext bloqueia T()/construtores. No app: src/main/java/com/arthur/security/spel/GreetingController.java."
doc_pointer "$HERE"
section 6 "Referencias"
ref "Spring4Shell CVE-2022-22965 | Spring Cloud Function CVE-2022-22963 | SpEL guard bypass CVE-2026-59283"
ref "PortSwigger SSTI: https://portswigger.net/web-security/server-side-template-injection"
ref "Repos: JoyChou93/java-sec-code, javaspringvulny (ver DEEP-DIVE.md)"
ref "CWE-917: https://cwe.mitre.org/data/definitions/917.html"
footer
