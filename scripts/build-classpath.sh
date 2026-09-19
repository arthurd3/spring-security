#!/usr/bin/env bash
# Regenerates scripts/lib/classpath.txt so the exploits that use real libraries
# (BCrypt, H2, Jackson, Spring Expression) can run. Safe to re-run any time.
set -euo pipefail
cd "$(dirname "$0")/.."
./mvnw -q dependency:build-classpath -Dmdep.outputFile=scripts/lib/classpath.txt
echo "OK: scripts/lib/classpath.txt atualizado ($(wc -c < scripts/lib/classpath.txt) bytes)"
