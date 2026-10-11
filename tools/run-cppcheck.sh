#!/usr/bin/env bash
# Analyse statique cppcheck du code de tlsrelay. Échoue à la première alerte.
# Usage : tools/run-cppcheck.sh <répertoire de build avec compile_commands.json>
#
# Suppressions globales (tools/cppcheck-suppressions.txt) :
# - missingReturn : cppcheck ne reconnaît pas les coroutines C++20 dont le corps
#   se termine sans co_return (asio::awaitable<void>) ; un vrai retour manquant est
#   déjà une erreur de compilation (-Werror=return-type, MSVC C4715 avec /WX) ;
# - en-têtes système et dépendances.
set -euo pipefail
build=${1:?usage : $0 <répertoire de build>}
root=$(cd "$(dirname "$0")/.." && pwd)
cppcheck --project="$build/compile_commands.json" --file-filter="*/src/*" \
  --enable=warning,performance,portability --check-level=exhaustive --inline-suppr \
  --suppressions-list="$root/tools/cppcheck-suppressions.txt" \
  --error-exitcode=1 --quiet -j "$(nproc)"
echo "cppcheck : aucune alerte"
