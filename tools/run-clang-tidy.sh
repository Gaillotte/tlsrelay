#!/usr/bin/env bash
# Analyse statique clang-tidy du code de tlsrelay (règles : .clang-tidy).
# Échoue si une alerte porte sur le code du projet. Les alertes situées dans
# les en-têtes d'Asio (faux positifs connus de l'analyseur de chemins sur les
# cadres de coroutines) sont affichées à part, sans faire échouer l'analyse.
# Usage : tools/run-clang-tidy.sh <répertoire de build avec compile_commands.json>
set -euo pipefail
build=${1:?usage : $0 <répertoire de build>}
root=$(cd "$(dirname "$0")/.." && pwd)
tidy=$(command -v clang-tidy-18 || command -v clang-tidy)
out=$(mktemp)
trap 'rm -f "$out"' EXIT

find "$root/src" -name '*.cpp' ! -name 'windows.cpp' ! -name 'platform_windows.cpp' -print0 |
  xargs -0 -P "$(nproc)" -n1 "$tidy" -p "$build" --quiet >"$out" 2>/dev/null || true

project=$(grep -E "^$root/(src|fuzz)/.*: (warning|error):" "$out" | sort -u || true)
external=$(grep -cE "^/usr/include/.*: (warning|error):" "$out" || true)
if [ -n "$project" ]; then
  echo "$project"
  echo "clang-tidy : $(echo "$project" | wc -l) alerte(s) dans le code du projet" >&2
  exit 1
fi
echo "clang-tidy : aucune alerte dans le code du projet ($external diagnostic(s) dans des en-têtes externes ignoré(s))"
