#!/usr/bin/env bash
# Couverture de code (TESTS.md §6) : build instrumenté GCC (gcov), exécution de
# tous les tests ctest, puis rapport gcovr sur le code livré (src/core, src/app,
# src/admin ; le testkit est un outil de test, exercé par les scripts de perf).
# Usage : tools/coverage.sh [répertoire de build] [seuil minimal de lignes en %]
# Rapports : <build>/coverage/index.html, summary.txt, summary.json.
set -euo pipefail

build=${1:-build/coverage}
threshold=${2:-0}
root=$(cd "$(dirname "$0")/.." && pwd)

command -v gcovr >/dev/null || { echo "gcovr requis (pip install gcovr)" >&2; exit 1; }

cmake -S "$root" -B "$build" -G Ninja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_COMPILER=g++ \
  -DTLSRELAY_COVERAGE=ON -DTLSRELAY_BUILD_ADMIN=ON -DTLSRELAY_WARNINGS_AS_ERRORS=ON
cmake --build "$build"

# Compteurs remis à zéro : la mesure ne porte que sur cette exécution.
find "$build" -name '*.gcda' -delete
(cd "$build" && QT_QPA_PLATFORM=offscreen ctest --output-on-failure -j 2)
# Commande supplémentaire mesurée avant le rapport, par exemple le cycle de vie
# systemd en root (CI) : COVERAGE_EXTRA="sudo bash tests/lifecycle/systemd.sh <build>/src/app/tlsrelay".
if [ -n "${COVERAGE_EXTRA:-}" ]; then (cd "$root" && bash -c "$COVERAGE_EXTRA"); fi

out="$build/coverage"
mkdir -p "$out"
common=(--root "$root" "$build"
  --filter "$root/src/core/" --filter "$root/src/app/" --filter "$root/src/admin/"
  --exclude '.*_autogen/.*'
  --exclude-unreachable-branches --exclude-throw-branches
  --gcov-ignore-parse-errors=negative_hits.warn -j "$(nproc)")

gcovr "${common[@]}" \
  --html-details "$out/index.html" \
  --txt "$out/summary.txt" \
  --json-summary-pretty --json-summary "$out/summary.json" \
  --print-summary --fail-under-line "$threshold"

echo "rapport : $out/index.html"
