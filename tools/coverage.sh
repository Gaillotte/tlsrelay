#!/usr/bin/env bash
# Code coverage (TESTS.md §6): GCC instrumented build (gcov), run of all
# ctest tests, then gcovr report on the shipped code (src/core, src/app,
# src/admin; the testkit is a test tool, exercised by the perf scripts).
# Usage: tools/coverage.sh [build directory] [minimum line threshold in %]
# Reports: <build>/coverage/index.html, summary.txt, summary.json.
set -euo pipefail

build=${1:-build/coverage}
threshold=${2:-0}
root=$(cd "$(dirname "$0")/.." && pwd)

command -v gcovr >/dev/null || { echo "gcovr required (pip install gcovr)" >&2; exit 1; }

cmake -S "$root" -B "$build" -G Ninja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_COMPILER=g++ \
  -DTLSRELAY_COVERAGE=ON -DTLSRELAY_BUILD_ADMIN=ON -DTLSRELAY_WARNINGS_AS_ERRORS=ON
cmake --build "$build"

# Counters reset: the measurement covers this run only.
find "$build" -name '*.gcda' -delete
(cd "$build" && QT_QPA_PLATFORM=offscreen ctest --output-on-failure -j 2)
# Additional command measured before the report, for example the systemd
# lifecycle as root (CI): COVERAGE_EXTRA="sudo bash tests/lifecycle/systemd.sh <build>/src/app/tlsrelay".
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

echo "report: $out/index.html"
