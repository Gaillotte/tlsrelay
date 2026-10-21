#!/usr/bin/env bash
# clang-tidy static analysis of the tlsrelay code (rules: clang-tidy.yaml).
# Fails if a warning concerns the project's code. Warnings located in
# the Asio headers (known false positives of the path analyzer on
# coroutine frames) are reported separately, without failing the analysis.
# Usage: tools/run-clang-tidy.sh <build directory with compile_commands.json>
set -euo pipefail
build=${1:?usage: $0 <build directory>}
root=$(cd "$(dirname "$0")/.." && pwd)
tidy=$(command -v clang-tidy-18 || command -v clang-tidy)
# The rules are kept in clang-tidy.yaml (a file name with an extension) and passed explicitly;
# fail if clang-tidy cannot load them, since its own errors are discarded below.
config="$root/clang-tidy.yaml"
"$tidy" --config-file="$config" --dump-config >/dev/null
out=$(mktemp)
trap 'rm -f "$out"' EXIT

find "$root/src" -name '*.cpp' ! -name 'windows.cpp' ! -name 'platform_windows.cpp' -print0 |
  xargs -0 -P "$(nproc)" -n1 "$tidy" --config-file="$config" -p "$build" --quiet >"$out" 2>/dev/null || true

project=$(grep -E "^$root/(src|fuzz)/.*: (warning|error):" "$out" | sort -u || true)
external=$(grep -cE "^/usr/include/.*: (warning|error):" "$out" || true)
if [ -n "$project" ]; then
  echo "$project"
  echo "clang-tidy: $(echo "$project" | wc -l) warning(s) in the project code" >&2
  exit 1
fi
echo "clang-tidy: no warning in the project code ($external diagnostic(s) in external headers ignored)"
