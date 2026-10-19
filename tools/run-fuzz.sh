#!/usr/bin/env bash
# Runs each fuzzing target for <seconds>, starting from its corpus
# (fuzz/corpus/<target>, enriched in <build>/corpus). Inputs that make
# a target fail are kept in <build>/../fuzz-artifacts.
# Usage: tools/run-fuzz.sh <linux-fuzz build> <seconds> [target...]
set -euo pipefail
build=$(realpath "${1:?usage: $0 <build> <seconds> [target...]}")
seconds=${2:?duration in seconds}
shift 2
root=$(cd "$(dirname "$0")/.." && pwd)
targets=("$@")
[ ${#targets[@]} -eq 0 ] && targets=(frame config whitelist csr dn admin)
artifacts="$build/../fuzz-artifacts"
mkdir -p "$artifacts"
status=0
for t in "${targets[@]}"; do
  corpus="$build/corpus/$t"
  mkdir -p "$corpus"
  cp -n "$root/fuzz/corpus/$t/"* "$corpus/" 2>/dev/null || true
  echo "== fuzz_$t: $seconds s"
  if ! "$build/fuzz/fuzz_$t" -max_total_time="$seconds" -timeout=10 -rss_limit_mb=2048 \
        -artifact_prefix="$artifacts/$t-" -print_final_stats=1 "$corpus" 2>"$build/fuzz_$t.log"; then
    status=1
    tail -40 "$build/fuzz_$t.log"
  fi
  grep -E "stat::number_of_executed_units|^#[0-9]+.*DONE" "$build/fuzz_$t.log" | tail -2 || true
done
exit $status
