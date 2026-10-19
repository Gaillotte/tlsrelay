#!/usr/bin/env bash
# Linux executable hardening (PLAN §6, docs/PENTEST.md): PIE, full RELRO,
# non-executable stack, stack protection, FORTIFY.
# Usage: check-hardening.sh <executable>...
set -euo pipefail

status=0
for bin in "$@"; do
  problems=()
  readelf -h "$bin" | grep -q 'Type:.*DYN' || problems+=("not PIE")
  readelf -lW "$bin" | grep -q 'GNU_RELRO' || problems+=("no RELRO")
  readelf -dW "$bin" | grep -qE 'BIND_NOW|FLAGS.*NOW' || problems+=("partial RELRO (no BIND_NOW)")
  readelf -lW "$bin" | grep 'GNU_STACK' | grep -q 'RWE' && problems+=("executable stack")
  symbols=$(readelf -sW --dyn-syms "$bin")
  grep -q '__stack_chk_fail' <<<"$symbols" || problems+=("no stack protection")
  grep -qE '__[a-z]+_chk@' <<<"$symbols" || problems+=("no FORTIFY")
  if [ ${#problems[@]} -eq 0 ]; then
    echo "OK     $bin: PIE, full RELRO, non-executable stack, stack protection, FORTIFY"
  else
    echo "FAILED $bin: ${problems[*]}"
    status=1
  fi
done
exit "$status"
