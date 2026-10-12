#!/usr/bin/env bash
# Durcissement des exécutables Linux (PLAN §6, docs/PENTEST.md) : PIE, RELRO
# complet, pile non exécutable, protection de pile, FORTIFY.
# Usage : check-hardening.sh <exécutable>...
set -euo pipefail

status=0
for bin in "$@"; do
  problems=()
  readelf -h "$bin" | grep -q 'Type:.*DYN' || problems+=("pas PIE")
  readelf -lW "$bin" | grep -q 'GNU_RELRO' || problems+=("pas de RELRO")
  readelf -dW "$bin" | grep -qE 'BIND_NOW|FLAGS.*NOW' || problems+=("RELRO partiel (pas de BIND_NOW)")
  readelf -lW "$bin" | grep 'GNU_STACK' | grep -q 'RWE' && problems+=("pile exécutable")
  symbols=$(readelf -sW --dyn-syms "$bin")
  grep -q '__stack_chk_fail' <<<"$symbols" || problems+=("pas de protection de pile")
  grep -qE '__[a-z]+_chk@' <<<"$symbols" || problems+=("pas de FORTIFY")
  if [ ${#problems[@]} -eq 0 ]; then
    echo "OK    $bin : PIE, RELRO complet, pile non exécutable, protection de pile, FORTIFY"
  else
    echo "ÉCHEC $bin : ${problems[*]}"
    status=1
  fi
done
exit "$status"
