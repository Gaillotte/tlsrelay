#!/usr/bin/env bash
# Vulnérabilités des dépendances (PLAN §5.4), à chaque build :
# - OpenSSL livré sous Windows (port vcpkg du dépôt) : même version que le job
#   OpenSSL 3.5 de la CI, et dernière version corrective publiée de la branche
#   3.5 LTS (OpenSSL publie ses correctifs de sécurité dans ces versions) ;
# - OpenSSL de la distribution (Linux) : signale les mises à jour en attente.
# Code de sortie 1 si une version corrective manque.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
fail=0

pinned=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$root/vcpkg-overlays/openssl/vcpkg.json")
ci=$(sed -n 's/^ *OPENSSL_VERSION: *//p' "$root/.github/workflows/ci.yml" | head -n 1)
echo "OpenSSL livré sous Windows : $pinned (CI OpenSSL 3.5 : $ci)"
if [ "$pinned" != "$ci" ]; then
  echo "ÉCHEC : versions d'OpenSSL différentes entre vcpkg-overlays et la CI"
  fail=1
fi

branch=${pinned%.*}
latest=$(git ls-remote --tags --refs https://github.com/openssl/openssl.git "openssl-$branch.*" |
  sed -n "s#.*refs/tags/openssl-\($branch\.[0-9]*\)\$#\1#p" | sort -t. -k3,3n | tail -n 1)
if [ -z "$latest" ]; then
  echo "ÉCHEC : versions publiées d'OpenSSL $branch introuvables"
  fail=1
elif [ "$latest" != "$pinned" ]; then
  echo "ÉCHEC : OpenSSL $latest est publié (livré : $pinned) ; mettre à jour vcpkg-overlays/openssl et la CI"
  fail=1
else
  echo "OpenSSL $pinned : dernière version corrective de la branche $branch"
fi

if command -v dpkg-query >/dev/null 2>&1; then
  for pkg in libssl3t64 libssl3; do
    v=$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null || true)
    [ -n "$v" ] && { echo "OpenSSL de la distribution : $pkg $v"; break; }
  done
  pending=$(apt list --upgradable 2>/dev/null | grep -E '^(libssl|openssl)' || true)
  if [ -n "$pending" ]; then
    echo "AVERTISSEMENT : mises à jour d'OpenSSL en attente sur ce système :"
    echo "$pending"
  fi
fi

exit "$fail"
