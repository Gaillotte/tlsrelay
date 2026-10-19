#!/usr/bin/env bash
# Dependency vulnerabilities (PLAN §5.4), on every build:
# - OpenSSL shipped on Windows (the repository's vcpkg port): same version as the
#   CI OpenSSL 3.5 job, and latest patch release published on the
#   3.5 LTS branch (OpenSSL publishes its security fixes in these releases);
# - distribution OpenSSL (Linux): reports pending updates.
# Exit code 1 if a patch release is missing.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
fail=0

pinned=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$root/vcpkg-overlays/openssl/vcpkg.json")
ci=$(sed -n 's/^ *OPENSSL_VERSION: *//p' "$root/.github/workflows/ci.yml" | head -n 1)
echo "OpenSSL shipped on Windows: $pinned (CI OpenSSL 3.5: $ci)"
if [ "$pinned" != "$ci" ]; then
  echo "FAILED: OpenSSL versions differ between vcpkg-overlays and the CI"
  fail=1
fi

branch=${pinned%.*}
latest=$(git ls-remote --tags --refs https://github.com/openssl/openssl.git "openssl-$branch.*" |
  sed -n "s#.*refs/tags/openssl-\($branch\.[0-9]*\)\$#\1#p" | sort -t. -k3,3n | tail -n 1)
if [ -z "$latest" ]; then
  echo "FAILED: published OpenSSL $branch releases not found"
  fail=1
elif [ "$latest" != "$pinned" ]; then
  echo "FAILED: OpenSSL $latest is published (shipped: $pinned); update vcpkg-overlays/openssl and the CI"
  fail=1
else
  echo "OpenSSL $pinned: latest patch release of the $branch branch"
fi

if command -v dpkg-query >/dev/null 2>&1; then
  for pkg in libssl3t64 libssl3; do
    v=$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null || true)
    [ -n "$v" ] && { echo "distribution OpenSSL: $pkg $v"; break; }
  done
  pending=$(apt list --upgradable 2>/dev/null | grep -E '^(libssl|openssl)' || true)
  if [ -n "$pending" ]; then
    echo "WARNING: pending OpenSSL updates on this system:"
    echo "$pending"
  fi
fi

exit "$fail"
