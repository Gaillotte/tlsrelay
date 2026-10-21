#!/usr/bin/env bash
# Dependency vulnerabilities (PLAN §5.4), on every build:
# - OpenSSL shipped on Windows (tools/build-openssl.ps1): same version and archive
#   hash as the CI OpenSSL 3.5 job, and latest patch release published on the
#   3.5 LTS branch (OpenSSL publishes its security fixes in these releases);
# - distribution OpenSSL (Linux): reports pending updates.
# Exit code 1 if a patch release is missing.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
fail=0

script="$root/tools/build-openssl.ps1"
pinned=$(sed -n "s/^ *\[string\]\\\$Version = '\([^']*\)'.*/\1/p" "$script")
pinned_sha=$(sed -n "s/^ *\[string\]\\\$Sha512 = '\([^']*\)'.*/\1/p" "$script")
ci=$(sed -n 's/^ *OPENSSL_VERSION: *//p' "$root/.github/workflows/ci.yml" | head -n 1)
ci_sha=$(sed -n 's/^ *OPENSSL_SHA512: *//p' "$root/.github/workflows/ci.yml" | head -n 1)
echo "OpenSSL shipped on Windows: $pinned (CI OpenSSL 3.5: $ci)"
if [ -z "$pinned" ] || [ "$pinned" != "$ci" ] || [ "$pinned_sha" != "$ci_sha" ]; then
  echo "FAILED: OpenSSL version or archive hash differs between tools/build-openssl.ps1 and the CI"
  fail=1
fi

branch=${pinned%.*}
latest=$(git ls-remote --tags --refs https://github.com/openssl/openssl.git "openssl-$branch.*" |
  sed -n "s#.*refs/tags/openssl-\($branch\.[0-9]*\)\$#\1#p" | sort -t. -k3,3n | tail -n 1)
if [ -z "$latest" ]; then
  echo "FAILED: published OpenSSL $branch releases not found"
  fail=1
elif [ "$latest" != "$pinned" ]; then
  echo "FAILED: OpenSSL $latest is published (shipped: $pinned); update tools/build-openssl.ps1 and the CI"
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
