#!/usr/bin/env bash
# Test of a tlsrelay Linux package on a clean distribution (container):
# installation, account and directory created, mTLS exchange between an installed
# client and server, then uninstallation (and purge for Debian).
#
# Usage, from the repository root:
#   docker run --rm -v "$PWD:/src" -w /src ubuntu:24.04 packaging/test-linux-package.sh packages
set -euo pipefail

dir=$(realpath "${1:?packages directory}")
. /etc/os-release
fail() { echo "FAILED: $*" >&2; exit 1; }
step() { echo "== $*"; }

step "installation ($PRETTY_NAME)"
case "$ID" in
  ubuntu|debian)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -q >/dev/null
    apt-get install -y -q "$dir"/tlsrelay_*.deb "$dir"/tlsrelay-testkit_*.deb >/dev/null
    kind=deb
    ;;
  rocky|rhel|almalinux|centos)
    dnf install -y -q "$dir"/tlsrelay-[0-9]*.rpm "$dir"/tlsrelay-testkit-[0-9]*.rpm >/dev/null
    kind=rpm
    ;;
  *) fail "unsupported distribution: $ID" ;;
esac

tlsrelay version
[ "$(command -v tlsrelay)" = /usr/bin/tlsrelay ] || fail "tlsrelay missing from /usr/bin"
command -v tlsrelay-testkit >/dev/null || fail "tlsrelay-testkit missing"
getent passwd tlsrelay >/dev/null || fail "tlsrelay account not created"
[ "$(stat -c '%a %U %G' /etc/tlsrelay)" = "750 root tlsrelay" ] || fail "permissions of /etc/tlsrelay: $(stat -c '%a %U %G' /etc/tlsrelay)"
# Package contents (minimized images do not install /usr/share/doc).
if [ "$kind" = deb ]; then files=$(dpkg-deb -c "$dir"/tlsrelay_*.deb); else files=$(rpm -qlp "$dir"/tlsrelay-[0-9]*.rpm); fi
grep -q 'share/doc/tlsrelay/THIRD-PARTY-NOTICES.txt' <<<"$files" || fail "third-party notices missing from the package"
grep -q 'share/doc/tlsrelay/LICENSE' <<<"$files" || fail "license missing from the package"
for f in /usr/share/doc/tlsrelay/examples/*.yaml; do
  case "$f" in *whitelist*) continue ;; esac
  tlsrelay check-config -c "$f" >/dev/null 2>&1 || true  # commented examples: paths to adapt
done

step "mTLS exchange between an installed client and server"
work=$(mktemp -d)
cd "$work"
tlsrelay-testkit pki --out pki >/dev/null
cat > wl.yaml <<'YAML'
peers:
  - { name: trial, ip: 127.0.0.1, ports: [mtls], subject: "CN=client.test,O=tlsrelay-test" }
YAML
cat > server.yaml <<YAML
mode: server
instance: trial-server
admin: { endpoint: $work/server.sock }
logging: { output: $work/server.log }
credentials: { pki_root: $work/pki/server }
whitelist: { file: $work/wl.yaml }
destination: { address: 127.0.0.1, port: 28080 }
ports:
  mtls: { listen: "127.0.0.1:29003" }
YAML
cat > client.yaml <<YAML
mode: client
instance: trial-client
admin: { endpoint: $work/client.sock }
logging: { output: $work/client.log }
credentials: { pki_root: $work/pki/client }
ports:
  mtls: { listen: "127.0.0.1:27003", upstream: "127.0.0.1:29003", server_name: relay.test }
YAML
tlsrelay-testkit echo --listen 127.0.0.1:28080 >/dev/null &
tlsrelay run -c server.yaml & tlsrelay run -c client.yaml &
for _ in $(seq 50); do tlsrelay status -c client.yaml >/dev/null 2>&1 && tlsrelay status -c server.yaml >/dev/null 2>&1 && break; sleep 0.1; done
tlsrelay-testkit load --target 127.0.0.1:27003 --channels 50 --bytes 256KiB || { tail -n 20 server.log client.log; fail "mTLS exchange"; }
tlsrelay stop -c client.yaml >/dev/null
tlsrelay stop -c server.yaml >/dev/null
kill %1 2>/dev/null || true
wait 2>/dev/null || true
cd / && rm -rf "$work"

step "uninstallation"
if [ "$kind" = deb ]; then
  apt-get purge -y -q tlsrelay-testkit tlsrelay >/dev/null
else
  dnf remove -y -q tlsrelay-testkit tlsrelay >/dev/null
fi
[ ! -e /usr/bin/tlsrelay ] || fail "binary still present"
[ -d /etc/tlsrelay ] || fail "/etc/tlsrelay removed (configurations and PKI must be kept)"
echo "$kind package on $PRETTY_NAME: OK"
