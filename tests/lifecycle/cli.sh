#!/usr/bin/env bash
# Command-line refusals and edge cases (TESTS.md §6.4, CT-08 and CT-09),
# with the real binary: each command prints its message and exits with its
# code (0 success, 1 runtime error, 2 configuration rejected).
# Also covers entering the CA passphrase (pipe and terminal).
# Installs no service: only the refusals that precede installation are tested.
# Usage: cli.sh <path to tlsrelay>
set -euo pipefail

bin=$(realpath "$1")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
unset TLSRELAY_CA_PASSPHRASE

fail() { echo "FAILED: $*" >&2; exit 1; }
# expect <code> <pattern> <command...>: exit code and pattern (standard output and error combined).
expect() {
  local code=$1 pattern=$2 out rc=0
  shift 2
  out=$("$@" 2>&1) || rc=$?
  [ "$rc" = "$code" ] || fail "$*: code $rc, expected $code"$'\n'"$out"
  grep -q -- "$pattern" <<<"$out" || fail "$*: \"$pattern\" missing"$'\n'"$out"
}

echo "test passphrase" > pass.txt
echo "another passphrase" > pass2.txt

cat > server.yaml <<YAML
mode: server
instance: srv
credentials: { pki_root: $work/pki-server }
whitelist: { file: $work/wl.yaml }
destination: { address: 127.0.0.1, port: 9 }
admin: { endpoint: $work/srv.sock }
ports:
  mtls: { listen: "127.0.0.1:1" }
YAML
cat > plain.yaml <<YAML
mode: server
instance: plaintext
whitelist: { file: $work/wl.yaml }
destination: { address: 127.0.0.1, port: 9 }
admin: { endpoint: $work/plaintext.sock }
ports:
  plain: { listen: "127.0.0.1:1" }
YAML
cat > tls-server.yaml <<YAML
mode: server
instance: tlsonly
credentials: { pki_root: $work/pki-tls }
whitelist: { file: $work/wl.yaml }
destination: { address: 127.0.0.1, port: 9 }
ports:
  tls: { listen: "127.0.0.1:1" }
YAML
cat > tls-client.yaml <<YAML
mode: client
instance: tlsclient
credentials: { pki_root: $work/pki-empty }
ports:
  tls: { listen: "127.0.0.1:1", upstream: "127.0.0.1:2", server_name: relay.test }
YAML
printf 'mode: server\nports: { plain: { listen: "0.0.0.0:99999" } }\n' > invalid.yaml
printf 'peers:\n  - { name: branch, ip: 127.0.0.1, ports: [mtls], subject: "CN=branch.test,O=Test" }\n' > wl.yaml

echo "== version and check-config"
expect 0 "OpenSSL" "$bin" version
expect 0 "valid configuration" "$bin" check-config -c server.yaml
expect 2 "error(s) in" "$bin" check-config -c invalid.yaml

echo "== CA and server PKI"
"$bin" ca init --dir ca --org Test --passphrase-file pass.txt >/dev/null
"$bin" ca init --dir ca2 --org Other --passphrase-file pass2.txt >/dev/null
"$bin" pki gen-csr -c server.yaml --subject "CN=relay.test,O=Test" --san relay.test >/dev/null
"$bin" ca sign --dir ca --role server --csr pki-server/v1/request.csr --san relay.test --out kit1 \
  --passphrase-file pass.txt >/dev/null
"$bin" pki install -c server.yaml --from kit1 >/dev/null
"$bin" pki activate -c server.yaml v1 >/dev/null
expect 0 "generation \"v1\" valid" "$bin" check-pki -c server.yaml

echo "== instance PKI command refusals"
expect 2 "no tls or mtls port" "$bin" check-pki -c plain.yaml
expect 2 "does not present a certificate" "$bin" pki gen-csr -c tls-client.yaml --subject "CN=x"
expect 2 "invalid IP address" "$bin" pki gen-csr -c server.yaml --subject "CN=relay.test" --san IP:999.1.1.1
expect 2 "generation \"v9\" rejected" "$bin" check-pki -c server.yaml v9
# New identity issued by another root: rejected by the safeguard.
"$bin" pki gen-csr -c server.yaml --subject "CN=relay.test,O=Other" --san relay.test >/dev/null
"$bin" ca sign --dir ca2 --role server --csr pki-server/v2/request.csr --san relay.test --out kit2 \
  --passphrase-file pass2.txt >/dev/null
expect 2 "installed but rejected" "$bin" pki install -c server.yaml --from kit2
expect 2 "not activated (--force" "$bin" pki activate -c server.yaml v2
expect 0 "generation \"v2\" activated" "$bin" pki activate -c server.yaml v2 --force
"$bin" pki activate -c server.yaml v1 --force >/dev/null 2>&1

echo "== CRL"
expect 2 "CRL not applicable" "$bin" pki crl -c tls-server.yaml whatever.pem
echo "not a CRL" > bogus.pem
expect 2 "CRL rejected: bogus.pem" "$bin" pki crl -c server.yaml bogus.pem
expect 2 "error" "$bin" pki crl -c tls-client.yaml bogus.pem
"$bin" ca crl --dir ca --out crl.pem --passphrase-file pass.txt >/dev/null
expect 0 "CRL installed" "$bin" pki crl -c server.yaml crl.pem
expect 0 "CRL valid" "$bin" check-pki -c server.yaml
cp bogus.pem pki-server/crl.pem
expect 2 "CRL rejected" "$bin" check-pki -c server.yaml
rm pki-server/crl.pem

echo "== mini-CA: refusals"
expect 2 "unknown reason" "$bin" ca revoke --dir ca --serial 01 --reason forgotten --passphrase-file pass.txt
expect 1 "error" "$bin" ca revoke --dir ca --serial 0123456789 --passphrase-file pass.txt
expect 1 "cannot read" "$bin" ca sign --dir ca --role client --csr absent.csr --out kit3 --passphrase-file pass.txt
expect 2 "invalid IP address" "$bin" ca sign --dir ca --role server --csr pki-server/v1/request.csr \
  --san IP:999.1.1.1 --out kit3 --passphrase-file pass.txt
expect 1 "error" "$bin" ca root-change --dir ca --new missing --out transition
expect 0 "README.txt" "$bin" ca root-change --dir ca --new ca2 --out transition
[ -f transition/README.txt ] && [ -d transition/server ] && [ -d transition/client ] || fail "transition files"
expect 1 "error" "$bin" ca list --dir missing
expect 1 "error" "$bin" ca audit --dir missing

echo "== CA passphrase"
expect 0 "CA created" sh -c "printf 'test phrase 1234\ntest phrase 1234\n' | '$bin' ca init --dir cap"
expect 1 "the two entries differ" sh -c "printf 'test phrase 1234\nother phrase 123\n' | '$bin' ca init --dir caq"
[ ! -e caq/root.key.pem ] || fail "CA created despite two different entries"
expect 1 "" sh -c "'$bin' ca init --dir car </dev/null"
expect 1 "unreadable passphrase" "$bin" ca init --dir cas --passphrase-file absent.txt
if command -v script >/dev/null; then
  # Terminal: entry without echo; the passphrase does not appear in the output. Each line
  # is typed after the prompt (input typed ahead is discarded when echo is turned off).
  out=$( (sleep 1; printf 'secret phrase 12\n'; sleep 1; printf 'secret phrase 12\n'; sleep 1) \
          | script -qec "'$bin' ca init --dir cat" /dev/null 2>&1) \
    || fail "ca init in a terminal"$'\n'"$out"
  grep -q "CA created" <<<"$out" || fail "ca init in a terminal"$'\n'"$out"
  ! grep -q "secret phrase" <<<"$out" || fail "passphrase shown in the terminal"
fi

echo "== commands to an instance"
expect 2 "belongs to instance \"srv\"" "$bin" run -c server.yaml --instance other
expect 2 "invalid timeout" "$bin" stop -c server.yaml --timeout abc
expect 0 "already stopped" "$bin" stop -c server.yaml
expect 0 "already stopped" "$bin" kill -c server.yaml
expect 2 "error" "$bin" status -c invalid.yaml
expect 1 "unreachable" "$bin" status --admin "$work/absent.sock"

echo "== service manager: refusals before installation"
expect 2 "invalid instance name" "$bin" start --instance "invalid name"
expect 2 "invalid timeout" "$bin" start --instance missing --timeout abc
expect 1 "is not installed" "$bin" start --instance missing-cli
expect 1 "is not installed" "$bin" restart --instance missing-cli
expect 2 "invalid instance name" "$bin" service install --instance "invalid name"
expect 2 "declares instance \"srv\"" "$bin" service install --instance other -c server.yaml
expect 2 "remove admin.endpoint" "$bin" service install --instance srv -c server.yaml
expect 2 "error" "$bin" service install --instance srv -c invalid.yaml
expect 2 "invalid instance name" "$bin" service uninstall --instance "invalid name"
expect 1 "error" "$bin" service uninstall --instance missing-cli

echo "cli.sh : OK"
