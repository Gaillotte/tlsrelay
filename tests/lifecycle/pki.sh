#!/usr/bin/env bash
# Command-line PKI (SPEC §7.6), with the real binary:
# ca init → pki gen-csr → ca sign → pki install → pki activate, mTLS chain
# in service, verification with "openssl verify", live renewal,
# CA policy refusals, revocation (CRL) and audit log.
# Usage: pki.sh <path to tlsrelay>
set -euo pipefail

bin=$(realpath "$1")
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$work"' EXIT
cd "$work"

# Looks for a pattern in the whole output of a command (grep -q would close the pipe too early: SIGPIPE with pipefail).
has() { local out; out=$(cat); grep -q -- "$1" <<<"$out"; }
fail() { echo "FAILED: $*" >&2; exit 1; }
port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }

echo "test passphrase" > pass.txt
dest=$(port); srv=$(port); cli=$(port)

cat > server.yaml <<YAML
mode: server
instance: srv
logging: { output: $work/server.log }
credentials: { pki_root: $work/pki-server }
whitelist: { file: $work/wl.yaml }
destination: { address: 127.0.0.1, port: $dest }
admin: { endpoint: $work/srv.sock }
limits: { session_lifetime: 4s, renegotiation_grace: 1s, idle_timeout: 3s }
ports:
  mtls: { listen: "127.0.0.1:$srv" }
YAML
cat > client.yaml <<YAML
mode: client
instance: cli
logging: { output: $work/client.log }
credentials: { pki_root: $work/pki-client }
admin: { endpoint: $work/cli.sock }
limits: { session_lifetime: 4s, renegotiation_grace: 1s, idle_timeout: 3s }
ports:
  mtls: { listen: "127.0.0.1:$cli", upstream: "127.0.0.1:$srv", server_name: relay.test }
YAML
cat > wl.yaml <<YAML
peers:
  - { name: branch, ip: 127.0.0.1, ports: [mtls], subject: "CN=branch.test,O=Test" }
YAML

echo "== mini-CA"
"$bin" ca init --dir ca --org Test --passphrase-file pass.txt
[ "$(stat -c %a ca/root.key.pem)" = 600 ] || fail "root key permissions"

echo "== server: request, signing, installation, activation"
"$bin" pki gen-csr -c server.yaml --subject "CN=relay.test,O=Test" --san relay.test
"$bin" ca sign --dir ca --role server --csr pki-server/v1/request.csr --san relay.test --out kit-s --passphrase-file pass.txt
"$bin" pki install -c server.yaml --from kit-s
"$bin" pki activate -c server.yaml v1

echo "== client"
"$bin" pki gen-csr -c client.yaml --subject "CN=branch.test,O=Test"
TLSRELAY_CA_PASSPHRASE="test passphrase" \
  "$bin" ca sign --dir ca --role client --csr pki-client/v1/request.csr --out kit-c
"$bin" pki install -c client.yaml --from kit-c
"$bin" pki activate -c client.yaml v1

echo "== independent verification with OpenSSL"
openssl verify -CAfile kit-s/trust-roots.pem -untrusted kit-s/chain.pem -purpose sslserver kit-s/cert.pem
openssl verify -CAfile kit-c/trust-roots.pem -untrusted kit-c/chain.pem -purpose sslclient kit-c/cert.pem
openssl x509 -in kit-s/cert.pem -noout -ext basicConstraints,extendedKeyUsage,subjectAltName | tee ext.txt
grep -q "CA:FALSE" ext.txt && grep -q "TLS Web Server Authentication" ext.txt && grep -q "DNS:relay.test" ext.txt \
  || fail "server certificate extensions"

echo "== mTLS chain in service"
python3 "$here/echo.py" "$dest" &
"$bin" run -c server.yaml & "$bin" run -c client.yaml &
for _ in $(seq 50); do "$bin" status -c client.yaml >/dev/null 2>&1 && "$bin" status -c server.yaml >/dev/null 2>&1 && break; sleep 0.1; done
python3 "$here/exchange.py" "$cli" || fail "mTLS exchange"

echo "== live renewal of the client certificate (new key, v2)"
"$bin" pki gen-csr -c client.yaml --subject "CN=branch.test,O=Test"
if "$bin" ca sign --dir ca --role client --csr pki-client/v2/request.csr --out kit-c2 --passphrase-file pass.txt 2>err.txt; then
  fail "already assigned subject accepted without --renew"
fi
grep -q "already assigned" err.txt || fail "already assigned subject message"
"$bin" ca sign --dir ca --role client --csr pki-client/v2/request.csr --renew --out kit-c2 --passphrase-file pass.txt
"$bin" pki install -c client.yaml --from kit-c2
"$bin" pki activate -c client.yaml v2
"$bin" reload -c client.yaml | has "switched from v1 to v2" || fail "client switch"
python3 "$here/exchange.py" "$cli" || fail "exchange after renewal"
"$bin" ca list --dir ca | tee list.txt
grep -c "replaced" list.txt | has 1 || fail "inventory"

echo "== CA policy refusals"
openssl req -new -newkey rsa:2048 -nodes -keyout rsa.key -subj "/CN=rsa.test" -out rsa.csr 2>req.err \
  || fail "openssl req (RSA): $(cat req.err)"
if "$bin" ca sign --dir ca --role client --csr rsa.csr --out kit-rsa --passphrase-file pass.txt 2>err.txt; then
  fail "RSA key accepted"
fi
grep -q "P-256" err.txt || fail "RSA refusal message"
echo "wrong passphrase" > bad.txt
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout x.key -subj "/CN=x.test" -out x.csr \
  2>req.err || fail "openssl req (P-256): $(cat req.err)"
if "$bin" ca sign --dir ca --role client --csr x.csr --out kit-x --passphrase-file bad.txt 2>err.txt; then
  fail "wrong passphrase accepted"
fi
grep -q "wrong passphrase (or" err.txt || fail "passphrase message"

echo "== client certificate revocation and CRL"
serial=$(awk '$2 == "client" && $3 == "valid" { print $1 }' list.txt)
[ -n "$serial" ] || fail "client certificate serial"
"$bin" ca revoke --dir ca --serial "$serial" --reason keyCompromise --out crl.pem --passphrase-file pass.txt
openssl storeutl -noout -text -crls crl.pem | has "Key Compromise" || fail "reason missing from the CRL"
cat kit-c2/trust-roots.pem kit-c2/chain.pem crl.pem > crl-check.pem
if openssl verify -crl_check -CAfile crl-check.pem -untrusted kit-c2/chain.pem kit-c2/cert.pem >verify.txt 2>&1; then
  fail "revoked certificate accepted by openssl verify -crl_check"
fi
grep -q "revoked" verify.txt || fail "openssl verify: $(cat verify.txt)"
"$bin" pki crl -c server.yaml crl.pem
"$bin" check-pki -c server.yaml | has "CRL valid: 1 certificate" || fail "check-pki without the CRL"
for _ in $(seq 50); do "$bin" status -c server.yaml | has "CRL: 1 certificate" && break; sleep 0.1; done
"$bin" status -c server.yaml | has "CRL: 1 certificate" || fail "CRL not applied by the server"
if python3 "$here/exchange.py" "$cli" 2>/dev/null; then fail "revoked client accepted"; fi
grep -q "revoked" server.log || fail "refusal not logged"
"$bin" ca list --dir ca | has "revoked on" || fail "inventory after revocation"
"$bin" ca audit --dir ca | tee audit.txt
grep -q "hash chain intact" audit.txt || fail "audit log"
[ "$(grep -c -E '  (init|sign|revoke|crl)  ' audit.txt)" = 6 ] || fail "audit operations"
sed -i 's/revoke/revok3/' ca/audit.log
if "$bin" ca audit --dir ca >/dev/null 2>err.txt; then fail "tampered audit log not detected"; fi
grep -q "tampered with at line 5" err.txt || fail "tampered line: $(cat err.txt)"

"$bin" stop -c client.yaml >/dev/null; "$bin" stop -c server.yaml >/dev/null
echo "command-line PKI: OK"
