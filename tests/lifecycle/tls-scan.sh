#!/usr/bin/env bash
# TLS configuration of ports 2 and 3 seen from outside (PLAN §5.4, sslyze and
# testssl.sh): only TLS 1.3 is accepted, with only the allowed suites
# (SPEC §3); no session resumption; compliant certificate presented;
# no known vulnerability reported.
# Usage: tls-scan.sh <path to tlsrelay>
# TESTSSL=<path to testssl.sh>: adds the testssl.sh scan.
set -euo pipefail

bin=$(realpath "$1")
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
work=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$work"' EXIT
cd "$work"
fail() { echo "FAILED: $*" >&2; exit 1; }
port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }

"$root/tools/make-test-pki.sh" pki >/dev/null 2>&1
tls=$(port); mtls=$(port)
cat > wl.yaml <<YAML
peers:
  - { name: scan, ip: 127.0.0.1, ports: [tls, mtls], subject: "CN=client.test,O=tlsrelay-test" }
YAML
cat > server.yaml <<YAML
mode: server
instance: scan
credentials: { pki_root: $work/pki/server }
whitelist: { file: $work/wl.yaml }
destination: { address: 127.0.0.1, port: 9 }
admin: { enabled: false }
logging: { output: $work/server.log }
ports:
  tls:  { listen: "127.0.0.1:$tls" }
  mtls: { listen: "127.0.0.1:$mtls" }
YAML
"$bin" run -c server.yaml &
sleep 0.5

for p in $tls $mtls; do
  # mtls port: the scanner presents the client certificate of the test PKI.
  client_auth=()
  [ "$p" = "$mtls" ] && client_auth=(--cert "$work/pki/client/v1/cert.pem" --key "$work/pki/client/v1/key.pem")
  python3 -W ignore -m sslyze "${client_auth[@]}" --json_out="scan-$p.json" --sslv2 --sslv3 --tlsv1 --tlsv1_1 --tlsv1_2 --tlsv1_3 \
    --resum --certinfo --elliptic_curves --heartbleed --robot --openssl_ccs "127.0.0.1:$p" >/dev/null || true
  python3 - "scan-$p.json" <<'PY' || fail "port $p"
import json, sys
scan = json.load(open(sys.argv[1]))["server_scan_results"][0]
assert scan["scan_status"] == "COMPLETED", scan.get("connectivity_error_trace")
r = scan["scan_result"]
allowed = {"TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_128_GCM_SHA256"}
problems = []
for proto in ["ssl_2_0", "ssl_3_0", "tls_1_0", "tls_1_1", "tls_1_2"]:
    accepted = r[f"{proto}_cipher_suites"]["result"]["accepted_cipher_suites"]
    if accepted:
        problems.append(f"{proto} accepted: {[c['cipher_suite']['name'] for c in accepted]}")
tls13 = {c["cipher_suite"]["name"] for c in r["tls_1_3_cipher_suites"]["result"]["accepted_cipher_suites"]}
if not tls13:
    problems.append("TLS 1.3 not accepted")
if tls13 - allowed:
    problems.append(f"suites not allowed: {tls13 - allowed}")
if r["heartbleed"]["result"]["is_vulnerable_to_heartbleed"]:
    problems.append("heartbleed")
if r["openssl_ccs_injection"]["result"]["is_vulnerable_to_ccs_injection"]:
    problems.append("CCS injection")
resum = r["session_resumption"]["result"]
if resum.get("session_id_resumption_result") == "FULLY_SUPPORTED" or resum.get("tls_ticket_resumption_result") == "SUCCEEDED":
    problems.append("TLS session resumption accepted")
curves = r["elliptic_curves"]["result"]
if curves and curves.get("supported_curves"):
    names = {c["name"] for c in curves["supported_curves"]}
    if names - {"X25519", "secp256r1", "prime256v1", "secp384r1"}:
        problems.append(f"unexpected groups: {names}")
print(f"{sys.argv[1]}: TLS 1.3 only, suites {sorted(tls13)}")
if problems:
    print("\n".join(problems)); sys.exit(1)
PY
done

if [ -n "${TESTSSL:-}" ]; then
  cat pki/client/v1/cert.pem pki/client/v1/key.pem > client-identity.pem
  for p in $tls $mtls; do
    mtls_opt=()
    [ "$p" = "$mtls" ] && mtls_opt=(--mtls "$work/client-identity.pem")
    "$TESTSSL" --quiet --warnings off --color 0 --sneaky "${mtls_opt[@]}" --add-ca "$work/pki/client/v1/trust-roots.pem" \
      --protocols --server-defaults \
      --vulnerable --server-preference --jsonfile "testssl-$p.json" "127.0.0.1:$p" >"testssl-$p.txt" 2>&1 || true
    python3 - "testssl-$p.json" <<'PY' || { cat "testssl-$p.txt"; fail "testssl.sh, port $p"; }
import json, sys
findings = json.load(open(sys.argv[1]))
by_id = {f["id"]: f for f in findings}
problems = []
# Protocols: TLS 1.3 offered, all others refused.
for pid in ["SSLv2", "SSLv3", "TLS1", "TLS1_1", "TLS1_2"]:
    f = by_id.get(pid)
    if f is None or not f["finding"].startswith("not offered"):
        problems.append(f"{pid}: {f['finding'] if f else 'missing from the report'}")
if not by_id.get("TLS1_3", {}).get("finding", "").startswith("offered"):
    problems.append(f"TLS1_3: {by_id.get('TLS1_3', {}).get('finding')}")
# No high or critical severity finding, and no scan error.
# Accepted deviation (docs/PENTEST.md): no CRL or OCSP, revocation goes through
# the whitelist and the retirement of PKI generations (SPEC §6 and §7).
accepted = {"cert_revocation"}
for f in findings:
    if f["id"] in accepted:
        continue
    if f["severity"] in ("HIGH", "CRITICAL") or (f["severity"] == "FATAL" and f["id"] != "scanProblem"):
        problems.append(f"{f['id']} [{f['severity']}]: {f['finding']}")
    if f["id"] == "scanProblem":
        problems.append(f"incomplete scan: {f['finding']}")
print(f"{sys.argv[1]}: {len(findings)} findings, none of high severity" if not problems else "")
if problems:
    print("\n".join(problems)); sys.exit(1)
PY
  done
fi
echo "TLS configuration of the tls and mtls ports: OK"
