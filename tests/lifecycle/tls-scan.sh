#!/usr/bin/env bash
# Configuration TLS des ports 2 et 3 vue de l'extérieur (PLAN §5, sslyze) :
# seul TLS 1.3 est accepté, avec les seules suites autorisées (SPEC §3) ;
# pas de reprise de session ; certificat présenté conforme.
# Usage : tls-scan.sh <chemin de tlsrelay>
set -euo pipefail

bin=$(realpath "$1")
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
work=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$work"' EXIT
cd "$work"
fail() { echo "ÉCHEC : $*" >&2; exit 1; }
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
credentials: { pki_root: $work/pki/serveur }
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
  # Port mtls : le scanner présente le certificat client de la PKI de test.
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
        problems.append(f"{proto} accepté : {[c['cipher_suite']['name'] for c in accepted]}")
tls13 = {c["cipher_suite"]["name"] for c in r["tls_1_3_cipher_suites"]["result"]["accepted_cipher_suites"]}
if not tls13:
    problems.append("TLS 1.3 non accepté")
if tls13 - allowed:
    problems.append(f"suites non autorisées : {tls13 - allowed}")
if r["heartbleed"]["result"]["is_vulnerable_to_heartbleed"]:
    problems.append("heartbleed")
if r["openssl_ccs_injection"]["result"]["is_vulnerable_to_ccs_injection"]:
    problems.append("injection CCS")
resum = r["session_resumption"]["result"]
if resum.get("session_id_resumption_result") == "FULLY_SUPPORTED" or resum.get("tls_ticket_resumption_result") == "SUCCEEDED":
    problems.append("reprise de session TLS acceptée")
curves = r["elliptic_curves"]["result"]
if curves and curves.get("supported_curves"):
    names = {c["name"] for c in curves["supported_curves"]}
    if names - {"X25519", "secp256r1", "prime256v1", "secp384r1"}:
        problems.append(f"groupes non attendus : {names}")
print(f"{sys.argv[1]} : TLS 1.3 seul, suites {sorted(tls13)}")
if problems:
    print("\n".join(problems)); sys.exit(1)
PY
done
echo "configuration TLS des ports tls et mtls : OK"
