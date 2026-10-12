#!/usr/bin/env bash
# PKI en ligne de commande (SPEC §7.6), avec le binaire réel :
# ca init → pki gen-csr → ca sign → pki install → pki activate, chaîne mTLS
# en service, vérification par « openssl verify », renouvellement à chaud,
# refus de la politique de l'AC, révocation (CRL) et journal d'audit.
# Usage : pki.sh <chemin de tlsrelay>
set -euo pipefail

bin=$(realpath "$1")
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$work"' EXIT
cd "$work"

# Cherche un motif dans toute la sortie d'une commande (grep -q fermerait le tube trop tôt : SIGPIPE avec pipefail).
has() { local out; out=$(cat); grep -q -- "$1" <<<"$out"; }
fail() { echo "ÉCHEC : $*" >&2; exit 1; }
port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }

echo "phrase de passe d'essai" > pass.txt
dest=$(port); srv=$(port); cli=$(port)

cat > server.yaml <<YAML
mode: server
instance: srv
logging: { output: $work/server.log }
credentials: { pki_root: $work/pki-serveur }
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
  mtls: { listen: "127.0.0.1:$cli", upstream: "127.0.0.1:$srv", server_name: relay.essai }
YAML
cat > wl.yaml <<YAML
peers:
  - { name: agence, ip: 127.0.0.1, ports: [mtls], subject: "CN=agence.essai,O=Essai" }
YAML

echo "== mini-AC"
"$bin" ca init --dir ac --org Essai --passphrase-file pass.txt
[ "$(stat -c %a ac/root.key.pem)" = 600 ] || fail "droits de la clé racine"

echo "== serveur : demande, signature, installation, activation"
"$bin" pki gen-csr -c server.yaml --subject "CN=relay.essai,O=Essai" --san relay.essai
"$bin" ca sign --dir ac --role server --csr pki-serveur/v1/request.csr --san relay.essai --out kit-s --passphrase-file pass.txt
"$bin" pki install -c server.yaml --from kit-s
"$bin" pki activate -c server.yaml v1

echo "== client"
"$bin" pki gen-csr -c client.yaml --subject "CN=agence.essai,O=Essai"
TLSRELAY_CA_PASSPHRASE="phrase de passe d'essai" \
  "$bin" ca sign --dir ac --role client --csr pki-client/v1/request.csr --out kit-c
"$bin" pki install -c client.yaml --from kit-c
"$bin" pki activate -c client.yaml v1

echo "== vérification indépendante par OpenSSL"
openssl verify -CAfile kit-s/trust-roots.pem -untrusted kit-s/chain.pem -purpose sslserver kit-s/cert.pem
openssl verify -CAfile kit-c/trust-roots.pem -untrusted kit-c/chain.pem -purpose sslclient kit-c/cert.pem
openssl x509 -in kit-s/cert.pem -noout -ext basicConstraints,extendedKeyUsage,subjectAltName | tee ext.txt
grep -q "CA:FALSE" ext.txt && grep -q "TLS Web Server Authentication" ext.txt && grep -q "DNS:relay.essai" ext.txt \
  || fail "extensions du certificat serveur"

echo "== chaîne mTLS en service"
python3 "$here/echo.py" "$dest" &
"$bin" run -c server.yaml & "$bin" run -c client.yaml &
for _ in $(seq 50); do "$bin" status -c client.yaml >/dev/null 2>&1 && "$bin" status -c server.yaml >/dev/null 2>&1 && break; sleep 0.1; done
python3 "$here/exchange.py" "$cli" || fail "échange mTLS"

echo "== renouvellement à chaud du certificat client (nouvelle clé, v2)"
"$bin" pki gen-csr -c client.yaml --subject "CN=agence.essai,O=Essai"
if "$bin" ca sign --dir ac --role client --csr pki-client/v2/request.csr --out kit-c2 --passphrase-file pass.txt 2>err.txt; then
  fail "sujet déjà attribué accepté sans --renew"
fi
grep -q "déjà attribué" err.txt || fail "message de sujet déjà attribué"
"$bin" ca sign --dir ac --role client --csr pki-client/v2/request.csr --renew --out kit-c2 --passphrase-file pass.txt
"$bin" pki install -c client.yaml --from kit-c2
"$bin" pki activate -c client.yaml v2
"$bin" reload -c client.yaml | has "bascule de v1 vers v2" || fail "bascule du client"
python3 "$here/exchange.py" "$cli" || fail "échange après renouvellement"
"$bin" ca list --dir ac | tee list.txt
grep -c "remplacé" list.txt | has 1 || fail "inventaire"

echo "== refus de la politique de l'AC"
openssl req -new -newkey rsa:2048 -nodes -keyout rsa.key -subj "/CN=rsa.essai" -out rsa.csr 2>req.err \
  || fail "openssl req (RSA) : $(cat req.err)"
if "$bin" ca sign --dir ac --role client --csr rsa.csr --out kit-rsa --passphrase-file pass.txt 2>err.txt; then
  fail "clé RSA acceptée"
fi
grep -q "P-256" err.txt || fail "message de refus RSA"
echo "mauvaise phrase de passe" > bad.txt
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout x.key -subj "/CN=x.essai" -out x.csr \
  2>req.err || fail "openssl req (P-256) : $(cat req.err)"
if "$bin" ca sign --dir ac --role client --csr x.csr --out kit-x --passphrase-file bad.txt 2>err.txt; then
  fail "mauvaise phrase de passe acceptée"
fi
grep -q "phrase de passe incorrecte" err.txt || fail "message de phrase de passe"

echo "== révocation du certificat client et CRL"
serial=$(awk '$2 == "client" && $3 == "valide" { print $1 }' list.txt)
[ -n "$serial" ] || fail "série du certificat client"
"$bin" ca revoke --dir ac --serial "$serial" --reason keyCompromise --out crl.pem --passphrase-file pass.txt
openssl storeutl -noout -text -crls crl.pem | has "Key Compromise" || fail "motif absent de la CRL"
cat kit-c2/trust-roots.pem kit-c2/chain.pem crl.pem > crl-check.pem
if openssl verify -crl_check -CAfile crl-check.pem -untrusted kit-c2/chain.pem kit-c2/cert.pem >verify.txt 2>&1; then
  fail "certificat révoqué accepté par openssl verify -crl_check"
fi
grep -q "revoked" verify.txt || fail "openssl verify : $(cat verify.txt)"
"$bin" pki crl -c server.yaml crl.pem
"$bin" check-pki -c server.yaml | has "CRL valide : 1 certificat" || fail "check-pki sans la CRL"
for _ in $(seq 50); do "$bin" status -c server.yaml | has "CRL : 1 certificat" && break; sleep 0.1; done
"$bin" status -c server.yaml | has "CRL : 1 certificat" || fail "CRL non prise en compte par le serveur"
if python3 "$here/exchange.py" "$cli" 2>/dev/null; then fail "client révoqué accepté"; fi
grep -q "révoqué" server.log || fail "refus non journalisé"
"$bin" ca list --dir ac | has "révoqué le" || fail "inventaire après révocation"
"$bin" ca audit --dir ac | tee audit.txt
grep -q "chaîne d'empreintes intacte" audit.txt || fail "journal d'audit"
[ "$(grep -c -E '  (init|sign|revoke|crl)  ' audit.txt)" = 6 ] || fail "opérations d'audit"
sed -i 's/revoke/revok3/' ac/audit.log
if "$bin" ca audit --dir ac >/dev/null 2>err.txt; then fail "journal d'audit altéré non détecté"; fi
grep -q "altéré à la ligne 5" err.txt || fail "ligne altérée : $(cat err.txt)"

"$bin" stop -c client.yaml >/dev/null; "$bin" stop -c server.yaml >/dev/null
echo "PKI en ligne de commande : OK"
