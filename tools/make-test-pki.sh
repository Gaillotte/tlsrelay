#!/usr/bin/env bash
# Crée une PKI de TEST pour essayer tlsrelay en TLS (SPEC §7) :
#   racine (P-384) -> AC Serveurs / AC Clients (P-384) -> certificats (P-256)
# et deux répertoires prêts à l'emploi :
#   <dossier>/serveur : pki_root d'un tlsrelay serveur
#   <dossier>/client  : pki_root d'un tlsrelay client
#
# Usage : tools/make-test-pki.sh <dossier> [nom du serveur, défaut relay.test]
#
# ATTENTION : clés non chiffrées, AC conservée dans <dossier>/ac. Réservé aux
# essais ; en production, utiliser la mini-AC (phase 7) ou tlsrelay-admin.
set -euo pipefail

out=${1:?usage : $0 <dossier> [nom du serveur]}
server_name=${2:-relay.test}
ca="$out/ac"
mkdir -p "$ca"
cd "$ca"

ext() { printf '%s\n' "$@" > "$1.ext.tmp"; }

key() { openssl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:$2" -out "$1.key" 2>/dev/null; }

# Racine
key racine P-384
openssl req -x509 -new -key racine.key -sha384 -days 5475 -subj "/O=tlsrelay-test/CN=Racine de test" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" -out racine.pem

# Signe <nom>.csr avec l'AC <signataire> ; extensions dans <nom>.ext
sign() {
  openssl x509 -req -in "$1.csr" -CA "$2.pem" -CAkey "$2.key" -CAcreateserial -sha384 -days "$3" \
    -extfile "$1.ext" -out "$1.pem" 2>/dev/null
  rm -f "$1.csr"
}

for role in serveurs clients; do
  key "ac-$role" P-384
  openssl req -new -key "ac-$role.key" -subj "/O=tlsrelay-test/CN=AC ${role^} de test" -out "ac-$role.csr"
  usage=$([ "$role" = serveurs ] && echo serverAuth || echo clientAuth)
  printf '%s\n' "basicConstraints=critical,CA:TRUE,pathlen:0" "keyUsage=critical,keyCertSign,cRLSign" \
    "extendedKeyUsage=$usage" "subjectKeyIdentifier=hash" "authorityKeyIdentifier=keyid:always" > "ac-$role.ext"
  sign "ac-$role" racine 1825
done

key serveur P-256
openssl req -new -key serveur.key -subj "/O=tlsrelay-test/CN=$server_name" -out serveur.csr
printf '%s\n' "basicConstraints=critical,CA:FALSE" "keyUsage=critical,digitalSignature" "extendedKeyUsage=serverAuth" \
  "subjectAltName=DNS:$server_name,IP:127.0.0.1" "subjectKeyIdentifier=hash" "authorityKeyIdentifier=keyid:always" > serveur.ext
sign serveur ac-serveurs 365

key client P-256
openssl req -new -key client.key -subj "/O=tlsrelay-test/CN=client.test" -out client.csr
printf '%s\n' "basicConstraints=critical,CA:FALSE" "keyUsage=critical,digitalSignature" "extendedKeyUsage=clientAuth" \
  "subjectKeyIdentifier=hash" "authorityKeyIdentifier=keyid:always" > client.ext
sign client ac-clients 365

rm -f ./*.ext ./*.srl ./*.tmp
cd - >/dev/null

# Répertoires de génération (SPEC §7.2)
install_generation() {  # <pki_root> <clé> <cert> <chaîne> <AC attendue chez le pair>
  local dir="$1/v1"
  mkdir -p "$dir"
  cp "$ca/$2.key" "$dir/key.pem"
  cp "$ca/$3.pem" "$dir/cert.pem"
  cp "$ca/$4.pem" "$dir/chain.pem"
  cp "$ca/racine.pem" "$dir/trust-roots.pem"
  cp "$ca/$5.pem" "$dir/trust-issuer.pem"
  chmod 600 "$dir/key.pem"
  echo v1 > "$1/current"
}
install_generation "$out/serveur" serveur serveur ac-serveurs ac-clients
install_generation "$out/client" client client ac-clients ac-serveurs

echo "PKI de test créée dans $out :"
echo "  serveur : credentials.pki_root: $out/serveur   (certificat CN=$server_name)"
echo "  client  : credentials.pki_root: $out/client    (server_name: $server_name)"
