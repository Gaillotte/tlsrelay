#!/usr/bin/env bash
# Creates a TEST PKI to try tlsrelay with TLS (SPEC §7):
#   root (P-384) -> Servers CA / Clients CA (P-384) -> certificates (P-256)
# and two ready-to-use directories:
#   <directory>/server : pki_root of a server tlsrelay
#   <directory>/client : pki_root of a client tlsrelay
#
# Usage: tools/make-test-pki.sh <directory> [server name, default relay.test]
#
# WARNING: unencrypted keys, CA kept in <directory>/ca. For trials
# only; in production, use the mini-CA (phase 7) or tlsrelay-admin.
set -euo pipefail

out=${1:?usage: $0 <directory> [server name]}
server_name=${2:-relay.test}
ca="$out/ca"
mkdir -p "$ca"
cd "$ca"

ext() { printf '%s\n' "$@" > "$1.ext.tmp"; }

key() { openssl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:$2" -out "$1.key" 2>/dev/null; }

# Root
key root P-384
openssl req -x509 -new -key root.key -sha384 -days 5475 -subj "/O=tlsrelay-test/CN=Test root" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" -out root.pem

# Signs <name>.csr with the <issuer> CA; extensions in <name>.ext
sign() {
  openssl x509 -req -in "$1.csr" -CA "$2.pem" -CAkey "$2.key" -CAcreateserial -sha384 -days "$3" \
    -extfile "$1.ext" -out "$1.pem" 2>/dev/null
  rm -f "$1.csr"
}

for role in servers clients; do
  key "ca-$role" P-384
  openssl req -new -key "ca-$role.key" -subj "/O=tlsrelay-test/CN=Test ${role^} CA" -out "ca-$role.csr"
  usage=$([ "$role" = servers ] && echo serverAuth || echo clientAuth)
  printf '%s\n' "basicConstraints=critical,CA:TRUE,pathlen:0" "keyUsage=critical,keyCertSign,cRLSign" \
    "extendedKeyUsage=$usage" "subjectKeyIdentifier=hash" "authorityKeyIdentifier=keyid:always" > "ca-$role.ext"
  sign "ca-$role" root 1825
done

key server P-256
openssl req -new -key server.key -subj "/O=tlsrelay-test/CN=$server_name" -out server.csr
printf '%s\n' "basicConstraints=critical,CA:FALSE" "keyUsage=critical,digitalSignature" "extendedKeyUsage=serverAuth" \
  "subjectAltName=DNS:$server_name,IP:127.0.0.1" "subjectKeyIdentifier=hash" "authorityKeyIdentifier=keyid:always" > server.ext
sign server ca-servers 365

key client P-256
openssl req -new -key client.key -subj "/O=tlsrelay-test/CN=client.test" -out client.csr
printf '%s\n' "basicConstraints=critical,CA:FALSE" "keyUsage=critical,digitalSignature" "extendedKeyUsage=clientAuth" \
  "subjectKeyIdentifier=hash" "authorityKeyIdentifier=keyid:always" > client.ext
sign client ca-clients 365

rm -f ./*.ext ./*.srl ./*.tmp
cd - >/dev/null

# Generation directories (SPEC §7.2)
install_generation() {  # <pki_root> <key> <cert> <chain> <CA expected from the peer>
  local dir="$1/v1"
  mkdir -p "$dir"
  cp "$ca/$2.key" "$dir/key.pem"
  cp "$ca/$3.pem" "$dir/cert.pem"
  cp "$ca/$4.pem" "$dir/chain.pem"
  cp "$ca/root.pem" "$dir/trust-roots.pem"
  cp "$ca/$5.pem" "$dir/trust-issuer.pem"
  chmod 600 "$dir/key.pem"
  echo v1 > "$1/current"
}
install_generation "$out/server" server server ca-servers ca-clients
install_generation "$out/client" client client ca-clients ca-servers

echo "test PKI created in $out:"
echo "  server: credentials.pki_root: $out/server   (certificate CN=$server_name)"
echo "  client: credentials.pki_root: $out/client   (server_name: $server_name)"
