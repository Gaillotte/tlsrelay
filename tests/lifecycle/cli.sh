#!/usr/bin/env bash
# Refus et cas limites de la ligne de commande (TESTS.md §6.4, CT-08 et CT-09),
# avec le binaire réel : chaque commande affiche son message et sort avec son
# code (0 succès, 1 erreur d'exécution, 2 configuration refusée).
# Couvre aussi la saisie de la phrase de passe de l'AC (tube et terminal).
# N'installe aucun service : seuls les refus qui précèdent l'installation sont testés.
# Usage : cli.sh <chemin de tlsrelay>
set -euo pipefail

bin=$(realpath "$1")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
unset TLSRELAY_CA_PASSPHRASE

fail() { echo "ÉCHEC : $*" >&2; exit 1; }
# expect <code> <motif> <commande...> : code de sortie et motif (sortie standard et d'erreur réunies).
expect() {
  local code=$1 pattern=$2 out rc=0
  shift 2
  out=$("$@" 2>&1) || rc=$?
  [ "$rc" = "$code" ] || fail "$* : code $rc, $code attendu"$'\n'"$out"
  grep -q -- "$pattern" <<<"$out" || fail "$* : « $pattern » absent"$'\n'"$out"
}

echo "phrase de passe d'essai" > pass.txt
echo "autre phrase de passe" > pass2.txt

cat > server.yaml <<YAML
mode: server
instance: srv
credentials: { pki_root: $work/pki-serveur }
whitelist: { file: $work/wl.yaml }
destination: { address: 127.0.0.1, port: 9 }
admin: { endpoint: $work/srv.sock }
ports:
  mtls: { listen: "127.0.0.1:1" }
YAML
cat > plain.yaml <<YAML
mode: server
instance: clair
whitelist: { file: $work/wl.yaml }
destination: { address: 127.0.0.1, port: 9 }
admin: { endpoint: $work/clair.sock }
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
credentials: { pki_root: $work/pki-vide }
ports:
  tls: { listen: "127.0.0.1:1", upstream: "127.0.0.1:2", server_name: relay.essai }
YAML
printf 'mode: server\nports: { plain: { listen: "0.0.0.0:99999" } }\n' > invalide.yaml
printf 'peers:\n  - { name: agence, ip: 127.0.0.1, ports: [mtls], subject: "CN=agence.essai,O=Essai" }\n' > wl.yaml

echo "== version et check-config"
expect 0 "OpenSSL" "$bin" version
expect 0 "configuration valide" "$bin" check-config -c server.yaml
expect 2 "erreur(s) dans" "$bin" check-config -c invalide.yaml

echo "== AC et PKI du serveur"
"$bin" ca init --dir ac --org Essai --passphrase-file pass.txt >/dev/null
"$bin" ca init --dir ac2 --org Autre --passphrase-file pass2.txt >/dev/null
"$bin" pki gen-csr -c server.yaml --subject "CN=relay.essai,O=Essai" --san relay.essai >/dev/null
"$bin" ca sign --dir ac --role server --csr pki-serveur/v1/request.csr --san relay.essai --out kit1 \
  --passphrase-file pass.txt >/dev/null
"$bin" pki install -c server.yaml --from kit1 >/dev/null
"$bin" pki activate -c server.yaml v1 >/dev/null
expect 0 "génération « v1 » valide" "$bin" check-pki -c server.yaml

echo "== refus des commandes PKI d'instance"
expect 2 "aucun port tls ou mtls" "$bin" check-pki -c plain.yaml
expect 2 "ne présente pas de certificat" "$bin" pki gen-csr -c tls-client.yaml --subject "CN=x"
expect 2 "adresse IP invalide" "$bin" pki gen-csr -c server.yaml --subject "CN=relay.essai" --san IP:999.1.1.1
expect 2 "génération « v9 » refusée" "$bin" check-pki -c server.yaml v9
# Nouvelle identité émise par une autre racine : refusée par le garde-fou.
"$bin" pki gen-csr -c server.yaml --subject "CN=relay.essai,O=Autre" --san relay.essai >/dev/null
"$bin" ca sign --dir ac2 --role server --csr pki-serveur/v2/request.csr --san relay.essai --out kit2 \
  --passphrase-file pass2.txt >/dev/null
expect 2 "installée mais refusée" "$bin" pki install -c server.yaml --from kit2
expect 2 "non activée (--force" "$bin" pki activate -c server.yaml v2
expect 0 "génération « v2 » activée" "$bin" pki activate -c server.yaml v2 --force
"$bin" pki activate -c server.yaml v1 --force >/dev/null 2>&1

echo "== CRL"
expect 2 "CRL sans objet" "$bin" pki crl -c tls-server.yaml whatever.pem
echo "pas une CRL" > faux.pem
expect 2 "CRL refusée : faux.pem" "$bin" pki crl -c server.yaml faux.pem
expect 2 "erreur" "$bin" pki crl -c tls-client.yaml faux.pem
"$bin" ca crl --dir ac --out crl.pem --passphrase-file pass.txt >/dev/null
expect 0 "CRL installée" "$bin" pki crl -c server.yaml crl.pem
expect 0 "CRL valide" "$bin" check-pki -c server.yaml
cp faux.pem pki-serveur/crl.pem
expect 2 "CRL refusée" "$bin" check-pki -c server.yaml
rm pki-serveur/crl.pem

echo "== mini-AC : refus"
expect 2 "motif inconnu" "$bin" ca revoke --dir ac --serial 01 --reason oubli --passphrase-file pass.txt
expect 1 "erreur" "$bin" ca revoke --dir ac --serial 0123456789 --passphrase-file pass.txt
expect 1 "lecture impossible" "$bin" ca sign --dir ac --role client --csr absent.csr --out kit3 --passphrase-file pass.txt
expect 2 "adresse IP invalide" "$bin" ca sign --dir ac --role server --csr pki-serveur/v1/request.csr \
  --san IP:999.1.1.1 --out kit3 --passphrase-file pass.txt
expect 1 "erreur" "$bin" ca root-change --dir ac --new absente --out transition
expect 0 "LISEZMOI.txt" "$bin" ca root-change --dir ac --new ac2 --out transition
[ -f transition/LISEZMOI.txt ] && [ -d transition/serveur ] && [ -d transition/client ] || fail "fichiers de transition"
expect 1 "erreur" "$bin" ca list --dir absente
expect 1 "erreur" "$bin" ca audit --dir absente

echo "== phrase de passe de l'AC"
expect 0 "AC créée" sh -c "printf 'phrase de test 12\nphrase de test 12\n' | '$bin' ca init --dir acp"
expect 1 "les deux saisies diffèrent" sh -c "printf 'phrase de test 12\nautre phrase 1234\n' | '$bin' ca init --dir acq"
[ ! -e acq/root.key.pem ] || fail "AC créée malgré deux saisies différentes"
expect 1 "" sh -c "'$bin' ca init --dir acr </dev/null"
expect 1 "phrase de passe illisible" "$bin" ca init --dir acs --passphrase-file absent.txt
if command -v script >/dev/null; then
  # Terminal : saisie sans écho ; la phrase de passe n'apparaît pas dans la sortie. Chaque ligne
  # est tapée après l'invite (une saisie anticipée est effacée quand l'écho est coupé).
  out=$( (sleep 1; printf 'phrase secrete 12\n'; sleep 1; printf 'phrase secrete 12\n'; sleep 1) \
          | script -qec "'$bin' ca init --dir act" /dev/null 2>&1) \
    || fail "ca init en terminal"$'\n'"$out"
  grep -q "AC créée" <<<"$out" || fail "ca init en terminal"$'\n'"$out"
  ! grep -q "phrase secrete" <<<"$out" || fail "phrase de passe affichée en terminal"
fi

echo "== commandes vers une instance"
expect 2 "est celle de l'instance « srv »" "$bin" run -c server.yaml --instance autre
expect 2 "délai invalide" "$bin" stop -c server.yaml --timeout abc
expect 0 "déjà arrêtée" "$bin" stop -c server.yaml
expect 0 "déjà arrêtée" "$bin" kill -c server.yaml
expect 2 "erreur" "$bin" status -c invalide.yaml
expect 1 "injoignable" "$bin" status --admin "$work/absent.sock"

echo "== gestionnaire de services : refus avant installation"
expect 2 "nom d'instance invalide" "$bin" start --instance "nom invalide"
expect 2 "délai invalide" "$bin" start --instance absente --timeout abc
expect 1 "n'est pas installée" "$bin" start --instance absente-cli
expect 1 "n'est pas installée" "$bin" restart --instance absente-cli
expect 2 "nom d'instance invalide" "$bin" service install --instance "nom invalide"
expect 2 "déclare l'instance « srv »" "$bin" service install --instance autre -c server.yaml
expect 2 "retirer admin.endpoint" "$bin" service install --instance srv -c server.yaml
expect 2 "erreur" "$bin" service install --instance srv -c invalide.yaml
expect 2 "nom d'instance invalide" "$bin" service uninstall --instance "nom invalide"
expect 1 "erreur" "$bin" service uninstall --instance absente-cli

echo "cli.sh : OK"
