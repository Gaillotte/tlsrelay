#!/usr/bin/env bash
# Test d'un paquet Linux de tlsrelay sur une distribution propre (conteneur) :
# installation, compte et répertoire créés, échange mTLS entre un client et un
# serveur installés, puis désinstallation (et purge pour Debian).
#
# Usage, depuis la racine du dépôt :
#   docker run --rm -v "$PWD:/src" -w /src ubuntu:24.04 packaging/test-linux-package.sh paquets
set -euo pipefail

dir=$(realpath "${1:?répertoire des paquets}")
. /etc/os-release
fail() { echo "ÉCHEC : $*" >&2; exit 1; }
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
  *) fail "distribution non prise en charge : $ID" ;;
esac

tlsrelay version
[ "$(command -v tlsrelay)" = /usr/bin/tlsrelay ] || fail "tlsrelay absent de /usr/bin"
command -v tlsrelay-testkit >/dev/null || fail "tlsrelay-testkit absent"
getent passwd tlsrelay >/dev/null || fail "compte tlsrelay non créé"
[ "$(stat -c '%a %U %G' /etc/tlsrelay)" = "750 root tlsrelay" ] || fail "droits de /etc/tlsrelay : $(stat -c '%a %U %G' /etc/tlsrelay)"
# Contenu du paquet (les images minimisées n'installent pas /usr/share/doc).
if [ "$kind" = deb ]; then files=$(dpkg-deb -c "$dir"/tlsrelay_*.deb); else files=$(rpm -qlp "$dir"/tlsrelay-[0-9]*.rpm); fi
grep -q 'share/doc/tlsrelay/THIRD-PARTY-NOTICES.txt' <<<"$files" || fail "avis des composants tiers absents du paquet"
grep -q 'share/doc/tlsrelay/LICENSE' <<<"$files" || fail "licence absente du paquet"
for f in /usr/share/doc/tlsrelay/examples/*.yaml; do
  case "$f" in *whitelist*) continue ;; esac
  tlsrelay check-config -c "$f" >/dev/null 2>&1 || true  # exemples commentés : chemins à adapter
done

step "échange mTLS entre un client et un serveur installés"
work=$(mktemp -d)
cd "$work"
tlsrelay-testkit pki --out pki >/dev/null
cat > wl.yaml <<'YAML'
peers:
  - { name: essai, ip: 127.0.0.1, ports: [mtls], subject: "CN=client.test,O=tlsrelay-test" }
YAML
cat > server.yaml <<YAML
mode: server
instance: essai-serveur
admin: { endpoint: $work/server.sock }
logging: { output: $work/server.log }
credentials: { pki_root: $work/pki/serveur }
whitelist: { file: $work/wl.yaml }
destination: { address: 127.0.0.1, port: 28080 }
ports:
  mtls: { listen: "127.0.0.1:29003" }
YAML
cat > client.yaml <<YAML
mode: client
instance: essai-client
admin: { endpoint: $work/client.sock }
logging: { output: $work/client.log }
credentials: { pki_root: $work/pki/client }
ports:
  mtls: { listen: "127.0.0.1:27003", upstream: "127.0.0.1:29003", server_name: relay.test }
YAML
tlsrelay-testkit echo --listen 127.0.0.1:28080 >/dev/null &
tlsrelay run -c server.yaml & tlsrelay run -c client.yaml &
for _ in $(seq 50); do tlsrelay status -c client.yaml >/dev/null 2>&1 && tlsrelay status -c server.yaml >/dev/null 2>&1 && break; sleep 0.1; done
tlsrelay-testkit load --target 127.0.0.1:27003 --channels 50 --bytes 256KiB || { tail -n 20 server.log client.log; fail "échange mTLS"; }
tlsrelay stop -c client.yaml >/dev/null
tlsrelay stop -c server.yaml >/dev/null
kill %1 2>/dev/null || true
wait 2>/dev/null || true
cd / && rm -rf "$work"

step "désinstallation"
if [ "$kind" = deb ]; then
  apt-get purge -y -q tlsrelay-testkit tlsrelay >/dev/null
else
  dnf remove -y -q tlsrelay-testkit tlsrelay >/dev/null
fi
[ ! -e /usr/bin/tlsrelay ] || fail "binaire encore présent"
[ -d /etc/tlsrelay ] || fail "/etc/tlsrelay supprimé (configurations et PKI à conserver)"
echo "paquet $kind sur $PRETTY_NAME : OK"
