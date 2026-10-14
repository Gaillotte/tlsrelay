#!/usr/bin/env bash
# Cycle de vie sous systemd (SPEC §10), à exécuter en root sur une machine de
# test : installation, démarrage au boot, relais, reload, restart, stop, kill,
# arrêt par systemctl, refus d'un utilisateur non autorisé, désinstallation.
# Usage : sudo systemd.sh <chemin de tlsrelay>
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
fail() { echo "ÉCHEC : $*" >&2; journalctl -u tlsrelay@ci --no-pager -n 50 || true; exit 1; }
step() { echo "== $*"; }

# Binaire installé hors de /home (ProtectHome=yes dans l'unité).
install -m 0755 "$1" /usr/local/bin/tlsrelay
bin=/usr/local/bin/tlsrelay

python3 "$here/echo.py" 18080 & echo_pid=$!
work=$(mktemp -d)
cleanup() {
  kill $echo_pid ${client_pid:-} 2>/dev/null || true
  "$bin" service uninstall --instance ci >/dev/null 2>&1 || true
  rm -rf "$work" /etc/tlsrelay/ci.yaml /etc/tlsrelay/ci-whitelist.yaml
}
trap cleanup EXIT

mkdir -p /etc/tlsrelay
cat > /etc/tlsrelay/ci-whitelist.yaml <<YAML
peers:
  - { name: local, ip: 127.0.0.1, ports: [plain] }
YAML
cat > /etc/tlsrelay/ci.yaml <<YAML
mode: server
instance: ci
whitelist: { file: /etc/tlsrelay/ci-whitelist.yaml }
destination: { address: 127.0.0.1, port: 18080 }
limits: { shutdown_timeout: 3s }
ports:
  plain: { listen: "127.0.0.1:19001" }
YAML

step "installation avec démarrage au boot"
"$bin" service install --instance ci --boot
chgrp tlsrelay /etc/tlsrelay/ci.yaml /etc/tlsrelay/ci-whitelist.yaml
chmod 0640 /etc/tlsrelay/ci.yaml /etc/tlsrelay/ci-whitelist.yaml
[ "$(systemctl is-enabled tlsrelay@ci)" = enabled ] || fail "démarrage au boot"

step "démarrage"
"$bin" start --instance ci
[ "$(systemctl is-active tlsrelay@ci)" = active ] || fail "service inactif"
"$bin" status --instance ci | tee "$work/status" | grep -q "instance : ci" || fail "status"
[ "$(ps -o user= -p "$(systemctl show -p MainPID --value tlsrelay@ci)")" = tlsrelay ] || fail "compte du service"
"$bin" start --instance ci | grep -q "déjà démarrée" || fail "second démarrage"

step "relais de données à travers le service"
cat > "$work/client.yaml" <<YAML
mode: client
instance: ci-client
admin: { enabled: false }
ports:
  plain: { listen: "127.0.0.1:17001", upstream: "127.0.0.1:19001" }
YAML
"$bin" run -c "$work/client.yaml" & client_pid=$!
sleep 0.5
python3 "$here/exchange.py" 17001 || fail "échange"

step "accès refusé à un utilisateur non autorisé"
if sudo -u nobody "$bin" status --instance ci 2>"$work/nobody.err"; then fail "nobody a obtenu l'état"; fi
cat "$work/nobody.err"

step "rechargement (tlsrelay reload et systemctl reload)"
"$bin" reload --instance ci | grep -q "liste blanche : 1 pair" || fail "reload"
systemctl reload tlsrelay@ci || fail "systemctl reload"

step "redémarrage"
pid1=$(systemctl show -p MainPID --value tlsrelay@ci)
"$bin" restart --instance ci
pid2=$(systemctl show -p MainPID --value tlsrelay@ci)
[ "$pid1" != "$pid2" ] && [ "$pid2" != 0 ] || fail "PID inchangé après restart"
python3 "$here/exchange.py" 17001 || fail "échange après restart"

step "arrêt propre"
"$bin" stop --instance ci
sleep 0.5
[ "$(systemctl is-active tlsrelay@ci || true)" = inactive ] || fail "toujours actif après stop"
"$bin" stop --instance ci | grep -q "déjà arrêtée" || fail "arrêt d'une instance arrêtée"

step "arrêt par systemctl stop (SIGTERM, drain)"
"$bin" start --instance ci
systemctl stop tlsrelay@ci
journalctl -u tlsrelay@ci --no-pager -n 20 | grep -q "service arrêté" || fail "arrêt propre non journalisé"

step "arrêt immédiat"
"$bin" start --instance ci
"$bin" kill --instance ci
sleep 0.5
[ "$(systemctl is-active tlsrelay@ci || true)" != active ] || fail "toujours actif après kill"

step "désinstallation"
"$bin" service uninstall --instance ci
[ ! -e /etc/systemd/system/tlsrelay@ci.service.d ] || fail "drop-in restant"
if "$bin" service uninstall --instance ci 2>"$work/uninstall.err"; then fail "seconde désinstallation acceptée"; fi
grep -q "n'est pas installé" "$work/uninstall.err" || fail "message de la seconde désinstallation"

echo "cycle de vie systemd : OK"
