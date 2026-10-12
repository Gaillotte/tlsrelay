#!/usr/bin/env bash
# Cycle de vie en console (SPEC §10), avec le binaire réel :
# démarrage, verrou d'instance, status, reload, stop avec drain, kill, SIGTERM.
# Usage : console.sh <chemin de tlsrelay>
set -euo pipefail

bin=$(realpath "$1")
work=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$work"' EXIT
cd "$work"

# Cherche un motif dans toute la sortie d'une commande (grep -q fermerait le tube trop tôt : SIGPIPE avec pipefail).
has() { local out; out=$(cat); grep -q -- "$1" <<<"$out"; }
fail() { echo "ÉCHEC : $*" >&2; exit 1; }
port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }

dest=$(port)
listen=$(port)
cat > whitelist.yaml <<YAML
peers:
  - { name: local, ip: 127.0.0.1, ports: [plain] }
YAML
cat > server.yaml <<YAML
mode: server
instance: essai
logging: { output: $work/server.log }
whitelist: { file: $work/whitelist.yaml }
destination: { address: 127.0.0.1, port: $dest }
admin: { endpoint: $work/essai.sock }
limits: { shutdown_timeout: 2s }
ports:
  plain: { listen: "127.0.0.1:$listen" }
YAML

wait_ready() {
  for _ in $(seq 50); do "$bin" status -c server.yaml >/dev/null 2>&1 && return 0; sleep 0.1; done
  fail "l'instance ne répond pas"
}

# 1. Démarrage et état
"$bin" run -c server.yaml & pid=$!
wait_ready
"$bin" status -c server.yaml | has "instance : essai" || fail "status"
"$bin" status -c server.yaml | has "pid : $pid" || fail "pid"

# 2. Une seule exécution par instance
if "$bin" run -c server.yaml 2> second.err; then fail "seconde exécution acceptée"; fi
grep -q "autre exécution" second.err || fail "message de verrou : $(cat second.err)"

# 3. Rechargement et journalisation à chaud
"$bin" reload -c server.yaml | has "liste blanche : 1 pair" || fail "reload"
"$bin" log-level -c server.yaml debug | has "activity=debug" || fail "log-level"
"$bin" metrics -c server.yaml | has '^tlsrelay_channels_opened_total{instance="essai"} 0$' || fail "metrics"

# 4. Arrêt propre
"$bin" stop -c server.yaml --timeout 1s | has "arrêtée" || fail "stop"
wait $pid || fail "code de sortie après stop"
[ ! -e essai.sock ] || fail "socket non supprimé"
{ "$bin" status -c server.yaml 2>&1 || true; } | has "injoignable" || fail "status après arrêt"
"$bin" stop -c server.yaml | has "déjà arrêtée" || fail "stop d'une instance arrêtée"

# 5. Arrêt immédiat
"$bin" run -c server.yaml & pid=$!
wait_ready
"$bin" kill -c server.yaml | has "immédiatement" || fail "kill"
wait $pid || true

# 6. SIGTERM : arrêt propre (gestionnaire de services)
"$bin" run -c server.yaml & pid=$!
wait_ready
kill -TERM $pid
wait $pid || fail "code de sortie après SIGTERM"
grep -q "service arrêté" server.log || fail "journal"

# 7. Redémarrage après un arrêt brutal : verrou libéré, socket orphelin remplacé
"$bin" run -c server.yaml & pid=$!
wait_ready
kill -KILL $pid; wait $pid 2>/dev/null || true
[ -e essai.sock ] || fail "socket orphelin attendu"
"$bin" run -c server.yaml & pid=$!
wait_ready
"$bin" stop -c server.yaml >/dev/null
wait $pid

echo "cycle de vie en console : OK"
