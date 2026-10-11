#!/usr/bin/env bash
# Endurance (PLAN §5.6) : rotations PKI et renégociations continues, coupures
# réseau périodiques ; mémoire, descripteurs et générations doivent rester stables.
#
#   testkit ──► tlsrelay client ══ mTLS ══► proxy (coupures) ══► tlsrelay serveur ──► écho
#
# Pendant toute la durée : un flux continu (empreinte vérifiée à la fin) et des
# vagues de canaux intègres ; rotation PKI des deux côtés à intervalle régulier.
# Usage : soak.sh <répertoire de build> <durée en minutes> [fichier CSV des relevés]
set -euo pipefail

build=$(realpath "$1")
minutes=${2:?durée en minutes}
csv_out=${3:+$(realpath -m "$3")}
bin="$build/src/app/tlsrelay"
kit="$build/src/testkit/tlsrelay-testkit"
work=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; [ -n "${KEEP:-}" ] || rm -rf "$work"' EXIT
cd "$work"
port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
log() { echo "[$(date -u +%H:%M:%S)] $*"; }

# Rythmes : réduits pour un essai court, réalistes pour 72 h.
# Variables d'environnement LIFETIME, ROTATE_EVERY et CUT_EVERY pour les forcer.
lifetime=${LIFETIME:-$(( minutes >= 120 ? 600 : 60 ))}            # session_lifetime (s)
rotate_every=${ROTATE_EVERY:-$(( minutes >= 120 ? 1800 : 180 ))}  # rotation PKI (s)
cut_every=${CUT_EVERY:-$(( minutes >= 120 ? 900 : 30 ))}         # coupure réseau (s)

"$kit" pki --out pki >/dev/null
dest=$(port); srv=$(port); prx=$(port); cli=$(port)
cat > wl.yaml <<YAML
peers:
  - { name: soak, ip: 127.0.0.1, ports: [mtls], subject: "CN=client.test,O=tlsrelay-test" }
YAML
limits="limits: { session_lifetime: ${lifetime}s, renegotiation_grace: 20s, idle_timeout: 50s, keepalive_interval: 5s }"
cat > server.yaml <<YAML
mode: server
instance: soak-server
logging: { output: $work/server.log, level: ${LOG_LEVEL:-debug} }
admin: { endpoint: $work/server.sock }
credentials: { pki_root: $work/pki/serveur }
whitelist: { file: $work/wl.yaml }
destination: { address: 127.0.0.1, port: $dest }
$limits
ports:
  mtls: { listen: "127.0.0.1:$srv" }
YAML
cat > client.yaml <<YAML
mode: client
instance: soak-client
logging: { output: $work/client.log, level: ${LOG_LEVEL:-debug} }
admin: { endpoint: $work/client.sock }
credentials: { pki_root: $work/pki/client }
$limits
ports:
  mtls: { listen: "127.0.0.1:$cli", upstream: "127.0.0.1:$prx", server_name: relay.test }
YAML

"$kit" echo --listen "127.0.0.1:$dest" >/dev/null &
"$kit" proxy --listen "127.0.0.1:$prx" --target "127.0.0.1:$srv" --cut-every "${cut_every}s" >proxy.log &
"$bin" run -c server.yaml & "$bin" run -c client.yaml &
for _ in $(seq 50); do "$bin" status -c client.yaml >/dev/null 2>&1 && "$bin" status -c server.yaml >/dev/null 2>&1 && break; sleep 0.1; done

metric() { "$bin" metrics -c "$1.yaml" | awk -v m="$2" '$1 ~ "^"m"[{ ]" {print $2; exit}'; }

# Flux continu pendant toute la durée : renégociations, coupures et rotations le traversent.
"$kit" throughput --target "127.0.0.1:$cli" --duration "$((minutes * 60 - 30))s" --json > stream.json &
stream=$!

echo "temps_s,vague_ok,rss_serveur_kio,rss_client_kio,fd_serveur,fd_client,generations_serveur,generations_client,renegociations_client,coupures" > samples.csv
start=$(date +%s); end=$((start + minutes * 60 - 60)); next_rotation=$((start + rotate_every)); rounds=0; failed_rounds=0
log "endurance : ${minutes} min, session_lifetime ${lifetime}s, rotation toutes les ${rotate_every}s, coupure toutes les ${cut_every}s"
while [ "$(date +%s)" -lt "$end" ]; do
  if "$kit" load --target "127.0.0.1:$cli" --channels 200 --bytes 256KiB --threads 2 --json > round.json; then ok=1; else ok=0; failed_rounds=$((failed_rounds + 1)); cat round.json; fi
  rounds=$((rounds + 1))
  if [ "$(date +%s)" -ge "$next_rotation" ]; then
    "$kit" pki --out pki >/dev/null
    "$bin" reload -c server.yaml >/dev/null; "$bin" reload -c client.yaml >/dev/null
    log "rotation PKI : serveur $(cat pki/serveur/current), client $(cat pki/client/current)"
    next_rotation=$((next_rotation + rotate_every))
  fi
  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' "$(( $(date +%s) - start ))" "$ok" \
    "$(( $(metric server tlsrelay_process_resident_memory_bytes) / 1024 ))" \
    "$(( $(metric client tlsrelay_process_resident_memory_bytes) / 1024 ))" \
    "$(metric server tlsrelay_process_open_descriptors)" "$(metric client tlsrelay_process_open_descriptors)" \
    "$(metric server tlsrelay_pki_generations_live)" "$(metric client tlsrelay_pki_generations_live)" \
    "$(metric client tlsrelay_renegotiations_total)" "$(grep -c coupure proxy.log || true)" >> samples.csv
  sleep 5
done
if ! wait "$stream"; then
  cat stream.json
  # Historique du canal de flux (le premier ouvert) des deux côtés.
  session=$(grep -m1 -o 'canal=[0-9]* ouvert .*session=[0-9a-f]*' client.log | grep -o 'session=[0-9a-f]*' | cut -d= -f2)
  ccanal=$(grep -m1 "session=$session" client.log | grep -o 'canal=[0-9]*')
  scanal=$(grep -m1 "session=$session" server.log | grep -o 'canal=[0-9]*' || true)
  echo "-- flux, client ($ccanal)"; grep -E "$ccanal[^0-9]" client.log | tail -n 60
  echo "-- flux, serveur (${scanal:-?})"; [ -n "$scanal" ] && grep -E "$scanal[^0-9]|$session" server.log | tail -n 60
fi
[ -n "$csv_out" ] && cp samples.csv "$csv_out"

python3 - "$rounds" "$failed_rounds" "$minutes" <<'PY'
import csv, json, statistics, sys
rounds, failed, minutes = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
rows = list(csv.DictReader(open("samples.csv")))
stream = json.load(open("stream.json"))
n = len(rows)
def med(key, part):
    vals = [int(r[key]) for r in part]
    return statistics.median(vals) if vals else 0
# Mémoire : régime établi (2e quintile) comparé à la fin (dernier quintile).
q = max(1, n // 5)
early, late = rows[q:2 * q] or rows[:q], rows[-q:]
checks = {
    f"vagues de canaux intègres ({rounds - failed}/{rounds})": failed == 0 and rounds > 0,
    f"flux continu intègre ({stream['bytes'] / 2**30:.1f} Gio)": stream["intact"] == 1,
    "renégociations effectuées": int(rows[-1]["renegociations_client"]) > 0,
    "coupures réseau traversées": int(rows[-1]["coupures"]) > 0,
}
for side in ("serveur", "client"):
    e, l = med(f"rss_{side}_kio", early), med(f"rss_{side}_kio", late)
    # Sur une course courte, la mémoire n'a pas atteint son régime établi
    # (allocateur, génération ajoutée par la rotation) : relevé indicatif.
    label = f"mémoire {side} stable ({e / 1024:.0f} → {l / 1024:.0f} Mio)"
    if minutes >= 30:
        checks[label] = l <= e * 1.25 + 8192
    else:
        print(f"INFO  {label} (indicatif sous 30 min)")
    fe, fl = med(f"fd_{side}", early), med(f"fd_{side}", late)
    checks[f"descripteurs {side} stables ({fe:.0f} → {fl:.0f})"] = fl <= fe + 20
    gens = max(int(r[f"generations_{side}"]) for r in late)
    checks[f"générations {side} libérées (≤ 2 vivantes en fin : {gens})"] = gens <= 2
print(f"{n} relevés, {rounds} vagues")
for k, ok in checks.items():
    print(("OK    " if ok else "ÉCHEC ") + k)
sys.exit(0 if all(checks.values()) else 1)
PY
