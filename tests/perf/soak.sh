#!/usr/bin/env bash
# Soak test (PLAN §5.6): continuous PKI rotations and renegotiations, periodic
# network cuts; memory, descriptors and generations must stay stable.
#
#   testkit ──► tlsrelay client ══ mTLS ══► proxy (cuts) ══► tlsrelay server ──► echo
#
# For the whole duration: a continuous stream (hash checked at the end) and
# waves of intact channels; PKI rotation on both sides at regular intervals.
# Usage: soak.sh <build directory> <duration in minutes> [CSV file of samples]
set -euo pipefail

build=$(realpath "$1")
minutes=${2:?duration in minutes}
csv_out=${3:+$(realpath -m "$3")}
bin="$build/src/app/tlsrelay"
kit="$build/src/testkit/tlsrelay-testkit"
work=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; [ -n "${KEEP:-}" ] || rm -rf "$work"' EXIT
cd "$work"
port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
log() { echo "[$(date -u +%H:%M:%S)] $*"; }

# Paces: reduced for a short run, realistic for 72 h.
# Environment variables LIFETIME, ROTATE_EVERY and CUT_EVERY to force them.
lifetime=${LIFETIME:-$(( minutes >= 120 ? 600 : 60 ))}            # session_lifetime (s)
rotate_every=${ROTATE_EVERY:-$(( minutes >= 120 ? 1800 : 180 ))}  # PKI rotation (s)
cut_every=${CUT_EVERY:-$(( minutes >= 120 ? 900 : 30 ))}         # network cut (s)

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
credentials: { pki_root: $work/pki/server }
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

# Continuous stream for the whole duration: renegotiations, cuts and rotations go through it.
# Paced stream (STREAM_RATE Mbit/s, default 200): a saturated stream on the
# loopback can stall (known limitation, README "Performance").
"$kit" throughput --target "127.0.0.1:$cli" --duration "$((minutes * 60 - 30))s" --rate "${STREAM_RATE:-200}" --json > stream.json &
stream=$!

echo "time_s,wave_ok,rss_server_kib,rss_client_kib,fd_server,fd_client,generations_server,generations_client,renegotiations_client,cuts" > samples.csv
start=$(date +%s); end=$((start + minutes * 60 - 60)); next_rotation=$((start + rotate_every)); rounds=0; failed_rounds=0
log "soak: ${minutes} min, session_lifetime ${lifetime}s, rotation every ${rotate_every}s, cut every ${cut_every}s"
while [ "$(date +%s)" -lt "$end" ]; do
  if "$kit" load --target "127.0.0.1:$cli" --channels 200 --bytes 256KiB --threads 2 --json > round.json; then ok=1; else ok=0; failed_rounds=$((failed_rounds + 1)); cat round.json; fi
  rounds=$((rounds + 1))
  if [ "$(date +%s)" -ge "$next_rotation" ]; then
    "$kit" pki --out pki >/dev/null
    "$bin" reload -c server.yaml >/dev/null; "$bin" reload -c client.yaml >/dev/null
    log "PKI rotation: server $(cat pki/server/current), client $(cat pki/client/current)"
    next_rotation=$((next_rotation + rotate_every))
  fi
  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' "$(( $(date +%s) - start ))" "$ok" \
    "$(( $(metric server tlsrelay_process_resident_memory_bytes) / 1024 ))" \
    "$(( $(metric client tlsrelay_process_resident_memory_bytes) / 1024 ))" \
    "$(metric server tlsrelay_process_open_descriptors)" "$(metric client tlsrelay_process_open_descriptors)" \
    "$(metric server tlsrelay_pki_generations_live)" "$(metric client tlsrelay_pki_generations_live)" \
    "$(metric client tlsrelay_renegotiations_total)" "$(grep -c "cut of" proxy.log || true)" >> samples.csv
  sleep 5
done
if ! wait "$stream"; then
  cat stream.json
  # History of the stream channel (the first one opened) on both sides.
  session=$(grep -m1 -o 'channel=[0-9]* opened .*session=[0-9a-f]*' client.log | grep -o 'session=[0-9a-f]*' | cut -d= -f2)
  cchannel=$(grep -m1 "session=$session" client.log | grep -o 'channel=[0-9]*')
  schannel=$(grep -m1 "session=$session" server.log | grep -o 'channel=[0-9]*' || true)
  echo "-- stream, client ($cchannel)"; grep -E "$cchannel[^0-9]" client.log | tail -n 60
  echo "-- stream, server (${schannel:-?})"; [ -n "$schannel" ] && grep -E "$schannel[^0-9]|$session" server.log | tail -n 60
fi
[ -n "$csv_out" ] && cp samples.csv "$csv_out"

# Descriptors at the end of the run, after renegotiation_grace: the channels cut
# last wait until then for a resumption before being closed.
sleep 25
fd_final_server=$(metric server tlsrelay_process_open_descriptors)
fd_final_client=$(metric client tlsrelay_process_open_descriptors)

python3 - "$rounds" "$failed_rounds" "$minutes" "$fd_final_server" "$fd_final_client" <<'PY'
import csv, json, statistics, sys
rounds, failed, minutes = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
fd_final = {"server": int(sys.argv[4]), "client": int(sys.argv[5])}
rows = list(csv.DictReader(open("samples.csv")))
stream = json.load(open("stream.json"))
n = len(rows)
def med(key, part):
    vals = [int(r[key]) for r in part]
    return statistics.median(vals) if vals else 0
# Memory: steady state (2nd quintile) compared with the end (last quintile).
q = max(1, n // 5)
early, late = rows[q:2 * q] or rows[:q], rows[-q:]
checks = {
    f"waves of intact channels ({rounds - failed}/{rounds})": failed == 0 and rounds > 0,
    f"continuous stream intact ({stream['bytes'] / 2**30:.1f} GiB)": stream["intact"] == 1,
    "renegotiations performed": int(rows[-1]["renegotiations_client"]) > 0,
    "network cuts survived": int(rows[-1]["cuts"]) > 0,
}
for side in ("server", "client"):
    e, l = med(f"rss_{side}_kib", early), med(f"rss_{side}_kib", late)
    # On a short run, memory has not reached its steady state
    # (allocator, generation added by the rotation): sample for information only.
    label = f"{side} memory stable ({e / 1024:.0f} → {l / 1024:.0f} MiB)"
    if minutes >= 30:
        checks[label] = l <= e * 1.25 + 8192
    else:
        print(f"INFO  {label} (informational under 30 min)")
    fe, fl = med(f"fd_{side}", early), fd_final[side]
    checks[f"{side} descriptors stable ({fe:.0f} → {fl:.0f} at the end of the run)"] = fl <= fe + 20
    gens = max(int(r[f"generations_{side}"]) for r in late)
    checks[f"{side} generations released (≤ 2 live at the end: {gens})"] = gens <= 2
print(f"{n} samples, {rounds} waves")
for k, ok in checks.items():
    print(("OK    " if ok else "FAILED ") + k)
sys.exit(0 if all(checks.values()) else 1)
PY
