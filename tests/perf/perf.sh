#!/usr/bin/env bash
# Objectifs de performance (PLAN §5.6), chaîne réelle en mTLS :
#   testkit ──► tlsrelay client ══ mTLS ══► tlsrelay serveur ──► écho testkit
# - canaux simultanés (défaut 5000), tous intègres (SHA-256 par canal) ;
# - débit d'un canal ≥ 100 Mbit/s ;
# - latence ajoutée < 1 ms (médiane de l'aller-retour via tlsrelay moins direct).
# Usage : perf.sh <répertoire de build> [canaux] [fichier de rapport JSON]
set -euo pipefail

build=$(realpath "$1")
channels=${2:-5000}
report=${3:+$(realpath -m "$3")}
bin="$build/src/app/tlsrelay"
kit="$build/src/testkit/tlsrelay-testkit"
work=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; [ -n "${KEEP:-}" ] || rm -rf "$work"' EXIT
cd "$work"
port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }

need=$((channels * 2 + 200))
if [ "$(ulimit -n)" -lt "$need" ]; then ulimit -n "$need" 2>/dev/null || {
  echo "limite de descripteurs trop basse ($(ulimit -n) < $need) pour $channels canaux" >&2; exit 2; }; fi

"$kit" pki --out pki >/dev/null
dest=$(port); srv=$(port); cli=$(port)
cat > wl.yaml <<YAML
peers:
  - { name: perf, ip: 127.0.0.1, ports: [mtls], subject: "CN=client.test,O=tlsrelay-test" }
YAML
for role in server client; do
  if [ $role = server ]; then
    ports="  mtls: { listen: \"127.0.0.1:$srv\" }"
    extra="whitelist: { file: $work/wl.yaml }
destination: { address: 127.0.0.1, port: $dest }
credentials: { pki_root: $work/pki/serveur }"
  else
    ports="  mtls: { listen: \"127.0.0.1:$cli\", upstream: \"127.0.0.1:$srv\", server_name: relay.test }"
    extra="credentials: { pki_root: $work/pki/client }"
  fi
  cat > $role.yaml <<YAML
mode: $role
instance: perf-$role
logging: { output: $work/$role.log }
admin: { endpoint: $work/$role.sock }
limits: { max_channels: $((channels + 100)) }
$extra
ports:
$ports
YAML
done

"$kit" echo --listen "127.0.0.1:$dest" >/dev/null &
"$bin" run -c server.yaml & "$bin" run -c client.yaml &
for _ in $(seq 50); do "$bin" status -c client.yaml >/dev/null 2>&1 && "$bin" status -c server.yaml >/dev/null 2>&1 && break; sleep 0.1; done

metric() { "$bin" metrics -c "$1.yaml" | awk -v m="$2" '$1 ~ "^"m"[{ ]" {print $2}'; }

echo "== $channels canaux simultanés"
# Mémoire relevée pendant le maintien des canaux ouverts.
( sleep 4; metric server tlsrelay_process_resident_memory_bytes > peak_server
  metric client tlsrelay_process_resident_memory_bytes > peak_client ) &
sampler=$!
"$kit" load --target "127.0.0.1:$cli" --channels "$channels" --bytes 64KiB --hold 6s --json | tee load.json
wait "$sampler"
echo "== débit d'un canal (10 s)"
"$kit" throughput --target "127.0.0.1:$cli" --duration 10s --json > throughput.json &
tp=$!
# Diagnostic d'un blocage : état du contrôle de flux des deux côtés pendant le blocage.
for _ in $(seq 40); do kill -0 "$tp" 2>/dev/null || break; sleep 1; done
if kill -0 "$tp" 2>/dev/null; then
  echo "débit : canal bloqué au-delà de 40 s, état des relais :"
  for role in client server; do echo "-- $role"; "$bin" channels -c $role.yaml || true; done
  for _ in 1 2 3; do sleep 5; for role in client server; do "$bin" channels -c $role.yaml | tail -n +2 || true; done; done
  echo "-- mémoire TCP du noyau"; cat /proc/net/sockstat; echo "tcp_mem=$(cat /proc/sys/net/ipv4/tcp_mem) tcp_rmem=$(cat /proc/sys/net/ipv4/tcp_rmem) tcp_wmem=$(cat /proc/sys/net/ipv4/tcp_wmem)"
  nstat -az 2>/dev/null | grep -iE "pressure|prune|drop|zerowindow|rcvq|collapse|ofo|probe" || true
  echo "-- sockets (Recv-Q / Send-Q)"; ss -tnpmi state established "( sport = :$dest or dport = :$dest or sport = :$srv or dport = :$srv or sport = :$cli or dport = :$cli )" || true
  for role in client server; do echo "-- journal $role"; tail -n 30 $role.log; done
  kill "$tp" 2>/dev/null || true
fi
wait "$tp" || true
cat throughput.json
echo "== latence (aller-retour 64 octets)"
"$kit" latency --target "127.0.0.1:$dest" --count 5000 --json | tee direct.json
"$kit" latency --target "127.0.0.1:$cli" --count 5000 --json | tee relay.json

python3 - "$channels" "${report:-/dev/null}" "$(cat peak_server)" "$(cat peak_client)" <<'PY'
import json, sys
channels, report, peak_s, peak_c = int(sys.argv[1]), sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
load = json.load(open("load.json")); tp = json.load(open("throughput.json"))
direct = json.load(open("direct.json")); relay = json.load(open("relay.json"))
added_ms = (relay["p50_us"] - direct["p50_us"]) / 1000
result = {
    "channels": channels, "channels_intact": load["ok"], "channels_failed": load["failed"],
    "throughput_mbit_per_channel": round(tp["mbit_per_s_per_channel"], 1),
    "added_latency_p50_ms": round(added_ms, 3),
    "relay_latency_p99_us": relay["p99_us"],
    "peak_memory_mib": {"server": peak_s // 2**20, "client": peak_c // 2**20},
    "memory_per_channel_kib": round(max(peak_s, peak_c) / 1024 / channels, 1),
}
checks = {
    f"{channels} canaux simultanés intègres": load["ok"] == channels and load["failed"] == 0,
    "débit d'un canal ≥ 100 Mbit/s": tp["mbit_per_s_per_channel"] >= 100 and tp["intact"] == 1,
    "latence ajoutée < 1 ms": added_ms < 1.0,
}
result["checks"] = checks
print(json.dumps(result, ensure_ascii=False, indent=2))
if report != "/dev/null":
    json.dump(result, open(report, "w"), ensure_ascii=False, indent=2)
failed = [k for k, ok in checks.items() if not ok]
for k, ok in checks.items():
    print(("OK    " if ok else "ÉCHEC ") + k)
sys.exit(1 if failed else 0)
PY
"$bin" stop -c client.yaml >/dev/null; "$bin" stop -c server.yaml >/dev/null
