#!/usr/bin/env bash
# Narrated end-to-end demonstration of tlsrelay on one Linux machine, with the
# real binaries: mini-CA and PKI, client and server instances on the three
# ports, TLS seen from outside, whitelist reload, transparent renegotiation,
# resumption after network cuts, hot PKI rotation, revocation (CRL),
# administration and metrics, editor check (and screenshots if Xvfb is present).
#
# Usage : tools/demo.sh [build directory] [first port]
#   build directory : contains src/app/tlsrelay, src/testkit/tlsrelay-testkit
#                     and, optionally, src/admin/tlsrelay-admin (default: build/linux-release)
#   first port      : 12 consecutive ports from this one are used (default: 31000)
# Environment : DEMO_PAUSE=1 waits for Enter between steps (live presentation);
#               DEMO_DIR=<dir> keeps the working files (configurations, PKI, logs, screenshots).
# Takes about 3 minutes. Exit code 0 if every check passed.
set -uo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
build=$(cd "${1:-$root/build/linux-release}" && pwd)
base=${2:-31000}
bin=$build/src/app/tlsrelay
kit=$build/src/testkit/tlsrelay-testkit
editor=$build/src/admin/tlsrelay-admin
for b in "$bin" "$kit"; do [ -x "$b" ] || { echo "missing: $b (build the project first)" >&2; exit 2; }; done

work=${DEMO_DIR:-$(mktemp -d)}
mkdir -p "$work"
keep=${DEMO_DIR:+1}
pids=()
cleanup() {
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null; done
  wait 2>/dev/null
  [ -n "$keep" ] || rm -rf "$work"
}
trap cleanup EXIT
cd "$work"
unset TLSRELAY_CA_PASSPHRASE
# Qt expects a runtime directory (set by desktop and SSH sessions; not always in containers).
if [ -z "${XDG_RUNTIME_DIR:-}" ]; then export XDG_RUNTIME_DIR="$work/.runtime"; mkdir -p -m 0700 "$XDG_RUNTIME_DIR"; fi

# Ports.
echo_port=$base
srv_plain=$((base + 1)) srv_tls=$((base + 2)) srv_mtls=$((base + 3))
cli_plain=$((base + 11)) cli_tls=$((base + 12)) cli_mtls=$((base + 13))
proxy_port=$((base + 20))

# ---------------------------------------------------------------- presentation
if [ -t 1 ]; then B=$'\e[1m' G=$'\e[32m' R=$'\e[31m' C=$'\e[36m' D=$'\e[2m' N=$'\e[0m'; else B='' G='' R='' C='' D='' N=''; fi
step_no=0 passed=0 failed=0
step() {
  step_no=$((step_no + 1))
  [ "${DEMO_PAUSE:-0}" = 1 ] && [ $step_no -gt 1 ] && read -r -p "${D}(Enter to continue)${N}" _
  printf '\n%s━━ %d. %s %s\n' "$B" "$step_no" "$1" "$N"
}
say() { printf '%s%s%s\n' "$C" "$*" "$N"; }
# Shows a command, runs it, indents its output.
run() {
  printf '%s$ %s%s\n' "$D" "$(printf '%q ' "$@" | sed "s#$bin#tlsrelay#g; s#$kit#tlsrelay-testkit#g; s#$editor#tlsrelay-admin#g; s#$work/##g")" "$N"
  "$@" 2>&1 | sed "s#$work/##g; s/^/    /"
  return "${PIPESTATUS[0]}"
}
# Shell pipeline shown as typed: shell "<command line>" (tlsrelay = the binary under test).
shell() {
  printf '%s$ %s%s\n' "$D" "$1" "$N"
  bash -c "tlsrelay() { '$bin' \"\$@\"; }; $1" 2>&1 | sed "s#$work/##g; s/^/    /"
}
check() {  # check <description> <command...>
  local what=$1; shift
  if "$@" >/dev/null 2>&1; then printf '  %s✔%s %s\n' "$G" "$N" "$what"; passed=$((passed + 1))
  else printf '  %s✘%s %s\n' "$R" "$N" "$what"; failed=$((failed + 1)); fi
}
json() { "$kit" --json "$@" 2>/dev/null | grep '^{' | tail -1; }
field() { jq -r ".$1" <<<"$2"; }
metric() { "$bin" metrics -c "$1.yaml" 2>/dev/null | awk -v m="tlsrelay_$2" '$1 ~ "^"m"({|$)" {s += $2} END {print s + 0}'; }
background() { "$@" >/dev/null 2>&1 & pids+=($!); }
wait_admin() { for _ in $(seq 50); do "$bin" status -c "$1.yaml" >/dev/null 2>&1 && return 0; sleep 0.1; done; return 1; }

# ---------------------------------------------------------------- configuration
echo "phrase de passe de démonstration" > passphrase.txt
write_whitelist() {
  if [ "$1" = with ]; then
    printf 'peers:\n  - { name: poste, ip: 127.0.0.1, ports: [plain, tls, mtls], subject: "CN=poste.demo,O=Demo" }\n'
  else
    printf 'peers: []\n'
  fi > whitelist.yaml
}
write_whitelist with
cat > server.yaml <<YAML
mode: server
instance: demo-server
logging: { level: info, output: $work/server.log }
credentials: { pki_root: $work/pki-server }
whitelist: { file: $work/whitelist.yaml }
destination: { address: 127.0.0.1, port: $echo_port }
admin: { endpoint: $work/server.sock }
limits: { session_lifetime: 15s, renegotiation_grace: 4s, idle_timeout: 10s, shutdown_timeout: 5s }
ports:
  plain: { listen: "127.0.0.1:$srv_plain" }
  tls:   { listen: "127.0.0.1:$srv_tls" }
  mtls:  { listen: "127.0.0.1:$srv_mtls" }
YAML
cat > client.yaml <<YAML
mode: client
instance: demo-client
logging: { level: info, output: $work/client.log }
credentials: { pki_root: $work/pki-client }
admin: { endpoint: $work/client.sock }
limits: { session_lifetime: 15s, renegotiation_grace: 4s, idle_timeout: 10s, shutdown_timeout: 5s }
ports:
  plain: { listen: "127.0.0.1:$cli_plain", upstream: "127.0.0.1:$srv_plain" }
  tls:   { listen: "127.0.0.1:$cli_tls",   upstream: "127.0.0.1:$srv_tls",    server_name: relay.demo }
  mtls:  { listen: "127.0.0.1:$cli_mtls",  upstream: "127.0.0.1:$proxy_port", server_name: relay.demo }
YAML

printf '%stlsrelay demonstration%s — working directory %s\n' "$B" "$N" "$work"
cat <<EOF

  application ──► client relay ══ plain :$srv_plain | TLS 1.3 :$srv_tls | mTLS :$srv_mtls (via proxy :$proxy_port) ══► server relay ──► echo :$echo_port
                  :$cli_plain :$cli_tls :$cli_mtls
EOF

# ================================================================ 1
step "Versions"
run "$bin" version

# ================================================================ 2
step "PKI built by the mini-CA"
say "The CA (root P-384, Servers CA, Clients CA) lives on an administration machine; its keys are encrypted."
run "$bin" ca init --dir ca --org Demo --passphrase-file passphrase.txt
say "Each instance creates its own key and a signing request; the key never leaves the instance."
run "$bin" pki gen-csr -c server.yaml --subject "CN=relay.demo,O=Demo" --san relay.demo
run "$bin" ca sign --dir ca --role server --csr pki-server/v1/request.csr --san relay.demo --out kit-server --passphrase-file passphrase.txt
run "$bin" pki install -c server.yaml --from kit-server
run "$bin" pki activate -c server.yaml v1
run "$bin" pki gen-csr -c client.yaml --subject "CN=poste.demo,O=Demo"
run "$bin" ca sign --dir ca --role client --csr pki-client/v1/request.csr --out kit-client --passphrase-file passphrase.txt
run "$bin" pki install -c client.yaml --from kit-client
run "$bin" pki activate -c client.yaml v1
run "$bin" ca list --dir ca
check "server certificate verified by OpenSSL (chain to the root, serverAuth)" \
  openssl verify -CAfile kit-server/trust-roots.pem -untrusted kit-server/chain.pem -purpose sslserver kit-server/cert.pem
check "a second certificate for the same subject is refused" \
  bash -c "! '$bin' ca sign --dir ca --role client --csr pki-client/v1/request.csr --out kit-x --passphrase-file passphrase.txt"

# ================================================================ 3
step "Starting the destination, the server and the client"
background "$kit" echo --listen "127.0.0.1:$echo_port"
background "$kit" proxy --listen "127.0.0.1:$proxy_port" --target "127.0.0.1:$srv_mtls"
background "$bin" run -c server.yaml
background "$bin" run -c client.yaml
wait_admin server && wait_admin client
run "$bin" status -c server.yaml
check "server answers on its administration channel" "$bin" status -c server.yaml
check "client answers on its administration channel" "$bin" status -c client.yaml

# ================================================================ 4
step "Data through the three ports (integrity checked by SHA-256 per channel)"
for p in plain:$cli_plain tls:$cli_tls mtls:$cli_mtls; do
  r=$(json load --target "127.0.0.1:${p#*:}" --channels 50 --bytes 256KiB)
  say "${p%%:*} port: $(field ok "$r")/$(field channels "$r") channels intact, $(field mbit_per_s "$r" | cut -d. -f1) Mbit/s"
  check "${p%%:*}: 50 concurrent channels, all intact" test "$(field ok "$r")" = 50
done
r=$(json latency --target "127.0.0.1:$cli_mtls" --count 2000)
say "mTLS round trip through both relays: median $(field p50_us "$r" | cut -d. -f1) µs"

# ================================================================ 5
step "TLS seen from outside (openssl s_client against the server's TLS port)"
out=$(openssl s_client -connect "127.0.0.1:$srv_tls" -servername relay.demo -alpn tlsrelay/1 -CAfile kit-server/trust-roots.pem </dev/null 2>&1)
grep -E "^(New|Protocol|Verify return code|ALPN protocol)|Cipher is" <<<"$out" | sort -u | sed 's/^/    /'
check "TLS 1.3 negotiated, ALPN tlsrelay/1, certificate verified" \
  bash -c "grep -q 'TLSv1.3' <<<\"\$1\" && grep -q 'ALPN protocol: tlsrelay/1' <<<\"\$1\" && grep -q 'Verify return code: 0' <<<\"\$1\"" _ "$out"
check "TLS 1.2 refused" bash -c "! openssl s_client -connect 127.0.0.1:$srv_tls -tls1_2 </dev/null >/dev/null 2>&1"
say "Without a client certificate, the mTLS port answers with a TLS alert:"
out=$(printf 'x\n' | timeout 5 openssl s_client -connect "127.0.0.1:$srv_mtls" -alpn tlsrelay/1 -CAfile kit-server/trust-roots.pem 2>&1)
grep -o "alert certificate required.*" <<<"$out" | head -1 | sed 's/^/    /'
check "client certificate required on the mTLS port (alert 116)" grep -q "alert certificate required" <<<"$out"

# ================================================================ 6
step "Whitelist reloaded while running"
say "The client's entry is removed: the server reloads the file within 2 s (or on reload) and refuses it."
write_whitelist without
run "$bin" reload -c server.yaml
r=$(json load --target "127.0.0.1:$cli_tls" --channels 5 --bytes 1KiB)
check "new channels refused once the peer is removed ($(field ok "$r")/5 accepted)" test "$(field ok "$r")" = 0
write_whitelist with
run "$bin" reload -c server.yaml
r=$(json load --target "127.0.0.1:$cli_tls" --channels 5 --bytes 1KiB)
check "accepted again once the entry is restored" test "$(field ok "$r")" = 5
grep -E "liste blanche" server.log | tail -2 | sed 's/^/    log: /'

# ================================================================ 7
step "Transparent renegotiation (session_lifetime 15 s)"
say "A continuous 40 s stream on the mTLS port: the client opens a new TLS connection before each deadline and the session moves to it."
before=$(metric client renegotiations_total)
r=$(json throughput --target "127.0.0.1:$cli_mtls" --duration 40s --rate 50)
count=$(( $(metric client renegotiations_total) - before ))
say "$(( $(field bytes "$r") / 1048576 )) MiB transferred, $count renegotiation(s), application never disconnected"
check "stream intact across renegotiations" test "$(field intact "$r")" = 1
check "at least two renegotiations" test "$count" -ge 2

# ================================================================ 8
step "Network cuts: the session resumes without loss"
say "The proxy between the relays now resets every connection every 3 s."
kill "${pids[1]}" 2>/dev/null; wait "${pids[1]}" 2>/dev/null
background "$kit" proxy --listen "127.0.0.1:$proxy_port" --target "127.0.0.1:$srv_mtls" --cut-every 3s
sleep 0.3
before=$(metric client renegotiations_total)
r=$(json throughput --target "127.0.0.1:$cli_mtls" --duration 15s --rate 20)
count=$(( $(metric client renegotiations_total) - before ))
say "$(( $(field bytes "$r") / 1048576 )) MiB transferred through $count resumption(s)"
check "stream intact through the cuts" test "$(field intact "$r")" = 1
check "session resumed after the cuts" test "$count" -ge 3
kill "${pids[-1]}" 2>/dev/null; wait "${pids[-1]}" 2>/dev/null
background "$kit" proxy --listen "127.0.0.1:$proxy_port" --target "127.0.0.1:$srv_mtls"
sleep 0.3

# ================================================================ 9
step "Hot PKI rotation: new server key and certificate (generation v2)"
background "$kit" load --target "127.0.0.1:$cli_mtls" --channels 3 --bytes 64KiB --hold 12s
sleep 1
run "$bin" pki gen-csr -c server.yaml --subject "CN=relay.demo,O=Demo" --san relay.demo
run "$bin" ca sign --dir ca --role server --csr pki-server/v2/request.csr --san relay.demo --renew --out kit-server-v2 --passphrase-file passphrase.txt
run "$bin" pki install -c server.yaml --from kit-server-v2
run "$bin" pki activate -c server.yaml v2
sleep 3
shell "tlsrelay status -c server.yaml | grep -i génération"
r=$(json load --target "127.0.0.1:$cli_mtls" --channels 10 --bytes 64KiB)
check "new connections served by generation v2" bash -c "'$bin' status -c server.yaml | grep -q 'v2'"
check "service uninterrupted: 10/10 new channels intact" test "$(field ok "$r")" = 10
grep -E "bascule|libérée" server.log | tail -2 | sed 's/^/    log: /'

# ================================================================ 10
step "Revocation: the client's certificate is revoked and the CRL deployed"
"$kit" --json load --target "127.0.0.1:$cli_mtls" --channels 3 --bytes 64KiB --hold 15s > held.json 2>/dev/null &
held=$!
sleep 1.5
serial=$("$bin" ca list --dir ca | awk '/client/ && /valide/ {print $1; exit}')
run "$bin" ca revoke --dir ca --serial "$serial" --reason keyCompromise --out crl.pem --passphrase-file passphrase.txt
run "$bin" pki crl -c server.yaml crl.pem
sleep 3
wait $held
check "open channels of the revoked peer closed (held load failed)" bash -c "[ \"\$(jq -r .failed held.json)\" -gt 0 ]"
r=$(json load --target "127.0.0.1:$cli_mtls" --channels 5 --bytes 1KiB)
check "new mTLS channels refused at the handshake" test "$(field ok "$r")" = 0
grep -E "révoqu" server.log | tail -2 | sed 's/^/    log: /'
say "A new certificate is issued to the client (renewal); it is accepted again."
run "$bin" pki gen-csr -c client.yaml --subject "CN=poste.demo,O=Demo"
run "$bin" ca sign --dir ca --role client --csr pki-client/v2/request.csr --out kit-client-v2 --passphrase-file passphrase.txt
run "$bin" pki install -c client.yaml --from kit-client-v2
run "$bin" pki activate -c client.yaml v2
sleep 3
r=$(json load --target "127.0.0.1:$cli_mtls" --channels 5 --bytes 1KiB)
check "client with its new certificate accepted again" test "$(field ok "$r")" = 5

# ================================================================ 11
step "Administration and metrics"
background "$kit" load --target "127.0.0.1:$cli_tls" --channels 4 --bytes 1KiB --hold 6s
sleep 1
run "$bin" channels -c server.yaml
shell "tlsrelay metrics -c server.yaml | grep -E '^tlsrelay_(channels_opened|peers_rejected|peers_revoked|pki_rotations|certificates_revoked|renegotiations)_total'"
check "metrics in Prometheus text format" bash -c "'$bin' metrics -c server.yaml | grep -q '^# TYPE tlsrelay_channels_active gauge'"
check "no private key nor passphrase in the logs" \
  bash -c "! grep -qE 'PRIVATE KEY|phrase de passe de démonstration' server.log client.log"

# ================================================================ 12
step "Editor tlsrelay-admin"
if [ -x "$editor" ]; then
  run "$editor" --check server.yaml
  sed "s/127.0.0.1:$srv_tls/127.0.0.1:99999/" server.yaml > server-invalid.yaml
  run "$editor" --check server-invalid.yaml
  check "editor validates with the service's own rules" bash -c "'$editor' --check server.yaml && ! '$editor' --check server-invalid.yaml"
  if command -v xvfb-run >/dev/null && command -v import >/dev/null; then
    for f in server server-invalid; do
      xvfb-run -a -s "-screen 0 1280x860x24" bash -c \
        "'$editor' '$work/$f.yaml' & sleep 3; import -window root png:- | convert - -trim +repage '$work/editor-$f.png'; kill \$!" >/dev/null 2>&1
    done
    say "screenshots: editor-server.png, editor-server-invalid.png"
  fi
else
  say "(editor not built in this directory: skipped)"
fi

# ================================================================ 13
step "Graceful stop and audit"
run "$bin" stop -c client.yaml
run "$bin" stop -c server.yaml
run "$bin" ca audit --dir ca
check "CA audit log intact" "$bin" ca audit --dir ca

printf '\n%s━━ Result: %d check(s) passed, %d failed%s\n' "$B" "$passed" "$failed" "$N"
[ -n "$keep" ] && echo "files kept in $work"
[ "$failed" = 0 ]
