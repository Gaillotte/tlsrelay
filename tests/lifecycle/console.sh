#!/usr/bin/env bash
# Console-mode lifecycle (SPEC §10), with the real binary:
# startup, instance lock, status, reload, stop with drain, kill, SIGTERM.
# Usage: console.sh <path to tlsrelay>
set -euo pipefail

bin=$(realpath "$1")
work=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$work"' EXIT
cd "$work"

# Looks for a pattern in the whole output of a command (grep -q would close the pipe too early: SIGPIPE with pipefail).
has() { local out; out=$(cat); grep -q -- "$1" <<<"$out"; }
fail() { echo "FAILED: $*" >&2; exit 1; }
port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }

dest=$(port)
listen=$(port)
cat > whitelist.yaml <<YAML
peers:
  - { name: local, ip: 127.0.0.1, ports: [plain] }
YAML
cat > server.yaml <<YAML
mode: server
instance: trial
logging: { output: $work/server.log }
whitelist: { file: $work/whitelist.yaml }
destination: { address: 127.0.0.1, port: $dest }
admin: { endpoint: $work/trial.sock }
limits: { shutdown_timeout: 2s }
ports:
  plain: { listen: "127.0.0.1:$listen" }
YAML

wait_ready() {
  for _ in $(seq 50); do "$bin" status -c server.yaml >/dev/null 2>&1 && return 0; sleep 0.1; done
  fail "the instance does not respond"
}

# 1. Startup and status
"$bin" run -c server.yaml & pid=$!
wait_ready
"$bin" status -c server.yaml | has "instance: trial" || fail "status"
"$bin" status -c server.yaml | has "pid: $pid" || fail "pid"

# 2. A single run per instance
if "$bin" run -c server.yaml 2> second.err; then fail "second run accepted"; fi
grep -q "another run" second.err || fail "lock message: $(cat second.err)"

# 3. Reload and live logging changes
"$bin" reload -c server.yaml | has "whitelist: 1 peer" || fail "reload"
"$bin" log-level -c server.yaml debug | has "activity=debug" || fail "log-level"
"$bin" metrics -c server.yaml | has '^tlsrelay_channels_opened_total{instance="trial"} 0$' || fail "metrics"

# 4. Graceful stop
"$bin" stop -c server.yaml --timeout 1s | has "stopped" || fail "stop"
wait $pid || fail "exit code after stop"
[ ! -e trial.sock ] || fail "socket not removed"
{ "$bin" status -c server.yaml 2>&1 || true; } | has "unreachable" || fail "status after stop"
"$bin" stop -c server.yaml | has "already stopped" || fail "stop of a stopped instance"

# 5. Immediate stop
"$bin" run -c server.yaml & pid=$!
wait_ready
"$bin" kill -c server.yaml | has "immediately" || fail "kill"
wait $pid || true

# 6. SIGTERM: graceful stop (service manager)
"$bin" run -c server.yaml & pid=$!
wait_ready
kill -TERM $pid
wait $pid || fail "exit code after SIGTERM"
grep -q "service stopped" server.log || fail "log"

# 7. Restart after a hard kill: lock released, orphaned socket replaced
"$bin" run -c server.yaml & pid=$!
wait_ready
kill -KILL $pid; wait $pid 2>/dev/null || true
[ -e trial.sock ] || fail "orphaned socket expected"
"$bin" run -c server.yaml & pid=$!
wait_ready
"$bin" stop -c server.yaml >/dev/null
wait $pid

echo "console lifecycle: OK"
