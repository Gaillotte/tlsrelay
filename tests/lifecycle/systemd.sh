#!/usr/bin/env bash
# Lifecycle under systemd (SPEC §10), to be run as root on a test
# machine: installation, start at boot, relaying, reload, restart, stop, kill,
# stop through systemctl, refusal of an unauthorized user, uninstallation.
# Usage: sudo systemd.sh <path to tlsrelay>
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
fail() { echo "FAILED: $*" >&2; journalctl -u tlsrelay@ci --no-pager -n 50 || true; exit 1; }
step() { echo "== $*"; }

# Binary installed outside /home (ProtectHome=yes in the unit).
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

step "installation with start at boot"
"$bin" service install --instance ci --boot
chgrp tlsrelay /etc/tlsrelay/ci.yaml /etc/tlsrelay/ci-whitelist.yaml
chmod 0640 /etc/tlsrelay/ci.yaml /etc/tlsrelay/ci-whitelist.yaml
[ "$(systemctl is-enabled tlsrelay@ci)" = enabled ] || fail "start at boot"

step "startup"
"$bin" start --instance ci
[ "$(systemctl is-active tlsrelay@ci)" = active ] || fail "service inactive"
"$bin" status --instance ci | tee "$work/status" | grep -q "instance: ci" || fail "status"
[ "$(ps -o user= -p "$(systemctl show -p MainPID --value tlsrelay@ci)")" = tlsrelay ] || fail "service account"
"$bin" start --instance ci | grep -q "already started" || fail "second start"

step "relaying data through the service"
cat > "$work/client.yaml" <<YAML
mode: client
instance: ci-client
admin: { enabled: false }
ports:
  plain: { listen: "127.0.0.1:17001", upstream: "127.0.0.1:19001" }
YAML
"$bin" run -c "$work/client.yaml" & client_pid=$!
sleep 0.5
python3 "$here/exchange.py" 17001 || fail "exchange"

step "access refused to an unauthorized user"
if sudo -u nobody "$bin" status --instance ci 2>"$work/nobody.err"; then fail "nobody obtained the status"; fi
cat "$work/nobody.err"

step "reload (tlsrelay reload and systemctl reload)"
"$bin" reload --instance ci | grep -q "whitelist: 1 peer" || fail "reload"
systemctl reload tlsrelay@ci || fail "systemctl reload"

step "restart"
pid1=$(systemctl show -p MainPID --value tlsrelay@ci)
"$bin" restart --instance ci
pid2=$(systemctl show -p MainPID --value tlsrelay@ci)
[ "$pid1" != "$pid2" ] && [ "$pid2" != 0 ] || fail "PID unchanged after restart"
python3 "$here/exchange.py" 17001 || fail "exchange after restart"

step "graceful stop"
"$bin" stop --instance ci
sleep 0.5
[ "$(systemctl is-active tlsrelay@ci || true)" = inactive ] || fail "still active after stop"
"$bin" stop --instance ci | grep -q "already stopped" || fail "stop of a stopped instance"

step "stop through systemctl stop (SIGTERM, drain)"
# Log read since this start (a binary instrumented for coverage adds its own lines to it).
since=$(date '+%Y-%m-%d %H:%M:%S')
"$bin" start --instance ci
systemctl stop tlsrelay@ci
journalctl -u tlsrelay@ci --no-pager --since "$since" | grep -q "service stopped" || fail "graceful stop not logged"

step "immediate stop"
"$bin" start --instance ci
"$bin" kill --instance ci
sleep 0.5
[ "$(systemctl is-active tlsrelay@ci || true)" != active ] || fail "still active after kill"

step "uninstallation"
"$bin" service uninstall --instance ci
[ ! -e /etc/systemd/system/tlsrelay@ci.service.d ] || fail "drop-in left behind"
if "$bin" service uninstall --instance ci 2>"$work/uninstall.err"; then fail "second uninstallation accepted"; fi
grep -q "is not installed" "$work/uninstall.err" || fail "message of the second uninstallation"

echo "systemd lifecycle: OK"
