# tlsrelay RPM package: system account, configuration directory; after an
# upgrade ($1 = 2), running instances are restarted with the new binary.
getent group tlsrelay >/dev/null || groupadd --system tlsrelay
getent passwd tlsrelay >/dev/null ||
    useradd --system --gid tlsrelay --no-create-home --home-dir /nonexistent --shell /sbin/nologin tlsrelay
[ -d /etc/tlsrelay ] || install -d -m 0750 -o root -g tlsrelay /etc/tlsrelay
if [ "$1" -ge 2 ] && [ -d /run/systemd/system ]; then
    systemctl try-restart 'tlsrelay@*.service' >/dev/null 2>&1 || :
fi
exit 0
