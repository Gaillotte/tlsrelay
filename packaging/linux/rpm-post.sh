# Paquet RPM tlsrelay : compte système, répertoire de configuration ; après une
# mise à jour ($1 = 2), instances en service relancées avec le nouveau binaire.
getent group tlsrelay >/dev/null || groupadd --system tlsrelay
getent passwd tlsrelay >/dev/null ||
    useradd --system --gid tlsrelay --no-create-home --home-dir /nonexistent --shell /sbin/nologin tlsrelay
[ -d /etc/tlsrelay ] || install -d -m 0750 -o root -g tlsrelay /etc/tlsrelay
if [ "$1" -ge 2 ] && [ -d /run/systemd/system ]; then
    systemctl try-restart 'tlsrelay@*.service' >/dev/null 2>&1 || :
fi
exit 0
