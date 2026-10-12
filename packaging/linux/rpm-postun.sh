# Paquet RPM tlsrelay : désinstallation ($1 = 0), unités systemd écrites par
# « tlsrelay service install » retirées. /etc/tlsrelay (configurations, listes
# blanches, PKI) et le compte tlsrelay sont conservés.
if [ "$1" -eq 0 ]; then
    rm -f /etc/systemd/system/tlsrelay@.service
    rm -rf /etc/systemd/system/tlsrelay@*.service.d
    [ -d /run/systemd/system ] && systemctl daemon-reload >/dev/null 2>&1 || :
fi
exit 0
