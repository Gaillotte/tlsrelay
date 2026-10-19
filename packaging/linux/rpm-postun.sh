# tlsrelay RPM package: uninstallation ($1 = 0), systemd units written by
# "tlsrelay service install" removed. /etc/tlsrelay (configurations, whitelists,
# PKI) and the tlsrelay account are kept.
if [ "$1" -eq 0 ]; then
    rm -f /etc/systemd/system/tlsrelay@.service
    rm -rf /etc/systemd/system/tlsrelay@*.service.d
    [ -d /run/systemd/system ] && systemctl daemon-reload >/dev/null 2>&1 || :
fi
exit 0
