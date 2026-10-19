# tlsrelay RPM package: uninstallation ($1 = 0), instances stopped (with drain).
if [ "$1" -eq 0 ] && [ -d /run/systemd/system ]; then
    systemctl stop 'tlsrelay@*.service' >/dev/null 2>&1 || :
fi
exit 0
