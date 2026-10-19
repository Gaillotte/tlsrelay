#!/bin/sh
# tlsrelay Debian package: uninstallation, instances stopped (with drain).
set -e
if [ "$1" = remove ] && [ -d /run/systemd/system ]; then
    systemctl stop 'tlsrelay@*.service' >/dev/null 2>&1 || true
fi
exit 0
