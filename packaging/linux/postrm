#!/bin/sh
# tlsrelay Debian package: purge, systemd units written by "tlsrelay service
# install" removed. /etc/tlsrelay (configurations, whitelists, PKI) and the
# tlsrelay account are kept.
set -e
if [ "$1" = purge ]; then
    rm -f /etc/systemd/system/tlsrelay@.service
    rm -rf /etc/systemd/system/tlsrelay@*.service.d
    [ -d /run/systemd/system ] && systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0
