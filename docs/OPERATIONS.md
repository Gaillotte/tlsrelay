# tlsrelay — operations

Day-to-day operation of installed instances ([INSTALLATION.md](INSTALLATION.md)). Commands target an instance with `--instance <name>` (default configuration) or `-c <configuration>`; on Linux, they require `sudo` or membership of the `tlsrelay` group; on Windows, an administrator PowerShell.

## 1. Common commands

| Need | Command |
|---|---|
| Status: version, OpenSSL, PKI generation, whitelist, channels per port | `tlsrelay status --instance branch` |
| Open channels: peer, generation, age, bytes, flow-control state | `tlsrelay channels --instance branch` |
| Metrics (Prometheus format) | `tlsrelay metrics --instance branch` |
| Reload whitelist, PKI and log levels without stopping | `tlsrelay reload --instance branch` |
| Start, restart | `tlsrelay start --instance branch`, `tlsrelay restart --instance branch` |
| Graceful stop: no new channels, drain (30 s by default), stop | `tlsrelay stop --instance branch [--timeout 60s]` |
| Immediate stop | `tlsrelay kill --instance branch` |
| Change the log level on the fly | `tlsrelay log-level --instance branch debug` (or `activity=trace`) |
| Reopen the log file (rotation) | `tlsrelay log-reopen --instance branch` |
| Validate a configuration or a PKI without applying it | `tlsrelay check-config -c <file>`, `tlsrelay check-pki -c <file> [vN]` |

## 2. Logs

| System | Default location |
|---|---|
| Linux (systemd) | system journal: `journalctl -u tlsrelay@branch` |
| Windows (service) | `%ProgramData%\tlsrelay\logs\branch.log` |
| Chosen file | `logging.output: /var/log/tlsrelay/branch.log` in the configuration |

- Levels (SPEC §9): `info` (startup, shutdown, reloads, rejections, failures to reach the destination, administration operations), `debug` (opening and closing of each channel, renegotiations), `trace` (handshakes, frames). Never any key, token or relayed data; data coming from a peer is escaped.
- JSON format (one line per event) for a log collector: `logging.format: json`.
- Rotating a log file on Linux, for example `/etc/logrotate.d/tlsrelay`:

```
/var/log/tlsrelay/*.log {
    weekly
    rotate 8
    compress
    delaycompress
    missingok
    notifempty
    postrotate
        for i in /etc/tlsrelay/*.yaml; do tlsrelay log-reopen -c "$i" >/dev/null 2>&1 || true; done
    endscript
}
```

## 3. Monitoring

Metrics are read over the administration channel (`tlsrelay metrics`), in Prometheus text format. With node_exporter, a textfile collector is enough, for example a scheduled task every minute:

```sh
tlsrelay metrics --instance branch > /var/lib/node_exporter/textfile/tlsrelay_branch.prom.tmp &&
    mv /var/lib/node_exporter/textfile/tlsrelay_branch.prom.tmp /var/lib/node_exporter/textfile/tlsrelay_branch.prom
```

| Metric | What to watch |
|---|---|
| `tlsrelay_channels_active` | Close to `limits.max_channels`: capacity needs reviewing |
| `tlsrelay_channels_rejected_total` | Increasing: `max_channels` limit reached |
| `tlsrelay_tls_handshake_failures_total` | Increasing: certificates refused, non-compliant peers or scans |
| `tlsrelay_peers_rejected_total` | Increasing: connections from peers not in the whitelist |
| `tlsrelay_dial_failures_total` | Increasing: destination unreachable (server) or server unreachable (client) |
| `tlsrelay_resume_failures_total` | Increasing: session resumptions refused or failed (unstable network) |
| `tlsrelay_pki_reload_failures_total` | Increasing: new PKI generation refused, the old one stays in service |
| `tlsrelay_pki_generations_live` | Stays above 1 for a long time: connections still on a retired generation |
| `tlsrelay_crl_reload_failures_total` | Increasing: CRL file refused, the previous CRLs stay in force |
| `tlsrelay_certificates_revoked_total` | Increasing: channels closed after their peer's certificate was revoked |
| `tlsrelay_process_resident_memory_bytes`, `tlsrelay_process_open_descriptors` | Continuous growth |

The log also reports, at startup and at every reload, certificates that expire in less than `credentials.expiry_warning` (30 days by default), and stale CRLs (to be republished).

## 4. PKI

**Renewing an instance's certificate** (before it expires), without interruption:

```sh
sudo tlsrelay pki gen-csr -c /etc/tlsrelay/branch.yaml --subject "CN=relay.branch.example,O=Example" --san relay.branch.example
# CA workstation: tlsrelay ca sign --dir <ca> --role server --csr request.csr --san relay.branch.example --renew --out kit
sudo tlsrelay pki install -c /etc/tlsrelay/branch.yaml --from kit
sudo tlsrelay pki activate -c /etc/tlsrelay/branch.yaml v2
sudo tlsrelay reload --instance branch          # or wait for the automatic watch (2 s)
```

New connections use the new generation; open channels move to it at their next renegotiation (`session_lifetime`), without a cut.

**Changing the root**: three-step procedure in SPEC §7.5 (pre-trust, switchover, withdrawal). After `tlsrelay ca init --dir <new ca>`, `tlsrelay ca root-change --dir <ca> --new <new ca> --out <directory>` (or the wizard in the PKI tab of `tlsrelay-admin`) produces the trust files for steps 1 and 2 for each role, and a `README.txt` with the commands for each step (`pki install --roots` and `--issuer`). Scenario R09 of `tools/acceptance.ps1` runs the procedure end to end.

**Revoking a certificate** (lost or compromised key, decommissioned instance), on the CA workstation and then on each instance:

```sh
tlsrelay ca list --dir <ca>                                     # certificate serial number
tlsrelay ca revoke --dir <ca> --serial <serial> --reason keyCompromise --out crl.pem
sudo tlsrelay pki crl -c /etc/tlsrelay/branch.yaml crl.pem      # on each instance
```

Instances that verify their peer (server with an `mtls` port, clients) immediately refuse the revoked certificate and close the channels using it (SPEC §7.7). CRLs have a validity period (30 days by default): republish them before they expire with `tlsrelay ca crl --dir <ca> --out crl.pem` and redeploy them, for example every month; a stale CRL stays in force but the log reports it.

**Emergency revocation** of a peer, without waiting for the CA: remove it from the whitelist, then `tlsrelay reload` (its channels are closed if `revoke_mode: immediate`). Of a compromised generation: activate a new generation, then `tlsrelay reload --kill-old`, which immediately closes the old generation's connections.

**CA**: the mini-CA directory and its passphrase stay on the administration workstation, backed up offline; `tlsrelay ca list --dir <ca>` gives its inventory, `tlsrelay ca audit --dir <ca>` the log of operations (creation, signatures, revocations, CRLs) and its integrity check.

## 5. Backup

To back up: the configuration, whitelist and PKI of each instance (`/etc/tlsrelay`, `%ProgramData%\tlsrelay`, CRL included), protecting the private keys; the CA directory (audit log included), on the administration workstation. tlsrelay keeps no other state.

## 6. Troubleshooting

| Symptom | Probable cause | Action |
|---|---|---|
| The service does not start | Invalid configuration, or unreadable by the service account; PKI refused | `journalctl -u tlsrelay@<name>` or `%ProgramData%\tlsrelay\logs\<name>.log`; `tlsrelay check-config`, `tlsrelay check-pki`; file permissions (INSTALLATION §4.4) |
| "TLS handshake refused: peer certificate refused" | Certificate expired, from another PKI or from an unexpected issuing CA, server name different from `server_name` | `tlsrelay status` and `check-pki` on both sides; `openssl x509 -text` on the certificate |
| "client certificate revoked" or "server certificate revoked" | Peer certificate listed in the CRL in `<pki_root>/crl.pem` | Normal after `ca revoke`; otherwise `tlsrelay ca list` on the CA workstation, then a new certificate for the peer |
| "invalid CRL" at startup or reload | `crl.pem` unreadable or signed by another CA | `tlsrelay check-pki -c <config>`; redeploy the CRL published by `ca crl` |
| "peer refused by the whitelist" | Address or subject missing from the server's whitelist, or in two different entries | Compare with the address seen by the server (NAT) and the exact subject of the client certificate |
| "<destination> unreachable after N attempt(s)" | Destination stopped or filtered | Check the destination from the server; `destination.dial_*` |
| Channels closed for inactivity (`reason=idle_timeout` at `debug`) | No data during `idle_timeout` | Increase `limits.idle_timeout` if the application stays silent for long periods |
| Frequent cuts "no frame received" | Silent link (stateful firewall, NAT that forgets connections) | Lower `limits.keepalive_interval` below the firewall timeout; the session is resumed automatically |
| Throughput of a saturated channel stalls for a few tens of seconds, without loss | Known limitation on the loopback (README, "Known limitation") | `tlsrelay channels` shows the flow-control state; does not affect traffic at nominal throughput |
| `tlsrelay status`: "instance unreachable" | Instance stopped, or caller without rights on the channel | `systemctl status tlsrelay@<name>` / `Get-Service tlsrelay-<name>`; use `sudo` or an administrator PowerShell |
