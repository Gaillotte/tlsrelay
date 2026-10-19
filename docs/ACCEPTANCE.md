# tlsrelay — acceptance test plan

Acceptance of release 1 by the project manager, on a single Windows workstation (PLAN §5.7). The `tools/acceptance.ps1` script runs the automated scenarios and produces the report; the manual steps in section 5 cover what a script cannot check on its own (rebooting the workstation, another user's rights, reading the logs). The results are recorded in the acceptance report ([ACCEPTANCE-REPORT.md](ACCEPTANCE-REPORT.md)).

## 1. Acceptance testkit

```
                                      Windows workstation
┌───────────────────────────────────────────────────────────────────────────────────────────────┐
│ testkit ──► tlsrelay rc-client ──(testkit proxy, mtls port)──► tlsrelay rc-server ──► echo    │
│              127.0.0.2                 127.0.0.5                       127.0.0.3      127.0.0.4│
│                                                                                               │
│ Hyper-V VM Ubuntu 22.04 (internal switch): Linux instances for the cross tests (R13)          │
└───────────────────────────────────────────────────────────────────────────────────────────────┘
```

| Component | Address | Ports |
|---|---|---|
| Client `rc-client` | 127.0.0.2 (also source address towards the server) | 17101 plain, 17102 tls, 17103 mtls |
| Disturbance proxy (testkit) | 127.0.0.5 | 19203 → 19103 on the server |
| Server `rc-server` | 127.0.0.3 | 19101 plain, 19102 tls, 19103 mtls |
| Destination (testkit echo) | 127.0.0.4 | 18080 |

The plain and tls ports go directly from the client to the server; the mtls port goes through the proxy, which cuts the connections in scenario R06. The server whitelist only allows 127.0.0.2, with the subject `CN=rc-client,O=Acceptance` on the mtls port.

## 2. Prerequisites

**Windows workstation**
- Windows 10 or 11, Pro or Enterprise edition (Hyper-V for the cross tests); administrator account.
- tlsrelay and tlsrelay-testkit (release package, or build directory `build\windows-msvc\src\app\Release` and `...\src\testkit\Release`).
- PowerShell 5.1 (included in Windows) or PowerShell 7; OpenSSH client (included in Windows 10 and 11) for the cross tests.
- Ports 17101 to 19303 free on the loopback addresses.

**Linux VM (optional, cross tests R13)**
1. Hyper-V: create an **internal** virtual switch `tlsrelay-acceptance`, then an Ubuntu 22.04 VM connected to this switch.
2. Static addresses, for example workstation `192.168.50.1/24` (adapter "vEthernet (tlsrelay-acceptance)") and VM `192.168.50.2/24`.
3. On the VM: `sudo apt install openssh-server`; build tlsrelay for this distribution (README, "Building" section, Linux) until the `.deb` package is delivered (phase 11): binaries from another distribution do not work there (different library versions); open port 29303 (`sudo ufw allow 29303/tcp` if the firewall is active).
4. On the workstation: `ssh-keygen`, then copy `%USERPROFILE%\.ssh\id_ed25519.pub` into `~/.ssh/authorized_keys` on the VM; check `ssh user@192.168.50.2` works without a password.
5. Copy the built Linux binaries (`tlsrelay`, `tlsrelay-testkit`) to a directory on the workstation, for example `C:\acceptance\linux`.

## 3. Running

In an **administrator** PowerShell, from the root of the repository (or of the package):

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\tools\acceptance.ps1 -BuildDir 'C:\Program Files\tlsrelay' -Services -Keep `
    -LinuxHost acceptance@192.168.50.2 -LinuxBuildDir C:\acceptance\linux -LocalAddress 192.168.50.1
```

| Option | Effect |
|---|---|
| `-BuildDir` | Directory of `tlsrelay.exe`; `-TestkitDir` if the testkit is elsewhere |
| `-Services` | Instances installed as Windows services (`tlsrelay-rc-server`, `tlsrelay-rc-client`), under their virtual account, each instance's files restricted to its account and to administrators. Without this option: console processes |
| `-Keep` | Instances left running after the scenarios, for the manual steps; `stop-acceptance.ps1` (in the working directory) then stops everything |
| `-LinuxHost`, `-LinuxBuildDir`, `-LocalAddress`, `-SshPort` | Cross tests with the VM (R13) |
| `-Quick` | Shorter durations (quick check) |
| `-WorkDir` | Working and report directory (default: `%ProgramData%\tlsrelay\acceptance-<date>` in services mode, `.\acceptance-<date>` otherwise) |

Duration: about 10 minutes (3 minutes with `-Quick`). The `report.md` report in the working directory gives the versions, the SHA-256 fingerprints of the binaries, the result and details of each scenario, and log excerpts on failure. The exit code is 0 if all automated scenarios are OK.

## 4. Automated scenarios

| No. | Scenario | Expected result |
|---|---|---|
| R01 | Acceptance PKI from the mini-CA: `ca init`, `pki gen-csr`, `ca sign`, `pki install`, `pki activate`, `check-pki` for the server and the client | Hierarchy created, certificates issued and installed; a second certificate for the same subject is refused |
| R02 | Starting the instances (services or console) | Valid configurations; PKI generation v1 and whitelist loaded; services under their virtual account |
| R03 | Concurrent channels on the three ports (500 per port, 100 with `-Quick`) | All intact (SHA-256 fingerprint per channel) |
| R04 | Throughput and latency | Throughput ≥ 100 Mbit/s (measured paced at 200); added latency < 1 ms |
| R05 | Whitelist: client address removed, `reload`, then restored | New channels refused, then accepted again; refusals counted |
| R06 | Network cuts every 5 s on the mtls port (proxy) | Continuous stream intact; session resumptions performed |
| R07 | Renegotiation (`session_lifetime` 30 s) during a continuous stream | At least one renegotiation; stream intact, application never cut |
| R08 | Hot PKI rotation (server generation v2, `--renew`) | Switchover without interruption; new channels on v2 |
| R09 | Three-step root change (SPEC §7.5) with a second CA, continuous stream throughout the procedure | Channels accepted at each step; stream intact; no generation refused |
| R10 | Logging: `debug` level set at runtime, marker relayed | Channels logged at `debug`; no relayed data, private key or passphrase in the logs |
| R11 | Administration: `status`, `channels`, `metrics` | Complete responses |
| R12 | Lifecycle: `stop` (drain) and restart of the client, `kill` and restart of the server; service `restart` | Service restored each time; new process after `restart`; no exception logged |
| R13 | Cross tests (optional): workstation → Linux and Linux → workstation, over mTLS | All channels intact in both directions |

## 5. Manual steps

To be run after a run with `-Services -Keep`. Commands: `tlsrelay` stands for `C:\Program Files\tlsrelay-acceptance\tlsrelay.exe` (copy installed by the script); `$rc` stands for the working directory.

| No. | Step | Expected result | OK/KO |
|---|---|---|---|
| M01 | **Start at boot.** For `rc-server` then `rc-client`: `tlsrelay service uninstall --instance rc-server`, then `tlsrelay service install --instance rc-server -c $rc\rc-server.yaml --boot`; reboot the workstation, then `tlsrelay status --instance rc-server` | Services started without intervention; `status` answers "in service" | |
| M02 | **Workstation shutdown with open channels.** Run `tlsrelay-testkit throughput --target 127.0.0.2:17102 --duration 300s --rate 20`, then reboot the workstation | After the reboot, the `$rc\logs\rc-server.log` log shows "shutdown requested", the drain, then "service stopped" | |
| M03 | **Immediate stop during a transfer.** Same stream, then `tlsrelay kill --instance rc-server`; then `tlsrelay start --instance rc-server` and `tlsrelay-testkit load --target 127.0.0.2:17102 --channels 50` | The running stream stops (expected); the service restarts cleanly; the new channels are all intact | |
| M04 | **Command refused to a non-administrator.** Log in as a standard user, then `tlsrelay status --instance rc-server` | Access to the administration channel refused | |
| M05 | **Logging levels.** `tlsrelay log-level --instance rc-server trace`, one exchange (`tlsrelay-testkit load --target 127.0.0.2:17103 --channels 5`), then `log-level ... info` | At `trace`: handshake details (version, suite, chain) and frames; back to `info` level; content compliant with SPEC §9 | |
| M06 | **Log rotation.** Rename `$rc\logs\rc-server.log`, then `tlsrelay log-reopen --instance rc-server` | New file created; the old one is no longer written to | |
| M07 | **File permissions.** `icacls $rc\pki\rc-server` and `icacls $rc\rc-server.yaml` | Only SYSTEM, Administrators and `NT SERVICE\tlsrelay-rc-server` have access | |
| M08 | **Report.** Read `$rc\report.md` | tlsrelay and OpenSSL (3.5 LTS) versions and fingerprints match the release; all scenarios OK | |
| M09 | **End.** `& $rc\stop-acceptance.ps1` | Services uninstalled, processes stopped | |

## 6. tlsrelay-admin editor (release 1.1)

On the acceptance workstation, with the MSI installed with the "tlsrelay-admin" feature (`ADDLOCAL=ALL`), after the automated scenarios (the acceptance PKI and configurations are in `$rc`). The detailed behaviour of the editor is also covered by its automated tests (Qt Test, in CI); these steps check the actual installation and use. Guide: [EDITOR.md](EDITOR.md).

| No. | Step | Expected result | OK |
|---|---|---|---|
| E01 | **Installation.** Start "tlsrelay-admin" from the Start menu; "Help > About" | Window opens without DLL errors; tlsrelay, OpenSSL (3.5 LTS) and Qt versions displayed, LGPLv3 notice; `doc\LICENSES` present | |
| E02 | **Opening and validation.** Open a copy of `$rc\rc-server.yaml`; clear the mtls listening port, then enter `five minutes` in "Idle timeout" | Whitelist displayed; each error appears immediately, field outlined, message identical to `tlsrelay check-config` on the same content | |
| E03 | **Saving.** Fix, change `max_channels` and add a peer to the whitelist; Ctrl+S | Diff preview of both files; after confirmation, `.bak` files created; `tlsrelay check-config -c <copy>` valid | |
| E04 | **Picked up by an instance.** Open `$rc\rc-server.yaml` itself, remove the `rc-client` peer from the whitelist, save | Within 2 s, the `rc-server` log reports "whitelist reloaded" and the removed peer; mtls channels are refused; put the peer back: they are restored | |
| E05 | **Deployment package.** File > Export deployment package, Windows target machine, with a kit and CRLs | Directory named after the instance; `install.ps1` run on a test instance: configuration copied, `check-config` succeeds | |
| E06 | **Taking over the mini-CA.** PKI tab > Open a CA: `$rc\ca` | Summary (root, Servers and Clients CAs, fingerprints); inventory identical to `tlsrelay ca list --dir $rc\ca`; audit log "intact" | |
| E07 | **Signing and renewal.** On `rc-client`: `tlsrelay pki gen-csr`; in the editor: Renew (`rc-client` certificate selected); install the kit, activate, `reload` | Request examined (subject, extensions ignored); kit produced; the old certificate is "replaced"; `rc-client` switches over without a cut | |
| E08 | **Revocation.** Revoke the certificate of a test machine (reason "Key compromised") with a copy of the CRLs; on `rc-server`: `tlsrelay pki crl -c $rc\rc-server.yaml <copy of the CRLs>` | CRLs published; the certificate is refused at handshake ("revoked" in the log); `rc-server` `status` shows the CRL | |
| E09 | **Passphrase.** Start a signing with a wrong passphrase, then cancel an entry | Refused with "wrong passphrase", nothing is signed or written; cancelling performs no operation | |
| E10 | **Audit and root change.** Root change wizard to a new CA (created by the wizard); then modify a line of `$rc\ca\audit.log` in a text editor and reopen the CA | Step files and `README.txt` produced; operation recorded in the audit log of both CAs; after modification: "Log tampered with" in red (restore the file afterwards) | |

## 7. Beyond the scope of a single workstation

A single workstation does not cover a real network between machines (NAT, firewall, MTU, latency): the CI cross tests and R13 (VM on an internal switch) partly make up for this. A complementary test between two physical machines is recommended before going into production (PLAN §6), for example with `tools/acceptance-linux.ps1` from a second machine.
