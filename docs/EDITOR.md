# tlsrelay-admin — editor guide

`tlsrelay-admin` is the graphical editor for tlsrelay (release 1.1), for a Windows administration workstation. It edits the configurations and whitelists of the instances, prepares their deployment packages and manages the mini-CA. It does not connect to any instance: it works on files, which the instances then read.

## 1. Installation

"tlsrelay-admin" feature of the MSI (INSTALLATION §3):

```powershell
msiexec /i tlsrelay-<version>-win64.msi /qn ADDLOCAL=ALL
```

The editor is installed in `C:\Program Files\tlsrelay\bin`, with the Qt 6 libraries (LGPLv3, see `doc\THIRD-PARTY-NOTICES.txt` and `doc\LICENSES`), and a shortcut is added to the Start menu. It can also be opened on a file: `tlsrelay-admin.exe C:\path\branch.yaml`.

Checking a file without a window, with the service's rules (exit code 0: valid, 1: invalid, 2: unreadable; messages on standard error and in the `--report` file). It also works on a machine without a display (Linux server, SSH session):

```powershell
Start-Process -Wait -PassThru "C:\Program Files\tlsrelay\bin\tlsrelay-admin.exe" `
    -ArgumentList '--check', 'C:\path\branch.yaml', '--report', 'C:\path\check.txt'
```

## 2. Configuring an instance

- **File > New server / client configuration**, or **Open** an existing configuration. An invalid file opens too: its errors are listed so they can be fixed. Items the editor cannot take over (unknown key, value of an unexpected type) are reported: they will not be rewritten.
- The **Configuration** tab shows all sections of the file (SPEC §8). An empty field takes the default value, shown greyed out. Fields that do not apply to the selected mode (for example `destination` for a client) are hidden, unless they contain a value.
- Each entry is validated by the service's own loader: the errors shown at the bottom of the window are exactly those `tlsrelay check-config` would report. The field in error is outlined in red, with the message as a tooltip; double-clicking an error puts the cursor in the field.
- In server mode, the **Whitelist** tab edits the file designated by `whitelist.file` (a relative path is resolved from the configuration's directory): one peer per line (name, IP address or range, ports, certificate subject). With no port box checked, the peer gets the default ports (plain and tls, plus mtls if a subject is given). Cells in error are highlighted.

## 3. Saving

**File > Save** (Ctrl+S):

1. saving is refused as long as errors remain;
2. a preview shows the differences for each file (configuration and, in server mode, whitelist);
3. after confirmation, each modified file is first copied to `<file>.bak`, then replaced in one go (rename): an instance watching the file never reads a half-written file.

Files are rewritten in a normalized form: sections in SPEC order, default values omitted, "Written by tlsrelay-admin" header. **Comments in the original file are not preserved** (they remain in the `.bak`).

A saved whitelist is picked up by the instance within 2 seconds (file watching) or with `tlsrelay reload`. A modified configuration requires restarting the instance, except for logging levels.

## 4. Deployment package

**File > Export deployment package** (Ctrl+E) creates, in the chosen directory, a subdirectory named after the instance, to be copied to its machine:

| File | Contents |
|---|---|
| `<instance>.yaml` | configuration |
| `whitelist.yaml` | whitelist (server) |
| `kit\` | PKI kit produced by a signing (optional) |
| `crl.pem` | CRLs published by the CA (optional) |
| `install.sh` or `install.ps1` | installation of the files, check of the configuration, kit and CRLs |
| `README.txt` | remaining steps, in order: certificate request, activation, file permissions, service |

The configuration is installed at the instance's default location (`/etc/tlsrelay/<instance>.yaml`, `C:\ProgramData\tlsrelay\<instance>.yaml`), the one used by `--instance` and `service install`. The dialog points out things to watch for, for example a relative path (the service would resolve it from its working directory) or an `admin.endpoint` defined for a service.

## 5. PKI (certificate authority)

The **PKI** tab manages a mini-CA, the same as `tlsrelay ca`: the directory can be used interchangeably by the editor and by the command line.

- **Open a CA** (created by `tlsrelay ca init` or by the editor) or **Create a CA** (15-year P-384 root, 5-year Servers CA and Clients CA). The summary shows the CA certificates (subject, expiry, SHA-256 fingerprint), the inventory and the state of the CRLs: CRLs that are expired or due for republishing within 7 days are flagged.
- **Inventory** ("Issued certificates" tab): serial, role, state, end of validity, subject, revocation; filters (in service, revoked, expiring within 30 days, replaced or expired). Revoked certificates are shown in red, those expiring within 30 days on an orange background.
- **Sign a request**: the request (`request.csr`, produced on the instance by `tlsrelay pki gen-csr`) is examined as soon as it is selected: subject, requested extensions (ignored: the CA imposes its own), compliance (P-256 key, proof of possession). For a server, at least one name (SAN) is mandatory. The produced kit (`cert.pem`, `chain.pem`, `trust-roots.pem`, `trust-issuer.pem`) is to be installed on the instance: `tlsrelay pki install -c <conf> --from <kit>`, then `pki activate`.
- **Renew**: wizard to renew the selected certificate. The new request, with a new key, is produced on the instance with the same subject; the editor flags a different subject. The old certificate is marked "replaced".
- **Revoke**: choose the certificate and the reason; the CRLs are published immediately (and copied if a file is given). The revocation takes effect on each instance when the CRLs are installed there: `tlsrelay pki crl -c <conf> crl.pem` (SPEC §7.7).
- **Publish CRLs**: to be redone before they expire (30 days by default), then redeployed.
- **Audit log**: all CA operations (creation, signings, revocations, CRLs, root change), with the operator; the hash chain is checked each time it is displayed and tampering is flagged in red.
- **Root change**: the wizard creates the new CA (or takes over an existing one), then prepares the trust files for steps 1 and 2 for each role and a `README.txt` with the commands for the three steps (SPEC §7.5). Same result as `tlsrelay ca root-change`.

The CA passphrase is asked for on each operation that uses a CA key; it is never stored. The CA directory and its passphrase stay on the administration workstation and are backed up offline (OPERATIONS §4).

## 6. Good practices

- Keep the configurations under version control, or at least keep the `.bak` files; the diff preview serves as a review before each save.
- Use absolute paths for `whitelist.file`, `credentials.pki_root` and `logging.output`.
- Do not define `admin.endpoint` for an instance installed as a service.
- Publish the CRLs on a fixed schedule (for example every month) and deploy them to every instance that verifies its peers.
