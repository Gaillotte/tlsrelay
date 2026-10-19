# tlsrelay — installation

Installing the release packages, setting up a first instance, upgrading and uninstalling. Day-to-day operations (monitoring, logs, PKI rotation, troubleshooting) are described in [OPERATIONS.md](OPERATIONS.md); the configuration format and detailed behavior, in [SPEC.md](SPEC.md).

## 1. Packages

| File | Systems | Content |
|---|---|---|
| `tlsrelay_<version>-1_amd64.deb` | Ubuntu 22.04 and later, Debian 12 and later | `tlsrelay`, documentation, examples |
| `tlsrelay-testkit_<version>-1_amd64.deb` | same | `tlsrelay-testkit` (test and acceptance tooling) |
| `tlsrelay-<version>-1.el9.x86_64.rpm` | RHEL 9, Rocky Linux 9, AlmaLinux 9 | `tlsrelay`, documentation, examples |
| `tlsrelay-testkit-<version>-1.el9.x86_64.rpm` | same | `tlsrelay-testkit` |
| `tlsrelay-<version>-win64.msi` | Windows 10 and 11, Windows Server 2019 and later (64-bit) | `tlsrelay`, OpenSSL 3.5 LTS, MSVC runtime, documentation; optional features "tlsrelay-testkit" (tooling and acceptance scripts) and "tlsrelay-admin" (graphical editor, Qt 6 under LGPLv3, [EDITOR.md](EDITOR.md)) |

- Linux: `tlsrelay` uses the distribution's OpenSSL (3.0 or later), kept up to date by its security fixes; the other libraries are built into the binary.
- Windows: OpenSSL 3.5 LTS is shipped in the package; an OpenSSL patch update comes with a new version of the package.
- `tlsrelay-testkit` is not needed in production; it is used for load and disturbance testing and for acceptance.

**Integrity.** Each release comes with a `SHA256SUMS` file:

```sh
sha256sum -c SHA256SUMS --ignore-missing          # Linux
```
```powershell
Get-FileHash -Algorithm SHA256 .\tlsrelay-0.1.0-win64.msi   # Windows: compare with SHA256SUMS
```

## 2. Installing on Linux

```sh
# Debian, Ubuntu
sudo apt install ./tlsrelay_0.1.0-1_amd64.deb
# RHEL, Rocky Linux, AlmaLinux
sudo dnf install ./tlsrelay-0.1.0-1.el9.x86_64.rpm
```

The package installs `/usr/bin/tlsrelay`, the documentation and the examples in `/usr/share/doc/tlsrelay/`, and creates the `tlsrelay` system account and the `/etc/tlsrelay` directory (`0750`, `root:tlsrelay`). It neither installs nor starts any instance: each instance is created by the administrator (section 4).

## 3. Installing on Windows

To build the project and the MSI yourself: [BUILD-WINDOWS.md](BUILD-WINDOWS.md).

Double-click the MSI, or install silently from an administrator PowerShell:

```powershell
msiexec /i tlsrelay-0.1.0-win64.msi /qn                    # tlsrelay only
msiexec /i tlsrelay-0.1.0-win64.msi /qn ADDLOCAL=ALL       # with tlsrelay-testkit, the acceptance scripts and tlsrelay-admin
```

Layout: `C:\Program Files\tlsrelay\bin` (executables and DLLs), `doc` (documentation, examples), `tools` (acceptance scripts, with the testkit). The `bin` directory is not added to the `PATH`: the commands below use `tlsrelay` for `& 'C:\Program Files\tlsrelay\bin\tlsrelay.exe'`.

## 4. First instance

Example: a server instance `branch` that accepts tlsrelay clients over mTLS on port 9003 and relays to `10.0.0.5:8080`. The steps are the same for a client instance (section 4.6).

### 4.1 Configuration

Start from the shipped example:

| | Linux | Windows |
|---|---|---|
| Examples | `/usr/share/doc/tlsrelay/examples/` | `C:\Program Files\tlsrelay\doc\examples\` |
| Instance configuration | `/etc/tlsrelay/branch.yaml` | `%ProgramData%\tlsrelay\branch.yaml` |
| Instance PKI | for example `/etc/tlsrelay/branch/pki` | for example `%ProgramData%\tlsrelay\branch\pki` |

```yaml
mode: server
instance: branch
credentials: { pki_root: /etc/tlsrelay/branch/pki }
whitelist: { file: /etc/tlsrelay/branch/whitelist.yaml }
destination: { address: 10.0.0.5, port: 8080 }
ports:
  mtls: { listen: "0.0.0.0:9003" }
```

Without `logging.output`, the log goes to the system journal (systemd) or to `%ProgramData%\tlsrelay\logs\branch.log` (Windows). The administration channel is the default one (do not set `admin.endpoint` for a service).

### 4.2 Whitelist

```yaml
peers:
  - name: site-lyon
    ip: 192.0.2.10
    ports: [mtls]
    subject: "CN=site-lyon,O=Example"
```

### 4.3 PKI

On the instance, create the key and the certificate request (the key never leaves the machine):

```sh
sudo tlsrelay pki gen-csr -c /etc/tlsrelay/branch.yaml --subject "CN=relay.branch.example,O=Example" --san relay.branch.example
```

On the CA workstation (mini-CA created once with `tlsrelay ca init --dir <ca>`), sign the request, then bring the kit back to the instance:

```sh
tlsrelay ca sign --dir <ca> --role server --csr request.csr --san relay.branch.example --out branch-kit
```

On the instance:

```sh
sudo tlsrelay pki install -c /etc/tlsrelay/branch.yaml --from branch-kit
sudo tlsrelay pki activate -c /etc/tlsrelay/branch.yaml v1
```

### 4.4 File permissions

The service account reads the configuration, the whitelist and the PKI; nobody other than it and the administrators may access them.

```sh
sudo chown -R root:tlsrelay /etc/tlsrelay/branch.yaml /etc/tlsrelay/branch
sudo chmod 0640 /etc/tlsrelay/branch.yaml
sudo find /etc/tlsrelay/branch -type d -exec chmod 0750 {} + -o -type f -exec chmod 0640 {} +
```

On Windows, after installing the service (section 4.5), which creates the virtual account `NT SERVICE\tlsrelay-branch`:

```powershell
icacls "$env:ProgramData\tlsrelay\branch" /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "NT SERVICE\tlsrelay-branch:(OI)(CI)RX"
icacls "$env:ProgramData\tlsrelay\branch.yaml" /inheritance:r /grant:r "*S-1-5-32-544:F" "*S-1-5-18:F" "NT SERVICE\tlsrelay-branch:R"
```

### 4.5 Service

```sh
sudo tlsrelay check-config -c /etc/tlsrelay/branch.yaml
sudo tlsrelay check-pki -c /etc/tlsrelay/branch.yaml
sudo tlsrelay service install --instance branch --boot      # start at system boot
sudo tlsrelay start --instance branch
sudo tlsrelay status --instance branch
```

On Windows, same commands in an administrator PowerShell; the default configuration is `%ProgramData%\tlsrelay\branch.yaml` (`-c` for another location). If the service does not start, the cause is in `%ProgramData%\tlsrelay\logs\branch.log` (Windows) or `journalctl -u tlsrelay@branch` (Linux).

### 4.6 Client instance

Same procedure with `mode: client`, ports that declare `upstream` and `server_name`, and a certificate with the `client` role (`tlsrelay ca sign --role client`). The client certificate's subject must be in the server's whitelist, together with the IP address the client connects from. Example: `client.yaml` in the examples.

## 5. Upgrading

- **Linux**: `sudo apt install ./tlsrelay_<new version>_amd64.deb` or `sudo dnf install ./tlsrelay-<new version>.rpm`. Running instances are restarted with the new binary (stop with drain, then start); configurations, whitelists and PKIs are kept.
- **Windows**: stop the instances (`tlsrelay stop --instance <name>`), install the new MSI (it replaces the old version), then restart them (`tlsrelay start --instance <name>`).

## 6. Uninstalling

- **Linux**: `sudo apt remove tlsrelay` (or `sudo dnf remove tlsrelay`) stops the instances (with drain) and removes the binary. `sudo apt purge tlsrelay` also removes the instances' systemd units. `/etc/tlsrelay` (configurations, whitelists, PKIs) and the `tlsrelay` account are kept: delete them by hand if needed.
- **Windows**: first uninstall each instance (`tlsrelay service uninstall --instance <name>`), then the package ("Installed apps", or `msiexec /x tlsrelay-0.1.0-win64.msi /qn`). `%ProgramData%\tlsrelay` is kept.
