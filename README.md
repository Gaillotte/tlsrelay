# tlsrelay

Command-line TCP relay that works in pairs (client / server) and carries an application's data to a destination in one of three modes:

| Port | Mode |
|---|---|
| 1 | Plaintext |
| 2 | TLS 1.3 |
| 3 | mTLS (TLS 1.3, mutual authentication) |

Main features:

- C++20, OpenSSL 3 (dynamically linked), 64-bit Windows and Linux
- Several parallel channels per port
- Hot rotation of key pairs, certificates and CAs up to the root, without service interruption
- Maximum idle time and maximum session lifetime, with full, transparent renegotiation
- Server-side peer whitelist (IP + certificate subject + issuing CA)
- Service started at system boot, stop / restart / forced stop, named instances
- Verbose mode (activity and configuration operation logs)
- Windows configuration and PKI editor (`tlsrelay-admin`, release 1.1)

## Documentation

- [Design document](docs/DESIGN.md): architecture, security, protocol, PKI, editor, quality; in 10 slides: [tlsrelay-design-slides.pdf](docs/tlsrelay-design-slides.pdf)
- [tlsrelay-admin editor](docs/EDITOR.md): configuration, whitelist, deployment packages, mini-CA (release 1.1)
- [Building and testing on Windows](docs/BUILD-WINDOWS.md): tools to install, build, tests, MSI package, troubleshooting
- [Installation](docs/INSTALLATION.md): `.deb`, `.rpm` and `.msi` packages, first instance, upgrade, uninstallation
- [Operations](docs/OPERATIONS.md): common commands, logs, monitoring, PKI, backup, troubleshooting
- [Development plan](docs/PLAN.md): decisions, architecture, schedule, test strategy, acceptance
- [Technical specification](docs/SPEC.md): TLS, tunnel protocol, whitelist, PKI, configuration, lifecycle
- [Test plan and report](docs/TESTS.md): strategy, environments, description of every test, requirements coverage
- [Penetration test checklist](docs/PENTEST.md): checkpoints, method, expected result, automated coverage
- [Acceptance test plan](docs/ACCEPTANCE.md) and [acceptance report](docs/ACCEPTANCE-REPORT.md): automated scenarios (`tools/acceptance.ps1`) and manual steps

## Status

| Phase | Content | Status |
|---|---|---|
| 0 | Specification | Done |
| 1 | Foundation: CMake/vcpkg, configuration and validation, logs and verbose mode, plaintext relay, multiple channels, `idle_timeout`, dial attempts to the destination, graceful shutdown | Done |
| 2 | TLS 1.3 on OpenSSL: `tls` port, ALPN `tlsrelay/1`, verification of the server name and issuing CA, PKI loading and checks | Done |
| 3 | mTLS (client certificate issued by the Clients CA) and peer whitelist (IP, subject, ports), hot-reloaded | Done |
| 4 | Hot rotation of certificates and CAs up to the root (generations, drain, safeguard, `check-pki`, `pki activate`, `SIGHUP`) | Done |
| 5 | `tlsrelay/1` tunnel protocol (frames, acknowledgements, backpressure, half-close), transparent renegotiation when `session_lifetime` expires, session resumption after a cut | Done |
| 6 | Lifecycle: systemd and Windows services (boot, start, stop, restart, kill), named instances, administration channel, Prometheus metrics, hot log-level changes | Done |
| 7 | Command-line PKI: `pki gen-csr`, `pki install`, mini-CA (`ca init`, `ca sign`, `ca list`) | Done |
| 8 | Hardening: periodic PING (silent link), libFuzzer fuzzing (6 targets, 1 h nightly), clang-tidy and cppcheck warning-free, TLS scan (sslyze), OpenSSL 3.5 on Linux | Done |
| 9 | `tlsrelay-testkit` test tooling (load, throughput, latency, network disturbances, test PKI), measured performance targets, soak testing | Done |
| 10 | Security campaign: automated attack cases, testssl.sh, MSVC `/analyze`, hardening and dependencies checked in CI, penetration test checklist; acceptance kit (`acceptance.ps1`, test plan, report) | Done |
| 11 | `.deb`, `.rpm` and `.msi` packages (OpenSSL 3.5 LTS on Windows), install-tested on Ubuntu 22.04 and 24.04, Debian 12, RHEL 9 and equivalents, Windows; installation and operations guides | Done |

Release 1.1 (`tlsrelay-admin` editor, [PLAN §4](docs/PLAN.md)):

| Phase | Content | Status |
|---|---|---|
| 12 | Editor foundation: normalized writing of the configuration and whitelist, diffs; mini-CA: revocation (`ca revoke`), CRL (`ca crl`), hash-chained audit log (`ca audit`); CRLs enforced by the service (`pki crl`, hot reload) | Done |
| 13 | `tlsrelay-admin` Qt application: configuration form and whitelist validated by the service's rules, diff preview and `.bak` copy on save, deployment package export (Linux, Windows) | Done |
| 14 | Editor PKI module: open or create the mini-CA, inventory (filters, expiry), signing and renewal of requests, revocation and CRL, audit log, root change wizard (`ca root-change` on the command line) | Done |
| 15 | Editor in the MSI ("tlsrelay-admin" feature: deployed Qt DLLs, shortcut, LGPL and GPL texts), headless check (`--check`), editor guide, acceptance scenarios E01 to E10 | Done |

All three ports are available. The client and server talk over the tunnel protocol (SPEC §4): on the `tls` and `mtls` ports, the client renegotiates the session when `session_lifetime` expires (new connection, full handshake with the current PKI generation) without the application seeing any cut, and resumes the session if the connection drops. The server only accepts tlsrelay clients: an application cannot connect to it directly.

In server mode, the whitelist is mandatory (commented example: [examples/whitelist.yaml](examples/whitelist.yaml)).

## Building

### Linux

Dependencies (Ubuntu 24.04):

```sh
sudo apt-get install cmake ninja-build g++ libssl-dev libasio-dev libyaml-cpp-dev \
    libspdlog-dev libcli11-dev libgtest-dev
```

```sh
cmake --preset linux-release
cmake --build --preset linux-release
ctest --preset linux-release
```

With AddressSanitizer and UBSan (Clang, `libclang-rt-18-dev` package): `linux-asan` preset.

Hardening (Linux):

```sh
tools/run-clang-tidy.sh build/linux-release          # static analysis (clang-tidy-18 package)
tools/run-cppcheck.sh build/linux-release            # static analysis (cppcheck package)
cmake --preset linux-fuzz && cmake --build --preset linux-fuzz
tools/run-fuzz.sh build/linux-fuzz 60                # 60 s per libFuzzer target
tests/lifecycle/tls-scan.sh build/linux-release/src/app/tlsrelay   # TLS configuration (sslyze)
tools/coverage.sh build/coverage                     # code coverage (gcovr package): build/coverage/coverage/index.html
```

Measured coverage (at least 90% of lines of the shipped code, enforced by CI): [TESTS.md §6](docs/TESTS.md#6-code-coverage).

### tlsrelay-admin editor (Qt 6)

The editor is built with the `-DTLSRELAY_BUILD_ADMIN=ON` option (Qt 6.4 or later, dynamically linked):

```sh
sudo apt-get install qt6-base-dev          # Linux (distribution package)
cmake --preset linux-release -DTLSRELAY_BUILD_ADMIN=ON
cmake --build --preset linux-release && build/linux-release/src/admin/tlsrelay-admin examples/server.yaml
```

On Windows, Qt 6.8 LTS (msvc2022_64) is given with `-DCMAKE_PREFIX_PATH=<Qt directory>`. The editor tests (Qt Test) run headless (`QT_QPA_PLATFORM=offscreen`) and check, among other things, that the editor and the service report exactly the same errors.

The editor opens a configuration and, in server mode, its whitelist; every input is validated by the service's loader. Saving shows the differences, rewrites the files in a normalized form (comments are not kept) and keeps the original as `.bak`. The "PKI" tab opens a mini-CA directory (created by `tlsrelay ca init` or by the editor): inventory of issued certificates (revoked in red, expiring within 30 days in orange), signing of a request that is reviewed before signing, renewal wizard, revocation followed by CRL publication, audit log and integrity check, root change wizard (trust files and commands for the three steps). The CA passphrase is asked for at each operation and never stored.

"Export deployment package" creates a directory to copy to the instance's machine: configuration, whitelist, PKI kit and CRL if any, `install.sh` or `install.ps1` and `README.txt`.

### Packages

```sh
# Linux, in a container of the oldest targeted distribution (bundled dependencies):
docker run --rm -v "$PWD:/src" -w /src ubuntu:22.04 packaging/build-linux.sh packages   # .deb
docker run --rm -v "$PWD:/src" -w /src rockylinux:9 packaging/build-linux.sh packages   # .rpm
docker run --rm -v "$PWD:/src" -w /src debian:12 packaging/test-linux-package.sh packages   # installation test
```

```bat
rem Windows, after building:
cd build\windows-msvc && cpack -C Release -G WIX
```

`-DTLSRELAY_FETCH_DEPS=ON` replaces the system dependencies (Asio, CLI11, spdlog, yaml-cpp) with pinned, statically linked versions; only OpenSSL remains the distribution's. License: [LICENSE](LICENSE); third-party components: [THIRD-PARTY-NOTICES.txt](THIRD-PARTY-NOTICES.txt).

### Windows (x64)

Prerequisites: Visual Studio 2022 and [vcpkg](https://github.com/microsoft/vcpkg), with the `VCPKG_ROOT` variable set. The dependencies, including OpenSSL, are installed by vcpkg from `vcpkg.json`.

```bat
cmake --preset windows-msvc
cmake --build --preset windows-release
ctest --preset windows-release
```

Complete guide (tool installation, Qt editor, all Windows tests, MSI package, troubleshooting): [docs/BUILD-WINDOWS.md](docs/BUILD-WINDOWS.md).

## Usage

```sh
tlsrelay check-config -c examples/server.yaml   # validate a configuration
tlsrelay run -c examples/server.yaml            # server, in the foreground
tlsrelay run -c examples/client.yaml -v         # client, verbose mode (-vv: trace)
tlsrelay version                                # tlsrelay and OpenSSL versions
```

### Trying TLS

The PKI is read from the `credentials.pki_root` directory (format described in [SPEC §7.2](docs/SPEC.md)). For a trial, `tools/make-test-pki.sh` creates a test PKI (root, Servers CA, Clients CA, certificates) and the two ready-to-use directories:

```sh
tools/make-test-pki.sh /tmp/pki-test          # requires the openssl command
```

```yaml
# server                                    # client
credentials: { pki_root: /tmp/pki-test/server }    credentials: { pki_root: /tmp/pki-test/client }
ports:                                      ports:
  tls: { listen: "0.0.0.0:9002" }             tls: { listen: "127.0.0.1:7002", upstream: "relay:9002", server_name: relay.test }
```

For the `mtls` port, the client presents the test PKI's `CN=client.test,O=tlsrelay-test` certificate; the server's whitelist must contain this subject:

```yaml
peers:
  - { name: local-host, ip: 127.0.0.1, ports: [mtls], subject: "CN=client.test,O=tlsrelay-test" }
```

The keys produced by this script are not encrypted: it is for trials only. For a real PKI, use the mini-CA (below).

### Production PKI: mini-CA and signing requests

Each instance's key is generated on its own machine and never leaves it; only the signing request (CSR) travels. The CA (root, Servers CA, Clients CA, passphrase-encrypted keys) stays on an administration workstation.

```sh
# Administration workstation, once
tlsrelay ca init --dir /ca --org MyCompany

# tlsrelay server machine
tlsrelay pki gen-csr -c server.yaml --subject "CN=relay.example,O=MyCompany" --san relay.example
#   → send <pki_root>/v1/request.csr to the administration workstation

# Administration workstation: signing according to the CA policy
tlsrelay ca sign --dir /ca --role server --csr request.csr --san relay.example --out relay-kit
#   → send the relay-kit directory back

# Server machine
tlsrelay pki install  -c server.yaml --from relay-kit   # completes v1 and checks it
tlsrelay pki activate -c server.yaml v1
```

Same process for an mTLS client with `--role client` (without `--san`). The CA policy requires an ECDSA P-256 key and applies its own extensions (those in the request are ignored), refuses a subject that is already assigned (unless `--renew`) and keeps the inventory (`tlsrelay ca list --dir /ca`). The passphrase is prompted for on the keyboard, or read from `--passphrase-file` or the `TLSRELAY_CA_PASSPHRASE` variable.

Revocation: `tlsrelay ca revoke --dir /ca --serial <serial> --reason keyCompromise --out crl.pem` publishes the CRLs, to be installed on each instance with `tlsrelay pki crl -c <config> crl.pem`; the certificate is refused at handshake and the channels using it are closed (SPEC §7.7). CRLs are republished before they expire (`tlsrelay ca crl`, 30 days by default). Every CA operation is recorded in a SHA-256 hash-chained audit log (`tlsrelay ca audit --dir /ca`).

### Certificate rotation

A PKI generation is a `vN` directory of the `pki_root`; the `current` file designates the generation in service. To renew a certificate (new key):

```sh
tlsrelay pki gen-csr -c server.yaml --subject "CN=relay.example,O=MyCompany"   # creates v2
tlsrelay ca sign --dir /ca --role server --csr request.csr --san relay.example --renew --out kit-v2
tlsrelay pki install  -c server.yaml --from kit-v2   # trust files taken from v1; safeguard checked
tlsrelay pki activate -c server.yaml v2              # picked up within 2 s by the running service
```

New connections use v2. Channels already open stay on v1 until their next renegotiation (at most `limits.session_lifetime`, 1 h by default), which moves them to v2 without a cut; v1 is released when no connection uses it any more. To change the root, follow the 3 steps in [SPEC §7.5](docs/SPEC.md).

### Renegotiation

On the `tls` and `mtls` ports, each channel switches to a new TLS connection when `limits.session_lifetime` (± `session_jitter`) expires. Data keeps flowing during renegotiation and the application sees no cut. The same mechanism resumes the session if the connection drops, within `limits.renegotiation_grace` (30 s by default). With `logging.level: debug`, each renegotiation is logged.

### Test tooling: tlsrelay-testkit

```sh
tlsrelay-testkit pki --out /tmp/pki                         # test PKI (run again: new generation)
tlsrelay-testkit echo --listen 127.0.0.1:8080               # echo destination
tlsrelay-testkit load --target 127.0.0.1:7003 --channels 5000 --bytes 1MiB --hold 10s   # SHA-256 digest per channel
tlsrelay-testkit throughput --target 127.0.0.1:7003 --duration 10s     # --rate 200: capped throughput (Mbit/s)
tlsrelay-testkit latency --target 127.0.0.1:7003            # compare with --target 127.0.0.1:8080 (direct)
tlsrelay-testkit proxy --listen 127.0.0.1:9100 --target 127.0.0.1:9003 --delay 20ms --cut-every 60s
```

`--json` gives a result that a script can process. `tests/perf/perf.sh <build> [channels]` checks the performance targets; `tests/perf/soak.sh <build> <minutes>` runs the soak test (72 h: 4320 minutes, on a dedicated machine).

Measurements (Linux, development workstation, full mTLS chain client → server):

| Indicator | Target | Measured |
|---|---|---|
| Concurrent channels | 5,000 | 5,000, all intact |
| Throughput per channel | 100 Mbit/s | ≈ 800 Mbit/s |
| Added latency (round trip) | < 1 ms | ≈ 0.35 ms |
| Memory | — | ≈ 50 KiB per open channel and per relay (≈ 250 MiB for 5,000 channels) |

In CI, `perf.sh` measures throughput paced at 500 Mbit/s (`RATE` variable, 0: unlimited) and the soak test's continuous stream runs at 200 Mbit/s (`STREAM_RATE`).

**Known limitation: saturated stream on the loopback.** A channel pushed to its maximum in both directions at once (≈ 1 Gbit/s, relay and destination on the same machine) can stall for several tens of seconds, without data loss or corruption. The relay then applies backpressure and stops reading from a socket; the kernel drops received segments (`TCPRcvQDrop` in `nstat`) instead of closing the window in time, and the sender waits between two retransmissions for a delay that doubles at each attempt (up to 25 s and more). Observed on GitHub CI machines, not reproduced on a development workstation; the investigation continues outside the per-push CI. `tlsrelay channels` (flow-control state of each channel) and the "Performance stress" workflow are used for diagnosis.

### Security and acceptance

| Tool | Checks |
|---|---|
| `tests/test_attacks.cpp` | Expired or not-yet-valid certificates, wrong usage, fake server, hostile frames, flooding without handshake, injection and secrets in logs |
| `tests/lifecycle/tls-scan.sh` | TLS configuration seen from outside (sslyze; testssl.sh with `TESTSSL=<path>`) |
| `tools/check-hardening.sh`, `tools/check-hardening.ps1` | PIE, RELRO, NX, stack protection, FORTIFY; ASLR, DEP, CFG |
| `tools/check-deps.sh` | OpenSSL shipped on Windows at the latest patch release of the 3.5 branch |
| `cmake -DTLSRELAY_MSVC_ANALYZE=ON` | MSVC static analysis (`/analyze`) |
| `tools/acceptance.ps1` | Automated acceptance on a single workstation (see the [acceptance test plan](docs/ACCEPTANCE.md)) |

```powershell
.\tools\acceptance.ps1 -BuildDir 'C:\Program Files\tlsrelay' -Services -Keep   # report.md in %ProgramData%\tlsrelay\acceptance-<date>
```

On Linux (PowerShell 7), in console mode: `pwsh tools/acceptance.ps1 -BuildDir build/linux-release/src/app -TestkitDir build/linux-release/src/testkit`.

### Demo and video

`tools/demo.sh` shows the whole solution in 3 minutes on a Linux machine, with the real binaries and an English commentary: PKI from the mini-CA, client and server on all three ports, TLS seen from outside (openssl), whitelist reload, transparent renegotiation, resumption after network cuts, hot PKI rotation, revocation (CRL), administration and metrics, editor, shutdown and audit. Each step ends with checks (25 in total); exit code 0 if they all pass.

```sh
tools/demo.sh build/linux-release              # DEMO_PAUSE=1: wait for Enter between steps (live presentation)
DEMO_DIR=/tmp/demo tools/demo.sh build/linux-release   # keeps configurations, PKI, logs and captures
```

`tools/video/make-video.sh <build> [output.mp4]` turns it into a video (MP4 1280×720, no sound, English subtitles, about 3 minutes): a real recording of `demo.sh`, replayed in a terminal with chapter cards, followed by the editor screens (`tlsrelay-admin-tour`, a target excluded from the default build). Prerequisites: a build with the editor, node and the playwright package with its Chromium, ffmpeg, npm access (xterm.js).

### Service and administration

```sh
sudo tlsrelay service install --instance branch --boot   # config: /etc/tlsrelay/branch.yaml
sudo tlsrelay start   --instance branch
sudo tlsrelay status  --instance branch                  # PID, OpenSSL, PKI generation, channels per port
sudo tlsrelay reload  --instance branch                  # whitelist, PKI, log levels
sudo tlsrelay stop    --instance branch --timeout 30s    # drain then stop; kill: immediate stop
```

On Windows, in an administrator console: same commands (service `tlsrelay-branch`, configuration `%ProgramData%\tlsrelay\branch.yaml`, account `NT SERVICE\tlsrelay-branch`). The service account must be able to read the configuration, the whitelist and the PKI.

An instance started in a console (`tlsrelay run`) is controlled the same way with `-c <config>` instead of `--instance`. Other commands: `channels` (open channels), `metrics` (Prometheus format), `log-level debug` (hot log-level change), `log-reopen` (rotation). Details: [SPEC §10](docs/SPEC.md).

- Ctrl+C (or `SIGTERM`): graceful shutdown, draining channels for `limits.shutdown_timeout`; a second Ctrl+C forces an immediate stop.
- Exit codes: 0 (success), 1 (runtime error), 2 (invalid configuration).
