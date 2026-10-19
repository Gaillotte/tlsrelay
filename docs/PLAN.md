# tlsrelay — Development plan

> Version 1.0 of the plan, consolidated from the decisions made during scoping.
> The detailed technical specification is in [`SPEC.md`](SPEC.md).

## 1. Purpose

`tlsrelay` is a command-line TCP relay that carries an application's data to a destination, across an untrusted network, with three levels of protection:

| Port | Mode | Protection |
|---|---|---|
| Port 1 | Plaintext | None (simple relay) |
| Port 2 | TLS 1.3 | Encryption, server authentication |
| Port 3 | mTLS (TLS 1.3) | Encryption, mutual certificate authentication |

It always works **in pairs**: one `tlsrelay` in client mode and one `tlsrelay` in server mode.

```
App ──plain──► [tlsrelay CLIENT] ══ plain / TLS 1.3 / mTLS ══► [tlsrelay SERVER] ──plain──► Destination
                                    (tunnel protocol)                                (address:port)
```

The project has two deliverables:

- **Release 1**: the `tlsrelay` service (64-bit Windows and Linux), with a command-line mini-CA.
- **Release 1.1**: the `tlsrelay-admin` Windows graphical editor (configuration and PKI).

## 2. Scoping decisions

| Topic | Decision |
|---|---|
| Language | C++20 (coroutines) |
| Networking | Asio (IOCP on Windows, epoll on Linux) |
| TLS | OpenSSL via `asio::ssl`, dynamically linked |
| OpenSSL version | 3.0 minimum (3.0 API only). Linux: the distribution's OpenSSL. Windows: OpenSSL 3.5 LTS shipped with the application |
| FIPS | Not required |
| Platforms | Windows 10 / Server 2019 and later (64-bit), Linux (Ubuntu 22.04, RHEL 9 and equivalents) |
| Build | CMake + vcpkg; MSVC 2022, GCC ≥ 12, Clang ≥ 16 |
| Libraries | yaml-cpp, spdlog, CLI11, GoogleTest; Qt 6 for the editor (v1.1) |
| Client mode | Plaintext input from the application; plaintext, TLS 1.3 or mTLS output to the server `tlsrelay` depending on the port |
| Server mode | Plaintext, TLS 1.3 or mTLS input; **plaintext** output to a single configurable destination (address and port) |
| Remote peer | Always a `tlsrelay`. Tunnel protocol mandatory, ALPN identifier `tlsrelay/1` |
| Channels | Several parallel channels per port; one tunnel session per channel |
| Hot rotation | Key pair, certificate, intermediate and root CAs. New connections move to the new generation; open connections finish on the old one, which is released when it has no connections left |
| Root change | 3-step procedure: pre-trust, switchover, withdrawal |
| Inactivity | `idle_timeout` on all 3 ports |
| Session lifetime | `session_lifetime` on ports 2 and 3 only |
| Renegotiation | Full handshake (new keys, new certificates, new chain verification), **transparent** to the application and the destination |
| Destination unavailable | 3 attempts with increasing delay, then the channel is closed |
| PROXY protocol | No |
| Whitelist (server) | Peers allowed to connect, defined by IP (or CIDR range) and subject, can be restricted to certain ports. Ports 1 and 2: IP check. Port 3: IP + subject (exact DN) + issued by the Clients CA |
| PKI hierarchy | One root (ECDSA P-384), two intermediate CAs: Servers CA (`serverAuth`) and Clients CA (`clientAuth`), in P-384. `tlsrelay` certificates in ECDSA P-256 |
| Key pair delivery | Via a certificate signing request (CSR): the private key is generated on the `tlsrelay` machine and never leaves it |
| Root CA | On a dedicated administration workstation, key encrypted at rest |
| Logs | Levels `error`, `info`, `debug` (`-v`), `trace` (`-vv`); categories `activity` and `config`; hot log-level change; no secrets or relayed content in the logs |
| Lifecycle | systemd / Windows service; start at boot; `stop` (30 s drain by default), `restart`, `kill`, `reload`; named instances |
| Windows editor | Qt 6, shares the `libtlsrelay-core` library (same validation rules as the service), includes the root CA |

## 3. Architecture

```
             ┌───────────────────────────────┐
             │       libtlsrelay-core        │  C++20 + OpenSSL 3
             │  config · validation · PKI    │
             │  tunnel protocol · logs       │
             └───────┬───────────────┬───────┘
                     │               │
          ┌──────────▼───┐    ┌──────▼─────────────┐
          │  tlsrelay    │    │  tlsrelay-admin    │
          │  (service)   │    │  (Windows editor)  │
          │ Win + Linux  │    │  Release 1.1       │
          └──────────────┘    └────────────────────┘
```

Main modules of `libtlsrelay-core`:

| Module | Role |
|---|---|
| `config` | YAML reading, configuration model, validation (shared with the editor) |
| `whitelist` | Whitelist loading and matching |
| `pki` | Certificate generations, loading and validation of PKI directories, CSR, mini-CA |
| `tls` | One `SSL_CTX` per generation; verification of chains and of the issuing CA |
| `tunnel` | Frame encoding, sequence numbering, ACK, resumption (`RESUME`) |
| `channel` | Channel state machine, timers (inactivity, lifetime) |
| `relay` | Listeners, dialers, bidirectional copy |
| `admin` | Administration channel (Unix socket / named pipe) |
| `log` | Structured logging, levels and categories |
| `platform` | OS abstractions: service, signals, file permissions |

## 4. Schedule

### Release 1: `tlsrelay` service — about 12 weeks

| Phase | Content | Effort |
|---|---|---|
| 0 | Specification: tunnel protocol, config, whitelist, channel states, rotation | 2 d |
| 1 | Foundation: CMake and vcpkg, `libtlsrelay-core`, CLI, logs and verbose mode, plaintext relay, multiple channels, `idle_timeout` | 5 d |
| 2 | TLS 1.3 with OpenSSL and `asio::ssl`, ALPN `tlsrelay/1` | 3 d |
| 3 | mTLS and whitelist (IP, subject, issuing CA) | 4 d |
| 4 | Hot rotation up to the root, one `SSL_CTX` per generation, `check-pki` | 6 d |
| 5 | Tunnel protocol, transparent renegotiation, 3 attempts to the destination | 8 d |
| 6 | Lifecycle: systemd and Windows services, boot, stop, restart, kill, named instances, administration channel, metrics | 4 d |
| 7 | Command-line PKI: `pki gen-csr`, `pki install`, mini-CA (`ca init`, `ca sign`) | 3 d |
| 8 | Hardening: sanitizers, fuzzing, static analysis | 6 d |
| 9 | Test tooling: `tlsrelay-testkit`, test PKI factory, cross-platform environments, network disturbances, soak testing | 10 d |
| 10 | Internal security campaign, acceptance kit and test plan, penetration test checklist | 5 d |
| 11 | Packaging (`.deb`, `.rpm`, `.msi` with OpenSSL 3.5) and documentation | 3 d |
| | Acceptance | 2 d |

### Release 1.1: `tlsrelay-admin` editor — about 6 weeks

| Work package | Content | Effort |
|---|---|---|
| A | Adapting `libtlsrelay-core` for the editor | 3 d |
| B | Qt configuration editor: forms, validation on input, whitelist, diff preview, deployment package export | 8 d |
| C | PKI module: root and intermediate CAs, CSR signing, inventory, revocation (CRL), rotation and root change wizard, audit log; opening the mini-CA directory | 10 d |
| D | Tests (Qt Test, editor/service validation parity), installer, documentation | 9 d |

Breakdown into phases, each on its own branch, validated by CI and then merged:

| Phase | Work package | Content |
|---|---|---|
| 12 | A | Editor foundation in `libtlsrelay-core`: normalized writing of the configuration and whitelist, text diffs; mini-CA: revocation, CRL, hash-chained audit log; CRL enforcement by the service (SPEC §7.7) |
| 13 | B | `tlsrelay-admin` Qt application: configuration forms, validation on input (the service's rules), whitelist, diff preview, deployment package export; Qt in CI (Linux and Windows) |
| 14 | C | Editor PKI module: CA, CSR signing, inventory, revocation and CRL, renewal and root change wizards, audit log |
| 15 | D | Qt Test tests and validation parity, "tlsrelay-admin" MSI feature (Qt DLLs, LGPL notice), documentation, editor acceptance |

Release 1.1 decisions:

| Topic | Decision |
|---|---|
| Revocation | CRLs published by the CA (`ca crl`, editor) and **enforced by the service**: `<pki_root>/crl.pem`, hot-reloaded, channels of the revoked peer closed (SPEC §7.7) |
| Qt license | Qt 6 under LGPLv3, dynamic linking: unmodified Qt DLLs shipped with the editor, LGPL text and Qt source offer in the third-party notices |
| Editor platforms | Shipped on Windows (MSI feature); also built and tested on Linux in CI, without a Linux package |
| Saving a configuration | Normalized rewrite (`to_yaml`): comments from the original file are not kept; the diff preview shows this and a `.bak` copy of the original is kept |
| CA audit log | `<ca>/audit.log`, one line per operation, SHA-256 hash-chained; written by the command line and by the editor |

## 5. Test strategy

### 5.1 Principles

- **Traceability**: each requirement is linked to the tests that verify it (traceability matrix; full list of requirements: [SPEC §11](SPEC.md#11-requirements); requirements/tests matrix: [TESTS.md §4](TESTS.md#4-requirements-coverage)). A requirement without a passing test is not delivered.
- **Tests written with the code**: a phase is only done when its tests pass.
- **Dual platform**: all automated tests pass on Windows and Linux, against OpenSSL 3.0 and 3.5.
- **End-to-end integrity**: a generator sends a reproducible pseudo-random stream; the receiver compares the SHA-256 digest. This proves there is no loss, duplication or reordering, in particular during renegotiations.
- **Injectable clock**: unit tests of timeouts (inactivity, lifetime, dial attempts to the destination) are deterministic and fast.

### 5.2 Test levels

| Level | Tools | Content | Target |
|---|---|---|---|
| Unit | GoogleTest | Config and validation; whitelist; frames; numbering and ACK; resumption token; generations; state machines; dial attempts to the destination; masking of secrets in logs | ≥ 85% coverage of `libtlsrelay-core`; 100% of branches in the frame decoder, the whitelist and validation. Target raised to 90% of lines of all shipped code, enforced by CI; measurement: [TESTS.md §6](TESTS.md#6-code-coverage) |
| Integration | GoogleTest + real OpenSSL locally | TLS 1.3 and mTLS handshakes, rotation, renegotiation, inactivity | All scenarios in the catalog |
| System | Real binaries + `tlsrelay-testkit` | Full chain, Windows ↔ Linux cross combinations | All requirements, on both OSes |
| Network disturbances | toxiproxy, `tc netem` | Latency, losses, cuts during a transfer and during a renegotiation | Resumption without loss, or clean close |
| Security | See 5.4 | Attack cases, fuzzing, TLS analysis | No critical defect |
| Performance and soak | testkit | Throughput, added latency, number of channels, handshakes; 72 h soak | See 5.6 |
| Lifecycle | Windows and Linux VMs | Installation, boot, stop, restart, kill, named instances, administration channel permissions | 100% of scenarios |
| Acceptance | Acceptance kit | Business scenarios | Signed acceptance report |

### 5.3 Scenario catalog (extract from the traceability matrix)

| Requirement | Scenarios |
|---|---|
| 3 ports / 3 modes | Transfer in each mode, digest verified; port 2 refuses TLS 1.2; port 3 requires a certificate |
| Multiple channels | 1, 100, then 5,000 parallel channels with per-channel verification; no memory, descriptor or handle leaks |
| Key pair / certificate rotation | Long-lived channels on gen1, rotation, new channels on gen2, gen1 released when its counter drops to 0 |
| CA rotation up to the root | The 3 steps; premature switchover (expected failure, clear message); incomplete directory or mismatched key (rejected, service keeps running); rotation of a single intermediate CA |
| `idle_timeout` | Close when it expires; service frames do not push back the deadline; also applies to the link to the destination |
| Transparent renegotiation | Continuous transfer of several GB over 20 renegotiations: identical digest, application and destination never cut; renegotiation during a rotation; peer that does not renegotiate (closed at the end of the grace period) |
| Whitelist | Unlisted IP (rejected before handshake); IP and DN from two different entries; Servers CA certificate presented as a client; peer removed during a session; ports 1 and 2 with IP check only |
| Destination unavailable | Exactly 3 attempts, delays measured; `OPEN_FAIL`; no loss if attempt 2 or 3 succeeds |
| Verbose mode | Expected content at each level; hot change; automatic search for secrets and relayed data in all logs (zero occurrences tolerated) |
| Lifecycle | stop with drain; restart; kill during a transfer then clean restart; start at boot; two named instances; command refused to a non-administrator |
| Command-line PKI | `gen-csr` → `ca sign` → `pki install`; refusal of an RSA request or a duplicate subject; requested extensions ignored; certificates also verified by `openssl verify` |

### 5.4 Security campaign

- **Automated attack cases**: TLS 1.2, missing `tlsrelay/1` ALPN, certificate expired / not yet valid / from another PKI / with the wrong usage, replayed or forged resumption token, oversized or malformed frame, inconsistent sequence number, flooding with connections that never handshake.
- **Fuzzing (libFuzzer)**: frame decoder, config and whitelist loaders, CSR parsing. 1 h per night; 24 h cumulative without a crash before each release.
- **Memory errors**: AddressSanitizer, UndefinedBehaviorSanitizer, ThreadSanitizer (Linux); Application Verifier (Windows).
- **Static analysis**: `clang-tidy`, `cppcheck`, MSVC `/analyze`; zero high-severity warnings.
- **TLS configuration**: `testssl.sh` and `sslyze` on ports 2 and 3.
- **Dependency vulnerabilities**: checked at every build.
- **Internal penetration test** before going into production, following a checklist based on the ANSSI recommendations for TLS.

### 5.5 Continuous integration

| Trigger | Content | Target duration |
|---|---|---|
| Every commit / pull request | Windows and Linux build, unit and integration tests, sanitizers (selection), `clang-tidy` | < 15 min |
| Every night | Cross-platform end-to-end, network disturbances, 1 h fuzzing, full ThreadSanitizer, OpenSSL 3.0 and 3.5, compared performance measurements | < 3 h |
| Before a release | 72 h soak, 24 h cumulative fuzzing, `sslyze` / `testssl.sh`, internal penetration test, acceptance | ~1 week |

### 5.6 Performance targets

| Indicator | Target |
|---|---|
| Concurrent channels | 5,000 |
| Throughput per channel | 100 Mbit/s |
| Added latency (local) | < 1 ms |
| Soak | 72 h with continuous rotations and renegotiations; stable memory, handles and number of generations |

### 5.7 Acceptance

Carried out by the project lead, on **a single Windows workstation**:

```
                              Windows workstation
┌──────────────────────────────────────────────────────────────────────────────────────────┐
│ testkit app ──► tlsrelay@rc-client ══(toxiproxy)══► tlsrelay@rc-server ──► testkit destination │
│  127.0.0.1        127.0.0.2                          127.0.0.3              127.0.0.4          │
│                                                                                          │
│ Hyper-V VM Ubuntu 22.04 (internal switch): Linux instance for cross-platform tests       │
└──────────────────────────────────────────────────────────────────────────────────────────┘
```

- Multiple loopback addresses to test the IP whitelist (`source_address` option on the client side).
- `acceptance.ps1` script: creates the test PKI (mini-CA), installs the Windows instances, deploys the `.deb` package in the VM, runs the Windows ↔ Windows, Windows → Linux and Linux → Windows scenarios.
- Acceptance test plan: steps, expected result, OK/KO box; guided manual steps (reboot for the boot test, `kill`, root change, log levels).
- Generated report: results, digests, log excerpts, versions (`tlsrelay`, OpenSSL, OS).
- Not covered on a single workstation: a real network between machines (NAT, firewall, MTU); compensated for by the cross-platform tests in continuous integration. An additional trial on two machines is recommended before production.
- Prerequisites: Windows 10/11 Pro or Enterprise (Hyper-V).

### 5.8 Release exit criteria

- 100% of requirements covered by passing tests, on both OSes.
- No open critical or major defect.
- Coverage thresholds reached: 90% of lines of the shipped code (measured on every push, [TESTS.md §6](TESTS.md#6-code-coverage)).
- 24 h of fuzzing without a crash; no sanitizer warnings.
- 72 h soak test passed.
- Performance targets met.
- Signed acceptance report.

## 6. Risks

| Risk | Mitigation |
|---|---|
| Memory defects in C++ on an exposed network component | RAII on all OpenSSL objects, sanitizers, fuzzing, static analysis, compiler protections |
| Complexity of transparent renegotiation | Formal specification of the states, end-to-end tests with digest verification, network disturbances |
| Service outage during a root change | 3-step procedure, anti-outage safeguard in validation, `check-pki` before switchover |
| OpenSSL 3.0 reaching end of support | 3.0 API only; OpenSSL 3.5 LTS shipped on Windows; Linux fixes via the distribution |
| Compromise of the root CA | Dedicated administration workstation, encrypted key, root used only to sign the intermediates |
| Acceptance limited to one workstation | Cross-machine tests in continuous integration; additional trial on two machines recommended |
