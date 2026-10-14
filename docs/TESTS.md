# tlsrelay — Test plan and test report

> Test strategy, test environments, full description of every test, coverage of the requirements ([SPEC §11](SPEC.md#11-requirements)) by the tests, and code coverage with the new tests it calls for.
> Scope: deliveries 1.0 (service `tlsrelay`, tool `tlsrelay-testkit`) and 1.1 (editor `tlsrelay-admin`).
> Related documents: [PLAN.md](PLAN.md) §5 (original test strategy), [RECETTE.md](RECETTE.md) (acceptance procedure), [PV-RECETTE.md](PV-RECETTE.md) (acceptance sign-off record), [PENTEST.md](PENTEST.md) (penetration-test checklist).

## Contents

1. [Strategy](#1-strategy)
2. [Test environments](#2-test-environments)
3. [Test inventory](#3-test-inventory)
4. [Requirements coverage](#4-requirements-coverage)
5. [Coverage summary, gaps and deviations](#5-coverage-summary-gaps-and-deviations)
6. [Code coverage](#6-code-coverage)

---

## 1. Strategy

### 1.1 Objectives

- Every requirement of SPEC §11 is verified by at least one test, and the verification is repeatable.
- Everything that can run automatically runs on **every push**, on Linux and Windows, so that a regression is caught by the commit that introduces it.
- What cannot run in CI (long durations, real machines, human judgement) is described as a manual step with an expected result and recorded in the acceptance sign-off.

### 1.2 Principles

| Principle | How it is applied |
|---|---|
| **Traceability** | Each test lists the requirements it verifies (section 3); each requirement lists its tests (section 4). A requirement without a passing verification is not delivered. |
| **Tests written with the code** | A development phase is finished only when its tests pass in CI; each phase was merged only with all CI jobs green. |
| **Real components** | Integration tests run the real service (`Service` in a thread) with real OpenSSL TLS 1.3 on the loopback interface; no TLS mock. Lifecycle tests use the real binary, systemd and the Windows service manager. |
| **End-to-end integrity** | Data is a reproducible pseudo-random stream (xorshift64*); the receiver compares SHA-256 hashes. This proves no loss, duplication or reordering, including across renegotiations, resumptions and rotations. |
| **Generated test PKI** | Certificates are generated on the fly (`tests/support/test_pki.*`): standard hierarchy plus "trapped" variants (expired, not yet valid, wrong usage, foreign PKI, wrong issuer, encrypted key, garbage). No certificate is committed to the repository. |
| **Fault injection** | A cutting proxy (`cut_proxy.hpp`, testkit `proxy`) breaks connections (RST) or freezes them (silent link); raw OpenSSL clients and servers (`raw_tls_client.hpp`, `raw_tls_server.hpp`) play non-conforming or hostile peers. |
| **Short timers** | Timers (idle, lifetime, grace, keepalive, dial back-off) are configuration values; tests set them to tens or hundreds of milliseconds so that scenarios lasting an hour in production run in seconds. |
| **Parity by construction** | The editor validates through the service's own loader; a corpus test checks that both report the same errors. |
| **Warnings are errors** | Every CI build uses `-DTLSRELAY_WARNINGS_AS_ERRORS=ON`; static analysis findings fail the build. |

### 1.3 Test levels

| Level | Tools | Contents | Where it runs |
|---|---|---|---|
| Unit | GoogleTest | Parsers and formats, configuration and validation, whitelist, frames, PKI loading and validation, writers and diff, logging | CI, every push, Linux and Windows |
| Integration | GoogleTest + real OpenSSL on loopback | Plain/TLS/mTLS chains, whitelist enforcement, rotation and guard, tunnel protocol (renegotiation, resume, back-pressure, keepalive), CRL enforcement, mini-CA, administration channel, attack cases | CI, every push, Linux (4 builds + OpenSSL 3.5) and Windows |
| Editor | Qt Test (offscreen platform) | Forms, parity, save pipeline, export, PKI panel and wizards | CI, Linux (4 builds) and Windows |
| System / lifecycle | Shell and PowerShell scripts with the real binary | Console lifecycle, systemd service, Windows service, CLI PKI | CI, Linux and Windows |
| Security | libFuzzer, sanitizers, clang-tidy, cppcheck, MSVC `/analyze`, sslyze, testssl.sh, hardening and dependency checks; penetration-test checklist | See 3.10–3.12 | CI (automated parts); penetration test manual |
| Performance and endurance | `tlsrelay-testkit`, `perf.sh`, `soak.sh` | Concurrent channels, throughput, latency, resource stability | CI (1,000 channels, 4-minute soak); full targets on a test machine |
| Packaging | Container installs, MSI install/uninstall | Build, install, upgrade, uninstall, licences | CI, 5 Linux distributions and Windows |
| Acceptance | `tools/recette.ps1` + manual steps | Business scenarios R01–R13, service steps M01–M09, editor steps E01–E10 | Automated part in CI (Linux console, Windows services); full run on the acceptance station |

### 1.4 Test design techniques

- **Equivalence classes and boundaries** for parsers: valid units, invalid syntax, overflow (`ParseDuration.RejectsOverflow`), maximum frame size plus one, empty lists.
- **Negative testing** for every security decision: each refusal path (TLS version, ALPN, certificate date, usage, issuer, PKI, whitelist IP, subject, port, revoked certificate, wrong passphrase) has its own test.
- **State-transition testing** for the channel state machine (OPENING → DIALING → ESTABLISHED ↔ MIGRATING → CLOSED): opening, refusal, renegotiation, resume after cut, grace expiry, cut before `OPEN_OK`, cut during handshake.
- **Round-trip testing** for writers: load → write → reload gives the same object; examples shipped in `examples/` are part of the corpus.
- **Differential testing** for the editor: editor errors compared with service errors on the same file.
- **Fuzzing** for every parser that reads untrusted or operator input.
- **Load and soak** for resource leaks and scalability.

### 1.5 Entry and exit criteria

**Entry** (a test campaign starts): code compiles without warnings on both platforms; the test PKI and the testkit build.

**Exit** (a delivery can be released; PLAN §5.8):

| Criterion | Status for 1.0 / 1.1 |
|---|---|
| All automated tests pass on both OSes, every CI job green on the release commit | Met: all CI jobs green on every merged phase |
| Every requirement of SPEC §11 covered by a passing verification | Met for the automated part (section 4); manual items recorded in the acceptance sign-off |
| No open critical or major defect | Met |
| No sanitizer finding; fuzzing without crash | Met in CI (60 s per target per push); 24 h cumulated fuzzing: manual, before production |
| Performance targets met | Met (section 3.21) |
| Line coverage of the delivered code ≥ 90 % | **Not met**: 84.4 % (section 6); new tests specified in 6.4 |
| 72 h endurance | Manual, before production (4-minute soak in CI) |
| Acceptance sign-off record signed | [PV-RECETTE.md](PV-RECETTE.md), to be signed by the project owner |

### 1.6 Defect handling

A failing CI job blocks the merge of its branch. A failure is root-caused before any re-run: a timing-dependent test is made robust (wider margins, explicit synchronisation) rather than retried, and no test is disabled to obtain a green run. Defects found during acceptance are recorded in the sign-off record with their severity.

---

## 2. Test environments

### 2.1 Continuous integration (GitHub Actions, every push and pull request)

| Job | Runner / image | Compiler, libraries | What runs |
|---|---|---|---|
| Linux GCC Release | ubuntu-24.04 | GCC 13, OpenSSL 3.0 (distribution), Qt 6.4 | ctest (GoogleTest, Qt Test, `Lifecycle.Console`, `Lifecycle.Pki`, `Admin.Check*`); `systemd.sh` (real systemd service, root); `tls-scan.sh` with sslyze and testssl.sh 3.2.1; `check-deps.sh`; `check-hardening.sh`; `recette.ps1 -Quick` in console mode (report uploaded) |
| Linux Clang Release | ubuntu-24.04 | Clang 18, OpenSSL 3.0, Qt 6.4 | ctest |
| Linux Clang ASan+UBSan | ubuntu-24.04 | Clang 18 Debug, AddressSanitizer + UndefinedBehaviorSanitizer | ctest |
| Linux Clang TSan | ubuntu-24.04 | Clang 18 Debug, ThreadSanitizer (`halt_on_error=1`) | ctest |
| Linux OpenSSL 3.5 LTS | ubuntu-24.04 | GCC, OpenSSL 3.5 built from the official archive (SHA-512 verified) | Version check (`OpenSSL 3.5.x`), ctest with the matching `openssl` command |
| Analyse statique (clang-tidy, cppcheck) | ubuntu-24.04 | clang-tidy 18, cppcheck | `tools/run-clang-tidy.sh`, `tools/run-cppcheck.sh` on the whole code base, editor included |
| Couverture de code (gcovr) | ubuntu-24.04 | GCC 13 `--coverage`, Qt 6.4, gcovr 8.6 | `tools/coverage.sh`: instrumented build, all ctest entries, HTML report (`couverture` artifact); fails below 83 % of lines (section 6) |
| Fuzzing (60 s par cible) | ubuntu-24.04 | Clang libFuzzer + ASan/UBSan | `tools/run-fuzz.sh` on the 6 targets from their corpus |
| Performances et endurance | ubuntu-24.04 | Release build | `perf.sh` with 1,000 channels; `soak.sh` for 4 minutes (reports uploaded) |
| Windows MSVC Release | windows-2022 | MSVC 2022, vcpkg (OpenSSL 3.5 LTS, Asio, CLI11, spdlog, yaml-cpp, GoogleTest), Qt 6.8 LTS | ctest; `check-hardening.ps1`; shipped OpenSSL version check; `windows-service.ps1` (real service); `windows-pki.ps1`; MSI build; MSI installation; installed editor check (without the runner's Qt); `recette.ps1 -Services -Quick` on the installed binaries; MSI uninstallation |
| Windows MSVC /analyze | windows-2022 | MSVC code analysis | Build with `/analyze`, findings are errors |
| Paquets deb (ubuntu:22.04) | container | Distribution toolchain, bundled dependencies | `.deb` build |
| Paquets rpm (rockylinux:9) | container | Distribution toolchain | `.rpm` build |
| Installation deb/rpm (×5) | ubuntu:22.04, ubuntu:24.04, debian:12, rockylinux:9, almalinux:9 | — | `packaging/test-linux-package.sh`: install, run, upgrade in place, licences, uninstall |
| Paquets de la livraison | ubuntu-24.04 | — | Gathers `.deb`, `.rpm`, `.msi` and `SHA256SUMS` into the `tlsrelay-livraison` artifact |

Totals per push: 19 jobs; 196 ctest entries on Linux (191 GoogleTest cases, 14 Qt Test functions counted as one ctest entry, `Admin.CheckValid`, `Admin.CheckInvalid`, `Lifecycle.Console`, `Lifecycle.Pki`); on Windows, 188 GoogleTest cases (3 are Linux-only, see 3.1) plus the Qt and `Admin.Check*` entries.

### 2.2 Test network layout

All automated tests run on one machine, on the loopback interface:

```
 test client / testkit ──► tlsrelay client ══ transport ══► [cut proxy] ══► tlsrelay server ──► echo destination
      127.0.0.1               127.0.0.1                      127.0.0.1           127.0.0.1          127.0.0.1
```

- Ports are allocated dynamically (port 0) so that tests run in parallel (`ctest -j 2`).
- "Reserved ports" (bound but not listening) give a destination that refuses connections, for the dial-retry tests.
- Whitelist tests use other loopback addresses (`127.0.0.2`, …) with the client's `source_address` to test the IP check.
- The cut proxy sits between the two relays when a test needs network faults.

### 2.3 Acceptance station (PLAN §5.7, RECETTE.md)

| Item | Value |
|---|---|
| Machine | One Windows 10/11 Pro or Enterprise workstation (Hyper-V) |
| Instances | `rc-client` and `rc-server`, installed as Windows services under their virtual accounts |
| Addresses | testkit application 127.0.0.1, client 127.0.0.2, server 127.0.0.3, destination 127.0.0.4 |
| Network faults | `tlsrelay-testkit proxy` between client and server (scenario R06) |
| Linux cross tests | Optional Ubuntu 22.04 Hyper-V VM on an internal switch, `.deb` package installed (R13) |
| PKI | Created by the mini-CA itself (R01) |
| Report | `rapport.md`: results, hashes, log extracts, versions of tlsrelay, OpenSSL and the OS |

### 2.4 Performance machine

The full performance targets (5,000 channels) were measured on a Linux development machine with the full mTLS chain (`perf.sh build 5000`). CI runners use 1,000 channels to stay within their resources.

### 2.5 Running the tests locally

| Purpose | Command |
|---|---|
| Linux build and all ctest entries | `cmake -S . -B build -G Ninja -DTLSRELAY_BUILD_ADMIN=ON && cmake --build build && ctest --test-dir build -j 2` |
| Windows build and tests | `cmake --preset windows-msvc -DTLSRELAY_BUILD_ADMIN=ON && cmake --build --preset windows-release && ctest --preset windows-release` |
| Sanitizers | `-DCMAKE_BUILD_TYPE=Debug -DTLSRELAY_SANITIZERS=address,undefined` (or `thread`) with Clang |
| One suite | `ctest --test-dir build -R TunnelTest` or `build/tests/tlsrelay_tests --gtest_filter='TunnelTest.*'` |
| Code coverage | `tools/coverage.sh build/coverage` (needs `gcovr`) → `build/coverage/coverage/index.html` |
| Fuzzing | Configure the `linux-fuzz` preset, then `tools/run-fuzz.sh build/linux-fuzz <seconds> [target…]` |
| Performance / soak | `tests/perf/perf.sh build 5000 perf.json`; `tests/perf/soak.sh build 4320 soak.csv` (72 h) |
| Service lifecycle | `sudo tests/lifecycle/systemd.sh build/src/app/tlsrelay`; Windows: `tests\lifecycle\windows-service.ps1 <bin dir>` as administrator |
| Acceptance | `tools/recette.ps1` (see RECETTE.md) |

---

## 3. Test inventory

Each table lists the tests of one suite, what each test does and checks, and the requirements (SPEC §11) it verifies. GoogleTest sources are in `tests/`, helpers in `tests/support/`.

### 3.1 Units and formats — `test_units.cpp`, `test_endpoint.cpp`, `test_writer.cpp` (units)

| Test | Description | Req. |
|---|---|---|
| `ParseDuration.AcceptsAllUnits` | `ms`, `s`, `m`, `h`, `d` are parsed to the right duration; surrounding spaces ignored | CFG-03 |
| `ParseDuration.RejectsInvalidInput` | Malformed durations (missing or unknown unit, non-numeric) are refused | CFG-03 |
| `ParseDuration.RejectsOverflow` | A value too large for the duration type is refused instead of wrapping | CFG-03 |
| `ParseSize.AcceptsUnitsAndPlainBytes` | `KiB`, `MiB`, `GiB` and plain byte counts | CFG-03 |
| `ParseSize.RejectsInvalidInput` | Malformed sizes are refused | CFG-03 |
| `ParsePercent.ReturnsFraction` | `10%` gives 0.10 | CFG-03 |
| `ParsePercent.RejectsInvalidInput` | Malformed percentages are refused | CFG-03 |
| `FormatDuration.UsesLargestExactUnit` | Durations are written with the largest exact unit (`5m`, `90s`, `1500ms`, `2d`) | CFG-04 |
| `Units.FormatSizeAndPercentRoundTrip` | Sizes and percentages written then parsed give the same value | CFG-04 |
| `ParseEndpoint.AcceptsIpv4HostnameAndIpv6` | `host:port`, `a.b.c.d:port` and `[v6]:port` | CFG-03 |
| `ParseEndpoint.RejectsInvalidInput` | Malformed endpoints (missing or out-of-range port, bad host) are refused | CFG-03 |
| `Endpoint.ToStringBracketsIpv6` | IPv6 endpoints are printed with brackets | CFG-03 |
| `IpLiteral.RecognisesAddresses` | IP literals are told apart from host names (used for SAN and `server_name`); wildcard addresses recognised | CFG-03, TLS-05 |

### 3.2 Configuration and validation — `test_config.cpp`

| Test | Description | Req. |
|---|---|---|
| `Config.LoadsValidClient` | A complete client configuration loads with every field set as written | CFG-01, GEN-05 |
| `Config.LoadsValidServerWithDefaults` | A minimal server configuration gets every documented default (SPEC §5.2, §5.4) | CFG-01, GEN-05 |
| `Config.ExamplesAreValid` | Every file in `examples/` is valid | CFG-01 |
| `Config.ReportsYamlSyntaxErrorWithPosition` | A YAML syntax error is reported with line and column | CFG-01 |
| `Config.RejectsUnknownKeysAtEveryLevel` | An unknown key is refused at the root, in each section and in each port | CFG-01 |
| `Config.CollectsAllFormatErrors` | Several errors in one file are all reported, each with its path | CFG-01 |
| `Config.RequiresModeAndListen` | `mode` and each port's `listen` are mandatory | CFG-01, CFG-02 |
| `Config.RejectsSectionWithWrongType` | A section given as a scalar or a list is refused with its path | CFG-01 |
| `Validate.ClientRules` | Client mode: `upstream` mandatory and valid per port, `server_name` meaningless on `plain`, `destination` forbidden, `source_address` checked, `pki_root` required for `tls` | CFG-02 |
| `Validate.ServerRules` | Server mode: `destination` and `whitelist.file` mandatory, `upstream` forbidden | CFG-02 |
| `Validate.DestinationRules` | Destination port, `dial_retries` and `dial_timeout` ranges | CFG-02, CAN-04 |
| `Validate.ListenAddressRules` | Ports 1–65535, no duplicate listen address | CFG-02 |
| `Validate.RequiresAtLeastOnePort` | A configuration without any port is refused | CFG-02, GEN-04 |
| `Validate.LimitsCoherence` | `idle_timeout` < `session_lifetime`, `renegotiation_grace` < lifetime / 2, jitter ≤ 50 % | CAN-05, CFG-02 |
| `Validate.InstanceNameAndLogOutput` | Instance name syntax; unsupported log outputs refused | CFG-02, LOG-01 |
| `Validate.ProgrammaticConfigUsesSameRules` | A configuration built in code (as the editor does) goes through the same validation | CFG-02, EDT-01 |

### 3.3 Writers and diff — `test_writer.cpp`

| Test | Description | Req. |
|---|---|---|
| `ConfigWriter.ExamplesRoundTrip` | Each example is loaded, written and reloaded: identical configuration | CFG-04 |
| `ConfigWriter.EveryFieldRoundTrips` | A configuration with every field set to a non-default value survives write and reload | CFG-04 |
| `ConfigWriter.DefaultsAreOmittedAndHeaderIsCommented` | Default values are not written; the file starts with a comment header | CFG-04 |
| `WhitelistWriter.RoundTripKeepsDefaultPorts` | An entry without `ports` is written without `ports` (default semantics kept) | CFG-04 |
| `WhitelistWriter.ExampleRoundTrip` | The example whitelist survives write and reload | CFG-04 |
| `TextDiff.LinesAddedRemovedAndChanged` | The line diff reports additions, removals and changes | EDT-02 |
| `TextDiff.FormatKeepsContext` | The formatted diff keeps context lines around changes | EDT-02 |

### 3.4 Logging — `test_logging.cpp`

| Test | Description | Req. |
|---|---|---|
| `JsonEscape.EscapesSpecialCharacters` | Quotes, backslashes and control characters are escaped in JSON output | LOG-01, LOG-03 |
| `JsonFormatter.WritesOneObjectPerLine` | JSON format writes one complete object per line with the context fields | LOG-01 |
| `Logging.CliLevelOverridesCategories` | `-v`/`-vv`/`-q` override the configured category levels | LOG-01 |
| `Logging.UnwritableFileIsReported` | An unwritable log file gives a clear error on every OS | LOG-01 |
| `Logging.WritesToFile` | `logging.output: <path>` writes to the file | LOG-01 |

### 3.5 Tunnel frames — `test_frame.cpp`

| Test | Description | Req. |
|---|---|---|
| `Frame.HeaderIsBigEndian` | The 8-byte header is encoded in network byte order | TUN-01 |
| `Frame.RoundTripOfEveryType` | Every frame type of SPEC §4.2 is encoded and decoded identically | TUN-01 |
| `Frame.StatusMessageIsTruncated` | `CLOSE`/`OPEN_FAIL` messages over 256 bytes are truncated | TUN-14 |
| `Frame.StatusMessageControlCharactersAreEscaped` | Control characters, newlines and terminal escape sequences from the peer are escaped (`\xNN`) | TUN-14, LOG-03 |
| `Frame.WaitsForCompleteFrame` | The decoder waits for the complete header and payload, byte by byte | TUN-01 |
| `Frame.RejectsUnknownType` | Unknown type → `PROTOCOL_ERROR` | TUN-01 |
| `Frame.RejectsNonZeroReservedField` | Non-zero reserved field → `PROTOCOL_ERROR` | TUN-01 |
| `Frame.RejectsOversizedFrameFromHeaderAlone` | A length above 16 KiB + 64 is refused from the header, without waiting for or storing the payload (`FRAME_TOO_LARGE`) | TUN-01 |
| `Frame.RejectsSizeInconsistentWithType` | A payload size that does not match the type is refused | TUN-01 |
| `Frame.RejectsUnknownPortKindInOpen` | `OPEN` with a port kind other than 1, 2 or 3 is refused | TUN-01, TUN-02 |
| `Frame.ErrorIsFinal` | After an error, the decoder stays in error | TUN-01 |

### 3.6 Whitelist — `test_whitelist.cpp`

| Test | Description | Req. |
|---|---|---|
| `Whitelist.LoadsEntriesWithDefaults` | Without `ports` and `subject`: `plain` and `tls` only; without `ports` but with a subject: all ports | WL-01 |
| `Whitelist.ReportsFormatErrors` | Unknown keys, bad IP/CIDR (host bits set), bad DN, `mtls` without subject: each error reported | WL-01 |
| `Whitelist.RejectsSameSubjectTwice` | A subject in two entries is refused | WL-01 |
| `Whitelist.RequiresPeersSection` | The `peers` section is mandatory | WL-01 |
| `Whitelist.EmptyListIsValidWithWarning` | An empty list is accepted with a warning | WL-01 |
| `IpRange.MatchesAddresses` | CIDR matching for IPv4 and IPv6, including an IPv4 address seen through an IPv6 socket | WL-02, CFG-03 |
| `Whitelist.AuthorizesByIpAndPort` | Authorisation by address and port | WL-02 |
| `Whitelist.MtlsRequiresIpAndSubjectInTheSameEntry` | Canonical comparison (case and spaces ignored); right subject with another entry's IP, and the reverse, refused; component order matters | WL-03 |
| `Dn.ParsesEscapesAndMatchesCertificateForm` | RFC 4514 DN parsing with escapes; multi-valued and hex values refused; matches the certificate's form | WL-03 |
| `Whitelist.DiffReportsChanges` | The reload diff lists peers added, removed and modified | WL-04 |

### 3.7 Instance PKI — `test_pki.cpp`

| Test | Description | Req. |
|---|---|---|
| `PkiTest.LoadsServerGeneration` | A complete server generation loads | PKI-02, PKI-03 |
| `PkiTest.LoadsClientGenerationWithTrustOnly` | A TLS client without an identity loads a trust-only generation | PKI-03, PKI-10 |
| `PkiTest.RejectsMissingOrInvalidPointer` | Missing `current`, or a `current` that does not name a valid generation: refused | PKI-02 |
| `PkiTest.ReportsEveryMissingFile` | All missing files are reported at once | PKI-03 |
| `PkiTest.RejectsKeyNotMatchingCertificate` | Key and certificate mismatch refused | PKI-03 |
| `PkiTest.RejectsEncryptedKeyWithoutPrompting` | An encrypted key is refused without asking for a passphrase | PKI-04 |
| `PkiTest.RejectsExpiredAndNotYetValidCertificates` | Dates checked on the whole chain | PKI-03, TLS-07 |
| `PkiTest.WarnsWhenExpiryIsNear` | Warning below `expiry_warning` | PKI-03 |
| `PkiTest.RejectsCertificateWithWrongUsageForRole` | A client certificate presented by a server is refused | PKI-03 |
| `PkiTest.RejectsChainThatDidNotIssueCertificate` | `chain.pem` that did not issue the leaf is refused | PKI-03 |
| `PkiTest.RejectsChainNotAnchoredInTrustedRoots` | A chain not anchored in `trust-roots.pem` is refused | PKI-03 |
| `PkiTest.RejectsTrustIssuerThatIsNotACa` | `trust-issuer.pem` must contain CAs | PKI-03 |
| `PkiTest.RejectsGarbageFiles` | Non-PEM or truncated files are refused cleanly | PKI-03 |
| `PkiRequirements.DependOnModeAndPorts` | Which files are needed depends on mode and ports (identity, trust, issuer) | PKI-03 |
| `PkiTest.CheckCandidateAppliesRootGuard` | New root without pre-trust refused; same root with a new certificate accepted; server without mTLS must still chain to current roots | PKI-07 |
| `PkiTest.ActivateReplacesCurrentPointer` | `pki activate` replaces `current` atomically | PKI-02 |

### 3.8 Plain relay, channels and lifecycle — `test_relay.cpp`

| Test | Description | Req. |
|---|---|---|
| `Relay.PlainChainPreservesDataIntegrity` | Client → server → destination on the plain port; SHA-256 identical both ways | GEN-04, GEN-05 |
| `Relay.ManyChannelsInParallel` | Many channels at once, each with its own hash | CAN-01 |
| `Relay.HalfClosePropagatesThroughTheChain` | The destination's end of stream reaches the application while the other direction continues | TUN-13 |
| `Relay.IdleTimeoutClosesChannel` | A silent channel is closed at `idle_timeout`, on both relays | CAN-03 |
| `Relay.ActivityKeepsChannelOpen` | Regular application data pushes the deadline back | CAN-03 |
| `Relay.DestinationUnreachableAfterThreeAttempts` | Three attempts with doubled back-off, then `OPEN_FAIL(DEST_UNREACHABLE)` | CAN-04 |
| `Relay.DestinationRetrySucceeds` | Destination appears during retries: the channel opens without loss; attempt timing measured | CAN-04 |
| `Relay.MaxChannelsRejectsExtraConnections` | Connections above `max_channels` are refused | CAN-02 |
| `Relay.GracefulStopDrainsThenClosesRemainingChannels` | Graceful stop: no new connections, drain, then close at `shutdown_timeout` | ADM-02 |
| `Relay.GracefulStopWithoutChannelsIsImmediate` | Stop without channels does not wait | ADM-02 |
| `Relay.AbortClosesChannelsImmediately` | Immediate stop closes all channels | ADM-02 |
| `Relay.SignalTriggersGracefulStop` | SIGINT / Ctrl+C starts a graceful stop | ADM-02 |
| `Relay.SecondSignalForcesImmediateStop` | A second signal during the drain stops at once | ADM-02 |

### 3.9 TLS and mTLS — `test_tls.cpp`, `test_mtls.cpp`

| Test | Description | Req. |
|---|---|---|
| `TlsTest.ChainPreservesDataIntegrity` | TLS port chain, hashes identical | GEN-04 |
| `TlsTest.ManyChannelsInParallel` | Many TLS channels at once | CAN-01 |
| `TlsTest.HalfClosePropagatesOverTls` | Half-close across the TLS tunnel | TUN-13 |
| `TlsTest.ClientAcceptsIpAddressAsServerName` | `server_name` given as an IP is checked against the IP SAN | TLS-05 |
| `TlsTest.ClientRejectsServerFromAnotherPki` | Server from another PKI refused by the client | TLS-05 |
| `TlsTest.ClientRejectsWrongServerName` | Host name mismatch refused | TLS-05 |
| `TlsTest.ClientRejectsServerCertificateFromUnexpectedCa` | Same root, wrong intermediate: refused during the handshake, the destination is not contacted | TLS-05 |
| `TlsTest.ServerNegotiatesTls13WithAlpn` | Raw client sees TLS 1.3 and ALPN `tlsrelay/1` | TLS-01, TLS-03 |
| `TlsTest.ServerRejectsTls12` | A TLS 1.2-only client is refused | TLS-01 |
| `TlsTest.ServerRejectsWrongAlpn` | Another ALPN is refused | TLS-03 |
| `TlsTest.ServerRejectsMissingAlpn` | No ALPN: the server closes before contacting the destination | TLS-03, GEN-03 |
| `TlsTest.ServerRejectsPlaintextOnTlsPort` | Plaintext on the TLS port is refused | TLS-01 |
| `TlsTest.HandshakeTimeoutClosesSilentConnection` | A connection without a handshake is closed at `handshake_timeout` | TLS-08 |
| `TlsTest.ServiceRefusesToStartWithInvalidPki` | Invalid PKI at startup: the service does not start | PKI-06 |
| `MtlsTest.ChainPreservesDataIntegrity` | mTLS port chain, hashes identical | GEN-04 |
| `MtlsTest.ServerRejectsClientWithoutCertificate` | No client certificate: refused | TLS-06 |
| `MtlsTest.ServerRejectsClientCertificateFromUnexpectedCa` | Same root, intermediate other than the Clients CA: refused | TLS-06 |
| `MtlsTest.ServerRejectsServerCertificateUsedAsClientCertificate` | A server certificate used as client certificate is refused | TLS-06 |
| `MtlsTest.WhitelistRejectsUnknownSubjectBeforeContactingDestination` | Unknown subject refused; destination never contacted | WL-03 |
| `MtlsTest.WhitelistRequiresIpAndSubjectInTheSameEntry` | Subject allowed only from 127.0.0.2; from 127.0.0.1 (another entry): refused | WL-03 |
| `MtlsTest.UnknownAddressIsRejectedBeforeHandshake` | Unknown IP closed before any TLS byte | WL-02 |
| `MtlsTest.PeerIsLimitedToItsPorts` | Entry allowed on `tls` only: refused on `plain` | WL-02 |
| `MtlsTest.ReloadRevokesActiveChannelOfRemovedPeer` | Peer removed from the file: its open channel is closed (`PEER_REVOKED`) | WL-05, WL-04 |
| `MtlsTest.ReloadWithNextRenegotiationKeepsActiveChannel` | `next_renegotiation`: channel kept until its next renegotiation, new connections refused | WL-05 |
| `MtlsTest.InvalidReloadKeepsCurrentList` | Invalid file on reload: list in force kept | WL-04 |
| `MtlsTest.ReloadAddsPeer` | Added peer accepted after the 2 s watch | WL-04 |
| `MtlsTest.ServiceRefusesInvalidWhitelistAtStartup` | Invalid whitelist at startup: service does not start | WL-06 |

### 3.10 Rotation and root change — `test_rotation.cpp`

| Test | Description | Req. |
|---|---|---|
| `RotationTest.NewConnectionsUseNewGenerationWhileOldOnesDrain` | New key pair and certificate: new connections on v2, the connection opened before stays on v1 | PKI-05 |
| `RotationTest.OldGenerationIsReleasedWhenItsLastConnectionCloses` | v1 released (and logged) when its last connection closes | PKI-05 |
| `RotationTest.InvalidGenerationIsRefusedAndServiceContinues` | Invalid v2: refused, error logged, v1 still serves | PKI-06 |
| `RotationTest.GuardRefusesRootChangeWithoutPreTrust` | Direct switch from root A to root B refused | PKI-07 |
| `RotationTest.GuardRefusesIdentityFromUnknownRootEvenWithoutMtls` | TLS-only server: identity from root B refused (clients knowing only A would be cut) | PKI-07 |
| `RotationTest.KillOldClosesConnectionsOfRetiredGeneration` | `reload --kill-old` closes the retired generation's connections | PKI-05 |
| `RotationTest.WatchDisabledWaitsForExplicitReload` | `watch: false`: no switch until an explicit reload | PKI-09 |
| `RotationTest.SighupTriggersReload` | SIGHUP triggers the reload (Linux only) | PKI-09 |
| `RotationTest.ThreeStepRootChangeKeepsServiceAvailable` | Three-step root change in mTLS; new connections succeed at every step and a connection opened at the start stays open to the end | PKI-08 |

### 3.11 Tunnel protocol — `test_tunnel.cpp`

| Test | Description | Req. |
|---|---|---|
| `TunnelTest.RenegotiationIsTransparentUnderLoad` | Continuous transfer across several renegotiations; hash identical, application never cut | TUN-06 |
| `TunnelTest.RenegotiationMovesOpenChannelToNewGeneration` | After a rotation, the next renegotiation moves the channel to v2; v1 released on both sides | TUN-06, PKI-05 |
| `TunnelTest.SessionResumesAfterTransportLoss` | Cut by the proxy: session resumed, no loss or duplication | TUN-09 |
| `TunnelTest.PlainTransportLossClosesChannel` | Plain port: a cut closes the channel | TUN-12 |
| `TunnelTest.ServerClosesSessionThatIsNotRenegotiated` | Client that never renegotiates: `LIFETIME_EXCEEDED` after the grace period | TUN-08 |
| `TunnelTest.ResumeTokenIsBoundToConnectionAndSingleUse` | Replayed or forged token refused; valid resume replays unacknowledged data | TUN-07 |
| `TunnelTest.ServerWaitsForResumeOnlyDuringGrace` | After `renegotiation_grace`, the server closes the session and destination | TUN-09 |
| `TunnelTest.InvalidFrameClosesChannelWithProtocolError` | A malformed frame closes the channel with `PROTOCOL_ERROR` | TUN-01 |
| `TunnelTest.OpenIsRefusedForAnotherPortOrDuplicateSession` | `OPEN` for another port kind or a session id already in use: refused | TUN-02 |
| `TunnelTest.SmallResumeBufferAppliesBackpressureWithoutLoss` | Small `resume_buffer`: sources paused, nothing lost | TUN-04 |
| `TunnelTest.SilentTransportIsDetectedByKeepaliveAndResumed` | Frozen link: detected after 3 keepalive intervals, session resumed | TUN-11 |
| `TunnelTest.SilentPlainTransportClosesChannel` | Frozen plain link: channel closed | TUN-11, TUN-12 |
| `TunnelTest.KeepaliveToleratesApplicationNotReading` | Application not reading (TCP buffers full): no false dead-link verdict | TUN-05, TUN-11 |
| `TunnelTest.SlowDestinationDoesNotStallAcknowledgements` | Server blocked writing to a slow destination still processes the client's ACKs | TUN-05 |
| `TunnelTest.TransportLossDuringHandshakeReopensTunnel` | Cut during the TLS handshake: tunnel reopened, no loss | TUN-10 |
| `TunnelTest.TransportLossBeforeOpenOkReopensTunnel` | Cut while the server is still dialling: tunnel reopened, no loss | TUN-10 |

### 3.12 Revocation — `test_crl.cpp`

| Test | Description | Req. |
|---|---|---|
| `CrlTest.ServerRefusesRevokedClientCertificate` | Revoked client certificate refused at the handshake on the mTLS port | CRL-01 |
| `CrlTest.ClientRefusesRevokedServerCertificate` | Revoked server certificate refused by the client | CRL-01 |
| `CrlTest.CrlOfOtherCertificatesChangesNothing` | CRL listing other certificates: no effect; the Servers CA CRL is ignored by a server | CRL-01 |
| `CrlTest.PublishedCrlClosesActiveChannelAndRefusesNewOnes` | New CRL: open channel of the revoked peer closed, new connections refused | CRL-02 |
| `CrlTest.NextRenegotiationKeepsActiveChannel` | `next_renegotiation`: channel kept until its next renegotiation | CRL-02 |
| `CrlTest.InvalidCrlIsRefusedAtStartupAndKeptAsIsOnReload` | CRL signed by another key: startup refused; on reload, CRLs in force kept | CRL-03 |
| `CrlTest.ExpiredCrlIsStillAppliedWithWarning` | Stale CRL still applied with a warning; expected CA without CRL: warning, nothing revoked | CRL-03 |
| `CrlTest.RevokedInstanceCertificateIsReported` | The instance's own revoked certificate is reported | CRL-03 |

### 3.13 Mini-CA — `test_ca.cpp`

| Test | Description | Req. |
|---|---|---|
| `CaTest.InitCreatesHierarchyWithEncryptedKeys` | `ca init`: hierarchy of SPEC §7.1, encrypted keys, `0600` (Linux); a second init overwrites nothing | CA-01, PKI-01 |
| `CaTest.ProvisionedPkiCarriesAnMtlsChain` | PKI produced by the CA commands carries a working mTLS chain | PKI-01, PKI-10 |
| `CaTest.GenCsrCreatesNextGenerationWithPrivateKey` | `pki gen-csr` creates `vN` with an owner-only key and a CSR | PKI-04, PKI-10 |
| `CaTest.SignAppliesCaPolicyAndIgnoresRequestedExtensions` | Requested CA rights and usages ignored; chain verified by OpenSSL; one-year default validity | CA-02 |
| `CaTest.SignRefusesNonConformingRequests` | RSA or P-384 key, unreadable request, altered signature, server without SAN, wrong passphrase: refused, nothing issued | CA-02 |
| `CaTest.SubjectIsAttributedOnceUnlessRenewed` | Same subject refused without `--renew`; renewal of an unknown subject or another role refused | CA-03 |
| `CaTest.RenewalRotatesKeyAndKeepsTrustFiles` | Renewal: new key in v2, trust files taken from v1; a complete generation cannot be reinstalled | PKI-10 |
| `CaTest.InstallRejectsCertificateForAnotherKey` | `pki install` refuses a certificate for another key | PKI-10 |
| `SubjectAltNames.ParsesTypedAndBareValues` | `--san` values with or without `DNS:`/`IP:` prefixes | CA-02 |
| `CaTest.RevocationIsPublishedInSignedCrls` | Revocation: lowercase serial accepted, double and unknown refused; OpenSSL recognises the revoked certificate; increasing CRL numbers; subject reusable after revocation | CA-05 |
| `CaTest.AuditLogRecordsOperationsAndDetectsTampering` | Each operation logged; modified or deleted line breaks the chain; tabs and newlines in fields cannot break the format | CA-06 |
| `CaTest.IndexWithoutRevocationColumnsIsStillRead` | Five-column inventory from delivery 1.0 still read | CA-04 |
| `CaTest.PublishedCrlIsAcceptedByInstancesOfBothRoles` | Published CRLs accepted by `pki crl` on a server and a client; the client learns its own certificate is revoked | CRL-01, CRL-04 |
| `CaTest.DescribeAuthoritySummarizesCertificatesAndCrl` | CA summary (certificates, fingerprints, CRL state) used by the editor | CA-04, EDT-04 |
| `CaTest.RootTransitionFilesDriveTheThreeSteps` | Files from `ca root-change` pass the rotation guard at each step on a server and a client | CA-07, PKI-08 |

### 3.14 Administration channel — `test_admin.cpp`

| Test | Description | Req. |
|---|---|---|
| `AdminProtocol.ParsesRequestWords` | Request line split into command and arguments; empty lines and control characters refused; `OK <n>` / `ERREUR <n>` reply encoding | ADM-03 |
| `AdminTest.StatusDescribesInstance` | `status`: instance, mode, OpenSSL version, ports, whitelist size; `ping` answers `pong` | ADM-05 |
| `AdminTest.UnknownOrMalformedCommandsAreRefused` | Unknown command, unexpected argument and over-long line: `ERREUR` reply with the command list, service unaffected | ADM-03 |
| `AdminTest.SecondExecutionOfSameInstanceIsRefused` | Instance lock; released at stop | ADM-04 |
| `AdminTest.UnreachableInstanceIsReported` | Command to a stopped instance: clear error | ADM-05 |
| `AdminTest.SocketIsRestrictedToOwnerAndGroup` | Socket `0660`, directory `0750` (Linux only) | ADM-03 |
| `AdminTest.StopDrainsThenStops` | `stop` drains then stops | ADM-02 |
| `AdminTest.KillStopsImmediately` | `kill` stops at once | ADM-02 |
| `AdminTest.ChannelsListsOpenChannels` | `channels` lists port, state, session, peer, generation, bytes | ADM-05 |
| `AdminTest.MetricsUsePrometheusTextFormat` | `metrics`: valid Prometheus text, one sample per line | ADM-08 |
| `AdminTest.ReloadReportsWhatChanged` | `reload` reports whitelist, PKI and configuration changes; non-runtime changes flagged as requiring a restart | ADM-05, ADM-06 |
| `AdminTest.LogLevelChangesAtRuntime` | `log-level` changes global and per-category levels | LOG-02 |
| `AdminTest.LogReopenStartsNewFileAfterRotation` | `log-reopen` after a rename creates a new file (Linux only) | LOG-02 |

### 3.15 Attack cases — `test_attacks.cpp`

| Test | Description | Req. |
|---|---|---|
| `AttackTest.ServerRejectsExpiredClientCertificate` | Expired client certificate refused | TLS-07, SEC-03 |
| `AttackTest.ServerRejectsNotYetValidClientCertificate` | Not-yet-valid client certificate refused | TLS-07, SEC-03 |
| `AttackTest.ClientRejectsExpiredServerCertificate` | Expired server certificate refused | TLS-07, SEC-03 |
| `AttackTest.ClientRejectsNotYetValidServerCertificate` | Not-yet-valid server certificate refused | TLS-07, SEC-03 |
| `AttackTest.ClientRejectsServerPresentingClientCertificate` | Servers CA certificate with `clientAuth` usage presented by a server: refused | TLS-05, SEC-03 |
| `AttackTest.ClientSendsNothingToValidFakeServerWithoutTunnelProtocol` | Fake server with a valid certificate gets the handshake and `OPEN`, never application data | GEN-03, SEC-03 |
| `AttackTest.DataWithUnexpectedSequenceClosesChannel` | Out-of-sequence `DATA` closes the channel | TUN-03, SEC-03 |
| `AttackTest.OversizedFrameHeaderClosesChannelBeforePayload` | Header announcing 1 GiB refused without allocating | TUN-01, SEC-03 |
| `AttackTest.DataBeforeOpenIsRefused` | `DATA` before `OPEN` refused | TUN-02, SEC-03 |
| `AttackTest.ConnectionFloodWithoutHandshakeIsBoundedAndRecovers` | 30 silent connections: handshake slots bounded, extras refused, all closed, legitimate peer still served | TLS-08, SEC-03 |
| `AttackTest.TraceLogsContainNoSecretsNorRelayedData` | At `trace`, logs contain no private key line, token, nor relayed bytes | LOG-03, SEC-03 |
| `AttackTest.PeerMessageCannotInjectLogLines` | Peer `CLOSE` message with newlines produces a single escaped log line | LOG-03, TUN-14, SEC-03 |

### 3.16 Editor — Qt Test (`tests/admin/test_admin.cpp`, ctest `Admin.QtTests`)

Runs with the `offscreen` Qt platform; dialogs are replaced by injected hooks.

| Test | Description | Req. |
|---|---|---|
| `form_round_trips_examples` | Each example loaded into the form gives back the same configuration | EDT-01, CFG-04 |
| `validation_matches_service` | Corpus of valid and invalid files: the form reports exactly the service's errors (paths and messages) | EDT-01, CFG-02 |
| `invalid_fields_are_marked` | Faulty fields framed with a tooltip; a section-level error marks the section | EDT-01 |
| `fields_without_object_are_hidden_unless_filled` | Fields that do not apply to the mode are hidden unless they hold a value | EDT-01 |
| `whitelist_editor_round_trip_and_marks` | Whitelist table round trip; duplicate name, bad IP, `mtls` without subject marked | EDT-01 |
| `open_edit_save_with_preview_and_backup` | Files rewritten, originals as `.bak`, reread identically by the service; unchanged second save writes nothing; preview refused writes nothing | EDT-02 |
| `save_refused_while_invalid` | Save refused while errors remain | EDT-02 |
| `new_document_is_saved_normalized` | New document saved in normalised form | EDT-02, CFG-04 |
| `export_package_for_linux_and_windows` | Package for both targets; existing package not overwritten; relative Linux paths flagged for Windows; incomplete kit refused | EDT-03 |
| `diff_preview_lists_changes` | Preview lists every changed file with its diff | EDT-02 |
| `pki_panel_full_cycle` | Open CA, sign server and client, renewal and refusal, expiry filter, revocation with CRLs, audit log contents | EDT-04 |
| `pki_panel_refuses_wrong_passphrase_and_bad_directory` | Wrong passphrase and non-CA directory refused; cancelled entry does nothing | EDT-04 |
| `sign_dialog_inspects_request` | Request details shown; renewal with a different subject flagged | EDT-04 |
| `pki_root_change_preparation` | Root-change wizard produces the step files and `LISEZMOI.txt` | EDT-05 |

### 3.17 Editor command line — ctest

| Test | Description | Req. |
|---|---|---|
| `Admin.CheckValid` | `tlsrelay-admin --check examples/client.yaml` exits 0 | EDT-06 |
| `Admin.CheckInvalid` | `--check tests/admin/invalide.yaml` exits non-zero and reports `ports.plain.listen : adresse invalide` | EDT-06, EDT-01 |

### 3.18 Lifecycle scripts — real binary

| Script | Platform, where | Steps and checks | Req. |
|---|---|---|---|
| `tests/lifecycle/console.sh` (ctest `Lifecycle.Console`) | Linux, every ctest run | Console run; instance lock; `status`; `reload`; `stop` with drain; `kill`; SIGTERM | ADM-02, ADM-04, ADM-05 |
| `tests/lifecycle/pki.sh` (ctest `Lifecycle.Pki`) | Linux, every ctest run | `ca init` → `pki gen-csr` → `ca sign` → `pki install` → `pki activate`; mTLS chain in service; `openssl verify`; hot renewal; CA policy refusals; `ca revoke`, `ca crl`, `openssl verify -crl_check`, `pki crl`; `ca audit` intact then tampered | PKI-01, PKI-10, CA-05, CA-06, CRL-04 |
| `tests/lifecycle/systemd.sh` | Linux, CI (GCC Release), root | Install `tlsrelay@N` with `--boot`; relay; `reload`; `restart`; `stop`; `kill`; `systemctl stop`; non-authorised user refused; service account checked; uninstall | ADM-01, ADM-02, ADM-03, ADM-07 |
| `tests/lifecycle/windows-service.ps1` | Windows, CI, administrator | Install under `NT SERVICE\tlsrelay-ci`; start; relay; `reload`; `restart`; `stop`; stop by the service manager; `kill`; uninstall | ADM-01, ADM-02, ADM-07 |
| `tests/lifecycle/windows-pki.ps1` | Windows, CI | `ca init` (ACL of CA keys), `pki gen-csr`, `ca sign`, `pki install`, `check-pki`, duplicate subject refused, revocation and audit | PKI-10, CA-01, CA-06 |
| `tests/lifecycle/tls-scan.sh` | Linux, CI (GCC Release) | sslyze and testssl.sh on ports 2 and 3: TLS 1.3 only, allowed suites only, no session resumption, certificate conforming, no known vulnerability | TLS-01, TLS-02, TLS-04 |

### 3.19 Fuzzing — `fuzz/`, CI job "Fuzzing"

libFuzzer with ASan and UBSan, 60 s per target per push from the corpus in `fuzz/corpus/<target>`; crashing inputs kept as artifacts.

| Target | Input | Req. |
|---|---|---|
| `fuzz_frame` | Tunnel frame decoder | TUN-01, SEC-02 |
| `fuzz_config` | Configuration loader and validation | CFG-01, SEC-02 |
| `fuzz_whitelist` | Whitelist loader | WL-01, SEC-02 |
| `fuzz_dn` | DN parser | WL-01, WL-03, SEC-02 |
| `fuzz_csr` | CSR inspection and CA signing policy | CA-02, SEC-02 |
| `fuzz_admin` | Administration request parser | ADM-03, SEC-02 |

### 3.20 Static analysis, sanitizers, hardening, dependencies

| Check | Where | Pass criterion | Req. |
|---|---|---|---|
| AddressSanitizer + UndefinedBehaviorSanitizer | CI, full ctest | No report | SEC-02 |
| ThreadSanitizer | CI, full ctest, `halt_on_error=1` | No report | SEC-02 |
| clang-tidy, cppcheck | CI "Analyse statique" | No finding | SEC-02 |
| MSVC `/analyze` | CI "Windows MSVC /analyze" | No finding | SEC-02 |
| `tools/check-hardening.sh` | CI, Linux binaries | PIE, full RELRO, stack protector, `_FORTIFY_SOURCE`, non-executable stack | SEC-01 |
| `tools/check-hardening.ps1` | CI, Windows binaries | `/guard:cf`, DEP, ASLR (high entropy) | SEC-01 |
| `tools/check-deps.sh` | CI | Shipped OpenSSL is the latest 3.5 patch release; distribution OpenSSL has no pending update | SEC-04, GEN-02 |
| OpenSSL version | CI Linux 3.5 job, Windows job | `tlsrelay version` reports OpenSSL 3.5.x | GEN-02 |
| Penetration-test checklist | Manual, before production | [PENTEST.md](PENTEST.md) items | SEC-03 |

### 3.21 Performance and endurance — `tests/perf/`

| Script | Chain | Measures and targets | CI | Req. |
|---|---|---|---|---|
| `perf.sh <build> [channels] [report.json]` | testkit → client ══ mTLS ══► server → echo | Concurrent channels (all hashes intact); one-channel throughput ≥ 100 Mbit/s; added latency < 1 ms (median round trip via tlsrelay minus direct) | 1,000 channels | PERF-01, PERF-02, PERF-03 |
| `soak.sh <build> <minutes> [samples.csv]` | testkit → client ══ mTLS ══► cut proxy ══► server → echo | Continuous stream (hash checked at the end), waves of channels, PKI rotation on both sides, renegotiations and periodic cuts; memory, descriptors and live generations stable | 4 minutes | PERF-04 |

Measured on the Linux development machine (full mTLS chain): 5,000 concurrent channels all intact; ≈ 800 Mbit/s per channel; ≈ 0.35 ms added latency; ≈ 50 KiB per open channel per relay.

### 3.22 Packaging — CI

| Check | Where | Req. |
|---|---|---|
| `.deb` build (Ubuntu 22.04 container) and `.rpm` build (Rocky 9 container) | CI | PKG-01 |
| `packaging/test-linux-package.sh`: install, account and directories created, licence and notices present, mTLS exchange between an installed client and server, uninstall (and purge on Debian) | Ubuntu 22.04, 24.04, Debian 12, Rocky 9, Alma 9 | PKG-01, PKG-02, GEN-01 |
| MSI build, silent install (`ADDLOCAL=ALL`), files and licences present, `tlsrelay version`, uninstall leaves no binary | Windows CI | PKG-01, PKG-02 |
| Installed editor check: Qt DLLs and `qwindows.dll` deployed, LGPL/GPL texts, Start menu shortcut for all users, `--check` valid (0) and invalid (1) without the runner's Qt | Windows CI | EDT-06 |
| `tlsrelay-livraison` artifact with `SHA256SUMS` | CI "Paquets de la livraison" | PKG-03 |

### 3.23 Acceptance — `tools/recette.ps1`, [RECETTE.md](RECETTE.md)

Automated scenarios (CI runs them with `-Quick`: on Linux in console mode, on Windows as services on the installed MSI binaries):

| Id | Scenario | Expected result | Req. |
|---|---|---|---|
| R01 | Acceptance PKI built by the mini-CA (`ca init`, `pki gen-csr`, `ca sign`, `pki install`, `pki activate`, `check-pki`) for server and client | Hierarchy created, certificates issued and installed; second certificate for the same subject refused | PKI-10, CA-03 |
| R02 | Starting the instances (services or console) | Valid configurations; PKI v1 and whitelist loaded; services under their virtual accounts | GEN-02, ADM-01 |
| R03 | Concurrent channels on the three ports (500 per port, 100 with `-Quick`) | All intact | GEN-04, GEN-05, CAN-01 |
| R04 | Throughput and latency | ≥ 100 Mbit/s (measured at 200); added latency < 1 ms | PERF-02, PERF-03 |
| R05 | Client address removed from the whitelist, `reload`, restored | New channels refused then accepted again; refusals counted | WL-04 |
| R06 | Network cuts every 5 s on the mtls port (proxy) | Continuous stream intact; resumptions performed | TUN-09 |
| R07 | Renegotiation (`session_lifetime` 30 s) during a continuous stream | At least one renegotiation; stream intact | TUN-06 |
| R08 | Hot PKI rotation (server v2, `--renew`) | Switch without interruption; new channels on v2 | PKI-05 |
| R09 | Three-step root change with a second CA, continuous stream throughout | Channels accepted at every step; stream intact | PKI-08, CA-07 |
| R10 | Logging: `debug` at runtime, relayed marker | Channels logged; no relayed data, private key or passphrase in logs | LOG-02, LOG-03 |
| R11 | Administration: `status`, `channels`, `metrics` | Complete answers | ADM-05, ADM-08 |
| R12 | Lifecycle: `stop` and restart client, `kill` and restart server, `restart` the service | Service back each time; new process after `restart`; no exception logged | ADM-02 |
| R13 | Cross tests (optional): station → Linux and Linux → station, mTLS | All channels intact both ways | GEN-01 |

Manual steps — service (M) and editor (E):

| Id | Step | Req. |
|---|---|---|
| M01 | Start at boot after a station restart | ADM-01 |
| M02 | Station shutdown with open channels: drain logged | ADM-02 |
| M03 | `kill` during a transfer, then clean restart | ADM-02 |
| M04 | Command refused to a standard user | ADM-03 |
| M05 | Log levels: `trace` content conforms to SPEC §9 | LOG-01 |
| M06 | Log rotation with `log-reopen` | LOG-02 |
| M07 | File permissions (`icacls`) on PKI and configuration | ADM-07 |
| M08 | Report: versions and package hashes conform to the delivery | GEN-02, PKG-03 |
| M09 | End: services uninstalled | ADM-01 |
| E01 | Installation from the Start menu, About box (versions, LGPLv3) | EDT-06 |
| E02 | Open and validate: errors identical to `tlsrelay check-config` | EDT-01 |
| E03 | Save: diff preview, `.bak`, result valid | EDT-02 |
| E04 | Running instance picks up the saved whitelist within 2 s | EDT-02, WL-04 |
| E05 | Deployment package installed on a test instance | EDT-03 |
| E06 | Open the mini-CA: summary, inventory equal to `ca list`, audit intact | EDT-04 |
| E07 | Signing and renewal; client switches without a cut | EDT-04 |
| E08 | Revocation: CRL deployed, certificate refused at the handshake | EDT-04, CRL-01 |
| E09 | Wrong passphrase refused; cancelled entry does nothing | EDT-04 |
| E10 | Root-change wizard; tampered audit log flagged | EDT-05, CA-06 |

---

## 4. Requirements coverage

Legend for the **Status** column: **Auto** — fully verified by automated tests on every push; **Auto + manual** — automated in CI, with a manual complement in acceptance or before production; **Partial (manual)** — automated at reduced scale, full verification manual.

| Req. | Requirement (short) | Automated verification | Acceptance / manual | Status |
|---|---|---|---|---|
| GEN-01 | Windows and Linux platforms | Windows MSVC and Linux jobs; package install on 5 distributions | R13 | Auto + manual |
| GEN-02 | OpenSSL ≥ 3.0, 3.5 LTS on Windows, version logged | OpenSSL 3.5 job; Windows version check; `check-deps.sh` | R02, M08 | Auto |
| GEN-03 | Pairwise operation, mandatory ALPN | `TlsTest.ServerRejectsMissingAlpn`, `AttackTest.ClientSendsNothingToValidFakeServerWithoutTunnelProtocol` | — | Auto |
| GEN-04 | Three ports, absent port not opened | `Relay.PlainChainPreservesDataIntegrity`, `TlsTest.ChainPreservesDataIntegrity`, `MtlsTest.ChainPreservesDataIntegrity`, `Validate.RequiresAtLeastOnePort` | R03 | Auto |
| GEN-05 | Client and server modes, single destination | `Relay.*`, `Config.LoadsValidClient`, `Config.LoadsValidServerWithDefaults` | R03 | Auto |
| TLS-01 | TLS 1.3 only | `TlsTest.ServerRejectsTls12`, `TlsTest.ServerRejectsPlaintextOnTlsPort`, `TlsTest.ServerNegotiatesTls13WithAlpn`, `tls-scan.sh` | — | Auto |
| TLS-02 | Allowed suites and groups only | `tls-scan.sh` (sslyze, testssl.sh) | — | Auto |
| TLS-03 | ALPN `tlsrelay/1` | `TlsTest.ServerNegotiatesTls13WithAlpn`, `TlsTest.ServerRejectsMissingAlpn`, `TlsTest.ServerRejectsWrongAlpn` | — | Auto |
| TLS-04 | No TLS session resumption | `tls-scan.sh` | — | Auto |
| TLS-05 | Client verifies chain, name, issuer | `TlsTest.ClientRejectsServerFromAnotherPki`, `…WrongServerName`, `…AcceptsIpAddressAsServerName`, `…ServerCertificateFromUnexpectedCa`, `AttackTest.ClientRejectsServerPresentingClientCertificate`, `IpLiteral.RecognisesAddresses` | — | Auto |
| TLS-06 | Server requires Clients CA certificate on mtls | `MtlsTest.ServerRejectsClientWithoutCertificate`, `…ClientCertificateFromUnexpectedCa`, `…ServerCertificateUsedAsClientCertificate` | — | Auto |
| TLS-07 | Certificate dates on both sides | `AttackTest.*Expired*`, `AttackTest.*NotYetValid*` (4 tests), `PkiTest.RejectsExpiredAndNotYetValidCertificates` | — | Auto |
| TLS-08 | Handshake timeout, bounded flood | `TlsTest.HandshakeTimeoutClosesSilentConnection`, `AttackTest.ConnectionFloodWithoutHandshakeIsBoundedAndRecovers` | — | Auto |
| TUN-01 | Frame format and refusals | `Frame.*` (9 tests), `TunnelTest.InvalidFrameClosesChannelWithProtocolError`, `AttackTest.OversizedFrameHeaderClosesChannelBeforePayload`, `fuzz_frame` | — | Auto |
| TUN-02 | `OPEN` / `OPEN_OK` / `OPEN_FAIL` | `TunnelTest.OpenIsRefusedForAnotherPortOrDuplicateSession`, `AttackTest.DataBeforeOpenIsRefused`, `Frame.RejectsUnknownPortKindInOpen` | — | Auto |
| TUN-03 | Sequence numbers and cumulative ACK | `AttackTest.DataWithUnexpectedSequenceClosesChannel`; integrity hashes of every chain test | — | Auto |
| TUN-04 | Back-pressure without loss | `TunnelTest.SmallResumeBufferAppliesBackpressureWithoutLoss` | — | Auto |
| TUN-05 | Transport reading independent of peers' speed | `TunnelTest.SlowDestinationDoesNotStallAcknowledgements`, `TunnelTest.KeepaliveToleratesApplicationNotReading` | — | Auto |
| TUN-06 | Transparent renegotiation | `TunnelTest.RenegotiationIsTransparentUnderLoad`, `TunnelTest.RenegotiationMovesOpenChannelToNewGeneration` | R07 | Auto |
| TUN-07 | Resume token bound and single-use | `TunnelTest.ResumeTokenIsBoundToConnectionAndSingleUse` | — | Auto |
| TUN-08 | Session closed without renegotiation | `TunnelTest.ServerClosesSessionThatIsNotRenegotiated` | — | Auto |
| TUN-09 | Resume after a cut within grace | `TunnelTest.SessionResumesAfterTransportLoss`, `TunnelTest.ServerWaitsForResumeOnlyDuringGrace` | R06 | Auto |
| TUN-10 | Cut before `OPEN_OK` reopens the tunnel | `TunnelTest.TransportLossBeforeOpenOkReopensTunnel`, `TunnelTest.TransportLossDuringHandshakeReopensTunnel` | — | Auto |
| TUN-11 | Keepalive: dead link detection | `TunnelTest.SilentTransportIsDetectedByKeepaliveAndResumed`, `TunnelTest.SilentPlainTransportClosesChannel`, `TunnelTest.KeepaliveToleratesApplicationNotReading` | — | Auto |
| TUN-12 | Plain port: no resume | `TunnelTest.PlainTransportLossClosesChannel`, `TunnelTest.SilentPlainTransportClosesChannel` | — | Auto |
| TUN-13 | Half-close end to end | `Relay.HalfClosePropagatesThroughTheChain`, `TlsTest.HalfClosePropagatesOverTls` | — | Auto |
| TUN-14 | Peer messages truncated and escaped | `Frame.StatusMessageIsTruncated`, `Frame.StatusMessageControlCharactersAreEscaped`, `AttackTest.PeerMessageCannotInjectLogLines` | — | Auto |
| CAN-01 | Parallel channels | `Relay.ManyChannelsInParallel`, `TlsTest.ManyChannelsInParallel`, `perf.sh` | R03 | Auto |
| CAN-02 | `max_channels` | `Relay.MaxChannelsRejectsExtraConnections` | — | Auto |
| CAN-03 | `idle_timeout` | `Relay.IdleTimeoutClosesChannel`, `Relay.ActivityKeepsChannelOpen` | — | Auto |
| CAN-04 | Destination retries | `Relay.DestinationUnreachableAfterThreeAttempts`, `Relay.DestinationRetrySucceeds`, `Validate.DestinationRules` | — | Auto |
| CAN-05 | Timer consistency | `Validate.LimitsCoherence` | — | Auto |
| WL-01 | Strict whitelist validation | `Whitelist.LoadsEntriesWithDefaults`, `…ReportsFormatErrors`, `…RejectsSameSubjectTwice`, `…RequiresPeersSection`, `…EmptyListIsValidWithWarning`, `fuzz_whitelist`, `fuzz_dn` | — | Auto |
| WL-02 | IP checked before the handshake | `MtlsTest.UnknownAddressIsRejectedBeforeHandshake`, `MtlsTest.PeerIsLimitedToItsPorts`, `Whitelist.AuthorizesByIpAndPort`, `IpRange.MatchesAddresses` | — | Auto |
| WL-03 | Subject and IP in the same entry | `MtlsTest.WhitelistRequiresIpAndSubjectInTheSameEntry`, `MtlsTest.WhitelistRejectsUnknownSubjectBeforeContactingDestination`, `Whitelist.MtlsRequiresIpAndSubjectInTheSameEntry`, `Dn.ParsesEscapesAndMatchesCertificateForm` | — | Auto |
| WL-04 | Hot reload, invalid file kept out | `MtlsTest.ReloadAddsPeer`, `MtlsTest.InvalidReloadKeepsCurrentList`, `Whitelist.DiffReportsChanges` | R05, E04 | Auto |
| WL-05 | Removed peer's channels | `MtlsTest.ReloadRevokesActiveChannelOfRemovedPeer`, `MtlsTest.ReloadWithNextRenegotiationKeepsActiveChannel` | — | Auto |
| WL-06 | Invalid whitelist at startup | `MtlsTest.ServiceRefusesInvalidWhitelistAtStartup` | — | Auto |
| PKI-01 | PKI hierarchy | `CaTest.InitCreatesHierarchyWithEncryptedKeys`, `CaTest.ProvisionedPkiCarriesAnMtlsChain`, `pki.sh` | R01 | Auto |
| PKI-02 | Versioned generations, atomic pointer | `PkiTest.ActivateReplacesCurrentPointer`, `PkiTest.RejectsMissingOrInvalidPointer`, `PkiTest.LoadsServerGeneration` | — | Auto |
| PKI-03 | Full validation of a generation | `PkiTest.*` (13 tests), `PkiRequirements.DependOnModeAndPorts` | — | Auto |
| PKI-04 | Instance key on the machine, unencrypted, owner-only | `PkiTest.RejectsEncryptedKeyWithoutPrompting`, `CaTest.GenCsrCreatesNextGenerationWithPrivateKey` | M07 | Auto |
| PKI-05 | Hot rotation with drain | `RotationTest.NewConnectionsUseNewGenerationWhileOldOnesDrain`, `…OldGenerationIsReleasedWhenItsLastConnectionCloses`, `…KillOldClosesConnectionsOfRetiredGeneration`, `TunnelTest.RenegotiationMovesOpenChannelToNewGeneration`, `soak.sh` | R08 | Auto |
| PKI-06 | Invalid generation refused | `RotationTest.InvalidGenerationIsRefusedAndServiceContinues`, `TlsTest.ServiceRefusesToStartWithInvalidPki` | — | Auto |
| PKI-07 | Rotation guard | `PkiTest.CheckCandidateAppliesRootGuard`, `RotationTest.GuardRefusesRootChangeWithoutPreTrust`, `RotationTest.GuardRefusesIdentityFromUnknownRootEvenWithoutMtls` | — | Auto |
| PKI-08 | Three-step root change | `RotationTest.ThreeStepRootChangeKeepsServiceAvailable`, `CaTest.RootTransitionFilesDriveTheThreeSteps` | R09 | Auto |
| PKI-09 | Watch, SIGHUP, reload | `RotationTest.SighupTriggersReload`, `RotationTest.WatchDisabledWaitsForExplicitReload`, `AdminTest.ReloadReportsWhatChanged` | — | Auto |
| PKI-10 | Instance PKI commands | `CaTest.InstallRejectsCertificateForAnotherKey`, `CaTest.RenewalRotatesKeyAndKeepsTrustFiles`, `CaTest.GenCsrCreatesNextGenerationWithPrivateKey`, `pki.sh`, `windows-pki.ps1` | R01 | Auto |
| CA-01 | `ca init`, encrypted keys, permissions | `CaTest.InitCreatesHierarchyWithEncryptedKeys`, `windows-pki.ps1` (ACL) | — | Auto |
| CA-02 | Signing policy | `CaTest.SignAppliesCaPolicyAndIgnoresRequestedExtensions`, `CaTest.SignRefusesNonConformingRequests`, `SubjectAltNames.ParsesTypedAndBareValues`, `fuzz_csr` | — | Auto |
| CA-03 | Subject assigned once | `CaTest.SubjectIsAttributedOnceUnlessRenewed` | R01 | Auto |
| CA-04 | Inventory | `CaTest.IndexWithoutRevocationColumnsIsStillRead`, `CaTest.DescribeAuthoritySummarizesCertificatesAndCrl` | E06 | Auto |
| CA-05 | Revocation and CRL publication | `CaTest.RevocationIsPublishedInSignedCrls`, `pki.sh` | E08 | Auto |
| CA-06 | Hash-chained audit log | `CaTest.AuditLogRecordsOperationsAndDetectsTampering`, `pki.sh`, `windows-pki.ps1` | E10 | Auto |
| CA-07 | Root-change preparation | `CaTest.RootTransitionFilesDriveTheThreeSteps` | R09 | Auto |
| CRL-01 | Revoked certificate refused at the handshake | `CrlTest.ServerRefusesRevokedClientCertificate`, `CrlTest.ClientRefusesRevokedServerCertificate`, `CrlTest.CrlOfOtherCertificatesChangesNothing`, `CaTest.PublishedCrlIsAcceptedByInstancesOfBothRoles` | E08 | Auto |
| CRL-02 | Hot CRL reload, channels closed | `CrlTest.PublishedCrlClosesActiveChannelAndRefusesNewOnes`, `CrlTest.NextRenegotiationKeepsActiveChannel` | — | Auto |
| CRL-03 | Invalid, stale CRL; own certificate revoked | `CrlTest.InvalidCrlIsRefusedAtStartupAndKeptAsIsOnReload`, `CrlTest.ExpiredCrlIsStillAppliedWithWarning`, `CrlTest.RevokedInstanceCertificateIsReported` | — | Auto |
| CRL-04 | `pki crl`, status and metrics | `pki.sh`, `CaTest.PublishedCrlIsAcceptedByInstancesOfBothRoles` | E08 | Auto |
| CFG-01 | YAML, all errors with path, unknown keys | `Config.*` (8 tests), `fuzz_config` | — | Auto |
| CFG-02 | Shared validation rules | `Validate.*` (8 tests), Qt `validation_matches_service` | E02 | Auto |
| CFG-03 | Value formats | `ParseDuration.*`, `ParseSize.*`, `ParsePercent.*`, `ParseEndpoint.*`, `Endpoint.ToStringBracketsIpv6`, `IpLiteral.RecognisesAddresses`, `IpRange.MatchesAddresses` | — | Auto |
| CFG-04 | Normalised writing, round trip | `ConfigWriter.*`, `WhitelistWriter.*`, `Units.FormatSizeAndPercentRoundTrip`, `FormatDuration.UsesLargestExactUnit`, Qt `form_round_trips_examples`, `new_document_is_saved_normalized` | — | Auto |
| LOG-01 | Levels, categories, formats, outputs | `Logging.*`, `JsonFormatter.WritesOneObjectPerLine`, `JsonEscape.EscapesSpecialCharacters`, `Validate.InstanceNameAndLogOutput` | M05 | Auto + manual |
| LOG-02 | Runtime level, log reopen | `AdminTest.LogLevelChangesAtRuntime`, `AdminTest.LogReopenStartsNewFileAfterRotation` (Linux) | R10, M06 (Windows) | Auto + manual |
| LOG-03 | No secrets or relayed data; escaping | `AttackTest.TraceLogsContainNoSecretsNorRelayedData`, `AttackTest.PeerMessageCannotInjectLogLines`, `Frame.StatusMessageControlCharactersAreEscaped` | R10 | Auto |
| ADM-01 | systemd and Windows services, boot start | `systemd.sh`, `windows-service.ps1` | R02, M01, M09 | Auto + manual |
| ADM-02 | Graceful / immediate stop, restart | `Relay.GracefulStop*`, `Relay.AbortClosesChannelsImmediately`, `Relay.Signal*`, `Relay.SecondSignalForcesImmediateStop`, `AdminTest.StopDrainsThenStops`, `AdminTest.KillStopsImmediately`, `console.sh`, `systemd.sh`, `windows-service.ps1` | R12, M02, M03 | Auto + manual |
| ADM-03 | Restricted local admin channel, commands logged | `AdminTest.SocketIsRestrictedToOwnerAndGroup` (Linux), `AdminTest.UnknownOrMalformedCommandsAreRefused`, `AdminProtocol.ParsesRequestWords`, `systemd.sh` (non-authorised user), `fuzz_admin` | M04 (Windows) | Auto + manual |
| ADM-04 | Instance lock | `AdminTest.SecondExecutionOfSameInstanceIsRefused`, `console.sh` | — | Auto |
| ADM-05 | `status`, `channels`, `reload`, `check-config` | `AdminTest.StatusDescribesInstance`, `…ChannelsListsOpenChannels`, `…ReloadReportsWhatChanged`, `…UnreachableInstanceIsReported`, `console.sh` | R11 | Auto |
| ADM-06 | Configuration reload | `AdminTest.ReloadReportsWhatChanged` | — | Auto |
| ADM-07 | Least-privilege service accounts | `systemd.sh`, `windows-service.ps1` | M07 | Auto + manual |
| ADM-08 | Prometheus metrics | `AdminTest.MetricsUsePrometheusTextFormat` | R11 | Auto |
| SEC-01 | Hardened executables | `check-hardening.sh`, `check-hardening.ps1` | — | Auto |
| SEC-02 | No memory error or race; clean static analysis | ASan+UBSan, TSan, 6 fuzz targets, clang-tidy, cppcheck, MSVC `/analyze` | 24 h fuzzing, Application Verifier (before production) | Auto + manual |
| SEC-03 | Resistance to attacks | `AttackTest.*` (12 tests), negative TLS/mTLS tests | PENTEST.md penetration test | Auto + manual |
| SEC-04 | No known-vulnerable dependency | `check-deps.sh` | — | Auto |
| PERF-01 | 5,000 concurrent channels | `perf.sh` with 1,000 channels in CI | 5,000 measured on the performance machine | Partial (manual) |
| PERF-02 | 100 Mbit/s per channel | `perf.sh` | R04 | Auto |
| PERF-03 | Added latency < 1 ms | `perf.sh` | R04 | Auto |
| PERF-04 | 72 h endurance | `soak.sh` for 4 minutes | 72 h run before production | Partial (manual) |
| PKG-01 | `.deb`, `.rpm`, `.msi` lifecycle | Package jobs, installs on 5 distributions, MSI install/uninstall | In-place upgrade (before production) | Auto + manual |
| PKG-02 | Licences and notices shipped | `test-linux-package.sh`, Windows MSI checks | E01 | Auto |
| PKG-03 | SHA-256 hashes of the delivery | `tlsrelay-livraison` artifact | M08 | Auto |
| EDT-01 | Editing with service validation, fields marked | Qt `validation_matches_service`, `invalid_fields_are_marked`, `fields_without_object_are_hidden_unless_filled`, `whitelist_editor_round_trip_and_marks`, `form_round_trips_examples`, `Admin.CheckInvalid` | E02 | Auto |
| EDT-02 | Save pipeline: refusal, diff, `.bak`, atomic | Qt `open_edit_save_with_preview_and_backup`, `save_refused_while_invalid`, `new_document_is_saved_normalized`, `diff_preview_lists_changes`, `TextDiff.*` | E03, E04 | Auto |
| EDT-03 | Deployment package export | Qt `export_package_for_linux_and_windows` | E05 | Auto |
| EDT-04 | PKI module | Qt `pki_panel_full_cycle`, `pki_panel_refuses_wrong_passphrase_and_bad_directory`, `sign_dialog_inspects_request`, `CaTest.DescribeAuthoritySummarizesCertificatesAndCrl` | E06–E09 | Auto |
| EDT-05 | Root-change wizard | Qt `pki_root_change_preparation` | E10 | Auto |
| EDT-06 | Shipped in the MSI, `--check` | `Admin.CheckValid`, `Admin.CheckInvalid`, Windows "Éditeur installé" step | E01 | Auto |

---

## 5. Coverage summary, gaps and deviations

### 5.1 Summary

| Group | Requirements | Auto | Auto + manual | Partial (manual) |
|---|---|---|---|---|
| General and platforms (GEN) | 5 | 4 | 1 | 0 |
| TLS | 8 | 8 | 0 | 0 |
| Tunnel protocol (TUN) | 14 | 14 | 0 | 0 |
| Channels and timers (CAN) | 5 | 5 | 0 | 0 |
| Whitelist (WL) | 6 | 6 | 0 | 0 |
| Instance PKI | 10 | 10 | 0 | 0 |
| Mini-CA (CA) | 7 | 7 | 0 | 0 |
| Revocation (CRL) | 4 | 4 | 0 | 0 |
| Configuration (CFG) | 4 | 4 | 0 | 0 |
| Logging (LOG) | 3 | 1 | 2 | 0 |
| Lifecycle and administration (ADM) | 8 | 4 | 4 | 0 |
| Security (SEC) | 4 | 2 | 2 | 0 |
| Performance (PERF) | 4 | 2 | 0 | 2 |
| Delivery (PKG) | 3 | 2 | 1 | 0 |
| Editor (EDT) | 6 | 6 | 0 | 0 |
| **Total** | **91** | **79** | **10** | **2** |

All 91 requirements have at least one automated verification on every push. Every test listed in section 3 verifies at least one requirement.

### 5.2 Manual verifications still required before production

| Item | Requirement | Reason it is not in CI |
|---|---|---|
| 72 h endurance (`soak.sh build 4320`) | PERF-04 | Duration |
| 5,000 concurrent channels (`perf.sh build 5000`) | PERF-01 | CI runner resources (measured on the performance machine) |
| 24 h cumulated fuzzing | SEC-02 | Duration |
| Application Verifier on Windows | SEC-02 | Interactive tool |
| Internal penetration test (PENTEST.md) | SEC-03 | Human assessment |
| Boot start, station shutdown, standard-user refusal, file ACLs, log rotation on Windows | ADM-01, ADM-02, ADM-03, ADM-07, LOG-02 | Need a reboot, a second user or a human check (M01–M07) |
| In-place package upgrade (`.deb`, `.rpm`, `.msi` over the previous version) | PKG-01 | Needs a previous released package; the maintainer scripts and the MSI upgrade code support it |
| Acceptance between two physical machines (NAT, firewall, MTU) | GEN-01 | One-station acceptance only covers loopback and a Hyper-V VM |

### 5.3 Platform-specific gaps in the automated tests

| Test | Linux | Windows | Compensation on Windows |
|---|---|---|---|
| `AdminTest.SocketIsRestrictedToOwnerAndGroup` | Yes | No (Unix socket) | Named-pipe ACL: M04 |
| `AdminTest.LogReopenStartsNewFileAfterRotation` | Yes | No (open files cannot be renamed) | M06 |
| `RotationTest.SighupTriggersReload` | Yes | No (no SIGHUP) | `reload` command, covered on both OSes |
| `Lifecycle.Console`, `Lifecycle.Pki` (bash) | Yes | No | `windows-service.ps1`, `windows-pki.ps1` |
| `tls-scan.sh`, sanitizers, fuzzing, clang-tidy, cppcheck | Yes | No | MSVC `/analyze`; same code base |

### 5.4 Deviations from the original strategy (PLAN §5)

| PLAN §5 item | What was implemented | Impact |
|---|---|---|
| Nightly pipeline (cross tests, 1 h fuzzing, network disturbances) | Everything runs on every push instead: 19 jobs, fuzzing 60 s per target, disturbances through the project's own cut proxy | Faster feedback; longer fuzzing moved to the pre-production checklist |
| toxiproxy, `tc netem` for network disturbances | Own cutting/freezing proxy (`tests/support/cut_proxy.hpp`, `tlsrelay-testkit proxy`) | Same scenarios (cut, silent link) on both OSes without extra dependencies; latency and loss injection not exercised |
| Line coverage ≥ 85 % of the core library, 100 % of branches of the frame decoder, whitelist and validation | Measured on every push since 2026-10-14 (section 6): core library 93.0 % of lines (met); parser branches 84–88 % (not met) | Tests CT-11 and CT-13 (section 6.4) close the parser branch gaps; project target raised to 90 % of lines of all delivered code |
| Injectable clock for timer unit tests | Timers configured to milliseconds in integration tests | Tests are real-time but short; timing margins tuned for slow CI runners |
| Windows ↔ Linux cross tests in CI | Linux and Windows tested separately; cross tests in acceptance (R13) | Wire compatibility relies on one protocol implementation built for both OSes |
| OpenSSL 3.0 and 3.5 on both OSes | Linux: 3.0 and 3.5; Windows: 3.5 (the shipped version) | Matches what is delivered |

---

## 6. Code coverage

### 6.1 Method

| Item | Value |
|---|---|
| Tool | GCC 13 instrumentation (`--coverage`, `-O0`, `-fprofile-update=atomic`) and gcovr 8.6 |
| Build | `-DTLSRELAY_COVERAGE=ON`, Debug, editor included (`TLSRELAY_BUILD_ADMIN=ON`) |
| Tests executed | All 196 ctest entries on Linux: GoogleTest, Qt Test, `Admin.Check*`, `Lifecycle.Console`, `Lifecycle.Pki` |
| Code measured | Delivered code: `src/core` (library), `src/app` (`tlsrelay` command line), `src/admin` (editor). Excluded: Qt-generated files (`*_autogen`), tests, third-party code. `src/testkit` (test tool) is reported separately: ctest does not run it; the performance, soak and acceptance scripts do |
| Platform | Linux only. Windows-only files (`platform_windows.cpp`, named-pipe admin channel, Windows service glue) are not compiled there and are not in the figures; they are exercised by `windows-service.ps1`, `windows-pki.ps1` and the acceptance run on the installed MSI |
| Branches | Counted by gcov with unreachable and exception-only branches excluded (`--exclude-unreachable-branches --exclude-throw-branches`) |
| Command | `tools/coverage.sh [build dir] [minimum line %]` → `<build>/coverage/index.html`, `summary.txt`, `summary.json` |
| CI | Job "Couverture de code (gcovr)" on every push; HTML report uploaded as the `couverture` artifact; fails if line coverage drops below the regression floor (83 %) |
| Target | **90 % of lines** of the delivered code (this document); branch figures are reported for information |

Figures vary by about ±0.1 % between runs, because a few lines run only on timing-dependent paths (retries, races between close and timeout).

### 6.2 Results (main branch, measured on 2026-10-14)

| Component | Lines | Functions | Branches |
|---|---|---|---|
| `src/core` — service library | **93.0 %** (3,511 / 3,774) | 98.8 % (489 / 495) | 79.1 % |
| `src/app` — `tlsrelay` command line | **61.3 %** (457 / 745) | 58.8 % (30 / 51) | 53.4 % |
| `src/admin` — editor | **74.8 %** (1,187 / 1,586) | 69.8 % (120 / 172) | 59.7 % |
| **Delivered code (total)** | **84.4 %** (5,155 / 6,105) | **89.0 %** (639 / 718) | **69.6 %** |
| `src/testkit` (not run by ctest) | 0 % (0 / 367) | 0 % | 0 % |

**Verdict: below the 90 % target.** The service library is above the target; the shortfall is in the command line (`src/app`) and the editor (`src/admin`), in code that only runs with a terminal, a service manager or a modal dialog. 340 more lines must be covered to reach 90 % (5,495 / 6,105).

Files of the delivered code below 90 % of lines:

| File | Lines | Covered | Uncovered code |
|---|---|---|---|
| `src/admin/export_dialog.cpp` | 62 | 0 % | Whole export dialog (tests call `export_package()` directly) |
| `src/app/platform_linux.cpp` | 95 | 5 % | systemd unit generation, `service install/uninstall/start`, `useradd`, `systemctl` calls |
| `src/core/src/system/notify.cpp` | 14 | 21 % | `sd_notify` datagram (only under systemd, `NOTIFY_SOCKET` set) |
| `src/app/passphrase.cpp` | 44 | 36 % | Interactive passphrase prompt (terminal without echo, confirmation, mismatch) |
| `src/admin/pki_panel.cpp` | 416 | 53 % | Revocation, CRL and root-change dialogs, file pickers, passphrase confirmation, "new CA" flow |
| `src/admin/diff_dialog.cpp` | 50 | 58 % | Dialog construction (tests inject `confirm_save`); skipped unchanged file |
| `src/admin/main.cpp` | 38 | 68 % | `--check` with unreadable file or with a whitelist; GUI start |
| `src/app/main.cpp` | 606 | 71 % | Error exits of the `pki`, `ca`, `check-config` commands; `start`, `stop`, `restart`, `service install/uninstall` paths; `--instance` mismatch; invalid timeouts and instance names; `version` |
| `src/admin/main_window.cpp` | 277 | 74 % | Close with unsaved changes, issue list navigation, export dialog, open/save pickers, About box, read and save errors |
| `src/core/src/admin/posix.cpp` | 114 | 76 % | Admin channel errors: path too long, unwritable directory, lock file error, listen failure, send failure, truncated reply |
| `src/core/src/admin/session.hpp` | 35 | 77 % | Invalid reply header or size |
| `src/core/include/tlsrelay/config.hpp` | 65 | 83 % | Default member values of `Limits` and `AdminConfig` never default-constructed in tests |
| `src/core/src/tunnel/frame.cpp` | 205 | 87 % | `to_string()` of most frame types and close codes; decoder buffer compaction above 64 KiB |
| `src/admin/sign_dialog.cpp` | 114 | 89 % | Unreadable request file, request with extensions, file pickers |

Branch coverage of the parsers that PLAN §5.2 asked to cover at 100 %:

| File | Branches | Main uncovered branches |
|---|---|---|
| `src/core/src/tunnel/frame.cpp` (decoder) | 85 % (139 / 163) | Size checks per frame type not all exercised (`OPEN_OK` with payload, `ACK`/`PING` wrong sizes), `OPEN` port kind above 3, compaction |
| `src/core/src/whitelist.cpp` | 88 % (425 / 480) | Root not a map, unknown top-level key, `peers` not a list, entry not a map, non-scalar values |
| `src/core/src/config.cpp` (loader and validation) | 84 % (551 / 649) | Destination without address or port above 65535, invalid `revoke_mode`, `admin.endpoint` empty, `resume_buffer` < 64 KiB, `keepalive_interval` < 1 s, `max_channels` bounds, negative `shutdown_timeout`, empty `logging.output` |
| `src/core/src/units.cpp` | 88 % (90 / 102) | Size and percent overflow, unit edge cases |

### 6.3 Why the gaps exist

1. **Interactive code**: modal dialogs (`QDialog::exec()`, file pickers, message boxes) and the terminal prompt block a test; the existing tests inject hooks (`confirm_save`, `ask_passphrase`, `report`, `inform`) and call the underlying functions instead, so the dialog code itself is never run.
2. **Service-manager code**: `service install/start/stop` and `sd_notify` need root and a running systemd. `systemd.sh` covers them functionally in CI, but in the GCC Release job, not in an instrumented build.
3. **Error exits of the command line**: the lifecycle scripts test the main success paths and a few refusals; most "cannot read", "refused", "invalid value" exits of `src/app/main.cpp` have no test.
4. **Defensive error paths of the admin channel**: failures of `mkdir`, `open`, `bind`, `send` are hard to provoke on a healthy system.

### 6.4 New tests specified

Each test below is specified with its target, steps and expected result. "Gain" is the estimated number of currently uncovered lines it covers. Implementing CT-01 to CT-14 raises the delivered code to about **95 % of lines** (estimate: +650 lines); CT-01 to CT-08 alone exceed 90 %.

**Editor (Qt Test, `tests/admin/test_admin.cpp`).** Modal dialogs are driven with `QTimer::singleShot(0, …)`: the callback finds `QApplication::activeModalWidget()`, fills its widgets by type or object name, then clicks the OK or Cancel button of its `QDialogButtonBox`. File pickers and message boxes are replaced by injectable hooks (same pattern as `ask_passphrase`), defaulting to the Qt dialogs.

| Id | Test | Target | Steps | Expected result | Gain | Req. |
|---|---|---|---|---|---|---|
| CT-01 | `export_dialog_builds_request_and_warns` | `export_dialog.cpp`, `main_window.cpp` (`choose_and_export`) | Valid document; open the export dialog; set output directory, Windows target, a kit without `chain.pem`, a CRL file; read the warnings label and `request()`; press Export; then repeat with Cancel and with an empty output directory | `request()` holds the four values; warnings list the incomplete kit and the relative Linux paths; Export creates the package and reports it; Cancel and empty directory create nothing | ≈ 80 | EDT-03 |
| CT-02 | `diff_dialog_is_shown_and_controls_saving` | `diff_dialog.cpp`, `main_window.cpp` | Restore the default `confirm_save` hook; modify a field; save; accept the dialog; then modify again and reject it; then save a second document where the whitelist is unchanged | Accept writes files and `.bak`; reject writes nothing; the dialog shows only the changed file (unchanged file skipped) | ≈ 30 | EDT-02 |
| CT-03 | `revoke_and_crl_dialogs` | `pki_panel.cpp` (`revoke_dialog`, `crl_dialog`, `add_crl_fields`, `optional_path`) | Open a test CA with two issued certificates; select one; open "Revoke", choose `keyCompromise`, 7 days, a copy path; confirm; open "Publish CRLs", 10 days, no copy; confirm; open Revoke and cancel | Certificate shown as revoked with reason; CRL copy written and verifiable with `openssl crl`; CRL number incremented; next update in 10 days; cancel changes nothing; `inform` called with serial and CRL number | ≈ 60 | EDT-04, CA-05 |
| CT-04 | `root_change_dialog_creates_ca_and_prepares_files` | `pki_panel.cpp` (`root_change_dialog`) | Open a CA; open the wizard; "Create the new CA" with a passphrase given twice; set the output directory; press Prepare; press Prepare again with an empty field; close | New CA directory created with the old organisation; step files and `LISEZMOI.txt` produced and shown; empty field does nothing; mismatching passphrase confirmation creates nothing and reports "Les deux saisies diffèrent" | ≈ 70 | EDT-05, CA-07 |
| CT-05 | `sign_and_create_dialogs` | `pki_panel.cpp` (`sign_dialog`, `choose_and_create`, `ask_passphrase` default), `sign_dialog.cpp` | Create a CA through the "New CA" flow (directory hook, organisation input); sign through the dialog a CSR with requested extensions, then an unreadable CSR path; renew the selected certificate through the dialog | CA created and summary shown; issued-certificate message with serial and kit path; extensions listed as ignored; unreadable file reported in the dialog; renewal pre-fills subject and role | ≈ 60 | EDT-04, CA-02 |
| CT-06 | `main_window_navigation_and_close` | `main_window.cpp` | Load a file with errors in configuration and whitelist; activate each issue row; load a file with an unknown key; close with unsaved changes and answer Cancel, Discard, then Save; open the About box; save to a read-only directory; open a missing file | Issue rows focus the right tab, field or table row; unknown keys listed in load notes; close is refused on Cancel, accepted on Discard, saves on Save; About shows the tlsrelay, OpenSSL and Qt versions; read and write errors are reported | ≈ 55 | EDT-01, EDT-02 |
| CT-07 | `Admin.CheckWhitelistAndUnreadable` (ctest) | `src/admin/main.cpp` | `tlsrelay-admin --check` on a server configuration whose whitelist has an error; on a missing file | Exit 1 with the whitelist error path; exit 2 with "fichier illisible" | ≈ 10 | EDT-06 |

**Command line (`tests/lifecycle/cli.sh`, new ctest `Lifecycle.Cli`, Linux).** Runs the real binary and checks exit codes (0 success, 1 runtime error, 2 configuration error) and messages.

| Id | Test | Target | Steps | Expected result | Gain | Req. |
|---|---|---|---|---|---|---|
| CT-08 | `cli.sh` — configuration and PKI refusals | `src/app/main.cpp` | `check-config` on a valid and an invalid file; `check-pki` on a configuration without TLS port; `pki activate` of a generation refused by the guard (without and with `--force`); `pki install` refused by the checks; `pki gen-csr` for a TLS client; `pki crl` with an invalid file, a wrong-CA file and on an instance that does not verify its peer; `ca revoke` with an unknown reason; `ca root-change` with a missing directory and then successfully; `ca sign` with an unreadable CSR; `run --instance other` with a mismatching configuration; `stop --timeout abc`; `start`/`restart`/`service uninstall` with an invalid instance name and for a non-installed instance; `version` | Each command prints its documented message and exits with the documented code; `ca root-change` produces `serveur/`, `client/` and `LISEZMOI.txt` | ≈ 130 | ADM-05, PKI-10, CRL-04, CA-07 |
| CT-09 | `cli.sh` — passphrase prompt | `src/app/passphrase.cpp` | `ca init` without `--passphrase-file` and without `TLSRELAY_CA_PASSPHRASE`, passphrase given on stdin twice (pipe), then two different entries, then end of input; `--passphrase-file` on a missing file; run once under `script -qec` to get a pseudo-terminal | Pipe: CA created; mismatch: "les deux saisies diffèrent", nothing created; end of input and missing file: refused; with a terminal, the prompt does not echo the passphrase | ≈ 25 | CA-01 |

**Service manager (instrumented `systemd.sh`, coverage job, root).**

| Id | Test | Target | Steps | Expected result | Gain | Req. |
|---|---|---|---|---|---|---|
| CT-10 | Run `tests/lifecycle/systemd.sh` in the coverage job | `platform_linux.cpp`, `notify.cpp`, `main.cpp` (`cmd_install`, `cmd_start`, `cmd_stop`, restart) | In the "Couverture de code" job, after ctest, run `sudo tests/lifecycle/systemd.sh build/coverage/src/app/tlsrelay`; add `service install` with a configuration declaring another instance and with `admin.endpoint`, `start` of a running instance, `stop` of a stopped instance, `kill` when the channel does not answer | Same checks as today's `systemd.sh`; the command-line processes (root) write their counters, so the service code is measured; the refusals print their messages | ≈ 140 | ADM-01, ADM-02, ADM-07 |

**Library unit tests (GoogleTest).**

| Id | Test | Target | Steps | Expected result | Gain | Req. |
|---|---|---|---|---|---|---|
| CT-11 | `Frame.NamesOfEveryTypeAndCode`, `Frame.RejectsWrongSizeForEachType`, `Frame.DecoderCompactsLargeBuffers` | `frame.cpp` | `to_string()` of every `FrameType` and `CloseCode` and of an unknown value; for each type, a header with an invalid size; `OPEN` with port kind 0 and 4; feed > 64 KiB of frames in small chunks, consuming as they arrive | Names as in SPEC §4.2 and §4.6, `?` for unknown; each invalid size → `PROTOCOL_ERROR`; frames decoded identically across compaction | ≈ 25 lines, decoder branches to ≈ 100 % | TUN-01 |
| CT-12 | `AdminChannel.ReportsEndpointErrors`, `AdminChannel.RejectsInvalidReplies` | `posix.cpp`, `session.hpp` | Listen on a path longer than `sun_path`; on a path under a read-only directory; on a path whose `.lock` is a directory; call a socket served by a fake server that answers `XYZ`, `OK abc`, `OK 10` followed by 3 bytes, or closes at once | Each failure gives a clear `runtime_error` or `CallResult.error` ("chemin trop long", "impossible de créer", "impossible d'ouvrir", "réponse invalide", "connexion fermée avant la fin de la réponse"); no crash, no hang | ≈ 30 | ADM-03 |
| CT-13 | `Validate.EveryLimitBound`, `Config.DestinationAndWhitelistSectionErrors`, `Whitelist.StructureErrors` | `config.cpp`, `whitelist.cpp`, `config.hpp` | One configuration per violated rule of SPEC §8.3 and §5.2 not yet tested (destination address missing, port > 65535, `revoke_mode` invalid, `admin.endpoint` empty, `resume_buffer` < 64 KiB, `keepalive_interval` 500 ms, `max_channels` 0 and 100001, `shutdown_timeout` negative, `logging.output` empty); whitelists whose root is a list, with an unknown top-level key, `peers` as a map, an entry as a scalar, `name` as a list; default-constructed `Config` compared with SPEC §5.2 defaults | Exactly one error per case, with the documented path; defaults equal SPEC §5.2 | ≈ 20 lines, parser branches ≈ +12 % | CFG-01, CFG-02, CAN-05, WL-01 |
| CT-14 | `ParseSize.RejectsOverflow`, `ParsePercent.Bounds` | `units.cpp` | Sizes beyond 2⁶⁴, `1.5MiB`, percent above 100 % and negative | Refused without wrapping | ≈ 5 lines, branches | CFG-03 |

### 6.5 Plan

| Step | Content | Line coverage expected |
|---|---|---|
| Now | Coverage measured on every push; floor 83 % | 84.4 % |
| 1 | CT-01 to CT-08 (editor dialogs, `--check`, command-line refusals) | ≈ 91 % |
| 2 | CT-09 to CT-14 (prompt, systemd in the coverage job, frame, admin channel, validation, units) | ≈ 95 % |
| After each step | Raise the CI floor to the measured value minus 1 point; once above 90 %, set it to 90 % | — |

Coverage of the testkit (`src/testkit`) is not a target: it is a test tool, validated by the acceptance and performance runs that use it.
