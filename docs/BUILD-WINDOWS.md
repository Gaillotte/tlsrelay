# tlsrelay — Building and testing on Windows

> Complete guide for developers: install the tools, get the sources, compile the relay, the test tool and the editor, run every test that exists on Windows, build and test the MSI package.
> Audience: a developer starting from a clean Windows 10/11 machine. For installing the delivered MSI on a target machine, see [INSTALLATION.md](INSTALLATION.md); for operating instances, [EXPLOITATION.md](EXPLOITATION.md).
> Everything below is what the Windows CI jobs do (`.github/workflows/ci.yml`, jobs "Windows MSVC Release" and "Windows MSVC /analyze"); the same versions are used.

## Contents

1. [What you will build](#1-what-you-will-build)
2. [Machine and tools](#2-machine-and-tools)
3. [Getting the sources](#3-getting-the-sources)
4. [Compiling](#4-compiling)
5. [Testing](#5-testing)
6. [Building and testing the MSI package](#6-building-and-testing-the-msi-package)
7. [Static analysis (MSVC /analyze)](#7-static-analysis-msvc-analyze)
8. [Working in Visual Studio](#8-working-in-visual-studio)
9. [What runs on Linux only](#9-what-runs-on-linux-only)
10. [Troubleshooting](#10-troubleshooting)
11. [Command summary](#11-command-summary)

---

## 1. What you will build

| Output | Location after a Release build | Needs |
|---|---|---|
| `tlsrelay.exe` — the relay (service, command line, mini-CA) | `build\windows-msvc\src\app\Release\` | Visual Studio, vcpkg |
| `tlsrelay-testkit.exe` — traffic generators, echo destination, disturbance proxy | `build\windows-msvc\src\testkit\Release\` | same |
| `tlsrelay_tests.exe` — GoogleTest suites (unit and integration) | `build\windows-msvc\tests\Release\` | same |
| `tlsrelay-admin.exe` — graphical editor (optional) | `build\windows-msvc\src\admin\Release\` | Qt 6.8 LTS |
| `tlsrelay_admin_tests.exe` — editor tests (Qt Test, optional) | `build\windows-msvc\src\admin\Release\` | Qt 6.8 LTS |
| `tlsrelay-<version>-win64.msi` — installer | `build\windows-msvc\` | WiX Toolset v3 |

Third-party libraries (OpenSSL 3.5 LTS, Asio, CLI11, spdlog, yaml-cpp, GoogleTest) are **not** installed by hand: vcpkg builds them from `vcpkg.json` during the first CMake configuration. OpenSSL comes from the overlay port in `vcpkg-overlays/openssl` (official 3.5.x release archive, SHA-512 checked; see [vcpkg-overlays/README.md](../vcpkg-overlays/README.md)).

Expect about 20–40 minutes for the first configuration (vcpkg compiles OpenSSL and the other libraries) and a few minutes for later builds. Plan for about 15 GB of disk (Visual Studio, Qt, vcpkg build trees).

## 2. Machine and tools

### 2.1 Machine

- Windows 10 or 11 (x64), or Windows Server 2019 or later.
- An account with administrator rights for installing the tools, and for the service and MSI tests (sections 5.4 and 6).
- Internet access (tool installers, vcpkg sources, Qt).

### 2.2 Tools

All commands are given for `winget` (Windows Package Manager, included in Windows 10 1809+ and 11). Each tool can also be installed with its regular installer from its website.

| Tool | Version | Required for | Install |
|---|---|---|---|
| Visual Studio 2022 with "Desktop development with C++" | 17.x, MSVC v143, Windows 10/11 SDK | everything | see 2.3 |
| Git for Windows | any recent | sources, vcpkg | `winget install --id Git.Git -e` |
| CMake | 3.25 or later | everything | included in Visual Studio (2.3); or `winget install --id Kitware.CMake -e` |
| vcpkg | current | everything | see 2.4 |
| PowerShell 7 | 7.4 or later | test and acceptance scripts | `winget install --id Microsoft.PowerShell -e` |
| Python 3 | 3.10 or later | Qt installation (aqtinstall), service lifecycle test | `winget install --id Python.Python.3.12 -e` |
| Qt | 6.8 LTS (6.8.3), `msvc2022_64` | editor only | see 2.5 |
| WiX Toolset | v3 (3.14) | MSI package only | see 2.6 |

After installing tools, **open a new terminal** so that `PATH` changes are visible.

### 2.3 Visual Studio 2022

Community edition (free for individuals and open-source work), Professional or Enterprise all work. Install with the C++ desktop workload and its recommended components, which include the MSVC v143 compiler, the Windows SDK and the CMake tools:

```powershell
winget install --id Microsoft.VisualStudio.2022.Community -e --override "--add Microsoft.VisualStudio.Workload.NativeDesktop --includeRecommended --passive --wait"
```

Without the IDE, the Build Tools are enough:

```powershell
winget install --id Microsoft.VisualStudio.2022.BuildTools -e --override "--add Microsoft.VisualStudio.Workload.VCTools --includeRecommended --passive --wait"
```

To add the workload to an existing installation: Visual Studio Installer → Modify → "Desktop development with C++".

All build commands below are run in a **Developer PowerShell for VS 2022** (Start menu), which puts `cl.exe`, `cmake` and `ctest` on `PATH`. In a plain PowerShell, load it with:

```powershell
& "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\Launch-VsDevShell.ps1" -Arch amd64 -HostArch amd64
```

(Replace `Community` by `Professional`, `Enterprise` or `BuildTools` as installed.)

Check:

```powershell
cl          # Microsoft (R) C/C++ Optimizing Compiler Version 19.4x for x64
cmake --version   # 3.25 or later
```

### 2.4 vcpkg

vcpkg is used in manifest mode: the project's `vcpkg.json` lists the libraries, and the CMake preset loads the vcpkg toolchain from the `VCPKG_ROOT` environment variable. Install vcpkg in a short path:

```powershell
git clone https://github.com/microsoft/vcpkg C:\vcpkg
C:\vcpkg\bootstrap-vcpkg.bat -disableMetrics
[Environment]::SetEnvironmentVariable('VCPKG_ROOT', 'C:\vcpkg', 'User')
$env:VCPKG_ROOT = 'C:\vcpkg'
```

Optional but recommended: a binary cache, so that the libraries are compiled once and reused by every build directory:

```powershell
New-Item -ItemType Directory -Force C:\vcpkg-cache | Out-Null
[Environment]::SetEnvironmentVariable('VCPKG_DEFAULT_BINARY_CACHE', 'C:\vcpkg-cache', 'User')
$env:VCPKG_DEFAULT_BINARY_CACHE = 'C:\vcpkg-cache'
```

vcpkg downloads by itself the extra tools the OpenSSL build needs (Perl, NASM); nothing else has to be installed for it.

Note: Visual Studio 2022 also ships a copy of vcpkg; the standalone clone above is preferred because its location and version are under your control and match the CI.

### 2.5 Qt 6.8 LTS (editor only)

The editor `tlsrelay-admin` needs Qt 6.8 LTS built for MSVC 2022 64-bit (`msvc2022_64`); Qt is linked dynamically (LGPLv3). Skip this section if you do not build the editor.

**Option A — aqtinstall (what the CI uses, no Qt account needed):**

```powershell
py -m pip install --upgrade aqtinstall
py -m aqt install-qt windows desktop 6.8.3 win64_msvc2022_64 -O C:\Qt
```

Qt is then in `C:\Qt\6.8.3\msvc2022_64`.

**Option B — Qt Online Installer:** download it from qt.io (a Qt account is required), choose Qt 6.8.3 (or a later 6.8.x) → "MSVC 2022 64-bit". The default location is `C:\Qt\6.8.3\msvc2022_64`.

Set a variable used in the rest of this guide:

```powershell
[Environment]::SetEnvironmentVariable('QT_ROOT_DIR', 'C:\Qt\6.8.3\msvc2022_64', 'User')
$env:QT_ROOT_DIR = 'C:\Qt\6.8.3\msvc2022_64'
```

### 2.6 WiX Toolset v3 (MSI package only)

CPack's WIX generator uses WiX Toolset v3 (`candle.exe`, `light.exe`):

```powershell
winget install --id WiXToolset.WiXToolset -e
```

The installer sets the `WIX` environment variable, which CPack uses to find the tools (`%WIX%bin`). If it reports a missing .NET Framework feature, enable it in "Turn Windows features on or off" and run it again. Check in a new terminal:

```powershell
& "$env:WIX\bin\candle.exe" -?   # Windows Installer XML Toolset Compiler version 3.14…
```

## 3. Getting the sources

Clone into a short path (Windows path-length limits affect deep build trees):

```powershell
git clone https://github.com/Gaillotte/tlsrelay.git C:\src\tlsrelay
cd C:\src\tlsrelay
```

Git's default line-ending conversion on Windows is fine; the CI checks out the sources the same way.

Layout: `src\core` (library), `src\app` (`tlsrelay`), `src\admin` (editor), `src\testkit`, `tests\` (GoogleTest suites, `tests\admin` Qt tests, `tests\lifecycle` scripts), `tools\` (acceptance kit, hardening check), `docs\`.

## 4. Compiling

All commands from the repository root, in a Developer PowerShell (2.3).

### 4.1 Relay, test tool and tests

```powershell
cmake --preset windows-msvc
cmake --build --preset windows-release
```

- `cmake --preset windows-msvc` configures `build\windows-msvc` with the Visual Studio 2022 generator, x64, the vcpkg toolchain and the `x64-windows` triplet. The first run installs the vcpkg libraries (section 1).
- `cmake --build --preset windows-release` compiles the Release configuration. The vcpkg DLLs (OpenSSL, spdlog, fmt, yaml-cpp, GoogleTest) are copied next to each executable.

Check the result:

```powershell
.\build\windows-msvc\src\app\Release\tlsrelay.exe version
# tlsrelay 0.1.0
# bibliothèque : OpenSSL 3.5.x …
```

The project's messages and logs are in French; the commands and options are the same as in the documentation.

### 4.2 With the editor

Add the editor and point CMake at Qt:

```powershell
cmake --preset windows-msvc -DTLSRELAY_BUILD_ADMIN=ON "-DCMAKE_PREFIX_PATH=$env:QT_ROOT_DIR"
cmake --build --preset windows-release
```

The CMake cache keeps these options: later configurations of the same build directory do not need them again.

To run the editor from the build tree, Qt's DLLs must be found: put Qt on `PATH` for the session (the MSI deploys them next to the executable instead, section 6):

```powershell
$env:PATH = "$env:QT_ROOT_DIR\bin;$env:PATH"
.\build\windows-msvc\src\admin\Release\tlsrelay-admin.exe examples\server.yaml
```

### 4.3 Build options

Passed to the configure command as `-D<option>=<value>`:

| Option | Default | Effect |
|---|---|---|
| `TLSRELAY_BUILD_TESTS` | `ON` | GoogleTest suites and ctest entries |
| `TLSRELAY_BUILD_ADMIN` | `OFF` | Editor `tlsrelay-admin` and its Qt tests (needs Qt, `CMAKE_PREFIX_PATH`) |
| `TLSRELAY_WARNINGS_AS_ERRORS` | `OFF` | `/WX`; the CI always sets it to `ON` — use it before pushing |
| `TLSRELAY_MSVC_ANALYZE` | `OFF` | MSVC code analysis (section 7) |

The compiler flags are set by the project (`cmake/CompilerOptions.cmake`): `/W4 /permissive- /utf-8 /sdl /guard:cf`, and at link time `/guard:cf /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA`.

### 4.4 Debug builds

The Visual Studio generator holds every configuration in the same directory:

```powershell
cmake --build build\windows-msvc --config Debug
ctest --test-dir build\windows-msvc -C Debug --output-on-failure
```

Debug outputs are in the `Debug\` subdirectories instead of `Release\`.

### 4.5 Rebuilding from scratch

```powershell
Remove-Item -Recurse -Force build\windows-msvc
cmake --preset windows-msvc   # with the binary cache (2.4), the libraries are not recompiled
```

## 5. Testing

### 5.1 Unit, integration and editor tests (ctest)

```powershell
$env:PATH = "$env:QT_ROOT_DIR\bin;$env:PATH"   # only if the editor is built (4.2)
ctest --preset windows-release -j 2
```

This runs, on Windows:

- 199 GoogleTest cases: configuration, whitelist, frames, TLS and mTLS chains, rotation, tunnel (renegotiation, resumption after cuts, back-pressure), CRL, mini-CA, administration channel (named pipe), attack cases. Five suites that need Unix sockets, `SIGHUP` or bash are Linux-only ([TESTS.md §5.3](TESTS.md#53-platform-specific-gaps-in-the-automated-tests)).
- With the editor: `Admin.QtTests` (the editor's Qt Test functions, run without a window on the offscreen platform) and the `tlsrelay-admin --check` entries `Admin.CheckValid`, `Admin.CheckInvalid`, `Admin.CheckWhitelist`, `Admin.CheckUnreadable`.

Everything runs on `127.0.0.1`–`127.0.0.x` with ports chosen by the system; no firewall rule is needed. It takes about a minute.

Useful variants:

```powershell
ctest --preset windows-release -R TunnelTest                  # one suite (regular expression on the test name)
ctest --preset windows-release --rerun-failed --output-on-failure
.\build\windows-msvc\tests\Release\tlsrelay_tests.exe --gtest_filter=CrlTest.*   # directly, with GoogleTest options
.\build\windows-msvc\tests\Release\tlsrelay_tests.exe --gtest_list_tests
```

Each test and the requirement it verifies are described in [TESTS.md §3](TESTS.md#3-test-inventory).

### 5.2 Hardening of the executables

Checks ASLR (high entropy), DEP and Control Flow Guard in the PE headers:

```powershell
.\tools\check-hardening.ps1 build\windows-msvc\src\app\Release\tlsrelay.exe build\windows-msvc\src\testkit\Release\tlsrelay-testkit.exe
```

### 5.3 PKI on the command line (mini-CA)

`ca init`, `pki gen-csr`, `ca sign`, `pki install`, `check-pki`, duplicate subject refused, ACL of the CA keys, revocation and audit log, with the real executable:

```powershell
.\tests\lifecycle\windows-pki.ps1 -BuildDir build\windows-msvc\src\app\Release
```

Its working directory is `%TEMP%\tlsrelay-pki`.

### 5.4 Windows service lifecycle (administrator)

Installs a real service `tlsrelay-ci` under its virtual account `NT SERVICE\tlsrelay-ci`, relays data through it (Python echo server and client, ports 18080 and 17001), then checks `reload`, `restart`, `stop`, stop by the service manager, `kill` and uninstallation. Run it in an **elevated** PowerShell 7 (Run as administrator), after loading the developer environment if needed:

```powershell
.\tests\lifecycle\windows-service.ps1 -BuildDir build\windows-msvc\src\app\Release
```

The service is uninstalled at the end, also on failure.

### 5.5 Automated acceptance scenarios (console mode)

The acceptance kit runs the business scenarios R01–R12 ([RECETTE.md](RECETTE.md)): PKI built by the mini-CA, concurrent channels on the three ports, throughput and latency, whitelist reload, network cuts, renegotiation, PKI rotation, three-step root change, logging, administration, lifecycle. In console mode the relays run as processes of your session:

```powershell
.\tools\recette.ps1 -BuildDir build\windows-msvc\src\app\Release -TestkitDir build\windows-msvc\src\testkit\Release -Quick
```

`-Quick` shortens the durations (about 3 minutes); without it, the full scenarios take about 10 minutes. The report is `recette-<date>\rapport.md` in the current directory. To run the scenarios against Windows services instead, install the MSI first (section 6).

### 5.6 The editor by hand

```powershell
$env:PATH = "$env:QT_ROOT_DIR\bin;$env:PATH"
.\build\windows-msvc\src\admin\Release\tlsrelay-admin.exe examples\server.yaml
.\build\windows-msvc\src\admin\Release\tlsrelay-admin.exe --check examples\server.yaml; $LASTEXITCODE   # 0 valid, 1 invalid, 2 unreadable
```

The editor's manual acceptance steps are E01–E10 in [RECETTE.md](RECETTE.md); its user guide is [EDITEUR.md](EDITEUR.md).

### 5.7 Before pushing

The CI fails on any compiler warning. Configure once with warnings as errors, then build and test:

```powershell
cmake --preset windows-msvc -DTLSRELAY_WARNINGS_AS_ERRORS=ON -DTLSRELAY_BUILD_ADMIN=ON "-DCMAKE_PREFIX_PATH=$env:QT_ROOT_DIR"
cmake --build --preset windows-release
ctest --preset windows-release -j 2
```

## 6. Building and testing the MSI package

### 6.1 Build

After a Release build (with the editor if it is to be in the package):

```powershell
cd build\windows-msvc
cpack -C Release -G WIX
Get-ChildItem *.msi | ForEach-Object { $_.Name; (Get-FileHash -Algorithm SHA256 $_).Hash }
cd ..\..
```

The package `tlsrelay-0.1.0-win64.msi` installs for the whole machine in `C:\Program Files\tlsrelay`:

| Feature | Content |
|---|---|
| tlsrelay (always) | `tlsrelay.exe`, OpenSSL 3.5 LTS, MSVC runtime, documentation, licences |
| tlsrelay-testkit (optional) | `tlsrelay-testkit.exe`, acceptance scripts |
| tlsrelay-admin (optional, if built) | `tlsrelay-admin.exe`, Qt DLLs and plugins (deployed by `windeployqt`), LGPL and GPL texts, Start menu shortcut for all users |

### 6.2 Install, test, uninstall (administrator)

```powershell
$msi = (Get-ChildItem build\windows-msvc\*.msi).FullName
Start-Process msiexec -ArgumentList "/i `"$msi`" /qn ADDLOCAL=ALL /l*v `"$env:TEMP\msi-install.log`"" -Wait
& "$env:ProgramFiles\tlsrelay\bin\tlsrelay.exe" version

# Editor deployed without Qt on PATH: open a new terminal (no QT_ROOT_DIR in PATH) and run
& "$env:ProgramFiles\tlsrelay\bin\tlsrelay-admin.exe" --check C:\src\tlsrelay\examples\client.yaml; $LASTEXITCODE

# Acceptance scenarios with the installed binaries running as Windows services
.\tools\recette.ps1 -BuildDir "$env:ProgramFiles\tlsrelay\bin" -Services -Quick -WorkDir "$env:ProgramData\tlsrelay\recette-dev"

Start-Process msiexec -ArgumentList "/x `"$msi`" /qn" -Wait   # uninstall
```

`-Services` installs the instances `rc-server` and `rc-client` as services under their virtual accounts with restricted file permissions, runs the scenarios and uninstalls them (add `-Keep` to leave them running for the manual steps of [RECETTE.md](RECETTE.md)). Installation options for target machines are in [INSTALLATION.md](INSTALLATION.md).

## 7. Static analysis (MSVC /analyze)

The CI also builds the relay and the test tool with MSVC code analysis, findings treated as errors. Use a separate build directory:

```powershell
cmake --preset windows-msvc -B build\windows-analyze -DTLSRELAY_BUILD_TESTS=OFF -DTLSRELAY_MSVC_ANALYZE=ON -DTLSRELAY_WARNINGS_AS_ERRORS=ON
cmake --build build\windows-analyze --config Release
```

Only the project's code is analysed; headers of the vcpkg libraries are treated as external.

## 8. Working in Visual Studio

- **Open Folder** (File → Open → Folder… on the repository root): Visual Studio reads `CMakePresets.json`; choose the configure preset "Windows x64 (MSVC + vcpkg)" and the build preset `windows-release` in the toolbar. Add `TLSRELAY_BUILD_ADMIN` and `CMAKE_PREFIX_PATH` in Project → CMake Settings, or configure once from the command line (4.2) — the cache is shared.
- **Solution**: after configuring, `build\windows-msvc\tlsrelay.sln` can be opened as a regular solution.
- **Test Explorer** lists the GoogleTest cases (Test → Test Explorer) once the tests are built.
- **Debugging the relay**: set `tlsrelay` as startup item with arguments such as `run -c C:\src\tlsrelay\examples\server.yaml -vv`; debugging the editor needs Qt's `bin` directory on the debugger's `PATH` (Debug → Properties → Environment: `PATH=C:\Qt\6.8.3\msvc2022_64\bin;%PATH%`).

## 9. What runs on Linux only

Some checks rely on Linux tools and run in the Linux CI jobs only: AddressSanitizer/UndefinedBehaviorSanitizer and ThreadSanitizer builds, libFuzzer fuzzing, code coverage (gcovr), clang-tidy and cppcheck, the external TLS scan (sslyze, testssl.sh), the systemd lifecycle, the Linux packages, the demonstration script `tools/demo.sh` and its video. To run them from a Windows machine, use **WSL 2** with Ubuntu 24.04 and follow the Linux instructions of the [README](../README.md):

```powershell
wsl --install -d Ubuntu-24.04
```

Every push runs the complete set on GitHub Actions (19 jobs, [TESTS.md §2.1](TESTS.md#21-continuous-integration-github-actions-every-push-and-pull-request)).

## 10. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `Could not find toolchain file: /scripts/buildsystems/vcpkg.cmake` | `VCPKG_ROOT` not set in this terminal | Set it (2.4) and open a new terminal; then delete `build\windows-msvc` and configure again |
| Preset `windows-msvc` "not available" | Not on Windows, or old CMake | The preset is Windows-only; CMake 3.25+ is required (`cmake --version`) |
| `No CMAKE_CXX_COMPILER could be found` / generator "Visual Studio 17 2022" not found | C++ workload missing | Add "Desktop development with C++" (2.3) |
| vcpkg fails building OpenSSL with path or command-line errors | Repository or vcpkg in a deep path | Use short paths (`C:\src\tlsrelay`, `C:\vcpkg`); optionally enable long paths: `New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem -Name LongPathsEnabled -Value 1 -PropertyType DWord -Force` (administrator) |
| vcpkg download errors | Proxy or firewall | Set `HTTP_PROXY`/`HTTPS_PROXY` for the session, or pre-populate the binary cache from another machine |
| `Could not find a package configuration file provided by "Qt6"` | Editor enabled without Qt path | Add `"-DCMAKE_PREFIX_PATH=$env:QT_ROOT_DIR"` (4.2) |
| Qt found but link errors (`LNK2038` mismatch) | Qt built for another compiler (MinGW, msvc2019) | Install the `msvc2022_64` variant (2.5) |
| `Admin.QtTests` fails at once, or the editor does not start: `Qt6Core.dll was not found` | Qt not on `PATH` | `$env:PATH = "$env:QT_ROOT_DIR\bin;$env:PATH"` before `ctest` (5.1) |
| `qt.qpa.plugin: Could not find the Qt platform plugin "windows"` | Mixed Qt installations on `PATH` | Keep only one Qt `bin` directory on `PATH` |
| `cpack` : `Could not find WiX` / `candle.exe` | WiX not installed, or terminal opened before installation | Install WiX v3 (2.6), open a new terminal, check `$env:WIX` |
| `windows-service.ps1` : access denied | Not elevated | Run PowerShell as administrator |
| `windows-service.ps1` : `python` not found | Python not on `PATH` | Install Python 3 (2.2) with "Add to PATH", or the `py` launcher alias `python` |
| A test fails only on your machine | Antivirus scanning or slowing the test executables | Exclude the `build` directory from real-time scanning, re-run with `--rerun-failed`; if it persists, report it with the `--output-on-failure` log |
| `tlsrelay.exe version` shows an OpenSSL other than 3.5.x | A different `libcrypto-3-x64.dll` earlier on `PATH` | Run from the build directory or the MSI installation, whose DLLs sit next to the executable |

## 11. Command summary

```powershell
# Once: tools (2), then in a Developer PowerShell for VS 2022
git clone https://github.com/Gaillotte/tlsrelay.git C:\src\tlsrelay; cd C:\src\tlsrelay

# Build (relay, testkit, tests, editor)
cmake --preset windows-msvc -DTLSRELAY_WARNINGS_AS_ERRORS=ON -DTLSRELAY_BUILD_ADMIN=ON "-DCMAKE_PREFIX_PATH=$env:QT_ROOT_DIR"
cmake --build --preset windows-release

# Tests
$env:PATH = "$env:QT_ROOT_DIR\bin;$env:PATH"
ctest --preset windows-release -j 2
.\tools\check-hardening.ps1 build\windows-msvc\src\app\Release\tlsrelay.exe build\windows-msvc\src\testkit\Release\tlsrelay-testkit.exe
.\tests\lifecycle\windows-pki.ps1 -BuildDir build\windows-msvc\src\app\Release
.\tests\lifecycle\windows-service.ps1 -BuildDir build\windows-msvc\src\app\Release        # administrator
.\tools\recette.ps1 -BuildDir build\windows-msvc\src\app\Release -TestkitDir build\windows-msvc\src\testkit\Release -Quick

# Package
cd build\windows-msvc; cpack -C Release -G WIX; cd ..\..
```
