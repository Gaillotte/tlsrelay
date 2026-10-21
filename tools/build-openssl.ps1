<#
.SYNOPSIS
    Builds OpenSSL (3.5 LTS) for the Windows build of tlsrelay, from the official release archive.

.DESCRIPTION
    Downloads openssl-<Version>.tar.gz from the OpenSSL project's release page, checks its
    SHA-512 hash, builds it with OpenSSL's own build system (Configure VC-WIN64A, nmake) and
    installs headers, import libraries and DLLs into OutDir (default: build\openssl), which the
    windows-msvc CMake preset uses as OPENSSL_ROOT_DIR. Nothing is done when OutDir already
    holds this version.

    The paths compiled into the DLLs (OPENSSLDIR, ENGINESDIR, MODULESDIR) keep OpenSSL's
    defaults under %ProgramFiles% and %CommonProgramFiles%, which only administrators can
    write: the files are staged with DESTDIR and moved to OutDir afterwards. Never configure
    with --prefix/--openssldir pointing to a user-writable directory: the shipped DLLs would
    read openssl.cnf from there.

    Requirements: Visual Studio 2022 with the C++ workload (the developer environment is
    loaded automatically when cl.exe is not on PATH), a native Windows Perl (Strawberry Perl;
    the Perl of Git for Windows does not work) and NASM. See docs/BUILD-WINDOWS.md.

.EXAMPLE
    .\tools\build-openssl.ps1
#>
param(
    [string]$Version = '3.5.9',
    [string]$Sha512 = 'c4c8136fd2c98d13bb85a57bfb0def25c906f47f1fe97675cd114594944eab957b5b81a3e0f48826e1a0f093afff5e83766b539d49768f6db68310fd678d7de6',
    [string]$OutDir = (Join-Path $PSScriptRoot '..\build\openssl'),
    # Next to OutDir: same volume (the result is moved), short path.
    [string]$WorkDir = ''
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$OutDir = [IO.Path]::GetFullPath($OutDir)
if (-not $WorkDir) { $WorkDir = "$OutDir-work" }
$marker = Join-Path $OutDir 'tlsrelay-openssl-version.txt'

if ((Test-Path $marker) -and ((Get-Content $marker -Raw).Trim() -eq $Version) -and
    (Test-Path (Join-Path $OutDir 'lib\libcrypto.lib'))) {
    Write-Host "OpenSSL $Version already built in $OutDir"
    return
}

# Developer environment (cl, nmake, link) when not started from a Developer PowerShell.
if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path $vswhere)) { throw 'Visual Studio not found (vswhere.exe missing): install Visual Studio 2022 with the C++ workload' }
    $vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (-not $vs) { throw 'Visual Studio with the C++ x64 tools not found' }
    $vcvars = Join-Path $vs 'VC\Auxiliary\Build\vcvars64.bat'
    foreach ($line in (cmd.exe /c "`"$vcvars`" >nul && set")) {
        if ($line -match '^([^=]+)=(.*)$') { [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2]) }
    }
    if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) { throw "cl.exe still not found after $vcvars" }
}

# OpenSSL's Configure needs a native Windows Perl: the MSYS Perl of Git for Windows produces Unix paths.
$perl = @((Get-Command perl.exe -All -ErrorAction SilentlyContinue).Source) + 'C:\Strawberry\perl\bin\perl.exe' |
    Where-Object { $_ -and (Test-Path $_) -and ((& $_ -e 'print $^O') -eq 'MSWin32') } | Select-Object -First 1
if (-not $perl) { throw 'native Windows Perl not found: install Strawberry Perl (winget install StrawberryPerl.StrawberryPerl)' }
$nasm = (Get-Command nasm.exe -ErrorAction SilentlyContinue).Source
if (-not $nasm -and (Test-Path "$env:ProgramFiles\NASM\nasm.exe")) { $env:PATH = "$env:ProgramFiles\NASM;$env:PATH"; $nasm = "$env:ProgramFiles\NASM\nasm.exe" }
if (-not $nasm) { throw 'NASM not found: install it (winget install NASM.NASM) or add it to PATH' }
Write-Host "Perl: $perl"
Write-Host "NASM: $nasm"

if (Test-Path $WorkDir) { Remove-Item -Recurse -Force $WorkDir }
New-Item -ItemType Directory -Force $WorkDir | Out-Null
$archive = Join-Path $WorkDir "openssl-$Version.tar.gz"
$url = "https://github.com/openssl/openssl/releases/download/openssl-$Version/openssl-$Version.tar.gz"
Write-Host "Downloading $url"
Invoke-WebRequest -Uri $url -OutFile $archive -UseBasicParsing
$actual = (Get-FileHash -Algorithm SHA512 $archive).Hash
if ($actual -ne $Sha512) { throw "SHA-512 mismatch for openssl-$Version.tar.gz: expected $Sha512, got $actual" }
Write-Host 'SHA-512 verified'

tar -xzf $archive -C $WorkDir
if ($LASTEXITCODE -ne 0) { throw 'extraction failed' }
$source = Join-Path $WorkDir "openssl-$Version"
$stage = Join-Path $WorkDir 'stage'

Push-Location $source
try {
    & $perl Configure VC-WIN64A shared no-tests no-docs
    if ($LASTEXITCODE -ne 0) { throw 'Configure failed' }
    # jom builds in parallel when available; nmake (sequential) finishes or does the build,
    # since a parallel build of OpenSSL can stop on a race between targets.
    if (Get-Command jom.exe -ErrorAction SilentlyContinue) {
        & jom.exe
        if ($LASTEXITCODE -ne 0) { Write-Host 'jom failed: continuing with nmake' }
    }
    & nmake.exe
    if ($LASTEXITCODE -ne 0) { throw 'nmake failed' }
    & nmake.exe install_sw "DESTDIR=$stage"
    if ($LASTEXITCODE -ne 0) { throw 'install failed' }
} finally {
    Pop-Location
}

# DESTDIR keeps the default installation directory under the staging directory (drive removed).
$lib = Get-ChildItem $stage -Recurse -Filter libcrypto.lib | Select-Object -First 1
if (-not $lib) { throw "libcrypto.lib not found under $stage" }
$root = $lib.Directory.Parent.FullName
if (Test-Path $OutDir) { Remove-Item -Recurse -Force $OutDir }
New-Item -ItemType Directory -Force (Split-Path $OutDir) | Out-Null
Move-Item $root $OutDir
Set-Content -Path $marker -Value $Version
Remove-Item -Recurse -Force $WorkDir

& (Join-Path $OutDir 'bin\openssl.exe') version
Write-Host "OpenSSL $Version installed in $OutDir (OPENSSL_ROOT_DIR)"
