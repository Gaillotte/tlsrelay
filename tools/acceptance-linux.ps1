<#
.SYNOPSIS
    Acceptance cross tests (PLAN §5.7): Windows → Linux and Linux → Windows, over mTLS.

.DESCRIPTION
    Called by acceptance.ps1 (-LinuxHost), after the acceptance PKI has been created.
    Prepares on this workstation the PKIs of a Linux server and client (same
    mini-CA), copies binaries, PKIs and configurations to the Linux machine (scp),
    starts an echo, a tlsrelay server and a tlsrelay client there (ssh), then:

      1. testkit (workstation) → tlsrelay client (workstation) ══ mTLS ══► tlsrelay server (Linux) → echo (Linux)
      2. testkit (Linux)       → tlsrelay client (Linux)       ══ mTLS ══► tlsrelay server (workstation) → echo (workstation)

    Prerequisites: key-based ssh access to the Linux machine; Linux binaries built
    for its distribution (or package installed); port 19303 of the workstation open
    from the Linux machine (firewall rule added if the script runs as
    administrator on Windows); port 29303 of the Linux machine open.
#>
param(
    [Parameter(Mandatory = $true)][string]$LinuxHost,
    [Parameter(Mandatory = $true)][string]$LinuxBuildDir,
    [Parameter(Mandatory = $true)][string]$LocalAddress,
    [Parameter(Mandatory = $true)][string]$WorkDir,
    [Parameter(Mandatory = $true)][string]$Bin,
    [Parameter(Mandatory = $true)][string]$Kit,
    [int]$SshPort = 22,
    [int]$Channels = 50
)
$ErrorActionPreference = 'Stop'
$onWindows = [System.Environment]::OSVersion.Platform -eq 'Win32NT'
$remoteIp = ($LinuxHost -split '@')[-1]
$sshOptions = @('-p', "$SshPort", '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=accept-new')
$scpOptions = @('-q', '-P', "$SshPort", '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=accept-new')
$local = Join-Path $WorkDir 'linux'
New-Item -ItemType Directory -Force -Path $local | Out-Null
$failures = 0

function Say([string]$text) { Write-Host "   $text" }
function Run([string]$exePath, [string[]]$arguments) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $out = & $exePath @arguments 2>&1 | Out-String
    $script:exitCode = $LASTEXITCODE
    $ErrorActionPreference = $previous
    return $out.TrimEnd()
}
function Remote([string]$command) {
    $out = Run 'ssh' ($sshOptions + @($LinuxHost, $command))
    if ($exitCode -ne 0) { throw "ssh: ${command}: $out" }
    return $out
}
function Yaml-Path([string]$path) { $path -replace '\\', '/' }

$remoteHome = (Remote 'echo $HOME').Trim()
$remoteDir = "$remoteHome/tlsrelay-acceptance"
$ac = Join-Path $WorkDir 'ca'

# --- PKI of the Linux instances, issued by the acceptance mini-CA -------------
foreach ($spec in @(@{ Name = 'lx-server'; Mode = 'server'; Role = 'server'; Subject = 'CN=relay.linux,O=Acceptance'; San = @('--san', 'relay.linux') },
                    @{ Name = 'lx-client'; Mode = 'client'; Role = 'client'; Subject = 'CN=lx-client,O=Acceptance'; San = @() })) {
    $cfg = Join-Path $local "$($spec.Name)-pki.yaml"
    $pki = Yaml-Path (Join-Path $local "pki/$($spec.Name)")
    if ($spec.Mode -eq 'server') {
        "mode: server`ninstance: $($spec.Name)`ncredentials: { pki_root: '$pki' }`nwhitelist: { file: 'x.yaml' }`ndestination: { address: 127.0.0.1, port: 9 }`nadmin: { enabled: false }`nports:`n  mtls: { listen: `"127.0.0.1:1`" }" |
            Set-Content -Encoding utf8 $cfg
    } else {
        "mode: client`ninstance: $($spec.Name)`ncredentials: { pki_root: '$pki' }`nadmin: { enabled: false }`nports:`n  mtls: { listen: `"127.0.0.1:1`", upstream: `"127.0.0.1:2`", server_name: relay.acceptance }" |
            Set-Content -Encoding utf8 $cfg
    }
    $out = Run $Bin (@('pki', 'gen-csr', '-c', $cfg, '--subject', $spec.Subject) + $spec.San)
    if ($exitCode -ne 0) { throw "$($spec.Name): gen-csr: $out" }
    $kitDir = Join-Path $local "kit-$($spec.Name)"
    $out = Run $Bin (@('ca', 'sign', '--dir', $ac, '--role', $spec.Role, '--csr', (Join-Path $local "pki/$($spec.Name)/v1/request.csr"), '--out', $kitDir) + $spec.San)
    if ($exitCode -ne 0) { throw "$($spec.Name): ca sign: $out" }
    foreach ($step in @(@('pki', 'install', '-c', $cfg, '--from', $kitDir), @('pki', 'activate', '-c', $cfg, 'v1'))) {
        $out = Run $Bin $step
        if ($exitCode -ne 0) { throw "$($spec.Name): $($step[1]): $out" }
    }
}
Say "PKI of the Linux instances issued by the acceptance mini-CA"

# --- Linux configurations -----------------------------------------------------
@"
mode: server
instance: lx-server
logging: { output: $remoteDir/lx-server.log }
admin: { endpoint: $remoteDir/lx-server.sock }
credentials: { pki_root: $remoteDir/pki/lx-server }
whitelist: { file: $remoteDir/lx-whitelist.yaml }
destination: { address: 127.0.0.1, port: 28080 }
ports:
  mtls: { listen: "0.0.0.0:29303" }
"@ | Set-Content -Encoding utf8 (Join-Path $local 'lx-server.yaml')
@"
peers:
  - { name: workstation, ip: $LocalAddress, ports: [mtls], subject: "CN=rc-client,O=Acceptance" }
"@ | Set-Content -Encoding utf8 (Join-Path $local 'lx-whitelist.yaml')
@"
mode: client
instance: lx-client
logging: { output: $remoteDir/lx-client.log }
admin: { endpoint: $remoteDir/lx-client.sock }
credentials: { pki_root: $remoteDir/pki/lx-client }
ports:
  mtls: { listen: "127.0.0.1:27303", upstream: "${LocalAddress}:19303", server_name: relay.acceptance }
"@ | Set-Content -Encoding utf8 (Join-Path $local 'lx-client.yaml')

# --- Workstation instances facing Linux ---------------------------------------
$w = Yaml-Path $WorkDir
$xServerAdmin = if ($onWindows) { '' } else { "admin: { endpoint: /tmp/tlsrelay-x-server-$PID.sock }" }
$xClientAdmin = if ($onWindows) { '' } else { "admin: { endpoint: /tmp/tlsrelay-x-client-$PID.sock }" }
@"
mode: server
instance: x-server
logging: { output: '$w/logs/x-server.log' }
$xServerAdmin
credentials: { pki_root: '$w/pki/rc-server' }
whitelist: { file: '$w/linux/x-whitelist.yaml' }
destination: { address: 127.0.0.4, port: 18080 }
ports:
  mtls: { listen: "${LocalAddress}:19303" }
"@ | Set-Content -Encoding utf8 (Join-Path $local 'x-server.yaml')
@"
peers:
  - { name: linux, ip: $remoteIp, ports: [mtls], subject: "CN=lx-client,O=Acceptance" }
"@ | Set-Content -Encoding utf8 (Join-Path $local 'x-whitelist.yaml')
@"
mode: client
instance: x-client
logging: { output: '$w/logs/x-client.log' }
$xClientAdmin
credentials: { pki_root: '$w/pki/rc-client' }
ports:
  mtls: { listen: "127.0.0.2:17303", upstream: "${remoteIp}:29303", server_name: relay.linux }
"@ | Set-Content -Encoding utf8 (Join-Path $local 'x-client.yaml')

$started = @()
$firewall = $false
try {
    # --- Deployment and startup on the Linux side ----------------------------
    Remote "rm -rf '$remoteDir' && mkdir -p '$remoteDir/pki'" | Out-Null
    $files = @((Join-Path $LinuxBuildDir 'tlsrelay'), (Join-Path $LinuxBuildDir 'tlsrelay-testkit'),
               (Join-Path $local 'lx-server.yaml'), (Join-Path $local 'lx-client.yaml'), (Join-Path $local 'lx-whitelist.yaml'))
    $out = Run 'scp' ($scpOptions + $files + @("${LinuxHost}:$remoteDir/"))
    if ($exitCode -ne 0) { throw "scp: $out" }
    $out = Run 'scp' ($scpOptions + @('-r', (Join-Path $local 'pki/lx-server'), (Join-Path $local 'pki/lx-client'), "${LinuxHost}:$remoteDir/pki/"))
    if ($exitCode -ne 0) { throw "scp PKI: $out" }
    Remote "cd '$remoteDir' && chmod 700 pki && chmod +x tlsrelay tlsrelay-testkit && ./tlsrelay version" | ForEach-Object { Say "Linux: $_" }
    Remote ("cd '$remoteDir' && " +
            "(nohup ./tlsrelay-testkit echo --listen 127.0.0.1:28080 >echo.out 2>&1 & echo `$! >> pids) && " +
            "(nohup ./tlsrelay run -c lx-server.yaml >lx-server.out 2>&1 & echo `$! >> pids) && " +
            "(nohup ./tlsrelay run -c lx-client.yaml >lx-client.out 2>&1 & echo `$! >> pids) && sleep 1 && " +
            "./tlsrelay status -c lx-server.yaml >/dev/null && ./tlsrelay status -c lx-client.yaml >/dev/null") | Out-Null
    Say "Linux: echo, tlsrelay server and client started"

    # --- Workstation: server and client facing Linux -------------------------
    if ($onWindows -and ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        New-NetFirewallRule -DisplayName 'tlsrelay-acceptance' -Direction Inbound -Protocol TCP -LocalPort 19303 -Action Allow | Out-Null
        $firewall = $true
    }
    foreach ($name in 'x-server', 'x-client') {
        $p = Start-Process -FilePath $Bin -ArgumentList @('run', '-c', "`"$(Join-Path $local "$name.yaml")`"") -PassThru -NoNewWindow `
            -RedirectStandardOutput (Join-Path $local "$name.out") -RedirectStandardError (Join-Path $local "$name.err")
        $started += $p
    }
    Start-Sleep -Seconds 1

    # --- 1. Workstation → Linux -----------------------------------------------
    $out = Run $Kit @('load', '--target', '127.0.0.2:17303', '--channels', "$Channels", '--bytes', '256KiB', '--json')
    $r = ($out -split "`n" | Where-Object { $_.TrimStart().StartsWith('{') } | Select-Object -Last 1) | ConvertFrom-Json
    Say ("workstation → Linux: {0} channels, {1} intact" -f $r.channels, $r.ok)
    if ($r.ok -ne $Channels) { $failures++; Say "KO  workstation → Linux: $($r.errors -join '; ')" } else { Say "OK  workstation → Linux (mTLS)" }

    # --- 2. Linux → workstation -----------------------------------------------
    $out = Remote "cd '$remoteDir' && ./tlsrelay-testkit load --target 127.0.0.1:27303 --channels $Channels --bytes 256KiB --json || true"
    $r = ($out -split "`n" | Where-Object { $_.TrimStart().StartsWith('{') } | Select-Object -Last 1) | ConvertFrom-Json
    Say ("Linux → workstation: {0} channels, {1} intact" -f $r.channels, $r.ok)
    if ($r.ok -ne $Channels) { $failures++; Say "KO  Linux → workstation: $($r.errors -join '; ')" } else { Say "OK  Linux → workstation (mTLS)" }
} catch {
    $failures++
    Say "KO  $($_.Exception.Message)"
} finally {
    foreach ($p in $started) { if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } }
    if ($firewall) { Remove-NetFirewallRule -DisplayName 'tlsrelay-acceptance' -ErrorAction SilentlyContinue }
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & ssh @sshOptions $LinuxHost "cd '$remoteDir' 2>/dev/null && { [ -f pids ] && kill `$(cat pids) 2>/dev/null; tail -n 20 lx-server.log lx-client.log 2>/dev/null; }" 2>&1 |
        Out-File -Encoding utf8 (Join-Path $WorkDir 'logs/linux.log')
    $ErrorActionPreference = $previous
}
exit $(if ($failures -eq 0) { 0 } else { 1 })
