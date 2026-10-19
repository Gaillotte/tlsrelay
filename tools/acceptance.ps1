<#
.SYNOPSIS
    tlsrelay acceptance kit (PLAN §5.7): automated scenarios on one workstation.

.DESCRIPTION
    Creates an acceptance PKI with the mini-CA (ca init, gen-csr, ca sign, pki install),
    starts a tlsrelay server and a tlsrelay client on distinct loopback addresses,
    then runs the scenarios of the acceptance test plan (docs/ACCEPTANCE.md):

        testkit ──► client 127.0.0.2 ──(disturbance proxy 127.0.0.5)──► server 127.0.0.3 ──► echo 127.0.0.4

    The plain and tls ports go directly from the client to the server; the mtls
    port goes through the testkit proxy (cuts, silent link). The report (report.md)
    gives the versions, the hashes of the binaries, the result of each
    scenario and log extracts on failure.

    Console mode (default): the relays run as processes; also works
    on Linux (PowerShell 7). -Services mode (Windows, administrator):
    the relays are installed as Windows services (rc-server, rc-client), under
    their virtual account, with restricted rights on their files.

.PARAMETER BuildDir
    Directory containing tlsrelay and tlsrelay-testkit (and the DLLs on Windows).

.PARAMETER TestkitDir
    Directory containing tlsrelay-testkit, if different from BuildDir (build tree).

.PARAMETER WorkDir
    Working and report directory (default: acceptance-<date> in the current directory;
    in -Services mode: %ProgramData%\tlsrelay\acceptance-<date>).

.PARAMETER Services
    Installs the relays as Windows services (requires administrator rights).

.PARAMETER Keep
    Leaves the instances, the echo and the proxy running after the automated scenarios, for
    the manual steps of the plan; stop-acceptance.ps1 (in WorkDir) then stops everything.

.PARAMETER Quick
    Shorter durations (quick check, CI).

.PARAMETER LinuxHost
    Cross tests (optional): Linux machine reachable over ssh (user@address),
    for example the acceptance Hyper-V VM. See docs/ACCEPTANCE.md.

.PARAMETER LinuxBuildDir
    With -LinuxHost: local directory containing the Linux binaries (tlsrelay, tlsrelay-testkit),
    copied to the Linux machine.

.PARAMETER LocalAddress
    With -LinuxHost: address of this workstation reachable from the Linux machine.

.PARAMETER SshPort
    With -LinuxHost: ssh port of the Linux machine (default: 22).

.EXAMPLE
    .\tools\acceptance.ps1 -BuildDir 'C:\Program Files\tlsrelay' -Services
#>
param(
    [Parameter(Mandatory = $true)][string]$BuildDir,
    [string]$TestkitDir,
    [string]$WorkDir,
    [switch]$Services,
    [switch]$Keep,
    [switch]$Quick,
    [string]$LinuxHost,
    [string]$LinuxBuildDir,
    [string]$LocalAddress,
    [int]$SshPort = 22
)
$ErrorActionPreference = 'Stop'
$onWindows = [System.Environment]::OSVersion.Platform -eq 'Win32NT'
$exe = if ($onWindows) { '.exe' } else { '' }
if ($Services -and -not $onWindows) { throw "-Services: Windows only" }
if ($LinuxHost -and (-not $LinuxBuildDir -or -not $LocalAddress)) { throw "-LinuxHost requires -LinuxBuildDir and -LocalAddress" }

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
if (-not $WorkDir) {
    $WorkDir = if ($Services) { Join-Path $env:ProgramData "tlsrelay\acceptance-$stamp" } else { Join-Path (Get-Location) "acceptance-$stamp" }
}
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$WorkDir = (Resolve-Path $WorkDir).Path
$BuildDir = (Resolve-Path $BuildDir).Path
$TestkitDir = if ($TestkitDir) { (Resolve-Path $TestkitDir).Path } else { $BuildDir }

# In services mode, the binaries are installed outside the user's directory.
if ($Services) {
    $install = Join-Path $env:ProgramFiles 'tlsrelay-acceptance'
    New-Item -ItemType Directory -Force -Path $install | Out-Null
    Copy-Item (Join-Path $BuildDir '*.exe'), (Join-Path $BuildDir '*.dll'), (Join-Path $TestkitDir '*.exe') $install
    $BuildDir = $install
    $TestkitDir = $install
}
$bin = Join-Path $BuildDir "tlsrelay$exe"
$kit = Join-Path $TestkitDir "tlsrelay-testkit$exe"
foreach ($f in $bin, $kit) { if (-not (Test-Path $f)) { throw "not found: $f" } }

$env:TLSRELAY_CA_PASSPHRASE = "acceptance passphrase $stamp"
$durations = if ($Quick) { @{ Throughput = 8; Renegotiation = 40; Cuts = 15 } } else { @{ Throughput = 15; Renegotiation = 75; Cuts = 30 } }
$channels = if ($Quick) { 100 } else { 500 }

# Addresses and ports (SPEC, PLAN §5.7).
$A = @{ Client = '127.0.0.2'; Server = '127.0.0.3'; Dest = '127.0.0.4'; Proxy = '127.0.0.5' }
$P = @{ Dest = 18080; ClientPlain = 17101; ClientTls = 17102; ClientMtls = 17103
        ServerPlain = 19101; ServerTls = 19102; ServerMtls = 19103; Proxy = 19203 }

# ---------------------------------------------------------------------------
# Helpers

$results = [System.Collections.Generic.List[object]]::new()
$processes = [System.Collections.Generic.List[object]]::new()
$script:notes = $null
$script:scenarioOk = $true

function Note([string]$text) { $script:notes.Add($text); Write-Host "   $text" }
function Check([bool]$condition, [string]$what) {
    if ($condition) { Note "OK  $what" } else { $script:scenarioOk = $false; Note "KO  $what" }
}

function Scenario([string]$id, [string]$title, [scriptblock]$body) {
    Write-Host "== $id $title"
    $script:notes = [System.Collections.Generic.List[string]]::new()
    $script:scenarioOk = $true
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    try { & $body } catch { $script:scenarioOk = $false; Note "KO  error: $($_.Exception.Message)" }
    $watch.Stop()
    $results.Add([pscustomobject]@{
        Id = $id; Title = $title; Ok = $script:scenarioOk
        Seconds = [math]::Round($watch.Elapsed.TotalSeconds, 1); Notes = @($script:notes)
        Logs = if ($script:scenarioOk) { $null } else { Get-LogExcerpt }
    })
}

function Invoke-Tool([string]$exePath, [string[]]$arguments) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $out = & $exePath @arguments 2>&1 | Out-String
    $script:exitCode = $LASTEXITCODE
    $ErrorActionPreference = $previous
    return $out.TrimEnd()
}
function Relay([string[]]$arguments) { Invoke-Tool $bin $arguments }
function Kit([string[]]$arguments) { Invoke-Tool $kit $arguments }
function KitJson([string[]]$arguments) {
    $out = Kit ($arguments + '--json')
    $line = ($out -split "`n" | Where-Object { $_.TrimStart().StartsWith('{') } | Select-Object -Last 1)
    if (-not $line) { throw "testkit $($arguments[0]): no result ($out)" }
    return $line | ConvertFrom-Json
}

function Start-Background([string]$name, [string]$exePath, [string[]]$arguments) {
    $out = Join-Path $WorkDir "$name.out.log"
    $err = Join-Path $WorkDir "$name.err.log"
    $quoted = $arguments | ForEach-Object { if ($_ -match '\s') { "`"$_`"" } else { $_ } }
    $p = Start-Process -FilePath $exePath -ArgumentList $quoted -PassThru -NoNewWindow `
        -RedirectStandardOutput $out -RedirectStandardError $err
    $processes.Add([pscustomobject]@{ Name = $name; Process = $p })
    return $p
}
function Stop-Background([string]$name) {
    foreach ($entry in @($processes | Where-Object { $_.Name -eq $name })) {
        if (-not $entry.Process.HasExited) { Stop-Process -Id $entry.Process.Id -Force -ErrorAction SilentlyContinue }
        $entry.Process.WaitForExit(5000) | Out-Null
        $processes.Remove($entry) | Out-Null
    }
}

function Wait-Until([scriptblock]$condition, [int]$seconds = 15) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline) {
        if (& $condition) { return $true }
        Start-Sleep -Milliseconds 200
    }
    return [bool](& $condition)
}

function Metric([string]$role, [string]$name) {
    $out = Relay @('metrics', '-c', (Config $role))
    $line = $out -split "`n" | Where-Object { $_ -match "^tlsrelay_$name(\{| )" } | Select-Object -First 1
    if (-not $line) { return -1 }
    return [double](($line.Trim() -split '\s+')[-1])
}

# Sends a text through a client port and reads the echo.
function Send-Text([int]$port, [string]$text) {
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $client.Connect($A.Client, $port)
        $stream = $client.GetStream()
        $stream.ReadTimeout = 5000
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
        $stream.Write($bytes, 0, $bytes.Length)
        $buffer = [byte[]]::new($bytes.Length)
        $got = 0
        while ($got -lt $bytes.Length) {
            $n = $stream.Read($buffer, $got, $bytes.Length - $got)
            if ($n -le 0) { break }
            $got += $n
        }
        return [System.Text.Encoding]::UTF8.GetString($buffer, 0, $got)
    } finally { $client.Dispose() }
}

function Config([string]$role) { Join-Path $WorkDir "$role.yaml" }
function LogFile([string]$role) { Join-Path $WorkDir "logs/$role.log" }
function Get-LogExcerpt {
    $excerpt = @()
    foreach ($role in 'rc-server', 'rc-client') {
        $log = LogFile $role
        if (Test-Path $log) { $excerpt += "--- $role"; $excerpt += Get-Content $log -Tail 25 }
    }
    return $excerpt
}

function Yaml-Path([string]$path) { $path -replace '\\', '/' }

# ---------------------------------------------------------------------------
# Configurations

$lifetime = if ($Quick) { 20 } else { 30 }
$socketDir = if ($onWindows) { '' } else { "/tmp/tlsrelay-rc-$stamp" }
if ($socketDir) { New-Item -ItemType Directory -Force -Path $socketDir | Out-Null }
function Write-Configs {
    $w = Yaml-Path $WorkDir
    # On Linux, administration sockets under a short path (108 characters at most).
    $adminServer = if ($onWindows) { '' } else { "admin: { endpoint: $socketDir/rc-server.sock }" }
    $adminClient = if ($onWindows) { '' } else { "admin: { endpoint: $socketDir/rc-client.sock }" }
    # Short session: several renegotiations during the acceptance run.
    $limits = "limits: { session_lifetime: ${lifetime}s, renegotiation_grace: 8s, idle_timeout: 15s, keepalive_interval: 5s, shutdown_timeout: 5s }"
    @"
mode: server
instance: rc-server
logging: { output: '$w/logs/rc-server.log' }
$adminServer
credentials: { pki_root: '$w/pki/rc-server' }
whitelist: { file: '$w/whitelist.yaml' }
destination: { address: $($A.Dest), port: $($P.Dest) }
$limits
ports:
  plain: { listen: "$($A.Server):$($P.ServerPlain)" }
  tls:   { listen: "$($A.Server):$($P.ServerTls)" }
  mtls:  { listen: "$($A.Server):$($P.ServerMtls)" }
"@ | Set-Content -Encoding utf8 (Config 'rc-server')
    @"
mode: client
instance: rc-client
logging: { output: '$w/logs/rc-client.log' }
$adminClient
credentials: { pki_root: '$w/pki/rc-client' }
source_address: $($A.Client)
$limits
ports:
  plain: { listen: "$($A.Client):$($P.ClientPlain)", upstream: "$($A.Server):$($P.ServerPlain)" }
  tls:   { listen: "$($A.Client):$($P.ClientTls)", upstream: "$($A.Server):$($P.ServerTls)", server_name: relay.acceptance }
  mtls:  { listen: "$($A.Client):$($P.ClientMtls)", upstream: "$($A.Proxy):$($P.Proxy)", server_name: relay.acceptance }
"@ | Set-Content -Encoding utf8 (Config 'rc-client')
}

function Write-Whitelist([string]$ip = $A.Client) {
    @"
peers:
  - name: rc-client
    ip: $ip
    ports: [plain, tls, mtls]
    subject: "CN=rc-client,O=Acceptance"
"@ | Set-Content -Encoding utf8 (Join-Path $WorkDir 'whitelist.yaml')
}

# ---------------------------------------------------------------------------
# Starting and stopping the relays

# Windows rights (icacls): failure reported, never ignored.
function Set-Acl-Checked([string]$path, [string[]]$arguments) {
    $out = & icacls $path @arguments 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { throw "icacls $path $($arguments -join ' '): $out" }
}
# Access restricted to Administrators, SYSTEM and the given account (no inheritance from the parent).
function Grant-Only([string]$path, [string]$account, [string]$rights) {
    $inherit = if ((Get-Item $path) -is [System.IO.DirectoryInfo]) { '(OI)(CI)' } else { '' }
    Set-Acl-Checked $path @('/inheritance:r', '/grant:r', "*S-1-5-32-544:${inherit}F", "*S-1-5-18:${inherit}F", "${account}:$rights")
}

function Start-Relay([string]$role) {
    if ($Services) {
        $out = Relay @('start', '--instance', $role)
        if ($exitCode -ne 0) {
            # Diagnostics: rights on the instance files, then the same configuration in console mode.
            foreach ($path in (Config $role), (Join-Path $WorkDir "pki/$role"), (Join-Path $WorkDir 'logs'), (Join-Path $WorkDir 'whitelist.yaml')) {
                if (Test-Path $path) { Note "  rights on ${path}:"; (& icacls $path 2>&1 | Out-String) -split "`r?`n" | Where-Object { $_.Trim() } | ForEach-Object { Note "    $($_.Trim())" } }
            }
            $serviceLog = Join-Path $env:ProgramData "tlsrelay\logs\$role.log"
            if (Test-Path $serviceLog) { Get-Content $serviceLog -Tail 10 | ForEach-Object { Note "  service log: $_" } }
            $console = Relay @('check-config', '-c', (Config $role))
            Note "  check-config (administrator): $console"
            throw "starting service ${role}: $out"
        }
    } else {
        Start-Background $role $bin @('run', '-c', (Config $role)) | Out-Null
    }
    if (-not (Wait-Until { Relay @('status', '-c', (Config $role)) | Out-Null; $exitCode -eq 0 } 20)) {
        throw "$role does not answer on its administration channel"
    }
}

function Stop-Relay([string]$role, [string]$how = 'stop') {
    $out = Relay @($how, '-c', (Config $role))
    if ($exitCode -ne 0) { throw "$how ${role}: $out" }
    if ($Services) {
        (Get-Service "tlsrelay-$role").WaitForStatus('Stopped', '00:00:30')
    } else {
        foreach ($entry in @($processes | Where-Object { $_.Name -eq $role })) {
            if (-not $entry.Process.WaitForExit(30000)) { throw "$role did not stop" }
            $processes.Remove($entry) | Out-Null
        }
    }
}

function Start-Proxy([string[]]$extra = @()) {
    Stop-Background 'proxy'
    Start-Background 'proxy' $kit (@('proxy', '--listen', "$($A.Proxy):$($P.Proxy)", '--target', "$($A.Server):$($P.ServerMtls)",
                                    '--source', $A.Client) + $extra) | Out-Null
    Start-Sleep -Milliseconds 500
}

# Load: N concurrent channels, SHA-256 hash per channel.
function Test-Load([int]$port, [int]$count, [string]$bytes = '256KiB') {
    $r = KitJson @('load', '--target', "$($A.Client):$port", '--channels', "$count", '--bytes', $bytes)
    Note ("  {0} channels, {1} intact, {2} failed, {3:N0} Mbit/s aggregate" -f $r.channels, $r.ok, $r.failed, $r.mbit_per_s)
    if ($r.failed -gt 0) { $r.errors | Select-Object -First 5 | ForEach-Object { Note "  $_" } }
    return ($r.ok -eq $count -and $r.failed -eq 0)
}

# ---------------------------------------------------------------------------
# Scenarios

$aborted = $null
$cleanup = {
    if ($Keep -and -not $aborted) {
        # Manual steps: everything keeps running; stop script for later.
        $lines = @('# Stops the tlsrelay acceptance run (generated by acceptance.ps1 -Keep)')
        foreach ($entry in @($processes | Where-Object { -not $_.Process.HasExited })) { $lines += "Stop-Process -Id $($entry.Process.Id) -Force -ErrorAction SilentlyContinue  # $($entry.Name)" }
        if ($Services) { foreach ($role in 'rc-client', 'rc-server') { $lines += "& '$bin' service uninstall --instance $role" } }
        if ($socketDir) { $lines += "Remove-Item -Recurse -Force '$socketDir' -ErrorAction SilentlyContinue" }
        $lines | Set-Content -Encoding utf8 (Join-Path $WorkDir 'stop-acceptance.ps1')
        Write-Host "Instances left running; to stop: $(Join-Path $WorkDir 'stop-acceptance.ps1')"
        return
    }
    foreach ($entry in @($processes)) {
        if (-not $entry.Process.HasExited) { Stop-Process -Id $entry.Process.Id -Force -ErrorAction SilentlyContinue }
    }
    if ($Services) {
        foreach ($role in 'rc-client', 'rc-server') { & $bin service uninstall --instance $role 2>$null | Out-Null }
    }
}

try {
    New-Item -ItemType Directory -Force -Path (Join-Path $WorkDir 'logs') | Out-Null
    $versionText = Relay @('version')
    $hashes = foreach ($f in $bin, $kit) { "{0}  {1}" -f (Get-FileHash -Algorithm SHA256 $f).Hash.ToLower(), (Split-Path $f -Leaf) }
    $osText = if ($onWindows) { (Get-CimInstance Win32_OperatingSystem).Caption + ' ' + [System.Environment]::OSVersion.Version } else { (uname -sr) }

    Scenario 'R01' 'Acceptance PKI from the mini-CA (ca init, gen-csr, ca sign, pki install)' {
        Write-Configs
        Write-Whitelist
        $ac = Join-Path $WorkDir 'ca'
        $out = Relay @('ca', 'init', '--dir', $ac, '--org', 'Acceptance'); Check ($exitCode -eq 0) 'ca init (root, Servers CA, Clients CA)'
        foreach ($spec in @(@{ Role = 'rc-server'; Kind = 'server'; Subject = 'CN=relay.acceptance,O=Acceptance'; San = @('--san', 'relay.acceptance') },
                            @{ Role = 'rc-client'; Kind = 'client'; Subject = 'CN=rc-client,O=Acceptance'; San = @() })) {
            $cfg = Config $spec.Role
            $out = Relay (@('pki', 'gen-csr', '-c', $cfg, '--subject', $spec.Subject) + $spec.San); Check ($exitCode -eq 0) "$($spec.Role): certificate request"
            $kitDir = Join-Path $WorkDir "kit-$($spec.Role)"
            $out = Relay (@('ca', 'sign', '--dir', $ac, '--role', $spec.Kind, '--csr', (Join-Path $WorkDir "pki/$($spec.Role)/v1/request.csr"), '--out', $kitDir) + $spec.San)
            Check ($exitCode -eq 0) "$($spec.Role): signed by the CA"
            $out = Relay @('pki', 'install', '-c', $cfg, '--from', $kitDir); Check ($exitCode -eq 0) "$($spec.Role): certificate installed"
            $out = Relay @('pki', 'activate', '-c', $cfg, 'v1'); Check ($exitCode -eq 0) "$($spec.Role): generation v1 activated"
            $out = Relay @('check-pki', '-c', $cfg); Check ($exitCode -eq 0) "$($spec.Role): check-pki"
        }
        $out = Relay @('ca', 'sign', '--dir', $ac, '--role', 'client', '--csr', (Join-Path $WorkDir 'pki/rc-client/v1/request.csr'), '--out', (Join-Path $WorkDir 'kit-double'))
        Check ($exitCode -ne 0) 'subject already assigned refused by the CA'
    }

    Scenario 'R02' 'Starting the instances' {
        foreach ($role in 'rc-server', 'rc-client') {
            $out = Relay @('check-config', '-c', (Config $role)); Check ($exitCode -eq 0) "${role}: valid configuration"
        }
        Start-Background 'echo' $kit @('echo', '--listen', "$($A.Dest):$($P.Dest)") | Out-Null
        Start-Proxy
        if ($Services) {
            foreach ($role in 'rc-server', 'rc-client') {
                $out = Relay @('service', 'install', '--instance', $role, '-c', (Config $role)); Check ($exitCode -eq 0) "${role}: service installed"
                $account = "NT SERVICE\tlsrelay-$role"
                # Instance files readable only by its own account and the administrators (SPEC §10.3).
                Grant-Only (Join-Path $WorkDir "pki/$role") $account '(OI)(CI)RX'
                Grant-Only (Config $role) $account 'R'
                Set-Acl-Checked (Join-Path $WorkDir 'logs') @('/grant', "${account}:(OI)(CI)M")
                Set-Acl-Checked $WorkDir @('/grant', "${account}:RX")
            }
            Set-Acl-Checked (Join-Path $WorkDir 'whitelist.yaml') @('/grant', 'NT SERVICE\tlsrelay-rc-server:R')
        }
        Start-Relay 'rc-server'
        Start-Relay 'rc-client'
        $status = Relay @('status', '-c', (Config 'rc-server'))
        Check ($status -match 'PKI generation: v1') 'server: PKI generation v1'
        Check ($status -match 'whitelist: 1 peer') 'server: whitelist loaded'
        if ($Services) {
            foreach ($role in 'rc-server', 'rc-client') {
                $svc = Get-CimInstance Win32_Service -Filter "Name='tlsrelay-$role'"
                Check ($svc.StartName -eq "NT SERVICE\tlsrelay-$role") "${role}: service virtual account"
            }
        }
    }

    if (-not $results[-1].Ok) { throw "starting the instances failed: following scenarios not run" }

    Scenario 'R03' "Concurrent intact channels on the three ports ($channels per port)" {
        Check (Test-Load $P.ClientPlain $channels) 'plain port'
        Check (Test-Load $P.ClientTls $channels) 'tls port'
        Check (Test-Load $P.ClientMtls $channels) 'mtls port (through the proxy)'
    }

    Scenario 'R04' 'Throughput and added latency (tls port)' {
        $t = KitJson @('throughput', '--target', "$($A.Client):$($P.ClientTls)", '--duration', "$($durations.Throughput)s", '--rate', '200')
        Note ("  throughput: {0:N0} Mbit/s in each direction (paced at 200)" -f $t.mbit_per_s)
        Check ($t.intact -eq 1 -and $t.mbit_per_s -ge 100) 'throughput ≥ 100 Mbit/s, stream intact'
        $direct = KitJson @('latency', '--target', "$($A.Dest):$($P.Dest)", '--count', '2000')
        $relay = KitJson @('latency', '--target', "$($A.Client):$($P.ClientTls)", '--count', '2000')
        $added = ($relay.p50_us - $direct.p50_us) / 1000
        Note ("  p50 latency: direct {0:N0} µs, through tlsrelay {1:N0} µs, added {2:N3} ms" -f $direct.p50_us, $relay.p50_us, $added)
        Check ($added -lt 1.0) 'added latency < 1 ms'
    }

    Scenario 'R05' 'Whitelist: address removed then restored' {
        $before = Metric 'rc-server' 'peers_rejected_total'
        Write-Whitelist '127.0.0.9'
        $out = Relay @('reload', '-c', (Config 'rc-server')); Check ($exitCode -eq 0) 'whitelist reloaded'
        $r = KitJson @('load', '--target', "$($A.Client):$($P.ClientTls)", '--channels', '5', '--bytes', '1KiB')
        Check ($r.ok -eq 0) 'new channels refused for an unlisted address'
        Check ((Metric 'rc-server' 'peers_rejected_total') -gt $before) 'refusals counted (peers_rejected_total)'
        Write-Whitelist
        $out = Relay @('reload', '-c', (Config 'rc-server'))
        Check (Test-Load $P.ClientTls 20 '64KiB') 'channels accepted after restoring'
    }

    Scenario 'R06' 'Network cuts: session resumption without loss (mtls port)' {
        $before = Metric 'rc-client' 'renegotiations_total'
        Start-Proxy @('--cut-every', '5s')
        $t = KitJson @('throughput', '--target', "$($A.Client):$($P.ClientMtls)", '--duration', "$($durations.Cuts)s", '--rate', '50')
        Start-Proxy
        Note ("  {0:N1} MiB transferred despite the cuts" -f ($t.bytes / 1MB))
        Check ($t.intact -eq 1) 'stream intact across the cuts'
        Check ((Metric 'rc-client' 'renegotiations_total') -gt $before) 'session resumptions performed'
    }

    Scenario 'R07' "Transparent renegotiation (session_lifetime ${lifetime}s)" {
        $before = Metric 'rc-client' 'renegotiations_total'
        $t = KitJson @('throughput', '--target', "$($A.Client):$($P.ClientTls)", '--duration', "$($durations.Renegotiation)s", '--rate', '50')
        $count = (Metric 'rc-client' 'renegotiations_total') - $before
        Note ("  {0} renegotiation(s) during {1} s of continuous stream" -f $count, $durations.Renegotiation)
        Check ($t.intact -eq 1) 'continuous stream intact'
        Check ($count -ge 1) 'renegotiations performed without cutting the application'
    }

    Scenario 'R08' 'Live PKI rotation (generation v2)' {
        $ac = Join-Path $WorkDir 'ca'
        $cfg = Config 'rc-server'
        $out = Relay @('pki', 'gen-csr', '-c', $cfg, '--subject', 'CN=relay.acceptance,O=Acceptance', '--san', 'relay.acceptance'); Check ($exitCode -eq 0) 'request v2'
        $out = Relay @('ca', 'sign', '--dir', $ac, '--role', 'server', '--csr', (Join-Path $WorkDir 'pki/rc-server/v2/request.csr'), '--san', 'relay.acceptance', '--renew', '--out', (Join-Path $WorkDir 'kit-v2'))
        Check ($exitCode -eq 0) 'renewal signed by the CA'
        $out = Relay @('pki', 'install', '-c', $cfg, '--from', (Join-Path $WorkDir 'kit-v2')); Check ($exitCode -eq 0) 'v2 installed'
        $out = Relay @('pki', 'activate', '-c', $cfg, 'v2'); Check ($exitCode -eq 0) 'v2 activated'
        $out = Relay @('reload', '-c', $cfg); Check ($exitCode -eq 0) 'reload'
        Check ((Relay @('status', '-c', $cfg)) -match 'PKI generation: v2') 'current generation v2'
        Check (Test-Load $P.ClientMtls 50 '64KiB') 'new channels on generation v2'
        Check ((Metric 'rc-server' 'pki_rotations_total') -ge 1) 'switch counted'
    }

    Scenario 'R09' 'Root change in three steps, without interruption (SPEC §7.5)' {
        $ac = Join-Path $WorkDir 'ca'
        $ac2 = Join-Path $WorkDir 'ca2'
        $out = Relay @('ca', 'init', '--dir', $ac2, '--org', 'Acceptance'); Check ($exitCode -eq 0) 'new CA (root, Servers CA, Clients CA)'
        # Trust files for steps 1 and 2 (two roots; CA expected from the peer under both roots).
        $transition = Join-Path $WorkDir 'root-change'
        $out = Relay @('ca', 'root-change', '--dir', $ac, '--new', $ac2, '--out', $transition); Check ($exitCode -eq 0) 'transition files (ca root-change)'
        $trust = @{}
        foreach ($pair in @(@('rc-server', 'server'), @('rc-client', 'client'))) {
            $trust[$pair[0]] = @('--roots', (Join-Path $transition "$($pair[1])/trust-roots.pem"),
                                 '--issuer', (Join-Path $transition "$($pair[1])/trust-issuer.pem"))
        }
        $instances = @(@{ Role = 'rc-server'; Kind = 'server'; Subject = 'CN=relay.acceptance,O=Acceptance'; San = @('--san', 'relay.acceptance') },
                       @{ Role = 'rc-client'; Kind = 'client'; Subject = 'CN=rc-client,O=Acceptance'; San = @() })
        # New generation for an instance: request, signature by the given CA, installation, activation.
        $nextGeneration = {
            param($spec, [string]$caDir, [bool]$renew, [string[]]$trust, [string]$step)
            $cfg = Config $spec.Role
            $out = Relay (@('pki', 'gen-csr', '-c', $cfg, '--subject', $spec.Subject) + $spec.San)
            $generation = [regex]::Match($out, 'generation (v\d+):').Groups[1].Value
            if (-not $generation) { $generation = (Get-ChildItem (Join-Path $WorkDir "pki/$($spec.Role)") -Directory | Sort-Object { [int]($_.Name.TrimStart('v')) } | Select-Object -Last 1).Name }
            $kitDir = Join-Path $WorkDir "kit-$($spec.Role)-$step"
            $sign = @('ca', 'sign', '--dir', $caDir, '--role', $spec.Kind, '--csr', (Join-Path $WorkDir "pki/$($spec.Role)/$generation/request.csr"), '--out', $kitDir) + $spec.San
            if ($renew) { $sign += '--renew' }
            $out = Relay $sign
            if ($exitCode -ne 0) { throw "$($spec.Role): signing ($step): $out" }
            $out = Relay (@('pki', 'install', '-c', $cfg, '--from', $kitDir) + $trust)
            if ($exitCode -ne 0) { throw "$($spec.Role): installation ($step): $out" }
            $out = Relay @('pki', 'activate', '-c', $cfg, $generation)
            if ($exitCode -ne 0) { throw "$($spec.Role): activation ($step): $out" }
            $out = Relay @('reload', '-c', $cfg)
            if ($exitCode -ne 0) { throw "$($spec.Role): reload ($step): $out" }
            return $generation
        }
        # Continuous stream during the whole procedure.
        $fluxSeconds = if ($Quick) { 20 } else { 40 }
        Start-Background 'root-stream' $kit @('throughput', '--target', "$($A.Client):$($P.ClientMtls)", '--duration', "${fluxSeconds}s", '--rate', '20', '--json') | Out-Null
        Start-Sleep -Seconds 1

        foreach ($spec in $instances) { $g = & $nextGeneration $spec $ac $true $trust[$spec.Role] 'step1' }
        Check (Test-Load $P.ClientMtls 20 '64KiB') 'step 1 (pre-trust: two roots, old PKI): mtls channels'
        foreach ($spec in $instances) { $g = & $nextGeneration $spec $ac2 $false $trust[$spec.Role] 'step2' }
        Check (Test-Load $P.ClientMtls 20 '64KiB') 'step 2 (switch: new PKI, two roots): mtls channels'
        Check (Test-Load $P.ClientTls 20 '64KiB') 'step 2: tls channels'
        foreach ($spec in $instances) { $g = & $nextGeneration $spec $ac2 $true @() 'step3' }
        Check (Test-Load $P.ClientMtls 20 '64KiB') 'step 3 (old root removed): mtls channels'
        $status = Relay @('status', '-c', (Config 'rc-server'))
        Note "  server: $(($status -split "`n" | Where-Object { $_ -match 'PKI generation' }))"

        $flux = $processes | Where-Object { $_.Name -eq 'root-stream' } | Select-Object -First 1
        $flux.Process.WaitForExit(($fluxSeconds + 30) * 1000) | Out-Null
        $line = Get-Content (Join-Path $WorkDir 'root-stream.out.log') | Where-Object { $_.TrimStart().StartsWith('{') } | Select-Object -Last 1
        $t = if ($line) { $line | ConvertFrom-Json } else { $null }
        Check ($t -and $t.intact -eq 1) 'continuous stream intact during the three steps'
        Check ((Metric 'rc-server' 'pki_reload_failures_total') -eq 0 -and (Metric 'rc-client' 'pki_reload_failures_total') -eq 0) 'no generation refused'
    }

    Scenario 'R10' 'Logging: live levels, no relayed data in the logs' {
        $out = Relay @('log-level', '-c', (Config 'rc-server'), 'debug'); Check ($exitCode -eq 0) 'debug level set live'
        $marker = "ACCEPTANCE-DATA-$stamp"
        Check ((Send-Text $P.ClientTls $marker) -eq $marker) 'marker relayed and returned by the echo'
        Check (Test-Load $P.ClientTls 5 '4KiB') 'traffic at debug level'
        $out = Relay @('log-level', '-c', (Config 'rc-server'), 'info'); Check ($exitCode -eq 0) 'back to info level'
        $serverLog = Get-Content (LogFile 'rc-server') -Raw
        Check ($serverLog -match 'channel=\d+ opened') 'channels logged at debug level'
        $all = (Get-ChildItem (Join-Path $WorkDir 'logs') -File | ForEach-Object { Get-Content $_.FullName -Raw }) -join "`n"
        Check (-not $all.Contains($marker)) 'relayed data absent from the logs'
        Check (-not ($all -match 'PRIVATE KEY')) 'no private key in the logs'
        Check (-not $all.Contains($env:TLSRELAY_CA_PASSPHRASE)) 'no passphrase in the logs'
    }

    Scenario 'R11' 'Administration : status, channels, metrics' {
        $out = Relay @('status', '-c', (Config 'rc-client')); Check ($exitCode -eq 0 -and $out -match 'instance: rc-client') 'status'
        $out = Relay @('channels', '-c', (Config 'rc-server')); Check ($exitCode -eq 0 -and $out -match 'channel\(s\)') 'channels'
        $out = Relay @('metrics', '-c', (Config 'rc-server')); Check ($exitCode -eq 0 -and $out -match 'tlsrelay_channels_opened_total') 'metrics (Prometheus)'
    }

    Scenario 'R12' 'Lifecycle: stop with drain, restart, immediate stop' {
        Stop-Relay 'rc-client' 'stop'
        Note '  client stopped cleanly'
        Start-Relay 'rc-client'
        Check (Test-Load $P.ClientTls 10 '16KiB') 'restarted client operational'
        Stop-Relay 'rc-server' 'kill'
        Note '  server stopped immediately (kill)'
        Start-Relay 'rc-server'
        Check (Test-Load $P.ClientTls 10 '16KiB') 'restarted server operational'
        if ($Services) {
            $pid1 = (Get-CimInstance Win32_Service -Filter "Name='tlsrelay-rc-server'").ProcessId
            $out = Relay @('restart', '--instance', 'rc-server'); Check ($exitCode -eq 0) 'service restart'
            $pid2 = (Get-CimInstance Win32_Service -Filter "Name='tlsrelay-rc-server'").ProcessId
            Check ($pid1 -ne $pid2 -and $pid2 -ne 0) 'new process after restart'
        }
        Check (-not ((Get-Content (LogFile 'rc-server') -Raw) -match 'unexpected exception')) 'no unexpected exception logged'
    }

    if ($LinuxHost) {
        Scenario 'R13' "Cross tests with Linux ($LinuxHost)" {
            $out = & (Join-Path $PSScriptRoot 'acceptance-linux.ps1') -LinuxHost $LinuxHost -LinuxBuildDir $LinuxBuildDir `
                -LocalAddress $LocalAddress -WorkDir $WorkDir -Bin $bin -Kit $kit -SshPort $SshPort 6>&1 | Out-String
            $code = $LASTEXITCODE
            $out -split "`r?`n" | Where-Object { $_.Trim() } | ForEach-Object { Note "  $($_.Trim())" }
            Check ($code -eq 0) 'workstation → Linux and Linux → workstation'
        }
    }
} catch {
    Write-Host "ABORTED: $($_.Exception.Message)"
    $aborted = $_.Exception.Message
} finally {
    & $cleanup
    if ($socketDir -and -not $Keep) { Remove-Item -Recurse -Force $socketDir -ErrorAction SilentlyContinue }
}

# ---------------------------------------------------------------------------
# Report

$ok = @($results | Where-Object { $_.Ok }).Count
$report = [System.Collections.Generic.List[string]]::new()
$report.Add("# tlsrelay acceptance report")
$report.Add("")
$report.Add("| | |")
$report.Add("|---|---|")
$report.Add("| Date | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') |")
$report.Add("| Workstation | $([System.Environment]::MachineName) — $osText |")
$report.Add("| Mode | $(if ($Services) { 'Windows services' } else { 'console' })$(if ($Quick) { ', shorter durations' }) |")
$report.Add("| Version | $($versionText -replace "`r?`n", '; ') |")
$report.Add("| Result | **$ok / $($results.Count) automated scenarios OK**$(if ($aborted) { " — acceptance run aborted: $aborted" }) |")
$report.Add("")
$report.Add("SHA-256 hashes of the binaries:")
$report.Add("")
$report.Add('```')
$hashes | ForEach-Object { $report.Add($_) }
$report.Add('```')
$report.Add("")
$report.Add("## Automated scenarios")
$report.Add("")
$report.Add("| No. | Scenario | Result | Duration |")
$report.Add("|---|---|---|---|")
foreach ($r in $results) { $report.Add("| $($r.Id) | $($r.Title) | $(if ($r.Ok) { 'OK' } else { '**KO**' }) | $($r.Seconds) s |") }
foreach ($r in $results) {
    $report.Add("")
    $report.Add("### $($r.Id) — $($r.Title)")
    $report.Add("")
    $r.Notes | ForEach-Object { $report.Add("- $($_.Trim())") }
    if ($r.Logs) {
        $report.Add("")
        $report.Add("Log extracts:")
        $report.Add("")
        $report.Add('```')
        $r.Logs | ForEach-Object { $report.Add($_) }
        $report.Add('```')
    }
}
$report.Add("")
$report.Add("## Manual steps")
$report.Add("")
$report.Add("To be run following the acceptance test plan (docs/ACCEPTANCE.md, section 4) and recorded in the acceptance report.")
$reportPath = Join-Path $WorkDir 'report.md'
$report | Set-Content -Encoding utf8 $reportPath

Write-Host ""
Write-Host "Report: $reportPath"
Write-Host "$ok / $($results.Count) automated scenarios OK"
if ($aborted -or $ok -ne $results.Count) { exit 1 }
exit 0
