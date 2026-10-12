<#
.SYNOPSIS
    Kit de recette de tlsrelay (PLAN §5.7) : scénarios automatisés sur une station.

.DESCRIPTION
    Crée une PKI de recette avec la mini-AC (ca init, gen-csr, ca sign, pki install),
    démarre un tlsrelay serveur et un tlsrelay client sur des adresses de bouclage
    distinctes, puis déroule les scénarios du cahier de recette (docs/RECETTE.md) :

        testkit ──► client 127.0.0.2 ──(proxy de perturbations 127.0.0.5)──► serveur 127.0.0.3 ──► écho 127.0.0.4

    Les ports plain et tls vont directement du client au serveur ; le port mtls
    passe par le proxy du testkit (coupures, lien muet). Le rapport (rapport.md)
    donne les versions, les empreintes des binaires, le résultat de chaque
    scénario et des extraits de journaux en cas d'échec.

    Mode console (défaut) : les relais sont lancés comme processus ; fonctionne
    aussi sous Linux (PowerShell 7). Mode -Services (Windows, administrateur) :
    les relais sont installés comme services Windows (rc-server, rc-client), sous
    leur compte virtuel, avec des droits restreints sur leurs fichiers.

.PARAMETER BuildDir
    Répertoire contenant tlsrelay et tlsrelay-testkit (et les DLL sous Windows).

.PARAMETER TestkitDir
    Répertoire contenant tlsrelay-testkit, s'il diffère de BuildDir (arborescence de compilation).

.PARAMETER WorkDir
    Répertoire de travail et du rapport (défaut : recette-<date> dans le répertoire courant ;
    en mode -Services : %ProgramData%\tlsrelay\recette-<date>).

.PARAMETER Services
    Installe les relais comme services Windows (nécessite les droits d'administrateur).

.PARAMETER Keep
    Laisse les instances, l'écho et le proxy en service après les scénarios automatisés, pour
    les étapes manuelles du cahier ; arret-recette.ps1 (dans WorkDir) arrête tout ensuite.

.PARAMETER Quick
    Durées réduites (contrôle rapide, CI).

.PARAMETER LinuxHost
    Tests croisés (facultatif) : machine Linux joignable par ssh (utilisateur@adresse),
    par exemple la VM Hyper-V de la recette. Voir docs/RECETTE.md.

.PARAMETER LinuxBuildDir
    Avec -LinuxHost : répertoire local contenant les binaires Linux (tlsrelay, tlsrelay-testkit),
    copiés sur la machine Linux.

.PARAMETER LocalAddress
    Avec -LinuxHost : adresse de cette station joignable depuis la machine Linux.

.PARAMETER SshPort
    Avec -LinuxHost : port ssh de la machine Linux (défaut : 22).

.EXAMPLE
    .\tools\recette.ps1 -BuildDir 'C:\Program Files\tlsrelay' -Services
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
if ($Services -and -not $onWindows) { throw "-Services : Windows uniquement" }
if ($LinuxHost -and (-not $LinuxBuildDir -or -not $LocalAddress)) { throw "-LinuxHost demande -LinuxBuildDir et -LocalAddress" }

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
if (-not $WorkDir) {
    $WorkDir = if ($Services) { Join-Path $env:ProgramData "tlsrelay\recette-$stamp" } else { Join-Path (Get-Location) "recette-$stamp" }
}
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$WorkDir = (Resolve-Path $WorkDir).Path
$BuildDir = (Resolve-Path $BuildDir).Path
$TestkitDir = if ($TestkitDir) { (Resolve-Path $TestkitDir).Path } else { $BuildDir }

# En mode services, les binaires sont installés hors du répertoire de l'utilisateur.
if ($Services) {
    $install = Join-Path $env:ProgramFiles 'tlsrelay-recette'
    New-Item -ItemType Directory -Force -Path $install | Out-Null
    Copy-Item (Join-Path $BuildDir '*.exe'), (Join-Path $BuildDir '*.dll'), (Join-Path $TestkitDir '*.exe') $install
    $BuildDir = $install
    $TestkitDir = $install
}
$bin = Join-Path $BuildDir "tlsrelay$exe"
$kit = Join-Path $TestkitDir "tlsrelay-testkit$exe"
foreach ($f in $bin, $kit) { if (-not (Test-Path $f)) { throw "introuvable : $f" } }

$env:TLSRELAY_CA_PASSPHRASE = "phrase de passe de recette $stamp"
$durations = if ($Quick) { @{ Throughput = 8; Renegotiation = 40; Cuts = 15 } } else { @{ Throughput = 15; Renegotiation = 75; Cuts = 30 } }
$channels = if ($Quick) { 100 } else { 500 }

# Adresses et ports (SPEC, PLAN §5.7).
$A = @{ Client = '127.0.0.2'; Server = '127.0.0.3'; Dest = '127.0.0.4'; Proxy = '127.0.0.5' }
$P = @{ Dest = 18080; ClientPlain = 17101; ClientTls = 17102; ClientMtls = 17103
        ServerPlain = 19101; ServerTls = 19102; ServerMtls = 19103; Proxy = 19203 }

# ---------------------------------------------------------------------------
# Outils

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
    try { & $body } catch { $script:scenarioOk = $false; Note "KO  erreur : $($_.Exception.Message)" }
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
    if (-not $line) { throw "testkit $($arguments[0]) : pas de résultat ($out)" }
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

# Envoie un texte par un port du client et lit l'écho.
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
    # Sous Linux, sockets d'administration sous un chemin court (108 caractères au plus).
    $adminServer = if ($onWindows) { '' } else { "admin: { endpoint: $socketDir/rc-server.sock }" }
    $adminClient = if ($onWindows) { '' } else { "admin: { endpoint: $socketDir/rc-client.sock }" }
    # Session courte : plusieurs renégociations pendant la recette.
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
  tls:   { listen: "$($A.Client):$($P.ClientTls)", upstream: "$($A.Server):$($P.ServerTls)", server_name: relay.recette }
  mtls:  { listen: "$($A.Client):$($P.ClientMtls)", upstream: "$($A.Proxy):$($P.Proxy)", server_name: relay.recette }
"@ | Set-Content -Encoding utf8 (Config 'rc-client')
}

function Write-Whitelist([string]$ip = $A.Client) {
    @"
peers:
  - name: rc-client
    ip: $ip
    ports: [plain, tls, mtls]
    subject: "CN=rc-client,O=Recette"
"@ | Set-Content -Encoding utf8 (Join-Path $WorkDir 'whitelist.yaml')
}

# ---------------------------------------------------------------------------
# Démarrage et arrêt des relais

function Start-Relay([string]$role) {
    if ($Services) {
        $out = Relay @('start', '--instance', $role)
        if ($exitCode -ne 0) { throw "démarrage du service $role : $out" }
    } else {
        Start-Background $role $bin @('run', '-c', (Config $role)) | Out-Null
    }
    if (-not (Wait-Until { Relay @('status', '-c', (Config $role)) | Out-Null; $exitCode -eq 0 } 20)) {
        throw "$role ne répond pas sur son canal d'administration"
    }
}

function Stop-Relay([string]$role, [string]$how = 'stop') {
    $out = Relay @($how, '-c', (Config $role))
    if ($exitCode -ne 0) { throw "$how $role : $out" }
    if ($Services) {
        (Get-Service "tlsrelay-$role").WaitForStatus('Stopped', '00:00:30')
    } else {
        foreach ($entry in @($processes | Where-Object { $_.Name -eq $role })) {
            if (-not $entry.Process.WaitForExit(30000)) { throw "$role ne s'est pas arrêté" }
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

# Charge : N canaux simultanés, empreinte SHA-256 par canal.
function Test-Load([int]$port, [int]$count, [string]$bytes = '256KiB') {
    $r = KitJson @('load', '--target', "$($A.Client):$port", '--channels', "$count", '--bytes', $bytes)
    Note ("  {0} canaux, {1} intègres, {2} en échec, {3:N0} Mbit/s agrégés" -f $r.channels, $r.ok, $r.failed, $r.mbit_per_s)
    if ($r.failed -gt 0) { $r.errors | Select-Object -First 5 | ForEach-Object { Note "  $_" } }
    return ($r.ok -eq $count -and $r.failed -eq 0)
}

# ---------------------------------------------------------------------------
# Scénarios

$aborted = $null
$cleanup = {
    if ($Keep -and -not $aborted) {
        # Étapes manuelles : tout reste en service ; script d'arrêt pour la suite.
        $lines = @('# Arrêt de la recette tlsrelay (généré par recette.ps1 -Keep)')
        foreach ($entry in @($processes | Where-Object { -not $_.Process.HasExited })) { $lines += "Stop-Process -Id $($entry.Process.Id) -Force -ErrorAction SilentlyContinue  # $($entry.Name)" }
        if ($Services) { foreach ($role in 'rc-client', 'rc-server') { $lines += "& '$bin' service uninstall --instance $role" } }
        if ($socketDir) { $lines += "Remove-Item -Recurse -Force '$socketDir' -ErrorAction SilentlyContinue" }
        $lines | Set-Content -Encoding utf8 (Join-Path $WorkDir 'arret-recette.ps1')
        Write-Host "Instances laissées en service ; arrêt : $(Join-Path $WorkDir 'arret-recette.ps1')"
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

    Scenario 'R01' 'PKI de recette par la mini-AC (ca init, gen-csr, ca sign, pki install)' {
        Write-Configs
        Write-Whitelist
        $ac = Join-Path $WorkDir 'ac'
        $out = Relay @('ca', 'init', '--dir', $ac, '--org', 'Recette'); Check ($exitCode -eq 0) 'ca init (racine, AC Serveurs, AC Clients)'
        foreach ($spec in @(@{ Role = 'rc-server'; Kind = 'server'; Subject = 'CN=relay.recette,O=Recette'; San = @('--san', 'relay.recette') },
                            @{ Role = 'rc-client'; Kind = 'client'; Subject = 'CN=rc-client,O=Recette'; San = @() })) {
            $cfg = Config $spec.Role
            $out = Relay (@('pki', 'gen-csr', '-c', $cfg, '--subject', $spec.Subject) + $spec.San); Check ($exitCode -eq 0) "$($spec.Role) : demande de certificat"
            $kitDir = Join-Path $WorkDir "kit-$($spec.Role)"
            $out = Relay (@('ca', 'sign', '--dir', $ac, '--role', $spec.Kind, '--csr', (Join-Path $WorkDir "pki/$($spec.Role)/v1/request.csr"), '--out', $kitDir) + $spec.San)
            Check ($exitCode -eq 0) "$($spec.Role) : signature par l'AC"
            $out = Relay @('pki', 'install', '-c', $cfg, '--from', $kitDir); Check ($exitCode -eq 0) "$($spec.Role) : installation du certificat"
            $out = Relay @('pki', 'activate', '-c', $cfg, 'v1'); Check ($exitCode -eq 0) "$($spec.Role) : activation de la génération v1"
            $out = Relay @('check-pki', '-c', $cfg); Check ($exitCode -eq 0) "$($spec.Role) : check-pki"
        }
        $out = Relay @('ca', 'sign', '--dir', $ac, '--role', 'client', '--csr', (Join-Path $WorkDir 'pki/rc-client/v1/request.csr'), '--out', (Join-Path $WorkDir 'kit-double'))
        Check ($exitCode -ne 0) 'sujet déjà attribué refusé par l''AC'
    }

    Scenario 'R02' 'Démarrage des instances' {
        foreach ($role in 'rc-server', 'rc-client') {
            $out = Relay @('check-config', '-c', (Config $role)); Check ($exitCode -eq 0) "$role : configuration valide"
        }
        Start-Background 'echo' $kit @('echo', '--listen', "$($A.Dest):$($P.Dest)") | Out-Null
        Start-Proxy
        if ($Services) {
            foreach ($role in 'rc-server', 'rc-client') {
                $out = Relay @('service', 'install', '--instance', $role, '-c', (Config $role)); Check ($exitCode -eq 0) "$role : service installé"
                $account = "NT SERVICE\tlsrelay-$role"
                # Fichiers de l'instance lisibles par son seul compte et les administrateurs (SPEC §10.3).
                foreach ($path in (Join-Path $WorkDir "pki/$role"), (Config $role)) {
                    & icacls $path /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' "${account}:(OI)(CI)R" | Out-Null
                }
            }
            & icacls (Join-Path $WorkDir 'whitelist.yaml') /grant 'NT SERVICE\tlsrelay-rc-server:R' | Out-Null
            & icacls (Join-Path $WorkDir 'logs') /grant 'NT SERVICE\tlsrelay-rc-server:(OI)(CI)M' 'NT SERVICE\tlsrelay-rc-client:(OI)(CI)M' | Out-Null
        }
        Start-Relay 'rc-server'
        Start-Relay 'rc-client'
        $status = Relay @('status', '-c', (Config 'rc-server'))
        Check ($status -match 'génération PKI : v1') 'serveur : génération PKI v1'
        Check ($status -match 'liste blanche : 1 pair') 'serveur : liste blanche chargée'
        if ($Services) {
            foreach ($role in 'rc-server', 'rc-client') {
                $svc = Get-CimInstance Win32_Service -Filter "Name='tlsrelay-$role'"
                Check ($svc.StartName -eq "NT SERVICE\tlsrelay-$role") "$role : compte virtuel du service"
            }
        }
    }

    if (-not $results[-1].Ok) { throw "démarrage des instances en échec : scénarios suivants non exécutés" }

    Scenario 'R03' "Canaux simultanés intègres sur les trois ports ($channels par port)" {
        Check (Test-Load $P.ClientPlain $channels) 'port plain'
        Check (Test-Load $P.ClientTls $channels) 'port tls'
        Check (Test-Load $P.ClientMtls $channels) 'port mtls (via le proxy)'
    }

    Scenario 'R04' 'Débit et latence ajoutée (port tls)' {
        $t = KitJson @('throughput', '--target', "$($A.Client):$($P.ClientTls)", '--duration', "$($durations.Throughput)s", '--rate', '200')
        Note ("  débit : {0:N0} Mbit/s dans chaque sens (cadencé à 200)" -f $t.mbit_per_s)
        Check ($t.intact -eq 1 -and $t.mbit_per_s -ge 100) 'débit ≥ 100 Mbit/s, flux intègre'
        $direct = KitJson @('latency', '--target', "$($A.Dest):$($P.Dest)", '--count', '2000')
        $relay = KitJson @('latency', '--target', "$($A.Client):$($P.ClientTls)", '--count', '2000')
        $added = ($relay.p50_us - $direct.p50_us) / 1000
        Note ("  latence p50 : directe {0:N0} µs, via tlsrelay {1:N0} µs, ajoutée {2:N3} ms" -f $direct.p50_us, $relay.p50_us, $added)
        Check ($added -lt 1.0) 'latence ajoutée < 1 ms'
    }

    Scenario 'R05' 'Liste blanche : adresse retirée puis rétablie' {
        $before = Metric 'rc-server' 'peers_rejected_total'
        Write-Whitelist '127.0.0.9'
        $out = Relay @('reload', '-c', (Config 'rc-server')); Check ($exitCode -eq 0) 'rechargement de la liste blanche'
        $r = KitJson @('load', '--target', "$($A.Client):$($P.ClientTls)", '--channels', '5', '--bytes', '1KiB')
        Check ($r.ok -eq 0) 'nouveaux canaux refusés pour une adresse non listée'
        Check ((Metric 'rc-server' 'peers_rejected_total') -gt $before) 'refus comptés (peers_rejected_total)'
        Write-Whitelist
        $out = Relay @('reload', '-c', (Config 'rc-server'))
        Check (Test-Load $P.ClientTls 20 '64KiB') 'canaux acceptés après rétablissement'
    }

    Scenario 'R06' 'Coupures réseau : reprise de session sans perte (port mtls)' {
        $before = Metric 'rc-client' 'renegotiations_total'
        Start-Proxy @('--cut-every', '5s')
        $t = KitJson @('throughput', '--target', "$($A.Client):$($P.ClientMtls)", '--duration', "$($durations.Cuts)s", '--rate', '50')
        Start-Proxy
        Note ("  {0:N1} Mio transférés malgré les coupures" -f ($t.bytes / 1MB))
        Check ($t.intact -eq 1) 'flux intègre à travers les coupures'
        Check ((Metric 'rc-client' 'renegotiations_total') -gt $before) 'reprises de session effectuées'
    }

    Scenario 'R07' "Renégociation transparente (session_lifetime ${lifetime}s)" {
        $before = Metric 'rc-client' 'renegotiations_total'
        $t = KitJson @('throughput', '--target', "$($A.Client):$($P.ClientTls)", '--duration', "$($durations.Renegotiation)s", '--rate', '50')
        $count = (Metric 'rc-client' 'renegotiations_total') - $before
        Note ("  {0} renégociation(s) pendant {1} s de flux continu" -f $count, $durations.Renegotiation)
        Check ($t.intact -eq 1) 'flux continu intègre'
        Check ($count -ge 1) 'renégociations effectuées sans coupure de l''application'
    }

    Scenario 'R08' 'Rotation de la PKI à chaud (génération v2)' {
        $ac = Join-Path $WorkDir 'ac'
        $cfg = Config 'rc-server'
        $out = Relay @('pki', 'gen-csr', '-c', $cfg, '--subject', 'CN=relay.recette,O=Recette', '--san', 'relay.recette'); Check ($exitCode -eq 0) 'demande v2'
        $out = Relay @('ca', 'sign', '--dir', $ac, '--role', 'server', '--csr', (Join-Path $WorkDir 'pki/rc-server/v2/request.csr'), '--san', 'relay.recette', '--renew', '--out', (Join-Path $WorkDir 'kit-v2'))
        Check ($exitCode -eq 0) 'renouvellement signé par l''AC'
        $out = Relay @('pki', 'install', '-c', $cfg, '--from', (Join-Path $WorkDir 'kit-v2')); Check ($exitCode -eq 0) 'installation v2'
        $out = Relay @('pki', 'activate', '-c', $cfg, 'v2'); Check ($exitCode -eq 0) 'activation v2'
        $out = Relay @('reload', '-c', $cfg); Check ($exitCode -eq 0) 'rechargement'
        Check ((Relay @('status', '-c', $cfg)) -match 'génération PKI : v2') 'génération courante v2'
        Check (Test-Load $P.ClientMtls 50 '64KiB') 'nouveaux canaux sur la génération v2'
        Check ((Metric 'rc-server' 'pki_rotations_total') -ge 1) 'bascule comptée'
    }

    Scenario 'R09' 'Changement de racine en trois étapes, sans interruption (SPEC §7.5)' {
        $ac = Join-Path $WorkDir 'ac'
        $ac2 = Join-Path $WorkDir 'ac2'
        $out = Relay @('ca', 'init', '--dir', $ac2, '--org', 'Recette'); Check ($exitCode -eq 0) 'nouvelle AC (racine, AC Serveurs, AC Clients)'
        $roots = Join-Path $WorkDir 'racines-ancienne-et-nouvelle.pem'
        (Get-Content (Join-Path $ac 'root.cert.pem') -Raw) + (Get-Content (Join-Path $ac2 'root.cert.pem') -Raw) | Set-Content -NoNewline -Encoding ascii $roots
        # AC attendue chez le pair : AC Clients pour le serveur, AC Serveurs pour le client.
        $issuers = @{}
        foreach ($pair in @(@('rc-server', 'clients'), @('rc-client', 'servers'))) {
            $file = Join-Path $WorkDir "emetteurs-$($pair[0]).pem"
            (Get-Content (Join-Path $ac "$($pair[1]).cert.pem") -Raw) + (Get-Content (Join-Path $ac2 "$($pair[1]).cert.pem") -Raw) |
                Set-Content -NoNewline -Encoding ascii $file
            $issuers[$pair[0]] = $file
        }
        $instances = @(@{ Role = 'rc-server'; Kind = 'server'; Subject = 'CN=relay.recette,O=Recette'; San = @('--san', 'relay.recette') },
                       @{ Role = 'rc-client'; Kind = 'client'; Subject = 'CN=rc-client,O=Recette'; San = @() })
        # Nouvelle génération pour une instance : demande, signature par l'AC donnée, installation, activation.
        $nextGeneration = {
            param($spec, [string]$caDir, [bool]$renew, [string[]]$trust, [string]$step)
            $cfg = Config $spec.Role
            $out = Relay (@('pki', 'gen-csr', '-c', $cfg, '--subject', $spec.Subject) + $spec.San)
            $generation = [regex]::Match($out, 'génération « (v\d+) »').Groups[1].Value
            if (-not $generation) { $generation = (Get-ChildItem (Join-Path $WorkDir "pki/$($spec.Role)") -Directory | Sort-Object { [int]($_.Name.TrimStart('v')) } | Select-Object -Last 1).Name }
            $kitDir = Join-Path $WorkDir "kit-$($spec.Role)-$step"
            $sign = @('ca', 'sign', '--dir', $caDir, '--role', $spec.Kind, '--csr', (Join-Path $WorkDir "pki/$($spec.Role)/$generation/request.csr"), '--out', $kitDir) + $spec.San
            if ($renew) { $sign += '--renew' }
            $out = Relay $sign
            if ($exitCode -ne 0) { throw "$($spec.Role) : signature ($step) : $out" }
            $out = Relay (@('pki', 'install', '-c', $cfg, '--from', $kitDir) + $trust)
            if ($exitCode -ne 0) { throw "$($spec.Role) : installation ($step) : $out" }
            $out = Relay @('pki', 'activate', '-c', $cfg, $generation)
            if ($exitCode -ne 0) { throw "$($spec.Role) : activation ($step) : $out" }
            $out = Relay @('reload', '-c', $cfg)
            if ($exitCode -ne 0) { throw "$($spec.Role) : rechargement ($step) : $out" }
            return $generation
        }
        # Flux continu pendant toute la procédure.
        $fluxSeconds = if ($Quick) { 20 } else { 40 }
        Start-Background 'flux-racine' $kit @('throughput', '--target', "$($A.Client):$($P.ClientMtls)", '--duration', "${fluxSeconds}s", '--rate', '20', '--json') | Out-Null
        Start-Sleep -Seconds 1

        foreach ($spec in $instances) { $g = & $nextGeneration $spec $ac $true @('--roots', $roots, '--issuer', $issuers[$spec.Role]) 'etape1' }
        Check (Test-Load $P.ClientMtls 20 '64KiB') 'étape 1 (pré-confiance : deux racines, ancienne PKI) : canaux mtls'
        foreach ($spec in $instances) { $g = & $nextGeneration $spec $ac2 $false @('--roots', $roots, '--issuer', $issuers[$spec.Role]) 'etape2' }
        Check (Test-Load $P.ClientMtls 20 '64KiB') 'étape 2 (bascule : nouvelle PKI, deux racines) : canaux mtls'
        Check (Test-Load $P.ClientTls 20 '64KiB') 'étape 2 : canaux tls'
        foreach ($spec in $instances) { $g = & $nextGeneration $spec $ac2 $true @() 'etape3' }
        Check (Test-Load $P.ClientMtls 20 '64KiB') 'étape 3 (retrait de l''ancienne racine) : canaux mtls'
        $status = Relay @('status', '-c', (Config 'rc-server'))
        Note "  serveur : $(($status -split "`n" | Where-Object { $_ -match 'génération PKI' }))"

        $flux = $processes | Where-Object { $_.Name -eq 'flux-racine' } | Select-Object -First 1
        $flux.Process.WaitForExit(($fluxSeconds + 30) * 1000) | Out-Null
        $line = Get-Content (Join-Path $WorkDir 'flux-racine.out.log') | Where-Object { $_.TrimStart().StartsWith('{') } | Select-Object -Last 1
        $t = if ($line) { $line | ConvertFrom-Json } else { $null }
        Check ($t -and $t.intact -eq 1) 'flux continu intègre pendant les trois étapes'
        Check ((Metric 'rc-server' 'pki_reload_failures_total') -eq 0 -and (Metric 'rc-client' 'pki_reload_failures_total') -eq 0) 'aucune génération refusée'
    }

    Scenario 'R10' 'Journalisation : niveaux à chaud, aucune donnée relayée dans les journaux' {
        $out = Relay @('log-level', '-c', (Config 'rc-server'), 'debug'); Check ($exitCode -eq 0) 'niveau debug à chaud'
        $marker = "DONNEE-DE-RECETTE-$stamp"
        Check ((Send-Text $P.ClientTls $marker) -eq $marker) 'marqueur relayé et renvoyé par l''écho'
        Check (Test-Load $P.ClientTls 5 '4KiB') 'trafic au niveau debug' 
        $out = Relay @('log-level', '-c', (Config 'rc-server'), 'info'); Check ($exitCode -eq 0) 'retour au niveau info'
        $serverLog = Get-Content (LogFile 'rc-server') -Raw
        Check ($serverLog -match 'canal=\d+ ouvert') 'canaux journalisés au niveau debug'
        $all = (Get-ChildItem (Join-Path $WorkDir 'logs') -File | ForEach-Object { Get-Content $_.FullName -Raw }) -join "`n"
        Check (-not $all.Contains($marker)) 'données relayées absentes des journaux'
        Check (-not ($all -match 'PRIVATE KEY')) 'aucune clé privée dans les journaux'
        Check (-not $all.Contains($env:TLSRELAY_CA_PASSPHRASE)) 'aucune phrase de passe dans les journaux'
    }

    Scenario 'R11' 'Administration : status, channels, metrics' {
        $out = Relay @('status', '-c', (Config 'rc-client')); Check ($exitCode -eq 0 -and $out -match 'instance : rc-client') 'status'
        $out = Relay @('channels', '-c', (Config 'rc-server')); Check ($exitCode -eq 0 -and $out -match 'canal\(aux\)') 'channels'
        $out = Relay @('metrics', '-c', (Config 'rc-server')); Check ($exitCode -eq 0 -and $out -match 'tlsrelay_channels_opened_total') 'metrics (Prometheus)'
    }

    Scenario 'R12' 'Cycle de vie : arrêt avec drain, redémarrage, arrêt immédiat' {
        Stop-Relay 'rc-client' 'stop'
        Note '  client arrêté proprement'
        Start-Relay 'rc-client'
        Check (Test-Load $P.ClientTls 10 '16KiB') 'client redémarré opérationnel'
        Stop-Relay 'rc-server' 'kill'
        Note '  serveur arrêté immédiatement (kill)'
        Start-Relay 'rc-server'
        Check (Test-Load $P.ClientTls 10 '16KiB') 'serveur redémarré opérationnel'
        if ($Services) {
            $pid1 = (Get-CimInstance Win32_Service -Filter "Name='tlsrelay-rc-server'").ProcessId
            $out = Relay @('restart', '--instance', 'rc-server'); Check ($exitCode -eq 0) 'restart du service'
            $pid2 = (Get-CimInstance Win32_Service -Filter "Name='tlsrelay-rc-server'").ProcessId
            Check ($pid1 -ne $pid2 -and $pid2 -ne 0) 'nouveau processus après restart'
        }
        Check (-not ((Get-Content (LogFile 'rc-server') -Raw) -match 'exception inattendue')) 'aucune exception inattendue journalisée'
    }

    if ($LinuxHost) {
        Scenario 'R13' "Tests croisés avec Linux ($LinuxHost)" {
            $out = & (Join-Path $PSScriptRoot 'recette-linux.ps1') -LinuxHost $LinuxHost -LinuxBuildDir $LinuxBuildDir `
                -LocalAddress $LocalAddress -WorkDir $WorkDir -Bin $bin -Kit $kit -SshPort $SshPort 6>&1 | Out-String
            $code = $LASTEXITCODE
            $out -split "`r?`n" | Where-Object { $_.Trim() } | ForEach-Object { Note "  $($_.Trim())" }
            Check ($code -eq 0) 'station → Linux et Linux → station'
        }
    }
} catch {
    Write-Host "ARRÊT : $($_.Exception.Message)"
    $aborted = $_.Exception.Message
} finally {
    & $cleanup
    if ($socketDir -and -not $Keep) { Remove-Item -Recurse -Force $socketDir -ErrorAction SilentlyContinue }
}

# ---------------------------------------------------------------------------
# Rapport

$ok = @($results | Where-Object { $_.Ok }).Count
$report = [System.Collections.Generic.List[string]]::new()
$report.Add("# Rapport de recette tlsrelay")
$report.Add("")
$report.Add("| | |")
$report.Add("|---|---|")
$report.Add("| Date | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') |")
$report.Add("| Station | $([System.Environment]::MachineName) — $osText |")
$report.Add("| Mode | $(if ($Services) { 'services Windows' } else { 'console' })$(if ($Quick) { ', durées réduites' }) |")
$report.Add("| Version | $($versionText -replace "`r?`n", ' ; ') |")
$report.Add("| Résultat | **$ok / $($results.Count) scénarios automatisés OK**$(if ($aborted) { " — recette interrompue : $aborted" }) |")
$report.Add("")
$report.Add("Empreintes SHA-256 des binaires :")
$report.Add("")
$report.Add('```')
$hashes | ForEach-Object { $report.Add($_) }
$report.Add('```')
$report.Add("")
$report.Add("## Scénarios automatisés")
$report.Add("")
$report.Add("| N° | Scénario | Résultat | Durée |")
$report.Add("|---|---|---|---|")
foreach ($r in $results) { $report.Add("| $($r.Id) | $($r.Title) | $(if ($r.Ok) { 'OK' } else { '**KO**' }) | $($r.Seconds) s |") }
foreach ($r in $results) {
    $report.Add("")
    $report.Add("### $($r.Id) — $($r.Title)")
    $report.Add("")
    $r.Notes | ForEach-Object { $report.Add("- $($_.Trim())") }
    if ($r.Logs) {
        $report.Add("")
        $report.Add("Extraits des journaux :")
        $report.Add("")
        $report.Add('```')
        $r.Logs | ForEach-Object { $report.Add($_) }
        $report.Add('```')
    }
}
$report.Add("")
$report.Add("## Étapes manuelles")
$report.Add("")
$report.Add("À dérouler selon le cahier de recette (docs/RECETTE.md, section 4) et à reporter dans le procès-verbal.")
$reportPath = Join-Path $WorkDir 'rapport.md'
$report | Set-Content -Encoding utf8 $reportPath

Write-Host ""
Write-Host "Rapport : $reportPath"
Write-Host "$ok / $($results.Count) scénarios automatisés OK"
if ($aborted -or $ok -ne $results.Count) { exit 1 }
exit 0
