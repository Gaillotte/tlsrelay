# Cycle de vie d'un service Windows (SPEC §10), à exécuter en administrateur :
# installation (compte virtuel NT SERVICE\tlsrelay-ci), démarrage, relais,
# reload, restart, stop, arrêt par le gestionnaire de services, kill,
# désinstallation.
# Usage : windows-service.ps1 <répertoire contenant tlsrelay.exe et ses DLL>
param([Parameter(Mandatory = $true)][string]$BuildDir)
$ErrorActionPreference = 'Stop'
$env:PYTHONIOENCODING = 'utf-8'
$here = $PSScriptRoot

function Fail($message) {
    Write-Host "ÉCHEC : $message"
    $log = "$env:ProgramData\tlsrelay\logs\ci.log"
    if (Test-Path $log) { Get-Content $log -Tail 40 }
    exit 1
}
function Step($message) { Write-Host "== $message" }
function Run([string[]]$arguments) {
    $out = & $script:bin @arguments 2>&1 | Out-String
    $script:code = $LASTEXITCODE
    Write-Host $out.TrimEnd()
    return $out
}

# Binaire installé hors du répertoire de travail, lisible par le compte du service.
$install = "$env:ProgramFiles\tlsrelay-ci"
New-Item -ItemType Directory -Force -Path $install | Out-Null
Copy-Item "$BuildDir\*.exe", "$BuildDir\*.dll" $install
$script:bin = "$install\tlsrelay.exe"

$data = "$env:ProgramData\tlsrelay"
New-Item -ItemType Directory -Force -Path $data | Out-Null
@"
peers:
  - { name: local, ip: 127.0.0.1, ports: [plain] }
"@ | Set-Content -Encoding utf8 "$data\ci-whitelist.yaml"
@"
mode: server
instance: ci
whitelist: { file: '$data\ci-whitelist.yaml' }
destination: { address: 127.0.0.1, port: 18080 }
limits: { shutdown_timeout: 3s }
ports:
  plain: { listen: "127.0.0.1:19001" }
"@ | Set-Content -Encoding utf8 "$data\ci.yaml"
@"
mode: client
instance: ci-client
admin: { enabled: false }
ports:
  plain: { listen: "127.0.0.1:17001", upstream: "127.0.0.1:19001" }
"@ | Set-Content -Encoding utf8 "$data\ci-client.yaml"

$echo = Start-Process python -ArgumentList "`"$here\echo.py`" 18080" -PassThru -WindowStyle Hidden
$client = $null
try {
    Step "installation avec démarrage au boot"
    Run @('service', 'install', '--instance', 'ci', '--boot') | Out-Null
    if ($code -ne 0) { Fail "installation" }
    $svc = Get-CimInstance Win32_Service -Filter "Name='tlsrelay-ci'"
    if ($svc.StartMode -ne 'Auto') { Fail "démarrage au boot : $($svc.StartMode)" }
    if ($svc.StartName -ne 'NT SERVICE\tlsrelay-ci') { Fail "compte du service : $($svc.StartName)" }

    Step "démarrage"
    Run @('start', '--instance', 'ci') | Out-Null
    if ($code -ne 0) { Fail "démarrage" }
    if ((Get-Service tlsrelay-ci).Status -ne 'Running') { Fail "service arrêté" }
    $out = Run @('status', '--instance', 'ci')
    if ($out -notmatch 'instance : ci') { Fail "status" }

    Step "relais de données à travers le service"
    $client = Start-Process $bin -ArgumentList "run -c `"$data\ci-client.yaml`"" -PassThru -WindowStyle Hidden
    Start-Sleep -Milliseconds 800
    python "$here\exchange.py" 17001
    if ($LASTEXITCODE -ne 0) { Fail "échange" }

    Step "rechargement"
    $out = Run @('reload', '--instance', 'ci')
    if ($out -notmatch 'liste blanche : 1 pair') { Fail "reload" }
    if ($out -match 'redémarrage nécessaire') { Fail "reload : changement signalé à tort" }

    Step "redémarrage"
    $pid1 = (Get-CimInstance Win32_Service -Filter "Name='tlsrelay-ci'").ProcessId
    Run @('restart', '--instance', 'ci') | Out-Null
    if ($code -ne 0) { Fail "restart" }
    $pid2 = (Get-CimInstance Win32_Service -Filter "Name='tlsrelay-ci'").ProcessId
    if ($pid1 -eq $pid2 -or $pid2 -eq 0) { Fail "PID inchangé après restart" }
    python "$here\exchange.py" 17001
    if ($LASTEXITCODE -ne 0) { Fail "échange après restart" }

    Step "arrêt propre"
    Run @('stop', '--instance', 'ci') | Out-Null
    if ($code -ne 0) { Fail "stop" }
    (Get-Service tlsrelay-ci).WaitForStatus('Stopped', '00:00:20')

    Step "arrêt par le gestionnaire de services (Stop-Service)"
    Run @('start', '--instance', 'ci') | Out-Null
    Stop-Service tlsrelay-ci
    (Get-Service tlsrelay-ci).WaitForStatus('Stopped', '00:00:20')
    if ((Get-Content "$data\logs\ci.log" -Raw) -notmatch 'service arrêté') { Fail "arrêt propre non journalisé" }

    Step "arrêt immédiat"
    Run @('start', '--instance', 'ci') | Out-Null
    Run @('kill', '--instance', 'ci') | Out-Null
    if ($code -ne 0) { Fail "kill" }
    (Get-Service tlsrelay-ci).WaitForStatus('Stopped', '00:00:20')

    Step "configuration devenue invalide : cause du refus dans le journal du service"
    $good = Get-Content "$data\ci.yaml" -Raw
    "$good`ninconnu: 1" | Set-Content -Encoding utf8 "$data\ci.yaml"
    Run @('start', '--instance', 'ci') | Out-Null
    $good | Set-Content -NoNewline -Encoding utf8 "$data\ci.yaml"
    if ($code -eq 0) { Fail "démarrage accepté avec une configuration invalide" }
    $log = Get-Content "$data\logs\ci.log" -Raw
    if ($log -notmatch 'configuration .* refusée' -or $log -notmatch 'inconnu') { Fail "cause du refus absente du journal du service" }

    Step "désinstallation"
    Run @('service', 'uninstall', '--instance', 'ci') | Out-Null
    if ($code -ne 0) { Fail "désinstallation" }
    if (Get-Service tlsrelay-ci -ErrorAction SilentlyContinue) { Fail "service encore présent" }
    Write-Host "cycle de vie du service Windows : OK"
}
finally {
    if ($client) { Stop-Process -Id $client.Id -Force -ErrorAction SilentlyContinue }
    Stop-Process -Id $echo.Id -Force -ErrorAction SilentlyContinue
    & $bin service uninstall --instance ci 2>$null | Out-Null
}
exit 0
