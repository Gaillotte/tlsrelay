# Windows service lifecycle (SPEC §10), to be run as administrator:
# installation (virtual account NT SERVICE\tlsrelay-ci), startup, relaying,
# reload, restart, stop, stop through the service manager, kill,
# uninstallation.
# Usage: windows-service.ps1 <directory containing tlsrelay.exe and its DLLs>
param([Parameter(Mandatory = $true)][string]$BuildDir)
$ErrorActionPreference = 'Stop'
$env:PYTHONIOENCODING = 'utf-8'
$here = $PSScriptRoot

function Fail($message) {
    Write-Host "FAILED: $message"
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

# Binary installed outside the working directory, readable by the service account.
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
    Step "installation with start at boot"
    Run @('service', 'install', '--instance', 'ci', '--boot') | Out-Null
    if ($code -ne 0) { Fail "installation" }
    $svc = Get-CimInstance Win32_Service -Filter "Name='tlsrelay-ci'"
    if ($svc.StartMode -ne 'Auto') { Fail "start at boot: $($svc.StartMode)" }
    if ($svc.StartName -ne 'NT SERVICE\tlsrelay-ci') { Fail "service account: $($svc.StartName)" }

    Step "startup"
    Run @('start', '--instance', 'ci') | Out-Null
    if ($code -ne 0) { Fail "startup" }
    if ((Get-Service tlsrelay-ci).Status -ne 'Running') { Fail "service stopped" }
    $out = Run @('status', '--instance', 'ci')
    if ($out -notmatch 'instance: ci') { Fail "status" }

    Step "relaying data through the service"
    $client = Start-Process $bin -ArgumentList "run -c `"$data\ci-client.yaml`"" -PassThru -WindowStyle Hidden
    Start-Sleep -Milliseconds 800
    python "$here\exchange.py" 17001
    if ($LASTEXITCODE -ne 0) { Fail "exchange" }

    Step "reload"
    $out = Run @('reload', '--instance', 'ci')
    if ($out -notmatch 'whitelist: 1 peer') { Fail "reload" }
    if ($out -match 'restart required') { Fail "reload: change wrongly reported" }

    Step "restart"
    $pid1 = (Get-CimInstance Win32_Service -Filter "Name='tlsrelay-ci'").ProcessId
    Run @('restart', '--instance', 'ci') | Out-Null
    if ($code -ne 0) { Fail "restart" }
    $pid2 = (Get-CimInstance Win32_Service -Filter "Name='tlsrelay-ci'").ProcessId
    if ($pid1 -eq $pid2 -or $pid2 -eq 0) { Fail "PID unchanged after restart" }
    python "$here\exchange.py" 17001
    if ($LASTEXITCODE -ne 0) { Fail "exchange after restart" }

    Step "graceful stop"
    Run @('stop', '--instance', 'ci') | Out-Null
    if ($code -ne 0) { Fail "stop" }
    (Get-Service tlsrelay-ci).WaitForStatus('Stopped', '00:00:20')

    Step "stop through the service manager (Stop-Service)"
    Run @('start', '--instance', 'ci') | Out-Null
    Stop-Service tlsrelay-ci
    (Get-Service tlsrelay-ci).WaitForStatus('Stopped', '00:00:20')
    if ((Get-Content "$data\logs\ci.log" -Raw) -notmatch 'service stopped') { Fail "graceful stop not logged" }

    Step "immediate stop"
    Run @('start', '--instance', 'ci') | Out-Null
    Run @('kill', '--instance', 'ci') | Out-Null
    if ($code -ne 0) { Fail "kill" }
    (Get-Service tlsrelay-ci).WaitForStatus('Stopped', '00:00:20')

    Step "configuration made invalid: cause of the refusal in the service log"
    $good = Get-Content "$data\ci.yaml" -Raw
    "$good`nunknown_entry: 1" | Set-Content -Encoding utf8 "$data\ci.yaml"
    Run @('start', '--instance', 'ci') | Out-Null
    $good | Set-Content -NoNewline -Encoding utf8 "$data\ci.yaml"
    if ($code -eq 0) { Fail "startup accepted with an invalid configuration" }
    $log = Get-Content "$data\logs\ci.log" -Raw
    if ($log -notmatch 'configuration .* rejected' -or $log -notmatch 'unknown_entry') { Fail "cause of the refusal missing from the service log" }

    Step "uninstallation"
    Run @('service', 'uninstall', '--instance', 'ci') | Out-Null
    if ($code -ne 0) { Fail "uninstallation" }
    if (Get-Service tlsrelay-ci -ErrorAction SilentlyContinue) { Fail "service still present" }
    Write-Host "Windows service lifecycle: OK"
}
finally {
    if ($client) { Stop-Process -Id $client.Id -Force -ErrorAction SilentlyContinue }
    Stop-Process -Id $echo.Id -Force -ErrorAction SilentlyContinue
    & $bin service uninstall --instance ci 2>$null | Out-Null
}
exit 0
