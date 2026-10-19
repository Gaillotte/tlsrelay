# Command-line PKI on Windows (SPEC §7.6): ca init, pki gen-csr,
# ca sign, pki install, check-pki, refusal of an already assigned subject, ACLs of
# the CA keys.
# Usage: windows-pki.ps1 <directory containing tlsrelay.exe and its DLLs>
param([Parameter(Mandatory = $true)][string]$BuildDir)
$ErrorActionPreference = 'Stop'
$bin = (Resolve-Path "$BuildDir\tlsrelay.exe").Path
$work = Join-Path $env:RUNNER_TEMP "tlsrelay-pki"
if (-not $work -or $work -eq "tlsrelay-pki") { $work = Join-Path $env:TEMP "tlsrelay-pki" }
Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $work | Out-Null
Set-Location $work
$env:TLSRELAY_CA_PASSPHRASE = "test passphrase"

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8  # tlsrelay output in UTF-8
function Fail($message) { Write-Host "FAILED: $message"; exit 1 }
function Check($what) { if ($LASTEXITCODE -ne 0) { Fail $what } }

@"
mode: server
instance: srv
credentials: { pki_root: '$work\pki' }
whitelist: { file: '$work\wl.yaml' }
destination: { address: 127.0.0.1, port: 18080 }
admin: { enabled: false }
ports:
  tls: { listen: "127.0.0.1:19002" }
"@ | Set-Content -Encoding utf8 server.yaml
"peers: []" | Set-Content -Encoding utf8 wl.yaml

& $bin ca init --dir ca --org Test; Check "ca init"
$acl = (Get-Acl ca\root.key.pem)
if (-not $acl.AreAccessRulesProtected) { Fail "root key ACL not protected" }
if ($acl.Access | Where-Object { $_.IdentityReference -match 'Users|Utilisateurs|Everyone' }) { Fail "root key readable by everyone" }

& $bin pki gen-csr -c server.yaml --subject "CN=relay.test,O=Test" --san relay.test; Check "gen-csr"
& $bin ca sign --dir ca --role server --csr pki\v1\request.csr --san relay.test --out kit; Check "ca sign"
& $bin pki install -c server.yaml --from kit; Check "pki install"
& $bin pki activate -c server.yaml v1; Check "pki activate"
& $bin check-pki -c server.yaml; Check "check-pki"

& $bin pki gen-csr -c server.yaml --subject "CN=relay.test,O=Test"; Check "gen-csr v2"
& $bin ca sign --dir ca --role server --csr pki\v2\request.csr --san relay.test --out kit2 2>$null
if ($LASTEXITCODE -eq 0) { Fail "already assigned subject accepted" }
& $bin ca sign --dir ca --role server --csr pki\v2\request.csr --san relay.test --renew --out kit2; Check "renewal"
& $bin pki install -c server.yaml --from kit2; Check "pki install v2"
& $bin check-pki -c server.yaml v2; Check "check-pki v2"
$serial = (Get-Content ca\index.tsv | Where-Object { $_ -match "`treplaced`t" } | ForEach-Object { ($_ -split "`t")[0] })
if (-not $serial) { Fail "serial of the replaced certificate" }
& $bin ca revoke --dir ca --serial $serial --reason superseded --out crl.pem; Check "ca revoke"
if (-not (Select-String -Path crl.pem -Pattern "BEGIN X509 CRL" -Quiet)) { Fail "CRL not written" }
& $bin ca list --dir ca | Tee-Object -Variable listing
if (-not ($listing -match "revoked on")) { Fail "inventory after revocation" }
& $bin ca audit --dir ca | Tee-Object -Variable audit; Check "ca audit"
if (-not ($audit -match "$([regex]::Escape($env:USERNAME))\s+revoke")) { Fail "operator missing from the audit log" }
Write-Host "command-line PKI on Windows: OK"
exit 0
