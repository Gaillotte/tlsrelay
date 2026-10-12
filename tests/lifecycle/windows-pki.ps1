# PKI en ligne de commande sous Windows (SPEC §7.6) : ca init, pki gen-csr,
# ca sign, pki install, check-pki, refus d'un sujet déjà attribué, ACL des
# clés de l'AC.
# Usage : windows-pki.ps1 <répertoire contenant tlsrelay.exe et ses DLL>
param([Parameter(Mandatory = $true)][string]$BuildDir)
$ErrorActionPreference = 'Stop'
$bin = (Resolve-Path "$BuildDir\tlsrelay.exe").Path
$work = Join-Path $env:RUNNER_TEMP "tlsrelay-pki"
if (-not $work -or $work -eq "tlsrelay-pki") { $work = Join-Path $env:TEMP "tlsrelay-pki" }
Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $work | Out-Null
Set-Location $work
$env:TLSRELAY_CA_PASSPHRASE = "phrase de passe d'essai"

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8  # sorties de tlsrelay en UTF-8
function Fail($message) { Write-Host "ÉCHEC : $message"; exit 1 }
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

& $bin ca init --dir ac --org Essai; Check "ca init"
$acl = (Get-Acl ac\root.key.pem)
if (-not $acl.AreAccessRulesProtected) { Fail "ACL de la clé racine non protégée" }
if ($acl.Access | Where-Object { $_.IdentityReference -match 'Users|Utilisateurs|Everyone' }) { Fail "clé racine lisible par tous" }

& $bin pki gen-csr -c server.yaml --subject "CN=relay.essai,O=Essai" --san relay.essai; Check "gen-csr"
& $bin ca sign --dir ac --role server --csr pki\v1\request.csr --san relay.essai --out kit; Check "ca sign"
& $bin pki install -c server.yaml --from kit; Check "pki install"
& $bin pki activate -c server.yaml v1; Check "pki activate"
& $bin check-pki -c server.yaml; Check "check-pki"

& $bin pki gen-csr -c server.yaml --subject "CN=relay.essai,O=Essai"; Check "gen-csr v2"
& $bin ca sign --dir ac --role server --csr pki\v2\request.csr --san relay.essai --out kit2 2>$null
if ($LASTEXITCODE -eq 0) { Fail "sujet déjà attribué accepté" }
& $bin ca sign --dir ac --role server --csr pki\v2\request.csr --san relay.essai --renew --out kit2; Check "renouvellement"
& $bin pki install -c server.yaml --from kit2; Check "pki install v2"
& $bin check-pki -c server.yaml v2; Check "check-pki v2"
$serial = (Get-Content ac\index.tsv | Where-Object { $_ -match "`tremplacé`t" } | ForEach-Object { ($_ -split "`t")[0] })
if (-not $serial) { Fail "série du certificat remplacé" }
& $bin ca revoke --dir ac --serial $serial --reason superseded --out crl.pem; Check "ca revoke"
if (-not (Select-String -Path crl.pem -Pattern "BEGIN X509 CRL" -Quiet)) { Fail "CRL non écrite" }
& $bin ca list --dir ac | Tee-Object -Variable listing
if (-not ($listing -match "révoqué le")) { Fail "inventaire après révocation" }
& $bin ca audit --dir ac | Tee-Object -Variable audit; Check "ca audit"
if (-not ($audit -match "$([regex]::Escape($env:USERNAME))\s+revoke")) { Fail "opérateur absent du journal d'audit" }
Write-Host "PKI en ligne de commande sous Windows : OK"
exit 0
