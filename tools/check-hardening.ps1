# Windows executable hardening (PLAN §6, docs/PENTEST.md): high-entropy
# ASLR, DEP, Control Flow Guard (PE header, DllCharacteristics).
# Usage: check-hardening.ps1 <executable>...
param([Parameter(Mandatory = $true, ValueFromRemainingArguments = $true)][string[]]$Paths)
$ErrorActionPreference = 'Stop'

$flags = [ordered]@{
    'High-entropy ASLR (HIGH_ENTROPY_VA)'   = 0x0020
    'ASLR (DYNAMIC_BASE)'                   = 0x0040
    'DEP (NX_COMPAT)'                       = 0x0100
    'Control Flow Guard (GUARD_CF)'         = 0x4000
}
$failed = $false
foreach ($path in $Paths) {
    $bytes = [System.IO.File]::ReadAllBytes((Resolve-Path $path))
    $pe = [BitConverter]::ToInt32($bytes, 0x3C)
    if ([BitConverter]::ToUInt32($bytes, $pe) -ne 0x00004550) { throw "${path}: PE header not found" }
    # Optional header: 24 bytes after the signature; DllCharacteristics at offset 70.
    $characteristics = [BitConverter]::ToUInt16($bytes, $pe + 24 + 70)
    $missing = @($flags.Keys | Where-Object { -not ($characteristics -band $flags[$_]) })
    if ($missing.Count -eq 0) {
        Write-Output "OK     ${path}: $($flags.Keys -join ', ')"
    } else {
        Write-Output "FAILED ${path}: missing $($missing -join ', ')"
        $failed = $true
    }
}
if ($failed) { exit 1 }
