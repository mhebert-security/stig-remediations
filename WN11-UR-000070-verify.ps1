#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Verifies the WN11-UR-000070 setting. Outputs PASS or FAIL.

.DESCRIPTION
    The "Deny access to this computer from the network" user right must include the Guests group.

.NOTES
    STIG-ID   : WN11-UR-000070
    Reference : https://stigaview.com/products/win11/v2r8/WN11-UR-000070
#>

$priv = 'SeDenyNetworkLogonRight'
$required = '*S-1-5-32-546'
$cfg = 'C:\Windows\Temp\seccheck.cfg'

& secedit /export /cfg $cfg /quiet | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Output 'FAIL - secedit export failed'; exit 1 }

$content = Get-Content -Raw $cfg
Remove-Item $cfg -Force -ErrorAction SilentlyContinue

if ($content -notmatch '\[Privilege Rights\]') {
    Write-Output "FAIL - expected $priv to include $required, got <no section>"
    exit 1
}

$section = ($content -split '\[Privilege Rights\]', 2)[1]
$section = ($section -split '\[', 2)[0]

$line = ($section -split "`r?`n") | Where-Object { $_ -match ('^' + $priv + '\s*=') } | Select-Object -First 1

if (-not $line) {
    Write-Output "FAIL - expected $priv to include $required, got <not defined>"
    exit 1
}

$value = ($line -split '=', 2)[1].Trim()

if ($value -match [regex]::Escape($required)) {
    Write-Output 'PASS'
    exit 0
}

Write-Output "FAIL - expected $priv to include $required, got $value"
exit 1
