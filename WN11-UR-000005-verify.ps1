#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Verifies the WN11-UR-000005 setting. Outputs PASS or FAIL.

.DESCRIPTION
    The "Access Credential Manager as a trusted caller" user right must not be assigned to any groups or accounts.

.NOTES
    STIG-ID   : WN11-UR-000005
    Reference : https://stigaview.com/products/win11/v2r8/WN11-UR-000005
#>

$priv = 'SeTrustedCredmanAccessPrivilege'
$cfg  = 'C:\Windows\Temp\seccheck.cfg'

& secedit /export /cfg $cfg /quiet | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Output 'FAIL - secedit export failed'; exit 1 }

$content = Get-Content -Raw $cfg
Remove-Item $cfg -Force -ErrorAction SilentlyContinue

if ($content -notmatch '\[Privilege Rights\]') {
    Write-Output 'PASS'
    exit 0
}

$section = ($content -split '\[Privilege Rights\]', 2)[1]
$section = ($section -split '\[', 2)[0]

$line = ($section -split "`r?`n") | Where-Object { $_ -match ('^' + $priv + '\s*=') } | Select-Object -First 1

if (-not $line) {
    Write-Output 'PASS'
    exit 0
}

$value = ($line -split '=', 2)[1].Trim()

if ([string]::IsNullOrEmpty($value)) {
    Write-Output 'PASS'
    exit 0
}

Write-Output "FAIL - expected $priv blank, got $value"
exit 1
