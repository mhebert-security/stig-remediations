#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Verifies the WN11-SO-000050 setting. Outputs PASS or FAIL.

.DESCRIPTION
    The computer account password must not be prevented from being reset.

.NOTES
    STIG-ID   : WN11-SO-000050
    Reference : https://stigaview.com/products/win11/v2r8/WN11-SO-000050
#>

$path  = 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
$name  = 'DisablePasswordChange'
$value = '0'

$out = & reg query $path /v $name 2>$null

if ($LASTEXITCODE -ne 0) {
    Write-Output "FAIL - expected DisablePasswordChange = $value, got <not present>"
    exit 1
}

$raw = ($out -join ' ') -replace '.*REG_DWORD', ''
$raw = $raw.Trim()

if ($raw -notmatch '^0x([0-9a-fA-F]+)$') {
    Write-Output "FAIL - expected DisablePasswordChange = $value, got $raw"
    exit 1
}

try { $got = [Convert]::ToInt64($Matches[1], 16) } catch { $got = -1 }

if ($got -eq [int64]$value) {
    Write-Output 'PASS'
    exit 0
}

Write-Output "FAIL - expected DisablePasswordChange = $value, got $raw"
exit 1
