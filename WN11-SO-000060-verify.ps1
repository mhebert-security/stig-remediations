#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Verifies the WN11-SO-000060 setting. Outputs PASS or FAIL.

.DESCRIPTION
    The system must be configured to require a strong session key.

.NOTES
    STIG-ID   : WN11-SO-000060
    Reference : https://stigaview.com/products/win11/v2r8/WN11-SO-000060
#>

$path  = 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
$name  = 'RequireStrongKey'
$value = '1'

$out = & reg query $path /v $name 2>$null

if ($LASTEXITCODE -ne 0) {
    Write-Output "FAIL - expected RequireStrongKey = $value, got <not present>"
    exit 1
}

$raw = ($out -join ' ') -replace '.*REG_DWORD', ''
$raw = $raw.Trim()

if ($raw -notmatch '^0x([0-9a-fA-F]+)$') {
    Write-Output "FAIL - expected RequireStrongKey = $value, got $raw"
    exit 1
}

try { $got = [Convert]::ToInt64($Matches[1], 16) } catch { $got = -1 }

if ($got -eq [int64]$value) {
    Write-Output 'PASS'
    exit 0
}

Write-Output "FAIL - expected RequireStrongKey = $value, got $raw"
exit 1
