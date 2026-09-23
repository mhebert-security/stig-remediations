#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Verifies the WN11-SO-000055 setting. Outputs PASS or FAIL.

.DESCRIPTION
    The maximum age for machine account passwords must be configured to 30 days or less.

.NOTES
    STIG-ID   : WN11-SO-000055
    Reference : https://stigaview.com/products/win11/v2r8/WN11-SO-000055
#>

$path  = 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
$name  = 'MaximumPasswordAge'
$max   = '30'

$out = & reg query $path /v $name 2>$null

if ($LASTEXITCODE -ne 0) {
    Write-Output "FAIL - expected MaximumPasswordAge <= $max (excluding 0), got <not present>"
    exit 1
}

$raw = ($out -join ' ') -replace '.*REG_DWORD', ''
$raw = $raw.Trim()

if ($raw -notmatch '^0x([0-9a-fA-F]+)$') {
    Write-Output "FAIL - expected MaximumPasswordAge <= $max (excluding 0), got $raw"
    exit 1
}

try { $got = [Convert]::ToInt64($Matches[1], 16) } catch { $got = -1 }

if ($got -ge 1 -and $got -le [int64]$max) {
    Write-Output 'PASS'
    exit 0
}

Write-Output "FAIL - expected MaximumPasswordAge <= $max (excluding 0), got $raw"
exit 1
