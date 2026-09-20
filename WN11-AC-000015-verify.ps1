#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Verifies the WN11-AC-000015 setting. Outputs PASS or FAIL.

.DESCRIPTION
    Reads "Reset account lockout counter after" (lockout observation window) via
    net accounts and checks it is 15 minutes or greater.

.NOTES
    STIG-ID   : WN11-AC-000015
    Reference : https://stigaview.com/products/win11/v2r5/WN11-AC-000015
#>

$output = & net accounts 2>$null

$line = $output | Where-Object { $_ -match 'Lockout observation window' }

if (-not $line) {
    Write-Output 'FAIL - expected Reset account lockout counter after >= 15, got <not found>'
    exit 1
}

$m = [regex]::Match(($line -join ''), ':\s*(\d+)')

if (-not $m.Success) {
    Write-Output "FAIL - expected Reset account lockout counter after >= 15, got $line"
    exit 1
}

$value = [int]$m.Groups[1].Value

if ($value -ge 15) {
    Write-Output 'PASS'
    exit 0
}

Write-Output "FAIL - expected Reset account lockout counter after >= 15, got $value"
exit 1
