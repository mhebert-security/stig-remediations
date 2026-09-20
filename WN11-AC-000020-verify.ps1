#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Verifies the WN11-AC-000020 setting. Outputs PASS or FAIL.

.DESCRIPTION
    Reads "Enforce password history" (length of password history maintained) via
    net accounts and checks it is 24 or greater.

.NOTES
    STIG-ID   : WN11-AC-000020
    Reference : https://stigaview.com/products/win11/v2r5/WN11-AC-000020
#>

$output = & net accounts 2>$null

$line = ($output | Where-Object { $_ -match 'Length of password history' }) -join ''

if (-not $line) {
    Write-Output 'FAIL - expected Enforce password history >= 24, got <not found>'
    exit 1
}

if ($line -match 'None') {
    Write-Output 'FAIL - expected Enforce password history >= 24, got None (0)'
    exit 1
}

$m = [regex]::Match($line, ':\s*(\d+)')

if (-not $m.Success) {
    Write-Output "FAIL - expected Enforce password history >= 24, got $line"
    exit 1
}

$value = [int]$m.Groups[1].Value

if ($value -ge 24) {
    Write-Output 'PASS'
    exit 0
}

Write-Output "FAIL - expected Enforce password history >= 24, got $value"
exit 1
