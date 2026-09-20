#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Verifies the WN11-AC-000010 setting. Outputs PASS or FAIL.

.DESCRIPTION
    Reads "Account lockout threshold" via net accounts and checks it is between 1
    and 3 inclusive. A value of Never (0) is a finding.

.NOTES
    STIG-ID   : WN11-AC-000010
    Reference : https://stigaview.com/products/win11/v2r5/WN11-AC-000010
#>

$output = & net accounts 2>$null

$line = ($output | Where-Object { $_ -match 'Lockout threshold' }) -join ''

if (-not $line) {
    Write-Output 'FAIL - expected Account lockout threshold 1-3, got <not found>'
    exit 1
}

if ($line -match 'Never') {
    Write-Output 'FAIL - expected Account lockout threshold 1-3, got Never (0)'
    exit 1
}

$m = [regex]::Match($line, ':\s*(\d+)')

if (-not $m.Success) {
    Write-Output "FAIL - expected Account lockout threshold 1-3, got $line"
    exit 1
}

$value = [int]$m.Groups[1].Value

if ($value -ge 1 -and $value -le 3) {
    Write-Output 'PASS'
    exit 0
}

Write-Output "FAIL - expected Account lockout threshold 1-3, got $value"
exit 1
