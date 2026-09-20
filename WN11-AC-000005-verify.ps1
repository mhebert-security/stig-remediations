#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Verifies the WN11-AC-000005 setting. Outputs PASS or FAIL.

.DESCRIPTION
    Reads "Account lockout duration" via net accounts and checks it is 15 minutes
    or greater (a value of 0 is also compliant).

.NOTES
    STIG-ID   : WN11-AC-000005
    Reference : https://stigaview.com/products/win11/v2r5/WN11-AC-000005
#>

$output = & net accounts 2>$null

$line = $output | Where-Object { $_ -match 'Lockout duration' }

if (-not $line) {
    Write-Output 'FAIL — expected Account lockout duration >= 15, got <not found>'
    exit 1
}

$m = [regex]::Match(($line -join ''), ':\s*(\d+)')

if (-not $m.Success) {
    Write-Output "FAIL — expected Account lockout duration >= 15, got $line"
    exit 1
}

$value = [int]$m.Groups[1].Value

if ($value -eq 0 -or $value -ge 15) {
    Write-Output 'PASS'
    exit 0
}

Write-Output "FAIL — expected Account lockout duration >= 15, got $value"
exit 1
