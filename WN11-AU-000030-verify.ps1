#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Verifies the WN11-AU-000030 setting. Outputs PASS or FAIL.

.DESCRIPTION
    The system must be configured to audit Account Management - Security Group Management successes.

.NOTES
    STIG-ID   : WN11-AU-000030
    Reference : https://stigaview.com/products/win11/v2r8/WN11-AU-000030
#>

$out = & auditpol /get /subcategory:"Security Group Management" 2>$null

if ($LASTEXITCODE -ne 0) {
    Write-Output 'FAIL - expected Security Group Management Success enabled, got <auditpol error>'
    exit 1
}

$text = ($out -join ' ')

if ($text -match 'Security Group Management\s+(.*)') {
    $status = $Matches[1].Trim()
} else {
    Write-Output 'FAIL - expected Security Group Management Success enabled, got <unparseable>'
    exit 1
}

if ($status -match 'Success') {
    Write-Output 'PASS'
    exit 0
}

Write-Output "FAIL - expected Security Group Management Success enabled, got $status"
exit 1
