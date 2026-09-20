#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Verifies the WN11-AU-000505 setting. Outputs PASS or FAIL.

.DESCRIPTION
    Reads HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\MaxSize
    and checks it is 1024000 (0x000fa000) or greater.

.NOTES
    STIG-ID   : WN11-AU-000505
    Reference : https://stigaview.com/products/win11/v2r5/WN11-AU-000505
#>

$regPath  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
$valueName = 'MaxSize'
$required  = 1024000

$actual = (Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

if ($null -eq $actual) {
    Write-Output "FAIL - expected $valueName >= $required, got <not present>"
    exit 1
}

if ([int]$actual -ge $required) {
    Write-Output 'PASS'
    exit 0
}

Write-Output "FAIL - expected $valueName >= $required, got $actual"
exit 1
