#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Verifies the WN11-AU-000510 setting. Outputs PASS or FAIL.

.DESCRIPTION
    Reads HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\MaxSize
    and checks it is 32768 (0x00008000) or greater.

.NOTES
    STIG-ID   : WN11-AU-000510
    Reference : https://stigaview.com/products/win11/v2r5/WN11-AU-000510
#>

$regPath  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'
$valueName = 'MaxSize'
$required  = 32768

$actual = (Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

if ($null -eq $actual) {
    Write-Output "FAIL — expected $valueName >= $required, got <not present>"
    exit 1
}

if ([int]$actual -ge $required) {
    Write-Output 'PASS'
    exit 0
}

Write-Output "FAIL — expected $valueName >= $required, got $actual"
exit 1
