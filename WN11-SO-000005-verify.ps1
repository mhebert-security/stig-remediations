#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Verifies the WN11-SO-000005 setting. Outputs PASS or FAIL.

.DESCRIPTION
    Checks the built-in Administrator account (RID 500) is disabled.

.NOTES
    STIG-ID   : WN11-SO-000005
    Reference : https://stigaview.com/products/win11/v2r5/WN11-SO-000005
#>

$admin = Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' } | Select-Object -First 1

if ($null -eq $admin) {
    Write-Output 'FAIL — expected built-in Administrator (RID 500) account, got <not found>'
    exit 1
}

if ($admin.Enabled) {
    Write-Output 'FAIL — expected Administrator account Disabled, got Enabled'
    exit 1
}

Write-Output 'PASS'
exit 0
