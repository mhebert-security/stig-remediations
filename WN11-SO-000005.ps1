#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Applies the WN11-SO-000005 remediation.

.DESCRIPTION
    Title: The built-in administrator account must be disabled.
    Severity: CAT I

    Check Text:
    In Local Group Policy Editor navigate to Computer Configuration >> Windows
    Settings >> Security Settings >> Local Policies >> Security Options. If the
    value for "Accounts: Administrator account status" is not "Disabled", this is a
    finding.

    Fix Text:
    Set "Accounts: Administrator account status" to "Disabled".

.NOTES
    STIG-ID   : WN11-SO-000005
    Reference : https://stigaview.com/products/win11/v2r5/WN11-SO-000005

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    PS C:\> .\WN11-SO-000005.ps1
#>

$ErrorActionPreference = 'Stop'

# The built-in Administrator always carries RID 500.
$admin = Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' } | Select-Object -First 1

if ($null -eq $admin) {
    Write-Output 'Built-in Administrator account (RID 500) not found'
    exit 1
}

if ($admin.Enabled) {
    Disable-LocalUser -SID $admin.SID
    Write-Output "Disabled built-in Administrator account '$($admin.Name)'"
}
else {
    Write-Output "Built-in Administrator account '$($admin.Name)' already disabled"
}
