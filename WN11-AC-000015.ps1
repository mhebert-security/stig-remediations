#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Applies the WN11-AC-000015 remediation.

.DESCRIPTION
    Title: The period of time before the bad logon counter is reset must be
           configured to 15 minutes.
    Severity: CAT II

    Check Text:
    In Local Group Policy Editor navigate to Computer Configuration >> Windows
    Settings >> Security Settings >> Account Policies >> Account Lockout Policy.
    If "Reset account lockout counter after" is less than 15 minutes, this is a
    finding.

    Fix Text:
    Set "Reset account lockout counter after" to 15 minutes.

.NOTES
    STIG-ID   : WN11-AC-000015
    Reference : https://stigaview.com/products/win11/v2r5/WN11-AC-000015

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    PS C:\> .\WN11-AC-000015.ps1
#>

$ErrorActionPreference = 'Stop'

$minutes = 15

$result = & net accounts "/lockoutwindow:$minutes" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Output "net accounts failed: $result"
    exit 1
}

Write-Output "Configured reset account lockout counter after = $minutes minutes"
