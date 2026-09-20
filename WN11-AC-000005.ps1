#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Applies the WN11-AC-000005 remediation.

.DESCRIPTION
    Title: Windows 11 account lockout duration must be configured to 15 minutes or
           greater.
    Severity: CAT II

    Check Text:
    In Local Group Policy Editor navigate to Computer Configuration >> Windows
    Settings >> Security Settings >> Account Policies >> Account Lockout Policy.
    If "Account lockout duration" is less than 15 minutes (excluding 0), this is a
    finding. A value of 0 is more restrictive and is not a finding.

    Fix Text:
    Set "Account lockout duration" to 15 minutes or greater. A value of 0 is also
    acceptable.

.NOTES
    STIG-ID   : WN11-AC-000005
    Reference : https://stigaview.com/products/win11/v2r5/WN11-AC-000005

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    PS C:\> .\WN11-AC-000005.ps1
#>

$ErrorActionPreference = 'Stop'

$minutes = 15

$result = & net accounts "/lockoutduration:$minutes" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Output "net accounts failed: $result"
    exit 1
}

Write-Output "Configured account lockout duration = $minutes minutes"
