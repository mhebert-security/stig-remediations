#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Applies the WN11-AC-000010 remediation.

.DESCRIPTION
    Title: The number of allowed bad logon attempts must be configured to three or
           less.
    Severity: CAT II

    Check Text:
    In Local Group Policy Editor navigate to Computer Configuration >> Windows
    Settings >> Security Settings >> Account Policies >> Account Lockout Policy.
    If "Account lockout threshold" is 0 or more than 3 attempts, this is a finding.

    Fix Text:
    Set "Account lockout threshold" to 3 or fewer invalid logon attempts (excluding
    0, which is unacceptable).

.NOTES
    STIG-ID   : WN11-AC-000010
    Reference : https://stigaview.com/products/win11/v2r5/WN11-AC-000010

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    PS C:\> .\WN11-AC-000010.ps1
#>

$ErrorActionPreference = 'Stop'

$threshold = 3

$result = & net accounts "/lockoutthreshold:$threshold" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Output "net accounts failed: $result"
    exit 1
}

Write-Output "Configured account lockout threshold = $threshold invalid logon attempts"
