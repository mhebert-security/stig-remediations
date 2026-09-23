#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Applies the WN11-AU-000030 remediation.

.DESCRIPTION
    Title: The system must be configured to audit Account Management - Security Group Management successes.
    Severity: medium (CAT II)

    Check Text:
    If Success auditing for Security Group Management is not enabled, this is a finding.

    Fix Text:
    Enable Success auditing for the Security Group Management subcategory.

.NOTES
    STIG-ID   : WN11-AU-000030
    Reference : https://stigaview.com/products/win11/v2r8/WN11-AU-000030

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    PS C:\> .\WN11-AU-000030.ps1
#>

$ErrorActionPreference = 'Stop'

$out = & auditpol /set /subcategory:"Security Group Management" /success:enable 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Output "auditpol set failed: $out"
    exit 1
}

Write-Output 'Enabled Success auditing for Security Group Management'
