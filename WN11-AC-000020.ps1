#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Applies the WN11-AC-000020 remediation.

.DESCRIPTION
    Title: The password history must be configured to 24 passwords remembered.
    Severity: CAT II

    Check Text:
    In Local Group Policy Editor navigate to Computer Configuration >> Windows
    Settings >> Security Settings >> Account Policies >> Password Policy. If the
    value for "Enforce password history" is less than 24 passwords remembered, this
    is a finding.

    Fix Text:
    Set "Enforce password history" to 24 passwords remembered.

.NOTES
    STIG-ID   : WN11-AC-000020
    Reference : https://stigaview.com/products/win11/v2r5/WN11-AC-000020

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    PS C:\> .\WN11-AC-000020.ps1
#>

$ErrorActionPreference = 'Stop'

$history = 24

$result = & net accounts "/uniquepw:$history" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Output "net accounts failed: $result"
    exit 1
}

Write-Output "Configured enforce password history = $history passwords remembered"
