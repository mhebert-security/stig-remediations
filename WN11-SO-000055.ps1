#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Applies the WN11-SO-000055 remediation.

.DESCRIPTION
    Title: The maximum age for machine account passwords must be configured to 30 days or less.
    Severity: low (CAT III)

    Check Text:
    If the registry value MaximumPasswordAge is not 30 or less (excluding 0), this is a finding.

    Fix Text:
    Set HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge to 30.

.NOTES
    STIG-ID   : WN11-SO-000055
    Reference : https://stigaview.com/products/win11/v2r8/WN11-SO-000055

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    PS C:\> .\WN11-SO-000055.ps1
#>

$ErrorActionPreference = 'Stop'

$path  = 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
$name  = 'MaximumPasswordAge'
$value = '30'

& reg add $path /v $name /t REG_DWORD /d $value /f | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Output "reg add failed for $name"; exit 1 }

Write-Output "Configured $name = $value"
