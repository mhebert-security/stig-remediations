#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Applies the WN11-SO-000050 remediation.

.DESCRIPTION
    Title: The computer account password must not be prevented from being reset.
    Severity: low (CAT III)

    Check Text:
    If the registry value DisablePasswordChange is not 0, this is a finding.

    Fix Text:
    Set HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange to 0.

.NOTES
    STIG-ID   : WN11-SO-000050
    Reference : https://stigaview.com/products/win11/v2r8/WN11-SO-000050

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    PS C:\> .\WN11-SO-000050.ps1
#>

$ErrorActionPreference = 'Stop'

$path  = 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
$name  = 'DisablePasswordChange'
$value = '0'

& reg add $path /v $name /t REG_DWORD /d $value /f | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Output "reg add failed for $name"; exit 1 }

Write-Output "Configured $name = $value"
