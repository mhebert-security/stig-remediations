#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Applies the WN11-SO-000060 remediation.

.DESCRIPTION
    Title: The system must be configured to require a strong session key.
    Severity: medium (CAT II)

    Check Text:
    If the registry value RequireStrongKey is not 1, this is a finding.

    Fix Text:
    Set HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey to 1.

.NOTES
    STIG-ID   : WN11-SO-000060
    Reference : https://stigaview.com/products/win11/v2r8/WN11-SO-000060

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    PS C:\> .\WN11-SO-000060.ps1
#>

$ErrorActionPreference = 'Stop'

$path  = 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
$name  = 'RequireStrongKey'
$value = '1'

& reg add $path /v $name /t REG_DWORD /d $value /f | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Output "reg add failed for $name"; exit 1 }

Write-Output "Configured $name = $value"
