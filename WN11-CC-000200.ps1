#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Applies the WN11-CC-000200 remediation.

.DESCRIPTION
    Title: Administrator accounts must not be enumerated during elevation.
    Severity: medium (CAT II)

    Check Text:
    If the registry value EnumerateAdministrators is not 0, this is a finding.

    Fix Text:
    Set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators to 0.

.NOTES
    STIG-ID   : WN11-CC-000200
    Reference : https://stigaview.com/products/win11/v2r8/WN11-CC-000200

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    PS C:\> .\WN11-CC-000200.ps1
#>

$ErrorActionPreference = 'Stop'

$path  = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI'
$name  = 'EnumerateAdministrators'
$value = '0'

& reg add $path /v $name /t REG_DWORD /d $value /f | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Output "reg add failed for $name"; exit 1 }

Write-Output "Configured $name = $value"
