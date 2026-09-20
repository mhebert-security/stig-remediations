#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Applies the WN11-AU-000505 remediation.

.DESCRIPTION
    Title: The Security event log size must be configured to 5120000 KB or greater.
    Severity: CAT II

    Check Text:
    If the system is configured to send audit records directly to an audit server,
    this is NA and must be documented with the ISSO. If the registry value
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\MaxSize does not
    exist or is not 0x4E2000 (5120000) or greater, this is a finding.

    Fix Text:
    Configure Computer Configuration >> Administrative Templates >> Windows
    Components >> Event Log Service >> Security >> "Specify the maximum log file
    size (KB)" to "Enabled" with a "Maximum Log Size (KB)" of 5120000 or greater.

.NOTES
    STIG-ID   : WN11-AU-000505
    Reference : https://stigaview.com/products/win11/v2r8/WN11-AU-000505

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    PS C:\> .\WN11-AU-000505.ps1
#>

$ErrorActionPreference = 'Stop'

$regPath  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
$valueName = 'MaxSize'
$required  = 5120000   # 0x4E2000

if (-not (Test-Path -LiteralPath $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

Set-ItemProperty -Path $regPath -Name $valueName -Value $required -Type DWord

Write-Output "Configured ${regPath}\${valueName} = $required"
