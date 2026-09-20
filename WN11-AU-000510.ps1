#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Applies the WN11-AU-000510 remediation.

.DESCRIPTION
    Title: The System event log size must be configured to 32768 KB or greater.
    Severity: CAT II

    Check Text:
    If the system is configured to send audit records directly to an audit server,
    this is NA and must be documented with the ISSO. If the registry value
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\MaxSize does not
    exist or is not 0x00008000 (32768) or greater, this is a finding.

    Fix Text:
    Configure Computer Configuration >> Administrative Templates >> Windows
    Components >> Event Log Service >> System >> "Specify the maximum log file
    size (KB)" to "Enabled" with a "Maximum Log Size (KB)" of 32768 or greater.

.NOTES
    STIG-ID   : WN11-AU-000510
    Reference : https://stigaview.com/products/win11/v2r5/WN11-AU-000510

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    PS C:\> .\WN11-AU-000510.ps1
#>

$ErrorActionPreference = 'Stop'

$regPath  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'
$valueName = 'MaxSize'
$required  = 32768   # 0x00008000

if (-not (Test-Path -LiteralPath $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

Set-ItemProperty -Path $regPath -Name $valueName -Value $required -Type DWord

Write-Output "Configured ${regPath}\${valueName} = $required"
