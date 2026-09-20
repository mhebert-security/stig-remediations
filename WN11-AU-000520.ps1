#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Applies the WN11-AU-000520 remediation.

.DESCRIPTION
    Title: Windows 11 permissions for the Security event log must prevent access
           by non-privileged accounts.
    Severity: CAT II

    Check Text:
    Verify the permissions on the Security event log (Security.evtx). Standard user
    accounts or groups must not have access. The acceptable ACL is Eventlog, SYSTEM,
    and Administrators with Full Control. The default location is
    %SystemRoot%\System32\winevt\Logs. If permissions are less restrictive than the
    listed ACLs, this is a finding.

    Fix Text:
    Ensure the permissions on Security.evtx prevent standard user accounts or groups
    from having access. Apply the ACL: Eventlog, SYSTEM, and Administrators with
    Full Control. If the log location changed, add Eventlog as "NT Service\Eventlog".

.NOTES
    STIG-ID   : WN11-AU-000520
    Reference : https://stigaview.com/products/win11/v2r5/WN11-AU-000520

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    PS C:\> .\WN11-AU-000520.ps1
#>

$ErrorActionPreference = 'Stop'

$logFile = Join-Path $env:SystemRoot 'System32\winevt\Logs\Security.evtx'

if (-not (Test-Path -LiteralPath $logFile)) {
    Write-Output "Log file not found: $logFile"
    exit 1
}

# Build a fresh, protected ACL with exactly three Full Control principals.
$acl = New-Object System.Security.AccessControl.FileSecurity
$acl.SetAccessRuleProtection($true, $false)   # disable inheritance, keep no inherited rules
$acl.SetOwner([System.Security.Principal.NTAccount]'BUILTIN\Administrators')

$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    'NT SERVICE\Eventlog', 'FullControl', 'Allow')))
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    'NT AUTHORITY\SYSTEM', 'FullControl', 'Allow')))
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    'BUILTIN\Administrators', 'FullControl', 'Allow')))

Set-Acl -Path $logFile -AclObject $acl

Write-Output "Reset permissions on $logFile to Eventlog, SYSTEM, Administrators (Full Control)"
