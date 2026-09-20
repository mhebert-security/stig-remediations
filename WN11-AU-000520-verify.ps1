#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Verifies the WN11-AU-000520 setting. Outputs PASS or FAIL.

.DESCRIPTION
    Checks the ACL on Security.evtx. Eventlog, SYSTEM, and Administrators must hold
    Full Control and no other principal may hold an allow rule.

.NOTES
    STIG-ID   : WN11-AU-000520
    Reference : https://stigaview.com/products/win11/v2r5/WN11-AU-000520
#>

$logFile = Join-Path $env:SystemRoot 'System32\winevt\Logs\Security.evtx'

if (-not (Test-Path -LiteralPath $logFile)) {
    Write-Output "FAIL — expected log file $logFile, got <missing>"
    exit 1
}

$acl = Get-Acl -Path $logFile

$required = @('NT SERVICE\Eventlog', 'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators')
# The STIG note permits ALL APPLICATION PACKAGES holding Special Permissions.
$allowedExtra = @('ALL APPLICATION PACKAGES')

function Get-AccountName([System.Security.Principal.IdentityReference]$Ref) {
    try { return $Ref.Translate([System.Security.Principal.NTAccount]).Value }
    catch { return $Ref.Value }
}

foreach ($name in $required) {
    $match = $acl.Access | Where-Object {
        (Get-AccountName $_.IdentityReference) -eq $name -and
        $_.AccessControlType -eq 'Allow' -and
        ($_.FileSystemRights -band 'FullControl') -eq 'FullControl'
    }
    if (-not $match) {
        Write-Output "FAIL — expected $name FullControl, got <missing or insufficient>"
        exit 1
    }
}

$others = $acl.Access | Where-Object {
    $n = Get-AccountName $_.IdentityReference
    $_.AccessControlType -eq 'Allow' -and $n -notin $required -and $n -notin $allowedExtra
}

if ($others) {
    $names = (($others | ForEach-Object { Get-AccountName $_.IdentityReference }) |
        Sort-Object -Unique) -join ', '
    Write-Output "FAIL — expected no non-privileged allow rules, got $names"
    exit 1
}

Write-Output 'PASS'
exit 0
