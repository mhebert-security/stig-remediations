#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Verifies the WN11-CC-000200 setting. Outputs PASS or FAIL.

.DESCRIPTION
    Administrator accounts must not be enumerated during elevation.

.NOTES
    STIG-ID   : WN11-CC-000200
    Reference : https://stigaview.com/products/win11/v2r8/WN11-CC-000200
#>

$path  = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI'
$name  = 'EnumerateAdministrators'
$value = '0'

$out = & reg query $path /v $name 2>$null

if ($LASTEXITCODE -ne 0) {
    Write-Output "FAIL - expected EnumerateAdministrators = $value, got <not present>"
    exit 1
}

$raw = ($out -join ' ') -replace '.*REG_DWORD', ''
$raw = $raw.Trim()

if ($raw -notmatch '^0x([0-9a-fA-F]+)$') {
    Write-Output "FAIL - expected EnumerateAdministrators = $value, got $raw"
    exit 1
}

try { $got = [Convert]::ToInt64($Matches[1], 16) } catch { $got = -1 }

if ($got -eq [int64]$value) {
    Write-Output 'PASS'
    exit 0
}

Write-Output "FAIL - expected EnumerateAdministrators = $value, got $raw"
exit 1
