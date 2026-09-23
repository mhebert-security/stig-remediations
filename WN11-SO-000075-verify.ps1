#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Verifies the WN11-SO-000075 setting. Outputs PASS or FAIL.

.DESCRIPTION
    The required legal notice must be configured to display before console logon.

.NOTES
    STIG-ID   : WN11-SO-000075
    Reference : https://stigaview.com/products/win11/v2r8/WN11-SO-000075
#>

$path = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'

$out = & reg query $path /v LegalNoticeText 2>$null

if ($LASTEXITCODE -ne 0) {
    Write-Output 'FAIL - expected LegalNoticeText to begin with the USG banner, got <not present>'
    exit 1
}

$raw = ($out -join ' ')
if ($raw -notmatch 'LegalNoticeText\s+REG_SZ\s+(.*)') {
    Write-Output 'FAIL - expected LegalNoticeText to begin with the USG banner, got <unparseable>'
    exit 1
}

$value = $Matches[1].Trim()

if ($value -match '^You are accessing a U\.S\. Government \(USG\) Information System \(IS\)') {
    Write-Output 'PASS'
    exit 0
}

Write-Output "FAIL - expected LegalNoticeText to begin with the USG banner, got $value"
exit 1
