#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Applies the WN11-UR-000005 remediation.

.DESCRIPTION
    Title: The "Access Credential Manager as a trusted caller" user right must not be assigned to any groups or accounts.
    Severity: medium (CAT II)

    Check Text:
    Verify User Rights Assignment. If any groups or accounts are granted the "Access Credential Manager as a trusted caller" user right, this is a finding.

    Fix Text:
    Configure "Access Credential Manager as a trusted caller" to be defined but containing no entries (blank).

.NOTES
    STIG-ID   : WN11-UR-000005
    Reference : https://stigaview.com/products/win11/v2r8/WN11-UR-000005

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    PS C:\> .\WN11-UR-000005.ps1
#>

$ErrorActionPreference = 'Stop'

$priv = 'SeTrustedCredmanAccessPrivilege'
$cfg  = 'C:\Windows\Temp\secpol.cfg'
$db   = 'C:\Windows\Temp\stig.sdb'

& secedit /export /cfg $cfg /quiet | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Output 'secedit export failed'; exit 1 }

$lines = New-Object System.Collections.Generic.List[string]
foreach ($l in (Get-Content $cfg)) { $lines.Add($l) }

$header = -1
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match '^\s*\[Privilege Rights\]') { $header = $i; break }
}
if ($header -lt 0) {
    if ($lines.Count -gt 0 -and $lines[$lines.Count - 1] -ne '') { $lines.Add('') }
    $lines.Add('[Privilege Rights]')
    $header = $lines.Count - 1
}

$privLine = -1
for ($i = $header + 1; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match '^\s*\[') { break }
    if ($lines[$i] -match ('^' + $priv + '\s*=')) { $privLine = $i; break }
}

if ($privLine -ge 0) {
    $lines[$privLine] = "$priv = "
} else {
    $lines.Insert($header + 1, "$priv = ")
}

Set-Content -Path $cfg -Value $lines -Encoding Unicode

& secedit /configure /db $db /cfg $cfg /quiet | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Output 'secedit configure failed'; exit 1 }

Remove-Item $cfg, $db -Force -ErrorAction SilentlyContinue

Write-Output "Configured $priv to blank"
