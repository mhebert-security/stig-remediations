#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Applies the WN11-SO-000075 remediation.

.DESCRIPTION
    Title: The required legal notice must be configured to display before console logon.
    Severity: medium (CAT II)

    Check Text:
    If LegalNoticeText is not set to the DoD logon banner, this is a finding.

    Fix Text:
    Set LegalNoticeText to the DoD logon banner and LegalNoticeCaption to a non-blank title.

.NOTES
    STIG-ID   : WN11-SO-000075
    Reference : https://stigaview.com/products/win11/v2r8/WN11-SO-000075

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    PS C:\> .\WN11-SO-000075.ps1
#>

$ErrorActionPreference = 'Stop'

$path   = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$text   = 'You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions: -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. -At any time, the USG may inspect and seize data stored on this IS. -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy. -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.'

& reg add $path /v LegalNoticeText /t REG_SZ /d $text /f | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Output 'reg add LegalNoticeText failed'; exit 1 }

& reg add $path /v LegalNoticeCaption /t REG_SZ /d 'USG Warning' /f | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Output 'reg add LegalNoticeCaption failed'; exit 1 }

Write-Output 'Configured LegalNoticeText and LegalNoticeCaption'
