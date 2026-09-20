# STIG Remediations — Windows 11

PowerShell remediation and verification scripts for DISA Windows 11 STIG v2r6.

Each STIG ID has two scripts:
- `{STIG-ID}.ps1` — applies the remediation
- `{STIG-ID}-verify.ps1` — reads the controlled setting and returns PASS or FAIL

Scripts are tested against a live Azure VM using `az vm run-command invoke`.
Results are logged in Obsidian before each commit.

## Usage

Apply a remediation:
```powershell
.\WN11-AU-000500.ps1
```

Verify compliance state:
```powershell
.\WN11-AU-000500-verify.ps1
```
