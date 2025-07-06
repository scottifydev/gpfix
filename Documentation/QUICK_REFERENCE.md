# Teenager Policy Quick Reference Guide

## PowerShell Commands

### Deployment & Management
```powershell
#Requires -Version 5.1
#Requires -RunAsAdministrator
#Requires -Modules ActiveDirectory, GroupPolicy

# Deploy policy with default settings
.\Scripts\Deploy-TeenagerPolicy.ps1

# Deploy with custom parameters
.\Scripts\Deploy-TeenagerPolicy.ps1 -DomainName "scottify.io" -TeenagerGroupName "Teenagers" -GPOName "Teenager Restrictions Policy"

# Test mode deployment (no changes made)
.\Scripts\Deploy-TeenagerPolicy.ps1 -TestMode

# Check policy status
.\Scripts\Get-TeenagerPolicyStatus.ps1 -Username "teenager1"

# Remove policy
.\Scripts\Remove-TeenagerPolicy.ps1 -Username "teenager1" -RemoveAppLocker

# Test compliance
.\Scripts\Test-PolicyCompliance.ps1 -Username "teenager1"
```

### Policy Refresh
```powershell
#Requires -RunAsAdministrator

# Force immediate policy update
gpupdate /force /target:user

# Update only computer policies
gpupdate /force /target:computer

# Logoff after update
gpupdate /force /logoff

# Boot after update (for computer policies)
gpupdate /force /boot
```

### AppLocker Management
```powershell
#Requires -Version 5.1
#Requires -RunAsAdministrator
#Requires -Modules AppLocker

# Get AppLocker policy
Get-AppLockerPolicy -Effective -Xml > current-policy.xml

# Test AppLocker policy
Test-AppLockerPolicy -Path "C:\Program Files\Game.exe" -User teenager1

# Get AppLocker file information
Get-AppLockerFileInformation -Path "C:\Program Files\*.exe"

# Import AppLocker policy
Set-AppLockerPolicy -XmlPolicy "AppLocker-Rules.xml"
```

## Troubleshooting Checklist

🔄 Verify user is logged off before applying policy
🔄 Check Event Viewer for policy errors
🔄 Confirm ADMX/ADML files are in PolicyDefinitions
🔄 Verify AppLocker service is running
🔄 Check user group membership
🔄 Review effective permissions with `gpresult`
🔄 Ensure no conflicting policies exist
🔄 Verify registry permissions
🔄 Check for policy processing errors in event logs
🔄 Confirm time sync between DC and client

## Emergency Procedures

### 1. Policy Lockout Recovery
```powershell
#Requires -RunAsAdministrator

# Boot into Safe Mode and run:
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\*" -Recurse -Force
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\*" -Recurse -Force
gpupdate /force
```

### 2. AppLocker Emergency Bypass
```powershell
#Requires -RunAsAdministrator

# Disable AppLocker (requires admin)
Set-Service -Name "AppIDSvc" -StartupType Disabled
Stop-Service -Name "AppIDSvc" -Force
```

### 3. Browser Access Restoration
```powershell
#Requires -RunAsAdministrator

# Reset Chrome policies
Remove-Item "HKLM:\SOFTWARE\Policies\Google\Chrome" -Recurse -Force
Remove-Item "HKCU:\SOFTWARE\Policies\Google\Chrome" -Recurse -Force
```

### 4. Full Policy Reset
```powershell
#Requires -RunAsAdministrator

# Nuclear option - removes ALL policies
secedit /configure /cfg %windir%\inf\defltbase.inf /db defltbase.sdb /verbose
gpupdate /force
```

## Key File Locations

```
# Policy Templates
C:\Windows\PolicyDefinitions\                    # ADMX/ADML files
C:\Windows\SYSVOL\domain\Policies\               # Domain GPOs

# Local Policy Storage
C:\Windows\System32\GroupPolicy\                 # Local GPO
C:\Windows\System32\GroupPolicyUsers\            # User-specific GPOs

# AppLocker
C:\Windows\System32\AppLocker\                   # AppLocker files
C:\Windows\System32\LogFiles\                    # AppLocker logs

# Policy Results
C:\Windows\debug\usermode\                       # GPResult outputs
%TEMP%\gpresult.html                            # HTML reports
```

## Registry Paths

```
# User Policies
HKEY_CURRENT_USER\Software\Policies\             # User policy settings
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\

# Computer Policies  
HKEY_LOCAL_MACHINE\Software\Policies\            # Computer policy settings
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\

# Chrome Policies
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome\
HKEY_CURRENT_USER\SOFTWARE\Policies\Google\Chrome\

# AppLocker
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SrpV2\
```

## Event Log IDs

### Group Policy Events (System Log)
- **1500**: Policy processing started
- **1501**: Policy processing successful
- **1502**: Policy processing failed
- **1503**: Policy processing aborted
- **1704**: GPO download successful
- **1705**: GPO download failed

### AppLocker Events (Application and Services\Microsoft\Windows\AppLocker)
- **8003**: File allowed to run
- **8004**: File blocked from running
- **8005**: Script allowed
- **8006**: Script blocked
- **8007**: MSI/MSP allowed
- **8008**: MSI/MSP blocked

### User Profile Service (Application Log)
- **1530**: Windows detected slow link
- **1531**: Windows detected fast link

## Common Error Codes

| Code | Description | Solution |
|------|-------------|----------|
| 0x80070005 | Access Denied | Check permissions, run as admin |
| 0x80070002 | File Not Found | Verify path, check ADMX files |
| 0x800706BA | RPC Server Unavailable | Check network, firewall, services |
| 0x8007054B | Domain Controller Not Found | Verify DNS, domain connectivity |
| 0x80070534 | No Mapping Between Names | Check user/group names |
| 0x800703FA | Illegal Operation | Policy conflict, check settings |
| 0x80070057 | Invalid Parameter | Review policy syntax |
| 0x800706BE | Remote Procedure Call Failed | Restart services, check connectivity |

## Contact Information

```
IT Administrator:     ________________________
Phone:               ________________________
Email:               ________________________

Escalation Contact:  ________________________
Phone:               ________________________
Email:               ________________________

Emergency Hotline:   ________________________
Ticket System:       ________________________
```

## Useful One-Liners

```powershell
#Requires -Version 5.1

# Generate detailed policy report
gpresult /h "%USERPROFILE%\Desktop\PolicyReport.html" /f

# List all applied policies
gpresult /r /scope:user

# Export effective policies
gpresult /x "%USERPROFILE%\Desktop\policies.xml" /f

# Check specific policy setting
reg query "HKLM\SOFTWARE\Policies\Google\Chrome\URLBlocklist" /s

# List all AppLocker rules
Get-AppLockerPolicy -Effective | Format-List

# Find policy processing errors
Get-WinEvent -LogName System | Where {$_.ID -eq 1502} | Select -First 10

# Check AppLocker blocks
Get-WinEvent -LogName "Microsoft-Windows-AppLocker/EXE and DLL" | Where {$_.ID -eq 8004}

# List all GPOs applied to user
gpresult /r /user teenager1 | findstr "Applied Group Policy Objects"

# Quick policy backup
Copy-Item "C:\Windows\System32\GroupPolicy" -Destination "C:\Backup\GroupPolicy" -Recurse

# Test specific website block
nslookup blocked-site.com
ping blocked-site.com

# Reset Chrome to defaults (removes policies)
# Note: Chrome must be closed first
taskkill /F /IM chrome.exe
reg delete "HKLM\SOFTWARE\Policies\Google\Chrome" /f
reg delete "HKCU\SOFTWARE\Policies\Google\Chrome" /f

# Force sync with domain controller
w32tm /resync
gpupdate /force

# Check policy inheritance
gpresult /z > detailed_policy.txt

# Find users with specific policy
Get-ADUser -Filter * | ForEach {gpresult /r /user $_.SamAccountName 2>$null | Select-String "Teenager-Policy"}
```

---
*Last Updated: [DATE] | Version: 1.0 | Print double-sided for easy reference*