# Teenager Group Policy System Documentation

## Table of Contents
1. [Overview](#overview)
2. [Prerequisites and Requirements](#prerequisites-and-requirements)
3. [Installation Instructions](#installation-instructions)
4. [Policy Components](#policy-components)
5. [Deployment Steps](#deployment-steps)
6. [Testing and Verification](#testing-and-verification)
7. [Troubleshooting](#troubleshooting)
8. [User Management](#user-management)
9. [Emergency Override Procedures](#emergency-override-procedures)
10. [Regular Maintenance](#regular-maintenance)

---

## Overview

The Teenager Group Policy system is a comprehensive security solution designed to restrict and monitor computer usage for teenage users in the scottify.io domain. This policy implements application whitelisting, browser restrictions, and security controls while allowing access to approved gaming platforms (Steam and Epic Games).

### Key Features:
- **Application Whitelisting**: Only approved applications can run (Steam, Epic Games, and essential Windows programs)
- **Browser Restrictions**: Chrome-only access with forced sign-in to scottify.io domain accounts
- **Security Controls**: Disabled command prompt, registry editor, and task manager
- **Content Filtering**: Enforced safe search and YouTube restricted mode
- **Monitoring**: All activity tied to domain accounts for oversight

### Target Environment:
- Domain: scottify.io
- Security Group: Teenagers
- GPO Name: Teenager Restrictions Policy
- Organizational Unit: OU=Teenagers,DC=scottify,DC=io

---

## Prerequisites and Requirements

### System Requirements:
- **Domain Controller**: Windows Server 2016 or later
- **Client Computers**: Windows 10 Pro/Enterprise or Windows 11 Pro/Enterprise
- **Active Directory**: Functional domain (scottify.io)
- **PowerShell**: Version 5.1 or later

### Required Windows Features:
1. **Group Policy Management Console (GPMC)**
   ```powershell
   Install-WindowsFeature GPMC
   ```

2. **Active Directory Module for PowerShell**
   ```powershell
   Install-WindowsFeature RSAT-AD-PowerShell
   ```

3. **AppLocker (Application Control Policies)**
   - Available on Windows Pro/Enterprise editions
   - Requires Application Identity service

### Administrative Requirements:
- Domain Administrator privileges
- Access to domain controller
- Permission to create and link GPOs
- Access to SYSVOL share

---

## Installation Instructions

### Step 1: Prepare the Environment

1. **Clone or Copy the GroupPolicy folder** to your domain controller:
   ```powershell
   Copy-Item -Path "\\source\GroupPolicy" -Destination "C:\GroupPolicy" -Recurse
   ```

2. **Verify folder structure**:
   ```
   C:\GroupPolicy\
   ├── Documentation\
   ├── Policies\
   │   ├── Default\
   │   └── Teenagers\
   │       ├── AppLocker-Rules.xml
   │       └── Browser-Restrictions.pol
   ├── Scripts\
   │   ├── Deploy-TeenagerPolicy.ps1
   │   └── Test-PolicyCompliance.ps1
   └── Templates\
       ├── ADMX\
       └── ADML\
   ```

### Step 2: Install Chrome ADMX Templates

1. **Copy ADMX files** to the Central Store:
   ```powershell
   $centralStore = "\\scottify.io\SYSVOL\scottify.io\Policies\PolicyDefinitions"
   
   # Create Central Store if it doesn't exist
   New-Item -Path $centralStore -ItemType Directory -Force
   
   # Copy ADMX files
   Copy-Item -Path "C:\GroupPolicy\Templates\ADMX\*.admx" -Destination $centralStore -Force
   
   # Copy language files
   Copy-Item -Path "C:\GroupPolicy\Templates\ADML\*.adml" -Destination "$centralStore\en-US\" -Force
   ```

### Step 3: Create Required Active Directory Objects

1. **Create the Teenagers Security Group**:
   ```powershell
   New-ADGroup -Name "Teenagers" `
               -GroupCategory Security `
               -GroupScope Global `
               -Description "Security group for teenagers with restricted access" `
               -Path "CN=Users,DC=scottify,DC=io"
   ```

2. **Create the Teenagers Organizational Unit** (optional but recommended):
   ```powershell
   New-ADOrganizationalUnit -Name "Teenagers" `
                            -Path "DC=scottify,DC=io" `
                            -Description "OU for teenager user accounts"
   ```

---

## Policy Components

### 1. AppLocker Rules (Application Whitelisting)

**File**: `Policies/Teenagers/AppLocker-Rules.xml`

**Components**:

#### Executable Rules:
- **Allow Windows System Files**: `%WINDIR%\*`
  - Exceptions: Temp, Tasks, and Tracing folders
- **Allow Program Files**: `%PROGRAMFILES%\*`
- **Allow Steam**: 
  - Publisher: `O=VALVE CORPORATION, L=BELLEVUE, S=WASHINGTON, C=US`
  - Path: `%PROGRAMFILES(X86)%\Steam\*`
- **Allow Epic Games**:
  - Publisher: `CN=EPIC GAMES INC, O=EPIC GAMES INC, L=CARY, S=NORTH CAROLINA, C=US`
  - Path: `%PROGRAMFILES%\Epic Games\*`
- **Default Deny Rule**: Block all other executables

#### Script Rules:
- Allow scripts in Windows directory (except Temp)
- Deny all other scripts

#### Windows Installer Rules:
- Allow digitally signed MSI files (Audit mode)
- Allow installers in Windows\Installer folder

### 2. Chrome Browser Restrictions

**File**: `Policies/Teenagers/Browser-Restrictions.pol`

**Key Policies**:

| Policy | Setting | Description |
|--------|---------|-------------|
| BrowserSignin | 2 | Force users to sign in to Chrome |
| RestrictSigninToPattern | *@scottify.io | Only allow scottify.io domain accounts |
| IncognitoModeAvailability | 1 | Completely disable incognito mode |
| ForceSafeSearch | 1 | Enable safe search on all search engines |
| ForceGoogleSafeSearch | 1 | Force Google SafeSearch |
| ForceYouTubeRestrict | 2 | Set YouTube to Strict Restricted Mode |
| DeveloperToolsDisabled | 1 | Disable Chrome Developer Tools |
| PasswordManagerEnabled | 0 | Disable password manager |
| SyncDisabled | 0 | Enable sync for monitoring |

**URL Blacklist**:
- `*://*.vpn.com/*`
- `*://*.proxy.com/*`
- `*://*.hideip.com/*`
- `*://*.torproject.org/*`
- `*://chrome.google.com/webstore/*`

### 3. Blocked Applications

The following applications are explicitly blocked:
- **All web browsers except Chrome**:
  - Microsoft Edge
  - Mozilla Firefox
  - Opera
  - Brave
  - Internet Explorer
- **System Tools**:
  - Command Prompt (cmd.exe)
  - PowerShell
  - Registry Editor (regedit.exe)
  - Task Manager (taskmgr.exe)
- **Developer Tools**:
  - Visual Studio Code
  - Notepad++
  - Any IDE or code editor

### 4. Security Restrictions

**Registry-based restrictions**:
- **DisableCMD**: Prevents command prompt access
- **DisableRegistryTools**: Blocks registry editor
- **DisableTaskMgr**: Prevents task manager access
- **Windows Defender Application Control**: Enhanced security

---

## Deployment Steps

### Deployment Status
✅ **Prerequisites Met** - All requirements verified
❌ **Scripts Validated** - Pending compliance fixes
🔄 **GPO Creation** - Ready when scripts pass validation
🔄 **Policy Import** - Awaiting script fixes
🔄 **Testing Complete** - Not started

### Automated Deployment

1. **Open PowerShell as Administrator** on your domain controller

2. **Navigate to the Scripts directory**:
   ```powershell
   cd C:\GroupPolicy\Scripts
   ```

3. **Run the deployment script**:
   ```powershell
   .\Deploy-TeenagerPolicy.ps1 -DomainName "scottify.io" -TeenagerGroupName "Teenagers"
   ```

4. **Test mode deployment** (no changes made):
   ```powershell
   .\Deploy-TeenagerPolicy.ps1 -TestMode
   ```

### Manual Deployment

If you prefer manual deployment:

1. **Create the GPO**:
   ```powershell
   New-GPO -Name "Teenager Restrictions Policy" -Comment "Restrictions for teenager accounts"
   ```

2. **Import Chrome policies**:
   - Open Group Policy Management Console
   - Edit the GPO
   - Navigate to: Computer Configuration → Policies → Administrative Templates → Google → Google Chrome
   - Configure each policy as specified in the Browser Restrictions section

3. **Import AppLocker rules**:
   ```powershell
   Set-AppLockerPolicy -XmlPolicy "C:\GroupPolicy\Policies\Teenagers\AppLocker-Rules.xml"
   ```

4. **Link GPO to OU**:
   ```powershell
   New-GPLink -Name "Teenager Restrictions Policy" -Target "OU=Teenagers,DC=scottify,DC=io"
   ```

---

## Testing and Verification

### Running the Compliance Test

1. **On a test computer**, run as Administrator:
   ```powershell
   C:\GroupPolicy\Scripts\Test-PolicyCompliance.ps1
   ```

2. **For detailed testing**:
   ```powershell
   .\Test-PolicyCompliance.ps1 -Detailed -UserName "test.teenager"
   ```

### Manual Verification Steps

1. **Verify GPO Application**:
   ```cmd
   gpresult /r
   ```
   Look for "Teenager Restrictions Policy" in the applied GPOs

2. **Check AppLocker Status**:
   ```powershell
   Get-Service AppIDSvc
   Get-AppLockerPolicy -Effective
   ```

3. **Test Application Blocking**:
   - Try to run Firefox or Edge (should be blocked)
   - Try to run Steam (should be allowed)
   - Attempt to open Command Prompt (should be blocked)

4. **Verify Chrome Restrictions**:
   - Open Chrome
   - Verify forced sign-in prompt
   - Try to open incognito mode (Ctrl+Shift+N) - should fail
   - Check that only scottify.io accounts can sign in

### Expected Test Results

✅ **Should PASS**:
- Steam launches successfully
- Epic Games Launcher opens
- Chrome opens with sign-in requirement
- Safe Search is enforced
- Windows system applications work

❌ **Should FAIL**:
- Other browsers cannot launch
- Command Prompt access denied
- Registry Editor blocked
- Task Manager disabled
- Incognito mode unavailable

---

## Troubleshooting

### Common Issues and Solutions

#### 1. GPO Not Applying

**Symptoms**: Policies don't take effect, applications not blocked

**Solutions**:
```powershell
# Force Group Policy update
gpupdate /force

# Check GPO application
gpresult /h C:\gpresult.html
Start-Process C:\gpresult.html

# Verify computer is in correct OU
Get-ADComputer -Identity "ComputerName" -Properties DistinguishedName
```

#### 2. AppLocker Not Working

**Symptoms**: Applications that should be blocked are running

**Solutions**:
```powershell
# Ensure Application Identity service is running
Start-Service AppIDSvc
Set-Service AppIDSvc -StartupType Automatic

# Re-import AppLocker policy
Set-AppLockerPolicy -XmlPolicy "C:\GroupPolicy\Policies\Teenagers\AppLocker-Rules.xml" -Merge

# Check AppLocker events
Get-WinEvent -LogName "Microsoft-Windows-AppLocker/EXE and DLL"
```

#### 3. Chrome Policies Not Applied

**Symptoms**: Chrome doesn't show managed by organization, restrictions not working

**Solutions**:
1. Verify ADMX templates are in Central Store
2. Check registry:
   ```powershell
   Get-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome"
   ```
3. Restart Chrome completely:
   ```cmd
   taskkill /F /IM chrome.exe
   start chrome
   ```

#### 4. User Can Still Access Blocked Sites

**Solutions**:
- Clear Chrome cache and cookies
- Check for VPN software
- Verify DNS settings:
  ```powershell
  nslookup blocked-site.com
  ```

### Event Log Locations

Monitor these logs for issues:
- **AppLocker**: Applications and Services Logs → Microsoft → Windows → AppLocker
- **Group Policy**: Applications and Services Logs → Microsoft → Windows → GroupPolicy
- **System Events**: Windows Logs → System

---

## User Management

### Adding Users to the Teenagers Group

#### Method 1: PowerShell
```powershell
# Add single user
Add-ADGroupMember -Identity "Teenagers" -Members "john.doe"

# Add multiple users
$users = @("john.doe", "jane.smith", "tim.teenager")
Add-ADGroupMember -Identity "Teenagers" -Members $users

# Add all users from an OU
Get-ADUser -Filter * -SearchBase "OU=Teenagers,DC=scottify,DC=io" | 
    ForEach-Object { Add-ADGroupMember -Identity "Teenagers" -Members $_ }
```

#### Method 2: Active Directory Users and Computers GUI
1. Open Active Directory Users and Computers
2. Navigate to the Teenagers group
3. Right-click → Properties → Members tab
4. Click Add and search for users
5. Click OK to save

### Removing Users from the Teenagers Group

```powershell
# Remove single user
Remove-ADGroupMember -Identity "Teenagers" -Members "john.doe" -Confirm:$false

# Remove all members
Get-ADGroupMember -Identity "Teenagers" | 
    ForEach-Object { Remove-ADGroupMember -Identity "Teenagers" -Members $_ -Confirm:$false }
```

### Checking Group Membership

```powershell
# List all members of Teenagers group
Get-ADGroupMember -Identity "Teenagers" | Select-Object Name, SamAccountName

# Check if specific user is in group
(Get-ADUser -Identity "john.doe" -Properties MemberOf).MemberOf -contains "CN=Teenagers,CN=Users,DC=scottify,DC=io"
```

---

## Emergency Override Procedures

### Temporary Policy Disable

#### For Single Computer:
```powershell
# Disable policy temporarily (requires admin rights)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableGPO" -Value 1

# Re-enable after emergency
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableGPO"
gpupdate /force
```

#### For All Computers:
1. **Unlink GPO** (fastest method):
   ```powershell
   Remove-GPLink -Name "Teenager Restrictions Policy" -Target "OU=Teenagers,DC=scottify,DC=io"
   ```

2. **Disable GPO**:
   ```powershell
   (Get-GPO -Name "Teenager Restrictions Policy").GpoStatus = "AllSettingsDisabled"
   ```

### Emergency Access Procedures

#### Grant Temporary Admin Access:
```powershell
# Create temporary admin account
$password = ConvertTo-SecureString "TempP@ssw0rd!" -AsPlainText -Force
New-ADUser -Name "TempAdmin" `
           -AccountPassword $password `
           -Enabled $true `
           -PasswordNeverExpires $true

Add-ADGroupMember -Identity "Domain Admins" -Members "TempAdmin"

# Remove after use
Remove-ADUser -Identity "TempAdmin" -Confirm:$false
```

#### Bypass AppLocker Temporarily:
```powershell
# Stop AppLocker enforcement
Stop-Service AppIDSvc
Set-Service AppIDSvc -StartupType Disabled

# Re-enable after emergency
Set-Service AppIDSvc -StartupType Automatic
Start-Service AppIDSvc
```

### Recovery Procedures

If a computer becomes unusable due to policy:

1. **Boot into Safe Mode**:
   - Restart computer
   - Press F8 during boot
   - Select "Safe Mode with Networking"

2. **Remove from domain** (last resort):
   ```powershell
   # Run in Safe Mode as local admin
   Remove-Computer -UnjoinDomainCredential (Get-Credential) -Force -Restart
   ```

3. **Clear local policy cache**:
   ```cmd
   rd /s /q "%windir%\system32\GroupPolicy"
   rd /s /q "%windir%\system32\GroupPolicyUsers"
   gpupdate /force
   ```

---

## Regular Maintenance

### Daily Tasks

1. **Monitor AppLocker Events**:
   ```powershell
   # Check for blocked execution attempts
   Get-WinEvent -LogName "Microsoft-Windows-AppLocker/EXE and DLL" -MaxEvents 100 |
       Where-Object {$_.LevelDisplayName -eq "Warning" -or $_.LevelDisplayName -eq "Error"}
   ```

2. **Review Chrome Sync Data**:
   - Check browsing history in Google Admin Console
   - Monitor for policy violation attempts

### Weekly Tasks

1. **Verify Policy Compliance**:
   ```powershell
   # Run on sample computers
   .\Test-PolicyCompliance.ps1 -ComputerName "TEEN-PC01"
   ```

2. **Check Group Membership Changes**:
   ```powershell
   # Export current membership
   Get-ADGroupMember -Identity "Teenagers" | 
       Export-Csv "C:\Reports\Teenagers-$(Get-Date -Format 'yyyyMMdd').csv"
   ```

3. **Review Security Logs**:
   ```powershell
   # Check for security events
   Get-EventLog -LogName Security -After (Get-Date).AddDays(-7) |
       Where-Object {$_.EventID -in @(4624, 4625, 4634)} |
       Group-Object EventID
   ```

### Monthly Tasks

1. **Update Application Signatures**:
   - Check for new versions of Steam/Epic Games
   - Update publisher certificates if needed
   - Test with latest application versions

2. **Policy Review Meeting**:
   - Review blocked application requests
   - Assess policy effectiveness
   - Plan any policy adjustments

3. **Backup Policy Configuration**:
   ```powershell
   # Backup GPO
   Backup-GPO -Name "Teenager Restrictions Policy" `
              -Path "C:\Backups\GPO\$(Get-Date -Format 'yyyyMM')" `
              -Comment "Monthly backup"
   
   # Export AppLocker policy
   Get-AppLockerPolicy -Effective -Xml > "C:\Backups\AppLocker-$(Get-Date -Format 'yyyyMMdd').xml"
   ```

### Quarterly Tasks

1. **Security Audit**:
   - Review all policy exceptions
   - Audit user permissions
   - Check for bypass attempts

2. **Update Documentation**:
   - Document any policy changes
   - Update troubleshooting procedures
   - Review emergency procedures

3. **Test Disaster Recovery**:
   - Practice emergency override procedures
   - Test policy restoration from backup
   - Verify recovery documentation

### Annual Tasks

1. **Complete Policy Review**:
   - Reassess business requirements
   - Review with stakeholders
   - Plan major updates

2. **Update Chrome ADMX Templates**:
   ```powershell
   # Download latest Chrome ADMX templates
   # From: https://chromeenterprise.google/browser/download/
   ```

3. **Security Assessment**:
   - Third-party security audit
   - Penetration testing
   - Compliance verification

---

## Appendix

### Useful PowerShell Commands

```powershell
# Get all computers with applied GPO
Get-ADComputer -Filter * -Properties Name | ForEach-Object {
    $result = gpresult /s $_.Name /r | Select-String "Teenager Restrictions Policy"
    if ($result) { Write-Host "$($_.Name) has policy applied" -ForegroundColor Green }
}

# Find users not in domain
Get-ADUser -Filter * -Properties MemberOf | Where-Object {
    $_.MemberOf -contains "CN=Teenagers,CN=Users,DC=scottify,DC=io" -and
    $_.UserPrincipalName -notlike "*@scottify.io"
}

# Generate compliance report
$report = @()
Get-ADGroupMember -Identity "Teenagers" | ForEach-Object {
    $user = Get-ADUser -Identity $_.SamAccountName -Properties LastLogonDate
    $report += [PSCustomObject]@{
        Username = $user.SamAccountName
        Name = $user.Name
        LastLogon = $user.LastLogonDate
        Enabled = $user.Enabled
    }
}
$report | Export-Csv "C:\Reports\TeenagerUsers-$(Get-Date -Format 'yyyyMMdd').csv"
```

### Registry Keys Reference

**Chrome Policies**: `HKLM:\SOFTWARE\Policies\Google\Chrome`
**AppLocker**: `HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2`
**Security**: `HKLM:\SOFTWARE\Policies\Microsoft\Windows\System`

### Support Contact

For additional support or questions about this policy system:
- **Email**: admin@scottify.io
- **Internal Ticket System**: https://support.scottify.io
- **Emergency Contact**: +1-XXX-XXX-XXXX (24/7 for critical issues)

---

**Document Version**: 1.0  
**Last Updated**: 2025-07-06  
**Maintained By**: IT Security Team - scottify.io