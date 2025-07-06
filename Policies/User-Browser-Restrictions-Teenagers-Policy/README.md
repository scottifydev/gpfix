# User Browser Restrictions Policy for Teenagers

## Purpose and Scope

This policy implements comprehensive browser and system restrictions for teenage users to ensure safe and monitored internet usage. It enforces Chrome as the primary browser with extensive safety controls while blocking alternative browsers and system tools that could bypass restrictions.

### Key Features
- Forces Chrome browser sign-in with domain restrictions
- Disables private browsing (Incognito mode)
- Enforces SafeSearch and YouTube Restricted Mode
- Blocks VPN and proxy websites
- Disables browser developer tools and extensions
- Prevents access to Registry Editor, Command Prompt, and Task Manager
- Blocks Microsoft Edge and other browsers

## Security Implications

### Strengths
- **Multi-layered Protection**: Combines browser policies, URL filtering, and system restrictions
- **Anti-bypass Measures**: Blocks common methods to circumvent restrictions (VPNs, proxies, developer tools)
- **Centralized Management**: All settings controlled via Group Policy
- **Audit Trail**: Browser sync enabled for activity monitoring
- **Safe Content**: Forced SafeSearch across Google services

### Considerations
- Password manager disabled - users need alternative secure password storage
- No browser extensions allowed - may impact productivity tools
- Command prompt and registry access blocked - limits troubleshooting
- Browser sync enabled - privacy implications for browsing history

### Potential Vulnerabilities
- Portable browsers on USB drives could bypass restrictions
- Web-based proxies not in blocklist might be accessible
- System restrictions apply per-user, not system-wide
- PowerShell not explicitly blocked (though scripts are controlled via AppLocker)

## Target Audience

This policy is designed for:
- **Teenagers (13-17 years)**: Primary target for safe internet browsing
- **Home Environments**: Parents managing family computers
- **Schools**: Student computers in educational settings
- **Libraries**: Public access computers for minors
- **Youth Organizations**: Controlled internet access environments

### Prerequisites
- Windows 10/11 Pro, Enterprise, or Education
- Active Directory domain environment
- Google Chrome installed on target systems
- Users must have domain accounts for sign-in restriction

## Testing Procedures

### Pre-Deployment Testing

1. **Test Environment Setup**
   ```powershell
   # Create test OU
   New-ADOrganizationalUnit -Name "Test-Browser-Restrictions" -Path "DC=domain,DC=com"
   
   # Create test user
   New-ADUser -Name "TestTeenager" -SamAccountName "testteen" -Path "OU=Test-Browser-Restrictions,DC=domain,DC=com"
   
   # Apply policy
   New-GPLink -Name "User-Browser-Restrictions-Teenagers-Policy" -Target "OU=Test-Browser-Restrictions,DC=domain,DC=com"
   ```

2. **Browser Functionality Tests**
   - Launch Chrome - verify sign-in requirement
   - Attempt sign-in with non-domain account (should fail)
   - Try opening Incognito window (Ctrl+Shift+N) - should be blocked
   - Search for adult content - verify SafeSearch active
   - Access YouTube - verify Restricted Mode
   - Try installing extension from Chrome Web Store (should be blocked)
   - Press F12 for Developer Tools (should be blocked)

3. **URL Blocking Tests**
   ```
   Test URLs:
   - https://www.vpn.com (should be blocked)
   - https://proxy.com (should be blocked)
   - https://www.torproject.org (should be blocked)
   - https://chrome.google.com/webstore (should be blocked)
   ```

4. **System Restrictions Tests**
   - Press Win+R, type "regedit" (should be blocked)
   - Press Win+R, type "cmd" (should be blocked)
   - Press Ctrl+Shift+Esc for Task Manager (should be blocked)
   - Try launching Microsoft Edge (should fail)

5. **Policy Application Verification**
   ```powershell
   # Check applied policies
   gpresult /h GPReport.html /user domain\testteen
   
   # Verify Chrome policies
   Get-ItemProperty "HKLM:\SOFTWARE\Policies\Google\Chrome"
   
   # Check system policies
   Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
   ```

### User Acceptance Testing

1. **Typical Usage Scenarios**
   - Browse educational websites
   - Use Google Workspace applications
   - Watch educational YouTube videos
   - Complete online homework

2. **Document Issues**
   - Note any legitimate sites incorrectly blocked
   - Record any needed applications that don't work
   - List any educational tools impacted

## Rollback Procedures

### Immediate Rollback

1. **Emergency Disable**
   ```powershell
   # Unlink policy immediately
   Remove-GPLink -Name "User-Browser-Restrictions-Teenagers-Policy" -Target "OU=Teenagers,DC=domain,DC=com"
   
   # Force policy refresh
   Invoke-GPUpdate -Force -Computer "TargetComputer" -User "domain\teenager"
   
   # Clear Chrome policies via registry (run as admin)
   Remove-Item "HKLM:\SOFTWARE\Policies\Google\Chrome" -Recurse -Force
   Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Recurse -Force
   ```

2. **Re-enable System Tools**
   ```powershell
   # Re-enable Task Manager
   Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableTaskMgr" -Value 0
   
   # Re-enable Registry Editor
   Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableRegistryTools" -Value 0
   
   # Re-enable Command Prompt
   Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableCMD"
   ```

### Gradual Rollback

1. **Selective Policy Modification**
   - Keep SafeSearch enabled but allow extensions
   - Maintain URL blocklist but enable developer tools
   - Allow Task Manager but keep Registry Editor blocked

2. **Convert to Advisory Mode**
   - Remove enforcement policies
   - Implement monitoring and alerting instead
   - Educate users on safe browsing practices

### Post-Rollback Actions

1. **Impact Analysis**
   ```powershell
   # Export current browser history before policy removal
   $profile = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"
   Copy-Item "$profile\History" "C:\Backup\Chrome-History-$(Get-Date -Format yyyyMMdd).db"
   
   # Document policy violations that would have occurred
   Get-EventLog -LogName Application -Source Chrome | Where-Object {$_.EventID -eq 1001}
   ```

2. **Policy Refinement Options**
   - Add specific domains to allowlist
   - Create time-based restrictions (school hours only)
   - Implement different restriction levels by age group
   - Allow specific educational extensions

## Deployment Instructions

### Using the Conversion Script

1. **Convert Registry File to GPO**
   ```powershell
   # Navigate to scripts directory
   cd "C:\GroupPolicy\Scripts"
   
   # Run conversion with your domain
   .\Convert-RegToGPO.ps1 -InputFile "..\Policies\User-Browser-Restrictions-Teenagers-Policy\Browser-Restrictions.pol" `
                          -OutputFile "..\Policies\User-Browser-Restrictions-Teenagers-Policy\Browser-Restrictions.xml" `
                          -DomainPattern "*@yourdomain.com"
   ```

2. **Import to Group Policy**
   ```powershell
   # Create new GPO
   New-GPO -Name "User-Browser-Restrictions-Teenagers"
   
   # Import settings (manual process - use Group Policy Management Console)
   # 1. Open GPMC
   # 2. Right-click the new GPO and select "Edit"
   # 3. Navigate to each policy location and configure according to XML output
   ```

3. **Link to Appropriate OU**
   ```powershell
   New-GPLink -Name "User-Browser-Restrictions-Teenagers" -Target "OU=Teenagers,DC=domain,DC=com"
   ```

## Maintenance and Updates

### Regular Tasks

1. **Weekly Reviews**
   - Check blocked URL attempts in proxy logs
   - Review Chrome sync data for policy violations
   - Monitor for new bypass methods

2. **Monthly Updates**
   - Update VPN/proxy blocklist with new domains
   - Review and adjust SafeSearch effectiveness
   - Check for Chrome policy updates

3. **Quarterly Audits**
   - Full policy effectiveness review
   - User feedback collection
   - Security assessment for new threats

### Adding URL Blocks
```powershell
# Add new blocked URL
$blocklist = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Google\Chrome\URLBlocklist"
$newIndex = ($blocklist.PSObject.Properties | Where-Object {$_.Name -match '^\d+$'} | Measure-Object).Count + 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome\URLBlocklist" -Name $newIndex -Value "*://newblockedsite.com/*"
```

### Monitoring Commands
```powershell
# Check Chrome policy application
Start-Process "chrome://policy"

# Verify specific policies
(Get-ItemProperty "HKLM:\SOFTWARE\Policies\Google\Chrome").IncognitoModeAvailability

# Test URL blocking
Test-NetConnection -ComputerName "vpn.com" -Port 443

# Check user's Chrome sync status
Get-Process Chrome | Select-Object -Property ProcessName, StartTime, @{Name="User";Expression={$_.GetOwner().User}}
```

## Troubleshooting

### Common Issues

1. **Chrome Won't Start**
   - Check if sign-in pattern matches user's domain
   - Verify Chrome is properly installed
   - Check Event Viewer for policy conflicts

2. **Legitimate Sites Blocked**
   - Add to Chrome's URLAllowlist
   - Create exception in policy
   - Consider category-based filtering instead

3. **Policy Not Applying**
   ```powershell
   # Force policy update
   gpupdate /force
   
   # Check policy application
   rsop.msc
   
   # Verify registry keys
   reg query "HKLM\SOFTWARE\Policies\Google\Chrome" /s
   ```

### Support Escalation Path
1. First Level: Check policy application and basic troubleshooting
2. Second Level: Modify policy exceptions and allowlists
3. Third Level: Policy architecture review and redesign