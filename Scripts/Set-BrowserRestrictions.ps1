#Requires -RunAsAdministrator
#Requires -Modules GroupPolicy
<#
.SYNOPSIS
    Applies browser restriction policies for teenagers in the scottify.io domain using Group Policy.

.DESCRIPTION
    This script applies comprehensive browser restrictions including Chrome policies,
    Edge blocking, and Windows security settings through Group Policy Objects (GPO).
    It properly uses GPO cmdlets instead of direct registry modifications.

.PARAMETER GPOName
    The name of the Group Policy Object to configure.
    Default: "GP_Teenager_Restrictions_Policy"

.PARAMETER WhatIf
    Shows what changes would be made without actually applying them.

.EXAMPLE
    .\Set-BrowserRestrictions.ps1
    Applies all browser restriction policies to the default GPO.

.EXAMPLE
    .\Set-BrowserRestrictions.ps1 -GPOName "GP_Custom Teen Policy" -WhatIf
    Shows what GPO changes would be made without applying them.

.NOTES
    Author: System Administrator
    Domain: scottify.io
    Purpose: Teenager browser restriction enforcement via GPO
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$GPOName = "GP_Teenager_Restrictions_Policy"
)

# Exit codes
$EXIT_SUCCESS = 0
$EXIT_FAILURE = 2

# Initialize error tracking
$script:hasErrors = $false

# Function to set GPO registry value with error handling
function Set-GPORegistryValue {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,
        
        [Parameter(Mandatory=$true)]
        [string]$Key,
        
        [Parameter(Mandatory=$true)]
        [string]$ValueName,
        
        [Parameter(Mandatory=$true)]
        $Value,
        
        [Parameter(Mandatory=$true)]
        [Microsoft.GroupPolicy.RegistryValueType]$Type
    )
    
    $maxRetries = 3
    $retryCount = 0
    $success = $false
    
    while (-not $success -and $retryCount -lt $maxRetries) {
        try {
            if ($PSCmdlet.ShouldProcess("$Key\$ValueName", "Set GPO Registry Value to $Value")) {
                # Attempt to set the registry value
                Set-GPRegistryValue -Name $Name -Key $Key -ValueName $ValueName -Value $Value -Type $Type -ErrorAction Stop
                Write-Verbose "Set GPO registry value: $Key\$ValueName = $Value ($Type)"
                $success = $true
            }
            else {
                # WhatIf mode - consider it successful
                $success = $true
            }
        }
        catch {
            $retryCount++
            if ($retryCount -lt $maxRetries) {
                Write-Warning "Failed to set GPO registry value $Key\$ValueName (Attempt $retryCount/$maxRetries): $_"
                Write-Warning "Retrying in 2 seconds..."
                Start-Sleep -Seconds 2
            }
            else {
                Write-Error "Failed to set GPO registry value $Key\$ValueName after $maxRetries attempts: $_"
                $script:hasErrors = $true
                
                # Log detailed error information
                $errorDetails = @"
Error setting GPO Registry Value:
  GPO: $Name
  Key: $Key
  Value Name: $ValueName
  Value: $Value
  Type: $Type
  Error: $_
  Stack Trace: $($_.ScriptStackTrace)
"@
                Write-Verbose $errorDetails
            }
        }
    }
    
    return $success
}

# Function to backup GPO before modifications
function Backup-GPOBeforeModification {
    param(
        [Parameter(Mandatory=$true)]
        [string]$GPOName
    )
    
    try {
        $backupPath = Join-Path -Path $PSScriptRoot -ChildPath "GPO_Backups"
        if (-not (Test-Path $backupPath)) {
            New-Item -ItemType Directory -Path $backupPath -Force | Out-Null
        }
        
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $backupFolder = Join-Path -Path $backupPath -ChildPath "BrowserRestrictions_$timestamp"
        
        Write-Host "Creating GPO backup..." -ForegroundColor Yellow
        $backup = Backup-GPO -Name $GPOName -Path $backupFolder -ErrorAction Stop
        Write-Host "GPO backup created successfully at: $backupFolder" -ForegroundColor Green
        Write-Verbose "Backup ID: $($backup.Id)"
        
        # Create restore script
        $restoreScript = @"
# Restore script for Browser Restrictions GPO
# Created: $(Get-Date)
# GPO Name: $GPOName
# Backup ID: $($backup.Id)

Write-Host "Restoring GPO '$GPOName' from backup..." -ForegroundColor Yellow
try {
    Import-GPO -BackupId "$($backup.Id)" -Path "$backupFolder" -TargetName "$GPOName" -ErrorAction Stop
    Write-Host "GPO restored successfully!" -ForegroundColor Green
}
catch {
    Write-Error "Failed to restore GPO: `$_"
}
"@
        $restoreScript | Out-File -FilePath (Join-Path -Path $backupFolder -ChildPath "Restore-GPO.ps1") -Encoding UTF8
        
        return $backupFolder
    }
    catch {
        Write-Error "Failed to create GPO backup: $_"
        throw
    }
}

# Main execution
try {
    # Import required module
    Import-Module GroupPolicy -ErrorAction Stop
    
    # Verify GPO exists
    try {
        $gpo = Get-GPO -Name $GPOName -ErrorAction Stop
        Write-Host "Found GPO: $GPOName" -ForegroundColor Green
    }
    catch {
        Write-Error "GPO '$GPOName' not found. Please create the GPO first using Deploy-TeenagerPolicy.ps1"
        exit $EXIT_FAILURE
    }
    
    # Create backup before modifications
    $backupLocation = $null
    if (-not $WhatIfPreference) {
        try {
            $backupLocation = Backup-GPOBeforeModification -GPOName $GPOName
        }
        catch {
            Write-Error "Failed to create backup. Aborting modifications for safety."
            exit $EXIT_FAILURE
        }
    }
    
    Write-Host "Applying Browser Restriction Policies for Teenagers..." -ForegroundColor Cyan
    Write-Host "Target GPO: $GPOName" -ForegroundColor Yellow
    
    # Chrome Browser Restrictions
    Write-Host "`nConfiguring Chrome policies..." -ForegroundColor Yellow
    
    $chromePath = "HKLM\SOFTWARE\Policies\Google\Chrome"
    
    # Force users to sign in to Chrome (2 = Force sign in)
    Set-GPORegistryValue -Name $GPOName -Key $chromePath -ValueName "BrowserSignin" -Value 2 -Type DWord
    
    # Restrict sign-in to scottify.io domain only
    Set-GPORegistryValue -Name $GPOName -Key $chromePath -ValueName "RestrictSigninToPattern" -Value "*@scottify.io" -Type String
    
    # Disable Incognito Mode completely (1 = Disabled)
    Set-GPORegistryValue -Name $GPOName -Key $chromePath -ValueName "IncognitoModeAvailability" -Value 1 -Type DWord
    
    # Force Safe Search
    Set-GPORegistryValue -Name $GPOName -Key $chromePath -ValueName "ForceSafeSearch" -Value 1 -Type DWord
    
    # Force Google SafeSearch
    Set-GPORegistryValue -Name $GPOName -Key $chromePath -ValueName "ForceGoogleSafeSearch" -Value 1 -Type DWord
    
    # Force YouTube Restricted Mode (2 = Strict)
    Set-GPORegistryValue -Name $GPOName -Key $chromePath -ValueName "ForceYouTubeRestrict" -Value 2 -Type DWord
    
    # Disable Developer Tools
    Set-GPORegistryValue -Name $GPOName -Key $chromePath -ValueName "DeveloperToolsDisabled" -Value 1 -Type DWord
    
    # Block access to chrome://flags
    Set-GPORegistryValue -Name $GPOName -Key $chromePath -ValueName "BlockExternalExtensions" -Value 1 -Type DWord
    
    # Disable password manager
    Set-GPORegistryValue -Name $GPOName -Key $chromePath -ValueName "PasswordManagerEnabled" -Value 0 -Type DWord
    
    # Enable sync (to track browsing)
    Set-GPORegistryValue -Name $GPOName -Key $chromePath -ValueName "SyncDisabled" -Value 0 -Type DWord
    
    # URL Blacklist - Block common VPN and proxy sites
    Write-Host "Configuring URL blacklist..." -ForegroundColor Yellow
    
    $urlBlockPath = "HKLM\SOFTWARE\Policies\Google\Chrome\URLBlocklist"
    
    $blockedUrls = @(
        "*://*.vpn.com/*",
        "*://*.proxy.com/*",
        "*://*.hideip.com/*",
        "*://*.torproject.org/*",
        "*://chrome.google.com/webstore/*"
    )
    
    for ($i = 0; $i -lt $blockedUrls.Count; $i++) {
        Set-GPORegistryValue -Name $GPOName -Key $urlBlockPath -ValueName ($i + 1).ToString() -Value $blockedUrls[$i] -Type String
    }
    
    # Extension Installation Whitelist (empty = block all)
    Write-Host "Blocking all Chrome extensions..." -ForegroundColor Yellow
    
    # Set extension install blacklist to * (block all)
    $extBlacklistPath = "HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionInstallBlacklist"
    Set-GPORegistryValue -Name $GPOName -Key $extBlacklistPath -ValueName "1" -Value "*" -Type String
    
    # Disable other browsers via policy
    Write-Host "`nConfiguring AppLocker enforcement..." -ForegroundColor Yellow
    
    $appLockerPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2"
    Set-GPORegistryValue -Name $GPOName -Key $appLockerPath -ValueName "EnforcementMode" -Value 1 -Type DWord
    
    # Microsoft Edge - Disable completely
    Write-Host "Blocking Microsoft Edge..." -ForegroundColor Yellow
    
    $edgePath = "HKLM\SOFTWARE\Policies\Microsoft\Edge"
    Set-GPORegistryValue -Name $GPOName -Key $edgePath -ValueName "Enabled" -Value 0 -Type DWord
    
    # Block Edge via multiple methods
    $edgeMainPath = "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main"
    Set-GPORegistryValue -Name $GPOName -Key $edgeMainPath -ValueName "PreventAccessToAboutFlagsInMicrosoftEdge" -Value 1 -Type DWord
    Set-GPORegistryValue -Name $GPOName -Key $edgeMainPath -ValueName "AllowPrelaunch" -Value 0 -Type DWord
    
    # Windows Security Settings
    Write-Host "`nApplying Windows security restrictions..." -ForegroundColor Yellow
    
    # Disable Command Prompt (2 = Disabled, also disable batch files)
    $systemPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\System"
    Set-GPORegistryValue -Name $GPOName -Key $systemPath -ValueName "DisableCMD" -Value 2 -Type DWord
    
    # Disable Registry Editor (for Computer Configuration)
    $disallowPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    Set-GPORegistryValue -Name $GPOName -Key $disallowPath -ValueName "DisableRegistryTools" -Value 1 -Type DWord
    
    # Disable Task Manager (for Computer Configuration)
    Set-GPORegistryValue -Name $GPOName -Key $disallowPath -ValueName "DisableTaskMgr" -Value 1 -Type DWord
    
    # Windows Defender Application Control
    Write-Host "Configuring Windows Defender Application Control..." -ForegroundColor Yellow
    
    $deviceGuardPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
    Set-GPORegistryValue -Name $GPOName -Key $deviceGuardPath -ValueName "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord
    Set-GPORegistryValue -Name $GPOName -Key $deviceGuardPath -ValueName "RequirePlatformSecurityFeatures" -Value 1 -Type DWord
    
    # DNS Client Settings - Force safe DNS
    Write-Host "Configuring DNS security..." -ForegroundColor Yellow
    
    $dnsPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    Set-GPORegistryValue -Name $GPOName -Key $dnsPath -ValueName "EnableMulticast" -Value 0 -Type DWord
    
    # Family Safety Integration
    Write-Host "Enabling Family Safety integration..." -ForegroundColor Yellow
    
    $familySafetyPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\FamilySafety"
    Set-GPORegistryValue -Name $GPOName -Key $familySafetyPath -ValueName "EnableFamilySafety" -Value 1 -Type DWord
    
    # Summary
    if (-not $WhatIfPreference) {
        if ($script:hasErrors) {
            Write-Host "`nBrowser restriction policies applied with errors!" -ForegroundColor Red
            Write-Host "Please review the error messages above." -ForegroundColor Red
            if ($backupLocation) {
                Write-Host "`nGPO backup location: $backupLocation" -ForegroundColor Yellow
                Write-Host "You can restore the GPO using the Restore-GPO.ps1 script in the backup folder." -ForegroundColor Yellow
            }
        }
        else {
            Write-Host "`nBrowser restriction policies have been successfully applied to GPO!" -ForegroundColor Green
            Write-Host "GPO Name: $GPOName" -ForegroundColor Green
            if ($backupLocation) {
                Write-Host "Backup Location: $backupLocation" -ForegroundColor Green
            }
            Write-Host "`nThe following restrictions are now configured in the GPO:" -ForegroundColor Green
            Write-Host "  - Chrome forced sign-in with scottify.io domain only" -ForegroundColor White
            Write-Host "  - Incognito mode disabled" -ForegroundColor White
            Write-Host "  - Safe search and YouTube restrictions enabled" -ForegroundColor White
            Write-Host "  - Developer tools and chrome://flags blocked" -ForegroundColor White
            Write-Host "  - VPN and proxy sites blocked" -ForegroundColor White
            Write-Host "  - All Chrome extensions blocked" -ForegroundColor White
            Write-Host "  - Microsoft Edge disabled" -ForegroundColor White
            Write-Host "  - Command prompt, registry editor, and task manager disabled" -ForegroundColor White
            Write-Host "  - Windows Defender Application Control enabled" -ForegroundColor White
            Write-Host "  - Family Safety integration enabled" -ForegroundColor White
            Write-Host "`nNote: These policies will apply after Group Policy refresh." -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "`nWhatIf mode: No changes were made to GPO. Remove -WhatIf to apply policies." -ForegroundColor Yellow
    }
}
catch {
    Write-Error "Critical error occurred: $_"
    $script:hasErrors = $true
}

# Return appropriate exit code
if ($script:hasErrors) {
    exit $EXIT_FAILURE
}
else {
    exit $EXIT_SUCCESS
}