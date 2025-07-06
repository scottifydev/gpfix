<#
.SYNOPSIS
    Safely removes the teenager restrictions Group Policy.

.DESCRIPTION
    This script removes all components of the teenager restrictions policy including:
    - GPO links from OUs
    - The GPO itself
    - AppLocker rules
    - Chrome policy registry entries
    - Restores default security settings
    
.PARAMETER Force
    Skip all confirmation prompts

.PARAMETER WhatIf
    Shows what would happen without making actual changes

.PARAMETER BackupPath
    Path to store backup before removal (default: current directory)

.PARAMETER DomainDN
    Distinguished Name of the domain (default: DC=scottify,DC=io)

.EXAMPLE
    .\Remove-TeenagerPolicy.ps1
    Removes the policy with confirmation prompts

.EXAMPLE
    .\Remove-TeenagerPolicy.ps1 -Force
    Removes the policy without confirmation prompts

.EXAMPLE
    .\Remove-TeenagerPolicy.ps1 -WhatIf
    Shows what would be removed without making changes
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter()]
    [switch]$Force,
    
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$BackupPath = ".\TeenagerPolicy_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$DomainDN = "DC=scottify,DC=io"
)

#Requires -RunAsAdministrator
#Requires -Modules ActiveDirectory, GroupPolicy, AppLocker

# Script configuration
$GPOName = "GP_Teenager_Restrictions_Policy"
$TeenagerOUPath = "OU=Teenagers,OU=Users,$DomainDN"
$LogFile = ".\TeenagerPolicyRemoval_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$ChromeRegPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
$EdgeRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"

# Initialize logging
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp [$Level] $Message"
    
    # Write to console with color
    switch ($Level) {
        "Error" { Write-Host $logMessage -ForegroundColor Red }
        "Warning" { Write-Host $logMessage -ForegroundColor Yellow }
        "Success" { Write-Host $logMessage -ForegroundColor Green }
        default { Write-Host $logMessage }
    }
    
    # Write to log file
    $logMessage | Out-File -FilePath $LogFile -Append
}

function Test-Prerequisites {
    Write-Log "Checking prerequisites..."
    
    $issues = @()
    
    # Check if running as administrator
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        $issues += "Script must be run as Administrator"
    }
    
    # Check required modules
    $requiredModules = @("GroupPolicy", "AppLocker")
    foreach ($module in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            $issues += "Required module '$module' is not installed"
        }
    }
    
    # Check if GPO exists
    try {
        $gpo = Get-GPO -Name $GPOName -ErrorAction Stop
        Write-Log "Found GPO: $($gpo.DisplayName) (ID: $($gpo.Id))"
    }
    catch {
        $issues += "GPO '$GPOName' not found"
    }
    
    if ($issues.Count -gt 0) {
        Write-Log "Prerequisites check failed:" "Error"
        $issues | ForEach-Object { Write-Log "  - $_" "Error" }
        return $false
    }
    
    Write-Log "Prerequisites check passed" "Success"
    return $true
}

function Backup-CurrentState {
    param([string]$Path)
    
    Write-Log "Creating backup at: $Path"
    
    if (-not (Test-Path $Path)) {
        try {
            New-Item -ItemType Directory -Path $Path -Force | Out-Null
        }
        catch {
            Write-Log "Failed to create backup directory: $_" "Error"
            return $false
        }
    }
    
    $backupSuccess = $true
    
    try {
        # Backup GPO
        Write-Log "Backing up GPO..."
        try {
            $gpo = Get-GPO -Name $GPOName -ErrorAction Stop
            $backupResult = Backup-GPO -Guid $gpo.Id -Path $Path -ErrorAction Stop
            Write-Log "GPO backed up successfully (ID: $($backupResult.Id))" "Success"
        }
        catch {
            Write-Log "Failed to backup GPO: $_" "Error"
            $backupSuccess = $false
        }
        
        # Backup AppLocker policies
        Write-Log "Backing up AppLocker policies..."
        try {
            $appLockerPolicy = Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop
            if ($appLockerPolicy) {
                $appLockerPolicy | Out-File "$Path\AppLockerPolicy.xml" -ErrorAction Stop
                Write-Log "AppLocker policies backed up successfully" "Success"
            }
        }
        catch {
            Write-Log "Failed to backup AppLocker policies: $_" "Warning"
            # Not critical - continue
        }
        
        # Backup Chrome registry settings
        Write-Log "Backing up Chrome registry settings..."
        if (Test-Path $ChromeRegPath) {
            try {
                $regResult = reg export "HKLM\SOFTWARE\Policies\Google\Chrome" "$Path\ChromePolicies.reg" /y 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-Log "Chrome policies backed up successfully" "Success"
                }
                else {
                    Write-Log "Failed to backup Chrome policies: $regResult" "Warning"
                }
            }
            catch {
                Write-Log "Failed to backup Chrome policies: $_" "Warning"
            }
        }
        
        # Backup Edge registry settings
        Write-Log "Backing up Edge registry settings..."
        if (Test-Path $EdgeRegPath) {
            try {
                $regResult = reg export "HKLM\SOFTWARE\Policies\Microsoft\Edge" "$Path\EdgePolicies.reg" /y 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-Log "Edge policies backed up successfully" "Success"
                }
                else {
                    Write-Log "Failed to backup Edge policies: $regResult" "Warning"
                }
            }
            catch {
                Write-Log "Failed to backup Edge policies: $_" "Warning"
            }
        }
        
        # Create restoration script
        $restorationScript = @"
# Restoration script for Teenager Policy
# Generated on: $(Get-Date)

Write-Host "Restoring Teenager Policy from backup..."

# Restore GPO
Import-GPO -BackupId (Get-ChildItem -Path "." -Directory | Where-Object {`$_.Name -match "^{.*}$"} | Select-Object -First 1).Name -Path "." -TargetName "$GPOName" -CreateIfNeeded

# Restore AppLocker policies
Set-AppLockerPolicy -XmlPolicy (Get-Content ".\AppLockerPolicy.xml" -Raw)

# Restore Chrome policies
if (Test-Path ".\ChromePolicies.reg") {
    reg import ".\ChromePolicies.reg"
}

# Restore Edge policies
if (Test-Path ".\EdgePolicies.reg") {
    reg import ".\EdgePolicies.reg"
}

Write-Host "Restoration complete!"
"@
        
        $restorationScript | Out-File "$Path\Restore-TeenagerPolicy.ps1"
        
        Write-Log "Backup completed successfully" "Success"
        return $backupSuccess
    }
    catch {
        Write-Log "Backup process encountered error: $_" "Error"
        return $false
    }
}

function Remove-GPOLinks {
    Write-Log "Removing GPO links..."
    
    $overallSuccess = $true
    
    try {
        # Get all GPO links
        $gpo = Get-GPO -Name $GPOName -ErrorAction Stop
        
        # Get GPO Report and parse links
        $gpoReport = Get-GPOReport -Name $GPOName -ReportType Xml -ErrorAction Stop
        $xml = [xml]$gpoReport
        $links = $xml.GPO.LinksTo | Where-Object { $_.Enabled -eq "true" }
        
        if (-not $links -or $links.Count -eq 0) {
            Write-Log "No GPO links found" "Warning"
            return $true
        }
        
        foreach ($link in $links) {
            $targetPath = $link.SOMPath
            if ($PSCmdlet.ShouldProcess($targetPath, "Remove GPO link")) {
                try {
                    Write-Log "Removing GPO link from: $targetPath"
                    Remove-GPLink -Name $GPOName -Target $targetPath -Confirm:$false -ErrorAction Stop
                    Write-Log "GPO link removed from: $targetPath" "Success"
                }
                catch {
                    Write-Log "Failed to remove GPO link from ${targetPath}: $_" "Error"
                    $overallSuccess = $false
                    # Continue with other links even if one fails
                }
            }
        }
        
        return $overallSuccess
    }
    catch {
        Write-Log "Failed to retrieve GPO links: $_" "Error"
        return $false
    }
}

function Remove-GroupPolicy {
    Write-Log "Removing Group Policy Object..."
    
    try {
        $gpo = Get-GPO -Name $GPOName -ErrorAction Stop
        
        if ($PSCmdlet.ShouldProcess($GPOName, "Remove GPO")) {
            if (-not $Force) {
                $confirmation = Read-Host "Are you sure you want to delete the GPO '$GPOName'? (Y/N)"
                if ($confirmation -ne 'Y') {
                    Write-Log "GPO removal cancelled by user" "Warning"
                    return $false
                }
            }
            
            try {
                Remove-GPO -Name $GPOName -Confirm:$false -ErrorAction Stop
                Write-Log "GPO '$GPOName' removed successfully" "Success"
                return $true
            }
            catch {
                Write-Log "Failed to remove GPO during deletion: $_" "Error"
                
                # Try alternative removal method
                try {
                    Write-Log "Attempting alternative removal method..." "Warning"
                    $gpo | Remove-GPO -Confirm:$false -ErrorAction Stop
                    Write-Log "GPO removed successfully using alternative method" "Success"
                    return $true
                }
                catch {
                    Write-Log "Alternative removal method also failed: $_" "Error"
                    return $false
                }
            }
        }
        
        return $true
    }
    catch {
        Write-Log "Failed to retrieve GPO for removal: $_" "Error"
        return $false
    }
}

function Remove-AppLockerRules {
    Write-Log "Removing AppLocker rules..."
    
    try {
        # Get current AppLocker policy
        $currentPolicy = Get-AppLockerPolicy -Effective -Xml
        
        # Parse XML and remove teenager-specific rules
        $xml = [xml]$currentPolicy
        $rulesToRemove = @()
        
        # Find rules with teenager-specific conditions
        $ruleCollections = $xml.AppLockerPolicy.RuleCollection
        
        foreach ($collection in $ruleCollections) {
            foreach ($rule in $collection.ChildNodes) {
                if ($rule.Name -match "Teenager" -or $rule.Description -match "Teenager") {
                    $rulesToRemove += $rule
                    Write-Log "Found teenager rule to remove: $($rule.Name)"
                }
            }
        }
        
        if ($rulesToRemove.Count -eq 0) {
            Write-Log "No teenager-specific AppLocker rules found" "Warning"
            return $true
        }
        
        if ($PSCmdlet.ShouldProcess("AppLocker Rules", "Remove $($rulesToRemove.Count) teenager rules")) {
            # Remove the rules
            foreach ($rule in $rulesToRemove) {
                $rule.ParentNode.RemoveChild($rule) | Out-Null
            }
            
            # Apply the modified policy
            Set-AppLockerPolicy -XmlPolicy $xml.OuterXml
            Write-Log "Removed $($rulesToRemove.Count) AppLocker rules" "Success"
        }
        
        return $true
    }
    catch {
        Write-Log "Failed to remove AppLocker rules: $_" "Error"
        return $false
    }
}

function Remove-BrowserPolicies {
    Write-Log "Removing browser policy registry entries..."
    
    $registryPaths = @(
        @{Path = $ChromeRegPath; Name = "Chrome"},
        @{Path = $EdgeRegPath; Name = "Edge"}
    )
    
    foreach ($reg in $registryPaths) {
        if (Test-Path $reg.Path) {
            try {
                if ($PSCmdlet.ShouldProcess($reg.Path, "Remove registry entries")) {
                    # Remove specific teenager-related keys
                    $keysToRemove = @(
                        "URLBlocklist",
                        "URLAllowlist",
                        "SafeBrowsingEnabled",
                        "IncognitoModeAvailability",
                        "DeveloperToolsAvailability",
                        "ExtensionInstallBlocklist",
                        "ExtensionInstallAllowlist"
                    )
                    
                    foreach ($key in $keysToRemove) {
                        try {
                            if (Get-ItemProperty -Path $reg.Path -Name $key -ErrorAction SilentlyContinue) {
                                Remove-ItemProperty -Path $reg.Path -Name $key -Force -ErrorAction Stop
                                Write-Log "Removed $($reg.Name) policy: $key"
                            }
                        }
                        catch {
                            Write-Log "Failed to remove $($reg.Name) policy '$key': $_" "Error"
                        }
                    }
                    
                    # If no other policies remain, remove the entire key
                    try {
                        $remainingValues = (Get-Item -Path $reg.Path -ErrorAction Stop).Property
                        if ($remainingValues.Count -eq 0) {
                            Remove-Item -Path $reg.Path -Recurse -Force -ErrorAction Stop
                            Write-Log "Removed empty $($reg.Name) policy key" "Success"
                        }
                    }
                    catch {
                        Write-Log "Failed to check/remove empty $($reg.Name) key: $_" "Error"
                    }
                }
            }
            catch {
                Write-Log "Failed to remove $($reg.Name) policies: $_" "Error"
            }
        }
        else {
            Write-Log "$($reg.Name) policy registry key not found" "Warning"
        }
    }
    
    return $true
}

function Restore-DefaultSettings {
    Write-Log "Restoring default security settings..."
    
    try {
        if ($PSCmdlet.ShouldProcess("Security Settings", "Restore defaults")) {
            # Force Group Policy update
            Write-Log "Forcing Group Policy update..."
            gpupdate /force | Out-Null
            
            # Clear local Group Policy cache
            Write-Log "Clearing Group Policy cache..."
            Remove-Item -Path "$env:windir\System32\GroupPolicy\Machine\Registry.pol" -Force -ErrorAction SilentlyContinue
            Remove-Item -Path "$env:windir\System32\GroupPolicy\User\Registry.pol" -Force -ErrorAction SilentlyContinue
            
            # Reset AppLocker service to manual
            Write-Log "Setting AppLocker service to manual start..."
            Set-Service -Name AppIDSvc -StartupType Manual -ErrorAction SilentlyContinue
            
            Write-Log "Default settings restored" "Success"
        }
        
        return $true
    }
    catch {
        Write-Log "Failed to restore default settings: $_" "Error"
        return $false
    }
}

function Generate-RemovalReport {
    Write-Log "Generating removal report..."
    
    $report = @"
================================
Teenager Policy Removal Report
================================
Date: $(Get-Date)
Operator: $env:USERNAME
Computer: $env:COMPUTERNAME

Actions Performed:
------------------
"@

    # Read the log file and extract key actions
    if (Test-Path $LogFile) {
        $logContent = Get-Content $LogFile
        $keyActions = $logContent | Where-Object { $_ -match "\[Success\]|\[Error\]|\[Warning\]" }
        
        $report += "`n$($keyActions -join "`n")"
    }
    
    $report += @"

Backup Location: $BackupPath

To restore the policy, run:
  .\$BackupPath\Restore-TeenagerPolicy.ps1

================================
"@

    $reportFile = ".\TeenagerPolicyRemoval_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $report | Out-File -FilePath $reportFile
    
    Write-Log "Report saved to: $reportFile" "Success"
    
    # Display report
    Write-Host "`n$report" -ForegroundColor Cyan
}

# Main execution
function Main {
    Write-Log "=== Starting Teenager Policy Removal Process ==="
    
    # Check prerequisites
    if (-not (Test-Prerequisites)) {
        Write-Log "Prerequisites check failed. Exiting." "Error"
        exit 2
    }
    
    # Display warning
    if (-not $Force -and -not $WhatIf) {
        Write-Host "`n*** WARNING ***" -ForegroundColor Yellow
        Write-Host "This script will remove the GP_Teenager_Restrictions_Policy and all associated settings." -ForegroundColor Yellow
        Write-Host "A backup will be created before removal." -ForegroundColor Yellow
        Write-Host ""
        
        $continue = Read-Host "Do you want to continue? (Y/N)"
        if ($continue -ne 'Y') {
            Write-Log "Operation cancelled by user" "Warning"
            exit 0
        }
    }
    
    # Create backup
    if (-not $WhatIf) {
        if (-not (Backup-CurrentState -Path $BackupPath)) {
            Write-Log "Backup failed. Aborting removal process." "Error"
            exit 2
        }
    }
    
    # Perform removal steps
    $steps = @(
        @{Name = "Remove GPO Links"; Function = { Remove-GPOLinks }},
        @{Name = "Remove AppLocker Rules"; Function = { Remove-AppLockerRules }},
        @{Name = "Remove Browser Policies"; Function = { Remove-BrowserPolicies }},
        @{Name = "Remove Group Policy"; Function = { Remove-GroupPolicy }},
        @{Name = "Restore Default Settings"; Function = { Restore-DefaultSettings }}
    )
    
    $success = $true
    foreach ($step in $steps) {
        Write-Log "`nExecuting: $($step.Name)" "Info"
        
        try {
            $result = & $step.Function
            if (-not $result) {
                $success = $false
                Write-Log "$($step.Name) failed or was cancelled" "Warning"
            }
        }
        catch {
            $success = $false
            Write-Log "$($step.Name) encountered an error: $_" "Error"
        }
    }
    
    # Generate report
    if (-not $WhatIf) {
        Generate-RemovalReport
    }
    
    # Final status
    if ($success) {
        Write-Log "`n=== Teenager Policy Removal Completed Successfully ===" "Success"
        exit 0
    }
    else {
        Write-Log "`n=== Teenager Policy Removal Completed with Warnings ===" "Warning"
        Write-Log "Check the log file for details: $LogFile" "Warning"
        exit 2
    }
}

# Execute main function
Main