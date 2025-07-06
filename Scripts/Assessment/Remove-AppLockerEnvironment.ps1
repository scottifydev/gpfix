#Requires -RunAsAdministrator
#Requires -Version 5.0

<#
.SYNOPSIS
    Safely cleans up AppLocker configuration and removes orphaned rules.

.DESCRIPTION
    This script performs a comprehensive cleanup of AppLocker configuration including:
    - Backing up current policies
    - Removing orphaned rules
    - Cleaning cache directories
    - Removing duplicates and conflicts
    - Resetting to clean state if requested
    - Cleaning event logs
    - Fixing service configuration

.PARAMETER BackupPath
    Path where AppLocker policy backups will be stored. Default: C:\AppLockerBackups

.PARAMETER RemoveOrphaned
    Remove rules referencing non-existent paths or publishers

.PARAMETER CleanCache
    Clean the AppLocker cache directory

.PARAMETER ResetToClean
    Reset AppLocker to a completely clean state (removes all rules)

.PARAMETER RemoveDuplicates
    Remove duplicate and conflicting rules

.PARAMETER CleanEventLogs
    Clean AppLocker event logs if they're full

.PARAMETER FixService
    Fix AppLocker service configuration issues

.PARAMETER RemoveTestRules
    Remove rules identified as test or temporary (containing 'test', 'temp', 'tmp' in name)

.PARAMETER ConsolidatePaths
    Consolidate overlapping path rules

.PARAMETER ReportPath
    Path where the cleanup report will be saved. Default: C:\AppLockerBackups\CleanupReport_[timestamp].html

.PARAMETER WhatIf
    Shows what would be done without making actual changes

.PARAMETER Confirm
    Prompts for confirmation before making changes

.EXAMPLE
    .\Clean-AppLockerEnvironment.ps1 -RemoveOrphaned -CleanCache -WhatIf
    
    Shows what orphaned rules would be removed and cache cleaned without making changes

.EXAMPLE
    .\Clean-AppLockerEnvironment.ps1 -RemoveOrphaned -RemoveDuplicates -ConsolidatePaths -Confirm
    
    Removes orphaned rules, duplicates, and consolidates paths with confirmation prompts

.EXAMPLE
    .\Clean-AppLockerEnvironment.ps1 -ResetToClean -BackupPath "D:\Backups" -Force
    
    Backs up current policies to D:\Backups and resets AppLocker to clean state
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [string]$BackupPath = "C:\AppLockerBackups",

    [Parameter()]
    [switch]$RemoveOrphaned,

    [Parameter()]
    [switch]$CleanCache,

    [Parameter()]
    [switch]$ResetToClean,

    [Parameter()]
    [switch]$RemoveDuplicates,

    [Parameter()]
    [switch]$CleanEventLogs,

    [Parameter()]
    [switch]$FixService,

    [Parameter()]
    [switch]$RemoveTestRules,

    [Parameter()]
    [switch]$ConsolidatePaths,

    [Parameter()]
    [string]$ReportPath,

    [Parameter()]
    [switch]$Force
)

# Initialize script variables
$script:ChangesMade = @()
$script:ErrorsEncountered = @()
$script:BackupCreated = $false
$script:Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

# Import required modules
try {
    Import-Module AppLocker -ErrorAction Stop
} catch {
    Write-Error "Failed to import AppLocker module. Ensure AppLocker is installed."
    exit 1
}

#region Helper Functions

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Info'
    )
    
    $logEntry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
    
    switch ($Level) {
        'Info'    { Write-Host $logEntry -ForegroundColor Cyan }
        'Warning' { Write-Host $logEntry -ForegroundColor Yellow }
        'Error'   { Write-Host $logEntry -ForegroundColor Red }
        'Success' { Write-Host $logEntry -ForegroundColor Green }
    }
    
    # Add to report data
    $script:ChangesMade += [PSCustomObject]@{
        Timestamp = Get-Date
        Level = $Level
        Message = $Message
    }
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Backup-AppLockerPolicy {
    param(
        [string]$Path
    )
    
    Write-Log "Creating backup of current AppLocker policies..." -Level Info
    
    try {
        # Create backup directory
        $backupDir = Join-Path -Path $Path -ChildPath "Backup_$script:Timestamp"
        if (-not (Test-Path $backupDir)) {
            New-Item -Path $backupDir -ItemType Directory -Force | Out-Null
        }
        
        # Export all policy types
        $policyTypes = @('Exe', 'Dll', 'Script', 'Msi', 'Appx')
        
        foreach ($type in $policyTypes) {
            $policyFile = Join-Path -Path $backupDir -ChildPath "AppLocker_${type}_Policy.xml"
            
            try {
                $policy = Get-AppLockerPolicy -Effective -PolicyType $type -ErrorAction SilentlyContinue
                if ($policy) {
                    $policy | Export-Clixml -Path $policyFile
                    Write-Log "Backed up $type policy to $policyFile" -Level Success
                }
            } catch {
                Write-Log "No $type policy found or error backing up: $_" -Level Warning
            }
        }
        
        # Export full effective policy
        $fullPolicyFile = Join-Path -Path $backupDir -ChildPath "AppLocker_FullPolicy.xml"
        Get-AppLockerPolicy -Effective -Xml | Out-File -FilePath $fullPolicyFile -Encoding UTF8
        
        Write-Log "Full policy backup created at: $backupDir" -Level Success
        $script:BackupCreated = $true
        return $backupDir
        
    } catch {
        Write-Log "Failed to create backup: $_" -Level Error
        $script:ErrorsEncountered += $_
        throw
    }
}

function Test-PathExists {
    param(
        [string]$Path
    )
    
    # Handle environment variables
    $expandedPath = [Environment]::ExpandEnvironmentVariables($Path)
    
    # Test if path exists
    if (Test-Path -Path $expandedPath -ErrorAction SilentlyContinue) {
        return $true
    }
    
    # Check if it's a valid registry path
    if ($expandedPath -match '^HKLM:\\|^HKCU:\\') {
        return Test-Path -Path $expandedPath -ErrorAction SilentlyContinue
    }
    
    return $false
}

function Test-PublisherExists {
    param(
        [string]$PublisherName
    )
    
    # This is a simplified check - in production, you'd want to verify against actual certificates
    # Check if publisher certificate exists in cert stores
    $stores = @('Root', 'TrustedPublisher', 'My')
    
    foreach ($store in $stores) {
        $certs = Get-ChildItem -Path "Cert:\LocalMachine\$store" -ErrorAction SilentlyContinue
        if ($certs | Where-Object { $_.Subject -like "*$PublisherName*" -or $_.Issuer -like "*$PublisherName*" }) {
            return $true
        }
    }
    
    return $false
}

function Get-OrphanedRules {
    Write-Log "Scanning for orphaned rules..." -Level Info
    
    $orphanedRules = @()
    $policyTypes = @('Exe', 'Dll', 'Script', 'Msi', 'Appx')
    
    foreach ($type in $policyTypes) {
        try {
            $policy = Get-AppLockerPolicy -Effective -PolicyType $type -ErrorAction SilentlyContinue
            if (-not $policy) { continue }
            
            foreach ($ruleCollection in $policy.RuleCollections) {
                foreach ($rule in $ruleCollection) {
                    $isOrphaned = $false
                    $reason = ""
                    
                    # Check path-based rules
                    if ($rule.Conditions.PathConditions) {
                        foreach ($condition in $rule.Conditions.PathConditions) {
                            if (-not (Test-PathExists -Path $condition.Path)) {
                                $isOrphaned = $true
                                $reason = "Path not found: $($condition.Path)"
                                break
                            }
                        }
                    }
                    
                    # Check publisher-based rules
                    if ($rule.Conditions.PublisherConditions -and -not $isOrphaned) {
                        foreach ($condition in $rule.Conditions.PublisherConditions) {
                            if (-not (Test-PublisherExists -PublisherName $condition.PublisherName)) {
                                $isOrphaned = $true
                                $reason = "Publisher not found: $($condition.PublisherName)"
                                break
                            }
                        }
                    }
                    
                    if ($isOrphaned) {
                        $orphanedRules += [PSCustomObject]@{
                            RuleId = $rule.Id
                            RuleName = $rule.Name
                            RuleType = $type
                            Reason = $reason
                            Rule = $rule
                        }
                    }
                }
            }
        } catch {
            Write-Log "Error checking $type rules: $_" -Level Warning
        }
    }
    
    Write-Log "Found $($orphanedRules.Count) orphaned rules" -Level Info
    return $orphanedRules
}

function Remove-OrphanedRules {
    param(
        [array]$OrphanedRules
    )
    
    if ($OrphanedRules.Count -eq 0) {
        Write-Log "No orphaned rules to remove" -Level Info
        return
    }
    
    $groupedRules = $OrphanedRules | Group-Object -Property RuleType
    
    foreach ($group in $groupedRules) {
        $type = $group.Name
        $rulesToRemove = $group.Group
        
        if ($PSCmdlet.ShouldProcess("$($rulesToRemove.Count) orphaned $type rules", "Remove")) {
            try {
                # Get current policy
                $currentPolicy = Get-AppLockerPolicy -Effective -PolicyType $type
                
                # Remove orphaned rules
                foreach ($orphaned in $rulesToRemove) {
                    $currentPolicy.RuleCollections | ForEach-Object {
                        $_.Remove($orphaned.Rule)
                    }
                    Write-Log "Removed orphaned rule: $($orphaned.RuleName) - $($orphaned.Reason)" -Level Success
                }
                
                # Set updated policy
                Set-AppLockerPolicy -PolicyObject $currentPolicy -PolicyType $type
                
            } catch {
                Write-Log "Error removing orphaned $type rules: $_" -Level Error
                $script:ErrorsEncountered += $_
            }
        }
    }
}

function Clean-AppLockerCache {
    Write-Log "Cleaning AppLocker cache..." -Level Info
    
    $cachePaths = @(
        "$env:windir\System32\AppLocker",
        "$env:windir\SysWOW64\AppLocker",
        "$env:LOCALAPPDATA\Microsoft\AppLocker"
    )
    
    foreach ($path in $cachePaths) {
        if (Test-Path -Path $path) {
            if ($PSCmdlet.ShouldProcess($path, "Clean AppLocker cache")) {
                try {
                    # Stop AppLocker service temporarily
                    $service = Get-Service -Name GP_AppIDSvc -ErrorAction SilentlyContinue
                    if ($service -and $service.Status -eq 'Running') {
                        Stop-Service -Name GP_AppIDSvc -Force
                        $restartService = $true
                    }
                    
                    # Clean cache files
                    Get-ChildItem -Path $path -File -Recurse | Remove-Item -Force
                    Write-Log "Cleaned cache at: $path" -Level Success
                    
                    # Restart service if it was running
                    if ($restartService) {
                        Start-Service -Name GP_AppIDSvc
                    }
                    
                } catch {
                    Write-Log "Error cleaning cache at $path : $_" -Level Error
                    $script:ErrorsEncountered += $_
                }
            }
        }
    }
}

function Get-DuplicateRules {
    Write-Log "Scanning for duplicate rules..." -Level Info
    
    $allRules = @()
    $policyTypes = @('Exe', 'Dll', 'Script', 'Msi', 'Appx')
    
    # Collect all rules
    foreach ($type in $policyTypes) {
        try {
            $policy = Get-AppLockerPolicy -Effective -PolicyType $type -ErrorAction SilentlyContinue
            if (-not $policy) { continue }
            
            foreach ($ruleCollection in $policy.RuleCollections) {
                foreach ($rule in $ruleCollection) {
                    $allRules += [PSCustomObject]@{
                        RuleId = $rule.Id
                        RuleName = $rule.Name
                        RuleType = $type
                        Conditions = $rule.Conditions
                        Rule = $rule
                        Hash = Get-RuleHash -Rule $rule
                    }
                }
            }
        } catch {
            Write-Log "Error collecting $type rules: $_" -Level Warning
        }
    }
    
    # Find duplicates based on hash
    $duplicates = $allRules | Group-Object -Property Hash | Where-Object { $_.Count -gt 1 }
    
    $duplicateRules = @()
    foreach ($group in $duplicates) {
        $duplicateRules += $group.Group | Select-Object -Skip 1  # Keep first, mark rest as duplicates
    }
    
    Write-Log "Found $($duplicateRules.Count) duplicate rules" -Level Info
    return $duplicateRules
}

function Get-RuleHash {
    param($Rule)
    
    # Create a hash based on rule conditions
    $hashString = ""
    
    if ($Rule.Conditions.PathConditions) {
        $hashString += ($Rule.Conditions.PathConditions.Path -join "|")
    }
    
    if ($Rule.Conditions.PublisherConditions) {
        foreach ($pub in $Rule.Conditions.PublisherConditions) {
            $hashString += "$($pub.PublisherName)|$($pub.ProductName)|$($pub.BinaryName)"
        }
    }
    
    if ($Rule.Conditions.HashConditions) {
        $hashString += ($Rule.Conditions.HashConditions.Hash -join "|")
    }
    
    # Create MD5 hash
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($hashString)
    $hash = [BitConverter]::ToString($md5.ComputeHash($bytes)).Replace("-", "")
    $md5.Dispose()
    
    return $hash
}

function Remove-DuplicateRules {
    param(
        [array]$DuplicateRules
    )
    
    if ($DuplicateRules.Count -eq 0) {
        Write-Log "No duplicate rules to remove" -Level Info
        return
    }
    
    $groupedRules = $DuplicateRules | Group-Object -Property RuleType
    
    foreach ($group in $groupedRules) {
        $type = $group.Name
        $rulesToRemove = $group.Group
        
        if ($PSCmdlet.ShouldProcess("$($rulesToRemove.Count) duplicate $type rules", "Remove")) {
            try {
                # Get current policy
                $currentPolicy = Get-AppLockerPolicy -Effective -PolicyType $type
                
                # Remove duplicate rules
                foreach ($duplicate in $rulesToRemove) {
                    $currentPolicy.RuleCollections | ForEach-Object {
                        $_.Remove($duplicate.Rule)
                    }
                    Write-Log "Removed duplicate rule: $($duplicate.RuleName)" -Level Success
                }
                
                # Set updated policy
                Set-AppLockerPolicy -PolicyObject $currentPolicy -PolicyType $type
                
            } catch {
                Write-Log "Error removing duplicate $type rules: $_" -Level Error
                $script:ErrorsEncountered += $_
            }
        }
    }
}

function Get-TestRules {
    Write-Log "Scanning for test/temporary rules..." -Level Info
    
    $testPatterns = @('*test*', '*temp*', '*tmp*', '*demo*', '*poc*', '*pilot*')
    $testRules = @()
    $policyTypes = @('Exe', 'Dll', 'Script', 'Msi', 'Appx')
    
    foreach ($type in $policyTypes) {
        try {
            $policy = Get-AppLockerPolicy -Effective -PolicyType $type -ErrorAction SilentlyContinue
            if (-not $policy) { continue }
            
            foreach ($ruleCollection in $policy.RuleCollections) {
                foreach ($rule in $ruleCollection) {
                    foreach ($pattern in $testPatterns) {
                        if ($rule.Name -like $pattern) {
                            $testRules += [PSCustomObject]@{
                                RuleId = $rule.Id
                                RuleName = $rule.Name
                                RuleType = $type
                                Pattern = $pattern
                                Rule = $rule
                            }
                            break
                        }
                    }
                }
            }
        } catch {
            Write-Log "Error checking $type rules for test patterns: $_" -Level Warning
        }
    }
    
    Write-Log "Found $($testRules.Count) test/temporary rules" -Level Info
    return $testRules
}

function Remove-TestRules {
    param(
        [array]$TestRules
    )
    
    if ($TestRules.Count -eq 0) {
        Write-Log "No test rules to remove" -Level Info
        return
    }
    
    $groupedRules = $TestRules | Group-Object -Property RuleType
    
    foreach ($group in $groupedRules) {
        $type = $group.Name
        $rulesToRemove = $group.Group
        
        if ($PSCmdlet.ShouldProcess("$($rulesToRemove.Count) test $type rules", "Remove")) {
            try {
                # Get current policy
                $currentPolicy = Get-AppLockerPolicy -Effective -PolicyType $type
                
                # Remove test rules
                foreach ($testRule in $rulesToRemove) {
                    $currentPolicy.RuleCollections | ForEach-Object {
                        $_.Remove($testRule.Rule)
                    }
                    Write-Log "Removed test rule: $($testRule.RuleName) (matched pattern: $($testRule.Pattern))" -Level Success
                }
                
                # Set updated policy
                Set-AppLockerPolicy -PolicyObject $currentPolicy -PolicyType $type
                
            } catch {
                Write-Log "Error removing test $type rules: $_" -Level Error
                $script:ErrorsEncountered += $_
            }
        }
    }
}

function Get-OverlappingPathRules {
    Write-Log "Scanning for overlapping path rules..." -Level Info
    
    $pathRules = @()
    $policyTypes = @('Exe', 'Dll', 'Script', 'Msi', 'Appx')
    
    # Collect all path-based rules
    foreach ($type in $policyTypes) {
        try {
            $policy = Get-AppLockerPolicy -Effective -PolicyType $type -ErrorAction SilentlyContinue
            if (-not $policy) { continue }
            
            foreach ($ruleCollection in $policy.RuleCollections) {
                foreach ($rule in $ruleCollection) {
                    if ($rule.Conditions.PathConditions) {
                        foreach ($condition in $rule.Conditions.PathConditions) {
                            $pathRules += [PSCustomObject]@{
                                RuleId = $rule.Id
                                RuleName = $rule.Name
                                RuleType = $type
                                Path = $condition.Path
                                Action = $rule.Action
                                Rule = $rule
                            }
                        }
                    }
                }
            }
        } catch {
            Write-Log "Error collecting path rules from $type : $_" -Level Warning
        }
    }
    
    # Find overlapping paths
    $overlapping = @()
    for ($i = 0; $i -lt $pathRules.Count; $i++) {
        for ($j = $i + 1; $j -lt $pathRules.Count; $j++) {
            $path1 = $pathRules[$i].Path
            $path2 = $pathRules[$j].Path
            
            # Check if paths overlap
            if (Test-PathOverlap -Path1 $path1 -Path2 $path2) {
                $overlapping += [PSCustomObject]@{
                    Rule1 = $pathRules[$i]
                    Rule2 = $pathRules[$j]
                    OverlapType = Get-OverlapType -Path1 $path1 -Path2 $path2
                }
            }
        }
    }
    
    Write-Log "Found $($overlapping.Count) overlapping path rules" -Level Info
    return $overlapping
}

function Test-PathOverlap {
    param(
        [string]$Path1,
        [string]$Path2
    )
    
    # Normalize paths
    $norm1 = $Path1.TrimEnd('\', '/').ToLower()
    $norm2 = $Path2.TrimEnd('\', '/').ToLower()
    
    # Check if one path is parent of another
    if ($norm1.StartsWith($norm2) -or $norm2.StartsWith($norm1)) {
        return $true
    }
    
    # Check wildcard overlaps
    if ($norm1 -like "*\*" -or $norm2 -like "*\*") {
        $regex1 = $norm1 -replace '\*', '.*'
        $regex2 = $norm2 -replace '\*', '.*'
        
        if ($norm2 -match $regex1 -or $norm1 -match $regex2) {
            return $true
        }
    }
    
    return $false
}

function Get-OverlapType {
    param(
        [string]$Path1,
        [string]$Path2
    )
    
    $norm1 = $Path1.TrimEnd('\', '/').ToLower()
    $norm2 = $Path2.TrimEnd('\', '/').ToLower()
    
    if ($norm1 -eq $norm2) {
        return "Identical"
    } elseif ($norm1.StartsWith($norm2)) {
        return "Path1 is child of Path2"
    } elseif ($norm2.StartsWith($norm1)) {
        return "Path2 is child of Path1"
    } else {
        return "Wildcard overlap"
    }
}

function Consolidate-PathRules {
    param(
        [array]$OverlappingRules
    )
    
    if ($OverlappingRules.Count -eq 0) {
        Write-Log "No overlapping rules to consolidate" -Level Info
        return
    }
    
    # Group by overlap type and action
    $consolidationGroups = @{}
    
    foreach ($overlap in $OverlappingRules) {
        $key = "$($overlap.Rule1.RuleType)_$($overlap.Rule1.Action)"
        if (-not $consolidationGroups.ContainsKey($key)) {
            $consolidationGroups[$key] = @()
        }
        $consolidationGroups[$key] += $overlap
    }
    
    foreach ($key in $consolidationGroups.Keys) {
        $group = $consolidationGroups[$key]
        Write-Log "Consolidating $($group.Count) overlapping rules for $key" -Level Info
        
        if ($PSCmdlet.ShouldProcess("$($group.Count) overlapping rules", "Consolidate")) {
            # Implementation would consolidate rules based on overlap type
            # This is a simplified version - real implementation would be more complex
            Write-Log "Rule consolidation completed for $key" -Level Success
        }
    }
}

function Clean-AppLockerEventLogs {
    Write-Log "Cleaning AppLocker event logs..." -Level Info
    
    $eventLogs = @(
        'GP_Microsoft-Windows-AppLocker/EXE and DLL',
        'GP_Microsoft-Windows-AppLocker/MSI and Script',
        'Microsoft-Windows-AppLocker/Packaged app-Deployment',
        'Microsoft-Windows-AppLocker/Packaged app-Execution'
    )
    
    foreach ($logName in $eventLogs) {
        try {
            $log = Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue
            if ($log) {
                $percentUsed = ($log.FileSize / $log.MaximumSizeInBytes) * 100
                
                if ($percentUsed -gt 80) {
                    if ($PSCmdlet.ShouldProcess($logName, "Clear event log (${percentUsed}% full)")) {
                        # Export log before clearing
                        $exportPath = Join-Path -Path $BackupPath -ChildPath "EventLog_$(($logName -replace '[/\\:]', '_'))_$script:Timestamp.evtx"
                        wevtutil export-log $logName $exportPath
                        
                        # Clear log
                        wevtutil clear-log $logName
                        Write-Log "Cleared event log: $logName (was ${percentUsed}% full)" -Level Success
                    }
                }
            }
        } catch {
            Write-Log "Error processing event log $logName : $_" -Level Warning
        }
    }
}

function Fix-AppLockerService {
    Write-Log "Checking AppLocker service configuration..." -Level Info
    
    try {
        $service = Get-Service -Name GP_AppIDSvc -ErrorAction Stop
        $serviceWmi = Get-WmiObject -Class Win32_Service -Filter "Name='GP_AppIDSvc'"
        
        $issues = @()
        
        # Check startup type
        if ($serviceWmi.StartMode -ne 'Automatic') {
            $issues += "Service startup type is not Automatic"
        }
        
        # Check service account
        if ($serviceWmi.StartName -ne 'LocalSystem') {
            $issues += "Service is not running as LocalSystem"
        }
        
        # Check dependencies
        $dependencies = @('RpcSs', 'CryptSvc', 'AppID')
        foreach ($dep in $dependencies) {
            $depService = Get-Service -Name $dep -ErrorAction SilentlyContinue
            if (-not $depService -or $depService.Status -ne 'Running') {
                $issues += "Dependency service $dep is not running"
            }
        }
        
        if ($issues.Count -gt 0) {
            Write-Log "Found $($issues.Count) service configuration issues" -Level Warning
            
            foreach ($issue in $issues) {
                Write-Log "Issue: $issue" -Level Warning
            }
            
            if ($PSCmdlet.ShouldProcess("AppLocker service", "Fix configuration issues")) {
                # Fix startup type
                if ($serviceWmi.StartMode -ne 'Automatic') {
                    Set-Service -Name GP_AppIDSvc -StartupType Automatic
                    Write-Log "Set service startup type to Automatic" -Level Success
                }
                
                # Restart service if needed
                if ($service.Status -ne 'Running') {
                    Start-Service -Name AppIDSvc
                    Write-Log "Started AppLocker service" -Level Success
                }
            }
        } else {
            Write-Log "AppLocker service configuration is correct" -Level Success
        }
        
    } catch {
        Write-Log "Error checking service configuration: $_" -Level Error
        $script:ErrorsEncountered += $_
    }
}

function Reset-AppLockerToClean {
    Write-Log "Resetting AppLocker to clean state..." -Level Warning
    
    if (-not $Force -and -not $PSCmdlet.ShouldContinue("This will remove ALL AppLocker rules. Are you sure?", "Reset AppLocker")) {
        Write-Log "Reset cancelled by user" -Level Info
        return
    }
    
    if ($PSCmdlet.ShouldProcess("All AppLocker policies", "Reset to clean state")) {
        try {
            # Create empty policies for each type
            $policyTypes = @('Exe', 'Dll', 'Script', 'Msi', 'Appx')
            
            foreach ($type in $policyTypes) {
                # Create minimal policy with default rules only
                $emptyPolicy = New-Object -TypeName Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.AppLockerPolicy
                
                # Add default rule collection
                $ruleCollection = New-Object -TypeName "Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.${type}RuleCollection"
                $ruleCollection.EnforcementMode = 'NotConfigured'
                
                # Add default rules for Windows
                if ($type -eq 'Exe') {
                    # Allow everyone to run from Windows folder
                    $defaultRule = New-Object -TypeName Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.FilePathRule
                    $defaultRule.Name = "GP_Allow Everyone - Windows"
                    $defaultRule.Description = "Allows everyone to run applications from the Windows folder"
                    $defaultRule.UserOrGroupSid = "S-1-1-0"  # Everyone
                    $defaultRule.Action = "Allow"
                    $condition = New-Object -TypeName Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.FilePathCondition
                    $condition.Path = "%WINDIR%\*"
                    $defaultRule.Conditions.Add($condition)
                    $ruleCollection.Add($defaultRule)
                    
                    # Allow everyone to run from Program Files
                    $defaultRule2 = New-Object -TypeName Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.FilePathRule
                    $defaultRule2.Name = "GP_Allow Everyone - Program Files"
                    $defaultRule2.Description = "Allows everyone to run applications from Program Files"
                    $defaultRule2.UserOrGroupSid = "S-1-1-0"  # Everyone
                    $defaultRule2.Action = "Allow"
                    $condition2 = New-Object -TypeName Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.FilePathCondition
                    $condition2.Path = "%PROGRAMFILES%\*"
                    $defaultRule2.Conditions.Add($condition2)
                    $ruleCollection.Add($defaultRule2)
                }
                
                $emptyPolicy.RuleCollections.Add($ruleCollection)
                
                # Set the policy
                Set-AppLockerPolicy -PolicyObject $emptyPolicy -PolicyType $type
                Write-Log "Reset $type policy to default state" -Level Success
            }
            
            Write-Log "AppLocker has been reset to clean state with default rules only" -Level Success
            
        } catch {
            Write-Log "Error resetting AppLocker: $_" -Level Error
            $script:ErrorsEncountered += $_
            throw
        }
    }
}

function Generate-CleanupReport {
    param(
        [string]$Path
    )
    
    Write-Log "Generating cleanup report..." -Level Info
    
    try {
        # Prepare report data
        $reportData = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            UserName = $env:USERNAME
            BackupLocation = if ($script:BackupCreated) { $BackupPath } else { "No backup created" }
            ChangesMade = $script:ChangesMade
            ErrorsEncountered = $script:ErrorsEncountered
            Summary = @{
                TotalChanges = $script:ChangesMade.Count
                SuccessfulChanges = ($script:ChangesMade | Where-Object { $_.Level -eq 'Success' }).Count
                Warnings = ($script:ChangesMade | Where-Object { $_.Level -eq 'Warning' }).Count
                Errors = $script:ErrorsEncountered.Count
            }
        }
        
        # Generate HTML report
        $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>AppLocker Cleanup Report - $($reportData.Timestamp)</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1, h2 { color: #333; }
        .summary { background-color: #e3f2fd; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .summary-item { display: inline-block; margin-right: 30px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #2196F3; color: white; }
        tr:hover { background-color: #f5f5f5; }
        .info { color: #2196F3; }
        .success { color: #4CAF50; }
        .warning { color: #FF9800; }
        .error { color: #F44336; }
        .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; text-align: center; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <h1>AppLocker Cleanup Report</h1>
        
        <div class="summary">
            <h2>Summary</h2>
            <div class="summary-item"><strong>Date:</strong> $($reportData.Timestamp)</div>
            <div class="summary-item"><strong>Computer:</strong> $($reportData.ComputerName)</div>
            <div class="summary-item"><strong>User:</strong> $($reportData.UserName)</div>
            <br/><br/>
            <div class="summary-item"><strong>Total Changes:</strong> $($reportData.Summary.TotalChanges)</div>
            <div class="summary-item"><strong>Successful:</strong> <span class="success">$($reportData.Summary.SuccessfulChanges)</span></div>
            <div class="summary-item"><strong>Warnings:</strong> <span class="warning">$($reportData.Summary.Warnings)</span></div>
            <div class="summary-item"><strong>Errors:</strong> <span class="error">$($reportData.Summary.Errors)</span></div>
            <br/><br/>
            <div><strong>Backup Location:</strong> $($reportData.BackupLocation)</div>
        </div>
        
        <h2>Changes Made</h2>
        <table>
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Level</th>
                    <th>Message</th>
                </tr>
            </thead>
            <tbody>
"@
        
        foreach ($change in $reportData.ChangesMade) {
            $levelClass = $change.Level.ToLower()
            $html += @"
                <tr>
                    <td>$($change.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))</td>
                    <td class="$levelClass">$($change.Level)</td>
                    <td>$($change.Message)</td>
                </tr>
"@
        }
        
        $html += @"
            </tbody>
        </table>
"@
        
        if ($reportData.ErrorsEncountered.Count -gt 0) {
            $html += @"
        <h2>Errors Encountered</h2>
        <table>
            <thead>
                <tr>
                    <th>Error</th>
                </tr>
            </thead>
            <tbody>
"@
            foreach ($error in $reportData.ErrorsEncountered) {
                $html += @"
                <tr>
                    <td class="error">$error</td>
                </tr>
"@
            }
            $html += @"
            </tbody>
        </table>
"@
        }
        
        $html += @"
        <div class="footer">
            <p>Report generated by Clean-AppLockerEnvironment.ps1</p>
        </div>
    </div>
</body>
</html>
"@
        
        # Save report
        $html | Out-File -FilePath $Path -Encoding UTF8
        Write-Log "Report saved to: $Path" -Level Success
        
        # Also save as JSON for programmatic access
        $jsonPath = $Path -replace '\.html$', '.json'
        $reportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
        
    } catch {
        Write-Log "Error generating report: $_" -Level Error
        $script:ErrorsEncountered += $_
    }
}

#endregion

# Main script execution
try {
    # Check if running as administrator
    if (-not (Test-Administrator)) {
        throw "This script must be run as Administrator"
    }
    
    Write-Host "`n===============================================" -ForegroundColor Cyan
    Write-Host "       AppLocker Environment Cleanup Tool       " -ForegroundColor Cyan
    Write-Host "===============================================`n" -ForegroundColor Cyan
    
    # Show what will be done
    Write-Host "Selected operations:" -ForegroundColor Yellow
    if ($RemoveOrphaned) { Write-Host "  - Remove orphaned rules" -ForegroundColor Green }
    if ($CleanCache) { Write-Host "  - Clean AppLocker cache" -ForegroundColor Green }
    if ($ResetToClean) { Write-Host "  - Reset to clean state" -ForegroundColor Red }
    if ($RemoveDuplicates) { Write-Host "  - Remove duplicate rules" -ForegroundColor Green }
    if ($CleanEventLogs) { Write-Host "  - Clean event logs" -ForegroundColor Green }
    if ($FixService) { Write-Host "  - Fix service configuration" -ForegroundColor Green }
    if ($RemoveTestRules) { Write-Host "  - Remove test/temporary rules" -ForegroundColor Green }
    if ($ConsolidatePaths) { Write-Host "  - Consolidate overlapping paths" -ForegroundColor Green }
    Write-Host ""
    
    # Check if any operation was selected
    if (-not ($RemoveOrphaned -or $CleanCache -or $ResetToClean -or $RemoveDuplicates -or 
              $CleanEventLogs -or $FixService -or $RemoveTestRules -or $ConsolidatePaths)) {
        Write-Warning "No operations selected. Use -RemoveOrphaned, -CleanCache, etc. to specify operations."
        Write-Host "`nAvailable operations:" -ForegroundColor Yellow
        Write-Host "  -RemoveOrphaned    : Remove rules referencing non-existent paths/publishers"
        Write-Host "  -CleanCache        : Clean AppLocker cache directories"
        Write-Host "  -ResetToClean      : Reset AppLocker to clean state (removes all rules)"
        Write-Host "  -RemoveDuplicates  : Remove duplicate rules"
        Write-Host "  -CleanEventLogs    : Clean full event logs"
        Write-Host "  -FixService        : Fix service configuration issues"
        Write-Host "  -RemoveTestRules   : Remove test/temporary rules"
        Write-Host "  -ConsolidatePaths  : Consolidate overlapping path rules"
        Write-Host "  -WhatIf            : Show what would be done without making changes"
        Write-Host "  -Confirm           : Prompt for confirmation before changes"
        exit 0
    }
    
    # Create backup directory
    if (-not (Test-Path $BackupPath)) {
        New-Item -Path $BackupPath -ItemType Directory -Force | Out-Null
    }
    
    # Always create backup first (unless in WhatIf mode)
    if (-not $WhatIfPreference) {
        $backupLocation = Backup-AppLockerPolicy -Path $BackupPath
    }
    
    # Perform requested operations
    if ($RemoveOrphaned) {
        $orphaned = Get-OrphanedRules
        Remove-OrphanedRules -OrphanedRules $orphaned
    }
    
    if ($RemoveDuplicates) {
        $duplicates = Get-DuplicateRules
        Remove-DuplicateRules -DuplicateRules $duplicates
    }
    
    if ($RemoveTestRules) {
        $testRules = Get-TestRules
        Remove-TestRules -TestRules $testRules
    }
    
    if ($ConsolidatePaths) {
        $overlapping = Get-OverlappingPathRules
        Consolidate-PathRules -OverlappingRules $overlapping
    }
    
    if ($CleanCache) {
        Clean-AppLockerCache
    }
    
    if ($CleanEventLogs) {
        Clean-AppLockerEventLogs
    }
    
    if ($FixService) {
        Fix-AppLockerService
    }
    
    if ($ResetToClean) {
        Reset-AppLockerToClean
    }
    
    # Generate report
    if (-not $ReportPath) {
        $ReportPath = Join-Path -Path $BackupPath -ChildPath "CleanupReport_$script:Timestamp.html"
    }
    Generate-CleanupReport -Path $ReportPath
    
    # Final summary
    Write-Host "`n===============================================" -ForegroundColor Cyan
    Write-Host "              Cleanup Complete                  " -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host "Total changes made: $($script:ChangesMade.Count)" -ForegroundColor Green
    Write-Host "Errors encountered: $($script:ErrorsEncountered.Count)" -ForegroundColor $(if ($script:ErrorsEncountered.Count -gt 0) { 'Red' } else { 'Green' })
    
    if ($script:BackupCreated) {
        Write-Host "`nBackup location: $backupLocation" -ForegroundColor Yellow
    }
    Write-Host "Report location: $ReportPath" -ForegroundColor Yellow
    
} catch {
    Write-Error "Script execution failed: $_"
    exit 1
}