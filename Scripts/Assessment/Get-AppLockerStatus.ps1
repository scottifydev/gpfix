#Requires -RunAsAdministrator
#Requires -Version 5.1

<#
.SYNOPSIS
    Comprehensive AppLocker configuration and status assessment script.

.DESCRIPTION
    This script performs a thorough check of AppLocker configuration, including:
    - Application Identity service status
    - Existing AppLocker rules analysis
    - Conflict detection
    - Event log configuration
    - Policy processing verification
    - Enforcement mode analysis
    - Rule validation
    - Coverage analysis
    - Default rules assessment
    - Functionality testing

.PARAMETER ComputerName
    Target computers to assess. Defaults to local computer.

.PARAMETER OutputPath
    Path for detailed report output. Defaults to current directory.

.PARAMETER TestApplications
    Perform application execution tests. Requires test applications to be present.

.PARAMETER SkipServiceCheck
    Skip Application Identity service checks (useful for offline analysis).

.EXAMPLE
    .\Check-AppLockerStatus.ps1 -ComputerName "PC01","PC02" -OutputPath "C:\Reports"

.NOTES
    Author: Group Policy Assessment Tool
    Version: 1.0
    Requires: Administrative privileges, AppLocker cmdlets
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string[]]$ComputerName = $env:COMPUTERNAME,
    
    [Parameter(Position = 1)]
    [string]$OutputPath = (Get-Location).Path,
    
    [Parameter()]
    [switch]$TestApplications,
    
    [Parameter()]
    [switch]$SkipServiceCheck
)

# Initialize variables and functions
$Script:Issues = @()
$Script:Warnings = @()
$Script:Recommendations = @()
$Script:TeenagerPolicyRecommendations = @()

function Write-ColorOutput {
    param(
        [string]$Message,
        [ConsoleColor]$Color = 'White'
    )
    Write-Host $Message -ForegroundColor $Color
}

function Add-Issue {
    param([string]$Issue, [string]$Category = "General")
    $Script:Issues += [PSCustomObject]@{
        Category = $Category
        Issue = $Issue
        Timestamp = Get-Date
    }
}

function Add-Warning {
    param([string]$Warning, [string]$Category = "General")
    $Script:Warnings += [PSCustomObject]@{
        Category = $Category
        Warning = $Warning
        Timestamp = Get-Date
    }
}

function Add-Recommendation {
    param([string]$Recommendation, [string]$Category = "General")
    $Script:Recommendations += [PSCustomObject]@{
        Category = $Category
        Recommendation = $Recommendation
        Timestamp = Get-Date
    }
}

function Add-TeenagerPolicyRecommendation {
    param([string]$Recommendation)
    $Script:TeenagerPolicyRecommendations += $Recommendation
}

# Function to check Application Identity service
function Test-AppLockerService {
    param([string[]]$Computers)
    
    Write-ColorOutput "`n=== Checking Application Identity Service ===" -Color Cyan
    
    $serviceResults = @()
    
    foreach ($computer in $Computers) {
        try {
            Write-Host "Checking service on $computer..." -NoNewline
            
            $service = Get-Service -Name "AppIDSvc" -ComputerName $computer -ErrorAction Stop
            $serviceInfo = [PSCustomObject]@{
                ComputerName = $computer
                ServiceName = $service.Name
                DisplayName = $service.DisplayName
                Status = $service.Status
                StartType = $service.StartType
                CanStart = $service.Status -ne 'Running'
            }
            
            $serviceResults += $serviceInfo
            
            if ($service.Status -ne 'Running') {
                Write-ColorOutput " [WARNING]" -Color Yellow
                Add-Issue "Application Identity service not running on $computer" "Service"
                Add-Recommendation "Start Application Identity service on $computer for AppLocker to function" "Service"
            } else {
                Write-ColorOutput " [OK]" -Color Green
            }
            
            if ($service.StartType -eq 'Disabled') {
                Add-Issue "Application Identity service is disabled on $computer" "Service"
                Add-Recommendation "Set Application Identity service to Automatic on $computer" "Service"
            }
            
        } catch {
            Write-ColorOutput " [ERROR]" -Color Red
            Add-Issue "Failed to check Application Identity service on $computer`: $_" "Service"
        }
    }
    
    return $serviceResults
}

# Function to get AppLocker rules
function Get-AppLockerRuleInfo {
    param([string]$Computer)
    
    Write-ColorOutput "`n=== Retrieving AppLocker Rules from $Computer ===" -Color Cyan
    
    $ruleTypes = @('Exe', 'Msi', 'Script', 'Dll', 'Appx')
    $allRules = @()
    
    foreach ($type in $ruleTypes) {
        try {
            Write-Host "Checking $type rules..." -NoNewline
            
            $rules = Get-AppLockerPolicy -Effective -ErrorAction Stop | 
                     Select-Object -ExpandProperty RuleCollections | 
                     Where-Object { $_.RuleCollectionType -eq $type }
            
            if ($rules.Count -gt 0) {
                Write-ColorOutput " [Found $($rules.Count) rules]" -Color Green
                $allRules += $rules
            } else {
                Write-ColorOutput " [No rules]" -Color Yellow
                Add-Warning "No $type rules configured" "Rules"
            }
            
        } catch {
            Write-ColorOutput " [ERROR]" -Color Red
            Add-Issue "Failed to retrieve $type rules: $_" "Rules"
        }
    }
    
    return $allRules
}

# Function to check for rule conflicts
function Test-AppLockerRuleConflicts {
    param($Rules)
    
    Write-ColorOutput "`n=== Checking for Rule Conflicts ===" -Color Cyan
    
    $conflicts = @()
    $exeRules = $Rules | Where-Object { $_.RuleCollectionType -eq 'Exe' }
    
    # Check for overlapping path rules
    $pathRules = $exeRules | Where-Object { $_.RuleType -eq 'Path' }
    
    for ($i = 0; $i -lt $pathRules.Count; $i++) {
        for ($j = $i + 1; $j -lt $pathRules.Count; $j++) {
            $rule1 = $pathRules[$i]
            $rule2 = $pathRules[$j]
            
            # Check if paths overlap
            if ($rule1.Path -like "*$($rule2.Path)*" -or $rule2.Path -like "*$($rule1.Path)*") {
                if ($rule1.Action -ne $rule2.Action) {
                    $conflict = [PSCustomObject]@{
                        Rule1 = $rule1.Name
                        Rule1Path = $rule1.Path
                        Rule1Action = $rule1.Action
                        Rule2 = $rule2.Name
                        Rule2Path = $rule2.Path
                        Rule2Action = $rule2.Action
                        Type = "Path Overlap"
                    }
                    $conflicts += $conflict
                    Add-Issue "Conflicting rules: $($rule1.Name) and $($rule2.Name) have overlapping paths with different actions" "Conflicts"
                }
            }
        }
    }
    
    # Check for publisher rules that might conflict
    $publisherRules = $exeRules | Where-Object { $_.RuleType -eq 'Publisher' }
    
    # Group by publisher name
    $publisherGroups = $publisherRules | Group-Object -Property { $_.PublisherName }
    
    foreach ($group in $publisherGroups | Where-Object { $_.Count -gt 1 }) {
        $allowRules = $group.Group | Where-Object { $_.Action -eq 'Allow' }
        $denyRules = $group.Group | Where-Object { $_.Action -eq 'Deny' }
        
        if ($allowRules.Count -gt 0 -and $denyRules.Count -gt 0) {
            Add-Warning "Publisher '$($group.Name)' has both Allow and Deny rules" "Conflicts"
        }
    }
    
    if ($conflicts.Count -eq 0) {
        Write-ColorOutput "No direct conflicts found" -Color Green
    } else {
        Write-ColorOutput "Found $($conflicts.Count) conflicts" -Color Yellow
    }
    
    return $conflicts
}

# Function to check event logs
function Test-AppLockerEventLogs {
    param([string[]]$Computers)
    
    Write-ColorOutput "`n=== Checking AppLocker Event Logs ===" -Color Cyan
    
    $logResults = @()
    $logNames = @(
        'GP_Microsoft-Windows-AppLocker/EXE and DLL',
        'GP_Microsoft-Windows-AppLocker/MSI and Script',
        'Microsoft-Windows-AppLocker/Packaged app-Deployment',
        'Microsoft-Windows-AppLocker/Packaged app-Execution'
    )
    
    foreach ($computer in $Computers) {
        foreach ($logName in $logNames) {
            try {
                Write-Host "Checking $logName on $computer..." -NoNewline
                
                $log = Get-WinEvent -ListLog $logName -ComputerName $computer -ErrorAction Stop
                
                $logInfo = [PSCustomObject]@{
                    ComputerName = $computer
                    LogName = $logName
                    IsEnabled = $log.IsEnabled
                    LogMode = $log.LogMode
                    MaximumSizeInBytes = $log.MaximumSizeInBytes
                    FileSize = $log.FileSize
                    RecordCount = $log.RecordCount
                    OldestRecordTime = $null
                }
                
                # Get oldest record time if records exist
                if ($log.RecordCount -gt 0) {
                    try {
                        $oldestEvent = Get-WinEvent -LogName $logName -ComputerName $computer -MaxEvents 1 -Oldest -ErrorAction Stop
                        $logInfo.OldestRecordTime = $oldestEvent.TimeCreated
                    } catch {
                        # Ignore if we can't get the oldest event
                    }
                }
                
                $logResults += $logInfo
                
                if (-not $log.IsEnabled) {
                    Write-ColorOutput " [DISABLED]" -Color Red
                    Add-Issue "$logName is disabled on $computer" "EventLog"
                    Add-Recommendation "Enable $logName on $computer for AppLocker auditing" "EventLog"
                } elseif ($log.MaximumSizeInBytes -lt 20MB) {
                    Write-ColorOutput " [WARNING: Small log size]" -Color Yellow
                    Add-Warning "$logName on $computer has small maximum size ($($log.MaximumSizeInBytes / 1MB)MB)" "EventLog"
                    Add-Recommendation "Increase $logName size on $computer to at least 20MB" "EventLog"
                } else {
                    Write-ColorOutput " [OK]" -Color Green
                }
                
            } catch {
                Write-ColorOutput " [ERROR]" -Color Red
                Add-Issue "Failed to check $logName on $computer`: $_" "EventLog"
            }
        }
    }
    
    return $logResults
}

# Function to verify policy processing
function Test-AppLockerPolicyProcessing {
    param([string[]]$Computers)
    
    Write-ColorOutput "`n=== Verifying AppLocker Policy Processing ===" -Color Cyan
    
    $processingResults = @()
    
    foreach ($computer in $Computers) {
        try {
            Write-Host "Checking policy processing on $computer..." -NoNewline
            
            # Check for AppLocker CSE in registry
            $cseKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D02B1F72-8A3F-11D1-9A6C-00C04FBBCFA2}"
            
            if ($computer -eq $env:COMPUTERNAME) {
                $cseExists = Test-Path $cseKey
            } else {
                $cseExists = Invoke-Command -ComputerName $computer -ScriptBlock {
                    Test-Path $using:cseKey
                } -ErrorAction Stop
            }
            
            # Check for recent policy application events
            $recentEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'GP_Microsoft-Windows-AppLocker/EXE and DLL'
                ID = 8003, 8004, 8005, 8006, 8007
                StartTime = (Get-Date).AddDays(-7)
            } -ComputerName $computer -ErrorAction SilentlyContinue
            
            $processingInfo = [PSCustomObject]@{
                ComputerName = $computer
                CSERegistered = $cseExists
                RecentPolicyEvents = $recentEvents.Count
                LastPolicyEvent = if ($recentEvents) { $recentEvents[0].TimeCreated } else { $null }
            }
            
            $processingResults += $processingInfo
            
            if (-not $cseExists) {
                Write-ColorOutput " [CSE NOT REGISTERED]" -Color Red
                Add-Issue "AppLocker Client Side Extension not registered on $computer" "PolicyProcessing"
            } elseif ($recentEvents.Count -eq 0) {
                Write-ColorOutput " [NO RECENT EVENTS]" -Color Yellow
                Add-Warning "No recent AppLocker policy events on $computer" "PolicyProcessing"
            } else {
                Write-ColorOutput " [OK]" -Color Green
            }
            
        } catch {
            Write-ColorOutput " [ERROR]" -Color Red
            Add-Issue "Failed to check policy processing on $computer`: $_" "PolicyProcessing"
        }
    }
    
    return $processingResults
}

# Function to check enforcement mode
function Test-AppLockerEnforcementMode {
    param([string[]]$Computers)
    
    Write-ColorOutput "`n=== Checking AppLocker Enforcement Mode ===" -Color Cyan
    
    $enforcementResults = @()
    
    foreach ($computer in $Computers) {
        try {
            Write-Host "Checking enforcement mode on $computer..." -NoNewline
            
            $policy = Get-AppLockerPolicy -Effective -ErrorAction Stop
            
            $enforcementInfo = [PSCustomObject]@{
                ComputerName = $computer
                ExeEnforcement = "NotConfigured"
                MsiEnforcement = "NotConfigured"
                ScriptEnforcement = "NotConfigured"
                DllEnforcement = "NotConfigured"
                AppxEnforcement = "NotConfigured"
            }
            
            foreach ($ruleCollection in $policy.RuleCollections) {
                $property = "$($ruleCollection.RuleCollectionType)Enforcement"
                if ($enforcementInfo.PSObject.Properties[$property]) {
                    $enforcementInfo.$property = $ruleCollection.EnforcementMode
                }
            }
            
            $enforcementResults += $enforcementInfo
            
            # Check for audit mode
            $auditModeCount = ($enforcementInfo.PSObject.Properties | 
                              Where-Object { $_.Value -eq 'AuditOnly' }).Count
            
            if ($auditModeCount -gt 0) {
                Write-ColorOutput " [AUDIT MODE]" -Color Yellow
                Add-Warning "$auditModeCount rule types in Audit mode on $computer" "Enforcement"
                Add-TeenagerPolicyRecommendation "Start with Audit mode for teenager policies to test before enforcement"
            } else {
                Write-ColorOutput " [ENFORCE MODE]" -Color Green
            }
            
        } catch {
            Write-ColorOutput " [ERROR]" -Color Red
            Add-Issue "Failed to check enforcement mode on $computer`: $_" "Enforcement"
        }
    }
    
    return $enforcementResults
}

# Function to validate rule paths
function Test-AppLockerRulePaths {
    param($Rules)
    
    Write-ColorOutput "`n=== Validating Rule Paths ===" -Color Cyan
    
    $pathIssues = @()
    $pathRules = $Rules | Where-Object { $_.RuleType -eq 'Path' }
    
    foreach ($rule in $pathRules) {
        Write-Host "Checking path for rule '$($rule.Name)'..." -NoNewline
        
        $path = $rule.Path
        $expandedPath = [System.Environment]::ExpandEnvironmentVariables($path)
        
        # Check if path exists
        if ($expandedPath -notlike '*\*.*' -and $expandedPath -notlike '*\**') {
            # It's a directory path
            if (-not (Test-Path -Path $expandedPath -PathType Container -ErrorAction SilentlyContinue)) {
                Write-ColorOutput " [PATH NOT FOUND]" -Color Red
                $pathIssues += [PSCustomObject]@{
                    RuleName = $rule.Name
                    Path = $path
                    ExpandedPath = $expandedPath
                    Issue = "Directory not found"
                }
                Add-Issue "Rule '$($rule.Name)' references non-existent directory: $expandedPath" "PathValidation"
            } else {
                Write-ColorOutput " [OK]" -Color Green
            }
        } else {
            # It's a file path or wildcard
            $directory = Split-Path -Path $expandedPath -Parent -ErrorAction SilentlyContinue
            if ($directory -and -not (Test-Path -Path $directory -PathType Container -ErrorAction SilentlyContinue)) {
                Write-ColorOutput " [PARENT PATH NOT FOUND]" -Color Red
                $pathIssues += [PSCustomObject]@{
                    RuleName = $rule.Name
                    Path = $path
                    ExpandedPath = $expandedPath
                    Issue = "Parent directory not found"
                }
                Add-Issue "Rule '$($rule.Name)' references non-existent parent directory: $directory" "PathValidation"
            } else {
                Write-ColorOutput " [OK]" -Color Green
            }
        }
    }
    
    return $pathIssues
}

# Function to analyze rule coverage
function Get-AppLockerRuleCoverage {
    param($Rules)
    
    Write-ColorOutput "`n=== Analyzing Rule Coverage ===" -Color Cyan
    
    $coverage = @{
        TotalRules = $Rules.Count
        AllowRules = ($Rules | Where-Object { $_.Action -eq 'Allow' }).Count
        DenyRules = ($Rules | Where-Object { $_.Action -eq 'Deny' }).Count
        PathRules = ($Rules | Where-Object { $_.RuleType -eq 'Path' }).Count
        PublisherRules = ($Rules | Where-Object { $_.RuleType -eq 'Publisher' }).Count
        HashRules = ($Rules | Where-Object { $_.RuleType -eq 'Hash' }).Count
        RulesByType = @{}
        DefaultRules = @()
        CriticalPaths = @()
    }
    
    # Count rules by type
    foreach ($type in @('Exe', 'Msi', 'Script', 'Dll', 'Appx')) {
        $coverage.RulesByType[$type] = ($Rules | Where-Object { $_.RuleCollectionType -eq $type }).Count
    }
    
    # Check for default rules
    $defaultRulePatterns = @(
        '*\Program Files\*',
        '*\Program Files (x86)\*',
        '*\Windows\*',
        '*\ProgramData\*'
    )
    
    foreach ($rule in $Rules | Where-Object { $_.RuleType -eq 'Path' }) {
        foreach ($pattern in $defaultRulePatterns) {
            if ($rule.Path -like $pattern) {
                $coverage.DefaultRules += $rule
                break
            }
        }
    }
    
    # Check critical paths coverage
    $criticalPaths = @(
        @{ Path = 'C:\Windows\System32'; Description = 'System32 directory' },
        @{ Path = 'C:\Windows\SysWOW64'; Description = 'SysWOW64 directory' },
        @{ Path = 'C:\Program Files'; Description = 'Program Files' },
        @{ Path = 'C:\Program Files (x86)'; Description = 'Program Files (x86)' }
    )
    
    foreach ($critical in $criticalPaths) {
        $covered = $false
        foreach ($rule in $Rules | Where-Object { $_.RuleType -eq 'Path' -and $_.Action -eq 'Allow' }) {
            $expandedPath = [System.Environment]::ExpandEnvironmentVariables($rule.Path)
            if ($expandedPath -like "*$($critical.Path)*") {
                $covered = $true
                break
            }
        }
        
        $coverage.CriticalPaths += [PSCustomObject]@{
            Path = $critical.Path
            Description = $critical.Description
            Covered = $covered
        }
        
        if (-not $covered) {
            Add-Warning "Critical path not covered by Allow rules: $($critical.Description)" "Coverage"
        }
    }
    
    # Display coverage summary
    Write-Host "`nRule Coverage Summary:"
    Write-Host "  Total Rules: $($coverage.TotalRules)"
    Write-Host "  Allow Rules: $($coverage.AllowRules)"
    Write-Host "  Deny Rules: $($coverage.DenyRules)"
    Write-Host "`nRules by Type:"
    foreach ($type in $coverage.RulesByType.Keys) {
        Write-Host "  $type`: $($coverage.RulesByType[$type])"
    }
    
    if ($coverage.DefaultRules.Count -eq 0) {
        Add-Warning "No default rules found - this might block critical Windows components" "Coverage"
        Add-Recommendation "Add default Allow rules for Windows and Program Files directories" "Coverage"
    }
    
    return $coverage
}

# Function to check for problematic default rules
function Test-AppLockerDefaultRules {
    param($Rules)
    
    Write-ColorOutput "`n=== Checking Default Rules ===" -Color Cyan
    
    $issues = @()
    
    # Check for overly permissive rules
    $permissivePatterns = @(
        @{ Pattern = '*'; Description = 'Allows everything' },
        @{ Pattern = 'C:\*'; Description = 'Allows entire C: drive' },
        @{ Pattern = '*\Users\*\*'; Description = 'Allows all user directories' }
    )
    
    foreach ($rule in $Rules | Where-Object { $_.Action -eq 'Allow' -and $_.RuleType -eq 'Path' }) {
        foreach ($permissive in $permissivePatterns) {
            if ($rule.Path -like $permissive.Pattern) {
                Write-ColorOutput "Found overly permissive rule: $($rule.Name)" -Color Yellow
                $issues += [PSCustomObject]@{
                    RuleName = $rule.Name
                    Path = $rule.Path
                    Issue = $permissive.Description
                }
                Add-Warning "Rule '$($rule.Name)' is overly permissive: $($permissive.Description)" "DefaultRules"
            }
        }
    }
    
    # Check for missing standard rules
    $standardRules = @(
        @{ Path = '%WINDIR%\*'; Description = 'Windows directory' },
        @{ Path = '%PROGRAMFILES%\*'; Description = 'Program Files' }
    )
    
    foreach ($standard in $standardRules) {
        $found = $false
        foreach ($rule in $Rules | Where-Object { $_.Action -eq 'Allow' -and $_.RuleType -eq 'Path' }) {
            if ($rule.Path -eq $standard.Path) {
                $found = $true
                break
            }
        }
        
        if (-not $found) {
            Add-Warning "Missing standard Allow rule for: $($standard.Description)" "DefaultRules"
            Add-Recommendation "Add Allow rule for $($standard.Path)" "DefaultRules"
        }
    }
    
    return $issues
}

# Function to test AppLocker functionality
function Test-AppLockerFunctionality {
    param([string]$Computer)
    
    if (-not $TestApplications) {
        Write-ColorOutput "`n=== Skipping Application Tests (use -TestApplications to enable) ===" -Color Yellow
        return
    }
    
    Write-ColorOutput "`n=== Testing AppLocker Functionality ===" -Color Cyan
    
    $testResults = @()
    
    # Create test executables in temp directory
    $testPath = "$env:TEMP\AppLockerTest"
    New-Item -Path $testPath -ItemType Directory -Force | Out-Null
    
    try {
        # Test 1: Unsigned executable in user temp
        $testExe1 = "$testPath\TestApp1.exe"
        $testBatch = "$testPath\TestScript.bat"
        
        # Create a simple batch file as test
        "echo Test AppLocker Script`npause" | Out-File -FilePath $testBatch -Encoding ASCII
        
        Write-Host "Testing script execution..." -NoNewline
        try {
            $result = Start-Process -FilePath $testBatch -Wait -PassThru -WindowStyle Hidden
            Write-ColorOutput " [ALLOWED]" -Color Green
            $testResults += [PSCustomObject]@{
                Test = "Script execution from user temp"
                Path = $testBatch
                Result = "Allowed"
                ExpectedResult = "Should be blocked if AppLocker is enforcing"
            }
        } catch {
            Write-ColorOutput " [BLOCKED]" -Color Yellow
            $testResults += [PSCustomObject]@{
                Test = "Script execution from user temp"
                Path = $testBatch
                Result = "Blocked"
                ExpectedResult = "Correct if AppLocker is enforcing"
            }
        }
        
        # Check for AppLocker events from our test
        $testEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'GP_Microsoft-Windows-AppLocker/MSI and Script'
            StartTime = (Get-Date).AddMinutes(-5)
        } -ErrorAction SilentlyContinue | Where-Object { $_.Message -like "*$testBatch*" }
        
        if ($testEvents) {
            Write-Host "Found $($testEvents.Count) AppLocker events for test" -ForegroundColor Green
        } else {
            Write-Host "No AppLocker events found for test" -ForegroundColor Yellow
            Add-Warning "AppLocker may not be actively monitoring script execution" "Testing"
        }
        
    } finally {
        # Cleanup
        Remove-Item -Path $testPath -Recurse -Force -ErrorAction SilentlyContinue
    }
    
    return $testResults
}

# Function to generate teenager policy recommendations
function Get-TeenagerPolicyRecommendations {
    param($Rules, $Coverage)
    
    Write-ColorOutput "`n=== Teenager Policy Deployment Recommendations ===" -Color Cyan
    
    # Base recommendations
    Add-TeenagerPolicyRecommendation "Start with AppLocker in Audit mode to understand teenager application usage patterns"
    Add-TeenagerPolicyRecommendation "Create Allow rules for educational software and approved applications"
    Add-TeenagerPolicyRecommendation "Use Publisher rules for signed applications when possible (more flexible than path rules)"
    
    # Check if gaming directories are blocked
    $gamingPaths = @(
        'C:\Program Files\Steam\*',
        'C:\Program Files (x86)\Steam\*',
        'C:\Program Files\Epic Games\*',
        'C:\Users\*\AppData\Local\*\Games\*'
    )
    
    $gamingBlocked = $true
    foreach ($path in $gamingPaths) {
        foreach ($rule in $Rules | Where-Object { $_.Action -eq 'Allow' -and $_.RuleType -eq 'Path' }) {
            if ($rule.Path -like $path) {
                $gamingBlocked = $false
                break
            }
        }
    }
    
    if ($gamingBlocked) {
        Add-TeenagerPolicyRecommendation "Consider time-based rules or parental approval workflow for gaming applications"
    }
    
    # Check for user-writable locations
    $userWritablePaths = @(
        '%USERPROFILE%\Downloads\*',
        '%USERPROFILE%\Desktop\*',
        '%TEMP%\*'
    )
    
    $userWritableBlocked = $true
    foreach ($path in $userWritablePaths) {
        foreach ($rule in $Rules | Where-Object { $_.Action -eq 'Allow' -and $_.RuleType -eq 'Path' }) {
            if ($rule.Path -eq $path) {
                $userWritableBlocked = $false
                break
            }
        }
    }
    
    if ($userWritableBlocked) {
        Add-TeenagerPolicyRecommendation "Block execution from user-writable directories to prevent running downloaded executables"
    }
    
    # Educational software recommendations
    Add-TeenagerPolicyRecommendation "Create specific Allow rules for educational platforms (Office, Adobe Creative, coding tools)"
    Add-TeenagerPolicyRecommendation "Use hash rules for portable educational applications that don't have publishers"
    
    # Monitoring recommendations
    Add-TeenagerPolicyRecommendation "Enable and monitor AppLocker event logs to understand blocked application attempts"
    Add-TeenagerPolicyRecommendation "Implement alerting for repeated block events that might indicate needed policy adjustments"
    
    # Maintenance recommendations
    Add-TeenagerPolicyRecommendation "Establish a process for teenagers to request new application approvals"
    Add-TeenagerPolicyRecommendation "Review audit logs monthly to refine rules based on actual usage"
    Add-TeenagerPolicyRecommendation "Consider using Group Policy to apply different AppLocker policies based on age groups"
    
    return $Script:TeenagerPolicyRecommendations
}

# Main execution
try {
    Write-ColorOutput "`n========================================" -Color Cyan
    Write-ColorOutput "     AppLocker Status Assessment" -Color Cyan
    Write-ColorOutput "========================================" -Color Cyan
    Write-ColorOutput "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Color White
    Write-ColorOutput "Target Computers: $($ComputerName -join ', ')" -Color White
    
    # 1. Check Application Identity service
    if (-not $SkipServiceCheck) {
        $serviceStatus = Test-AppLockerService -Computers $ComputerName
    }
    
    # 2. Get AppLocker rules
    $allRules = @()
    foreach ($computer in $ComputerName) {
        $rules = Get-AppLockerRuleInfo -Computer $computer
        if ($rules) {
            $allRules += $rules
        }
    }
    
    if ($allRules.Count -eq 0) {
        Write-ColorOutput "`nNo AppLocker rules found!" -Color Red
        Add-Issue "No AppLocker rules configured" "Rules"
        Add-Recommendation "Configure AppLocker rules to control application execution" "Rules"
    } else {
        # 3. Check for conflicts
        $conflicts = Test-AppLockerRuleConflicts -Rules $allRules
        
        # 4. Check event logs
        $eventLogs = Test-AppLockerEventLogs -Computers $ComputerName
        
        # 5. Verify policy processing
        $policyProcessing = Test-AppLockerPolicyProcessing -Computers $ComputerName
        
        # 6. Check enforcement mode
        $enforcementMode = Test-AppLockerEnforcementMode -Computers $ComputerName
        
        # 7. Validate rule paths
        $pathValidation = Test-AppLockerRulePaths -Rules $allRules
        
        # 8. Analyze coverage
        $coverage = Get-AppLockerRuleCoverage -Rules $allRules
        
        # 9. Check default rules
        $defaultRuleIssues = Test-AppLockerDefaultRules -Rules $allRules
        
        # 10. Test functionality
        if ($ComputerName.Count -eq 1 -and $ComputerName[0] -eq $env:COMPUTERNAME) {
            $functionalityTest = Test-AppLockerFunctionality -Computer $ComputerName[0]
        }
    }
    
    # Generate teenager policy recommendations
    $teenagerRecommendations = Get-TeenagerPolicyRecommendations -Rules $allRules -Coverage $coverage
    
    # Generate report
    Write-ColorOutput "`n========================================" -Color Cyan
    Write-ColorOutput "           Assessment Summary" -Color Cyan
    Write-ColorOutput "========================================" -Color Cyan
    
    # Summary statistics
    Write-Host "`nIssues Found: $($Script:Issues.Count)" -ForegroundColor $(if ($Script:Issues.Count -gt 0) { 'Red' } else { 'Green' })
    Write-Host "Warnings: $($Script:Warnings.Count)" -ForegroundColor $(if ($Script:Warnings.Count -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host "Recommendations: $($Script:Recommendations.Count)" -ForegroundColor Cyan
    
    # Display issues
    if ($Script:Issues.Count -gt 0) {
        Write-ColorOutput "`nCritical Issues:" -Color Red
        $Script:Issues | Group-Object Category | ForEach-Object {
            Write-Host "`n  $($_.Name):" -ForegroundColor Red
            $_.Group | ForEach-Object {
                Write-Host "    - $($_.Issue)" -ForegroundColor Red
            }
        }
    }
    
    # Display warnings
    if ($Script:Warnings.Count -gt 0) {
        Write-ColorOutput "`nWarnings:" -Color Yellow
        $Script:Warnings | Group-Object Category | ForEach-Object {
            Write-Host "`n  $($_.Name):" -ForegroundColor Yellow
            $_.Group | ForEach-Object {
                Write-Host "    - $($_.Warning)" -ForegroundColor Yellow
            }
        }
    }
    
    # Display recommendations
    if ($Script:Recommendations.Count -gt 0) {
        Write-ColorOutput "`nRecommendations:" -Color Cyan
        $Script:Recommendations | Group-Object Category | ForEach-Object {
            Write-Host "`n  $($_.Name):" -ForegroundColor Cyan
            $_.Group | ForEach-Object {
                Write-Host "    - $($_.Recommendation)" -ForegroundColor Cyan
            }
        }
    }
    
    # Display teenager policy recommendations
    if ($Script:TeenagerPolicyRecommendations.Count -gt 0) {
        Write-ColorOutput "`nTeenager Policy Deployment Recommendations:" -Color Magenta
        $Script:TeenagerPolicyRecommendations | ForEach-Object {
            Write-Host "  - $_" -ForegroundColor Magenta
        }
    }
    
    # Export detailed report
    $reportPath = Join-Path $OutputPath "AppLocker_Assessment_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    
    # Generate HTML report
    $htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>AppLocker Assessment Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1, h2, h3 { color: #333; }
        .issue { color: #d32f2f; }
        .warning { color: #f57c00; }
        .recommendation { color: #0288d1; }
        .teenager { color: #7b1fa2; }
        .ok { color: #388e3c; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f5f5f5; }
        .summary-box { background-color: #f5f5f5; padding: 15px; margin: 20px 0; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>AppLocker Assessment Report</h1>
    <p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    
    <div class="summary-box">
        <h2>Summary</h2>
        <p>Assessed Computers: $($ComputerName -join ', ')</p>
        <p>Total Rules Found: $($allRules.Count)</p>
        <p class="issue">Critical Issues: $($Script:Issues.Count)</p>
        <p class="warning">Warnings: $($Script:Warnings.Count)</p>
        <p class="recommendation">Recommendations: $($Script:Recommendations.Count)</p>
    </div>
"@
    
    # Add service status
    if ($serviceStatus) {
        $htmlReport += @"
    <h2>Application Identity Service Status</h2>
    <table>
        <tr>
            <th>Computer</th>
            <th>Status</th>
            <th>Start Type</th>
        </tr>
"@
        foreach ($service in $serviceStatus) {
            $statusClass = if ($service.Status -eq 'Running') { 'ok' } else { 'issue' }
            $htmlReport += @"
        <tr>
            <td>$($service.ComputerName)</td>
            <td class="$statusClass">$($service.Status)</td>
            <td>$($service.StartType)</td>
        </tr>
"@
        }
        $htmlReport += "</table>"
    }
    
    # Add rule summary
    if ($coverage) {
        $htmlReport += @"
    <h2>Rule Coverage Analysis</h2>
    <table>
        <tr>
            <th>Rule Type</th>
            <th>Count</th>
        </tr>
"@
        foreach ($type in $coverage.RulesByType.Keys) {
            $htmlReport += @"
        <tr>
            <td>$type</td>
            <td>$($coverage.RulesByType[$type])</td>
        </tr>
"@
        }
        $htmlReport += @"
    </table>
    <p>Total Allow Rules: $($coverage.AllowRules)</p>
    <p>Total Deny Rules: $($coverage.DenyRules)</p>
"@
    }
    
    # Add issues
    if ($Script:Issues.Count -gt 0) {
        $htmlReport += "<h2 class='issue'>Critical Issues</h2><ul>"
        $Script:Issues | ForEach-Object {
            $htmlReport += "<li class='issue'>[$($_.Category)] $($_.Issue)</li>"
        }
        $htmlReport += "</ul>"
    }
    
    # Add warnings
    if ($Script:Warnings.Count -gt 0) {
        $htmlReport += "<h2 class='warning'>Warnings</h2><ul>"
        $Script:Warnings | ForEach-Object {
            $htmlReport += "<li class='warning'>[$($_.Category)] $($_.Warning)</li>"
        }
        $htmlReport += "</ul>"
    }
    
    # Add recommendations
    if ($Script:Recommendations.Count -gt 0) {
        $htmlReport += "<h2 class='recommendation'>Recommendations</h2><ul>"
        $Script:Recommendations | ForEach-Object {
            $htmlReport += "<li class='recommendation'>[$($_.Category)] $($_.Recommendation)</li>"
        }
        $htmlReport += "</ul>"
    }
    
    # Add teenager recommendations
    if ($Script:TeenagerPolicyRecommendations.Count -gt 0) {
        $htmlReport += "<h2 class='teenager'>Teenager Policy Deployment Recommendations</h2><ul>"
        $Script:TeenagerPolicyRecommendations | ForEach-Object {
            $htmlReport += "<li class='teenager'>$_</li>"
        }
        $htmlReport += "</ul>"
    }
    
    $htmlReport += @"
</body>
</html>
"@
    
    # Save report
    $htmlReport | Out-File -FilePath $reportPath -Encoding UTF8
    Write-ColorOutput "`nDetailed report saved to: $reportPath" -Color Green
    
    # Export data for further analysis
    $dataExport = @{
        AssessmentDate = Get-Date
        Computers = $ComputerName
        ServiceStatus = $serviceStatus
        Rules = $allRules
        Conflicts = $conflicts
        EventLogs = $eventLogs
        PolicyProcessing = $policyProcessing
        EnforcementMode = $enforcementMode
        PathValidation = $pathValidation
        Coverage = $coverage
        Issues = $Script:Issues
        Warnings = $Script:Warnings
        Recommendations = $Script:Recommendations
        TeenagerRecommendations = $Script:TeenagerPolicyRecommendations
    }
    
    $jsonPath = Join-Path $OutputPath "AppLocker_Assessment_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $dataExport | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
    Write-ColorOutput "Data export saved to: $jsonPath" -Color Green
    
} catch {
    Write-ColorOutput "`nFATAL ERROR: $_" -Color Red
    Write-ColorOutput $_.ScriptStackTrace -Color Red
    exit 1
}

Write-ColorOutput "`nAssessment completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Color Green