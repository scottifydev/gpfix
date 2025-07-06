#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Comprehensively checks Chrome browser policies in Active Directory environment.

.DESCRIPTION
    This script performs a thorough assessment of Chrome browser policies including:
    - ADMX template versions
    - Registry restrictions
    - GPO conflicts
    - Policy application testing
    - Extension and update policies
    - URL filtering configurations
    - Cross-browser consistency

.PARAMETER DomainController
    Specify a domain controller to query. If not specified, uses the current domain controller.

.PARAMETER ComputerName
    Target computer(s) to test policy application. Default is local computer.

.PARAMETER ExportPath
    Path to export detailed report. Default is current directory.

.PARAMETER IncludeUserPolicies
    Include user-based Chrome policies in the assessment.

.EXAMPLE
    .\Check-ChromePolicies.ps1 -ExportPath "C:\Reports" -IncludeUserPolicies

.NOTES
    Author: Group Policy Assessment Team
    Version: 1.0
    Requires: Domain Admin rights for comprehensive assessment
#>

[CmdletBinding()]
param(
    [string]$DomainController,
    [string[]]$ComputerName = $env:COMPUTERNAME,
    [string]$ExportPath = (Get-Location).Path,
    [switch]$IncludeUserPolicies
)

# Initialize script
$ErrorActionPreference = 'Stop'
$VerbosePreference = 'Continue'
$script:Findings = @()
$script:Recommendations = @()
$script:Conflicts = @()

# Import required modules
function Initialize-Script {
    Write-Verbose "Initializing Chrome policy assessment..."
    
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        Import-Module GroupPolicy -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to import required modules: $_"
        exit 1
    }
    
    # Create report directory
    $script:ReportPath = Join-Path $ExportPath "ChromePolicyReport_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    New-Item -ItemType Directory -Path $script:ReportPath -Force | Out-Null
    
    Write-Verbose "Report will be saved to: $script:ReportPath"
}

# Function to check Chrome ADMX template versions
function Test-ChromeADMXTemplates {
    param(
        [string]$DC = $DomainController
    )
    
    Write-Verbose "Checking Chrome ADMX template versions..."
    $templateInfo = @{
        TemplatesFound = $false
        Version = "Not Found"
        Files = @()
        Issues = @()
    }
    
    try {
        # Check central store
        $centralStorePath = "\\$((Get-ADDomain).PDCEmulator)\SYSVOL\$((Get-ADDomain).DNSRoot)\Policies\PolicyDefinitions"
        
        if (Test-Path $centralStorePath) {
            $chromeADMX = Get-ChildItem -Path $centralStorePath -Filter "chrome.admx" -Recurse
            $chromeADML = Get-ChildItem -Path "$centralStorePath\en-US" -Filter "chrome.adml" -ErrorAction SilentlyContinue
            
            if ($chromeADMX) {
                $templateInfo.TemplatesFound = $true
                $templateInfo.Files += $chromeADMX.FullName
                
                # Try to extract version from ADMX content
                $admxContent = Get-Content $chromeADMX.FullName -Raw
                if ($admxContent -match 'revision="(\d+\.\d+)"') {
                    $templateInfo.Version = $matches[1]
                }
                
                # Check for language files
                if (-not $chromeADML) {
                    $templateInfo.Issues += "Chrome ADML language file not found in en-US folder"
                }
                else {
                    $templateInfo.Files += $chromeADML.FullName
                }
            }
            else {
                $templateInfo.Issues += "Chrome ADMX template not found in central store"
            }
            
            # Check for Google common templates
            $googleADMX = Get-ChildItem -Path $centralStorePath -Filter "google.admx" -Recurse
            if (-not $googleADMX) {
                $templateInfo.Issues += "Google common ADMX template not found (required for Chrome policies)"
            }
        }
        else {
            $templateInfo.Issues += "Central policy store not accessible at: $centralStorePath"
        }
    }
    catch {
        $templateInfo.Issues += "Error checking ADMX templates: $_"
    }
    
    return $templateInfo
}

# Function to check Chrome registry restrictions
function Get-ChromeRegistryPolicies {
    param(
        [string[]]$Computers = $ComputerName
    )
    
    Write-Verbose "Checking Chrome registry policies..."
    $registryPolicies = @()
    
    $chromePaths = @(
        'HKLM:\SOFTWARE\Policies\Google\Chrome',
        'HKLM:\SOFTWARE\Policies\Google\Update',
        'HKCU:\SOFTWARE\Policies\Google\Chrome',
        'HKCU:\SOFTWARE\Policies\Google\Update'
    )
    
    foreach ($computer in $Computers) {
        Write-Verbose "Checking registry on $computer..."
        
        $computerPolicies = @{
            ComputerName = $computer
            Policies = @{}
            Issues = @()
        }
        
        try {
            $session = if ($computer -ne $env:COMPUTERNAME) {
                New-PSSession -ComputerName $computer -ErrorAction Stop
            }
            else {
                $null
            }
            
            $scriptBlock = {
                param($paths)
                $results = @{}
                
                foreach ($path in $paths) {
                    if (Test-Path $path) {
                        $policies = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
                        if ($policies) {
                            $policyList = @{}
                            $policies.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
                                $policyList[$_.Name] = $_.Value
                            }
                            $results[$path] = $policyList
                        }
                        
                        # Check for subkeys
                        Get-ChildItem -Path $path -ErrorAction SilentlyContinue | ForEach-Object {
                            $subPolicies = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                            if ($subPolicies) {
                                $subPolicyList = @{}
                                $subPolicies.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
                                    $subPolicyList[$_.Name] = $_.Value
                                }
                                $results[$_.PSPath] = $subPolicyList
                            }
                        }
                    }
                }
                
                return $results
            }
            
            if ($session) {
                $computerPolicies.Policies = Invoke-Command -Session $session -ScriptBlock $scriptBlock -ArgumentList $chromePaths
                Remove-PSSession -Session $session
            }
            else {
                $computerPolicies.Policies = & $scriptBlock $chromePaths
            }
        }
        catch {
            $computerPolicies.Issues += "Failed to check registry: $_"
        }
        
        $registryPolicies += $computerPolicies
    }
    
    return $registryPolicies
}

# Function to identify Chrome policy conflicts across GPOs
function Find-ChromePolicyConflicts {
    Write-Verbose "Searching for Chrome policy conflicts across GPOs..."
    $conflicts = @()
    $chromePolicies = @{}
    
    try {
        # Get all GPOs
        $gpos = Get-GPO -All
        
        foreach ($gpo in $gpos) {
            Write-Verbose "Analyzing GPO: $($gpo.DisplayName)"
            
            try {
                # Generate GPO report
                $report = Get-GPOReport -Guid $gpo.Id -ReportType Xml
                $xml = [xml]$report
                
                # Search for Chrome policies in Computer Configuration
                $computerPolicies = $xml.GPO.Computer.ExtensionData.Extension | 
                    Where-Object { $_.type -eq 'Registry' } |
                    ForEach-Object { $_.RegistrySettings.Registry } |
                    Where-Object { $_.Properties.key -like '*Google\Chrome*' }
                
                # Search for Chrome policies in User Configuration
                $userPolicies = $xml.GPO.User.ExtensionData.Extension | 
                    Where-Object { $_.type -eq 'Registry' } |
                    ForEach-Object { $_.RegistrySettings.Registry } |
                    Where-Object { $_.Properties.key -like '*Google\Chrome*' }
                
                # Process policies
                $allPolicies = @()
                if ($computerPolicies) { $allPolicies += $computerPolicies }
                if ($userPolicies) { $allPolicies += $userPolicies }
                
                foreach ($policy in $allPolicies) {
                    $policyKey = "$($policy.Properties.key)\$($policy.Properties.value)"
                    
                    if (-not $chromePolicies.ContainsKey($policyKey)) {
                        $chromePolicies[$policyKey] = @()
                    }
                    
                    $chromePolicies[$policyKey] += @{
                        GPO = $gpo.DisplayName
                        GPOId = $gpo.Id
                        Key = $policy.Properties.key
                        Value = $policy.Properties.value
                        Data = $policy.Properties.data
                        Type = $policy.Properties.type
                        Action = $policy.Properties.action
                    }
                }
            }
            catch {
                Write-Warning "Failed to analyze GPO '$($gpo.DisplayName)': $_"
            }
        }
        
        # Identify conflicts
        foreach ($policyKey in $chromePolicies.Keys) {
            if ($chromePolicies[$policyKey].Count -gt 1) {
                $conflictingGPOs = $chromePolicies[$policyKey]
                $uniqueValues = $conflictingGPOs | Select-Object -ExpandProperty Data -Unique
                
                if ($uniqueValues.Count -gt 1) {
                    $conflicts += @{
                        PolicyKey = $policyKey
                        ConflictingGPOs = $conflictingGPOs
                        Severity = 'High'
                        Description = "Multiple GPOs setting different values for the same Chrome policy"
                    }
                }
            }
        }
    }
    catch {
        Write-Error "Failed to find Chrome policy conflicts: $_"
    }
    
    return $conflicts
}

# Function to test Chrome policy application
function Test-ChromePolicyApplication {
    param(
        [string[]]$Computers = $ComputerName
    )
    
    Write-Verbose "Testing Chrome policy application..."
    $testResults = @()
    
    foreach ($computer in $Computers) {
        Write-Verbose "Testing policy application on $computer..."
        
        $result = @{
            ComputerName = $computer
            ChromeInstalled = $false
            PolicyFilesExist = $false
            PoliciesApplied = @()
            Issues = @()
            LastPolicyUpdate = $null
        }
        
        try {
            $session = if ($computer -ne $env:COMPUTERNAME) {
                New-PSSession -ComputerName $computer -ErrorAction Stop
            }
            else {
                $null
            }
            
            $scriptBlock = {
                $testInfo = @{
                    ChromeInstalled = $false
                    PolicyFilesExist = $false
                    PoliciesApplied = @()
                    Issues = @()
                    LastPolicyUpdate = $null
                }
                
                # Check if Chrome is installed
                $chromePaths = @(
                    "${env:ProgramFiles}\Google\Chrome\Application\chrome.exe",
                    "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
                )
                
                foreach ($path in $chromePaths) {
                    if (Test-Path $path) {
                        $testInfo.ChromeInstalled = $true
                        break
                    }
                }
                
                if (-not $testInfo.ChromeInstalled) {
                    $testInfo.Issues += "Chrome is not installed on this computer"
                    return $testInfo
                }
                
                # Check for Chrome policy files
                $policyPaths = @(
                    "${env:ProgramFiles}\Google\Chrome\Application\master_preferences",
                    "${env:ProgramFiles(x86)}\Google\Chrome\Application\master_preferences"
                )
                
                foreach ($path in $policyPaths) {
                    if (Test-Path $path) {
                        $testInfo.PolicyFilesExist = $true
                        break
                    }
                }
                
                # Check registry for applied policies
                if (Test-Path 'HKLM:\SOFTWARE\Policies\Google\Chrome') {
                    $policies = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Google\Chrome' -ErrorAction SilentlyContinue
                    if ($policies) {
                        $policies.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
                            $testInfo.PoliciesApplied += @{
                                Name = $_.Name
                                Value = $_.Value
                                Source = 'Computer Policy'
                            }
                        }
                    }
                }
                
                # Check when policies were last updated
                try {
                    $gpResult = gpresult /r /scope computer
                    if ($gpResult -match 'Last time Group Policy was applied: (.+)') {
                        $testInfo.LastPolicyUpdate = $matches[1]
                    }
                }
                catch {
                    $testInfo.Issues += "Could not determine last policy update time"
                }
                
                return $testInfo
            }
            
            if ($session) {
                $testInfo = Invoke-Command -Session $session -ScriptBlock $scriptBlock
                Remove-PSSession -Session $session
            }
            else {
                $testInfo = & $scriptBlock
            }
            
            $result.ChromeInstalled = $testInfo.ChromeInstalled
            $result.PolicyFilesExist = $testInfo.PolicyFilesExist
            $result.PoliciesApplied = $testInfo.PoliciesApplied
            $result.Issues = $testInfo.Issues
            $result.LastPolicyUpdate = $testInfo.LastPolicyUpdate
        }
        catch {
            $result.Issues += "Failed to test policy application: $_"
        }
        
        $testResults += $result
    }
    
    return $testResults
}

# Function to document current Chrome settings
function Get-ChromeSettingsDocumentation {
    Write-Verbose "Documenting current Chrome settings..."
    
    $settings = @{
        SecuritySettings = @{}
        PrivacySettings = @{}
        ExtensionSettings = @{}
        UpdateSettings = @{}
        URLFilteringSettings = @{}
        TeenagerRelevantSettings = @{}
    }
    
    # Get settings from registry
    $registryPolicies = Get-ChromeRegistryPolicies -Computers $ComputerName
    
    foreach ($computerPolicy in $registryPolicies) {
        foreach ($path in $computerPolicy.Policies.Keys) {
            foreach ($policy in $computerPolicy.Policies[$path].Keys) {
                $value = $computerPolicy.Policies[$path][$policy]
                
                # Categorize settings
                switch -Regex ($policy) {
                    'IncognitoModeAvailability' {
                        $settings.PrivacySettings[$policy] = @{
                            Value = $value
                            Description = "Controls incognito mode availability (0=Available, 1=Disabled, 2=Forced)"
                            TeenagerRelevant = $true
                        }
                    }
                    'SafeSearchMode|SafeBrowsingEnabled|ForceGoogleSafeSearch' {
                        $settings.SecuritySettings[$policy] = @{
                            Value = $value
                            Description = "Safe browsing and search settings"
                            TeenagerRelevant = $true
                        }
                    }
                    'ExtensionInstallBlocklist|ExtensionInstallAllowlist|ExtensionInstallForcelist' {
                        $settings.ExtensionSettings[$policy] = @{
                            Value = $value
                            Description = "Extension installation control"
                            TeenagerRelevant = $true
                        }
                    }
                    'UpdateDefault|AutoUpdateCheckPeriodMinutes' {
                        $settings.UpdateSettings[$policy] = @{
                            Value = $value
                            Description = "Chrome update settings"
                            TeenagerRelevant = $false
                        }
                    }
                    'URLBlocklist|URLAllowlist' {
                        $settings.URLFilteringSettings[$policy] = @{
                            Value = $value
                            Description = "URL filtering rules"
                            TeenagerRelevant = $true
                        }
                    }
                    'SupervisedUserManualHosts|SupervisedUserManualURLs' {
                        $settings.TeenagerRelevantSettings[$policy] = @{
                            Value = $value
                            Description = "Supervised user settings"
                            TeenagerRelevant = $true
                        }
                    }
                    default {
                        # Determine if setting is teenager-relevant
                        $teenagerKeywords = @('Block', 'Restrict', 'Disable', 'Force', 'Supervised', 'Parent', 'Safe')
                        $isTeenagerRelevant = $false
                        foreach ($keyword in $teenagerKeywords) {
                            if ($policy -match $keyword) {
                                $isTeenagerRelevant = $true
                                break
                            }
                        }
                        
                        if ($isTeenagerRelevant) {
                            $settings.TeenagerRelevantSettings[$policy] = @{
                                Value = $value
                                Description = "Policy may be relevant for teenager restrictions"
                                TeenagerRelevant = $true
                            }
                        }
                    }
                }
            }
        }
    }
    
    return $settings
}

# Function to check Chrome extension policies
function Get-ChromeExtensionPolicies {
    Write-Verbose "Checking Chrome extension policies..."
    
    $extensionPolicies = @{
        Blocklist = @()
        Allowlist = @()
        Forcelist = @()
        Settings = @{}
        Issues = @()
    }
    
    $registryPolicies = Get-ChromeRegistryPolicies -Computers $ComputerName
    
    foreach ($computerPolicy in $registryPolicies) {
        foreach ($path in $computerPolicy.Policies.Keys) {
            if ($path -match 'Chrome') {
                $policies = $computerPolicy.Policies[$path]
                
                # Check extension-related policies
                if ($policies.ContainsKey('ExtensionInstallBlocklist')) {
                    $extensionPolicies.Blocklist += $policies['ExtensionInstallBlocklist']
                }
                
                if ($policies.ContainsKey('ExtensionInstallAllowlist')) {
                    $extensionPolicies.Allowlist += $policies['ExtensionInstallAllowlist']
                }
                
                if ($policies.ContainsKey('ExtensionInstallForcelist')) {
                    $extensionPolicies.Forcelist += $policies['ExtensionInstallForcelist']
                }
                
                # Check for extension settings
                if ($path -match 'ExtensionSettings') {
                    $extensionPolicies.Settings = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
                }
            }
        }
    }
    
    # Analyze extension policies
    if ($extensionPolicies.Blocklist -contains '*' -and $extensionPolicies.Allowlist.Count -eq 0) {
        $extensionPolicies.Issues += "All extensions are blocked with no allowlist configured"
    }
    
    if ($extensionPolicies.Forcelist.Count -gt 0) {
        $extensionPolicies.Issues += "Forced extensions configured - verify these are necessary"
    }
    
    return $extensionPolicies
}

# Function to verify Chrome update policies
function Get-ChromeUpdatePolicies {
    Write-Verbose "Checking Chrome update policies..."
    
    $updatePolicies = @{
        UpdatesEnabled = $true
        AutoUpdateCheck = $true
        UpdateInterval = "Default"
        UpdateRestrictions = @()
        Issues = @()
    }
    
    $registryPolicies = Get-ChromeRegistryPolicies -Computers $ComputerName
    
    foreach ($computerPolicy in $registryPolicies) {
        foreach ($path in $computerPolicy.Policies.Keys) {
            if ($path -match 'Google\\Update') {
                $policies = $computerPolicy.Policies[$path]
                
                if ($policies.ContainsKey('UpdateDefault')) {
                    $updatePolicies.UpdatesEnabled = $policies['UpdateDefault'] -ne 0
                }
                
                if ($policies.ContainsKey('AutoUpdateCheckPeriodMinutes')) {
                    $updatePolicies.UpdateInterval = "$($policies['AutoUpdateCheckPeriodMinutes']) minutes"
                }
                
                if ($policies.ContainsKey('InstallDefault')) {
                    if ($policies['InstallDefault'] -eq 0) {
                        $updatePolicies.UpdateRestrictions += "New installations disabled"
                    }
                }
            }
        }
    }
    
    # Check for issues
    if (-not $updatePolicies.UpdatesEnabled) {
        $updatePolicies.Issues += "Chrome updates are disabled - security risk"
    }
    
    return $updatePolicies
}

# Function to check URL filtering configurations
function Get-ChromeURLFiltering {
    Write-Verbose "Checking Chrome URL filtering configurations..."
    
    $urlFiltering = @{
        Blocklist = @()
        Allowlist = @()
        SafeSearchEnforced = $false
        YouTubeRestricted = $false
        Issues = @()
    }
    
    $registryPolicies = Get-ChromeRegistryPolicies -Computers $ComputerName
    
    foreach ($computerPolicy in $registryPolicies) {
        foreach ($path in $computerPolicy.Policies.Keys) {
            if ($path -match 'Chrome') {
                $policies = $computerPolicy.Policies[$path]
                
                # URL filtering
                if ($policies.ContainsKey('URLBlocklist')) {
                    $urlFiltering.Blocklist += $policies['URLBlocklist']
                }
                
                if ($policies.ContainsKey('URLAllowlist')) {
                    $urlFiltering.Allowlist += $policies['URLAllowlist']
                }
                
                # Safe search
                if ($policies.ContainsKey('ForceGoogleSafeSearch')) {
                    $urlFiltering.SafeSearchEnforced = $policies['ForceGoogleSafeSearch'] -eq 1
                }
                
                # YouTube restrictions
                if ($policies.ContainsKey('ForceYouTubeRestrict')) {
                    $urlFiltering.YouTubeRestricted = $policies['ForceYouTubeRestrict'] -gt 0
                }
            }
        }
    }
    
    # Analyze URL filtering
    if ($urlFiltering.Blocklist.Count -eq 0 -and -not $urlFiltering.SafeSearchEnforced) {
        $urlFiltering.Issues += "No URL filtering or safe search configured"
    }
    
    return $urlFiltering
}

# Function to compare Chrome policies with Edge/Firefox
function Compare-BrowserPolicies {
    Write-Verbose "Comparing Chrome policies with Edge and Firefox..."
    
    $comparison = @{
        Chrome = @{}
        Edge = @{}
        Firefox = @{}
        Inconsistencies = @()
    }
    
    # Get Chrome policies
    $chromePolicies = Get-ChromeRegistryPolicies -Computers $ComputerName
    foreach ($computerPolicy in $chromePolicies) {
        foreach ($path in $computerPolicy.Policies.Keys) {
            if ($path -match 'Chrome') {
                $comparison.Chrome = $computerPolicy.Policies[$path]
            }
        }
    }
    
    # Get Edge policies
    $edgePaths = @(
        'HKLM:\SOFTWARE\Policies\Microsoft\Edge',
        'HKCU:\SOFTWARE\Policies\Microsoft\Edge'
    )
    
    foreach ($path in $edgePaths) {
        if (Test-Path $path) {
            $edgePolicies = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            if ($edgePolicies) {
                $edgePolicies.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
                    $comparison.Edge[$_.Name] = $_.Value
                }
            }
        }
    }
    
    # Get Firefox policies
    $firefoxPath = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'
    if (Test-Path $firefoxPath) {
        $firefoxPolicies = Get-ItemProperty -Path $firefoxPath -ErrorAction SilentlyContinue
        if ($firefoxPolicies) {
            $firefoxPolicies.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
                $comparison.Firefox[$_.Name] = $_.Value
            }
        }
    }
    
    # Compare common policies
    $commonPolicies = @{
        'IncognitoMode' = @{
            Chrome = 'IncognitoModeAvailability'
            Edge = 'InPrivateModeAvailability'
            Firefox = 'DisablePrivateBrowsing'
        }
        'SafeSearch' = @{
            Chrome = 'ForceGoogleSafeSearch'
            Edge = 'ForceSafeSearch'
            Firefox = 'SearchSuggestEnabled'
        }
        'Extensions' = @{
            Chrome = 'ExtensionInstallBlocklist'
            Edge = 'ExtensionInstallBlocklist'
            Firefox = 'ExtensionSettings'
        }
    }
    
    foreach ($policy in $commonPolicies.Keys) {
        $chromeValue = $comparison.Chrome[$commonPolicies[$policy].Chrome]
        $edgeValue = $comparison.Edge[$commonPolicies[$policy].Edge]
        $firefoxValue = $comparison.Firefox[$commonPolicies[$policy].Firefox]
        
        # Check for inconsistencies
        if (($chromeValue -and -not $edgeValue) -or ($edgeValue -and -not $chromeValue)) {
            $comparison.Inconsistencies += @{
                Policy = $policy
                Chrome = $chromeValue
                Edge = $edgeValue
                Firefox = $firefoxValue
                Issue = "Policy configured for one browser but not others"
            }
        }
    }
    
    return $comparison
}

# Function to generate teenager policy recommendations
function Get-TeenagerPolicyRecommendations {
    Write-Verbose "Generating teenager policy recommendations..."
    
    $recommendations = @{
        HighPriority = @()
        MediumPriority = @()
        LowPriority = @()
        ConflictingPolicies = @()
    }
    
    # Get current settings
    $currentSettings = Get-ChromeSettingsDocumentation
    $urlFiltering = Get-ChromeURLFiltering
    $extensionPolicies = Get-ChromeExtensionPolicies
    
    # High priority recommendations
    if (-not $currentSettings.PrivacySettings.ContainsKey('IncognitoModeAvailability') -or 
        $currentSettings.PrivacySettings['IncognitoModeAvailability'].Value -ne 1) {
        $recommendations.HighPriority += @{
            Policy = 'IncognitoModeAvailability'
            CurrentValue = $currentSettings.PrivacySettings['IncognitoModeAvailability'].Value
            RecommendedValue = 1
            Reason = "Disable incognito mode to prevent bypassing content filters"
            Implementation = 'Set HKLM:\SOFTWARE\Policies\Google\Chrome\IncognitoModeAvailability = 1'
        }
    }
    
    if (-not $urlFiltering.SafeSearchEnforced) {
        $recommendations.HighPriority += @{
            Policy = 'ForceGoogleSafeSearch'
            CurrentValue = $false
            RecommendedValue = $true
            Reason = "Enforce safe search to filter inappropriate content"
            Implementation = 'Set HKLM:\SOFTWARE\Policies\Google\Chrome\ForceGoogleSafeSearch = 1'
        }
    }
    
    if (-not $urlFiltering.YouTubeRestricted) {
        $recommendations.HighPriority += @{
            Policy = 'ForceYouTubeRestrict'
            CurrentValue = 0
            RecommendedValue = 2
            Reason = "Enable YouTube Restricted Mode to filter mature content"
            Implementation = 'Set HKLM:\SOFTWARE\Policies\Google\Chrome\ForceYouTubeRestrict = 2'
        }
    }
    
    # Medium priority recommendations
    if ($urlFiltering.Blocklist.Count -eq 0) {
        $recommendations.MediumPriority += @{
            Policy = 'URLBlocklist'
            CurrentValue = @()
            RecommendedValue = @('*://example-adult-site.com/*', '*://gambling-site.com/*')
            Reason = "Block access to inappropriate websites"
            Implementation = 'Configure URL blocklist with inappropriate site patterns'
        }
    }
    
    if ($extensionPolicies.Blocklist -notcontains '*') {
        $recommendations.MediumPriority += @{
            Policy = 'ExtensionInstallBlocklist'
            CurrentValue = $extensionPolicies.Blocklist
            RecommendedValue = @('*')
            Reason = "Block all extensions by default, then allowlist approved ones"
            Implementation = 'Set ExtensionInstallBlocklist = * and configure ExtensionInstallAllowlist'
        }
    }
    
    # Low priority recommendations
    $recommendations.LowPriority += @{
        Policy = 'HomepageLocation'
        CurrentValue = 'Not Set'
        RecommendedValue = 'https://www.google.com'
        Reason = "Set a safe default homepage"
        Implementation = 'Set HKLM:\SOFTWARE\Policies\Google\Chrome\HomepageLocation'
    }
    
    $recommendations.LowPriority += @{
        Policy = 'DefaultSearchProviderEnabled'
        CurrentValue = 'Not Set'
        RecommendedValue = $true
        Reason = "Ensure safe search provider is used"
        Implementation = 'Configure default search provider with safe search enabled'
    }
    
    # Check for conflicting policies
    $conflicts = Find-ChromePolicyConflicts
    foreach ($conflict in $conflicts) {
        if ($conflict.PolicyKey -match 'IncognitoMode|SafeSearch|URLBlock|Extension') {
            $recommendations.ConflictingPolicies += $conflict
        }
    }
    
    return $recommendations
}

# Function to generate comprehensive report
function Export-ChromePolicyReport {
    param(
        [hashtable]$ADMXInfo,
        [array]$RegistryPolicies,
        [array]$Conflicts,
        [array]$ApplicationTests,
        [hashtable]$CurrentSettings,
        [hashtable]$ExtensionPolicies,
        [hashtable]$UpdatePolicies,
        [hashtable]$URLFiltering,
        [hashtable]$BrowserComparison,
        [hashtable]$Recommendations
    )
    
    Write-Verbose "Generating comprehensive Chrome policy report..."
    
    # Create HTML report
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Chrome Policy Assessment Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #1a73e8; border-bottom: 3px solid #1a73e8; padding-bottom: 10px; }
        h2 { color: #5f6368; margin-top: 30px; }
        h3 { color: #202124; }
        table { border-collapse: collapse; width: 100%; margin-top: 10px; }
        th, td { border: 1px solid #dadce0; padding: 8px; text-align: left; }
        th { background-color: #f8f9fa; font-weight: bold; }
        tr:nth-child(even) { background-color: #f8f9fa; }
        .high { background-color: #fce4ec; }
        .medium { background-color: #fff3cd; }
        .low { background-color: #e3f2fd; }
        .success { color: #1e8e3e; }
        .warning { color: #f9ab00; }
        .error { color: #d93025; }
        .recommendation { background-color: #e8f5e9; padding: 10px; margin: 10px 0; border-radius: 5px; }
        .conflict { background-color: #ffebee; padding: 10px; margin: 10px 0; border-radius: 5px; }
        .summary-box { background-color: #e3f2fd; padding: 15px; border-radius: 5px; margin: 20px 0; }
    </style>
</head>
<body>
    <h1>Chrome Policy Assessment Report</h1>
    <p>Generated on: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    
    <div class="summary-box">
        <h2>Executive Summary</h2>
        <ul>
            <li>ADMX Templates: $(if ($ADMXInfo.TemplatesFound) { "<span class='success'>Found (Version $($ADMXInfo.Version))</span>" } else { "<span class='error'>Not Found</span>" })</li>
            <li>Total Policies Configured: $($RegistryPolicies | ForEach-Object { $_.Policies.Values.Count } | Measure-Object -Sum | Select-Object -ExpandProperty Sum)</li>
            <li>Policy Conflicts Found: $($Conflicts.Count)</li>
            <li>High Priority Recommendations: $($Recommendations.HighPriority.Count)</li>
            <li>Computers Assessed: $($ComputerName -join ', ')</li>
        </ul>
    </div>
    
    <h2>1. ADMX Template Status</h2>
    <table>
        <tr><th>Component</th><th>Status</th><th>Details</th></tr>
        <tr>
            <td>Chrome ADMX Template</td>
            <td>$(if ($ADMXInfo.TemplatesFound) { "<span class='success'>Installed</span>" } else { "<span class='error'>Missing</span>" })</td>
            <td>Version: $($ADMXInfo.Version)</td>
        </tr>
        <tr>
            <td>Template Files</td>
            <td colspan="2">$($ADMXInfo.Files -join '<br/>')</td>
        </tr>
        $(if ($ADMXInfo.Issues.Count -gt 0) {
            "<tr class='warning'><td>Issues</td><td colspan='2'>$($ADMXInfo.Issues -join '<br/>')</td></tr>"
        })
    </table>
    
    <h2>2. Current Chrome Policies</h2>
    <h3>Security Settings</h3>
    <table>
        <tr><th>Policy</th><th>Value</th><th>Description</th><th>Teenager Relevant</th></tr>
        $(foreach ($policy in $CurrentSettings.SecuritySettings.Keys) {
            $setting = $CurrentSettings.SecuritySettings[$policy]
            "<tr><td>$policy</td><td>$($setting.Value)</td><td>$($setting.Description)</td><td>$(if ($setting.TeenagerRelevant) { 'Yes' } else { 'No' })</td></tr>"
        })
    </table>
    
    <h3>Privacy Settings</h3>
    <table>
        <tr><th>Policy</th><th>Value</th><th>Description</th><th>Teenager Relevant</th></tr>
        $(foreach ($policy in $CurrentSettings.PrivacySettings.Keys) {
            $setting = $CurrentSettings.PrivacySettings[$policy]
            "<tr><td>$policy</td><td>$($setting.Value)</td><td>$($setting.Description)</td><td>$(if ($setting.TeenagerRelevant) { 'Yes' } else { 'No' })</td></tr>"
        })
    </table>
    
    <h3>URL Filtering</h3>
    <table>
        <tr><th>Setting</th><th>Value</th></tr>
        <tr><td>Blocked URLs</td><td>$(if ($URLFiltering.Blocklist.Count -gt 0) { $URLFiltering.Blocklist -join '<br/>' } else { 'None' })</td></tr>
        <tr><td>Allowed URLs</td><td>$(if ($URLFiltering.Allowlist.Count -gt 0) { $URLFiltering.Allowlist -join '<br/>' } else { 'None' })</td></tr>
        <tr><td>Safe Search Enforced</td><td>$(if ($URLFiltering.SafeSearchEnforced) { "<span class='success'>Yes</span>" } else { "<span class='warning'>No</span>" })</td></tr>
        <tr><td>YouTube Restricted</td><td>$(if ($URLFiltering.YouTubeRestricted) { "<span class='success'>Yes</span>" } else { "<span class='warning'>No</span>" })</td></tr>
    </table>
    
    <h3>Extension Policies</h3>
    <table>
        <tr><th>Policy Type</th><th>Extensions</th></tr>
        <tr><td>Blocked Extensions</td><td>$(if ($ExtensionPolicies.Blocklist.Count -gt 0) { $ExtensionPolicies.Blocklist -join '<br/>' } else { 'None' })</td></tr>
        <tr><td>Allowed Extensions</td><td>$(if ($ExtensionPolicies.Allowlist.Count -gt 0) { $ExtensionPolicies.Allowlist -join '<br/>' } else { 'None' })</td></tr>
        <tr><td>Forced Extensions</td><td>$(if ($ExtensionPolicies.Forcelist.Count -gt 0) { $ExtensionPolicies.Forcelist -join '<br/>' } else { 'None' })</td></tr>
    </table>
    
    <h2>3. Policy Conflicts</h2>
    $(if ($Conflicts.Count -gt 0) {
        foreach ($conflict in $Conflicts) {
            @"
            <div class='conflict'>
                <h4>Conflict: $($conflict.PolicyKey)</h4>
                <p><strong>Description:</strong> $($conflict.Description)</p>
                <p><strong>Severity:</strong> <span class='error'>$($conflict.Severity)</span></p>
                <p><strong>Conflicting GPOs:</strong></p>
                <ul>
                $(foreach ($gpo in $conflict.ConflictingGPOs) {
                    "<li>$($gpo.GPO) - Value: $($gpo.Data)</li>"
                })
                </ul>
            </div>
"@
        }
    } else {
        "<p class='success'>No policy conflicts detected</p>"
    })
    
    <h2>4. Policy Application Status</h2>
    <table>
        <tr><th>Computer</th><th>Chrome Installed</th><th>Policies Applied</th><th>Last Update</th><th>Issues</th></tr>
        $(foreach ($test in $ApplicationTests) {
            @"
            <tr>
                <td>$($test.ComputerName)</td>
                <td>$(if ($test.ChromeInstalled) { "<span class='success'>Yes</span>" } else { "<span class='error'>No</span>" })</td>
                <td>$($test.PoliciesApplied.Count)</td>
                <td>$($test.LastPolicyUpdate)</td>
                <td>$(if ($test.Issues.Count -gt 0) { $test.Issues -join '<br/>' } else { 'None' })</td>
            </tr>
"@
        })
    </table>
    
    <h2>5. Browser Policy Comparison</h2>
    <table>
        <tr><th>Policy Type</th><th>Chrome</th><th>Edge</th><th>Firefox</th><th>Consistency</th></tr>
        $(foreach ($inconsistency in $BrowserComparison.Inconsistencies) {
            @"
            <tr>
                <td>$($inconsistency.Policy)</td>
                <td>$($inconsistency.Chrome)</td>
                <td>$($inconsistency.Edge)</td>
                <td>$($inconsistency.Firefox)</td>
                <td><span class='warning'>$($inconsistency.Issue)</span></td>
            </tr>
"@
        })
    </table>
    
    <h2>6. Teenager Policy Recommendations</h2>
    
    <h3 class='high'>High Priority</h3>
    $(foreach ($rec in $Recommendations.HighPriority) {
        @"
        <div class='recommendation'>
            <h4>$($rec.Policy)</h4>
            <p><strong>Current Value:</strong> $($rec.CurrentValue)</p>
            <p><strong>Recommended Value:</strong> $($rec.RecommendedValue)</p>
            <p><strong>Reason:</strong> $($rec.Reason)</p>
            <p><strong>Implementation:</strong> <code>$($rec.Implementation)</code></p>
        </div>
"@
    })
    
    <h3 class='medium'>Medium Priority</h3>
    $(foreach ($rec in $Recommendations.MediumPriority) {
        @"
        <div class='recommendation'>
            <h4>$($rec.Policy)</h4>
            <p><strong>Current Value:</strong> $(if ($rec.CurrentValue -is [array]) { $rec.CurrentValue -join ', ' } else { $rec.CurrentValue })</p>
            <p><strong>Recommended Value:</strong> $(if ($rec.RecommendedValue -is [array]) { $rec.RecommendedValue -join ', ' } else { $rec.RecommendedValue })</p>
            <p><strong>Reason:</strong> $($rec.Reason)</p>
            <p><strong>Implementation:</strong> <code>$($rec.Implementation)</code></p>
        </div>
"@
    })
    
    <h3 class='low'>Low Priority</h3>
    $(foreach ($rec in $Recommendations.LowPriority) {
        @"
        <div class='recommendation'>
            <h4>$($rec.Policy)</h4>
            <p><strong>Current Value:</strong> $($rec.CurrentValue)</p>
            <p><strong>Recommended Value:</strong> $($rec.RecommendedValue)</p>
            <p><strong>Reason:</strong> $($rec.Reason)</p>
            <p><strong>Implementation:</strong> <code>$($rec.Implementation)</code></p>
        </div>
"@
    })
    
    <h2>7. Implementation Script</h2>
    <div class='recommendation'>
        <h4>PowerShell Script for Teenager Chrome Policies</h4>
        <pre><code>
# Create Chrome policy registry keys for teenager restrictions
\$chromePolicyPath = 'HKLM:\SOFTWARE\Policies\Google\Chrome'

# Ensure Chrome policy path exists
if (!(Test-Path \$chromePolicyPath)) {
    New-Item -Path \$chromePolicyPath -Force
}

# Disable incognito mode
try {
    Set-ItemProperty -Path \$chromePolicyPath -Name 'IncognitoModeAvailability' -Value 1 -Type DWord
} catch {
    Write-Error "Failed to set IncognitoModeAvailability: \$_"
}

# Force safe search
try {
    Set-ItemProperty -Path \$chromePolicyPath -Name 'ForceGoogleSafeSearch' -Value 1 -Type DWord
    Set-ItemProperty -Path \$chromePolicyPath -Name 'SafeBrowsingEnabled' -Value 1 -Type DWord
} catch {
    Write-Error "Failed to set safe search settings: \$_"
}

# Force YouTube restricted mode
try {
    Set-ItemProperty -Path \$chromePolicyPath -Name 'ForceYouTubeRestrict' -Value 2 -Type DWord
} catch {
    Write-Error "Failed to set YouTube restrict mode: \$_"
}

# Block developer tools
try {
    Set-ItemProperty -Path \$chromePolicyPath -Name 'DeveloperToolsAvailability' -Value 2 -Type DWord
} catch {
    Write-Error "Failed to set DeveloperToolsAvailability: \$_"
}

# Configure URL blocklist
\$urlBlocklistPath = '\$chromePolicyPath\URLBlocklist'
if (!(Test-Path \$urlBlocklistPath)) {
    New-Item -Path \$urlBlocklistPath -Force
}
# Add blocked URLs (example)
try {
    Set-ItemProperty -Path \$urlBlocklistPath -Name '1' -Value '*://example-adult-site.com/*' -Type String
} catch {
    Write-Error "Failed to set URL blocklist: \$_"
}

# Configure extension blocklist (block all by default)
\$extensionBlocklistPath = '\$chromePolicyPath\ExtensionInstallBlocklist'
if (!(Test-Path \$extensionBlocklistPath)) {
    New-Item -Path \$extensionBlocklistPath -Force
}
try {
    Set-ItemProperty -Path \$extensionBlocklistPath -Name '1' -Value '*' -Type String
} catch {
    Write-Error "Failed to set extension blocklist: \$_"
}

# Force update group policies
gpupdate /force
        </code></pre>
    </div>
    
    <h2>8. Next Steps</h2>
    <ol>
        <li>Review and approve recommended policies</li>
        <li>Test policies in a pilot group before widespread deployment</li>
        <li>Create a dedicated "Teenager Chrome Restrictions" GPO</li>
        <li>Link GPO to appropriate OUs containing teenager accounts</li>
        <li>Monitor policy application and effectiveness</li>
        <li>Consider implementing similar policies for Edge and Firefox</li>
    </ol>
    
    <hr/>
    <p><em>Report generated by Chrome Policy Assessment Tool v1.0</em></p>
</body>
</html>
"@
    
    # Save HTML report
    $htmlPath = Join-Path $script:ReportPath "ChromePolicyReport.html"
    $html | Out-File -FilePath $htmlPath -Encoding UTF8
    
    # Create JSON export
    $jsonExport = @{
        ReportDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        ADMXStatus = $ADMXInfo
        CurrentPolicies = $RegistryPolicies
        Conflicts = $Conflicts
        ApplicationStatus = $ApplicationTests
        Settings = $CurrentSettings
        ExtensionPolicies = $ExtensionPolicies
        UpdatePolicies = $UpdatePolicies
        URLFiltering = $URLFiltering
        BrowserComparison = $BrowserComparison
        Recommendations = $Recommendations
    }
    
    $jsonPath = Join-Path $script:ReportPath "ChromePolicyData.json"
    $jsonExport | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
    
    # Create CSV summary
    $csvData = @()
    foreach ($rec in $Recommendations.HighPriority) {
        $csvData += [PSCustomObject]@{
            Priority = 'High'
            Policy = $rec.Policy
            CurrentValue = $rec.CurrentValue
            RecommendedValue = $rec.RecommendedValue
            Reason = $rec.Reason
        }
    }
    foreach ($rec in $Recommendations.MediumPriority) {
        $csvData += [PSCustomObject]@{
            Priority = 'Medium'
            Policy = $rec.Policy
            CurrentValue = if ($rec.CurrentValue -is [array]) { $rec.CurrentValue -join '; ' } else { $rec.CurrentValue }
            RecommendedValue = if ($rec.RecommendedValue -is [array]) { $rec.RecommendedValue -join '; ' } else { $rec.RecommendedValue }
            Reason = $rec.Reason
        }
    }
    
    $csvPath = Join-Path $script:ReportPath "ChromePolicyRecommendations.csv"
    $csvData | Export-Csv -Path $csvPath -NoTypeInformation
    
    Write-Host "`nReports saved to: $script:ReportPath" -ForegroundColor Green
    Write-Host "  - HTML Report: ChromePolicyReport.html" -ForegroundColor Cyan
    Write-Host "  - JSON Data: ChromePolicyData.json" -ForegroundColor Cyan
    Write-Host "  - CSV Summary: ChromePolicyRecommendations.csv" -ForegroundColor Cyan
}

# Main execution
try {
    Initialize-Script
    
    Write-Host "`n=== Chrome Policy Assessment ===" -ForegroundColor Cyan
    Write-Host "Starting comprehensive Chrome policy check..." -ForegroundColor Yellow
    
    # 1. Check ADMX templates
    Write-Host "`n[1/10] Checking Chrome ADMX templates..." -ForegroundColor Yellow
    $admxInfo = Test-ChromeADMXTemplates
    
    # 2. Check registry policies
    Write-Host "[2/10] Checking Chrome registry policies..." -ForegroundColor Yellow
    $registryPolicies = Get-ChromeRegistryPolicies
    
    # 3. Find conflicts
    Write-Host "[3/10] Identifying policy conflicts..." -ForegroundColor Yellow
    $conflicts = Find-ChromePolicyConflicts
    
    # 4. Test application
    Write-Host "[4/10] Testing policy application..." -ForegroundColor Yellow
    $applicationTests = Test-ChromePolicyApplication
    
    # 5. Document settings
    Write-Host "[5/10] Documenting current settings..." -ForegroundColor Yellow
    $currentSettings = Get-ChromeSettingsDocumentation
    
    # 6. Check extensions
    Write-Host "[6/10] Checking extension policies..." -ForegroundColor Yellow
    $extensionPolicies = Get-ChromeExtensionPolicies
    
    # 7. Check updates
    Write-Host "[7/10] Verifying update policies..." -ForegroundColor Yellow
    $updatePolicies = Get-ChromeUpdatePolicies
    
    # 8. Check URL filtering
    Write-Host "[8/10] Checking URL filtering..." -ForegroundColor Yellow
    $urlFiltering = Get-ChromeURLFiltering
    
    # 9. Compare browsers
    Write-Host "[9/10] Comparing with other browsers..." -ForegroundColor Yellow
    $browserComparison = Compare-BrowserPolicies
    
    # 10. Generate recommendations
    Write-Host "[10/10] Generating recommendations..." -ForegroundColor Yellow
    $recommendations = Get-TeenagerPolicyRecommendations
    
    # Generate report
    Export-ChromePolicyReport -ADMXInfo $admxInfo `
                             -RegistryPolicies $registryPolicies `
                             -Conflicts $conflicts `
                             -ApplicationTests $applicationTests `
                             -CurrentSettings $currentSettings `
                             -ExtensionPolicies $extensionPolicies `
                             -UpdatePolicies $updatePolicies `
                             -URLFiltering $urlFiltering `
                             -BrowserComparison $browserComparison `
                             -Recommendations $recommendations
    
    # Display summary
    Write-Host "`n=== Assessment Summary ===" -ForegroundColor Green
    Write-Host "ADMX Templates: $(if ($admxInfo.TemplatesFound) { 'Found' } else { 'Missing' })" -ForegroundColor $(if ($admxInfo.TemplatesFound) { 'Green' } else { 'Red' })
    Write-Host "Policy Conflicts: $($conflicts.Count)" -ForegroundColor $(if ($conflicts.Count -eq 0) { 'Green' } else { 'Yellow' })
    Write-Host "High Priority Recommendations: $($recommendations.HighPriority.Count)" -ForegroundColor $(if ($recommendations.HighPriority.Count -eq 0) { 'Green' } else { 'Yellow' })
    
    if ($recommendations.HighPriority.Count -gt 0) {
        Write-Host "`nTop Recommendations for Teenager Policy:" -ForegroundColor Yellow
        foreach ($rec in $recommendations.HighPriority[0..2]) {
            Write-Host "  - $($rec.Policy): $($rec.Reason)" -ForegroundColor Cyan
        }
    }
    
    Write-Host "`nAssessment completed successfully!" -ForegroundColor Green
}
catch {
    Write-Error "Chrome policy assessment failed: $_"
    exit 1
}