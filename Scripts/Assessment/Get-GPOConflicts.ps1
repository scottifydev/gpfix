<#
.SYNOPSIS
    Detects conflicts between Group Policy Objects in the domain.

.DESCRIPTION
    This script analyzes Group Policy Objects to identify conflicts in various policy areas including:
    - AppLocker policies
    - Browser policies (Chrome/Edge)
    - Security settings
    - WMI filters
    - GPO precedence and inheritance
    - Registry settings
    - Software installation policies
    - User rights assignments
    - Script execution policies

.PARAMETER DomainController
    Specifies the domain controller to query. If not specified, uses the current domain controller.

.PARAMETER OutputPath
    Path where the conflict report will be saved. Defaults to current directory.

.PARAMETER IncludeDisabledGPOs
    Include disabled GPOs in the conflict analysis.

.PARAMETER ExportFormat
    Export format for the report (HTML, CSV, JSON). Defaults to HTML.

.EXAMPLE
    .\Find-GPOConflicts.ps1
    Runs conflict detection with default parameters.

.EXAMPLE
    .\Find-GPOConflicts.ps1 -OutputPath "C:\Reports" -ExportFormat "HTML,CSV"
    Generates both HTML and CSV reports in the specified directory.

.NOTES
    Author: Group Policy Assessment Tool
    Version: 1.0
    Requires: Active Directory PowerShell module, Group Policy module
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$DomainController,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".",
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeDisabledGPOs,
    
    [Parameter(Mandatory=$false)]
    [string[]]$ExportFormat = @("HTML")
)

#region Functions

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Level = "Info"
    )
    
    switch ($Level) {
        "Critical" { Write-Host $Message -ForegroundColor Red }
        "Warning" { Write-Host $Message -ForegroundColor Yellow }
        "Success" { Write-Host $Message -ForegroundColor Green }
        "Info" { Write-Host $Message -ForegroundColor Cyan }
        default { Write-Host $Message }
    }
}

function Get-GPOSettings {
    param(
        [Parameter(Mandatory=$true)]
        [Microsoft.GroupPolicy.Gpo]$GPO
    )
    
    try {
        $settings = @{
            GPOName = $GPO.DisplayName
            GPOId = $GPO.Id
            GPOStatus = $GPO.GpoStatus
            Created = $GPO.CreationTime
            Modified = $GPO.ModificationTime
            ComputerEnabled = $GPO.Computer.Enabled
            UserEnabled = $GPO.User.Enabled
            WMIFilter = $GPO.WmiFilter
            Links = @()
            Settings = @{}
        }
        
        # Get GPO links
        $links = Get-GPOReport -Guid $GPO.Id -ReportType Xml
        $xmlReport = [xml]$links
        
        # Extract various settings
        $settings.Settings = Extract-GPOSettings -XmlReport $xmlReport
        
        # Get linked OUs
        $settings.Links = Get-GPOLinks -GPO $GPO
        
        return $settings
    }
    catch {
        Write-ColorOutput "Error processing GPO '$($GPO.DisplayName)': $_" -Level "Warning"
        return $null
    }
}

function Extract-GPOSettings {
    param(
        [xml]$XmlReport
    )
    
    $extractedSettings = @{
        AppLocker = @()
        BrowserPolicies = @()
        SecuritySettings = @()
        RegistrySettings = @()
        SoftwareInstallation = @()
        UserRightsAssignment = @()
        ScriptExecutionPolicies = @()
        WMIFilters = @()
    }
    
    # Extract AppLocker policies
    $appLockerPath = "//q1:AppLockerPolicy"
    $appLockerNodes = $XmlReport.SelectNodes($appLockerPath, (Get-XmlNamespaceManager $XmlReport))
    foreach ($node in $appLockerNodes) {
        $extractedSettings.AppLocker += @{
            RuleType = $node.RuleType
            Action = $node.Action
            Conditions = $node.Conditions
        }
    }
    
    # Extract Browser policies (Chrome/Edge)
    $browserPaths = @(
        "//q1:Extension[@q1:type='q1:ChromeSettings']",
        "//q1:Extension[@q1:type='q1:EdgeSettings']",
        "//q1:Policy[contains(@q1:name, 'Chrome') or contains(@q1:name, 'Edge')]"
    )
    
    foreach ($path in $browserPaths) {
        $browserNodes = $XmlReport.SelectNodes($path, (Get-XmlNamespaceManager $XmlReport))
        foreach ($node in $browserNodes) {
            $extractedSettings.BrowserPolicies += @{
                PolicyName = $node.name
                PolicyValue = $node.InnerText
                PolicyType = $node.type
            }
        }
    }
    
    # Extract Security Settings
    $securityPaths = @(
        "//q1:SecurityOptions",
        "//q1:SystemServices",
        "//q1:RestrictedGroups",
        "//q1:FileSystem",
        "//q1:Registry"
    )
    
    foreach ($path in $securityPaths) {
        $securityNodes = $XmlReport.SelectNodes($path, (Get-XmlNamespaceManager $XmlReport))
        foreach ($node in $securityNodes) {
            $extractedSettings.SecuritySettings += @{
                SettingType = $node.LocalName
                SettingName = $node.name
                SettingValue = $node.InnerText
            }
        }
    }
    
    # Extract Registry Settings
    $regPath = "//q1:RegistrySettings/q1:Registry"
    $regNodes = $XmlReport.SelectNodes($regPath, (Get-XmlNamespaceManager $XmlReport))
    foreach ($node in $regNodes) {
        $extractedSettings.RegistrySettings += @{
            KeyPath = $node.Properties.key
            ValueName = $node.Properties.name
            Value = $node.Properties.value
            Type = $node.Properties.type
            Action = $node.Properties.action
        }
    }
    
    # Extract Software Installation policies
    $softwarePath = "//q1:SoftwareInstallation"
    $softwareNodes = $XmlReport.SelectNodes($softwarePath, (Get-XmlNamespaceManager $XmlReport))
    foreach ($node in $softwareNodes) {
        $extractedSettings.SoftwareInstallation += @{
            PackageName = $node.Name
            PackagePath = $node.Path
            DeploymentType = $node.DeploymentType
            InstallationType = $node.InstallationType
        }
    }
    
    # Extract User Rights Assignment
    $userRightsPath = "//q1:UserRightsAssignment"
    $userRightsNodes = $XmlReport.SelectNodes($userRightsPath, (Get-XmlNamespaceManager $XmlReport))
    foreach ($node in $userRightsNodes) {
        $extractedSettings.UserRightsAssignment += @{
            Right = $node.Name
            Members = $node.Member
        }
    }
    
    # Extract Script Execution Policies
    $scriptPaths = @(
        "//q1:Scripts",
        "//q1:PowerShellExecutionPolicy"
    )
    
    foreach ($path in $scriptPaths) {
        $scriptNodes = $XmlReport.SelectNodes($path, (Get-XmlNamespaceManager $XmlReport))
        foreach ($node in $scriptNodes) {
            $extractedSettings.ScriptExecutionPolicies += @{
                ScriptType = $node.Type
                ScriptPath = $node.Path
                Parameters = $node.Parameters
                ExecutionPolicy = $node.ExecutionPolicy
            }
        }
    }
    
    return $extractedSettings
}

function Get-XmlNamespaceManager {
    param([xml]$XmlDocument)
    
    $nsmgr = New-Object System.Xml.XmlNamespaceManager($XmlDocument.NameTable)
    $nsmgr.AddNamespace("q1", $XmlDocument.DocumentElement.NamespaceURI)
    return $nsmgr
}

function Get-GPOLinks {
    param(
        [Microsoft.GroupPolicy.Gpo]$GPO
    )
    
    $links = @()
    try {
        $domain = Get-ADDomain
        $searchBase = $domain.DistinguishedName
        
        # Search for OUs and domains that have this GPO linked
        $linkedOUs = Get-ADOrganizationalUnit -Filter * -SearchBase $searchBase -Properties gpLink | 
            Where-Object { $_.gpLink -like "*$($GPO.Id)*" }
        
        foreach ($ou in $linkedOUs) {
            $links += @{
                OU = $ou.DistinguishedName
                OUName = $ou.Name
                LinkEnabled = $true  # Would need to parse gpLink to get actual status
            }
        }
        
        # Check domain root
        $domainRoot = Get-ADObject -Identity $searchBase -Properties gpLink
        if ($domainRoot.gpLink -like "*$($GPO.Id)*") {
            $links += @{
                OU = $searchBase
                OUName = "GP_Domain Root"
                LinkEnabled = $true
            }
        }
    }
    catch {
        Write-ColorOutput "Error getting GPO links: $_" -Level "Warning"
    }
    
    return $links
}

function Find-AppLockerConflicts {
    param(
        [array]$GPOSettingsList
    )
    
    $conflicts = @()
    $appLockerPolicies = @{}
    
    # Group AppLocker policies by type and rule
    foreach ($gpoSettings in $GPOSettingsList) {
        if ($gpoSettings.Settings.AppLocker.Count -gt 0) {
            foreach ($policy in $gpoSettings.Settings.AppLocker) {
                $key = "$($policy.RuleType)-$($policy.Conditions)"
                if (-not $appLockerPolicies.ContainsKey($key)) {
                    $appLockerPolicies[$key] = @()
                }
                $appLockerPolicies[$key] += @{
                    GPO = $gpoSettings
                    Policy = $policy
                }
            }
        }
    }
    
    # Find conflicts
    foreach ($key in $appLockerPolicies.Keys) {
        if ($appLockerPolicies[$key].Count -gt 1) {
            $conflictingGPOs = $appLockerPolicies[$key] | ForEach-Object { $_.GPO.GPOName }
            $conflicts += @{
                Type = "AppLocker"
                Severity = "Warning"
                Description = "Conflicting AppLocker rules for $key"
                AffectedGPOs = $conflictingGPOs
                Details = $appLockerPolicies[$key]
                Remediation = "Review and consolidate AppLocker rules across GPOs. Consider using a single GPO for AppLocker policies."
            }
        }
    }
    
    return $conflicts
}

function Find-BrowserPolicyConflicts {
    param(
        [array]$GPOSettingsList
    )
    
    $conflicts = @()
    $browserPolicies = @{}
    
    # Group browser policies by name
    foreach ($gpoSettings in $GPOSettingsList) {
        if ($gpoSettings.Settings.BrowserPolicies.Count -gt 0) {
            foreach ($policy in $gpoSettings.Settings.BrowserPolicies) {
                $key = $policy.PolicyName
                if (-not $browserPolicies.ContainsKey($key)) {
                    $browserPolicies[$key] = @()
                }
                $browserPolicies[$key] += @{
                    GPO = $gpoSettings
                    Policy = $policy
                }
            }
        }
    }
    
    # Find conflicts
    foreach ($key in $browserPolicies.Keys) {
        if ($browserPolicies[$key].Count -gt 1) {
            # Check if values differ
            $values = $browserPolicies[$key] | ForEach-Object { $_.Policy.PolicyValue } | Select-Object -Unique
            if ($values.Count -gt 1) {
                $conflictingGPOs = $browserPolicies[$key] | ForEach-Object { $_.GPO.GPOName }
                $conflicts += @{
                    Type = "BrowserPolicy"
                    Severity = "Warning"
                    Description = "Conflicting browser policy '$key' with different values"
                    AffectedGPOs = $conflictingGPOs
                    Details = $browserPolicies[$key]
                    Remediation = "Standardize browser policy settings across GPOs. Consider using a dedicated browser configuration GPO."
                }
            }
        }
    }
    
    return $conflicts
}

function Find-SecuritySettingConflicts {
    param(
        [array]$GPOSettingsList
    )
    
    $conflicts = @()
    $securitySettings = @{}
    
    # Group security settings by type and name
    foreach ($gpoSettings in $GPOSettingsList) {
        if ($gpoSettings.Settings.SecuritySettings.Count -gt 0) {
            foreach ($setting in $gpoSettings.Settings.SecuritySettings) {
                $key = "$($setting.SettingType)-$($setting.SettingName)"
                if (-not $securitySettings.ContainsKey($key)) {
                    $securitySettings[$key] = @()
                }
                $securitySettings[$key] += @{
                    GPO = $gpoSettings
                    Setting = $setting
                }
            }
        }
    }
    
    # Find conflicts
    foreach ($key in $securitySettings.Keys) {
        if ($securitySettings[$key].Count -gt 1) {
            $values = $securitySettings[$key] | ForEach-Object { $_.Setting.SettingValue } | Select-Object -Unique
            if ($values.Count -gt 1) {
                $conflictingGPOs = $securitySettings[$key] | ForEach-Object { $_.GPO.GPOName }
                $severity = if ($key -match "Password|Audit|Encryption") { "Critical" } else { "Warning" }
                
                $conflicts += @{
                    Type = "SecuritySetting"
                    Severity = $severity
                    Description = "Conflicting security setting: $key"
                    AffectedGPOs = $conflictingGPOs
                    Details = $securitySettings[$key]
                    Remediation = "Review security settings and ensure consistency. Critical security settings should be managed by a single authoritative GPO."
                }
            }
        }
    }
    
    return $conflicts
}

function Find-WMIFilterConflicts {
    param(
        [array]$GPOSettingsList
    )
    
    $conflicts = @()
    $wmiFilters = @{}
    
    # Check for GPOs with WMI filters
    foreach ($gpoSettings in $GPOSettingsList) {
        if ($gpoSettings.WMIFilter) {
            # Check if WMI filter is valid
            try {
                $filter = Get-ADObject -Identity $gpoSettings.WMIFilter -Properties msWMI-Parm2
                $wmiQuery = $filter.'msWMI-Parm2'
                
                # Test WMI query
                $testResult = Get-WmiObject -Query $wmiQuery -ErrorAction Stop
            }
            catch {
                $conflicts += @{
                    Type = "WMIFilter"
                    Severity = "Critical"
                    Description = "Invalid or failing WMI filter"
                    AffectedGPOs = @($gpoSettings.GPOName)
                    Details = @{
                        FilterName = $gpoSettings.WMIFilter
                        Error = $_.Exception.Message
                    }
                    Remediation = "Fix or remove the invalid WMI filter. Test WMI queries before applying to GPOs."
                }
            }
        }
    }
    
    return $conflicts
}

function Find-GPOPrecedenceConflicts {
    param(
        [array]$GPOSettingsList
    )
    
    $conflicts = @()
    $ouGPOMap = @{}
    
    # Map GPOs to their linked OUs
    foreach ($gpoSettings in $GPOSettingsList) {
        foreach ($link in $gpoSettings.Links) {
            if (-not $ouGPOMap.ContainsKey($link.OU)) {
                $ouGPOMap[$link.OU] = @()
            }
            $ouGPOMap[$link.OU] += $gpoSettings
        }
    }
    
    # Check for multiple GPOs linked to same OU with potential conflicts
    foreach ($ou in $ouGPOMap.Keys) {
        if ($ouGPOMap[$ou].Count -gt 1) {
            # Check for overlapping settings
            $settingOverlaps = @{}
            
            foreach ($gpo in $ouGPOMap[$ou]) {
                foreach ($settingType in $gpo.Settings.Keys) {
                    if ($gpo.Settings[$settingType].Count -gt 0) {
                        if (-not $settingOverlaps.ContainsKey($settingType)) {
                            $settingOverlaps[$settingType] = @()
                        }
                        $settingOverlaps[$settingType] += $gpo.GPOName
                    }
                }
            }
            
            foreach ($settingType in $settingOverlaps.Keys) {
                if ($settingOverlaps[$settingType].Count -gt 1) {
                    $conflicts += @{
                        Type = "GPOPrecedence"
                        Severity = "Warning"
                        Description = "Multiple GPOs with $settingType settings linked to same OU"
                        AffectedGPOs = $settingOverlaps[$settingType]
                        Details = @{
                            OU = $ou
                            SettingType = $settingType
                        }
                        Remediation = "Review GPO link order and ensure proper precedence. Consider consolidating overlapping settings."
                    }
                }
            }
        }
    }
    
    return $conflicts
}

function Find-RegistrySettingConflicts {
    param(
        [array]$GPOSettingsList
    )
    
    $conflicts = @()
    $registrySettings = @{}
    
    # Group registry settings by key path and value name
    foreach ($gpoSettings in $GPOSettingsList) {
        if ($gpoSettings.Settings.RegistrySettings.Count -gt 0) {
            foreach ($setting in $gpoSettings.Settings.RegistrySettings) {
                $key = "$($setting.KeyPath)\$($setting.ValueName)"
                if (-not $registrySettings.ContainsKey($key)) {
                    $registrySettings[$key] = @()
                }
                $registrySettings[$key] += @{
                    GPO = $gpoSettings
                    Setting = $setting
                }
            }
        }
    }
    
    # Find conflicts
    foreach ($key in $registrySettings.Keys) {
        if ($registrySettings[$key].Count -gt 1) {
            $values = $registrySettings[$key] | ForEach-Object { $_.Setting.Value } | Select-Object -Unique
            if ($values.Count -gt 1) {
                $conflictingGPOs = $registrySettings[$key] | ForEach-Object { $_.GPO.GPOName }
                $conflicts += @{
                    Type = "RegistrySetting"
                    Severity = "Warning"
                    Description = "Conflicting registry setting: $key"
                    AffectedGPOs = $conflictingGPOs
                    Details = $registrySettings[$key]
                    Remediation = "Consolidate registry settings to avoid conflicts. The last applied GPO will win."
                }
            }
        }
    }
    
    return $conflicts
}

function Find-SoftwareInstallationConflicts {
    param(
        [array]$GPOSettingsList
    )
    
    $conflicts = @()
    $softwarePackages = @{}
    
    # Group software packages by name
    foreach ($gpoSettings in $GPOSettingsList) {
        if ($gpoSettings.Settings.SoftwareInstallation.Count -gt 0) {
            foreach ($package in $gpoSettings.Settings.SoftwareInstallation) {
                $key = $package.PackageName
                if (-not $softwarePackages.ContainsKey($key)) {
                    $softwarePackages[$key] = @()
                }
                $softwarePackages[$key] += @{
                    GPO = $gpoSettings
                    Package = $package
                }
            }
        }
    }
    
    # Find conflicts
    foreach ($key in $softwarePackages.Keys) {
        if ($softwarePackages[$key].Count -gt 1) {
            # Check for different package paths or deployment types
            $paths = $softwarePackages[$key] | ForEach-Object { $_.Package.PackagePath } | Select-Object -Unique
            $deployTypes = $softwarePackages[$key] | ForEach-Object { $_.Package.DeploymentType } | Select-Object -Unique
            
            if ($paths.Count -gt 1 -or $deployTypes.Count -gt 1) {
                $conflictingGPOs = $softwarePackages[$key] | ForEach-Object { $_.GPO.GPOName }
                $conflicts += @{
                    Type = "SoftwareInstallation"
                    Severity = "Critical"
                    Description = "Conflicting software installation for package: $key"
                    AffectedGPOs = $conflictingGPOs
                    Details = $softwarePackages[$key]
                    Remediation = "Use a single GPO for each software package deployment. Remove duplicate deployments."
                }
            }
        }
    }
    
    return $conflicts
}

function Find-UserRightsConflicts {
    param(
        [array]$GPOSettingsList
    )
    
    $conflicts = @()
    $userRights = @{}
    
    # Group user rights by right name
    foreach ($gpoSettings in $GPOSettingsList) {
        if ($gpoSettings.Settings.UserRightsAssignment.Count -gt 0) {
            foreach ($right in $gpoSettings.Settings.UserRightsAssignment) {
                $key = $right.Right
                if (-not $userRights.ContainsKey($key)) {
                    $userRights[$key] = @()
                }
                $userRights[$key] += @{
                    GPO = $gpoSettings
                    Right = $right
                }
            }
        }
    }
    
    # Find conflicts
    foreach ($key in $userRights.Keys) {
        if ($userRights[$key].Count -gt 1) {
            $conflictingGPOs = $userRights[$key] | ForEach-Object { $_.GPO.GPOName }
            $severity = if ($key -match "Logon|Admin|Backup|Security") { "Critical" } else { "Warning" }
            
            $conflicts += @{
                Type = "UserRights"
                Severity = $severity
                Description = "Conflicting user rights assignment: $key"
                AffectedGPOs = $conflictingGPOs
                Details = $userRights[$key]
                Remediation = "User rights should be managed centrally. Consolidate assignments to avoid security gaps."
            }
        }
    }
    
    return $conflicts
}

function Find-ScriptExecutionConflicts {
    param(
        [array]$GPOSettingsList
    )
    
    $conflicts = @()
    $scriptPolicies = @{}
    
    # Check for conflicting PowerShell execution policies
    foreach ($gpoSettings in $GPOSettingsList) {
        if ($gpoSettings.Settings.ScriptExecutionPolicies.Count -gt 0) {
            foreach ($policy in $gpoSettings.Settings.ScriptExecutionPolicies) {
                if ($policy.ExecutionPolicy) {
                    $key = "PowerShellExecutionPolicy"
                    if (-not $scriptPolicies.ContainsKey($key)) {
                        $scriptPolicies[$key] = @()
                    }
                    $scriptPolicies[$key] += @{
                        GPO = $gpoSettings
                        Policy = $policy
                    }
                }
            }
        }
    }
    
    # Find conflicts
    foreach ($key in $scriptPolicies.Keys) {
        if ($scriptPolicies[$key].Count -gt 1) {
            $policies = $scriptPolicies[$key] | ForEach-Object { $_.Policy.ExecutionPolicy } | Select-Object -Unique
            if ($policies.Count -gt 1) {
                $conflictingGPOs = $scriptPolicies[$key] | ForEach-Object { $_.GPO.GPOName }
                $conflicts += @{
                    Type = "ScriptExecution"
                    Severity = "Warning"
                    Description = "Conflicting PowerShell execution policies"
                    AffectedGPOs = $conflictingGPOs
                    Details = $scriptPolicies[$key]
                    Remediation = "Standardize PowerShell execution policy across the domain. Use the most restrictive policy that meets requirements."
                }
            }
        }
    }
    
    return $conflicts
}

function Generate-ConflictMatrix {
    param(
        [array]$AllConflicts,
        [array]$GPOSettingsList
    )
    
    $matrix = @{}
    $gpoNames = $GPOSettingsList | ForEach-Object { $_.GPOName } | Sort-Object
    
    # Initialize matrix
    foreach ($gpo1 in $gpoNames) {
        $matrix[$gpo1] = @{}
        foreach ($gpo2 in $gpoNames) {
            $matrix[$gpo1][$gpo2] = @{
                ConflictCount = 0
                ConflictTypes = @()
            }
        }
    }
    
    # Populate matrix with conflicts
    foreach ($conflict in $AllConflicts) {
        $affectedGPOs = $conflict.AffectedGPOs
        for ($i = 0; $i -lt $affectedGPOs.Count; $i++) {
            for ($j = $i + 1; $j -lt $affectedGPOs.Count; $j++) {
                $gpo1 = $affectedGPOs[$i]
                $gpo2 = $affectedGPOs[$j]
                
                $matrix[$gpo1][$gpo2].ConflictCount++
                $matrix[$gpo1][$gpo2].ConflictTypes += $conflict.Type
                
                $matrix[$gpo2][$gpo1].ConflictCount++
                $matrix[$gpo2][$gpo1].ConflictTypes += $conflict.Type
            }
        }
    }
    
    return $matrix
}

function Export-ConflictReport {
    param(
        [array]$Conflicts,
        [hashtable]$ConflictMatrix,
        [array]$GPOSettingsList,
        [string]$OutputPath,
        [string[]]$ExportFormat
    )
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportName = "GP_GPO_Conflict_Report_$timestamp"
    
    foreach ($format in $ExportFormat) {
        switch ($format.ToUpper()) {
            "HTML" {
                $htmlReport = Generate-HTMLReport -Conflicts $Conflicts -ConflictMatrix $ConflictMatrix -GPOSettingsList $GPOSettingsList
                $htmlPath = Join-Path $OutputPath "$reportName.html"
                $htmlReport | Out-File -FilePath $htmlPath -Encoding UTF8
                Write-ColorOutput "HTML report saved to: $htmlPath" -Level "Success"
            }
            "CSV" {
                $csvData = $Conflicts | Select-Object Type, Severity, Description, @{N='AffectedGPOs';E={$_.AffectedGPOs -join ';'}}, Remediation
                $csvPath = Join-Path $OutputPath "$reportName.csv"
                $csvData | Export-Csv -Path $csvPath -NoTypeInformation
                Write-ColorOutput "CSV report saved to: $csvPath" -Level "Success"
            }
            "JSON" {
                $jsonData = @{
                    ReportDate = Get-Date
                    TotalConflicts = $Conflicts.Count
                    Conflicts = $Conflicts
                    ConflictMatrix = $ConflictMatrix
                    AnalyzedGPOs = $GPOSettingsList.Count
                }
                $jsonPath = Join-Path $OutputPath "$reportName.json"
                $jsonData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
                Write-ColorOutput "JSON report saved to: $jsonPath" -Level "Success"
            }
        }
    }
}

function Generate-HTMLReport {
    param(
        [array]$Conflicts,
        [hashtable]$ConflictMatrix,
        [array]$GPOSettingsList
    )
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>GPO Conflict Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1, h2, h3 { color: #333; }
        .summary { background: #f0f0f0; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .critical { color: #d9534f; font-weight: bold; }
        .warning { color: #f0ad4e; font-weight: bold; }
        .info { color: #5bc0de; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .conflict-matrix { overflow-x: auto; }
        .matrix-cell { text-align: center; }
        .has-conflict { background-color: #ffcccc; }
        .no-conflict { background-color: #ccffcc; }
        .remediation { background: #e8f4f8; padding: 10px; border-left: 4px solid #5bc0de; margin: 10px 0; }
    </style>
</head>
<body>
    <h1>Group Policy Conflict Analysis Report</h1>
    <p>Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p>Total GPOs Analyzed: $($GPOSettingsList.Count)</p>
        <p>Total Conflicts Found: $($Conflicts.Count)</p>
        <p>Critical Conflicts: $($Conflicts | Where-Object { $_.Severity -eq 'Critical' } | Measure-Object | Select-Object -ExpandProperty Count)</p>
        <p>Warning Conflicts: $($Conflicts | Where-Object { $_.Severity -eq 'Warning' } | Measure-Object | Select-Object -ExpandProperty Count)</p>
    </div>
    
    <h2>Conflict Details</h2>
    <table>
        <tr>
            <th>Type</th>
            <th>Severity</th>
            <th>Description</th>
            <th>Affected GPOs</th>
            <th>Remediation</th>
        </tr>
"@
    
    foreach ($conflict in $Conflicts) {
        $severityClass = switch ($conflict.Severity) {
            "Critical" { "critical" }
            "Warning" { "warning" }
            default { "info" }
        }
        
        $html += @"
        <tr>
            <td>$($conflict.Type)</td>
            <td class="$severityClass">$($conflict.Severity)</td>
            <td>$($conflict.Description)</td>
            <td>$($conflict.AffectedGPOs -join '<br/>')</td>
            <td><div class="remediation">$($conflict.Remediation)</div></td>
        </tr>
"@
    }
    
    $html += @"
    </table>
    
    <h2>Conflict Matrix</h2>
    <p>This matrix shows the number of conflicts between each pair of GPOs.</p>
    <div class="conflict-matrix">
        <table>
            <tr>
                <th>GPO</th>
"@
    
    $gpoNames = $ConflictMatrix.Keys | Sort-Object
    foreach ($gpo in $gpoNames) {
        $html += "<th>$gpo</th>"
    }
    $html += "</tr>"
    
    foreach ($gpo1 in $gpoNames) {
        $html += "<tr><th>$gpo1</th>"
        foreach ($gpo2 in $gpoNames) {
            if ($gpo1 -eq $gpo2) {
                $html += '<td class="matrix-cell">-</td>'
            } else {
                $conflictCount = $ConflictMatrix[$gpo1][$gpo2].ConflictCount
                $cellClass = if ($conflictCount -gt 0) { "has-conflict" } else { "no-conflict" }
                $html += "<td class='matrix-cell $cellClass'>$conflictCount</td>"
            }
        }
        $html += "</tr>"
    }
    
    $html += @"
        </table>
    </div>
    
    <h2>Recommendations</h2>
    <ol>
        <li><strong>Consolidate Policies:</strong> Where possible, consolidate similar policies into dedicated GPOs (e.g., all browser settings in one GPO).</li>
        <li><strong>Review Critical Conflicts:</strong> Address all critical conflicts immediately as they may impact security or functionality.</li>
        <li><strong>Document Policy Decisions:</strong> Maintain documentation explaining why certain policies exist in multiple GPOs.</li>
        <li><strong>Test Changes:</strong> Before making changes, test in a non-production environment.</li>
        <li><strong>Regular Reviews:</strong> Schedule regular GPO conflict reviews to prevent accumulation of issues.</li>
    </ol>
    
</body>
</html>
"@
    
    return $html
}

#endregion

#region Main Script

try {
    Write-ColorOutput "`n===== GPO Conflict Detection Tool =====" -Level "Info"
    Write-ColorOutput "Starting analysis at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level "Info"
    
    # Import required modules
    Write-ColorOutput "`nImporting required modules..." -Level "Info"
    Import-Module ActiveDirectory -ErrorAction Stop
    Import-Module GroupPolicy -ErrorAction Stop
    
    # Set domain controller if specified
    if ($DomainController) {
        $dcParam = @{ Server = $DomainController }
    } else {
        $dcParam = @{}
    }
    
    # Get all GPOs
    Write-ColorOutput "`nRetrieving Group Policy Objects..." -Level "Info"
    if ($IncludeDisabledGPOs) {
        $gpos = Get-GPO -All @dcParam
    } else {
        $gpos = Get-GPO -All @dcParam | Where-Object { $_.GpoStatus -ne 'AllSettingsDisabled' }
    }
    
    Write-ColorOutput "Found $($gpos.Count) GPOs to analyze" -Level "Info"
    
    # Collect GPO settings
    Write-ColorOutput "`nCollecting GPO settings..." -Level "Info"
    $gpoSettingsList = @()
    $progress = 0
    
    foreach ($gpo in $gpos) {
        $progress++
        Write-Progress -Activity "Analyzing GPOs" -Status "Processing $($gpo.DisplayName)" -PercentComplete (($progress / $gpos.Count) * 100)
        
        $gpoSettings = Get-GPOSettings -GPO $gpo
        if ($gpoSettings) {
            $gpoSettingsList += $gpoSettings
        }
    }
    
    Write-Progress -Activity "Analyzing GPOs" -Completed
    
    # Find conflicts
    Write-ColorOutput "`nSearching for conflicts..." -Level "Info"
    $allConflicts = @()
    
    Write-ColorOutput "  - Checking AppLocker conflicts..." -Level "Info"
    $allConflicts += Find-AppLockerConflicts -GPOSettingsList $gpoSettingsList
    
    Write-ColorOutput "  - Checking Browser policy conflicts..." -Level "Info"
    $allConflicts += Find-BrowserPolicyConflicts -GPOSettingsList $gpoSettingsList
    
    Write-ColorOutput "  - Checking Security setting conflicts..." -Level "Info"
    $allConflicts += Find-SecuritySettingConflicts -GPOSettingsList $gpoSettingsList
    
    Write-ColorOutput "  - Checking WMI filter conflicts..." -Level "Info"
    $allConflicts += Find-WMIFilterConflicts -GPOSettingsList $gpoSettingsList
    
    Write-ColorOutput "  - Checking GPO precedence conflicts..." -Level "Info"
    $allConflicts += Find-GPOPrecedenceConflicts -GPOSettingsList $gpoSettingsList
    
    Write-ColorOutput "  - Checking Registry setting conflicts..." -Level "Info"
    $allConflicts += Find-RegistrySettingConflicts -GPOSettingsList $gpoSettingsList
    
    Write-ColorOutput "  - Checking Software installation conflicts..." -Level "Info"
    $allConflicts += Find-SoftwareInstallationConflicts -GPOSettingsList $gpoSettingsList
    
    Write-ColorOutput "  - Checking User rights conflicts..." -Level "Info"
    $allConflicts += Find-UserRightsConflicts -GPOSettingsList $gpoSettingsList
    
    Write-ColorOutput "  - Checking Script execution conflicts..." -Level "Info"
    $allConflicts += Find-ScriptExecutionConflicts -GPOSettingsList $gpoSettingsList
    
    # Generate conflict matrix
    Write-ColorOutput "`nGenerating conflict matrix..." -Level "Info"
    $conflictMatrix = Generate-ConflictMatrix -AllConflicts $allConflicts -GPOSettingsList $gpoSettingsList
    
    # Display summary
    Write-ColorOutput "`n===== Conflict Summary =====" -Level "Info"
    Write-ColorOutput "Total conflicts found: $($allConflicts.Count)" -Level "Info"
    
    $criticalCount = ($allConflicts | Where-Object { $_.Severity -eq 'Critical' }).Count
    $warningCount = ($allConflicts | Where-Object { $_.Severity -eq 'Warning' }).Count
    $infoCount = ($allConflicts | Where-Object { $_.Severity -eq 'Info' }).Count
    
    if ($criticalCount -gt 0) {
        Write-ColorOutput "Critical conflicts: $criticalCount" -Level "Critical"
    }
    if ($warningCount -gt 0) {
        Write-ColorOutput "Warning conflicts: $warningCount" -Level "Warning"
    }
    if ($infoCount -gt 0) {
        Write-ColorOutput "Info conflicts: $infoCount" -Level "Info"
    }
    
    # Export reports
    Write-ColorOutput "`nExporting reports..." -Level "Info"
    Export-ConflictReport -Conflicts $allConflicts -ConflictMatrix $conflictMatrix -GPOSettingsList $gpoSettingsList -OutputPath $OutputPath -ExportFormat $ExportFormat
    
    # Display top conflicts
    if ($allConflicts.Count -gt 0) {
        Write-ColorOutput "`n===== Top Conflicts to Address =====" -Level "Info"
        $topConflicts = $allConflicts | Sort-Object @{E={switch($_.Severity){"Critical"{1}"Warning"{2}"Info"{3}}}} | Select-Object -First 5
        
        foreach ($conflict in $topConflicts) {
            $severity = switch ($conflict.Severity) {
                "Critical" { "Critical" }
                "Warning" { "Warning" }
                default { "Info" }
            }
            Write-ColorOutput "`n$($conflict.Type) - $($conflict.Description)" -Level $severity
            Write-Host "Affected GPOs: $($conflict.AffectedGPOs -join ', ')"
            Write-Host "Remediation: $($conflict.Remediation)"
        }
    } else {
        Write-ColorOutput "`nNo conflicts found!" -Level "Success"
    }
    
    Write-ColorOutput "`n===== Analysis Complete =====" -Level "Success"
    Write-ColorOutput "Reports saved to: $OutputPath" -Level "Info"
}
catch {
    Write-ColorOutput "`nError: $_" -Level "Critical"
    Write-ColorOutput $_.ScriptStackTrace -Level "Critical"
    exit 1
}

#endregion