#Requires -Version 5.1
#Requires -Modules GroupPolicy, ActiveDirectory

<#
.SYNOPSIS
    Finds outdated and legacy Group Policy Objects in the domain.

.DESCRIPTION
    This script identifies various types of legacy and outdated policies including:
    - Software Restriction Policies (deprecated in Windows 11)
    - Old/unused GPOs (not linked for >90 days)
    - Empty GPOs with no settings
    - Policies referencing non-existent users/groups/computers
    - Policies using legacy ADMX templates
    - Policies with broken WMI filters
    - Policies referencing old server names or shares
    - Internet Explorer specific policies
    - Policies using deprecated Windows features
    - Policies created before a certain date

.PARAMETER DaysUnlinked
    Number of days a GPO must be unlinked to be considered old (default: 90)

.PARAMETER CreatedBeforeDate
    Find policies created before this date (default: 2 years ago)

.PARAMETER ReportPath
    Path to save the HTML report (default: current directory)

.PARAMETER IncludeRiskAssessment
    Include detailed risk assessment for each finding (default: $true)

.EXAMPLE
    .\Find-LegacyPolicies.ps1 -DaysUnlinked 180 -ReportPath "C:\Reports"
#>

[CmdletBinding()]
param (
    [int]$DaysUnlinked = 90,
    [DateTime]$CreatedBeforeDate = (Get-Date).AddYears(-2),
    [string]$ReportPath = $PSScriptRoot,
    [bool]$IncludeRiskAssessment = $true
)

# Import required modules
Import-Module GroupPolicy -ErrorAction Stop
Import-Module ActiveDirectory -ErrorAction Stop

# Initialize results collection
$results = @{
    SoftwareRestrictionPolicies = @()
    UnusedGPOs = @()
    EmptyGPOs = @()
    BrokenReferences = @()
    LegacyADMX = @()
    BrokenWMIFilters = @()
    OldServerReferences = @()
    IEPolicies = @()
    DeprecatedFeatures = @()
    OldPolicies = @()
}

# Helper function to assess risk level
function Get-RiskLevel {
    param (
        [string]$Type,
        [hashtable]$Details
    )
    
    $risk = @{
        Level = "Low"
        Score = 1
        Recommendation = "Safe to remove after review"
        Considerations = @()
    }
    
    switch ($Type) {
        "SoftwareRestriction" {
            $risk.Level = "Medium"
            $risk.Score = 5
            $risk.Recommendation = "Test removal in pilot group first"
            $risk.Considerations = @(
                "May affect legacy applications",
                "Check for AppLocker replacement policies",
                "Review application compatibility requirements"
            )
        }
        "UnusedGPO" {
            if ($Details.DaysUnlinked -gt 365) {
                $risk.Level = "Low"
                $risk.Score = 2
            }
            else {
                $risk.Level = "Medium"
                $risk.Score = 4
            }
            $risk.Considerations = @(
                "Verify GPO is not used for testing",
                "Check if GPO is referenced in documentation",
                "Confirm with GPO owner before deletion"
            )
        }
        "EmptyGPO" {
            $risk.Level = "Low"
            $risk.Score = 1
            $risk.Recommendation = "Safe to remove"
            $risk.Considerations = @(
                "Verify GPO was not recently created",
                "Check if GPO is a template or placeholder"
            )
        }
        "BrokenReference" {
            $risk.Level = "High"
            $risk.Score = 7
            $risk.Recommendation = "Fix references or remove policy"
            $risk.Considerations = @(
                "Policy may be causing errors",
                "Could affect security if filtering is broken",
                "Review security implications before changes"
            )
        }
        "LegacyADMX" {
            $risk.Level = "Medium"
            $risk.Score = 5
            $risk.Recommendation = "Update to newer ADMX templates"
            $risk.Considerations = @(
                "May require policy recreation",
                "Test compatibility with target systems",
                "Document current settings before migration"
            )
        }
        "IEPolicy" {
            $risk.Level = "Medium"
            $risk.Score = 6
            $risk.Recommendation = "Migrate to Edge policies"
            $risk.Considerations = @(
                "Check for IE mode requirements in Edge",
                "Review legacy web application dependencies",
                "Plan phased migration approach"
            )
        }
        default {
            $risk.Level = "Medium"
            $risk.Score = 5
        }
    }
    
    return $risk
}

Write-Host "Starting legacy Group Policy assessment..." -ForegroundColor Cyan

# 1. Detect Software Restriction Policies
Write-Host "`nChecking for Software Restriction Policies..." -ForegroundColor Yellow
try {
    $allGPOs = Get-GPO -All
    foreach ($gpo in $allGPOs) {
        $gpoReport = Get-GPOReport -Guid $gpo.Id -ReportType Xml
        if ($gpoReport -match 'Software\\Policies\\Microsoft\\Windows\\Safer') {
            $results.SoftwareRestrictionPolicies += @{
                GPOName = $gpo.DisplayName
                GPOID = $gpo.Id
                CreationTime = $gpo.CreationTime
                ModificationTime = $gpo.ModificationTime
                Risk = Get-RiskLevel -Type "SoftwareRestriction" -Details @{}
            }
            Write-Host "  Found SRP in: $($gpo.DisplayName)" -ForegroundColor Red
        }
    }
}
catch {
    Write-Warning "Error checking Software Restriction Policies: $_"
}

# 2. Find old/unused GPOs
Write-Host "`nChecking for unused GPOs (unlinked for >$DaysUnlinked days)..." -ForegroundColor Yellow
try {
    foreach ($gpo in $allGPOs) {
        $links = (Get-GPOReport -Guid $gpo.Id -ReportType Xml | 
                 Select-String -Pattern '<LinksTo>' -Context 0,10).Context.PostContext
        
        if (-not $links -or $links.Count -eq 0) {
            $daysSinceModified = (Get-Date) - $gpo.ModificationTime
            if ($daysSinceModified.Days -gt $DaysUnlinked) {
                $results.UnusedGPOs += @{
                    GPOName = $gpo.DisplayName
                    GPOID = $gpo.Id
                    CreationTime = $gpo.CreationTime
                    ModificationTime = $gpo.ModificationTime
                    DaysUnlinked = $daysSinceModified.Days
                    Risk = Get-RiskLevel -Type "UnusedGPO" -Details @{DaysUnlinked = $daysSinceModified.Days}
                }
                Write-Host "  Found unlinked GPO: $($gpo.DisplayName) (unlinked for $($daysSinceModified.Days) days)" -ForegroundColor Red
            }
        }
    }
}
catch {
    Write-Warning "Error checking unused GPOs: $_"
}

# 3. Identify empty GPOs
Write-Host "`nChecking for empty GPOs..." -ForegroundColor Yellow
try {
    foreach ($gpo in $allGPOs) {
        $gpoReport = Get-GPOReport -Guid $gpo.Id -ReportType Xml
        $userSettings = $gpoReport -match '<User>.*<ExtensionData>'
        $computerSettings = $gpoReport -match '<Computer>.*<ExtensionData>'
        
        if (-not $userSettings -and -not $computerSettings) {
            $results.EmptyGPOs += @{
                GPOName = $gpo.DisplayName
                GPOID = $gpo.Id
                CreationTime = $gpo.CreationTime
                ModificationTime = $gpo.ModificationTime
                Risk = Get-RiskLevel -Type "EmptyGPO" -Details @{}
            }
            Write-Host "  Found empty GPO: $($gpo.DisplayName)" -ForegroundColor Red
        }
    }
}
catch {
    Write-Warning "Error checking empty GPOs: $_"
}

# 4. Find policies referencing non-existent users/groups/computers
Write-Host "`nChecking for broken security references..." -ForegroundColor Yellow
try {
    foreach ($gpo in $allGPOs) {
        $gpoReport = Get-GPOReport -Guid $gpo.Id -ReportType Xml
        $brokenRefs = @()
        
        # Extract SIDs from permissions and filtering
        $sids = ([regex]::Matches($gpoReport, 'S-1-5-[0-9\-]+') | ForEach-Object { $_.Value }) | Select-Object -Unique
        
        foreach ($sid in $sids) {
            try {
                $null = [System.Security.Principal.SecurityIdentifier]::new($sid).Translate([System.Security.Principal.NTAccount])
            }
            catch {
                $brokenRefs += $sid
            }
        }
        
        if ($brokenRefs.Count -gt 0) {
            $results.BrokenReferences += @{
                GPOName = $gpo.DisplayName
                GPOID = $gpo.Id
                BrokenSIDs = $brokenRefs
                Count = $brokenRefs.Count
                Risk = Get-RiskLevel -Type "BrokenReference" -Details @{}
            }
            Write-Host "  Found broken references in: $($gpo.DisplayName) ($($brokenRefs.Count) broken SIDs)" -ForegroundColor Red
        }
    }
}
catch {
    Write-Warning "Error checking broken references: $_"
}

# 5. Check for policies using legacy ADMX templates
Write-Host "`nChecking for legacy ADMX templates..." -ForegroundColor Yellow
try {
    $legacyTemplates = @(
        'WindowsXP',
        'Windows2000',
        'WindowsVista',
        'Windows7',
        'Windows8',
        'InternetExplorer',
        'WindowsMediaPlayer'
    )
    
    foreach ($gpo in $allGPOs) {
        $gpoReport = Get-GPOReport -Guid $gpo.Id -ReportType Xml
        $foundLegacy = @()
        
        foreach ($template in $legacyTemplates) {
            if ($gpoReport -match $template) {
                $foundLegacy += $template
            }
        }
        
        if ($foundLegacy.Count -gt 0) {
            $results.LegacyADMX += @{
                GPOName = $gpo.DisplayName
                GPOID = $gpo.Id
                LegacyTemplates = $foundLegacy
                Risk = Get-RiskLevel -Type "LegacyADMX" -Details @{}
            }
            Write-Host "  Found legacy templates in: $($gpo.DisplayName) ($($foundLegacy -join ', '))" -ForegroundColor Red
        }
    }
}
catch {
    Write-Warning "Error checking legacy ADMX templates: $_"
}

# 6. Identify policies with broken WMI filters
Write-Host "`nChecking for broken WMI filters..." -ForegroundColor Yellow
try {
    foreach ($gpo in $allGPOs) {
        if ($gpo.WmiFilter) {
            try {
                $wmiFilter = Get-ADObject -Identity $gpo.WmiFilter.Path -Properties msWMI-Name, msWMI-Parm2 -ErrorAction Stop
            }
            catch {
                $results.BrokenWMIFilters += @{
                    GPOName = $gpo.DisplayName
                    GPOID = $gpo.Id
                    WMIFilterPath = $gpo.WmiFilter.Path
                    Error = $_.Exception.Message
                    Risk = Get-RiskLevel -Type "BrokenReference" -Details @{}
                }
                Write-Host "  Found broken WMI filter in: $($gpo.DisplayName)" -ForegroundColor Red
            }
        }
    }
}
catch {
    Write-Warning "Error checking WMI filters: $_"
}

# 7. Find policies referencing old server names or shares
Write-Host "`nChecking for old server references..." -ForegroundColor Yellow
try {
    foreach ($gpo in $allGPOs) {
        $gpoReport = Get-GPOReport -Guid $gpo.Id -ReportType Xml
        $serverRefs = @()
        
        # Look for UNC paths and server names
        $uncPaths = [regex]::Matches($gpoReport, '\\\\[^\\]+\\[^<>"]+') | ForEach-Object { $_.Value }
        
        foreach ($path in $uncPaths) {
            $server = ($path -split '\\')[2]
            try {
                $null = Test-Connection -ComputerName $server -Count 1 -Quiet -ErrorAction Stop
            }
            catch {
                $serverRefs += @{
                    Path = $path
                    Server = $server
                }
            }
        }
        
        if ($serverRefs.Count -gt 0) {
            $results.OldServerReferences += @{
                GPOName = $gpo.DisplayName
                GPOID = $gpo.Id
                References = $serverRefs
                Risk = Get-RiskLevel -Type "BrokenReference" -Details @{}
            }
            Write-Host "  Found old server references in: $($gpo.DisplayName)" -ForegroundColor Red
        }
    }
}
catch {
    Write-Warning "Error checking server references: $_"
}

# 8. Detect Internet Explorer specific policies
Write-Host "`nChecking for Internet Explorer policies..." -ForegroundColor Yellow
try {
    $iePolicyPaths = @(
        'Internet Explorer',
        'Microsoft\\Internet Explorer',
        'Windows\\CurrentVersion\\Internet Settings',
        'Zones\\3',  # Internet Zone
        'Zones\\2',  # Trusted Zone
        'Zones\\1',  # Intranet Zone
        'Zones\\4'   # Restricted Zone
    )
    
    foreach ($gpo in $allGPOs) {
        $gpoReport = Get-GPOReport -Guid $gpo.Id -ReportType Xml
        $foundIE = $false
        
        foreach ($path in $iePolicyPaths) {
            if ($gpoReport -match [regex]::Escape($path)) {
                $foundIE = $true
                break
            }
        }
        
        if ($foundIE) {
            $results.IEPolicies += @{
                GPOName = $gpo.DisplayName
                GPOID = $gpo.Id
                CreationTime = $gpo.CreationTime
                ModificationTime = $gpo.ModificationTime
                Risk = Get-RiskLevel -Type "IEPolicy" -Details @{}
            }
            Write-Host "  Found IE policies in: $($gpo.DisplayName)" -ForegroundColor Red
        }
    }
}
catch {
    Write-Warning "Error checking IE policies: $_"
}

# 9. Find policies using deprecated Windows features
Write-Host "`nChecking for deprecated Windows features..." -ForegroundColor Yellow
try {
    $deprecatedFeatures = @{
        'Windows\\HomeGroup' = 'HomeGroup (removed in Windows 10 1803)'
        'Windows\\Connect' = 'Windows Connect (deprecated)'
        'Windows Media Center' = 'Windows Media Center (removed in Windows 10)'
        'Windows\\Personalization\\Desktop Slideshow' = 'Desktop Slideshow (deprecated)'
        'RemoteApp and Desktop Connections' = 'RemoteApp (deprecated for Azure Virtual Desktop)'
        'Windows\\Windows Search\\Cortana' = 'Cortana policies (deprecated in many regions)'
    }
    
    foreach ($gpo in $allGPOs) {
        $gpoReport = Get-GPOReport -Guid $gpo.Id -ReportType Xml
        $foundDeprecated = @()
        
        foreach ($feature in $deprecatedFeatures.Keys) {
            if ($gpoReport -match [regex]::Escape($feature)) {
                $foundDeprecated += @{
                    Feature = $feature
                    Description = $deprecatedFeatures[$feature]
                }
            }
        }
        
        if ($foundDeprecated.Count -gt 0) {
            $results.DeprecatedFeatures += @{
                GPOName = $gpo.DisplayName
                GPOID = $gpo.Id
                Features = $foundDeprecated
                Risk = Get-RiskLevel -Type "DeprecatedFeature" -Details @{}
            }
            Write-Host "  Found deprecated features in: $($gpo.DisplayName)" -ForegroundColor Red
        }
    }
}
catch {
    Write-Warning "Error checking deprecated features: $_"
}

# 10. Check for policies created before a certain date
Write-Host "`nChecking for policies created before $CreatedBeforeDate..." -ForegroundColor Yellow
try {
    foreach ($gpo in $allGPOs) {
        if ($gpo.CreationTime -lt $CreatedBeforeDate) {
            $results.OldPolicies += @{
                GPOName = $gpo.DisplayName
                GPOID = $gpo.Id
                CreationTime = $gpo.CreationTime
                ModificationTime = $gpo.ModificationTime
                Age = ((Get-Date) - $gpo.CreationTime).Days
                Risk = Get-RiskLevel -Type "OldPolicy" -Details @{Age = ((Get-Date) - $gpo.CreationTime).Days}
            }
            Write-Host "  Found old policy: $($gpo.DisplayName) (created $(((Get-Date) - $gpo.CreationTime).Days) days ago)" -ForegroundColor Red
        }
    }
}
catch {
    Write-Warning "Error checking old policies: $_"
}

# Generate HTML Report
Write-Host "`nGenerating cleanup report..." -ForegroundColor Cyan

# Use StringBuilder for better performance
$reportBuilder = New-Object System.Text.StringBuilder

[void]$reportBuilder.AppendLine(@"
<!DOCTYPE html>
<html>
<head>
    <title>Legacy Group Policy Assessment Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 3px solid #0078d4; padding-bottom: 10px; }
        h2 { color: #0078d4; margin-top: 30px; }
        .summary { background-color: #e7f3ff; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }
        .summary-item { background-color: white; padding: 10px; border-radius: 5px; text-align: center; }
        .summary-item .count { font-size: 24px; font-weight: bold; color: #0078d4; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th { background-color: #0078d4; color: white; padding: 10px; text-align: left; }
        td { padding: 8px; border-bottom: 1px solid #ddd; }
        tr:hover { background-color: #f5f5f5; }
        .risk-high { background-color: #ffcccc; color: #cc0000; padding: 2px 8px; border-radius: 3px; }
        .risk-medium { background-color: #fff3cd; color: #856404; padding: 2px 8px; border-radius: 3px; }
        .risk-low { background-color: #d4edda; color: #155724; padding: 2px 8px; border-radius: 3px; }
        .considerations { font-size: 0.9em; color: #666; }
        .no-issues { padding: 20px; text-align: center; color: #28a745; font-weight: bold; }
        .export-section { margin-top: 30px; padding: 15px; background-color: #f8f9fa; border-radius: 5px; }
        .recommendation { background-color: #e7f3ff; padding: 10px; margin: 10px 0; border-left: 4px solid #0078d4; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Legacy Group Policy Assessment Report</h1>
        <p>Generated on: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
        
        <div class="summary">
            <h3>Executive Summary</h3>
            <div class="summary-grid">
                <div class="summary-item">
                    <div class="count">$($results.SoftwareRestrictionPolicies.Count)</div>
                    <div>Software Restriction Policies</div>
                </div>
                <div class="summary-item">
                    <div class="count">$($results.UnusedGPOs.Count)</div>
                    <div>Unused GPOs</div>
                </div>
                <div class="summary-item">
                    <div class="count">$($results.EmptyGPOs.Count)</div>
                    <div>Empty GPOs</div>
                </div>
                <div class="summary-item">
                    <div class="count">$($results.BrokenReferences.Count)</div>
                    <div>Broken References</div>
                </div>
                <div class="summary-item">
                    <div class="count">$($results.LegacyADMX.Count)</div>
                    <div>Legacy ADMX</div>
                </div>
                <div class="summary-item">
                    <div class="count">$($results.BrokenWMIFilters.Count)</div>
                    <div>Broken WMI Filters</div>
                </div>
                <div class="summary-item">
                    <div class="count">$($results.OldServerReferences.Count)</div>
                    <div>Old Server References</div>
                </div>
                <div class="summary-item">
                    <div class="count">$($results.IEPolicies.Count)</div>
                    <div>IE Policies</div>
                </div>
                <div class="summary-item">
                    <div class="count">$($results.DeprecatedFeatures.Count)</div>
                    <div>Deprecated Features</div>
                </div>
                <div class="summary-item">
                    <div class="count">$($results.OldPolicies.Count)</div>
                    <div>Old Policies</div>
                </div>
            </div>
        </div>
"@
)

# Add sections for each finding type
$sections = @(
    @{Title = "Software Restriction Policies (Deprecated in Windows 11)"; Data = $results.SoftwareRestrictionPolicies; Type = "SRP"},
    @{Title = "Unused GPOs (Unlinked for >$DaysUnlinked days)"; Data = $results.UnusedGPOs; Type = "Unused"},
    @{Title = "Empty GPOs"; Data = $results.EmptyGPOs; Type = "Empty"},
    @{Title = "Policies with Broken References"; Data = $results.BrokenReferences; Type = "Broken"},
    @{Title = "Policies Using Legacy ADMX Templates"; Data = $results.LegacyADMX; Type = "Legacy"},
    @{Title = "Policies with Broken WMI Filters"; Data = $results.BrokenWMIFilters; Type = "WMI"},
    @{Title = "Policies with Old Server References"; Data = $results.OldServerReferences; Type = "Server"},
    @{Title = "Internet Explorer Specific Policies"; Data = $results.IEPolicies; Type = "IE"},
    @{Title = "Policies Using Deprecated Windows Features"; Data = $results.DeprecatedFeatures; Type = "Deprecated"},
    @{Title = "Policies Created Before $CreatedBeforeDate"; Data = $results.OldPolicies; Type = "Old"}
)

foreach ($section in $sections) {
        [void]$reportBuilder.AppendLine("<h2>$($section.Title)</h2>")
    
    if ($section.Data.Count -eq 0) {
        [void]$reportBuilder.AppendLine("<div class='no-issues'>No issues found in this category</div>")
    }
    else {
        [void]$reportBuilder.AppendLine("<table><thead><tr>")
        
        # Dynamic headers based on data type
        switch ($section.Type) {
            "SRP" {
                [void]$reportBuilder.AppendLine("<th>GPO Name</th><th>Creation Time</th><th>Last Modified</th><th>Risk Level</th><th>Recommendation</th>")
            }
            "Unused" {
                [void]$reportBuilder.AppendLine("<th>GPO Name</th><th>Days Unlinked</th><th>Last Modified</th><th>Risk Level</th><th>Recommendation</th>")
            }
            "Empty" {
                [void]$reportBuilder.AppendLine("<th>GPO Name</th><th>Creation Time</th><th>Last Modified</th><th>Risk Level</th><th>Recommendation</th>")
            }
            "Broken" {
                [void]$reportBuilder.AppendLine("<th>GPO Name</th><th>Broken SIDs Count</th><th>Risk Level</th><th>Recommendation</th>")
            }
            "Legacy" {
                [void]$reportBuilder.AppendLine("<th>GPO Name</th><th>Legacy Templates</th><th>Risk Level</th><th>Recommendation</th>")
            }
            "WMI" {
                [void]$reportBuilder.AppendLine("<th>GPO Name</th><th>Error</th><th>Risk Level</th><th>Recommendation</th>")
            }
            "Server" {
                [void]$reportBuilder.AppendLine("<th>GPO Name</th><th>Unreachable Servers</th><th>Risk Level</th><th>Recommendation</th>")
            }
            "IE" {
                [void]$reportBuilder.AppendLine("<th>GPO Name</th><th>Creation Time</th><th>Last Modified</th><th>Risk Level</th><th>Recommendation</th>")
            }
            "Deprecated" {
                [void]$reportBuilder.AppendLine("<th>GPO Name</th><th>Deprecated Features</th><th>Risk Level</th><th>Recommendation</th>")
            }
            "Old" {
                [void]$reportBuilder.AppendLine("<th>GPO Name</th><th>Age (Days)</th><th>Last Modified</th><th>Risk Level</th><th>Recommendation</th>")
            }
        }
        
        [void]$reportBuilder.AppendLine("</tr></thead><tbody>")
        
        foreach ($item in $section.Data) {
            [void]$reportBuilder.AppendLine("<tr>")
            
            # Format risk level
            $riskClass = switch ($item.Risk.Level) {
                "High" { "risk-high" }
                "Medium" { "risk-medium" }
                "Low" { "risk-low" }
            }
            
            # Dynamic row content based on data type
            switch ($section.Type) {
                "SRP" {
                    [void]$reportBuilder.AppendLine("<td>$($item.GPOName)</td>")
                    [void]$reportBuilder.AppendLine("<td>$($item.CreationTime.ToString('yyyy-MM-dd'))</td>")
                    [void]$reportBuilder.AppendLine("<td>$($item.ModificationTime.ToString('yyyy-MM-dd'))</td>")
                    [void]$reportBuilder.AppendLine("<td><span class='$riskClass'>$($item.Risk.Level)</span></td>")
                    [void]$reportBuilder.AppendLine("<td>$($item.Risk.Recommendation)</td>")
                }
                "Unused" {
                    [void]$reportBuilder.AppendLine("<td>$($item.GPOName)</td>")
                    [void]$reportBuilder.AppendLine("<td>$($item.DaysUnlinked)</td>")
                    [void]$reportBuilder.AppendLine("<td>$($item.ModificationTime.ToString('yyyy-MM-dd'))</td>")
                    [void]$reportBuilder.AppendLine("<td><span class='$riskClass'>$($item.Risk.Level)</span></td>")
                    [void]$reportBuilder.AppendLine("<td>$($item.Risk.Recommendation)</td>")
                }
                "Empty" {
                    [void]$reportBuilder.AppendLine("<td>$($item.GPOName)</td>")
                    [void]$reportBuilder.AppendLine("<td>$($item.CreationTime.ToString('yyyy-MM-dd'))</td>")
                    [void]$reportBuilder.AppendLine("<td>$($item.ModificationTime.ToString('yyyy-MM-dd'))</td>")
                    [void]$reportBuilder.AppendLine("<td><span class='$riskClass'>$($item.Risk.Level)</span></td>")
                    [void]$reportBuilder.AppendLine("<td>$($item.Risk.Recommendation)</td>")
                }
                "Broken" {
                    [void]$reportBuilder.AppendLine("<td>$($item.GPOName)</td>")
                    [void]$reportBuilder.AppendLine("<td>$($item.Count)</td>")
                    [void]$reportBuilder.AppendLine("<td><span class='$riskClass'>$($item.Risk.Level)</span></td>")
                    [void]$reportBuilder.AppendLine("<td>$($item.Risk.Recommendation)</td>")
                }
                "Legacy" {
                    [void]$reportBuilder.AppendLine("<td>$($item.GPOName)</td>")
                    [void]$reportBuilder.AppendLine("<td>$($item.LegacyTemplates -join ', ')</td>")
                    [void]$reportBuilder.AppendLine("<td><span class='$riskClass'>$($item.Risk.Level)</span></td>")
                    [void]$reportBuilder.AppendLine("<td>$($item.Risk.Recommendation)</td>")
                }
                "WMI" {
                    [void]$reportBuilder.AppendLine("<td>$($item.GPOName)</td>")
                    [void]$reportBuilder.AppendLine("<td>$($item.Error)</td>")
                    [void]$reportBuilder.AppendLine("<td><span class='$riskClass'>$($item.Risk.Level)</span></td>")
                    [void]$reportBuilder.AppendLine("<td>$($item.Risk.Recommendation)</td>")
                }
                "Server" {
                    [void]$reportBuilder.AppendLine("<td>$($item.GPOName)</td>")
                    [void]$reportBuilder.AppendLine("<td>$($item.References | ForEach-Object { $_.Server } | Select-Object -Unique | Join-String -Separator ', ')</td>")
                    [void]$reportBuilder.AppendLine("<td><span class='$riskClass'>$($item.Risk.Level)</span></td>")
                    [void]$reportBuilder.AppendLine("<td>$($item.Risk.Recommendation)</td>")
                }
                "IE" {
                    [void]$reportBuilder.AppendLine("<td>$($item.GPOName)</td>")
                    [void]$reportBuilder.AppendLine("<td>$($item.CreationTime.ToString('yyyy-MM-dd'))</td>")
                    [void]$reportBuilder.AppendLine("<td>$($item.ModificationTime.ToString('yyyy-MM-dd'))</td>")
                    [void]$reportBuilder.AppendLine("<td><span class='$riskClass'>$($item.Risk.Level)</span></td>")
                    [void]$reportBuilder.AppendLine("<td>$($item.Risk.Recommendation)</td>")
                }
                "Deprecated" {
                    [void]$reportBuilder.AppendLine("<td>$($item.GPOName)</td>")
                    [void]$reportBuilder.AppendLine("<td>$($item.Features | ForEach-Object { $_.Description } | Join-String -Separator '<br>')</td>")
                    [void]$reportBuilder.AppendLine("<td><span class='$riskClass'>$($item.Risk.Level)</span></td>")
                    [void]$reportBuilder.AppendLine("<td>$($item.Risk.Recommendation)</td>")
                }
                "Old" {
                    [void]$reportBuilder.AppendLine("<td>$($item.GPOName)</td>")
                    [void]$reportBuilder.AppendLine("<td>$($item.Age)</td>")
                    [void]$reportBuilder.AppendLine("<td>$($item.ModificationTime.ToString('yyyy-MM-dd'))</td>")
                    [void]$reportBuilder.AppendLine("<td><span class='$riskClass'>$($item.Risk.Level)</span></td>")
                    [void]$reportBuilder.AppendLine("<td>$($item.Risk.Recommendation)</td>")
                }
            }
            
            [void]$reportBuilder.AppendLine("</tr>")
            
            # Add considerations row if risk assessment is enabled
            if ($IncludeRiskAssessment -and $item.Risk.Considerations.Count -gt 0) {
                [void]$reportBuilder.AppendLine("<tr><td colspan='5' class='considerations'><strong>Considerations:</strong> ")
                [void]$reportBuilder.AppendLine("<ul>")
                foreach ($consideration in $item.Risk.Considerations) {
                    [void]$reportBuilder.AppendLine("<li>$consideration</li>")
                }
                [void]$reportBuilder.AppendLine("</ul></td></tr>")
            }
        }
        
        [void]$reportBuilder.AppendLine("</tbody></table>")
    }
}

# Add cleanup recommendations
[void]$reportBuilder.AppendLine(@"
        <div class="export-section">
            <h2>Cleanup Recommendations</h2>
            <div class="recommendation">
                <h3>High Priority Actions</h3>
                <ul>
                    <li>Address all broken references and WMI filters immediately as they may cause policy processing errors</li>
                    <li>Review and migrate Internet Explorer policies to Microsoft Edge policies</li>
                    <li>Replace Software Restriction Policies with AppLocker or Windows Defender Application Control</li>
                </ul>
            </div>
            
            <div class="recommendation">
                <h3>Medium Priority Actions</h3>
                <ul>
                    <li>Review unused GPOs and confirm they can be safely removed</li>
                    <li>Update policies using legacy ADMX templates to current versions</li>
                    <li>Migrate policies using deprecated Windows features to supported alternatives</li>
                </ul>
            </div>
            
            <div class="recommendation">
                <h3>Low Priority Actions</h3>
                <ul>
                    <li>Clean up empty GPOs that serve no purpose</li>
                    <li>Review old policies for relevance and consolidation opportunities</li>
                    <li>Document any legacy policies that must be retained for compliance</li>
                </ul>
            </div>
            
            <div class="recommendation">
                <h3>Best Practices Going Forward</h3>
                <ul>
                    <li>Implement a regular GPO review cycle (quarterly recommended)</li>
                    <li>Document GPO purposes and owners in the description field</li>
                    <li>Use GPO versioning and backup before making significant changes</li>
                    <li>Test GPO removal in a lab environment before production deletion</li>
                    <li>Maintain an inventory of required legacy policies with business justification</li>
                </ul>
            </div>
        </div>
    </div>
</body>
</html>
"@
)

# Save the report
$reportFileName = "GP_LegacyGPO_Assessment_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
$reportFullPath = Join-Path -Path $ReportPath -ChildPath $reportFileName
$reportBuilder.ToString() | Out-File -FilePath $reportFullPath -Encoding UTF8

# Also save a CSV summary for further analysis
$csvSummary = @()
foreach ($category in $results.Keys) {
    foreach ($item in $results[$category]) {
        $csvSummary += [PSCustomObject]@{
            Category = $category
            GPOName = $item.GPOName
            GPOID = $item.GPOID
            RiskLevel = $item.Risk.Level
            RiskScore = $item.Risk.Score
            Recommendation = $item.Risk.Recommendation
            Details = ($item | ConvertTo-Json -Compress)
        }
    }
}

$csvFileName = "GP_LegacyGPO_Summary_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$csvFullPath = Join-Path -Path $ReportPath -ChildPath $csvFileName
$csvSummary | Export-Csv -Path $csvFullPath -NoTypeInformation

# Display summary
Write-Host "`n========== Assessment Complete ==========" -ForegroundColor Green
Write-Host "Total legacy items found: $($csvSummary.Count)" -ForegroundColor Yellow
Write-Host "High risk items: $(($csvSummary | Where-Object { $_.RiskLevel -eq 'High' }).Count)" -ForegroundColor Red
Write-Host "Medium risk items: $(($csvSummary | Where-Object { $_.RiskLevel -eq 'Medium' }).Count)" -ForegroundColor Yellow
Write-Host "Low risk items: $(($csvSummary | Where-Object { $_.RiskLevel -eq 'Low' }).Count)" -ForegroundColor Green
Write-Host "`nReports saved to:"
Write-Host "  HTML Report: $reportFullPath" -ForegroundColor Cyan
Write-Host "  CSV Summary: $csvFullPath" -ForegroundColor Cyan

# Open the HTML report if running interactively
if ($Host.UI.RawUI.WindowTitle) {
    Start-Process $reportFullPath
}