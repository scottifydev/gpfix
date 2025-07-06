#Requires -Module GroupPolicy
#Requires -Module ActiveDirectory

<#
.SYNOPSIS
    Creates a comprehensive inventory of all Group Policy Objects in the domain
.DESCRIPTION
    This script analyzes all GPOs and creates detailed reports including:
    - GPO metadata (creation, modification, owner)
    - GPO links and target OUs
    - User group targeting
    - AppLocker policies
    - Browser restrictions
    - OU structure with inheritance
    - GPO categories and processing order
.PARAMETER OutputPath
    Path where reports and backups will be saved
.PARAMETER ExportFormat
    Format for detailed export (CSV or JSON)
.EXAMPLE
    .\Get-GPOInventory.ps1 -OutputPath "C:\GPO_Reports" -ExportFormat "Both"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\GPO_Inventory_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("CSV", "JSON", "Both")]
    [string]$ExportFormat = "Both"
)

# Import required modules
Import-Module GroupPolicy -ErrorAction Stop
Import-Module ActiveDirectory -ErrorAction Stop

# Create output directory
if (!(Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

# Create subdirectories
$BackupPath = Join-Path $OutputPath "GPO_Backups"
$ReportsPath = Join-Path $OutputPath "Reports"
New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
New-Item -ItemType Directory -Path $ReportsPath -Force | Out-Null

Write-Host "Starting GPO Inventory Analysis..." -ForegroundColor Cyan
Write-Host "Output Path: $OutputPath" -ForegroundColor Yellow

# Initialize collections
$GPOInventory = @()
$GPOLinks = @()
$TeenagerGPOs = @()
$AppLockerGPOs = @()
$BrowserGPOs = @()
$OUStructure = @()
$GPOCategories = @{
    Security = @()
    Software = @()
    UserConfiguration = @()
    ComputerConfiguration = @()
    NetworkSettings = @()
    Other = @()
}

# Function to get GPO XML report
function Get-GPOXMLReport {
    param($GPO)
    try {
        [xml]$Report = Get-GPOReport -Guid $GPO.Id -ReportType Xml -ErrorAction Stop
        return $Report
    }
    catch {
        Write-Warning "Failed to get XML report for GPO: $($GPO.DisplayName)"
        return $null
    }
}

# Function to check for teenager/user group targeting
function Test-TeenagerTargeting {
    param($GPOReport)
    
    $teenagerKeywords = @('teenager', 'teen', 'student', 'youth', 'minor', 'under18', 'restricted')
    $hasTeenagerTargeting = $false
    $targetedGroups = @()
    
    # Check security filtering
    if ($GPOReport.GPO.SecurityDescriptor.Permissions.TrusteePermissions) {
        foreach ($permission in $GPOReport.GPO.SecurityDescriptor.Permissions.TrusteePermissions) {
            $trusteeName = $permission.Trustee.Name.'#text'
            if ($trusteeName) {
                $targetedGroups += $trusteeName
                foreach ($keyword in $teenagerKeywords) {
                    if ($trusteeName -like "*$keyword*") {
                        $hasTeenagerTargeting = $true
                    }
                }
            }
        }
    }
    
    # Check WMI filters and group policy preferences for targeting
    $xmlString = $GPOReport.OuterXml
    foreach ($keyword in $teenagerKeywords) {
        if ($xmlString -like "*$keyword*") {
            $hasTeenagerTargeting = $true
        }
    }
    
    return @{
        HasTeenagerTargeting = $hasTeenagerTargeting
        TargetedGroups = $targetedGroups
    }
}

# Function to check for AppLocker policies
function Test-AppLockerPolicies {
    param($GPOReport)
    
    $hasAppLocker = $false
    $appLockerDetails = @()
    
    # Check for AppLocker in Computer Configuration
    $appLockerPaths = @(
        "Computer.ExtensionData.Extension | Where-Object {`$_.type -eq '{F35378EF-E733-4d0b-9F82-4D7E5A8D0705}'}"
        "Computer.ExtensionData | Where-Object {`$_ -like '*AppLocker*'}"
    )
    
    if ($GPOReport.GPO.Computer.ExtensionData) {
        $xmlString = $GPOReport.GPO.Computer.ExtensionData.OuterXml
        if ($xmlString -like "*AppLocker*" -or $xmlString -like "*Application Control*") {
            $hasAppLocker = $true
            
            # Try to extract AppLocker rule details
            if ($xmlString -match '<RuleCollection[^>]*Type="([^"]+)"') {
                $appLockerDetails += "Rule Collection Type: $($Matches[1])"
            }
        }
    }
    
    return @{
        HasAppLocker = $hasAppLocker
        Details = $appLockerDetails
    }
}

# Function to check for browser restrictions
function Test-BrowserRestrictions {
    param($GPOReport)
    
    $browserRestrictions = @{
        Chrome = $false
        Edge = $false
        Firefox = $false
        InternetExplorer = $false
        Details = @()
    }
    
    $xmlString = $GPOReport.OuterXml
    
    # Check for Chrome policies
    if ($xmlString -like "*Chrome*" -or $xmlString -like "*Google\Chrome*") {
        $browserRestrictions.Chrome = $true
        if ($xmlString -like "*URLBlacklist*" -or $xmlString -like "*URLWhitelist*") {
            $browserRestrictions.Details += "Chrome: URL filtering configured"
        }
    }
    
    # Check for Edge policies
    if ($xmlString -like "*Edge*" -or $xmlString -like "*Microsoft\Edge*") {
        $browserRestrictions.Edge = $true
        if ($xmlString -like "*EdgeDisabledSchemes*" -or $xmlString -like "*EdgeHomepage*") {
            $browserRestrictions.Details += "Edge: Homepage/Scheme restrictions"
        }
    }
    
    # Check for Firefox policies
    if ($xmlString -like "*Firefox*" -or $xmlString -like "*Mozilla*") {
        $browserRestrictions.Firefox = $true
        $browserRestrictions.Details += "Firefox: Policies configured"
    }
    
    # Check for IE policies
    if ($xmlString -like "*Internet Explorer*" -or $xmlString -like "*InternetExplorer*") {
        $browserRestrictions.InternetExplorer = $true
        $browserRestrictions.Details += "Internet Explorer: Policies configured"
    }
    
    return $browserRestrictions
}

# Function to categorize GPO
function Get-GPOCategory {
    param($GPO, $GPOReport)
    
    $categories = @()
    $xmlString = $GPOReport.OuterXml.ToLower()
    
    # Security category
    if ($xmlString -match 'password|audit|security|firewall|applocker|bitlocker|defender') {
        $categories += "Security"
    }
    
    # Software category
    if ($xmlString -match 'software|installation|msi|application|package') {
        $categories += "Software"
    }
    
    # Network category
    if ($xmlString -match 'network|vpn|wifi|proxy|dns|dhcp') {
        $categories += "NetworkSettings"
    }
    
    # User vs Computer configuration
    if ($GPO.User.Enabled) {
        $categories += "UserConfiguration"
    }
    if ($GPO.Computer.Enabled) {
        $categories += "ComputerConfiguration"
    }
    
    if ($categories.Count -eq 0) {
        $categories += "Other"
    }
    
    return $categories
}

# Get all GPOs
Write-Host "`nRetrieving all GPOs..." -ForegroundColor Yellow
$AllGPOs = Get-GPO -All

# Process each GPO
$gpoCount = 0
foreach ($GPO in $AllGPOs) {
    $gpoCount++
    Write-Progress -Activity "Processing GPOs" -Status "Processing: $($GPO.DisplayName)" -PercentComplete (($gpoCount / $AllGPOs.Count) * 100)
    
    # Get GPO report
    $GPOReport = Get-GPOXMLReport -GPO $GPO
    
    # Get GPO permissions/owner
    $GPOPermissions = Get-GPPermission -Guid $GPO.Id -All
    $Owner = ($GPOPermissions | Where-Object { $_.Permission -eq "GpoEditDeleteModifySecurity" } | Select-Object -First 1).Trustee.Name
    
    # Test for teenager targeting
    $teenagerTargeting = Test-TeenagerTargeting -GPOReport $GPOReport
    
    # Test for AppLocker
    $appLockerTest = Test-AppLockerPolicies -GPOReport $GPOReport
    
    # Test for browser restrictions
    $browserTest = Test-BrowserRestrictions -GPOReport $GPOReport
    
    # Get GPO categories
    $categories = Get-GPOCategory -GPO $GPO -GPOReport $GPOReport
    
    # Create GPO inventory object
    $GPOInfo = [PSCustomObject]@{
        DisplayName = $GPO.DisplayName
        Id = $GPO.Id
        CreationTime = $GPO.CreationTime
        ModificationTime = $GPO.ModificationTime
        Owner = $Owner
        DomainName = $GPO.DomainName
        Status = $GPO.GpoStatus
        UserEnabled = $GPO.User.Enabled
        ComputerEnabled = $GPO.Computer.Enabled
        WmiFilter = $GPO.WmiFilter.Name
        Description = $GPO.Description
        HasTeenagerTargeting = $teenagerTargeting.HasTeenagerTargeting
        TargetedGroups = ($teenagerTargeting.TargetedGroups -join "; ")
        HasAppLocker = $appLockerTest.HasAppLocker
        AppLockerDetails = ($appLockerTest.Details -join "; ")
        HasChromeRestrictions = $browserTest.Chrome
        HasEdgeRestrictions = $browserTest.Edge
        HasFirefoxRestrictions = $browserTest.Firefox
        HasIERestrictions = $browserTest.InternetExplorer
        BrowserRestrictionDetails = ($browserTest.Details -join "; ")
        Categories = ($categories -join "; ")
    }
    
    $GPOInventory += $GPOInfo
    
    # Add to teenager GPOs if applicable
    if ($teenagerTargeting.HasTeenagerTargeting) {
        $TeenagerGPOs += $GPOInfo
    }
    
    # Add to AppLocker GPOs if applicable
    if ($appLockerTest.HasAppLocker) {
        $AppLockerGPOs += $GPOInfo
    }
    
    # Add to Browser GPOs if applicable
    if ($browserTest.Chrome -or $browserTest.Edge -or $browserTest.Firefox -or $browserTest.InternetExplorer) {
        $BrowserGPOs += $GPOInfo
    }
    
    # Categorize GPO
    foreach ($category in $categories) {
        $GPOCategories[$category] += $GPOInfo
    }
    
    # Backup GPO
    try {
        $backupFolder = Join-Path $BackupPath $GPO.Id.ToString()
        Backup-GPO -Guid $GPO.Id -Path $backupFolder -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Warning "Failed to backup GPO: $($GPO.DisplayName)"
    }
}

Write-Progress -Activity "Processing GPOs" -Completed

# Get GPO Links
Write-Host "`nAnalyzing GPO Links..." -ForegroundColor Yellow
$AllOUs = Get-ADOrganizationalUnit -Filter * -Properties gpLink, gPOptions
$DomainRoot = Get-ADDomain

# Process domain root
if ($DomainRoot.LinkedGroupPolicyObjects) {
    foreach ($gpoLink in $DomainRoot.LinkedGroupPolicyObjects) {
        $gpoGuid = [regex]::Match($gpoLink, '{([^}]+)}').Groups[1].Value
        $linkedGPO = $AllGPOs | Where-Object { $_.Id -eq $gpoGuid }
        
        if ($linkedGPO) {
            $GPOLinks += [PSCustomObject]@{
                GPOName = $linkedGPO.DisplayName
                GPOId = $linkedGPO.Id
                LinkedTo = $DomainRoot.DistinguishedName
                LinkType = "Domain"
                LinkEnabled = $true
                LinkOrder = 0
                InheritanceBlocked = $false
            }
        }
    }
}

# Process each OU
foreach ($OU in $AllOUs) {
    $inheritanceBlocked = $OU.gPOptions -eq 1
    
    if ($OU.gpLink) {
        # Parse gpLink attribute
        $links = $OU.gpLink -split '\]\['
        $linkOrder = 0
        
        foreach ($link in $links) {
            $linkOrder++
            if ($link -match 'LDAP://([^;]+);(\d+)') {
                $gpoDN = $Matches[1]
                $linkFlags = [int]$Matches[2]
                $linkEnabled = ($linkFlags -band 1) -eq 0
                
                # Extract GUID from DN
                if ($gpoDN -match '{([^}]+)}') {
                    $gpoGuid = $Matches[1]
                    $linkedGPO = $AllGPOs | Where-Object { $_.Id -eq $gpoGuid }
                    
                    if ($linkedGPO) {
                        $GPOLinks += [PSCustomObject]@{
                            GPOName = $linkedGPO.DisplayName
                            GPOId = $linkedGPO.Id
                            LinkedTo = $OU.DistinguishedName
                            LinkType = "OU"
                            LinkEnabled = $linkEnabled
                            LinkOrder = $linkOrder
                            InheritanceBlocked = $inheritanceBlocked
                        }
                    }
                }
            }
        }
    }
    
    # Add to OU structure
    $OUStructure += [PSCustomObject]@{
        Name = $OU.Name
        DistinguishedName = $OU.DistinguishedName
        LinkedGPOCount = ($GPOLinks | Where-Object { $_.LinkedTo -eq $OU.DistinguishedName }).Count
        InheritanceBlocked = $inheritanceBlocked
        Path = $OU.DistinguishedName
    }
}

# Export data
Write-Host "`nExporting data..." -ForegroundColor Yellow

# Export to CSV
if ($ExportFormat -eq "CSV" -or $ExportFormat -eq "Both") {
    $GPOInventory | Export-Csv -Path (Join-Path $ReportsPath "GPO_Inventory.csv") -NoTypeInformation
    $GPOLinks | Export-Csv -Path (Join-Path $ReportsPath "GPO_Links.csv") -NoTypeInformation
    $OUStructure | Export-Csv -Path (Join-Path $ReportsPath "OU_Structure.csv") -NoTypeInformation
    $TeenagerGPOs | Export-Csv -Path (Join-Path $ReportsPath "Teenager_GPOs.csv") -NoTypeInformation
    $AppLockerGPOs | Export-Csv -Path (Join-Path $ReportsPath "AppLocker_GPOs.csv") -NoTypeInformation
    $BrowserGPOs | Export-Csv -Path (Join-Path $ReportsPath "Browser_Restriction_GPOs.csv") -NoTypeInformation
}

# Export to JSON
if ($ExportFormat -eq "JSON" -or $ExportFormat -eq "Both") {
    $GPOInventory | ConvertTo-Json -Depth 10 | Out-File -Path (Join-Path $ReportsPath "GPO_Inventory.json")
    $GPOLinks | ConvertTo-Json -Depth 10 | Out-File -Path (Join-Path $ReportsPath "GPO_Links.json")
    $OUStructure | ConvertTo-Json -Depth 10 | Out-File -Path (Join-Path $ReportsPath "OU_Structure.json")
    
    # Combined export
    @{
        GPOInventory = $GPOInventory
        GPOLinks = $GPOLinks
        OUStructure = $OUStructure
        TeenagerGPOs = $TeenagerGPOs
        AppLockerGPOs = $AppLockerGPOs
        BrowserGPOs = $BrowserGPOs
        Categories = $GPOCategories
    } | ConvertTo-Json -Depth 10 | Out-File -Path (Join-Path $ReportsPath "Complete_GPO_Analysis.json")
}

# Generate Summary Report
Write-Host "`nGenerating summary report..." -ForegroundColor Yellow

$summaryReport = @"
================================================================================
                        GROUP POLICY INVENTORY SUMMARY REPORT
================================================================================
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Domain: $($DomainRoot.Name)

OVERVIEW
--------
Total GPOs: $($AllGPOs.Count)
Total GPO Links: $($GPOLinks.Count)
Total OUs: $($AllOUs.Count)

GPO STATUS BREAKDOWN
-------------------
Enabled GPOs: $($GPOInventory | Where-Object { $_.Status -eq "AllSettingsEnabled" } | Measure-Object).Count
User Settings Disabled: $($GPOInventory | Where-Object { $_.Status -eq "UserSettingsDisabled" } | Measure-Object).Count
Computer Settings Disabled: $($GPOInventory | Where-Object { $_.Status -eq "ComputerSettingsDisabled" } | Measure-Object).Count
All Settings Disabled: $($GPOInventory | Where-Object { $_.Status -eq "AllSettingsDisabled" } | Measure-Object).Count

CATEGORY BREAKDOWN
-----------------
Security GPOs: $($GPOCategories.Security.Count)
Software GPOs: $($GPOCategories.Software.Count)
User Configuration GPOs: $($GPOCategories.UserConfiguration.Count)
Computer Configuration GPOs: $($GPOCategories.ComputerConfiguration.Count)
Network Settings GPOs: $($GPOCategories.NetworkSettings.Count)
Other GPOs: $($GPOCategories.Other.Count)

SPECIAL POLICY DETECTION
-----------------------
GPOs with Teenager/Youth Targeting: $($TeenagerGPOs.Count)
GPOs with AppLocker Policies: $($AppLockerGPOs.Count)
GPOs with Browser Restrictions: $($BrowserGPOs.Count)
  - Chrome Restrictions: $($BrowserGPOs | Where-Object { $_.HasChromeRestrictions } | Measure-Object).Count
  - Edge Restrictions: $($BrowserGPOs | Where-Object { $_.HasEdgeRestrictions } | Measure-Object).Count
  - Firefox Restrictions: $($BrowserGPOs | Where-Object { $_.HasFirefoxRestrictions } | Measure-Object).Count
  - IE Restrictions: $($BrowserGPOs | Where-Object { $_.HasIERestrictions } | Measure-Object).Count

OU STRUCTURE SUMMARY
-------------------
Total OUs: $($OUStructure.Count)
OUs with Blocked Inheritance: $($OUStructure | Where-Object { $_.InheritanceBlocked } | Measure-Object).Count
OUs with Linked GPOs: $($OUStructure | Where-Object { $_.LinkedGPOCount -gt 0 } | Measure-Object).Count

TOP 10 MOST LINKED GPOs
----------------------
"@

$topLinkedGPOs = $GPOLinks | Group-Object GPOName | Sort-Object Count -Descending | Select-Object -First 10
foreach ($gpo in $topLinkedGPOs) {
    $summaryReport += "`n$($gpo.Name): $($gpo.Count) links"
}

$summaryReport += @"

RECENTLY MODIFIED GPOs (Last 30 Days)
------------------------------------
"@

$recentGPOs = $GPOInventory | Where-Object { $_.ModificationTime -gt (Get-Date).AddDays(-30) } | Sort-Object ModificationTime -Descending
foreach ($gpo in $recentGPOs) {
    $summaryReport += "`n$($gpo.DisplayName) - Modified: $($gpo.ModificationTime.ToString('yyyy-MM-dd'))"
}

$summaryReport += @"

GPO PROCESSING ORDER AND PRECEDENCE
----------------------------------
Note: GPOs are processed in the following order (LSDOU):
1. Local Computer Policy
2. Site-linked GPOs
3. Domain-linked GPOs
4. OU-linked GPOs (parent to child)

Within each level, GPOs are processed by link order (higher number = processed first).
Later processed GPOs override earlier ones unless blocked by:
- Enforced links (cannot be blocked)
- Block Inheritance (blocks non-enforced GPOs from parent containers)

DOMAIN-LINKED GPOs (Highest Level)
"@

$domainLinkedGPOs = $GPOLinks | Where-Object { $_.LinkType -eq "Domain" } | Sort-Object LinkOrder
foreach ($link in $domainLinkedGPOs) {
    $summaryReport += "`n  Order $($link.LinkOrder): $($link.GPOName) $(if (-not $link.LinkEnabled) { '[DISABLED]' })"
}

$summaryReport += @"

TEENAGER/YOUTH TARGETED GPOs
---------------------------
"@

if ($TeenagerGPOs.Count -gt 0) {
    foreach ($gpo in $TeenagerGPOs) {
        $summaryReport += "`n- $($gpo.DisplayName)"
        if ($gpo.TargetedGroups) {
            $summaryReport += "`n  Target Groups: $($gpo.TargetedGroups)"
        }
    }
} else {
    $summaryReport += "`nNo GPOs found with explicit teenager/youth targeting."
}

$summaryReport += @"

APPLOCKER POLICY GPOs
--------------------
"@

if ($AppLockerGPOs.Count -gt 0) {
    foreach ($gpo in $AppLockerGPOs) {
        $summaryReport += "`n- $($gpo.DisplayName)"
        if ($gpo.AppLockerDetails) {
            $summaryReport += "`n  Details: $($gpo.AppLockerDetails)"
        }
    }
} else {
    $summaryReport += "`nNo GPOs found with AppLocker policies."
}

$summaryReport += @"

BROWSER RESTRICTION GPOs
-----------------------
"@

if ($BrowserGPOs.Count -gt 0) {
    foreach ($gpo in $BrowserGPOs) {
        $summaryReport += "`n- $($gpo.DisplayName)"
        $browsers = @()
        if ($gpo.HasChromeRestrictions) { $browsers += "Chrome" }
        if ($gpo.HasEdgeRestrictions) { $browsers += "Edge" }
        if ($gpo.HasFirefoxRestrictions) { $browsers += "Firefox" }
        if ($gpo.HasIERestrictions) { $browsers += "IE" }
        $summaryReport += "`n  Browsers: $($browsers -join ', ')"
        if ($gpo.BrowserRestrictionDetails) {
            $summaryReport += "`n  Details: $($gpo.BrowserRestrictionDetails)"
        }
    }
} else {
    $summaryReport += "`nNo GPOs found with browser restrictions."
}

$summaryReport += @"

================================================================================
                              END OF REPORT
================================================================================
"@

# Save summary report
$summaryReport | Out-File -Path (Join-Path $ReportsPath "GPO_Summary_Report.txt")

# Generate HTML report
$htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>GPO Inventory Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #2c3e50; }
        h2 { color: #34495e; border-bottom: 2px solid #3498db; padding-bottom: 5px; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #3498db; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .warning { background-color: #f39c12; color: white; padding: 5px; }
        .success { background-color: #27ae60; color: white; padding: 5px; }
        .info { background-color: #3498db; color: white; padding: 5px; }
    </style>
</head>
<body>
    <h1>Group Policy Object Inventory Report</h1>
    <p>Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
    
    <h2>Overview</h2>
    <table>
        <tr><th>Metric</th><th>Value</th></tr>
        <tr><td>Total GPOs</td><td>$($AllGPOs.Count)</td></tr>
        <tr><td>Total GPO Links</td><td>$($GPOLinks.Count)</td></tr>
        <tr><td>Total OUs</td><td>$($AllOUs.Count)</td></tr>
        <tr><td>GPOs with Teenager Targeting</td><td>$($TeenagerGPOs.Count)</td></tr>
        <tr><td>GPOs with AppLocker</td><td>$($AppLockerGPOs.Count)</td></tr>
        <tr><td>GPOs with Browser Restrictions</td><td>$($BrowserGPOs.Count)</td></tr>
    </table>
    
    <h2>All GPOs</h2>
    <table>
        <tr>
            <th>Name</th>
            <th>Status</th>
            <th>Created</th>
            <th>Modified</th>
            <th>Categories</th>
            <th>Special Policies</th>
        </tr>
"@

foreach ($gpo in $GPOInventory | Sort-Object DisplayName) {
    $specialPolicies = @()
    if ($gpo.HasTeenagerTargeting) { $specialPolicies += "Teenager Targeting" }
    if ($gpo.HasAppLocker) { $specialPolicies += "AppLocker" }
    if ($gpo.HasChromeRestrictions -or $gpo.HasEdgeRestrictions -or $gpo.HasFirefoxRestrictions) {
        $specialPolicies += "Browser Restrictions"
    }
    
    $htmlReport += @"
        <tr>
            <td>$($gpo.DisplayName)</td>
            <td>$($gpo.Status)</td>
            <td>$($gpo.CreationTime.ToString('yyyy-MM-dd'))</td>
            <td>$($gpo.ModificationTime.ToString('yyyy-MM-dd'))</td>
            <td>$($gpo.Categories)</td>
            <td>$($specialPolicies -join ', ')</td>
        </tr>
"@
}

$htmlReport += @"
    </table>
</body>
</html>
"@

$htmlReport | Out-File -Path (Join-Path $ReportsPath "GPO_Inventory_Report.html")

# Display completion message
Write-Host "`n========================================" -ForegroundColor Green
Write-Host "GPO Inventory Analysis Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "`nReports saved to: $ReportsPath" -ForegroundColor Yellow
Write-Host "GPO Backups saved to: $BackupPath" -ForegroundColor Yellow
Write-Host "`nGenerated files:" -ForegroundColor Cyan
Write-Host "  - GPO_Summary_Report.txt (Readable summary)" -ForegroundColor White
Write-Host "  - GPO_Inventory_Report.html (HTML report)" -ForegroundColor White

if ($ExportFormat -eq "CSV" -or $ExportFormat -eq "Both") {
    Write-Host "  - GPO_Inventory.csv" -ForegroundColor White
    Write-Host "  - GPO_Links.csv" -ForegroundColor White
    Write-Host "  - OU_Structure.csv" -ForegroundColor White
    Write-Host "  - Teenager_GPOs.csv" -ForegroundColor White
    Write-Host "  - AppLocker_GPOs.csv" -ForegroundColor White
    Write-Host "  - Browser_Restriction_GPOs.csv" -ForegroundColor White
}

if ($ExportFormat -eq "JSON" -or $ExportFormat -eq "Both") {
    Write-Host "  - Complete_GPO_Analysis.json (All data combined)" -ForegroundColor White
}

Write-Host "`nKey Findings:" -ForegroundColor Cyan
Write-Host "  - Total GPOs: $($AllGPOs.Count)" -ForegroundColor White
Write-Host "  - Teenager-targeted GPOs: $($TeenagerGPOs.Count)" -ForegroundColor $(if ($TeenagerGPOs.Count -gt 0) { 'Yellow' } else { 'White' })
Write-Host "  - AppLocker GPOs: $($AppLockerGPOs.Count)" -ForegroundColor $(if ($AppLockerGPOs.Count -gt 0) { 'Yellow' } else { 'White' })
Write-Host "  - Browser Restriction GPOs: $($BrowserGPOs.Count)" -ForegroundColor $(if ($BrowserGPOs.Count -gt 0) { 'Yellow' } else { 'White' })

# Return summary object for pipeline use
[PSCustomObject]@{
    TotalGPOs = $AllGPOs.Count
    TotalLinks = $GPOLinks.Count
    TeenagerGPOs = $TeenagerGPOs.Count
    AppLockerGPOs = $AppLockerGPOs.Count
    BrowserGPOs = $BrowserGPOs.Count
    OutputPath = $OutputPath
}