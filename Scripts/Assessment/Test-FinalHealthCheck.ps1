#Requires -Version 5.1
#Requires -Modules GroupPolicy, ActiveDirectory

<#
.SYNOPSIS
    Performs final comprehensive health check before Group Policy deployment.

.DESCRIPTION
    This script performs a final validation of all prerequisites, resolved conflicts,
    and system readiness before deploying teenager-specific Group Policies.
    It generates a deployment readiness score and go/no-go recommendation.

.PARAMETER DomainController
    Target domain controller for health checks.

.PARAMETER BackupLocation
    Path to verify GPO backup availability.

.PARAMETER LogPath
    Directory for output logs and reports.

.PARAMETER SkipPrompts
    Skip confirmation prompts for automated execution.

.EXAMPLE
    .\Run-FinalHealthCheck.ps1 -DomainController "DC01" -BackupLocation "\\FileServer\GPOBackups"

.NOTES
    Author: System Administrator
    Version: 1.0
    This is the final gate before deployment - ensure all checks pass!
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$DomainController = $env:LOGONSERVER.Replace('\\', ''),
    
    [Parameter(Mandatory = $false)]
    [string]$BackupLocation = "\\$env:COMPUTERNAME\GPOBackups",
    
    [Parameter(Mandatory = $false)]
    [string]$LogPath = ".\Logs\FinalHealthCheck",
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipPrompts
)

# Initialize script
$ErrorActionPreference = 'Stop'
$StartTime = Get-Date
$Script:TotalScore = 0
$Script:MaxScore = 0
$Script:CriticalFailures = @()
$Script:Warnings = @()
$Script:SuccessItems = @()

# Create log directory
if (-not (Test-Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
}

# Logging function
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    
    # Console output with color
    switch ($Level) {
        "ERROR"   { Write-Host $LogMessage -ForegroundColor Red }
        "WARNING" { Write-Host $LogMessage -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $LogMessage -ForegroundColor Green }
        "INFO"    { Write-Host $LogMessage -ForegroundColor Cyan }
        default   { Write-Host $LogMessage }
    }
    
    # File output
    $LogFile = Join-Path $LogPath "FinalHealthCheck_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $LogFile -Value $LogMessage
}

# Score tracking function
function Add-CheckResult {
    param(
        [string]$CheckName,
        [int]$MaxPoints,
        [int]$EarnedPoints,
        [bool]$IsCritical = $false,
        [string]$Details = ""
    )
    
    $Script:MaxScore += $MaxPoints
    $Script:TotalScore += $EarnedPoints
    
    if ($EarnedPoints -eq 0 -and $IsCritical) {
        $Script:CriticalFailures += @{
            Check = $CheckName
            Details = $Details
        }
        Write-Log "CRITICAL FAILURE: $CheckName - $Details" -Level ERROR
    }
    elseif ($EarnedPoints -lt $MaxPoints) {
        $Script:Warnings += @{
            Check = $CheckName
            Score = "$EarnedPoints/$MaxPoints"
            Details = $Details
        }
        Write-Log "WARNING: $CheckName scored $EarnedPoints/$MaxPoints - $Details" -Level WARNING
    }
    else {
        $Script:SuccessItems += $CheckName
        Write-Log "SUCCESS: $CheckName passed with full score" -Level SUCCESS
    }
}

Write-Log "=== FINAL DEPLOYMENT HEALTH CHECK INITIATED ===" -Level INFO
Write-Log "Domain Controller: $DomainController" -Level INFO
Write-Log "Backup Location: $BackupLocation" -Level INFO

# 1. Verify Domain and Forest Functional Levels
Write-Log "`nChecking domain and forest functional levels..." -Level INFO
try {
    $Domain = Get-ADDomain -Server $DomainController
    $Forest = Get-ADForest -Server $DomainController
    
    $MinLevel = [Microsoft.ActiveDirectory.Management.ADDomainMode]::Windows2012R2
    
    if ($Domain.DomainMode -ge $MinLevel -and $Forest.ForestMode -ge $MinLevel) {
        Add-CheckResult -CheckName "Domain/Forest Functional Level" -MaxPoints 10 -EarnedPoints 10
    }
    else {
        Add-CheckResult -CheckName "Domain/Forest Functional Level" -MaxPoints 10 -EarnedPoints 5 `
            -Details "Current levels: Domain=$($Domain.DomainMode), Forest=$($Forest.ForestMode)"
    }
}
catch {
    Add-CheckResult -CheckName "Domain/Forest Functional Level" -MaxPoints 10 -EarnedPoints 0 `
        -IsCritical $true -Details $_.Exception.Message
}

# 2. Verify Teenager Group Exists and Has Members
Write-Log "`nVerifying teenager security group..." -Level INFO
try {
    $TeenagerGroup = Get-ADGroup -Filter "Name -eq 'Teenagers'" -Server $DomainController
    if ($TeenagerGroup) {
        $Members = Get-ADGroupMember -Identity $TeenagerGroup -Server $DomainController
        if ($Members.Count -gt 0) {
            Add-CheckResult -CheckName "Teenager Group Configuration" -MaxPoints 15 -EarnedPoints 15
            Write-Log "Found $($Members.Count) members in Teenagers group" -Level INFO
        }
        else {
            Add-CheckResult -CheckName "Teenager Group Configuration" -MaxPoints 15 -EarnedPoints 10 `
                -Details "Group exists but has no members"
        }
    }
    else {
        Add-CheckResult -CheckName "Teenager Group Configuration" -MaxPoints 15 -EarnedPoints 0 `
            -IsCritical $true -Details "Teenagers security group not found"
    }
}
catch {
    Add-CheckResult -CheckName "Teenager Group Configuration" -MaxPoints 15 -EarnedPoints 0 `
        -IsCritical $true -Details $_.Exception.Message
}

# 3. Verify Teenager OU Structure
Write-Log "`nVerifying teenager OU structure..." -Level INFO
try {
    $RequiredOUs = @(
        "OU=Teenagers,DC=*",
        "OU=Computers,OU=Teenagers,DC=*",
        "OU=Users,OU=Teenagers,DC=*"
    )
    
    $OUCount = 0
    foreach ($OUPattern in $RequiredOUs) {
        $OU = Get-ADOrganizationalUnit -Filter * -Server $DomainController | 
              Where-Object { $_.DistinguishedName -like $OUPattern }
        if ($OU) { $OUCount++ }
    }
    
    if ($OUCount -eq $RequiredOUs.Count) {
        Add-CheckResult -CheckName "OU Structure" -MaxPoints 15 -EarnedPoints 15
    }
    else {
        Add-CheckResult -CheckName "OU Structure" -MaxPoints 15 -EarnedPoints (5 * $OUCount) `
            -IsCritical $true -Details "Only $OUCount of $($RequiredOUs.Count) required OUs found"
    }
}
catch {
    Add-CheckResult -CheckName "OU Structure" -MaxPoints 15 -EarnedPoints 0 `
        -IsCritical $true -Details $_.Exception.Message
}

# 4. Check GPO Backup Availability and Integrity
Write-Log "`nVerifying GPO backup availability..." -Level INFO
try {
    if (Test-Path $BackupLocation) {
        $Backups = Get-ChildItem -Path $BackupLocation -Directory
        if ($Backups.Count -gt 0) {
            # Check for recent backup (within 7 days)
            $RecentBackup = $Backups | Where-Object { $_.CreationTime -gt (Get-Date).AddDays(-7) }
            if ($RecentBackup) {
                Add-CheckResult -CheckName "GPO Backup Availability" -MaxPoints 20 -EarnedPoints 20
                Write-Log "Found $($Backups.Count) backups, $($RecentBackup.Count) are recent" -Level INFO
            }
            else {
                Add-CheckResult -CheckName "GPO Backup Availability" -MaxPoints 20 -EarnedPoints 15 `
                    -Details "Backups exist but none are recent (< 7 days old)"
            }
        }
        else {
            Add-CheckResult -CheckName "GPO Backup Availability" -MaxPoints 20 -EarnedPoints 0 `
                -IsCritical $true -Details "No GPO backups found"
        }
    }
    else {
        Add-CheckResult -CheckName "GPO Backup Availability" -MaxPoints 20 -EarnedPoints 0 `
            -IsCritical $true -Details "Backup location not accessible"
    }
}
catch {
    Add-CheckResult -CheckName "GPO Backup Availability" -MaxPoints 20 -EarnedPoints 0 `
        -IsCritical $true -Details $_.Exception.Message
}

# 5. Verify ADMX Templates Installation
Write-Log "`nVerifying ADMX template installation..." -Level INFO
try {
    $SysvolPath = "\\$DomainController\SYSVOL\$($Domain.DNSRoot)\Policies\PolicyDefinitions"
    
    if (Test-Path $SysvolPath) {
        $ADMXFiles = Get-ChildItem -Path $SysvolPath -Filter "*.admx" -File
        $ADMLFiles = Get-ChildItem -Path "$SysvolPath\en-US" -Filter "*.adml" -File -ErrorAction SilentlyContinue
        
        if ($ADMXFiles.Count -gt 20 -and $ADMLFiles.Count -gt 20) {
            Add-CheckResult -CheckName "ADMX Templates" -MaxPoints 10 -EarnedPoints 10
            Write-Log "Found $($ADMXFiles.Count) ADMX and $($ADMLFiles.Count) ADML files" -Level INFO
        }
        else {
            Add-CheckResult -CheckName "ADMX Templates" -MaxPoints 10 -EarnedPoints 5 `
                -Details "Limited ADMX templates found: $($ADMXFiles.Count) ADMX, $($ADMLFiles.Count) ADML"
        }
    }
    else {
        Add-CheckResult -CheckName "ADMX Templates" -MaxPoints 10 -EarnedPoints 0 `
            -IsCritical $true -Details "Central Store not found"
    }
}
catch {
    Add-CheckResult -CheckName "ADMX Templates" -MaxPoints 10 -EarnedPoints 0 `
        -Details $_.Exception.Message
}

# 6. Test SYSVOL Replication Health
Write-Log "`nTesting SYSVOL replication health..." -Level INFO
try {
    $TestFile = "SysvolTest_$(Get-Date -Format 'yyyyMMddHHmmss').txt"
    $TestPath = "\\$DomainController\SYSVOL\$($Domain.DNSRoot)\scripts\$TestFile"
    
    # Create test file
    "Replication test at $(Get-Date)" | Out-File -FilePath $TestPath -Force
    
    # Wait for replication
    Start-Sleep -Seconds 5
    
    # Check if file exists on all DCs
    $AllDCs = Get-ADDomainController -Filter * -Server $DomainController
    $ReplicationSuccess = $true
    
    foreach ($DC in $AllDCs) {
        $DCTestPath = "\\$($DC.HostName)\SYSVOL\$($Domain.DNSRoot)\scripts\$TestFile"
        if (-not (Test-Path $DCTestPath)) {
            $ReplicationSuccess = $false
            Write-Log "Replication failed to $($DC.HostName)" -Level WARNING
        }
    }
    
    # Cleanup
    Remove-Item -Path $TestPath -Force -ErrorAction SilentlyContinue
    
    if ($ReplicationSuccess) {
        Add-CheckResult -CheckName "SYSVOL Replication" -MaxPoints 15 -EarnedPoints 15
    }
    else {
        Add-CheckResult -CheckName "SYSVOL Replication" -MaxPoints 15 -EarnedPoints 8 `
            -Details "Replication delays detected on some domain controllers"
    }
}
catch {
    Add-CheckResult -CheckName "SYSVOL Replication" -MaxPoints 15 -EarnedPoints 0 `
        -IsCritical $true -Details $_.Exception.Message
}

# 7. Check for Policy Conflicts
Write-Log "`nChecking for policy conflicts..." -Level INFO
try {
    # Check for existing teenager-specific GPOs
    $ExistingGPOs = Get-GPO -All -Server $DomainController | 
                    Where-Object { $_.DisplayName -match "Teen|Youth|Student|Child" }
    
    if ($ExistingGPOs.Count -eq 0) {
        Add-CheckResult -CheckName "Policy Conflicts" -MaxPoints 15 -EarnedPoints 15
    }
    else {
        # Check if they're linked to teenager OUs
        $LinkedToTeenOU = $false
        foreach ($GPO in $ExistingGPOs) {
            $Links = Get-GPOReport -Guid $GPO.Id -ReportType Xml -Server $DomainController
            if ($Links -match "Teenagers") {
                $LinkedToTeenOU = $true
                break
            }
        }
        
        if ($LinkedToTeenOU) {
            Add-CheckResult -CheckName "Policy Conflicts" -MaxPoints 15 -EarnedPoints 0 `
                -IsCritical $true -Details "Found $($ExistingGPOs.Count) existing policies targeting teenagers"
        }
        else {
            Add-CheckResult -CheckName "Policy Conflicts" -MaxPoints 15 -EarnedPoints 10 `
                -Details "Found $($ExistingGPOs.Count) similar policies but not linked to teenager OUs"
        }
    }
}
catch {
    Add-CheckResult -CheckName "Policy Conflicts" -MaxPoints 15 -EarnedPoints 0 `
        -Details $_.Exception.Message
}

# 8. Verify Service Account Permissions
Write-Log "`nVerifying service account permissions..." -Level INFO
try {
    $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $IsAdmin = (New-Object Security.Principal.WindowsPrincipal $CurrentUser).IsInRole(
        [Security.Principal.WindowsBuiltinRole]::Administrator)
    
    if ($IsAdmin) {
        # Check for Group Policy management permissions
        $GPMgmt = Get-ADObject -Filter "objectClass -eq 'groupPolicyContainer'" -Server $DomainController -Properties nTSecurityDescriptor | 
                  Select-Object -First 1
        
        if ($GPMgmt) {
            Add-CheckResult -CheckName "Service Account Permissions" -MaxPoints 10 -EarnedPoints 10
        }
        else {
            Add-CheckResult -CheckName "Service Account Permissions" -MaxPoints 10 -EarnedPoints 5 `
                -Details "Limited Group Policy permissions detected"
        }
    }
    else {
        Add-CheckResult -CheckName "Service Account Permissions" -MaxPoints 10 -EarnedPoints 0 `
            -IsCritical $true -Details "Current user is not an administrator"
    }
}
catch {
    Add-CheckResult -CheckName "Service Account Permissions" -MaxPoints 10 -EarnedPoints 5 `
        -Details "Could not fully verify permissions"
}

# 9. Check Domain Controller Health
Write-Log "`nChecking domain controller health..." -Level INFO
try {
    $DCDiag = dcdiag /s:$DomainController /q 2>&1
    $FailedTests = $DCDiag | Where-Object { $_ -match "failed test" }
    
    if ($FailedTests.Count -eq 0) {
        Add-CheckResult -CheckName "Domain Controller Health" -MaxPoints 10 -EarnedPoints 10
    }
    else {
        Add-CheckResult -CheckName "Domain Controller Health" -MaxPoints 10 -EarnedPoints 5 `
            -Details "$($FailedTests.Count) DCDiag tests failed"
    }
}
catch {
    Add-CheckResult -CheckName "Domain Controller Health" -MaxPoints 10 -EarnedPoints 5 `
        -Details "Could not run full DCDiag tests"
}

# 10. Verify No Recent Critical Events
Write-Log "`nChecking for recent critical events..." -Level INFO
try {
    $CriticalEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'GP_System'
        Level = 2  # Error
        StartTime = (Get-Date).AddHours(-24)
    } -ComputerName $DomainController -ErrorAction SilentlyContinue |
    Where-Object { $_.ProviderName -match "GroupPolicy|NETLOGON|NTDS" }
    
    if ($CriticalEvents.Count -eq 0) {
        Add-CheckResult -CheckName "System Stability" -MaxPoints 10 -EarnedPoints 10
    }
    else {
        Add-CheckResult -CheckName "System Stability" -MaxPoints 10 -EarnedPoints 5 `
            -Details "Found $($CriticalEvents.Count) critical events in last 24 hours"
    }
}
catch {
    Add-CheckResult -CheckName "System Stability" -MaxPoints 10 -EarnedPoints 8 `
        -Details "Could not access all event logs"
}

# Calculate final score
$FinalScore = [math]::Round(($Script:TotalScore / $Script:MaxScore) * 100, 2)
$DeploymentReady = ($FinalScore -ge 85 -and $Script:CriticalFailures.Count -eq 0)

# Generate deployment checklist
$Checklist = @"
DEPLOYMENT READINESS CHECKLIST
==============================
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

OVERALL SCORE: $FinalScore% ($Script:TotalScore/$Script:MaxScore points)
DEPLOYMENT RECOMMENDATION: $(if ($DeploymentReady) { "GO" } else { "NO-GO" })

CRITICAL CHECKS:
"@

foreach ($Success in $Script:SuccessItems) {
    $Checklist += "`n[OK] $Success"
}

foreach ($Warning in $Script:Warnings) {
    $Checklist += "`n[!] $($Warning.Check) - Score: $($Warning.Score) - $($Warning.Details)"
}

foreach ($Failure in $Script:CriticalFailures) {
    $Checklist += "`n[X] $($Failure.Check) - $($Failure.Details)"
}

$Checklist += @"

DEPLOYMENT PREREQUISITES:
[$(if ($Domain.DomainMode -ge [Microsoft.ActiveDirectory.Management.ADDomainMode]::Windows2012R2) {'OK'} else {'X'})] Domain functional level 2012 R2 or higher
[$(if ($TeenagerGroup) {'OK'} else {'X'})] Teenagers security group exists
[$(if ($OUCount -eq 3) {'OK'} else {'X'})] All required OUs created
[$(if ((Get-ChildItem -Path $BackupLocation -Directory -ErrorAction SilentlyContinue).Count -gt 0) {'OK'} else {'X'})] GPO backups available
[$(if ($ADMXFiles.Count -gt 20) {'OK'} else {'X'})] ADMX templates installed
[$(if ($ReplicationSuccess) {'OK'} else {'X'})] SYSVOL replication healthy
[$(if ($ExistingGPOs.Count -eq 0) {'OK'} else {'X'})] No conflicting policies
[$(if ($IsAdmin) {'OK'} else {'X'})] Administrative permissions verified

RISK ASSESSMENT:
- Critical Failures: $($Script:CriticalFailures.Count)
- Warnings: $($Script:Warnings.Count)
- Success Items: $($Script:SuccessItems.Count)
"@

# Generate executive summary
$ExecutiveSummary = @"
EXECUTIVE SUMMARY - GROUP POLICY DEPLOYMENT READINESS
====================================================

Date: $(Get-Date -Format 'yyyy-MM-dd')
Assessment Duration: $([math]::Round(((Get-Date) - $StartTime).TotalMinutes, 2)) minutes

DEPLOYMENT RECOMMENDATION: $(if ($DeploymentReady) { "APPROVED FOR DEPLOYMENT" } else { "DEPLOYMENT NOT RECOMMENDED" })

Overall Readiness Score: $FinalScore%

KEY FINDINGS:
"@

if ($DeploymentReady) {
    $ExecutiveSummary += @"

[OK] All critical systems checks passed
[OK] Infrastructure is properly configured
[OK] Backup and recovery mechanisms are in place
[OK] No conflicts with existing policies detected
[OK] Target organizational units and groups are ready

The environment is fully prepared for teenager-specific Group Policy deployment.
Recommended next steps:
1. Schedule deployment during maintenance window
2. Deploy policies in staged approach (pilot group first)
3. Monitor policy application and user feedback
4. Be prepared to rollback if issues arise
"@
}
else {
    $ExecutiveSummary += @"

[X] Critical issues prevent safe deployment:
"@
    foreach ($Failure in $Script:CriticalFailures) {
        $ExecutiveSummary += "`n  - $($Failure.Check): $($Failure.Details)"
    }
    
    $ExecutiveSummary += @"

REQUIRED REMEDIATION:
1. Address all critical failures before proceeding
2. Resolve or document all warnings
3. Re-run health check after remediation
4. Do not proceed with deployment until score >= 85% with no critical failures

Proceeding with deployment in current state risks:
- Policy application failures
- Service disruptions
- Security vulnerabilities
- Inability to rollback changes
"@
}

$ExecutiveSummary += @"

TECHNICAL DETAILS:
- Domain: $($Domain.Name)
- Domain Controllers: $($AllDCs.Count)
- Target Group: Teenagers ($(if ($Members) { $Members.Count } else { 0 }) members)
- Backup Location: $BackupLocation
- Assessment Score: $Script:TotalScore/$Script:MaxScore points

Report Generated By: $($CurrentUser.Name)
"@

# Save reports
$ChecklistFile = Join-Path $LogPath "DeploymentChecklist_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$ExecutiveFile = Join-Path $LogPath "ExecutiveSummary_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$DetailedReport = Join-Path $LogPath "DetailedHealthCheck_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"

$Checklist | Out-File -FilePath $ChecklistFile -Encoding UTF8
$ExecutiveSummary | Out-File -FilePath $ExecutiveFile -Encoding UTF8

# Create detailed JSON report
$DetailedData = @{
    Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    FinalScore = $FinalScore
    DeploymentReady = $DeploymentReady
    CriticalFailures = $Script:CriticalFailures
    Warnings = $Script:Warnings
    SuccessItems = $Script:SuccessItems
    Domain = @{
        Name = $Domain.Name
        FunctionalLevel = $Domain.DomainMode.ToString()
        Controllers = $AllDCs.Count
    }
    Environment = @{
        TeenagerGroupExists = [bool]$TeenagerGroup
        TeenagerGroupMembers = if ($Members) { $Members.Count } else { 0 }
        RequiredOUsCreated = $OUCount
        BackupsAvailable = (Get-ChildItem -Path $BackupLocation -Directory -ErrorAction SilentlyContinue).Count
        ADMXTemplates = @{
            ADMX = $ADMXFiles.Count
            ADML = $ADMLFiles.Count
        }
    }
}

$DetailedData | ConvertTo-Json -Depth 10 | Out-File -FilePath $DetailedReport -Encoding UTF8

# Display summary
Write-Host "`n$('='*60)" -ForegroundColor Cyan
Write-Host "FINAL HEALTH CHECK COMPLETE" -ForegroundColor Cyan
Write-Host $('='*60) -ForegroundColor Cyan

Write-Host "`nDEPLOYMENT READINESS SCORE: " -NoNewline
if ($FinalScore -ge 85) {
    Write-Host "$FinalScore%" -ForegroundColor Green
}
elseif ($FinalScore -ge 70) {
    Write-Host "$FinalScore%" -ForegroundColor Yellow
}
else {
    Write-Host "$FinalScore%" -ForegroundColor Red
}

Write-Host "`nDEPLOYMENT RECOMMENDATION: " -NoNewline
if ($DeploymentReady) {
    Write-Host "GO" -ForegroundColor Green -BackgroundColor DarkGreen
    Write-Host "`nAll systems are GO for deployment!" -ForegroundColor Green
}
else {
    Write-Host "NO-GO" -ForegroundColor Red -BackgroundColor DarkRed
    Write-Host "`nDO NOT PROCEED with deployment!" -ForegroundColor Red
    Write-Host "Critical issues must be resolved first." -ForegroundColor Red
}

Write-Host "`nReports saved to:" -ForegroundColor Cyan
Write-Host "  - Checklist: $ChecklistFile" -ForegroundColor White
Write-Host "  - Executive Summary: $ExecutiveFile" -ForegroundColor White
Write-Host "  - Detailed Report: $DetailedReport" -ForegroundColor White

if (-not $SkipPrompts -and -not $DeploymentReady) {
    Write-Host "`nPress any key to view critical failures..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    
    Write-Host "`nCRITICAL FAILURES:" -ForegroundColor Red
    foreach ($Failure in $Script:CriticalFailures) {
        Write-Host "  - $($Failure.Check): $($Failure.Details)" -ForegroundColor Red
    }
}

# Return deployment readiness for automation
return @{
    DeploymentReady = $DeploymentReady
    Score = $FinalScore
    CriticalFailures = $Script:CriticalFailures.Count
    Warnings = $Script:Warnings.Count
}