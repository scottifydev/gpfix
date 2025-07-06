#!/usr/bin/env pwsh
# pre-deployment-check.ps1 - Comprehensive pre-deployment validation for Group Policy changes
#
# SYNOPSIS
#   pre-deployment-check.ps1 [options]
#
# DESCRIPTION
#   Runs all validation scripts, checks backup availability, verifies test environment,
#   and confirms rollback procedures exist before GPO deployment.
#
# OPTIONS
#   -Debug            Enable debug output
#   -SkipBackup       Skip backup verification (NOT RECOMMENDED)
#   -SkipTestEnv      Skip test environment check (NOT RECOMMENDED)
#   -Force            Bypass safety checks (DANGEROUS)
#
# EXIT CODES
#   0 - Success (all checks passed - ready for deployment)
#   1 - General error (missing dependencies, etc.)
#   2 - ANY issues found - deployment should be blocked

param(
    [switch]$Debug,
    [switch]$SkipBackup,
    [switch]$SkipTestEnv,
    [switch]$Force
)

# Don't use strict mode for controlled error handling
$ErrorActionPreference = "Continue"

# ============================================================================
# COLOR DEFINITIONS AND UTILITIES
# ============================================================================

$RED = "`e[0;31m"
$GREEN = "`e[0;32m"
$YELLOW = "`e[0;33m"
$BLUE = "`e[0;34m"
$CYAN = "`e[0;36m"
$MAGENTA = "`e[0;35m"
$NC = "`e[0m" # No Color

# Debug mode
$script:DebugMode = $Debug -or ($env:GPO_HOOKS_DEBUG -eq "1")

# Logging functions
function Write-DebugLog {
    param([string]$Message)
    if ($script:DebugMode) {
        Write-Host "${CYAN}[DEBUG]${NC} $Message" -NoNewline:$false
    }
}

function Write-InfoLog {
    param([string]$Message)
    Write-Host "${BLUE}[INFO]${NC} $Message" -NoNewline:$false
}

function Write-ErrorLog {
    param([string]$Message)
    Write-Host "${RED}[ERROR]${NC} $Message" -NoNewline:$false
}

function Write-SuccessLog {
    param([string]$Message)
    Write-Host "${GREEN}[OK]${NC} $Message" -NoNewline:$false
}

function Write-WarningLog {
    param([string]$Message)
    Write-Host "${YELLOW}[WARN]${NC} $Message" -NoNewline:$false
}

function Write-CriticalLog {
    param([string]$Message)
    Write-Host "${MAGENTA}[CRITICAL]${NC} $Message" -NoNewline:$false
}

# ============================================================================
# CHECK TRACKING
# ============================================================================

$script:CheckResults = @{
    CodeValidation = @{ Status = "Not Run"; Issues = @() }
    GPOValidation = @{ Status = "Not Run"; Issues = @() }
    BackupVerification = @{ Status = "Not Run"; Issues = @() }
    TestEnvironment = @{ Status = "Not Run"; Issues = @() }
    RollbackProcedures = @{ Status = "Not Run"; Issues = @() }
    DomainController = @{ Status = "Not Run"; Issues = @() }
}

$script:CriticalIssues = 0
$script:Warnings = 0

function Update-CheckStatus {
    param(
        [string]$Check,
        [string]$Status,
        [string[]]$Issues = @()
    )
    
    $script:CheckResults[$Check].Status = $Status
    $script:CheckResults[$Check].Issues = $Issues
    
    if ($Status -eq "Failed") {
        $script:CriticalIssues += $Issues.Count
    }
    elseif ($Status -eq "Warning") {
        $script:Warnings += $Issues.Count
    }
}

function Show-DeploymentSummary {
    Write-Host "`n${BLUE}═══════════════════════════════════════════════════════${NC}" -NoNewline:$false
    Write-Host "${BLUE}           PRE-DEPLOYMENT CHECK SUMMARY                 ${NC}" -NoNewline:$false
    Write-Host "${BLUE}═══════════════════════════════════════════════════════${NC}" -NoNewline:$false
    
    foreach ($check in $script:CheckResults.Keys) {
        $result = $script:CheckResults[$check]
        $statusIcon = switch ($result.Status) {
            "Passed" { "${GREEN}✅${NC}" }
            "Warning" { "${YELLOW}⚠${NC}" }
            "Failed" { "${RED}❌${NC}" }
            "Skipped" { "${CYAN}⏭${NC}" }
            default { "${CYAN}❓${NC}" }
        }
        
        Write-Host "$statusIcon $check : $($result.Status)" -NoNewline:$false
        
        if ($result.Issues.Count -gt 0) {
            foreach ($issue in $result.Issues) {
                Write-Host "   └─ $issue" -NoNewline:$false
            }
        }
    }
    
    Write-Host "`n${BLUE}═══════════════════════════════════════════════════════${NC}" -NoNewline:$false
    
    if ($script:CriticalIssues -gt 0) {
        Write-Host "${RED}DEPLOYMENT READINESS: NOT READY${NC}" -NoNewline:$false
        Write-Host "${RED}Critical Issues: $($script:CriticalIssues)${NC}" -NoNewline:$false
        Write-Host "${RED}════════════════════════════════════════════${NC}" -NoNewline:$false
        Write-Host "${RED}❌ DO NOT PROCEED WITH DEPLOYMENT ❌${NC}" -NoNewline:$false
        Write-Host "${RED}════════════════════════════════════════════${NC}" -NoNewline:$false
    }
    elseif ($script:Warnings -gt 0) {
        Write-Host "${YELLOW}DEPLOYMENT READINESS: PROCEED WITH CAUTION${NC}" -NoNewline:$false
        Write-Host "${YELLOW}Warnings: $($script:Warnings)${NC}" -NoNewline:$false
        Write-Host "${YELLOW}Review warnings before proceeding${NC}" -NoNewline:$false
    }
    else {
        Write-Host "${GREEN}DEPLOYMENT READINESS: READY${NC}" -NoNewline:$false
        Write-Host "${GREEN}✅ All checks passed - Safe to deploy${NC}" -NoNewline:$false
    }
}

# ============================================================================
# VALIDATION SCRIPT EXECUTION
# ============================================================================

function Invoke-CodeValidation {
    Write-InfoLog "Running PowerShell code validation..."
    
    $scriptPath = Join-Path $PSScriptRoot "smart-lint.ps1"
    if (-not (Test-Path $scriptPath)) {
        Update-CheckStatus -Check "CodeValidation" -Status "Failed" `
            -Issues @("smart-lint.ps1 not found in hooks directory")
        return $false
    }
    
    try {
        $result = & $scriptPath
        if ($LASTEXITCODE -eq 0) {
            Update-CheckStatus -Check "CodeValidation" -Status "Passed"
            return $true
        }
        else {
            Update-CheckStatus -Check "CodeValidation" -Status "Failed" `
                -Issues @("Code validation failed with exit code: $LASTEXITCODE")
            return $false
        }
    }
    catch {
        Update-CheckStatus -Check "CodeValidation" -Status "Failed" `
            -Issues @("Error running code validation: $_")
        return $false
    }
}

function Invoke-GPOValidation {
    Write-InfoLog "Running GPO validation..."
    
    $scriptPath = Join-Path $PSScriptRoot "validate-gpo.ps1"
    if (-not (Test-Path $scriptPath)) {
        Update-CheckStatus -Check "GPOValidation" -Status "Failed" `
            -Issues @("validate-gpo.ps1 not found in hooks directory")
        return $false
    }
    
    try {
        $result = & $scriptPath
        if ($LASTEXITCODE -eq 0) {
            Update-CheckStatus -Check "GPOValidation" -Status "Passed"
            return $true
        }
        else {
            Update-CheckStatus -Check "GPOValidation" -Status "Failed" `
                -Issues @("GPO validation failed with exit code: $LASTEXITCODE")
            return $false
        }
    }
    catch {
        Update-CheckStatus -Check "GPOValidation" -Status "Failed" `
            -Issues @("Error running GPO validation: $_")
        return $false
    }
}

# ============================================================================
# BACKUP VERIFICATION
# ============================================================================

function Test-BackupAvailability {
    if ($SkipBackup) {
        Update-CheckStatus -Check "BackupVerification" -Status "Skipped" `
            -Issues @("Backup verification skipped by user")
        return $true
    }
    
    Write-InfoLog "Verifying backup availability..."
    
    $issues = @()
    
    # Check for backup script
    $backupScript = Get-ChildItem -Path .. -Recurse -Filter "*Backup*.ps1" | 
        Where-Object { $_.Name -match "Backup|backup" } | 
        Select-Object -First 1
    
    if (-not $backupScript) {
        $issues += "No backup script found"
    }
    else {
        Write-DebugLog "Found backup script: $($backupScript.FullName)"
    }
    
    # Check for recent backups
    $backupDirs = @(
        ".\Backups",
        "..\Backups",
        "$env:TEMP\GPOBackups",
        "$env:USERPROFILE\Documents\GPOBackups"
    )
    
    $recentBackup = $false
    foreach ($dir in $backupDirs) {
        if (Test-Path $dir) {
            $latestBackup = Get-ChildItem -Path $dir -Directory | 
                Sort-Object CreationTime -Descending | 
                Select-Object -First 1
            
            if ($latestBackup -and $latestBackup.CreationTime -gt (Get-Date).AddDays(-7)) {
                $recentBackup = $true
                Write-DebugLog "Found recent backup: $($latestBackup.FullName)"
                break
            }
        }
    }
    
    if (-not $recentBackup) {
        $issues += "No recent backup found (within 7 days)"
    }
    
    # Check for backup documentation
    $backupDocs = Get-ChildItem -Path .. -Recurse -Include "*backup*.md", "*backup*.txt", "*recovery*.md" |
        Select-Object -First 1
    
    if (-not $backupDocs) {
        $issues += "No backup/recovery documentation found"
    }
    
    if ($issues.Count -eq 0) {
        Update-CheckStatus -Check "BackupVerification" -Status "Passed"
        return $true
    }
    else {
        Update-CheckStatus -Check "BackupVerification" -Status "Warning" -Issues $issues
        return $false
    }
}

# ============================================================================
# TEST ENVIRONMENT VERIFICATION
# ============================================================================

function Test-TestEnvironment {
    if ($SkipTestEnv) {
        Update-CheckStatus -Check "TestEnvironment" -Status "Skipped" `
            -Issues @("Test environment check skipped by user")
        return $true
    }
    
    Write-InfoLog "Verifying test environment..."
    
    $issues = @()
    
    # Check for test OU references
    $testOUs = @("Test", "Testing", "Pilot", "Staging")
    $foundTestOU = $false
    
    $scripts = Get-ChildItem -Path .. -Recurse -Filter "*.ps1"
    foreach ($script in $scripts) {
        $content = Get-Content -Path $script.FullName -Raw
        foreach ($ou in $testOUs) {
            if ($content -match "OU=$ou" -or $content -match "$ou.*OU") {
                $foundTestOU = $true
                Write-DebugLog "Found test OU reference in: $($script.Name)"
                break
            }
        }
        if ($foundTestOU) { break }
    }
    
    if (-not $foundTestOU) {
        $issues += "No test OU references found in scripts"
    }
    
    # Check for test documentation
    $testDocs = Get-ChildItem -Path .. -Recurse -Include "*test*.md", "*pilot*.md", "*staging*.md" |
        Where-Object { $_.Name -notmatch "Test-.*\.ps1" } |
        Select-Object -First 1
    
    if (-not $testDocs) {
        $issues += "No test procedure documentation found"
    }
    
    # Check for test validation scripts
    $testScripts = Get-ChildItem -Path .. -Recurse -Filter "Test-*.ps1"
    if ($testScripts.Count -eq 0) {
        $issues += "No test validation scripts found"
    }
    
    if ($issues.Count -eq 0) {
        Update-CheckStatus -Check "TestEnvironment" -Status "Passed"
        return $true
    }
    else {
        Update-CheckStatus -Check "TestEnvironment" -Status "Warning" -Issues $issues
        return $false
    }
}

# ============================================================================
# ROLLBACK PROCEDURES
# ============================================================================

function Test-RollbackProcedures {
    Write-InfoLog "Verifying rollback procedures..."
    
    $issues = @()
    
    # Check for rollback scripts
    $rollbackScripts = Get-ChildItem -Path .. -Recurse -Filter "*" |
        Where-Object { $_.Name -match "Rollback|rollback|Restore|restore|Remove|remove" -and $_.Extension -eq ".ps1" }
    
    if ($rollbackScripts.Count -eq 0) {
        $issues += "No rollback/restore scripts found"
    }
    else {
        Write-DebugLog "Found $($rollbackScripts.Count) rollback script(s)"
        
        # Verify rollback scripts have error handling
        foreach ($script in $rollbackScripts) {
            $content = Get-Content -Path $script.FullName -Raw
            if ($content -notmatch "try\s*{" -and $content -notmatch "-ErrorAction") {
                $issues += "$($script.Name) lacks proper error handling"
            }
        }
    }
    
    # Check for rollback documentation
    $rollbackDocs = Get-ChildItem -Path .. -Recurse -Include "*rollback*.md", "*recovery*.md", "*restore*.md" |
        Select-Object -First 1
    
    if (-not $rollbackDocs) {
        $issues += "No rollback procedure documentation found"
    }
    
    # Check for GPO versioning
    $gpoFiles = Get-ChildItem -Path .. -Recurse -Include "*.xml", "*.pol" |
        Where-Object { $_.FullName -match "\\(Policies|Templates|GPO|GroupPolicy)\\" }
    
    $versionedGPOs = $gpoFiles | Where-Object { $_.Name -match "v\d+|backup|\d{8}" }
    
    if ($gpoFiles.Count -gt 0 -and $versionedGPOs.Count -eq 0) {
        $issues += "No GPO versioning detected"
    }
    
    if ($issues.Count -eq 0) {
        Update-CheckStatus -Check "RollbackProcedures" -Status "Passed"
        return $true
    }
    else {
        Update-CheckStatus -Check "RollbackProcedures" -Status "Warning" -Issues $issues
        return $false
    }
}

# ============================================================================
# DOMAIN CONTROLLER CHECKS
# ============================================================================

function Test-DomainControllerReadiness {
    Write-InfoLog "Checking domain controller readiness..."
    
    $issues = @()
    
    # Check if we can import GroupPolicy module
    try {
        Import-Module GroupPolicy -ErrorAction Stop
        Write-DebugLog "GroupPolicy module loaded successfully"
    }
    catch {
        $issues += "GroupPolicy PowerShell module not available"
        Update-CheckStatus -Check "DomainController" -Status "Warning" -Issues $issues
        return $false
    }
    
    # Check for DC connectivity script
    $dcCheckScript = Get-ChildItem -Path .. -Recurse -Filter "*" |
        Where-Object { $_.Name -match "Check.*DC|Domain.*Controller|DC.*Health" -and $_.Extension -eq ".ps1" } |
        Select-Object -First 1
    
    if ($dcCheckScript) {
        Write-DebugLog "Found DC check script: $($dcCheckScript.Name)"
        
        # Try to run it if not in Force mode
        if (-not $Force) {
            try {
                Write-InfoLog "Running DC health check..."
                $dcResult = & $dcCheckScript.FullName
                if ($LASTEXITCODE -ne 0) {
                    $issues += "DC health check reported issues"
                }
            }
            catch {
                $issues += "Failed to run DC health check: $_"
            }
        }
    }
    else {
        $issues += "No DC health check script found"
    }
    
    # Check for SYSVOL replication monitoring
    $sysvolCheck = Get-ChildItem -Path .. -Recurse -Filter "*.ps1" |
        Where-Object { (Get-Content $_.FullName -Raw) -match "SYSVOL|Replication|DFS" } |
        Select-Object -First 1
    
    if (-not $sysvolCheck) {
        $issues += "No SYSVOL replication check found"
    }
    
    if ($issues.Count -eq 0) {
        Update-CheckStatus -Check "DomainController" -Status "Passed"
        return $true
    }
    else {
        Update-CheckStatus -Check "DomainController" -Status "Warning" -Issues $issues
        return $false
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

# Print header
Write-Host "" -NoNewline:$false
Write-Host "${BLUE}╔══════════════════════════════════════════════════════╗${NC}" -NoNewline:$false
Write-Host "${BLUE}║        PRE-DEPLOYMENT CHECK FOR GROUP POLICY         ║${NC}" -NoNewline:$false
Write-Host "${BLUE}╚══════════════════════════════════════════════════════╝${NC}" -NoNewline:$false
Write-Host "" -NoNewline:$false

if ($Force) {
    Write-WarningLog "Running in FORCE mode - some safety checks bypassed!"
}

# Run all checks
$allPassed = $true

# 1. Code Validation
if (-not (Invoke-CodeValidation)) {
    $allPassed = $false
    if (-not $Force) {
        Write-CriticalLog "Code validation failed - stopping checks"
        Show-DeploymentSummary
        exit 2
    }
}

# 2. GPO Validation
if (-not (Invoke-GPOValidation)) {
    $allPassed = $false
    if (-not $Force) {
        Write-CriticalLog "GPO validation failed - stopping checks"
        Show-DeploymentSummary
        exit 2
    }
}

# 3. Backup Verification
if (-not (Test-BackupAvailability)) {
    $allPassed = $false
}

# 4. Test Environment
if (-not (Test-TestEnvironment)) {
    $allPassed = $false
}

# 5. Rollback Procedures
if (-not (Test-RollbackProcedures)) {
    $allPassed = $false
}

# 6. Domain Controller Readiness
if (-not (Test-DomainControllerReadiness)) {
    $allPassed = $false
}

# Show final summary
Show-DeploymentSummary

# Deployment checklist
if ($script:CriticalIssues -eq 0) {
    Write-Host "`n${YELLOW}📋 DEPLOYMENT CHECKLIST:${NC}" -NoNewline:$false
    Write-Host "${YELLOW}  ✓ Create fresh backup before deployment${NC}" -NoNewline:$false
    Write-Host "${YELLOW}  ✓ Deploy to test OU first${NC}" -NoNewline:$false
    Write-Host "${YELLOW}  ✓ Monitor SYSVOL replication${NC}" -NoNewline:$false
    Write-Host "${YELLOW}  ✓ Test with pilot users${NC}" -NoNewline:$false
    Write-Host "${YELLOW}  ✓ Have rollback plan ready${NC}" -NoNewline:$false
    Write-Host "${YELLOW}  ✓ Schedule deployment during maintenance window${NC}" -NoNewline:$false
}

# Exit based on results
if ($script:CriticalIssues -gt 0) {
    exit 2
}
elseif ($script:Warnings -gt 0 -and -not $Force) {
    Write-Host "`n${YELLOW}Use -Force to proceed despite warnings${NC}" -NoNewline:$false
    exit 2
}
else {
    exit 0
}