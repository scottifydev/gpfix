#!/usr/bin/env pwsh
# smart-lint.ps1 - Intelligent PowerShell and GPO validation for Group Policy management
#
# SYNOPSIS
#   smart-lint.ps1 [options]
#
# DESCRIPTION
#   Automatically detects PowerShell scripts and GPO files and runs ALL quality checks.
#   Every issue found is blocking - code must be 100% clean to proceed.
#
# OPTIONS
#   -Debug        Enable debug output
#   -Fast         Skip slow checks (deep analysis, security scans)
#
# EXIT CODES
#   0 - Success (all checks passed - everything is ✅ GREEN)
#   1 - General error (missing dependencies, etc.)
#   2 - ANY issues found - ALL must be fixed
#
# CONFIGURATION
#   Project-specific overrides can be placed in .gpo-hooks-config.ps1

param(
    [switch]$Debug,
    [switch]$Fast
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

# Performance timing
function Start-Timing {
    if ($script:DebugMode) {
        return [System.Diagnostics.Stopwatch]::StartNew()
    }
}

function Stop-Timing {
    param($Stopwatch)
    if ($script:DebugMode -and $Stopwatch) {
        $Stopwatch.Stop()
        Write-DebugLog "Execution time: $($Stopwatch.ElapsedMilliseconds)ms"
    }
}

# Check if a command exists
function Test-Command {
    param([string]$Command)
    return $null -ne (Get-Command $Command -ErrorAction SilentlyContinue)
}

# ============================================================================
# ERROR TRACKING
# ============================================================================

$script:ErrorSummary = @()
$script:ErrorCount = 0

function Add-ValidationError {
    param([string]$Message)
    $script:ErrorCount++
    $script:ErrorSummary += "${RED}❌${NC} $Message"
}

function Show-Summary {
    if ($script:ErrorCount -gt 0) {
        Write-Host "`n${BLUE}═══ Summary ═══${NC}" -NoNewline:$false
        foreach ($item in $script:ErrorSummary) {
            Write-Host $item -NoNewline:$false
        }
        
        Write-Host "`n${RED}Found $($script:ErrorCount) issue(s) that MUST be fixed!${NC}" -NoNewline:$false
        Write-Host "${RED}════════════════════════════════════════════${NC}" -NoNewline:$false
        Write-Host "${RED}❌ ALL ISSUES ARE BLOCKING ❌${NC}" -NoNewline:$false
        Write-Host "${RED}════════════════════════════════════════════${NC}" -NoNewline:$false
        Write-Host "${RED}Fix EVERYTHING above until all checks are ✅ GREEN${NC}" -NoNewline:$false
    }
}

# ============================================================================
# CONFIGURATION LOADING
# ============================================================================

function Import-Configuration {
    # Default configuration
    $script:Config = @{
        Enabled = $true
        FailFast = $false
        ShowTiming = $false
        PSScriptAnalyzer = @{
            Enabled = $true
            Rules = @('PSAvoidUsingWriteHost', 'PSAvoidUsingCmdletAliases', 
                     'PSAvoidUsingPositionalParameters', 'PSUseShouldProcessForStateChangingFunctions',
                     'PSAvoidUsingPlainTextForPassword', 'PSAvoidUsingConvertToSecureStringWithPlainText')
        }
        ForbiddenPatterns = @{
            Enabled = $true
            Patterns = @(
                @{Pattern = 'password\s*=\s*["\''`]'; Description = "Hardcoded password detected"},
                @{Pattern = 'Set-ItemProperty.*HKLM:\\'; Description = "Direct registry edit without GPO context"},
                @{Pattern = 'New-ItemProperty.*HKLM:\\'; Description = "Direct registry creation without GPO context"},
                @{Pattern = 'Remove-ItemProperty.*HKLM:\\'; Description = "Direct registry deletion without GPO context"},
                @{Pattern = '\$cred.*Get-Credential.*-Credential'; Description = "Credential handling needs review"},
                @{Pattern = 'ConvertTo-SecureString.*-AsPlainText'; Description = "Plain text to secure string conversion"}
            )
        }
        NamingConventions = @{
            Enabled = $true
            GPOPrefix = "GP_"
            ScriptPrefix = @("Deploy-", "Test-", "Get-", "Set-", "Remove-", "New-", "Update-")
        }
    }
    
    # Load project-specific overrides
    $configFile = ".gpo-hooks-config.ps1"
    if (Test-Path $configFile) {
        try {
            . $configFile
        }
        catch {
            Write-ErrorLog "Failed to load ${configFile}: $_"
            exit 2
        }
    }
    
    # Quick exit if hooks are disabled
    if (-not $script:Config.Enabled) {
        Write-InfoLog "GPO hooks are disabled"
        exit 0
    }
}

# ============================================================================
# POWERSHELL SCRIPT VALIDATION
# ============================================================================

function Test-PowerShellSyntax {
    param([string]$FilePath)
    
    Write-DebugLog "Checking PowerShell syntax for: $FilePath"
    
    try {
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($FilePath, [ref]$tokens, [ref]$errors)
        
        if ($errors.Count -gt 0) {
            Add-ValidationError "PowerShell syntax errors in $FilePath"
            foreach ($error in $errors) {
                Write-Host "  Line $($error.Extent.StartLineNumber): $($error.Message)" -ForegroundColor Red
            }
            return $false
        }
        
        return $true
    }
    catch {
        Add-ValidationError "Failed to parse ${FilePath}: $_"
        return $false
    }
}

function Test-PSScriptAnalyzer {
    param([string]$FilePath)
    
    if (-not $script:Config.PSScriptAnalyzer.Enabled) {
        Write-DebugLog "PSScriptAnalyzer disabled"
        return $true
    }
    
    if (-not (Test-Command "Invoke-ScriptAnalyzer")) {
        Write-InfoLog "PSScriptAnalyzer not installed - skipping advanced analysis"
        Write-InfoLog "Install with: Install-Module -Name PSScriptAnalyzer -Force"
        return $true
    }
    
    Write-DebugLog "Running PSScriptAnalyzer on: $FilePath"
    
    try {
        $results = Invoke-ScriptAnalyzer -Path $FilePath -Severity @('Error', 'Warning') -ErrorAction SilentlyContinue
        
        if ($results) {
            Add-ValidationError "PSScriptAnalyzer found issues in $FilePath"
            foreach ($result in $results) {
                $severity = if ($result.Severity -eq 'Error') { $RED } else { $YELLOW }
                Write-Host "  ${severity}[$($result.Severity)]${NC} Line $($result.Line): $($result.RuleName) - $($result.Message)" -NoNewline:$false
            }
            return $false
        }
        
        return $true
    }
    catch {
        Write-DebugLog "PSScriptAnalyzer error: $_"
        return $true
    }
}

function Test-ForbiddenPatterns {
    param([string]$FilePath)
    
    if (-not $script:Config.ForbiddenPatterns.Enabled) {
        Write-DebugLog "Forbidden pattern checking disabled"
        return $true
    }
    
    Write-DebugLog "Checking forbidden patterns in: $FilePath"
    
    $content = Get-Content -Path $FilePath -Raw
    $foundIssues = $false
    
    foreach ($pattern in $script:Config.ForbiddenPatterns.Patterns) {
        if ($content -match $pattern.Pattern) {
            if (-not $foundIssues) {
                Add-ValidationError "Forbidden patterns found in $FilePath"
                $foundIssues = $true
            }
            
            # Find line numbers
            $lines = $content -split "`n"
            for ($i = 0; $i -lt $lines.Count; $i++) {
                if ($lines[$i] -match $pattern.Pattern) {
                    Write-Host "  Line $($i + 1): $($pattern.Description)" -ForegroundColor Red
                }
            }
        }
    }
    
    return -not $foundIssues
}

function Test-ErrorHandling {
    param([string]$FilePath)
    
    Write-DebugLog "Checking error handling in: $FilePath"
    
    $content = Get-Content -Path $FilePath -Raw
    
    # Check for try-catch blocks in functions that modify state
    $stateChangingPatterns = @(
        'Set-GPRegistryValue',
        'Set-GPPermission',
        'New-GPO',
        'Remove-GPO',
        'Set-ItemProperty',
        'New-ItemProperty'
    )
    
    $foundIssues = $false
    
    foreach ($pattern in $stateChangingPatterns) {
        # Skip if this is just a string literal or pattern definition
        if ($content -match "['\`"`"]$pattern['\`"`"]" -or $content -match "@.*$pattern.*Pattern") {
            continue
        }
        
        # Skip Test-CodebaseIntegrity.ps1 as it only contains pattern strings for validation
        if ($FilePath -like "*Test-CodebaseIntegrity.ps1") {
            continue
        }
        
        if ($content -match $pattern -and $content -notmatch "try\s*{[^}]*$pattern") {
            if (-not $foundIssues) {
                Add-ValidationError "Missing error handling in $FilePath"
                $foundIssues = $true
            }
            Write-Host "  State-changing command '$pattern' used without try-catch block" -ForegroundColor Red
        }
    }
    
    return -not $foundIssues
}

function Test-NamingConventions {
    param([string]$FilePath)
    
    if (-not $script:Config.NamingConventions.Enabled) {
        Write-DebugLog "Naming convention checking disabled"
        return $true
    }
    
    Write-DebugLog "Checking naming conventions in: $FilePath"
    
    $fileName = Split-Path -Leaf $FilePath
    $validPrefix = $false
    
    foreach ($prefix in $script:Config.NamingConventions.ScriptPrefix) {
        if ($fileName -like "$prefix*") {
            $validPrefix = $true
            break
        }
    }
    
    if (-not $validPrefix) {
        Add-ValidationError "Script name '$fileName' doesn't follow naming conventions"
        Write-Host "  Expected prefixes: $($script:Config.NamingConventions.ScriptPrefix -join ', ')" -ForegroundColor Yellow
        return $false
    }
    
    # Check GPO naming in script content
    $content = Get-Content -Path $FilePath -Raw
    
    # More specific patterns for actual GPO operations
    $gpoPatterns = @(
        # New-GPO -Name "something"
        'New-GPO\s+.*-Name\s+["\''`]([^"\''`]+)["\''`]',
        # Get-GPO -Name "something"
        'Get-GPO\s+.*-Name\s+["\''`]([^"\''`]+)["\''`]',
        # Remove-GPO -Name "something"
        'Remove-GPO\s+.*-Name\s+["\''`]([^"\''`]+)["\''`]',
        # Set-GPLink ... -Name "something"
        'Set-GPLink\s+.*-Name\s+["\''`]([^"\''`]+)["\''`]',
        # New-GPLink ... -Name "something"
        'New-GPLink\s+.*-Name\s+["\''`]([^"\''`]+)["\''`]',
        # $GPOName = "something" or $gpoName = "something"
        '\$\w*GPO\w*Name\s*=\s*["\''`]([^"\''`]+)["\''`]',
        # -GPOName "something" parameter (but not variables like "$GPOName")
        '-GPOName\s+["\''`]([^"\''`$]+)["\''`]'
    )
    
    $foundNamingIssues = $false
    foreach ($pattern in $gpoPatterns) {
        $matches = [regex]::Matches($content, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        
        foreach ($match in $matches) {
            $gpoName = $match.Groups[1].Value
            # Skip if this is already using the prefix
            if ($gpoName -notlike "$($script:Config.NamingConventions.GPOPrefix)*") {
                if (-not $foundNamingIssues) {
                    Add-ValidationError "GPO naming convention violations in $FilePath"
                    $foundNamingIssues = $true
                }
                
                # Find line number for better error reporting
                $lines = $content -split "`n"
                for ($i = 0; $i -lt $lines.Count; $i++) {
                    if ($lines[$i] -match [regex]::Escape($match.Value)) {
                        Write-Host "  Line $($i + 1): GPO name '$gpoName' should start with '$($script:Config.NamingConventions.GPOPrefix)'" -ForegroundColor Yellow
                        break
                    }
                }
            }
        }
    }
    
    return -not $foundNamingIssues
}

function Test-PowerShellScript {
    param([string]$FilePath)
    
    Write-InfoLog "Validating PowerShell script: $FilePath"
    
    $allPassed = $true
    
    # Syntax check
    if (-not (Test-PowerShellSyntax -FilePath $FilePath)) {
        $allPassed = $false
    }
    
    # PSScriptAnalyzer
    if (-not (Test-PSScriptAnalyzer -FilePath $FilePath)) {
        $allPassed = $false
    }
    
    # Forbidden patterns
    if (-not (Test-ForbiddenPatterns -FilePath $FilePath)) {
        $allPassed = $false
    }
    
    # Error handling
    if (-not (Test-ErrorHandling -FilePath $FilePath)) {
        $allPassed = $false
    }
    
    # Naming conventions
    if (-not (Test-NamingConventions -FilePath $FilePath)) {
        $allPassed = $false
    }
    
    if ($allPassed) {
        Write-SuccessLog "PowerShell script validation passed: $FilePath"
    }
    
    return $allPassed
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

# Print header
Write-Host "" -NoNewline:$false
Write-Host "🔍 Smart Lint - Validating PowerShell scripts and GPO configuration..." -NoNewline:$false
Write-Host "────────────────────────────────────────────────────────────────────────" -NoNewline:$false

# Load configuration
Import-Configuration

# Start timing
$stopwatch = Start-Timing

# Find all PowerShell scripts
Write-InfoLog "Scanning for PowerShell scripts..."

$psFiles = Get-ChildItem -Path . -Recurse -Include "*.ps1", "*.psm1", "*.psd1" -File | 
    Where-Object { $_.FullName -notmatch "\\(\.git|node_modules|temp_claude_repo|hooks)\\" -and $_.FullName -notmatch "/(\.git|node_modules|temp_claude_repo|hooks)/" }

if ($psFiles.Count -eq 0) {
    Write-InfoLog "No PowerShell scripts found to validate"
}
else {
    Write-InfoLog "Found $($psFiles.Count) PowerShell script(s) to validate"
    
    foreach ($file in $psFiles) {
        Test-PowerShellScript -FilePath $file.FullName
        
        # Fail fast if configured
        if ($script:Config.FailFast -and $script:ErrorCount -gt 0) {
            break
        }
    }
}

# Stop timing
Stop-Timing -Stopwatch $stopwatch

# Print summary
Show-Summary

# Final message and exit
if ($script:ErrorCount -gt 0) {
    Write-Host "`n${RED}🛑 FAILED - Fix all issues above! 🛑${NC}" -NoNewline:$false
    Write-Host "${YELLOW}📋 NEXT STEPS:${NC}" -NoNewline:$false
    Write-Host "${YELLOW}  1. Fix the issues listed above${NC}" -NoNewline:$false
    Write-Host "${YELLOW}  2. Verify the fix by running: .\hooks\smart-lint.ps1${NC}" -NoNewline:$false
    Write-Host "${YELLOW}  3. Continue with your original task${NC}" -NoNewline:$false
    exit 2
}
else {
    Write-Host "`n${GREEN}✅ All PowerShell validation checks passed!${NC}" -NoNewline:$false
    Write-Host "${YELLOW}👉 Style clean. Continue with your task.${NC}" -NoNewline:$false
    exit 0
}