#!/usr/bin/env pwsh
# validate-gpo.ps1 - Group Policy Object validation and conflict detection
#
# SYNOPSIS
#   validate-gpo.ps1 [options]
#
# DESCRIPTION
#   Validates GPO XML syntax, checks for policy conflicts, verifies ADMX templates,
#   and ensures GPO best practices are followed.
#
# OPTIONS
#   -Debug        Enable debug output
#   -GPOPath      Path to specific GPO file/directory to validate
#   -SkipADMX     Skip ADMX template validation
#
# EXIT CODES
#   0 - Success (all checks passed - everything is ✅ GREEN)
#   1 - General error (missing dependencies, etc.)
#   2 - ANY issues found - ALL must be fixed

param(
    [switch]$Debug,
    [string]$GPOPath,
    [switch]$SkipADMX
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

function Write-WarningLog {
    param([string]$Message)
    Write-Host "${YELLOW}[WARN]${NC} $Message" -NoNewline:$false
}

# ============================================================================
# ERROR TRACKING
# ============================================================================

$script:ErrorSummary = @()
$script:ErrorCount = 0
$script:PolicyConflicts = @()

function Add-ValidationError {
    param([string]$Message)
    $script:ErrorCount++
    $script:ErrorSummary += "${RED}❌${NC} $Message"
}

function Add-PolicyConflict {
    param(
        [string]$Policy1,
        [string]$Policy2,
        [string]$Description
    )
    $script:PolicyConflicts += @{
        Policy1 = $Policy1
        Policy2 = $Policy2
        Description = $Description
    }
    Add-ValidationError "Policy conflict: $Description"
}

function Show-Summary {
    if ($script:ErrorCount -gt 0) {
        Write-Host "`n${BLUE}═══ Validation Summary ═══${NC}" -NoNewline:$false
        foreach ($item in $script:ErrorSummary) {
            Write-Host $item -NoNewline:$false
        }
        
        if ($script:PolicyConflicts.Count -gt 0) {
            Write-Host "`n${YELLOW}═══ Policy Conflicts ═══${NC}" -NoNewline:$false
            foreach ($conflict in $script:PolicyConflicts) {
                Write-Host "  ${YELLOW}⚠${NC} $($conflict.Policy1) conflicts with $($conflict.Policy2)" -NoNewline:$false
                Write-Host "    $($conflict.Description)" -NoNewline:$false
            }
        }
        
        Write-Host "`n${RED}Found $($script:ErrorCount) issue(s) that MUST be fixed!${NC}" -NoNewline:$false
        Write-Host "${RED}════════════════════════════════════════════${NC}" -NoNewline:$false
        Write-Host "${RED}❌ ALL ISSUES ARE BLOCKING ❌${NC}" -NoNewline:$false
        Write-Host "${RED}════════════════════════════════════════════${NC}" -NoNewline:$false
        Write-Host "${RED}Fix EVERYTHING above until all checks are ✅ GREEN${NC}" -NoNewline:$false
    }
}

# ============================================================================
# XML VALIDATION
# ============================================================================

function Test-GPOXMLSyntax {
    param([string]$FilePath)
    
    Write-DebugLog "Validating XML syntax: $FilePath"
    
    try {
        $xml = [xml](Get-Content -Path $FilePath -Raw)
        
        # Basic structure validation
        if ($FilePath -match "\.pol$") {
            # Registry.pol files have specific structure
            Write-DebugLog "Validating registry.pol structure"
            return $true  # .pol files are binary, skip XML validation
        }
        
        # Check for common GPO XML elements
        if ($xml.DocumentElement.Name -eq "AppLockerPolicy") {
            Write-DebugLog "Validating AppLocker policy structure"
            if (-not $xml.AppLockerPolicy.RuleCollection) {
                Add-ValidationError "Invalid AppLocker policy structure in $FilePath - missing RuleCollection"
                return $false
            }
        }
        
        return $true
    }
    catch {
        Add-ValidationError "Invalid XML in ${FilePath}: $_"
        return $false
    }
}

# ============================================================================
# ADMX TEMPLATE VALIDATION
# ============================================================================

function Test-ADMXAvailability {
    param([string]$PolicyFile)
    
    if ($SkipADMX) {
        Write-DebugLog "ADMX validation skipped"
        return $true
    }
    
    Write-DebugLog "Checking ADMX template availability for: $PolicyFile"
    
    # Extract policy references from the file
    $content = Get-Content -Path $PolicyFile -Raw
    $admxReferences = @()
    
    # Look for ADMX references in various formats
    $patterns = @(
        'class="([^"]+)"',
        'category="([^"]+)"',
        'parentCategory="([^"]+)"'
    )
    
    foreach ($pattern in $patterns) {
        $matches = [regex]::Matches($content, $pattern)
        foreach ($match in $matches) {
            $admxReferences += $match.Groups[1].Value
        }
    }
    
    # Check if referenced ADMX templates exist
    $templatesPath = Join-Path $PSScriptRoot "..\Templates\ADMX"
    $missingTemplates = @()
    
    foreach ($ref in ($admxReferences | Select-Object -Unique)) {
        # Common ADMX mappings
        $possibleFiles = @(
            "$ref.admx",
            "$($ref.ToLower()).admx",
            "$($ref -replace 'Microsoft\.Policies\.', '').admx"
        )
        
        $found = $false
        foreach ($file in $possibleFiles) {
            if (Test-Path (Join-Path $templatesPath $file)) {
                $found = $true
                Write-DebugLog "Found ADMX template: $file"
                break
            }
        }
        
        if (-not $found -and $ref -notmatch "^(User|Computer|Machine)$") {
            $missingTemplates += $ref
        }
    }
    
    if ($missingTemplates.Count -gt 0) {
        Add-ValidationError "Missing ADMX templates for $PolicyFile"
        foreach ($template in $missingTemplates) {
            Write-Host "  Missing template for: $template" -ForegroundColor Yellow
        }
        return $false
    }
    
    return $true
}

# ============================================================================
# SECURITY VALIDATION
# ============================================================================

function Test-SecuritySettings {
    param([string]$FilePath)
    
    Write-DebugLog "Validating security settings in: $FilePath"
    
    $content = Get-Content -Path $FilePath -Raw
    $foundIssues = $false
    
    # Check for overly permissive settings
    $dangerousPatterns = @(
        @{Pattern = 'Everyone.*Allow.*FullControl'; Description = "Overly permissive 'Everyone' full control"},
        @{Pattern = 'Password.*Never.*Expire'; Description = "Password never expires setting"},
        @{Pattern = 'MinimumPasswordLength.*value="0"'; Description = "No minimum password length"},
        @{Pattern = 'RequireLogonToChangePassword.*value="0"'; Description = "No logon required to change password"},
        @{Pattern = 'DisableWindowsDefender.*value="1"'; Description = "Windows Defender disabled"},
        @{Pattern = 'EnableLUA.*value="0"'; Description = "UAC disabled"}
    )
    
    foreach ($pattern in $dangerousPatterns) {
        if ($content -match $pattern.Pattern) {
            if (-not $foundIssues) {
                Add-ValidationError "Security concerns in $FilePath"
                $foundIssues = $true
            }
            Write-Host "  ${YELLOW}⚠${NC} $($pattern.Description)" -NoNewline:$false
        }
    }
    
    # Check for proper security group usage
    if ($content -match 'S-1-1-0' -and $content -match 'Allow') {
        if (-not $foundIssues) {
            Add-ValidationError "Security concerns in $FilePath"
            $foundIssues = $true
        }
        Write-Host "  ${YELLOW}⚠${NC} 'Everyone' group (S-1-1-0) used with Allow permissions" -NoNewline:$false
    }
    
    return -not $foundIssues
}

# ============================================================================
# HARDCODED VALUES VALIDATION
# ============================================================================

function Test-HardcodedValues {
    param([string]$FilePath)
    
    Write-DebugLog "Checking for hardcoded values in: $FilePath"
    
    $content = Get-Content -Path $FilePath -Raw
    $foundIssues = $false
    
    # Patterns for hardcoded values
    $hardcodedPatterns = @(
        @{Pattern = 'DC=[\w]+,DC=[\w]+'; Description = "Hardcoded domain name"},
        @{Pattern = '\\\\[\w]+\.[\w]+\.[\w]+\\'; Description = "Hardcoded server FQDN"},
        @{Pattern = '[A-Z]:\\Program Files'; Description = "Hardcoded program path"},
        @{Pattern = 'C:\\Users\\[\w]+\\'; Description = "Hardcoded user path"},
        @{Pattern = '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'; Description = "Hardcoded IP address"}
    )
    
    foreach ($pattern in $hardcodedPatterns) {
        $matches = [regex]::Matches($content, $pattern.Pattern)
        if ($matches.Count -gt 0) {
            if (-not $foundIssues) {
                Add-ValidationError "Hardcoded values found in $FilePath"
                $foundIssues = $true
            }
            Write-Host "  $($pattern.Description): $($matches[0].Value)" -ForegroundColor Yellow
        }
    }
    
    return -not $foundIssues
}

# ============================================================================
# POLICY CONFLICT DETECTION
# ============================================================================

function Test-PolicyConflicts {
    param([System.Collections.ArrayList]$PolicyFiles)
    
    Write-InfoLog "Checking for policy conflicts across $($PolicyFiles.Count) files..."
    
    $policies = @{}
    
    # Load all policies
    foreach ($file in $PolicyFiles) {
        $fileName = Split-Path -Leaf $file
        $content = Get-Content -Path $file -Raw
        
        # Extract policy settings
        $settings = @{}
        
        # Registry settings
        $regMatches = [regex]::Matches($content, 'key="([^"]+)".*valueName="([^"]+)"')
        foreach ($match in $regMatches) {
            $key = "$($match.Groups[1].Value)\$($match.Groups[2].Value)"
            $settings[$key] = $fileName
        }
        
        # AppLocker rules
        if ($content -match "AppLockerPolicy") {
            $appLockerMatches = [regex]::Matches($content, 'Id="([^"]+)".*Name="([^"]+)"')
            foreach ($match in $appLockerMatches) {
                $key = "AppLocker:$($match.Groups[2].Value)"
                $settings[$key] = $fileName
            }
        }
        
        $policies[$fileName] = $settings
    }
    
    # Check for conflicts
    $allKeys = $policies.Values | ForEach-Object { $_.Keys } | Select-Object -Unique
    
    foreach ($key in $allKeys) {
        $filesWithKey = @()
        foreach ($file in $policies.Keys) {
            if ($policies[$file].ContainsKey($key)) {
                $filesWithKey += $file
            }
        }
        
        if ($filesWithKey.Count -gt 1) {
            Add-PolicyConflict -Policy1 $filesWithKey[0] -Policy2 $filesWithKey[1] `
                -Description "Both policies modify: $key"
        }
    }
    
    return $script:PolicyConflicts.Count -eq 0
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

# Print header
Write-Host "" -NoNewline:$false
Write-Host "🔍 GPO Validation - Checking Group Policy Objects..." -NoNewline:$false
Write-Host "──────────────────────────────────────────────────────" -NoNewline:$false

# Determine search path
$searchPath = if ($GPOPath) { $GPOPath } else { "." }

# Find GPO-related files
Write-InfoLog "Scanning for GPO files..."

$gpoFiles = @()
$gpoFiles += Get-ChildItem -Path $searchPath -Recurse -Include "*.xml", "*.pol", "*.inf" -File |
    Where-Object { 
        $_.FullName -notmatch "/(\.git|node_modules|temp_claude_repo)/" -and
        $_.FullName -match "/(Policies|Templates|GPO|GroupPolicy)/"
    }

if ($gpoFiles.Count -eq 0) {
    Write-InfoLog "No GPO files found to validate"
    exit 0
}

Write-InfoLog "Found $($gpoFiles.Count) GPO file(s) to validate"

# Validate each file
foreach ($file in $gpoFiles) {
    Write-InfoLog "Validating: $($file.Name)"
    
    $allPassed = $true
    
    # XML syntax (skip for .pol files)
    if ($file.Extension -ne ".pol") {
        if (-not (Test-GPOXMLSyntax -FilePath $file.FullName)) {
            $allPassed = $false
        }
    }
    
    # ADMX availability
    if (-not (Test-ADMXAvailability -PolicyFile $file.FullName)) {
        $allPassed = $false
    }
    
    # Security settings
    if (-not (Test-SecuritySettings -FilePath $file.FullName)) {
        $allPassed = $false
    }
    
    # Hardcoded values
    if (-not (Test-HardcodedValues -FilePath $file.FullName)) {
        $allPassed = $false
    }
    
    if ($allPassed) {
        Write-SuccessLog "Validation passed: $($file.Name)"
    }
}

# Check for conflicts across all policies
if ($gpoFiles.Count -gt 1) {
    Test-PolicyConflicts -PolicyFiles $gpoFiles
}

# Print summary
Show-Summary

# Final message and exit
if ($script:ErrorCount -gt 0) {
    Write-Host "`n${RED}🛑 FAILED - Fix all GPO issues above! 🛑${NC}" -NoNewline:$false
    Write-Host "${YELLOW}📋 NEXT STEPS:${NC}" -NoNewline:$false
    Write-Host "${YELLOW}  1. Fix the issues listed above${NC}" -NoNewline:$false
    Write-Host "${YELLOW}  2. Verify the fix by running: .\hooks\validate-gpo.ps1${NC}" -NoNewline:$false
    Write-Host "${YELLOW}  3. Run pre-deployment check before deployment${NC}" -NoNewline:$false
    exit 2
}
else {
    Write-Host "`n${GREEN}✅ All GPO validation checks passed!${NC}" -NoNewline:$false
    Write-Host "${YELLOW}👉 GPOs are valid. Ready for deployment.${NC}" -NoNewline:$false
    exit 0
}