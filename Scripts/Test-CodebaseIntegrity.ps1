#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
    Tests the Group Policy codebase for common issues and validates fixes
.DESCRIPTION
    This script performs automated testing of the Group Policy scripts to ensure
    they are free from syntax errors and common issues after code review fixes.
    
    NOTE: This is a read-only validation script that analyzes other scripts.
    It does not execute any state-changing commands like New-GPO, Remove-GPO, 
    Set-ItemProperty, or New-ItemProperty. These command names appear in the 
    script only as pattern strings used to check for their presence in other files.
.PARAMETER ScriptPath
    Path to the GroupPolicy scripts directory
.PARAMETER QuickTest
    Perform only syntax validation without deep analysis
#>

[CmdletBinding()]
param(
    [string]$ScriptPath = $PSScriptRoot,
    [switch]$QuickTest
)

Write-Host "=== Group Policy Codebase Integrity Test ===" -ForegroundColor Cyan
Write-Host "Test Date: $(Get-Date)" -ForegroundColor Yellow
Write-Host "Script Path: $ScriptPath" -ForegroundColor Yellow
Write-Host "❌ ALL issues are BLOCKING - EVERYTHING must be GREEN!" -ForegroundColor Red
Write-Host ""

# Initialize results
$testResults = @{
    TotalTests = 0
    Passed = 0
    Failed = 0
    Warnings = 0  # Deprecated - ALL issues are now Failed, not Warnings
    Issues = @()
}

function Test-ScriptSyntax {
    param([string]$FilePath)
    
    try {
        $null = [System.Management.Automation.PSParser]::Tokenize((Get-Content $FilePath -Raw), [ref]$null)
        return @{Success = $true; Error = $null}
    } catch {
        return @{Success = $false; Error = $_.Exception.Message}
    }
}

function Test-DomainConsistency {
    param([string]$FilePath)
    
    $content = Get-Content $FilePath -Raw
    $issues = @()
    
    # Check for incorrect domains
    if ($content -match 'DC=contoso,DC=com|DC=domain,DC=com|contoso\.com') {
        $issues += "Found incorrect domain references (should be scottify.io)"
    }
    
    return $issues
}

function Test-GPONameConsistency {
    param([string]$FilePath)
    
    $content = Get-Content $FilePath -Raw
    $issues = @()
    
    # Check for inconsistent GPO names
    if ($content -match '"Teenager Restrictions"(?!\s*Policy)') {
        $issues += "Found inconsistent GPO name (should be 'GP_Teenager_Restrictions_Policy')"
    }
    
    return $issues
}

function Test-CommonErrors {
    param([string]$FilePath)
    
    $content = Get-Content $FilePath -Raw
    $issues = @()
    
    # Check for Export-ModuleMember in scripts
    if ($FilePath -notlike "*.psm1" -and $content -match 'Export-ModuleMember') {
        $issues += "Export-ModuleMember found in script (only valid in modules)"
    }
    
    # Check for invalid cmdlets
    if ($content -match 'Invoke-WmiMethod\s+-Query') {
        $issues += "Invalid cmdlet usage: Invoke-WmiMethod -Query"
    }
    
    # Check for Get-EventLog (deprecated)
    if ($content -match 'Get-EventLog\s+') {
        $issues += "Deprecated cmdlet: Get-EventLog (use Get-WinEvent)"
    }
    
    # Check for TODOs in production scripts
    if ($content -match '\bTODO\b|\bFIXME\b|\bHACK\b') {
        $issues += "Found TODO/FIXME/HACK comments in production code"
    }
    
    # Check for hardcoded passwords
    if ($content -match '(password|pwd)\s*=\s*["''][^"'']+["'']' -and $content -notmatch 'ConvertTo-SecureString') {
        $issues += "Possible hardcoded password detected"
    }
    
    return $issues
}

function Test-GPOSpecificValidation {
    param([string]$FilePath)
    
    try {
        $content = Get-Content $FilePath -Raw
        $issues = @()
        
        # Check for direct registry edits without GPO
        # Note: These are pattern strings for validation, not actual commands
        if ($content -match 'Set-ItemProperty.*HKLM:|New-ItemProperty.*HKLM:' -and 
            $content -notmatch 'Set-GPRegistryValue') {
            $issues += "Direct registry edit detected (use GPO methods when possible)"
        }
        
        # Check for GPO operations without error handling
        # Note: These are pattern strings for validation, not actual commands
        # Split content into lines for more accurate checking
        $lines = $content -split "`n"
        $inTryBlock = $false
        $tryDepth = 0
        
        for ($i = 0; $i -lt $lines.Count; $i++) {
            $line = $lines[$i]
            
            # Track try block depth
            if ($line -match '\btry\s*{') {
                $inTryBlock = $true
                $tryDepth++
            }
            
            # Track closing braces
            if ($line -match '}' -and $tryDepth -gt 0) {
                # Count opening and closing braces on this line
                $openBraces = ([regex]::Matches($line, '{').Count)
                $closeBraces = ([regex]::Matches($line, '}').Count)
                $tryDepth = $tryDepth + $openBraces - $closeBraces
                
                if ($tryDepth -le 0) {
                    $inTryBlock = $false
                    $tryDepth = 0
                }
            }
            
            # Check for GPO commands
            if ($line -match '\b(New-GPO|Set-GPO|Remove-GPO|Set-GPRegistryValue)\b' -and 
                $line -notmatch '^\s*#' -and  # Not a comment
                $line -notmatch '"[^"]*\b(New-GPO|Set-GPO|Remove-GPO|Set-GPRegistryValue)\b[^"]*"' -and  # Not in a string
                $line -notmatch "'[^']*\b(New-GPO|Set-GPO|Remove-GPO|Set-GPRegistryValue)\b[^']*'") {  # Not in a string
                
                if (-not $inTryBlock) {
                    # Look ahead and behind for try blocks within reasonable distance
                    $foundTry = $false
                    
                    # Check previous 10 lines for try
                    for ($j = [Math]::Max(0, $i - 10); $j -lt $i; $j++) {
                        if ($lines[$j] -match '\btry\s*{') {
                            # Check if we're still in that try block
                            $tempDepth = 1
                            for ($k = $j + 1; $k -le $i; $k++) {
                                if ($lines[$k] -match '{') { $tempDepth += ([regex]::Matches($lines[$k], '{').Count) }
                                if ($lines[$k] -match '}') { $tempDepth -= ([regex]::Matches($lines[$k], '}').Count) }
                            }
                            if ($tempDepth -gt 0) {
                                $foundTry = $true
                                break
                            }
                        }
                    }
                    
                    if (-not $foundTry) {
                        $cmdlet = $matches[1]
                        $lineNum = $i + 1
                        $issues += "GPO operation '$cmdlet' without proper error handling at line $lineNum"
                    }
                }
            }
        }
        
        # Check for missing backup before GPO changes
        if ($content -match '(Remove-GPO|Set-GPO|Set-GPRegistryValue)' -and 
            $content -notmatch '(Backup-GPO|Backup-GPOBeforeModification)') {
            $issues += "GPO modifications without backup"
        }
        
        return $issues
    }
    catch {
        Write-Host "  ⚠️ Error during GPO-specific validation: $_" -ForegroundColor Yellow
        return @("Failed to perform GPO-specific validation: $_")
    }
}

# Test all PowerShell scripts
Write-Host "Testing PowerShell Scripts..." -ForegroundColor Cyan
$scripts = Get-ChildItem -Path $ScriptPath -Filter "*.ps1" -Recurse

foreach ($script in $scripts) {
    # Skip testing this script itself to avoid self-flagging
    if ($script.Name -eq "Test-CodebaseIntegrity.ps1") {
        Write-Host "`nSkipping: $($script.Name) (self-exclusion)" -ForegroundColor Yellow
        continue
    }
    
    Write-Host "`nTesting: $($script.Name)" -ForegroundColor White
    $testResults.TotalTests++
    
    # Test 1: Syntax validation
    $syntaxResult = Test-ScriptSyntax -FilePath $script.FullName
    if ($syntaxResult.Success) {
        Write-Host "  ✅ Syntax valid" -ForegroundColor Green
    } else {
        Write-Host "  ❌ Syntax error: $($syntaxResult.Error)" -ForegroundColor Red
        $testResults.Issues += "[$($script.Name)] Syntax error: $($syntaxResult.Error)"
        $testResults.Failed++
        continue
    }
    
    if (-not $QuickTest) {
        # Test 2: Domain consistency
        $domainIssues = Test-DomainConsistency -FilePath $script.FullName
        if ($domainIssues.Count -eq 0) {
            Write-Host "  ✅ Domain references consistent" -ForegroundColor Green
        } else {
            Write-Host "  ❌ Domain issues found" -ForegroundColor Red
            foreach ($issue in $domainIssues) {
                Write-Host "    - $issue" -ForegroundColor Red
                $testResults.Issues += "[$($script.Name)] $issue"
            }
            $testResults.Failed++  # Changed from Warnings to Failed - ALL issues are BLOCKING
        }
        
        # Test 3: GPO name consistency
        $gpoIssues = Test-GPONameConsistency -FilePath $script.FullName
        if ($gpoIssues.Count -eq 0) {
            Write-Host "  ✅ GPO names consistent" -ForegroundColor Green
        } else {
            Write-Host "  ❌ GPO name inconsistency" -ForegroundColor Red
            foreach ($issue in $gpoIssues) {
                Write-Host "    - $issue" -ForegroundColor Red  # Changed from Yellow to Red
                $testResults.Issues += "[$($script.Name)] $issue"
            }
            $testResults.Failed++  # Changed from Warnings to Failed - ALL issues are BLOCKING
        }
        
        # Test 4: Common errors
        $commonErrors = Test-CommonErrors -FilePath $script.FullName
        if ($commonErrors.Count -eq 0) {
            Write-Host "  ✅ No common errors found" -ForegroundColor Green
        } else {
            Write-Host "  ❌ Common errors detected" -ForegroundColor Red
            foreach ($issue in $commonErrors) {
                Write-Host "    - $issue" -ForegroundColor Red
                $testResults.Issues += "[$($script.Name)] $issue"
            }
            $testResults.Failed++
        }
        
        # Test 5: GPO-specific validation
        $gpoIssues = Test-GPOSpecificValidation -FilePath $script.FullName
        if ($gpoIssues.Count -eq 0) {
            Write-Host "  ✅ GPO-specific checks passed" -ForegroundColor Green
        } else {
            Write-Host "  ❌ GPO-specific issues found" -ForegroundColor Red
            foreach ($issue in $gpoIssues) {
                Write-Host "    - $issue" -ForegroundColor Red
                $testResults.Issues += "[$($script.Name)] $issue"
            }
            $testResults.Failed++
        }
    }
    
    if ($syntaxResult.Success -and 
        ($QuickTest -or ($domainIssues.Count -eq 0 -and $gpoIssues.Count -eq 0 -and $commonErrors.Count -eq 0))) {
        $testResults.Passed++
    }
}

# Test policy files
Write-Host "`n`nTesting Policy Files..." -ForegroundColor Cyan
$policyPath = Join-Path (Split-Path $ScriptPath -Parent) "Policies"

# Check if Browser-Restrictions.pol exists
$browserPolPath = Join-Path $policyPath "Teenagers\Browser-Restrictions.pol"
if (Test-Path $browserPolPath) {
    Write-Host "`nChecking Browser-Restrictions.pol" -ForegroundColor White
    $content = Get-Content $browserPolPath -Raw
    if ($content -match 'Windows Registry Editor Version') {
        Write-Host "  ❌ File is in .reg format (should use Set-BrowserRestrictions.ps1 instead)" -ForegroundColor Red
        $testResults.Failed++  # Changed from Warnings to Failed
        $testResults.Issues += "[Browser-Restrictions.pol] File in .reg format instead of binary .pol"
    }
}

# Check for Set-BrowserRestrictions.ps1
$setBrowserPath = Join-Path $ScriptPath "Set-BrowserRestrictions.ps1"
if (Test-Path $setBrowserPath) {
    Write-Host "  ✅ Set-BrowserRestrictions.ps1 exists (replacement for .pol file)" -ForegroundColor Green
} else {
    Write-Host "  ❌ Set-BrowserRestrictions.ps1 not found" -ForegroundColor Red
    $testResults.Failed++
}

# Generate summary
Write-Host "`n`n=== Test Summary ===" -ForegroundColor Cyan
$totalScriptsTested = $scripts.Count - 1  # Exclude Test-CodebaseIntegrity.ps1 itself
Write-Host "Total Scripts Tested: $totalScriptsTested (excluded Test-CodebaseIntegrity.ps1)" -ForegroundColor White
Write-Host "Passed: $($testResults.Passed)" -ForegroundColor $(if ($testResults.Passed -eq $totalScriptsTested) { 'Green' } else { 'Red' })
Write-Host "Failed: $($testResults.Failed)" -ForegroundColor $(if ($testResults.Failed -gt 0) { 'Red' } else { 'Green' })
Write-Host "Total Issues: $($testResults.Issues.Count)" -ForegroundColor $(if ($testResults.Issues.Count -gt 0) { 'Red' } else { 'Green' })

if ($testResults.Issues.Count -gt 0) {
    Write-Host "`n❌ BLOCKING ISSUES FOUND:" -ForegroundColor Red
    foreach ($issue in $testResults.Issues) {
        Write-Host "  - $issue" -ForegroundColor Red
    }
    Write-Host "`nALL issues must be fixed before deployment!" -ForegroundColor Red
}

# Final result
if ($testResults.Failed -gt 0 -or $testResults.Issues.Count -gt 0) {
    Write-Host "`n❌ VALIDATION FAILED!" -ForegroundColor Red
    Write-Host "Fix ALL issues before deployment. There are NO acceptable warnings in production." -ForegroundColor Red
    Write-Host "Exit code: 2" -ForegroundColor Red
} else {
    Write-Host "`n✅ ALL TESTS PASSED!" -ForegroundColor Green
    Write-Host "Codebase is ready for deployment." -ForegroundColor Green
    Write-Host "Remember to test in a non-production environment first." -ForegroundColor Yellow
    Write-Host "Exit code: 0" -ForegroundColor Green
}

# Return results for automation and set exit code
if ($testResults.Failed -gt 0 -or $testResults.Issues.Count -gt 0) {
    # Exit code 2 for any issues (not just 1) - ALL issues are BLOCKING
    exit 2
} else {
    exit 0
}