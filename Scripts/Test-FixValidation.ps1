#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Runs all validation scripts and provides a comprehensive status summary
.DESCRIPTION
    This script executes all validation scripts in sequence and shows a clear
    summary of what's fixed vs what's still broken. Returns exit code 0 only
    if ALL checks pass.
#>

param(
    [switch]$Verbose
)

$ErrorActionPreference = 'Continue'

# Initialize results tracking
$results = @{
    TotalChecks = 0
    Passed = 0
    Failed = 0
    Details = @()
}

# Color codes for output
$colors = @{
    Success = "`e[32m"
    Error = "`e[31m"
    Warning = "`e[33m"
    Info = "`e[36m"
    Reset = "`e[0m"
}

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = 'Info'
    )
    Write-Host "$($colors[$Color])$Message$($colors.Reset)"
}

function Run-ValidationScript {
    param(
        [string]$ScriptPath,
        [string]$DisplayName,
        [string]$WorkingDirectory = $null
    )
    
    $results.TotalChecks++
    
    Write-Host "`n" -NoNewline
    Write-ColorOutput "========================================" "Info"
    Write-ColorOutput "Running: $DisplayName" "Info"
    Write-ColorOutput "========================================" "Info"
    
    try {
        # Prepare script execution parameters
        $scriptParams = @{
            FilePath = 'pwsh'
            ArgumentList = @('-NoProfile', '-File', $ScriptPath)
            NoNewWindow = $true
            Wait = $true
            PassThru = $true
        }
        
        if ($WorkingDirectory) {
            $scriptParams.WorkingDirectory = $WorkingDirectory
        }
        
        if ($Verbose) {
            $scriptParams.ArgumentList += '-Verbose'
        }
        
        # Execute the script
        $process = Start-Process @scriptParams
        $exitCode = $process.ExitCode
        
        if ($exitCode -eq 0) {
            $results.Passed++
            $status = "✅ PASSED"
            $color = "Success"
        } else {
            $results.Failed++
            $status = "❌ FAILED (Exit Code: $exitCode)"
            $color = "Error"
        }
        
        # Add to results
        $results.Details += [PSCustomObject]@{
            Script = $DisplayName
            Status = $status
            ExitCode = $exitCode
            Passed = ($exitCode -eq 0)
        }
        
        Write-ColorOutput "`n${DisplayName}: $status" $color
        
    } catch {
        $results.Failed++
        $status = "❌ ERROR: $($_.Exception.Message)"
        
        $results.Details += [PSCustomObject]@{
            Script = $DisplayName
            Status = $status
            ExitCode = -1
            Passed = $false
        }
        
        Write-ColorOutput "`n${DisplayName}: $status" "Error"
    }
}

# Main execution
Write-ColorOutput @"
╔══════════════════════════════════════════╗
║      GROUP POLICY VALIDATION SUITE       ║
║         Comprehensive Fix Checker        ║
╚══════════════════════════════════════════╝
"@ "Info"

Write-Host "`nStarting validation sequence at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"

# Define validation scripts
$validationScripts = @(
    @{
        Path = Join-Path $PSScriptRoot "Test-CodebaseIntegrity.ps1"
        Name = "GP_Codebase Integrity Check"
    },
    @{
        Path = Join-Path (Split-Path $PSScriptRoot) "hooks/smart-lint.ps1"
        Name = "GP_Smart Linting"
    },
    @{
        Path = Join-Path (Split-Path $PSScriptRoot) "hooks/validate-gpo.ps1"
        Name = "GP_GPO Validation"
    },
    @{
        Path = Join-Path (Split-Path $PSScriptRoot) "hooks/pre-deployment-check.ps1"
        Name = "GP_Pre-Deployment Check"
    }
)

# Run each validation script
foreach ($script in $validationScripts) {
    if (Test-Path $script.Path) {
        Run-ValidationScript -ScriptPath $script.Path -DisplayName $script.Name
    } else {
        $results.TotalChecks++
        $results.Failed++
        $results.Details += [PSCustomObject]@{
            Script = $script.Name
            Status = "❌ MISSING: Script not found at $($script.Path)"
            ExitCode = -1
            Passed = $false
        }
        Write-ColorOutput "`n$($script.Name): ❌ MISSING" "Error"
    }
}

# Generate summary report
Write-Host "`n`n"
Write-ColorOutput "╔══════════════════════════════════════════╗" "Info"
Write-ColorOutput "║           VALIDATION SUMMARY             ║" "Info"
Write-ColorOutput "╚══════════════════════════════════════════╝" "Info"

Write-Host "`nExecution completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"

# Display detailed results
Write-ColorOutput "Detailed Results:" "Info"
Write-Host "─" * 60

foreach ($result in $results.Details) {
    $icon = if ($result.Passed) { "✅" } else { "❌" }
    $color = if ($result.Passed) { "Success" } else { "Error" }
    Write-Host "$icon " -NoNewline
    Write-ColorOutput "$($result.Script)" $color
}

Write-Host "`n" + ("─" * 60)

# Display statistics
$passRate = if ($results.TotalChecks -gt 0) { 
    [math]::Round(($results.Passed / $results.TotalChecks) * 100, 2)
} else { 
    0 
}

Write-ColorOutput "`nStatistics:" "Info"
Write-Host "  Total Checks: $($results.TotalChecks)"
Write-Host "  ✅ Passed: $($results.Passed)" -ForegroundColor Green
Write-Host "  ❌ Failed: $($results.Failed)" -ForegroundColor Red
Write-Host "  Pass Rate: $passRate%"

# Overall status
Write-Host "`n" + ("═" * 60)
if ($results.Failed -eq 0 -and $results.TotalChecks -gt 0) {
    Write-ColorOutput "🎉 ALL CHECKS PASSED! The codebase is in good shape." "Success"
    Write-ColorOutput "═" * 60 "Success"
    exit 0
} else {
    Write-ColorOutput "⚠️  VALIDATION FAILED! $($results.Failed) check(s) need attention." "Error"
    Write-ColorOutput "═" * 60 "Error"
    
    # Show which scripts failed
    Write-Host "`nFailed Scripts:"
    foreach ($result in $results.Details | Where-Object { -not $_.Passed }) {
        Write-Host "  - $($result.Script)" -ForegroundColor Red
    }
    
    Write-Host "`nPlease fix the issues above and run this script again.`n"
    exit 1
}