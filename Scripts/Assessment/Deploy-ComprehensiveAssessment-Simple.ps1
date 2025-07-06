#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Simple version of comprehensive assessment that works in Constrained Language Mode
.DESCRIPTION
    This simplified version works when AppLocker or other security policies
    enforce Constrained Language Mode on the system.
#>

[CmdletBinding()]
param(
    [string]$AssessmentPath = ".\AssessmentReports_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    [switch]$SkipBackup,
    [switch]$FastMode
)

# Ensure we have a proper script path
$scriptDir = if ($PSScriptRoot) { 
    $PSScriptRoot 
} else { 
    Split-Path -Parent $MyInvocation.MyCommand.Path
}

if (-not $scriptDir) {
    $scriptDir = Get-Location
}

Write-Host "=== Comprehensive Group Policy Environment Assessment (Simple Mode) ===" -ForegroundColor Cyan
Write-Host "Running from: $scriptDir" -ForegroundColor Yellow
Write-Host "Assessment Date: $(Get-Date)" -ForegroundColor Yellow
Write-Host "Output Path: $AssessmentPath" -ForegroundColor Yellow
Write-Host ""

# Create assessment directory
if (-not (Test-Path $AssessmentPath)) {
    New-Item -Path $AssessmentPath -ItemType Directory -Force | Out-Null
}

# Start transcript
Start-Transcript -Path "$AssessmentPath\AssessmentTranscript.log"

# Define phases with scripts
$phases = @{
    "Infrastructure" = @(
        "Test-DomainControllerHealth.ps1",
        "Test-GPOInfrastructure.ps1"
    )
    "Inventory" = @(
        "Get-GPOInventory.ps1"
    )
    "ConflictAnalysis" = @(
        "Get-GPOConflicts.ps1",
        "Get-LegacyPolicies.ps1"
    )
}

$results = @{}

# Run each phase
foreach ($phaseName in $phases.Keys) {
    Write-Host "`n=== Phase: $phaseName ===" -ForegroundColor Cyan
    
    $phaseResults = @{
        Success = $true
        Scripts = @{}
    }
    
    foreach ($script in $phases[$phaseName]) {
        $scriptPath = Join-Path $scriptDir $script
        
        if (Test-Path $scriptPath) {
            Write-Host "Running: $script" -ForegroundColor White
            
            try {
                & $scriptPath -OutputPath $AssessmentPath -ErrorAction Stop
                Write-Host "  [OK] Completed successfully" -ForegroundColor Green
                $phaseResults.Scripts[$script] = @{Status = "Success"}
            }
            catch {
                Write-Host "  [FAIL] Failed: $_" -ForegroundColor Red
                $phaseResults.Scripts[$script] = @{Status = "Failed"; Error = $_.ToString()}
                $phaseResults.Success = $false
            }
        }
        else {
            Write-Host "  [!] Script not found: $script" -ForegroundColor Yellow
            $phaseResults.Scripts[$script] = @{Status = "NotFound"}
            $phaseResults.Success = $false
        }
    }
    
    $results[$phaseName] = $phaseResults
}

# Generate simple text report
$reportPath = Join-Path $AssessmentPath "AssessmentReport.txt"
$report = @"
Group Policy Environment Assessment Report
==========================================
Date: $(Get-Date)
Computer: $env:COMPUTERNAME
Domain: $env:USERDNSDOMAIN

Phase Results:
--------------
"@

foreach ($phase in $results.Keys) {
    $report += "`n$phase`: "
    if ($results[$phase].Success) {
        $report += "PASSED`n"
    } else {
        $report += "FAILED`n"
    }
    
    foreach ($script in $results[$phase].Scripts.Keys) {
        $status = $results[$phase].Scripts[$script].Status
        $report += "  - ${script}: $status`n"
        if ($results[$phase].Scripts[$script].Error) {
            $report += "    Error: $($results[$phase].Scripts[$script].Error)`n"
        }
    }
}

# Determine overall readiness
$allPassed = $true
foreach ($phase in $results.Values) {
    if (-not $phase.Success) {
        $allPassed = $false
        break
    }
}

$report += "`nDeployment Readiness: "
if ($allPassed) {
    $report += "READY`n"
} else {
    $report += "NOT READY - Issues found`n"
}

# Save report
$report | Out-File -FilePath $reportPath

Write-Host "`n=== Assessment Complete ===" -ForegroundColor Cyan
Write-Host "Report saved to: $reportPath" -ForegroundColor Green

# Stop transcript
Stop-Transcript

# Display summary
Write-Host "`nSummary:" -ForegroundColor Cyan
if ($allPassed) {
    Write-Host "Environment is READY for deployment" -ForegroundColor Green
} else {
    Write-Host "Environment is NOT READY - please review the report" -ForegroundColor Red
}

Write-Host "`nView the full report at: $reportPath" -ForegroundColor Yellow