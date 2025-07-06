#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Orchestrates a comprehensive Group Policy environment assessment before teenager policy deployment
.DESCRIPTION
    This script runs all assessment scripts in the proper order and generates a consolidated
    report to determine if the environment is ready for teenager restriction policy deployment.
.PARAMETER AssessmentPath
    Path where all assessment reports will be saved
.PARAMETER SkipBackup
    Skip the backup phase (not recommended)
.PARAMETER FastMode
    Run only critical assessments
#>

[CmdletBinding()]
param(
    [string]$AssessmentPath = "$PSScriptRoot\AssessmentReports_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    [switch]$SkipBackup,
    [switch]$FastMode
)

# Create assessment directory
if (-not (Test-Path $AssessmentPath)) {
    New-Item -Path $AssessmentPath -ItemType Directory -Force | Out-Null
}

# Start transcript
Start-Transcript -Path "$AssessmentPath\AssessmentTranscript.log"

Write-Host "=== Comprehensive Group Policy Environment Assessment ===" -ForegroundColor Cyan
Write-Host "Assessment Date: $(Get-Date)" -ForegroundColor Yellow
Write-Host "Output Path: $AssessmentPath" -ForegroundColor Yellow
Write-Host ""

# Phase tracking
$phases = @{
    "Infrastructure" = @{
        Scripts = @("Test-DomainControllerHealth.ps1", "Test-GPOInfrastructure.ps1")
        Status = "Pending"
        Critical = $true
    }
    "Inventory" = @{
        Scripts = @("Get-GPOInventory.ps1")
        Status = "Pending"
        Critical = $true
    }
    "ConflictAnalysis" = @{
        Scripts = @("Get-GPOConflicts.ps1", "Get-LegacyPolicies.ps1")
        Status = "Pending"
        Critical = $true
    }
    "PolicyReadiness" = @{
        Scripts = @("Get-AppLockerStatus.ps1", "Get-ChromePolicies.ps1")
        Status = "Pending"
        Critical = $false
    }
    "Backup" = @{
        Scripts = @("New-EnvironmentBackup.ps1")
        Status = "Pending"
        Critical = $true
    }
    "FinalCheck" = @{
        Scripts = @("Test-FinalHealthCheck.ps1")
        Status = "Pending"
        Critical = $true
    }
}

# Results tracking
$assessmentResults = @{
    StartTime = Get-Date
    Phases = @{}
    OverallStatus = "Unknown"
    CriticalIssues = @()
    Warnings = @()
    Recommendations = @()
}

function Run-AssessmentPhase {
    param(
        [string]$PhaseName,
        [array]$Scripts,
        [bool]$IsCritical
    )
    
    Write-Host "`n=== Phase: $PhaseName ===" -ForegroundColor Cyan
    
    $phaseResults = @{
        Success = $true
        Scripts = @{}
    }
    
    foreach ($script in $Scripts) {
        $scriptPath = Join-Path $PSScriptRoot $script
        $scriptName = [System.IO.Path]::GetFileNameWithoutExtension($script)
        
        if (Test-Path $scriptPath) {
            Write-Host "Running: $script" -ForegroundColor White
            
            try {
                # Create output subdirectory for this script
                $scriptOutput = Join-Path $AssessmentPath $scriptName
                New-Item -Path $scriptOutput -ItemType Directory -Force | Out-Null
                
                # Run the script with appropriate parameters
                $params = @{}
                
                # Add common parameters based on script type
                switch -Regex ($script) {
                    "Test-|Get-" { 
                        $params.Add("OutputPath", $scriptOutput)
                        if ($script -match "Get-ChromePolicies") {
                            $params.Add("ExportPath", $scriptOutput)
                        }
                    }
                    "Get-" { 
                        $params.Add("OutputPath", $scriptOutput)
                        if ($script -match "Get-LegacyPolicies") {
                            $params.Add("ReportPath", $scriptOutput)
                        }
                    }
                    "New-" { 
                        $params.Add("BackupPath", $scriptOutput)
                    }
                    "Test-FinalHealthCheck" {
                        $params.Add("LogPath", $scriptOutput)
                        $params.Add("BackupLocation", "$AssessmentPath\New-EnvironmentBackup")
                    }
                    "Remove-" {
                        # For cleanup scripts, run in WhatIf mode during assessment
                        $params.Add("WhatIf", $true)
                        $params.Add("ReportPath", $scriptOutput)
                    }
                }
                
                # Execute the script
                $result = & $scriptPath @params
                
                Write-Host "  ✓ Completed successfully" -ForegroundColor Green
                $phaseResults.Scripts[$scriptName] = @{
                    Status = "Success"
                    Result = $result
                }
                
            } catch {
                Write-Host "  ✗ Failed: $_" -ForegroundColor Red
                $phaseResults.Scripts[$scriptName] = @{
                    Status = "Failed"
                    Error = $_.Exception.Message
                }
                $phaseResults.Success = $false
                
                if ($IsCritical) {
                    $assessmentResults.CriticalIssues += "$script failed: $_"
                }
            }
        } else {
            Write-Host "  ! Script not found: $script" -ForegroundColor Yellow
            $phaseResults.Scripts[$scriptName] = @{
                Status = "NotFound"
            }
            $assessmentResults.Warnings += "Script not found: $script"
        }
    }
    
    return $phaseResults
}

# Execute assessment phases
foreach ($phase in $phases.GetEnumerator()) {
    if ($SkipBackup -and $phase.Key -eq "Backup") {
        Write-Host "`nSkipping backup phase as requested" -ForegroundColor Yellow
        $assessmentResults.Warnings += "Backup was skipped - this is not recommended!"
        continue
    }
    
    if ($FastMode -and -not $phase.Value.Critical) {
        Write-Host "`nSkipping non-critical phase: $($phase.Key)" -ForegroundColor Yellow
        continue
    }
    
    $result = Run-AssessmentPhase -PhaseName $phase.Key -Scripts $phase.Value.Scripts -IsCritical $phase.Value.Critical
    $assessmentResults.Phases[$phase.Key] = $result
    
    # Stop if critical phase failed
    if (-not $result.Success -and $phase.Value.Critical) {
        Write-Host "`nCritical phase failed! Stopping assessment." -ForegroundColor Red
        $assessmentResults.OverallStatus = "Failed"
        break
    }
}

# Generate consolidated report
Write-Host "`n=== Generating Consolidated Report ===" -ForegroundColor Cyan

$reportPath = Join-Path $AssessmentPath "ConsolidatedAssessmentReport.html"
$jsonReportPath = Join-Path $AssessmentPath "AssessmentResults.json"

# Check if final health check passed
$finalCheckPath = Join-Path $AssessmentPath "Test-FinalHealthCheck\DeploymentChecklist_*.txt"
$finalCheckResult = Get-Content (Get-ChildItem $finalCheckPath | Select-Object -First 1) -ErrorAction SilentlyContinue

if ($finalCheckResult -match "DEPLOYMENT READINESS: (APPROVED|NOT RECOMMENDED)") {
    $deploymentReady = $Matches[1] -eq "APPROVED"
} else {
    $deploymentReady = $false
}

# Create HTML report
$htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>Group Policy Environment Assessment Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 3px solid #0078d4; padding-bottom: 10px; }
        h2 { color: #0078d4; margin-top: 30px; }
        .status-pass { color: #107c10; font-weight: bold; }
        .status-fail { color: #d13438; font-weight: bold; }
        .status-warning { color: #ff8c00; font-weight: bold; }
        .summary-box { background-color: #e8f4fd; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .phase-box { background-color: #f8f8f8; padding: 15px; margin: 10px 0; border-left: 4px solid #0078d4; }
        .critical-issues { background-color: #fde8e9; padding: 15px; border-radius: 5px; border: 1px solid #d13438; }
        .warnings { background-color: #fff4e6; padding: 15px; border-radius: 5px; border: 1px solid #ff8c00; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #0078d4; color: white; }
        .deployment-ready { font-size: 24px; padding: 20px; text-align: center; margin: 20px 0; border-radius: 5px; }
        .ready-yes { background-color: #dff6dd; color: #107c10; border: 2px solid #107c10; }
        .ready-no { background-color: #fde8e9; color: #d13438; border: 2px solid #d13438; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Group Policy Environment Assessment Report</h1>
        
        <div class="summary-box">
            <h3>Assessment Summary</h3>
            <p><strong>Date:</strong> $(Get-Date)</p>
            <p><strong>Domain:</strong> $env:USERDNSDOMAIN</p>
            <p><strong>Assessment Type:</strong> $(if ($FastMode) { "Fast Mode" } else { "Comprehensive" })</p>
        </div>
        
        <div class="deployment-ready $(if ($deploymentReady) { "ready-yes" } else { "ready-no" })">
            DEPLOYMENT $(if ($deploymentReady) { "APPROVED" } else { "NOT RECOMMENDED" })
        </div>
"@

# Add phase results
foreach ($phase in $assessmentResults.Phases.GetEnumerator()) {
    $phaseStatus = if ($phase.Value.Success) { "Pass" } else { "Fail" }
    $statusClass = if ($phase.Value.Success) { "status-pass" } else { "status-fail" }
    
    $htmlReport += @"
        <div class="phase-box">
            <h3>$($phase.Key): <span class="$statusClass">$phaseStatus</span></h3>
            <ul>
"@
    
    foreach ($script in $phase.Value.Scripts.GetEnumerator()) {
        $scriptStatus = switch ($script.Value.Status) {
            "Success" { "<span class='status-pass'>✓ Success</span>" }
            "Failed" { "<span class='status-fail'>✗ Failed</span>" }
            "NotFound" { "<span class='status-warning'>! Not Found</span>" }
        }
        
        $htmlReport += "            <li>$($script.Key): $scriptStatus</li>`n"
    }
    
    $htmlReport += "        </ul>`n    </div>`n"
}

# Add critical issues if any
if ($assessmentResults.CriticalIssues.Count -gt 0) {
    $htmlReport += @"
        <div class="critical-issues">
            <h3>Critical Issues</h3>
            <ul>
"@
    foreach ($issue in $assessmentResults.CriticalIssues) {
        $htmlReport += "            <li>$issue</li>`n"
    }
    $htmlReport += "        </ul>`n    </div>`n"
}

# Add warnings if any
if ($assessmentResults.Warnings.Count -gt 0) {
    $htmlReport += @"
        <div class="warnings">
            <h3>Warnings</h3>
            <ul>
"@
    foreach ($warning in $assessmentResults.Warnings) {
        $htmlReport += "            <li>$warning</li>`n"
    }
    $htmlReport += "        </ul>`n    </div>`n"
}

# Add next steps
$htmlReport += @"
        <h2>Next Steps</h2>
        <ol>
"@

if ($deploymentReady) {
    $htmlReport += @"
            <li>Review all assessment reports in detail</li>
            <li>Ensure all stakeholders are informed</li>
            <li>Schedule deployment window</li>
            <li>Run deployment script: Deploy-TeenagerPolicy.ps1</li>
            <li>Monitor deployment with Get-TeenagerPolicyStatus.ps1</li>
"@
} else {
    $htmlReport += @"
            <li>Address all critical issues listed above</li>
            <li>Review detailed reports in each subdirectory</li>
            <li>Re-run failed assessments after fixes</li>
            <li>Perform another comprehensive assessment</li>
            <li>Do not proceed with deployment until all issues are resolved</li>
"@
}

$htmlReport += @"
        </ol>
        
        <h2>Report Details</h2>
        <p>Detailed reports for each assessment phase can be found in the following subdirectories:</p>
        <ul>
            <li>Domain Controller Health: Test-DomainControllerHealth/</li>
            <li>GPO Infrastructure: Test-GPOInfrastructure/</li>
            <li>GPO Inventory: Get-GPOInventory/</li>
            <li>Conflict Analysis: Get-GPOConflicts/ and Get-LegacyPolicies/</li>
            <li>AppLocker Status: Get-AppLockerStatus/</li>
            <li>Chrome Policies: Get-ChromePolicies/</li>
            <li>Backup: New-EnvironmentBackup/</li>
            <li>Final Health Check: Test-FinalHealthCheck/</li>
        </ul>
    </div>
</body>
</html>
"@

# Save reports
$htmlReport | Out-File -FilePath $reportPath -Encoding UTF8
$assessmentResults.EndTime = Get-Date
$assessmentResults.Duration = $assessmentResults.EndTime - $assessmentResults.StartTime
$assessmentResults.DeploymentReady = $deploymentReady
$assessmentResults | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonReportPath

# Stop transcript
Stop-Transcript

# Display final summary
Write-Host "`n=== Assessment Complete ===" -ForegroundColor Cyan
Write-Host "Duration: $($assessmentResults.Duration.ToString('hh\:mm\:ss'))" -ForegroundColor White
Write-Host "Reports saved to: $AssessmentPath" -ForegroundColor White

if ($deploymentReady) {
    Write-Host "`nDEPLOYMENT STATUS: APPROVED" -ForegroundColor Green
    Write-Host "The environment is ready for teenager policy deployment." -ForegroundColor Green
} else {
    Write-Host "`nDEPLOYMENT STATUS: NOT RECOMMENDED" -ForegroundColor Red
    Write-Host "Critical issues must be resolved before deployment." -ForegroundColor Red
}

Write-Host "`nOpen the consolidated report: $reportPath" -ForegroundColor Yellow

# Open report in default browser
Start-Process $reportPath

# Return assessment object for automation
return $assessmentResults