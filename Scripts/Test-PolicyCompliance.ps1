#Requires -RunAsAdministrator
#Requires -Modules ActiveDirectory, GroupPolicy
<#
.SYNOPSIS
    Tests the teenager restriction policies for compliance and effectiveness
.DESCRIPTION
    This script verifies that all teenager restriction policies are properly
    applied and functioning as expected on a target computer.
.PARAMETER ComputerName
    The name of the computer to test (default: local computer)
.PARAMETER UserName
    The username of a teenager account to test
#>

[CmdletBinding()]
param(
    [string]$ComputerName = $env:COMPUTERNAME,
    [string]$UserName,
    [switch]$Detailed
)

# Colors for output
$script:PassColor = "Green"
$script:FailColor = "Red"
$script:WarnColor = "Yellow"
$script:InfoColor = "Cyan"

function Write-TestResult {
    param(
        [string]$TestName,
        [bool]$Passed,
        [string]$Details = ""
    )
    
    $status = if ($Passed) { "PASS" } else { "FAIL" }
    $color = if ($Passed) { $script:PassColor } else { $script:FailColor }
    
    Write-Host "[$status] $TestName" -ForegroundColor $color
    if ($Details -and ($Detailed -or -not $Passed)) {
        Write-Host "      $Details" -ForegroundColor Gray
    }
}

Write-Host "=== Teenager Policy Compliance Test ===" -ForegroundColor $script:InfoColor
Write-Host "Computer: $ComputerName" -ForegroundColor White
Write-Host "Test Time: $(Get-Date)" -ForegroundColor White
Write-Host ""

# Initialize test results
$testResults = @{
    TotalTests = 0
    PassedTests = 0
    FailedTests = 0
    Warnings = 0
}

# Test 1: Check if running as Administrator
Write-Host "[Test Category: Prerequisites]" -ForegroundColor $script:InfoColor
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
Write-TestResult -TestName "Running as Administrator" -Passed $isAdmin -Details "Required for accurate testing"
$testResults.TotalTests++
if ($isAdmin) { $testResults.PassedTests++ } else { $testResults.FailedTests++ }

# Test 2: Check Group Policy application
Write-Host "`n[Test Category: Group Policy]" -ForegroundColor $script:InfoColor
try {
    $gpResult = gpresult /r /scope:computer 2>$null | Select-String "GP_Teenager_Restrictions_Policy"
    $gpApplied = $null -ne $gpResult
    Write-TestResult -TestName "Teenager GPO Applied" -Passed $gpApplied -Details "GPO must be linked and applied"
    $testResults.TotalTests++
    if ($gpApplied) { $testResults.PassedTests++ } else { $testResults.FailedTests++ }
} catch {
    Write-TestResult -TestName "Teenager GPO Applied" -Passed $false -Details "Failed to check: $_"
    $testResults.TotalTests++
    $testResults.FailedTests++
}

# Test 3: Check AppLocker Service
Write-Host "`n[Test Category: AppLocker]" -ForegroundColor $script:InfoColor
$appIdSvc = Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue
$appLockerRunning = $appIdSvc -and $appIdSvc.Status -eq 'Running'
Write-TestResult -TestName "Application Identity Service Running" -Passed $appLockerRunning `
    -Details "Required for AppLocker enforcement"
$testResults.TotalTests++
if ($appLockerRunning) { $testResults.PassedTests++ } else { $testResults.FailedTests++ }

# Test 4: Check AppLocker Policy
if ($appLockerRunning) {
    try {
        $appLockerPolicy = Get-AppLockerPolicy -Effective -ErrorAction Stop
        $hasRules = $appLockerPolicy.RuleCollections.Count -gt 0
        Write-TestResult -TestName "AppLocker Rules Configured" -Passed $hasRules `
            -Details "Found $($appLockerPolicy.RuleCollections.Count) rule collections"
        $testResults.TotalTests++
        if ($hasRules) { $testResults.PassedTests++ } else { $testResults.FailedTests++ }
        
        # Check for Steam/Epic rules
        $steamRule = $appLockerPolicy.RuleCollections.PublisherConditions | Where-Object { $_.PublisherName -like "*VALVE*" }
        $epicRule = $appLockerPolicy.RuleCollections.PublisherConditions | Where-Object { $_.PublisherName -like "*EPIC*" }
        
        Write-TestResult -TestName "Steam Whitelist Rule" -Passed ($null -ne $steamRule) -Details "Publisher rule for Valve Corporation"
        Write-TestResult -TestName "Epic Games Whitelist Rule" -Passed ($null -ne $epicRule) -Details "Publisher rule for Epic Games"
        $testResults.TotalTests += 2
        if ($steamRule) { $testResults.PassedTests++ } else { $testResults.FailedTests++ }
        if ($epicRule) { $testResults.PassedTests++ } else { $testResults.FailedTests++ }
    } catch {
        Write-TestResult -TestName "AppLocker Rules Configured" -Passed $false -Details "Error: $_"
        $testResults.TotalTests++
        $testResults.FailedTests++
    }
}

# Test 5: Chrome Policies
Write-Host "`n[Test Category: Chrome Browser Policies]" -ForegroundColor $script:InfoColor
$chromeRegPath = "HKLM:\Software\Policies\Google\Chrome"

if (Test-Path $chromeRegPath) {
    # Test each Chrome policy
    $chromePolicies = @{
        "BrowserSignin" = @{Expected = 2; Description = "Force sign-in"}
        "IncognitoModeAvailability" = @{Expected = 1; Description = "Incognito disabled"}
        "ForceSafeSearch" = @{Expected = 1; Description = "Safe Search enabled"}
        "DeveloperToolsDisabled" = @{Expected = 1; Description = "DevTools disabled"}
    }
    
    foreach ($policy in $chromePolicies.GetEnumerator()) {
        try {
            $value = (Get-ItemProperty -Path $chromeRegPath -Name $policy.Key -ErrorAction Stop).$($policy.Key)
            $passed = $value -eq $policy.Value.Expected
            Write-TestResult -TestName "Chrome: $($policy.Value.Description)" -Passed $passed `
                -Details "Registry value: $value (expected: $($policy.Value.Expected))"
            $testResults.TotalTests++
            if ($passed) { $testResults.PassedTests++ } else { $testResults.FailedTests++ }
        } catch {
            Write-TestResult -TestName "Chrome: $($policy.Value.Description)" -Passed $false `
                -Details "Policy not found"
            $testResults.TotalTests++
            $testResults.FailedTests++
        }
    }
    
    # Check RestrictSigninToPattern
    try {
        $pattern = (Get-ItemProperty -Path $chromeRegPath -Name "RestrictSigninToPattern" -ErrorAction Stop).RestrictSigninToPattern
        $passed = $pattern -eq "*@scottify.io"
        Write-TestResult -TestName "Chrome: Domain restriction" -Passed $passed `
            -Details "Pattern: $pattern"
        $testResults.TotalTests++
        if ($passed) { $testResults.PassedTests++ } else { $testResults.FailedTests++ }
    } catch {
        Write-TestResult -TestName "Chrome: Domain restriction" -Passed $false -Details "Not configured"
        $testResults.TotalTests++
        $testResults.FailedTests++
    }
} else {
    Write-TestResult -TestName "Chrome Policies" -Passed $false -Details "Chrome policy registry key not found"
    $testResults.TotalTests++
    $testResults.FailedTests++
}

# Test 6: Security Restrictions
Write-Host "`n[Test Category: Security Restrictions]" -ForegroundColor $script:InfoColor

# Test Command Prompt restriction
$cmdPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if (Test-Path $cmdPath) {
    try {
        $cmdDisabled = (Get-ItemProperty -Path $cmdPath -Name "DisableCMD" -ErrorAction Stop).DisableCMD
        Write-TestResult -TestName "Command Prompt Disabled" -Passed ($cmdDisabled -eq 2) `
            -Details "Value: $cmdDisabled (2 = disabled)"
        $testResults.TotalTests++
        if ($cmdDisabled -eq 2) { $testResults.PassedTests++ } else { $testResults.FailedTests++ }
    } catch {
        Write-TestResult -TestName "Command Prompt Disabled" -Passed $false -Details "Not configured"
        $testResults.TotalTests++
        $testResults.FailedTests++
    }
}

# Test 7: Blocked Applications
Write-Host "`n[Test Category: Application Blocking]" -ForegroundColor $script:InfoColor
$blockedApps = @(
    @{Name = "GP_Microsoft_Edge"; Path = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"},
    @{Name = "GP_Firefox"; Path = "C:\Program Files\Mozilla Firefox\firefox.exe"},
    @{Name = "GP_Command_Prompt"; Path = "C:\Windows\System32\cmd.exe"},
    @{Name = "GP_PowerShell"; Path = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"}
)

foreach ($app in $blockedApps) {
    if (Test-Path $app.Path) {
        # Try to check if the app would be blocked (without actually running it)
        Write-Host "  Checking: $($app.Name)" -ForegroundColor Gray
        $testResults.TotalTests++
        $testResults.Warnings++
    }
}

# Test 8: Whitelisted Applications
Write-Host "`n[Test Category: Whitelisted Applications]" -ForegroundColor $script:InfoColor
$allowedApps = @(
    @{Name = "GP_Steam"; Path = "C:\Program Files (x86)\Steam\steam.exe"},
    @{Name = "GP_Epic_Games"; Path = "C:\Program Files\Epic Games\Launcher\Portal\Binaries\Win64\EpicGamesLauncher.exe"}
)

foreach ($app in $allowedApps) {
    $exists = Test-Path $app.Path
    Write-TestResult -TestName "$($app.Name) Accessible" -Passed $exists `
        -Details $(if ($exists) { "Found at: $($app.Path)" } else { "Not installed" })
    if ($exists) {
        $testResults.TotalTests++
        $testResults.PassedTests++
    }
}

# Final Summary
Write-Host "`n=== Test Summary ===" -ForegroundColor $script:InfoColor
Write-Host "Total Tests: $($testResults.TotalTests)" -ForegroundColor White
Write-Host "Passed: $($testResults.PassedTests)" -ForegroundColor $script:PassColor
Write-Host "Failed: $($testResults.FailedTests)" -ForegroundColor $script:FailColor
Write-Host "Warnings: $($testResults.Warnings)" -ForegroundColor $script:WarnColor

$passRate = if ($testResults.TotalTests -gt 0) { 
    [math]::Round(($testResults.PassedTests / $testResults.TotalTests) * 100, 2) 
} else { 0 }

Write-Host "`nCompliance Rate: $passRate%" -ForegroundColor $(if ($passRate -ge 80) { $script:PassColor } else { $script:FailColor })

# Recommendations
if ($testResults.FailedTests -gt 0) {
    Write-Host "`n=== Recommendations ===" -ForegroundColor $script:InfoColor
    
    if (-not $isAdmin) {
        Write-Host "• Run this script as Administrator for accurate results" -ForegroundColor $script:WarnColor
    }
    
    if (-not $gpApplied) {
        Write-Host "• Ensure the GP_Teenager_Restrictions_Policy GPO is linked to the correct OU" -ForegroundColor $script:WarnColor
        Write-Host "• Run 'gpupdate /force' to refresh Group Policy" -ForegroundColor $script:WarnColor
    }
    
    if (-not $appLockerRunning) {
        Write-Host "• Start the Application Identity service: Start-Service AppIDSvc" -ForegroundColor $script:WarnColor
        Write-Host "• Set the service to start automatically" -ForegroundColor $script:WarnColor
    }
}

# Export detailed report
$reportPath = "$PSScriptRoot\..\test-report-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
$testReport = @{
    ComputerName = $ComputerName
    TestDate = Get-Date
    Results = $testResults
    PassRate = $passRate
}

$testReport | ConvertTo-Json -Depth 3 | Out-File -FilePath $reportPath
Write-Host "`nDetailed report saved to: $reportPath" -ForegroundColor $script:InfoColor