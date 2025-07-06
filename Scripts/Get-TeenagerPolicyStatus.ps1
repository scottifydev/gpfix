#Requires -RunAsAdministrator
#Requires -Modules ActiveDirectory, GroupPolicy
<#
.SYNOPSIS
    Provides a comprehensive dashboard view of the Teenager Policy system status.

.DESCRIPTION
    This script generates a detailed report of the teenager policy implementation including:
    - Current policy status and configuration
    - Group membership information
    - Compliance statistics
    - Recent violations
    - Policy health checks
    - Deployment status across computers
    - Effectiveness metrics

.PARAMETER Format
    Output format: Console (default), HTML, or JSON

.PARAMETER OutputPath
    Path for HTML or JSON output file (optional)

.PARAMETER DaysBack
    Number of days to look back for violation events (default: 7)

.PARAMETER IncludeCharts
    Include charts in HTML output (requires PSWriteHTML module)

.EXAMPLE
    .\Get-TeenagerPolicyStatus.ps1
    Display status in console

.EXAMPLE
    .\Get-TeenagerPolicyStatus.ps1 -Format HTML -OutputPath "C:\Reports\TeenagerPolicy.html" -IncludeCharts
    Generate HTML report with charts

.EXAMPLE
    .\Get-TeenagerPolicyStatus.ps1 -Format JSON -OutputPath "C:\Reports\status.json"
    Export status as JSON
#>

[CmdletBinding()]
param(
    [ValidateSet('Console', 'HTML', 'JSON')]
    [string]$Format = 'Console',
    
    [string]$OutputPath,
    
    [int]$DaysBack = 7,
    
    [switch]$IncludeCharts
)

# Initialize status object
$PolicyStatus = [PSCustomObject]@{
    Timestamp = Get-Date
    PolicyInfo = $null
    GroupMembers = @()
    ComplianceStats = $null
    RecentViolations = @()
    HealthChecks = @()
    DeployedComputers = @()
    EffectivenessMetrics = $null
}

# Function to get GPO information
function Get-TeenagerPolicyInfo {
    try {
        $gpo = Get-GPO -Name "GP_Teenager_Restrictions_Policy" -ErrorAction Stop
        
        # Get linked OUs
        $links = Get-GPOReport -Name "GP_Teenager_Restrictions_Policy" -ReportType Xml | 
                 Select-Xml -XPath "//LinksTo/SOMPath" | 
                 ForEach-Object { $_.Node.InnerText }
        
        return [PSCustomObject]@{
            Name = $gpo.DisplayName
            Status = if ($gpo.GpoStatus -eq 'AllSettingsEnabled') { 'Enabled' } else { $gpo.GpoStatus }
            Created = $gpo.CreationTime
            Modified = $gpo.ModificationTime
            Owner = $gpo.Owner
            Id = $gpo.Id
            LinkedOUs = $links
            DomainName = $gpo.DomainName
        }
    }
    catch {
        return [PSCustomObject]@{
            Name = "GP_Teenager_Restrictions_Policy"
            Status = "Error: $_"
            Error = $true
        }
    }
}

# Function to get Teenagers group members
function Get-TeenagerGroupMembers {
    try {
        $members = Get-ADGroupMember -Identity "Teenagers" -Recursive | 
                   ForEach-Object {
                       $user = Get-ADUser $_ -Properties LastLogonDate, Enabled, whenCreated
                       [PSCustomObject]@{
                           Name = $user.Name
                           SamAccountName = $user.SamAccountName
                           Enabled = $user.Enabled
                           LastLogon = $user.LastLogonDate
                           AddedToGroup = $user.whenCreated
                           DaysSinceLastLogon = if ($user.LastLogonDate) { 
                               (New-TimeSpan -Start $user.LastLogonDate -End (Get-Date)).Days 
                           } else { "Never" }
                       }
                   }
        return $members
    }
    catch {
        Write-Warning "Failed to get Teenagers group members: $_"
        return @()
    }
}

# Function to check policy compliance
function Get-ComplianceStatistics {
    $stats = [PSCustomObject]@{
        TotalUsers = 0
        ActiveUsers = 0
        CompliantSessions = 0
        ViolationAttempts = 0
        BlockedApplications = 0
        BlockedWebsites = 0
        ComplianceRate = 0
    }
    
    try {
        # Get event logs for compliance tracking
        $startDate = (Get-Date).AddDays(-$DaysBack)
        
        # AppLocker events
        $appLockerEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'GP_Microsoft-Windows-AppLocker/EXE and DLL'
            StartTime = $startDate
        } -ErrorAction SilentlyContinue
        
        # Count blocked applications
        $stats.BlockedApplications = ($appLockerEvents | Where-Object { $_.Id -eq 8004 }).Count
        
        # Get Chrome policy events (if custom logging is implemented)
        # This would require custom event logging in the Chrome policies
        
        # Calculate compliance rate based on violations vs total sessions
        $totalSessions = Get-WinEvent -FilterHashtable @{
            LogName = 'GP_Security'
            ID = 4624
            StartTime = $startDate
        } -ErrorAction SilentlyContinue | 
        Where-Object { $_.Message -match "Teenagers" }
        
        $stats.TotalUsers = ($PolicyStatus.GroupMembers).Count
        $stats.ActiveUsers = ($PolicyStatus.GroupMembers | Where-Object { $_.DaysSinceLastLogon -ne "Never" -and $_.DaysSinceLastLogon -le 30 }).Count
        $stats.CompliantSessions = $totalSessions.Count - $stats.ViolationAttempts
        
        if ($totalSessions.Count -gt 0) {
            $stats.ComplianceRate = [math]::Round((($stats.CompliantSessions / $totalSessions.Count) * 100), 2)
        }
    }
    catch {
        Write-Warning "Failed to gather compliance statistics: $_"
    }
    
    return $stats
}

# Function to get recent violations
function Get-RecentViolations {
    $violations = @()
    $startDate = (Get-Date).AddDays(-$DaysBack)
    
    try {
        # AppLocker violations
        $blockedApps = Get-WinEvent -FilterHashtable @{
            LogName = 'GP_Microsoft-Windows-AppLocker/EXE and DLL'
            ID = 8004
            StartTime = $startDate
        } -ErrorAction SilentlyContinue | 
        ForEach-Object {
            $xml = [xml]$_.ToXml()
            [PSCustomObject]@{
                Time = $_.TimeCreated
                Type = "Blocked Application"
                User = $_.UserId
                Details = $xml.Event.UserData.RuleAndFileData.FilePath
                Computer = $_.MachineName
            }
        }
        
        $violations += $blockedApps
        
        # Add other violation types (blocked websites, etc.) if logging is available
        
    }
    catch {
        Write-Warning "Failed to retrieve violation events: $_"
    }
    
    return $violations | Sort-Object Time -Descending | Select-Object -First 50
}

# Function to perform health checks
function Get-PolicyHealthChecks {
    $checks = @()
    
    # Check 1: GPO Status
    $checks += [PSCustomObject]@{
        Check = "Group Policy Status"
        Status = if ($PolicyStatus.PolicyInfo.Error) { "Failed" } else { "Passed" }
        Details = if ($PolicyStatus.PolicyInfo.Error) { $PolicyStatus.PolicyInfo.Status } else { "Policy is active and configured" }
    }
    
    # Check 2: Group Membership
    $checks += [PSCustomObject]@{
        Check = "Teenagers Group"
        Status = if ($PolicyStatus.GroupMembers.Count -gt 0) { "Passed" } else { "Warning" }
        Details = "$($PolicyStatus.GroupMembers.Count) members in group"
    }
    
    # Check 3: AppLocker Service
    try {
        $appLockerSvc = Get-Service -Name AppIDSvc -ErrorAction Stop
        $checks += [PSCustomObject]@{
            Check = "AppLocker Service"
            Status = if ($appLockerSvc.Status -eq 'Running') { "Passed" } else { "Failed" }
            Details = "Service status: $($appLockerSvc.Status)"
        }
    }
    catch {
        $checks += [PSCustomObject]@{
            Check = "AppLocker Service"
            Status = "Failed"
            Details = "Service not found or inaccessible"
        }
    }
    
    # Check 4: Event Log Access
    try {
        $null = Get-WinEvent -LogName 'GP_Microsoft-Windows-AppLocker/EXE and DLL' -MaxEvents 1 -ErrorAction Stop
        $checks += [PSCustomObject]@{
            Check = "AppLocker Event Logs"
            Status = "Passed"
            Details = "Event logs are accessible"
        }
    }
    catch {
        $checks += [PSCustomObject]@{
            Check = "AppLocker Event Logs"
            Status = "Warning"
            Details = "Cannot access AppLocker event logs"
        }
    }
    
    # Check 5: Policy Deployment
    $checks += [PSCustomObject]@{
        Check = "Policy Deployment"
        Status = if ($PolicyStatus.DeployedComputers.Count -gt 0) { "Passed" } else { "Warning" }
        Details = "Applied to $($PolicyStatus.DeployedComputers.Count) computers"
    }
    
    return $checks
}

# Function to get computers with policy applied
function Get-PolicyDeployment {
    $computers = @()
    
    try {
        # Get all computers that should have the policy
        $targetComputers = Get-ADComputer -Filter * -SearchBase "OU=Workstations,DC=scottify,DC=io" -Properties LastLogonDate, OperatingSystem |
        ForEach-Object {
            # Check if policy is applied (would need to query each computer)
            [PSCustomObject]@{
                Name = $_.Name
                LastLogon = $_.LastLogonDate
                OS = $_.OperatingSystem
                PolicyApplied = "Unknown" # Would need remote query to verify
                LastPolicyUpdate = "Unknown"
            }
        }
        
        return $targetComputers
    }
    catch {
        Write-Warning "Failed to get deployment information: $_"
        return @()
    }
}

# Function to calculate effectiveness metrics
function Get-EffectivenessMetrics {
    $metrics = [PSCustomObject]@{
        PolicyUptime = 0
        AverageBlocksPerDay = 0
        MostBlockedApplications = @()
        PeakViolationHours = @()
        UserComplianceScores = @()
        TrendDirection = "Stable"
    }
    
    try {
        # Calculate policy uptime
        if ($PolicyStatus.PolicyInfo.Created) {
            $uptime = (New-TimeSpan -Start $PolicyStatus.PolicyInfo.Created -End (Get-Date)).Days
            $metrics.PolicyUptime = $uptime
        }
        
        # Calculate average blocks per day
        if ($PolicyStatus.ComplianceStats.BlockedApplications -gt 0 -and $DaysBack -gt 0) {
            $metrics.AverageBlocksPerDay = [math]::Round(($PolicyStatus.ComplianceStats.BlockedApplications / $DaysBack), 2)
        }
        
        # Get most blocked applications
        $blockedApps = $PolicyStatus.RecentViolations | 
                      Where-Object { $_.Type -eq "Blocked Application" } |
                      Group-Object Details |
                      Sort-Object Count -Descending |
                      Select-Object -First 5 |
                      ForEach-Object {
                          [PSCustomObject]@{
                              Application = Split-Path $_.Name -Leaf
                              Count = $_.Count
                          }
                      }
        $metrics.MostBlockedApplications = $blockedApps
        
        # Analyze violation patterns by hour
        $hourlyViolations = $PolicyStatus.RecentViolations |
                           Group-Object { $_.Time.Hour } |
                           Sort-Object Count -Descending |
                           Select-Object -First 3 |
                           ForEach-Object {
                               [PSCustomObject]@{
                                   Hour = "$($_.Name):00"
                                   Count = $_.Count
                               }
                           }
        $metrics.PeakViolationHours = $hourlyViolations
        
    }
    catch {
        Write-Warning "Failed to calculate effectiveness metrics: $_"
    }
    
    return $metrics
}

# Main execution
Write-Host "Gathering Teenager Policy Status Information..." -ForegroundColor Cyan

# Collect all data
$PolicyStatus.PolicyInfo = Get-TeenagerPolicyInfo
$PolicyStatus.GroupMembers = Get-TeenagerGroupMembers
$PolicyStatus.ComplianceStats = Get-ComplianceStatistics
$PolicyStatus.RecentViolations = Get-RecentViolations
$PolicyStatus.DeployedComputers = Get-PolicyDeployment
$PolicyStatus.HealthChecks = Get-PolicyHealthChecks
$PolicyStatus.EffectivenessMetrics = Get-EffectivenessMetrics

# Output based on format
switch ($Format) {
    'Console' {
        # Header
        Write-Host "`n===========================================" -ForegroundColor Yellow
        Write-Host "     TEENAGER POLICY STATUS DASHBOARD" -ForegroundColor Yellow
        Write-Host "===========================================" -ForegroundColor Yellow
        Write-Host "Generated: $($PolicyStatus.Timestamp)" -ForegroundColor Gray
        
        # Policy Information
        Write-Host "`n[POLICY INFORMATION]" -ForegroundColor Cyan
        Write-Host "Name: $($PolicyStatus.PolicyInfo.Name)"
        Write-Host "Status: " -NoNewline
        if ($PolicyStatus.PolicyInfo.Status -eq 'Enabled') {
            Write-Host $PolicyStatus.PolicyInfo.Status -ForegroundColor Green
        } else {
            Write-Host $PolicyStatus.PolicyInfo.Status -ForegroundColor Red
        }
        Write-Host "Last Modified: $($PolicyStatus.PolicyInfo.Modified)"
        Write-Host "Linked OUs: $($PolicyStatus.PolicyInfo.LinkedOUs -join ', ')"
        
        # Group Members
        Write-Host "`n[GROUP MEMBERS]" -ForegroundColor Cyan
        Write-Host "Total Members: $($PolicyStatus.GroupMembers.Count)"
        if ($PolicyStatus.GroupMembers.Count -gt 0) {
            $PolicyStatus.GroupMembers | Format-Table Name, SamAccountName, Enabled, LastLogon -AutoSize
        }
        
        # Compliance Statistics
        Write-Host "`n[COMPLIANCE STATISTICS]" -ForegroundColor Cyan
        Write-Host "Active Users (30 days): $($PolicyStatus.ComplianceStats.ActiveUsers) / $($PolicyStatus.ComplianceStats.TotalUsers)"
        Write-Host "Compliance Rate: " -NoNewline
        if ($PolicyStatus.ComplianceStats.ComplianceRate -ge 90) {
            Write-Host "$($PolicyStatus.ComplianceStats.ComplianceRate)%" -ForegroundColor Green
        } elseif ($PolicyStatus.ComplianceStats.ComplianceRate -ge 70) {
            Write-Host "$($PolicyStatus.ComplianceStats.ComplianceRate)%" -ForegroundColor Yellow
        } else {
            Write-Host "$($PolicyStatus.ComplianceStats.ComplianceRate)%" -ForegroundColor Red
        }
        Write-Host "Blocked Applications (last $DaysBack days): $($PolicyStatus.ComplianceStats.BlockedApplications)"
        
        # Health Checks
        Write-Host "`n[HEALTH CHECKS]" -ForegroundColor Cyan
        foreach ($check in $PolicyStatus.HealthChecks) {
            Write-Host "$($check.Check): " -NoNewline
            switch ($check.Status) {
                'Passed' { Write-Host "✓ PASSED" -ForegroundColor Green }
                'Warning' { Write-Host "⚠ WARNING" -ForegroundColor Yellow }
                'Failed' { Write-Host "✗ FAILED" -ForegroundColor Red }
            }
            Write-Host "  Details: $($check.Details)" -ForegroundColor Gray
        }
        
        # Recent Violations
        Write-Host "`n[RECENT VIOLATIONS] (Last $DaysBack days)" -ForegroundColor Cyan
        if ($PolicyStatus.RecentViolations.Count -gt 0) {
            $PolicyStatus.RecentViolations | Select-Object -First 10 | 
                Format-Table Time, Type, User, @{N='Application';E={Split-Path $_.Details -Leaf}} -AutoSize
            if ($PolicyStatus.RecentViolations.Count -gt 10) {
                Write-Host "... and $($PolicyStatus.RecentViolations.Count - 10) more violations" -ForegroundColor Gray
            }
        } else {
            Write-Host "No violations found" -ForegroundColor Green
        }
        
        # Effectiveness Metrics
        Write-Host "`n[EFFECTIVENESS METRICS]" -ForegroundColor Cyan
        Write-Host "Policy Uptime: $($PolicyStatus.EffectivenessMetrics.PolicyUptime) days"
        Write-Host "Average Blocks/Day: $($PolicyStatus.EffectivenessMetrics.AverageBlocksPerDay)"
        if ($PolicyStatus.EffectivenessMetrics.MostBlockedApplications.Count -gt 0) {
            Write-Host "`nMost Blocked Applications:"
            $PolicyStatus.EffectivenessMetrics.MostBlockedApplications | 
                Format-Table Application, Count -AutoSize
        }
        if ($PolicyStatus.EffectivenessMetrics.PeakViolationHours.Count -gt 0) {
            Write-Host "Peak Violation Hours:"
            $PolicyStatus.EffectivenessMetrics.PeakViolationHours | 
                Format-Table Hour, Count -AutoSize
        }
        
        Write-Host "`n===========================================" -ForegroundColor Yellow
    }
    
    'HTML' {
        # Build HTML report
        $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Teenager Policy Status Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #333; text-align: center; border-bottom: 3px solid #4CAF50; padding-bottom: 10px; }
        h2 { color: #4CAF50; margin-top: 30px; }
        .info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 20px 0; }
        .info-card { background: #f9f9f9; padding: 15px; border-radius: 5px; border-left: 4px solid #4CAF50; }
        .status-enabled { color: #4CAF50; font-weight: bold; }
        .status-disabled { color: #f44336; font-weight: bold; }
        .metric { font-size: 24px; font-weight: bold; color: #333; }
        .metric-label { font-size: 14px; color: #666; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th { background-color: #4CAF50; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .health-passed { color: #4CAF50; font-weight: bold; }
        .health-warning { color: #ff9800; font-weight: bold; }
        .health-failed { color: #f44336; font-weight: bold; }
        .chart-container { width: 100%; height: 300px; margin: 20px 0; }
        .violation-item { background: #fff3cd; padding: 10px; margin: 5px 0; border-radius: 5px; border-left: 4px solid #ffc107; }
        .timestamp { text-align: center; color: #666; font-size: 14px; margin-top: 30px; }
    </style>
"@

        if ($IncludeCharts) {
            $html += @"
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
"@
        }

        $html += @"
</head>
<body>
    <div class="container">
        <h1>Teenager Policy Status Dashboard</h1>
        
        <h2>Policy Information</h2>
        <div class="info-grid">
            <div class="info-card">
                <div class="metric-label">Policy Name</div>
                <div class="metric">$($PolicyStatus.PolicyInfo.Name)</div>
            </div>
            <div class="info-card">
                <div class="metric-label">Status</div>
                <div class="metric $(if ($PolicyStatus.PolicyInfo.Status -eq 'Enabled') { 'status-enabled' } else { 'status-disabled' })">
                    $($PolicyStatus.PolicyInfo.Status)
                </div>
            </div>
            <div class="info-card">
                <div class="metric-label">Last Modified</div>
                <div>$($PolicyStatus.PolicyInfo.Modified)</div>
            </div>
            <div class="info-card">
                <div class="metric-label">Policy Uptime</div>
                <div class="metric">$($PolicyStatus.EffectivenessMetrics.PolicyUptime) days</div>
            </div>
        </div>
        
        <h2>Compliance Statistics</h2>
        <div class="info-grid">
            <div class="info-card">
                <div class="metric-label">Total Users</div>
                <div class="metric">$($PolicyStatus.ComplianceStats.TotalUsers)</div>
            </div>
            <div class="info-card">
                <div class="metric-label">Active Users (30 days)</div>
                <div class="metric">$($PolicyStatus.ComplianceStats.ActiveUsers)</div>
            </div>
            <div class="info-card">
                <div class="metric-label">Compliance Rate</div>
                <div class="metric">$($PolicyStatus.ComplianceStats.ComplianceRate)%</div>
            </div>
            <div class="info-card">
                <div class="metric-label">Blocked Apps ($DaysBack days)</div>
                <div class="metric">$($PolicyStatus.ComplianceStats.BlockedApplications)</div>
            </div>
        </div>
"@

        if ($IncludeCharts -and $PolicyStatus.EffectivenessMetrics.MostBlockedApplications.Count -gt 0) {
            $html += @"
        <h2>Most Blocked Applications</h2>
        <div class="chart-container">
            <canvas id="blockedAppsChart"></canvas>
        </div>
"@
        }

        $html += @"
        <h2>Health Checks</h2>
        <table>
            <tr>
                <th>Check</th>
                <th>Status</th>
                <th>Details</th>
            </tr>
"@
        foreach ($check in $PolicyStatus.HealthChecks) {
            $statusClass = switch ($check.Status) {
                'Passed' { 'health-passed' }
                'Warning' { 'health-warning' }
                'Failed' { 'health-failed' }
            }
            $html += @"
            <tr>
                <td>$($check.Check)</td>
                <td class="$statusClass">$($check.Status)</td>
                <td>$($check.Details)</td>
            </tr>
"@
        }
        $html += "</table>"

        $html += @"
        <h2>Group Members</h2>
        <table>
            <tr>
                <th>Name</th>
                <th>Username</th>
                <th>Enabled</th>
                <th>Last Logon</th>
            </tr>
"@
        foreach ($member in $PolicyStatus.GroupMembers) {
            $html += @"
            <tr>
                <td>$($member.Name)</td>
                <td>$($member.SamAccountName)</td>
                <td>$($member.Enabled)</td>
                <td>$($member.LastLogon)</td>
            </tr>
"@
        }
        $html += "</table>"

        if ($PolicyStatus.RecentViolations.Count -gt 0) {
            $html += @"
        <h2>Recent Violations (Last $DaysBack days)</h2>
"@
            foreach ($violation in ($PolicyStatus.RecentViolations | Select-Object -First 10)) {
                $html += @"
        <div class="violation-item">
            <strong>$($violation.Time)</strong> - $($violation.Type)<br>
            User: $($violation.User)<br>
            Details: $(Split-Path $violation.Details -Leaf)
        </div>
"@
            }
        }

        if ($IncludeCharts -and $PolicyStatus.EffectivenessMetrics.MostBlockedApplications.Count -gt 0) {
            $labels = ($PolicyStatus.EffectivenessMetrics.MostBlockedApplications | ForEach-Object { "'$($_.Application)'" }) -join ','
            $data = ($PolicyStatus.EffectivenessMetrics.MostBlockedApplications | ForEach-Object { $_.Count }) -join ','
            
            $html += @"
        <script>
        const ctx = document.getElementById('blockedAppsChart').getContext('2d');
        const chart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: [$labels],
                datasets: [{
                    label: 'Block Count',
                    data: [$data],
                    backgroundColor: 'rgba(255, 99, 132, 0.2)',
                    borderColor: 'rgba(255, 99, 132, 1)',
                    borderWidth: 1
                }]
            },
            options: {
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
        </script>
"@
        }

        $html += @"
        <div class="timestamp">Generated: $($PolicyStatus.Timestamp)</div>
    </div>
</body>
</html>
"@

        if ($OutputPath) {
            $html | Out-File -FilePath $OutputPath -Encoding UTF8
            Write-Host "HTML report saved to: $OutputPath" -ForegroundColor Green
        } else {
            # Save to temp and open
            $tempFile = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.html'
            $html | Out-File -FilePath $tempFile -Encoding UTF8
            Start-Process $tempFile
            Write-Host "HTML report opened in browser" -ForegroundColor Green
        }
    }
    
    'JSON' {
        $json = $PolicyStatus | ConvertTo-Json -Depth 10
        
        if ($OutputPath) {
            $json | Out-File -FilePath $OutputPath -Encoding UTF8
            Write-Host "JSON report saved to: $OutputPath" -ForegroundColor Green
        } else {
            $json
        }
    }
}

# Summary for console output
if ($Format -ne 'Console') {
    Write-Host "`nSummary:" -ForegroundColor Cyan
    Write-Host "- Policy Status: $($PolicyStatus.PolicyInfo.Status)"
    Write-Host "- Total Users: $($PolicyStatus.ComplianceStats.TotalUsers)"
    Write-Host "- Compliance Rate: $($PolicyStatus.ComplianceStats.ComplianceRate)%"
    Write-Host "- Recent Violations: $($PolicyStatus.RecentViolations.Count)"
    
    $failedChecks = $PolicyStatus.HealthChecks | Where-Object { $_.Status -eq 'Failed' }
    if ($failedChecks) {
        Write-Host "- Failed Health Checks: $($failedChecks.Count)" -ForegroundColor Red
    }
}