<#
.SYNOPSIS
    Comprehensive Domain Controller Health Check Script
.DESCRIPTION
    This script performs detailed health checks on all domain controllers including:
    - DC availability and response
    - AD replication status
    - SYSVOL replication
    - DNS resolution
    - Critical services
    - Event log analysis
    - LDAP connectivity
    - Disk space
    - Time synchronization
.PARAMETER DomainName
    Specific domain to check. If not specified, checks current domain.
.PARAMETER HTMLReport
    Generate an HTML report in addition to console output
.PARAMETER ReportPath
    Path for the HTML report (default: current directory)
.PARAMETER EventLogHours
    Hours to look back in event logs (default: 24)
.EXAMPLE
    .\Check-DomainControllerHealth.ps1
.EXAMPLE
    .\Check-DomainControllerHealth.ps1 -HTMLReport -ReportPath "C:\Reports"
.EXAMPLE
    .\Check-DomainControllerHealth.ps1 -DomainName "child.domain.com" -EventLogHours 48
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$DomainName,
    
    [Parameter(Mandatory=$false)]
    [switch]$HTMLReport,
    
    [Parameter(Mandatory=$false)]
    [string]$ReportPath = (Get-Location).Path,
    
    [Parameter(Mandatory=$false)]
    [int]$EventLogHours = 24
)

#region Functions

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White",
        [switch]$NoNewline
    )
    
    $params = @{
        Object = $Message
        ForegroundColor = $Color
        NoNewline = $NoNewline
    }
    Write-Host @params
}

function Get-TestResult {
    param(
        [string]$TestName,
        [bool]$Passed,
        [string]$Details = "",
        [string]$ErrorDetails = ""
    )
    
    return [PSCustomObject]@{
        TestName = $TestName
        Passed = $Passed
        Status = if ($Passed) { "PASS" } else { "FAIL" }
        Details = $Details
        ErrorDetails = $ErrorDetails
        Timestamp = Get-Date
    }
}

function Test-DCConnectivity {
    param(
        [string]$DCName
    )
    
    try {
        $result = Test-Connection -ComputerName $DCName -Count 2 -Quiet
        return $result
    }
    catch {
        return $false
    }
}

function Test-ADReplication {
    param(
        [string]$DCName
    )
    
    $results = @()
    
    try {
        # Run repadmin /showrepl
        $replOutput = repadmin /showrepl $DCName /csv | ConvertFrom-Csv
        
        foreach ($line in $replOutput) {
            if ($line.'Number of Failures' -gt 0) {
                $results += [PSCustomObject]@{
                    SourceDC = $line.'Source DSA'
                    DestinationDC = $line.'Destination DSA'
                    NamingContext = $line.'Naming Context'
                    Failures = $line.'Number of Failures'
                    LastSuccess = $line.'Last Success Time'
                    Status = "Failed"
                }
            }
        }
        
        if ($results.Count -eq 0) {
            return @{
                Success = $true
                Details = "All replication links healthy"
            }
        }
        else {
            return @{
                Success = $false
                Details = "Replication failures detected"
                Failures = $results
            }
        }
    }
    catch {
        return @{
            Success = $false
            Details = "Failed to check replication"
            Error = $_.Exception.Message
        }
    }
}

function Test-SYSVOLReplication {
    param(
        [string]$DCName
    )
    
    try {
        # Check if SYSVOL share is accessible
        $sysvolPath = "\\$DCName\SYSVOL"
        if (Test-Path $sysvolPath) {
            # Check for DFSR service
            $dfsrService = Get-Service -ComputerName $DCName -Name DFSR -ErrorAction SilentlyContinue
            if ($dfsrService -and $dfsrService.Status -eq 'Running') {
                return @{
                    Success = $true
                    Details = "SYSVOL accessible and DFSR running"
                }
            }
            else {
                # Check for FRS (legacy)
                $frsService = Get-Service -ComputerName $DCName -Name NtFrs -ErrorAction SilentlyContinue
                if ($frsService -and $frsService.Status -eq 'Running') {
                    return @{
                        Success = $true
                        Details = "SYSVOL accessible and FRS running (legacy)"
                    }
                }
                else {
                    return @{
                        Success = $false
                        Details = "SYSVOL accessible but replication service not running"
                    }
                }
            }
        }
        else {
            return @{
                Success = $false
                Details = "SYSVOL share not accessible"
            }
        }
    }
    catch {
        return @{
            Success = $false
            Details = "Failed to check SYSVOL"
            Error = $_.Exception.Message
        }
    }
}

function Test-DNSResolution {
    param(
        [string]$SourceDC,
        [string]$TargetDC,
        [string]$DomainDNS
    )
    
    try {
        # Test forward lookup
        $forwardResult = Resolve-DnsName -Name $TargetDC -Server $SourceDC -ErrorAction Stop
        
        # Test domain SRV records
        $srvRecord = "_ldap._tcp.$DomainDNS"
        $srvResult = Resolve-DnsName -Name $srvRecord -Type SRV -Server $SourceDC -ErrorAction Stop
        
        if ($forwardResult -and $srvResult) {
            return @{
                Success = $true
                Details = "DNS resolution successful"
            }
        }
        else {
            return @{
                Success = $false
                Details = "DNS resolution incomplete"
            }
        }
    }
    catch {
        return @{
            Success = $false
            Details = "DNS resolution failed"
            Error = $_.Exception.Message
        }
    }
}

function Test-CriticalServices {
    param(
        [string]$DCName
    )
    
    $criticalServices = @(
        @{Name = "GP_NTDS"; DisplayName = "GP_Active Directory Domain Services"},
        @{Name = "GP_DNS"; DisplayName = "GP_DNS Server"},
        @{Name = "GP_KDC"; DisplayName = "GP_Kerberos Key Distribution Center"},
        @{Name = "GP_Netlogon"; DisplayName = "GP_Net Logon"},
        @{Name = "GP_W32Time"; DisplayName = "GP_Windows Time"}
    )
    
    $results = @()
    $allRunning = $true
    
    foreach ($service in $criticalServices) {
        try {
            $svc = Get-Service -ComputerName $DCName -Name $service.Name -ErrorAction Stop
            $results += [PSCustomObject]@{
                Service = $service.DisplayName
                Status = $svc.Status
                Running = ($svc.Status -eq 'Running')
            }
            
            if ($svc.Status -ne 'Running') {
                $allRunning = $false
            }
        }
        catch {
            $results += [PSCustomObject]@{
                Service = $service.DisplayName
                Status = "Error"
                Running = $false
            }
            $allRunning = $false
        }
    }
    
    return @{
        Success = $allRunning
        Services = $results
    }
}

function Get-ADEventLogErrors {
    param(
        [string]$DCName,
        [int]$Hours
    )
    
    $startTime = (Get-Date).AddHours(-$Hours)
    $results = @()
    
    $eventLogs = @(
        @{LogName = "GP_Directory Service"; EventIDs = @(1083, 1311, 1864, 1865, 2042, 2043)},
        @{LogName = "GP_System"; EventIDs = @(5774, 5775, 5781, 5783)},
        @{LogName = "GP_DNS Server"; EventIDs = @(4013, 4015, 4016)}
    )
    
    foreach ($log in $eventLogs) {
        try {
            $events = Get-WinEvent -ComputerName $DCName -FilterHashtable @{
                LogName = $log.LogName
                Level = @(1,2,3) # Critical, Error, Warning
                StartTime = $startTime
            } -ErrorAction SilentlyContinue | Where-Object { $_.Id -in $log.EventIDs }
            
            foreach ($event in $events) {
                $results += [PSCustomObject]@{
                    TimeCreated = $event.TimeCreated
                    LogName = $log.LogName
                    EventID = $event.Id
                    Level = $event.LevelDisplayName
                    Message = $event.Message.Substring(0, [Math]::Min(200, $event.Message.Length))
                }
            }
        }
        catch {
            # Log might not exist or be accessible
        }
    }
    
    return $results
}

function Test-LDAPConnectivity {
    param(
        [string]$DCName
    )
    
    try {
        $ldapPath = "LDAP://$DCName"
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
        $searcher.Filter = "(objectClass=domain)"
        $searcher.SearchScope = "Base"
        $searcher.PropertiesToLoad.Add("name") | Out-Null
        
        $result = $searcher.FindOne()
        
        if ($result) {
            return @{
                Success = $true
                Details = "LDAP connectivity verified"
            }
        }
        else {
            return @{
                Success = $false
                Details = "LDAP query returned no results"
            }
        }
    }
    catch {
        return @{
            Success = $false
            Details = "LDAP connection failed"
            Error = $_.Exception.Message
        }
    }
}

function Test-DiskSpace {
    param(
        [string]$DCName
    )
    
    try {
        $volumes = Get-WmiObject -ComputerName $DCName -Class Win32_LogicalDisk -Filter "DriveType=3"
        $results = @()
        $allHealthy = $true
        
        foreach ($volume in $volumes) {
            $freePercent = [math]::Round(($volume.FreeSpace / $volume.Size) * 100, 2)
            $freeGB = [math]::Round($volume.FreeSpace / 1GB, 2)
            
            $healthy = $freePercent -gt 10
            if (-not $healthy) { $allHealthy = $false }
            
            $results += [PSCustomObject]@{
                Drive = $volume.DeviceID
                TotalGB = [math]::Round($volume.Size / 1GB, 2)
                FreeGB = $freeGB
                FreePercent = $freePercent
                Healthy = $healthy
            }
        }
        
        return @{
            Success = $allHealthy
            Volumes = $results
        }
    }
    catch {
        return @{
            Success = $false
            Details = "Failed to check disk space"
            Error = $_.Exception.Message
        }
    }
}

function Test-TimeSync {
    param(
        [string[]]$DCNames
    )
    
    $results = @()
    $maxDrift = 0
    
    foreach ($dc in $DCNames) {
        try {
            $w32tm = w32tm /stripchart /computer:$dc /samples:1 /dataonly
            $timeLine = $w32tm | Where-Object { $_ -match "error:" -or $_ -match "\d+\.\d+s$" }
            
            if ($timeLine -match "(-?\d+\.\d+)s") {
                $offset = [math]::Abs([double]$matches[1])
                $results += [PSCustomObject]@{
                    DC = $dc
                    Offset = $offset
                    Status = if ($offset -lt 1) { "Healthy" } else { "Warning" }
                }
                
                if ($offset -gt $maxDrift) { $maxDrift = $offset }
            }
            else {
                $results += [PSCustomObject]@{
                    DC = $dc
                    Offset = -1
                    Status = "Error"
                }
            }
        }
        catch {
            $results += [PSCustomObject]@{
                DC = $dc
                Offset = -1
                Status = "Error"
            }
        }
    }
    
    return @{
        Success = ($maxDrift -lt 5)
        MaxDrift = $maxDrift
        Results = $results
    }
}

function New-HTMLReport {
    param(
        [array]$TestResults,
        [string]$DomainName,
        [string]$ReportPath
    )
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Domain Controller Health Report - $DomainName</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .summary { background-color: white; padding: 20px; margin: 20px 0; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .test-section { background-color: white; padding: 20px; margin: 20px 0; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .pass { color: #27ae60; font-weight: bold; }
        .fail { color: #e74c3c; font-weight: bold; }
        .warning { color: #f39c12; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th { background-color: #34495e; color: white; padding: 10px; text-align: left; }
        td { padding: 8px; border-bottom: 1px solid #ddd; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .details { font-size: 0.9em; color: #555; }
        .error { background-color: #ffe6e6; padding: 5px; border-radius: 3px; margin: 5px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Domain Controller Health Report</h1>
        <p>Domain: $DomainName</p>
        <p>Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <table>
            <tr>
                <th>Test Category</th>
                <th>Status</th>
                <th>Details</th>
            </tr>
"@

    # Group results by DC
    $dcGroups = $TestResults | Group-Object -Property DC
    
    foreach ($dcGroup in $dcGroups) {
        $dcName = $dcGroup.Name
        $dcTests = $dcGroup.Group
        
        $html += @"
        </table>
    </div>
    
    <div class="test-section">
        <h2>Domain Controller: $dcName</h2>
        <table>
            <tr>
                <th>Test</th>
                <th>Status</th>
                <th>Details</th>
            </tr>
"@
        
        foreach ($test in $dcTests) {
            $statusClass = if ($test.Passed) { "pass" } else { "fail" }
            $statusText = if ($test.Passed) { "PASS" } else { "FAIL" }
            
            $html += @"
            <tr>
                <td>$($test.TestName)</td>
                <td class="$statusClass">$statusText</td>
                <td class="details">$($test.Details)</td>
            </tr>
"@
            
            if ($test.ErrorDetails) {
                $html += @"
            <tr>
                <td colspan="3" class="error">Error: $($test.ErrorDetails)</td>
            </tr>
"@
            }
        }
        
        $html += "</table>"
    }
    
    $html += @"
    </div>
</body>
</html>
"@
    
    $reportFileName = "GP_DC_Health_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    $fullPath = Join-Path $ReportPath $reportFileName
    
    $html | Out-File -FilePath $fullPath -Encoding UTF8
    
    return $fullPath
}

#endregion

#region Main Script

# Initialize
$script:TestResults = @()
$ErrorActionPreference = "Stop"

Write-ColorOutput "`n=== Domain Controller Health Check ===" -Color Cyan
Write-ColorOutput "Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n" -Color Gray

try {
    # Get domain information
    if ($DomainName) {
        $domain = Get-ADDomain -Identity $DomainName
    }
    else {
        $domain = Get-ADDomain
        $DomainName = $domain.DNSRoot
    }
    
    Write-ColorOutput "Domain: $($domain.DNSRoot)" -Color Yellow
    Write-ColorOutput "Forest: $($domain.Forest)`n" -Color Yellow
    
    # Get all domain controllers
    $domainControllers = Get-ADDomainController -Filter * -Server $domain.PDCEmulator
    
    Write-ColorOutput "Found $($domainControllers.Count) Domain Controllers:`n" -Color Green
    foreach ($dc in $domainControllers) {
        Write-ColorOutput "  - $($dc.HostName) [$($dc.IPv4Address)]" -Color White
    }
    Write-ColorOutput "`n" -Color White
    
    # Test each domain controller
    foreach ($dc in $domainControllers) {
        $dcName = $dc.HostName
        Write-ColorOutput "`n--- Testing: $dcName ---" -Color Cyan
        
        # 1. Test DC Connectivity
        Write-ColorOutput "  Checking connectivity... " -Color White -NoNewline
        $pingTest = Test-DCConnectivity -DCName $dcName
        if ($pingTest) {
            Write-ColorOutput "PASS" -Color Green
            $script:TestResults += Get-TestResult -TestName "Connectivity" -Passed $true -Details "DC is reachable" | 
                Add-Member -NotePropertyName DC -NotePropertyValue $dcName -PassThru
        }
        else {
            Write-ColorOutput "FAIL" -Color Red
            $script:TestResults += Get-TestResult -TestName "Connectivity" -Passed $false -Details "DC is not reachable" | 
                Add-Member -NotePropertyName DC -NotePropertyValue $dcName -PassThru
            continue
        }
        
        # 2. Test AD Replication
        Write-ColorOutput "  Checking AD replication... " -Color White -NoNewline
        $replTest = Test-ADReplication -DCName $dcName
        if ($replTest.Success) {
            Write-ColorOutput "PASS" -Color Green
            $script:TestResults += Get-TestResult -TestName "AD Replication" -Passed $true -Details $replTest.Details | 
                Add-Member -NotePropertyName DC -NotePropertyValue $dcName -PassThru
        }
        else {
            Write-ColorOutput "FAIL" -Color Red
            $script:TestResults += Get-TestResult -TestName "AD Replication" -Passed $false -Details $replTest.Details -ErrorDetails $replTest.Error | 
                Add-Member -NotePropertyName DC -NotePropertyValue $dcName -PassThru
        }
        
        # 3. Test SYSVOL Replication
        Write-ColorOutput "  Checking SYSVOL replication... " -Color White -NoNewline
        $sysvolTest = Test-SYSVOLReplication -DCName $dcName
        if ($sysvolTest.Success) {
            Write-ColorOutput "PASS" -Color Green
            $script:TestResults += Get-TestResult -TestName "SYSVOL Replication" -Passed $true -Details $sysvolTest.Details | 
                Add-Member -NotePropertyName DC -NotePropertyValue $dcName -PassThru
        }
        else {
            Write-ColorOutput "FAIL" -Color Red
            $script:TestResults += Get-TestResult -TestName "SYSVOL Replication" -Passed $false -Details $sysvolTest.Details -ErrorDetails $sysvolTest.Error | 
                Add-Member -NotePropertyName DC -NotePropertyValue $dcName -PassThru
        }
        
        # 4. Test DNS Resolution
        Write-ColorOutput "  Checking DNS resolution... " -Color White -NoNewline
        $dnsTest = Test-DNSResolution -SourceDC $dcName -TargetDC $dcName -DomainDNS $domain.DNSRoot
        if ($dnsTest.Success) {
            Write-ColorOutput "PASS" -Color Green
            $script:TestResults += Get-TestResult -TestName "DNS Resolution" -Passed $true -Details $dnsTest.Details | 
                Add-Member -NotePropertyName DC -NotePropertyValue $dcName -PassThru
        }
        else {
            Write-ColorOutput "FAIL" -Color Red
            $script:TestResults += Get-TestResult -TestName "DNS Resolution" -Passed $false -Details $dnsTest.Details -ErrorDetails $dnsTest.Error | 
                Add-Member -NotePropertyName DC -NotePropertyValue $dcName -PassThru
        }
        
        # 5. Test Critical Services
        Write-ColorOutput "  Checking critical services... " -Color White -NoNewline
        $servicesTest = Test-CriticalServices -DCName $dcName
        if ($servicesTest.Success) {
            Write-ColorOutput "PASS" -Color Green
            $details = "All critical services running"
        }
        else {
            Write-ColorOutput "FAIL" -Color Red
            $failedServices = $servicesTest.Services | Where-Object { -not $_.Running }
            $details = "Failed services: $($failedServices.Service -join ', ')"
        }
        $script:TestResults += Get-TestResult -TestName "Critical Services" -Passed $servicesTest.Success -Details $details | 
            Add-Member -NotePropertyName DC -NotePropertyValue $dcName -PassThru
        
        # 6. Check Event Logs
        Write-ColorOutput "  Checking event logs... " -Color White -NoNewline
        $events = Get-ADEventLogErrors -DCName $dcName -Hours $EventLogHours
        if ($events.Count -eq 0) {
            Write-ColorOutput "PASS" -Color Green
            $script:TestResults += Get-TestResult -TestName "Event Logs" -Passed $true -Details "No critical errors in last $EventLogHours hours" | 
                Add-Member -NotePropertyName DC -NotePropertyValue $dcName -PassThru
        }
        else {
            Write-ColorOutput "WARNING" -Color Yellow
            $script:TestResults += Get-TestResult -TestName "Event Logs" -Passed $false -Details "$($events.Count) error events found" | 
                Add-Member -NotePropertyName DC -NotePropertyValue $dcName -PassThru
        }
        
        # 7. Test LDAP Connectivity
        Write-ColorOutput "  Testing LDAP connectivity... " -Color White -NoNewline
        $ldapTest = Test-LDAPConnectivity -DCName $dcName
        if ($ldapTest.Success) {
            Write-ColorOutput "PASS" -Color Green
            $script:TestResults += Get-TestResult -TestName "LDAP Connectivity" -Passed $true -Details $ldapTest.Details | 
                Add-Member -NotePropertyName DC -NotePropertyValue $dcName -PassThru
        }
        else {
            Write-ColorOutput "FAIL" -Color Red
            $script:TestResults += Get-TestResult -TestName "LDAP Connectivity" -Passed $false -Details $ldapTest.Details -ErrorDetails $ldapTest.Error | 
                Add-Member -NotePropertyName DC -NotePropertyValue $dcName -PassThru
        }
        
        # 8. Check Disk Space
        Write-ColorOutput "  Checking disk space... " -Color White -NoNewline
        $diskTest = Test-DiskSpace -DCName $dcName
        if ($diskTest.Success) {
            Write-ColorOutput "PASS" -Color Green
            $details = "All volumes have adequate free space"
        }
        else {
            Write-ColorOutput "FAIL" -Color Red
            $lowVolumes = $diskTest.Volumes | Where-Object { -not $_.Healthy }
            $details = "Low disk space on: $($lowVolumes.Drive -join ', ')"
        }
        $script:TestResults += Get-TestResult -TestName "Disk Space" -Passed $diskTest.Success -Details $details | 
            Add-Member -NotePropertyName DC -NotePropertyValue $dcName -PassThru
    }
    
    # 9. Test Time Synchronization
    Write-ColorOutput "`n  Checking time synchronization across all DCs... " -Color White -NoNewline
    $timeTest = Test-TimeSync -DCNames $domainControllers.HostName
    if ($timeTest.Success) {
        Write-ColorOutput "PASS" -Color Green
        $details = "Maximum time drift: $($timeTest.MaxDrift) seconds"
    }
    else {
        Write-ColorOutput "FAIL" -Color Red
        $details = "Excessive time drift detected: $($timeTest.MaxDrift) seconds"
    }
    
    foreach ($dc in $domainControllers) {
        $script:TestResults += Get-TestResult -TestName "Time Synchronization" -Passed $timeTest.Success -Details $details | 
            Add-Member -NotePropertyName DC -NotePropertyValue $dc.HostName -PassThru
    }
    
    # Summary
    Write-ColorOutput "`n`n=== SUMMARY ===" -Color Cyan
    $totalTests = $script:TestResults.Count
    $passedTests = ($script:TestResults | Where-Object { $_.Passed }).Count
    $failedTests = $totalTests - $passedTests
    $passRate = [math]::Round(($passedTests / $totalTests) * 100, 2)
    
    Write-ColorOutput "Total Tests: $totalTests" -Color White
    Write-ColorOutput "Passed: $passedTests" -Color Green
    Write-ColorOutput "Failed: $failedTests" -Color Red
    Write-ColorOutput "Pass Rate: $passRate%`n" -Color Yellow
    
    # Generate HTML Report if requested
    if ($HTMLReport) {
        Write-ColorOutput "`nGenerating HTML report... " -Color White -NoNewline
        $reportFile = New-HTMLReport -TestResults $script:TestResults -DomainName $DomainName -ReportPath $ReportPath
        Write-ColorOutput "Done" -Color Green
        Write-ColorOutput "Report saved to: $reportFile" -Color Yellow
    }
    
    # Display failed tests
    if ($failedTests -gt 0) {
        Write-ColorOutput "`n=== FAILED TESTS ===" -Color Red
        $script:TestResults | Where-Object { -not $_.Passed } | ForEach-Object {
            Write-ColorOutput "$($_.DC) - $($_.TestName): $($_.Details)" -Color Red
            if ($_.ErrorDetails) {
                Write-ColorOutput "  Error: $($_.ErrorDetails)" -Color Gray
            }
        }
    }
    
    Write-ColorOutput "`nHealth check completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Color Gray
    
}
catch {
    Write-ColorOutput "`nERROR: $($_.Exception.Message)" -Color Red
    Write-ColorOutput "Stack Trace: $($_.ScriptStackTrace)" -Color Gray
    exit 1
}

#endregion