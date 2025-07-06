<#
.SYNOPSIS
    Comprehensive Group Policy infrastructure health check script.

.DESCRIPTION
    This script performs a thorough assessment of the Group Policy infrastructure including:
    - Group Policy service status on domain controllers
    - SYSVOL share accessibility and permissions
    - PolicyDefinitions folder structure and ADMX files
    - Group Policy processing with gpresult
    - Orphaned GPO folders in SYSVOL
    - GPO version consistency between AD and SYSVOL
    - GPOs with no links
    - WMI filter functionality
    - Client Group Policy refresh capability
    - GPO replication status across domain controllers

.PARAMETER DomainController
    Specific domain controller to check. If not specified, all DCs will be checked.

.PARAMETER OutputPath
    Path for the detailed report file. Default is current directory.

.PARAMETER SkipClientTests
    Skip tests that require client-side execution.

.EXAMPLE
    .\Check-GPOInfrastructure.ps1
    
.EXAMPLE
    .\Check-GPOInfrastructure.ps1 -DomainController "DC01" -OutputPath "C:\Reports"

.NOTES
    Author: System Administrator
    Version: 1.0
    Requires: ActiveDirectory module, GroupPolicy module, Domain Admin privileges
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$DomainController,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = $PWD.Path,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipClientTests
)

# Import required modules
Import-Module ActiveDirectory -ErrorAction Stop
Import-Module GroupPolicy -ErrorAction Stop

# Initialize variables
$script:Issues = @()
$script:Warnings = @()
$script:Information = @()
$script:Recommendations = @()
$script:ErrorCount = 0
$script:WarningCount = 0

# Get domain information
$Domain = Get-ADDomain
$DomainName = $Domain.Name
$PDCEmulator = $Domain.PDCEmulator

# Get all domain controllers if not specified
if (-not $DomainController) {
    $DomainControllers = Get-ADDomainController -Filter *
} else {
    $DomainControllers = Get-ADDomainController -Identity $DomainController
}

#region Helper Functions

function Write-ColoredOutput {
    param(
        [string]$Message,
        [string]$Type = "Info"
    )
    
    switch ($Type) {
        "Error" { 
            Write-Host $Message -ForegroundColor Red
            $script:Issues += $Message
            $script:ErrorCount++
        }
        "Warning" { 
            Write-Host $Message -ForegroundColor Yellow
            $script:Warnings += $Message
            $script:WarningCount++
        }
        "Success" { 
            Write-Host $Message -ForegroundColor Green
            $script:Information += $Message
        }
        "Info" { 
            Write-Host $Message -ForegroundColor Cyan
            $script:Information += $Message
        }
    }
}

function Test-ServiceStatus {
    param(
        [string]$ComputerName,
        [string]$ServiceName,
        [string]$DisplayName
    )
    
    try {
        $Service = Get-Service -ComputerName $ComputerName -Name $ServiceName -ErrorAction Stop
        if ($Service.Status -eq 'Running') {
            Write-ColoredOutput "[OK] $DisplayName is running on $ComputerName" -Type Success
            return $true
        } else {
            Write-ColoredOutput "[X] $DisplayName is $($Service.Status) on $ComputerName" -Type Error
            $script:Recommendations += "Start the $DisplayName service on $ComputerName"
            return $false
        }
    } catch {
        Write-ColoredOutput "[X] Failed to query $DisplayName on $ComputerName`: $_" -Type Error
        return $false
    }
}

function Test-SYSVOLShare {
    param(
        [string]$DCName
    )
    
    $SharePath = "\\$DCName\SYSVOL"
    Write-ColoredOutput "`nChecking SYSVOL share on $DCName..." -Type Info
    
    try {
        # Test share accessibility
        if (Test-Path $SharePath) {
            Write-ColoredOutput "[OK] SYSVOL share is accessible on $DCName" -Type Success
            
            # Check permissions
            $Acl = Get-Acl $SharePath -ErrorAction Stop
            $AuthenticatedUsers = $Acl.Access | Where-Object { $_.IdentityReference -like "*Authenticated Users*" }
            
            if ($AuthenticatedUsers) {
                if ($AuthenticatedUsers.FileSystemRights -match "ReadAndExecute") {
                    Write-ColoredOutput "[OK] Authenticated Users have proper read permissions" -Type Success
                } else {
                    Write-ColoredOutput "[X] Authenticated Users permissions are incorrect" -Type Warning
                    $script:Recommendations += "Fix Authenticated Users permissions on $SharePath"
                }
            } else {
                Write-ColoredOutput "[X] Authenticated Users not found in SYSVOL permissions" -Type Error
                $script:Recommendations += "Add Authenticated Users with Read & Execute permissions to $SharePath"
            }
            
            # Check for SYSVOL junction points
            $SysvolPath = Join-Path $SharePath $DomainName
            if (Test-Path $SysvolPath) {
                Write-ColoredOutput "[OK] Domain SYSVOL folder exists" -Type Success
            } else {
                Write-ColoredOutput "[X] Domain SYSVOL folder missing at $SysvolPath" -Type Error
                $script:Recommendations += "Investigate missing domain SYSVOL folder on $DCName"
            }
            
            return $true
        } else {
            Write-ColoredOutput "[X] SYSVOL share is not accessible on $DCName" -Type Error
            $script:Recommendations += "Verify SYSVOL share configuration on $DCName"
            return $false
        }
    } catch {
        Write-ColoredOutput "[X] Error checking SYSVOL on $DCName`: $_" -Type Error
        return $false
    }
}

function Test-PolicyDefinitions {
    param(
        [string]$DCName
    )
    
    $PolicyDefinitionsPath = "\\$DCName\SYSVOL\$DomainName\Policies\PolicyDefinitions"
    Write-ColoredOutput "`nChecking PolicyDefinitions on $DCName..." -Type Info
    
    try {
        if (Test-Path $PolicyDefinitionsPath) {
            Write-ColoredOutput "[OK] PolicyDefinitions folder exists" -Type Success
            
            # Count ADMX files
            $ADMXFiles = Get-ChildItem -Path $PolicyDefinitionsPath -Filter "*.admx" -ErrorAction Stop
            $ADMLFolders = Get-ChildItem -Path $PolicyDefinitionsPath -Directory -ErrorAction Stop
            
            Write-ColoredOutput "  Found $($ADMXFiles.Count) ADMX files" -Type Info
            Write-ColoredOutput "  Found $($ADMLFolders.Count) language folders" -Type Info
            
            if ($ADMXFiles.Count -eq 0) {
                Write-ColoredOutput "[X] No ADMX files found in PolicyDefinitions" -Type Warning
                $script:Recommendations += "Deploy ADMX templates to Central Store on $DCName"
            }
            
            # Check for common ADMX files
            $CommonADMX = @('Windows.admx', 'WindowsBackup.admx', 'EventLog.admx')
            foreach ($File in $CommonADMX) {
                if (-not (Test-Path (Join-Path $PolicyDefinitionsPath $File))) {
                    Write-ColoredOutput "  Missing common ADMX: $File" -Type Warning
                }
            }
            
            return $true
        } else {
            Write-ColoredOutput "! PolicyDefinitions folder not found (Central Store not configured)" -Type Warning
            $script:Recommendations += "Consider creating a Central Store for ADMX templates"
            return $false
        }
    } catch {
        Write-ColoredOutput "[X] Error checking PolicyDefinitions`: $_" -Type Error
        return $false
    }
}

function Test-GPOVersionConsistency {
    Write-ColoredOutput "`nChecking GPO version consistency..." -Type Info
    
    try {
        $AllGPOs = Get-GPO -All -ErrorAction Stop
        $InconsistentGPOs = @()
        
        foreach ($GPO in $AllGPOs) {
            $ADVersion = $GPO.Computer.DSVersion + $GPO.User.DSVersion
            $SysvolVersion = $GPO.Computer.SysvolVersion + $GPO.User.SysvolVersion
            
            if ($ADVersion -ne $SysvolVersion) {
                $InconsistentGPOs += [PSCustomObject]@{
                    Name = $GPO.DisplayName
                    Id = $GPO.Id
                    ADVersion = $ADVersion
                    SysvolVersion = $SysvolVersion
                    Difference = [Math]::Abs($ADVersion - $SysvolVersion)
                }
            }
        }
        
        if ($InconsistentGPOs.Count -gt 0) {
            Write-ColoredOutput "[X] Found $($InconsistentGPOs.Count) GPOs with version inconsistencies:" -Type Error
            foreach ($GPO in $InconsistentGPOs) {
                Write-ColoredOutput "  - $($GPO.Name) (AD: $($GPO.ADVersion), SYSVOL: $($GPO.SysvolVersion))" -Type Error
            }
            $script:Recommendations += "Force replication or recreate GPOs with version mismatches"
        } else {
            Write-ColoredOutput "[OK] All GPO versions are consistent between AD and SYSVOL" -Type Success
        }
        
        return $InconsistentGPOs
    } catch {
        Write-ColoredOutput "[X] Error checking GPO version consistency`: $_" -Type Error
        return @()
    }
}

function Test-OrphanedGPOs {
    param(
        [string]$DCName
    )
    
    Write-ColoredOutput "`nChecking for orphaned GPO folders on $DCName..." -Type Info
    
    try {
        $PoliciesPath = "\\$DCName\SYSVOL\$DomainName\Policies"
        $SysvolGPOs = Get-ChildItem -Path $PoliciesPath -Directory | 
            Where-Object { $_.Name -match '^{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}}$' }
        
        $ADGPOs = Get-GPO -All | Select-Object -ExpandProperty Id
        $OrphanedFolders = @()
        
        foreach ($Folder in $SysvolGPOs) {
            if ($Folder.Name -notin $ADGPOs) {
                $OrphanedFolders += $Folder.Name
            }
        }
        
        if ($OrphanedFolders.Count -gt 0) {
            Write-ColoredOutput "[X] Found $($OrphanedFolders.Count) orphaned GPO folders in SYSVOL:" -Type Warning
            foreach ($Folder in $OrphanedFolders) {
                Write-ColoredOutput "  - $Folder" -Type Warning
            }
            $script:Recommendations += "Remove orphaned GPO folders from SYSVOL to free up space"
        } else {
            Write-ColoredOutput "[OK] No orphaned GPO folders found" -Type Success
        }
        
        return $OrphanedFolders
    } catch {
        Write-ColoredOutput "[X] Error checking for orphaned GPOs`: $_" -Type Error
        return @()
    }
}

function Test-UnlinkedGPOs {
    Write-ColoredOutput "`nChecking for unlinked GPOs..." -Type Info
    
    try {
        $AllGPOs = Get-GPO -All -ErrorAction Stop
        $UnlinkedGPOs = @()
        
        foreach ($GPO in $AllGPOs) {
            [xml]$Report = Get-GPOReport -Guid $GPO.Id -ReportType Xml
            $Links = $Report.GPO.LinksTo
            
            if (-not $Links) {
                $UnlinkedGPOs += [PSCustomObject]@{
                    Name = $GPO.DisplayName
                    Id = $GPO.Id
                    CreationTime = $GPO.CreationTime
                    ModificationTime = $GPO.ModificationTime
                }
            }
        }
        
        if ($UnlinkedGPOs.Count -gt 0) {
            Write-ColoredOutput "! Found $($UnlinkedGPOs.Count) unlinked GPOs:" -Type Warning
            foreach ($GPO in $UnlinkedGPOs) {
                Write-ColoredOutput "  - $($GPO.Name) (Created: $($GPO.CreationTime))" -Type Warning
            }
            $script:Recommendations += "Review and remove unlinked GPOs if no longer needed"
        } else {
            Write-ColoredOutput "[OK] All GPOs are linked" -Type Success
        }
        
        return $UnlinkedGPOs
    } catch {
        Write-ColoredOutput "[X] Error checking for unlinked GPOs`: $_" -Type Error
        return @()
    }
}

function Test-WMIFilters {
    Write-ColoredOutput "`nChecking WMI filters..." -Type Info
    
    try {
        $WMIFilters = Get-ADObject -Filter 'objectClass -eq "msWMI-Som"' -Properties *
        
        if ($WMIFilters.Count -eq 0) {
            Write-ColoredOutput "  No WMI filters found in domain" -Type Info
            return $true
        }
        
        Write-ColoredOutput "  Found $($WMIFilters.Count) WMI filters" -Type Info
        
        foreach ($Filter in $WMIFilters) {
            $FilterName = $Filter.'msWMI-Name'
            $FilterQuery = $Filter.'msWMI-Parm2'
            
            # Test WMI query syntax
            try {
                # Extract the actual WQL query from the stored format
                if ($FilterQuery -match 'WQL;(.+);') {
                    $WQLQuery = $Matches[1]
                    $TestQuery = Get-WmiObject -Query $WQLQuery -ErrorAction Stop
                    Write-ColoredOutput "  [OK] WMI Filter '$FilterName' syntax is valid" -Type Success
                }
            } catch {
                Write-ColoredOutput "  [X] WMI Filter '$FilterName' has invalid syntax" -Type Error
                $script:Recommendations += "Fix or remove invalid WMI filter: $FilterName"
            }
        }
        
        return $true
    } catch {
        Write-ColoredOutput "[X] Error checking WMI filters`: $_" -Type Error
        return $false
    }
}

function Test-GPOReplication {
    Write-ColoredOutput "`nChecking GPO replication across domain controllers..." -Type Info
    
    if ($DomainControllers.Count -eq 1) {
        Write-ColoredOutput "  Only one domain controller found, skipping replication check" -Type Info
        return $true
    }
    
    try {
        $ReferenceGPOs = Get-GPO -All -Server $PDCEmulator -ErrorAction Stop
        $ReplicationIssues = @()
        
        foreach ($DC in $DomainControllers | Where-Object { $_.HostName -ne $PDCEmulator }) {
            Write-ColoredOutput "  Comparing with $($DC.HostName)..." -Type Info
            
            try {
                $DCGPOs = Get-GPO -All -Server $DC.HostName -ErrorAction Stop
                
                # Check for missing GPOs
                $MissingGPOs = $ReferenceGPOs | Where-Object { $_.Id -notin $DCGPOs.Id }
                if ($MissingGPOs) {
                    foreach ($GPO in $MissingGPOs) {
                        $ReplicationIssues += [PSCustomObject]@{
                            DC = $DC.HostName
                            Issue = "Missing GPO"
                            GPOName = $GPO.DisplayName
                            GPOId = $GPO.Id
                        }
                    }
                }
                
                # Check for version differences
                foreach ($RefGPO in $ReferenceGPOs) {
                    $DCGPO = $DCGPOs | Where-Object { $_.Id -eq $RefGPO.Id }
                    if ($DCGPO) {
                        if ($RefGPO.ModificationTime -ne $DCGPO.ModificationTime) {
                            $ReplicationIssues += [PSCustomObject]@{
                                DC = $DC.HostName
                                Issue = "Version Mismatch"
                                GPOName = $RefGPO.DisplayName
                                GPOId = $RefGPO.Id
                                PDCModified = $RefGPO.ModificationTime
                                DCModified = $DCGPO.ModificationTime
                            }
                        }
                    }
                }
            } catch {
                Write-ColoredOutput "  [X] Failed to check replication with $($DC.HostName)`: $_" -Type Error
            }
        }
        
        if ($ReplicationIssues.Count -gt 0) {
            Write-ColoredOutput "[X] Found $($ReplicationIssues.Count) replication issues:" -Type Error
            foreach ($Issue in $ReplicationIssues) {
                Write-ColoredOutput "  - $($Issue.DC): $($Issue.Issue) for $($Issue.GPOName)" -Type Error
            }
            $script:Recommendations += "Force AD replication or investigate replication topology"
        } else {
            Write-ColoredOutput "[OK] GPO replication is consistent across all domain controllers" -Type Success
        }
        
        return $ReplicationIssues
    } catch {
        Write-ColoredOutput "[X] Error checking GPO replication`: $_" -Type Error
        return @()
    }
}

function Test-ClientGPProcessing {
    if ($SkipClientTests) {
        Write-ColoredOutput "`nSkipping client Group Policy tests" -Type Info
        return
    }
    
    Write-ColoredOutput "`nTesting client Group Policy processing..." -Type Info
    
    try {
        # Run gpresult
        $GPResult = gpresult /r /scope:computer
        if ($LASTEXITCODE -eq 0) {
            Write-ColoredOutput "[OK] Group Policy processing completed successfully" -Type Success
        } else {
            Write-ColoredOutput "[X] Group Policy processing failed with exit code: $LASTEXITCODE" -Type Error
            $script:Recommendations += "Investigate Group Policy processing errors on clients"
        }
        
        # Check last policy application time
        $ComputerGPO = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Extension-List\{00000000-0000-0000-0000-000000000000}" -ErrorAction SilentlyContinue
        if ($ComputerGPO) {
            $LastApplied = [DateTime]::FromFileTime($ComputerGPO.EndTimeHi * [Math]::Pow(2, 32) + $ComputerGPO.EndTimeLo)
            $TimeSinceApplied = (Get-Date) - $LastApplied
            
            if ($TimeSinceApplied.TotalHours -gt 2) {
                Write-ColoredOutput "! Group Policy last applied $([int]$TimeSinceApplied.TotalHours) hours ago" -Type Warning
                $script:Recommendations += "Investigate why Group Policy hasn't refreshed recently"
            } else {
                Write-ColoredOutput "[OK] Group Policy applied recently ($([int]$TimeSinceApplied.TotalMinutes) minutes ago)" -Type Success
            }
        }
        
        # Test manual refresh
        Write-ColoredOutput "  Testing manual Group Policy refresh..." -Type Info
        $RefreshResult = gpupdate /force
        if ($LASTEXITCODE -eq 0) {
            Write-ColoredOutput "  [OK] Manual Group Policy refresh successful" -Type Success
        } else {
            Write-ColoredOutput "  [X] Manual Group Policy refresh failed" -Type Error
        }
        
    } catch {
        Write-ColoredOutput "[X] Error testing client GP processing`: $_" -Type Error
    }
}

#endregion

#region Main Execution

Write-Host "`n" -NoNewline
Write-Host "====================================" -ForegroundColor Cyan
Write-Host "  Group Policy Infrastructure Check " -ForegroundColor Cyan
Write-Host "====================================" -ForegroundColor Cyan
Write-Host "Domain: $DomainName" -ForegroundColor White
Write-Host "PDC Emulator: $PDCEmulator" -ForegroundColor White
Write-Host "DCs to check: $($DomainControllers.Count)" -ForegroundColor White
Write-Host "====================================" -ForegroundColor Cyan

# 1. Check Group Policy services on DCs
Write-Host "`n[1/10] Checking Group Policy services..." -ForegroundColor Yellow
foreach ($DC in $DomainControllers) {
    Write-ColoredOutput "`nChecking services on $($DC.HostName)..." -Type Info
    
    # Check Group Policy Client service
    Test-ServiceStatus -ComputerName $DC.HostName -ServiceName "gpsvc" -DisplayName "Group Policy Client"
    
    # Check DFS Replication service (for SYSVOL replication)
    Test-ServiceStatus -ComputerName $DC.HostName -ServiceName "DFSR" -DisplayName "DFS Replication"
    
    # Check Active Directory Domain Services
    Test-ServiceStatus -ComputerName $DC.HostName -ServiceName "NTDS" -DisplayName "Active Directory Domain Services"
}

# 2. Check SYSVOL share accessibility
Write-Host "`n[2/10] Checking SYSVOL share accessibility..." -ForegroundColor Yellow
foreach ($DC in $DomainControllers) {
    Test-SYSVOLShare -DCName $DC.HostName
}

# 3. Check PolicyDefinitions folder
Write-Host "`n[3/10] Checking PolicyDefinitions folder..." -ForegroundColor Yellow
Test-PolicyDefinitions -DCName $PDCEmulator

# 4. Test Group Policy processing
Write-Host "`n[4/10] Testing Group Policy processing..." -ForegroundColor Yellow
Test-ClientGPProcessing

# 5. Check for orphaned GPO folders
Write-Host "`n[5/10] Checking for orphaned GPO folders..." -ForegroundColor Yellow
$OrphanedGPOs = Test-OrphanedGPOs -DCName $PDCEmulator

# 6. Check GPO version consistency
Write-Host "`n[6/10] Checking GPO version consistency..." -ForegroundColor Yellow
$VersionMismatches = Test-GPOVersionConsistency

# 7. Check for unlinked GPOs
Write-Host "`n[7/10] Checking for unlinked GPOs..." -ForegroundColor Yellow
$UnlinkedGPOs = Test-UnlinkedGPOs

# 8. Validate WMI filters
Write-Host "`n[8/10] Validating WMI filters..." -ForegroundColor Yellow
Test-WMIFilters

# 9. Additional client tests (if not skipped)
if (-not $SkipClientTests) {
    Write-Host "`n[9/10] Running additional client tests..." -ForegroundColor Yellow
    
    # Check Group Policy event log
    Write-ColoredOutput "`nChecking Group Policy event logs..." -Type Info
    try {
        $GPErrors = Get-WinEvent -FilterHashtable @{LogName='GP_System'; ID=1085,1006,1030,1058,1053} -MaxEvents 10 -ErrorAction SilentlyContinue
        if ($GPErrors) {
            Write-ColoredOutput "[X] Found $($GPErrors.Count) Group Policy errors in event log" -Type Error
            foreach ($Event in $GPErrors | Select-Object -First 5) {
                Write-ColoredOutput "  - Event $($Event.Id): $($Event.Message.Split("`n")[0])" -Type Error
            }
            $script:Recommendations += "Review and resolve Group Policy errors in event log"
        } else {
            Write-ColoredOutput "[OK] No recent Group Policy errors in event log" -Type Success
        }
    } catch {
        Write-ColoredOutput "  Unable to query event log" -Type Warning
    }
} else {
    Write-Host "`n[9/10] Skipping client tests" -ForegroundColor Yellow
}

# 10. Check GPO replication
Write-Host "`n[10/10] Checking GPO replication..." -ForegroundColor Yellow
$ReplicationIssues = Test-GPOReplication

#endregion

#region Generate Report

Write-Host "`n`nGenerating detailed report..." -ForegroundColor Cyan

$ReportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$ReportFile = Join-Path $OutputPath "GPO_Infrastructure_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"

$HTMLReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>Group Policy Infrastructure Health Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 3px solid #0078d4; padding-bottom: 10px; }
        h2 { color: #0078d4; margin-top: 30px; }
        h3 { color: #333; margin-top: 20px; }
        .summary { background-color: #f0f0f0; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .error { color: #d83b01; font-weight: bold; }
        .warning { color: #ca5010; font-weight: bold; }
        .success { color: #107c10; font-weight: bold; }
        .info { color: #0078d4; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #0078d4; color: white; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .recommendation { background-color: #fff4ce; padding: 10px; border-left: 4px solid #ca5010; margin: 10px 0; }
        .metric { display: inline-block; margin: 10px 20px 10px 0; }
        .metric-value { font-size: 24px; font-weight: bold; }
        .metric-label { color: #666; }
        ul { margin: 10px 0; }
        li { margin: 5px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Group Policy Infrastructure Health Report</h1>
        
        <div class="summary">
            <h2>Executive Summary</h2>
            <p><strong>Report Generated:</strong> $ReportDate</p>
            <p><strong>Domain:</strong> $DomainName</p>
            <p><strong>PDC Emulator:</strong> $PDCEmulator</p>
            <p><strong>Domain Controllers Checked:</strong> $($DomainControllers.Count)</p>
            
            <div class="metrics">
                <div class="metric">
                    <div class="metric-value error">$script:ErrorCount</div>
                    <div class="metric-label">Critical Issues</div>
                </div>
                <div class="metric">
                    <div class="metric-value warning">$script:WarningCount</div>
                    <div class="metric-label">Warnings</div>
                </div>
                <div class="metric">
                    <div class="metric-value success">$((Get-GPO -All).Count)</div>
                    <div class="metric-label">Total GPOs</div>
                </div>
            </div>
        </div>

        <h2>Critical Issues Found</h2>
        $(if ($script:Issues.Count -gt 0) {
            "<ul class='error'>"
            foreach ($Issue in $script:Issues) {
                "<li>$Issue</li>"
            }
            "</ul>"
        } else {
            "<p class='success'>No critical issues found!</p>"
        })

        <h2>Warnings</h2>
        $(if ($script:Warnings.Count -gt 0) {
            "<ul class='warning'>"
            foreach ($Warning in $script:Warnings) {
                "<li>$Warning</li>"
            }
            "</ul>"
        } else {
            "<p class='success'>No warnings found!</p>"
        })

        <h2>Detailed Findings</h2>
        
        <h3>Domain Controller Services</h3>
        <table>
            <tr>
                <th>Domain Controller</th>
                <th>Group Policy Client</th>
                <th>DFS Replication</th>
                <th>AD DS</th>
            </tr>
"@

foreach ($DC in $DomainControllers) {
    $GPSvc = Get-Service -ComputerName $DC.HostName -Name "gpsvc" -ErrorAction SilentlyContinue
    $DFSR = Get-Service -ComputerName $DC.HostName -Name "DFSR" -ErrorAction SilentlyContinue
    $NTDS = Get-Service -ComputerName $DC.HostName -Name "NTDS" -ErrorAction SilentlyContinue
    
    $HTMLReport += @"
            <tr>
                <td>$($DC.HostName)</td>
                <td class="$(if ($GPSvc.Status -eq 'Running') { 'success' } else { 'error' })">$(if ($GPSvc) { $GPSvc.Status } else { 'Unknown' })</td>
                <td class="$(if ($DFSR.Status -eq 'Running') { 'success' } else { 'error' })">$(if ($DFSR) { $DFSR.Status } else { 'Unknown' })</td>
                <td class="$(if ($NTDS.Status -eq 'Running') { 'success' } else { 'error' })">$(if ($NTDS) { $NTDS.Status } else { 'Unknown' })</td>
            </tr>
"@
}

$HTMLReport += @"
        </table>

        <h3>GPO Statistics</h3>
        <table>
            <tr>
                <th>Metric</th>
                <th>Count</th>
                <th>Status</th>
            </tr>
            <tr>
                <td>Total GPOs</td>
                <td>$((Get-GPO -All).Count)</td>
                <td class="info">-</td>
            </tr>
            <tr>
                <td>Unlinked GPOs</td>
                <td>$($UnlinkedGPOs.Count)</td>
                <td class="$(if ($UnlinkedGPOs.Count -gt 0) { 'warning' } else { 'success' })">$(if ($UnlinkedGPOs.Count -gt 0) { 'Review needed' } else { 'OK' })</td>
            </tr>
            <tr>
                <td>Version Mismatches</td>
                <td>$($VersionMismatches.Count)</td>
                <td class="$(if ($VersionMismatches.Count -gt 0) { 'error' } else { 'success' })">$(if ($VersionMismatches.Count -gt 0) { 'Fix required' } else { 'OK' })</td>
            </tr>
            <tr>
                <td>Orphaned GPO Folders</td>
                <td>$($OrphanedGPOs.Count)</td>
                <td class="$(if ($OrphanedGPOs.Count -gt 0) { 'warning' } else { 'success' })">$(if ($OrphanedGPOs.Count -gt 0) { 'Cleanup needed' } else { 'OK' })</td>
            </tr>
        </table>

        $(if ($VersionMismatches.Count -gt 0) {
            "<h3>GPOs with Version Mismatches</h3>"
            "<table>"
            "<tr><th>GPO Name</th><th>AD Version</th><th>SYSVOL Version</th><th>Difference</th></tr>"
            foreach ($GPO in $VersionMismatches) {
                "<tr><td>$($GPO.Name)</td><td>$($GPO.ADVersion)</td><td>$($GPO.SysvolVersion)</td><td>$($GPO.Difference)</td></tr>"
            }
            "</table>"
        })

        $(if ($UnlinkedGPOs.Count -gt 0) {
            "<h3>Unlinked GPOs</h3>"
            "<table>"
            "<tr><th>GPO Name</th><th>Created</th><th>Last Modified</th></tr>"
            foreach ($GPO in $UnlinkedGPOs) {
                "<tr><td>$($GPO.Name)</td><td>$($GPO.CreationTime)</td><td>$($GPO.ModificationTime)</td></tr>"
            }
            "</table>"
        })

        <h2>Recommendations</h2>
        $(if ($script:Recommendations.Count -gt 0) {
            foreach ($Rec in $script:Recommendations | Sort-Object -Unique) {
                "<div class='recommendation'>$Rec</div>"
            }
        } else {
            "<p class='success'>No recommendations - infrastructure is healthy!</p>"
        })

        <h2>Next Steps</h2>
        <ol>
            <li>Address all critical issues (shown in red) immediately</li>
            <li>Review and resolve warnings (shown in orange) as soon as possible</li>
            <li>Consider implementing recommendations to improve infrastructure</li>
            <li>Schedule regular infrastructure health checks (monthly recommended)</li>
            <li>Document any changes made based on this report</li>
        </ol>

        <h2>Additional Resources</h2>
        <ul>
            <li><a href="https://docs.microsoft.com/en-us/troubleshoot/windows-server/group-policy/group-policy-overview">Group Policy Troubleshooting Guide</a></li>
            <li><a href="https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/troubleshoot/troubleshooting-active-directory-replication-problems">AD Replication Troubleshooting</a></li>
            <li><a href="https://docs.microsoft.com/en-us/troubleshoot/windows-server/group-policy/deploying-group-policy-troubleshooting">Deploying Group Policy - Best Practices</a></li>
        </ul>
    </div>
</body>
</html>
"@

# Save the report
$HTMLReport | Out-File -FilePath $ReportFile -Encoding UTF8

Write-Host "`n`n====================================" -ForegroundColor Green
Write-Host "        ASSESSMENT COMPLETE         " -ForegroundColor Green
Write-Host "====================================" -ForegroundColor Green
Write-Host "`nSummary:" -ForegroundColor White
Write-Host "  Critical Issues: " -NoNewline
Write-Host $script:ErrorCount -ForegroundColor $(if ($script:ErrorCount -gt 0) { "Red" } else { "Green" })
Write-Host "  Warnings: " -NoNewline
Write-Host $script:WarningCount -ForegroundColor $(if ($script:WarningCount -gt 0) { "Yellow" } else { "Green" })
Write-Host "`nDetailed report saved to:" -ForegroundColor White
Write-Host "  $ReportFile" -ForegroundColor Cyan
Write-Host "`nOpen the HTML report for detailed findings and recommendations." -ForegroundColor White

# Return summary object
return @{
    ErrorCount = $script:ErrorCount
    WarningCount = $script:WarningCount
    ReportPath = $ReportFile
    Issues = $script:Issues
    Warnings = $script:Warnings
    Recommendations = $script:Recommendations | Sort-Object -Unique
}

#endregion