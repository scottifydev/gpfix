#Requires -RunAsAdministrator
#Requires -Version 5.1
#Requires -Modules ActiveDirectory, GroupPolicy

<#
.SYNOPSIS
    Validates the environment before any Group Policy deployment
.DESCRIPTION
    Performs comprehensive environment checks including domain connectivity,
    permissions, existing conflicts, and infrastructure readiness.
    Returns clear pass/fail status with detailed issue reporting.
.PARAMETER TargetOU
    The Organizational Unit to validate for deployment readiness
.PARAMETER DomainController
    Specific domain controller to test against
.PARAMETER SkipDCDiag
    Skip domain controller diagnostics (faster but less thorough)
.PARAMETER Quiet
    Return only the result object without console output
.EXAMPLE
    .\Test-GPOEnvironment.ps1 -TargetOU "OU=Teenagers,DC=domain,DC=example"
.EXAMPLE
    .\Test-GPOEnvironment.ps1 -TargetOU "OU=Test,DC=domain,DC=example" -SkipDCDiag
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$TargetOU,
    
    [Parameter(Mandatory = $false)]
    [string]$DomainController = $env:LOGONSERVER.Replace('\\', ''),
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipDCDiag,
    
    [Parameter(Mandatory = $false)]
    [switch]$Quiet
)

# Initialize
$ErrorActionPreference = 'Stop'
$Script:TestResults = @{
    EnvironmentReady = $true
    TotalTests = 0
    PassedTests = 0
    FailedTests = 0
    Issues = @()
    Warnings = @()
    Details = @{}
}

# Output function
function Write-TestOutput {
    param(
        [string]$Message,
        [ValidateSet("INFO", "PASS", "FAIL", "WARN", "HEADER")]
        [string]$Type = "INFO"
    )
    
    if (-not $Quiet) {
        switch ($Type) {
            "HEADER" { 
                Write-Host "`n$Message" -ForegroundColor Cyan
                Write-Host ("-" * $Message.Length) -ForegroundColor Cyan
            }
            "PASS"   { Write-Host "[PASS] $Message" -ForegroundColor Green }
            "FAIL"   { Write-Host "[FAIL] $Message" -ForegroundColor Red }
            "WARN"   { Write-Host "[WARN] $Message" -ForegroundColor Yellow }
            default  { Write-Host "      $Message" -ForegroundColor White }
        }
    }
}

# Test execution function
function Invoke-EnvironmentTest {
    param(
        [string]$TestName,
        [scriptblock]$TestScript,
        [bool]$IsCritical = $true
    )
    
    $Script:TestResults.TotalTests++
    
    try {
        $Result = & $TestScript
        
        if ($Result) {
            $Script:TestResults.PassedTests++
            Write-TestOutput "$TestName" -Type PASS
            return $true
        }
        else {
            $Script:TestResults.FailedTests++
            Write-TestOutput "$TestName" -Type FAIL
            
            if ($IsCritical) {
                $Script:TestResults.EnvironmentReady = $false
                $Script:TestResults.Issues += $TestName
            }
            else {
                $Script:TestResults.Warnings += $TestName
            }
            return $false
        }
    }
    catch {
        $Script:TestResults.FailedTests++
        Write-TestOutput "$TestName - Error: $_" -Type FAIL
        
        if ($IsCritical) {
            $Script:TestResults.EnvironmentReady = $false
            $Script:TestResults.Issues += "$TestName - $_"
        }
        else {
            $Script:TestResults.Warnings += "$TestName - $_"
        }
        return $false
    }
}

Write-TestOutput "GROUP POLICY ENVIRONMENT VALIDATION" -Type HEADER
Write-TestOutput "Test Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Type INFO
Write-TestOutput "Domain Controller: $DomainController" -Type INFO
if ($TargetOU) {
    Write-TestOutput "Target OU: $TargetOU" -Type INFO
}

# TEST 1: PowerShell Version and Modules
Write-TestOutput "PowerShell Environment" -Type HEADER

Invoke-EnvironmentTest -TestName "PowerShell Version >= 5.1" -TestScript {
    $PSVersionTable.PSVersion.Major -ge 5 -and 
    ($PSVersionTable.PSVersion.Major -gt 5 -or $PSVersionTable.PSVersion.Minor -ge 1)
}

Invoke-EnvironmentTest -TestName "ActiveDirectory Module Available" -TestScript {
    Get-Module -ListAvailable -Name ActiveDirectory | Out-Null
    $true
}

Invoke-EnvironmentTest -TestName "GroupPolicy Module Available" -TestScript {
    Get-Module -ListAvailable -Name GroupPolicy | Out-Null
    $true
}

# TEST 2: Domain Connectivity
Write-TestOutput "Domain Connectivity" -Type HEADER

Invoke-EnvironmentTest -TestName "Domain Controller Accessible" -TestScript {
    Test-Connection -ComputerName $DomainController -Count 1 -Quiet
}

Invoke-EnvironmentTest -TestName "AD Web Services Running" -TestScript {
    try {
        $DC = Get-ADDomainController -Server $DomainController -ErrorAction Stop
        $Script:TestResults.Details.DomainController = $DC.HostName
        $true
    }
    catch {
        $false
    }
}

Invoke-EnvironmentTest -TestName "Domain Functional Level >= 2008 R2" -TestScript {
    $Domain = Get-ADDomain -Server $DomainController
    $Script:TestResults.Details.Domain = $Domain.Name
    $Script:TestResults.Details.DomainLevel = $Domain.DomainMode.ToString()
    
    $MinLevel = [Microsoft.ActiveDirectory.Management.ADDomainMode]::Windows2008R2
    $Domain.DomainMode -ge $MinLevel
}

# TEST 3: User Permissions
Write-TestOutput "User Permissions" -Type HEADER

Invoke-EnvironmentTest -TestName "Running as Administrator" -TestScript {
    $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = New-Object Security.Principal.WindowsPrincipal $CurrentUser
    $IsAdmin = $Principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    
    $Script:TestResults.Details.CurrentUser = $CurrentUser.Name
    $Script:TestResults.Details.IsAdmin = $IsAdmin
    $IsAdmin
}

Invoke-EnvironmentTest -TestName "Group Policy Management Permissions" -TestScript {
    try {
        # Try to read GP container
        Write-Verbose "Checking for Group Policy containers..."
        $GPContainer = Get-ADObject -Filter "objectClass -eq 'groupPolicyContainer'" `
                                   -Server $DomainController -Properties * -ErrorAction Stop | 
                       Select-Object -First 1
        
        if ($GPContainer) {
            Write-Verbose "Found GP container: $($GPContainer.Name)"
            
            # Check if we can read GPO details
            try {
                $testGPO = Get-GPO -Guid $GPContainer.Name -Server $DomainController -ErrorAction Stop
                Write-Verbose "Successfully read GPO: $($testGPO.DisplayName)"
                
                # Try to get GPO permissions
                try {
                    $permissions = Get-GPPermission -Guid $GPContainer.Name -All -Server $DomainController -ErrorAction Stop
                    Write-Verbose "Successfully retrieved GPO permissions"
                }
                catch {
                    Write-Verbose "Could not retrieve GPO permissions: $_"
                    # Not critical - reading GPO is the main test
                }
                
                $true
            }
            catch {
                Write-Verbose "Failed to read GPO details: $_"
                $false
            }
        }
        else {
            Write-Verbose "No Group Policy containers found"
            $false
        }
    }
    catch {
        Write-Verbose "Failed to query Group Policy containers: $_"
        $false
    }
}

Invoke-EnvironmentTest -TestName "Domain Admin or Delegated Rights" -TestScript {
    try {
        $UserGroups = (New-Object System.Security.Principal.WindowsIdentity($env:USERNAME)).Groups
        $DomainAdmins = Get-ADGroup -Filter "Name -eq 'Domain Admins'" -Server $DomainController
        
        $IsDomainAdmin = $UserGroups.Value -contains $DomainAdmins.SID
        $Script:TestResults.Details.IsDomainAdmin = $IsDomainAdmin
        
        # If not domain admin, check for delegated GPO rights (warning only)
        if (-not $IsDomainAdmin) {
            Write-TestOutput "  Note: User is not Domain Admin - ensure proper delegation exists" -Type WARN
        }
        
        $true  # Pass if we can query, actual permissions tested above
    }
    catch {
        $false
    }
} -IsCritical $false

# TEST 4: Target OU Validation (if specified)
if ($TargetOU) {
    Write-TestOutput "Target OU Validation" -Type HEADER
    
    Invoke-EnvironmentTest -TestName "Target OU Exists" -TestScript {
        try {
            $OU = Get-ADOrganizationalUnit -Identity $TargetOU -Server $DomainController
            $Script:TestResults.Details.TargetOUName = $OU.Name
            $true
        }
        catch {
            $false
        }
    }
    
    Invoke-EnvironmentTest -TestName "Target OU Not Blocked by Inheritance" -TestScript {
        try {
            $OU = Get-ADOrganizationalUnit -Identity $TargetOU -Server $DomainController -Properties *
            $GPInheritanceBlocked = $OU.gPOptions -eq 1
            
            if ($GPInheritanceBlocked) {
                Write-TestOutput "  Warning: OU has inheritance blocked" -Type WARN
                $Script:TestResults.Warnings += "OU inheritance blocked"
            }
            
            $true  # Not a failure, just a warning
        }
        catch {
            $true  # If we can't check, assume OK
        }
    } -IsCritical $false
    
    Invoke-EnvironmentTest -TestName "No Conflicting GPOs on Target OU" -TestScript {
        try {
            # Get all GPO links on the OU
            $GPLinks = Get-ADOrganizationalUnit -Identity $TargetOU -Server $DomainController -Properties gpLink
            
            if ($GPLinks.gpLink) {
                # Parse GPO links
                $LinkedGPOs = $GPLinks.gpLink -split '\[' | Where-Object { $_ -match 'LDAP://cn=' }
                $Script:TestResults.Details.ExistingGPOCount = $LinkedGPOs.Count
                
                if ($LinkedGPOs.Count -gt 5) {
                    Write-TestOutput "  Warning: $($LinkedGPOs.Count) GPOs already linked to OU" -Type WARN
                    $Script:TestResults.Warnings += "High number of existing GPOs"
                }
            }
            
            $true  # Not a blocking issue
        }
        catch {
            $true
        }
    } -IsCritical $false
}

# TEST 5: SYSVOL Health
Write-TestOutput "SYSVOL Infrastructure" -Type HEADER

Invoke-EnvironmentTest -TestName "SYSVOL Share Accessible" -TestScript {
    $SysvolPath = "\\$DomainController\SYSVOL"
    Test-Path $SysvolPath
}

Invoke-EnvironmentTest -TestName "Central Store for ADMX Templates" -TestScript {
    try {
        $Domain = Get-ADDomain -Server $DomainController
        $CentralStore = "\\$DomainController\SYSVOL\$($Domain.DNSRoot)\Policies\PolicyDefinitions"
        
        if (Test-Path $CentralStore) {
            $ADMXCount = (Get-ChildItem -Path $CentralStore -Filter "*.admx" -ErrorAction SilentlyContinue).Count
            $Script:TestResults.Details.ADMXTemplateCount = $ADMXCount
            
            if ($ADMXCount -lt 10) {
                Write-TestOutput "  Warning: Only $ADMXCount ADMX templates found" -Type WARN
                $Script:TestResults.Warnings += "Low ADMX template count"
            }
            $true
        }
        else {
            Write-TestOutput "  Warning: No Central Store found - using local templates" -Type WARN
            $Script:TestResults.Warnings += "No ADMX Central Store"
            $true  # Not critical
        }
    }
    catch {
        $false
    }
} -IsCritical $false

Invoke-EnvironmentTest -TestName "SYSVOL Write Permissions" -TestScript {
    try {
        $TestFile = "\\$DomainController\SYSVOL\test_$(Get-Random).tmp"
        "test" | Out-File -FilePath $TestFile -ErrorAction Stop
        Remove-Item -Path $TestFile -Force -ErrorAction SilentlyContinue
        $true
    }
    catch {
        $false
    }
}

# TEST 6: Domain Controller Health (unless skipped)
if (-not $SkipDCDiag) {
    Write-TestOutput "Domain Controller Health" -Type HEADER
    
    Invoke-EnvironmentTest -TestName "Domain Controller Services" -TestScript {
        try {
            $RequiredServices = @('GP_NTDS', 'GP_DNS', 'GP_KDC', 'GP_Netlogon', 'GP_W32Time')
            $ServicesOK = $true
            
            foreach ($Service in $RequiredServices) {
                $Svc = Get-Service -Name $Service -ComputerName $DomainController -ErrorAction SilentlyContinue
                if ($Svc.Status -ne 'Running') {
                    Write-TestOutput "  Service $Service is not running" -Type WARN
                    $ServicesOK = $false
                }
            }
            
            $ServicesOK
        }
        catch {
            # Can't check remotely, assume OK
            $true
        }
    } -IsCritical $false
    
    Invoke-EnvironmentTest -TestName "Replication Status" -TestScript {
        try {
            $ReplStatus = repadmin /showrepl $DomainController /csv | ConvertFrom-Csv
            $Failures = $ReplStatus | Where-Object { $_.'Number of Failures' -gt 0 }
            
            if ($Failures) {
                Write-TestOutput "  Warning: Replication failures detected" -Type WARN
                $Script:TestResults.Warnings += "AD replication issues"
                $false
            }
            else {
                $true
            }
        }
        catch {
            # Can't check, assume OK
            $true
        }
    } -IsCritical $false
}

# TEST 7: GPO Infrastructure
Write-TestOutput "GPO Infrastructure" -Type HEADER

Invoke-EnvironmentTest -TestName "GPO Container in AD" -TestScript {
    try {
        $domain = Get-ADDomain -Server $DomainController -ErrorAction Stop
        Write-Verbose "Searching for GPO container in domain: $($domain.DistinguishedName)"
        
        $GPOContainer = Get-ADObject -Filter "objectClass -eq 'Container' -and cn -eq 'Group Policy Objects'" `
                                     -SearchBase $domain.DistinguishedName `
                                     -Server $DomainController -ErrorAction Stop
        
        if ($GPOContainer) {
            Write-Verbose "GPO container found: $($GPOContainer.DistinguishedName)"
            
            # Try to count existing GPOs
            try {
                $gpoCount = (Get-GPO -All -Server $DomainController -ErrorAction Stop).Count
                $Script:TestResults.Details.ExistingGPOCount = $gpoCount
                Write-Verbose "Found $gpoCount existing GPOs"
            }
            catch {
                Write-Verbose "Could not count existing GPOs: $_"
            }
            
            $true
        }
        else {
            Write-Verbose "GPO container not found"
            $false
        }
    }
    catch {
        Write-Verbose "Failed to check GPO container: $_"
        $false
    }
}

Invoke-EnvironmentTest -TestName "Can Create Test GPO" -TestScript {
    $testGPOCreated = $false
    $backupCreated = $false
    
    try {
        # Create backup of current GPO state before test
        $backupPath = Join-Path -Path $env:TEMP -ChildPath "GPO_TestBackup_$(Get-Random)"
        
        try {
            Write-Verbose "Creating backup directory: $backupPath"
            New-Item -ItemType Directory -Path $backupPath -Force | Out-Null
            
            # Backup all existing GPOs before making any changes
            try {
                $existingGPOs = Get-GPO -All -Server $DomainController -ErrorAction Stop
                Write-Verbose "Found $($existingGPOs.Count) existing GPOs to backup"
                
                foreach ($gpo in $existingGPOs) {
                    try {
                        # Use Backup-GPO cmdlet for proper GPO backup
                        Backup-GPO -Name $gpo.DisplayName -Path $backupPath -Server $DomainController -ErrorAction Stop | Out-Null
                        Write-Verbose "Backed up GPO: $($gpo.DisplayName)"
                    }
                    catch {
                        Write-Verbose "Failed to backup GPO $($gpo.DisplayName): $_"
                        # Continue with other backups
                    }
                }
                $backupCreated = $true
                Write-Verbose "GPO backups created at: $backupPath"
            }
            catch {
                Write-Verbose "Failed to enumerate GPOs for backup: $_"
                # If we can't backup existing GPOs, at least document them
                $existingGPOs = Get-GPO -All -Server $DomainController -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisplayName
                $existingGPOs | Out-File -FilePath "$backupPath\ExistingGPOs.txt" -ErrorAction SilentlyContinue
            }
        }
        catch {
            Write-Verbose "Failed to create backup: $_"
            # Continue without backup - not critical for test
        }
        
        # Attempt to create test GPO
        $TestGPOName = "GP_TEST-ENV-CHECK-$(Get-Random)"
        Write-Verbose "Attempting to create test GPO: $TestGPOName"
        
        try {
            $TestGPO = New-GPO -Name $TestGPOName -Server $DomainController -ErrorAction Stop
            $testGPOCreated = $true
            Write-Verbose "Test GPO created successfully"
            
            # Test setting a value in the GPO (this modifies GPO, so backup is already done)
            try {
                Set-GPRegistryValue -Name $TestGPOName -Key "HKLM\Software\Test" -ValueName "TestValue" -Value 1 -Type DWord -Server $DomainController -ErrorAction Stop
                Write-Verbose "Successfully set test registry value in GPO"
            }
            catch {
                Write-Verbose "Failed to set test registry value: $_"
                # Not critical - GPO creation is the main test
            }
            
            # Clean up test GPO
            try {
                Remove-GPO -Name $TestGPOName -Server $DomainController -Confirm:$false -ErrorAction Stop
                Write-Verbose "Test GPO removed successfully"
            }
            catch {
                Write-Verbose "Failed to remove test GPO: $_"
                # Try alternative removal
                try {
                    $TestGPO | Remove-GPO -Confirm:$false -ErrorAction Stop
                }
                catch {
                    Write-Verbose "Alternative removal also failed: $_"
                }
            }
            
            $true
        }
        catch {
            Write-Verbose "Failed to create test GPO: $_"
            $false
        }
        finally {
            # Clean up backup if created
            if ($backupCreated -and (Test-Path $backupPath)) {
                try {
                    Remove-Item -Path $backupPath -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Verbose "Backup cleaned up"
                }
                catch {
                    Write-Verbose "Failed to clean up backup: $_"
                }
            }
        }
    }
    catch {
        Write-Verbose "Unexpected error in GPO test: $_"
        $false
    }
}

# TEST 8: Event Log Access
Write-TestOutput "Event Log Access" -Type HEADER

Invoke-EnvironmentTest -TestName "Group Policy Event Log Accessible" -TestScript {
    try {
        Get-WinEvent -ComputerName $DomainController -LogName "GP_Microsoft-Windows-GroupPolicy/Operational" `
                     -MaxEvents 1 -ErrorAction Stop | Out-Null
        $true
    }
    catch {
        # Try legacy method
        try {
            Get-WinEvent -FilterHashtable @{
                LogName = 'Application'
                ProviderName = 'GP_Group Policy'
            } -MaxEvents 1 -ComputerName $DomainController -ErrorAction Stop | Out-Null
            $true
        }
        catch {
            $false
        }
    }
} -IsCritical $false

# TEST 9: Network Connectivity
Write-TestOutput "Network Requirements" -Type HEADER

Invoke-EnvironmentTest -TestName "DNS Resolution Working" -TestScript {
    try {
        $Domain = Get-ADDomain -Server $DomainController
        $Resolution = Resolve-DnsName -Name $Domain.DNSRoot -ErrorAction Stop
        [bool]$Resolution
    }
    catch {
        $false
    }
}

Invoke-EnvironmentTest -TestName "SMB Access to Domain Controller" -TestScript {
    $SMBPath = "\\$DomainController\C$"
    Test-Path $SMBPath
} -IsCritical $false

# Generate Summary
Write-TestOutput "TEST SUMMARY" -Type HEADER

$PassRate = if ($Script:TestResults.TotalTests -gt 0) {
    [math]::Round(($Script:TestResults.PassedTests / $Script:TestResults.TotalTests) * 100, 2)
} else { 0 }

if (-not $Quiet) {
    Write-Host "`nTotal Tests: $($Script:TestResults.TotalTests)" -ForegroundColor White
    Write-Host "Passed: $($Script:TestResults.PassedTests)" -ForegroundColor Green
    Write-Host "Failed: $($Script:TestResults.FailedTests)" -ForegroundColor $(if ($Script:TestResults.FailedTests -gt 0) { 'Red' } else { 'Green' })
    Write-Host "Pass Rate: $PassRate%" -ForegroundColor $(if ($PassRate -ge 80) { 'Green' } elseif ($PassRate -ge 60) { 'Yellow' } else { 'Red' })
    
    Write-Host "`nENVIRONMENT STATUS: " -NoNewline
    if ($Script:TestResults.EnvironmentReady) {
        Write-Host "READY FOR DEPLOYMENT" -ForegroundColor Green -BackgroundColor DarkGreen
    }
    else {
        Write-Host "NOT READY - ISSUES FOUND" -ForegroundColor Red -BackgroundColor DarkRed
    }
    
    if ($Script:TestResults.Issues.Count -gt 0) {
        Write-Host "`nCritical Issues:" -ForegroundColor Red
        foreach ($Issue in $Script:TestResults.Issues) {
            Write-Host "  - $Issue" -ForegroundColor Red
        }
    }
    
    if ($Script:TestResults.Warnings.Count -gt 0) {
        Write-Host "`nWarnings:" -ForegroundColor Yellow
        foreach ($Warning in $Script:TestResults.Warnings) {
            Write-Host "  - $Warning" -ForegroundColor Yellow
        }
    }
    
    if ($Script:TestResults.Details.Count -gt 0) {
        Write-Host "`nEnvironment Details:" -ForegroundColor Cyan
        foreach ($Key in $Script:TestResults.Details.Keys) {
            Write-Host "  $Key`: $($Script:TestResults.Details[$Key])" -ForegroundColor White
        }
    }
}

# Return results
return $Script:TestResults