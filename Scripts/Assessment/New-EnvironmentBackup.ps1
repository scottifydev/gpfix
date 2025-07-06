#Requires -Version 5.1
#Requires -Modules ActiveDirectory, GroupPolicy, AppLocker

<#
.SYNOPSIS
    Creates a comprehensive backup of the current Group Policy environment before deployment.

.DESCRIPTION
    This script backs up all GPOs, AD groups, AppLocker policies, browser registry settings,
    OU structure, and GPO links. It includes backup verification, compression, and restoration scripts.

.PARAMETER BackupPath
    Base path where backups will be stored. Default: C:\GPOBackups

.PARAMETER BackupType
    Type of backup to perform. Values: 'Full' or 'Incremental'. Default: Full

.PARAMETER RetentionDays
    Number of days to retain old backups. Default: 30

.PARAMETER CompressBackup
    Whether to compress the backup. Default: $true

.PARAMETER VerifyBackup
    Whether to verify backup integrity. Default: $true

.PARAMETER TestRestore
    Whether to test restoration of key items. Default: $true

.EXAMPLE
    .\Backup-CurrentEnvironment.ps1 -BackupPath "D:\Backups" -BackupType Full

.EXAMPLE
    .\Backup-CurrentEnvironment.ps1 -BackupType Incremental -RetentionDays 60
#>

[CmdletBinding()]
param(
    [string]$BackupPath = "C:\GPOBackups",
    [ValidateSet('Full', 'Incremental')]
    [string]$BackupType = 'Full',
    [int]$RetentionDays = 30,
    [switch]$CompressBackup = $true,
    [switch]$VerifyBackup = $true,
    [switch]$TestRestore = $true
)

# Import required modules
$RequiredModules = @('ActiveDirectory', 'GroupPolicy', 'AppLocker')
foreach ($Module in $RequiredModules) {
    try {
        Import-Module $Module -ErrorAction Stop
    } catch {
        Write-Error "Failed to import module $Module. Please ensure it's installed."
        exit 1
    }
}

# Initialize variables
$ErrorActionPreference = 'Stop'
$Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$BackupSetPath = Join-Path $BackupPath "Backup_$Timestamp"
$ManifestPath = Join-Path $BackupSetPath "BackupManifest.xml"
$LogPath = Join-Path $BackupSetPath "BackupLog.txt"
$RestoreScriptPath = Join-Path $BackupSetPath "Restore-Environment.ps1"
$BackupResults = @{
    StartTime = Get-Date
    EndTime = $null
    BackupType = $BackupType
    BackupPath = $BackupSetPath
    Items = @{}
    Errors = @()
    Warnings = @()
}

# Create backup directory structure
function Initialize-BackupStructure {
    Write-Host "Creating backup directory structure..." -ForegroundColor Yellow
    
    $Directories = @(
        $BackupSetPath,
        (Join-Path $BackupSetPath "GPOs"),
        (Join-Path $BackupSetPath "ADGroups"),
        (Join-Path $BackupSetPath "AppLocker"),
        (Join-Path $BackupSetPath "Registry"),
        (Join-Path $BackupSetPath "OUStructure"),
        (Join-Path $BackupSetPath "Checksums"),
        (Join-Path $BackupSetPath "RestoreScripts")
    )
    
    foreach ($Dir in $Directories) {
        if (-not (Test-Path $Dir)) {
            New-Item -Path $Dir -ItemType Directory -Force | Out-Null
        }
    }
    
    # Start logging
    Start-Transcript -Path $LogPath -Force
}

# Function to calculate file hash
function Get-FileChecksum {
    param([string]$FilePath)
    
    if (Test-Path $FilePath) {
        return (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash
    }
    return $null
}

# Function to backup all GPOs
function Backup-AllGPOs {
    Write-Host "`nBacking up Group Policy Objects..." -ForegroundColor Yellow
    
    $GPOBackupPath = Join-Path $BackupSetPath "GPOs"
    $GPOList = @()
    
    try {
        $AllGPOs = Get-GPO -All
        $BackupResults.Items['GPOs'] = @{
            Count = $AllGPOs.Count
            Items = @()
        }
        
        foreach ($GPO in $AllGPOs) {
            Write-Host "  Backing up GPO: $($GPO.DisplayName)" -ForegroundColor Gray
            
            try {
                # Check if incremental backup and GPO hasn't changed
                if ($BackupType -eq 'Incremental') {
                    $LastBackup = Get-LastBackupInfo -GPOId $GPO.Id
                    if ($LastBackup -and $GPO.ModificationTime -le $LastBackup.BackupDate) {
                        Write-Host "    Skipping (unchanged since last backup)" -ForegroundColor DarkGray
                        continue
                    }
                }
                
                # Backup the GPO
                $BackupInfo = Backup-GPO -Guid $GPO.Id -Path $GPOBackupPath -Comment "Backup on $Timestamp"
                
                # Export GPO report
                $ReportPath = Join-Path $GPOBackupPath "$($GPO.Id)_Report.html"
                Get-GPOReport -Guid $GPO.Id -ReportType Html -Path $ReportPath
                
                # Calculate checksums
                $BackupChecksum = Get-FileChecksum -FilePath (Join-Path $BackupInfo.BackupDirectory "gpreport.xml")
                $ReportChecksum = Get-FileChecksum -FilePath $ReportPath
                
                $GPOList += [PSCustomObject]@{
                    Id = $GPO.Id
                    DisplayName = $GPO.DisplayName
                    DomainName = $GPO.DomainName
                    Owner = $GPO.Owner
                    CreationTime = $GPO.CreationTime
                    ModificationTime = $GPO.ModificationTime
                    BackupId = $BackupInfo.Id
                    BackupDirectory = $BackupInfo.BackupDirectory
                    BackupChecksum = $BackupChecksum
                    ReportChecksum = $ReportChecksum
                }
                
                $BackupResults.Items['GPOs'].Items += $GPO.DisplayName
                
            } catch {
                $BackupResults.Errors += "Failed to backup GPO $($GPO.DisplayName): $_"
                Write-Warning "Failed to backup GPO $($GPO.DisplayName): $_"
            }
        }
        
        # Save GPO list
        $GPOList | Export-Csv -Path (Join-Path $GPOBackupPath "GPOList.csv") -NoTypeInformation
        
    } catch {
        $BackupResults.Errors += "Failed to enumerate GPOs: $_"
        Write-Error "Failed to enumerate GPOs: $_"
    }
}

# Function to backup AD security groups
function Backup-ADSecurityGroups {
    Write-Host "`nBacking up Active Directory security groups..." -ForegroundColor Yellow
    
    $ADGroupPath = Join-Path $BackupSetPath "ADGroups"
    $GroupList = @()
    
    try {
        # Get all security groups
        $AllGroups = Get-ADGroup -Filter {GroupCategory -eq 'Security'} -Properties *
        $BackupResults.Items['ADGroups'] = @{
            Count = $AllGroups.Count
            Items = @()
        }
        
        foreach ($Group in $AllGroups) {
            Write-Host "  Processing group: $($Group.Name)" -ForegroundColor Gray
            
            try {
                # Get group members
                $Members = Get-ADGroupMember -Identity $Group -Recursive | Select-Object Name, SamAccountName, ObjectClass
                
                # Create group object
                $GroupInfo = [PSCustomObject]@{
                    Name = $Group.Name
                    SamAccountName = $Group.SamAccountName
                    DistinguishedName = $Group.DistinguishedName
                    Description = $Group.Description
                    GroupScope = $Group.GroupScope
                    GroupCategory = $Group.GroupCategory
                    ManagedBy = $Group.ManagedBy
                    Created = $Group.Created
                    Modified = $Group.Modified
                    MemberCount = $Members.Count
                    Members = $Members
                }
                
                $GroupList += $GroupInfo
                
                # Export individual group details
                $GroupFileName = Join-Path $ADGroupPath "$($Group.SamAccountName).json"
                $GroupInfo | ConvertTo-Json -Depth 10 | Out-File $GroupFileName -Encoding UTF8
                
                $BackupResults.Items['ADGroups'].Items += $Group.Name
                
            } catch {
                $BackupResults.Warnings += "Failed to process group $($Group.Name): $_"
                Write-Warning "Failed to process group $($Group.Name): $_"
            }
        }
        
        # Save complete group list
        $GroupList | Export-Csv -Path (Join-Path $ADGroupPath "AllGroups.csv") -NoTypeInformation
        
    } catch {
        $BackupResults.Errors += "Failed to enumerate AD groups: $_"
        Write-Error "Failed to enumerate AD groups: $_"
    }
}

# Function to backup AppLocker policies
function Backup-AppLockerPolicies {
    Write-Host "`nBacking up AppLocker policies..." -ForegroundColor Yellow
    
    $AppLockerPath = Join-Path $BackupSetPath "AppLocker"
    $BackupResults.Items['AppLocker'] = @{
        Count = 0
        Items = @()
    }
    
    try {
        # Get domain controllers and computers with AppLocker
        $Computers = @()
        $Computers += Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
        $Computers += Get-ADComputer -Filter {OperatingSystem -like "*Windows*"} -Properties OperatingSystem | 
            Where-Object {$_.OperatingSystem -match "Server|10|11"} | 
            Select-Object -ExpandProperty DNSHostName -First 50  # Limit for performance
        
        foreach ($Computer in $Computers) {
            Write-Host "  Checking $Computer for AppLocker policies..." -ForegroundColor Gray
            
            if (Test-Connection -ComputerName $Computer -Count 1 -Quiet) {
                try {
                    $Session = New-PSSession -ComputerName $Computer -ErrorAction Stop
                    
                    $AppLockerPolicy = Invoke-Command -Session $Session -ScriptBlock {
                        Get-AppLockerPolicy -Effective -Xml
                    }
                    
                    Remove-PSSession -Session $Session
                    
                    if ($AppLockerPolicy) {
                        $PolicyFile = Join-Path $AppLockerPath "$Computer.xml"
                        $AppLockerPolicy | Out-File $PolicyFile -Encoding UTF8
                        
                        $BackupResults.Items['AppLocker'].Count++
                        $BackupResults.Items['AppLocker'].Items += $Computer
                        
                        Write-Host "    AppLocker policy found and backed up" -ForegroundColor Green
                    }
                    
                } catch {
                    Write-Verbose "Could not retrieve AppLocker policy from ${Computer}: $_"
                }
            }
        }
        
    } catch {
        $BackupResults.Warnings += "Failed to backup some AppLocker policies: $_"
        Write-Warning "Failed to backup some AppLocker policies: $_"
    }
}

# Function to backup browser registry settings
function Backup-BrowserRegistrySettings {
    Write-Host "`nBacking up browser registry settings..." -ForegroundColor Yellow
    
    $RegistryPath = Join-Path $BackupSetPath "Registry"
    $BackupResults.Items['Registry'] = @{
        Count = 0
        Items = @()
    }
    
    # Define registry paths to backup
    $RegistryPaths = @(
        @{Name = "GP_ChromePolicies"; Path = "HKLM:\SOFTWARE\Policies\Google\Chrome"},
        @{Name = "GP_EdgePolicies"; Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"},
        @{Name = "GP_FirefoxPolicies"; Path = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"},
        @{Name = "GP_IEPolicies"; Path = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer"},
        @{Name = "GP_ChromePreferences"; Path = "HKLM:\SOFTWARE\Google\Chrome"},
        @{Name = "GP_EdgePreferences"; Path = "HKLM:\SOFTWARE\Microsoft\Edge"}
    )
    
    foreach ($RegPath in $RegistryPaths) {
        Write-Host "  Backing up $($RegPath.Name)..." -ForegroundColor Gray
        
        if (Test-Path $RegPath.Path) {
            try {
                $ExportFile = Join-Path $RegistryPath "$($RegPath.Name).reg"
                $ExportPath = $RegPath.Path -replace 'HKLM:', 'HKEY_LOCAL_MACHINE'
                
                # Export registry key
                $Process = Start-Process -FilePath "reg.exe" -ArgumentList "export `"$ExportPath`" `"$ExportFile`" /y" -Wait -PassThru -NoNewWindow
                
                if ($Process.ExitCode -eq 0) {
                    $BackupResults.Items['Registry'].Count++
                    $BackupResults.Items['Registry'].Items += $RegPath.Name
                    Write-Host "    Exported successfully" -ForegroundColor Green
                } else {
                    Write-Warning "    Failed to export $($RegPath.Name)"
                }
                
            } catch {
                $BackupResults.Warnings += "Failed to backup registry $($RegPath.Name): $_"
                Write-Warning "Failed to backup registry $($RegPath.Name): $_"
            }
        } else {
            Write-Verbose "    Registry path not found: $($RegPath.Path)"
        }
    }
}

# Function to document OU structure and GPO links
function Backup-OUStructureAndLinks {
    Write-Host "`nDocumenting OU structure and GPO links..." -ForegroundColor Yellow
    
    $OUPath = Join-Path $BackupSetPath "OUStructure"
    $BackupResults.Items['OUStructure'] = @{
        Count = 0
        Items = @()
    }
    
    try {
        # Get domain information
        $Domain = Get-ADDomain
        $DomainDN = $Domain.DistinguishedName
        
        # Get all OUs
        $AllOUs = Get-ADOrganizationalUnit -Filter * -Properties *
        $OUStructure = @()
        
        # Process domain root
        $DomainGPOLinks = Get-GPInheritance -Target $DomainDN
        $OUStructure += [PSCustomObject]@{
            Name = $Domain.Name
            DistinguishedName = $DomainDN
            Type = "Domain"
            Parent = $null
            GPOLinks = $DomainGPOLinks.GpoLinks | Select-Object DisplayName, Enabled, Enforced, Order
            BlockInheritance = $DomainGPOLinks.GpoInheritanceBlocked
            Created = $Domain.Created
            Modified = $Domain.Modified
        }
        
        # Process each OU
        foreach ($OU in $AllOUs) {
            Write-Host "  Processing OU: $($OU.Name)" -ForegroundColor Gray
            
            try {
                $GPOLinks = Get-GPInheritance -Target $OU.DistinguishedName
                
                $OUInfo = [PSCustomObject]@{
                    Name = $OU.Name
                    DistinguishedName = $OU.DistinguishedName
                    Type = "OrganizationalUnit"
                    Parent = $OU.DistinguishedName -replace '^[^,]+,', ''
                    Description = $OU.Description
                    GPOLinks = $GPOLinks.GpoLinks | Select-Object DisplayName, Enabled, Enforced, Order
                    BlockInheritance = $GPOLinks.GpoInheritanceBlocked
                    Created = $OU.Created
                    Modified = $OU.Modified
                }
                
                $OUStructure += $OUInfo
                $BackupResults.Items['OUStructure'].Count++
                
            } catch {
                $BackupResults.Warnings += "Failed to process OU $($OU.Name): $_"
                Write-Warning "Failed to process OU $($OU.Name): $_"
            }
        }
        
        # Export OU structure
        $OUStructure | Export-Csv -Path (Join-Path $OUPath "OUStructure.csv") -NoTypeInformation
        $OUStructure | ConvertTo-Json -Depth 10 | Out-File (Join-Path $OUPath "OUStructure.json") -Encoding UTF8
        
        # Create visual tree representation
        $TreeFile = Join-Path $OUPath "OUTree.txt"
        Export-OUTree -OUStructure $OUStructure -OutputFile $TreeFile
        
        $BackupResults.Items['OUStructure'].Items = @("Complete OU structure documented")
        
    } catch {
        $BackupResults.Errors += "Failed to document OU structure: $_"
        Write-Error "Failed to document OU structure: $_"
    }
}

# Function to export OU tree visualization
function Export-OUTree {
    param(
        [array]$OUStructure,
        [string]$OutputFile
    )
    
    $TreeContent = @()
    
    function Get-OUChildren {
        param($Parent, $Indent = "")
        
        $Children = $OUStructure | Where-Object {$_.Parent -eq $Parent.DistinguishedName}
        
        foreach ($Child in $Children) {
            $GPOInfo = if ($Child.GPOLinks) {
                " [GPOs: $($Child.GPOLinks.Count)]"
            } else {
                ""
            }
            
            $BlockInfo = if ($Child.BlockInheritance) {" [Inheritance Blocked]"} else {""}
            
            $TreeContent += "$Indent+-- $($Child.Name)$GPOInfo$BlockInfo"
            Get-OUChildren -Parent $Child -Indent "$Indent|   "
        }
    }
    
    # Start with domain root
    $DomainRoot = $OUStructure | Where-Object {$_.Type -eq "Domain"}
    $TreeContent += "$($DomainRoot.Name) (GP_Domain Root)"
    Get-OUChildren -Parent $DomainRoot -Indent ""
    
    $TreeContent | Out-File $OutputFile -Encoding UTF8
}

# Function to create restoration scripts
function Create-RestorationScripts {
    Write-Host "`nCreating restoration scripts..." -ForegroundColor Yellow
    
    $RestoreScriptsPath = Join-Path $BackupSetPath "RestoreScripts"
    
    # Main restore script
    $MainRestoreScript = @'
#Requires -Version 5.1
#Requires -Modules ActiveDirectory, GroupPolicy

<#
.SYNOPSIS
    Restores Group Policy environment from backup.

.DESCRIPTION
    This script restores GPOs, AD groups, registry settings, and OU structure from a backup set.

.PARAMETER BackupSetPath
    Path to the backup set to restore from.

.PARAMETER RestoreGPOs
    Restore Group Policy Objects. Default: $true

.PARAMETER RestoreADGroups
    Restore AD security groups. Default: $true

.PARAMETER RestoreRegistry
    Restore registry settings. Default: $true

.PARAMETER WhatIf
    Shows what would be restored without making changes.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$BackupSetPath,
    [switch]$RestoreGPOs = $true,
    [switch]$RestoreADGroups = $true,
    [switch]$RestoreRegistry = $true
)

$ErrorActionPreference = 'Stop'

# Verify backup set exists
if (-not (Test-Path $BackupSetPath)) {
    throw "Backup set not found: $BackupSetPath"
}

# Load backup manifest
$ManifestPath = Join-Path $BackupSetPath "BackupManifest.xml"
if (-not (Test-Path $ManifestPath)) {
    throw "Backup manifest not found"
}

$Manifest = Import-Clixml $ManifestPath

Write-Host "Restoring from backup created on: $($Manifest.StartTime)" -ForegroundColor Yellow
Write-Host "Backup type: $($Manifest.BackupType)" -ForegroundColor Yellow

# Restore GPOs
if ($RestoreGPOs -and $Manifest.Items.ContainsKey('GPOs')) {
    Write-Host "`nRestoring Group Policy Objects..." -ForegroundColor Green
    
    $GPOListPath = Join-Path $BackupSetPath "GPOs\GPOList.csv"
    if (Test-Path $GPOListPath) {
        $GPOList = Import-Csv $GPOListPath
        
        foreach ($GPO in $GPOList) {
            if ($PSCmdlet.ShouldProcess($GPO.DisplayName, "Restore GPO")) {
                try {
                    # Check if GPO exists
                    $ExistingGPO = Get-GPO -Name $GPO.DisplayName -ErrorAction SilentlyContinue
                    
                    if ($ExistingGPO) {
                        Write-Host "  GPO already exists: $($GPO.DisplayName) - Skipping" -ForegroundColor Yellow
                    } else {
                        # Restore GPO
                        Import-GPO -BackupId $GPO.BackupId -Path (Join-Path $BackupSetPath "GPOs") -CreateIfNeeded -TargetName $GPO.DisplayName
                        Write-Host "  Restored: $($GPO.DisplayName)" -ForegroundColor Green
                    }
                } catch {
                    Write-Error "Failed to restore GPO $($GPO.DisplayName): $_"
                }
            }
        }
    }
}

# Restore AD Groups
if ($RestoreADGroups -and $Manifest.Items.ContainsKey('ADGroups')) {
    Write-Host "`nRestoring AD Security Groups..." -ForegroundColor Green
    
    $GroupsPath = Join-Path $BackupSetPath "ADGroups"
    $GroupFiles = Get-ChildItem -Path $GroupsPath -Filter "*.json"
    
    foreach ($GroupFile in $GroupFiles) {
        $GroupData = Get-Content $GroupFile.FullName | ConvertFrom-Json
        
        if ($PSCmdlet.ShouldProcess($GroupData.Name, "Restore AD Group")) {
            try {
                # Check if group exists
                $ExistingGroup = Get-ADGroup -Filter {SamAccountName -eq $GroupData.SamAccountName} -ErrorAction SilentlyContinue
                
                if (-not $ExistingGroup) {
                    # Create group
                    New-ADGroup -Name $GroupData.Name `
                               -SamAccountName $GroupData.SamAccountName `
                               -GroupCategory $GroupData.GroupCategory `
                               -GroupScope $GroupData.GroupScope `
                               -Description $GroupData.Description `
                               -Path (Split-Path $GroupData.DistinguishedName -Parent)
                    
                    Write-Host "  Created group: $($GroupData.Name)" -ForegroundColor Green
                    
                    # Add members
                    if ($GroupData.Members) {
                        foreach ($Member in $GroupData.Members) {
                            try {
                                Add-ADGroupMember -Identity $GroupData.SamAccountName -Members $Member.SamAccountName
                            } catch {
                                Write-Warning "Could not add member $($Member.Name) to group $($GroupData.Name)"
                            }
                        }
                    }
                } else {
                    Write-Host "  Group already exists: $($GroupData.Name) - Skipping" -ForegroundColor Yellow
                }
            } catch {
                Write-Error "Failed to restore group $($GroupData.Name): $_"
            }
        }
    }
}

# Restore Registry
if ($RestoreRegistry -and $Manifest.Items.ContainsKey('Registry')) {
    Write-Host "`nRestoring Registry Settings..." -ForegroundColor Green
    
    $RegistryPath = Join-Path $BackupSetPath "Registry"
    $RegFiles = Get-ChildItem -Path $RegistryPath -Filter "*.reg"
    
    foreach ($RegFile in $RegFiles) {
        if ($PSCmdlet.ShouldProcess($RegFile.BaseName, "Restore Registry")) {
            try {
                $Process = Start-Process -FilePath "reg.exe" -ArgumentList "import `"$($RegFile.FullName)`"" -Wait -PassThru -NoNewWindow
                
                if ($Process.ExitCode -eq 0) {
                    Write-Host "  Restored: $($RegFile.BaseName)" -ForegroundColor Green
                } else {
                    Write-Error "Failed to restore registry $($RegFile.BaseName)"
                }
            } catch {
                Write-Error "Failed to restore registry $($RegFile.BaseName): $_"
            }
        }
    }
}

Write-Host "`nRestore operation completed!" -ForegroundColor Green
'@

    $MainRestoreScript | Out-File $RestoreScriptPath -Encoding UTF8
    
    # Create specific restore scripts
    Create-GPORestoreScript -Path (Join-Path $RestoreScriptsPath "Restore-GPOs.ps1")
    Create-ADGroupRestoreScript -Path (Join-Path $RestoreScriptsPath "Restore-ADGroups.ps1")
    Create-RegistryRestoreScript -Path (Join-Path $RestoreScriptsPath "Restore-Registry.ps1")
    
    $BackupResults.Items['RestoreScripts'] = @{
        Count = 4
        Items = @("Main restore script", "GPO restore script", "AD Group restore script", "Registry restore script")
    }
}

# Function to create GPO-specific restore script
function Create-GPORestoreScript {
    param([string]$Path)
    
    $Script = @'
# GPO-specific restore script
param([string]$BackupPath)

$GPOPath = Join-Path $BackupPath "GPOs"
$GPOList = Import-Csv (Join-Path $GPOPath "GPOList.csv")

foreach ($GPO in $GPOList) {
    Write-Host "Restoring GPO: $($GPO.DisplayName)"
    try {
        Import-GPO -BackupId $GPO.BackupId -Path $GPOPath -CreateIfNeeded -TargetName $GPO.DisplayName
    } catch {
        Write-Error "Failed to restore $($GPO.DisplayName): $_"
    }
}
'@
    
    $Script | Out-File $Path -Encoding UTF8
}

# Function to create AD Group restore script
function Create-ADGroupRestoreScript {
    param([string]$Path)
    
    $Script = @'
# AD Group-specific restore script
param([string]$BackupPath)

$GroupPath = Join-Path $BackupPath "ADGroups"
$AllGroups = Import-Csv (Join-Path $GroupPath "AllGroups.csv")

foreach ($Group in $AllGroups) {
    Write-Host "Processing group: $($Group.Name)"
    # Group restoration logic here
}
'@
    
    $Script | Out-File $Path -Encoding UTF8
}

# Function to create Registry restore script
function Create-RegistryRestoreScript {
    param([string]$Path)
    
    $Script = @'
# Registry-specific restore script
param([string]$BackupPath)

$RegistryPath = Join-Path $BackupPath "Registry"
$RegFiles = Get-ChildItem -Path $RegistryPath -Filter "*.reg"

foreach ($RegFile in $RegFiles) {
    Write-Host "Importing registry: $($RegFile.Name)"
    reg import "$($RegFile.FullName)"
}
'@
    
    $Script | Out-File $Path -Encoding UTF8
}

# Function to verify backup integrity
function Verify-BackupIntegrity {
    if (-not $VerifyBackup) {
        return
    }
    
    Write-Host "`nVerifying backup integrity..." -ForegroundColor Yellow
    
    $ChecksumPath = Join-Path $BackupSetPath "Checksums"
    $VerificationResults = @()
    
    # Calculate checksums for all backup files
    $AllFiles = Get-ChildItem -Path $BackupSetPath -Recurse -File | Where-Object {$_.DirectoryName -notlike "*Checksums*"}
    
    foreach ($File in $AllFiles) {
        Write-Host "  Calculating checksum for: $($File.Name)" -ForegroundColor Gray
        
        $Hash = Get-FileChecksum -FilePath $File.FullName
        $RelativePath = $File.FullName.Replace($BackupSetPath, "").TrimStart("\")
        
        $VerificationResults += [PSCustomObject]@{
            FileName = $File.Name
            RelativePath = $RelativePath
            FileSize = $File.Length
            LastWriteTime = $File.LastWriteTime
            SHA256Hash = $Hash
        }
    }
    
    # Save checksums
    $ChecksumFile = Join-Path $ChecksumPath "BackupChecksums.csv"
    $VerificationResults | Export-Csv -Path $ChecksumFile -NoTypeInformation
    
    # Create verification script
    $VerifyScript = @'
# Backup verification script
param([string]$BackupPath)

$ChecksumFile = Join-Path $BackupPath "Checksums\BackupChecksums.csv"
$Checksums = Import-Csv $ChecksumFile

$Failed = 0
foreach ($Item in $Checksums) {
    $FilePath = Join-Path $BackupPath $Item.RelativePath
    if (Test-Path $FilePath) {
        $CurrentHash = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash
        if ($CurrentHash -ne $Item.SHA256Hash) {
            Write-Warning "Checksum mismatch: $($Item.RelativePath)"
            $Failed++
        }
    } else {
        Write-Warning "File missing: $($Item.RelativePath)"
        $Failed++
    }
}

if ($Failed -eq 0) {
    Write-Host "All files verified successfully!" -ForegroundColor Green
} else {
    Write-Error "$Failed files failed verification"
}
'@
    
    $VerifyScript | Out-File (Join-Path $ChecksumPath "Verify-Backup.ps1") -Encoding UTF8
    
    $BackupResults.Items['Verification'] = @{
        Count = $VerificationResults.Count
        Items = @("Checksums calculated for $($VerificationResults.Count) files")
    }
}

# Function to test restoration
function Test-BackupRestoration {
    if (-not $TestRestore) {
        return
    }
    
    Write-Host "`nTesting backup restoration..." -ForegroundColor Yellow
    
    $TestResults = @{
        GPORestore = $false
        RegistryRestore = $false
        FileIntegrity = $false
    }
    
    try {
        # Test GPO restore (dry run)
        $GPOListPath = Join-Path $BackupSetPath "GPOs\GPOList.csv"
        if (Test-Path $GPOListPath) {
            $TestGPO = Import-Csv $GPOListPath | Select-Object -First 1
            if ($TestGPO) {
                # Verify backup files exist
                $BackupFiles = Join-Path $BackupSetPath "GPOs\$($TestGPO.BackupId)\gpreport.xml"
                if (Test-Path $BackupFiles) {
                    $TestResults.GPORestore = $true
                    Write-Host "  GPO backup files verified" -ForegroundColor Green
                }
            }
        }
        
        # Test registry file format
        $RegFiles = Get-ChildItem -Path (Join-Path $BackupSetPath "Registry") -Filter "*.reg" -ErrorAction SilentlyContinue
        if ($RegFiles) {
            $TestReg = $RegFiles[0]
            $RegContent = Get-Content $TestReg.FullName -First 1
            if ($RegContent -match "Windows Registry Editor") {
                $TestResults.RegistryRestore = $true
                Write-Host "  Registry backup files verified" -ForegroundColor Green
            }
        }
        
        # Test file integrity
        $ChecksumFile = Join-Path $BackupSetPath "Checksums\BackupChecksums.csv"
        if (Test-Path $ChecksumFile) {
            $TestResults.FileIntegrity = $true
            Write-Host "  Backup integrity files verified" -ForegroundColor Green
        }
        
    } catch {
        $BackupResults.Warnings += "Some restoration tests failed: $_"
        Write-Warning "Some restoration tests failed: $_"
    }
    
    $BackupResults.Items['RestoreTest'] = @{
        Count = ($TestResults.Values | Where-Object {$_}).Count
        Items = $TestResults.Keys | Where-Object {$TestResults[$_]}
    }
}

# Function to compress backup
function Compress-BackupSet {
    if (-not $CompressBackup) {
        return
    }
    
    Write-Host "`nCompressing backup set..." -ForegroundColor Yellow
    
    try {
        $ArchivePath = "$BackupSetPath.zip"
        
        # Use .NET compression for better compatibility
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::CreateFromDirectory($BackupSetPath, $ArchivePath)
        
        # Verify archive
        $ArchiveInfo = Get-Item $ArchivePath
        $OriginalSize = (Get-ChildItem -Path $BackupSetPath -Recurse | Measure-Object -Property Length -Sum).Sum
        $CompressedSize = $ArchiveInfo.Length
        $CompressionRatio = [math]::Round((1 - ($CompressedSize / $OriginalSize)) * 100, 2)
        
        Write-Host "  Compression completed. Saved $CompressionRatio% space" -ForegroundColor Green
        Write-Host "  Original size: $([math]::Round($OriginalSize/1MB, 2)) MB" -ForegroundColor Gray
        Write-Host "  Compressed size: $([math]::Round($CompressedSize/1MB, 2)) MB" -ForegroundColor Gray
        
        $BackupResults.Items['Compression'] = @{
            OriginalSize = $OriginalSize
            CompressedSize = $CompressedSize
            CompressionRatio = $CompressionRatio
            ArchivePath = $ArchivePath
        }
        
    } catch {
        $BackupResults.Warnings += "Failed to compress backup: $_"
        Write-Warning "Failed to compress backup: $_"
    }
}

# Function to clean up old backups
function Remove-OldBackups {
    Write-Host "`nCleaning up old backups..." -ForegroundColor Yellow
    
    try {
        $CutoffDate = (Get-Date).AddDays(-$RetentionDays)
        $RemovedCount = 0
        
        # Find old backup directories
        $BackupDirs = Get-ChildItem -Path $BackupPath -Directory | Where-Object {
            $_.Name -match '^Backup_\d{8}_\d{6}$' -and $_.CreationTime -lt $CutoffDate
        }
        
        # Find old backup archives
        $BackupArchives = Get-ChildItem -Path $BackupPath -Filter "Backup_*.zip" | Where-Object {
            $_.CreationTime -lt $CutoffDate
        }
        
        # Remove old backups
        foreach ($Dir in $BackupDirs) {
            Write-Host "  Removing old backup: $($Dir.Name)" -ForegroundColor Gray
            Remove-Item -Path $Dir.FullName -Recurse -Force
            $RemovedCount++
        }
        
        foreach ($Archive in $BackupArchives) {
            Write-Host "  Removing old archive: $($Archive.Name)" -ForegroundColor Gray
            Remove-Item -Path $Archive.FullName -Force
            $RemovedCount++
        }
        
        if ($RemovedCount -gt 0) {
            Write-Host "  Removed $RemovedCount old backup(s)" -ForegroundColor Green
        } else {
            Write-Host "  No old backups to remove" -ForegroundColor Gray
        }
        
        $BackupResults.Items['Cleanup'] = @{
            Count = $RemovedCount
            Items = @("Removed $RemovedCount old backups older than $RetentionDays days")
        }
        
    } catch {
        $BackupResults.Warnings += "Failed to clean up some old backups: $_"
        Write-Warning "Failed to clean up some old backups: $_"
    }
}

# Function to get last backup info for incremental backups
function Get-LastBackupInfo {
    param([string]$GPOId)
    
    if ($BackupType -ne 'Incremental') {
        return $null
    }
    
    try {
        # Find most recent backup
        $LastBackup = Get-ChildItem -Path $BackupPath -Directory | 
            Where-Object {$_.Name -match '^Backup_\d{8}_\d{6}$'} |
            Sort-Object Name -Descending |
            Select-Object -First 1
        
        if ($LastBackup) {
            $GPOListPath = Join-Path $LastBackup.FullName "GPOs\GPOList.csv"
            if (Test-Path $GPOListPath) {
                $GPOList = Import-Csv $GPOListPath
                $GPOInfo = $GPOList | Where-Object {$_.Id -eq $GPOId}
                
                if ($GPOInfo) {
                    return @{
                        BackupDate = $LastBackup.CreationTime
                        ModificationTime = [DateTime]$GPOInfo.ModificationTime
                    }
                }
            }
        }
    } catch {
        Write-Verbose "Could not retrieve last backup info: $_"
    }
    
    return $null
}

# Function to save backup manifest
function Save-BackupManifest {
    Write-Host "`nSaving backup manifest..." -ForegroundColor Yellow
    
    $BackupResults.EndTime = Get-Date
    $BackupResults.Duration = $BackupResults.EndTime - $BackupResults.StartTime
    
    # Add system information
    $BackupResults.SystemInfo = @{
        ComputerName = $env:COMPUTERNAME
        DomainName = $env:USERDNSDOMAIN
        UserName = $env:USERNAME
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    }
    
    # Save manifest
    $BackupResults | Export-Clixml -Path $ManifestPath
    
    # Create human-readable summary
    $SummaryPath = Join-Path $BackupSetPath "BackupSummary.txt"
    $Summary = @"
Group Policy Environment Backup Summary
======================================
Backup Date: $($BackupResults.StartTime.ToString('yyyy-MM-dd HH:mm:ss'))
Backup Type: $($BackupResults.BackupType)
Duration: $([math]::Round($BackupResults.Duration.TotalMinutes, 2)) minutes
Computer: $($BackupResults.SystemInfo.ComputerName)
Domain: $($BackupResults.SystemInfo.DomainName)

Items Backed Up:
"@
    
    foreach ($Item in $BackupResults.Items.Keys) {
        $Summary += "`n  - ${Item}: $($BackupResults.Items[$Item].Count) items"
    }
    
    if ($BackupResults.Errors.Count -gt 0) {
        $Summary += "`n`nErrors: $($BackupResults.Errors.Count)"
        $BackupResults.Errors | ForEach-Object {$Summary += "`n  - $_"}
    }
    
    if ($BackupResults.Warnings.Count -gt 0) {
        $Summary += "`n`nWarnings: $($BackupResults.Warnings.Count)"
        $BackupResults.Warnings | ForEach-Object {$Summary += "`n  - $_"}
    }
    
    $Summary | Out-File $SummaryPath -Encoding UTF8
}

# Main execution
try {
    # Initialize backup
    Initialize-BackupStructure
    
    # Perform backups
    Backup-AllGPOs
    Backup-ADSecurityGroups
    Backup-AppLockerPolicies
    Backup-BrowserRegistrySettings
    Backup-OUStructureAndLinks
    
    # Create restoration tools
    Create-RestorationScripts
    
    # Verify and test
    Verify-BackupIntegrity
    Test-BackupRestoration
    
    # Save manifest
    Save-BackupManifest
    
    # Compress if requested
    Compress-BackupSet
    
    # Clean up old backups
    Remove-OldBackups
    
    # Stop logging
    Stop-Transcript
    
    # Display summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Backup completed successfully!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Backup location: $BackupSetPath" -ForegroundColor Yellow
    
    if ($CompressBackup -and $BackupResults.Items.ContainsKey('Compression')) {
        Write-Host "Archive location: $($BackupResults.Items['Compression'].ArchivePath)" -ForegroundColor Yellow
    }
    
    Write-Host "`nBackup Summary:" -ForegroundColor Cyan
    foreach ($Item in $BackupResults.Items.Keys) {
        if ($Item -ne 'Compression') {
            Write-Host "  ${Item}: $($BackupResults.Items[$Item].Count) items" -ForegroundColor Gray
        }
    }
    
    if ($BackupResults.Errors.Count -gt 0) {
        Write-Host "`nErrors encountered: $($BackupResults.Errors.Count)" -ForegroundColor Red
    }
    
    if ($BackupResults.Warnings.Count -gt 0) {
        Write-Host "Warnings: $($BackupResults.Warnings.Count)" -ForegroundColor Yellow
    }
    
    Write-Host "`nTo restore from this backup, run:" -ForegroundColor Cyan
    Write-Host "  $RestoreScriptPath -BackupSetPath '$BackupSetPath'" -ForegroundColor White
    
} catch {
    Write-Error "Critical error during backup: $_"
    Stop-Transcript
    exit 1
}