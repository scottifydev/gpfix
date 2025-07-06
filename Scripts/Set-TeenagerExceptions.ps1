#Requires -Version 5.1
#Requires -RunAsAdministrator
#Requires -Modules ActiveDirectory, GroupPolicy

<#
.SYNOPSIS
    Manages temporary exceptions for teenager computer usage policies.

.DESCRIPTION
    This script allows administrators to manage temporary exceptions for specific teenagers,
    including app whitelisting, browser settings, and time-based access. It includes
    logging, expiration management, and approval workflow hooks.
    
    The script preferentially uses Group Policy Objects (GPO) to manage registry settings
    but falls back to direct registry manipulation when GPO modules are not available.
    
    Registry Usage Rationale:
    - Exceptions need to be applied immediately without waiting for GPO refresh cycles
    - Per-user granular control requires dynamic registry paths based on username
    - Temporary nature of exceptions benefits from direct manipulation for quick removal
    - GPO method is preferred when available for better auditing and consistency
    - Direct registry is used as fallback for environments without RSAT tools

.PARAMETER Action
    The action to perform: Add, Remove, List, Clean, Report, Approve, Reject

.PARAMETER Username
    The username of the teenager for the exception

.PARAMETER ExceptionType
    Type of exception: AppWhitelist, BrowserSettings, TimeAccess, NetworkAccess

.PARAMETER ExceptionData
    The specific data for the exception (e.g., app path, website URL, time range)

.PARAMETER Duration
    Duration in hours for the exception (default: 24)

.PARAMETER Reason
    Reason for the exception request

.PARAMETER ApprovalRequired
    Whether approval is required before the exception becomes active

.EXAMPLE
    .\Manage-TeenagerExceptions.ps1 -Action Add -Username "john.doe" -ExceptionType AppWhitelist -ExceptionData "C:\Program Files\Zoom\bin\Zoom.exe" -Duration 4 -Reason "Online class"

.EXAMPLE
    .\Manage-TeenagerExceptions.ps1 -Action List -Username "john.doe"

.EXAMPLE
    .\Manage-TeenagerExceptions.ps1 -Action Report -ReportType Summary
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Add', 'Remove', 'List', 'Clean', 'Report', 'Approve', 'Reject')]
    [string]$Action,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$Username,

    [Parameter(Mandatory = $false)]
    [ValidateSet('AppWhitelist', 'BrowserSettings', 'TimeAccess', 'NetworkAccess')]
    [string]$ExceptionType,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$ExceptionData,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 168)]
    [int]$Duration = 24,

    [Parameter(Mandatory = $false)]
    [ValidateLength(1, 500)]
    [string]$Reason,

    [Parameter(Mandatory = $false)]
    [switch]$ApprovalRequired,

    [Parameter(Mandatory = $false)]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$ExceptionId,

    [Parameter(Mandatory = $false)]
    [ValidateSet('Summary', 'Detailed', 'Audit', 'Expired')]
    [string]$ReportType = 'Summary',

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$NotificationEmail,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$SMTPServer,

    [Parameter(Mandatory = $false)]
    [string]$GPOName = 'GP_TeenagerControl-Exceptions'
)

# Configuration
$script:Config = @{
    DataPath = "$env:ProgramData\TeenagerExceptions"
    ExceptionsFile = "$env:ProgramData\TeenagerExceptions\exceptions.json"
    LogFile = "$env:ProgramData\TeenagerExceptions\exceptions.log"
    AuditLogFile = "$env:ProgramData\TeenagerExceptions\audit.log"
    NotificationEmail = if ($NotificationEmail) { $NotificationEmail } else { $null }
    SMTPServer = if ($SMTPServer) { $SMTPServer } else { $null }
    MaxExceptionDuration = 168  # 7 days in hours
    RequireApprovalAbove = 48  # Require approval for exceptions > 48 hours
    GPOName = $GPOName
    UseGPO = $true  # Flag to determine if we use GPO or direct registry
    LastBackupPath = $null  # Track the last backup path for output
}

# Initialize data directory
function Initialize-DataDirectory {
    if (-not (Test-Path $script:Config.DataPath)) {
        New-Item -ItemType Directory -Path $script:Config.DataPath -Force | Out-Null
        
        # Set appropriate permissions
        $acl = Get-Acl $script:Config.DataPath
        $acl.SetAccessRuleProtection($true, $false)
        
        # Add Administrators full control
        $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
        )
        $acl.AddAccessRule($adminRule)
        
        # Add SYSTEM full control
        $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
        )
        $acl.AddAccessRule($systemRule)
        
        Set-Acl -Path $script:Config.DataPath -AclObject $acl
    }
}

# Logging functions
function Write-ExceptionLog {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error', 'Audit')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp [$Level] $Message"
    
    $logFile = if ($Level -eq 'Audit') { $script:Config.AuditLogFile } else { $script:Config.LogFile }
    
    Add-Content -Path $logFile -Value $logEntry -Force
    
    # Also write to console if verbose
    if ($VerbosePreference -eq 'Continue') {
        Write-Verbose $logEntry
    }
}

# Load exceptions from file
function Get-ExceptionData {
    if (Test-Path $script:Config.ExceptionsFile) {
        try {
            $content = Get-Content $script:Config.ExceptionsFile -Raw
            if ($content) {
                return $content | ConvertFrom-Json
            }
        }
        catch {
            Write-ExceptionLog -Message "Error loading exceptions: $_" -Level Error
        }
    }
    
    return @{
        Exceptions = @()
        PendingApprovals = @()
    }
}

# Save exceptions to file
function Save-ExceptionData {
    param($Data)
    
    try {
        $Data | ConvertTo-Json -Depth 10 | Set-Content -Path $script:Config.ExceptionsFile -Force
        Write-ExceptionLog -Message "Exception data saved successfully" -Level Info
    }
    catch {
        Write-ExceptionLog -Message "Error saving exceptions: $_" -Level Error
        throw
    }
}

# Function to backup GPO before modifications
function Backup-GPOBeforeModification {
    param(
        [Parameter(Mandatory=$true)]
        [string]$GPOName,
        
        [Parameter(Mandatory=$true)]
        [string]$ExceptionId
    )
    
    try {
        $backupPath = Join-Path -Path $script:Config.DataPath -ChildPath "GPO_Backups"
        if (-not (Test-Path $backupPath)) {
            New-Item -ItemType Directory -Path $backupPath -Force | Out-Null
        }
        
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $backupFolder = Join-Path -Path $backupPath -ChildPath "Exception_${ExceptionId}_$timestamp"
        
        Write-ExceptionLog -Message "Creating GPO backup before applying exception $ExceptionId" -Level Info
        $backup = Backup-GPO -Name $GPOName -Path $backupFolder -ErrorAction Stop
        Write-ExceptionLog -Message "GPO backup created successfully at: $backupFolder" -Level Info
        
        # Create restore script
        $restoreScript = @"
# Restore script for Teenager Exception GPO
# Created: $(Get-Date)
# GPO Name: $GPOName
# Backup ID: $($backup.Id)
# Exception ID: $ExceptionId

Write-Host "Restoring GPO '$GPOName' from backup..." -ForegroundColor Yellow
try {
    Import-GPO -BackupId "$($backup.Id)" -Path "$backupFolder" -TargetName "$GPOName" -ErrorAction Stop
    Write-Host "GPO restored successfully!" -ForegroundColor Green
}
catch {
    Write-Error "Failed to restore GPO: `$_"
}
"@
        $restoreScript | Out-File -FilePath (Join-Path -Path $backupFolder -ChildPath "Restore-GPO.ps1") -Encoding UTF8
        
        # Store backup info in exception data for reference
        $backupInfo = @{
            BackupId = $backup.Id
            BackupPath = $backupFolder
            BackupDate = $timestamp
        }
        
        return $backupInfo
    }
    catch {
        Write-ExceptionLog -Message "Failed to create GPO backup: $_" -Level Error
        throw
    }
}

# Generate unique exception ID
function New-ExceptionId {
    return [guid]::NewGuid().ToString()
}

# Add new exception
function Add-Exception {
    param(
        [string]$Username,
        [string]$ExceptionType,
        [string]$ExceptionData,
        [int]$Duration,
        [string]$Reason,
        [bool]$ApprovalRequired
    )
    
    # Validate duration
    if ($Duration -gt $script:Config.MaxExceptionDuration) {
        throw "Exception duration cannot exceed $($script:Config.MaxExceptionDuration) hours"
    }
    
    # Auto-require approval for long exceptions
    if ($Duration -gt $script:Config.RequireApprovalAbove) {
        $ApprovalRequired = $true
        Write-Warning "Approval required for exceptions longer than $($script:Config.RequireApprovalAbove) hours"
    }
    
    # Validate username
    try {
        $user = Get-ADUser -Identity $Username -ErrorAction Stop
    }
    catch {
        throw "User '$Username' not found in Active Directory"
    }
    
    $exceptionId = New-ExceptionId
    $currentTime = Get-Date
    $expirationTime = $currentTime.AddHours($Duration)
    
    $newException = @{
        Id = $exceptionId
        Username = $Username
        UserDisplayName = $user.Name
        Type = $ExceptionType
        Data = $ExceptionData
        Reason = $Reason
        CreatedBy = $env:USERNAME
        CreatedAt = $currentTime.ToString('o')
        ExpiresAt = $expirationTime.ToString('o')
        Duration = $Duration
        Status = if ($ApprovalRequired) { 'PendingApproval' } else { 'Active' }
        ApprovalRequired = $ApprovalRequired
        ApprovedBy = $null
        ApprovedAt = $null
    }
    
    $data = Get-ExceptionData
    
    if ($ApprovalRequired) {
        $data.PendingApprovals += $newException
    }
    else {
        $data.Exceptions += $newException
        Apply-Exception -Exception $newException
    }
    
    Save-ExceptionData -Data $data
    
    # Log the action
    $auditMessage = "Exception added - ID: $exceptionId, User: $Username, Type: $ExceptionType, Duration: $Duration hours, Status: $($newException.Status)"
    Write-ExceptionLog -Message $auditMessage -Level Audit
    
    # Send notification if approval required
    if ($ApprovalRequired) {
        Send-ApprovalNotification -Exception $newException
    }
    
    return $newException
}

# Apply exception to system
function Apply-Exception {
    param($Exception)
    
    try {
        if ($script:Config.UseGPO) {
            # Use GPO method
            Apply-ExceptionViaGPO -Exception $Exception
        }
        else {
            # Fall back to direct registry method with proper error handling
            Apply-ExceptionViaRegistry -Exception $Exception
        }
        
        Write-ExceptionLog -Message "Applied exception $($Exception.Id) for user $($Exception.Username)" -Level Info
    }
    catch {
        Write-ExceptionLog -Message "Failed to apply exception $($Exception.Id): $_" -Level Error
        throw
    }
}

# Apply exception via GPO
function Apply-ExceptionViaGPO {
    param($Exception)
    
    try {
        # Get or create the GPO
        $gpo = Get-GPO -Name $script:Config.GPOName -ErrorAction SilentlyContinue
        if (-not $gpo) {
            Write-ExceptionLog -Message "GPO '$($script:Config.GPOName)' not found. Creating new GPO." -Level Info
            try {
                $gpo = New-GPO -Name $script:Config.GPOName -Comment "Manages temporary exceptions for teenager policies"
            }
            catch {
                Write-ExceptionLog -Message "Failed to create GPO: $_" -Level Error
                throw
            }
        }
        
        # Create backup before making changes
        $backupInfo = $null
        try {
            $backupInfo = Backup-GPOBeforeModification -GPOName $script:Config.GPOName -ExceptionId $Exception.Id
            Write-ExceptionLog -Message "GPO backup created. Backup ID: $($backupInfo.BackupId)" -Level Info
        }
        catch {
            Write-ExceptionLog -Message "Failed to create GPO backup, proceeding with caution: $_" -Level Warning
            # Optionally, you might want to throw here to abort the operation
            # throw "Cannot proceed without backup"
        }
        
        # Build the registry path based on exception type
        $basePath = "HKLM\SOFTWARE\Policies\TeenagerControl"
        $subPath = switch ($Exception.Type) {
            'AppWhitelist' { "AppWhitelist\$($Exception.Username)" }
            'BrowserSettings' { "BrowserWhitelist\$($Exception.Username)" }
            'TimeAccess' { "TimeExceptions\$($Exception.Username)" }
            'NetworkAccess' { "NetworkExceptions\$($Exception.Username)" }
        }
        
        $fullPath = "$basePath\$subPath"
        
        # Apply the registry setting via GPO
        switch ($Exception.Type) {
            'AppWhitelist' {
                $appName = [System.IO.Path]::GetFileNameWithoutExtension($Exception.Data)
                try {
                    Set-GPRegistryValue -Name $script:Config.GPOName -Key $fullPath -ValueName $appName -Type String -Value $Exception.Data
                    Set-GPRegistryValue -Name $script:Config.GPOName -Key $fullPath -ValueName "${appName}_ExceptionId" -Type String -Value $Exception.Id
                }
                catch {
                    Write-ExceptionLog -Message "Failed to set GPO registry value for AppWhitelist: $_" -Level Error
                    throw
                }
            }
            
            'BrowserSettings' {
                $urlHash = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Exception.Data))
                $urlKey = [System.BitConverter]::ToString($urlHash).Replace("-", "").Substring(0, 16)
                
                try {
                    Set-GPRegistryValue -Name $script:Config.GPOName -Key $fullPath -ValueName $urlKey -Type String -Value $Exception.Data
                    Set-GPRegistryValue -Name $script:Config.GPOName -Key $fullPath -ValueName "${urlKey}_ExceptionId" -Type String -Value $Exception.Id
                }
                catch {
                    Write-ExceptionLog -Message "Failed to set GPO registry value for BrowserSettings: $_" -Level Error
                    throw
                }
            }
            
            'TimeAccess' {
                try {
                    Set-GPRegistryValue -Name $script:Config.GPOName -Key $fullPath -ValueName $Exception.Id -Type String -Value $Exception.Data
                }
                catch {
                    Write-ExceptionLog -Message "Failed to set GPO registry value for TimeAccess: $_" -Level Error
                    throw
                }
            }
            
            'NetworkAccess' {
                try {
                    Set-GPRegistryValue -Name $script:Config.GPOName -Key $fullPath -ValueName $Exception.Id -Type String -Value $Exception.Data
                }
                catch {
                    Write-ExceptionLog -Message "Failed to set GPO registry value for NetworkAccess: $_" -Level Error
                    throw
                }
            }
        }
        
        Write-ExceptionLog -Message "Applied exception via GPO: $($Exception.Id)" -Level Info
        
        # Log backup information if available
        if ($backupInfo) {
            Write-ExceptionLog -Message "GPO backup location: $($backupInfo.BackupPath)" -Level Info
            $script:Config.LastBackupPath = $backupInfo.BackupPath
        }
    }
    catch {
        Write-ExceptionLog -Message "Failed to apply exception via GPO, falling back to registry: $_" -Level Warning
        # Fall back to direct registry method
        Apply-ExceptionViaRegistry -Exception $Exception
    }
}

# Apply exception via direct registry (fallback method)
function Apply-ExceptionViaRegistry {
    param($Exception)
    
    try {
        switch ($Exception.Type) {
            'AppWhitelist' {
                # Add app to whitelist registry
                $regPath = "HKLM:\SOFTWARE\Policies\TeenagerControl\AppWhitelist\$($Exception.Username)"
                if (-not (Test-Path $regPath)) {
                    try {
                        New-Item -Path $regPath -Force -ErrorAction Stop | Out-Null
                    }
                    catch {
                        Write-ExceptionLog -Message "Failed to create registry path ${regPath}: $_" -Level Error
                        throw
                    }
                }
                
                $appName = [System.IO.Path]::GetFileNameWithoutExtension($Exception.Data)
                try {
                    New-ItemProperty -Path $regPath -Name $appName -Value $Exception.Data -PropertyType String -Force -ErrorAction Stop | Out-Null
                    
                    # Store exception ID for cleanup
                    New-ItemProperty -Path $regPath -Name "${appName}_ExceptionId" -Value $Exception.Id -PropertyType String -Force -ErrorAction Stop | Out-Null
                }
                catch {
                    Write-ExceptionLog -Message "Failed to set registry property for app whitelist: $_" -Level Error
                    throw
                }
            }
            
            'BrowserSettings' {
                # Add URL to allowed sites
                $regPath = "HKLM:\SOFTWARE\Policies\TeenagerControl\BrowserWhitelist\$($Exception.Username)"
                if (-not (Test-Path $regPath)) {
                    try {
                        New-Item -Path $regPath -Force -ErrorAction Stop | Out-Null
                    }
                    catch {
                        Write-ExceptionLog -Message "Failed to create registry path ${regPath}: $_" -Level Error
                        throw
                    }
                }
                
                $urlHash = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Exception.Data))
                $urlKey = [System.BitConverter]::ToString($urlHash).Replace("-", "").Substring(0, 16)
                
                try {
                    New-ItemProperty -Path $regPath -Name $urlKey -Value $Exception.Data -PropertyType String -Force -ErrorAction Stop | Out-Null
                    New-ItemProperty -Path $regPath -Name "${urlKey}_ExceptionId" -Value $Exception.Id -PropertyType String -Force -ErrorAction Stop | Out-Null
                }
                catch {
                    Write-ExceptionLog -Message "Failed to set registry property for browser settings: $_" -Level Error
                    throw
                }
            }
            
            'TimeAccess' {
                # Modify time restrictions
                $regPath = "HKLM:\SOFTWARE\Policies\TeenagerControl\TimeExceptions\$($Exception.Username)"
                if (-not (Test-Path $regPath)) {
                    try {
                        New-Item -Path $regPath -Force -ErrorAction Stop | Out-Null
                    }
                    catch {
                        Write-ExceptionLog -Message "Failed to create registry path ${regPath}: $_" -Level Error
                        throw
                    }
                }
                
                try {
                    New-ItemProperty -Path $regPath -Name $Exception.Id -Value $Exception.Data -PropertyType String -Force -ErrorAction Stop | Out-Null
                }
                catch {
                    Write-ExceptionLog -Message "Failed to set registry property for time access: $_" -Level Error
                    throw
                }
            }
            
            'NetworkAccess' {
                # Add network exception
                $regPath = "HKLM:\SOFTWARE\Policies\TeenagerControl\NetworkExceptions\$($Exception.Username)"
                if (-not (Test-Path $regPath)) {
                    try {
                        New-Item -Path $regPath -Force -ErrorAction Stop | Out-Null
                    }
                    catch {
                        Write-ExceptionLog -Message "Failed to create registry path ${regPath}: $_" -Level Error
                        throw
                    }
                }
                
                try {
                    New-ItemProperty -Path $regPath -Name $Exception.Id -Value $Exception.Data -PropertyType String -Force -ErrorAction Stop | Out-Null
                }
                catch {
                    Write-ExceptionLog -Message "Failed to set registry property for network access: $_" -Level Error
                    throw
                }
            }
        }
        
        Write-ExceptionLog -Message "Applied exception via direct registry: $($Exception.Id)" -Level Info
    }
    catch {
        Write-ExceptionLog -Message "Failed to apply exception via registry: $_" -Level Error
        throw
    }
}

# Remove exception from system
function Remove-ExceptionFromSystem {
    param($Exception)
    
    try {
        if ($script:Config.UseGPO) {
            # Use GPO method
            Remove-ExceptionViaGPO -Exception $Exception
        }
        else {
            # Fall back to direct registry method with proper error handling
            Remove-ExceptionViaRegistry -Exception $Exception
        }
        
        Write-ExceptionLog -Message "Removed exception $($Exception.Id) from system" -Level Info
    }
    catch {
        Write-ExceptionLog -Message "Failed to remove exception $($Exception.Id): $_" -Level Error
        throw
    }
}

# Remove exception via GPO
function Remove-ExceptionViaGPO {
    param($Exception)
    
    try {
        # Get the GPO
        $gpo = Get-GPO -Name $script:Config.GPOName -ErrorAction Stop
        
        # Create backup before removing exception
        $backupInfo = $null
        try {
            $backupInfo = Backup-GPOBeforeModification -GPOName $script:Config.GPOName -ExceptionId $Exception.Id
            Write-ExceptionLog -Message "GPO backup created before removal. Backup ID: $($backupInfo.BackupId)" -Level Info
        }
        catch {
            Write-ExceptionLog -Message "Failed to create GPO backup before removal, proceeding with caution: $_" -Level Warning
        }
        
        # Build the registry path based on exception type
        $basePath = "HKLM\SOFTWARE\Policies\TeenagerControl"
        $subPath = switch ($Exception.Type) {
            'AppWhitelist' { "AppWhitelist\$($Exception.Username)" }
            'BrowserSettings' { "BrowserWhitelist\$($Exception.Username)" }
            'TimeAccess' { "TimeExceptions\$($Exception.Username)" }
            'NetworkAccess' { "NetworkExceptions\$($Exception.Username)" }
        }
        
        $fullPath = "$basePath\$subPath"
        
        # Remove the registry settings via GPO
        switch ($Exception.Type) {
            'AppWhitelist' {
                $appName = [System.IO.Path]::GetFileNameWithoutExtension($Exception.Data)
                Remove-GPRegistryValue -Name $script:Config.GPOName -Key $fullPath -ValueName $appName -ErrorAction SilentlyContinue
                Remove-GPRegistryValue -Name $script:Config.GPOName -Key $fullPath -ValueName "${appName}_ExceptionId" -ErrorAction SilentlyContinue
            }
            
            'BrowserSettings' {
                # Find and remove the URL entry
                $urlHash = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Exception.Data))
                $urlKey = [System.BitConverter]::ToString($urlHash).Replace("-", "").Substring(0, 16)
                
                Remove-GPRegistryValue -Name $script:Config.GPOName -Key $fullPath -ValueName $urlKey -ErrorAction SilentlyContinue
                Remove-GPRegistryValue -Name $script:Config.GPOName -Key $fullPath -ValueName "${urlKey}_ExceptionId" -ErrorAction SilentlyContinue
            }
            
            'TimeAccess' {
                Remove-GPRegistryValue -Name $script:Config.GPOName -Key $fullPath -ValueName $Exception.Id -ErrorAction SilentlyContinue
            }
            
            'NetworkAccess' {
                Remove-GPRegistryValue -Name $script:Config.GPOName -Key $fullPath -ValueName $Exception.Id -ErrorAction SilentlyContinue
            }
        }
        
        Write-ExceptionLog -Message "Removed exception via GPO: $($Exception.Id)" -Level Info
        
        # Log backup information if available
        if ($backupInfo) {
            Write-ExceptionLog -Message "GPO backup location: $($backupInfo.BackupPath)" -Level Info
            $script:Config.LastBackupPath = $backupInfo.BackupPath
        }
    }
    catch {
        Write-ExceptionLog -Message "Failed to remove exception via GPO, falling back to registry: $_" -Level Warning
        # Fall back to direct registry method
        Remove-ExceptionViaRegistry -Exception $Exception
    }
}

# Remove exception via direct registry (fallback method)
function Remove-ExceptionViaRegistry {
    param($Exception)
    
    try {
        switch ($Exception.Type) {
            'AppWhitelist' {
                $regPath = "HKLM:\SOFTWARE\Policies\TeenagerControl\AppWhitelist\$($Exception.Username)"
                if (Test-Path $regPath) {
                    $appName = [System.IO.Path]::GetFileNameWithoutExtension($Exception.Data)
                    try {
                        Remove-ItemProperty -Path $regPath -Name $appName -ErrorAction Stop
                        Remove-ItemProperty -Path $regPath -Name "${appName}_ExceptionId" -ErrorAction Stop
                    }
                    catch {
                        Write-ExceptionLog -Message "Failed to remove registry property for app whitelist: $_" -Level Error
                        throw
                    }
                }
            }
            
            'BrowserSettings' {
                $regPath = "HKLM:\SOFTWARE\Policies\TeenagerControl\BrowserWhitelist\$($Exception.Username)"
                if (Test-Path $regPath) {
                    # Find and remove the URL entry
                    try {
                        $properties = Get-ItemProperty -Path $regPath -ErrorAction Stop
                        foreach ($prop in $properties.PSObject.Properties) {
                            if ($prop.Name -like "*_ExceptionId" -and $prop.Value -eq $Exception.Id) {
                                $urlKey = $prop.Name.Replace("_ExceptionId", "")
                                Remove-ItemProperty -Path $regPath -Name $urlKey -ErrorAction Stop
                                Remove-ItemProperty -Path $regPath -Name $prop.Name -ErrorAction Stop
                            }
                        }
                    }
                    catch {
                        Write-ExceptionLog -Message "Failed to remove registry property for browser settings: $_" -Level Error
                        throw
                    }
                }
            }
            
            'TimeAccess' {
                $regPath = "HKLM:\SOFTWARE\Policies\TeenagerControl\TimeExceptions\$($Exception.Username)"
                if (Test-Path $regPath) {
                    try {
                        Remove-ItemProperty -Path $regPath -Name $Exception.Id -ErrorAction Stop
                    }
                    catch {
                        Write-ExceptionLog -Message "Failed to remove registry property for time access: $_" -Level Error
                        throw
                    }
                }
            }
            
            'NetworkAccess' {
                $regPath = "HKLM:\SOFTWARE\Policies\TeenagerControl\NetworkExceptions\$($Exception.Username)"
                if (Test-Path $regPath) {
                    try {
                        Remove-ItemProperty -Path $regPath -Name $Exception.Id -ErrorAction Stop
                    }
                    catch {
                        Write-ExceptionLog -Message "Failed to remove registry property for network access: $_" -Level Error
                        throw
                    }
                }
            }
        }
        
        Write-ExceptionLog -Message "Removed exception via direct registry: $($Exception.Id)" -Level Info
    }
    catch {
        Write-ExceptionLog -Message "Failed to remove exception via registry: $_" -Level Error
        throw
    }
}

# Remove exception
function Remove-Exception {
    param([string]$ExceptionId)
    
    $data = Get-ExceptionData
    $exception = $data.Exceptions | Where-Object { $_.Id -eq $ExceptionId }
    
    if (-not $exception) {
        throw "Exception with ID '$ExceptionId' not found"
    }
    
    # Remove from system
    Remove-ExceptionFromSystem -Exception $exception
    
    # Remove from data
    $data.Exceptions = $data.Exceptions | Where-Object { $_.Id -ne $ExceptionId }
    Save-ExceptionData -Data $data
    
    # Log the action
    $auditMessage = "Exception removed - ID: $ExceptionId, User: $($exception.Username), Type: $($exception.Type)"
    Write-ExceptionLog -Message $auditMessage -Level Audit
    
    return $exception
}

# List exceptions
function Get-Exceptions {
    param(
        [string]$Username,
        [switch]$IncludePending,
        [switch]$ActiveOnly
    )
    
    $data = Get-ExceptionData
    $exceptions = $data.Exceptions
    
    if ($IncludePending) {
        $exceptions += $data.PendingApprovals
    }
    
    if ($Username) {
        $exceptions = $exceptions | Where-Object { $_.Username -eq $Username }
    }
    
    if ($ActiveOnly) {
        $currentTime = Get-Date
        $exceptions = $exceptions | Where-Object {
            $_.Status -eq 'Active' -and [DateTime]$_.ExpiresAt -gt $currentTime
        }
    }
    
    return $exceptions | Sort-Object CreatedAt -Descending
}

# Clean expired exceptions
function Remove-ExpiredExceptions {
    $data = Get-ExceptionData
    $currentTime = Get-Date
    $expiredExceptions = @()
    
    # Find expired exceptions
    $activeExceptions = @()
    foreach ($exception in $data.Exceptions) {
        if ([DateTime]$exception.ExpiresAt -lt $currentTime -and $exception.Status -eq 'Active') {
            $expiredExceptions += $exception
            $exception.Status = 'Expired'
            
            # Remove from system
            Remove-ExceptionFromSystem -Exception $exception
            
            # Log expiration
            $auditMessage = "Exception expired - ID: $($exception.Id), User: $($exception.Username), Type: $($exception.Type)"
            Write-ExceptionLog -Message $auditMessage -Level Audit
        }
        else {
            $activeExceptions += $exception
        }
    }
    
    # Update data
    $data.Exceptions = $activeExceptions
    Save-ExceptionData -Data $data
    
    # Send notifications for expired exceptions
    foreach ($expired in $expiredExceptions) {
        Send-ExpirationNotification -Exception $expired
    }
    
    return $expiredExceptions
}

# Approve exception
function Approve-Exception {
    param([string]$ExceptionId)
    
    $data = Get-ExceptionData
    $exception = $data.PendingApprovals | Where-Object { $_.Id -eq $ExceptionId }
    
    if (-not $exception) {
        throw "Pending exception with ID '$ExceptionId' not found"
    }
    
    # Update exception status
    $exception.Status = 'Active'
    $exception.ApprovedBy = $env:USERNAME
    $exception.ApprovedAt = (Get-Date).ToString('o')
    
    # Move from pending to active
    $data.PendingApprovals = $data.PendingApprovals | Where-Object { $_.Id -ne $ExceptionId }
    $data.Exceptions += $exception
    
    # Apply the exception
    Apply-Exception -Exception $exception
    
    Save-ExceptionData -Data $data
    
    # Log the action
    $auditMessage = "Exception approved - ID: $ExceptionId, User: $($exception.Username), Type: $($exception.Type), ApprovedBy: $($env:USERNAME)"
    Write-ExceptionLog -Message $auditMessage -Level Audit
    
    # Send approval notification
    Send-ApprovalStatusNotification -Exception $exception -Approved $true
    
    return $exception
}

# Reject exception
function Reject-Exception {
    param(
        [string]$ExceptionId,
        [string]$Reason
    )
    
    $data = Get-ExceptionData
    $exception = $data.PendingApprovals | Where-Object { $_.Id -eq $ExceptionId }
    
    if (-not $exception) {
        throw "Pending exception with ID '$ExceptionId' not found"
    }
    
    # Update exception status
    $exception.Status = 'Rejected'
    $exception.RejectedBy = $env:USERNAME
    $exception.RejectedAt = (Get-Date).ToString('o')
    $exception.RejectionReason = $Reason
    
    # Remove from pending
    $data.PendingApprovals = $data.PendingApprovals | Where-Object { $_.Id -ne $ExceptionId }
    
    Save-ExceptionData -Data $data
    
    # Log the action
    $auditMessage = "Exception rejected - ID: $ExceptionId, User: $($exception.Username), Type: $($exception.Type), RejectedBy: $($env:USERNAME), Reason: $Reason"
    Write-ExceptionLog -Message $auditMessage -Level Audit
    
    # Send rejection notification
    Send-ApprovalStatusNotification -Exception $exception -Approved $false -Reason $Reason
    
    return $exception
}

# Generate reports
function New-ExceptionReport {
    param(
        [ValidateSet('Summary', 'Detailed', 'Audit', 'Expired')]
        [string]$ReportType = 'Summary'
    )
    
    $data = Get-ExceptionData
    $report = @{
        GeneratedAt = Get-Date
        GeneratedBy = $env:USERNAME
        ReportType = $ReportType
    }
    
    switch ($ReportType) {
        'Summary' {
            $report.TotalExceptions = $data.Exceptions.Count
            $report.ActiveExceptions = ($data.Exceptions | Where-Object { $_.Status -eq 'Active' }).Count
            $report.PendingApprovals = $data.PendingApprovals.Count
            $report.ExceptionsByType = $data.Exceptions | Group-Object Type | Select-Object Name, Count
            $report.ExceptionsByUser = $data.Exceptions | Group-Object Username | Select-Object Name, Count
            $report.AverageDuration = if ($data.Exceptions.Count -gt 0) {
                ($data.Exceptions | Measure-Object -Property Duration -Average).Average
            } else { 0 }
        }
        
        'Detailed' {
            $report.Exceptions = $data.Exceptions | Select-Object Id, Username, Type, Data, Status, CreatedAt, ExpiresAt, CreatedBy
            $report.PendingApprovals = $data.PendingApprovals | Select-Object Id, Username, Type, Data, Reason, CreatedAt, CreatedBy
        }
        
        'Audit' {
            # Read audit log
            if (Test-Path $script:Config.AuditLogFile) {
                $auditEntries = Get-Content $script:Config.AuditLogFile -Tail 1000
                $report.AuditEntries = $auditEntries
            }
        }
        
        'Expired' {
            $expiredExceptions = $data.Exceptions | Where-Object { 
                $_.Status -eq 'Expired' -or ([DateTime]$_.ExpiresAt -lt (Get-Date) -and $_.Status -eq 'Active')
            }
            $report.ExpiredExceptions = $expiredExceptions | Select-Object Id, Username, Type, Data, CreatedAt, ExpiresAt, CreatedBy
            $report.Count = $expiredExceptions.Count
        }
    }
    
    return $report
}

# Email notification functions
function Send-EmailNotification {
    param(
        [string]$To,
        [string]$Subject,
        [string]$Body,
        [string]$Priority = 'Normal'
    )
    
    # Check if email configuration is available
    if (-not $script:Config.SMTPServer -or -not $script:Config.NotificationEmail) {
        Write-ExceptionLog -Message "Email notification skipped - SMTP configuration not provided" -Level Warning
        return
    }
    
    try {
        $mailParams = @{
            To = $To
            From = "TeenagerExceptions@$($script:Config.SMTPServer.Split('.')[1..$($script:Config.SMTPServer.Split('.').Count-1)] -join '.')"
            Subject = $Subject
            Body = $Body
            BodyAsHtml = $true
            SmtpServer = $script:Config.SMTPServer
            Priority = $Priority
        }
        
        Send-MailMessage @mailParams
        Write-ExceptionLog -Message "Email notification sent to $To" -Level Info
    }
    catch {
        Write-ExceptionLog -Message "Failed to send email notification: $_" -Level Error
    }
}

function Send-ApprovalNotification {
    param($Exception)
    
    # Skip if no email configuration
    if (-not $script:Config.NotificationEmail) {
        Write-ExceptionLog -Message "Approval notification skipped - no notification email configured" -Level Warning
        return
    }
    
    $subject = "Teenager Exception Approval Required - $($Exception.Username)"
    $body = @"
<html>
<body>
<h3>Exception Approval Required</h3>
<p>A new exception request requires your approval:</p>
<table border='1' cellpadding='5'>
<tr><td><b>Exception ID:</b></td><td>$($Exception.Id)</td></tr>
<tr><td><b>Username:</b></td><td>$($Exception.Username) ($($Exception.UserDisplayName))</td></tr>
<tr><td><b>Exception Type:</b></td><td>$($Exception.Type)</td></tr>
<tr><td><b>Exception Data:</b></td><td>$($Exception.Data)</td></tr>
<tr><td><b>Duration:</b></td><td>$($Exception.Duration) hours</td></tr>
<tr><td><b>Reason:</b></td><td>$($Exception.Reason)</td></tr>
<tr><td><b>Requested By:</b></td><td>$($Exception.CreatedBy)</td></tr>
<tr><td><b>Requested At:</b></td><td>$($Exception.CreatedAt)</td></tr>
</table>
<p>To approve or reject this request, run:</p>
<pre>
# To approve:
.\Manage-TeenagerExceptions.ps1 -Action Approve -ExceptionId "$($Exception.Id)"

# To reject:
.\Manage-TeenagerExceptions.ps1 -Action Reject -ExceptionId "$($Exception.Id)" -Reason "Your reason here"
</pre>
</body>
</html>
"@
    
    Send-EmailNotification -To $script:Config.NotificationEmail -Subject $subject -Body $body -Priority High
}

function Send-ExpirationNotification {
    param($Exception)
    
    # Skip if no email configuration
    if (-not $script:Config.NotificationEmail) {
        return
    }
    
    $subject = "Teenager Exception Expired - $($Exception.Username)"
    $body = @"
<html>
<body>
<h3>Exception Expired</h3>
<p>The following exception has expired and been removed:</p>
<table border='1' cellpadding='5'>
<tr><td><b>Exception ID:</b></td><td>$($Exception.Id)</td></tr>
<tr><td><b>Username:</b></td><td>$($Exception.Username) ($($Exception.UserDisplayName))</td></tr>
<tr><td><b>Exception Type:</b></td><td>$($Exception.Type)</td></tr>
<tr><td><b>Exception Data:</b></td><td>$($Exception.Data)</td></tr>
<tr><td><b>Created At:</b></td><td>$($Exception.CreatedAt)</td></tr>
<tr><td><b>Expired At:</b></td><td>$($Exception.ExpiresAt)</td></tr>
</table>
</body>
</html>
"@
    
    Send-EmailNotification -To $script:Config.NotificationEmail -Subject $subject -Body $body
}

function Send-ApprovalStatusNotification {
    param(
        $Exception,
        [bool]$Approved,
        [string]$Reason
    )
    
    $status = if ($Approved) { "Approved" } else { "Rejected" }
    $subject = "Teenager Exception $status - $($Exception.Username)"
    
    $body = @"
<html>
<body>
<h3>Exception $status</h3>
<p>The following exception request has been ${status}:</p>
<table border='1' cellpadding='5'>
<tr><td><b>Exception ID:</b></td><td>$($Exception.Id)</td></tr>
<tr><td><b>Username:</b></td><td>$($Exception.Username) ($($Exception.UserDisplayName))</td></tr>
<tr><td><b>Exception Type:</b></td><td>$($Exception.Type)</td></tr>
<tr><td><b>Exception Data:</b></td><td>$($Exception.Data)</td></tr>
<tr><td><b>Status:</b></td><td>$status</td></tr>
"@
    
    if ($Approved) {
        $body += "<tr><td><b>Approved By:</b></td><td>$($Exception.ApprovedBy)</td></tr>"
        $body += "<tr><td><b>Approved At:</b></td><td>$($Exception.ApprovedAt)</td></tr>"
    }
    else {
        $body += "<tr><td><b>Rejected By:</b></td><td>$($Exception.RejectedBy)</td></tr>"
        $body += "<tr><td><b>Rejection Reason:</b></td><td>$Reason</td></tr>"
    }
    
    $body += @"
</table>
</body>
</html>
"@
    
    # Send to requester
    try {
        $requesterEmail = (Get-ADUser -Identity $Exception.CreatedBy -Properties EmailAddress).EmailAddress
        if ($requesterEmail) {
            Send-EmailNotification -To $requesterEmail -Subject $subject -Body $body
        }
    }
    catch {
        Write-ExceptionLog -Message "Could not send notification to requester: $_" -Level Warning
    }
}

# Check for GPO module availability
function Test-GPOModuleAvailable {
    try {
        $null = Get-Command Get-GPO -ErrorAction Stop
        return $true
    }
    catch {
        Write-ExceptionLog -Message "GroupPolicy module not available. Falling back to direct registry method." -Level Warning
        return $false
    }
}

# Main execution
try {
    # Check if GPO module is available
    if (-not (Test-GPOModuleAvailable)) {
        $script:Config.UseGPO = $false
        Write-Warning "GroupPolicy module not available. Using direct registry method."
        Write-Warning "Direct registry changes require manual policy refresh for immediate effect."
        Write-Warning "Consider installing RSAT Group Policy Management tools for better integration."
    }
    
    Initialize-DataDirectory
    
    switch ($Action) {
        'Add' {
            if (-not $Username -or -not $ExceptionType -or -not $ExceptionData) {
                throw "Username, ExceptionType, and ExceptionData are required for Add action"
            }
            
            $exception = Add-Exception -Username $Username -ExceptionType $ExceptionType `
                -ExceptionData $ExceptionData -Duration $Duration -Reason $Reason `
                -ApprovalRequired $ApprovalRequired
            
            Write-Host "Exception created successfully!" -ForegroundColor Green
            $exception | Format-Table -AutoSize
            
            # Display backup path if available
            if ($script:Config.UseGPO -and $script:Config.LastBackupPath) {
                Write-Host "`nGPO Backup Location: $($script:Config.LastBackupPath)" -ForegroundColor Yellow
                Write-Host "To restore GPO, run the Restore-GPO.ps1 script in the backup folder." -ForegroundColor Gray
            }
        }
        
        'Remove' {
            if (-not $ExceptionId) {
                throw "ExceptionId is required for Remove action"
            }
            
            $exception = Remove-Exception -ExceptionId $ExceptionId
            Write-Host "Exception removed successfully!" -ForegroundColor Green
            $exception | Format-Table -AutoSize
            
            # Display backup path if available
            if ($script:Config.UseGPO -and $script:Config.LastBackupPath) {
                Write-Host "`nGPO Backup Location: $($script:Config.LastBackupPath)" -ForegroundColor Yellow
                Write-Host "To restore GPO, run the Restore-GPO.ps1 script in the backup folder." -ForegroundColor Gray
            }
        }
        
        'List' {
            $exceptions = Get-Exceptions -Username $Username -IncludePending
            
            if ($exceptions.Count -eq 0) {
                Write-Host "No exceptions found." -ForegroundColor Yellow
            }
            else {
                Write-Host "`nActive and Pending Exceptions:" -ForegroundColor Cyan
                $exceptions | Format-Table Id, Username, Type, Data, Status, ExpiresAt, CreatedBy -AutoSize
            }
        }
        
        'Clean' {
            $expired = Remove-ExpiredExceptions
            
            if ($expired.Count -eq 0) {
                Write-Host "No expired exceptions found." -ForegroundColor Green
            }
            else {
                Write-Host "Removed $($expired.Count) expired exception(s):" -ForegroundColor Yellow
                $expired | Format-Table Id, Username, Type, ExpiresAt -AutoSize
            }
        }
        
        'Report' {
            $report = New-ExceptionReport -ReportType $ReportType
            
            Write-Host "`nException Report - Type: $ReportType" -ForegroundColor Cyan
            Write-Host "Generated: $($report.GeneratedAt)" -ForegroundColor Gray
            Write-Host "Generated By: $($report.GeneratedBy)" -ForegroundColor Gray
            Write-Host ("-" * 50) -ForegroundColor Gray
            
            switch ($ReportType) {
                'Summary' {
                    Write-Host "Total Exceptions: $($report.TotalExceptions)"
                    Write-Host "Active Exceptions: $($report.ActiveExceptions)"
                    Write-Host "Pending Approvals: $($report.PendingApprovals)"
                    Write-Host "Average Duration: $([Math]::Round($report.AverageDuration, 2)) hours"
                    
                    if ($report.ExceptionsByType) {
                        Write-Host "`nExceptions by Type:" -ForegroundColor Yellow
                        $report.ExceptionsByType | Format-Table -AutoSize
                    }
                    
                    if ($report.ExceptionsByUser) {
                        Write-Host "Exceptions by User:" -ForegroundColor Yellow
                        $report.ExceptionsByUser | Format-Table -AutoSize
                    }
                }
                
                'Detailed' {
                    if ($report.Exceptions) {
                        Write-Host "`nActive Exceptions:" -ForegroundColor Yellow
                        $report.Exceptions | Format-Table -AutoSize
                    }
                    
                    if ($report.PendingApprovals) {
                        Write-Host "`nPending Approvals:" -ForegroundColor Yellow
                        $report.PendingApprovals | Format-Table -AutoSize
                    }
                }
                
                'Audit' {
                    if ($report.AuditEntries) {
                        Write-Host "Recent Audit Entries:" -ForegroundColor Yellow
                        $report.AuditEntries | Select-Object -Last 50 | ForEach-Object { Write-Host $_ }
                    }
                    else {
                        Write-Host "No audit entries found." -ForegroundColor Gray
                    }
                }
                
                'Expired' {
                    Write-Host "Total Expired Exceptions: $($report.Count)"
                    if ($report.ExpiredExceptions) {
                        $report.ExpiredExceptions | Format-Table -AutoSize
                    }
                }
            }
        }
        
        'Approve' {
            if (-not $ExceptionId) {
                throw "ExceptionId is required for Approve action"
            }
            
            $exception = Approve-Exception -ExceptionId $ExceptionId
            Write-Host "Exception approved successfully!" -ForegroundColor Green
            $exception | Format-Table -AutoSize
            
            # Display backup path if available
            if ($script:Config.UseGPO -and $script:Config.LastBackupPath) {
                Write-Host "`nGPO Backup Location: $($script:Config.LastBackupPath)" -ForegroundColor Yellow
                Write-Host "To restore GPO, run the Restore-GPO.ps1 script in the backup folder." -ForegroundColor Gray
            }
        }
        
        'Reject' {
            if (-not $ExceptionId) {
                throw "ExceptionId is required for Reject action"
            }
            
            if (-not $Reason) {
                $Reason = Read-Host "Please provide a reason for rejection"
            }
            
            $exception = Reject-Exception -ExceptionId $ExceptionId -Reason $Reason
            Write-Host "Exception rejected successfully!" -ForegroundColor Green
            $exception | Format-Table -AutoSize
        }
    }
}
catch {
    Write-Error "Error: $_"
    Write-ExceptionLog -Message "Script error: $_" -Level Error
    exit 2
}

# Note: Functions are available within this script
# To use in other scripts, dot-source this file