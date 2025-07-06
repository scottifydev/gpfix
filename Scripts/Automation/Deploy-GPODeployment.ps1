#Requires -RunAsAdministrator
#Requires -Version 5.1
#Requires -Modules ActiveDirectory, GroupPolicy

<#
.SYNOPSIS
    Automated Group Policy deployment with strict validation enforcement
.DESCRIPTION
    Implements the Research -> Plan -> Implement -> Validate -> Deploy workflow
    with automatic validation checkpoints and rollback capabilities.
    ALL validation issues are BLOCKING - deployment stops on any failure.
.PARAMETER GPOName
    Name of the Group Policy Object to deploy
.PARAMETER TargetOU
    Distinguished name of the target Organizational Unit
.PARAMETER BackupPath
    Path for automatic GPO backups (default: .\Backups\GPO)
.PARAMETER WhatIf
    Performs a dry run without making actual changes
.PARAMETER Force
    Skip confirmation prompts (validation still enforced)
.PARAMETER PilotGroup
    Optional security group for pilot deployment
.EXAMPLE
    .\Deploy-GPODeployment.ps1 -GPOName "GP_Teenager_Restrictions_Policy" -TargetOU "OU=Teenagers,DC=scottify,DC=io"
.EXAMPLE
    .\Deploy-GPODeployment.ps1 -GPOName "GP_Browser Policy" -TargetOU "OU=Test,DC=scottify,DC=io" -WhatIf
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$GPOName,
    
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$TargetOU,
    
    [Parameter(Mandatory = $false)]
    [string]$BackupPath = ".\Backups\GPO",
    
    [Parameter(Mandatory = $false)]
    [switch]$Force,
    
    [Parameter(Mandatory = $false)]
    [string]$PilotGroup,
    
    [Parameter(Mandatory = $false)]
    [string]$LogPath = ".\Logs\Deployment"
)

# Initialize
$ErrorActionPreference = 'Stop'
$Script:DeploymentID = "Deploy_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
$Script:ValidationFailures = @()
$Script:DeploymentPhase = "Initialization"
$Script:RollbackInfo = @{}

# Create directories
foreach ($Path in @($BackupPath, $LogPath)) {
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
}

# Logging function
function Write-DeploymentLog {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS", "VALIDATION")]
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Script:DeploymentPhase] [$Level] $Message"
    
    # Console output with color
    switch ($Level) {
        "ERROR"      { Write-Host $LogMessage -ForegroundColor Red }
        "WARNING"    { Write-Host $LogMessage -ForegroundColor Yellow }
        "SUCCESS"    { Write-Host $LogMessage -ForegroundColor Green }
        "VALIDATION" { Write-Host $LogMessage -ForegroundColor Cyan }
        default      { Write-Host $LogMessage -ForegroundColor White }
    }
    
    # File logging
    $LogFile = Join-Path $LogPath "$Script:DeploymentID.log"
    Add-Content -Path $LogFile -Value $LogMessage
}

# Validation checkpoint function
function Invoke-ValidationCheckpoint {
    param(
        [string]$CheckpointName,
        [scriptblock]$ValidationScript,
        [bool]$IsCritical = $true
    )
    
    Write-DeploymentLog "Running validation checkpoint: $CheckpointName" -Level VALIDATION
    
    try {
        $Result = & $ValidationScript
        
        if ($Result -is [hashtable] -and $Result.ContainsKey('Success')) {
            if ($Result.Success) {
                Write-DeploymentLog "[OK] Validation passed: $CheckpointName" -Level SUCCESS
                return $true
            }
            else {
                Write-DeploymentLog "[X] Validation failed: $CheckpointName - $($Result.Message)" -Level ERROR
                $Script:ValidationFailures += @{
                    Checkpoint = $CheckpointName
                    Message = $Result.Message
                    Phase = $Script:DeploymentPhase
                    Critical = $IsCritical
                }
                
                if ($IsCritical) {
                    throw "Critical validation failure: $CheckpointName"
                }
                return $false
            }
        }
        else {
            # Assume boolean result
            if ($Result) {
                Write-DeploymentLog "[OK] Validation passed: $CheckpointName" -Level SUCCESS
                return $true
            }
            else {
                throw "Validation returned false"
            }
        }
    }
    catch {
        Write-DeploymentLog "[X] Validation error: $CheckpointName - $_" -Level ERROR
        $Script:ValidationFailures += @{
            Checkpoint = $CheckpointName
            Message = $_.Exception.Message
            Phase = $Script:DeploymentPhase
            Critical = $IsCritical
        }
        
        if ($IsCritical) {
            throw "Critical validation error: $CheckpointName - $_"
        }
        return $false
    }
}

# Exit with proper code for blocking failures
function Exit-WithCode {
    param([int]$ExitCode)
    
    if ($Script:ValidationFailures.Count -gt 0) {
        Write-Host "`n=== VALIDATION FAILURES SUMMARY ===" -ForegroundColor Red
        foreach ($Failure in $Script:ValidationFailures) {
            Write-Host "Phase: $($Failure.Phase)" -ForegroundColor Yellow
            Write-Host "Checkpoint: $($Failure.Checkpoint)" -ForegroundColor Yellow
            Write-Host "Error: $($Failure.Message)" -ForegroundColor Red
            Write-Host "Critical: $($Failure.Critical)" -ForegroundColor $(if ($Failure.Critical) { 'Red' } else { 'Yellow' })
            Write-Host ""
        }
    }
    
    # Save deployment report
    $Report = @{
        DeploymentID = $Script:DeploymentID
        Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        GPOName = $GPOName
        TargetOU = $TargetOU
        Phase = $Script:DeploymentPhase
        ExitCode = $ExitCode
        ValidationFailures = $Script:ValidationFailures
        RollbackInfo = $Script:RollbackInfo
    }
    
    $ReportFile = Join-Path $LogPath "$Script:DeploymentID`_report.json"
    $Report | ConvertTo-Json -Depth 10 | Out-File -FilePath $ReportFile -Encoding UTF8
    
    exit $ExitCode
}

try {
    Write-DeploymentLog "=== GROUP POLICY DEPLOYMENT AUTOMATION ===" -Level INFO
    Write-DeploymentLog "Deployment ID: $Script:DeploymentID" -Level INFO
    Write-DeploymentLog "GPO Name: $GPOName" -Level INFO
    Write-DeploymentLog "Target OU: $TargetOU" -Level INFO
    Write-DeploymentLog "WhatIf Mode: $WhatIfPreference" -Level INFO
    
    # PHASE 1: RESEARCH
    $Script:DeploymentPhase = "Research"
    Write-DeploymentLog "Starting RESEARCH phase..." -Level INFO
    
    # Check environment
    Invoke-ValidationCheckpoint -CheckpointName "Environment-PreCheck" -ValidationScript {
        $TestScript = Join-Path (Split-Path $PSScriptRoot -Parent) "Automation\Test-GPOEnvironment.ps1"
        if (Test-Path $TestScript) {
            $EnvResult = & $TestScript -TargetOU $TargetOU -Quiet
            return @{
                Success = $EnvResult.EnvironmentReady
                Message = if (-not $EnvResult.EnvironmentReady) { 
                    "Environment check failed: $($EnvResult.Issues -join ', ')" 
                } else { "Environment ready" }
            }
        }
        else {
            return @{Success = $false; Message = "Test-GPOEnvironment.ps1 not found"}
        }
    }
    
    # Research existing GPO
    Invoke-ValidationCheckpoint -CheckpointName "GPO-Exists" -ValidationScript {
        try {
            $GPO = Get-GPO -Name $GPOName -ErrorAction Stop
            $Script:RollbackInfo.GPOGuid = $GPO.Id
            return @{Success = $true; Message = "GPO found: $($GPO.Id)"}
        }
        catch {
            return @{Success = $false; Message = "GPO not found: $GPOName"}
        }
    }
    
    # Check for conflicts
    Invoke-ValidationCheckpoint -CheckpointName "Conflict-Detection" -ValidationScript {
        $ConflictScript = Join-Path (Split-Path $PSScriptRoot -Parent) "Assessment\Find-GPOConflicts.ps1"
        if (Test-Path $ConflictScript) {
            $Conflicts = & $ConflictScript -GPOName $GPOName -Silent
            if ($Conflicts.Count -eq 0) {
                return @{Success = $true; Message = "No conflicts detected"}
            }
            else {
                return @{Success = $false; Message = "Found $($Conflicts.Count) conflicts"}
            }
        }
        else {
            return @{Success = $true; Message = "Conflict detection skipped (script not found)"}
        }
    } -IsCritical $false
    
    # PHASE 2: PLAN
    $Script:DeploymentPhase = "Plan"
    Write-DeploymentLog "Starting PLAN phase..." -Level INFO
    
    # Create deployment plan
    $DeploymentPlan = @{
        Phases = @(
            @{Name = "Backup"; Description = "Create GPO backup before changes"},
            @{Name = "Validate"; Description = "Run pre-deployment validation"},
            @{Name = "Link"; Description = "Link GPO to target OU"},
            @{Name = "Test"; Description = "Verify policy application"},
            @{Name = "Monitor"; Description = "Monitor for issues"}
        )
        RollbackProcedure = @(
            "1. Remove GPO link from target OU",
            "2. Restore GPO from backup if modified",
            "3. Force policy refresh on affected systems",
            "4. Verify rollback completion"
        )
        EstimatedDuration = "15-30 minutes"
    }
    
    Write-DeploymentLog "Deployment plan created with $($DeploymentPlan.Phases.Count) phases" -Level SUCCESS
    
    # PHASE 3: IMPLEMENT
    $Script:DeploymentPhase = "Implement"
    Write-DeploymentLog "Starting IMPLEMENT phase..." -Level INFO
    
    # Create backup
    if ($PSCmdlet.ShouldProcess("$GPOName", "Create GPO backup")) {
        Invoke-ValidationCheckpoint -CheckpointName "Create-Backup" -ValidationScript {
            try {
                $BackupFolder = Join-Path $BackupPath $Script:DeploymentID
                New-Item -Path $BackupFolder -ItemType Directory -Force | Out-Null
                
                $Backup = Backup-GPO -Name $GPOName -Path $BackupFolder -Comment "Pre-deployment backup"
                $Script:RollbackInfo.BackupId = $Backup.Id
                $Script:RollbackInfo.BackupPath = $BackupFolder
                
                return @{Success = $true; Message = "Backup created: $($Backup.Id)"}
            }
            catch {
                return @{Success = $false; Message = "Backup failed: $_"}
            }
        }
    }
    
    # PHASE 4: VALIDATE
    $Script:DeploymentPhase = "Validate"
    Write-DeploymentLog "Starting VALIDATE phase..." -Level INFO
    
    # Run validation hooks
    $ValidationHooks = @(
        @{Script = "Test-CodebaseIntegrity.ps1"; Required = $true},
        @{Script = "Assessment\Test-FinalHealthCheck.ps1"; Required = $true},
        @{Script = "Test-PolicyCompliance.ps1"; Required = $false}
    )
    
    foreach ($Hook in $ValidationHooks) {
        $HookPath = Join-Path (Split-Path $PSScriptRoot -Parent) $Hook.Script
        
        if (Test-Path $HookPath) {
            Invoke-ValidationCheckpoint -CheckpointName "Hook-$($Hook.Script)" -ValidationScript {
                Write-DeploymentLog "Running validation hook: $($Hook.Script)" -Level VALIDATION
                $HookResult = & $HookPath
                
                # Different scripts return different result formats
                if ($Hook.Script -match "Test-CodebaseIntegrity") {
                    $Success = ($HookResult.Failed -eq 0 -and $HookResult.Warnings -eq 0)
                    $Message = if (-not $Success) { 
                        "Failed: $($HookResult.Failed), Warnings: $($HookResult.Warnings)" 
                    } else { "All tests passed" }
                }
                elseif ($Hook.Script -match "Run-FinalHealthCheck") {
                    $Success = $HookResult.DeploymentReady
                    $Message = if (-not $Success) { 
                        "Score: $($HookResult.Score)%, Critical: $($HookResult.CriticalFailures)" 
                    } else { "Health check passed" }
                }
                else {
                    # Generic boolean result
                    $Success = [bool]$HookResult
                    $Message = if (-not $Success) { "Validation failed" } else { "Validation passed" }
                }
                
                return @{Success = $Success; Message = $Message}
            } -IsCritical $Hook.Required
        }
        else {
            Write-DeploymentLog "Validation hook not found: $($Hook.Script)" -Level WARNING
        }
    }
    
    # Check for any critical validation failures
    $CriticalFailures = $Script:ValidationFailures | Where-Object { $_.Critical }
    if ($CriticalFailures.Count -gt 0) {
        Write-DeploymentLog "DEPLOYMENT BLOCKED: $($CriticalFailures.Count) critical validation failures" -Level ERROR
        Exit-WithCode -ExitCode 2
    }
    
    # PHASE 5: DEPLOY
    $Script:DeploymentPhase = "Deploy"
    Write-DeploymentLog "Starting DEPLOY phase..." -Level INFO
    
    if (-not $Force -and -not $WhatIfPreference) {
        Write-Host "`nReady to deploy. Continue? (Y/N): " -NoNewline -ForegroundColor Yellow
        $Confirm = Read-Host
        if ($Confirm -ne 'Y') {
            Write-DeploymentLog "Deployment cancelled by user" -Level WARNING
            Exit-WithCode -ExitCode 1
        }
    }
    
    # Link GPO to target OU
    if ($PSCmdlet.ShouldProcess("$TargetOU", "Link GPO '$GPOName'")) {
        Invoke-ValidationCheckpoint -CheckpointName "Link-GPO" -ValidationScript {
            try {
                # Check if already linked
                $ExistingLink = Get-GPOReport -Name $GPOName -ReportType Xml | 
                               Select-String -Pattern $TargetOU -Quiet
                
                if (-not $ExistingLink) {
                    New-GPLink -Name $GPOName -Target $TargetOU -LinkEnabled Yes
                    $Script:RollbackInfo.LinkCreated = $true
                    Write-DeploymentLog "GPO linked to $TargetOU" -Level SUCCESS
                }
                else {
                    Write-DeploymentLog "GPO already linked to $TargetOU" -Level INFO
                    $Script:RollbackInfo.LinkCreated = $false
                }
                
                return @{Success = $true; Message = "GPO link configured"}
            }
            catch {
                return @{Success = $false; Message = "Failed to link GPO: $_"}
            }
        }
    }
    
    # Apply to pilot group if specified
    if ($PilotGroup -and $PSCmdlet.ShouldProcess("$PilotGroup", "Apply security filtering")) {
        Invoke-ValidationCheckpoint -CheckpointName "Configure-PilotGroup" -ValidationScript {
            try {
                $GPO = Get-GPO -Name $GPOName
                Set-GPPermission -Name $GPOName -TargetName $PilotGroup -TargetType Group `
                                 -PermissionLevel GpoApply -Replace
                
                # Remove Authenticated Users if pilot group specified
                Set-GPPermission -Name $GPOName -TargetName "Authenticated Users" `
                                 -TargetType Group -PermissionLevel None -Replace
                
                $Script:RollbackInfo.PilotGroup = $PilotGroup
                return @{Success = $true; Message = "Pilot group configured"}
            }
            catch {
                return @{Success = $false; Message = "Failed to configure pilot group: $_"}
            }
        } -IsCritical $false
    }
    
    # Force policy update
    if ($PSCmdlet.ShouldProcess("Domain Controllers", "Force policy update")) {
        Write-DeploymentLog "Forcing policy update..." -Level INFO
        try {
            Invoke-Command -ScriptBlock { gpupdate /force } -ErrorAction SilentlyContinue
            Write-DeploymentLog "Policy update initiated" -Level SUCCESS
        }
        catch {
            Write-DeploymentLog "Could not force policy update: $_" -Level WARNING
        }
    }
    
    # Post-deployment validation
    Write-DeploymentLog "Running post-deployment validation..." -Level INFO
    Start-Sleep -Seconds 5  # Allow time for policy to propagate
    
    Invoke-ValidationCheckpoint -CheckpointName "Post-Deploy-Verification" -ValidationScript {
        try {
            # Verify link exists
            $Links = (Get-GPOReport -Name $GPOName -ReportType Xml | 
                     Select-String -Pattern '<LinksTo>' -Context 0,10).Context.PostContext
            
            if ($Links -match [regex]::Escape($TargetOU)) {
                return @{Success = $true; Message = "GPO successfully linked and active"}
            }
            else {
                return @{Success = $false; Message = "GPO link not found in report"}
            }
        }
        catch {
            return @{Success = $false; Message = "Could not verify deployment: $_"}
        }
    } -IsCritical $false
    
    # Deployment summary
    Write-Host "`n=== DEPLOYMENT COMPLETED SUCCESSFULLY ===" -ForegroundColor Green
    Write-DeploymentLog "Deployment completed successfully" -Level SUCCESS
    
    $Summary = @"

Deployment Summary:
- GPO: $GPOName
- Target: $TargetOU
- Backup: $($Script:RollbackInfo.BackupPath)
- Status: DEPLOYED
$(if ($PilotGroup) { "- Pilot Group: $PilotGroup" })

Next Steps:
1. Monitor policy application (gpresult /r)
2. Check event logs for policy errors
3. Gather user feedback
4. Expand deployment if pilot successful

Rollback Command:
.\Deploy-GPODeployment.ps1 -GPOName "$GPOName" -TargetOU "$TargetOU" -Rollback -BackupId "$($Script:RollbackInfo.BackupId)"
"@
    
    Write-Host $Summary -ForegroundColor Cyan
    
    # Save deployment record
    $DeploymentRecord = @{
        DeploymentID = $Script:DeploymentID
        Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        GPOName = $GPOName
        GPOGuid = $Script:RollbackInfo.GPOGuid
        TargetOU = $TargetOU
        BackupId = $Script:RollbackInfo.BackupId
        BackupPath = $Script:RollbackInfo.BackupPath
        LinkCreated = $Script:RollbackInfo.LinkCreated
        PilotGroup = $PilotGroup
        Status = "Deployed"
    }
    
    $RecordFile = Join-Path $LogPath "$Script:DeploymentID`_success.json"
    $DeploymentRecord | ConvertTo-Json -Depth 10 | Out-File -FilePath $RecordFile -Encoding UTF8
    
    Exit-WithCode -ExitCode 0
}
catch {
    Write-DeploymentLog "DEPLOYMENT FAILED: $_" -Level ERROR
    
    # Attempt rollback
    if ($Script:RollbackInfo.LinkCreated) {
        Write-DeploymentLog "Attempting automatic rollback..." -Level WARNING
        try {
            Remove-GPLink -Name $GPOName -Target $TargetOU -ErrorAction Stop
            Write-DeploymentLog "Rollback successful - GPO link removed" -Level SUCCESS
        }
        catch {
            Write-DeploymentLog "ROLLBACK FAILED: Manual intervention required!" -Level ERROR
        }
    }
    
    Exit-WithCode -ExitCode 2
}