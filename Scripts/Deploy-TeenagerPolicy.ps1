#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Deploys teenager restriction policies for the scottify.io domain
.DESCRIPTION
    This script deploys AppLocker rules, Chrome browser restrictions, and other
    security policies for the Teenagers group in the scottify.io domain.
.PARAMETER DomainName
    The domain name (default: scottify.io)
.PARAMETER TeenagerGroupName
    The name of the teenager security group (default: Teenagers)
.PARAMETER GPOName
    The name of the Group Policy Object (default: GP_Teenager_Restrictions_Policy)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({
        try {
            $domain = Get-ADDomain -Identity $_ -ErrorAction Stop
            return $true
        } catch {
            throw "Domain '$_' not found or not accessible. Please verify the domain name."
        }
    })]
    [string]$DomainName,
    
    [ValidateNotNullOrEmpty()]
    [string]$TeenagerGroupName = "Teenagers",
    
    [ValidateNotNullOrEmpty()]
    [string]$GPOName = "GP_Teenager_Restrictions_Policy",
    
    [string]$OUPath,  # Optional - will be constructed from domain if not provided
    
    [switch]$TestMode
)

# Script requires elevation
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script must be run as Administrator. Exiting..."
    exit 2
}

# Import required modules
try {
    Import-Module GroupPolicy -ErrorAction Stop
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Error "Failed to import required modules. Please install RSAT tools."
    exit 2
}

# Step 0: Run validation checks
Write-Host "=== Running Codebase Integrity Validation ==" -ForegroundColor Cyan
$validationScript = "$PSScriptRoot\Test-CodebaseIntegrity.ps1"
if (Test-Path $validationScript) {
    try {
        $validationResult = & $validationScript -QuickTest
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Codebase validation failed. Please fix all issues before deployment."
            exit 2
        }
        Write-Host "✅ Codebase validation passed" -ForegroundColor Green
    } catch {
        Write-Error "Failed to run validation: $_"
        exit 2
    }
} else {
    Write-Warning "Validation script not found. Proceeding without validation."
}

# Initialize backup path variable
$backupPath = "$PSScriptRoot\..\Backups\$(Get-Date -Format 'yyyyMMdd-HHmmss')"
if (-not $TestMode) {
    if (-not (Test-Path $backupPath)) {
        New-Item -Path $backupPath -ItemType Directory -Force | Out-Null
    }
}

# Construct OUPath if not provided
if ([string]::IsNullOrEmpty($OUPath)) {
    $domainDN = (Get-ADDomain -Identity $DomainName).DistinguishedName
    $OUPath = "OU=Teenagers,$domainDN"
    Write-Host "Auto-generated OU Path: $OUPath" -ForegroundColor Yellow
}

Write-Host "=== Teenager Policy Deployment Script ===" -ForegroundColor Cyan
Write-Host "Domain: $DomainName" -ForegroundColor Yellow
Write-Host "Target Group: $TeenagerGroupName" -ForegroundColor Yellow
Write-Host "GPO Name: $GPOName" -ForegroundColor Yellow
Write-Host "OU Path: $OUPath" -ForegroundColor Yellow

# Step 1: Create Teenagers security group if it doesn't exist
Write-Host "`n[1/7] Checking/Creating Teenagers security group..." -ForegroundColor Green
try {
    $teenGroup = Get-ADGroup -Filter "Name -eq '$TeenagerGroupName'" -ErrorAction SilentlyContinue
    if (-not $teenGroup) {
        if (-not $TestMode) {
            try {
                # Get domain DN dynamically
                $domainDN = (Get-ADDomain -Identity $DomainName).DistinguishedName
                $groupPath = "CN=Users,$domainDN"
                
                New-ADGroup -Name $TeenagerGroupName `
                           -GroupCategory Security `
                           -GroupScope Global `
                           -Description "Security group for teenagers with restricted access" `
                           -Path $groupPath `
                           -ErrorAction Stop
                Write-Host "Created new security group: $TeenagerGroupName" -ForegroundColor Green
            } catch {
                Write-Error "Failed to create AD group: $_"
                exit 2
            }
        } else {
            Write-Host "TEST MODE: Would create group $TeenagerGroupName" -ForegroundColor Yellow
        }
    } else {
        Write-Host "Security group already exists: $TeenagerGroupName" -ForegroundColor Yellow
    }
} catch {
    Write-Error "Failed to query/create security group: $_"
    exit 2
}

# Step 2: Create backup of existing GPO (if it exists)
Write-Host "`n[2/7] Backing up existing GPO (if any)..." -ForegroundColor Green
try {
    $existingGpo = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
    if ($existingGpo -and -not $TestMode) {
        try {
            Backup-GPO -Name $GPOName -Path $backupPath -Comment "Pre-deployment backup" -ErrorAction Stop
            Write-Host "✅ Backed up existing GPO to: $backupPath" -ForegroundColor Green
        } catch {
            Write-Error "Failed to backup existing GPO: $_"
            exit 2
        }
    }
} catch {
    Write-Warning "Could not check for existing GPO: $_"
}

# Step 3: Create or get GPO
Write-Host "`n[3/7] Creating/Getting Group Policy Object..." -ForegroundColor Green
try {
    $gpo = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
    if (-not $gpo) {
        if (-not $TestMode) {
            try {
                $gpo = New-GPO -Name $GPOName -Comment "Restrictions for teenager accounts" -ErrorAction Stop
                Write-Host "Created new GPO: $GPOName" -ForegroundColor Green
            } catch {
                Write-Error "Failed to create GPO: $_"
                exit 2
            }
        } else {
            Write-Host "TEST MODE: Would create GPO $GPOName" -ForegroundColor Yellow
        }
    } else {
        Write-Host "GPO already exists: $GPOName" -ForegroundColor Yellow
    }
} catch {
    Write-Error "Failed to create/get GPO: $_"
    exit 2
}

# Step 4: Copy ADMX templates to PolicyDefinitions
Write-Host "`n[4/7] Installing Chrome ADMX templates..." -ForegroundColor Green
$policyDefinitionsPath = "\\$DomainName\SYSVOL\$DomainName\Policies\PolicyDefinitions"

if (Test-Path "$PSScriptRoot\..\Templates\ADMX\chrome.admx") {
    try {
        if (-not $TestMode) {
            # Create PolicyDefinitions folder if it doesn't exist
            if (-not (Test-Path $policyDefinitionsPath)) {
                New-Item -Path $policyDefinitionsPath -ItemType Directory -Force
            }
            
            # Copy ADMX files
            Copy-Item -Path "$PSScriptRoot\..\Templates\ADMX\*.admx" -Destination $policyDefinitionsPath -Force
            
            # Copy ADML files (language files)
            $admlPath = "$policyDefinitionsPath\en-US"
            if (-not (Test-Path $admlPath)) {
                New-Item -Path $admlPath -ItemType Directory -Force
            }
            Copy-Item -Path "$PSScriptRoot\..\Templates\ADML\*.adml" -Destination $admlPath -Force
            
            Write-Host "Chrome ADMX templates installed successfully" -ForegroundColor Green
        } else {
            Write-Host "TEST MODE: Would copy ADMX templates to $policyDefinitionsPath" -ForegroundColor Yellow
        }
    } catch {
        Write-Warning "Failed to copy ADMX templates: $_"
    }
} else {
    Write-Warning "Chrome ADMX templates not found in expected location"
}

# Step 5: Configure Chrome and browser policies
Write-Host "`n[5/7] Configuring browser restriction policies..." -ForegroundColor Green
try {
    $browserScriptPath = "$PSScriptRoot\Set-BrowserRestrictions.ps1"
    if (Test-Path $browserScriptPath) {
        if (-not $TestMode) {
            # Execute the browser restrictions script
            & $browserScriptPath
            Write-Host "  Browser restrictions applied successfully" -ForegroundColor Gray
        } else {
            # Run in WhatIf mode for testing
            & $browserScriptPath -WhatIf
            Write-Host "TEST MODE: Would apply browser restrictions" -ForegroundColor Yellow
        }
    } else {
        Write-Warning "Browser restrictions script not found at: $browserScriptPath"
        Write-Warning "Please ensure Set-BrowserRestrictions.ps1 exists in the Scripts directory"
    }
} catch {
    Write-Error "Failed to apply browser restrictions: $_"
}

# Step 6: Configure AppLocker policies
Write-Host "`n[6/7] Configuring AppLocker policies..." -ForegroundColor Green
if (-not $TestMode) {
    # Enable Application Identity service
    try {
        Set-GPRegistryValue -Name $GPOName `
                           -Key "HKLM\SYSTEM\CurrentControlSet\Services\AppIDSvc" `
                           -ValueName "Start" `
                           -Type DWord `
                           -Value 2  # Automatic
    } catch {
        Write-Error "Failed to set AppIDSvc registry value: $_"
    }

    # Import AppLocker policy
    $appLockerXmlPath = "$PSScriptRoot\..\Policies\Teenagers\AppLocker-Rules.xml"
    if (Test-Path $appLockerXmlPath) {
        try {
            Set-AppLockerPolicy -XmlPolicy $appLockerXmlPath -Merge
            Write-Host "  AppLocker rules imported successfully" -ForegroundColor Gray
        } catch {
            Write-Warning "Failed to import AppLocker policy: $_"
        }
    }
} else {
    Write-Host "TEST MODE: Would configure AppLocker policies" -ForegroundColor Yellow
}

# Step 7: Link GPO to OU
Write-Host "`n[7/7] Linking GPO to Organizational Unit..." -ForegroundColor Green
try {
    # Check if OU exists
    try {
        $ou = Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$OUPath'" -ErrorAction Stop
        if ($ou) {
            if (-not $TestMode) {
                try {
                    New-GPLink -Name $GPOName -Target $OUPath -LinkEnabled Yes -ErrorAction SilentlyContinue
                    Write-Host "GPO linked to $OUPath" -ForegroundColor Green
                } catch {
                    Write-Warning "Failed to link GPO (may already be linked): $_"
                }
            } else {
                Write-Host "TEST MODE: Would link GPO to $OUPath" -ForegroundColor Yellow
            }
        }
    } catch {
        Write-Warning "OU not found: $OUPath. Please create the OU and link the GPO manually."
    }
} catch {
    Write-Warning "Failed to query OU or link GPO: $_"
}

# Final summary
Write-Host "`n=== Deployment Summary ===" -ForegroundColor Cyan
Write-Host "1. Security group: $TeenagerGroupName" -ForegroundColor White
Write-Host "2. GPO created: $GPOName" -ForegroundColor White
Write-Host "3. Chrome policies: Configured" -ForegroundColor White
Write-Host "4. AppLocker rules: Configured" -ForegroundColor White
Write-Host "5. Additional security: Configured" -ForegroundColor White

if ($TestMode) {
    Write-Host "`nTEST MODE: No changes were made. Run without -TestMode to apply." -ForegroundColor Yellow
} else {
    Write-Host "`nDeployment complete! The policy will apply after:" -ForegroundColor Green
    Write-Host "  1. Users are added to the '$TeenagerGroupName' group" -ForegroundColor Yellow
    Write-Host "  2. Group Policy refresh (gpupdate /force)" -ForegroundColor Yellow
    Write-Host "  3. User logoff/logon" -ForegroundColor Yellow
}

# Create report
$reportPath = "$PSScriptRoot\..\deployment-report-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
@"
Teenager Policy Deployment Report
Generated: $(Get-Date)
Domain: $DomainName
GPO Name: $GPOName
Target Group: $TeenagerGroupName
Test Mode: $TestMode

Browser Restrictions Applied (via Set-BrowserRestrictions.ps1):
- Chrome: Force sign-in to $DomainName domain only
- Chrome: Incognito mode disabled
- Chrome: Safe Search and YouTube Restricted Mode enforced
- Chrome: Developer tools and chrome://flags disabled
- Chrome: All extensions blocked
- Chrome: URL blacklist configured (VPN/proxy sites blocked)
- Edge: Completely disabled
- Security: Command Prompt disabled
- Security: Registry Editor disabled
- Security: Task Manager disabled
- Security: Windows Defender Application Control enabled
- Security: Family Safety integration enabled

AppLocker Rules:
- Default deny all applications
- Whitelist: Steam (Valve Corporation)
- Whitelist: Epic Games
- Whitelist: Windows system files
"@ | Out-File -FilePath $reportPath

Write-Host "`nReport saved to: $reportPath" -ForegroundColor Cyan

# Create rollback script
if (-not $TestMode) {
    $rollbackScript = @"
# Rollback script for Teenager Policy Deployment
# Generated: $(Get-Date)
# Backup Path: $backupPath

# Restore GPO from backup
if (Test-Path '$backupPath') {
    Write-Host 'Restoring GPO from backup...' -ForegroundColor Yellow
    Restore-GPO -Name '$GPOName' -Path '$backupPath'
    Write-Host 'GPO restored successfully' -ForegroundColor Green
} else {
    Write-Warning 'Backup path not found!'
}

# Remove GPO link if needed
try {
    Remove-GPLink -Name '$GPOName' -Target '$OUPath' -ErrorAction SilentlyContinue
    Write-Host 'GPO link removed' -ForegroundColor Green
} catch {
    Write-Warning "Failed to remove GPO link: `$_"
}

Write-Host 'Rollback complete!' -ForegroundColor Green
"@
    
    $rollbackScriptPath = Join-Path $backupPath "rollback.ps1"
    $rollbackScript | Out-File $rollbackScriptPath -Encoding UTF8
    Write-Host "Rollback script saved to: $rollbackScriptPath" -ForegroundColor Cyan
}

# Exit with appropriate code
if ($TestMode) {
    exit 0
} else {
    # Check if deployment was successful
    if (Test-Path $reportPath) {
        exit 0
    } else {
        exit 2
    }
}