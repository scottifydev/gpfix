# Group Policy Environment Assessment Scripts

This directory contains comprehensive assessment scripts to evaluate your Active Directory environment before deploying teenager restriction policies.

## Overview

These scripts perform a thorough health check and readiness assessment of your Group Policy infrastructure to ensure a smooth deployment of teenager restrictions.

## Script Inventory

### 1. Deploy-ComprehensiveAssessment.ps1
**Purpose**: Master orchestration script that runs all assessments in proper order  
**Usage**: `.\Deploy-ComprehensiveAssessment.ps1`  
**Output**: Consolidated HTML report with go/no-go recommendation

### 2. Test-DomainControllerHealth.ps1
**Purpose**: Verifies domain controller health and replication  
**Checks**:
- DC connectivity and services
- AD replication status
- SYSVOL replication
- DNS health
- Time synchronization

### 3. Test-GPOInfrastructure.ps1
**Purpose**: Validates Group Policy infrastructure  
**Checks**:
- GPO service status
- SYSVOL accessibility
- PolicyDefinitions (ADMX) structure
- Orphaned GPOs
- Version consistency

### 4. Get-GPOInventory.ps1
**Purpose**: Creates complete inventory of existing GPOs  
**Outputs**:
- All GPOs with metadata
- GPO links and targeting
- AppLocker policies
- Browser restrictions
- OU structure documentation

### 5. Get-GPOConflicts.ps1
**Purpose**: Detects policy conflicts across GPOs  
**Identifies**:
- AppLocker conflicts
- Browser policy conflicts
- Security setting overlaps
- Registry conflicts
- Precedence issues

### 6. Get-LegacyPolicies.ps1
**Purpose**: Identifies outdated/deprecated policies  
**Finds**:
- Software Restriction Policies
- Unused GPOs
- Broken references
- Legacy ADMX usage
- Deprecated settings

### 7. Get-AppLockerStatus.ps1
**Purpose**: Assesses AppLocker readiness  
**Validates**:
- Application Identity service
- Existing rules
- Event log configuration
- Enforcement modes
- Rule conflicts

### 8. Remove-AppLockerEnvironment.ps1
**Purpose**: Cleans up AppLocker configuration  
**Features**:
- Remove orphaned rules
- Clean cache
- Fix service issues
- Consolidate rules
- Reset if needed

### 9. Get-ChromePolicies.ps1
**Purpose**: Evaluates Chrome browser policies  
**Reviews**:
- ADMX template versions
- Existing restrictions
- Extension policies
- URL filtering
- Cross-browser consistency

### 10. New-EnvironmentBackup.ps1
**Purpose**: Creates comprehensive backup  
**Backs up**:
- All GPOs
- AD security groups
- AppLocker policies
- Registry settings
- OU structure

### 11. Test-FinalHealthCheck.ps1
**Purpose**: Final go/no-go assessment  
**Provides**:
- Deployment readiness score
- Critical issue identification
- Executive summary
- Deployment checklist

## Usage Workflow

### Quick Assessment (Recommended First Run)
```powershell
# Run the orchestration script
.\Deploy-ComprehensiveAssessment.ps1

# Review the HTML report that opens automatically
```

### Individual Script Usage
```powershell
# Check specific components
.\Test-DomainControllerHealth.ps1 -HTMLReport
.\Get-GPOInventory.ps1 -OutputPath "C:\Reports"
.\Get-GPOConflicts.ps1 -ExportFormat "HTML","CSV"
```

### Pre-Deployment Checklist
1. Run `Deploy-ComprehensiveAssessment.ps1`
2. Review consolidated report
3. Address any critical issues
4. Re-run failed assessments
5. Ensure backup is complete
6. Get deployment approval

## Output Structure

Running the comprehensive assessment creates:
```
AssessmentReports_YYYYMMDD_HHMMSS/
├── Test-DomainControllerHealth/
├── Test-GPOInfrastructure/
├── Get-GPOInventory/
├── Get-GPOConflicts/
├── Get-LegacyPolicies/
├── Get-AppLockerStatus/
├── Get-ChromePolicies/
├── New-EnvironmentBackup/
├── Test-FinalHealthCheck/
├── ConsolidatedAssessmentReport.html
├── AssessmentResults.json
└── AssessmentTranscript.log
```

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+
- Domain Administrator privileges
- RSAT tools installed (AD and Group Policy modules)
- Network access to all domain controllers

## Best Practices

1. **Always run the comprehensive assessment** before making GPO changes
2. **Keep assessment reports** for compliance and rollback purposes
3. **Address all critical issues** before deployment
4. **Re-run assessments** after making fixes
5. **Review the backup** to ensure it's complete

## Troubleshooting

### Common Issues

**Issue**: Scripts fail with "module not found"  
**Solution**: Install RSAT tools: `Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0`

**Issue**: Access denied errors  
**Solution**: Run PowerShell as Administrator with Domain Admin credentials

**Issue**: Cannot reach domain controllers  
**Solution**: Check network connectivity and firewall rules

## Support

For issues or questions about these assessment scripts, consult:
- The detailed logs in each script's output directory
- The consolidated assessment transcript
- Your organization's AD/GPO documentation
- Microsoft's Group Policy troubleshooting guide

## Next Steps

After successful assessment:
1. Review teenager policy documentation in `/Documentation`
2. Test deployment with `Deploy-TeenagerPolicy.ps1 -TestMode`
3. Schedule deployment window
4. Deploy policies with `Deploy-TeenagerPolicy.ps1`
5. Monitor with `Get-TeenagerPolicyStatus.ps1`