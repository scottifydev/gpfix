# Claude Instructions for Windows Group Policy Administration

## Overview
This document summarizes the Claude instructions that have been adapted from a development-focused workflow to Windows Group Policy administration. The instructions maintain the rigorous validation and multi-agent approach while being specifically tailored for GP management.

## Key Files Created

### 1. Core Instructions
- **CLAUDE.md** - Primary instructions for GP administration partnership
- **TODO.md** - Task tracking template
- **PROGRESS.md** - Deployment progress tracking

### 2. Validation Hooks
Located in `/hooks/`:
- **smart-lint.ps1** - PowerShell syntax and security validation
- **validate-gpo.ps1** - GPO structure and conflict checking  
- **pre-deployment-check.ps1** - Comprehensive pre-deployment validation

### 3. Automation Scripts
Located in `/Scripts/Automation/`:
- **Invoke-GPODeployment.ps1** - Enforces Research → Plan → Implement → Validate → Deploy workflow
- **Test-GPOEnvironment.ps1** - Environment readiness validation

### 4. Templates
Located in `/Templates/`:
- **DEPLOYMENT_PLAN_TEMPLATE.md** - Structured deployment planning
- **POLICY_DOCUMENTATION_TEMPLATE.md** - GPO documentation standard
- **VALIDATION_REPORT_TEMPLATE.md** - Validation results format

### 5. Configuration
- **settings.json** - Hook configuration for automated validation

## Core Principles Implemented

### 1. 🚨 ALL Validation Issues are BLOCKING
- No warnings are acceptable in production
- Exit code 2 for any validation failure
- Scripts cannot proceed past validation failures

### 2. Multi-Agent Approach
- Instructions encourage spawning parallel agents
- Divide complex tasks across multiple agents
- Example: One agent checks conflicts while another validates syntax

### 3. Mandatory Workflow
```
Research → Plan → Implement → Validate → Deploy
```
- Never skip steps
- Each phase has validation checkpoints
- Documentation required at each step

### 4. Reality Checkpoints
Mandatory stops for validation:
- After creating a GPO
- Before linking to production
- When security implications arise
- Before declaring "complete"

### 5. Zero Tolerance for Production Issues
- No hardcoded passwords
- No untested policies
- No TODOs in scripts
- No assumptions about environment

## Key Adaptations from Original

### From Development to Administration
| Original (Dev) | Adapted (GP Admin) |
|---------------|-------------------|
| Go syntax rules | PowerShell best practices |
| Code linting | GPO validation |
| Unit tests | Policy compliance tests |
| Git commits | GPO deployment |
| Build errors | Validation failures |

### Security Focus
- Added rollback procedures requirement
- Mandatory backup before changes
- Security compliance validation
- Audit trail documentation

### Communication Protocols
- Clear status indicators (✅ ❌)
- Structured deployment communications
- Progress tracking requirements
- Failure documentation

## Usage Instructions

### For New GP Tasks
1. Read CLAUDE.md first
2. Create/update TODO.md
3. Follow the workflow strictly
4. Run validation at each checkpoint
5. Document in PROGRESS.md

### For Deployments
1. Use Invoke-GPODeployment.ps1
2. Let it enforce validation
3. Follow rollback procedures if needed
4. Update documentation

### For Validation
1. Run Test-CodebaseIntegrity.ps1 regularly
2. Fix ALL issues before proceeding
3. No exceptions for "minor" warnings

## Benefits

1. **Reduced Risk** - Validation prevents misconfigurations
2. **Consistency** - Standardized workflow for all GP tasks
3. **Auditability** - Clear documentation trail
4. **Efficiency** - Multi-agent approach speeds complex tasks
5. **Recovery** - Always have rollback procedures ready

## Remember

> "When in doubt, we choose security over convenience"

> "If CLAUDE.md hasn't been referenced in 30+ minutes, RE-READ IT!"

These instructions create a framework for safe, efficient, and well-documented Group Policy administration.