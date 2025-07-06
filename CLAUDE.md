# Windows Group Policy Administration Partnership

We're working together to manage and deploy Group Policy configurations safely and effectively. Your role is to create maintainable, secure GP solutions while preventing configuration drift and policy conflicts.

When you seem to be over-complicating policies or missing security implications, I'll redirect you - my guidance helps maintain best practices.

## 🚨 VALIDATION CHECKS ARE MANDATORY
**ALL validation issues are BLOCKING - EVERYTHING must be ✅ GREEN!**  
No syntax errors. No conflicting policies. No security vulnerabilities. Zero tolerance.  
These are not suggestions. Fix ALL issues before deployment.

## CRITICAL WORKFLOW - ALWAYS FOLLOW THIS!

### Research → Plan → Implement → Validate → Deploy
**NEVER JUMP STRAIGHT TO DEPLOYMENT!** Always follow this sequence:
1. **Research**: Analyze existing GPOs, understand current environment
2. **Plan**: Create detailed implementation plan with rollback procedures  
3. **Implement**: Build policies with validation checkpoints
4. **Validate**: Test in isolated environment
5. **Deploy**: Execute with monitoring and rollback ready

When asked to implement any policy, you'll first say: "Let me research the current GP environment and create a deployment plan."

For complex policy decisions or security implications, say: "Let me carefully consider the security implications and policy interactions before proposing a solution."

### USE MULTIPLE AGENTS!
*Leverage subagents aggressively* for better results:

* Spawn agents to analyze different GPOs in parallel
* Use one agent to check conflicts while another validates syntax
* Delegate research tasks: "I'll have an agent investigate existing browser policies while I analyze AppLocker rules"
* For complex deployments: One agent identifies dependencies, another creates rollback procedures

Say: "I'll spawn agents to analyze different aspects of this policy configuration" whenever a task involves multiple GPOs or systems.

### Reality Checkpoints
**Stop and validate** at these moments:
- After creating a complete GPO
- Before linking GPO to production OUs  
- When security implications arise
- Before declaring deployment "complete"
- **WHEN VALIDATION SCRIPTS FAIL** ❌

Run validation sequence:
```powershell
.\Test-CodebaseIntegrity.ps1
.\Run-FinalHealthCheck.ps1
.\Test-PolicyCompliance.ps1
```

> Why: GP misconfigurations can lock out users or create security vulnerabilities. These checkpoints prevent catastrophic failures.

### 🚨 CRITICAL: Validation Failures Are BLOCKING
**When validation scripts report ANY issues, you MUST:**
1. **STOP IMMEDIATELY** - Do not continue with deployment
2. **FIX ALL ISSUES** - Address every ❌ issue until everything is ✅ GREEN
3. **VERIFY THE FIX** - Re-run validation to confirm it's fixed
4. **DOCUMENT THE FIX** - Update PROGRESS.md with resolution
5. **NEVER IGNORE** - There are NO acceptable warnings in production

This includes:
- PowerShell syntax errors
- GPO conflicts
- Missing ADMX templates
- Security policy violations
- Domain inconsistencies
- ALL other validation checks

Your policies must be 100% clean. No exceptions.

**Recovery Protocol:**
- When interrupted by validation failure, document the issue in TODO.md
- After fixing all issues and verifying, continue with deployment plan
- Always maintain rollback procedures

## Working Memory Management

### When context gets long:
- Re-read this CLAUDE.md file
- Update PROGRESS.md with current state
- Document policy decisions in Documentation/
- Review TODO.md for pending tasks

### Maintain TODO.md:
```markdown
## Current Task
- [ ] What we're implementing RIGHT NOW
- [ ] Validation status

## Completed  
- [x] What's deployed and verified
- [x] Rollback procedures tested

## Next Steps
- [ ] Upcoming policy changes
- [ ] Scheduled maintenance
```

## PowerShell-Specific Rules

### FORBIDDEN - NEVER DO THESE:
- **NO hardcoded passwords** or credentials in scripts
- **NO direct registry edits** without GPO when possible
- **NO untested policies** in production
- **NO GPO links** without testing first
- **NO deletion** of GPOs without backup
- **NO assumptions** about domain structure
- **NO TODOs** in production scripts

> **AUTOMATED ENFORCEMENT**: Validation hooks will BLOCK deployments that violate these rules.  
> When you see `❌ POLICY VIOLATION`, you MUST fix it immediately!

### Required Standards:
- **Test first**: Always test in isolated OU
- **Meaningful names**: `Teenager-Restrictions-Policy` not `GPO1`
- **Documentation**: Every GPO must have purpose documented
- **Modular approach**: Separate GPOs for different functions
- **Version tracking**: Document all GPO changes
- **Error handling**: All scripts must handle failures gracefully
- **Rollback ready**: Every deployment needs rollback procedure

## Implementation Standards

### Our deployment is complete when:
- ✅ All validation scripts pass
- ✅ Test deployment successful  
- ✅ Documentation updated
- ✅ Rollback procedure tested
- ✅ Monitoring configured
- ✅ Change logged in AD

### Testing Strategy
- Complex policies → Test in lab first
- Security policies → Test with limited scope
- User policies → Pilot group testing
- Computer policies → Test on non-critical systems
- Always have rollback GPO ready

### GPO Structure Best Practices
```
/Policies/
  /Security/          # Security settings
  /Users/            # User configurations  
  /Computers/        # Computer settings
  /Applications/     # Software policies
  
/Scripts/
  /Deployment/       # Deployment automation
  /Validation/       # Testing scripts
  /Maintenance/      # Ongoing management
  
/Documentation/
  /Policies/         # GPO documentation
  /Procedures/       # Operational procedures
  /Changes/          # Change history
```

## Problem-Solving Together

When facing GP challenges:
1. **Stop** - Don't create overly complex policies
2. **Research** - Check for existing solutions/conflicts
3. **Delegate** - Use agents for parallel investigation
4. **Analyze** - Consider security and user impact
5. **Simplify** - Simple policies are more maintainable
6. **Ask** - "I see two approaches: [A] vs [B]. Which aligns with our security requirements?"

My insights on better approaches are valued - please ask for them!

## Security & Compliance

### **Security First**:
- Validate all policy settings against security baselines
- Use Security Compliance Toolkit
- Regular security audits
- Principle of least privilege
- Defense in depth

### **Compliance Always**:
- Document all changes
- Maintain audit trail
- Follow change management
- Regular compliance scans
- Keep rollback procedures current

## Communication Protocol

### Progress Updates:
```
✅ Created AppLocker policy (validated)
✅ Tested with pilot group  
❌ Found conflict with existing software policy - investigating
🔄 Rolling back to previous version
```

### Suggesting Improvements:
"The current browser restrictions work, but I notice [security concern].
Would you like me to implement [specific hardening]?"

### Deployment Communications:
```
📋 DEPLOYMENT PLAN: Teenager Restrictions
- Target: Teenagers OU (15 users)
- Policies: AppLocker + Browser restrictions  
- Test Status: ✅ Passed in lab
- Rollback: Ready (GPO-Backup-20240706)
- Schedule: Today 14:00 PST
```

## PowerShell Best Practices

### Script Standards:
```powershell
#Requires -RunAsAdministrator
#Requires -Modules ActiveDirectory, GroupPolicy

[CmdletBinding()]
param(
    # Always use parameter validation
    [ValidateNotNullOrEmpty()]
    [string]$DomainName = "scottify.io"
)

# Always use try-catch for AD operations
try {
    # Operations here
} catch {
    Write-Error "Failed: $_"
    # Always provide rollback
}
```

### Never Do:
```powershell
# ❌ NEVER hardcode credentials
$password = "Password123"

# ❌ NEVER skip error handling  
Get-ADUser "testuser" # Might not exist

# ❌ NEVER use non-descriptive variables
$g = Get-GPO -All # What is 'g'?

# ❌ NEVER modify production without backup
Remove-GPO -Name "Important-Policy" # No backup!
```

## Working Together

- Always work in test environments first
- Document every decision and change
- When in doubt, we choose security over convenience
- **REMINDER**: If this file hasn't been referenced in 30+ minutes, RE-READ IT!

Remember: Group Policy affects all users in its scope. One misconfiguration can impact hundreds of users. Always validate, test, and have rollback procedures ready.