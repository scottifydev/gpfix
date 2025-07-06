# PowerShell Script Validation Guide

## Overview

This guide explains the validation process for PowerShell scripts in the Group Policy management system and documents the improvements made to catch syntax errors that were previously missed.

## Why PSParser::Tokenize Is Insufficient

The original validation used only `[System.Management.Automation.PSParser]::Tokenize()`, which performs basic tokenization but misses many syntax errors:

- **Tokenization only** - Breaks script into tokens but doesn't validate syntax rules
- **No compilation check** - Doesn't verify the script can actually be compiled
- **Misses here-string issues** - Can't detect improper here-string syntax
- **No AST analysis** - Doesn't build or validate the Abstract Syntax Tree

## Enhanced Validation Approach

The improved `Test-ScriptSyntax` function now performs three levels of validation:

### 1. Basic Tokenization
```powershell
$errors = $null
$tokens = $null
$null = [System.Management.Automation.PSParser]::Tokenize($content, [ref]$errors)
```

### 2. AST Parsing
```powershell
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $FilePath,
    [ref]$null,
    [ref]$parseErrors
)
```

### 3. Script Compilation
```powershell
$scriptBlock = [ScriptBlock]::Create($content)
```

## Common PowerShell Syntax Pitfalls

### 1. Here-String Syntax

**Incorrect:**
```powershell
$html += @"
    <div>Content</div>
"@
```

**Why it fails:** Complex here-string concatenation can confuse Windows PowerShell 5.1

**Correct:**
```powershell
$builder = New-Object System.Text.StringBuilder
[void]$builder.AppendLine(@"
    <div>Content</div>
"@)
```

### 2. Variable References in Strings

**Incorrect:**
```powershell
Write-Host "$computer: Error occurred"
```

**Why it fails:** PowerShell interprets `:` as scope modifier

**Correct:**
```powershell
Write-Host "${computer}: Error occurred"
```

### 3. Unicode Characters

**Problematic:**
```powershell
Write-Host "✓ Success"
Write-Host "✗ Failed"
```

**Why it fails:** Can cause encoding issues on some systems

**Correct:**
```powershell
Write-Host "[OK] Success"
Write-Host "[FAIL] Failed"
```

### 4. Here-String Terminators

**Incorrect:**
```powershell
$text = @"
    Content
"@)  # Mixing terminator with method call
```

**Correct:**
```powershell
$text = @"
    Content
"@
)  # Separate lines
```

## Validation Checks Added

### 1. Here-String Validation
- Checks opener `@"` is at end of line
- Verifies closer `"@` is at start of line
- Detects unclosed here-strings
- Identifies orphaned closers

### 2. Unicode Detection
- Scans for non-ASCII characters
- Reports line numbers
- Suggests ASCII replacements

### 3. Enhanced Syntax Checking
- Full AST parsing
- Script compilation test
- Detailed error reporting with line numbers

## Running Validation

### Basic Validation
```powershell
.\Scripts\Test-CodebaseIntegrity.ps1
```

### Quick Syntax Check Only
```powershell
.\Scripts\Test-CodebaseIntegrity.ps1 -QuickTest
```

### Smart Linting
```powershell
.\hooks\Test-SmartLint.ps1
```

## Best Practices

1. **Always use StringBuilder for HTML generation**
   - More efficient than string concatenation
   - Avoids here-string complexity
   - Better compatibility

2. **Avoid Unicode characters in scripts**
   - Use ASCII equivalents
   - Ensures cross-platform compatibility
   - Prevents encoding issues

3. **Test on Windows PowerShell 5.1**
   - Most restrictive parser
   - What domain controllers typically run
   - Catches compatibility issues

4. **Use proper variable delimiters**
   - `${variable}` when followed by special characters
   - Prevents scope confusion
   - Clear intent

## Validation Requirements

Per CLAUDE.md principles:
- **ALL validation issues are BLOCKING**
- **Zero tolerance for syntax errors**
- **No warnings accepted in production**
- **100% pass rate required**

## Troubleshooting

### Script fails on Windows but passes on Linux
- Check PowerShell version differences
- Look for here-string patterns
- Verify no Unicode characters
- Test with Windows PowerShell 5.1

### Variable reference errors
- Look for `$var:` patterns
- Replace with `${var}:`
- Check string interpolation

### Here-string errors
- Ensure `@"` ends the line
- Ensure `"@` starts the line
- No code between here-string blocks
- Consider StringBuilder instead