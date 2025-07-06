# Update-RegToGPO.ps1
# Converts registry format policy files to proper GPO format
# Author: Group Policy Administrator
# Date: 2025-07-06

param(
    [Parameter(Mandatory=$true)]
    [string]$InputFile,
    
    [Parameter(Mandatory=$true)]
    [string]$OutputFile,
    
    [Parameter(Mandatory=$false)]
    [string]$DomainPattern = "*@domain.com"
)

function Convert-RegToGPO {
    param(
        [string]$RegistryContent,
        [string]$DomainPattern
    )
    
    # Initialize GPO policy structure
    $gpoPolicy = @{
        'Computer Configuration' = @{
            'Policies' = @{
                'Administrative Templates' = @{}
                'Windows Settings' = @{
                    'Security Settings' = @{
                        'Application Control Policies' = @{}
                    }
                }
            }
        }
        'User Configuration' = @{
            'Policies' = @{
                'Administrative Templates' = @{}
            }
        }
    }
    
    # Parse registry content
    $lines = $RegistryContent -split "`r?`n"
    $currentKey = ""
    
    foreach ($line in $lines) {
        $line = $line.Trim()
        
        # Skip empty lines and comments
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith(";")) {
            continue
        }
        
        # Process registry key
        if ($line -match '^\[(.+)\]$') {
            $currentKey = $matches[1]
            continue
        }
        
        # Process registry values
        if ($line -match '^"([^"]+)"=(.+)$') {
            $valueName = $matches[1]
            $valueData = $matches[2]
            
            # Convert based on key path
            switch -Regex ($currentKey) {
                'SOFTWARE\\Policies\\Google\\Chrome$' {
                    $chromePolicies = @{
                        'BrowserSignin' = @{
                            Name = 'GP_Browser sign-in settings'
                            Type = 'DWORD'
                            Path = 'Computer Configuration\Policies\Administrative Templates\Google\Google Chrome'
                        }
                        'RestrictSigninToPattern' = @{
                            Name = 'GP_Restrict sign-in to pattern'
                            Type = 'STRING'
                            Path = 'Computer Configuration\Policies\Administrative Templates\Google\Google Chrome'
                        }
                        'IncognitoModeAvailability' = @{
                            Name = 'GP_Incognito mode availability'
                            Type = 'DWORD'
                            Path = 'Computer Configuration\Policies\Administrative Templates\Google\Google Chrome'
                        }
                        'ForceSafeSearch' = @{
                            Name = 'GP_Force SafeSearch'
                            Type = 'DWORD'
                            Path = 'Computer Configuration\Policies\Administrative Templates\Google\Google Chrome\Safe Browsing settings'
                        }
                        'ForceGoogleSafeSearch' = @{
                            Name = 'GP_Force Google SafeSearch'
                            Type = 'DWORD'
                            Path = 'Computer Configuration\Policies\Administrative Templates\Google\Google Chrome\Safe Browsing settings'
                        }
                        'ForceYouTubeRestrict' = @{
                            Name = 'GP_Force YouTube Restricted Mode'
                            Type = 'DWORD'
                            Path = 'Computer Configuration\Policies\Administrative Templates\Google\Google Chrome\Content settings'
                        }
                        'DeveloperToolsDisabled' = @{
                            Name = 'GP_Disable Developer Tools'
                            Type = 'DWORD'
                            Path = 'Computer Configuration\Policies\Administrative Templates\Google\Google Chrome'
                        }
                        'PasswordManagerEnabled' = @{
                            Name = 'GP_Enable password manager'
                            Type = 'DWORD'
                            Path = 'Computer Configuration\Policies\Administrative Templates\Google\Google Chrome\Password manager'
                        }
                        'SyncDisabled' = @{
                            Name = 'GP_Disable synchronization'
                            Type = 'DWORD'
                            Path = 'Computer Configuration\Policies\Administrative Templates\Google\Google Chrome'
                        }
                    }
                    
                    if ($chromePolicies.ContainsKey($valueName)) {
                        $policy = $chromePolicies[$valueName]
                        
                        # Replace hardcoded domain with parameter
                        if ($valueName -eq 'RestrictSigninToPattern' -and $valueData -match '"(.+)"') {
                            $valueData = "`"$DomainPattern`""
                        }
                        
                        # Add to GPO structure
                        $pathParts = $policy.Path -split '\\'
                        $current = $gpoPolicy
                        foreach ($part in $pathParts) {
                            if (-not $current.ContainsKey($part)) {
                                $current[$part] = @{}
                            }
                            $current = $current[$part]
                        }
                        
                        $current[$policy.Name] = @{
                            'Value' = $valueData
                            'Type' = $policy.Type
                            'State' = 'Enabled'
                        }
                    }
                }
                
                'SOFTWARE\\Policies\\Google\\Chrome\\URLBlocklist$' {
                    # Handle URL blocklist
                    if ($valueData -match '"(.+)"') {
                        $url = $matches[1]
                        $blocklistPath = 'Computer Configuration\Policies\Administrative Templates\Google\Google Chrome\Block access to a list of URLs'
                        
                        $pathParts = $blocklistPath -split '\\'
                        $current = $gpoPolicy
                        foreach ($part in $pathParts[0..($pathParts.Length-2)]) {
                            if (-not $current.ContainsKey($part)) {
                                $current[$part] = @{}
                            }
                            $current = $current[$part]
                        }
                        
                        if (-not $current.ContainsKey('URL Blocklist')) {
                            $current['URL Blocklist'] = @{
                                'Value' = @()
                                'Type' = 'LIST'
                                'State' = 'Enabled'
                            }
                        }
                        
                        $current['URL Blocklist']['Value'] += $url
                    }
                }
                
                'SOFTWARE\\Policies\\Microsoft\\Edge$' {
                    # Handle Edge policies
                    $edgePath = 'Computer Configuration\Policies\Administrative Templates\Microsoft Edge'
                    $pathParts = $edgePath -split '\\'
                    $current = $gpoPolicy
                    foreach ($part in $pathParts) {
                        if (-not $current.ContainsKey($part)) {
                            $current[$part] = @{}
                        }
                        $current = $current[$part]
                    }
                    
                    $current['GP_Microsoft Edge enabled'] = @{
                        'Value' = $valueData
                        'Type' = 'DWORD'
                        'State' = 'Disabled'
                    }
                }
                
                'SOFTWARE\\Policies\\Microsoft\\Windows\\System$' {
                    # Handle system policies
                    if ($valueName -eq 'DisableCMD') {
                        $cmdPath = 'User Configuration\Policies\Administrative Templates\System'
                        $pathParts = $cmdPath -split '\\'
                        $current = $gpoPolicy
                        foreach ($part in $pathParts) {
                            if (-not $current.ContainsKey($part)) {
                                $current[$part] = @{}
                            }
                            $current = $current[$part]
                        }
                        
                        $current['GP_Prevent access to the command prompt'] = @{
                            'Value' = $valueData
                            'Type' = 'DWORD'
                            'State' = 'Enabled'
                        }
                    }
                }
                
                'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System$' {
                    # Handle user system policies
                    $systemPolicies = @{
                        'DisableRegistryTools' = 'GP_Prevent access to registry editing tools'
                        'DisableTaskMgr' = 'GP_Remove Task Manager'
                    }
                    
                    if ($systemPolicies.ContainsKey($valueName)) {
                        $sysPath = 'User Configuration\Policies\Administrative Templates\System'
                        $pathParts = $sysPath -split '\\'
                        $current = $gpoPolicy
                        foreach ($part in $pathParts) {
                            if (-not $current.ContainsKey($part)) {
                                $current[$part] = @{}
                            }
                            $current = $current[$part]
                        }
                        
                        $current[$systemPolicies[$valueName]] = @{
                            'Value' = $valueData
                            'Type' = 'DWORD'
                            'State' = 'Enabled'
                        }
                    }
                }
            }
        }
    }
    
    return $gpoPolicy
}

function Export-GPOToXML {
    param(
        [hashtable]$GPOPolicy,
        [string]$OutputFile
    )
    
    $xml = New-Object System.Xml.XmlDocument
    $xmlDeclaration = $xml.CreateXmlDeclaration("1.0", "UTF-8", $null)
    $xml.AppendChild($xmlDeclaration) | Out-Null
    
    $root = $xml.CreateElement("GroupPolicy")
    $root.SetAttribute("xmlns", "http://www.microsoft.com/GroupPolicy/Settings")
    $root.SetAttribute("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
    $root.SetAttribute("xmlns:xsd", "http://www.w3.org/2001/XMLSchema")
    $xml.AppendChild($root) | Out-Null
    
    function Add-PolicyNode {
        param(
            [System.Xml.XmlElement]$Parent,
            [hashtable]$Policies,
            [string]$Path
        )
        
        foreach ($key in $Policies.Keys) {
            $value = $Policies[$key]
            
            if ($value -is [hashtable]) {
                if ($value.ContainsKey('Value') -and $value.ContainsKey('Type')) {
                    # This is a policy setting
                    $policyNode = $Parent.OwnerDocument.CreateElement("Policy")
                    $policyNode.SetAttribute("name", $key)
                    $policyNode.SetAttribute("path", $Path)
                    $policyNode.SetAttribute("state", $value.State)
                    
                    $valueNode = $Parent.OwnerDocument.CreateElement("Value")
                    
                    if ($value.Type -eq 'LIST' -and $value.Value -is [array]) {
                        foreach ($item in $value.Value) {
                            $itemNode = $Parent.OwnerDocument.CreateElement("Item")
                            $itemNode.InnerText = $item
                            $valueNode.AppendChild($itemNode) | Out-Null
                        }
                    } else {
                        $valueNode.InnerText = $value.Value -replace '^"|"$|dword:', ''
                    }
                    
                    $policyNode.AppendChild($valueNode) | Out-Null
                    $Parent.AppendChild($policyNode) | Out-Null
                } else {
                    # This is a container
                    $containerNode = $Parent.OwnerDocument.CreateElement("Container")
                    $containerNode.SetAttribute("name", $key)
                    $Parent.AppendChild($containerNode) | Out-Null
                    
                    $newPath = if ($Path) { "$Path\$key" } else { $key }
                    Add-PolicyNode -Parent $containerNode -Policies $value -Path $newPath
                }
            }
        }
    }
    
    Add-PolicyNode -Parent $root -Policies $GPOPolicy -Path ""
    
    $xml.Save($OutputFile)
}

# Main execution
try {
    if (-not (Test-Path $InputFile)) {
        throw "Input file not found: $InputFile"
    }
    
    Write-Host "Reading registry file: $InputFile"
    $regContent = Get-Content $InputFile -Raw
    
    Write-Host "Converting to GPO format..."
    $gpoPolicy = Convert-RegToGPO -RegistryContent $regContent -DomainPattern $DomainPattern
    
    Write-Host "Exporting to XML: $OutputFile"
    Export-GPOToXML -GPOPolicy $gpoPolicy -OutputFile $OutputFile
    
    Write-Host "Conversion completed successfully!"
    Write-Host "Domain pattern used: $DomainPattern"
    
    # Also create a summary report
    $summaryFile = [System.IO.Path]::ChangeExtension($OutputFile, ".summary.txt")
    $summary = @"
GPO Conversion Summary
=====================
Source File: $InputFile
Output File: $OutputFile
Domain Pattern: $DomainPattern
Conversion Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

Policies Converted:
- GP_Chrome browser restrictions
- GP_URL blocklist
- GP_Microsoft Edge restrictions
- GP_System policies (Command Prompt, Registry, Task Manager)
- GP_Security settings

Note: The hardcoded domain 'scottify.io' has been replaced with the configurable domain pattern.
"@
    
    $summary | Out-File -FilePath $summaryFile -Encoding UTF8
    Write-Host "Summary saved to: $summaryFile"
    
} catch {
    Write-Error "Error during conversion: $_"
    exit 1
}