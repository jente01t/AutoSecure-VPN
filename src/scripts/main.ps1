<#
.SYNOPSIS
    Automatic OpenVPN Server and Client Setup for Windows
    
.DESCRIPTION
    This script automatically installs and configures OpenVPN for both server and client setup.
    It provides full automation of certificate generation, firewall configuration, and VPN connection.
    
.NOTES
    Requires: PowerShell 7.0, Administrator privileges
#>

#Requires -RunAsAdministrator
#Requires -Version 5.1

[CmdletBinding()]
param()

# Import module via manifest 
try {
    $ManifestPath = Join-Path $PSScriptRoot "../module/AutoSecureVPN.psd1"
    if (Test-Path $ManifestPath) {
        Import-Module $ManifestPath -Force
    }
    else {
        # Fallback to psm1 if manifest not found
        $ModulePath = Join-Path $PSScriptRoot "../module/AutoSecureVPN.psm1"
        Import-Module $ModulePath -Force
    }
}
catch {
    Write-Host "ERROR: Could not load AutoSecureVPN module. $_" -ForegroundColor Red
    Read-Host "`nPress Enter to exit"
    exit 1
}

# Dot-source Orchestration Libraries
Get-ChildItem -Path "$PSScriptRoot\*.ps1" -Exclude "main.ps1" | ForEach-Object { . $_.FullName }

# Set base path
$Script:BasePath = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent

# Load settings
$Script:Settings = @{}
try {
    # Load stable settings first
    $stableConfigPath = Join-Path $PSScriptRoot '..\config\Stable.psd1'
    if (Test-Path $stableConfigPath) {
        $stableSettings = Import-PowerShellDataFile -Path $stableConfigPath -ErrorAction Stop
        if ($stableSettings) { $Script:Settings = $stableSettings.Clone() }
    }
    
    # Load variable settings and merge (variable overrides stable)
    $variableConfigPath = Join-Path $PSScriptRoot '..\config\Variable.psd1'
    if (Test-Path $variableConfigPath) {
        $variableSettings = Import-PowerShellDataFile -Path $variableConfigPath -ErrorAction Stop
        if ($variableSettings) {
            foreach ($key in $variableSettings.Keys) {
                $Script:Settings[$key] = $variableSettings[$key]
            }
        }
    }
}
catch {
    Write-Host "Could not load settings: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Start the script
Start-VPNSetup

# Loading settings and base path is now handled in the AutoSecureVPN module.
# main.ps1 handles import and transcription.

# Stop transcript
Stop-Transcript