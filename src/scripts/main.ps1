<#
.SYNOPSIS
    Automatische OpenVPN Server en Client Setup voor Windows
    
.DESCRIPTION
    Dit script installeert en configureert automatisch OpenVPN voor zowel server als client setup.
    Het biedt volledige automatisering van certificaatgeneratie, firewall-configuratie en VPN-verbinding.
    
.NOTES
    Vereist: PowerShell 7.0, Administrator rechten
#>

#Requires -RunAsAdministrator
#Requires -Version 7.0

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
    Write-Host "FOUT: Kan module AutoSecureVPN niet laden. $_" -ForegroundColor Red
    Read-Host "`nDruk op Enter om af te sluiten"
    exit 1
}

# Dot-source Orchestration Libraries
Get-ChildItem -Path "$PSScriptRoot\*.ps1" -Exclude "main.ps1" | ForEach-Object { . $_.FullName }

# Stel base path in
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
    Write-Host "Kon settings niet laden: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Start het script
Start-VPNSetup

# Het laden van settings en base path gebeurt nu in de module AutoSecureVPN.
# main.ps1 zorgt voor de import en de transcriptie.

# Stop transcript
Stop-Transcript