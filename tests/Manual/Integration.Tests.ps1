# Requires -RunAsAdministrator
# Requires -Version 7.0

<#
.SYNOPSIS
    Manual Integration Test for AutoSecure-VPN.
    This script is intended for manual testing only and is NOT used by CI/CD.
    
.DESCRIPTION
    Tests local to remote connectivity and full VPN orchestration flows.
#>

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent (Split-Path -Parent $ScriptDir)

# Import module
$ManifestPath = Join-Path $ProjectRoot "src\module\AutoSecureVPN.psd1"
if (Test-Path $ManifestPath) {
    Import-Module $ManifestPath -Force
}
else {
    Write-Error "Could not find AutoSecureVPN module at $ManifestPath"
    return
}

# Dot-source Orchestration Libraries
$OrchestrationPath = Join-Path $ProjectRoot "src\scripts"
Get-ChildItem -Path "$OrchestrationPath\*.ps1" -Exclude "main.ps1" | ForEach-Object { . $_.FullName }

# Set base path for scripts (needed for some orchestration functions)
$Script:BasePath = $ProjectRoot

# Load settings
$Script:Settings = @{}
try {
    $stablePath = Join-Path $ProjectRoot "src\config\Stable.psd1"
    $variablePath = Join-Path $ProjectRoot "src\config\Variable.psd1"
    
    if (Test-Path $stablePath) {
        $stable = Import-PowerShellDataFile -Path $stablePath
        if ($stable) { $Script:Settings = $stable.Clone() }
    }
    
    if (Test-Path $variablePath) {
        $variable = Import-PowerShellDataFile -Path $variablePath
        if ($variable) {
            foreach ($key in $variable.Keys) {
                $Script:Settings[$key] = $variable[$key]
            }
        }
    }
}
catch {
    Write-Warning "Could not load settings: $_"
}

function Show-TestMenu {
    Clear-Host
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "   AutoSecure-VPN Manual Integration Test  " -ForegroundColor Cyan
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "1. Test Connectivity (Ping & WinRM)"
    Write-Host "2. Full Remote OpenVPN Server Setup"
    Write-Host "3. Full Remote OpenVPN Client Setup"
    Write-Host "4. Full Remote WireGuard Server Setup"
    Write-Host "5. Full Remote WireGuard Client Setup"
    Write-Host "6. Running Connectivity Check"
    Write-Host "7. Combo: Remote OpenVPN Server + Local OpenVPN Client"
    Write-Host "8. Combo: Remote WireGuard Server + Local WireGuard Client"
    Write-Host "Q. Quit"
    Write-Host "==========================================" -ForegroundColor Cyan
    
    $choice = Read-Host "Select an option"
    return $choice
}

function Test-RemoteConnectivity {
    $remoteIP = $Script:Settings['serverIP']
    if (-not $remoteIP -or $remoteIP -eq 'your.server.ip.here') {
        $remoteIP = Read-Host "Enter remote IP for testing"
    }
    
    Write-Host "`n[*] Testing Ping to $remoteIP..." -ForegroundColor Cyan
    if (Test-Connection -ComputerName $remoteIP -Count 1 -Quiet) {
        Write-Host "  ✓ Ping successful" -ForegroundColor Green
    }
    else {
        Write-Host "  ✗ Ping failed" -ForegroundColor Red
    }
    
    Write-Host "[*] Testing WinRM to $remoteIP..." -ForegroundColor Cyan
    try {
        Test-WSMan -ComputerName $remoteIP -ErrorAction Stop | Out-Null
        Write-Host "  ✓ WinRM active" -ForegroundColor Green
    }
    catch {
        Write-Host "  ✗ WinRM failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "    Tip: Run 'Enable-PSRemoting -Force' on remote" -ForegroundColor Yellow
    }
    
    Pause
}

function Invoke-OpenVPNCombo {
    Write-Host "`n[*] Starting OpenVPN Combo: Remote Server + Local Client..." -ForegroundColor Magenta
    Invoke-RemoteOpenVPNServerSetup
    Write-Host "`n[*] Remote Server Setup finished. Press Enter to start Local Client Setup..." -ForegroundColor Cyan
    Pause
    Invoke-OpenVPNClientSetup
}

function Invoke-WireGuardCombo {
    Write-Host "`n[*] Starting WireGuard Combo: Remote Server + Local Client..." -ForegroundColor Magenta
    Invoke-RemoteWireGuardServerSetup
    Write-Host "`n[*] Remote Server Setup finished. Press Enter to start Local Client Setup..." -ForegroundColor Cyan
    Pause
    Invoke-WireGuardClientSetup
}

# Main Loop
do {
    $choice = Show-TestMenu
    switch ($choice) {
        '1' { Test-RemoteConnectivity }
        '2' { Invoke-RemoteOpenVPNServerSetup }
        '3' { Invoke-RemoteOpenVPNClientSetup }
        '4' { Invoke-RemoteWireGuardServerSetup }
        '5' { Invoke-RemoteWireGuardClientSetup }
        '6' { Test-VPNConnection }
        '7' { Invoke-OpenVPNCombo }
        '8' { Invoke-WireGuardCombo }
        'q' { break }
    }
} while ($true)
