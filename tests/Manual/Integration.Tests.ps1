#Requires -RunAsAdministrator
#Requires -Version 7.0

<#
.SYNOPSIS
    Manual Integration Test for AutoSecure-VPN.
    This script is intended for manual testing only and is NOT used by CI/CD because there is no possibility for remote execution.
    
.DESCRIPTION
    Tests local to remote connectivity and full VPN orchestration flows.
#>

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent (Split-Path -Parent $ScriptDir)

# Import module
$ManifestPath = Join-Path $ProjectRoot "src\module\AutoSecure-VPN.psd1"
if (Test-Path $ManifestPath) {
    Import-Module $ManifestPath -Force
}
else {
    Write-Error "Could not find AutoSecure-VPN module at $ManifestPath"
    return
}

# Get module settings
$moduleInfo = Get-Module AutoSecure-VPN
if ($moduleInfo) {
    Write-Host "Module loaded successfully: $($moduleInfo.Name) v$($moduleInfo.Version)" -ForegroundColor Green
} else {
    Write-Error "Module not loaded properly"
    return
}

# Set base path for scripts
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
    param(
        [string]$RemoteIP
    )
    
    if (-not $RemoteIP) {
        if ($Script:Settings -and $Script:Settings['serverIP']) {
            $RemoteIP = $Script:Settings['serverIP']
        }
        
        if (-not $RemoteIP -or $RemoteIP -eq 'your.server.ip.here') {
            $RemoteIP = Read-Host "Enter remote IP for testing"
        }
    }
    
    Write-Host "`n[*] Testing Ping to $RemoteIP..." -ForegroundColor Cyan
    if (Test-Connection -ComputerName $RemoteIP -Count 1 -Quiet -ErrorAction SilentlyContinue) {
        Write-Host "  ✓ Ping successful" -ForegroundColor Green
    }
    else {
        Write-Host "  ✗ Ping failed" -ForegroundColor Red
    }
    
    Write-Host "[*] Testing WinRM to $RemoteIP..." -ForegroundColor Cyan
    try {
        $null = Test-WSMan -ComputerName $RemoteIP -ErrorAction Stop
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
    
    try {
        Invoke-RemoteOpenVPNServerSetup
        Write-Host "`n[*] Remote Server Setup finished. Press Enter to start Local Client Setup..." -ForegroundColor Cyan
        Pause
        Invoke-OpenVPNClientSetup
        Write-Host "`n[✓] OpenVPN Combo completed successfully!" -ForegroundColor Green
    }
    catch {
        Write-Host "`n[✗] OpenVPN Combo failed: $_" -ForegroundColor Red
    }
}

function Invoke-WireGuardCombo {
    Write-Host "`n[*] Starting WireGuard Combo: Remote Server + Local Client..." -ForegroundColor Magenta
    
    try {
        Invoke-RemoteWireGuardServerSetup
        Write-Host "`n[*] Remote Server Setup finished. Press Enter to start Local Client Setup..." -ForegroundColor Cyan
        Pause
        Invoke-WireGuardClientSetup
        Write-Host "`n[✓] WireGuard Combo completed successfully!" -ForegroundColor Green
    }
    catch {
        Write-Host "`n[✗] WireGuard Combo failed: $_" -ForegroundColor Red
    }
}

# Main Loop
if ($MyInvocation.InvocationName -ne '.') {
    Write-Host "`nStarting AutoSecure-VPN Manual Integration Tests..." -ForegroundColor Cyan
    Write-Host "Note: This script requires Administrator privileges and remote access." -ForegroundColor Yellow
    Write-Host ""

    do {
        $choice = Show-TestMenu
        
        switch ($choice) {
            '1' { Test-RemoteConnectivity }
            '2' { 
                Write-Host "`n[*] Starting Remote OpenVPN Server Setup..." -ForegroundColor Cyan
                Invoke-RemoteOpenVPNServerSetup
                Pause
            }
            '3' { 
                Write-Host "`n[*] Starting Remote OpenVPN Client Setup..." -ForegroundColor Cyan
                Invoke-RemoteOpenVPNClientSetup
                Pause
            }
            '4' { 
                Write-Host "`n[*] Starting Remote WireGuard Server Setup..." -ForegroundColor Cyan
                Invoke-RemoteWireGuardServerSetup
                Pause
            }
            '5' { 
                Write-Host "`n[*] Starting Remote WireGuard Client Setup..." -ForegroundColor Cyan
                Invoke-RemoteWireGuardClientSetup
                Pause
            }
            '6' { 
                Write-Host "`n[*] Testing VPN Connection..." -ForegroundColor Cyan
                # Test-VPNConnection
                Write-Host "VPN Connection test - Implementation needed" -ForegroundColor Yellow
                Pause
            }
            '7' { Invoke-OpenVPNCombo }
            '8' { Invoke-WireGuardCombo }
            'q' { 
                Write-Host "`nExiting Manual Integration Tests. Goodbye!" -ForegroundColor Cyan
                break 
            }
            'Q' { 
                Write-Host "`nExiting Manual Integration Tests. Goodbye!" -ForegroundColor Cyan
                break 
            }
            default {
                Write-Host "`nInvalid option. Please try again." -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }
    } while ($true)
} else {
    Write-Host "Integration test functions loaded. Call Show-TestMenu to start." -ForegroundColor Green
}
