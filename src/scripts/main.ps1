<#
.SYNOPSIS
    Automatische OpenVPN Server en Client Setup voor Windows
    
.DESCRIPTION
    Dit script installeert en configureert automatisch OpenVPN voor zowel server als client setup.
    Het biedt volledige automatisering van certificaatgeneratie, firewall-configuratie en VPN-verbinding.
    
.NOTES
    Auteur: VPN-AutoSetup Project
    Datum: 31 oktober 2025
    Versie: 1.0
    Vereist: PowerShell 5.1+, Administrator rechten
#>

# Requires -RunAsAdministrator

# Import module
try {
	$ModulePath = Join-Path $PSScriptRoot "../module/AutoSecureVPN.psm1"
	Import-Module $ModulePath -Force
}
catch {
	Write-Host "FOUT: Kan module AutoSecureVPN niet laden. $_" -ForegroundColor Red
	exit 1
}


# Globale variabelen
$logsPath = Join-Path $PSScriptRoot "..\logs"
if (-not (Test-Path $logsPath)) {
    New-Item -ItemType Directory -Path $logsPath -Force
}
$script:LogFile = Join-Path $logsPath "vpn-setup.log"
$script:ConfigPath = Join-Path $env:ProgramFiles "OpenVPN\config"
$script:EasyRSAPath = Join-Path $env:ProgramFiles "OpenVPN\easy-rsa"

# Hoofdfunctie
function Start-VPNSetup {
    <#
    .SYNOPSIS
        Hoofdmenu voor VPN setup keuze
    #>
    
    # Write-Log "=== OpenVPN Automatische Setup Gestart ===" -Level "INFO"
    Write-Host "`n╔════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║   OpenVPN Automatische Setup v1.0         ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Kies een optie:" -ForegroundColor Yellow
    Write-Host "  [1] Server Setup (VPN-server installeren en configureren)" -ForegroundColor Green
    Write-Host "  [2] Client Setup (VPN-client installeren en verbinden)" -ForegroundColor Green
    Write-Host "  [3] Afsluiten" -ForegroundColor Red
    Write-Host ""
    
    $choice = Read-Host "Voer uw keuze in (1-3)"
    
    switch ($choice) {
        "1" {
            Write-Host "`n[*] Server Setup geselecteerd..." -ForegroundColor Cyan
            Invoke-ServerSetup
        }
        "2" {
            Write-Host "`n[*] Client Setup geselecteerd..." -ForegroundColor Cyan
            Invoke-ClientSetup
        }
        "3" {
            Write-Host "`n[*] Setup wordt afgesloten..." -ForegroundColor Yellow
            Write-Log "Setup afgesloten door gebruiker" -Level "INFO"
            exit 0
        }
        default {
            Write-Host "`n[!] Ongeldige keuze. Probeer opnieuw." -ForegroundColor Red
            Start-Sleep -Seconds 2
            Start-VPNSetup
        }
    }
}

