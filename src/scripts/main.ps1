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

function Invoke-ServerSetup {
    <#
    .SYNOPSIS
        Voert volledige VPN-server setup uit
    #>
    
    Write-Log "=== Server Setup Gestart ===" -Level "INFO"
    
    try {
        # Stap 1: Administrator check
        Write-Host "`n[1/8] Controleren administrator rechten..." -ForegroundColor Cyan
        if (-not (Test-AdminRights)) {
            throw "Script moet als Administrator worden uitgevoerd!"
        }
        Write-Host "  ✓ Administrator rechten bevestigd" -ForegroundColor Green
        
        # Stap 2: OpenVPN installeren
        Write-Host "`n[2/8] OpenVPN installeren..." -ForegroundColor Cyan
        if (-not (Install-OpenVPN)) {
            throw "OpenVPN installatie mislukt"
        }
        Write-Host "  ✓ OpenVPN geïnstalleerd" -ForegroundColor Green
        
        # Stap 3: Firewall configureren
        Write-Host "`n[3/8] Windows Firewall configureren..." -ForegroundColor Cyan
        if (-not (Configure-Firewall -Port 443 -Protocol "TCP")) {
            throw "Firewall configuratie mislukt"
        }
        Write-Host "  ✓ Firewall regels toegevoegd" -ForegroundColor Green
        
        # Stap 4: Gebruikersinput verzamelen
        Write-Host "`n[4/8] Server configuratie parameters..." -ForegroundColor Cyan
        $serverConfig = Get-ServerConfiguration
        
        # Stap 5: EasyRSA en certificaten
        Write-Host "`n[5/8] Certificaten genereren (dit kan even duren)..." -ForegroundColor Cyan
        if (-not (Initialize-EasyRSA -EasyRSAPath $script:EasyRSAPath)) {
            throw "EasyRSA initialisatie mislukt"
        }
        if (-not (Initialize-Certificates -ServerName $serverConfig.ServerName -Password $serverConfig.Password -EasyRSAPath $script:EasyRSAPath)) {
            throw "Certificaat generatie mislukt"
        }
        Write-Host "  ✓ Certificaten gegenereerd" -ForegroundColor Green
        
        # Stap 6: Server configuratie genereren
        Write-Host "`n[6/8] Server configuratie aanmaken..." -ForegroundColor Cyan
        if (-not (Generate-ServerConfig -Config $serverConfig -EasyRSAPath $script:EasyRSAPath -ConfigPath $script:ConfigPath)) {
            throw "Server configuratie generatie mislukt"
        }
        Write-Host "  ✓ Server configuratie aangemaakt" -ForegroundColor Green
        
        # Stap 7: OpenVPN service starten
        Write-Host "`n[7/8] OpenVPN service starten..." -ForegroundColor Cyan
        if (-not (Start-VPNService)) {
            throw "OpenVPN service starten mislukt"
        }
        Write-Host "  ✓ OpenVPN service actief" -ForegroundColor Green
        
        # Stap 8: Client package maken
        Write-Host "`n[8/8] Client configuratie package maken..." -ForegroundColor Cyan
        $zipPath = New-ClientPackage -Config $serverConfig -EasyRSAPath $script:EasyRSAPath -OutputPath (Join-Path $PSScriptRoot "..\output")
        if (-not $zipPath) {
            throw "Client package aanmaken mislukt"
        }
        Write-Host "  ✓ Client package aangemaakt: $zipPath" -ForegroundColor Green
        
        Write-Host "`n╔════════════════════════════════════════════╗" -ForegroundColor Green
        Write-Host "║     Server Setup Succesvol Voltooid!      ║" -ForegroundColor Green
        Write-Host "╚════════════════════════════════════════════╝" -ForegroundColor Green
        Write-Host "`nLogbestand: $script:LogFile" -ForegroundColor Yellow
        Write-Host "Client package: $zipPath" -ForegroundColor Yellow
        Write-Host "`nDit ZIP-bestand naar de client overzetten om de verbinding te maken." -ForegroundColor Cyan
        
        Write-Log "Server setup succesvol voltooid" -Level "SUCCESS"
    }
    catch {
        Write-Host "`n[!] FOUT tijdens server setup: $_" -ForegroundColor Red
        Write-Log "Server setup FOUT: $_" -Level "ERROR"
        Write-Host "`nControleer het logbestand voor details: $script:LogFile" -ForegroundColor Yellow
    }
}


# Start het script
Start-VPNSetup
