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

# Load settings
$Script:Settings = @{}
try {
    $configPath = Join-Path $PSScriptRoot '..\config\Settings.psd1'
    if (Test-Path $configPath) {
        $loaded = Import-PowerShellDataFile -Path $configPath -ErrorAction Stop
        if ($loaded) { $Script:Settings = $loaded }
    }
}
catch {
    Write-Host "Kon settings niet laden: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Globale variabelen
$logsPath = Join-Path $PSScriptRoot "..\$($Script:Settings.logsPath)"
if (-not (Test-Path $logsPath)) {
    New-Item -ItemType Directory -Path $logsPath -Force
}
$script:LogFile = Join-Path $logsPath $Script:Settings.logFileName
$script:ConfigPath = $Script:Settings.configPath
$script:EasyRSAPath = $Script:Settings.easyRSAPath

# Hoofdfunctie
function Start-VPNSetup {
    <#
    .SYNOPSIS
        Toont het hoofdmenu voor VPN setup keuze.

    .DESCRIPTION
        Deze functie toont een menu met opties voor server setup, client setup (lokaal of remote), en afsluiten.

    .EXAMPLE
        Start-VPNSetup
    #>
    
    Write-Log "=== OpenVPN Automatische Setup Gestart ===" -Level "INFO"
    Write-Host "`n╔════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║   OpenVPN Automatische Setup v1.0         ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Kies een optie:" -ForegroundColor Yellow
    Write-Host "  [1] Server Setup (VPN-server installeren en configureren)" -ForegroundColor Green
    Write-Host "  [2] Client Setup (Lokaal - VPN-client installeren en verbinden)" -ForegroundColor Green
    Write-Host "  [3] Client Setup (Remote - VPN-client op afstand installeren)" -ForegroundColor Green
    Write-Host "  [4] Server Setup (Remote - VPN-server op afstand installeren)" -ForegroundColor Green
    Write-Host "  [5] Afsluiten" -ForegroundColor Red
    Write-Host ""
    
    $choice = Read-Host "Voer uw keuze in (1-5)"
    
    switch ($choice) {
        "1" {
            Write-Host "`n[*] Server Setup geselecteerd..." -ForegroundColor Cyan
            Invoke-ServerSetup
        }
        "2" {
            Write-Host "`n[*] Client Setup (Lokaal) geselecteerd..." -ForegroundColor Cyan
            Invoke-ClientSetup
        }
        "3" {
            Write-Host "`n[*] Client Setup (Remote) geselecteerd..." -ForegroundColor Cyan
            Invoke-RemoteClientSetup
        }
        "4" {
            Write-Host "`n[*] Server Setup (Remote) geselecteerd..." -ForegroundColor Cyan
            Invoke-RemoteServerSetup
        }
        "5" {
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
        Voert volledige VPN-server setup uit.

    .DESCRIPTION
        Deze functie voert alle stappen uit voor het opzetten van een OpenVPN server, inclusief installatie, certificaten, configuratie en service start.

    .EXAMPLE
        Invoke-ServerSetup
    #>
    
    Write-Log "=== Server Setup Gestart ===" -Level "INFO"
    
    try {
        # Stap 1: Administrator check
        Write-Host "`n[1/8] Controleren administrator rechten..." -ForegroundColor Cyan
        if (-not (Test-IsAdmin)) {
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
        if (-not (Set-Firewall -Port 443 -Protocol "TCP")) {
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
        if (-not (New-ServerConfig -Config $serverConfig -EasyRSAPath $script:EasyRSAPath -ConfigPath $script:ConfigPath)) {
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

function Invoke-ClientSetup {
    <#
    .SYNOPSIS
        Voert volledige VPN-client setup uit.

    .DESCRIPTION
        Deze functie voert alle stappen uit voor het opzetten van een OpenVPN client, inclusief installatie, configuratie importeren en verbinding starten.

    .EXAMPLE
        Invoke-ClientSetup
    #>
    
    Write-Log "=== Client Setup Gestart ===" -Level "INFO"
    
    try {
        # Stap 1: Administrator check
        Write-Host "`n[1/6] Controleren administrator rechten..." -ForegroundColor Cyan
        if (-not (Test-IsAdmin)) {
            throw "Script moet als Administrator worden uitgevoerd!"
        }
        Write-Host "  ✓ Administrator rechten bevestigd" -ForegroundColor Green
        
        # Stap 2: OpenVPN installeren
        Write-Host "`n[2/6] OpenVPN installeren..." -ForegroundColor Cyan
        if (-not (Install-OpenVPN)) {
            throw "OpenVPN installatie mislukt"
        }
        Write-Host "  ✓ OpenVPN geïnstalleerd" -ForegroundColor Green
        
        # Stap 3: Client configuratie importeren
        Write-Host "`n[3/6] Client configuratie importeren..." -ForegroundColor Cyan
        $configPath = Import-ClientConfiguration
        if (-not $configPath) {
            throw "Client configuratie importeren mislukt"
        }
        Write-Host "  ✓ Configuratie geïmporteerd" -ForegroundColor Green
        
        # Stap 4: TAP adapter controleren
        Write-Host "`n[4/6] TAP adapter controleren..." -ForegroundColor Cyan
        if (-not (Test-TAPAdapter)) {
            Write-Host "  ! TAP adapter niet gevonden, OpenVPN moet mogelijk opnieuw worden geïnstalleerd" -ForegroundColor Yellow
            Write-Log "TAP adapter niet gevonden" -Level "WARNING"
        }
        else {
            Write-Host "  ✓ TAP adapter gevonden" -ForegroundColor Green
        }
        
        # Stap 5: VPN verbinding starten
        Write-Host "`n[5/6] VPN verbinding starten..." -ForegroundColor Cyan
        if (-not (Start-VPNConnection -ConfigFile $configPath)) {
            throw "VPN verbinding starten mislukt"
        }
        Write-Host "  ✓ VPN verbinding gestart" -ForegroundColor Green
        
        # Stap 6: Verbinding testen
        Write-Host "`n[6/6] VPN verbinding testen..." -ForegroundColor Cyan
        Start-Sleep -Seconds 5  # Wacht tot verbinding is opgezet
        Test-VPNConnection
        
        Write-Host "`n╔════════════════════════════════════════════╗" -ForegroundColor Green
        Write-Host "║     Client Setup Succesvol Voltooid!      ║" -ForegroundColor Green
        Write-Host "╚════════════════════════════════════════════╝" -ForegroundColor Green
        Write-Host "`nLogbestand: $script:LogFile" -ForegroundColor Yellow
        
        Write-Log "Client setup succesvol voltooid" -Level "SUCCESS"
    }
    catch {
        Write-Host "`n[!] FOUT tijdens client setup: $_" -ForegroundColor Red
        Write-Log "Client setup FOUT: $_" -Level "ERROR"
        Write-Host "`nControleer het logbestand voor details: $script:LogFile" -ForegroundColor Yellow
    }
}

function Invoke-RemoteClientSetup {
    <#
    .SYNOPSIS
        Voert remote VPN-client setup uit.

    .DESCRIPTION
        Deze functie voert setup uit voor een VPN client op een remote machine via PowerShell remoting.

    .EXAMPLE
        Invoke-RemoteClientSetup
    #>
    
    Write-Log "=== Remote Client Setup Gestart ===" -Level "INFO"
    
    try {
        # Stap 1: Administrator check (voor lokale machine)
        Write-Host "`n[1/4] Controleren administrator rechten..." -ForegroundColor Cyan
        if (-not (Test-IsAdmin)) {
            throw "Script moet als Administrator worden uitgevoerd!"
        }
        Write-Host "  ✓ Administrator rechten bevestigd" -ForegroundColor Green
        
        # Stap 2: Remote computer details
        Write-Host "`n[2/5] Remote computer configuratie..." -ForegroundColor Cyan
        $computerName = Read-Host "  Voer de naam of IP van de remote computer in"
        if ([string]::IsNullOrWhiteSpace($computerName)) {
            throw "Remote computer naam is verplicht"
        }
        Write-Host "  ✓ Remote computer: $computerName" -ForegroundColor Green
        
        # Stap 3: WinRM configuratie
        Write-Host "`n[3/5] WinRM configuratie controleren..." -ForegroundColor Cyan
        try {
            $trustedHosts = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Client -Name TrustedHosts -ErrorAction Stop).TrustedHosts
        } catch {
            $trustedHosts = ""
        }
        if ($trustedHosts -notlike "*$computerName*" -and $trustedHosts -ne "*") {
            Write-Host "  Remote computer niet in TrustedHosts. Toevoegen..." -ForegroundColor Yellow
            $newTrustedHosts = if ($trustedHosts) { "$trustedHosts,$computerName" } else { $computerName }
            Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Client -Name TrustedHosts -Value $newTrustedHosts
            Restart-Service winrm -Force
            Write-Host "  ✓ $computerName toegevoegd aan TrustedHosts en WinRM herstart" -ForegroundColor Green
        } elseif ($trustedHosts -eq "*") {
            Write-Host "  ✓ TrustedHosts staat op wildcard (*), geen toevoeging nodig" -ForegroundColor Green
        } else {
            Write-Host "  ✓ $computerName staat al in TrustedHosts" -ForegroundColor Green
        }
        
        Write-Host "  Controleren of PSRemoting actief is op remote machine..." -ForegroundColor Cyan
        try {
            Test-WSMan -ComputerName $computerName -ErrorAction Stop | Out-Null
            Write-Host "  ✓ PSRemoting is actief op $computerName" -ForegroundColor Green
        }
        catch {
            Write-Host "  ! PSRemoting lijkt niet actief op $computerName" -ForegroundColor Yellow
            Write-Host "    Zorg ervoor dat 'Enable-PSRemoting -Force' is uitgevoerd op de remote machine" -ForegroundColor Yellow
            $continue = Read-Host "  Doorgaan? (J/N)"
            if ($continue -notmatch "^[Jj]") {
                throw "PSRemoting niet beschikbaar op remote machine"
            }
        }
        
        # Stap 4: Credentials
        Write-Host "`n[4/5] Authenticatie..." -ForegroundColor Cyan
        $cred = Get-Credential -Message "Voer credentials in voor $computerName (moet Administrator zijn)"
        if (-not $cred) {
            throw "Credentials zijn verplicht"
        }
        Write-Host "  ✓ Credentials ingevoerd" -ForegroundColor Green
        
        # Stap 5: Client ZIP bestand
        Write-Host "`n[5/5] Client configuratie bestand..." -ForegroundColor Cyan
        $defaultZipPath = Join-Path $PSScriptRoot "..\$($Script:Settings.outputPath)\vpn-client-$($Script:Settings.clientNameDefault).zip"
        if (Test-Path $defaultZipPath) {
            $zipPath = $defaultZipPath
            Write-Host "  ✓ Standaard client ZIP bestand gevonden: $zipPath" -ForegroundColor Green
        } else {
            Write-Host "  Standaard client ZIP bestand niet gevonden op $defaultZipPath" -ForegroundColor Yellow
            $zipPath = Read-Host "  Pad naar client ZIP bestand (gegenereerd door server setup)"
        }
        if (-not (Test-Path $zipPath)) {
            throw "ZIP bestand niet gevonden: $zipPath"
        }
        Write-Host "  ✓ ZIP bestand gevonden: $zipPath" -ForegroundColor Green
        
        # Remote installatie uitvoeren
        Write-Host "`n[*] Remote installatie starten..." -ForegroundColor Cyan
        if (-not (Install-RemoteClient -ComputerName $computerName -Credential $cred -ZipPath $zipPath)) {
            throw "Remote client installatie mislukt"
        }
        Write-Host "  ✓ Remote installatie voltooid" -ForegroundColor Green
        
        Write-Host "`n╔════════════════════════════════════════════╗" -ForegroundColor Green
        Write-Host "║  Remote Client Setup Succesvol Voltooid!  ║" -ForegroundColor Green
        Write-Host "╚════════════════════════════════════════════╝" -ForegroundColor Green
        Write-Host "`nLogbestand: $script:LogFile" -ForegroundColor Yellow
        Write-Host "`nOp de remote machine kun je nu de VPN verbinding starten via OpenVPN." -ForegroundColor Cyan
        
        Write-Log "Remote client setup succesvol voltooid voor $computerName" -Level "SUCCESS"
    }
    catch {
        Write-Host "`n[!] FOUT tijdens remote client setup: $_" -ForegroundColor Red
        Write-Log "Remote client setup FOUT: $_" -Level "ERROR"
        Write-Host "`nControleer het logbestand voor details: $script:LogFile" -ForegroundColor Yellow
    }
}

function Invoke-RemoteServerSetup {
    <#
    .SYNOPSIS
        Voert remote VPN-server setup uit.

    .DESCRIPTION
        Deze functie voert setup uit voor een VPN server op een remote machine via PowerShell remoting.

    .EXAMPLE
        Invoke-RemoteServerSetup
    #>
    
    Write-Log "=== Remote Server Setup Gestart ===" -Level "INFO"
    
    try {
        # Stap 1: Administrator check (voor lokale machine)
        Write-Host "`n[1/6] Controleren administrator rechten..." -ForegroundColor Cyan
        if (-not (Test-IsAdmin)) {
            throw "Script moet als Administrator worden uitgevoerd!"
        }
        Write-Host "  ✓ Administrator rechten bevestigd" -ForegroundColor Green
        
        # Stap 1.5: Controleer lokale OpenVPN installatie
        if (-not (Test-Path $Script:Settings.installedPath)) {
            Write-Host "`n[1.5] OpenVPN lokaal installeren voor certificaat generatie..." -ForegroundColor Cyan
            if (-not (Install-OpenVPN)) {
                throw "Lokale OpenVPN installatie mislukt"
            }
            Write-Host "  ✓ OpenVPN lokaal geïnstalleerd" -ForegroundColor Green
        }
        
        # Stap 2: Remote computer details
        Write-Host "`n[2/6] Remote computer configuratie..." -ForegroundColor Cyan
        $computerName = Read-Host "  Voer de naam of IP van de remote computer in"
        if ([string]::IsNullOrWhiteSpace($computerName)) {
            throw "Remote computer naam is verplicht"
        }
        Write-Host "  ✓ Remote computer: $computerName" -ForegroundColor Green
        
        # Stap 3: WinRM configuratie
        Write-Host "`n[3/6] WinRM configuratie controleren..." -ForegroundColor Cyan
        try {
            $trustedHosts = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Client -Name TrustedHosts -ErrorAction Stop).TrustedHosts
        } catch {
            $trustedHosts = ""
        }
        if ($trustedHosts -notlike "*$computerName*" -and $trustedHosts -ne "*") {
            Write-Host "  Remote computer niet in TrustedHosts. Toevoegen..." -ForegroundColor Yellow
            $newTrustedHosts = if ($trustedHosts) { "$trustedHosts,$computerName" } else { $computerName }
            Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Client -Name TrustedHosts -Value $newTrustedHosts
            Restart-Service winrm -Force
            Write-Host "  ✓ $computerName toegevoegd aan TrustedHosts en WinRM herstart" -ForegroundColor Green
        } elseif ($trustedHosts -eq "*") {
            Write-Host "  ✓ TrustedHosts staat op wildcard (*), geen toevoeging nodig" -ForegroundColor Green
        } else {
            Write-Host "  ✓ $computerName staat al in TrustedHosts" -ForegroundColor Green
        }
        
        Write-Host "  Controleren of PSRemoting actief is op remote machine..." -ForegroundColor Cyan
        try {
            Test-WSMan -ComputerName $computerName -ErrorAction Stop | Out-Null
            Write-Host "  ✓ PSRemoting actief op $computerName" -ForegroundColor Green
        } catch {
            Write-Host "  ! PSRemoting niet actief op $computerName. Inschakelen..." -ForegroundColor Yellow
            Write-Host "    Voer het volgende uit op de remote machine als Administrator:" -ForegroundColor Yellow
            Write-Host "    Enable-PSRemoting -Force" -ForegroundColor White
            Write-Host "    Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Client -Name TrustedHosts -Value '*'" -ForegroundColor White
            throw "PSRemoting moet ingeschakeld zijn op de remote machine"
        }
        
        # Stap 4: Credentials verkrijgen
        Write-Host "`n[4/6] Authenticatie..." -ForegroundColor Cyan
        $cred = Get-Credential -Message "Voer Administrator credentials in voor $computerName"
        if (-not $cred) {
            throw "Credentials zijn verplicht"
        }
        Write-Host "  ✓ Credentials verkregen" -ForegroundColor Green
        
        # Stap 5: Server configuratie verkrijgen
        Write-Host "`n[5/6] Server configuratie..." -ForegroundColor Cyan
        $serverConfig = Get-ServerConfiguration
        Write-Host "  ✓ Server configuratie verkregen" -ForegroundColor Green
        
        # Stap 6: Certificaten lokaal genereren
        Write-Host "`n[6/6] Certificaten lokaal genereren..." -ForegroundColor Cyan
        $localEasyRSA = $Script:Settings.easyRSAPath
        if (-not (Initialize-EasyRSA)) {
            throw "EasyRSA initialisatie mislukt lokaal"
        }
        if (-not (Initialize-Certificates -ServerName $serverConfig.ServerName -Password $serverConfig.Password -EasyRSAPath $Script:Settings.easyRSAPath)) {
            throw "Certificaat generatie mislukt lokaal"
        }
        Write-Host "  ✓ Certificaten lokaal gegenereerd" -ForegroundColor Green
        
        # Remote installatie uitvoeren
        Write-Host "`n[*] Remote server installatie starten..." -ForegroundColor Cyan
        if (-not (Install-RemoteServer -ComputerName $computerName -Credential $cred -ServerConfig $serverConfig -LocalEasyRSAPath $localEasyRSA)) {
            throw "Remote server installatie mislukt"
        }
        Write-Host "  ✓ Remote installatie voltooid" -ForegroundColor Green
        
        Write-Host "`n╔════════════════════════════════════════════╗" -ForegroundColor Green
        Write-Host "║  Remote Server Setup Succesvol Voltooid!  ║" -ForegroundColor Green
        Write-Host "╚════════════════════════════════════════════╝" -ForegroundColor Green
        Write-Host "`nLogbestand: $script:LogFile" -ForegroundColor Yellow
        Write-Host "`nDe VPN server draait nu op de remote machine." -ForegroundColor Cyan
        
        Write-Log "Remote server setup succesvol voltooid voor $computerName" -Level "SUCCESS"
    }
    catch {
        Write-Host "`n[!] FOUT tijdens remote server setup: $_" -ForegroundColor Red
        Write-Log "Remote server setup FOUT: $_" -Level "ERROR"
        Write-Host "`nControleer het logbestand voor details: $script:LogFile" -ForegroundColor Yellow
    }
}

# Start het script
Start-VPNSetup
