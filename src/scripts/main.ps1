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

# Import module required werken !!!
try {
    $ModulePath = Join-Path $PSScriptRoot "../module/AutoSecureVPN.psm1"
    Import-Module $ModulePath -Force
}
catch {
    Write-Host "FOUT: Kan module AutoSecureVPN niet laden. $_" -ForegroundColor Red
    Read-Host "`nDruk op Enter om af te sluiten"
    exit 1
}

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

# Globale variabelen
$logsPath = Join-Path $Script:BasePath "logs"
if (-not (Test-Path $logsPath)) {
    New-Item -ItemType Directory -Path $logsPath -Force
}
$script:LogFile = Join-Path $logsPath $Script:Settings.logFileName
$script:ConfigPath = $Script:Settings.configPath
$script:EasyRSAPath = $Script:Settings.easyRSAPath
$Script:OutputPath = Join-Path $Script:BasePath $Script:Settings.outputPath

# Start transcript voor logging
$transcriptPath = Join-Path $logsPath $Script:Settings.transcriptFileName
Start-Transcript -Path $transcriptPath -Append -NoClobber

# Hoofdfunctie
#region Menu en UI functies

########################################################################################################################
# Menu en UI functies
########################################################################################################################

function Start-VPNSetup {
    <#
    .SYNOPSIS
        Toont het hoofdmenu voor VPN setup keuze.

    .DESCRIPTION
        Deze functie toont een menu met opties voor server of client setup keuze.

    .EXAMPLE
        Start-VPNSetup
    #>
    
    Write-Log "=== OpenVPN Automatische Setup Gestart ===" -Level "INFO"
    
    $choice = Show-Menu -Mode Menu -Title "OpenVPN Automatische Setup v1.0" -Options @("Server Setup", "Client Setup", "Afsluiten") -HeaderColor Cyan -OptionColor Green -FooterColor Cyan -Prompt "Voer uw keuze in (1-3)"
    
    switch ($choice) {
        1 {
            Write-Host "`n[*] Server Setup geselecteerd..." -ForegroundColor Cyan
            Write-Log "Server Setup geselecteerd" -Level "INFO"
            Select-ServerMode
        }
        2 {
            Write-Host "`n[*] Client Setup geselecteerd..." -ForegroundColor Cyan
            Write-Log "Client Setup geselecteerd" -Level "INFO"
            Select-ClientMode
        }
        3 {
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

function Select-ServerMode {
    <#
    .SYNOPSIS
        Toont submenu voor server setup keuze (lokaal of remote).

    .DESCRIPTION
        Deze functie toont een submenu voor het kiezen tussen lokale of remote server setup.

    .EXAMPLE
        Select-ServerMode
    #>
    
    $choice = Show-Menu -Mode Menu -Title "Server Setup Opties" -Options @("Lokaal (VPN-server installeren en configureren op deze machine)", "Remote (VPN-server installeren en configureren op afstand)", "Terug naar hoofdmenu") -HeaderColor Yellow -OptionColor Green -FooterColor Red -Prompt "Voer uw keuze in (1-3)"
    
    switch ($choice) {
        1 {
            Write-Host "`n[*] Lokale Server Setup geselecteerd..." -ForegroundColor Cyan
            Write-Log "Lokale Server Setup geselecteerd" -Level "INFO"
            
            $protocol = Select-VPNProtocol
            if ($protocol -eq "OpenVPN") {
                Invoke-OpenVPNServerSetup
            }
            elseif ($protocol -eq "WireGuard") {
                Invoke-WireGuardServerSetup
            }
        }
        2 {
            Write-Host "`n[*] Remote Server Setup geselecteerd..." -ForegroundColor Cyan
            Write-Log "Remote Server Setup geselecteerd" -Level "INFO"
            
            $protocol = Select-VPNProtocol
            if ($protocol -eq "OpenVPN") {
                Invoke-RemoteOpenVPNServerSetup
            }
            elseif ($protocol -eq "WireGuard") {
                Invoke-RemoteWireGuardServerSetup
            }
        }
        3 {
            Write-Host "`n[*] Terug naar hoofdmenu..." -ForegroundColor Yellow
            Write-Log "Terug naar hoofdmenu" -Level "INFO"
            Start-VPNSetup
        }
        default {
            Write-Host "`n[!] Ongeldige keuze. Probeer opnieuw." -ForegroundColor Red
            Start-Sleep -Seconds 2
            Select-ServerMode
        }
    }
}

function Select-ClientMode {
    <#
    .SYNOPSIS
        Toont submenu voor client setup keuze (lokaal of remote).

    .DESCRIPTION
        Deze functie toont een submenu voor het kiezen tussen lokale of remote client setup.

    .EXAMPLE
        Select-ClientMode
    #>
    
    $choice = Show-Menu -Mode Menu -Title "Client Setup Opties" -Options @("Lokaal (VPN-client installeren en verbinden op deze machine)", "Remote (VPN-client installeren en verbinden op afstand)", "Batch Remote (VPN-client installeren op meerdere machines)", "Terug naar hoofdmenu") -HeaderColor Yellow -OptionColor Green -FooterColor Red -Prompt "Voer uw keuze in (1-4)"
    
    switch ($choice) {
        1 {
            Write-Host "`n[*] Lokale Client Setup geselecteerd..." -ForegroundColor Cyan
            Write-Log "Lokale Client Setup geselecteerd" -Level "INFO"
            
            $protocol = Select-VPNProtocol
            if ($protocol -eq "OpenVPN") {
                Invoke-OpenVPNClientSetup
            }
            elseif ($protocol -eq "WireGuard") {
                Invoke-WireGuardClientSetup
            }
        }
        2 {
            Write-Host "`n[*] Remote Client Setup geselecteerd..." -ForegroundColor Cyan
            Write-Log "Remote Client Setup geselecteerd" -Level "INFO"
             
            $protocol = Select-VPNProtocol
            if ($protocol -eq "OpenVPN") {
                Invoke-RemoteOpenVPNClientSetup
            }
            elseif ($protocol -eq "WireGuard") {
                Invoke-RemoteWireGuardClientSetup
            }
        }
        3 {
            Write-Host "`n[*] Batch Remote Client Setup geselecteerd..." -ForegroundColor Cyan
            Write-Log "Batch Remote Client Setup geselecteerd" -Level "INFO"
            Invoke-BatchRemoteClientSetup
        }
        4 {
            Write-Host "`n[*] Terug naar hoofdmenu..." -ForegroundColor Yellow
            Write-Log "Terug naar hoofdmenu" -Level "INFO"
            Start-VPNSetup
        }
        default {
            Write-Host "`n[!] Ongeldige keuze. Probeer opnieuw." -ForegroundColor Red
            Start-Sleep -Seconds 2
            Select-ClientMode
        }
    }
}


function Select-VPNProtocol {
    <#
    .SYNOPSIS
        Vraagt de gebruiker om een VPN protocol te kiezen.
    #>
    $choice = Show-Menu -Mode Menu -Title "Kies VPN Protocol" -Options @("OpenVPN", "WireGuard (Experimental)") -HeaderColor Magenta -OptionColor White -Prompt "Kies protocol (1-2)"
    
    switch ($choice) {
        1 { return "OpenVPN" }
        2 { return "WireGuard" }
    }
}

#endregion Menu en UI functies



#region Client Setup functies

########################################################################################################################
# Client Setup functies
########################################################################################################################



function Invoke-OpenVPNClientSetup {
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
        Write-Progress -Activity "Client Setup" -Status "Stap 1 van 6: Controleren administrator rechten" -PercentComplete 0
        Write-Host "`n[1/6] Controleren administrator rechten..." -ForegroundColor Cyan
        if (-not (Test-IsAdmin)) {
            throw "Script moet als Administrator worden uitgevoerd!"
        }
        Write-Host "  ✓ Administrator rechten bevestigd" -ForegroundColor Green
        Write-Verbose "Administrator rechten succesvol gecontroleerd"
        Write-Log "Administrator rechten bevestigd" -Level "INFO"
        
        # Stap 2: OpenVPN installeren
        Write-Progress -Activity "Client Setup" -Status "Stap 2 van 6: OpenVPN installeren" -PercentComplete 16.67
        Write-Host "`n[2/6] OpenVPN installeren..." -ForegroundColor Cyan
        if (-not (Install-OpenVPN)) {
            throw "OpenVPN installatie mislukt"
        }
        Write-Host "  ✓ OpenVPN geïnstalleerd" -ForegroundColor Green
        Write-Verbose "OpenVPN succesvol geïnstalleerd"
        Write-Log "OpenVPN geïnstalleerd" -Level "INFO"
        
        # Stap 3: Client configuratie importeren
        Write-Progress -Activity "Client Setup" -Status "Stap 3 van 6: Client configuratie importeren" -PercentComplete 33.33
        Write-Host "`n[3/6] Client configuratie importeren..." -ForegroundColor Cyan
        $configPath = Import-ClientConfiguration
        if (-not $configPath) {
            throw "Client configuratie importeren mislukt"
        }
        Write-Host "  ✓ Configuratie geïmporteerd" -ForegroundColor Green
        Write-Verbose "Client configuratie succesvol geïmporteerd van $configPath"
        Write-Log "Client configuratie geïmporteerd" -Level "INFO"
        
        # Stap 4: TAP adapter controleren
        Write-Progress -Activity "Client Setup" -Status "Stap 4 van 6: TAP adapter controleren" -PercentComplete 50
        Write-Host "`n[4/6] TAP adapter controleren..." -ForegroundColor Cyan
        if (-not (Test-TAPAdapter)) {
            Write-Host "  ! TAP adapter niet gevonden, OpenVPN moet mogelijk opnieuw worden geïnstalleerd" -ForegroundColor Yellow
            Write-Log "TAP adapter niet gevonden" -Level "WARNING"
            Write-Verbose "TAP adapter niet gevonden, mogelijk herinstallatie nodig"
        }
        else {
            Write-Host "  ✓ TAP adapter gevonden" -ForegroundColor Green
            Write-Verbose "TAP adapter succesvol gevonden"
            Write-Log "TAP adapter gevonden" -Level "INFO"
        }
        
        # Stap 5: VPN verbinding starten
        Write-Progress -Activity "Client Setup" -Status "Stap 5 van 6: VPN verbinding starten" -PercentComplete 66.67
        Write-Host "`n[5/6] VPN verbinding starten..." -ForegroundColor Cyan
        if (-not (Start-VPNConnection -ConfigFile $configPath)) {
            throw "VPN verbinding starten mislukt"
        }
        Write-Host "  ✓ VPN verbinding gestart" -ForegroundColor Green
        Write-Verbose "VPN verbinding succesvol gestart"
        Write-Log "VPN verbinding gestart" -Level "INFO"
        
        # Stap 6: Verbinding testen
        Write-Progress -Activity "Client Setup" -Status "Stap 6 van 6: VPN verbinding testen" -PercentComplete 83.33
        Write-Host "`n[6/6] VPN verbinding testen..." -ForegroundColor Cyan
        Start-Sleep -Seconds 30  # Wacht langer tot verbinding volledig is opgezet
        $testResult = Test-VPNConnection
        if (-not $testResult) {
            throw "VPN verbinding test mislukt"
        }
        Write-Verbose "VPN verbinding succesvol getest"
        Write-Log "VPN verbinding getest" -Level "INFO"
        
        Write-Progress -Activity "Client Setup" -Completed
        
        Show-Menu -Mode Success -SuccessTitle "Client Setup Succesvol Voltooid!" -LogFile $script:LogFile
    }
    catch {
        Write-Progress -Activity "Client Setup" -Completed
        Write-Log "Fout tijdens Client Setup: $($_.Exception.Message)" -Level "ERROR"
        $choice = Show-Menu -Mode Error -SuccessTitle "Client Setup Gefaald!" -LogFile $script:LogFile -ExtraMessage "Controleer het logbestand voor details." -Options @("Opnieuw proberen", "Terug naar hoofdmenu", "Afsluiten")
        switch ($choice) {
            1 {
                # Rollback uitvoeren voordat opnieuw proberen
                Write-Host "`n[*] Rollback uitvoeren om wijzigingen ongedaan te maken..." -ForegroundColor Yellow
                Invoke-Rollback -SetupType "Client"
                Invoke-Rollback -SetupType "Client"
                Invoke-OpenVPNClientSetup
            }
            2 {
                # Rollback uitvoeren voordat terug naar hoofdmenu
                Write-Host "`n[*] Rollback uitvoeren om wijzigingen ongedaan te maken..." -ForegroundColor Yellow
                Invoke-Rollback -SetupType "Client"
                Start-VPNSetup
            }
            3 {
                # Rollback uitvoeren voordat afsluiten
                Write-Host "`n[*] Rollback uitvoeren om wijzigingen ongedaan te maken..." -ForegroundColor Yellow
                Invoke-Rollback -SetupType "Client"
                exit
            }
        }
    }
}

function Invoke-RemoteOpenVPNClientSetup {
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
        Write-Progress -Activity "Remote Client Setup" -Status "Stap 1 van 5: Controleren administrator rechten" -PercentComplete 0
        Write-Host "`n[1/5] Controleren administrator rechten..." -ForegroundColor Cyan
        if (-not (Test-IsAdmin)) {
            throw "Script moet als Administrator worden uitgevoerd!"
        }
        Write-Host "  ✓ Administrator rechten bevestigd" -ForegroundColor Green
        Write-Verbose "Lokale administrator rechten succesvol gecontroleerd"
        Write-Log "Administrator rechten bevestigd" -Level "INFO"
        
        # Stap 2: Remote computer details - gebruik settings wanneer beschikbaar
        Write-Progress -Activity "Remote Client Setup" -Status "Stap 2 van 5: Remote computer configuratie" -PercentComplete 20
        Write-Host "`n[2/5] Remote computer configuratie..." -ForegroundColor Cyan

        # remoteClientIP ophalen en valideren; als leeg -> fout (geen prompt)
        try {
            if ($Script:Settings.ContainsKey('remoteClientIP') -and -not [string]::IsNullOrWhiteSpace($Script:Settings.remoteClientIP) -and $Script:Settings.remoteClientIP -ne 'jouw.client.ip.hier') {
                $computerName = $Script:Settings.remoteClientIP
                Write-Verbose "Remote client afkomstig uit settings: $computerName"
            }
        }
        catch {
            Write-Verbose "Fout bij ophalen remoteClientIP uit settings: $_"
        }

        if ([string]::IsNullOrWhiteSpace($computerName)) {
            throw "Instelling 'remoteClientIP' is leeg of ongeldig in Variable.psd1. Vul 'remoteClientIP' in of pas de configuratie aan."
        }
        
        Write-Host "  ✓ Remote computer: $computerName" -ForegroundColor Green
        Write-Verbose "Remote computer naam gebruikt: $computerName"
        Write-Log "Remote computer: $computerName" -Level "INFO"
        
        # Stap 3: WinRM configuratie
        Write-Progress -Activity "Remote Client Setup" -Status "Stap 3 van 5: WinRM configuratie controleren" -PercentComplete 40
        Write-Host "`n[3/5] WinRM configuratie controleren..." -ForegroundColor Cyan
        try {
            $trustedHosts = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Client -Name TrustedHosts -ErrorAction Stop).TrustedHosts
        }
        catch {
            $trustedHosts = ""
        }
        if ($trustedHosts -notlike "*$computerName*" -and $trustedHosts -ne "*") {
            Write-Host "  Remote computer niet in TrustedHosts. Toevoegen..." -ForegroundColor Yellow
            $newTrustedHosts = if ($trustedHosts) { "$trustedHosts,$computerName" } else { $computerName }
            Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Client -Name TrustedHosts -Value $newTrustedHosts
            Restart-Service winrm -Force
            Write-Host "  ✓ $computerName toegevoegd aan TrustedHosts en WinRM herstart" -ForegroundColor Green
            Write-Verbose "TrustedHosts bijgewerkt en WinRM herstart"
            Write-Log "$computerName toegevoegd aan TrustedHosts en WinRM herstart" -Level "INFO"
        }
        elseif ($trustedHosts -eq "*") {
            Write-Host "  ✓ TrustedHosts staat op wildcard (*), geen toevoeging nodig" -ForegroundColor Green
            Write-Verbose "TrustedHosts staat op wildcard"
            Write-Log "TrustedHosts staat op wildcard (*)" -Level "INFO"
        }
        else {
            Write-Host "  ✓ $computerName staat al in TrustedHosts" -ForegroundColor Green
            Write-Verbose "$computerName staat al in TrustedHosts"
            Write-Log "$computerName staat al in TrustedHosts" -Level "INFO"
        }
        
        Write-Host "  Controleren of PSRemoting actief is op remote machine..." -ForegroundColor Cyan
        try {
            Test-WSMan -ComputerName $computerName -ErrorAction Stop | Out-Null
            Write-Host "  ✓ PSRemoting is actief op $computerName" -ForegroundColor Green
            Write-Verbose "PSRemoting succesvol getest op $computerName"
            Write-Log "PSRemoting actief op $computerName" -Level "INFO"
        }
        catch {
            Write-Host "  ! PSRemoting lijkt niet actief op $computerName" -ForegroundColor Yellow
            Write-Host "    Zorg ervoor dat 'Enable-PSRemoting -Force' is uitgevoerd op de remote machine" -ForegroundColor Yellow
            $continue = Read-Host "  Doorgaan? (J/N)"
            if ($continue -notmatch "^[Jj]") {
                throw "PSRemoting niet beschikbaar op remote machine"
            }
            Write-Verbose "PSRemoting niet beschikbaar, maar doorgaan gekozen"
        }
        
        # Stap 4: Credentials
        Write-Progress -Activity "Remote Client Setup" -Status "Stap 4 van 5: Authenticatie" -PercentComplete 60
        Write-Host "`n[4/5] Authenticatie..." -ForegroundColor Cyan
        $cred = Get-Credential -Message "Voer credentials in voor $computerName (moet Administrator zijn)"
        if (-not $cred) {
            throw "Credentials zijn verplicht"
        }
        Write-Host "  ✓ Credentials ingevoerd" -ForegroundColor Green
        Write-Verbose "Credentials succesvol ingevoerd voor $computerName"
        Write-Log "Credentials ingevoerd voor $computerName" -Level "INFO"
        
        # Stap 5: Client ZIP bestand
        Write-Progress -Activity "Remote Client Setup" -Status "Stap 5 van 5: Client configuratie bestand" -PercentComplete 80
        Write-Host "`n[5/5] Client configuratie bestand..." -ForegroundColor Cyan
        # Bepaal standaard client naam (verschillende settings keys mogelijk)
        $clientDefaultName = if ($Script:Settings.ContainsKey('clientName') -and -not [string]::IsNullOrWhiteSpace($Script:Settings.clientName)) { $Script:Settings.clientName } else { 'client' }
        $defaultZipPath = Join-Path $Script:OutputPath "vpn-client-$clientDefaultName.zip"
        if (Test-Path $defaultZipPath) {
            $zipPath = $defaultZipPath
            Write-Host "  ✓ Standaard client ZIP bestand gevonden: $zipPath" -ForegroundColor Green
            Write-Verbose "Standaard client ZIP bestand gebruikt: $zipPath"
            Write-Log "Standaard client ZIP bestand gevonden: $zipPath" -Level "INFO"
        }
        else {
            Write-Host "  Standaard client ZIP bestand niet gevonden op $defaultZipPath" -ForegroundColor Yellow
            $zipPath = Read-Host "  Pad naar client ZIP bestand (gegenereerd door server setup)"
            Write-Verbose "Handmatig ZIP pad ingevoerd: $zipPath"
        }
        if (-not (Test-Path $zipPath)) {
            throw "ZIP bestand niet gevonden: $zipPath"
        }
        Write-Host "  ✓ ZIP bestand gevonden: $zipPath" -ForegroundColor Green
        Write-Log "ZIP bestand gevonden: $zipPath" -Level "INFO"
        
        # Remote installatie uitvoeren
        Write-Progress -Activity "Remote Client Setup" -Status "Remote installatie uitvoeren" -PercentComplete 90
        Write-Host "`n[*] Remote installatie starten..." -ForegroundColor Cyan
        if (-not (Install-RemoteClient -ComputerName $computerName -Credential $cred -ZipPath $zipPath -RemoteConfigPath $Script:Settings.remoteConfigPath)) {
            throw "Remote client installatie mislukt"
        }
        Write-Host "  ✓ Remote installatie voltooid" -ForegroundColor Green
        Write-Verbose "Remote client installatie succesvol voltooid voor $computerName"
        Write-Log "Remote client installatie voltooid voor $computerName" -Level "INFO"

        # Remote OpenVPN service starten via GUI
        Write-Progress -Activity "Remote Client Setup" -Status "OpenVPN service op remote machine starten" -PercentComplete 71
        Write-Host "`n[*] OpenVPN service op remote machine starten..." -ForegroundColor Cyan
        $remoteOvpn = Join-Path $Script:Settings.remoteConfigPath "client.ovpn"
        if (-not (Start-VPNConnection -ConfigFile $remoteOvpn -ComputerName $computerName -Credential $cred)) {
            throw "Remote OpenVPN service starten mislukt"
        }
        Write-Host " ✓ Remote OpenVPN starten voltooid" -ForegroundColor Green
        Write-Verbose "Remote OpenVPN starten succesvol volottoid voor $computerName"
        Write-Log "Remote OpenVPN service gestart voor $computerName" -Level "INFO"
        
        Write-Progress -Activity "Remote Client Setup" -Completed
        
        Show-Menu -Mode Success -SuccessTitle "Remote Client Setup Succesvol Voltooid!" -LogFile $script:LogFile -ExtraMessage "Op de remote machine kun je nu de VPN verbinding starten via OpenVPN." -ComputerName $computerName
    }
    catch {
        Write-Progress -Activity "Remote Client Setup" -Completed
        Write-Log "Fout tijdens Remote Client Setup: $($_.Exception.Message)" -Level "ERROR"
        $choice = Show-Menu -Mode Error -SuccessTitle "Remote Client Setup Gefaald!" -LogFile $script:LogFile -ExtraMessage "Controleer het logbestand voor details." -Options @("Opnieuw proberen", "Terug naar hoofdmenu", "Afsluiten")
        switch ($choice) {
            1 { Invoke-RemoteOpenVPNClientSetup }
            2 { Start-VPNSetup }
            3 { exit }
        }
    }
}

function Invoke-BatchRemoteClientSetup {
    <#
    .SYNOPSIS
        Voert batch remote VPN-client setup uit voor meerdere computers.
    #>
    
    Write-Log "=== Batch Remote Client Setup Gestart ===" -Level "INFO"
    
    # Keuze protocol
    $protocol = Select-VPNProtocol
    
    try {
        # Stap 1: CSV bestand vragen
        Write-Host "`n[1/4] CSV bestand selecteren..." -ForegroundColor Cyan
        $csvPath = Read-Host "  Voer het pad naar het CSV bestand in (bijv. C:\clients.csv)"
        if (-not (Test-Path $csvPath)) { throw "CSV bestand niet gevonden: $csvPath" }
        Write-Host "  ✓ CSV bestand gevonden" -ForegroundColor Green
        
        $clients = Import-Csv -Path $csvPath
        if ($clients.Count -eq 0) { throw "Geen clients gevonden in CSV" }
        Write-Log "$($clients.Count) clients gevonden" -Level "INFO"
        
        # Stap 2: Protocol specifieke input
        if ($protocol -eq "OpenVPN") {
            # ... OpenVPN Existing Logic ...
            Write-Host "`n[2/4] Client ZIP bestand selecteren..." -ForegroundColor Cyan
            $clientDefaultName = if ($Script:Settings.ContainsKey('clientName')) { $Script:Settings.clientName } else { 'client' }
            $defaultZipPath = Join-Path $Script:OutputPath "vpn-client-$clientDefaultName.zip"
             
            if (Test-Path $defaultZipPath) {
                Write-Host "  Standaard gevonden: $defaultZipPath"
                if ((Read-Host "  Gebruiken? (J/N)") -match "^[Jj]") { $zipPath = $defaultZipPath }
            }
             
            if (-not $zipPath) { $zipPath = Read-Host "  Pad naar client ZIP bestand" }
            if (-not (Test-Path $zipPath)) { throw "ZIP bestand niet gevonden" }
             
            # Execute Batch OpenVPN
            Write-Host "`n[3/4] Starten Batch OpenVPN Setup..." -ForegroundColor Cyan
            $cpuCores = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
            $throttleLimit = [math]::Max(1, $cpuCores - 1)
             
            $results = Invoke-BatchRemoteClientInstall -Clients $clients -ZipPath $zipPath -ModulePath $ModulePath -Settings $Script:Settings -BasePath $Script:BasePath -ThrottleLimit $throttleLimit
             
        }
        elseif ($protocol -eq "WireGuard") {
            # WireGuard Logic
            Write-Host "`n[2/4] WireGuard Server gegevens..." -ForegroundColor Cyan
            
            # Probeer gegevens uit een bestaande client config te halen (lokaal)
            $wgClientConfigMatch = Get-ChildItem -Path $Script:OutputPath -Filter "wg-client*.conf" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            
            $serverEndpoint = $null
            $serverPubKey = $null
            
            if ($wgClientConfigMatch) {
                Write-Host "  Found local config: $($wgClientConfigMatch.Name)" -ForegroundColor Gray
                $content = Get-Content $wgClientConfigMatch.FullName -Raw
                
                # Regex to extract Endpoint and PublicKey from [Peer] section
                if ($content -match 'Endpoint\s*=\s*(.*)') { $serverEndpoint = $matches[1].Trim() }
                if ($content -match 'PublicKey\s*=\s*(.*)') { $serverPubKey = $matches[1].Trim() }
            }
            
            if (-not $serverEndpoint -or -not $serverPubKey) {
                Write-Host "  Kon server gegevens niet automatisch vinden." -ForegroundColor Yellow
                if (-not $serverEndpoint) { $serverEndpoint = Read-Host "  Server Endpoint (Publiek IP:Poort, bijv. 1.2.3.4:51820)" }
                if (-not $serverPubKey) { $serverPubKey = Read-Host "  Server Public Key" }
            }
            else {
                Write-Host "  ✓ Server gegevens geladen uit $($wgClientConfigMatch.Name)" -ForegroundColor Green
                Write-Host "    Endpoint: $serverEndpoint" -ForegroundColor Gray
                Write-Host "    Public Key: $serverPubKey" -ForegroundColor Gray
            }
             
            if (-not $serverEndpoint -or -not $serverPubKey) { throw "Server gegevens verplicht" }
             
            $serverKeys = @{ PublicKey = $serverPubKey }
             
            # Execute Batch WireGuard
            Write-Host "`n[3/4] Starten Batch WireGuard Setup..." -ForegroundColor Cyan
             
            # Module path fix
            $modPath = Join-Path $PSScriptRoot "../module/AutoSecureVPN.psm1"
            
            $results = Invoke-BatchRemoteWireGuardClientInstall -Clients $clients -ServerKeys $serverKeys -ServerEndpoint $serverEndpoint -ModulePath $modPath -Settings $Script:Settings
        }

        # Resultaten tonen
        Write-Host "`nResultaten:" -ForegroundColor Yellow
        $successCount = 0
        foreach ($result in $results) {
            if ($result -like "SUCCESS:*") {
                Write-Host "  ✓ $result" -ForegroundColor Green
                $successCount++
            }
            else {
                Write-Host "  ✗ $result" -ForegroundColor Red
            }
        }
        
        Write-Log "Batch Remote Setup voltooid ($successCount/$($clients.Count) succesvol)" -Level "INFO"
        
        if ($successCount -eq $clients.Count) {
            Show-Menu -Mode Success -SuccessTitle "Batch Setup Succesvol!" -LogFile $script:LogFile
        }
        else {
            Show-Menu -Mode Error -SuccessTitle "Batch Setup Deels Mislukt" -LogFile $script:LogFile
        }

    }
    catch {
        Write-Log "Fout tijdens Batch Setup: $_" -Level "ERROR"
        Show-Menu -Mode Error -SuccessTitle "Batch Setup Gefaald!" -ExtraMessage $_
    }
}

#endregion Client Setup functies

#region Server Setup functies

########################################################################################################################
# Server Setup functies
########################################################################################################################

function Invoke-OpenVPNServerSetup {
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
        Write-Progress -Activity "Server Setup" -Status "Stap 1 van 8: Controleren administrator rechten" -PercentComplete 0
        Write-Host "`n[1/8] Controleren administrator rechten..." -ForegroundColor Cyan
        if (-not (Test-IsAdmin)) {
            throw "Script moet als Administrator worden uitgevoerd!"
        }
        Write-Host "  ✓ Administrator rechten bevestigd" -ForegroundColor Green
        Write-Verbose "Administrator rechten succesvol gecontroleerd"
        Write-Log "Administrator rechten bevestigd" -Level "INFO"
        
        # Stap 2: OpenVPN installeren
        Write-Progress -Activity "Server Setup" -Status "Stap 2 van 8: OpenVPN installeren" -PercentComplete 12.5
        Write-Host "`n[2/8] OpenVPN installeren..." -ForegroundColor Cyan
        if (-not (Install-OpenVPN)) {
            throw "OpenVPN installatie mislukt"
        }
        Write-Host "  ✓ OpenVPN geïnstalleerd" -ForegroundColor Green
        Write-Verbose "OpenVPN succesvol geïnstalleerd"
        Write-Log "OpenVPN geïnstalleerd" -Level "INFO"
        
        # Stap 3: Firewall configureren
        Write-Progress -Activity "Server Setup" -Status "Stap 3 van 8: Windows Firewall configureren" -PercentComplete 25
        Write-Host "`n[3/8] Windows Firewall configureren..." -ForegroundColor Cyan
        if (-not (Set-Firewall -Port 443 -Protocol "TCP")) {
            throw "Firewall configuratie mislukt"
        }
        Write-Host "  ✓ Firewall regels toegevoegd" -ForegroundColor Green
        Write-Verbose "Firewall regels succesvol toegevoegd"
        Write-Log "Firewall regels toegevoegd" -Level "INFO"
        
        # Stap 4: Gebruikersinput verzamelen
        Write-Progress -Activity "Server Setup" -Status "Stap 4 van 8: Server configuratie parameters verzamelen" -PercentComplete 37.5
        Write-Host "`n[4/8] Server configuratie parameters..." -ForegroundColor Cyan
        $serverConfig = Get-ServerConfiguration
        Write-Verbose "Server configuratie parameters verzameld: $($serverConfig | ConvertTo-Json)"
        Write-Log "Server configuratie parameters verzameld" -Level "INFO"
        
        # Stap 5: EasyRSA en certificaten
        Write-Progress -Activity "Server Setup" -Status "Stap 5 van 8: Certificaten genereren" -PercentComplete 50
        Write-Host "`n[5/8] Certificaten genereren (dit kan even duren)..." -ForegroundColor Cyan
        if (-not (Initialize-EasyRSA -EasyRSAPath $script:EasyRSAPath)) {
            throw "EasyRSA initialisatie mislukt"
        }
        if (-not (Initialize-Certificates -ServerName $serverConfig.ServerName -Password $serverConfig.Password -EasyRSAPath $script:EasyRSAPath)) {
            throw "Certificaat generatie mislukt"
        }
        Write-Host "  ✓ Certificaten gegenereerd" -ForegroundColor Green
        Write-Verbose "Certificaten succesvol gegenereerd voor server $($serverConfig.ServerName)"
        Write-Log "Certificaten gegenereerd" -Level "INFO"
        
        # Stap 6: Server configuratie genereren
        Write-Progress -Activity "Server Setup" -Status "Stap 6 van 8: Server configuratie aanmaken" -PercentComplete 62.5
        Write-Host "`n[6/8] Server configuratie aanmaken..." -ForegroundColor Cyan
        if (-not (New-ServerConfig -Config $serverConfig -EasyRSAPath $script:EasyRSAPath -ConfigPath $script:ConfigPath)) {
            throw "Server configuratie generatie mislukt"
        }
        Write-Host "  ✓ Server configuratie aangemaakt" -ForegroundColor Green
        Write-Verbose "Server configuratie succesvol aangemaakt"
        Write-Log "Server configuratie aangemaakt" -Level "INFO"
        
        # Stap 7: OpenVPN service starten
        Write-Progress -Activity "Server Setup" -Status "Stap 7 van 8: OpenVPN service starten" -PercentComplete 75
        Write-Host "`n[7/8] OpenVPN service starten..." -ForegroundColor Cyan
        if (-not (Start-VPNService)) {
            throw "OpenVPN service starten mislukt"
        }
        Write-Host "  ✓ OpenVPN service actief" -ForegroundColor Green
        Write-Verbose "OpenVPN service succesvol gestart"
        Write-Log "OpenVPN service actief" -Level "INFO"
        
        # Stap 8: Client package maken
        Write-Progress -Activity "Server Setup" -Status "Stap 8 van 8: Client configuratie package maken" -PercentComplete 87.5
        Write-Host "`n[8/8] Client configuratie package maken..." -ForegroundColor Cyan
        $zipPath = New-ClientPackage -Config $serverConfig -EasyRSAPath $script:EasyRSAPath
        if (-not $zipPath) {
            throw "Client package aanmaken mislukt"
        }
        Write-Host "  ✓ Client package aangemaakt: $zipPath" -ForegroundColor Green
        Write-Verbose "Client package succesvol aangemaakt: $zipPath"
        Write-Log "Client package aangemaakt: $zipPath" -Level "INFO"
        
        Write-Progress -Activity "Server Setup" -Completed
        
        Show-Menu -Mode Success -SuccessTitle "Server Setup Succesvol Voltooid!" -LogFile $script:LogFile -ExtraInfo "Client package: $zipPath" -ExtraMessage "Dit ZIP-bestand naar de client overzetten om de verbinding te maken."
    }
    catch {
        Write-Progress -Activity "Server Setup" -Completed
        Write-Log "Fout tijdens Server Setup: $($_.Exception.Message)" -Level "ERROR"   
        $choice = Show-Menu -Mode Error -SuccessTitle "Server Setup Gefaald!" -LogFile $script:LogFile -ExtraMessage "Controleer het logbestand voor details." -Options @("Opnieuw proberen", "Terug naar hoofdmenu", "Afsluiten")
        switch ($choice) {
            1 {
                # Rollback uitvoeren voordat opnieuw proberen
                Write-Host "`n[*] Rollback uitvoeren om wijzigingen ongedaan te maken..." -ForegroundColor Yellow
                Invoke-Rollback -SetupType "Server"
                Invoke-OpenVPNServerSetup
            }
            2 {
                # Rollback uitvoeren voordat terug naar hoofdmenu
                Write-Host "`n[*] Rollback uitvoeren om wijzigingen ongedaan te maken..." -ForegroundColor Yellow
                Invoke-Rollback -SetupType "Server"
                Start-VPNSetup
            }
            3 {
                # Rollback uitvoeren voordat afsluiten
                Write-Host "`n[*] Rollback uitvoeren om wijzigingen ongedaan te maken..." -ForegroundColor Yellow
                Invoke-Rollback -SetupType "Server"
                exit
            }
        }
    }
}

function Invoke-RemoteOpenVPNServerSetup {
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
        Write-Progress -Activity "Remote Server Setup" -Status "Stap 1 van 7: Controleren administrator rechten" -PercentComplete 0
        Write-Host "`n[1/7] Controleren administrator rechten..." -ForegroundColor Cyan
        if (-not (Test-IsAdmin)) {
            throw "Script moet als Administrator worden uitgevoerd!"
        }
        Write-Host "  ✓ Administrator rechten bevestigd" -ForegroundColor Green
        Write-Verbose "Lokale administrator rechten succesvol gecontroleerd"        Write-Log "Administrator rechten bevestigd" -Level "INFO"        
        # Stap 1.5: Controleer lokale OpenVPN installatie
        Write-Progress -Activity "Remote Server Setup" -Status "Stap 1.5 van 7: Lokale OpenVPN installatie controleren" -PercentComplete 7
        if (-not (Test-Path $Script:Settings.installedPath)) {
            Write-Host "`n[1.5] OpenVPN lokaal installeren voor certificaat generatie..." -ForegroundColor Cyan
            if (-not (Install-OpenVPN)) {
                throw "Lokale OpenVPN installatie mislukt"
            }
            Write-Host "  ✓ OpenVPN lokaal geïnstalleerd" -ForegroundColor Green
            Write-Verbose "OpenVPN lokaal geïnstalleerd voor certificaat generatie"
            Write-Log "OpenVPN lokaal geïnstalleerd" -Level "INFO"
        }
        else {
            Write-Verbose "OpenVPN al lokaal geïnstalleerd"
        }
        
        # Stap 2: Remote computer details
        Write-Progress -Activity "Remote Server Setup" -Status "Stap 2 van 7: Remote computer configuratie" -PercentComplete 14
        Write-Host "`n[2/7] Remote computer configuratie..." -ForegroundColor Cyan
        # Settings.serverIP ophalen
        try {
            if ($Script:Settings.ContainsKey('serverIP') -and -not [string]::IsNullOrWhiteSpace($Script:Settings.serverIP) -and $Script:Settings.serverIP -ne 'jouw.server.ip.hier') {
                $computerName = $Script:Settings.serverIP
                Write-Verbose "Remote server IP afkomstig uit settings: $computerName"
            } 
        }    
        catch {
            throw "Server IP address is leeg in variabel.psd1"
        }

        if ([string]::IsNullOrWhiteSpace($computerName)) {
            throw "Instelling 'remoteClientIP' is leeg of ongeldig in Variable.psd1. Vul 'remoteClientIP' in of pas de configuratie aan."
        }
        
        Write-Host "  ✓ Remote computer: $computerName" -ForegroundColor Green
        Write-Verbose "Remote computer naam gebruikt: $computerName"
        Write-Log "Remote computer: $computerName" -Level "INFO"
        
        # Stap 3: WinRM configuratie
        Write-Progress -Activity "Remote Server Setup" -Status "Stap 3 van 7: WinRM configuratie controleren" -PercentComplete 21
        Write-Host "`n[3/7] WinRM configuratie controleren..." -ForegroundColor Cyan
        try {
            $trustedHosts = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Client -Name TrustedHosts -ErrorAction Stop).TrustedHosts
        }
        catch {
            $trustedHosts = ""
        }
        if ($trustedHosts -notlike "*$computerName*" -and $trustedHosts -ne "*") {
            Write-Host "  Remote computer niet in TrustedHosts. Toevoegen..." -ForegroundColor Yellow
            $newTrustedHosts = if ($trustedHosts) { "$trustedHosts,$computerName" } else { $computerName }
            Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Client -Name TrustedHosts -Value $newTrustedHosts
            Restart-Service winrm -Force
            Write-Host "  ✓ $computerName toegevoegd aan TrustedHosts en WinRM herstart" -ForegroundColor Green
            Write-Verbose "TrustedHosts bijgewerkt en WinRM herstart"
        }
        elseif ($trustedHosts -eq "*") {
            Write-Host "  ✓ TrustedHosts staat op wildcard (*), geen toevoeging nodig" -ForegroundColor Green
            Write-Verbose "TrustedHosts staat op wildcard"
            Write-Log "TrustedHosts staat op wildcard (*)" -Level "INFO"
        }
        else {
            Write-Host "  ✓ $computerName staat al in TrustedHosts" -ForegroundColor Green
            Write-Verbose "$computerName staat al in TrustedHosts"
            Write-Log "$computerName staat al in TrustedHosts" -Level "INFO"
        }
        
        Write-Host "  Controleren of PSRemoting actief is op remote machine..." -ForegroundColor Cyan
        try {
            Test-WSMan -ComputerName $computerName -ErrorAction Stop | Out-Null
            Write-Host "  ✓ PSRemoting actief op $computerName" -ForegroundColor Green
            Write-Verbose "PSRemoting succesvol getest op $computerName"
            Write-Log "PSRemoting actief op $computerName" -Level "INFO"
        }
        catch {
            Write-Host "  ! PSRemoting niet actief op $computerName. Inschakelen..." -ForegroundColor Yellow
            Write-Host "    Voer het volgende uit op de remote machine als Administrator:" -ForegroundColor Yellow
            Write-Host "    Enable-PSRemoting -Force" -ForegroundColor White
            Write-Host "    Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Client -Name TrustedHosts -Value '*'" -ForegroundColor White
            throw "PSRemoting moet ingeschakeld zijn op de remote machine"
        }
        
        # Stap 4: Credentials verkrijgen
        Write-Progress -Activity "Remote Server Setup" -Status "Stap 4 van 7: Authenticatie" -PercentComplete 29
        Write-Host "`n[4/7] Authenticatie..." -ForegroundColor Cyan
        $cred = Get-Credential -Message "Voer Administrator credentials in voor $computerName"
        if (-not $cred) {
            throw "Credentials zijn verplicht"
        }
        Write-Host "  ✓ Credentials verkregen" -ForegroundColor Green
        Write-Verbose "Credentials succesvol ingevoerd voor $computerName"
        Write-Log "Credentials verkregen voor $computerName" -Level "INFO"
        
        # Stap 5: Server configuratie verkrijgen
        Write-Progress -Activity "Remote Server Setup" -Status "Stap 5 van 7: Server configuratie verkrijgen" -PercentComplete 36
        Write-Host "`n[5/7] Server configuratie..." -ForegroundColor Cyan
        $serverConfig = Get-ServerConfiguration
        Write-Host "  ✓ Server configuratie verkregen" -ForegroundColor Green
        Write-Verbose "Server configuratie verkregen: $($serverConfig | ConvertTo-Json)"
        Write-Log "Server configuratie verkregen" -Level "INFO"
        
        # Stap 6: Certificaten lokaal genereren
        Write-Progress -Activity "Remote Server Setup" -Status "Stap 6 van 7: Certificaten lokaal genereren" -PercentComplete 43
        Write-Host "`n[6/7] Certificaten lokaal genereren..." -ForegroundColor Cyan
        $localEasyRSA = $Script:Settings.easyRSAPath
        if (-not (Initialize-EasyRSA)) {
            throw "EasyRSA initialisatie mislukt lokaal"
        }
        if (-not (Initialize-Certificates -ServerName $serverConfig.ServerName -Password $serverConfig.Password -EasyRSAPath $Script:Settings.easyRSAPath)) {
            throw "Certificaat generatie mislukt lokaal"
        }
        Write-Host "  ✓ Certificaten lokaal gegenereerd" -ForegroundColor Green
        Write-Verbose "Certificaten lokaal gegenereerd voor server $($serverConfig.ServerName)"
        Write-Log "Certificaten lokaal gegenereerd" -Level "INFO"
        
        # Remote installatie uitvoeren
        Write-Progress -Activity "Remote Server Setup" -Status "Remote server installatie uitvoeren" -PercentComplete 57
        Write-Host "`n[*] Remote server installatie starten..." -ForegroundColor Cyan
        if (-not (Install-RemoteServer -ComputerName $computerName -Credential $cred -ServerConfig $serverConfig -LocalEasyRSAPath $localEasyRSA -RemoteConfigPath $Script:Settings.remoteConfigPath)) {
            throw "Remote server installatie mislukt"
        }
        Write-Host "  ✓ Remote installatie voltooid" -ForegroundColor Green
        Write-Verbose "Remote server installatie succesvol voltooid voor $computerName"
        Write-Log "Remote server installatie voltooid voor $computerName" -Level "INFO"

        # Remote OpenVPN service starten via GUI
        Write-Progress -Activity "Remote Server Setup" -Status "OpenVPN service op remote machine starten" -PercentComplete 71
        Write-Host "`n[*] OpenVPN service op remote machine starten..." -ForegroundColor Cyan
        $remoteOvpn = Join-Path $Script:Settings.remoteConfigPath "server.ovpn"
        if (-not (Start-VPNConnection -ConfigFile $remoteOvpn -ComputerName $computerName -Credential $cred)) {
            throw "Remote OpenVPN service starten mislukt"
        }
        Write-Host " ✓ Remote OpenVPN starten voltooid" -ForegroundColor Green
        Write-Verbose "Remote OpenVPN starten succesvol volottoid voor $computerName"
        Write-Log "Remote OpenVPN service gestart voor $computerName" -Level "INFO"
        
        # Stap 7: Client package maken
        Write-Progress -Activity "Remote Server Setup" -Status "Stap 7 van 7: Client configuratie package maken" -PercentComplete 86
        Write-Host "`n[7/7] Client configuratie package maken..." -ForegroundColor Cyan
        $zipPath = New-ClientPackage -Config $serverConfig -EasyRSAPath $script:EasyRSAPath
        if (-not $zipPath) {
            throw "Client package aanmaken mislukt"
        }
        Write-Host "  ✓ Client package aangemaakt: $zipPath" -ForegroundColor Green
        Write-Verbose "Client package succesvol aangemaakt: $zipPath"
        Write-Log "Client package aangemaakt: $zipPath" -Level "INFO"
        
        Write-Progress -Activity "Remote Server Setup" -Completed
        
        Show-Menu -Mode Success -SuccessTitle "Remote Server Setup Succesvol Voltooid!" -LogFile $script:LogFile -ExtraMessage "De VPN server draait nu op de remote machine.`nClient package beschikbaar: $zipPath" -ComputerName $computerName
    }
    catch {
        Write-Progress -Activity "Remote Server Setup" -Completed
        Write-Log "Fout tijdens Remote Server Setup: $($_.Exception.Message)" -Level "ERROR"
        $choice = Show-Menu -Mode Error -SuccessTitle "Remote Server Setup Gefaald!" -LogFile $script:LogFile -ExtraMessage "Controleer het logbestand voor details." -Options @("Opnieuw proberen", "Terug naar hoofdmenu", "Afsluiten")
        switch ($choice) {
            1 { Invoke-RemoteOpenVPNServerSetup }
            2 { Start-VPNSetup }
            3 { exit }
        }
    }
}

#region Remote WireGuard Functions (Script Level)


function Invoke-RemoteWireGuardServerSetup {
    Write-Log "=== Remote WireGuard Server Setup Gestart ===" -Level "INFO"
    try {
        # Admin check
        if (-not (Test-IsAdmin)) { throw "Moet als Administrator runnen" }
        
        # Remote Info - Use settings with fallback check
        Write-Host "Remote Computer IP/Hostname..." -ForegroundColor Cyan
        if ($Script:Settings.ContainsKey('serverIP') -and -not [string]::IsNullOrWhiteSpace($Script:Settings.serverIP) -and $Script:Settings.serverIP -ne 'jouw.server.ip.hier') {
            $computerName = $Script:Settings.serverIP
        }
        
        if (-not $computerName) {
            # Maybe prompt if missing (though user asked to use variable) - sticking to user request to NOT prompt if should be in variable, 
            # but usually it's better to fail or prompt if variable is missing/default.
            # Mirroring OpenVPN buffer: it throws error if invalid
            throw "Instelling 'serverIP' is leeg of ongeldig in Variable.psd1."
        }
        Write-Host "  ✓ Remote computer: $computerName" -ForegroundColor Green
        
        $cred = Get-Credential -Message "Admin Credentials voor $computerName"
        # Configure Local
        Write-Host "Genereren keys..."
        $serverKeys = Initialize-WireGuardKeys
        $clientKeys = Initialize-WireGuardKeys
        
        $wgPort = if ($Script:Settings.wireGuardPort) { $Script:Settings.wireGuardPort } else { 51820 }
        $baseSubnet = if ($Script:Settings.wireGuardBaseSubnet) { $Script:Settings.wireGuardBaseSubnet } else { "10.13.13" }
        $port = $wgPort
        
        if ($Script:Settings.ContainsKey('serverWanIP') -and -not [string]::IsNullOrWhiteSpace($Script:Settings.serverWanIP) -and $Script:Settings.serverWanIP -ne 'jouw.server.wan.ip.hier') {
            $wanIP = $Script:Settings.serverWanIP
        }

        if (-not $wanIP) {
            throw "Instelling 'serverWanIP' is leeg of ongeldig in Variable.psd1."
        }
        
        # Create Configs
        $serverConfPath = Join-Path $env:TEMP "wg_server_remote.conf"
        $serverConfContent = New-WireGuardServerConfig -ServerKeys $serverKeys -ClientKeys $clientKeys -Port $port -Address "$baseSubnet.1/24" -PeerAddress "$baseSubnet.2/32" -ServerType "Windows" -OutputPath $serverConfPath
        
        $clientConfPath = Join-Path $Script:OutputPath "wg-client-for-remote.conf"
        New-WireGuardClientConfig -ClientKeys $clientKeys -ServerKeys $serverKeys -ServerAvailableIP $wanIP -Port $port -Address "$baseSubnet.2/24" -OutputPath $clientConfPath
        
        # Install Remote
        if (Install-RemoteWireGuardServer -ComputerName $computerName -Credential $cred -ServerConfigContent $serverConfContent -RemoteConfigPath "C:\WireGuard" -Port $port) {
            Show-Menu -Mode Success -SuccessTitle "Remote WireGuard Server Setup Voltooid" -ExtraInfo "Client Config lokaal opgeslagen: $clientConfPath"
        }
    }
    catch {
        Write-Log "Fout: $_" -Level "ERROR"
        Show-Menu -Mode Error -SuccessTitle "Remote Setup Mislukt" -ExtraMessage $_
    }
}

function Invoke-RemoteWireGuardClientSetup {
    Write-Log "=== Remote WireGuard Client Setup Gestart ===" -Level "INFO"
    try {
        if (-not (Test-IsAdmin)) { throw "Moet als Administrator runnen" }
        
        # Remote Info
        Write-Host "Remote Computer IP/Hostname..." -ForegroundColor Cyan
        if ($Script:Settings.ContainsKey('remoteClientIP') -and -not [string]::IsNullOrWhiteSpace($Script:Settings.remoteClientIP) -and $Script:Settings.remoteClientIP -ne 'jouw.client.ip.hier') {
            $computerName = $Script:Settings.remoteClientIP
        }
        
        if (-not $computerName) {
            throw "Instelling 'remoteClientIP' is leeg of ongeldig in Variable.psd1."
        }
        Write-Host "  ✓ Remote computer: $computerName" -ForegroundColor Green
        
        $cred = Get-Credential -Message "Admin Credentials voor $computerName"
        
        $confPath = Read-Host "Pad naar .conf bestand"
        if (-not (Test-Path $confPath)) { throw "Bestand niet gevonden" }
        
        $content = Get-Content $confPath -Raw
        
        if (Install-RemoteWireGuardClient -ComputerName $computerName -Credential $cred -ClientConfigContent $content) {
            Show-Menu -Mode Success -SuccessTitle "Remote WireGuard Client Setup Voltooid"
        }
    }
    catch {
        Write-Log "Fout: $_" -Level "ERROR"
        Show-Menu -Mode Error -SuccessTitle "Remote Setup Mislukt" -ExtraMessage $_
    }
}

#endregion Remote WireGuard Functions

#endregion Server Setup functies





#region WireGuard Setup functies

########################################################################################################################
# WireGuard Setup functies
########################################################################################################################

function Invoke-WireGuardServerSetup {
    <#
    .SYNOPSIS
        Voert volledige WireGuard server setup uit.
    #>
    Write-Log "=== WireGuard Server Setup Gestart ===" -Level "INFO"
    
    try {
        # Stap 1: Admin check
        Write-Host "`n[1/6] Controleren administrator rechten..." -ForegroundColor Cyan
        if (-not (Test-IsAdmin)) { throw "Script moet als Administrator worden uitgevoerd!" }
        Write-Host "  ✓ Administrator rechten bevestigd" -ForegroundColor Green
        
        # Stap 2: Installeren
        Write-Host "`n[2/6] WireGuard installeren..." -ForegroundColor Cyan
        if (-not (Install-WireGuard)) { throw "WireGuard installatie mislukt" }
        Write-Host "  ✓ WireGuard geïnstalleerd" -ForegroundColor Green
        
        # Stap 3: Firewall
        $wgPort = if ($Script:Settings.wireGuardPort) { $Script:Settings.wireGuardPort } else { 51820 }
        $baseSubnet = if ($Script:Settings.wireGuardBaseSubnet) { $Script:Settings.wireGuardBaseSubnet } else { "10.13.13" }

        Write-Host "`n[3/6] Firewall configureren (UDP $wgPort)..." -ForegroundColor Cyan
        if (-not (Set-Firewall -Port $wgPort -Protocol "UDP")) { throw "Firewall configuratie mislukt" }
        Write-Host "  ✓ Firewall geconfigureerd" -ForegroundColor Green
        
        # Stap 4: Parameters en Keys
        Write-Host "`n[4/6] Configuratie en Keys genereren..." -ForegroundColor Cyan
        $serverWanIP = $Script:Settings.serverWanIP
        if (-not $serverWanIP -or $serverWanIP -eq "jouw.server.wan.ip.hier") {
            $serverWanIP = Read-Host "  Geef publieke IP of DNS van deze server op"
        }
        
        $serverKeys = Initialize-WireGuardKeys
        $clientKeys = Initialize-WireGuardKeys
        Write-Host "  ✓ Keys gegenereerd" -ForegroundColor Green
        
        # Stap 5: Configuraties maken
        Write-Host "`n[5/6] Configuraties aanmaken..." -ForegroundColor Cyan
        
        # Server config
        $wgConfigDir = "C:\Program Files\WireGuard\Data\Configurations" 
        if (-not (Test-Path $Script:ConfigPath)) { New-Item -ItemType Directory -Path $Script:ConfigPath -Force | Out-Null }
        $serverConfigPath = Join-Path $Script:ConfigPath "wg_server.conf"
        
        New-WireGuardServerConfig -ServerKeys $serverKeys -ClientKeys $clientKeys -Port $wgPort -Address "$baseSubnet.1/24" -PeerAddress "$baseSubnet.2/32" -ServerType "Windows" -OutputPath $serverConfigPath | Out-Null
        
        # Client config
        if (-not (Test-Path $Script:OutputPath)) { New-Item -ItemType Directory -Path $Script:OutputPath -Force | Out-Null }
        $clientConfigPath = Join-Path $Script:OutputPath "wg-client.conf"
        New-WireGuardClientConfig -ClientKeys $clientKeys -ServerKeys $serverKeys -ServerAvailableIP $serverWanIP -Port $wgPort -Address "$baseSubnet.2/24" -OutputPath $clientConfigPath | Out-Null
        
        Write-Host "  ✓ Configuraties aangemaakt" -ForegroundColor Green

        # Stap 6: Service starten
        Write-Host "`n[6/6] WireGuard Service starten..." -ForegroundColor Cyan
        if (-not (Start-WireGuardService -ConfigPath $serverConfigPath)) { throw "Starten service mislukt" }
        Write-Host "  ✓ Service gestart" -ForegroundColor Green
        
        Show-Menu -Mode Success -SuccessTitle "WireGuard Server Setup Voltooid!" -LogFile $script:LogFile -ExtraInfo "Client config is opgeslagen als: $clientConfigPath" -ExtraMessage "Kopieer dit bestand naar de client en importeer het in WireGuard."
        
    }
    catch {
        Write-Log "Fout tijdens WireGuard Setup: $($_.Exception.Message)" -Level "ERROR"
        Show-Menu -Mode Error -SuccessTitle "WireGuard Setup Gefaald!" -LogFile $script:LogFile -ExtraMessage $_
    }
}

function Invoke-WireGuardClientSetup {
    <#
    .SYNOPSIS
        Voert WireGuard client setup uit.
    #>
    Write-Log "=== WireGuard Client Setup Gestart ===" -Level "INFO"
    
    try {
        # Stap 1: Admin check
        Write-Host "`n[1/3] Controleren administrator rechten..." -ForegroundColor Cyan
        if (-not (Test-IsAdmin)) { throw "Script moet als Administrator worden uitgevoerd!" }
        
        # Stap 2: Installeren
        Write-Host "`n[2/3] WireGuard installeren..." -ForegroundColor Cyan
        if (-not (Install-WireGuard)) { throw "WireGuard installatie mislukt" }
        Write-Host "  ✓ WireGuard geïnstalleerd" -ForegroundColor Green
        
        # Stap 3: Config importeren / Service starten
        Write-Host "`n[3/3] Config importeren..." -ForegroundColor Cyan
        $configPath = Read-Host "  Sleep het .conf bestand hierheen of typ het pad"
        $configPath = $configPath.Trim('"') # Remove quotes
        
        if (-not (Test-Path $configPath)) { throw "Bestand niet gevonden: $configPath" }
        
        if (-not (Start-WireGuardService -ConfigPath $configPath)) { throw "Starten tunnel mislukt" }
        
        Write-Host "  ✓ Tunnel gestart" -ForegroundColor Green
        
        Show-Menu -Mode Success -SuccessTitle "WireGuard Client Setup Voltooid!" -LogFile $script:LogFile
        
    }
    catch {
        Write-Log "Fout tijdens WireGuard Client Setup: $_" -Level "ERROR"
        Show-Menu -Mode Error -SuccessTitle "WireGuard Client Setup Gefaald!" -LogFile $script:LogFile -ExtraMessage $_
    }
}

#endregion WireGuard Setup functies

# Start het script
Start-VPNSetup

# Stop transcript
Stop-Transcript