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
$logsPath = Join-Path $Script:BasePath "logs"
if (-not (Test-Path $logsPath)) {
    New-Item -ItemType Directory -Path $logsPath -Force
}
$script:LogFile = Join-Path $logsPath $Script:Settings.logFileName
$script:ConfigPath = $Script:Settings.configPath
$script:EasyRSAPath = $Script:Settings.easyRSAPath

# Start transcript voor logging
$transcriptPath = Join-Path $logsPath $Script:Settings.transcriptFileName
Start-Transcript -Path $transcriptPath -Append -NoClobber

# Hoofdfunctie
#region Menu en UI functies

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
    Write-Host "`n╔════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║   OpenVPN Automatische Setup v1.0          ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Kies een optie:" -ForegroundColor Yellow
    Write-Host "  [1] Server Setup" -ForegroundColor Green
    Write-Host "  [2] Client Setup" -ForegroundColor Green
    Write-Host "  [3] Afsluiten" -ForegroundColor Red
    Write-Host ""
    
    $choice = Read-Host "Voer uw keuze in (1-3)"
    
    switch ($choice) {
        "1" {
            Write-Host "`n[*] Server Setup geselecteerd..." -ForegroundColor Cyan
            Select-ServerMode
        }
        "2" {
            Write-Host "`n[*] Client Setup geselecteerd..." -ForegroundColor Cyan
            Select-ClientMode
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

function Select-ServerMode {
    <#
    .SYNOPSIS
        Toont submenu voor server setup keuze (lokaal of remote).

    .DESCRIPTION
        Deze functie toont een submenu voor het kiezen tussen lokale of remote server setup.

    .EXAMPLE
        Select-ServerMode
    #>
    
    Write-Host "`nServer Setup Opties:" -ForegroundColor Yellow
    Write-Host "  [1] Lokaal (VPN-server installeren en configureren op deze machine)" -ForegroundColor Green
    Write-Host "  [2] Remote (VPN-server installeren en configureren op afstand)" -ForegroundColor Green
    Write-Host "  [3] Terug naar hoofdmenu" -ForegroundColor Red
    Write-Host ""
    
    $choice = Read-Host "Voer uw keuze in (1-3)"
    
    switch ($choice) {
        "1" {
            Write-Host "`n[*] Lokale Server Setup geselecteerd..." -ForegroundColor Cyan
            Invoke-ServerSetup
        }
        "2" {
            Write-Host "`n[*] Remote Server Setup geselecteerd..." -ForegroundColor Cyan
            Invoke-RemoteServerSetup
        }
        "3" {
            Write-Host "`n[*] Terug naar hoofdmenu..." -ForegroundColor Yellow
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
    
    Write-Host "`nClient Setup Opties:" -ForegroundColor Yellow
    Write-Host "  [1] Lokaal (VPN-client installeren en verbinden op deze machine)" -ForegroundColor Green
    Write-Host "  [2] Remote (VPN-client installeren en verbinden op afstand)" -ForegroundColor Green
    Write-Host "  [3] Batch Remote (VPN-client installeren op meerdere machines)" -ForegroundColor Green
    Write-Host "  [4] Terug naar hoofdmenu" -ForegroundColor Red
    Write-Host ""
    
    $choice = Read-Host "Voer uw keuze in (1-4)"
    
    switch ($choice) {
        "1" {
            Write-Host "`n[*] Lokale Client Setup geselecteerd..." -ForegroundColor Cyan
            Invoke-ClientSetup
        }
        "2" {
            Write-Host "`n[*] Remote Client Setup geselecteerd..." -ForegroundColor Cyan
            Invoke-RemoteClientSetup
        }
        "3" {
            Write-Host "`n[*] Batch Remote Client Setup geselecteerd..." -ForegroundColor Cyan
            Invoke-BatchRemoteClientSetup
        }
        "4" {
            Write-Host "`n[*] Terug naar hoofdmenu..." -ForegroundColor Yellow
            Start-VPNSetup
        }
        default {
            Write-Host "`n[!] Ongeldige keuze. Probeer opnieuw." -ForegroundColor Red
            Start-Sleep -Seconds 2
            Select-ClientMode
        }
    }
}

#endregion Menu en UI functies



#region Client Setup functies

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
        Write-Progress -Activity "Client Setup" -Status "Stap 1 van 6: Controleren administrator rechten" -PercentComplete 0
        Write-Host "`n[1/6] Controleren administrator rechten..." -ForegroundColor Cyan
        if (-not (Test-IsAdmin)) {
            throw "Script moet als Administrator worden uitgevoerd!"
        }
        Write-Host "  ✓ Administrator rechten bevestigd" -ForegroundColor Green
        Write-Verbose "Administrator rechten succesvol gecontroleerd"
        
        # Stap 2: OpenVPN installeren
        Write-Progress -Activity "Client Setup" -Status "Stap 2 van 6: OpenVPN installeren" -PercentComplete 16.67
        Write-Host "`n[2/6] OpenVPN installeren..." -ForegroundColor Cyan
        if (-not (Install-OpenVPN)) {
            throw "OpenVPN installatie mislukt"
        }
        Write-Host "  ✓ OpenVPN geïnstalleerd" -ForegroundColor Green
        Write-Verbose "OpenVPN succesvol geïnstalleerd"
        
        # Stap 3: Client configuratie importeren
        Write-Progress -Activity "Client Setup" -Status "Stap 3 van 6: Client configuratie importeren" -PercentComplete 33.33
        Write-Host "`n[3/6] Client configuratie importeren..." -ForegroundColor Cyan
        $configPath = Import-ClientConfiguration
        if (-not $configPath) {
            throw "Client configuratie importeren mislukt"
        }
        Write-Host "  ✓ Configuratie geïmporteerd" -ForegroundColor Green
        Write-Verbose "Client configuratie succesvol geïmporteerd van $configPath"
        
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
        }
        
        # Stap 5: VPN verbinding starten
        Write-Progress -Activity "Client Setup" -Status "Stap 5 van 6: VPN verbinding starten" -PercentComplete 66.67
        Write-Host "`n[5/6] VPN verbinding starten..." -ForegroundColor Cyan
        if (-not (Start-VPNConnection -ConfigFile $configPath)) {
            throw "VPN verbinding starten mislukt"
        }
        Write-Host "  ✓ VPN verbinding gestart" -ForegroundColor Green
        Write-Verbose "VPN verbinding succesvol gestart"
        
        # Stap 6: Verbinding testen
        Write-Progress -Activity "Client Setup" -Status "Stap 6 van 6: VPN verbinding testen" -PercentComplete 83.33
        Write-Host "`n[6/6] VPN verbinding testen..." -ForegroundColor Cyan
        Start-Sleep -Seconds 30  # Wacht langer tot verbinding volledig is opgezet
        $testResult = Test-VPNConnection
        if (-not $testResult) {
            throw "VPN verbinding test mislukt"
        }
        Write-Verbose "VPN verbinding succesvol getest"
        
        Write-Progress -Activity "Client Setup" -Completed
        
        Write-Host "`n╔════════════════════════════════════════════╗" -ForegroundColor Green
        Write-Host "║     Client Setup Succesvol Voltooid!      ║" -ForegroundColor Green
        Write-Host "╚════════════════════════════════════════════╝" -ForegroundColor Green
        Write-Host "`nLogbestand: $script:LogFile" -ForegroundColor Yellow
        
        Write-Log "Client setup succesvol voltooid" -Level "SUCCESS"
    }
    catch {
        Write-Progress -Activity "Client Setup" -Completed
        Write-Host "`n[!] FOUT tijdens client setup: $_" -ForegroundColor Red
        Write-Log "Client setup FOUT: $_" -Level "ERROR"
        Write-Host "`nControleer het logbestand voor details: $script:LogFile" -ForegroundColor Yellow
        
        # Rollback uitvoeren
        Write-Host "`n[*] Rollback uitvoeren om wijzigingen ongedaan te maken..." -ForegroundColor Yellow
        Invoke-Rollback -SetupType "Client"
        
        Read-Host "`nDruk op Enter om door te gaan"
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
        Write-Progress -Activity "Remote Client Setup" -Status "Stap 1 van 5: Controleren administrator rechten" -PercentComplete 0
        Write-Host "`n[1/5] Controleren administrator rechten..." -ForegroundColor Cyan
        if (-not (Test-IsAdmin)) {
            throw "Script moet als Administrator worden uitgevoerd!"
        }
        Write-Host "  ✓ Administrator rechten bevestigd" -ForegroundColor Green
        Write-Verbose "Lokale administrator rechten succesvol gecontroleerd"
        
        # Stap 2: Remote computer details
        Write-Progress -Activity "Remote Client Setup" -Status "Stap 2 van 5: Remote computer configuratie" -PercentComplete 20
        Write-Host "`n[2/5] Remote computer configuratie..." -ForegroundColor Cyan
        $computerName = Read-Host "  Voer de naam of IP van de remote computer in"
        if ([string]::IsNullOrWhiteSpace($computerName)) {
            throw "Remote computer naam is verplicht"
        }
        Write-Host "  ✓ Remote computer: $computerName" -ForegroundColor Green
        Write-Verbose "Remote computer naam ingevoerd: $computerName"
        
        # Stap 3: WinRM configuratie
        Write-Progress -Activity "Remote Client Setup" -Status "Stap 3 van 5: WinRM configuratie controleren" -PercentComplete 40
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
            Write-Verbose "TrustedHosts bijgewerkt en WinRM herstart"
        } elseif ($trustedHosts -eq "*") {
            Write-Host "  ✓ TrustedHosts staat op wildcard (*), geen toevoeging nodig" -ForegroundColor Green
            Write-Verbose "TrustedHosts staat op wildcard"
        } else {
            Write-Host "  ✓ $computerName staat al in TrustedHosts" -ForegroundColor Green
            Write-Verbose "$computerName staat al in TrustedHosts"
        }
        
        Write-Host "  Controleren of PSRemoting actief is op remote machine..." -ForegroundColor Cyan
        try {
            Test-WSMan -ComputerName $computerName -ErrorAction Stop | Out-Null
            Write-Host "  ✓ PSRemoting is actief op $computerName" -ForegroundColor Green
            Write-Verbose "PSRemoting succesvol getest op $computerName"
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
        
        # Stap 5: Client ZIP bestand
        Write-Progress -Activity "Remote Client Setup" -Status "Stap 5 van 5: Client configuratie bestand" -PercentComplete 80
        Write-Host "`n[5/5] Client configuratie bestand..." -ForegroundColor Cyan
        $defaultZipPath = Join-Path $PSScriptRoot "..\$($Script:Settings.outputPath)\vpn-client-$($Script:Settings.clientNameDefault).zip"
        if (Test-Path $defaultZipPath) {
            $zipPath = $defaultZipPath
            Write-Host "  ✓ Standaard client ZIP bestand gevonden: $zipPath" -ForegroundColor Green
            Write-Verbose "Standaard client ZIP bestand gebruikt: $zipPath"
        } else {
            Write-Host "  Standaard client ZIP bestand niet gevonden op $defaultZipPath" -ForegroundColor Yellow
            $zipPath = Read-Host "  Pad naar client ZIP bestand (gegenereerd door server setup)"
            Write-Verbose "Handmatig ZIP pad ingevoerd: $zipPath"
        }
        if (-not (Test-Path $zipPath)) {
            throw "ZIP bestand niet gevonden: $zipPath"
        }
        Write-Host "  ✓ ZIP bestand gevonden: $zipPath" -ForegroundColor Green
        
        # Remote installatie uitvoeren
        Write-Progress -Activity "Remote Client Setup" -Status "Remote installatie uitvoeren" -PercentComplete 90
        Write-Host "`n[*] Remote installatie starten..." -ForegroundColor Cyan
        if (-not (Install-RemoteClient -ComputerName $computerName -Credential $cred -ZipPath $zipPath)) {
            throw "Remote client installatie mislukt"
        }
        Write-Host "  ✓ Remote installatie voltooid" -ForegroundColor Green
        Write-Verbose "Remote client installatie succesvol voltooid voor $computerName"
        
        Write-Progress -Activity "Remote Client Setup" -Completed
        
        Write-Host "`n╔════════════════════════════════════════════╗" -ForegroundColor Green
        Write-Host "║  Remote Client Setup Succesvol Voltooid!  ║" -ForegroundColor Green
        Write-Host "╚════════════════════════════════════════════╝" -ForegroundColor Green
        Write-Host "`nLogbestand: $script:LogFile" -ForegroundColor Yellow
        Write-Host "`nOp de remote machine kun je nu de VPN verbinding starten via OpenVPN." -ForegroundColor Cyan
        
        Write-Log "Remote client setup succesvol voltooid voor $computerName" -Level "SUCCESS"
    }
    catch {
        Write-Progress -Activity "Remote Client Setup" -Completed
        Write-Host "`n[!] FOUT tijdens remote client setup: $_" -ForegroundColor Red
        Write-Log "Remote client setup FOUT: $_" -Level "ERROR"
        Write-Host "`nControleer het logbestand voor details: $script:LogFile" -ForegroundColor Yellow
        
        Read-Host "`nDruk op Enter om door te gaan"
    }
}

function Invoke-BatchRemoteClientSetup {
    <#
    .SYNOPSIS
        Voert batch remote VPN-client setup uit voor meerdere computers.

    .DESCRIPTION
        Deze functie leest een CSV-bestand met computer details en voert remote client setup uit voor elke computer parallel.

    .EXAMPLE
        Invoke-BatchRemoteClientSetup
    #>
    
    Write-Log "=== Batch Remote Client Setup Gestart ===" -Level "INFO"
    
    try {
        # Stap 1: CSV bestand vragen
        Write-Progress -Activity "Batch Remote Client Setup" -Status "Stap 1 van 4: CSV bestand selecteren" -PercentComplete 0
        Write-Host "`n[1/4] CSV bestand selecteren..." -ForegroundColor Cyan
        $csvPath = Read-Host "  Voer het pad naar het CSV bestand in (bijv. C:\clients.csv)"
        if (-not (Test-Path $csvPath)) {
            throw "CSV bestand niet gevonden: $csvPath"
        }
        Write-Host "  ✓ CSV bestand gevonden: $csvPath" -ForegroundColor Green
        Write-Verbose "CSV bestand pad: $csvPath"
        
        # Stap 2: Client ZIP bestand vragen
        Write-Progress -Activity "Batch Remote Client Setup" -Status "Stap 2 van 4: Client ZIP bestand selecteren" -PercentComplete 25
        Write-Host "`n[2/4] Client ZIP bestand selecteren..." -ForegroundColor Cyan
        $zipPath = Read-Host "  Voer het pad naar het client ZIP bestand in (bijv. C:\output\client.zip)"
        if (-not (Test-Path $zipPath)) {
            throw "Client ZIP bestand niet gevonden: $zipPath"
        }
        Write-Host "  ✓ Client ZIP bestand gevonden: $zipPath" -ForegroundColor Green
        Write-Verbose "Client ZIP bestand pad: $zipPath"
        
        # Stap 3: CSV inlezen
        Write-Progress -Activity "Batch Remote Client Setup" -Status "Stap 3 van 4: CSV bestand inlezen" -PercentComplete 50
        Write-Host "`n[3/4] CSV bestand inlezen..." -ForegroundColor Cyan
        $clients = Import-Csv -Path $csvPath
        Write-Host "  ✓ $($clients.Count) clients gevonden" -ForegroundColor Green
        Write-Verbose "Clients: $($clients | ConvertTo-Json)"
        
        # Stap 4: Parallel uitvoeren
        Write-Progress -Activity "Batch Remote Client Setup" -Status "Stap 4 van 4: Remote setups uitvoeren" -PercentComplete 75
        Write-Host "`n[4/4] Remote client setups uitvoeren..." -ForegroundColor Cyan
        
        $totalClients = $clients.Count
        # Adaptieve ThrottleLimit gebaseerd op systeemresources
        $cpuCores = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
        $throttleLimit = [math]::Min([math]::Max(1, $cpuCores - 1), 10)  # Gebruik max 10, minimaal 1, en 1 minder dan totaal cores
        
        Write-Host "  Systeem heeft $cpuCores CPU cores, ThrottleLimit ingesteld op $throttleLimit" -ForegroundColor Cyan
        
        # Parallel uitvoering met Foreach-Object -Parallel
        $results = $clients | ForEach-Object -Parallel {
            $client = $_
            $name = $client.Name
            $ip = $client.IP
            $username = $client.Username
            $password = $client.Password
            
            # Maak credential object
            $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
            $cred = New-Object System.Management.Automation.PSCredential ($username, $securePassword)
            
            # Import module in parallel runspace
            Import-Module $using:ModulePath -Force
            
            # Stel settings in
            Set-ModuleSettings -Settings $using:Script:Settings -BasePath $using:Script:BasePath
            
            # Voer remote client installatie uit
            try {
                $result = Install-RemoteClient -ComputerName $ip -Credential $cred -ZipPath $using:zipPath
                if ($result) {
                    "SUCCESS: $name ($ip)"
                } else {
                    "ERROR: $name ($ip) - Installation failed"
                }
            }
            catch {
                "ERROR: $name ($ip) - $_"
            }
        } -ThrottleLimit $throttleLimit  # Beperk tot $throttleLimit parallelle uitvoeringen om resources te sparen
        
        Write-Progress -Activity "Batch Remote Client Setup" -Completed
        
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
        
        Write-Progress -Activity "Batch Remote Client Setup" -Completed
        
        # Resultaten tonen
        Write-Host "`nResultaten:" -ForegroundColor Yellow
        $successCount = 0
        foreach ($result in $results) {
            if ($result -like "SUCCESS:*") {
                Write-Host "  ✓ $($result -replace 'SUCCESS: ', '')" -ForegroundColor Green
                $successCount++
            }
            else {
                Write-Host "  ✗ $($result -replace 'ERROR: ', '')" -ForegroundColor Red
            }
        }
        
        if ($successCount -eq $totalClients) {
            Write-Host "`n╔════════════════════════════════════════════╗" -ForegroundColor Green
            Write-Host "║   Batch Remote Client Setup Succesvol!    ║" -ForegroundColor Green
            Write-Host "╚════════════════════════════════════════════╝" -ForegroundColor Green
            Write-Host "`nLogbestand: $script:LogFile" -ForegroundColor Yellow
            Write-Log "Batch remote client setup succesvol voltooid ($successCount/$totalClients)" -Level "SUCCESS"
        }
        else {
            Write-Host "`n╔════════════════════════════════════════════╗" -ForegroundColor Red
            Write-Host "║   Batch Remote Client Setup Gefaald!      ║" -ForegroundColor Red
            Write-Host "╚════════════════════════════════════════════╝" -ForegroundColor Red
            Write-Host "`n$successCount van $totalClients setups succesvol." -ForegroundColor Yellow
            Write-Host "Logbestand: $script:LogFile" -ForegroundColor Yellow
            Write-Log "Batch remote client setup gefaald ($successCount/$totalClients succesvol)" -Level "ERROR"
        }
    }
    catch {
        Write-Progress -Activity "Batch Remote Client Setup" -Completed
        Write-Host "`n[!] FOUT tijdens batch remote client setup: $_" -ForegroundColor Red
        Write-Log "Batch remote client setup FOUT: $_" -Level "ERROR"
        Write-Host "`nControleer het logbestand voor details: $script:LogFile" -ForegroundColor Yellow
        
        Read-Host "`nDruk op Enter om door te gaan"
    }
}

#endregion Client Setup functies

#region Server Setup functies

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
        Write-Progress -Activity "Server Setup" -Status "Stap 1 van 8: Controleren administrator rechten" -PercentComplete 0
        Write-Host "`n[1/8] Controleren administrator rechten..." -ForegroundColor Cyan
        if (-not (Test-IsAdmin)) {
            throw "Script moet als Administrator worden uitgevoerd!"
        }
        Write-Host "  ✓ Administrator rechten bevestigd" -ForegroundColor Green
        Write-Verbose "Administrator rechten succesvol gecontroleerd"
        
        # Stap 2: OpenVPN installeren
        Write-Progress -Activity "Server Setup" -Status "Stap 2 van 8: OpenVPN installeren" -PercentComplete 12.5
        Write-Host "`n[2/8] OpenVPN installeren..." -ForegroundColor Cyan
        if (-not (Install-OpenVPN)) {
            throw "OpenVPN installatie mislukt"
        }
        Write-Host "  ✓ OpenVPN geïnstalleerd" -ForegroundColor Green
        Write-Verbose "OpenVPN succesvol geïnstalleerd"
        
        # Stap 3: Firewall configureren
        Write-Progress -Activity "Server Setup" -Status "Stap 3 van 8: Windows Firewall configureren" -PercentComplete 25
        Write-Host "`n[3/8] Windows Firewall configureren..." -ForegroundColor Cyan
        if (-not (Set-Firewall -Port 443 -Protocol "TCP")) {
            throw "Firewall configuratie mislukt"
        }
        Write-Host "  ✓ Firewall regels toegevoegd" -ForegroundColor Green
        Write-Verbose "Firewall regels succesvol toegevoegd"
        
        # Stap 4: Gebruikersinput verzamelen
        Write-Progress -Activity "Server Setup" -Status "Stap 4 van 8: Server configuratie parameters verzamelen" -PercentComplete 37.5
        Write-Host "`n[4/8] Server configuratie parameters..." -ForegroundColor Cyan
        $serverConfig = Get-ServerConfiguration
        Write-Verbose "Server configuratie parameters verzameld: $($serverConfig | ConvertTo-Json)"
        
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
        
        # Stap 6: Server configuratie genereren
        Write-Progress -Activity "Server Setup" -Status "Stap 6 van 8: Server configuratie aanmaken" -PercentComplete 62.5
        Write-Host "`n[6/8] Server configuratie aanmaken..." -ForegroundColor Cyan
        if (-not (New-ServerConfig -Config $serverConfig -EasyRSAPath $script:EasyRSAPath -ConfigPath $script:ConfigPath)) {
            throw "Server configuratie generatie mislukt"
        }
        Write-Host "  ✓ Server configuratie aangemaakt" -ForegroundColor Green
        Write-Verbose "Server configuratie succesvol aangemaakt"
        
        # Stap 7: OpenVPN service starten
        Write-Progress -Activity "Server Setup" -Status "Stap 7 van 8: OpenVPN service starten" -PercentComplete 75
        Write-Host "`n[7/8] OpenVPN service starten..." -ForegroundColor Cyan
        if (-not (Start-VPNService)) {
            throw "OpenVPN service starten mislukt"
        }
        Write-Host "  ✓ OpenVPN service actief" -ForegroundColor Green
        Write-Verbose "OpenVPN service succesvol gestart"
        
        # Stap 8: Client package maken
        Write-Progress -Activity "Server Setup" -Status "Stap 8 van 8: Client configuratie package maken" -PercentComplete 87.5
        Write-Host "`n[8/8] Client configuratie package maken..." -ForegroundColor Cyan
        $zipPath = New-ClientPackage -Config $serverConfig -EasyRSAPath $script:EasyRSAPath -OutputPath (Join-Path $PSScriptRoot "..\output")
        if (-not $zipPath) {
            throw "Client package aanmaken mislukt"
        }
        Write-Host "  ✓ Client package aangemaakt: $zipPath" -ForegroundColor Green
        Write-Verbose "Client package succesvol aangemaakt: $zipPath"
        
        Write-Progress -Activity "Server Setup" -Completed
        
        Write-Host "`n╔════════════════════════════════════════════╗" -ForegroundColor Green
        Write-Host "║     Server Setup Succesvol Voltooid!      ║" -ForegroundColor Green
        Write-Host "╚════════════════════════════════════════════╝" -ForegroundColor Green
        Write-Host "`nLogbestand: $script:LogFile" -ForegroundColor Yellow
        Write-Host "Client package: $zipPath" -ForegroundColor Yellow
        Write-Host "`nDit ZIP-bestand naar de client overzetten om de verbinding te maken." -ForegroundColor Cyan
        
        Write-Log "Server setup succesvol voltooid" -Level "SUCCESS"
    }
    catch {
        Write-Progress -Activity "Server Setup" -Completed
        Write-Host "`n[!] FOUT tijdens server setup: $_" -ForegroundColor Red
        Write-Log "Server setup FOUT: $_" -Level "ERROR"
        Write-Host "`nControleer het logbestand voor details: $script:LogFile" -ForegroundColor Yellow
        
        # Rollback uitvoeren
        Write-Host "`n[*] Rollback uitvoeren om wijzigingen ongedaan te maken..." -ForegroundColor Yellow
        Invoke-Rollback -SetupType "Server"
        
        Read-Host "`nDruk op Enter om door te gaan"
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
        Write-Progress -Activity "Remote Server Setup" -Status "Stap 1 van 7: Controleren administrator rechten" -PercentComplete 0
        Write-Host "`n[1/7] Controleren administrator rechten..." -ForegroundColor Cyan
        if (-not (Test-IsAdmin)) {
            throw "Script moet als Administrator worden uitgevoerd!"
        }
        Write-Host "  ✓ Administrator rechten bevestigd" -ForegroundColor Green
        Write-Verbose "Lokale administrator rechten succesvol gecontroleerd"
        
        # Stap 1.5: Controleer lokale OpenVPN installatie
        Write-Progress -Activity "Remote Server Setup" -Status "Stap 1.5 van 7: Lokale OpenVPN installatie controleren" -PercentComplete 7
        if (-not (Test-Path $Script:Settings.installedPath)) {
            Write-Host "`n[1.5] OpenVPN lokaal installeren voor certificaat generatie..." -ForegroundColor Cyan
            if (-not (Install-OpenVPN)) {
                throw "Lokale OpenVPN installatie mislukt"
            }
            Write-Host "  ✓ OpenVPN lokaal geïnstalleerd" -ForegroundColor Green
            Write-Verbose "OpenVPN lokaal geïnstalleerd voor certificaat generatie"
        } else {
            Write-Verbose "OpenVPN al lokaal geïnstalleerd"
        }
        
        # Stap 2: Remote computer details
        Write-Progress -Activity "Remote Server Setup" -Status "Stap 2 van 7: Remote computer configuratie" -PercentComplete 14
        Write-Host "`n[2/7] Remote computer configuratie..." -ForegroundColor Cyan
        $computerName = Read-Host "  Voer de naam of IP van de remote computer in"
        if ([string]::IsNullOrWhiteSpace($computerName)) {
            throw "Remote computer naam is verplicht"
        }
        Write-Host "  ✓ Remote computer: $computerName" -ForegroundColor Green
        Write-Verbose "Remote computer naam ingevoerd: $computerName"
        
        # Stap 3: WinRM configuratie
        Write-Progress -Activity "Remote Server Setup" -Status "Stap 3 van 7: WinRM configuratie controleren" -PercentComplete 21
        Write-Host "`n[3/7] WinRM configuratie controleren..." -ForegroundColor Cyan
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
            Write-Verbose "TrustedHosts bijgewerkt en WinRM herstart"
        } elseif ($trustedHosts -eq "*") {
            Write-Host "  ✓ TrustedHosts staat op wildcard (*), geen toevoeging nodig" -ForegroundColor Green
            Write-Verbose "TrustedHosts staat op wildcard"
        } else {
            Write-Host "  ✓ $computerName staat al in TrustedHosts" -ForegroundColor Green
            Write-Verbose "$computerName staat al in TrustedHosts"
        }
        
        Write-Host "  Controleren of PSRemoting actief is op remote machine..." -ForegroundColor Cyan
        try {
            Test-WSMan -ComputerName $computerName -ErrorAction Stop | Out-Null
            Write-Host "  ✓ PSRemoting actief op $computerName" -ForegroundColor Green
            Write-Verbose "PSRemoting succesvol getest op $computerName"
        } catch {
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
        
        # Stap 5: Server configuratie verkrijgen
        Write-Progress -Activity "Remote Server Setup" -Status "Stap 5 van 7: Server configuratie verkrijgen" -PercentComplete 36
        Write-Host "`n[5/7] Server configuratie..." -ForegroundColor Cyan
        $serverConfig = Get-ServerConfiguration
        Write-Host "  ✓ Server configuratie verkregen" -ForegroundColor Green
        Write-Verbose "Server configuratie verkregen: $($serverConfig | ConvertTo-Json)"
        
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
        
        # Remote installatie uitvoeren
        Write-Progress -Activity "Remote Server Setup" -Status "Remote server installatie uitvoeren" -PercentComplete 57
        Write-Host "`n[*] Remote server installatie starten..." -ForegroundColor Cyan
        if (-not (Install-RemoteServer -ComputerName $computerName -Credential $cred -ServerConfig $serverConfig -LocalEasyRSAPath $localEasyRSA)) {
            throw "Remote server installatie mislukt"
        }
        Write-Host "  ✓ Remote installatie voltooid" -ForegroundColor Green
        Write-Verbose "Remote server installatie succesvol voltooid voor $computerName"
        
        # Stap 7: Client package maken
        Write-Progress -Activity "Remote Server Setup" -Status "Stap 7 van 7: Client configuratie package maken" -PercentComplete 86
        Write-Host "`n[7/7] Client configuratie package maken..." -ForegroundColor Cyan
        $zipPath = New-ClientPackage -Config $serverConfig -EasyRSAPath $script:EasyRSAPath -OutputPath (Join-Path $PSScriptRoot "..\output")
        if (-not $zipPath) {
            throw "Client package aanmaken mislukt"
        }
        Write-Host "  ✓ Client package aangemaakt: $zipPath" -ForegroundColor Green
        Write-Verbose "Client package succesvol aangemaakt: $zipPath"
        
        Write-Progress -Activity "Remote Server Setup" -Completed
        
        Write-Host "`n╔════════════════════════════════════════════╗" -ForegroundColor Green
        Write-Host "║  Remote Server Setup Succesvol Voltooid!  ║" -ForegroundColor Green
        Write-Host "╚════════════════════════════════════════════╝" -ForegroundColor Green
        Write-Host "`nLogbestand: $script:LogFile" -ForegroundColor Yellow
        Write-Host "`nDe VPN server draait nu op de remote machine." -ForegroundColor Cyan
        Write-Host "Client package beschikbaar: $zipPath" -ForegroundColor Cyan
        
        Write-Log "Remote server setup succesvol voltooid voor $computerName" -Level "SUCCESS"
    }
    catch {
        Write-Progress -Activity "Remote Server Setup" -Completed
        Write-Host "`n[!] FOUT tijdens remote server setup: $_" -ForegroundColor Red
        Write-Log "Remote server setup FOUT: $_" -Level "ERROR"
        Write-Host "`nControleer het logbestand voor details: $script:LogFile" -ForegroundColor Yellow
        
        Read-Host "`nDruk op Enter om door te gaan"
    }
}

#endregion Server Setup functies




# Start het script
Start-VPNSetup

# Stop transcript
Stop-Transcript