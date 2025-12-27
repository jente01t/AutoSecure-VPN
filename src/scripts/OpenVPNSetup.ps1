# Orchestration logic for OpenVPN setup
# Copy the full function definitions from main.ps1 to here.

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
        
        # Stap 3.5: NAT en IP Forwarding configureren voor internet toegang
        Write-Progress -Activity "Server Setup" -Status "Stap 3.5 van 9: NAT en IP Forwarding configureren" -PercentComplete 31
        Write-Host "`n[3.5/9] NAT en IP Forwarding configureren..." -ForegroundColor Cyan
        if (-not (Enable-VPNNAT -VPNSubnet "10.8.0.0/24")) { 
            Write-Host "  ! NAT configuratie warning - mogelijk handmatige configuratie nodig" -ForegroundColor Yellow
            Write-Log "NAT configuratie warning - handmatige setup mogelijk nodig" -Level "WARNING"
        }
        else {
            Write-Host "  ✓ NAT en IP Forwarding geconfigureerd" -ForegroundColor Green
        }
        
        # Stap 4: Gebruikersinput verzamelen
        Write-Progress -Activity "Server Setup" -Status "Stap 4 van 9: Server configuratie parameters verzamelen" -PercentComplete 37.5
        Write-Host "`n[4/9] Server configuratie parameters..." -ForegroundColor Cyan
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
        $zipPath = New-ClientPackage -Config $serverConfig -EasyRSAPath $script:EasyRSAPath -OutputPath $Script:OutputPath
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
        Write-Verbose "Lokale administrator rechten succesvol gecontroleerd"
        Write-Log "Administrator rechten bevestigd" -Level "INFO"
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
        $zipPath = New-ClientPackage -Config $serverConfig -EasyRSAPath $script:EasyRSAPath -OutputPath $Script:OutputPath
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
