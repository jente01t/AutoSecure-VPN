# Orchestration logic for WireGuard setup
# Copy the full function definitions from main.ps1 to here.

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
function Invoke-RemoteWireGuardServerSetup {
    Write-Log "=== Remote WireGuard Server Setup Gestart ===" -Level "INFO"
    try {
        # Admin check
        if (-not (Test-IsAdmin)) { throw "Moet als Administrator runnen" }
        
        # Remote Info - Use settings with fallback check
        Write-Verbose "Remote computer IP/Hostname opvragen..."
        if ($Script:Settings.ContainsKey('serverIP') -and -not [string]::IsNullOrWhiteSpace($Script:Settings.serverIP) -and $Script:Settings.serverIP -ne 'jouw.server.ip.hier') {
            $computerName = $Script:Settings.serverIP
        }
        
        if (-not $computerName) {
            # Maybe prompt if missing (though user asked to use variable) - sticking to user request to NOT prompt if should be in variable, 
            # but usually it's better to fail or prompt if variable is missing/default.
            # Mirroring OpenVPN buffer: it throws error if invalid
            throw "Instelling 'serverIP' is leeg of ongeldig in Variable.psd1."
        }
        Write-Verbose "Remote computer: $computerName"
        
        $cred = Get-Credential -Message "Admin Credentials voor $computerName"
        # Configure Local
        Write-Verbose "Genereren keys..."
        Write-Verbose "Genereren server keys..."
        $serverKeys = Initialize-WireGuardKeys
        Write-Verbose "Genereren client keys..."
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
        Write-Verbose "Aanmaken configuraties..."
        Write-Verbose "Aanmaken server config..."
        $serverConfPath = Join-Path $env:TEMP "wg_server_remote.conf"
        $serverConfContent = New-WireGuardServerConfig -ServerKeys $serverKeys -ClientKeys $clientKeys -Port $port -Address "$baseSubnet.1/24" -PeerAddress "$baseSubnet.2/32" -ServerType "Windows" -OutputPath $serverConfPath
        
        Write-Verbose "Aanmaken client config..."
        $clientConfPath = Join-Path $Script:OutputPath "wg-client.conf"
        $clientConfigContent = New-WireGuardClientConfig -ClientKeys $clientKeys -ServerKeys $serverKeys -ServerAvailableIP $wanIP -Port $port -Address "$baseSubnet.2/24" -OutputPath $clientConfPath
        
        # QR-code maken
        $qrPath = Join-Path $Script:OutputPath "wg-client-qr.png"
        New-WireGuardQRCode -ConfigContent $clientConfigContent -OutputPath $qrPath
        
        # Install Remote
        Write-Verbose "Starten remote installatie..."
        if (Install-RemoteWireGuardServer -ComputerName $computerName -Credential $cred -ServerConfigContent $serverConfContent -RemoteConfigPath "C:\WireGuard" -Port $port) {
            Show-Menu -Mode Success -SuccessTitle "Remote WireGuard Server Setup Voltooid" -ExtraInfo "Client Config lokaal opgeslagen: $clientConfPath`nQR-code: $qrPath"
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
        Write-Verbose "Remote computer IP/Hostname opvragen..."
        if ($Script:Settings.ContainsKey('remoteClientIP') -and -not [string]::IsNullOrWhiteSpace($Script:Settings.remoteClientIP) -and $Script:Settings.remoteClientIP -ne 'jouw.client.ip.hier') {
            $computerName = $Script:Settings.remoteClientIP
        }
        
        if (-not $computerName) {
            throw "Instelling 'remoteClientIP' is leeg of ongeldig in Variable.psd1."
        }
        Write-Verbose "Remote computer: $computerName"
        
        $cred = Get-Credential -Message "Admin Credentials voor $computerName"
        
        Write-Verbose "Pad naar .conf bestand opvragen..."
        $confPath = Read-Host "Pad naar .conf bestand"
        Write-Verbose "Pad ingevoerd: $confPath"
        if (-not (Test-Path $confPath)) { throw "Bestand niet gevonden: $confPath" }
        
        Write-Verbose "Inhoud van config lezen..."
        $content = Get-Content $confPath -Raw
        Write-Verbose "Config inhoud gelezen, lengte: $($content.Length)"
        
        Write-Verbose "Starten remote client installatie..."
        if (Install-RemoteWireGuardClient -ComputerName $computerName -Credential $cred -ClientConfigContent $content) {
            Show-Menu -Mode Success -SuccessTitle "Remote WireGuard Client Setup Voltooid"
        }
    }
    catch {
        Write-Log "Fout: $_" -Level "ERROR"
        Show-Menu -Mode Error -SuccessTitle "Remote Setup Mislukt" -ExtraMessage $_
    }
}
