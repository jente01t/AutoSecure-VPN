# Orchestration logic for WireGuard setup
# Copy the full function definitions from main.ps1 to here.

function Invoke-WireGuardClientSetup {
    <#
    .SYNOPSIS
        Performs WireGuard client setup.
    #>
    Write-Log "=== WireGuard Client Setup Started ===" -Level "INFO"
    
    try {
        # Step 1: Admin check
        Write-Host "`n[1/3] Checking administrator privileges..." -ForegroundColor Cyan
        if (-not (Test-IsAdmin)) { throw "Script must be run as Administrator!" }
        
        # Step 2: Install
        Write-Host "`n[2/3] Installing WireGuard..." -ForegroundColor Cyan
        if (-not (Install-WireGuard)) { throw "WireGuard installation failed" }
        Write-Host "  ✓ WireGuard installed" -ForegroundColor Green
        
        # Step 3: Import Config / Start Service
        Write-Host "`n[3/3] Importing config..." -ForegroundColor Cyan
        $configPath = Read-Host "  Drag the .conf file here or type the path"
        $configPath = $configPath.Trim('"') # Remove quotes
        
        if (-not (Test-Path $configPath)) { throw "File not found: $configPath" }
        
        if (-not (Start-WireGuardService -ConfigPath $configPath)) { throw "Starting tunnel failed" }
        
        Write-Host "  ✓ Tunnel started" -ForegroundColor Green
        
        Show-Menu -Mode Success -SuccessTitle "WireGuard Client Setup Completed!" -LogFile $script:LogFile
        
    }
    catch {
        Write-Log "Fout tijdens WireGuard Client Setup: $_" -Level "ERROR"
        Show-Menu -Mode Error -SuccessTitle "WireGuard Client Setup Gefaald!" -LogFile $script:LogFile -ExtraMessage $_
    }
}
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

        Write-Host "`n[3/7] Firewall configureren (UDP $wgPort)..." -ForegroundColor Cyan
        if (-not (Set-Firewall -Port $wgPort -Protocol "UDP")) { throw "Firewall configuratie mislukt" }
        Write-Host "  ✓ Firewall geconfigureerd" -ForegroundColor Green
        
        # Stap 3.5: NAT en IP Forwarding configureren voor internet toegang
        Write-Host "`n[3.5/7] NAT en IP Forwarding configureren..." -ForegroundColor Cyan
        if (-not (Enable-VPNNAT -VPNSubnet "$baseSubnet.0/24")) { 
            Write-Host "  ! NAT configuratie warning - mogelijk handmatige configuratie nodig" -ForegroundColor Yellow
            Write-Log "NAT configuratie warning - handmatige setup mogelijk nodig" -Level "WARNING"
        }
        else {
            Write-Host "  ✓ NAT en IP Forwarding geconfigureerd" -ForegroundColor Green
        }
        
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
        $clientConfigContent = New-WireGuardClientConfig -ClientKeys $clientKeys -ServerKeys $serverKeys -ServerAvailableIP $serverWanIP -Port $wgPort -Address "$baseSubnet.2/24" -OutputPath $clientConfigPath
        
        # QR-code maken
        $qrPath = Join-Path $Script:OutputPath "wg-client-qr.png"
        if (New-WireGuardQRCode -ConfigContent $clientConfigContent -OutputPath $qrPath) {
            Write-Host "  ✓ QR-code aangemaakt: $qrPath" -ForegroundColor Green
        }
        else {
            Write-Host "  ! QR-code maken mislukt" -ForegroundColor Yellow
        }
        
        Write-Host "  ✓ Configuraties aangemaakt" -ForegroundColor Green

        # Stap 6: Service starten
        Write-Host "`n[6/6] WireGuard Service starten..." -ForegroundColor Cyan
        if (-not (Start-WireGuardService -ConfigPath $serverConfigPath)) { throw "Starten service mislukt" }
        Write-Host "  ✓ Service gestart" -ForegroundColor Green
        
        Show-Menu -Mode Success -SuccessTitle "WireGuard Server Setup Voltooid!" -LogFile $script:LogFile -ExtraInfo "Client config: $clientConfigPath`nQR-code: $qrPath" -ExtraMessage "Kopieer het .conf bestand naar de client en importeer het in WireGuard, of scan de QR-code op mobiele apparaten."
        
    }
    catch {
        Write-Log "Fout tijdens WireGuard Setup: $($_.Exception.Message)" -Level "ERROR"
        Show-Menu -Mode Error -SuccessTitle "WireGuard Setup Gefaald!" -LogFile $script:LogFile -ExtraMessage $_
    }
}
function Invoke-RemoteWireGuardServerSetup {
    Write-Log "=== Remote WireGuard Server Setup Started ===" -Level "INFO"
    try {
        # Admin check
        if (-not (Test-IsAdmin)) { throw "Must be run as Administrator" }
        
        # Remote Info - Use settings with fallback check
        Write-Verbose "Requesting remote computer IP/Hostname..."
        if ($Script:Settings.ContainsKey('serverIP') -and -not [string]::IsNullOrWhiteSpace($Script:Settings.serverIP) -and $Script:Settings.serverIP -ne 'your.server.ip.here') {
            $computerName = $Script:Settings.serverIP
        }
        
        if (-not $computerName) {
            # Maybe prompt if missing (though user asked to use variable) - sticking to user request to NOT prompt if variable is missing/default.
            # Mirroring OpenVPN buffer: it throws error if invalid
            throw "Setting 'serverIP' is empty or invalid in Variable.psd1."
        }
        Write-Verbose "Remote computer: $computerName"
        
        $cred = Get-Credential -Message "Admin Credentials for $computerName"
        # Configure Local
        Write-Verbose "Generating keys..."
        Write-Verbose "Generating server keys..."
        $serverKeys = Initialize-WireGuardKeys
        Write-Verbose "Generating client keys..."
        $clientKeys = Initialize-WireGuardKeys
        
        $wgPort = if ($Script:Settings.wireGuardPort) { $Script:Settings.wireGuardPort } else { 51820 }
        $baseSubnet = if ($Script:Settings.wireGuardBaseSubnet) { $Script:Settings.wireGuardBaseSubnet } else { "10.13.13" }
        $port = $wgPort
        
        if ($Script:Settings.ContainsKey('serverWanIP') -and -not [string]::IsNullOrWhiteSpace($Script:Settings.serverWanIP) -and $Script:Settings.serverWanIP -ne 'your.server.wan.ip.here') {
            $wanIP = $Script:Settings.serverWanIP
        }

        if (-not $wanIP) {
            throw "Setting 'serverWanIP' is empty or invalid in Variable.psd1."
        }
        
        # Create Configs
        Write-Verbose "Creating configurations..."
        Write-Verbose "Creating server config..."
        $serverConfPath = Join-Path $env:TEMP "wg_server_remote.conf"
        $serverConfContent = New-WireGuardServerConfig -ServerKeys $serverKeys -ClientKeys $clientKeys -Port $port -Address "$baseSubnet.1/24" -PeerAddress "$baseSubnet.2/32" -ServerType "Windows" -OutputPath $serverConfPath
        
        Write-Verbose "Creating client config..."
        $clientConfPath = Join-Path $Script:OutputPath "wg-client.conf"
        $clientConfigContent = New-WireGuardClientConfig -ClientKeys $clientKeys -ServerKeys $serverKeys -ServerAvailableIP $wanIP -Port $port -Address "$baseSubnet.2/24" -OutputPath $clientConfPath
        
        # QR-code generation
        $qrPath = Join-Path $Script:OutputPath "wg-client-qr.png"
        New-WireGuardQRCode -ConfigContent $clientConfigContent -OutputPath $qrPath
        
        # Install Remote
        Write-Verbose "Starting remote installation..."
        if (Install-RemoteWireGuardServer -ComputerName $computerName -Credential $cred -ServerConfigContent $serverConfContent -RemoteConfigPath "C:\WireGuard" -Port $port) {
            Show-Menu -Mode Success -SuccessTitle "Remote WireGuard Server Setup Completed" -ExtraInfo "Client Config saved locally: $clientConfPath`nQR-code: $qrPath"
        }
    }
    catch {
        Write-Log "Error: $_" -Level "ERROR"
        Show-Menu -Mode Error -SuccessTitle "Remote Setup Failed" -ExtraMessage $_
    }
}
function Invoke-RemoteWireGuardClientSetup {
    Write-Log "=== Remote WireGuard Client Setup Started ===" -Level "INFO"
    try {
        if (-not (Test-IsAdmin)) { throw "Must be run as Administrator" }
        
        # Remote Info
        Write-Verbose "Requesting remote computer IP/Hostname..."
        if ($Script:Settings.ContainsKey('remoteClientIP') -and -not [string]::IsNullOrWhiteSpace($Script:Settings.remoteClientIP) -and $Script:Settings.remoteClientIP -ne 'your.client.ip.here') {
            $computerName = $Script:Settings.remoteClientIP
        }
        
        if (-not $computerName) {
            throw "Setting 'remoteClientIP' is empty or invalid in Variable.psd1."
        }
        Write-Verbose "Remote computer: $computerName"
        
        $cred = Get-Credential -Message "Admin Credentials for $computerName"
        
        Write-Verbose "Requesting path to .conf file..."
        $confPath = Read-Host "Path to .conf file"
        Write-Verbose "Path entered: $confPath"
        if (-not (Test-Path $confPath)) { throw "File not found: $confPath" }
        
        Write-Verbose "Reading config content..."
        $content = Get-Content $confPath -Raw
        Write-Verbose "Config content read, length: $($content.Length)"
        
        Write-Verbose "Starting remote client installation..."
        if (Install-RemoteWireGuardClient -ComputerName $computerName -Credential $cred -ClientConfigContent $content) {
            Show-Menu -Mode Success -SuccessTitle "Remote WireGuard Client Setup Completed"
        }
    }
    catch {
        Write-Log "Error: $_" -Level "ERROR"
        Show-Menu -Mode Error -SuccessTitle "Remote Setup Failed" -ExtraMessage $_
    }
}
