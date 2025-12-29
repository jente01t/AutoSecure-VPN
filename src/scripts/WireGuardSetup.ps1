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
        $outputPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "output"
        Write-Log "Output path: $outputPath" -Level "INFO"
        $configPath = ""

        if (Test-Path $outputPath) {
            $foundFile = Get-ChildItem -Path $outputPath -Filter "*.conf" | Select-Object -First 1
            if ($foundFile) {
                $configPath = $foundFile.FullName
                Write-Log "Found config in output folder: $($foundFile.Name)" -Level "INFO"
                Write-Host "  ✓ Found config in output folder: $($foundFile.Name)" -ForegroundColor Green
            }
        }

        if (-not $configPath) {
            $configPath = Read-Host " Automatic not found: Drag the .conf file here or type the path"
            $configPath = $configPath.Trim('"')
        }
        
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
        
        if (-not (Enable-VPNNAT -VPNSubnet "$baseSubnet.0/24" -VPNType "WireGuard")) { 
            Write-Host "  ! NAT configuration warning - manual check may be required" -ForegroundColor Yellow
            Write-Log "NAT configuration warning - manual setup may be needed" -Level "WARNING"
        }
        else {
            Write-Host "  ✓ NAT and IP Forwarding configured" -ForegroundColor Green
        }
        
        # Step 4: Parameters and Keys
        Write-Host "`n[4/6] Generating configuration and keys..." -ForegroundColor Cyan
        $serverWanIP = $Script:Settings.serverWanIP
        if (-not $serverWanIP -or $serverWanIP -eq "your.server.wan.ip.here") {
            $serverWanIP = Read-Host "  Enter public IP or DNS of this server"
        }
        
        $serverKeys = Initialize-WireGuardKeys
        $clientKeys = Initialize-WireGuardKeys
        Write-Host "  ✓ Keys generated" -ForegroundColor Green
        
        # Step 5: Create configurations
        Write-Host "`n[5/6] Creating configurations..." -ForegroundColor Cyan

        # Server config
        if (-not (Test-Path $Script:ConfigPath)) { New-Item -ItemType Directory -Path $Script:ConfigPath -Force | Out-Null }
        
        New-WireGuardServerConfig -ServerKeys $serverKeys -ClientKeys $clientKeys -Port $wgPort -Address "$baseSubnet.1/24" -PeerAddress "$baseSubnet.2/32" -ServerType "Windows" -OutputPath $serverConfigPath | Out-Null
        
        # Client config
        if (-not (Test-Path $Script:OutputPath)) { New-Item -ItemType Directory -Path $Script:OutputPath -Force | Out-Null }
        $clientConfigPath = Join-Path $Script:OutputPath "wg-client.conf"
        $clientConfigContent = New-WireGuardClientConfig -ClientKeys $clientKeys -ServerKeys $serverKeys -ServerAvailableIP $serverWanIP -Port $wgPort -Address "$baseSubnet.2/24" -OutputPath $clientConfigPath
        
        # QR-code
        $qrPath = Join-Path $Script:OutputPath "wg-client-qr.png"
        if (New-WireGuardQRCode -ConfigContent $clientConfigContent -OutputPath $qrPath) {
            Write-Host "  ✓ QR-code created: $qrPath" -ForegroundColor Green
        }
        else {
            Write-Host "  ! QR-code generation failed" -ForegroundColor Yellow
        }
        
        Write-Host "  ✓ Configurations created" -ForegroundColor Green

        # Step 6: Start service
        Write-Host "`n[6/6] Starting WireGuard Service..." -ForegroundColor Cyan
        if (-not (Start-WireGuardService -ConfigPath $serverConfigPath)) { throw "Failed to start service" }
        Write-Host "  ✓ Service started" -ForegroundColor Green
        
        Show-Menu -Mode Success -SuccessTitle "WireGuard Server Setup Completed!" -LogFile $script:LogFile -ExtraInfo "Client config: $clientConfigPath`nQR-code: $qrPath" -ExtraMessage "Copy the .conf file to the client and import it into WireGuard, or scan the QR-code on mobile devices."
        
    }
    catch {
        Write-Log "Error during WireGuard Setup: $($_.Exception.Message)" -Level "ERROR"
        Show-Menu -Mode Error -SuccessTitle "WireGuard Setup Failed!" -LogFile $script:LogFile -ExtraMessage $_
    }
}
function Invoke-RemoteWireGuardServerSetup {
    Write-Log "=== Remote WireGuard Server Setup Started ===" -Level "INFO"
    try {
        # Step 1: Administrator check
        Write-Progress -Activity "Remote WireGuard Setup" -Status "Step 1 of 6: Checking administrator privileges" -PercentComplete 0
        if (-not (Test-IsAdmin)) { throw "Must be run as Administrator" }
        Write-Host "  ✓ Administrator privileges confirmed" -ForegroundColor Green
        
        # Step 2: Remote Info - Use settings with fallback check
        Write-Progress -Activity "Remote WireGuard Setup" -Status "Step 2 of 6: Remote computer configuration" -PercentComplete 16
        Write-Host "`n[2/6] Remote computer configuration..." -ForegroundColor Cyan
        Write-Verbose "Requesting remote computer IP/Hostname..."
        if ($Script:Settings.ContainsKey('serverIP') -and -not [string]::IsNullOrWhiteSpace($Script:Settings.serverIP) -and $Script:Settings.serverIP -ne 'your.server.ip.here') {
            $computerName = $Script:Settings.serverIP
        }
        
        if (-not $computerName) {
            throw "Setting 'serverIP' is empty or invalid in Variable.psd1."
        }
        Write-Host "  ✓ Remote computer: $computerName" -ForegroundColor Green
        Write-Verbose "Remote computer: $computerName"
        
        # Step 3: Credentials
        Write-Progress -Activity "Remote WireGuard Setup" -Status "Step 3 of 6: Authentication" -PercentComplete 33
        Write-Host "`n[3/6] Authentication..." -ForegroundColor Cyan
        $cred = Get-Credential -Message "Admin Credentials for $computerName"
        Write-Host "  ✓ Credentials obtained" -ForegroundColor Green

        # Step 4: Configure Local
        Write-Progress -Activity "Remote WireGuard Setup" -Status "Step 4 of 6: Generating keys and configurations" -PercentComplete 50
        Write-Host "`n[4/6] Generating keys and configurations..." -ForegroundColor Cyan
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
        $clientConfPath = Join-Path $Script:Settings.OutputPath "wg-client.conf"
        $clientConfigContent = New-WireGuardClientConfig -ClientKeys $clientKeys -ServerKeys $serverKeys -ServerAvailableIP $wanIP -Port $port -Address "$baseSubnet.2/24" -OutputPath $clientConfPath
        
        # QR-code generation
        $qrPath = Join-Path $Script:Settings.OutputPath "wg-client-qr.png"
        New-WireGuardQRCode -ConfigContent $clientConfigContent -OutputPath $qrPath

        Write-Verbose "Client Config: $clientConfigContent"
        Write-Verbose "Server Config: $serverConfContent"
        
        # Step 5: Install Remote
        Write-Progress -Activity "Remote WireGuard Setup" -Status "Step 5 of 6: Performing remote installation" -PercentComplete 66
        Write-Host "`n[5/6] Starting remote installation..." -ForegroundColor Cyan
        if (Install-RemoteWireGuardServer -ComputerName $computerName -Credential $cred -ServerConfigContent $serverConfContent -RemoteConfigPath "C:\WireGuard" -Port $port) {
            
            # Step 5.5: Configure NAT and IP Forwarding (handled within Install-RemoteWireGuardServer but adding orchestrator reporting)
            Write-Progress -Activity "Remote WireGuard Setup" -Status "Step 5.5 of 6: Configuring NAT and IP Forwarding" -PercentComplete 83
            Write-Host "`n[5.5/6] Configuring NAT and IP Forwarding..." -ForegroundColor Cyan
            Write-Host "  ✓ NAT and IP Forwarding configured (Remote)" -ForegroundColor Green

            # Step 6: Success
            Write-Progress -Activity "Remote WireGuard Setup" -Completed
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
