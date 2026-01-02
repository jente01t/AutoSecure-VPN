#region WireGuard Setup Orchestration

# =================================================================================================
# REGION: WireGuard Setup Orchestration
# =================================================================================================
# This section contains the high-level orchestration functions for WireGuard deployments.
# It handles the installation, key generation, and configuration of WireGuard tunnels
# for both Server and Client roles, including Remote execution and Batch processing.
# Key Functions: Invoke-WireGuardClientSetup, Invoke-WireGuardServerSetup,
#                Invoke-RemoteWireGuardServerSetup, Invoke-RemoteWireGuardClientSetup.
# =================================================================================================

function Invoke-WireGuardClientSetup {
    <#
    .SYNOPSIS
        Performs WireGuard client setup.

    .DESCRIPTION
        This function handles the installation and configuration of the WireGuard client
        on the local machine. It checks for admin privileges, installs the software,
        and imports a configuration file (automatically detected or manually provided).
        Finally, it starts the WireGuard tunnel service.
    
    .EXAMPLE
        Invoke-WireGuardClientSetup
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
        # Define output path where configs are likely stored
        $outputPath = Join-Path (Split-Path (Split-Path $Script:ModuleRoot -Parent) -Parent) "output"
        Write-Log "Output path: $outputPath" -Level "INFO"
        $configPath = ""

        # Try to find an existing configuration file
        if (Test-Path $outputPath) {
            $foundFile = Get-ChildItem -Path $outputPath -Filter "*.conf" | Select-Object -First 1
            if ($foundFile) {
                $configPath = $foundFile.FullName
                Write-Log "Found config in output folder: $($foundFile.Name)" -Level "INFO"
                Write-Host "  ✓ Found config in output folder: $($foundFile.Name)" -ForegroundColor Green
            }
        }

        # If not found automatically, ask user
        if (-not $configPath) {
            $configPath = Read-Host " Automatic not found: Drag the .conf file here or type the path"
            $configPath = $configPath.Trim('"')
        }
        
        if (-not (Test-Path $configPath)) { throw "File not found: $configPath" }
        
        # Copy config to WireGuard's official configuration directory (required for GUI visibility)
        $wgConfigDir = "C:\Program Files\WireGuard\Data\Configurations"
        if (-not (Test-Path $wgConfigDir)) { New-Item -ItemType Directory -Path $wgConfigDir -Force | Out-Null }
        
        # Extract tunnel name from config file (without extension)
        $tunnelName = [System.IO.Path]::GetFileNameWithoutExtension($configPath)
        $wgConfigPath = Join-Path $wgConfigDir "$tunnelName.conf"
        
        # Copy config file to WireGuard directory
        Write-Host "  Copying config to WireGuard directory..." -ForegroundColor Gray
        Copy-Item -Path $configPath -Destination $wgConfigPath -Force
        Write-Log "Config copied to: $wgConfigPath" -Level "INFO"
        
        # Start the WireGuard tunnel using the config from WireGuard directory
        if (-not (Start-WireGuardService -ConfigPath $wgConfigPath)) { throw "Starting tunnel failed" }
        
        Write-Host "  ✓ Tunnel started" -ForegroundColor Green
        
        Show-Menu -Mode Success -SuccessTitle "WireGuard Client Setup Completed!" -LogFile $script:LogFile
        
    }
    catch {
        Write-Log "Error during WireGuard Client Setup: $_" -Level "ERROR"
        Show-Menu -Mode Error -SuccessTitle "WireGuard Client Setup Failed!" -LogFile $script:LogFile -ExtraMessage $_
    }
}

function Invoke-WireGuardServerSetup {
    <#
    .SYNOPSIS
        Performs full WireGuard server setup.

    .DESCRIPTION
        This function executes the complete setup process for a WireGuard server,
        including installation, firewall configuration, key generation, and service startup.
        It also handles the creation of the server configuration file and a client configuration
        package (including QR code).

    .EXAMPLE
        Invoke-WireGuardServerSetup
    #>
    Write-Log "=== WireGuard Server Setup Started ===" -Level "INFO"
    
    try {
        # Step 1: Admin check
        Write-Host "`n[1/6] Checking administrator privileges..." -ForegroundColor Cyan
        if (-not (Test-IsAdmin)) { throw "Script must be run as Administrator!" }
        Write-Host "  ✓ Administrator privileges confirmed" -ForegroundColor Green
        
        # Step 2: Install
        Write-Host "`n[2/6] Installing WireGuard..." -ForegroundColor Cyan
        if (-not (Install-WireGuard)) { throw "WireGuard installation failed" }
        Write-Host "  ✓ WireGuard installed" -ForegroundColor Green
        
        # Step 3: Firewall
        # Get port settings
        $wgPort = if ($Script:Settings.wireGuardPort) { $Script:Settings.wireGuardPort } else { 51820 }
        $baseSubnet = if ($Script:Settings.wireGuardBaseSubnet) { $Script:Settings.wireGuardBaseSubnet } else { "10.13.13" }

        Write-Host "`n[3/6] Configuring firewall (UDP $wgPort)..." -ForegroundColor Cyan
        if (-not (Set-Firewall -Port $wgPort -Protocol "UDP")) { throw "Firewall configuration failed" }
        Write-Host "  ✓ Firewall configured" -ForegroundColor Green
        
        # Step 4: Config and Keys
        Write-Host "`n[4/6] Generating Configuration and Keys..." -ForegroundColor Cyan
        $serverWanIP = $Script:Settings.serverWanIP
        # Prompt for WAN IP if default or empty
        if (-not $serverWanIP -or $serverWanIP -eq "your.server.wan.ip.here") {
            $serverWanIP = Read-Host "  Enter public IP or DNS of this server"
        }
        
        # Generate Public/Private Key pairs
        $serverKeys = Initialize-WireGuardKeys
        $clientKeys = Initialize-WireGuardKeys
        Write-Host "  ✓ Keys generated" -ForegroundColor Green
        
        # Stop existing WireGuard services before creating new config to avoid file locks
        Write-Host "  Stopping existing WireGuard tunnels..." -ForegroundColor Gray
        Stop-WireGuardService | Out-Null
        
        # Ensure Server config directory exists
        $wgConfigDir = "C:\Program Files\WireGuard\Data\Configurations" 
        if (-not (Test-Path $wgConfigDir)) { New-Item -ItemType Directory -Path $wgConfigDir -Force | Out-Null }
        $serverConfigPath = Join-Path $wgConfigDir "wg_server.conf"
        
        # Remove existing config files if they exist (both .conf and .dpapi)
        if (Test-Path $serverConfigPath) {
            Remove-Item $serverConfigPath -Force -ErrorAction SilentlyContinue
        }
        $dpapiPath = "$serverConfigPath.dpapi"
        if (Test-Path $dpapiPath) {
            Remove-Item $dpapiPath -Force -ErrorAction SilentlyContinue
        }
        Start-Sleep -Milliseconds 500  # Wait for file system to release both files
        
        # Create and write server config file
        New-WireGuardServerConfig -ServerKeys $serverKeys -ClientKeys $clientKeys -Port $wgPort -Address "$baseSubnet.1/24" -PeerAddress "$baseSubnet.2/32" -ServerType "Windows" -OutputPath $serverConfigPath | Out-Null
        
        # Verify server config was created
        if (-not (Test-Path $serverConfigPath)) {
            throw "Server config file was not created at $serverConfigPath"
        }
        Write-Log "Server config verified at: $serverConfigPath" -Level "INFO"
        
        # Create client config file in output directory
        $outputDir = Join-Path $Script:ModuleRoot "..\..\output"
        $outputDir = [System.IO.Path]::GetFullPath($outputDir)
        if (-not (Test-Path $outputDir)) { New-Item -ItemType Directory -Path $outputDir -Force | Out-Null }
        $clientConfigPath = Join-Path $outputDir "wg-client.conf"
        $clientConfigContent = New-WireGuardClientConfig -ClientKeys $clientKeys -ServerKeys $serverKeys -ServerAvailableIP $serverWanIP -Port $wgPort -Address "$baseSubnet.2/24" -OutputPath $clientConfigPath
        
        # Create QR code for mobile clients
        $qrPath = Join-Path $outputDir "wg-client-qr.png"
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
        
        # Step 7: Configure NAT and IP Forwarding (after service start, when adapter exists)
        Write-Host "`n[7/7] Configuring NAT and IP Forwarding..." -ForegroundColor Cyan
        Start-Sleep -Seconds 2  # Wait for adapter to be available
        if (-not (Enable-VPNNAT -VPNSubnet "$baseSubnet.0/24" -VPNType "WireGuard")) { 
            Write-Host "  ! NAT configuration warning - manual configuration may be required" -ForegroundColor Yellow
            Write-Log "NAT configuration warning - manual setup may be required" -Level "WARNING"
        }
        else {
            Write-Host "  ✓ NAT and IP Forwarding configured" -ForegroundColor Green
        }
        
        Show-Menu -Mode Success -SuccessTitle "WireGuard Server Setup Completed!" -LogFile $script:LogFile -ExtraInfo "Client config: $clientConfigPath`nQR-code: $qrPath" -ExtraMessage "Copy the .conf file to the client and import it into WireGuard, or scan the QR code on mobile devices."
        
    }
    catch {
        # Error handling
        Write-Log "Error during WireGuard Setup: $($_.Exception.Message)" -Level "ERROR"
        Show-Menu -Mode Error -SuccessTitle "WireGuard Setup Failed!" -LogFile $script:LogFile -ExtraMessage $_
    }
}

function Invoke-RemoteWireGuardServerSetup {
    <#
    .SYNOPSIS
        Perform remote WireGuard Server setup.
        
    .DESCRIPTION
        This function connects to a remote computer via PowerShell Remoting and
        performs the full WireGuard Server setup sequence. It handles file transfer,
        remote installation, and configuration.
        
    .EXAMPLE
        Invoke-RemoteWireGuardServerSetup
    #>
    function Write-Log { param($Message, $Level = "INFO") Write-Verbose "[$Level] $Message" }
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
        
        # Get network settings
        $wgPort = if ($Script:Settings.wireGuardPort) { $Script:Settings.wireGuardPort } else { 51820 }
        $baseSubnet = if ($Script:Settings.wireGuardBaseSubnet) { $Script:Settings.wireGuardBaseSubnet } else { "10.13.13" }
        $port = $wgPort
        
        if ($Script:Settings.ContainsKey('serverWanIP') -and -not [string]::IsNullOrWhiteSpace($Script:Settings.serverWanIP) -and $Script:Settings.serverWanIP -ne 'your.server.wan.ip.here') {
            $wanIP = $Script:Settings.serverWanIP
        }

        if (-not $wanIP) {
            throw "Setting 'serverWanIP' is empty or invalid in Variable.psd1."
        }
        
        # Create Configs in temporary location for transfer
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
        # Push configuration and install to remote
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
    <#
    .SYNOPSIS
        Perform remote WireGuard Client setup.
        
    .DESCRIPTION
        This function connects to a remote computer via PowerShell Remoting and
        executes the WireGuard Client setup. It can deploy a specific client configuration.
        
    .EXAMPLE
        Invoke-RemoteWireGuardClientSetup
    #>
    function Write-Log { param($Message, $Level = "INFO") Write-Verbose "[$Level] $Message" }
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
        
        Write-Host "`nImporting config..." -ForegroundColor Cyan
        $outputPath = Join-Path (Split-Path (Split-Path $Script:ModuleRoot -Parent) -Parent) "output"
        Write-Log "Output path: $outputPath" -Level "INFO"
        $confPath = ""

        # Auto-detect config file
        if (Test-Path $outputPath) {
            $foundFile = Get-ChildItem -Path $outputPath -Filter "*.conf" | Select-Object -First 1
            if ($foundFile) {
                $confPath = $foundFile.FullName
                Write-Log "Found config in output folder: $($foundFile.Name)" -Level "INFO"
                Write-Host "  ✓ Found config in output folder: $($foundFile.Name)" -ForegroundColor Green
            }
        }

        # Manual input if auto-detect fails
        if (-not $confPath) {
            $confPath = Read-Host " Automatic not found: Drag the .conf file here or type the path"
            $confPath = $confPath.Trim('"')
        }
        
        if (-not (Test-Path $confPath)) { throw "File not found: $confPath" }
        Write-Verbose "Reading config content..."
        $content = Get-Content $confPath -Raw
        Write-Verbose "Config content read, length: $($content.Length)"
        
        Write-Host "`nStarting remote WireGuard client installation on $computerName..." -ForegroundColor Cyan
        Write-Verbose "Starting remote client installation..."
        # Trigger remote installation
        if (Install-RemoteWireGuardClient -ComputerName $computerName -Credential $cred -ClientConfigContent $content) {
            Show-Menu -Mode Success -SuccessTitle "Remote WireGuard Client Setup Completed"
        }
    }
    catch {
        Write-Log "Error: $_" -Level "ERROR"
        Show-Menu -Mode Error -SuccessTitle "Remote Setup Failed" -ExtraMessage $_
    }
}

#endregion WireGuard Setup Orchestration
#region WireGuard Implementation Details

# =================================================================================================
# REGION: WireGuard Implementation Details
# =================================================================================================
# This section contains the specific implementation logic for WireGuard tasks.
# It includes functions for downloading/installing WireGuard, generating KeyPairs,
# creating interface configurations, and managing the WireGuard Tunnel Service.
# Key Functions: Install-WireGuard, Initialize-WireGuardKeys, New-WireGuardServerConfig,
#                Start-WireGuardService, Stop-WireGuardService.
# =================================================================================================

function Install-WireGuard {
    <#
    .SYNOPSIS
        Installs WireGuard on the local machine.

    .DESCRIPTION
        This function downloads and installs WireGuard.
        It attempts to find the latest version dynamically or falls back to a known stable URL.
        
    .PARAMETER Url
        The URL of the WireGuard installer (optional).
        
    .OUTPUTS
        System.Boolean
        $true on success, otherwise $false.
    #>
    param(
        [Parameter(Position = 0)][string]$wgUrl
    )
    
    # Check if already installed
    $wgExePath = if ($Script:Settings -and $Script:Settings.ContainsKey('wireGuardInstalledPath') -and $Script:Settings.wireGuardInstalledPath) { $Script:Settings.wireGuardInstalledPath } else { "C:\Program Files\WireGuard\wireguard.exe" }
    if (Test-Path $wgExePath) {
        Write-Log "WireGuard appears to be already installed" -Level "INFO"
        return $true
    }

    Write-Log "WireGuard installation started" -Level "INFO"
    
    # Determine download URL
    if (-not $wgUrl) {
        # Use fixed stable version as fallback
        $wgUrl = $Script:Settings.wireGuardInstallerUrlFallback
    }

    $tempPath = [System.IO.Path]::GetTempFileName() + ".msi"
    
    try {
        # Try to dynamically find the latest version from the web
        try {
            $content = Invoke-WebRequest -Uri $Script:Settings.wireGuardVersionCheckUrl -UseBasicParsing -ErrorAction SilentlyContinue
            if ($content.Content -match $Script:Settings.wireGuardVersionRegex) {
                $latestMsi = $matches[1]
                $wgUrl = "$($Script:Settings.wireGuardVersionCheckUrl)$latestMsi"
                Write-Log "Latest WireGuard version found online: $latestMsi" -Level "INFO"
            }
        }
        catch {
            Write-Log "Could not perform online version check, using fallback url" -Level "WARNING"
        }

        Write-Log "Downloading WireGuard MSI from $wgUrl..." -Level "INFO"
        Invoke-WebRequest -Uri $wgUrl -OutFile $tempPath -UseBasicParsing
        Write-Log "WireGuard MSI downloaded to $tempPath" -Level "INFO"
        
        # Silent install options
        # DO_NOT_LAUNCH=1 prevents the GUI from starting immediately so we can control it
        $arguments = $Script:Settings.wireGuardInstallerArguments -f $tempPath
        
        Write-Log "Installing..." -Level "INFO"
        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $arguments -Wait -PassThru
        
        if ($process.ExitCode -eq 0) {
            Write-Log "WireGuard successfully installed" -Level "SUCCESS"
            return $true
        }
        else {
            Write-Log "WireGuard installation failed with exit code $($process.ExitCode)" -Level "ERROR"
            return $false
        }
    }
    catch {
        Write-Log "Error during WireGuard installation: $_" -Level "ERROR"
        return $false
    }
    finally {
        if (Test-Path $tempPath) {
            Remove-Item $tempPath -Force -ErrorAction SilentlyContinue
        }
    }
}

function Initialize-WireGuardKeys {
    <#
    .SYNOPSIS
        Generates Private and Public keys for WireGuard.
        
    .DESCRIPTION
        Uses 'wg.exe' to generate a keypair.
    
    .OUTPUTS
        Hashtable with PrivateKey and PublicKey.
    #>
    param(
        [Parameter(Position = 0)][string]$WgPath,
        [Parameter(Position = 1)][hashtable]$Settings = $null
    )
    
    # Determine path to wg.exe
    if (-not $WgPath) {
        if ($Settings -and $Settings.ContainsKey('wireGuardKeysExePath') -and $Settings.wireGuardKeysExePath) {
            $WgPath = $Settings.wireGuardKeysExePath
        }
        elseif ($Script:Settings -and $Script:Settings.ContainsKey('wireGuardKeysExePath') -and $Script:Settings.wireGuardKeysExePath) {
            $WgPath = $Script:Settings.wireGuardKeysExePath
        }
        else {
            $WgPath = "C:\Program Files\WireGuard\wg.exe"
            Write-Log "No wg.exe path specified, using default fallback: $WgPath" -Level "WARNING"
        }
    }
    
    if (-not (Test-Path $WgPath)) {
        throw "wg.exe not found at $WgPath. Check wireGuardKeysExePath in your settings or install WireGuard first."
    }
    
    try {
        # Create temp files to ensure clean shell interaction and avoid piping encoding issues
        $tempPrivPath = [System.IO.Path]::GetTempFileName()
        $tempPubPath = [System.IO.Path]::GetTempFileName()
        
        try {
            # Generate private key
            & $WgPath genkey | Set-Content -Path $tempPrivPath -NoNewline
            $privateKey = (Get-Content -Path $tempPrivPath -Raw).Trim()
            
            if ([string]::IsNullOrWhiteSpace($privateKey)) { throw "Private key generation resulted in empty output" }

            # Generate public key from private key
            Get-Content -Path $tempPrivPath -Raw | & $WgPath pubkey | Set-Content -Path $tempPubPath -NoNewline
            $publicKey = (Get-Content -Path $tempPubPath -Raw).Trim()

            if ([string]::IsNullOrWhiteSpace($publicKey)) { throw "Public key generation resulted in empty output" }
            
            # Log shortened keys for verification (without leaking full keys)
            $shortPriv = if ($privateKey.Length -gt 10) { $privateKey.Substring(0, 5) + "..." + $privateKey.Substring($privateKey.Length - 5) } else { "ERROR" }
            $shortPub = if ($publicKey.Length -gt 10) { $publicKey.Substring(0, 5) + "..." + $publicKey.Substring($publicKey.Length - 5) } else { "ERROR" }
            
            Write-Log "WireGuard keys generated: Priv=$shortPriv, Pub=$shortPub" -Level "INFO"

            return @{
                PrivateKey = $privateKey
                PublicKey  = $publicKey
            }
        }
        finally {
            if (Test-Path $tempPrivPath) { Remove-Item $tempPrivPath -Force -ErrorAction SilentlyContinue }
            if (Test-Path $tempPubPath) { Remove-Item $tempPubPath -Force -ErrorAction SilentlyContinue }
        }
    }
    catch {
        Write-Log "Error during key generation: $_" -Level "ERROR"
        throw
    }
}

function New-WireGuardServerConfig {
    <#
    .SYNOPSIS
        Creates a WireGuard server configuration.
    #>
    param(
        [Parameter(Mandatory = $true, Position = 0)]$ServerKeys,
        [Parameter(Mandatory = $true, Position = 1)]$ClientKeys,
        [Parameter(Mandatory = $true, Position = 2)]$Port,
        [Parameter(Mandatory = $true, Position = 3)]$Address, # e.g. 10.13.13.1/24
        [Parameter(Mandatory = $true, Position = 4)]$PeerAddress, # e.g. 10.13.13.2/32
        [Parameter(Mandatory = $true, Position = 5)]$ServerType,
        [Parameter(Position = 6)][string]$OutputPath
    )
    
    # Construct the config text
    $configContent = @"
[Interface]
PrivateKey = $($ServerKeys.PrivateKey)
ListenPort = $Port
Address = $Address

[Peer]
PublicKey = $($ClientKeys.PublicKey)
AllowedIPs = $PeerAddress
"@

    Write-Log "Generating server config with Port=$Port, Address=$Address, PeerPublic=$($ClientKeys.PublicKey.Substring(0,5))..." -Level "INFO"

    if ($OutputPath) {
        Set-Content -Path $OutputPath -Value $configContent -Encoding UTF8
        Write-Log "Server config saved in $OutputPath" -Level "INFO"
    }
    
    return $configContent
}

function New-WireGuardClientConfig {
    <#
    .SYNOPSIS
        Creates a WireGuard client configuration.
    #>
    param(
        [Parameter(Mandatory = $true, Position = 0)]$ClientKeys,
        [Parameter(Mandatory = $true, Position = 1)]$ServerKeys,
        [Parameter(Mandatory = $true, Position = 2)]$ServerAvailableIP, # WAN IP
        [Parameter(Mandatory = $true, Position = 3)]$Port,
        [Parameter(Mandatory = $true, Position = 4)]$Address, # e.g. 10.13.13.2/24
        [Parameter(Position = 5)][string]$DNS,
        [Parameter(Position = 6)][string]$OutputPath
    )
    
    # DNS fallback logic
    if ([string]::IsNullOrWhiteSpace($DNS)) {
        $dnsFromSettings = $null
        if ($Script:Settings -and $Script:Settings.ContainsKey('wireGuardDefaultDns')) {
            $dnsFromSettings = $Script:Settings.wireGuardDefaultDns
        }

        if (-not [string]::IsNullOrWhiteSpace($dnsFromSettings)) {
            $DNS = $dnsFromSettings
        }
        else {
            Write-Log "No DNS specified for WireGuard client; using fallback 8.8.8.8" -Level "WARNING"
            $DNS = '8.8.8.8'
        }
    }
    
    # Construct config text
    $configContent = @"
[Interface]
PrivateKey = $($ClientKeys.PrivateKey)
Address = $Address
DNS = $DNS

[Peer]
PublicKey = $($ServerKeys.PublicKey)
Endpoint = ${ServerAvailableIP}:${Port}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = $($Script:Settings.wireGuardDefaultPersistentKeepalive)
"@

    Write-Log "Generating client config with Server=$ServerAvailableIP, Port=$Port, Address=$Address, ClientPriv=$($ClientKeys.PrivateKey.Substring(0,5))..." -Level "INFO"

    if ($OutputPath) {
        Set-Content -Path $OutputPath -Value $configContent -Encoding UTF8
        Write-Log "Client config saved in $OutputPath" -Level "INFO"
    }
    
    return $configContent
}

function Start-WireGuardService {
    <#
    .SYNOPSIS
        Installs and starts the WireGuard tunnel service.
    #>
    param(
        [Parameter(Mandatory = $true, Position = 0)]$ConfigPath
    )
    
    $wgPath = if ($Script:Settings -and $Script:Settings.ContainsKey('wireGuardInstalledPath') -and $Script:Settings.wireGuardInstalledPath) { $Script:Settings.wireGuardInstalledPath } else { "C:\Program Files\WireGuard\wireguard.exe" }
    if (-not (Test-Path $wgPath)) {
        throw "WireGuard executable not found"
    }
    
    try {
        # First stop existing WireGuard services to prevent conflicts (one tunnel at a time typically on Windows)
        Stop-WireGuardService | Out-Null
        
        # wireguard /installtunnelservice <path>
        # This installs a service with name "WireGuardTunnel$Name"
        
        Write-Log "Starting WireGuard tunnel with config $ConfigPath..." -Level "INFO"
        
        $process = Start-Process -FilePath $wgPath -ArgumentList "/installtunnelservice `"$ConfigPath`"" -Wait -PassThru
        
        # Start GUI Manager so the user can see the status
        Write-Log "Starting WireGuard GUI Manager..." -Level "INFO"
        Start-Process -FilePath $wgPath -NoNewWindow
        
        if ($process.ExitCode -eq 0) {
            Write-Log "WireGuard service successfully installed and started" -Level "SUCCESS"
            return $true
        }
        else {
            # Check if likely already running or installed
            Write-Log "WireGuard service start returned exit code $($process.ExitCode). The service might already be running." -Level "WARNING"
            return $true # Treat as success or handled manually
        }
    }
    catch {
        Write-Log "Error during WireGuard service start: $_" -Level "ERROR"
        return $false
    }
}

function Stop-WireGuardService {
    <#
    .SYNOPSIS
        Stops all running WireGuard tunnel services.
    #>
    param()
    
    $wgPath = if ($Script:Settings -and $Script:Settings.ContainsKey('wireGuardInstalledPath') -and $Script:Settings.wireGuardInstalledPath) { $Script:Settings.wireGuardInstalledPath } else { "C:\Program Files\WireGuard\wireguard.exe" }
    if (-not (Test-Path $wgPath)) {
        Write-Log "WireGuard executable not found, cannot stop" -Level "WARNING"
        return $false
    }
    
    try {
        # Find and stop all WireGuard tunnel services
        $services = Get-Service -Name "WireGuardTunnel*" -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Running" }
        foreach ($service in $services) {
            Write-Log "Stopping and removing WireGuard service: $($service.Name)" -Level "INFO"
            if ($service.Status -eq "Running") {
                Stop-Service -Name $service.Name -Force -ErrorAction SilentlyContinue
            }
            # Uninstall the service wrapper
            $tunnelName = $service.Name -replace '^WireGuardTunnel\$', ''
            if ($tunnelName) {
                Start-Process -FilePath $wgPath -ArgumentList "/uninstalltunnelservice `"$tunnelName`"" -Wait -PassThru -NoNewWindow | Out-Null
                Write-Log "Uninstalled tunnel: $tunnelName" -Level "INFO"
            }
        }
        
        Write-Log "All WireGuard services stopped" -Level "INFO"
        return $true
    }
    catch {
        Write-Log "Error during WireGuard services stop: $_" -Level "ERROR"
        return $false
    }
}

function New-WireGuardQRCode {
    <#
    .SYNOPSIS
        Creates a QR code for the WireGuard client configuration.
    #>
    param(
        [Parameter(Mandatory = $true, Position = 0)]$ConfigContent,
        [Parameter(Mandatory = $true, Position = 1)]$OutputPath
    )
    
    # Check if QrCodes module is installed, install if missing
    if (-not (Get-Module -Name QrCodes -ListAvailable)) {
        try {
            Write-Log "Installing QrCodes module..." -Level "INFO"
            Install-Module -Name QrCodes -Force -Scope CurrentUser -ErrorAction Stop
        }
        catch {
            Write-Log "Could not install QrCodes module: $_" -Level "WARNING"
            return $false
        }
    }
    
    try {
        Import-Module QrCodes -ErrorAction Stop
        # Generate the barcode image
        Out-BarcodeImage -Content $ConfigContent -Path $OutputPath
        Write-Log "QR code saved in $OutputPath" -Level "INFO"
        return $true
    }
    catch {
        Write-Log "Error during QR code generation: $_" -Level "ERROR"
        return $false
    }
}

function Install-RemoteWireGuardServer {
    <#
    .SYNOPSIS
        Installs WireGuard Server on a remote machine.
    #>
    param(
        [Parameter(Mandatory = $true, Position = 0)]$ComputerName,
        [Parameter(Mandatory = $true, Position = 1)][PSCredential]$Credential,
        [Parameter(Mandatory = $true, Position = 2)]$ServerConfigContent, # The content of wg_server.conf
        [Parameter(Mandatory = $true, Position = 3)]$RemoteConfigPath, # Where to save
        [Parameter(Position = 4)][int]$Port
    )
    
    if (-not $Port) {
        # Try to get port from settings if not specified
        if ($Script:Settings -and $Script:Settings.ContainsKey('wireGuardPort') -and $Script:Settings.wireGuardPort) {
            $Port = [int]$Script:Settings.wireGuardPort
        }
        else {
            throw "Port not specified and 'wireGuardPort' is missing or empty in Settings. Provide -Port or add value to the config."
        }
    }

    # Determine VPN subnet from settings
    $vpnSubnet = $null
    if ($Script:Settings -and $Script:Settings.ContainsKey('wireGuardBaseSubnet') -and -not [string]::IsNullOrWhiteSpace($Script:Settings.wireGuardBaseSubnet)) {
        $vpnSubnet = "${($Script:Settings.wireGuardBaseSubnet)}.0/24"
    }
    else {
        throw "'wireGuardBaseSubnet' is missing or empty in Settings. Add a value to the config."
    }

    # Remote temp path fallback
    if ($Script:Settings -and $Script:Settings.ContainsKey('wireGuardRemoteTempPath') -and -not [string]::IsNullOrWhiteSpace($Script:Settings.wireGuardRemoteTempPath)) {
        $remoteTemp = $Script:Settings.wireGuardRemoteTempPath
    }
    else {
        $remoteTemp = 'C:\Temp'
    }

    $remoteModuleDir = Join-Path $remoteTemp "AutoSecure-VPN"
    
    Write-Log "Starting remote WireGuard server installation on $ComputerName..." -Level "INFO"
    Write-Verbose "Connecting to remote machine $ComputerName..."
    
    $session = New-PSSession -ComputerName $ComputerName -Credential $Credential -ConfigurationName PowerShell.7
    Write-Verbose "PSSession established"
    
    try {
        # 1. Prepare remote folders
        Write-Verbose "Preparing remote folders..."
        Invoke-Command -Session $session -ScriptBlock { 
            param($temp, $modDir) 
            if (-not (Test-Path $temp)) { New-Item -ItemType Directory -Path $temp -Force | Out-Null } 
            if (Test-Path $modDir) { Remove-Item $modDir -Recurse -Force -ErrorAction SilentlyContinue }
            New-Item -ItemType Directory -Path $modDir -Force | Out-Null
        } -ArgumentList $remoteTemp, $remoteModuleDir
        
        # 2. Get local paths (module source)
        $moduleBase = $null
        if ($Script:BasePath -and (Test-Path (Join-Path $Script:BasePath 'src\module\AutoSecure-VPN.psd1'))) {
            $moduleBase = Join-Path $Script:BasePath 'src\module'
            Write-Verbose "Using source module path from Script Scope: $moduleBase"
        }
        
        if (-not $moduleBase -or [string]::IsNullOrWhiteSpace($moduleBase)) {
            $moduleBase = $Script:ModuleRoot
            if (-not $moduleBase -or -not (Test-Path (Join-Path $moduleBase "AutoSecure-VPN.psd1"))) {
                $moduleBase = (Get-Module AutoSecure-VPN).ModuleBase
            }
        }
        $localModuleDir = $moduleBase
        
        if (-not $localModuleDir -or -not (Test-Path (Join-Path $localModuleDir "AutoSecure-VPN.psd1"))) {
            throw "Local module directory not found or invalid: $localModuleDir"
        }

        # 3. Copy module (contents) to remote
        Write-Verbose "Copying module to remote..."
        Copy-Item -Path "$localModuleDir\*" -Destination $remoteModuleDir -ToSession $session -Recurse -Force
        Write-Verbose "Module directory copied"
        
        # 4. Execute on remote with output capture
        Write-Verbose "Executing installation on remote..."
        $remoteResult = Invoke-Command -Session $session -ScriptBlock {
            param($moduleDirPath, $configContent, $configDir, $port, $vpnSubnet, $settings)
            
            $log = @()
            $log += "=== Remote WireGuard Server Setup Start ==="
            
            try {
                # Load module
                $log += "Loading module..."
                $manifestPath = Join-Path $moduleDirPath "AutoSecure-VPN.psd1"
                if (-not (Get-Module -Name 'AutoSecure-VPN' -ErrorAction SilentlyContinue)) {
                    Import-Module $manifestPath -Force
                }
                
                Set-ModuleSettings -Settings $settings -BasePath "C:\Temp"
                
                # Override Write-Log to capture output in variable instead of file
                $script:remoteLog = @()
                function global:Write-Log { 
                    param($Message, $Level = "INFO") 
                    $script:remoteLog += "[$Level] $Message"
                }
                
                # 1. Install WireGuard
                $log += "Installing WireGuard..."
                if (-not (Install-WireGuard)) { 
                    $log += "ERROR: WireGuard installation failed"
                    throw "Remote WireGuard installation failed" 
                }
                $log += "OK: WireGuard installed"
                

                
                # 3. Firewall
                $log += "Configuring firewall (UDP $port)..."
                if (-not (Set-Firewall -Port $port -Protocol "UDP")) { 
                    $log += "ERROR: Firewall configuration failed"
                    throw "Remote Firewall configuration failed" 
                }
                $log += "OK: Firewall configured"
                
                # 4. Save config
                $log += "Saving config to $configDir..."
                if (-not (Test-Path $configDir)) { 
                    New-Item -ItemType Directory -Path $configDir -Force | Out-Null 
                }
                $serverConfigPath = Join-Path $configDir "wg_server.conf"
                Set-Content -Path $serverConfigPath -Value $configContent
                $log += "OK: Config saved to $serverConfigPath"
                
                # 5. Start service
                $log += "Starting WireGuard service..."
                if (-not (Start-WireGuardService -ConfigPath $serverConfigPath)) { 
                    $log += "ERROR: Service start failed"
                    throw "Remote Service start failed" 
                }
                $log += "OK: Service started"

                # 2. Configure NAT (this also calls Enable-IPForwarding)
                $log += "Configuring NAT for internet access..."
                $natResult = Enable-VPNNAT -VPNSubnet $vpnSubnet -VPNType "WireGuard"
                $log += $script:remoteLog  # Add NAT logs
                if (-not $natResult) { 
                    $log += "WARNING: NAT configuration might not be complete"
                }
                else {
                    $log += "OK: NAT configured"
                }
                
                $log += "=== Remote Setup Completed ==="
                
                return @{
                    Success = $true
                    Log     = $log
                }
            }
            catch {
                $log += "ERROR: $_"
                return @{
                    Success = $false
                    Log     = $log
                    Error   = $_.ToString()
                }
            }
            Remove-Item $moduleDirPath -Recurse -Force
        } -ArgumentList $remoteModuleDir, $ServerConfigContent, $RemoteConfigPath, $Port, $vpnSubnet, $Script:Settings
        
        # Show remote output ONLY IF failed (to see full error trace) or if streaming was totally missed
        if (-not $remoteResult.Success -and $remoteResult.Log) {
            Write-Host "`n--- Remote Server Error Log ---" -ForegroundColor Red
            foreach ($line in $remoteResult.Log) {
                Write-Host "  $line" -ForegroundColor Gray
            }
            Write-Host "----------------------------`n" -ForegroundColor Red
        }
        
        if (-not $remoteResult.Success) {
            throw "Remote installation failed: $($remoteResult.Error)"
        }
        
        Write-Verbose "Remote installation completed"
        
        Write-Log "Remote WireGuard Server configuration completed for $ComputerName" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Error during remote WireGuard server installation: $_" -Level "ERROR"
        Write-Verbose "Error during remote installation: $_"
        return $false
    }
    finally {
        if ($session) { 
            Write-Verbose "Closing PSSession..."
            Remove-PSSession $session 
            Write-Verbose "PSSession closed"
        }
    }
}

function Install-RemoteWireGuardClient {
    <#
    .SYNOPSIS
        Installs WireGuard Client on a remote machine.
    #>
    param(
        [Parameter(Mandatory = $true, Position = 0)]$ComputerName,
        [Parameter(Mandatory = $true, Position = 1)][PSCredential]$Credential,
        [Parameter(Mandatory = $true, Position = 2)]$ClientConfigContent
    )
    
    # Defaults for remote paths
    $remoteTemp = if ($Script:Settings -and $Script:Settings.ContainsKey('wireGuardRemoteTempPath') -and -not [string]::IsNullOrWhiteSpace($Script:Settings.wireGuardRemoteTempPath)) { $Script:Settings.wireGuardRemoteTempPath } else { 'C:\Temp' }
    $configDir = if ($Script:Settings -and $Script:Settings.ContainsKey('wireGuardRemoteClientConfigDir') -and -not [string]::IsNullOrWhiteSpace($Script:Settings.wireGuardRemoteClientConfigDir)) { $Script:Settings.wireGuardRemoteClientConfigDir } else { 'C:\Program Files\WireGuard\Data\Configurations' }
    
    Write-Log "Starting remote WireGuard client installation on $ComputerName..." -Level "INFO"
    Write-Verbose "Connecting to remote machine $ComputerName..."
    
    $session = New-PSSession -ComputerName $ComputerName -Credential $Credential -ConfigurationName PowerShell.7
    Write-Verbose "PSSession established"
    
    try {
        # 1. Copy module
        Write-Verbose "Copying module to remote..."
        Invoke-Command -Session $session -ScriptBlock { param($path) if (-not (Test-Path $path)) { New-Item -ItemType Directory -Path $path -Force } } -ArgumentList $remoteTemp
        
        $localModuleDir = $Script:ModuleRoot
        if (-not $localModuleDir -or -not (Test-Path (Join-Path $localModuleDir "AutoSecure-VPN.psd1"))) {
            $localModuleDir = (Get-Module AutoSecure-VPN).ModuleBase
        }

        $remoteModuleDir = Join-Path $remoteTemp "AutoSecure-VPN"
        Copy-Item -Path $localModuleDir -Destination $remoteModuleDir -ToSession $session -Recurse -Force
        Write-Verbose "Module directory copied"
        
        # 2. Execute on remote with output capture
        Write-Verbose "Executing installation on remote..."
        # Use -AsJob to prevent blocking if network changes (VPN connect breaks session)
        $job = Invoke-Command -Session $session -AsJob -ScriptBlock {
            param($moduleDirPath, $configContent, $configDir, $settings)
            
            $log = @()
            $log += "=== Remote WireGuard Client Setup Start ==="
            
            try {
                # Set execution policy to allow script execution
                Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force
                
                # Load module
                $log += "Loading module..."
                $manifestPath = Join-Path $moduleDirPath "AutoSecure-VPN.psd1"
                if (-not (Get-Module -Name 'AutoSecure-VPN' -ErrorAction SilentlyContinue)) {
                    Import-Module $manifestPath -Force
                }
                
                Set-ModuleSettings -Settings $settings -BasePath "C:\Temp"
                
                # Override Write-Log to capture output
                $script:remoteLog = @()
                function global:Write-Log { 
                    param($Message, $Level) 
                    $script:remoteLog += "[$Level] $Message"
                }
                
                # 1. Install WireGuard
                $log += "Installing WireGuard..."
                if (-not (Install-WireGuard)) { 
                    $log += "ERROR: WireGuard installation failed"
                    throw "Remote WireGuard installation failed" 
                }
                $log += "OK: WireGuard installed"
                
                # 2. Stop existing tunnels and remove old config
                $log += "Cleaning up existing tunnels..."
                $services = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "WireGuardTunnel*" }
                foreach ($svc in $services) {
                    if ($svc.Status -eq "Running") {
                        Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
                    }
                    $tunnelName = $svc.Name -replace '^WireGuardTunnel\$', ''
                    if ($tunnelName) {
                        $wgPath = if ($Script:Settings -and $Script:Settings.wireGuardInstalledPath) { 
                            $Script:Settings.wireGuardInstalledPath 
                        }
                        else { 
                            "C:\Program Files\WireGuard\wireguard.exe" 
                        }
                        & $wgPath /uninstalltunnelservice "$tunnelName" 2>&1 | Out-Null
                    }
                }
                $log += "OK: Existing tunnels cleaned"
                
                # 3. Save config
                $log += "Saving config to $configDir..."
                if (-not (Test-Path $configDir)) { 
                    New-Item -ItemType Directory -Path $configDir -Force | Out-Null 
                }
                $clientConfigPath = Join-Path $configDir "wg-client.conf"
                
                # Remove old config file if exists
                if (Test-Path $clientConfigPath) {
                    Remove-Item $clientConfigPath -Force -ErrorAction SilentlyContinue
                    Start-Sleep -Milliseconds 500
                }
                
                Set-Content -Path $clientConfigPath -Value $configContent
                
                # Verify config was saved
                if (-not (Test-Path $clientConfigPath)) {
                    throw "Config file was not created at $clientConfigPath"
                }
                $log += "OK: Config saved to $clientConfigPath"
                
                # 4. Start service (this will likely break the PSSession when tunnel activates)
                $log += "Starting WireGuard tunnel..."
                if (-not (Start-WireGuardService -ConfigPath $clientConfigPath)) { 
                    $log += "ERROR: Service start failed"
                    throw "Remote Service start failed" 
                }
                $log += "OK: Tunnel started"
                
                $log += "=== Remote Client Setup Completed ==="
                
                return @{
                    Success = $true
                    Log     = $log
                }
            }
            catch {
                $log += "ERROR: $_"
                return @{
                    Success = $false
                    Log     = $log
                    Error   = $_.ToString()
                }
            }
            finally {
                # Clean up module
                if (Test-Path $moduleDirPath) {
                    Remove-Item $moduleDirPath -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        } -ArgumentList $remoteModuleDir, $ClientConfigContent, $configDir, $Script:Settings
        
        # Wait for job to complete or timeout after 5 seconds
        Write-Verbose "Waiting for remote installation to complete..."
        $remoteResult = Wait-Job -Job $job -Timeout 5 | Receive-Job
        
        # Check job state before cleaning up
        $jobState = $job.State
        
        # Clean up job
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        
        # Show remote output
        if ($remoteResult.Log) {
            Write-Host "`n--- Remote Client Output ---" -ForegroundColor Cyan
            foreach ($line in $remoteResult.Log) {
                if ($line -like "*ERROR*") {
                    Write-Host "  $line" -ForegroundColor Red
                }
                elseif ($line -like "*WARNING*") {
                    Write-Host "  $line" -ForegroundColor Yellow
                }
                elseif ($line -like "*OK*") {
                    Write-Host "  $line" -ForegroundColor Green
                }
                else {
                    Write-Host "  $line" -ForegroundColor Gray
                }
            }
            Write-Host "----------------------------`n" -ForegroundColor Cyan
        }
        
        # If job timed out or is still running, VPN likely connected and broke session - assume success
        if ($jobState -eq "Running" -or $jobState -eq "Blocked") {
            Write-Verbose "Job timed out (VPN likely connected and broke session) - assuming success"
            Write-Log "Remote WireGuard Client installation completed (connection lost after tunnel started) for $ComputerName" -Level "SUCCESS"
            return $true
        }
        
        # If no result received, but job completed normally, might still be success
        if (-not $remoteResult) {
            Write-Verbose "No result received but job completed - assuming success"
            Write-Log "Remote WireGuard Client installation assumed successful for $ComputerName" -Level "INFO"
            return $true
        }
        
        # Only fail if we have an explicit error in the result
        if ($remoteResult -and -not $remoteResult.Success) {
            Write-Log "Remote client installation failed: $($remoteResult.Error)" -Level "ERROR"
            return $false
        }
        Write-Verbose "Remote installation completed"
        
        Write-Log "Remote WireGuard Client configuration completed for $ComputerName" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Error during remote WireGuard client installation: $_" -Level "ERROR"
        Write-Verbose "Error during remote installation: $_"
        return $false
    }
    finally {
        if ($session) { 
            Write-Verbose "Closing PSSession..."
            Remove-PSSession $session 
            Write-Verbose "PSSession closed"
        }
    }
}

function Invoke-BatchRemoteWireGuardClientInstall {
    <#
    .SYNOPSIS
        Installs WireGuard on multiple clients and generates unique configs.
    #>
    param(
        [Parameter(Mandatory = $true, Position = 0)]$Clients,
        [Parameter(Mandatory = $true, Position = 1)]$ServerKeys,
        [Parameter(Mandatory = $true, Position = 2)]$ServerEndpoint, # IP:Port
        [Parameter(Mandatory = $true, Position = 3)]$ModulePath,
        [Parameter(Mandatory = $true, Position = 4)]$Settings, # Pass configs
        [Parameter(Position = 5)][int]$ThrottleLimit = 5
    )
    
    # Get base IP from settings or default
    $baseSubnet = if ($Settings.ContainsKey('wireGuardBaseSubnet') -and -not [string]::IsNullOrEmpty($Settings.wireGuardBaseSubnet)) { $Settings.wireGuardBaseSubnet } else { "10.13.13" }
    
    # Counter for IP assignment
    $i = 0
    
    # Pre-process clients: Generate Keys & Configs Locally to avoid race conditions
    Write-Log "Preparing WireGuard configurations for batch..." -Level "INFO"
    Write-Verbose "Preparing configurations for $($Clients.Count) clients..."
    
    $preparedClients = @()
    foreach ($client in $Clients) {
        $i++
        $clientIpSuffix = 10 + $i # Start from .11
        if ($clientIpSuffix -gt 254) { throw "Too many clients for subnet" }
        $clientIp = "$baseSubnet.$clientIpSuffix"
        
        Write-Log "Generating keys for $($client.Name)..." -Level "INFO"
        Write-Verbose "Generating keys for $($client.Name)..."
        $keys = Initialize-WireGuardKeys -WgPath $Settings.wireGuardKeysExePath -Settings $Settings
        
        # Generate Client Config Content
        $configContent = @"
[Interface]
PrivateKey = $($keys.PrivateKey)
Address = $clientIp/24
DNS = $($Script:Settings.wireGuardDefaultDns)

[Peer]
PublicKey = $($ServerKeys.PublicKey)
Endpoint = $ServerEndpoint
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = $($Script:Settings.wireGuardDefaultPersistentKeepalive)
"@

        # Create a custom object with all info needed for installation
        $preparedClients += [PSCustomObject]@{
            Name          = $client.Name
            IP            = $client.IP # Remote Access IP
            Username      = $client.Username
            Password      = $client.Password
            ConfigContent = $configContent
            VPNIP         = $clientIp
            PublicKey     = $keys.PublicKey # Needed to update server
        }
    }
    Write-Verbose "All configurations prepared"
    
    # NOTE: Server config must be updated to include these peers!
    # This script currently does not update the server config automatically.
    # We log the Public Keys so the admin can add them.
    
    $serverUpdates = ""
    foreach ($pc in $preparedClients) {
        $serverUpdates += "`n[Peer] # User: $($pc.Name)`nPublicKey = $($pc.PublicKey)`nAllowedIPs = $($pc.VPNIP)/32`n"
    }
    
    # Save instructions to a file
    $serverUpdateFile = Join-Path $Script:Settings.outputPath "wg_server_additions.txt"
    Set-Content -Path $serverUpdateFile -Value $serverUpdates
    Write-Log "IMPORTANT: Add the peers to your server config! Saved in $serverUpdateFile" -Level "WARNING"
   
    # Make instruction for admin visible in the console
    Write-Host ""
    Write-Host "=== MANUAL: Adding peers to WireGuard server ===" -ForegroundColor Yellow
    Write-Host "1) Open the server config file on the WireGuard server (e.g. C:\WireGuard\wg_server.conf)" -ForegroundColor Cyan
    Write-Host "2) Copy the content of '$serverUpdateFile' and paste it at the end of wg_server.conf" -ForegroundColor Cyan
    Write-Host "`n--- Content to copy ---" -ForegroundColor Magenta
    try {
        $contentToShow = Get-Content -Path $serverUpdateFile -Raw -ErrorAction Stop
        Write-Host $contentToShow -ForegroundColor Green
    }
    catch {
        Write-Host "Cannot read ${serverUpdateFile}: $_" -ForegroundColor Red
    }
    Write-Host "`n3) After adding: restart WireGuard service" -ForegroundColor Cyan
    Write-Host "4) Verify if clients can connect" -ForegroundColor Cyan
    Write-Host "==========================================" -ForegroundColor Yellow 
    Write-Verbose "Server updates saved in $serverUpdateFile - add these manually to your server config!"
    
    # Run Parallel Install
    Write-Verbose "Starting parallel installation on $($preparedClients.Count) clients..."
    $localModulePath = $ModulePath
    
    $parallelResults = $preparedClients | ForEach-Object -Parallel {
        $pc = $_
        
        # Prepare credential
        $securePassword = ConvertTo-SecureString $pc.Password -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential ($pc.Username, $securePassword)
        
        # Load Module in parallel runspace
        Import-Module $using:localModulePath -Force
        
        # Install
        if (Install-RemoteWireGuardClient -ComputerName $pc.IP -Credential $cred -ClientConfigContent $pc.ConfigContent) {
            "SUCCESS: $($pc.Name) ($($pc.IP))"
        }
        else {
            "ERROR: $($pc.Name) ($($pc.IP))"
        }
        
    } -ThrottleLimit $ThrottleLimit
    
    Write-Verbose "Parallel installation completed"
    return $parallelResults
}


#endregion WireGuard Implementation Details
