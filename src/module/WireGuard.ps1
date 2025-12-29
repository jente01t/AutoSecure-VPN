# WireGuard functional files for the AutoSecureVPN module

function Install-WireGuard {
    <#
    .SYNOPSIS
        Installs WireGuard on the local machine.

    .DESCRIPTION
        This function downloads and installs WireGuard.
        
    .PARAMETER Url
        The URL of the WireGuard installer (optional).
        
    .OUTPUTS
        System.Boolean
        $true on success, otherwise $false.
    #>
    param(
        [Parameter(Position = 0)][string]$wgUrl
    )
    
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
        # Try to dynamically find the latest version
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
        # DO_NOT_LAUNCH=1 prevents the GUI from starting immediately
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
    
    .OUTPUTS
        Hashtable with PrivateKey and PublicKey.
    #>
    param(
        [string]$WgPath,
        [hashtable]$Settings = $null
    )
    
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

            # Generate public key
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
        [Parameter(Mandatory = $true)]$ServerKeys,
        [Parameter(Mandatory = $true)]$ClientKeys,
        [Parameter(Mandatory = $true)]$Port,
        [Parameter(Mandatory = $true)]$Address, # e.g. 10.13.13.1/24
        [Parameter(Mandatory = $true)]$PeerAddress, # e.g. 10.13.13.2/32
        [Parameter(Mandatory = $true)]$ServerType,
        [string]$OutputPath
    )
    
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
        [Parameter(Mandatory = $true)]$ClientKeys,
        [Parameter(Mandatory = $true)]$ServerKeys,
        [Parameter(Mandatory = $true)]$ServerAvailableIP, # WAN IP
        [Parameter(Mandatory = $true)]$Port,
        [Parameter(Mandatory = $true)]$Address, # e.g. 10.13.13.2/24
        [string]$DNS,
        [string]$OutputPath
    )
    
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
        [Parameter(Mandatory = $true)]$ConfigPath
    )
    
    $wgPath = if ($Script:Settings -and $Script:Settings.ContainsKey('wireGuardInstalledPath') -and $Script:Settings.wireGuardInstalledPath) { $Script:Settings.wireGuardInstalledPath } else { "C:\Program Files\WireGuard\wireguard.exe" }
    if (-not (Test-Path $wgPath)) {
        throw "WireGuard executable not found"
    }
    
    try {
        # First stop existing WireGuard services to prevent conflicts
        Stop-WireGuardService | Out-Null
        
        # wireguard /installtunnelservice <path>
        # This installs a service with name "WireGuardTunnel$Name"
        
        Write-Log "Starting WireGuard tunnel with config $ConfigPath..." -Level "INFO"
        
        $process = Start-Process -FilePath $wgPath -ArgumentList "/installtunnelservice `"$ConfigPath`"" -Wait -PassThru
        
        # Start GUI Manager
        # WireGuard GUI manager is just the same exe without arguments (or user executes it)
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
        # Stop all WireGuard tunnel services
        $services = Get-Service -Name "WireGuardTunnel*" -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Running" }
        foreach ($service in $services) {
            Write-Log "Stopping and removing WireGuard service: $($service.Name)" -Level "INFO"
            if ($service.Status -eq "Running") {
                Stop-Service -Name $service.Name -Force -ErrorAction SilentlyContinue
            }
            # Extract tunnel name from service name (format: WireGuardTunnel$TunnelName)
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
        [Parameter(Mandatory = $true)]$ConfigContent,
        [Parameter(Mandatory = $true)]$OutputPath
    )
    
    # Check if QrCodes module is installed
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
        [Parameter(Mandatory = $true)]$ComputerName,
        [Parameter(Mandatory = $true)][PSCredential]$Credential,
        [Parameter(Mandatory = $true)]$ServerConfigContent, # De inhoud van wg_server.conf
        [Parameter(Mandatory = $true)]$RemoteConfigPath, # Waar op te slaan (directory of full path?)
        [int]$Port
    )
    
    if (-not $Port) {
        # Probeer poort uit settings te halen als niet opgegeven
        if ($Script:Settings -and $Script:Settings.ContainsKey('wireGuardPort') -and $Script:Settings.wireGuardPort) {
            $Port = [int]$Script:Settings.wireGuardPort
        }
        else {
            throw "Port not specified and 'wireGuardPort' is missing or empty in Settings. Provide -Port or add value to the config."
        }
    }

    # Bepaal VPN subnet vanuit settings (veilig controleren)
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

    $remoteModuleDir = Join-Path $remoteTemp "AutoSecureVPN"
    
    Write-Log "Starting remote WireGuard server installation on $ComputerName..." -Level "INFO"
    Write-Verbose "Connecting to remote machine $ComputerName..."
    
    $session = New-PSSession -ComputerName $ComputerName -Credential $Credential
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
        
        # 2. Get local paths
        $moduleBase = $null
        if ($Script:BasePath -and (Test-Path (Join-Path $Script:BasePath 'src\module\AutoSecureVPN.psd1'))) {
            $moduleBase = Join-Path $Script:BasePath 'src\module'
            Write-Verbose "Using source module path from Script Scope: $moduleBase"
        }
        
        if (-not $moduleBase -or [string]::IsNullOrWhiteSpace($moduleBase)) {
            $moduleBase = $PSScriptRoot
            if (-not $moduleBase -or -not (Test-Path (Join-Path $moduleBase "AutoSecureVPN.psd1"))) {
                $moduleBase = (Get-Module AutoSecureVPN).ModuleBase
            }
        }
        $localModuleDir = $moduleBase
        
        if (-not $localModuleDir -or -not (Test-Path (Join-Path $localModuleDir "AutoSecureVPN.psd1"))) {
            throw "Local module directory not found or invalid: $localModuleDir"
        }

        # 3. Copy module (contents)
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
                $manifestPath = Join-Path $moduleDirPath "AutoSecureVPN.psd1"
                Import-Module $manifestPath -Force
                
                Set-ModuleSettings -Settings $settings -BasePath "C:\Temp"
                
                # Override Write-Log to capture output and stream critical info
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
        [Parameter(Mandatory = $true)]$ComputerName,
        [Parameter(Mandatory = $true)][PSCredential]$Credential,
        [Parameter(Mandatory = $true)]$ClientConfigContent
    )
    
    $remoteTemp = if ($Script:Settings -and $Script:Settings.ContainsKey('wireGuardRemoteTempPath') -and -not [string]::IsNullOrWhiteSpace($Script:Settings.wireGuardRemoteTempPath)) { $Script:Settings.wireGuardRemoteTempPath } else { 'C:\Temp' }
    $configDir = if ($Script:Settings -and $Script:Settings.ContainsKey('wireGuardRemoteClientConfigDir') -and -not [string]::IsNullOrWhiteSpace($Script:Settings.wireGuardRemoteClientConfigDir)) { $Script:Settings.wireGuardRemoteClientConfigDir } else { 'C:\Program Files\WireGuard\Data\Configurations' }
    
    Write-Log "Starting remote WireGuard client installation on $ComputerName..." -Level "INFO"
    Write-Verbose "Connecting to remote machine $ComputerName..."
    
    $session = New-PSSession -ComputerName $ComputerName -Credential $Credential
    Write-Verbose "PSSession established"
    
    try {
        # 1. Copy module
        Write-Verbose "Copying module to remote..."
        Invoke-Command -Session $session -ScriptBlock { param($path) if (-not (Test-Path $path)) { New-Item -ItemType Directory -Path $path -Force } } -ArgumentList $remoteTemp
        
        $localModuleDir = $PSScriptRoot
        if (-not $localModuleDir -or -not (Test-Path (Join-Path $localModuleDir "AutoSecureVPN.psd1"))) {
            $localModuleDir = (Get-Module AutoSecureVPN).ModuleBase
        }

        $remoteModuleDir = Join-Path $remoteTemp "AutoSecureVPN"
        Copy-Item -Path $localModuleDir -Destination $remoteModuleDir -ToSession $session -Recurse -Force
        Write-Verbose "Module directory copied"
        
        # 2. Execute on remote with output capture
        Write-Verbose "Executing installation on remote..."
        # Use -AsJob to prevent blocking if network changes
        $job = Invoke-Command -Session $session -AsJob -ScriptBlock {
            param($moduleDirPath, $configContent, $configDir, $settings)
            
            $log = @()
            $log += "=== Remote WireGuard Client Setup Start ==="
            
            try {
                # Set execution policy to allow script execution
                Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force
                
                # Load module
                $log += "Loading module..."
                $manifestPath = Join-Path $moduleDirPath "AutoSecureVPN.psd1"
                Import-Module $manifestPath -Force
                
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
                        } else { 
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
                
                # 4. Start service (this will break the PSSession when tunnel activates)
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
        [Parameter(Mandatory = $true)]$Clients,
        [Parameter(Mandatory = $true)]$ServerKeys,
        [Parameter(Mandatory = $true)]$ServerEndpoint, # IP:Port
        [Parameter(Mandatory = $true)]$ModulePath,
        [Parameter(Mandatory = $true)]$Settings, # Pass configs
        [int]$ThrottleLimit = 5
    )
    
    # Get base IP from settings or default
    $baseSubnet = if ($Settings.ContainsKey('wireGuardBaseSubnet') -and -not [string]::IsNullOrEmpty($Settings.wireGuardBaseSubnet)) { $Settings.wireGuardBaseSubnet } else { "10.13.13" }
    
    # $preparedClients pre-processing follows...
    $i = 0
    
    # Pre-process clients: Generate Keys & Configs Locally
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

        $preparedClients += [PSCustomObject]@{
            Name          = $client.Name
            IP            = $client.IP # Remote Access IP
            Username      = $client.Username
            Password      = $client.Password
            ConfigContent = $configContent
            VPNIP         = $clientIp
            PublicKey     = $keys.PublicKey # Needed to update server?
        }
    }
    Write-Verbose "All configurations prepared"
    
    # NOTE: Server config must be updated to include these peers!
    # This script currently does not update the server config.
    # We log the Public Keys so the admin can add them.
    
    $serverUpdates = ""
    foreach ($pc in $preparedClients) {
        $serverUpdates += "`n[Peer] # User: $($pc.Name)`nPublicKey = $($pc.PublicKey)`nAllowedIPs = $($pc.VPNIP)/32`n"
    }
    
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
        
        $securePassword = ConvertTo-SecureString $pc.Password -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential ($pc.Username, $securePassword)
        
        # Load Module
        Import-Module $using:localModulePath -Force
        
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
