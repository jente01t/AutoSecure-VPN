# Orchestration logic for OpenVPN setup
# Copy the full function definitions from main.ps1 to here.

function Invoke-OpenVPNClientSetup {
    <#
    .SYNOPSIS
        Performs full VPN client setup.

    .DESCRIPTION
        This function performs all steps for setting up an OpenVPN client, including installation, importing configuration, and starting the connection.

    .EXAMPLE
        Invoke-ClientSetup
    #>
    
    Write-Log "=== Client Setup Started ===" -Level "INFO"
    
    try {
        # Step 1: Administrator check
        Write-Progress -Activity "Client Setup" -Status "Step 1 of 6: Checking administrator privileges" -PercentComplete 0
        Write-Host "`n[1/6] Checking administrator privileges..." -ForegroundColor Cyan
        if (-not (Test-IsAdmin)) {
            throw "Script must be run as Administrator!"
        }
        Write-Host "  ✓ Administrator privileges confirmed" -ForegroundColor Green
        Write-Verbose "Administrator privileges successfully checked"
        Write-Log "Administrator privileges confirmed" -Level "INFO"
        
        # Step 2: Install OpenVPN
        Write-Progress -Activity "Client Setup" -Status "Step 2 of 6: Installing OpenVPN" -PercentComplete 16.67
        Write-Host "`n[2/6] Installing OpenVPN..." -ForegroundColor Cyan
        if (-not (Install-OpenVPN)) {
            throw "OpenVPN installation failed"
        }
        Write-Host "  ✓ OpenVPN installed" -ForegroundColor Green
        Write-Verbose "OpenVPN successfully installed"
        Write-Log "OpenVPN installed" -Level "INFO"
        
        # Step 3: Import client configuration
        Write-Progress -Activity "Client Setup" -Status "Step 3 of 6: Importing client configuration" -PercentComplete 33.33
        Write-Host "`n[3/6] Importing client configuration..." -ForegroundColor Cyan
        $configPath = Import-ClientConfiguration
        if (-not $configPath) {
            throw "Client configuration import failed"
        }
        Write-Host "  ✓ Configuration imported" -ForegroundColor Green
        Write-Verbose "Client configuration successfully imported from $configPath"
        Write-Log "Client configuration imported" -Level "INFO"
        
        # Step 4: Check TAP adapter
        Write-Progress -Activity "Client Setup" -Status "Step 4 of 6: Checking TAP adapter" -PercentComplete 50
        Write-Host "`n[4/6] Checking TAP adapter..." -ForegroundColor Cyan
        if (-not (Test-TAPAdapter)) {
            Write-Host "  ! TAP adapter not found, OpenVPN may need to be reinstalled" -ForegroundColor Yellow
            Write-Log "TAP adapter not found" -Level "WARNING"
            Write-Verbose "TAP adapter not found, reinstallation might be necessary"
        }
        else {
            Write-Host "  ✓ TAP adapter found" -ForegroundColor Green
            Write-Verbose "TAP adapter successfully found"
            Write-Log "TAP adapter found" -Level "INFO"
        }
        
        # Step 5: Start VPN connection
        Write-Progress -Activity "Client Setup" -Status "Step 5 of 6: Starting VPN connection" -PercentComplete 66.67
        Write-Host "`n[5/6] Starting VPN connection..." -ForegroundColor Cyan
        if (-not (Start-VPNConnection -ConfigFile $configPath)) {
            throw "Starting VPN connection failed"
        }
        Write-Host "  ✓ VPN connection started" -ForegroundColor Green
        Write-Verbose "VPN connection successfully started"
        Write-Log "VPN connection started" -Level "INFO"
        
        # Step 6: Test connection
        Write-Progress -Activity "Client Setup" -Status "Step 6 of 6: Testing VPN connection" -PercentComplete 83.33
        Write-Host "`n[6/6] Testing VPN connection..." -ForegroundColor Cyan
        Start-Sleep -Seconds 30  # Wait longer for connection to be fully established
        $testResult = Test-VPNConnection
        if (-not $testResult) {
            throw "VPN connection test failed"
        }
        Write-Verbose "VPN connection successfully tested"
        Write-Log "VPN connection tested" -Level "INFO"
        
        Write-Progress -Activity "Client Setup" -Completed
        
        Show-Menu -Mode Success -SuccessTitle "Client Setup Successfully Completed!" -LogFile $script:LogFile
    }
    catch {
        Write-Progress -Activity "Client Setup" -Completed
        Write-Log "Error during Client Setup: $($_.Exception.Message)" -Level "ERROR"
        $choice = Show-Menu -Mode Error -SuccessTitle "Client Setup Failed!" -LogFile $script:LogFile -ExtraMessage "Check the log file for details." -Options @("Try again", "Back to main menu", "Exit")
        switch ($choice) {
            1 {
                # Perform rollback before retrying
                Write-Host "`n[*] Performing rollback to undo changes..." -ForegroundColor Yellow
                Invoke-Rollback -SetupType "Client"
                Invoke-OpenVPNClientSetup
            }
            2 {
                # Perform rollback before returning to main menu
                Write-Host "`n[*] Performing rollback to undo changes..." -ForegroundColor Yellow
                Invoke-Rollback -SetupType "Client"
                Start-VPNSetup
            }
            3 {
                # Perform rollback before exiting
                Write-Host "`n[*] Performing rollback to undo changes..." -ForegroundColor Yellow
                Invoke-Rollback -SetupType "Client"
                exit
            }
        }
    }
}
function Invoke-RemoteOpenVPNClientSetup {
    <#
    .SYNOPSIS
        Performs remote VPN client setup.

    .DESCRIPTION
        This function performs setup for a VPN client on a remote machine via PowerShell remoting.

    .EXAMPLE
        Invoke-RemoteClientSetup
    #>
    
    Write-Log "=== Remote Client Setup Started ===" -Level "INFO"
    
    try {
        # Step 1: Administrator check (for local machine)
        Write-Progress -Activity "Remote Client Setup" -Status "Step 1 of 5: Checking administrator privileges" -PercentComplete 0
        Write-Host "`n[1/5] Checking administrator privileges..." -ForegroundColor Cyan
        if (-not (Test-IsAdmin)) {
            throw "Script must be run as Administrator!"
        }
        Write-Host "  ✓ Administrator privileges confirmed" -ForegroundColor Green
        Write-Verbose "Local administrator privileges successfully checked"
        Write-Log "Administrator privileges confirmed" -Level "INFO"
        
        # Step 2: Remote computer details - use settings when available
        Write-Progress -Activity "Remote Client Setup" -Status "Step 2 of 5: Remote computer configuration" -PercentComplete 20
        Write-Host "`n[2/5] Remote computer configuration..." -ForegroundColor Cyan

        # Retrieve and validate remoteClientIP; if empty -> error (no prompt)
        try {
            if ($Script:Settings.ContainsKey('remoteClientIP') -and -not [string]::IsNullOrWhiteSpace($Script:Settings.remoteClientIP) -and $Script:Settings.remoteClientIP -ne 'your.client.ip.here') {
                $computerName = $Script:Settings.remoteClientIP
                Write-Verbose "Remote client obtained from settings: $computerName"
            }
        }
        catch {
            Write-Verbose "Error retrieving remoteClientIP from settings: $_"
        }

        if ([string]::IsNullOrWhiteSpace($computerName)) {
            throw "Setting 'remoteClientIP' is empty or invalid in Variable.psd1. Please fill in 'remoteClientIP' or adjust the configuration."
        }
        
        Write-Host "  ✓ Remote computer: $computerName" -ForegroundColor Green
        Write-Verbose "Remote computer name used: $computerName"
        Write-Log "Remote computer: $computerName" -Level "INFO"
        
        # Step 3: WinRM configuration
        Write-Progress -Activity "Remote Client Setup" -Status "Step 3 of 5: Checking WinRM configuration" -PercentComplete 40
        Write-Host "`n[3/5] Checking WinRM configuration..." -ForegroundColor Cyan
        try {
            $trustedHosts = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Client -Name TrustedHosts -ErrorAction Stop).TrustedHosts
        }
        catch {
            $trustedHosts = ""
        }
        if ($trustedHosts -notlike "*$computerName*" -and $trustedHosts -ne "*") {
            Write-Host "  Remote computer not in TrustedHosts. Adding..." -ForegroundColor Yellow
            Set-Item WSMan:\localhost\client\TrustedHosts -Value $computerName -Concatenate -Force
            Restart-Service winrm -Force
            Write-Host "  ✓ $computerName added to TrustedHosts and WinRM restarted" -ForegroundColor Green
            Write-Verbose "TrustedHosts updated and WinRM restarted"
            Write-Log "$computerName added to TrustedHosts and WinRM restarted" -Level "INFO"
        }
        elseif ($trustedHosts -eq "*") {
            Write-Host "  ✓ TrustedHosts is set to wildcard (*), no addition needed" -ForegroundColor Green
            Write-Verbose "TrustedHosts set to wildcard"
            Write-Log "TrustedHosts set to wildcard (*)" -Level "INFO"
        }
        else {
            Write-Host "  ✓ $computerName is already in TrustedHosts" -ForegroundColor Green
            Write-Verbose "$computerName is already in TrustedHosts"
            Write-Log "$computerName is already in TrustedHosts" -Level "INFO"
        }
        
        Write-Host "  Checking if PSRemoting is active on remote machine..." -ForegroundColor Cyan
        try {
            Test-WSMan -ComputerName $computerName -ErrorAction Stop | Out-Null
            Write-Host "  ✓ PSRemoting is active on $computerName" -ForegroundColor Green
            Write-Verbose "PSRemoting successfully tested on $computerName"
            Write-Log "PSRemoting active on $computerName" -Level "INFO"
        }
        catch {
            Write-Host "  ! PSRemoting does not seem to be active on $computerName" -ForegroundColor Yellow
            Write-Host "    Make sure 'Enable-PSRemoting -Force' has been executed on the remote machine" -ForegroundColor Yellow
            $continue = Read-Host "  Continue? (Y/N)"
            if ($continue -notmatch "^[Yy]") {
                throw "PSRemoting not available on remote machine"
            }
            Write-Verbose "PSRemoting not available, but user chose to continue"
        }
        
        # Step 4: Credentials
        Write-Progress -Activity "Remote Client Setup" -Status "Step 4 of 5: Authentication" -PercentComplete 60
        Write-Host "`n[4/5] Authentication..." -ForegroundColor Cyan
        $cred = Get-Credential -Message "Enter credentials for $computerName (must be Administrator)"
        if (-not $cred) {
            throw "Credentials are required"
        }
        Write-Host "  ✓ Credentials entered" -ForegroundColor Green
        Write-Verbose "Credentials successfully entered for $computerName"
        Write-Log "Credentials entered for $computerName" -Level "INFO"
        
        # Step 5: Client ZIP file
        Write-Progress -Activity "Remote Client Setup" -Status "Step 5 of 5: Client configuration file" -PercentComplete 80
        Write-Host "`n[5/5] Client configuration file..." -ForegroundColor Cyan
        # Determine default client name (multiple settings keys possible)
        $clientDefaultName = if ($Script:Settings.ContainsKey('clientName') -and -not [string]::IsNullOrWhiteSpace($Script:Settings.clientName)) { $Script:Settings.clientName } else { 'client' }
        $defaultZipPath = Join-Path $Script:Settings.OutputPath "vpn-client-$clientDefaultName.zip"
        if (Test-Path $defaultZipPath) {
            $zipPath = $defaultZipPath
            Write-Host "  ✓ Default client ZIP file found: $zipPath" -ForegroundColor Green
            Write-Verbose "Default client ZIP file used: $zipPath"
            Write-Log "Default client ZIP file found: $zipPath" -Level "INFO"
        }
        else {
            Write-Host "  Default client ZIP file not found at $defaultZipPath" -ForegroundColor Yellow
            $zipPath = Read-Host "  Path to client ZIP file (generated by server setup)"
            Write-Verbose "Manual ZIP path entered: $zipPath"
        }
        if (-not (Test-Path $zipPath)) {
            throw "ZIP file not found: $zipPath"
        }
        Write-Host "  ✓ ZIP file found: $zipPath" -ForegroundColor Green
        Write-Log "ZIP file found: $zipPath" -Level "INFO"
        
        # Perform remote installation
        Write-Progress -Activity "Remote Client Setup" -Status "Performing remote installation" -PercentComplete 90
        Write-Host "`n[*] Starting remote installation..." -ForegroundColor Cyan
        if (-not (Install-RemoteClient -ComputerName $computerName -Credential $cred -ZipPath $zipPath -RemoteConfigPath $Script:Settings.remoteConfigPath)) {
            throw "Remote client installation failed"
        }
        Write-Host "  ✓ Remote installation completed" -ForegroundColor Green
        Write-Verbose "Remote client installation successfully completed for $computerName"
        Write-Log "Remote client installation completed for $computerName" -Level "INFO"

        # Start remote OpenVPN service via GUI
        Write-Progress -Activity "Remote Client Setup" -Status "Starting OpenVPN service on remote machine" -PercentComplete 95
        Write-Host "`n[*] Starting OpenVPN service on remote machine..." -ForegroundColor Cyan
        $remoteOvpn = Join-Path $Script:Settings.remoteConfigPath "client.ovpn"
        if (-not (Start-VPNConnection -ConfigFile $remoteOvpn -ComputerName $computerName -Credential $cred)) {
            throw "Starting remote OpenVPN service failed"
        }
        Write-Host " ✓ Remote OpenVPN starting completed" -ForegroundColor Green
        Write-Verbose "Remote OpenVPN starting successfully completed for $computerName"
        Write-Log "Remote OpenVPN service started for $computerName" -Level "INFO"
        
        Write-Progress -Activity "Remote Client Setup" -Completed
        
        Show-Menu -Mode Success -SuccessTitle "Remote Client Setup Successfully Completed!" -LogFile $script:LogFile -ExtraMessage "On the remote machine you can now start the VPN connection via OpenVPN." -ComputerName $computerName
    }
    catch {
        Write-Progress -Activity "Remote Client Setup" -Completed
        Write-Log "Error during Remote Client Setup: $($_.Exception.Message)" -Level "ERROR"
        $choice = Show-Menu -Mode Error -SuccessTitle "Remote Client Setup Failed!" -LogFile $script:LogFile -ExtraMessage "Check the log file for details." -Options @("Try again", "Back to main menu", "Exit")
        switch ($choice) {
            1 { Invoke-RemoteOpenVPNClientSetup }
            2 { Start-VPNSetup }
            3 { exit }
        }
    }
}

function Invoke-OpenVPNServerSetup {
    <#
    .SYNOPSIS
        Performs full VPN server setup.

    .DESCRIPTION
        This function performs all steps for setting up an OpenVPN server, including installation, certificates, configuration, and starting the service.

    .EXAMPLE
        Invoke-ServerSetup
    #>
    
    Write-Log "=== Server Setup Started ===" -Level "INFO"
    
    try {
        # Step 1: Administrator check
        Write-Progress -Activity "Server Setup" -Status "Step 1 of 8: Checking administrator privileges" -PercentComplete 0
        Write-Host "`n[1/8] Checking administrator privileges..." -ForegroundColor Cyan
        if (-not (Test-IsAdmin)) {
            throw "Script must be run as Administrator!"
        }
        Write-Host "  ✓ Administrator privileges confirmed" -ForegroundColor Green
        Write-Verbose "Administrator privileges successfully checked"
        Write-Log "Administrator privileges confirmed" -Level "INFO"
        
        # Step 2: Install OpenVPN
        Write-Progress -Activity "Server Setup" -Status "Step 2 of 8: Installing OpenVPN" -PercentComplete 12.5
        Write-Host "`n[2/8] Installing OpenVPN..." -ForegroundColor Cyan
        if (-not (Install-OpenVPN)) {
            throw "OpenVPN installation failed"
        }
        Write-Host "  ✓ OpenVPN installed" -ForegroundColor Green
        Write-Verbose "OpenVPN successfully installed"
        Write-Log "OpenVPN installed" -Level "INFO"
        
        # Step 3: Configure firewall
        Write-Progress -Activity "Server Setup" -Status "Step 3 of 8: Configuring Windows Firewall" -PercentComplete 25
        Write-Host "`n[3/8] Configuring Windows Firewall..." -ForegroundColor Cyan
        if (-not (Set-Firewall -Port 443 -Protocol "TCP")) {
            throw "Firewall configuration failed"
        }
        Write-Host "  ✓ Firewall rules added" -ForegroundColor Green
        Write-Verbose "Firewall rules successfully added"
        Write-Log "Firewall rules added" -Level "INFO"
        
        # Step 4: Collect user input
        Write-Progress -Activity "Server Setup" -Status "Step 4 of 8: Collecting server configuration parameters" -PercentComplete 37.5
        Write-Host "`n[4/8] Server configuration parameters..." -ForegroundColor Cyan
        $serverConfig = Get-ServerConfiguration
        Write-Verbose "Server configuration parameters collected: $($serverConfig | ConvertTo-Json)"
        Write-Log "Server configuration parameters collected" -Level "INFO"
        
        # Step 5: EasyRSA and certificates
        Write-Progress -Activity "Server Setup" -Status "Step 5 of 8: Generating certificates" -PercentComplete 50
        Write-Host "`n[5/8] Generating certificates (this may take a while)..." -ForegroundColor Cyan
        if (-not (Initialize-EasyRSA)) {
            throw "EasyRSA initialization failed"
        }
        if (-not (Initialize-Certificates -ServerName $serverConfig.ServerName -Password $serverConfig.Password)) {
            throw "Certificate generation failed"
        }
        Write-Host "  ✓ Certificates generated" -ForegroundColor Green
        Write-Verbose "Certificates successfully generated for server $($serverConfig.ServerName)"
        Write-Log "Certificates generated" -Level "INFO"
        
        # Step 6: Generate server configuration
        Write-Progress -Activity "Server Setup" -Status "Step 6 of 8: Creating server configuration" -PercentComplete 62.5
        Write-Host "`n[6/8] Creating server configuration..." -ForegroundColor Cyan
        if (-not (New-ServerConfig -Config $serverConfig)) {
            throw "Server configuration generation failed"
        }
        Write-Host "  ✓ Server configuration created" -ForegroundColor Green
        Write-Verbose "Server configuration successfully created"
        Write-Log "Server configuration created" -Level "INFO"
        
        # Step 7: Start OpenVPN service
        Write-Progress -Activity "Server Setup" -Status "Step 7 of 8: Starting OpenVPN service" -PercentComplete 70
        Write-Host "`n[7/8] Starting OpenVPN service..." -ForegroundColor Cyan
        if (-not (Start-VPNService)) {
            throw "Starting OpenVPN service failed"
        }
        Write-Host "  ✓ OpenVPN service active" -ForegroundColor Green
        Write-Verbose "OpenVPN service successfully started"
        Write-Log "OpenVPN service active" -Level "INFO"
        
        # Step 7.5: Start OpenVPN via GUI
        Write-Progress -Activity "Server Setup" -Status "Step 7.5 of 8: Starting OpenVPN GUI with server config" -PercentComplete 75
        Write-Host "`n[7.5/8] Starting OpenVPN GUI with server config..." -ForegroundColor Cyan
        $serverConfigFile = Join-Path $Script:Settings.configPath "server.ovpn"
        if (-not (Start-VPNConnection -ConfigFile $serverConfigFile)) {
            Write-Host "  ! OpenVPN GUI start warning - manual start might be needed" -ForegroundColor Yellow
            Write-Log "OpenVPN GUI start warning" -Level "WARNING"
        }
        else {
            Write-Host "  ✓ OpenVPN GUI started with server config" -ForegroundColor Green
            Write-Verbose "OpenVPN GUI successfully started"
            Write-Log "OpenVPN GUI started" -Level "INFO"
        }
        
        # Wait for TAP adapter to become active
        Write-Host "`n[*] Waiting for TAP adapter to initialize..." -ForegroundColor Cyan
        Start-Sleep -Seconds 10
        
        # Step 7.75: Configure ICS for internet access
        Write-Progress -Activity "Server Setup" -Status "Step 7.75 of 8: Configuring ICS for internet access" -PercentComplete 80
        Write-Host "`n[7.75/8] Configuring ICS (Internet Connection Sharing)..." -ForegroundColor Cyan
        # Configuring NAT for internet access (10.8.0.0/24 = OpenVPN default subnet)
        if (-not (Enable-VPNNAT -VPNSubnet "10.8.0.0/24")) { 
            Write-Host "  ! ICS configuration warning - manual configuration might be needed" -ForegroundColor Yellow
            Write-Log "ICS configuration warning - manual setup might be needed" -Level "WARNING"
        }
        else {
            Write-Host "  ✓ ICS configured for VPN internet access" -ForegroundColor Green
            Write-Verbose "ICS successfully configured"
            Write-Log "ICS configured" -Level "INFO"
        }
        
        # Step 8: Create client package
        Write-Progress -Activity "Server Setup" -Status "Step 8 of 8: Creating client configuration package" -PercentComplete 87.5
        Write-Host "`n[8/8] Creating client configuration package..." -ForegroundColor Cyan
        $zipPath = New-ClientPackage -Config $serverConfig -OutputPath $Script:OutputPath
        if (-not $zipPath) {
            throw "Creating client package failed"
        }
        Write-Host "  ✓ Client package created: $zipPath" -ForegroundColor Green
        Write-Verbose "Client package successfully created: $zipPath"
        Write-Log "Client package created: $zipPath" -Level "INFO"
        
        Write-Progress -Activity "Server Setup" -Completed
        
        Show-Menu -Mode Success -SuccessTitle "Server Setup Successfully Completed!" -LogFile $script:LogFile -ExtraInfo "Client package: $zipPath" -ExtraMessage "Transfer this ZIP file to the client to establish the connection."
    }
    catch {
        Write-Progress -Activity "Server Setup" -Completed
        Write-Log "Error during Server Setup: $($_.Exception.Message)" -Level "ERROR"   
        $choice = Show-Menu -Mode Error -SuccessTitle "Server Setup Failed!" -LogFile $script:LogFile -ExtraMessage "Check the log file for details." -Options @("Try again", "Back to main menu", "Exit")
        switch ($choice) {
            1 {
                # Perform rollback before retrying
                Write-Host "`n[*] Performing rollback to undo changes..." -ForegroundColor Yellow
                Invoke-Rollback -SetupType "Server"
                Invoke-OpenVPNServerSetup
            }
            2 {
                # Perform rollback before returning to main menu
                Write-Host "`n[*] Performing rollback to undo changes..." -ForegroundColor Yellow
                Invoke-Rollback -SetupType "Server"
                Start-VPNSetup
            }
            3 {
                # Perform rollback before exiting
                Write-Host "`n[*] Performing rollback to undo changes..." -ForegroundColor Yellow
                Invoke-Rollback -SetupType "Server"
                exit
            }
        }
    }
}
function Invoke-RemoteOpenVPNServerSetup {
    <#
    .SYNOPSIS
        Performs remote VPN server setup.

    .DESCRIPTION
        This function performs setup for a VPN server on a remote machine via PowerShell remoting.

    .EXAMPLE
        Invoke-RemoteServerSetup
    #>
    
    Write-Log "=== Remote Server Setup Started ===" -Level "INFO"
    
    try {
        # Step 1: Administrator check (for local machine)
        Write-Progress -Activity "Remote Server Setup" -Status "Step 1 of 8: Checking administrator privileges" -PercentComplete 0
        Write-Host "`n[1/8] Checking administrator privileges..." -ForegroundColor Cyan
        if (-not (Test-IsAdmin)) {
            throw "Script must be run as Administrator!"
        }
        Write-Host "  ✓ Administrator privileges confirmed" -ForegroundColor Green
        Write-Verbose "Local administrator privileges successfully checked"
        Write-Log "Administrator privileges confirmed" -Level "INFO"
        # Step 1.5: Check local OpenVPN installation
        Write-Progress -Activity "Remote Server Setup" -Status "Step 1.5 of 8: Checking local OpenVPN installation" -PercentComplete 6
        if (-not (Test-Path $Script:Settings.installedPath)) {
            Write-Host "`n[1.5] Installing OpenVPN locally for certificate generation..." -ForegroundColor Cyan
            if (-not (Install-OpenVPN)) {
                throw "Local OpenVPN installation failed"
            }
            Write-Host "  ✓ OpenVPN installed locally" -ForegroundColor Green
            Write-Verbose "OpenVPN installed locally for certificate generation"
            Write-Log "OpenVPN installed locally" -Level "INFO"
        }
        else {
            Write-Verbose "OpenVPN already installed locally"
        }
        
        # Step 2: Remote computer details
        Write-Progress -Activity "Remote Server Setup" -Status "Step 2 of 8: Remote computer configuration" -PercentComplete 12
        Write-Host "`n[2/8] Remote computer configuration..." -ForegroundColor Cyan
        # Retrieve Settings.serverIP
        try {
            if ($Script:Settings.ContainsKey('serverIP') -and -not [string]::IsNullOrWhiteSpace($Script:Settings.serverIP) -and $Script:Settings.serverIP -ne 'your.server.ip.here') {
                $computerName = $Script:Settings.serverIP
                Write-Verbose "Remote server IP obtained from settings: $computerName"
            } 
        }    
        catch {
            throw "Server IP address is empty in Variable.psd1"
        }

        if ([string]::IsNullOrWhiteSpace($computerName)) {
            throw "Setting 'remoteClientIP' is empty or invalid in Variable.psd1. Please fill in 'remoteClientIP' or adjust the configuration."
        }
        
        Write-Host "  ✓ Remote computer: $computerName" -ForegroundColor Green
        Write-Verbose "Remote computer name used: $computerName"
        Write-Log "Remote computer: $computerName" -Level "INFO"
        
        # Step 3: WinRM configuration
        Write-Progress -Activity "Remote Server Setup" -Status "Step 3 of 8: Checking WinRM configuration" -PercentComplete 25
        Write-Host "`n[3/8] Checking WinRM configuration..." -ForegroundColor Cyan
        try {
            $trustedHosts = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Client -Name TrustedHosts -ErrorAction Stop).TrustedHosts
        }
        catch {
            $trustedHosts = ""
        }
        if ($trustedHosts -notlike "*$computerName*" -and $trustedHosts -ne "*") {
            Write-Host "  Remote computer not in TrustedHosts. Adding..." -ForegroundColor Yellow
            $newTrustedHosts = if ($trustedHosts) { "$trustedHosts,$computerName" } else { $computerName }
            Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Client -Name TrustedHosts -Value $newTrustedHosts
            Restart-Service winrm -Force
            Write-Host "  ✓ $computerName added to TrustedHosts and WinRM restarted" -ForegroundColor Green
            Write-Verbose "TrustedHosts updated and WinRM restarted"
        }
        elseif ($trustedHosts -eq "*") {
            Write-Host "  ✓ TrustedHosts is set to wildcard (*), no addition needed" -ForegroundColor Green
            Write-Verbose "TrustedHosts set to wildcard"
            Write-Log "TrustedHosts set to wildcard (*)" -Level "INFO"
        }
        else {
            Write-Host "  ✓ $computerName is already in TrustedHosts" -ForegroundColor Green
            Write-Verbose "$computerName is already in TrustedHosts"
            Write-Log "$computerName is already in TrustedHosts" -Level "INFO"
        }
        
        Write-Host "  Checking if PSRemoting is active on remote machine..." -ForegroundColor Cyan
        try {
            Test-WSMan -ComputerName $computerName -ErrorAction Stop | Out-Null
            Write-Host "  ✓ PSRemoting active on $computerName" -ForegroundColor Green
            Write-Verbose "PSRemoting successfully tested on $computerName"
            Write-Log "PSRemoting active on $computerName" -Level "INFO"
        }
        catch {
            Write-Host "  ! PSRemoting not active on $computerName. Enabling..." -ForegroundColor Yellow
            Write-Host "    Execute the following on the remote machine as Administrator:" -ForegroundColor Yellow
            Write-Host "    Enable-PSRemoting -Force" -ForegroundColor White
            Write-Host "    Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Client -Name TrustedHosts -Value '*'" -ForegroundColor White
            throw "PSRemoting must be enabled on the remote machine"
        }
        
        # Step 4: Obtain credentials
        Write-Progress -Activity "Remote Server Setup" -Status "Step 4 of 8: Authentication" -PercentComplete 37
        Write-Host "`n[4/8] Authentication..." -ForegroundColor Cyan
        $cred = Get-Credential -Message "Enter Administrator credentials for $computerName"
        if (-not $cred) {
            throw "Credentials are required"
        }
        Write-Host "  ✓ Credentials obtained" -ForegroundColor Green
        Write-Verbose "Credentials successfully entered for $computerName"
        Write-Log "Credentials obtained for $computerName" -Level "INFO"
        
        # Step 5: Obtain server configuration
        Write-Progress -Activity "Remote Server Setup" -Status "Step 5 of 8: Obtaining server configuration" -PercentComplete 50
        Write-Host "`n[5/8] Server configuration..." -ForegroundColor Cyan
        $serverConfig = Get-ServerConfiguration
        Write-Host "  ✓ Server configuration obtained" -ForegroundColor Green
        Write-Verbose "Server configuration obtained: $($serverConfig | ConvertTo-Json)"
        Write-Log "Server configuration obtained" -Level "INFO"
        
        # Step 6: Generate certificates locally
        Write-Progress -Activity "Remote Server Setup" -Status "Step 6 of 8: Generating certificates locally" -PercentComplete 62
        Write-Host "`n[6/8] Generating certificates locally..." -ForegroundColor Cyan
        $localEasyRSA = $Script:Settings.easyRSAPath
        if (-not (Initialize-EasyRSA)) {
            throw "EasyRSA initialization failed locally"
        }
        if (-not (Initialize-Certificates -ServerName $serverConfig.ServerName -Password $serverConfig.Password -EasyRSAPath $Script:Settings.easyRSAPath)) {
            throw "Certificate generation failed locally"
        }
        Write-Host "  ✓ Certificates generated locally" -ForegroundColor Green
        Write-Verbose "Certificates generated locally for server $($serverConfig.ServerName)"
        Write-Log "Certificates generated locally" -Level "INFO"
        
        # Step 7: Perform remote installation
        Write-Progress -Activity "Remote Server Setup" -Status "Step 7 of 8: Performing remote server installation" -PercentComplete 75
        Write-Host "`n[7/8] Starting remote server installation..." -ForegroundColor Cyan
        if (-not (Install-RemoteServer -ComputerName $computerName -Credential $cred -ServerConfig $serverConfig -LocalEasyRSAPath $localEasyRSA -RemoteConfigPath $Script:Settings.remoteConfigPath)) {
            throw "Remote server installation failed"
        }
        Write-Host "  ✓ Remote installation completed" -ForegroundColor Green
        Write-Verbose "Remote server installation successfully completed for $computerName"
        Write-Log "Remote server installation completed for $computerName" -Level "INFO"

        # Step 7.5: Configure NAT and IP Forwarding (handled within Install-RemoteServer but adding orchestrator reporting)
        Write-Progress -Activity "Remote Server Setup" -Status "Step 7.5 of 8: Configuring NAT and IP Forwarding" -PercentComplete 87
        Write-Host "`n[7.5/8] Configuring NAT and IP Forwarding..." -ForegroundColor Cyan
        Write-Host "  ✓ NAT and IP Forwarding configured (Remote)" -ForegroundColor Green
        
        # Step 8: Start remote OpenVPN service via GUI
        Write-Progress -Activity "Remote Server Setup" -Status "Step 8 of 8: Starting OpenVPN service on remote machine" -PercentComplete 95
        Write-Host "`n[8/8] Starting OpenVPN service on remote machine..." -ForegroundColor Cyan
        $remoteOvpn = Join-Path $Script:Settings.remoteConfigPath "server.ovpn"
        if (-not (Start-VPNConnection -ConfigFile $remoteOvpn -ComputerName $computerName -Credential $cred)) {
            throw "Starting remote OpenVPN service failed"
        }
        Write-Host " ✓ Remote OpenVPN starting completed" -ForegroundColor Green
        Write-Verbose "Remote OpenVPN starting successfully completed for $computerName"
        Write-Log "Remote OpenVPN service started for $computerName" -Level "INFO"
        
        # Step 7: Create client package
        Write-Progress -Activity "Remote Server Setup" -Status "Step 7 of 7: Creating client configuration package" -PercentComplete 86
        Write-Host "`n[7/7] Creating client configuration package..." -ForegroundColor Cyan
        $zipPath = New-ClientPackage -Config $serverConfig -OutputPath $Script:OutputPath
        if (-not $zipPath) {
            throw "Creating client package failed"
        }
        Write-Host "  ✓ Client package created: $zipPath" -ForegroundColor Green
        Write-Verbose "Client package successfully created: $zipPath"
        Write-Log "Client package created: $zipPath" -Level "INFO"
        
        Write-Progress -Activity "Remote Server Setup" -Completed
        
        Show-Menu -Mode Success -SuccessTitle "Remote Server Setup Successfully Completed!" -LogFile $script:LogFile -ExtraMessage "The VPN server is now running on the remote machine." -ComputerName $computerName
    }
    catch {
        Write-Progress -Activity "Remote Server Setup" -Completed
        Write-Log "Error during Remote Server Setup: $($_.Exception.Message)" -Level "ERROR"
        $choice = Show-Menu -Mode Error -SuccessTitle "Remote Server Setup Failed!" -LogFile $script:LogFile -ExtraMessage "Check the log file for details." -Options @("Try again", "Back to main menu", "Exit")
        switch ($choice) {
            1 { Invoke-RemoteOpenVPNServerSetup }
            2 { Start-VPNSetup }
            3 { exit }
        }
    }
}

# Batch Remote Client Setup but also has the functionality for WireGuard clients
function Invoke-BatchRemoteClientSetup {
    <#
    .SYNOPSIS
        Performs batch remote VPN client setup for multiple computers.
    #>
    
    Write-Log "=== Batch Remote Client Setup Started ===" -Level "INFO"
    
    # Keuze protocol
    $protocol = Select-VPNProtocol
    
    try {
        # Step 1: Select CSV file
        Write-Host "`n[1/4] Selecting CSV file..." -ForegroundColor Cyan
        $csvPath = Read-Host "  Enter the path to the CSV file (e.g. C:\clients.csv)"
        if (-not (Test-Path $csvPath)) { throw "CSV file not found: $csvPath" }
        Write-Host "  ✓ CSV file found" -ForegroundColor Green
        
        $clients = Import-Csv -Path $csvPath
        if ($clients.Count -eq 0) { throw "No clients found in CSV" }
        Write-Log "$($clients.Count) clients found" -Level "INFO"
        
        # Step 2: Protocol specific input
        if ($protocol -eq "OpenVPN") {
            # ... OpenVPN Existing Logic ...
            Write-Host "`n[2/4] Selecting client ZIP file..." -ForegroundColor Cyan
            $clientDefaultName = if ($Script:Settings.ContainsKey('clientName')) { $Script:Settings.clientName } else { 'client' }
            $defaultZipPath = Join-Path $Script:Settings.OutputPath "vpn-client-$clientDefaultName.zip"
             
            if (Test-Path $defaultZipPath) {
                Write-Host "  Default found: $defaultZipPath"
                if ((Read-Host "  Use? (Y/N)") -match "^[Yy]") { $zipPath = $defaultZipPath }
            }
             
            if (-not $zipPath) { $zipPath = Read-Host "  Path to client ZIP file" }
            if (-not (Test-Path $zipPath)) { throw "ZIP file not found" }
             
            # Execute Batch OpenVPN
            Write-Host "`n[3/4] Starting Batch OpenVPN Setup..." -ForegroundColor Cyan
            $cpuCores = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
            $throttleLimit = [math]::Max(1, $cpuCores - 1)
            
            # Set module path for batch install
            $ModulePath = Join-Path $PSScriptRoot "../module/AutoSecureVPN.psd1"
             
            $results = Invoke-BatchRemoteClientInstall -Clients $clients -ZipPath $zipPath -ModulePath $ModulePath -Settings $Script:Settings -BasePath $Script:BasePath -ThrottleLimit $throttleLimit
             
        }
        elseif ($protocol -eq "WireGuard") {
            # WireGuard Logic
            Write-Host "`n[2/4] WireGuard Server data..." -ForegroundColor Cyan
            
            # Try to retrieve data from an existing client config (local)
            $wgClientConfigMatch = Get-ChildItem -Path $Script:Settings.OutputPath -Filter "wg-client*.conf" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            
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
                Write-Host "  Could not automatically find server data." -ForegroundColor Yellow
                if (-not $serverEndpoint) { $serverEndpoint = Read-Host "  Server Endpoint (Public IP:Port, e.g. 1.2.3.4:51820)" }
                if (-not $serverPubKey) { $serverPubKey = Read-Host "  Server Public Key" }
            }
            else {
                Write-Host "  ✓ Server data loaded from $($wgClientConfigMatch.Name)" -ForegroundColor Green
                Write-Host "    Endpoint: $serverEndpoint" -ForegroundColor Gray
                Write-Host "    Public Key: $serverPubKey" -ForegroundColor Gray
            }
             
            if (-not $serverEndpoint -or -not $serverPubKey) { throw "Server data is required" }
             
            $serverKeys = @{ PublicKey = $serverPubKey }
             
            # Execute Batch WireGuard
            Write-Host "`n[3/4] Starting Batch WireGuard Setup..." -ForegroundColor Cyan
             
            # Module path fix
            $modPath = Join-Path $PSScriptRoot "../module/AutoSecureVPN.psm1"
            
            $results = Invoke-BatchRemoteWireGuardClientInstall -Clients $clients -ServerKeys $serverKeys -ServerEndpoint $serverEndpoint -ModulePath $modPath -Settings $Script:Settings
        }

        # Show results
        Write-Host "`nResults:" -ForegroundColor Yellow
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
        
        Write-Log "Batch Remote Setup completed ($successCount/$($clients.Count) successful)" -Level "INFO"
        
        if ($successCount -eq $clients.Count) {
            Show-Menu -Mode Success -SuccessTitle "Batch Setup Successful!" -LogFile $script:LogFile
        }
        else {
            Show-Menu -Mode Error -SuccessTitle "Batch Setup Partially Failed" -LogFile $script:LogFile
        }

    }
    catch {
        Write-Log "Error during Batch Setup: $_" -Level "ERROR"
        Show-Menu -Mode Error -SuccessTitle "Batch Setup Failed!" -ExtraMessage $_
    }
}