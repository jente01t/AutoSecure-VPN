#regio Module Header
# Disclaimer: Function comments and inline comments are generated with Copilot.  


#region Module Header
<#
.SYNOPSIS
    AutoSecure-VPN Module - Automated VPN setup for OpenVPN and WireGuard.

.DESCRIPTION
    This module provides a complete automated setup for VPN server and client configurations.
    It supports both OpenVPN and WireGuard protocols.
    It can perform local and remote installations using PowerShell Remoting.

.NOTES
    Name:        AutoSecure-VPN.psm1
    Author:      Jente
    Version:     1.0
    Date:        December 2025
    Requires:    PowerShell 7.0+
#>

#Requires -Version 7.0
#endregion Module Header


[CmdletBinding()]
param()



# Set base path logic
# When module is installed via Install-Module, use user's Documents folder for logs/output to avoid permission issues.
# When running from development folder (e.g. git clone), use the project root.
if ($PSScriptRoot -match 'Documents\\PowerShell\\Modules|Program Files\\WindowsPowerShell\\Modules') {
    # Module is installed in a standard library location - use user's Documents folder
    $Script:BasePath = [Environment]::GetFolderPath('MyDocuments')
}
else {
    # Module is in development/source mode - use the project root (parent of the module folder)
    $Script:BasePath = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
}


#region Core / Menu System
# =================================================================================================
# REGION: Core / Menu System
# =================================================================================================
# This section contains the main entry points and menu logic for the AutoSecure-VPN module.
# It handles the initial user selection for Server/Client modes, protocol selection (OpenVPN/WireGuard),
# and the choice between Local and Remote deployment strategies.
# Key Functions: Start-VPNSetup, Select-ServerMode, Select-ClientMode, Select-VPNProtocol.
# =================================================================================================

function Start-VPNSetup {
    <#
    .SYNOPSIS
        Displays the main menu for VPN setup selection.

    .DESCRIPTION
        This function shows a menu with options for server or client setup selection.
        It initializes the configuration settings by loading .psd1 files before displaying the menu.

    .EXAMPLE
        Start-VPNSetup
    #>
    
    # Load settings here so messages are visible before menu clears console
    # Check if the global Settings hashtable is empty
    if ($Script:Settings.Count -eq 0) {
        try {
            $configDir = Join-Path (Split-Path $PSScriptRoot -Parent) 'config'
            # Load stable settings first (defaults from module directory)
            $stableConfigPath = Join-Path $configDir 'Stable.psd1'
            if (Test-Path $stableConfigPath) {
                # Import the PSD1 data file safely
                $stableSettings = Import-PowerShellDataFile -Path $stableConfigPath -ErrorAction Stop
                if ($stableSettings) { $Script:Settings = $stableSettings.Clone() }
            }
            else {
                # Check if example file exists and provide helpful message if configuration is missing
                $examplePath = Join-Path $configDir 'Stable.psd1.example'
                if (Test-Path $examplePath) {
                    Write-Host "Configuration file 'Stable.psd1' not found." -ForegroundColor Yellow
                    Write-Host "Please copy 'Stable.psd1.example' to 'Stable.psd1' and customize it." -ForegroundColor Yellow
                    Write-Host "Location: $configDir" -ForegroundColor Cyan
                    exit 1
                }
            }
            
            # Load variable settings and merge (variable overrides stable defaults)
            $variableConfigPath = Join-Path $configDir 'Variable.psd1'
            if (Test-Path $variableConfigPath) {
                $variableSettings = Import-PowerShellDataFile -Path $variableConfigPath -ErrorAction Stop
                if ($variableSettings) {
                    # Loop through variable settings and update the main Settings hashtable
                    foreach ($key in $variableSettings.Keys) {
                        $Script:Settings[$key] = $variableSettings[$key]
                    }
                }
            }
            else {
                # Check if example file exists and provide helpful message for the variable config
                $examplePath = Join-Path $configDir 'Variable.psd1.example'
                if (Test-Path $examplePath) {
                    Write-Host "Configuration file 'Variable.psd1' not found." -ForegroundColor Yellow
                    Write-Host "Please copy 'Variable.psd1.example' to 'Variable.psd1' and customize it." -ForegroundColor Yellow
                    Write-Host "Location: $configDir" -ForegroundColor Cyan
                    exit 1
                }
            }
        }
        catch {
            # Handle any errors during configuration loading (e.g., syntax errors in PSD1)
            Write-Host "Could not load settings: $($_.Exception.Message)" -ForegroundColor Yellow
            exit 1
        }
    }
    
    Write-Log "=== AutoSecure-VPN Automatic Setup Started ===" -Level "INFO"
    
    # Display the main menu
    $choice = Show-Menu -Mode Menu -Title "AutoSecure-VPN Automatic Setup" -Options @("Server Setup", "Client Setup", "Exit") -HeaderColor Cyan -OptionColor Green -FooterColor Cyan -Prompt "Enter your choice (1-3)"
    
    # Process user choice
    switch ($choice) {
        1 {
            Write-Host "`n[*] Server Setup selected..." -ForegroundColor Cyan
            Write-Log "Server Setup selected" -Level "INFO"
            Select-ServerMode
        }
        2 {
            Write-Host "`n[*] Client Setup selected..." -ForegroundColor Cyan
            Write-Log "Client Setup selected" -Level "INFO"
            Select-ClientMode
        }
        3 {
            Write-Host "`n[*] Exiting setup..." -ForegroundColor Yellow
            Write-Log "Setup closed by user" -Level "INFO"
            exit 0
        }
        default {
            Write-Host "`n[!] Invalid choice. Please try again." -ForegroundColor Red
            Start-Sleep -Seconds 2
            Start-VPNSetup
        }
    }
}

function Select-ServerMode {
    <#
    .SYNOPSIS
        Displays submenu for server setup choice (local or remote).

    .DESCRIPTION
        This function shows a submenu for choosing between local or remote server setup.
        It routes the logic to the specific protocol handlers (OpenVPN/WireGuard).

    .EXAMPLE
        Select-ServerMode
    #>
    
    $choice = Show-Menu -Mode Menu -Title "Server Setup Options" -Options @("Local (Install and configure VPN server on this machine)", "Remote (Install and configure VPN server remotely)", "Back to main menu") -HeaderColor Yellow -OptionColor Green -FooterColor Red -Prompt "Enter your choice (1-3)"
    
    switch ($choice) {
        1 {
            Write-Host "`n[*] Local Server Setup selected..." -ForegroundColor Cyan
            Write-Log "Local Server Setup selected" -Level "INFO"
            
            # Ask for protocol and execute corresponding local setup
            $protocol = Select-VPNProtocol
            if ($protocol -eq "OpenVPN") {
                Invoke-OpenVPNServerSetup
            }
            elseif ($protocol -eq "WireGuard") {
                Invoke-WireGuardServerSetup
            }
        }
        2 {
            Write-Host "`n[*] Remote Server Setup selected..." -ForegroundColor Cyan
            Write-Log "Remote Server Setup selected" -Level "INFO"
            
            # Ask for protocol and execute corresponding remote setup
            $protocol = Select-VPNProtocol
            if ($protocol -eq "OpenVPN") {
                Invoke-RemoteOpenVPNServerSetup
            }
            elseif ($protocol -eq "WireGuard") {
                Invoke-RemoteWireGuardServerSetup
            }
        }
        3 {
            Write-Host "`n[*] Back to main menu..." -ForegroundColor Yellow
            Write-Log "Back to main menu" -Level "INFO"
            Start-VPNSetup
        }
        default {
            Write-Host "`n[!] Invalid choice. Please try again." -ForegroundColor Red
            Start-Sleep -Seconds 2
            Select-ServerMode
        }
    }
}

function Select-ClientMode {
    <#
    .SYNOPSIS
        Displays submenu for client setup choice (local or remote).

    .DESCRIPTION
        This function shows a submenu for choosing between local, remote, or batch client setup.

    .EXAMPLE
        Select-ClientMode
    #>
    
    $choice = Show-Menu -Mode Menu -Title "Client Setup Options" -Options @("Local (Install and connect VPN client on this machine)", "Remote (Install and connect VPN client remotely)", "Batch Remote (Install VPN client on multiple machines)", "Back to main menu") -HeaderColor Yellow -OptionColor Green -FooterColor Red -Prompt "Enter your choice (1-4)"
    
    switch ($choice) {
        1 {
            Write-Host "`n[*] Local Client Setup selected..." -ForegroundColor Cyan
            Write-Log "Local Client Setup selected" -Level "INFO"
            
            $protocol = Select-VPNProtocol
            if ($protocol -eq "OpenVPN") {
                Invoke-OpenVPNClientSetup
            }
            elseif ($protocol -eq "WireGuard") {
                Invoke-WireGuardClientSetup
            }
        }
        2 {
            Write-Host "`n[*] Remote Client Setup selected..." -ForegroundColor Cyan
            Write-Log "Remote Client Setup selected" -Level "INFO"
             
            $protocol = Select-VPNProtocol
            if ($protocol -eq "OpenVPN") {
                Invoke-RemoteOpenVPNClientSetup
            }
            elseif ($protocol -eq "WireGuard") {
                Invoke-RemoteWireGuardClientSetup
            }
        }
        3 {
            Write-Host "`n[*] Batch Remote Client Setup selected..." -ForegroundColor Cyan
            Write-Log "Batch Remote Client Setup selected" -Level "INFO"
            # Batch setup handles protocol selection internally
            Invoke-BatchRemoteClientSetup
        }
        4 {
            Write-Host "`n[*] Back to main menu..." -ForegroundColor Yellow
            Write-Log "Back to main menu" -Level "INFO"
            Start-VPNSetup
        }
        default {
            Write-Host "`n[!] Invalid choice. Please try again." -ForegroundColor Red
            Start-Sleep -Seconds 2
            Select-ClientMode
        }
    }
}

function Select-VPNProtocol {
    <#
    .SYNOPSIS
        Asks the user to choose a VPN protocol.
    #>
    $choice = Show-Menu -Mode Menu -Title "Choose VPN Protocol" -Options @("OpenVPN", "WireGuard") -HeaderColor Magenta -OptionColor White -Prompt "Select protocol (1-2)"
    
    switch ($choice) {
        1 { return "OpenVPN" }
        2 { return "WireGuard" }
    }
}


#endregion Core / Menu System
#region OpenVPN Setup Orchestration

# =================================================================================================
# REGION: OpenVPN Setup Orchestration
# =================================================================================================
# This section contains the high-level orchestration functions for OpenVPN deployments.
# It coordinates the setup process for both Client and Server roles, covering both
# Local execution and Remote execution via PowerShell Remoting.
# Key Functions: Invoke-OpenVPNClientSetup, Invoke-RemoteOpenVPNClientSetup, 
#                Invoke-OpenVPNServerSetup, Invoke-RemoteOpenVPNServerSetup, Invoke-BatchRemoteClientSetup.
# =================================================================================================

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
        # Verify if the script is running with elevated privileges
        if (-not (Test-IsAdmin)) {
            throw "Script must be run as Administrator!"
        }
        Write-Host "  ✓ Administrator privileges confirmed" -ForegroundColor Green
        Write-Verbose "Administrator privileges successfully checked"
        Write-Log "Administrator privileges confirmed" -Level "INFO"
        
        # Step 2: Install OpenVPN
        Write-Progress -Activity "Client Setup" -Status "Step 2 of 6: Installing OpenVPN" -PercentComplete 16.67
        Write-Host "`n[2/6] Installing OpenVPN..." -ForegroundColor Cyan
        # Download and run the OpenVPN installer
        if (-not (Install-OpenVPN)) {
            throw "OpenVPN installation failed"
        }
        Write-Host "  ✓ OpenVPN installed" -ForegroundColor Green
        Write-Verbose "OpenVPN successfully installed"
        Write-Log "OpenVPN installed" -Level "INFO"
        
        # Step 3: Import client configuration
        Write-Progress -Activity "Client Setup" -Status "Step 3 of 6: Importing client configuration" -PercentComplete 33.33
        Write-Host "`n[3/6] Importing client configuration..." -ForegroundColor Cyan
        # Prompt user for ZIP file or use default, then extract to config folder
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
        # Verify if the TAP network driver was installed correctly
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
        # Launch OpenVPN GUI/Service with the imported config
        if (-not (Start-VPNConnection -ConfigFile $configPath)) {
            throw "Starting VPN connection failed"
        }
        Write-Host "  ✓ VPN connection started" -ForegroundColor Green
        Write-Verbose "VPN connection successfully started"
        Write-Log "VPN connection started" -Level "INFO"
        
        # Step 6: Test connection
        Write-Progress -Activity "Client Setup" -Status "Step 6 of 6: Testing VPN connection" -PercentComplete 83.33
        Write-Host "`n[6/6] Testing VPN connection..." -ForegroundColor Cyan
        Start-Sleep -Seconds 30  # Wait longer for connection to be fully established (Handshake time)
        # Ping the test IP to verify tunnel traffic
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
        # Error handling block
        Write-Progress -Activity "Client Setup" -Completed
        Write-Log "Error during Client Setup: $($_.Exception.Message)" -Level "ERROR"
        $choice = Show-Menu -Mode Error -SuccessTitle "Client Setup Failed!" -LogFile $script:LogFile -ExtraMessage "Check the log file for details." -Options @("Try again", "Back to main menu", "Exit")
        
        # Error recovery options
        switch ($choice) {
            1 {
                # Perform rollback (cleanup) before retrying
                Write-Host "`n[*] Performing rollback to undo changes..." -ForegroundColor Yellow
                Invoke-Rollback -SetupType "Client"
                Invoke-OpenVPNClientSetup
            }
            2 {
                # Rollback and return to menu
                Write-Host "`n[*] Performing rollback to undo changes..." -ForegroundColor Yellow
                Invoke-Rollback -SetupType "Client"
                Start-VPNSetup
            }
            3 {
                # Rollback and exit
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

        # Retrieve and validate remoteClientIP from loaded settings
        try {
            if ($Script:Settings.ContainsKey('remoteClientIP') -and -not [string]::IsNullOrWhiteSpace($Script:Settings.remoteClientIP) -and $Script:Settings.remoteClientIP -ne 'your.client.ip.here') {
                $computerName = $Script:Settings.remoteClientIP
                Write-Verbose "Remote client obtained from settings: $computerName"
            }
        }
        catch {
            Write-Verbose "Error retrieving remoteClientIP from settings: $_"
        }

        # Validate that we have a target
        if ([string]::IsNullOrWhiteSpace($computerName)) {
            throw "Setting 'remoteClientIP' is empty or invalid in Variable.psd1. Please fill in 'remoteClientIP' or adjust the configuration."
        }
        
        Write-Host "  ✓ Remote computer: $computerName" -ForegroundColor Green
        Write-Verbose "Remote computer name used: $computerName"
        Write-Log "Remote computer: $computerName" -Level "INFO"
        
        # Step 3: WinRM configuration
        # Checks if the remote host is trusted to allow PowerShell Remoting connections
        Write-Progress -Activity "Remote Client Setup" -Status "Step 3 of 5: Checking WinRM configuration" -PercentComplete 40
        Write-Host "`n[3/5] Checking WinRM configuration..." -ForegroundColor Cyan
        try {
            # Get current TrustedHosts list
            $trustedHosts = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Client -Name TrustedHosts -ErrorAction Stop).TrustedHosts
        }
        catch {
            $trustedHosts = ""
        }
        
        # Update TrustedHosts if necessary (adds target IP if not present)
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
        
        # Test basic connectivity to the WinRM service on the remote host
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
        # Ask user for remote Admin credentials
        $cred = Get-Credential -Message "Enter credentials for $computerName (must be Administrator)"
        if (-not $cred) {
            throw "Credentials are required"
        }
        Write-Host "  ✓ Credentials entered" -ForegroundColor Green
        Write-Verbose "Credentials successfully entered for $computerName"
        Write-Log "Credentials entered for $computerName" -Level "INFO"
        
        # Step 5: Client ZIP file selection
        Write-Progress -Activity "Remote Client Setup" -Status "Step 5 of 5: Client configuration file" -PercentComplete 80
        Write-Host "`n[5/5] Client configuration file..." -ForegroundColor Cyan
        # Determine default client name based on settings
        $clientDefaultName = if ($Script:Settings.ContainsKey('clientName') -and -not [string]::IsNullOrWhiteSpace($Script:Settings.clientName)) { $Script:Settings.clientName } else { 'client' }
        $defaultZipPath = Join-Path $Script:Settings.OutputPath "vpn-client-$clientDefaultName.zip"
        
        # Check if the auto-generated zip file exists
        if (Test-Path $defaultZipPath) {
            $zipPath = $defaultZipPath
            Write-Host "  ✓ Default client ZIP file found: $zipPath" -ForegroundColor Green
            Write-Verbose "Default client ZIP file used: $zipPath"
            Write-Log "Default client ZIP file found: $zipPath" -Level "INFO"
        }
        else {
            # Fallback to manual entry if default not found
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
        # This function copies the module and zip to the remote host and executes the setup there
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
        # Error handling for remote client setup
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
        # Open the specific port (usually 443 or 1194) in Windows Firewall
        if (-not (Set-Firewall -Port 443 -Protocol "TCP")) {
            throw "Firewall configuration failed"
        }
        Write-Host "  ✓ Firewall rules added" -ForegroundColor Green
        Write-Verbose "Firewall rules successfully added"
        Write-Log "Firewall rules added" -Level "INFO"
        
        # Step 4: Collect user input
        Write-Progress -Activity "Server Setup" -Status "Step 4 of 8: Collecting server configuration parameters" -PercentComplete 37.5
        Write-Host "`n[4/8] Server configuration parameters..." -ForegroundColor Cyan
        # Ask user for Subnet, IP, etc. or load from settings
        $serverConfig = Get-ServerConfiguration
        Write-Verbose "Server configuration parameters collected: $($serverConfig | ConvertTo-Json)"
        Write-Log "Server configuration parameters collected" -Level "INFO"
        
        # Step 5: EasyRSA and certificates (The PKI step)
        Write-Progress -Activity "Server Setup" -Status "Step 5 of 8: Generating certificates" -PercentComplete 50
        Write-Host "`n[5/8] Generating certificates (this may take a while)..." -ForegroundColor Cyan
        
        # Setup the EasyRSA environment (download/extract)
        if (-not (Initialize-EasyRSA)) {
            throw "EasyRSA initialization failed"
        }
        # Generate CA and Server certificates
        if (-not (Initialize-Certificates -ServerName $serverConfig.ServerName -Password $serverConfig.Password)) {
            throw "Certificate generation failed"
        }
        Write-Host "  ✓ Certificates generated" -ForegroundColor Green
        Write-Verbose "Certificates successfully generated for server $($serverConfig.ServerName)"
        Write-Log "Certificates generated" -Level "INFO"
        
        # Step 6: Generate server configuration
        Write-Progress -Activity "Server Setup" -Status "Step 6 of 8: Creating server configuration" -PercentComplete 62.5
        Write-Host "`n[6/8] Creating server configuration..." -ForegroundColor Cyan
        # Create server.ovpn file with paths to generated certs
        if (-not (New-ServerConfig -Config $serverConfig)) {
            throw "Server configuration generation failed"
        }
        Write-Host "  ✓ Server configuration created" -ForegroundColor Green
        Write-Verbose "Server configuration successfully created"
        Write-Log "Server configuration created" -Level "INFO"
        
        # Step 7: Start OpenVPN service
        Write-Progress -Activity "Server Setup" -Status "Step 7 of 8: Starting OpenVPN service" -PercentComplete 70
        Write-Host "`n[7/8] Starting OpenVPN service..." -ForegroundColor Cyan
        # Start the Windows Service for OpenVPN
        if (-not (Start-VPNService)) {
            throw "Starting OpenVPN service failed"
        }
        Write-Host "  ✓ OpenVPN service active" -ForegroundColor Green
        Write-Verbose "OpenVPN service successfully started"
        Write-Log "OpenVPN service active" -Level "INFO"
        
        # Step 7.5: Start OpenVPN via GUI (Visual feedback for user)
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
        
        # Wait for TAP adapter to become active before trying to configure NAT
        Write-Host "`n[*] Waiting for TAP adapter to initialize..." -ForegroundColor Cyan
        Start-Sleep -Seconds 10
        
        # Step 7.75: Configure ICS for internet access
        Write-Progress -Activity "Server Setup" -Status "Step 7.75 of 8: Configuring ICS for internet access" -PercentComplete 80
        Write-Host "`n[7.75/8] Configuring ICS (Internet Connection Sharing)..." -ForegroundColor Cyan
        # Configuring NAT/ICS so VPN clients can browse the internet through the server
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
        # Generate client keys and zip them up
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
        # Error handling for Server Setup
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
                # Rollback before menu
                Write-Host "`n[*] Performing rollback to undo changes..." -ForegroundColor Yellow
                Invoke-Rollback -SetupType "Server"
                Start-VPNSetup
            }
            3 {
                # Rollback before exit
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
        # We need local OpenVPN/EasyRSA tools to generate certificates BEFORE sending them to the remote server.
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
        
        # Retrieve Server IP from settings
        try {
            if ($Script:Settings.ContainsKey('serverIP') -and -not [string]::IsNullOrWhiteSpace($Script:Settings.serverIP) -and $Script:Settings.serverIP -ne 'your.server.ip.here') {
                $computerName = $Script:Settings.serverIP
                Write-Verbose "Remote server IP obtained from settings: $computerName"
            } 
        }    
        catch {
            throw "Server IP address is empty in Variable.psd1"
        }

        # Validate target IP
        if ([string]::IsNullOrWhiteSpace($computerName)) {
            throw "Setting 'serverIP' is empty or invalid in Variable.psd1. Please fill in 'serverIP' or adjust the configuration."
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
        
        # Add remote host to TrustedHosts if needed
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
        
        # Test WSMan connection
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
        
        # Step 5: Obtain server configuration details (subnets, etc)
        Write-Progress -Activity "Remote Server Setup" -Status "Step 5 of 8: Obtaining server configuration" -PercentComplete 50
        Write-Host "`n[5/8] Server configuration..." -ForegroundColor Cyan
        $serverConfig = Get-ServerConfiguration
        Write-Host "  ✓ Server configuration obtained" -ForegroundColor Green
        Write-Verbose "Server configuration obtained: $($serverConfig | ConvertTo-Json)"
        Write-Log "Server configuration obtained" -Level "INFO"
        
        # Step 6: Generate certificates locally
        # This is done locally to avoid installing full build tools on the remote server and easier file management.
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
        # Copies module, certs, and config to remote, then triggers setup via Invoke-Command
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
        
        # Step 7 (Correction: Step 9): Create client package
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
        # Error handling for Remote Server Setup
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
    
    # Choose protocol for the batch
    $protocol = Select-VPNProtocol
    
    try {
        # Step 1: Select CSV file
        Write-Host "`n[1/4] Selecting CSV file..." -ForegroundColor Cyan
        $csvPath = Read-Host "  Enter the path to the CSV file (e.g. C:\clients.csv)"
        if (-not (Test-Path $csvPath)) { throw "CSV file not found: $csvPath" }
        Write-Host "  ✓ CSV file found" -ForegroundColor Green
        
        # Import client data (CSV must have Name, IP, Username, Password columns)
        $clients = Import-Csv -Path $csvPath
        if ($clients.Count -eq 0) { throw "No clients found in CSV" }
        Write-Log "$($clients.Count) clients found" -Level "INFO"
        
        # Step 2: Protocol specific input
        if ($protocol -eq "OpenVPN") {
            # ... OpenVPN Existing Logic ...
            Write-Host "`n[2/4] Selecting client ZIP file..." -ForegroundColor Cyan
            $clientDefaultName = if ($Script:Settings.ContainsKey('clientName')) { $Script:Settings.clientName } else { 'client' }
            $defaultZipPath = Join-Path $Script:Settings.OutputPath "vpn-client-$clientDefaultName.zip"
             
            # Use default zip if found and user confirms
            if (Test-Path $defaultZipPath) {
                Write-Host "  Default found: $defaultZipPath"
                if ((Read-Host "  Use? (Y/N)") -match "^[Yy]") { $zipPath = $defaultZipPath }
            }
             
            if (-not $zipPath) { $zipPath = Read-Host "  Path to client ZIP file" }
            if (-not (Test-Path $zipPath)) { throw "ZIP file not found" }
             
            # Execute Batch OpenVPN
            Write-Host "`n[3/4] Starting Batch OpenVPN Setup..." -ForegroundColor Cyan
            # Calculate throttling to avoid overwhelming the local machine
            $cpuCores = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
            $throttleLimit = [math]::Max(1, $cpuCores - 1)
            
            # Set module path for batch install
            $ModulePath = Join-Path $PSScriptRoot "../module/AutoSecureVPN.psd1"
             
            # Run the parallel installation logic
            $results = Invoke-BatchRemoteClientInstall -Clients $clients -ZipPath $zipPath -ModulePath $ModulePath -Settings $Script:Settings -BasePath $Script:BasePath -ThrottleLimit $throttleLimit
             
        }
        elseif ($protocol -eq "WireGuard") {
            # WireGuard Logic
            Write-Host "`n[2/4] WireGuard Server data..." -ForegroundColor Cyan
            
            # Try to retrieve data from an existing client config (local) to auto-fill details
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
            
            # Manual input if auto-detection failed
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
             
            # Module path fix for WireGuard
            $modPath = Join-Path $PSScriptRoot "../module/AutoSecureVPN.psm1"
            
            # Run the parallel installation logic for WireGuard
            $results = Invoke-BatchRemoteWireGuardClientInstall -Clients $clients -ServerKeys $serverKeys -ServerEndpoint $serverEndpoint -ModulePath $modPath -Settings $Script:Settings
        }

        # Show results summary
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


#endregion OpenVPN Setup Orchestration
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
        $outputPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "output"
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
        
        # Start the WireGuard tunnel using the config
        if (-not (Start-WireGuardService -ConfigPath $configPath)) { throw "Starting tunnel failed" }
        
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
        
        # Remove existing config file if it exists
        if (Test-Path $serverConfigPath) {
            Remove-Item $serverConfigPath -Force -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 500  # Wait for file system to release
        }
        
        # Create and write server config file
        New-WireGuardServerConfig -ServerKeys $serverKeys -ClientKeys $clientKeys -Port $wgPort -Address "$baseSubnet.1/24" -PeerAddress "$baseSubnet.2/32" -ServerType "Windows" -OutputPath $serverConfigPath | Out-Null
        
        # Verify server config was created
        if (-not (Test-Path $serverConfigPath)) {
            throw "Server config file was not created at $serverConfigPath"
        }
        Write-Log "Server config verified at: $serverConfigPath" -Level "INFO"
        
        # Create client config file in output directory
        $outputDir = Join-Path $PSScriptRoot "..\..\output"
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
        if (-not (Enable-VPNNAT -VPNSubnet "$baseSubnet.0/24")) { 
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
        $outputPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "output"
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
#region Module Initialization & Configuration Loading

# =================================================================================================
# REGION: Module Initialization & Configuration Loading
# =================================================================================================
# This section handles the dynamic loading of configuration settings from .psd1 files
# upon module import. It establishes the global settings scope and base paths.
# =================================================================================================

# Load module settings from src/config/Stable.psd1 and Variable.psd1 (if present)
# Use $PSScriptRoot and $Script: scope so the module is import-safe in test runspaces.
$Script:Settings = @{}

# Only load config files if $PSScriptRoot is available (not available when loaded via Invoke-Expression)
if ($PSScriptRoot -and -not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
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
        Write-Log "Could not load settings: $($_.Exception.Message)" -Level "WARNING"
    }
}

# Set BasePath only if PSScriptRoot is available
if ($PSScriptRoot -and -not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
    $Script:BasePath = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
}
else {
    # Fallback for remote execution via Invoke-Expression where paths are volatile
    $Script:BasePath = "C:\Temp"
}



#endregion Module Initialization & Configuration Loading
#region Helper Functions & Utilities


# =================================================================================================
# REGION: Helper Functions & Utilities
# =================================================================================================
# This section contains shared utility functions used across the module.
# It includes UI helpers (Show-Menu), logging (Write-Log), system checks (Test-IsAdmin),
# network configuration (Set-Firewall, Enable-VPNNAT, Enable-IPForwarding), and 
# remote installation helpers (Install-RemoteServer, Install-OpenVPN).
# =================================================================================================

function Show-Menu {
    <#
    .SYNOPSIS
        Displays a menu with options and asks for choice, or shows a success message.

    .DESCRIPTION
        This function displays a menu with a title, list of options, and waits for user input.
        It validates the choice and returns the chosen number.
        If Mode is 'Success', it displays a success message in a box.

    .PARAMETER Mode
        'Menu' for displaying menu, 'Success' for success message.

    .PARAMETER Title
        The title of the menu or success message.

    .PARAMETER Options
        An array of options to display (Menu only).

    .PARAMETER SuccessTitle
        The title for success message (Success only).

    .PARAMETER LogFile
        Path to log file (for Success).

    .PARAMETER ExtraMessage
        Extra message (for Success).

    .PARAMETER ComputerName
        Name of computer for log (for Success).

    .PARAMETER HeaderColor
        Color for the header (default Cyan).

    .PARAMETER OptionColor
        Color for the options (default White).

    .PARAMETER FooterColor
        Color for the footer (default Cyan).

    .PARAMETER SeparatorChar
        Character for the separator (default '=').

    .PARAMETER NoPrompt
        If true, do not show prompt and return null (Menu only).

    .PARAMETER Prompt
        The prompt text (default 'Choice: ') (Menu only).

    .OUTPUTS
        System.Int32 for Menu, None for Success.

    .EXAMPLE
        Show-Menu -Mode Menu -Title "Hoofdmenu" -Options @("Optie 1", "Optie 2")

    .EXAMPLE
        Show-Menu -Mode Success -SuccessTitle "Remote Client Setup Succesvol Voltooid!" -LogFile $script:LogFile -ExtraMessage "Op de remote machine kun je nu de VPN verbinding starten via OpenVPN." -ComputerName $computerName

    .NOTES
        This function uses Write-Host for console output and Read-Host for input.
    #>
    param(
        [Parameter(Mandatory = $true, Position = 0)][ValidateSet('Menu', 'Success', 'Error')][string]$Mode,
        [Parameter(Mandatory = $false, Position = 1)][string]$Title,
        [Parameter(Mandatory = $false, Position = 2)][string[]]$Options,
        [Parameter(Mandatory = $false, Position = 3)][string]$SuccessTitle,
        [Parameter(Mandatory = $false, Position = 4)][string]$LogFile,
        [Parameter(Mandatory = $false, Position = 5)][string]$ExtraMessage,
        [Parameter(Mandatory = $false, Position = 6)][string]$ComputerName,
        [Parameter(Mandatory = $false, Position = 7)][string]$ExtraInfo,
        [Parameter(Position = 8)][ConsoleColor]$HeaderColor = 'Cyan',
        [Parameter(Position = 9)][ConsoleColor]$OptionColor = 'White',
        [Parameter(Position = 10)][ConsoleColor]$FooterColor = 'Cyan',
        [Parameter(Position = 11)][string]$SeparatorChar = '=',
        [Parameter(Mandatory = $false, Position = 12)][switch]$NoPrompt,
        [Parameter(Position = 13)][string]$Prompt = 'Choice: '
        , [Parameter(Position = 14)][string]$ErrorMessage
    )

    # Depending on the Mode, show a menu, success message or error message
    if ($Mode -eq 'Menu') {
        # Validate that Title and Options are present for Menu mode
        if (-not $Title -or -not $Options) {
            throw "For Mode 'Menu', Title and Options are required."
        }
        # Clear the screen for a clean display
        Clear-Host
        # Create a separator line for the header
        $sep = ($SeparatorChar * 30)
        Write-Host $sep -ForegroundColor $HeaderColor
        Write-Host "      $Title" -ForegroundColor $HeaderColor
        Write-Host $sep -ForegroundColor $HeaderColor

        # Show all options numbered
        for ($i = 0; $i -lt $Options.Count; $i++) {
            $num = $i + 1
            Write-Host "$num. $($Options[$i])" -ForegroundColor $OptionColor
        }

        Write-Host $sep -ForegroundColor $FooterColor

        # If NoPrompt is set, return null without prompt
        if ($NoPrompt) { return $null }

        # Ask for user input and validate the choice in a loop
        while ($true) {
            $userInput = Read-Host -Prompt $Prompt
            if ($userInput -match '^[0-9]+$') {
                $n = [int]$userInput
                if ($n -ge 1 -and $n -le $Options.Count) { return $n }
            }
            Write-Host "Invalid choice, please try again." -ForegroundColor Red
        }
    }
    elseif ($Mode -eq 'Success') {
        # Validate that SuccessTitle is present for Success mode
        if (-not $SuccessTitle) {
            throw "For Mode 'Success', SuccessTitle is required."
        }
        # Show a success box with the title
        Write-Host "`n╔════════════════════════════════════════════╗" -ForegroundColor Green
        Write-Host "║  $SuccessTitle  ║" -ForegroundColor Green
        Write-Host "╚════════════════════════════════════════════╝" -ForegroundColor Green
        # Show extra information if available
        if ($LogFile) {
            Write-Host "`nLog file: $LogFile" -ForegroundColor Yellow
        }
        if ($ExtraInfo) {
            Write-Host "$ExtraInfo" -ForegroundColor Yellow
        }
        if ($ExtraMessage) {
            Write-Host "`n$ExtraMessage" -ForegroundColor Cyan
        }
        # Log the successful action if ComputerName given
        if ($ComputerName) {
            Write-Log "Remote client setup successfully completed for $ComputerName" -Level "SUCCESS"
        }
    }
    elseif ($Mode -eq 'Error') {
        # Validate that SuccessTitle is present for Error mode (reused as error title)
        if (-not $SuccessTitle) {
            throw "For Mode 'Error', SuccessTitle is required."
        }
        # Show an error box with the title
        Write-Host "`n╔════════════════════════════════════════════╗" -ForegroundColor Red
        Write-Host "║  $SuccessTitle  ║" -ForegroundColor Red
        Write-Host "╚════════════════════════════════════════════╝" -ForegroundColor Red
        # Determine the best error text to show (priority: explicit parameter > extra fields > global error)
        $displayError = $null
        if ($ErrorMessage) { $displayError = $ErrorMessage }
        elseif ($ExtraMessage) { $displayError = $ExtraMessage }
        elseif ($ExtraInfo) { $displayError = $ExtraInfo }
        elseif ($LogFile) { $displayError = "See log file: $LogFile" }
        elseif ($global:Error.Count -gt 0) {
            # Attempt to retrieve the last error from the global stack
            try {
                $err = $global:Error[0]
                $msg = $err.Exception.Message
                if ($err.ScriptStackTrace) { $msg += "`n$($err.ScriptStackTrace)" }
                $displayError = $msg
            }
            catch { $displayError = $null }
        }

        # Show the error details if available
        if ($displayError) {
            Write-Host "`nERROR:" -ForegroundColor Red
            Write-Host "$displayError" -ForegroundColor Yellow
        }
        elseif ($LogFile) {
            Write-Host "`nLog file: $LogFile" -ForegroundColor Yellow
        }
        # Log the error if ComputerName given
        if ($ComputerName) {
            Write-Log "Batch remote client setup failed ($ComputerName)" -Level "ERROR"
        }
        # If options are given, show a menu for recovery (without clearing the screen)
        if ($Options) {
            # Keep the error output visible above the option menu
            $sep = ($SeparatorChar * 30)
            Write-Host $sep -ForegroundColor $HeaderColor
            Write-Host "      Error occurred - Choose an option" -ForegroundColor $HeaderColor
            Write-Host $sep -ForegroundColor $HeaderColor
            for ($i = 0; $i -lt $Options.Count; $i++) {
                $num = $i + 1
                Write-Host "$num. $($Options[$i])" -ForegroundColor $OptionColor
            }
            Write-Host $sep -ForegroundColor $FooterColor
            if (-not $NoPrompt) {
                # Ask for recovery choice
                while ($true) {
                    $userInput = Read-Host -Prompt $Prompt
                    if ($userInput -match '^[0-9]+$') {
                        $n = [int]$userInput
                        if ($n -ge 1 -and $n -le $Options.Count) { return $n }
                    }
                    Write-Host "Invalid choice, please try again." -ForegroundColor Red
                }
            }
        }
    }
}

function Wait-Input {
    <#
    .SYNOPSIS
        Waits for user input to continue.

    .DESCRIPTION
        This function displays a message and waits until the user presses Enter.

    .PARAMETER Message
        The message to display (default 'Press Enter to continue...').

    .OUTPUTS
        None

    .EXAMPLE
        Wait-Input

    .NOTES
        This function uses Read-Host to wait for input.
    #>
    param([Parameter(Position = 0)][string]$Message = 'Press Enter to continue...')
    Read-Host -Prompt $Message | Out-Null
}

function Set-ModuleSettings {
    <#
    .SYNOPSIS
        Sets the module settings for remote operations.

    .DESCRIPTION
        This function sets $Script:Settings and $Script:BasePath for use in remote sessions.
        It is typically called inside a remote ScriptBlock to initialize the environment.

    .PARAMETER Settings
        The hashtable with settings.

    .PARAMETER BasePath
        The base path for the module.

    .OUTPUTS
        None

    .EXAMPLE
        Set-ModuleSettings -Settings $mySettings -BasePath "C:\Temp"

    .NOTES
        This function modifies script-scoped variables.
    #>
    param(
        [Parameter(Mandatory = $true, Position = 0)][hashtable]$Settings,
        [Parameter(Mandatory = $true, Position = 1)][string]$BasePath
    )
    $Script:Settings = $Settings
    $Script:BasePath = $BasePath
}

function Test-IsAdmin {
    <#
    .SYNOPSIS
        Checks if the script is run as administrator.

    .DESCRIPTION
        This function checks if the current user has administrator privileges by verifying role membership.

    .OUTPUTS
        System.Boolean
        $true if administrator, otherwise $false.

    .EXAMPLE
        if (-not (Test-IsAdmin)) { Write-Log "Administrator privileges required" -Level "ERROR" }

    Reference: https://codeandkeep.com/Check-If-Running-As-Admin/.
    #>
    return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-Log {
    <#
    .SYNOPSIS
        Writes a message to the log file and console.

    .DESCRIPTION
        This function logs a message with level, timestamp, to a file and console.
        It handles log directory creation if needed.

    .PARAMETER Message
        The message to log.

    .PARAMETER Level
        The log level (INFO, WARNING, ERROR, SUCCESS).

    .PARAMETER LogFile
        The path to the log file (optional, uses default path).

    .OUTPUTS
        None

    .EXAMPLE
        Write-Log "Operation completed" -Level "SUCCESS"

    .NOTES
        This function uses Add-Content for file output and Write-Verbose for console.
    #>
    param(
        [Parameter(Mandatory = $true, Position = 0)][string]$Message,
        [Parameter(Position = 1)][string]$Level = "INFO",
        [Parameter(Position = 2)][string]$LogFile = $null
    )
    
    # Set default log path if not specified
    if (-not $LogFile) {
        # Always use the project root for logs, regardless of settings
        $logsPath = Join-Path $Script:BasePath "logs"
        # Create logs directory if it does not exist
        if (-not (Test-Path $logsPath)) {
            New-Item -ItemType Directory -Path $logsPath -Force | Out-Null
        }
        
        # Ensure logFileName setting exists
        if (-not $Script:Settings.logFileName) {
            $Script:Settings.logFileName = 'vpn-setup.log'
        }
        
        $LogFile = Join-Path $logsPath $Script:Settings.logFileName
    }
    
    # Verify LogFile is not a directory (safety check)
    if (Test-Path $LogFile -PathType Container) {
        Write-Warning "LogFile path is a directory, not a file: $LogFile"
        $LogFile = Join-Path $LogFile 'vpn-setup.log'
    }
    
    # Generate timestamp and format the log entry
    $timestamp = Get-Date -Format $Script:Settings.logTimestampFormat
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Try to write the log entry to the file
    try {
        Add-Content -Path $LogFile -Value $logEntry -Encoding UTF8
    }
    catch {
        Write-Verbose "Cannot write to log file: $_"
    }
    
    # Note: Console output handling is commented out here as the caller usually handles visual output
    # # Also write to the console depending on the log level
    # switch ($Level.ToUpper()) {
    #     "ERROR" { Write-Host $logEntry -ForegroundColor Red }
    #     "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
    #     "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
    #     default { Write-Host $logEntry -ForegroundColor White }
    # }
}

function Set-Firewall {
    <#
    .SYNOPSIS
        Configures the Windows Firewall for OpenVPN or WireGuard.

    .DESCRIPTION
        This function adds an inbound firewall rule for the specified port and protocol.
        It checks if the rule already exists to avoid duplication.

    .PARAMETER Port
        The port to open (default from settings).

    .PARAMETER Protocol
        The protocol (TCP/UDP, default from settings).

    .OUTPUTS
        System.Boolean
        $true on success, otherwise $false.

    .EXAMPLE
        Set-Firewall -Port 443 -Protocol "TCP"

    Reference: Based on New-NetFirewallRule cmdlet (Microsoft PowerShell Documentation: https://docs.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule), and Get-NetFirewallRule for check (https://docs.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule).
    #>
    param(
        [Parameter(Position = 0)][int]$Port,
        [Parameter(Position = 1)][string]$Protocol
    )
    
    # Set defaults if not provided
    if (-not $Port -or $Port -eq 0) {
        $Port = if ($Script:Settings.port -and $Script:Settings.port -gt 0) { $Script:Settings.port } else { 443 }
    }
    if (-not $Protocol -or [string]::IsNullOrWhiteSpace($Protocol)) {
        $Protocol = if ($Script:Settings.protocol) { $Script:Settings.protocol } else { 'TCP' }
    }
    
    # Validate after defaults are set
    if ($Port -lt 1 -or $Port -gt 65535) {
        throw "Port must be between 1 and 65535, received: $Port"
    }
    if ($Protocol -notin @('TCP', 'UDP')) {
        throw "Protocol must be TCP or UDP, received: $Protocol"
    }
    
    Write-Log "Firewall configuration started for port $Port $Protocol" -Level "INFO"
    
    try {
        # Define unique rule name
        $ruleName = "OpenVPN-Inbound-$Protocol-$Port"
        
        # Check if rule already exists
        $existingRule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
        
        if ($existingRule) {
            Write-Log "Firewall rule already exists: $ruleName" -Level "INFO"
            return $true
        }
        
        # Create new rule
        New-NetFirewallRule -Name $ruleName `
            -DisplayName "OpenVPN $Protocol $Port" `
            -Direction Inbound `
            -Protocol $Protocol `
            -LocalPort $Port `
            -Action Allow `
            -Profile Any
        
        Write-Log "Firewall rule added: $ruleName" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Error during firewall configuration: $_" -Level "ERROR"
        return $false
    }
}

function Enable-VPNNAT {
    <#
    .SYNOPSIS
        Configures NAT for VPN subnet (WireGuard or OpenVPN).
    
    .DESCRIPTION
        This function configures Network Address Translation (NAT) so that
        VPN clients have internet access via the server.
        It prioritizes Internet Connection Sharing (ICS) as it handles DNS/DHCP correctly for VPNs.
        It uses COM objects (HNetCfg.HNetShare) for configuration and Registry tweaks for persistence.
        
    .PARAMETER VPNSubnet
        The VPN subnet in CIDR notation (e.g. 10.13.13.0/24).
        
    .PARAMETER InterfaceAlias
        The name of the internet-facing network interface (optional, auto-detect).
    
    .OUTPUTS
        System.Boolean
        $true on success, otherwise $false.
        
    .EXAMPLE
        Enable-VPNNAT -VPNSubnet "10.13.13.0/24"
    #>
    param(
        [Parameter(Mandatory = $false)][string]$VPNSubnet,
        [Parameter(Mandatory = $false)][string]$InterfaceAlias,
        [Parameter(Mandatory = $false)][ValidateSet("OpenVPN", "WireGuard")][string]$VPNType
    )
    
    # Defaults logic for Subnet
    if ([string]::IsNullOrWhiteSpace($VPNSubnet)) {
        $base = $null
        if ($Script:Settings -and $Script:Settings.ContainsKey('wireGuardBaseSubnet')) {
            $base = $Script:Settings.wireGuardBaseSubnet
        }
        if (-not [string]::IsNullOrWhiteSpace($base)) {
            $VPNSubnet = "${base}.0/24"
        }
    }
    
    try {
        # 0. Enable IP Forwarding first (Prerequisite for any routing)
        if (-not (Enable-IPForwarding)) {
            Write-Log "Could not enable IP Forwarding" -Level "ERROR"
            return $false
        }
        
        # 1. Register DLL required for ICS COM objects
        Write-Log "Registering hnetcfg.dll..." -Level "INFO"
        Start-Process -FilePath "regsvr32.exe" -ArgumentList "/s hnetcfg.dll" -Wait -NoNewWindow
        
        # 2. Identify Adapters (Network Adapter Objects)
        # We generally need these for the Registry logic later
        
        # A. Internet Adapter detection
        if (-not $InterfaceAlias) {
            # Try to find the adapter with the default route (internet facing)
            $defaultRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | 
            Where-Object { $_.NextHop -ne "0.0.0.0" } | 
            Sort-Object RouteMetric | Select-Object -First 1
            
            if ($defaultRoute) {
                $InterfaceAlias = (Get-NetAdapter -InterfaceIndex $defaultRoute.InterfaceIndex -ErrorAction SilentlyContinue).Name
                Write-Log "Internet interface detected: $InterfaceAlias" -Level "INFO"
            }
            
            if (-not $InterfaceAlias) {
                # Fallback: find first Up non-VPN adapter
                $InterfaceAlias = (Get-NetAdapter | Where-Object { 
                        $_.Status -eq "Up" -and 
                        $_.Name -notlike "*WireGuard*" -and 
                        $_.Name -notlike "*VPN*" -and
                        $_.Name -notlike "*Loopback*"
                    } | Select-Object -First 1).Name
            }
            if (-not $InterfaceAlias) { throw "Could not detect any internet interface." }
        }
        $internetAdapter = Get-NetAdapter -Name $InterfaceAlias -ErrorAction SilentlyContinue

        # B. VPN Adapter detection (Strict Priority based on type)
        $vpnAdapter = $null
        if ($VPNType -eq "OpenVPN") {
            Write-Log "Looking for OpenVPN adapter (Priority: TAP-Windows)..." -Level "INFO"
            
            # Priority 1: TAP-Windows specifically (Name or Description)
            $vpnAdapter = Get-NetAdapter | Where-Object { 
                $_.InterfaceDescription -like "*TAP-Windows*" -or $_.Name -like "*TAP-Windows*" 
            } | Select-Object -First 1
            
            # Priority 2: Generic TAP if specific TAP-Windows not found
            if (-not $vpnAdapter) {
                Write-Log "TAP-Windows specific match not found. checking generic TAP..." -Level "INFO"
                $vpnAdapter = Get-NetAdapter | Where-Object { $_.Name -like "*TAP*" } | Select-Object -First 1
            }
            
            # Priority 3: Generic OpenVPN (Last resort, might catch Wintun)
            if (-not $vpnAdapter) {
                Write-Log "TAP adapter not found. Checking generic OpenVPN..." -Level "INFO"
                $vpnAdapter = Get-NetAdapter | Where-Object { $_.Name -like "*OpenVPN*" } | Select-Object -First 1
            }
        }
        elseif ($VPNType -eq "WireGuard") {
            Write-Log "Looking for WireGuard adapter..." -Level "INFO"
            # Look for WireGuard adapters, prefer 'Up' status
            $vpnAdapter = Get-NetAdapter | Where-Object { 
                ($_.Name -like "*wg_server*" -or $_.Name -like "*WireGuard*" -or $_.InterfaceDescription -like "*WireGuard*") -and $_.Status -eq 'Up'
            } | Sort-Object ifIndex | Select-Object -Last 1
            
            if (-not $vpnAdapter) {
                Start-Sleep -Seconds 3
                # Retry without 'Up' status requirement
                $vpnAdapter = Get-NetAdapter | Where-Object { 
                    ($_.Name -like "*wg_server*" -or $_.Name -like "*WireGuard*" -or $_.InterfaceDescription -like "*WireGuard*")
                } | Select-Object -First 1
            }
        }
        else {
            # Generic Fallback if type not specified
            $vpnAdapter = Get-NetAdapter | Where-Object { 
                ($_.Name -like "*wg*" -or $_.InterfaceDescription -like "*WireGuard*" -or $_.InterfaceDescription -like "*TAP-Windows*" -or $_.Name -like "*OpenVPN*")
            } | Select-Object -Last 1
        }
        
        if (-not $vpnAdapter) {
            $allAdapters = Get-NetAdapter | ForEach-Object { "  Name='$($_.Name)' Desc='$($_.InterfaceDescription)' Status='$($_.Status)'" }
            $msg = "Private VPN adapter not found. Available adapters:`n" + ($allAdapters -join "`n")
            Write-Warning $msg
            Write-Log $msg -Level "WARNING"
            return $false
        }

        Write-Log "Identified Adapters: Public='$($internetAdapter.Name)' <-> Private='$($vpnAdapter.Name)' ($($vpnAdapter.InterfaceDescription))" -Level "INFO"
        
        if ($internetAdapter.Name -eq $vpnAdapter.Name) {
            Write-Log "Source and Destination adapters are the same. Check detection logic." -Level "ERROR"
            return $false
        }

        # 3. PHASE 1: COM Cleanup & Enable
        # Use COM to clear existing sharing configs and set initial state
        try {
            $netShare = New-Object -ComObject HNetCfg.HNetShare -ErrorAction Stop
            $connections = @($netShare.EnumEveryConnection)
            
            Write-Log "Cleaning up existing ICS configurations (COM)..." -Level "INFO"
            # Disable sharing on all connections first
            foreach ($conn in $connections) {
                try {
                    $conf = $netShare.INetSharingConfigurationForINetConnection($conn)
                    if ($conf.SharingEnabled) {
                        $conf.DisableSharing()
                    }
                }
                catch {}
            }
            Start-Sleep -Seconds 2
            
            # Enable via COM (Best effort)
            $pubConn = $connections | Where-Object { $netShare.NetConnectionProps($_).Name -eq $internetAdapter.Name } | Select-Object -First 1
            $privConn = $connections | Where-Object { $netShare.NetConnectionProps($_).Name -eq $vpnAdapter.Name } | Select-Object -First 1
            
            if ($pubConn -and $privConn) {
                Write-Log "Setting initial COM sharing..." -Level "INFO"
                # Enable Public sharing (0 = public)
                $netShare.INetSharingConfigurationForINetConnection($pubConn).EnableSharing(0)
                # Enable Private sharing (1 = private)
                $netShare.INetSharingConfigurationForINetConnection($privConn).EnableSharing(1)
            }
            else {
                Write-Log "Could not find COM connection objects for one or both adapters (PublicFound=$($null -ne $pubConn), PrivateFound=$($null -ne $privConn))" -Level "WARNING"
            }
            Start-Sleep -Seconds 1
        }
        catch {
            Write-Log "COM Phase warning: $_" -Level "WARNING"
        }

        # 4. PHASE 2: Registry Enforcement (Persistence)
        # This forces the bindings in the registry and restarts the service, ensuring internet access works reliably.
        Write-Log "Enforcing ICS via Registry..." -Level "INFO"
        
        if ($internetAdapter -and $vpnAdapter) {
            # Get Network Connection GUIDs from Registry
            $netCfgPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}"
            $internetGuid = $null
            $vpnGuid = $null
            
            Get-ChildItem $netCfgPath -ErrorAction SilentlyContinue | ForEach-Object {
                $connPath = Join-Path $_.PSPath "Connection"
                if (Test-Path $connPath) {
                    $name = (Get-ItemProperty $connPath -Name "Name" -ErrorAction SilentlyContinue).Name
                    if ($name -eq $internetAdapter.Name) { $internetGuid = $_.PSChildName }
                    if ($name -eq $vpnAdapter.Name) { $vpnGuid = $_.PSChildName }
                }
            }
            
            if ($internetGuid -and $vpnGuid) {
                # Stop Service before registry edit
                Stop-Service SharedAccess -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
                
                # Registry Hacking for ICS Binding
                $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedAccess"
                
                # Explicitly Enable Sharing by GUID
                Set-ItemProperty -Path $regPath -Name "SharingPublicInterface" -Value $internetGuid -Type String -Force
                Set-ItemProperty -Path $regPath -Name "SharingPrivateInterface" -Value $vpnGuid -Type String -Force
                
                # Ensure start mode is Manual (triggered by dependencies) or Auto
                Set-Service SharedAccess -StartupType Manual
                
                # Start Service to apply changes
                Write-Log "Restarting SharedAccess service..." -Level "INFO"
                Start-Service SharedAccess
                
                # Wait for service to settle
                Start-Sleep -Seconds 3
                
                if ((Get-Service SharedAccess).Status -eq 'Running') {
                    Write-Log "Registry Enforcement Applied. SharedAccess service is running." -Level "SUCCESS"
                }
                else {
                    Write-Log "SharedAccess service failed to start." -Level "ERROR"
                    return $false
                }
            }
            else {
                Write-Log "Could not determine Interface GUIDs for Registry." -Level "WARNING"
            }
        }

        # 5. PHASE 3: Verification (COM)
        Write-Log "Verifying final ICS status..." -Level "INFO"
        $icsVerified = $false
        try {
            $netShare = New-Object -ComObject HNetCfg.HNetShare -ErrorAction Stop
            $conns = $netShare.EnumEveryConnection
            
            $pubConn = $conns | Where-Object { $netShare.NetConnectionProps($_).Name -eq $internetAdapter.Name } | Select-Object -First 1
            $privConn = $conns | Where-Object { $netShare.NetConnectionProps($_).Name -eq $vpnAdapter.Name } | Select-Object -First 1
            
            if ($pubConn -and $privConn) {
                $pubConfig = $netShare.INetSharingConfigurationForINetConnection($pubConn)
                $privConfig = $netShare.INetSharingConfigurationForINetConnection($privConn)
                
                if ($pubConfig.SharingEnabled -and $privConfig.SharingEnabled) {
                    Write-Log "Verification SUCCESS: ICS is active on both adapters." -Level "SUCCESS"
                    $icsVerified = $true
                }
                else {
                    Write-Log "Verification FAILED: COM reports sharing is NOT fully enabled." -Level "WARNING"
                }
            }
        }
        catch {}

        if ($icsVerified) {
            # Extra Packet Forwarding check on interfaces
            Set-NetIPInterface -InterfaceIndex $internetAdapter.ifIndex -Forwarding Enabled -ErrorAction SilentlyContinue
            Set-NetIPInterface -InterfaceIndex $vpnAdapter.ifIndex -Forwarding Enabled -ErrorAction SilentlyContinue
            return $true
        }
        else {
            # Provide manual instructions if automation failed
            $manualMsg = "WARNING: ICS configuration commands ran, but verification failed.`n" +
            "Please enable Internet Connection Sharing MANUALLY on the server:`n" +
            "  1. Go to Control Panel > Network Connections`n" +
            "  2. Right-click '$($internetAdapter.Name)' (Internet) > Properties > Sharing`n" +
            "  3. Check 'Allow other network users to connect...'`n" +
            "  4. Select '$($vpnAdapter.Name)' as the Home Networking Connection`n" +
            "  5. Click OK."
             
            Write-Warning $manualMsg
            Write-Log $manualMsg -Level "WARNING"
            # Return false so the warning is shown in summary
            return $false
        }

    }
    catch {
        Write-Log "Critical error in Enable-VPNNAT: $_" -Level "ERROR"
        return $false
    }
}

function Enable-IPForwarding {
    <#
    .SYNOPSIS
        Enables IP Forwarding on Windows for VPN routing.
    
    .DESCRIPTION
        This function enables IP routing via the Windows registry (IPEnableRouter).
        This is required to forward VPN traffic to the internet.
        
    .OUTPUTS
        System.Boolean
        $true on success, otherwise $false.
        
    .EXAMPLE
        Enable-IPForwarding
        
    .NOTES
        Requires admin privileges. A restart may be required for activation on some systems.
    #>
    param()
    
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
        $currentValue = Get-ItemProperty -Path $regPath -Name "IPEnableRouter" -ErrorAction SilentlyContinue
        
        # Check if already enabled
        if ($currentValue.IPEnableRouter -eq 1) {
            Write-Log "IP Forwarding is already enabled" -Level "INFO"
            return $true
        }
        
        # Enable it
        Set-ItemProperty -Path $regPath -Name "IPEnableRouter" -Value 1 -Type DWord
        Write-Log "IP Forwarding enabled in registry. Restart may be required." -Level "SUCCESS"
        
        # Attempt to start RemoteAccess service to activate routing without reboot
        try {
            $rasService = Get-Service -Name "RemoteAccess" -ErrorAction SilentlyContinue
            if ($rasService) {
                if ($rasService.Status -ne "Running") {
                    Set-Service -Name "RemoteAccess" -StartupType Automatic -ErrorAction SilentlyContinue
                    Start-Service -Name "RemoteAccess" -ErrorAction SilentlyContinue
                    Write-Log "RemoteAccess service started for IP routing" -Level "INFO"
                }
            }
        }
        catch {
            Write-Log "RemoteAccess service could not be started, restart required: $_" -Level "WARNING"
        }
        
        return $true
    }
    catch {
        Write-Log "Error enabling IP Forwarding: $_" -Level "ERROR"
        return $false
    }
}

function Invoke-Rollback {
    <#
    .SYNOPSIS
        Performs rollback to undo all changes upon setup failure.

    .DESCRIPTION
        This function attempts to revert all changes made during setup, including stopping services, removing files and firewall rules.
        It is used to clean up the system state if an installation fails partway through.

    .PARAMETER SetupType
        Type of setup ('Server' or 'Client').

    .OUTPUTS
        None

    .EXAMPLE
        Invoke-Rollback -SetupType "Server"

    .NOTES
        This function tries to ignore errors and logs warnings on failures, as the system might already be in an inconsistent state.
    #>
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateSet("Server", "Client")]
        [string]$SetupType
    )

    Write-Log "Rollback started for $SetupType setup" -Level "WARNING"

    try {
        switch ($SetupType) {
            "Server" {
                # Stop OpenVPN service
                Write-Log "Stopping OpenVPN service" -Level "INFO"
                try {
                    $service = Get-Service -Name "OpenVPNService" -ErrorAction SilentlyContinue
                    if ($service -and $service.Status -eq 'Running') {
                        Stop-Service -Name "OpenVPNService" -Force
                        Write-Log "OpenVPN service stopped" -Level "INFO"
                    }
                }
                catch {
                    Write-Log "Could not stop OpenVPN service: $_" -Level "WARNING"
                }

                # Remove firewall rule
                Write-Log "Removing firewall rule" -Level "INFO"
                try {
                    $ruleName = "OpenVPN-Inbound-TCP-443"
                    $existingRule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
                    if ($existingRule) {
                        Remove-NetFirewallRule -Name $ruleName
                        Write-Log "Firewall rule '$ruleName' removed" -Level "INFO"
                    }
                }
                catch {
                    Write-Log "Could not remove firewall rule: $_" -Level "WARNING"
                }

                # Remove server configuration file
                Write-Log "Removing server configuration file" -Level "INFO"
                try {
                    $serverConfigPath = Join-Path $Script:Settings.configPath "server.ovpn"
                    if (Test-Path $serverConfigPath) {
                        Remove-Item -Path $serverConfigPath -Force
                        Write-Log "Server configuration file removed: $serverConfigPath" -Level "INFO"
                    }
                }
                catch {
                    Write-Log "Could not remove server configuration file: $_" -Level "WARNING"
                }

                # Remove PKI directory (Certificates)
                Write-Log "Removing certificates (PKI directory)" -Level "INFO"
                try {
                    $pkiPath = Join-Path $Script:Settings.easyRSAPath "pki"
                    if (Test-Path $pkiPath) {
                        Remove-Item -Path $pkiPath -Recurse -Force
                        Write-Log "PKI directory removed: $pkiPath" -Level "INFO"
                    }
                }
                catch {
                    Write-Log "Could not remove PKI directory: $_" -Level "WARNING"
                }

                # Remove client package ZIP
                Write-Log "Removing client package ZIP" -Level "INFO"
                try {
                    $outputPath = Join-Path $Script:BasePath $Script:Settings.outputPath
                    $zipPath = Join-Path $outputPath "vpn-client-$($Script:Settings.clientName).zip"
                    if (Test-Path $zipPath) {
                        Remove-Item -Path $zipPath -Force
                        Write-Log "Client package ZIP removed: $zipPath" -Level "INFO"
                    }
                }
                catch {
                    Write-Log "Could not remove client package ZIP: $_" -Level "WARNING"
                }

                # Remove EasyRSA directory (optional, only if empty)
                Write-Log "Removing EasyRSA directory if empty" -Level "INFO"
                try {
                    $easyRSAPath = $Script:Settings.easyRSAPath
                    if (Test-Path $easyRSAPath) {
                        $items = Get-ChildItem -Path $easyRSAPath -Recurse
                        if ($items.Count -eq 0) {
                            Remove-Item -Path $easyRSAPath -Recurse -Force
                            Write-Log "EasyRSA directory removed: $easyRSAPath" -Level "INFO"
                        }
                    }
                }
                catch {
                    Write-Log "Could not remove EasyRSA directory: $_" -Level "WARNING"
                }
            }

            "Client" {
                # Stop VPN connection (Processes)
                Write-Log "Stopping VPN connection" -Level "INFO"
                try {
                    $openvpnProcesses = Get-Process -Name "openvpn" -ErrorAction SilentlyContinue
                    if ($openvpnProcesses) {
                        $openvpnProcesses | Stop-Process -Force
                        Write-Log "OpenVPN processes stopped" -Level "INFO"
                    }
                }
                catch {
                    Write-Log "Could not stop OpenVPN processes: $_" -Level "WARNING"
                }

                # Remove imported configuration files from config directory
                Write-Log "Removing imported configuration files" -Level "INFO"
                try {
                    $configPath = $Script:Settings.configPath
                    if (Test-Path $configPath) {
                        $ovpnFiles = Get-ChildItem -Path $configPath -Filter "*.ovpn" -ErrorAction SilentlyContinue
                        foreach ($file in $ovpnFiles) {
                            Remove-Item -Path $file.FullName -Force
                            Write-Log "Configuration file removed: $($file.FullName)" -Level "INFO"
                        }
                        $certFiles = Get-ChildItem -Path $configPath -Filter "*.crt" -ErrorAction SilentlyContinue
                        foreach ($file in $certFiles) {
                            Remove-Item -Path $file.FullName -Force
                            Write-Log "Certificate file removed: $($file.FullName)" -Level "INFO"
                        }
                        $keyFiles = Get-ChildItem -Path $configPath -Filter "*.key" -ErrorAction SilentlyContinue
                        foreach ($file in $keyFiles) {
                            Remove-Item -Path $file.FullName -Force
                            Write-Log "Key file removed: $($file.FullName)" -Level "INFO"
                        }
                    }
                }
                catch {
                    Write-Log "Could not remove configuration files: $_" -Level "WARNING"
                }
            }
        }

        Write-Log "Rollback for $SetupType setup completed" -Level "SUCCESS"
    }
    catch {
        Write-Log "Error during rollback: $_" -Level "ERROR"
    }
}


#endregion Helper Functions & Utilities
#region OpenVPN Implementation Details

# =================================================================================================
# REGION: OpenVPN Implementation Details
# =================================================================================================
# This section contains the specific implementation logic for OpenVPN tasks.
# It includes functions for installing the software, managing EasyRSA PKI,
# generating configurations, and controlling the OpenVPN Windows Service.
# Key Functions: Install-RemoteServer, Install-OpenVPN, Initialize-EasyRSA, 
#                Initialize-Certificates, New-ServerConfig, Start-VPNService.
# =================================================================================================

function Install-RemoteServer {
    <#
    .SYNOPSIS
        Installs OpenVPN Remote Server and fully configures it.
    .DESCRIPTION
        This function copies the module to a remote server, installs OpenVPN,
        configures the firewall, generates certificates, creates server config, and starts the service on a remote computer.

    .PARAMETER ComputerName
        Name of the remote computer.

    .PARAMETER Credential
        Credentials for the remote computer.

    .PARAMETER ServerConfig
        Hashtable with server configuration parameters.

    .PARAMETER LocalEasyRSAPath
        Local path to EasyRSA directory.

    .OUTPUTS
        System.Boolean
        $true on success, otherwise $false.

    .EXAMPLE
        $config = Get-ServerConfiguration -ServerName "vpn-server" -ServerIP "example.com"
        Install-RemoteServer -ComputerName "remote-pc" -Credential $cred -ServerConfig $config

    Reference: Based on PowerShell Remoting with New-PSSession, Invoke-Command, and Copy-Item (Microsoft PowerShell Documentation: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/new-pssession, https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/invoke-command, https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/copy-item).
    #>
    param (
        [Parameter(Mandatory = $true, Position = 0)][ValidatePattern('^[a-zA-Z0-9.-]+$')][string]$ComputerName,
        [Parameter(Mandatory = $true, Position = 1)][PSCredential]$Credential,
        [Parameter(Mandatory = $true, Position = 2)][hashtable]$ServerConfig,
        [Parameter(Mandatory = $true, Position = 3)][string]$LocalEasyRSAPath,
        [Parameter(Mandatory = $false)][string]$RemoteConfigPath
    )

    Write-Log "Remote server configuration started for $ComputerName" -Level "INFO"
    
    try {
        # Create session with bypassed execution policy (more reliable than setting inside scriptblock)
        $sessionOption = New-PSSessionOption -NoMachineProfile
        $session = New-PSSession -ComputerName $ComputerName -Credential $Credential -SessionOption $sessionOption -ErrorAction Stop
        
        # Get local paths logic to determine where the module source files are
        $moduleBase = $null
        
        # Priority 1: Use Script BasePath if available and valid (Development/Source context)
        if ($Script:BasePath -and (Test-Path (Join-Path $Script:BasePath 'src\module\AutoSecureVPN.psd1'))) {
            $moduleBase = Join-Path $Script:BasePath 'src\module'
            Write-Verbose "Using source module path from Script Scope: $moduleBase"
        }
        
        # Priority 2: Use loaded module base (Installed context)
        if (-not $moduleBase -or [string]::IsNullOrWhiteSpace($moduleBase)) {
            $moduleBase = $MyInvocation.MyCommand.Module.ModuleBase
        }

        # Priority 3: Fallbacks
        if (-not $moduleBase -or [string]::IsNullOrWhiteSpace($moduleBase)) {
            $moduleBase = $PSScriptRoot
            if (-not $moduleBase -or [string]::IsNullOrWhiteSpace($moduleBase)) {
                $moduleBase = Split-Path -Parent $MyInvocation.MyCommand.Definition
            }
        }
        # Ensure moduleBase is usable before building local module path
        if (-not $moduleBase -or [string]::IsNullOrWhiteSpace($moduleBase)) {
            if ($PSScriptRoot -and -not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
                $moduleBase = $PSScriptRoot
            }
            elseif ($Script:BasePath -and -not [string]::IsNullOrWhiteSpace($Script:BasePath)) {
                $moduleBase = Join-Path $Script:BasePath 'src\module'
            }
            else {
                $moduleBase = (Get-Location).Path
            }
        }
        $localModuleDir = $moduleBase
        if (-not (Test-Path (Join-Path $localModuleDir "AutoSecureVPN.psd1"))) {
            throw "Local module manifest not found in $localModuleDir"
        }

        # Ensure LocalEasyRSAPath is set (fallback to settings)
        if (-not $LocalEasyRSAPath -or [string]::IsNullOrWhiteSpace($LocalEasyRSAPath)) {
            if ($Script:Settings -and $Script:Settings.easyRSAPath) {
                $LocalEasyRSAPath = $Script:Settings.easyRSAPath
            }
            else {
                throw "LocalEasyRSAPath is empty and there is no fallback set in settings. Specify a valid path."
            }
        }

        # define remote temporary paths
        $remoteTemp = "C:\Temp"
        $remoteModuleDir = Join-Path $remoteTemp "AutoSecureVPN"
        $remoteEasyRSA = Join-Path $remoteTemp "easy-rsa"
        $remoteEasyRSAZip = Join-Path $remoteTemp "easy-rsa.zip"
        $remoteConfigDir = Join-Path $remoteTemp "config"

        # Prepare remote directories
        Invoke-Command -Session $session -ScriptBlock { 
            param($temp, $modDir, $cfgDir, $rsaDir) 
            if (-not (Test-Path $temp)) { New-Item -ItemType Directory -Path $temp -Force | Out-Null } 
            # Clean up before copy to prevent nesting and stale files
            if (Test-Path $modDir) { Remove-Item $modDir -Recurse -Force -ErrorAction SilentlyContinue }
            if (Test-Path $cfgDir) { Remove-Item $cfgDir -Recurse -Force -ErrorAction SilentlyContinue }
            if (Test-Path $rsaDir) { Remove-Item $rsaDir -Recurse -Force -ErrorAction SilentlyContinue }
            
            New-Item -ItemType Directory -Path $modDir -Force | Out-Null
            New-Item -ItemType Directory -Path $cfgDir -Force | Out-Null
        } -ArgumentList $remoteTemp, $remoteModuleDir, $remoteConfigDir, $remoteEasyRSA
        
        # Validate local files/paths before attempting remote copy
        if (-not (Test-Path $localModuleDir)) { throw "Local module directory not found" }
        if (-not (Test-Path $LocalEasyRSAPath)) { throw "Local EasyRSA path not found: $LocalEasyRSAPath" }
        $localConfigDir = Join-Path (Split-Path $localModuleDir -Parent) "config"
        if (-not (Test-Path $localConfigDir)) { throw "Local config directory not found: $localConfigDir" }

        # Compress EasyRSA locally for much faster transfer (10x+ speedup vs individual files)
        $tempZip = [System.IO.Path]::GetTempFileName() + ".zip"
        Write-Log "Compressing EasyRSA for faster transfer..." -Level "INFO"
        Compress-Archive -Path "$LocalEasyRSAPath\*" -DestinationPath $tempZip -Force

        # Copy files to remote (compression already provides major speedup)
        Write-Log "Transferring module files to remote server..." -Level "INFO"
        Copy-Item -Path "$localModuleDir\*" -Destination $remoteModuleDir -ToSession $session -ErrorAction Stop -Recurse -Force
        
        Write-Log "Transferring config files to remote server..." -Level "INFO"
        Copy-Item -Path "$localConfigDir\*" -Destination $remoteConfigDir -ToSession $session -Recurse -Force
        
        Write-Log "Transferring compressed EasyRSA to remote server..." -Level "INFO"
        Copy-Item -Path $tempZip -Destination $remoteEasyRSAZip -ToSession $session -ErrorAction Stop -Force
        Write-Log "File transfer completed" -Level "INFO"
        
        # Clean up local temp zip
        Remove-Item $tempZip -Force -ErrorAction SilentlyContinue
        
        # Execute the setup script block on the remote machine
        Invoke-Command -Session $session -ScriptBlock {
            param($moduleSettings, $moduleDirPath, $config, $remoteEasyRSAZip, $remoteEasyRSA, $remoteConfigPath, $remoteConfigDir)
            
            # Stop on errors from the start
            $ErrorActionPreference = 'Stop'
            
            # Disable file logging for remote operations (output is handled by PSSession)
            function global:Write-Log {
                param($Message, $Level = "INFO")
                Write-Verbose "[$Level] $Message"
            }
            
            # Extract EasyRSA ZIP using .NET (more reliable than Expand-Archive)
            Write-Verbose "Extracting EasyRSA..."
            # Remove existing directory to avoid extraction conflicts
            if (Test-Path $remoteEasyRSA) {
                Write-Verbose "Removing existing EasyRSA directory..."
                Remove-Item $remoteEasyRSA -Recurse -Force -ErrorAction SilentlyContinue
            }
            New-Item -ItemType Directory -Path $remoteEasyRSA -Force | Out-Null
            
            try {
                Add-Type -AssemblyName System.IO.Compression.FileSystem
                [System.IO.Compression.ZipFile]::ExtractToDirectory($remoteEasyRSAZip, $remoteEasyRSA)
            }
            catch {
                throw "Failed to extract EasyRSA ZIP: $_"
            }
            Remove-Item $remoteEasyRSAZip -Force -ErrorAction SilentlyContinue
            
            # Validate settings before importing module and set defaults if missing
            if (-not $moduleSettings) { 
                $moduleSettings = @{}
            }
            
            # Ensure critical settings have values with proper defaults for the remote context
            if (-not $moduleSettings.port -or $moduleSettings.port -eq 0) { $moduleSettings.port = 443 }
            if (-not $moduleSettings.protocol) { $moduleSettings.protocol = 'TCP' }
            if (-not $moduleSettings.easyRSAPath) { $moduleSettings.easyRSAPath = 'C:\Program Files\OpenVPN\easy-rsa' }
            if (-not $moduleSettings.configPath -or $remoteConfigPath) { $moduleSettings.configPath = if ($remoteConfigPath) { $remoteConfigPath } else { 'C:\Program Files\OpenVPN\config' } }
            if (-not $moduleSettings.installedPath) { $moduleSettings.installedPath = 'C:\Program Files\OpenVPN\bin\openvpn.exe' }
            
            Write-Log "Remote settings configured: Port=$($moduleSettings.port), Protocol=$($moduleSettings.protocol)" -Level "INFO"
            
            Write-Verbose "Settings after defaults: $($moduleSettings | ConvertTo-Json)"
            
            # Load module manifest (only when not already loaded)
            Write-Verbose "Loading module..."
            $manifestPath = Join-Path $moduleDirPath "AutoSecureVPN.psd1"
            if (-not (Get-Module -Name 'AutoSecure-VPN' -ErrorAction SilentlyContinue)) {
                try {
                    Import-Module $manifestPath -Force
                }
                catch {
                    throw "Failed to load module: $_"
                }
            }
            
            # Set module settings manually for the remote scope
            $Script:Settings = $moduleSettings
            $Script:BasePath = "C:\Temp"
            
            try {
                Write-Verbose "Starting remote server setup..."
                
                if (-not (Test-IsAdmin)) {
                    throw "Administrator rights required"
                }
                
                # Perform installation
                Write-Verbose "Installing OpenVPN..."
                if (-not (Install-OpenVPN)) {
                    throw "OpenVPN installation failed"
                }
                
                # Configure firewall
                Write-Verbose "Configuring firewall..."
                if (-not (Set-Firewall -Port $Script:Settings.port -Protocol $Script:Settings.protocol)) {
                    throw "Firewall configuration failed"
                }
                
                # Setup certificates (copy extracted files to final location)
                Write-Verbose "Copying EasyRSA with certificates..."
                $targetEasyRSAPath = $Script:Settings.easyRSAPath
                Write-Verbose "Target EasyRSA path: $targetEasyRSAPath"
                
                if (-not (Test-Path $targetEasyRSAPath)) {
                    Write-Verbose "Creating target directory: $targetEasyRSAPath"
                    New-Item -ItemType Directory -Path $targetEasyRSAPath -Force | Out-Null
                }
                if (-not (Test-Path $remoteEasyRSA)) {
                    throw "Remote EasyRSA directory not found: $remoteEasyRSA"
                }
                Write-Verbose "Copying from $remoteEasyRSA to $targetEasyRSAPath..."
                Copy-Item -Path "$remoteEasyRSA\*" -Destination $targetEasyRSAPath -Recurse -Force
                
                # Create config and start service
                Write-Verbose "Creating server config..."
                if (-not (New-ServerConfig -Config $config)) {
                    throw "Server config generation failed"
                }
                
                Write-Verbose "Starting VPN service..."
                if (-not (Start-VPNService)) {
                    throw "VPN service start failed"
                }

                Write-Verbose "Configuring NAT for internet access..."
                # Configure NAT for internet access (10.8.0.0/24 = OpenVPN default subnet)
                if (-not (Enable-VPNNAT -VPNSubnet "10.8.0.0/24" -VPNType "OpenVPN")) { 
                    Write-Verbose "NAT configuration warning - manual configuration may be needed"
                }
                
                
                Write-Log "Remote server setup completed successfully" -Level "SUCCESS"
            }
            catch {
                Write-Log "Error during remote server setup: $_" -Level "ERROR"
                throw
            }
            
            # Cleanup temp files on remote
            Remove-Item $moduleDirPath -Recurse -Force
            Remove-Item $remoteEasyRSA -Recurse -Force
            Remove-Item $remoteConfigDir -Recurse -Force
        } -ArgumentList $Script:Settings, $remoteModuleDir, $ServerConfig, $remoteEasyRSAZip, $remoteEasyRSA, $RemoteConfigPath, $remoteConfigDir -ErrorAction Stop
        
        Remove-PSSession $session
        
        Write-Log "Remote server configuration completed for $ComputerName" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Error during remote server configuration: $_" -Level "ERROR"
        
        # Try to perform remote rollback if setup fails
        try {
            $rollbackSession = New-PSSession -ComputerName $ComputerName -Credential $Credential -ErrorAction SilentlyContinue
            if ($rollbackSession) {
                Invoke-Command -Session $rollbackSession -ScriptBlock {
                    param($settings, $remoteEasyRSA, $remoteModule, $remoteConfigDir)
                    # Clean up transferred files
                    Write-Verbose "Rolling back: cleaning up transferred files..."
                    Remove-Item $remoteModule -Force -ErrorAction SilentlyContinue
                    Remove-Item $remoteEasyRSA -Recurse -Force -ErrorAction SilentlyContinue
                    Remove-Item $remoteConfigDir -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Verbose "Rollback cleanup completed"
                } -ArgumentList $Script:Settings, $remoteEasyRSA, $remoteModule, $remoteConfigDir
                Remove-PSSession $rollbackSession
            }
        }
        catch {
            Write-Log "Could not perform remote rollback: $_" -Level "WARNING"
        }
        
        if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
        return $false
    }
}

function Install-OpenVPN {
    <#
    .SYNOPSIS
        Downloads and installs OpenVPN.
        
    .DESCRIPTION
        Downloads the OpenVPN installer from the official website (or uses a cached version)
        and performs a silent installation.

    .PARAMETER Url
        The URL of the OpenVPN installer (default from settings).

    .OUTPUTS
        System.Boolean
        $true on success, otherwise $false.

    .EXAMPLE
        Install-OpenVPN

    Reference: Based on OpenVPN MSI installation process (OpenVPN Community Downloads: https://swupdate.openvpn.org/community/releases/), Invoke-WebRequest for download (Microsoft PowerShell Documentation: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest), and Start-Process for MSI installation (https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/start-process).
    #>
    param(
        [Parameter(Position = 0)][string]$openVpnUrl # url validation 
    )
    
    # Check if URL provided, else fetch latest version
    if (-not $openVpnUrl) {
        $version = if ($Script:Settings.openVpnVersion) { $Script:Settings.openVpnVersion } else { 
            try {
                $latest = Invoke-RestMethod -Uri 'https://api.github.com/repos/OpenVPN/openvpn/releases/latest'
                $latest.tag_name -replace '^v', ''
            }
            catch {
                Write-Log "2.6.15 used as fallback when retrieving latest OpenVPN version: $_" -Level "WARNING"
                '2.6.15'  #fallback
            }
        }
        $openVpnUrl = "https://swupdate.openvpn.org/community/releases/OpenVPN-$version-I001-amd64.msi"
    }
    
    # Check if already installed
    $installedPath = $Script:Settings.installedPath
    if (-not $installedPath -or [string]::IsNullOrWhiteSpace($installedPath)) {
        # Default fallback path for OpenVPN installation check
        $installedPath = "C:\Program Files\OpenVPN\bin\openvpn.exe"
    }
    if (Test-Path $installedPath) {
        Write-Log "OpenVPN seems already installed at $installedPath" -Level "INFO"
        return $true
    }
    
    Write-Log "OpenVPN installation started" -Level "INFO"
    
    $tempPath = [System.IO.Path]::GetTempFileName() + ".msi"
    
    try {
        # Download MSI
        Invoke-WebRequest -Uri $openVpnUrl -OutFile $tempPath -UseBasicParsing
        Write-Log "OpenVPN MSI downloaded to $tempPath" -Level "INFO"
        
        # Install silently
        $arguments = "/i `"$tempPath`" /qn /norestart"
        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $arguments -Wait -PassThru
        
        if ($process.ExitCode -eq 0) {
            Write-Log "OpenVPN successfully installed" -Level "SUCCESS"
            return $true
        }
        else {
            Write-Log "OpenVPN installation failed with exit code $($process.ExitCode)" -Level "ERROR"
            return $false
        }
    }
    catch {
        Write-Log "Error during OpenVPN installation: $_" -Level "ERROR"
        return $false
    }
    finally {
        if (Test-Path $tempPath) {
            Remove-Item $tempPath -Force
        }
    }
}

function Get-ServerConfiguration {
    <#
    .SYNOPSIS
        Prompts for server configuration parameters from the user.

    .DESCRIPTION
        This function asks for server name, IP, LAN subnet, and password for certificates.
        It validates IP addresses and ensures inputs are valid.

    .PARAMETER ServerName
        The name of the server (default from settings).

    .PARAMETER ServerIP
        The IP address of the server (default from settings).

    .PARAMETER LANSubnet
        The LAN subnet (default from settings).

    .PARAMETER LANMask
        The LAN subnet mask (default from settings).

    .PARAMETER NoPass
        If true, do not prompt for password for certificates (default from settings).

    .PARAMETER Password
        The password for certificates (optional).

    .OUTPUTS
        System.Collections.Hashtable
        A hashtable with server configuration.

    .EXAMPLE
        $config = Get-ServerConfiguration

    Reference: IP address validation based on regex from Stack Overflow (https://stackoverflow.com/questions/5284147/validating-ipv4-addresses-with-regexp)
    #>
    param(
        [Parameter(Position = 0)][ValidatePattern('^[a-zA-Z0-9_-]{1,63}$')][string]$ServerName = $Script:Settings.serverName,
        [Parameter(Position = 1)][string]$serverWanIP = $Script:Settings.serverWanIP,
        [Parameter(Position = 2)][string]$LANSubnet = $Script:Settings.lanSubnet,
        [Parameter(Position = 3)][string]$LANMask = $Script:Settings.lanMask,
        [Parameter(Position = 4)][switch]$NoPass = $Script:Settings.noPass,
        [Parameter(Position = 5)][ValidateLength(8, 128)][string]$Password
    )
    
    $config = @{}

    # ServerName: use parameter, otherwise default
    $inputServerName = $ServerName
    if ([string]::IsNullOrWhiteSpace($inputServerName)) {
        throw "Server name not set in Variable.psd1. Set serverName."
    }
    $config.ServerName = $inputServerName
    
    # ServerIP: use parameter, check if valid
    $inputServerIP = $serverWanIP
    if ([string]::IsNullOrWhiteSpace($inputServerIP) -or $inputServerIP -eq 'your.server.wan.ip.here') {
        throw "Server Wan IP not set in Variable.psd1. Set serverWanIP to a valid WAN IP or DDNS."
    }
    # Validate ServerIP: must be IP address or hostname regex check
    if ($inputServerIP -notmatch '^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$' -and $inputServerIP -notmatch '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$') {
        # https://stackoverflow.com/questions/5284147/validating-ipv4-addresses-with-regexp 
        throw "serverWanIP '$inputServerIP' is not a valid IP address or hostname."
    }
    $config.ServerIP = $inputServerIP
    
    # LANSubnet: use parameter, check if valid
    $inputLANSubnet = $LANSubnet
    if ([string]::IsNullOrWhiteSpace($inputLANSubnet)) {
        throw "LAN subnet not set in Variable.psd1. Set lanSubnet."
    }
    # Validate LANSubnet: must be IP address
    if ($inputLANSubnet -notmatch '^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$') {
        throw "LANSubnet '$inputLANSubnet' is not a valid IP address."
    }
    $config.LANSubnet = $inputLANSubnet

    $inputLANMask = $LANMask
    if ([string]::IsNullOrWhiteSpace($inputLANMask)) {
        throw "LAN subnet mask not set in Variable.psd1. Set lanMask."
    }
    # Validate LANMask: must be IP address
    if ($inputLANMask -notmatch '^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$') {
        throw "LANMask '$inputLANMask' is not a valid IP address."
    }
    $config.LANMask = $inputLANMask
    
    # NoPass: use parameter
    $config.NoPass = $NoPass
    
    # Password: only ask if NoPass is false
    if (-not $config.NoPass) {
        if ($Password) {
            $config.Password = $Password
        }
        else {
            # Loop until valid password entered
            while ($true) {
                $enteredPwd = Read-Host "Enter password for certificates (minimum 8 characters)"
                if ($enteredPwd.Length -ge 8) {
                    $config.Password = $enteredPwd
                    break
                }
                else {
                    Write-Log "Password must be at least 8 characters long." -Level "ERROR"
                }
            }
        }
    }
    else {
        # Explicitly set Password to null when noPass is true
        $config.Password = $null
    }
    
    Write-Log "Server configuration collected: ServerName=$($config.ServerName), ServerIP=$($config.ServerIP)" -Level "INFO"
    
    return $config
}

function Initialize-EasyRSA {
    <#
    .SYNOPSIS
        Initializes the PKI with EasyRSA.
        
    .DESCRIPTION
        Sets up the EasyRSA environment, including copying necessary files
        and initializing the Public Key Infrastructure.

    .PARAMETER EasyRSAPath
        The path where EasyRSA is installed (default from settings).

    .OUTPUTS
        System.Boolean
        $true on success, otherwise $false.

    .EXAMPLE
        Initialize-EasyRSA

    Referentie: Gebaseerd op EasyRSA installatieproces (EasyRSA GitHub: https://github.com/OpenVPN/easy-rsa), Invoke-WebRequest voor download (Microsoft PowerShell Documentatie: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest), en System.IO.Compression.ZipFile voor extractie (Microsoft .NET Framework Documentatie: https://docs.microsoft.com/en-us/dotnet/api/system.io.compression.zipfile).
    #>
    param(
        [Parameter(Position = 0)][string]$EasyRSAPath = $Script:Settings.easyRSAPath
    )
    
    if (Test-Path $EasyRSAPath) {
        Write-Log "EasyRSA is already installed in $EasyRSAPath" -Level "INFO"
        return $true
    }
    
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        # Determine version to download
        $version = if ($Script:Settings.easyRSAVersion) { $Script:Settings.easyRSAVersion } else { 
            try {
                $latest = Invoke-RestMethod -Uri 'https://api.github.com/repos/OpenVPN/easy-rsa/releases/latest'
                $latest.tag_name -replace '^v', ''
            }
            catch {
                Write-Log "3.2.4 used as fallback when retrieving latest EasyRSA version: $_" -Level "WARNING"
                '3.2.4'  # fallback
            }
        }
        $easyRSAUrl = "https://github.com/OpenVPN/easy-rsa/releases/download/v$version/EasyRSA-$version-win64.zip"
        $tempZip = Join-Path $env:TEMP "easyrsa.zip"
        
        # Download and extract
        Invoke-WebRequest -Uri $easyRSAUrl -OutFile $tempZip -UseBasicParsing
        [System.IO.Compression.ZipFile]::ExtractToDirectory($tempZip, $EasyRSAPath)
        
        # Fix nested directory structure if needed (e.g., EasyRSA-3.x.x folder inside)
        $nestedDir = Get-ChildItem $EasyRSAPath -Directory | Where-Object { $_.Name -like "EasyRSA-*" } | Select-Object -First 1
        if ($nestedDir) {
            Get-ChildItem $nestedDir.FullName | Move-Item -Destination $EasyRSAPath -Force
            Remove-Item $nestedDir.FullName -Recurse -Force
        }
        
        Write-Log "EasyRSA installed in $EasyRSAPath" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Error during EasyRSA installation: $_" -Level "ERROR"
        return $false
    }
    finally {
        if (Test-Path $tempZip) { Remove-Item $tempZip -Force }
    }
}

function Initialize-Certificates {
    <#
    .SYNOPSIS
        Generates CA and Server certificates.
        
    .DESCRIPTION
        Runs EasyRSA commands to build the Certificate Authority (CA)
        and generate the server certificate and key.

    .PARAMETER ServerName
        The name of the server (default from settings).

    .PARAMETER Password
        Password for certificates (optional).

    .PARAMETER EasyRSAPath
        Path to EasyRSA (default from settings).

    .OUTPUTS
        System.Boolean
        $true on success, otherwise $false.

    .EXAMPLE
        Initialize-Certificates -ServerName "vpn-server"

    Reference: Based on EasyRSA commands for certificate generation (EasyRSA Documentation: https://github.com/OpenVPN/easy-rsa), such as init-pki, build-ca, gen-req, sign-req, gen-dh, gen-crl. 
    #>
    param (
        [Parameter(Position = 0)][ValidatePattern('^[a-zA-Z0-9_-]{1,63}$')][string]$ServerName = $Script:Settings.servername,
        [Parameter(Position = 1)][System.Security.SecureString]$Password = $null,
        [Parameter(Position = 2)][string]$EasyRSAPath = $Script:Settings.easyRSAPath
    )
    
    # Validate password if provided
    if ($Password -and $Password.Length -lt 8) {
        throw "Password must be at least 8 characters long"
    }
    
    # Check if EasyRSA path exists
    if (-not (Test-Path $EasyRSAPath)) {
        Write-Log "EasyRSA path not found: $EasyRSAPath" -Level "ERROR"
        return $false
    }
    
    try {
        # Set environment variables for EasyRSA batch mode
        $env:EASYRSA_BATCH = "1"
        $env:EASYRSA_REQ_CN = $ServerName
        $varsFileWin = Join-Path $EasyRSAPath "vars"
        $env:PATH = "$EasyRSAPath;$EasyRSAPath\bin;$env:PATH"
        $sh = Join-Path $EasyRSAPath "bin\sh.exe"
        $easyrsa = Join-Path $EasyRSAPath "easyrsa"

        # Prepare Unix-style paths for bash (do not use them for Set-Content, only for execution)
        $drive = $EasyRSAPath.Substring(0, 1).ToLower()
        $unixEasyRSAPath = '/' + $drive + $EasyRSAPath.Substring(2) -replace '\\', '/'
        $env:EASYRSA = $unixEasyRSAPath

        # Create 'vars' file content (EasyRSA configuration)
        $pkiPath = Join-Path $EasyRSAPath "pki"
        $pkiPathUnix = (Join-Path $pkiPath '') -replace '\\', '/'
        $pkiPathUnix = '/' + $drive + $pkiPathUnix.Substring(2) -replace ' ', '\ '
        $varsContent = @"
set_var EASYRSA_REQ_CN "$ServerName"
set_var EASYRSA_BATCH "$($Script:Settings.easyRSABatch)"
set_var EASYRSA_PKI "pki"
set_var EASYRSA_ALGO "$($Script:Settings.easyRSAAlgo)"
set_var EASYRSA_KEY_SIZE "$($Script:Settings.easyRSAKeySize)"
set_var EASYRSA_CA_EXPIRE "$($Script:Settings.easyRSACAExpire)"
set_var EASYRSA_CERT_EXPIRE "$($Script:Settings.easyRSACertExpire)"
set_var EASYRSA_CRL_DAYS "$($Script:Settings.easyRSACRLDays)"
"@
        Set-Content -Path $varsFileWin -Value $varsContent -Encoding UTF8

        if (Test-Path $varsFileWin) {
            Write-Log "vars file successfully written to $varsFileWin" -Level "INFO"
        }
        else {
            Write-Log "vars file could not be written to $varsFileWin" -Level "ERROR"
        }

        # Also set the environment variable used by the easyrsa bash scripts to the Unix-style path
        $env:EASYRSA_VARS_FILE = '/' + $drive + $varsFileWin.Substring(2) -replace '\\', '/' -replace ' ', '\ '
        
        Push-Location $EasyRSAPath
        
        # Write vars file in the current directory (EasyRSA path) as backup
        Set-Content -Path "vars" -Value $varsContent -Encoding UTF8

        if (Test-Path "vars") {
            Write-Log "vars file successfully written to $(Join-Path $EasyRSAPath 'vars')" -Level "INFO"
        }
        else {
            Write-Log "vars file could not be written" -Level "ERROR"
        }

        # Set the environment variable to the relative path for the script execution
        $env:EASYRSA_VARS_FILE = "vars"
        $env:EASYRSA_PKI = "pki"
        
        # Remove existing PKI if it exists to avoid init-pki failure or stale certs
        if (Test-Path $pkiPath) {
            Write-Log "Removing existing PKI directory: $pkiPath" -Level "INFO"
            Remove-Item $pkiPath -Recurse -Force
        }
        
        # Build the bash PATH setup string - use semicolons for Windows sh.exe PATH separator
        # This setup ensures the bash environment has access to openssl and tools
        $unixEasyRSAPath = $EasyRSAPath -replace '\\', '/'
        $bashPathSetup = "export PATH=`"$unixEasyRSAPath;$unixEasyRSAPath/bin;`$PATH`"; export HOME=`"$unixEasyRSAPath`"; export EASYRSA_OPENSSL=`"$unixEasyRSAPath/openssl.exe`"; export EASYRSA_BATCH=1; cd `"$unixEasyRSAPath`";"
        
        Write-Verbose "Shell executable: $sh"
        Write-Verbose "EasyRSA path: $EasyRSAPath"
        Write-Verbose "Unix EasyRSA path: $unixEasyRSAPath"
        Write-Verbose "Bash PATH setup: $bashPathSetup"
        Write-Verbose "Current directory: $(Get-Location)"
        
        # Execute Step 1: Initialize PKI
        Write-Progress -Id 1 -Activity "Certificate Generation" -Status "Step 1 of 6: Initializing PKI" -PercentComplete 0
        Write-Verbose "Starting init-pki..."
        $initPkiCmd = "$bashPathSetup ./easyrsa init-pki"
        Write-Verbose "Command: $sh -c `"$initPkiCmd`""
        $easyrsaOutput = & $sh -c "$initPkiCmd" 2>&1
        Write-Verbose "init-pki completed with exit code: $LASTEXITCODE"
        if ($LASTEXITCODE -ne 0) {
            Write-Log "EasyRSA init-pki failed with exit code $LASTEXITCODE. Output: $easyrsaOutput" -Level "ERROR"
            return $false
        }
        Write-Log "Easy-RSA output: $easyrsaOutput"

        # Handle password logic if provided (create temp password file for non-interactive passing)
        $passFile = $null
        if ($Password) {
            $passFile = [System.IO.Path]::GetTempFileName()
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
            $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
            Set-Content -Path $passFile -Value $plainPassword -NoNewline -Encoding UTF8
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
            $env:EASYRSA_PASSOUT = "file:$passFile"
            $env:EASYRSA_PASSIN = "file:$passFile"
            Write-Log "Password file created for certificate generation" -Level "INFO"
        }

        # Execute Step 2: Build CA
        Write-Progress -Id 1 -Activity "Certificate Generation" -Status "Step 2 of 6: Generating CA certificate" -PercentComplete 16.67
        Write-Verbose "Starting build-ca (nopass=$(-not $Password))..."
        if ($Password) {
            $buildCaCmd = "$bashPathSetup ./easyrsa build-ca"
        }
        else {
            $buildCaCmd = "$bashPathSetup ./easyrsa build-ca nopass"
        }
        Write-Verbose "Command: $sh -c `"$buildCaCmd`""
        Write-Verbose "  Executing build-ca command..."
        $easyrsaOutput = & $sh -c "$buildCaCmd" 2>&1
        Write-Verbose "build-ca completed with exit code: $LASTEXITCODE"
        Write-Verbose "build-ca output: $easyrsaOutput"
        if ($LASTEXITCODE -ne 0) {
            Write-Log "EasyRSA build-ca failed with exit code $LASTEXITCODE. Output: $easyrsaOutput" -Level "ERROR"
            return $false
        }
        Write-Log "Easy-RSA output: $easyrsaOutput"
        
        # Execute Step 3: Generate Server Request
        Write-Progress -Id 1 -Activity "Certificate Generation" -Status "Step 3 of 6: Generating server certificate request" -PercentComplete 33.33
        Write-Verbose "Starting gen-req for $ServerName..."
        if ($Password) {
            $genReqCmd = "$bashPathSetup ./easyrsa gen-req $ServerName"
        }
        else {
            $genReqCmd = "$bashPathSetup ./easyrsa gen-req $ServerName nopass"
        }
        Write-Verbose "Command: $sh -c `"$genReqCmd`""
        Write-Verbose "  Executing gen-req command..."
        $easyrsaOutput = & $sh -c "$genReqCmd" 2>&1
        Write-Verbose "gen-req completed with exit code: $LASTEXITCODE"
        Write-Verbose "gen-req output: $easyrsaOutput"
        if ($LASTEXITCODE -ne 0) {
            Write-Log "EasyRSA gen-req failed with exit code $LASTEXITCODE. Output: $easyrsaOutput" -Level "ERROR"
            return $false
        }
        Write-Log "Easy-RSA output: $easyrsaOutput"

        # Execute Step 4: Sign Server Request
        Write-Progress -Id 1 -Activity "Certificate Generation" -Status "Step 4 of 6: Signing server certificate" -PercentComplete 50
        Write-Verbose "Starting sign-req for $ServerName..."
        $signReqCmd = "$bashPathSetup ./easyrsa sign-req server $ServerName"
        Write-Verbose "Command: $sh -c `"$signReqCmd`""
        Write-Verbose "  Executing sign-req command..."
        $easyrsaOutput = & $sh -c "$signReqCmd" 2>&1
        Write-Verbose "sign-req completed with exit code: $LASTEXITCODE"
        Write-Verbose "sign-req output: $easyrsaOutput"
        if ($LASTEXITCODE -ne 0) {
            Write-Log "EasyRSA sign-req server failed with exit code $LASTEXITCODE. Output: $easyrsaOutput" -Level "ERROR"
            return $false
        }
        
        # Execute Step 5: Diffie-Hellman Parameters
        Write-Progress -Id 1 -Activity "Certificate Generation" -Status "Step 5 of 6: Generating DH parameters" -PercentComplete 66.67
        Write-Verbose "Starting gen-dh (this may take a while)..."
        $genDhCmd = "$bashPathSetup ./easyrsa gen-dh"
        Write-Verbose "Command: $sh -c `"$genDhCmd`""
        Write-Verbose "  Executing gen-dh command (this may take a while)..."
        $easyrsaOutput = & $sh -c "$genDhCmd" 2>&1
        Write-Verbose "gen-dh completed with exit code: $LASTEXITCODE"
        Write-Verbose "gen-dh output: $easyrsaOutput"
        if ($LASTEXITCODE -ne 0) {
            Write-Log "EasyRSA gen-dh failed with exit code $LASTEXITCODE" -Level "ERROR"
            return $false
        }
        
        # Execute Step 6: Certificate Revocation List (CRL)
        Write-Progress -Id 1 -Activity "Certificate Generation" -Status "Step 6 of 6: Generating CRL" -PercentComplete 83.33
        Write-Verbose "Starting gen-crl..."
        $genCrlCmd = "$bashPathSetup ./easyrsa gen-crl"
        Write-Verbose "Command: $sh -c `"$genCrlCmd`""
        Write-Verbose "  Executing gen-crl command..."
        $easyrsaOutput = & $sh -c "$genCrlCmd" 2>&1
        Write-Verbose "gen-crl completed with exit code: $LASTEXITCODE"
        Write-Verbose "gen-crl output: $easyrsaOutput"
        if ($LASTEXITCODE -ne 0) {
            Write-Log "EasyRSA gen-crl failed with exit code $LASTEXITCODE" -Level "ERROR"
            return $false
        }
        
        Write-Progress -Id 1 -Activity "Certificate Generation" -Completed
        
        Write-Log "Certificates generated for $ServerName" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Error during certificate generation: $_" -Level "ERROR"
        return $false
    }
    finally {
        # Clean up password file for security
        if ($passFile -and (Test-Path $passFile)) {
            Remove-Item $passFile -Force
        }
        # Keep vars file for client generation later
        Pop-Location
    }
}

function New-ServerConfig {
    <#
    .SYNOPSIS
        Generates server.ovpn configuration.
        
    .DESCRIPTION
        Creates the 'server.ovpn' configuration file based on the provided settings
        (port, protocol, subnet, etc.).

    .PARAMETER Config
        Hashtable with server configuration.

    .PARAMETER EasyRSAPath
        Path to EasyRSA (default from settings).

    .PARAMETER ConfigPath
        Path where config is saved (default from settings).

    .OUTPUTS
        System.Boolean
        $true on success, otherwise $false.

    .EXAMPLE
        New-ServerConfig -Config $config

    Reference: Based on OpenVPN server configuration syntax (OpenVPN Reference Manual: https://openvpn.net/community-resources/reference-manual-for-openvpn-2-6/), including options such as port, proto, dev, ca, cert, key, dh, server, push, etc. Uses Set-Content for file writing (Microsoft PowerShell Documentation: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/set-content).
    #>
    param(
        [Parameter(Mandatory = $true, Position = 0)][hashtable]$Config,
        [Parameter(Position = 1)][string]$EasyRSAPath,
        [Parameter(Position = 2)][string]$ConfigPath
    )
    
    # Set defaults from settings if not provided
    if (-not $EasyRSAPath) {
        $EasyRSAPath = $Script:Settings.easyRSAPath
        if (-not $EasyRSAPath -or [string]::IsNullOrWhiteSpace($EasyRSAPath)) {
            $EasyRSAPath = 'C:\Program Files\OpenVPN\easy-rsa'
        }
    }
    if (-not $ConfigPath) {
        $ConfigPath = $Script:Settings.configPath
        if (-not $ConfigPath -or [string]::IsNullOrWhiteSpace($ConfigPath)) {
            $ConfigPath = 'C:\Program Files\OpenVPN\config'
        }
    }
    
    Write-Log "Server configuration generation started" -Level "INFO"
    
    $serverConfigFile = Join-Path $ConfigPath "server.ovpn"
    
    $pkiPath = Join-Path $EasyRSAPath "pki"

    # Define paths to keys/certs
    $caPath = Join-Path $pkiPath 'ca.crt'
    $certPath = Join-Path $pkiPath (Join-Path 'issued' "$($Config.ServerName).crt")
    $keyPath = Join-Path $pkiPath (Join-Path 'private' "$($Config.ServerName).key")
    $dhPath = Join-Path $pkiPath 'dh.pem'

    # Escape backslashes for OpenVPN config
    $caPath = $caPath -replace '\\', '\\'
    $certPath = $certPath -replace '\\', '\\'
    $keyPath = $keyPath -replace '\\', '\\'
    $dhPath = $dhPath -replace '\\', '\\'

    # Build the OpenVPN server config content
    $serverConfig = @"
port $($Script:Settings.port)
proto tcp
dev tun
ca "$caPath"
cert "$certPath"
key "$keyPath"
dh "$dhPath"
server $($Script:Settings.vpnSubnet) $($Script:Settings.vpnMask)
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS $($Script:Settings.dns1)"
push "dhcp-option DNS $($Script:Settings.dns2)"
keepalive 10 120
cipher AES-256-CBC
user nobody
group nobody
persist-key
persist-tun
status openvpn-status.log
verb 3
"@
    
    # Push LAN route if LAN access is configured
    if ($Config.LANSubnet) {
        $serverConfig += "`npush `"route $($Config.LANSubnet) $($Config.LANMask)`""
    }
    
    try {
        if (-not (Test-Path $ConfigPath)) {
            New-Item -ItemType Directory -Path $ConfigPath -Force
        }
        
        # Write config to file
        Set-Content -Path $serverConfigFile -Value $serverConfig -Encoding UTF8
        
        Write-Log "Server configuration created: $serverConfigFile" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Error during server configuration generation: $_" -Level "ERROR"
        return $false
    }
}

function Start-VPNService {
    <#
    .SYNOPSIS
        Starts the OpenVPN Service.
        
    .DESCRIPTION
        Starts the 'OpenVPNService' and sets its startup type to Automatic.

    .OUTPUTS
        System.Boolean
        $true on success, otherwise $false.

    .EXAMPLE
        Start-VPNService

    Reference: Start-Service cmdlets (Microsoft PowerShell Documentation: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/start-service).
    #>
    Write-Log "Starting OpenVPN service" -Level "INFO"
    
    try {
        $service = Get-Service -Name "OpenVPNService" -ErrorAction SilentlyContinue
        
        if (-not $service) {
            Write-Log "OpenVPN service not found" -Level "ERROR"
            return $false
        }
        
        if ($service.Status -ne "Running") {
            Start-Service -Name "OpenVPNService"
            Write-Log "OpenVPN service started" -Level "SUCCESS"
        }
        else {
            Write-Log "OpenVPN service was already active" -Level "INFO"
        }
        
        return $true
    }
    catch {
        Write-Log "Error during OpenVPN service start: $_" -Level "ERROR"
        return $false
    }
}

function New-ClientPackage {
    <#
    .SYNOPSIS
        Generates a client package for VPN connection.

    .DESCRIPTION
        This function generates certificates for a client, creates a client configuration file, and packs everything into a ZIP file.

    .PARAMETER Config
        Hashtable with server configuration.

    .PARAMETER EasyRSAPath
        Path to EasyRSA (default from settings).

    .PARAMETER OutputPath
        Path where the ZIP file is saved (default from settings).

    .OUTPUTS
        System.String
        The path to the ZIP file on success, otherwise $null.

    .EXAMPLE
        New-ClientPackage -Config $config

    Reference: Based on EasyRSA client certificate generation (EasyRSA Documentation: https://github.com/OpenVPN/easy-rsa), OpenVPN client config syntax (OpenVPN Reference Manual: https://openvpn.net/community-resources/reference-manual-for-openvpn-2-6/), and Compress-Archive for ZIP creation (Microsoft PowerShell Documentation: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.archive/compress-archive).
    #>
    param(
        [Parameter(Mandatory = $true, Position = 0)][hashtable]$Config,
        [Parameter(Position = 1)][string]$EasyRSAPath = $Script:Settings.easyRSAPath,
        [Parameter(Position = 2)][string]$OutputPath = $Script:OutputPath
    )
    
    # Default Output path check
    if (-not $OutputPath -or [string]::IsNullOrWhiteSpace($OutputPath)) {
        $OutputPath = Join-Path $Script:BasePath "output"
    }
    
    $pkiPath = Join-Path $EasyRSAPath "pki"
    
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force
    }
    
    $clientName = $Script:Settings.clientName
    $zipPath = Join-Path $OutputPath "vpn-client-$clientName.zip"
    
    try {
        Write-Log "Client package generation started for $clientName" -Level "INFO"
        Write-Log "EasyRSA path: $EasyRSAPath" -Level "INFO"
        Write-Log "PKI path: $pkiPath" -Level "INFO"
        Write-Log "Output path: $OutputPath" -Level "INFO"
        
        # Configure EasyRSA environment variables
        $env:EASYRSA_BATCH = "1"
        $env:EASYRSA_VARS_FILE = "vars"
        $env:EASYRSA_PKI = "pki"
        $env:PATH = "$EasyRSAPath;$EasyRSAPath\bin;$env:PATH"
        $sh = Join-Path $EasyRSAPath "bin\sh.exe"

        # Convert Windows path to Unix-style for bash (C:\... -> C:/...)
        $unixEasyRSAPath = $EasyRSAPath -replace '\\', '/'
        
        $env:EASYRSA_BATCH = "1"
        $env:EASYRSA_VARS_FILE = "vars"
        $env:EASYRSA_PKI = "pki"
        $env:PATH = "$EasyRSAPath;$EasyRSAPath\bin;$env:PATH"
        $sh = Join-Path $EasyRSAPath "bin\sh.exe"
        
        # Build the bash PATH setup - use semicolons for Windows sh.exe PATH separator
        # EASYRSA_BATCH=1 disables interactive prompts
        $bashPathSetup = "export PATH=`"$unixEasyRSAPath;$unixEasyRSAPath/bin;`$PATH`"; export HOME=`"$unixEasyRSAPath`"; export EASYRSA_OPENSSL=`"$unixEasyRSAPath/openssl.exe`"; export EASYRSA_BATCH=1; cd `"$unixEasyRSAPath`";"
        
        Write-Log "sh.exe path: $sh" -Level "INFO"
        Write-Log "Bash PATH setup: $bashPathSetup" -Level "INFO"
        
        Push-Location $EasyRSAPath
        Write-Log "Switched to directory: $EasyRSAPath" -Level "INFO"
        
        # Generate Client Request
        $genReqCmd = "$bashPathSetup ./easyrsa gen-req $clientName nopass"
        Write-Log "Executing: $sh -c `"$genReqCmd`"" -Level "INFO"
        $result1 = & $sh -c "$genReqCmd" 2>&1
        Write-Log "Exit code gen-req: $LASTEXITCODE" -Level "INFO"
        if ($LASTEXITCODE -ne 0) { Write-Log "Error during gen-req: $result1" -Level "ERROR" }
        
        # Sign Client Request
        $signReqCmd = "$bashPathSetup ./easyrsa sign-req client $clientName"
        Write-Log "Executing: $sh -c `"$signReqCmd`"" -Level "INFO"
        $result2 = & $sh -c "$signReqCmd" 2>&1
        Write-Log "Exit code sign-req: $LASTEXITCODE" -Level "INFO"
        if ($LASTEXITCODE -ne 0) { Write-Log "Error during sign-req: $result2" -Level "ERROR" }
        
        Pop-Location
        Write-Log "Returned to original directory" -Level "INFO"
        
        # Verify generated files exist
        Write-Log "Checking if certificates exist..." -Level "INFO"
        $caCrt = Join-Path $pkiPath 'ca.crt'
        $clientCrt = Join-Path $pkiPath (Join-Path 'issued' "$clientName.crt")
        $clientKey = Join-Path $pkiPath (Join-Path 'private' "$clientName.key")

        if ([System.IO.File]::Exists($caCrt)) { Write-Log "ca.crt found: $caCrt" -Level "INFO" } else { Write-Log "ca.crt not found: $caCrt" -Level "ERROR" }
        if ([System.IO.File]::Exists($clientCrt)) { Write-Log "$clientName.crt found: $clientCrt" -Level "INFO" } else { Write-Log "$clientName.crt not found: $clientCrt" -Level "ERROR" }
        if ([System.IO.File]::Exists($clientKey)) { Write-Log "$clientName.key found: $clientKey" -Level "INFO" } else { Write-Log "$clientName.key not found: $clientKey" -Level "ERROR" }
        
        # Create client config file content
        $clientConfig = @"
client
dev tun
proto tcp
remote $($Config.ServerIP) $($Script:Settings.port)
resolv-retry infinite
nobind
user nobody
group nobody
persist-key
persist-tun
ca ca.crt
cert $clientName.crt
key $clientName.key
remote-cert-tls server
cipher AES-256-CBC
verb 3
"@
        
        $clientConfigPath = Join-Path $OutputPath "client.ovpn"
        Set-Content -Path $clientConfigPath -Value $clientConfig -Encoding UTF8
        Write-Log "Client config created: $clientConfigPath" -Level "INFO"
        
        Write-Log "Copying certificates to output directory..." -Level "INFO"
        $copyFailed = $false
        
        # Copy keys/certs to output
        Copy-Item -Path $caCrt -Destination $OutputPath
        if ($?) { Write-Log "ca.crt copied" -Level "INFO" } else { Write-Log "cp failed for ca.crt" -Level "ERROR"; $copyFailed = $true }
        
        Copy-Item -Path $clientCrt -Destination $OutputPath
        if ($?) { Write-Log "$clientName.crt copied" -Level "INFO" } else { Write-Log "cp failed for $clientName.crt" -Level "ERROR"; $copyFailed = $true }
        
        Copy-Item -Path $clientKey -Destination $OutputPath
        if ($?) { Write-Log "$clientName.key copied" -Level "INFO" } else { Write-Log "cp failed for $clientName.key" -Level "ERROR"; $copyFailed = $true }
        
        if ($copyFailed) {
            Write-Log "Certificates could not be copied, client package creation failed" -Level "ERROR"
            return $null
        }
        
        # Zip all files
        Write-Log "Creating ZIP file: $zipPath" -Level "INFO"
        Compress-Archive -Path "$OutputPath\*" -DestinationPath $zipPath -Force
        
        # Cleanup temporary loose files in output
        Write-Log "Cleaning up temporary files" -Level "INFO"
        Remove-Item "$OutputPath\ca.crt", "$OutputPath\$clientName.crt", "$OutputPath\$clientName.key", $clientConfigPath -Force
        
        Write-Log "Client package created: $zipPath" -Level "SUCCESS"
        return $zipPath
    }
    catch {
        Write-Log "Error during client package generation: $_" -Level "ERROR"
        return $null
    }
}

function Import-ClientConfiguration {
    <#
    .SYNOPSIS
        Imports client configuration from a ZIP file.

    .DESCRIPTION
        This function extracts a client ZIP file to the configuration folder and returns the path to the OVPN file.

    .OUTPUTS
        System.String
        The path to the OVPN file on success, otherwise $null.

    .EXAMPLE
        Import-ClientConfiguration

    .NOTES
        This function uses Expand-Archive to extract the ZIP file.
    #>
    Write-Log "Importing client configuration started" -Level "INFO"
    
    if (-not $Script:OutputPath -or [string]::IsNullOrWhiteSpace($Script:OutputPath)) {
        $Script:OutputPath = Join-Path $Script:BasePath "output"
    }
    
    $configPath = $Script:Settings.configPath
    if (-not $configPath -or [string]::IsNullOrWhiteSpace($configPath)) {
        $configPath = 'C:\Program Files\OpenVPN\config'
    }
    
    # Try to find the default client ZIP file
    $defaultZipPath = Join-Path $Script:OutputPath "vpn-client-$($Script:Settings.clientName).zip"
    if (Test-Path $defaultZipPath) {
        $zipFile = $defaultZipPath
        Write-Log "Default client ZIP file found: $zipFile" -Level "INFO"
    }
    else {
        # Prompt user if default not found
        while ($true) {
            $zipFile = Read-Host "Path to client ZIP file"
            if ($zipFile -match '\.zip$' -and (Test-Path $zipFile)) {
                break
            }
            else {
                Write-Log "Invalid path or not a ZIP file. Try again." -Level "ERROR"
            }
        }
    }
    
    if (-not (Test-Path $zipFile)) {
        Write-Log "ZIP file not found: $zipFile" -Level "ERROR"
        return $null
    }
    
    try {
        Expand-Archive -Path $zipFile -DestinationPath $configPath -Force
        
        $ovpnFile = Get-ChildItem $configPath -Filter "*.ovpn" | Select-Object -First 1
        
        if ($ovpnFile) {
            # Update the OVPN file to use absolute paths for certificates
            # This is critical because OpenVPN GUI sometimes struggles with relative paths depending on CWD
            $ovpnContent = Get-Content $ovpnFile.FullName -Raw
            $escapedPath = $configPath -replace '\\', '\\\\'
            $ovpnContent = $ovpnContent -replace 'ca\s+ca\.crt', "ca `"$escapedPath\\ca.crt`""
            $ovpnContent = $ovpnContent -replace 'cert\s+client1\.crt', "cert `"$escapedPath\\client1.crt`""
            $ovpnContent = $ovpnContent -replace 'key\s+client1\.key', "key `"$escapedPath\\client1.key`""
            # Remove Windows-unsupported options (user/group dropping)
            $ovpnContent = $ovpnContent -replace 'user\s+nobody.*\n', ''
            $ovpnContent = $ovpnContent -replace 'group\s+nobody.*\n', ''
            # Update deprecated cipher
            $ovpnContent = $ovpnContent -replace 'cipher\s*AES-256-CBC', 'cipher AES-256-GCM'
            # Disable DCO to avoid device access issues
            $ovpnContent += "`ndisable-dco`n"
            Set-Content -Path $ovpnFile.FullName -Value $ovpnContent
            
            Write-Log "Client configuration imported: $($ovpnFile.FullName)" -Level "SUCCESS"
            return $ovpnFile.FullName
        }
        else {
            Write-Log "No OVPN file found in ZIP" -Level "ERROR"
            return $null
        }
    }
    catch {
        Write-Log "Error during client configuration import: $_" -Level "ERROR"
        return $null
    }
}

function Test-TAPAdapter {
    <#
    .SYNOPSIS
        Checks if a TAP adapter is present.

    .DESCRIPTION
        This function checks if a TAP adapter is installed, which is required for OpenVPN.

    .OUTPUTS
        System.Boolean
        $true if TAP adapter is found, otherwise $false.

    .EXAMPLE
        Test-TAPAdapter

    Reference: Based on Get-NetAdapter cmdlet (Microsoft PowerShell Documentation: https://docs.microsoft.com/en-us/powershell/module/netadapter/get-netadapter), used to detect TAP adapters installed by OpenVPN.
    #>
    Write-Log "TAP adapter check started" -Level "INFO"
    
    try {
        # Check NetAdapter list for TAP drivers
        $tapAdapters = Get-NetAdapter | Where-Object { $_.Name -like "*TAP*" -or $_.DriverDescription -like "*TAP*" }
        
        if ($tapAdapters) {
            Write-Log "TAP adapter found: $($tapAdapters[0].Name)" -Level "SUCCESS"
            return $true
        }
        else {
            Write-Log "No TAP adapter found" -Level "WARNING"
            return $false
        }
    }
    catch {
        Write-Log "Error during TAP adapter check: $_" -Level "ERROR"
        return $false
    }
}

function Start-VPNConnection {
    <#
    .SYNOPSIS
        Starts a VPN connection with a configuration file.

    .DESCRIPTION
        This function starts OpenVPN with the specified configuration file.
        On remote machines, it uses Task Scheduler to launch the GUI interactively.

    .PARAMETER ConfigFile
        Path to the OVPN configuration file.

    .OUTPUTS
        System.Boolean
        $true on success, otherwise $false.

    .EXAMPLE
        Start-VPNConnection -ConfigFile "C:\path\to\client.ovpn"

    Reference: Based on Start-Process for OpenVPN executable (Microsoft PowerShell Documentation: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/start-process), and Get-Process/Stop-Process for stopping existing processes (https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-process, https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/stop-process).
    #>
    param(
        [Parameter(Mandatory = $true, Position = 0)][ValidatePattern('\.ovpn$')][string]$ConfigFile,
        [Parameter(Mandatory = $false)][string]$ComputerName,
        [Parameter(Mandatory = $false)][PSCredential]$Credential
    )
    
    Write-Log "Starting VPN connection with config: $ConfigFile $(if ($ComputerName) { "on $ComputerName" })" -Level "INFO"
    
    try {
        if ($ComputerName) {
            # Remote execution - use Task Scheduler to start GUI interactively
            # This bypasses the limitation where remote PSSessions cannot launch visible GUIs for the logged-in user.
            $session = New-PSSession -ComputerName $ComputerName -Credential $Credential -ErrorAction Stop

            # Treat the provided ConfigFile as a path on the remote machine.
            $remoteConfigFile = $ConfigFile
            $remoteConfigDir = Split-Path $remoteConfigFile -Parent
            $profileName = [System.IO.Path]::GetFileNameWithoutExtension($remoteConfigFile)

            # Remote script block using Task Scheduler for GUI
            # To bypass this, you need a workaround to break out into the interactive session of the logged-in user.

            # We create a task via PowerShell on the remote PC that says: "Start OpenVPN GUI as soon as I give this command, but do it visible on the desktop of the logged-in user."
            $scriptBlock = {
                param($openVPNGuiPath, $profileName, $remoteConfigDir)

                # 1. Stop old processes
                Get-Process -Name "openvpn" -ErrorAction SilentlyContinue | Stop-Process -Force
                Get-Process -Name "openvpn-gui" -ErrorAction SilentlyContinue | Stop-Process -Force

                # 2. Define the action (start OpenVPN GUI with arguments)
                $argument = "--connect `"$profileName`""
                $action = New-ScheduledTaskAction -Execute $openVPNGuiPath -Argument $argument

                # 3. IMPORTANT: The task must run as 'Interactive' (only if user is logged on)
                # We use the 'Users' group so it starts for whoever is logged in.
                $principal = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Users" -RunLevel Highest

                # 4. Create task settings (RunOnlyIfLoggedOn is crucial for GUI visibility)
                $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0

                $taskName = "StartOpenVPNGUI_Remote"

                # 5. Register the task
                Register-ScheduledTask -Action $action -Principal $principal -Settings $settings -TaskName $taskName -Force | Out-Null

                # 6. Start the task (This launches the GUI on the user's screen)
                Start-ScheduledTask -TaskName $taskName

                # Wait a bit to ensure it has started
                Start-Sleep -Seconds 5

                # 7. Cleanup: remove the task again to keep the system clean
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false

                Write-Verbose "OpenVPN GUI has been started interactively via Task Scheduler."
            }

            Invoke-Command -Session $session -ScriptBlock $scriptBlock -ArgumentList $Script:Settings.openVPNGuiPath, $profileName, $remoteConfigDir

            Remove-PSSession -Session $session
        }
        else {
            # Local execution
            $openVPNGuiPath = $Script:Settings.openVPNGuiPath
            if (-not $openVPNGuiPath) {
                $openVPNGuiPath = $Script:Settings.openVPNGuiPath
            }
            
            if (-not (Test-Path $openVPNGuiPath)) {
                Write-Log "OpenVPN GUI executable not found: $openVPNGuiPath" -Level "ERROR"
                return $false
            }
            
            # Copy config to OpenVPN config directory if it's not already there
            $configDir = $Script:Settings.configPath
            if (-not (Test-Path $configDir)) {
                New-Item -ItemType Directory -Path $configDir -Force | Out-Null
            }
            
            $configFileName = Split-Path $ConfigFile -Leaf
            $destConfigFile = Join-Path $configDir $configFileName
            if ($ConfigFile -ne $destConfigFile) {
                Copy-Item -Path $ConfigFile -Destination $destConfigFile -Force
            }
            
            # Also copy any referenced certs/keys if in the same dir
            $sourceDir = Split-Path $ConfigFile
            $certs = Get-ChildItem -Path $sourceDir -Include "*.crt", "*.key" -File
            foreach ($cert in $certs) {
                Copy-Item -Path $cert.FullName -Destination $configDir -Force
            }
            
            # Get profile name (filename without extension)
            $profileName = [System.IO.Path]::GetFileNameWithoutExtension($configFileName)
            
            # Stop any existing OpenVPN processes
            Get-Process -Name "openvpn" -ErrorAction SilentlyContinue | Stop-Process -Force
            
            # Start connection using OpenVPN GUI
            $arguments = "--connect $profileName"
            Start-Process -FilePath $openVPNGuiPath -ArgumentList $arguments -NoNewWindow
        }
        
        Write-Log "VPN connection started via GUI with profile: $profileName $(if ($ComputerName) { "on $ComputerName" })" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Error during VPN connection start: $_" -Level "ERROR"
        return $false
    }
}

function Test-VPNConnection {
    <#
    .SYNOPSIS
        Tests the VPN connection.

    .DESCRIPTION
        This function tests the VPN connection by pinging a test IP address.

    .OUTPUTS
        System.Boolean
        $true if connection is successful, otherwise $false.

    .EXAMPLE
        Test-VPNConnection

    Reference: Based on Test-Connection cmdlet for ping testing (Microsoft PowerShell Documentation: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/test-connection), used to verify VPN connectivity.
    #>
    Write-Log "VPN connection test started" -Level "INFO"
    
    try {
        # Simple ping test to VPN server with retries
        $testIP = $Script:Settings.testIP
        if (-not $testIP) {
            $testIP = $Script:Settings.testIP
        }
        
        for ($i = 1; $i -le 5; $i++) {
            Write-Log "VPN test attempt $i to $testIP" -Level "INFO"
            $pingResult = Test-Connection -ComputerName $testIP -Count 1 -Quiet
            if ($pingResult) {
                Write-Log "VPN connection successfully tested" -Level "SUCCESS"
                return $true
            }
            Start-Sleep -Seconds 5
        }
        
        Write-Log "VPN connection test failed after 5 attempts" -Level "WARNING"
        return $false
    }
    catch {
        Write-Log "Error during VPN connection test: $_" -Level "ERROR"
        return $false
    }
}

function Install-RemoteClient {
    <#
    .SYNOPSIS
        Installs OpenVPN and client configuration on a remote machine.

    .DESCRIPTION
        This function uses PowerShell remoting to install OpenVPN, import configuration, and start the VPN connection on a remote computer.

    .PARAMETER ComputerName
        Name of the remote computer.

    .PARAMETER Credential
        Credentials for the remote computer.

    .PARAMETER ZipPath
        Path to the client ZIP file.

    .OUTPUTS
        System.Boolean
        $true on success, otherwise $false.

    .EXAMPLE
        Install-RemoteClient -ComputerName "remote-pc" -Credential $cred -ZipPath "C:\path\to\client.zip"

    Reference: Based on PowerShell Remoting with New-PSSession, Invoke-Command, Copy-Item (Microsoft PowerShell Documentation: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/new-pssession, https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/invoke-command, https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/copy-item), and System.IO.Compression.ZipFile for extraction (Microsoft .NET Framework Documentation: https://docs.microsoft.com/en-us/dotnet/api/system.io.compression.zipfile).
    #>
    param(
        [Parameter(Mandatory = $true, Position = 0)][ValidatePattern('^[a-zA-Z0-9.-]+$')][string]$ComputerName,
        [Parameter(Mandatory = $true, Position = 1)][PSCredential]$Credential,
        [Parameter(Mandatory = $true, Position = 2)][ValidatePattern('\.zip$')][string]$ZipPath,
        [Parameter(Position = 3)][string]$RemoteConfigPath = "C:\Program Files\OpenVPN\config"
    )
    
    Write-Log "Remote client configuration started for $ComputerName" -Level "INFO"
    
    if (-not (Test-Path $ZipPath)) {
        Write-Log "ZIP file not found: $ZipPath" -Level "ERROR"
        return $false
    }
    
    try {
        # Create session with bypassed execution policy
        $sessionOption = New-PSSessionOption -NoMachineProfile
        $session = New-PSSession -ComputerName $ComputerName -Credential $Credential -SessionOption $sessionOption -ErrorAction Stop
        
        # Get local paths for the module source
        $moduleBase = $MyInvocation.MyCommand.Module.ModuleBase
        # Ensure moduleBase is usable before building local module path
        if (-not $moduleBase -or [string]::IsNullOrWhiteSpace($moduleBase)) {
            if ($PSScriptRoot -and -not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
                $moduleBase = $PSScriptRoot
            }
            elseif ($Script:BasePath -and -not [string]::IsNullOrWhiteSpace($Script:BasePath)) {
                $moduleBase = Join-Path $Script:BasePath 'src\module'
            }
            else {
                $moduleBase = (Get-Location).Path
            }
        }
        $localModuleDir = $moduleBase
        if (-not (Test-Path (Join-Path $localModuleDir "AutoSecureVPN.psd1"))) {
            throw "Local module manifest not found in $localModuleDir"
        }
        
        # Copy module directory to remote temp
        $remoteTemp = "C:\Temp"
        Invoke-Command -Session $session -ScriptBlock { if (-not (Test-Path "C:\Temp")) { New-Item -ItemType Directory -Path "C:\Temp" -Force } } -ErrorAction Stop
        $remoteModuleDir = Join-Path $remoteTemp "AutoSecureVPN"
        $remoteZip = Join-Path $remoteTemp "client.zip"

        # Validate local files/paths before attempting remote copy
        if (-not (Test-Path $localModuleDir)) { throw "Local module directory not found: $localModuleDir" }
        if (-not (Test-Path $ZipPath)) { throw "ZIP file not found: $ZipPath" }

        Copy-Item -Path $localModuleDir -Destination $remoteModuleDir -ToSession $session -ErrorAction Stop -Recurse -Force
        Copy-Item -Path $ZipPath -Destination $remoteZip -ToSession $session -ErrorAction Stop -Force
        
        # Perform full client setup on remote by invoking the module logic remotely
        Invoke-Command -Session $session -ScriptBlock {
            param($settings, $moduleDirPath, $zipPath, $configPath)
            
            # Stop on errors from the start
            $ErrorActionPreference = 'Stop'
            
            # Set execution policy to allow script execution
            Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force
            
            # Load module manifest (only when not already loaded)
            $manifestPath = Join-Path $moduleDirPath "AutoSecureVPN.psd1"
            if (-not (Get-Module -Name 'AutoSecure-VPN' -ErrorAction SilentlyContinue)) {
                try {
                    Import-Module $manifestPath -Force
                }
                catch {
                    throw "Failed to load module: $_"
                }
            }
            
            # Disable file logging for remote operations
            function global:Write-Log {
                param($Message, $Level = "INFO")
                Write-Verbose "[$Level] $Message"
            }
            
            # Set module settings manually
            $Script:Settings = $settings
            $Script:BasePath = "C:\Temp"
            
            # Perform client setup
            try {
                Write-Verbose "Starting remote client setup..."
                
                # Check admin (assume true since we have session)
                if (-not (Test-IsAdmin)) {
                    throw "Administrator rights required on remote machine"
                }
                
                # Install OpenVPN
                if (-not (Install-OpenVPN)) {
                    throw "OpenVPN installation failed on remote machine"
                }
                
                # Expand client package
                if (-not (Test-Path $configPath)) {
                    New-Item -ItemType Directory -Path $configPath -Force | Out-Null
                }
                else {
                    # Remove existing config files to avoid conflicts
                    Get-ChildItem $configPath | Remove-Item -Force
                }
                Add-Type -AssemblyName System.IO.Compression.FileSystem
                [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $configPath)
                
                $ovpnFile = Get-ChildItem $configPath -Filter "*.ovpn" | Select-Object -First 1
                if (-not $ovpnFile) {
                    throw "No OVPN file found in client package"
                }
                
                # Test TAP adapter
                if (-not (Test-TAPAdapter)) {
                    Write-Log "TAP adapter not found, OpenVPN may need reinstallation" -Level "WARNING"
                }
            }
            catch {
                Write-Log "Error during remote client setup: $_" -Level "ERROR"
                throw
            }
            
            # Test connection
            Start-Sleep -Seconds 5
            Test-VPNConnection
            
            Write-Log "Remote client setup completed successfully" -Level "SUCCESS"
            
            # Clean up temp files
            Remove-Item $moduleDirPath -Recurse -Force
            Remove-Item $zipPath -Force
        } -ArgumentList $Script:Settings, $remoteModuleDir, $remoteZip, $remoteConfigPath -ErrorAction Stop
        
        Remove-PSSession $session
        
        Write-Log "Remote client configuration completed for $ComputerName" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Error during remote client configuration: $_" -Level "ERROR"
        
        # Attempt remote rollback on failure
        try {
            $rollbackSession = New-PSSession -ComputerName $ComputerName -Credential $Credential -ErrorAction SilentlyContinue
            if ($rollbackSession) {
                Invoke-Command -Session $rollbackSession -ScriptBlock {
                    param($settings, $modulePath)
                    try {
                        # Set execution policy to allow script execution
                        Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force
                        
                        $manifestPath = Join-Path $modulePath "AutoSecureVPN.psd1"
                        if (-not (Get-Module -Name 'AutoSecure-VPN' -ErrorAction SilentlyContinue)) {
                            Import-Module $manifestPath -Force
                        }
                    }
                    catch {
                        throw "Failed to load module: $_"
                    }
                    # Disable file logging for remote operations
                    function global:Write-Log {
                        param($Message, $Level = "INFO")
                        Write-Verbose "[$Level] $Message"
                    }
                    $Script:Settings = $settings
                    $Script:BasePath = "C:\Temp"
                    Invoke-Rollback -SetupType "Client"
                } -ArgumentList $Script:Settings, $remoteModuleDir
                Remove-PSSession $rollbackSession
            }
        }
        catch {
            Write-Log "Could not perform remote rollback: $_" -Level "WARNING"
        }
        
        if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
        return $false
    }
}

function Invoke-BatchRemoteClientInstall {
    <#
    .SYNOPSIS
        Perform batch remote client installs in parallel.

    .DESCRIPTION
        Accepts an array of client objects (Name, IP, Username, Password) and runs
        `Install-RemoteClient` in parallel runspaces. This centralizes the parallel
        logic so callers (scripts) remain small and focused.

    .PARAMETER Clients
        Array of client objects as imported from CSV.

    .PARAMETER ZipPath
        Path to the client ZIP package to deploy to each remote host.

    .PARAMETER ModulePath
        Path to this module file (used to import module inside parallel runspaces).

    .PARAMETER Settings
        Hashtable of module settings to apply in each runspace.

    .PARAMETER BasePath
        Base path to set in each runspace.

    .PARAMETER ThrottleLimit
        Maximum degree of parallelism. If omitted or less than 1, it will be computed
        based on local CPU cores (cores - 1, minimum 1).

    .OUTPUTS
        Array of result strings (SUCCESS: / ERROR:)
    #>
    
    param(
        [Parameter(Mandatory = $true, Position = 0)] [object[]]$Clients,
        [Parameter(Mandatory = $true, Position = 1)] [string]$ZipPath,
        [Parameter(Mandatory = $true, Position = 2)] [string]$ModulePath,
        [Parameter(Mandatory = $true, Position = 3)] [hashtable]$Settings,
        [Parameter(Mandatory = $true, Position = 4)] [string]$BasePath,
        [int]$ThrottleLimit = 0
    )

    # Local copies for use with $using: in the parallel scriptblock
    $clientsLocal = $Clients
    $zipPathLocal = $ZipPath
    $modulePathLocal = $ModulePath
    $settingsLocal = $Settings
    $basePathLocal = $BasePath

    # Set default throttling if not provided
    if (-not $ThrottleLimit -or $ThrottleLimit -lt 1) {
        try {
            $cpuCores = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).NumberOfLogicalProcessors
        }
        catch {
            $cpuCores = 2
        }
        $ThrottleLimit = [math]::Max(1, $cpuCores - 1)
    }

    # Parallel processing of clients
    $results = $clientsLocal | ForEach-Object -Parallel {
        param(
            [string]$Name,
            [string]$IP,
            [string]$Username,
            [string]$Password
        )
        $client = $_
        $name = $client.Name
        $ip = $client.IP
        $username = $client.Username
        $password = $client.Password

        # Create credential object safely
        $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential ($username, $securePassword)

        # Ensure module and settings are available in this isolated runspace
        Import-Module $using:modulePathLocal -Force
        Set-ModuleSettings -Settings $using:settingsLocal -BasePath $using:basePathLocal

        try {
            # Install
            $result = Install-RemoteClient -ComputerName $ip -Credential $cred -ZipPath $using:zipPathLocal
            if ($result) { 
                # Start VPN connection after successful installation
                $configPath = $using:settingsLocal.configPath
                if (-not $configPath -or [string]::IsNullOrWhiteSpace($configPath)) {
                    $configPath = 'C:\Program Files\OpenVPN\config'
                }
                $ovpnPath = Join-Path $configPath "client.ovpn"
                [void](Start-VPNConnection -ComputerName $ip -Credential $cred -ConfigFile $ovpnPath)
                "SUCCESS: $name ($ip)" 
            }
            else { 
                "ERROR: $name ($ip) - Installation failed" 
            }
        }
        catch {
            "ERROR: $name ($ip) - $_"
        }
    } -ThrottleLimit $ThrottleLimit

    return , $results
}


#endregion OpenVPN Implementation Details
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
        
        # 2. Get local paths (module source)
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
                $manifestPath = Join-Path $moduleDirPath "AutoSecureVPN.psd1"
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
                $manifestPath = Join-Path $moduleDirPath "AutoSecureVPN.psd1"
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