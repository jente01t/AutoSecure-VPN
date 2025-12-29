# OpenVPN functional files for the AutoSecureVPN module

function Install-RemoteServer {
    <#
    .SYNOPSIS
        Installs and configures OpenVPN server on a remote machine.

    .DESCRIPTION
        This function uses PowerShell remoting to install OpenVPN, configure firewall, generate certificates, create server config, and start the service on a remote computer.

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
        
        # Get local paths (robust fallback when module base is empty)
        # Get local paths
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

        # copy module to remote temp path
        $remoteTemp = "C:\Temp"
        $remoteModuleDir = Join-Path $remoteTemp "AutoSecureVPN"
        $remoteEasyRSA = Join-Path $remoteTemp "easy-rsa"
        $remoteEasyRSAZip = Join-Path $remoteTemp "easy-rsa.zip"
        $remoteConfigDir = Join-Path $remoteTemp "config"

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

        # Compress EasyRSA locally for much faster transfer (10x+ speedup)
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
        
        Invoke-Command -Session $session -ScriptBlock {
            param($moduleSettings, $moduleDirPath, $config, $remoteEasyRSAZip, $remoteEasyRSA, $remoteConfigPath, $remoteConfigDir)
            
            # Stop on errors from the start
            $ErrorActionPreference = 'Stop'
            
            # Disable file logging for remote operations - define early
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
            
            # Ensure critical settings have values with proper defaults
            if (-not $moduleSettings.port -or $moduleSettings.port -eq 0) { $moduleSettings.port = 443 }
            if (-not $moduleSettings.protocol) { $moduleSettings.protocol = 'TCP' }
            if (-not $moduleSettings.easyRSAPath) { $moduleSettings.easyRSAPath = 'C:\Program Files\OpenVPN\easy-rsa' }
            if (-not $moduleSettings.configPath -or $remoteConfigPath) { $moduleSettings.configPath = if ($remoteConfigPath) { $remoteConfigPath } else { 'C:\Program Files\OpenVPN\config' } }
            if (-not $moduleSettings.installedPath) { $moduleSettings.installedPath = 'C:\Program Files\OpenVPN\bin\openvpn.exe' }
            
            Write-Log "Remote settings configured: Port=$($moduleSettings.port), Protocol=$($moduleSettings.protocol)" -Level "INFO"
            
            Write-Verbose "Settings after defaults: $($moduleSettings | ConvertTo-Json)"
            
            # Load module manifest
            Write-Verbose "Loading module..."
            try {
                $manifestPath = Join-Path $moduleDirPath "AutoSecureVPN.psd1"
                Import-Module $manifestPath -Force
            }
            catch {
                throw "Failed to load module: $_"
            }
            
            # Set module settings manually
            $Script:Settings = $moduleSettings
            $Script:BasePath = "C:\Temp"
            
            try {
                Write-Verbose "Starting remote server setup..."
                
                if (-not (Test-IsAdmin)) {
                    throw "Administrator rights required"
                }
                
                Write-Verbose "Installing OpenVPN..."
                if (-not (Install-OpenVPN)) {
                    throw "OpenVPN installation failed"
                }
                
                Write-Verbose "Configuring firewall..."
                if (-not (Set-Firewall -Port $Script:Settings.port -Protocol $Script:Settings.protocol)) {
                    throw "Firewall configuration failed"
                }
                

                Write-Verbose "Copying EasyRSA with certificates..."
                $targetEasyRSAPath = $Script:Settings.easyRSAPath
                Write-Verbose "Target EasyRSA path: $targetEasyRSAPath"
                # easyRSAPath should now have a default value set above
                if (-not (Test-Path $targetEasyRSAPath)) {
                    Write-Verbose "Creating target directory: $targetEasyRSAPath"
                    New-Item -ItemType Directory -Path $targetEasyRSAPath -Force | Out-Null
                }
                if (-not (Test-Path $remoteEasyRSA)) {
                    throw "Remote EasyRSA directory not found: $remoteEasyRSA"
                }
                Write-Verbose "Copying from $remoteEasyRSA to $targetEasyRSAPath..."
                Copy-Item -Path "$remoteEasyRSA\*" -Destination $targetEasyRSAPath -Recurse -Force
                
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
        
        # Probeer remote rollback uit te voeren
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
            Write-Log "Kon remote rollback niet uitvoeren: $_" -Level "WARNING"
        }
        
        if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
        return $false
    }
}
function Install-OpenVPN {
    <#
    .SYNOPSIS
        Installs OpenVPN on the local machine.

    .DESCRIPTION
        This function downloads and installs OpenVPN via MSI if it is not already installed.

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
        Invoke-WebRequest -Uri $openVpnUrl -OutFile $tempPath -UseBasicParsing
        Write-Log "OpenVPN MSI downloaded to $tempPath" -Level "INFO"
        
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
    # Validate ServerIP: must be IP address or hostname
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
        Initialiseert EasyRSA voor certificaatbeheer.

    .DESCRIPTION
        Deze functie downloadt en installeert EasyRSA als het niet aanwezig is.

    .PARAMETER EasyRSAPath
        Het pad waar EasyRSA geïnstalleerd wordt (standaard uit settings).

    .OUTPUTS
        System.Boolean
        $true bij succes, anders $false.

    .EXAMPLE
        Initialize-EasyRSA

    Referentie: Gebaseerd op EasyRSA installatieproces (EasyRSA GitHub: https://github.com/OpenVPN/easy-rsa), Invoke-WebRequest voor download (Microsoft PowerShell Documentatie: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest), en System.IO.Compression.ZipFile voor extractie (Microsoft .NET Framework Documentatie: https://docs.microsoft.com/en-us/dotnet/api/system.io.compression.zipfile).
    #>
    param(
        [Parameter(Position = 0)][string]$EasyRSAPath = $Script:Settings.easyRSAPath
    )
    
    if (Test-Path $EasyRSAPath) {
        Write-Log "EasyRSA is al geïnstalleerd in $EasyRSAPath" -Level "INFO"
        return $true
    }
    
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $version = if ($Script:Settings.easyRSAVersion) { $Script:Settings.easyRSAVersion } else { 
            try {
                $latest = Invoke-RestMethod -Uri 'https://api.github.com/repos/OpenVPN/easy-rsa/releases/latest'
                $latest.tag_name -replace '^v', ''
            }
            catch {
                Write-Log "3.2.4 gebuikt als fallback bij ophalen van laatste EasyRSA versie: $_" -Level "WARNING"
                '3.2.4'  # fallback
            }
        }
        $easyRSAUrl = "https://github.com/OpenVPN/easy-rsa/releases/download/v$version/EasyRSA-$version-win64.zip"
        $tempZip = Join-Path $env:TEMP "easyrsa.zip"
        
        Invoke-WebRequest -Uri $easyRSAUrl -OutFile $tempZip -UseBasicParsing
        [System.IO.Compression.ZipFile]::ExtractToDirectory($tempZip, $EasyRSAPath)
        
        $nestedDir = Get-ChildItem $EasyRSAPath -Directory | Where-Object { $_.Name -like "EasyRSA-*" } | Select-Object -First 1
        if ($nestedDir) {
            Get-ChildItem $nestedDir.FullName | Move-Item -Destination $EasyRSAPath -Force
            Remove-Item $nestedDir.FullName -Recurse -Force
        }
        
        Write-Log "EasyRSA geïnstalleerd in $EasyRSAPath" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Fout tijdens EasyRSA installatie: $_" -Level "ERROR"
        return $false
    }
    finally {
        if (Test-Path $tempZip) { Remove-Item $tempZip -Force }
    }
}
function Initialize-Certificates {
    <#
    .SYNOPSIS
        Generates certificates for the VPN server.

    .DESCRIPTION
        This function initializes the PKI and generates CA, server, and DH certificates.

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
        $env:EASYRSA_BATCH = "1"
        $env:EASYRSA_REQ_CN = $ServerName
        $varsFileWin = Join-Path $EasyRSAPath "vars"
        $env:PATH = "$EasyRSAPath;$EasyRSAPath\bin;$env:PATH"
        $sh = Join-Path $EasyRSAPath "bin\sh.exe"
        $easyrsa = Join-Path $EasyRSAPath "easyrsa"

        # Prepare Unix-style paths for bash (do not use them for Set-Content)
        $drive = $EasyRSAPath.Substring(0, 1).ToLower()
        $unixEasyRSAPath = '/' + $drive + $EasyRSAPath.Substring(2) -replace '\\', '/'
        $env:EASYRSA = $unixEasyRSAPath

        # Create vars file (write using Windows path)
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
        
        # Write vars file in the current directory (EasyRSA path)
        Set-Content -Path "vars" -Value $varsContent -Encoding UTF8

        if (Test-Path "vars") {
            Write-Log "vars file successfully written to $(Join-Path $EasyRSAPath 'vars')" -Level "INFO"
        }
        else {
            Write-Log "vars file could not be written" -Level "ERROR"
        }

        # Set the environment variable to the relative path
        $env:EASYRSA_VARS_FILE = "vars"
        $env:EASYRSA_PKI = "pki"
        
        # Remove existing PKI if it exists to avoid init-pki failure
        if (Test-Path $pkiPath) {
            Write-Log "Removing existing PKI directory: $pkiPath" -Level "INFO"
            Remove-Item $pkiPath -Recurse -Force
        }
        
        # Build the bash PATH setup - use semicolons for Windows sh.exe PATH separator
        # Convert Windows path to Unix-style for bash (C:\... -> C:/...)
        $unixEasyRSAPath = $EasyRSAPath -replace '\\', '/'
        # EASYRSA_BATCH=1 disables interactive prompts
        $bashPathSetup = "export PATH=`"$unixEasyRSAPath;$unixEasyRSAPath/bin;`$PATH`"; export HOME=`"$unixEasyRSAPath`"; export EASYRSA_OPENSSL=`"$unixEasyRSAPath/openssl.exe`"; export EASYRSA_BATCH=1; cd `"$unixEasyRSAPath`";"
        
        Write-Verbose "Shell executable: $sh"
        Write-Verbose "EasyRSA path: $EasyRSAPath"
        Write-Verbose "Unix EasyRSA path: $unixEasyRSAPath"
        Write-Verbose "Bash PATH setup: $bashPathSetup"
        Write-Verbose "Current directory: $(Get-Location)"
        
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

        # Handle password if provided
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

        Write-Progress -Id 1 -Activity "Certificate Generation" -Status "Step 2 of 6: Generating CA certificate" -PercentComplete 16.67
        Write-Verbose "Starting build-ca (nopass=$(-not $Password))..."
        # EASYRSA_BATCH=1 handles confirmation prompts, no need for echo 'yes' |
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

        Write-Progress -Id 1 -Activity "Certificate Generation" -Status "Step 4 of 6: Signing server certificate" -PercentComplete 50
        Write-Verbose "Starting sign-req for $ServerName..."
        # EASYRSA_BATCH=1 handles confirmation prompts
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
        # Clean up password file
        if ($passFile -and (Test-Path $passFile)) {
            Remove-Item $passFile -Force
        }
        # Keep vars file for client
        Pop-Location
    }
}
function New-ServerConfig {
    <#
    .SYNOPSIS
        Generates the server configuration for OpenVPN.

    .DESCRIPTION
        This function creates a server.ovpn file with the specified configuration.

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

    $caPath = Join-Path $pkiPath 'ca.crt'
    $certPath = Join-Path $pkiPath (Join-Path 'issued' "$($Config.ServerName).crt")
    $keyPath = Join-Path $pkiPath (Join-Path 'private' "$($Config.ServerName).key")
    $dhPath = Join-Path $pkiPath 'dh.pem'

    # Escape backslashes for OpenVPN config
    $caPath = $caPath -replace '\\', '\\'
    $certPath = $certPath -replace '\\', '\\'
    $keyPath = $keyPath -replace '\\', '\\'
    $dhPath = $dhPath -replace '\\', '\\'

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
    
    if ($Config.LANSubnet) {
        $serverConfig += "`npush `"route $($Config.LANSubnet) $($Config.LANMask)`""
    }
    
    try {
        if (-not (Test-Path $ConfigPath)) {
            New-Item -ItemType Directory -Path $ConfigPath -Force
        }
        
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
        Starts the OpenVPN service.

    .DESCRIPTION
        This function starts the OpenVPN Windows service if it is not already running.

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
        
        $genReqCmd = "$bashPathSetup ./easyrsa gen-req $clientName nopass"
        Write-Log "Executing: $sh -c `"$genReqCmd`"" -Level "INFO"
        $result1 = & $sh -c "$genReqCmd" 2>&1
        Write-Log "Exit code gen-req: $LASTEXITCODE" -Level "INFO"
        if ($LASTEXITCODE -ne 0) { Write-Log "Error during gen-req: $result1" -Level "ERROR" }
        
        $signReqCmd = "$bashPathSetup ./easyrsa sign-req client $clientName"
        Write-Log "Executing: $sh -c `"$signReqCmd`"" -Level "INFO"
        $result2 = & $sh -c "$signReqCmd" 2>&1
        Write-Log "Exit code sign-req: $LASTEXITCODE" -Level "INFO"
        if ($LASTEXITCODE -ne 0) { Write-Log "Error during sign-req: $result2" -Level "ERROR" }
        
        Pop-Location
        Write-Log "Returned to original directory" -Level "INFO"
        
        Write-Log "Checking if certificates exist..." -Level "INFO"
        $caCrt = Join-Path $pkiPath 'ca.crt'
        $clientCrt = Join-Path $pkiPath (Join-Path 'issued' "$clientName.crt")
        $clientKey = Join-Path $pkiPath (Join-Path 'private' "$clientName.key")

        if ([System.IO.File]::Exists($caCrt)) { Write-Log "ca.crt found: $caCrt" -Level "INFO" } else { Write-Log "ca.crt not found: $caCrt" -Level "ERROR" }
        if ([System.IO.File]::Exists($clientCrt)) { Write-Log "$clientName.crt found: $clientCrt" -Level "INFO" } else { Write-Log "$clientName.crt not found: $clientCrt" -Level "ERROR" }
        if ([System.IO.File]::Exists($clientKey)) { Write-Log "$clientName.key found: $clientKey" -Level "INFO" } else { Write-Log "$clientName.key not found: $clientKey" -Level "ERROR" }
        
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
        
        Write-Log "Creating ZIP file: $zipPath" -Level "INFO"
        Compress-Archive -Path "$OutputPath\*" -DestinationPath $zipPath -Force
        
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
            $ovpnContent = Get-Content $ovpnFile.FullName -Raw
            $escapedPath = $configPath -replace '\\', '\\\\'
            $ovpnContent = $ovpnContent -replace 'ca\s+ca\.crt', "ca `"$escapedPath\\ca.crt`""
            $ovpnContent = $ovpnContent -replace 'cert\s+client1\.crt', "cert `"$escapedPath\\client1.crt`""
            $ovpnContent = $ovpnContent -replace 'key\s+client1\.key', "key `"$escapedPath\\client1.key`""
            # Remove Windows-unsupported options
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
            $session = New-PSSession -ComputerName $ComputerName -Credential $Credential -ErrorAction Stop

            # Treat the provided ConfigFile as a path on the remote machine.
            # Do NOT attempt to Test-Path or copy from the local host when starting remotely.
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

                # 4. Create task settings (RunOnlyIfLoggedOn is crucial for GUI)
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
            
            # Copy config to OpenVPN config directory
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
        
        # Get local paths
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
        
        # Perform full client setup on remote
        Invoke-Command -Session $session -ScriptBlock {
            param($settings, $moduleDirPath, $zipPath, $configPath)
            
            # Stop on errors from the start
            $ErrorActionPreference = 'Stop'
            
            # Set execution policy to allow script execution
            Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force
            
            # Load module manifest
            try {
                $manifestPath = Join-Path $moduleDirPath "AutoSecureVPN.psd1"
                Import-Module $manifestPath -Force
            }
            catch {
                throw "Failed to load module: $_"
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
        
        # Probeer remote rollback uit te voeren
        try {
            $rollbackSession = New-PSSession -ComputerName $ComputerName -Credential $Credential -ErrorAction SilentlyContinue
            if ($rollbackSession) {
                Invoke-Command -Session $rollbackSession -ScriptBlock {
                    param($settings, $modulePath)
                    try {
                        # Set execution policy to allow script execution
                        Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force
                        
                        $manifestPath = Join-Path $modulePath "AutoSecureVPN.psd1"
                        Import-Module $manifestPath -Force
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
            Write-Log "Kon remote rollback niet uitvoeren: $_" -Level "WARNING"
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

    if (-not $ThrottleLimit -or $ThrottleLimit -lt 1) {
        try {
            $cpuCores = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).NumberOfLogicalProcessors
        }
        catch {
            $cpuCores = 2
        }
        $ThrottleLimit = [math]::Max(1, $cpuCores - 1)
    }

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

        $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential ($username, $securePassword)

        # Ensure module and settings are available in this runspace
        Import-Module $using:modulePathLocal -Force
        Set-ModuleSettings -Settings $using:settingsLocal -BasePath $using:basePathLocal

        try {
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

